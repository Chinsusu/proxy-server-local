package agent

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Chinsusu/proxy-server-local/pkg/observability"
)

func TestAgentTelemetryRedactsCanariesAndRejectsHighCardinalityLabels(t *testing.T) {
	var output bytes.Buffer
	telemetry := NewTelemetry(observability.New("pgw-agent", &output))
	ctx, _ := observability.WithRequest(context.Background(), "request_123456", telemetry.Observer)
	telemetry.Log(ctx, "error", "reconcile_completed", map[string]any{
		"mapping_id": "mapping-1", "proxy_id": "proxy-1", "reason_code": "password=canary-secret",
		"password": "canary-secret", "ciphertext": "ciphertext-canary", "token": "eyJcanary.payload.signature",
	})
	telemetry.Metrics.ObserveReconcile("customer-controlled-outcome-123", "mapping-customer-opaque-987", time.Millisecond)
	telemetry.Metrics.ObserveNFT("mapping-customer-opaque-987", "tenant-specific-outcome")
	rendered := telemetry.Metrics.Render()
	combined := output.String() + rendered
	for _, prohibited := range []string{"canary-secret", "ciphertext-canary", "eyJcanary", "mapping-customer-opaque-987", "customer-controlled-outcome-123", "tenant-specific-outcome"} {
		if strings.Contains(combined, prohibited) {
			t.Fatalf("sensitive/high-cardinality value leaked: %q in %s", prohibited, combined)
		}
	}
	if !strings.Contains(output.String(), `"request_id":"request_123456"`) || !strings.Contains(output.String(), `"mapping_id":"mapping-1"`) {
		t.Fatalf("bounded log context absent: %s", output.String())
	}
	if !strings.Contains(rendered, `outcome="other",reason="other"`) || !strings.Contains(rendered, `operation="other",outcome="other"`) {
		t.Fatalf("invalid labels did not collapse to other: %s", rendered)
	}
}

func TestAgentMetricsConcurrentRenderIsDeterministic(t *testing.T) {
	metrics := NewAgentMetrics()
	var workers sync.WaitGroup
	for worker := 0; worker < 32; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := 0; index < 100; index++ {
				metrics.ObserveReconcile("success", "none", time.Millisecond)
				metrics.ObserveNFT("check", "success")
				metrics.ObserveLKG("save", "success")
				metrics.ObserveForwarder("ready", "success")
				metrics.ObserveTrigger("accepted")
				metrics.ObserveCoalesced()
				metrics.SetGeneration(11, 10)
			}
		}()
	}
	workers.Wait()
	first, second := metrics.Render(), metrics.Render()
	if first != second {
		t.Fatal("metric rendering is nondeterministic")
	}
	for _, want := range []string{"pgw_agent_reconcile_total", "pgw_agent_reconcile_generation_lag 1", "pgw_agent_queue_coalesced_total 3200", "pgw_agent_nft_operations_total", "pgw_agent_forwarder_lifecycle_total"} {
		if !strings.Contains(first, want) {
			t.Fatalf("missing %q in metrics:\n%s", want, first)
		}
	}
}
