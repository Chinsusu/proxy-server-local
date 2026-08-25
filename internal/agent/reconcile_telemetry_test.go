package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Chinsusu/proxy-server-local/pkg/observability"
)

type recoveryFailPlane struct{ *fakePlane }

func (recoveryFailPlane) VerifyBase(context.Context) error { return errors.New("base unavailable") }

func TestReconcileRollbackMetricsDoNotClaimGenerationApplied(t *testing.T) {
	events := []string{}
	snapshot := mustSnapshot(t, 9, activeMapping("m1", "192.168.2.101/32", 15001))
	control := &fakeControl{snapshot: snapshot, credentials: credentialMap(), events: &events}
	plane := &fakePlane{events: &events, applyErr: errors.New("canary ciphertext password token"), rolledBack: true}
	forwarders := &fakeForwarders{events: &events, ready: map[int]bool{}, stopError: map[int]error{}}
	store := &memoryLKG{value: emptyLKG(t), events: &events}
	telemetry := NewTelemetry(observability.NewDiscard("pgw-agent"))
	config := testConfig()
	config.Telemetry = telemetry
	reconciler, err := NewReconciler(config, control, plane, forwarders, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Reconcile(context.Background(), 9); err == nil {
		t.Fatal("expected rollback error")
	}

	shared := telemetry.Observer.Metrics.Render()
	agentMetrics := telemetry.Metrics.Render()
	if !strings.Contains(shared, "pgw_agent_generation_pending{service=\"pgw-agent\"} 9") || !strings.Contains(shared, "pgw_agent_generation_applied{service=\"pgw-agent\"} 0") {
		t.Fatalf("rollback generation truth is wrong: %s", shared)
	}
	if !strings.Contains(shared, "pgw_agent_state{service=\"pgw-agent\",state=\"rolled_back\"} 1") || !strings.Contains(agentMetrics, `outcome="rolled_back",reason="rolled_back"`) {
		t.Fatalf("rollback outcome absent: shared=%s agent=%s", shared, agentMetrics)
	}
	for _, secret := range []string{"canary", "ciphertext", "password", "token"} {
		if strings.Contains(agentMetrics, secret) {
			t.Fatalf("secret %q leaked to metrics", secret)
		}
	}
}

func TestStartupRecoveryFailureMetricsRemainFailClosedAndDoNotCallAPI(t *testing.T) {
	events := []string{}
	control := &fakeControl{snapshot: mustSnapshot(t, 44), credentials: credentialMap(), events: &events}
	forwarders := &fakeForwarders{events: &events, ready: map[int]bool{}, stopError: map[int]error{}}
	store := &memoryLKG{value: emptyLKG(t), events: &events}
	telemetry := NewTelemetry(observability.NewDiscard("pgw-agent"))
	config := testConfig()
	config.Telemetry = telemetry
	reconciler, err := NewReconciler(config, control, recoveryFailPlane{&fakePlane{events: &events}}, forwarders, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.StartupRecover(context.Background()); err == nil {
		t.Fatal("expected local recovery failure")
	}
	for _, event := range events {
		if strings.HasPrefix(event, "snapshot:") || strings.HasPrefix(event, "ack:") {
			t.Fatalf("startup recovery contacted API: %v", events)
		}
	}
	metrics := telemetry.Metrics.Render() + telemetry.Observer.Metrics.Render()
	if !strings.Contains(metrics, `pgw_agent_lkg_operations_total{operation="recovery",outcome="failure"} 1`) || !strings.Contains(metrics, `pgw_agent_state{service="pgw-agent",state="failed"} 1`) {
		t.Fatalf("recovery metric truth absent: %s", metrics)
	}
}
