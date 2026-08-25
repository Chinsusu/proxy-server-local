package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	agentcore "github.com/Chinsusu/proxy-server-local/internal/agent"
	"github.com/Chinsusu/proxy-server-local/pkg/observability"
)

func TestAgentMetricsEndpointIsCheapAndTriggerCarriesRequestID(t *testing.T) {
	var logs bytes.Buffer
	telemetry := agentcore.NewTelemetry(observability.New("pgw-agent", &logs))
	gate := newReconcileTriggerGate(time.Second, telemetry)
	handler := newAgentHandler(fixedTriggerAuthorizer(true), gate, telemetry)

	metrics := httptest.NewRecorder()
	handler.ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if metrics.Code != http.StatusOK || !strings.Contains(metrics.Body.String(), "pgw_agent_trigger_total") {
		t.Fatalf("metrics response: code=%d body=%s", metrics.Code, metrics.Body.String())
	}
	head := httptest.NewRecorder()
	handler.ServeHTTP(head, httptest.NewRequest(http.MethodHead, "/metrics", nil))
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Fatalf("HEAD metrics code=%d body=%q", head.Code, head.Body.String())
	}

	request := httptest.NewRequest(http.MethodPost, "/agent/reconcile", nil)
	request.Header.Set("Authorization", "Bearer scoped-token")
	request.Header.Set("X-Request-ID", "trigger_request_123")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("trigger status=%d", response.Code)
	}
	if response.Header().Get("X-Request-ID") != "trigger_request_123" {
		t.Fatalf("request id=%q", response.Header().Get("X-Request-ID"))
	}
	if !strings.Contains(logs.String(), `"request_id":"trigger_request_123"`) || !strings.Contains(logs.String(), `"event":"reconcile_trigger"`) {
		t.Fatalf("trigger log missing bounded request context: %s", logs.String())
	}
	if strings.Contains(metrics.Body.String(), "trigger_request_123") {
		t.Fatal("request ID leaked into metrics")
	}
}

func TestAgentTriggerMetricsUseOnlyBoundedOutcomes(t *testing.T) {
	telemetry := agentcore.NewTelemetry(observability.NewDiscard("pgw-agent"))
	handler := newAgentHandler(fixedTriggerAuthorizer(false), newReconcileTriggerGate(time.Second, telemetry), telemetry)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		request := httptest.NewRequest(method, "/agent/reconcile", nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
	}
	rendered := telemetry.Metrics.Render()
	if !strings.Contains(rendered, `outcome="method_not_allowed"`) || !strings.Contains(rendered, `outcome="unauthorized"`) {
		t.Fatalf("trigger outcomes missing: %s", rendered)
	}
}
