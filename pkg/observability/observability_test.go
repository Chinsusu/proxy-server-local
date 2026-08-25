package observability

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestStructuredLogRedactsSecretsAndBoundsFields(t *testing.T) {
	var output bytes.Buffer
	observer := New("pgw-api", &output)
	ctx, _ := WithRequest(t.Context(), "request_123", observer)
	observer.Logger.Log(ctx, "info", "mutation", map[string]any{"mapping_id": "mapping-1", "password": "canary-password", "reason_code": "jwt.eyJhbGciOiJIUzI1NiJ9.payload.signature", "ciphertext": "ciphertext-canary"})
	line := output.String()
	for _, prohibited := range []string{"canary-password", "ciphertext-canary", "eyJhbGciOiJIUzI1NiJ9"} {
		if strings.Contains(line, prohibited) {
			t.Fatalf("secret leaked in log: %s", line)
		}
	}
	if !strings.Contains(line, `"request_id":"request_123"`) || !strings.Contains(line, `"mapping_id":"mapping-1"`) {
		t.Fatalf("missing required bounded fields: %s", line)
	}
}

func TestMiddlewareUsesRequestIDAndRouteTemplate(t *testing.T) {
	var output bytes.Buffer
	observer := New("pgw-api", &output)
	handler := observer.WrapHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if RequestID(r.Context()) == "" {
			t.Error("request id absent")
		}
		w.WriteHeader(http.StatusCreated)
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v2/proxies/proxy-secret-id?token=not-logged", nil).WithContext(t.Context()))
	if recorder.Header().Get(requestIDHeader) == "" {
		t.Fatal("response request id absent")
	}
	if strings.Contains(output.String(), "proxy-secret-id") || strings.Contains(output.String(), "token=not-logged") || !strings.Contains(output.String(), "/v2/proxies/{id}") {
		t.Fatalf("raw path/query leaked or route absent: %s", output.String())
	}
	metrics := observer.Metrics.Render()
	if strings.Contains(metrics, "proxy-secret-id") || !strings.Contains(metrics, `route="/v2/proxies/{id}"`) {
		t.Fatalf("bad metrics: %s", metrics)
	}
}

func TestMetricsFormatLoopbackAndConcurrentUse(t *testing.T) {
	registry := NewRegistry("pgw-ui")
	var group sync.WaitGroup
	for n := 0; n < 32; n++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for i := 0; i < 100; i++ {
				registry.ObserveHTTPRequest(http.MethodGet, "/v2/mappings/opaque-id", 200, time.Millisecond)
				registry.ObserveAuth("success", "cookie")
			}
		}()
	}
	group.Wait()
	output := registry.Render()
	if !strings.Contains(output, "# TYPE pgw_http_requests_total counter") || !strings.Contains(output, "# HELP pgw_http_request_duration_seconds HTTP request duration in seconds.") || !strings.Contains(output, "# TYPE pgw_http_request_duration_seconds histogram") || !strings.Contains(output, `route="/v2/mappings/{id_or_action}"`) || strings.Contains(output, "opaque-id") {
		t.Fatalf("invalid metric output: %s", output)
	}
	if strings.Contains(output, "pgw_agent_") || strings.Contains(output, "pgw_schema_migration_ready") {
		t.Fatalf("UI metrics emitted control-plane collectors: %s", output)
	}
	server := httptest.NewServer(registry.Handler())
	defer server.Close()
	response, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if !strings.Contains(response.Header.Get("Content-Type"), "text/plain; version=0.0.4") {
		t.Fatalf("content type=%q", response.Header.Get("Content-Type"))
	}
	for _, addr := range []string{":9091", "localhost:9091", "0.0.0.0:9091", "192.0.2.1:9091"} {
		if _, err := ListenLoopback(addr); err == nil {
			t.Fatalf("accepted non-numeric/non-loopback metrics addr %q", addr)
		}
	}
}

func TestControlPlaneRegistersAgentSeriesOnlyAfterActualState(t *testing.T) {
	registry := NewRegistry("pgw-api")
	if output := registry.Render(); strings.Contains(output, "pgw_agent_") {
		t.Fatalf("uninitialized API registry emitted made-up agent state: %s", output)
	}
	registry.SetAgentState(9, 7, "APPLIED")
	output := registry.Render()
	if !strings.Contains(output, "pgw_agent_generation_pending") || !strings.Contains(output, `state="applied"`) {
		t.Fatalf("actual agent state omitted: %s", output)
	}
}
