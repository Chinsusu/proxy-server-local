package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Chinsusu/proxy-server-local/internal/application"
	"github.com/Chinsusu/proxy-server-local/internal/persistence/sqlite"
	"github.com/Chinsusu/proxy-server-local/pkg/observability"
)

func TestObservedMutationDoesNotLeakSecretOrRawResourceID(t *testing.T) {
	repository, err := sqlite.Open(context.Background(), sqlite.Config{Path: ":memory:", KeyProvider: testKey(bytes.Repeat([]byte{7}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	var logs bytes.Buffer
	observer := observability.New("pgw-api", &logs)
	server, err := New(Config{Service: application.New(repository), AgentToken: []byte("agent-token"), Observer: observer, AdminAuth: func(r *http.Request) (string, bool) { return "admin", r.Header.Get("Authorization") == "Bearer admin" }})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	secret := "canary-password-not-to-log"
	req := httptest.NewRequest(http.MethodPost, "/v2/proxies?access_token=not-logged", strings.NewReader(`{"id":"proxy-sensitive-id","type":"http","host":"proxy.example","port":8080,"username":"alice","password":"`+secret+`"}`))
	req.Header.Set("Authorization", "Bearer admin")
	req.Header.Set("Idempotency-Key", "observability-create")
	response := httptest.NewRecorder()
	observer.WrapHTTP(server).ServeHTTP(response, req)
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	for _, prohibited := range []string{secret, "proxy-sensitive-id", "access_token=not-logged", "Bearer admin"} {
		if strings.Contains(logs.String(), prohibited) || strings.Contains(observer.Metrics.Render(), prohibited) {
			t.Fatalf("observability leak %q logs=%s metrics=%s", prohibited, logs.String(), observer.Metrics.Render())
		}
	}
	if got := response.Header().Get("X-Request-ID"); got == "" || !strings.Contains(logs.String(), `"request_id":"`+got+`"`) {
		t.Fatalf("request id did not correlate response and log: response=%q logs=%s", got, logs.String())
	}
}
