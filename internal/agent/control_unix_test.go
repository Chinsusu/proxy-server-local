//go:build unix

package agent

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Chinsusu/proxy-server-local/internal/domain"
)

func TestHTTPControlUsesAuthenticatedUnixSocketForAllEndpoints(t *testing.T) {
	directory := t.TempDir()
	socket := filepath.Join(directory, "api-agent.sock")
	tokenFile := filepath.Join(directory, "agent.token")
	if err := os.WriteFile(tokenFile, []byte("scoped-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	snapshot := mustSnapshot(t, 5, activeMapping("m1", "192.168.2.101/32", 15001))
	mux := http.NewServeMux()
	auth := func(handler http.HandlerFunc) http.HandlerFunc {
		return func(response http.ResponseWriter, request *http.Request) {
			if request.Header.Get("Authorization") != "Bearer scoped-token" {
				http.Error(response, "unauthorized", http.StatusUnauthorized)
				return
			}
			handler(response, request)
		}
	}
	mux.HandleFunc("/internal/agent/v1/snapshot", auth(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("generation") != "5" {
			http.Error(response, "generation", http.StatusConflict)
			return
		}
		_ = json.NewEncoder(response).Encode(snapshot)
	}))
	mux.HandleFunc("/internal/agent/v1/mappings/m1/credential", auth(func(response http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(response).Encode(credentialFor(snapshot.Mappings[0], true))
	}))
	mux.HandleFunc("/internal/agent/v1/ack", auth(func(response http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(response).Encode(domain.ReconcileState{NodeID: "local", PendingGeneration: 5, AppliedGeneration: 5, State: "VERIFIED", UpdatedAt: time.Now().UTC()})
	}))
	server := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}
	defer server.Close()
	go server.Serve(listener)
	control, err := NewHTTPControl(HTTPControlConfig{APIBase: "http://pgw.internal", CredentialSocket: socket, TokenFile: tokenFile})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.FetchSnapshot(context.Background(), 5); err != nil {
		t.Fatal(err)
	}
	credential, err := control.FetchCredential(context.Background(), "m1")
	if err != nil || string(credential.Password) != "secret" {
		t.Fatalf("credential result: password_len=%d err=%v", len(credential.Password), err)
	}
	zero(credential.Password)
	if err := control.Acknowledge(context.Background(), domain.AgentAck{Generation: 5, DesiredHash: snapshot.DesiredHash, AppliedHash: "hash", Status: domain.DataPlaneVerified}); err != nil {
		t.Fatal(err)
	}
}
