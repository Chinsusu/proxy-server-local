package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Chinsusu/proxy-server-local/internal/application"
	"github.com/Chinsusu/proxy-server-local/internal/domain"
	"github.com/Chinsusu/proxy-server-local/internal/persistence/sqlite"
)

type testKey []byte

func (k testKey) Key(context.Context) ([]byte, error) { return append([]byte(nil), k...), nil }

func testServer(t *testing.T) *Server {
	t.Helper()
	repository, err := sqlite.Open(context.Background(), sqlite.Config{Path: ":memory:", KeyProvider: testKey(bytes.Repeat([]byte{3}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repository.Close() })
	server, err := New(Config{Service: application.New(repository), AgentToken: []byte("agent-token"), AdminAuth: func(r *http.Request) (string, bool) { return "admin", r.Header.Get("Authorization") == "Bearer admin" }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	return server
}

func request(t *testing.T, server http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	return recorder
}

func TestAgentStateReportsDenyOnlyIPv6AsVerifiedOnlyAfterAgentAck(t *testing.T) {
	server := testServer(t)
	headers := map[string]string{"Authorization": "Bearer admin"}
	decode := func() operatorAgentState {
		response := request(t, server, http.MethodGet, "/v2/agent/state", "", headers)
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		var state operatorAgentState
		if err := json.Unmarshal(response.Body.Bytes(), &state); err != nil {
			t.Fatal(err)
		}
		return state
	}
	if state := decode(); state.IPv6Policy != domain.IPv6PolicyDeny || state.IPv6PolicyVerified {
		t.Fatalf("initial state=%+v", state)
	}
	repository := server.service.Repository()
	snapshot, err := repository.DesiredSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.AcknowledgeAgent(context.Background(), domain.AgentAck{Generation: snapshot.Generation, DesiredHash: snapshot.DesiredHash, AppliedHash: "verified", Status: domain.DataPlaneVerified}, "agent"); err != nil {
		t.Fatal(err)
	}
	if state := decode(); !state.IPv6PolicyVerified || state.IPv6Policy != domain.IPv6PolicyDeny {
		t.Fatalf("verified state=%+v", state)
	}
}

func TestV2ControlPlaneUsesIdempotencyVersionsAndRedaction(t *testing.T) {
	server := testServer(t)
	admin := map[string]string{"Authorization": "Bearer admin"}
	proxyBody := `{"id":"proxy-a","type":"http","host":"proxy.example","port":8080,"username":"alice","password":"canary-password"}`
	proxyHeaders := map[string]string{"Authorization": "Bearer admin", "Idempotency-Key": "proxy-create"}
	response := request(t, server, http.MethodPost, "/v2/proxies", proxyBody, proxyHeaders)
	if response.Code != http.StatusCreated {
		t.Fatalf("proxy create status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "canary-password") {
		t.Fatal("public proxy response leaked password")
	}
	if !strings.Contains(response.Body.String(), `"password_configured":true`) {
		t.Fatal("public proxy response omitted configuration state")
	}
	replay := request(t, server, http.MethodPost, "/v2/proxies", proxyBody, proxyHeaders)
	if replay.Code != http.StatusCreated || replay.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatalf("proxy replay status=%d replay=%q", replay.Code, replay.Header().Get("Idempotency-Replayed"))
	}

	client := request(t, server, http.MethodPost, "/v2/clients", `{"id":"client-a","ip_cidr":"192.168.2.101"}`, map[string]string{"Authorization": "Bearer admin", "Idempotency-Key": "client-create"})
	if client.Code != http.StatusCreated || !strings.Contains(client.Body.String(), "192.168.2.101/32") {
		t.Fatalf("client status=%d body=%s", client.Code, client.Body.String())
	}
	mapping := request(t, server, http.MethodPost, "/v2/mappings", `{"id":"mapping-a","client_id":"client-a","proxy_id":"proxy-a","local_redirect_port":15001}`, map[string]string{"Authorization": "Bearer admin", "Idempotency-Key": "mapping-create"})
	if mapping.Code != http.StatusCreated {
		t.Fatalf("mapping status=%d body=%s", mapping.Code, mapping.Body.String())
	}
	if missing := request(t, server, http.MethodPost, "/v2/mappings/mapping-a/activate", `{}`, admin); missing.Code != 428 {
		t.Fatalf("missing If-Match status=%d body=%s", missing.Code, missing.Body.String())
	}
	activateHeaders := map[string]string{"Authorization": "Bearer admin", "If-Match": mapping.Header().Get("ETag"), "Idempotency-Key": "activate-a"}
	activated := request(t, server, http.MethodPost, "/v2/mappings/mapping-a/activate", `{}`, activateHeaders)
	if activated.Code != http.StatusOK {
		t.Fatalf("activate status=%d body=%s", activated.Code, activated.Body.String())
	}
	if !strings.Contains(activated.Body.String(), `"desired_state":"ACTIVE"`) {
		t.Fatal("mapping was not activated")
	}
	if next := request(t, server, http.MethodGet, "/v2/mappings?limit=201", "", admin); next.Code != http.StatusBadRequest {
		t.Fatalf("page max status=%d", next.Code)
	}

	agentHeaders := map[string]string{"Authorization": "Bearer agent-token"}
	snapshot := request(t, server, http.MethodGet, "/internal/agent/v1/snapshot", "", agentHeaders)
	if snapshot.Code != http.StatusOK || strings.Contains(snapshot.Body.String(), "canary-password") {
		t.Fatalf("snapshot status=%d secret=%t", snapshot.Code, strings.Contains(snapshot.Body.String(), "canary-password"))
	}
	var snapshotValue struct {
		Generation  int64  `json:"generation"`
		DesiredHash string `json:"desired_hash"`
	}
	if err := json.Unmarshal(snapshot.Body.Bytes(), &snapshotValue); err != nil {
		t.Fatal(err)
	}
	credential := request(t, server, http.MethodGet, "/internal/agent/v1/mappings/mapping-a/credential", "", agentHeaders)
	if credential.Code != http.StatusOK {
		t.Fatalf("credential status=%d body=%s", credential.Code, credential.Body.String())
	}
	var credentialValue struct {
		Password []byte `json:"password"`
	}
	if err := json.Unmarshal(credential.Body.Bytes(), &credentialValue); err != nil {
		t.Fatal(err)
	}
	if string(credentialValue.Password) != "canary-password" {
		t.Fatalf("credential encoding mismatch")
	}
	ack := request(t, server, http.MethodPost, "/internal/agent/v1/ack", `{"generation":`+jsonNumber(snapshotValue.Generation)+`,"desired_hash":"`+snapshotValue.DesiredHash+`","applied_hash":"applied-hash","status":"VERIFIED"}`, agentHeaders)
	if ack.Code != http.StatusOK {
		t.Fatalf("ack status=%d body=%s", ack.Code, ack.Body.String())
	}
	stale := request(t, server, http.MethodPost, "/internal/agent/v1/ack", `{"generation":0,"desired_hash":"`+snapshotValue.DesiredHash+`","status":"FAILED"}`, agentHeaders)
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale ack status=%d body=%s", stale.Code, stale.Body.String())
	}
	// A later failed reconciliation must retain the prior verified/LKG
	// generation rather than erasing the data-plane proof.
	current := request(t, server, http.MethodGet, "/v2/mappings/mapping-a", "", admin)
	suspended := request(t, server, http.MethodPost, "/v2/mappings/mapping-a/suspend", `{}`, map[string]string{"Authorization": "Bearer admin", "If-Match": current.Header().Get("ETag"), "Idempotency-Key": "suspend-a"})
	if suspended.Code != http.StatusOK {
		t.Fatalf("suspend status=%d body=%s", suspended.Code, suspended.Body.String())
	}
	nextSnapshot := request(t, server, http.MethodGet, "/internal/agent/v1/snapshot", "", agentHeaders)
	var next struct {
		Generation  int64  `json:"generation"`
		DesiredHash string `json:"desired_hash"`
	}
	if err := json.Unmarshal(nextSnapshot.Body.Bytes(), &next); err != nil {
		t.Fatal(err)
	}
	failed := request(t, server, http.MethodPost, "/internal/agent/v1/ack", `{"generation":`+jsonNumber(next.Generation)+`,"desired_hash":"`+next.DesiredHash+`","status":"FAILED","reason_code":"nft_check_failed"}`, agentHeaders)
	if failed.Code != http.StatusOK || !strings.Contains(failed.Body.String(), `"applied_generation":1`) || !strings.Contains(failed.Body.String(), `"state":"FAILED"`) {
		t.Fatalf("failed ack did not retain LKG: %d %s", failed.Code, failed.Body.String())
	}
}

func TestV2PatchRequiresMutationFieldsWithoutSideEffects(t *testing.T) {
	server := testServer(t)
	admin := map[string]string{"Authorization": "Bearer admin"}
	proxy := request(t, server, http.MethodPost, "/v2/proxies", `{"id":"empty-patch-proxy","type":"http","host":"proxy.example","port":8080}`, map[string]string{"Authorization": "Bearer admin", "Idempotency-Key": "create-empty-patch-proxy"})
	if proxy.Code != http.StatusCreated {
		t.Fatalf("proxy create=%d body=%s", proxy.Code, proxy.Body.String())
	}
	client := request(t, server, http.MethodPost, "/v2/clients", `{"id":"empty-patch-client","ip_cidr":"192.168.2.118"}`, map[string]string{"Authorization": "Bearer admin", "Idempotency-Key": "create-empty-patch-client"})
	if client.Code != http.StatusCreated {
		t.Fatalf("client create=%d body=%s", client.Code, client.Body.String())
	}

	for _, test := range []struct {
		name string
		path string
		etag string
		key  string
	}{
		{name: "proxy", path: "/v2/proxies/empty-patch-proxy", etag: proxy.Header().Get("ETag"), key: "empty-patch-proxy"},
		{name: "client", path: "/v2/clients/empty-patch-client", etag: client.Header().Get("ETag"), key: "empty-patch-client"},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := request(t, server, http.MethodGet, test.path, "", admin)
			if before.Code != http.StatusOK {
				t.Fatalf("before=%d body=%s", before.Code, before.Body.String())
			}
			auditsBefore, err := server.service.Repository().ListAuditPage(context.Background(), 0, 200)
			if err != nil {
				t.Fatal(err)
			}

			response := request(t, server, http.MethodPatch, test.path, `{}`, map[string]string{"Authorization": "Bearer admin", "If-Match": test.etag, "Idempotency-Key": test.key})
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"validation_error"`) || !strings.Contains(response.Body.String(), `"field":"body"`) {
				t.Fatalf("empty patch=%d body=%s", response.Code, response.Body.String())
			}

			after := request(t, server, http.MethodGet, test.path, "", admin)
			if after.Code != http.StatusOK || after.Header().Get("ETag") != before.Header().Get("ETag") {
				t.Fatalf("version changed before=%q after=%q body=%s", before.Header().Get("ETag"), after.Header().Get("ETag"), after.Body.String())
			}
			auditsAfter, err := server.service.Repository().ListAuditPage(context.Background(), 0, 200)
			if err != nil {
				t.Fatal(err)
			}
			if len(auditsAfter.Items) != len(auditsBefore.Items) {
				t.Fatalf("audit count changed from %d to %d", len(auditsBefore.Items), len(auditsAfter.Items))
			}
		})
	}
}

func TestV2ProxyAndClientDeleteReplaySetsHeader(t *testing.T) {
	server := testServer(t)
	proxy := request(t, server, http.MethodPost, "/v2/proxies", `{"id":"delete-replay-proxy","type":"http","host":"proxy.example","port":8080}`, map[string]string{"Authorization": "Bearer admin", "Idempotency-Key": "create-delete-replay-proxy"})
	if proxy.Code != http.StatusCreated {
		t.Fatalf("proxy create=%d body=%s", proxy.Code, proxy.Body.String())
	}
	client := request(t, server, http.MethodPost, "/v2/clients", `{"id":"delete-replay-client","ip_cidr":"192.168.2.119"}`, map[string]string{"Authorization": "Bearer admin", "Idempotency-Key": "create-delete-replay-client"})
	if client.Code != http.StatusCreated {
		t.Fatalf("client create=%d body=%s", client.Code, client.Body.String())
	}

	for _, test := range []struct {
		name string
		path string
		etag string
		key  string
	}{
		{name: "proxy", path: "/v2/proxies/delete-replay-proxy", etag: proxy.Header().Get("ETag"), key: "delete-replay-proxy"},
		{name: "client", path: "/v2/clients/delete-replay-client", etag: client.Header().Get("ETag"), key: "delete-replay-client"},
	} {
		t.Run(test.name, func(t *testing.T) {
			headers := map[string]string{"Authorization": "Bearer admin", "If-Match": test.etag, "Idempotency-Key": test.key}
			first := request(t, server, http.MethodDelete, test.path, "", headers)
			if first.Code != http.StatusNoContent || first.Header().Get("Idempotency-Replayed") != "" {
				t.Fatalf("first delete=%d replay=%q body=%s", first.Code, first.Header().Get("Idempotency-Replayed"), first.Body.String())
			}
			replay := request(t, server, http.MethodDelete, test.path, "", headers)
			if replay.Code != http.StatusNoContent || replay.Header().Get("Idempotency-Replayed") != "true" {
				t.Fatalf("replay delete=%d replay=%q body=%s", replay.Code, replay.Header().Get("Idempotency-Replayed"), replay.Body.String())
			}
		})
	}
}

func TestV1FacadeUsesApplicationStoreAndNeverReadsPassword(t *testing.T) {
	server := testServer(t)
	legacy := server.LegacyV1Handler()
	headers := map[string]string{"Authorization": "Bearer admin"}
	proxy := request(t, legacy, http.MethodPost, "/v1/proxies", `{"id":"legacy-p","type":"http","host":"proxy.example","port":8080,"username":"u","password":"legacy-canary"}`, headers)
	if proxy.Code != http.StatusCreated || strings.Contains(proxy.Body.String(), "legacy-canary") {
		t.Fatalf("legacy proxy status=%d leaked=%t", proxy.Code, strings.Contains(proxy.Body.String(), "legacy-canary"))
	}
	client := request(t, legacy, http.MethodPost, "/v1/clients", `{"id":"legacy-c","ip_cidr":"192.168.2.102"}`, headers)
	if client.Code != http.StatusCreated {
		t.Fatalf("legacy client status=%d body=%s", client.Code, client.Body.String())
	}
	mapping := request(t, legacy, http.MethodPost, "/v1/mappings", `{"id":"legacy-m","client_id":"legacy-c","proxy_id":"legacy-p","local_redirect_port":15002}`, headers)
	if mapping.Code != http.StatusCreated || !strings.Contains(mapping.Body.String(), `"state":"PENDING"`) {
		t.Fatalf("legacy mapping status=%d body=%s", mapping.Code, mapping.Body.String())
	}
	active := request(t, legacy, http.MethodGet, "/v1/mappings/active", "", headers)
	if active.Code != http.StatusOK || !strings.Contains(active.Body.String(), "legacy-m") || strings.Contains(active.Body.String(), "legacy-canary") {
		t.Fatalf("legacy active status=%d body=%s", active.Code, active.Body.String())
	}
}

func TestInternalAgentEndpointsRejectTCPWhenUDSIsRequired(t *testing.T) {
	server := testServer(t)
	server.requireAgentUDS = true
	tcp := request(t, server, http.MethodGet, "/internal/agent/v1/state", "", map[string]string{"Authorization": "Bearer agent-token"})
	if tcp.Code != http.StatusForbidden {
		t.Fatalf("TCP internal status=%d body=%s", tcp.Code, tcp.Body.String())
	}
	req := httptest.NewRequest(http.MethodGet, "/internal/agent/v1/state", nil)
	req.RemoteAddr = "@"
	req.Header.Set("Authorization", "Bearer agent-token")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("UDS internal status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func jsonNumber(value int64) string { return string(strconv.AppendInt(nil, value, 10)) }

func TestV1UIPayloadAllocatesPortAndSupportsNoAuthCredential(t *testing.T) {
	server := testServer(t)
	legacy := server.LegacyV1Handler()
	headers := map[string]string{"Authorization": "Bearer admin"}
	proxy := request(t, legacy, http.MethodPost, "/v1/proxies", `{"id":"ui-proxy","type":"http","host":"proxy.example","port":8080}`, headers)
	if proxy.Code != http.StatusCreated || strings.Contains(proxy.Body.String(), `"password":`) {
		t.Fatalf("v1 no-auth proxy=%d body=%s", proxy.Code, proxy.Body.String())
	}
	client := request(t, legacy, http.MethodPost, "/v1/clients", `{"id":"ui-client","ip_cidr":"192.168.2.111"}`, headers)
	if client.Code != http.StatusCreated {
		t.Fatalf("v1 client=%d %s", client.Code, client.Body.String())
	}
	// This is the shape emitted by the current UI: protocol is present and
	// local_redirect_port is omitted. The compatibility allocator must retain
	// the old immediate-ACTIVE behavior without opening an arbitrary port.
	mapping := request(t, legacy, http.MethodPost, "/v1/mappings", `{"id":"ui-mapping","client_id":"ui-client","proxy_id":"ui-proxy","protocol":"http"}`, headers)
	if mapping.Code != http.StatusCreated || !strings.Contains(mapping.Body.String(), `"local_redirect_port":15001`) {
		t.Fatalf("v1 mapping=%d body=%s", mapping.Code, mapping.Body.String())
	}
	credential := request(t, server, http.MethodGet, "/internal/agent/v1/mappings/ui-mapping/credential", "", map[string]string{"Authorization": "Bearer agent-token"})
	if credential.Code != http.StatusOK || !strings.Contains(credential.Body.String(), `"auth_configured":false`) {
		t.Fatalf("no-auth credential=%d body=%s", credential.Code, credential.Body.String())
	}
}

func TestV1ProxyCheckUsesSQLiteAndSoftDeletesCascadeMappings(t *testing.T) {
	server := testServer(t)
	legacy := server.LegacyV1Handler()
	headers := map[string]string{"Authorization": "Bearer admin"}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	stop := make(chan struct{})
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer connection.Close()
				buffer := make([]byte, 4096)
				_, _ = connection.Read(buffer)
				_, _ = connection.Write([]byte("HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n"))
			}()
			select {
			case <-stop:
				return
			default:
			}
		}
	}()
	t.Cleanup(func() { close(stop) })
	port := listener.Addr().(*net.TCPAddr).Port
	proxy := request(t, legacy, http.MethodPost, "/v1/proxies", `{"id":"check-proxy","type":"http","host":"127.0.0.1","port":`+strconv.Itoa(port)+`}`, headers)
	if proxy.Code != http.StatusCreated {
		t.Fatalf("proxy=%d %s", proxy.Code, proxy.Body.String())
	}
	check := request(t, legacy, http.MethodPost, "/v1/proxies/check-proxy/check", `{}`, headers)
	if check.Code != http.StatusOK || !strings.Contains(check.Body.String(), `"status":"`) {
		t.Fatalf("check=%d %s", check.Code, check.Body.String())
	}
	client := request(t, legacy, http.MethodPost, "/v1/clients", `{"id":"check-client","ip_cidr":"192.168.2.112"}`, headers)
	if client.Code != http.StatusCreated {
		t.Fatal(client.Body.String())
	}
	mapping := request(t, legacy, http.MethodPost, "/v1/mappings", `{"id":"check-mapping","client_id":"check-client","proxy_id":"check-proxy"}`, headers)
	if mapping.Code != http.StatusCreated {
		t.Fatal(mapping.Body.String())
	}
	deleted := request(t, legacy, http.MethodDelete, "/v1/proxies/check-proxy", "", headers)
	if deleted.Code != http.StatusNoContent {
		t.Fatalf("delete=%d %s", deleted.Code, deleted.Body.String())
	}
	if _, err := server.service.Repository().GetProxy(context.Background(), "check-proxy"); err == nil {
		t.Fatal("soft-deleted proxy was publicly readable")
	}
	stored, err := server.service.Repository().GetMapping(context.Background(), "check-mapping")
	if err != nil || stored.DesiredState != domain.DesiredDeleted {
		t.Fatalf("cascade mapping state=%s err=%v", stored.DesiredState, err)
	}
	deletedMapping := request(t, legacy, http.MethodGet, "/v1/mappings/check-mapping", "", headers)
	if deletedMapping.Code != http.StatusNotFound || !strings.Contains(deletedMapping.Body.String(), `"request_id":`) {
		t.Fatalf("cascade-deleted v1 mapping=%d body=%s", deletedMapping.Code, deletedMapping.Body.String())
	}
}

func TestProxyRevisionRotatesSnapshotAndSOCKSLengthIsRejected(t *testing.T) {
	server := testServer(t)
	admin := map[string]string{"Authorization": "Bearer admin"}
	createProxy := request(t, server, http.MethodPost, "/v2/proxies", `{"id":"rotate-p","type":"http","host":"proxy.example","port":8080,"username":"user","password":"old"}`, map[string]string{"Authorization": "Bearer admin", "Idempotency-Key": "create-rotate-proxy"})
	if createProxy.Code != http.StatusCreated {
		t.Fatal(createProxy.Body.String())
	}
	client := request(t, server, http.MethodPost, "/v2/clients", `{"id":"rotate-c","ip_cidr":"192.168.2.113"}`, map[string]string{"Authorization": "Bearer admin", "Idempotency-Key": "create-rotate-client"})
	if client.Code != http.StatusCreated {
		t.Fatal(client.Body.String())
	}
	mapping := request(t, server, http.MethodPost, "/v2/mappings", `{"id":"rotate-m","client_id":"rotate-c","proxy_id":"rotate-p","local_redirect_port":15003}`, map[string]string{"Authorization": "Bearer admin", "Idempotency-Key": "create-rotate-mapping"})
	activated := request(t, server, http.MethodPost, "/v2/mappings/rotate-m/activate", `{}`, map[string]string{"Authorization": "Bearer admin", "If-Match": mapping.Header().Get("ETag"), "Idempotency-Key": "activate-rotate"})
	if activated.Code != http.StatusOK {
		t.Fatal(activated.Body.String())
	}
	first := request(t, server, http.MethodGet, "/internal/agent/v1/snapshot", "", map[string]string{"Authorization": "Bearer agent-token"})
	if first.Code != http.StatusOK {
		t.Fatal(first.Body.String())
	}
	var firstSnapshot domain.DesiredSnapshot
	if err := json.Unmarshal(first.Body.Bytes(), &firstSnapshot); err != nil {
		t.Fatal(err)
	}
	if len(firstSnapshot.Mappings) != 1 || firstSnapshot.Mappings[0].CredentialRevision != 1 {
		t.Fatalf("first snapshot=%+v", firstSnapshot)
	}
	suspended := request(t, server, http.MethodPost, "/v2/mappings/rotate-m/suspend", `{}`, map[string]string{"Authorization": "Bearer admin", "If-Match": activated.Header().Get("ETag"), "Idempotency-Key": "suspend-rotate"})
	if suspended.Code != http.StatusOK {
		t.Fatal(suspended.Body.String())
	}
	patched := request(t, server, http.MethodPatch, "/v2/proxies/rotate-p", `{"password":"new"}`, map[string]string{"Authorization": "Bearer admin", "If-Match": createProxy.Header().Get("ETag"), "Idempotency-Key": "rotate-credential"})
	if patched.Code != http.StatusOK || !strings.Contains(patched.Body.String(), `"credential_revision":2`) {
		t.Fatalf("patch=%d body=%s", patched.Code, patched.Body.String())
	}
	reactivated := request(t, server, http.MethodPost, "/v2/mappings/rotate-m/activate", `{}`, map[string]string{"Authorization": "Bearer admin", "If-Match": suspended.Header().Get("ETag"), "Idempotency-Key": "reactivate-rotate"})
	if reactivated.Code != http.StatusOK {
		t.Fatal(reactivated.Body.String())
	}
	second := request(t, server, http.MethodGet, "/internal/agent/v1/snapshot", "", map[string]string{"Authorization": "Bearer agent-token"})
	var secondSnapshot domain.DesiredSnapshot
	if err := json.Unmarshal(second.Body.Bytes(), &secondSnapshot); err != nil {
		t.Fatal(err)
	}
	if secondSnapshot.DesiredHash == firstSnapshot.DesiredHash || secondSnapshot.Mappings[0].CredentialRevision != 2 {
		t.Fatalf("revision did not rotate snapshot first=%+v second=%+v", firstSnapshot, secondSnapshot)
	}
	tooLong := strings.Repeat("x", 256)
	badSOCKS := request(t, server, http.MethodPost, "/v2/proxies", `{"id":"long-socks","type":"socks5","host":"socks.example","port":1080,"username":"`+tooLong+`","password":"x"}`, map[string]string{"Authorization": "Bearer admin", "Idempotency-Key": "long-socks"})
	if badSOCKS.Code != http.StatusBadRequest {
		t.Fatalf("overlong SOCKS accepted: %d %s", badSOCKS.Code, badSOCKS.Body.String())
	}
	_ = admin
}

func TestAckLeavesDraftAndSuspendedMappingsUntouched(t *testing.T) {
	server := testServer(t)
	repository := server.service.Repository()
	ctx := context.Background()
	proxy, err := repository.CreateProxy(ctx, sqlite.CreateProxyInput{ID: "ack-p", Type: domain.ProxyHTTP, Host: "proxy.example", Port: 8080, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, client := range []struct{ id, ip string }{{"ack-c1", "192.168.2.114"}, {"ack-c2", "192.168.2.115"}, {"ack-c3", "192.168.2.116"}} {
		if _, err := repository.CreateClient(ctx, sqlite.CreateClientInput{ID: client.id, IPCIDR: client.ip, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	active, err := repository.CreateMapping(ctx, sqlite.CreateMappingInput{ID: "ack-active", ClientID: "ack-c1", ProxyID: proxy.ID, LocalRedirectPort: 15004})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.ActivateMapping(ctx, active.ID, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CreateMapping(ctx, sqlite.CreateMappingInput{ID: "ack-draft", ClientID: "ack-c2", ProxyID: proxy.ID, LocalRedirectPort: 15005}); err != nil {
		t.Fatal(err)
	}
	suspended, err := repository.CreateMapping(ctx, sqlite.CreateMappingInput{ID: "ack-suspended", ClientID: "ack-c3", ProxyID: proxy.ID, LocalRedirectPort: 15006})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.SuspendMapping(ctx, suspended.ID, "test"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := repository.DesiredSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.AcknowledgeAgent(ctx, domain.AgentAck{Generation: snapshot.Generation, DesiredHash: snapshot.DesiredHash, AppliedHash: "hash", Status: domain.DataPlaneVerified}, "agent"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"ack-draft", "ack-suspended"} {
		mapping, err := repository.GetMapping(ctx, id)
		if err != nil || mapping.AppliedGeneration != 0 || mapping.DataPlaneState != domain.DataPlaneUnknown {
			t.Fatalf("ack changed %s: %+v err=%v", id, mapping, err)
		}
	}
}

func TestSnapshotReadsAConsistentGenerationDuringMutation(t *testing.T) {
	server := testServer(t)
	repository := server.service.Repository()
	ctx := context.Background()
	proxy, _ := repository.CreateProxy(ctx, sqlite.CreateProxyInput{ID: "concurrent-p", Type: domain.ProxyHTTP, Host: "proxy.example", Port: 8080, Enabled: true})
	client, _ := repository.CreateClient(ctx, sqlite.CreateClientInput{ID: "concurrent-c", IPCIDR: "192.168.2.117", Enabled: true})
	mapping, err := repository.CreateMapping(ctx, sqlite.CreateMappingInput{ID: "concurrent-m", ClientID: client.ID, ProxyID: proxy.ID, LocalRedirectPort: 15007})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.ActivateMapping(ctx, mapping.ID, "test"); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 8 {
			_, _ = repository.SuspendMapping(context.Background(), mapping.ID, "test")
			_, _ = repository.ActivateMapping(context.Background(), mapping.ID, "test")
		}
	}()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case <-done:
			return
		case <-deadline:
			t.Fatal("concurrent mutation did not finish")
		default:
			snapshot, snapshotErr := repository.DesiredSnapshot(ctx)
			if snapshotErr != nil {
				t.Fatal(snapshotErr)
			}
			if err := domain.ValidateDesiredSnapshot(snapshot); err != nil {
				t.Fatalf("inconsistent snapshot: %v", err)
			}
		}
	}
}

func TestLegacyPortAllocatorReusesDeletedHistoryButReservesLiveStates(t *testing.T) {
	server := testServer(t)
	legacy := server.LegacyV1Handler()
	headers := map[string]string{"Authorization": "Bearer admin"}
	if response := request(t, legacy, http.MethodPost, "/v1/proxies", `{"id":"allocator-p","type":"http","host":"proxy.example","port":8080}`, headers); response.Code != http.StatusCreated {
		t.Fatal(response.Body.String())
	}
	for index := 1; index <= 4; index++ {
		id := "allocator-c" + strconv.Itoa(index)
		ip := "192.168.2." + strconv.Itoa(120+index)
		if response := request(t, legacy, http.MethodPost, "/v1/clients", `{"id":"`+id+`","ip_cidr":"`+ip+`"}`, headers); response.Code != http.StatusCreated {
			t.Fatalf("client %d: %d %s", index, response.Code, response.Body.String())
		}
	}
	first := request(t, legacy, http.MethodPost, "/v1/mappings", `{"id":"allocator-deleted","client_id":"allocator-c1","proxy_id":"allocator-p"}`, headers)
	if first.Code != http.StatusCreated || !strings.Contains(first.Body.String(), `"local_redirect_port":15001`) {
		t.Fatalf("first allocation: %d %s", first.Code, first.Body.String())
	}
	if _, err := server.service.Repository().CreateMapping(context.Background(), sqlite.CreateMappingInput{ID: "allocator-suspended", ClientID: "allocator-c2", ProxyID: "allocator-p", LocalRedirectPort: 15002}); err != nil {
		t.Fatal(err)
	}
	if _, err := server.service.Repository().SuspendMapping(context.Background(), "allocator-suspended", "test"); err != nil {
		t.Fatal(err)
	}
	third := request(t, legacy, http.MethodPost, "/v1/mappings", `{"id":"allocator-live","client_id":"allocator-c3","proxy_id":"allocator-p"}`, headers)
	if third.Code != http.StatusCreated || !strings.Contains(third.Body.String(), `"local_redirect_port":15003`) {
		t.Fatalf("live-state allocation: %d %s", third.Code, third.Body.String())
	}
	if response := request(t, legacy, http.MethodDelete, "/v1/mappings/allocator-deleted", "", headers); response.Code != http.StatusNoContent {
		t.Fatalf("delete history: %d %s", response.Code, response.Body.String())
	}
	reused := request(t, legacy, http.MethodPost, "/v1/mappings", `{"id":"allocator-reused","client_id":"allocator-c4","proxy_id":"allocator-p"}`, headers)
	if reused.Code != http.StatusCreated || !strings.Contains(reused.Body.String(), `"local_redirect_port":15001`) {
		t.Fatalf("deleted port was not reused: %d %s", reused.Code, reused.Body.String())
	}
}

func TestV2UnknownAndMalformedMappingRoutesUseUniformNotFound(t *testing.T) {
	server := testServer(t)
	headers := map[string]string{"Authorization": "Bearer admin"}
	for _, path := range []string{
		"/v2/does-not-exist",
		"/v2/mappings/mapping/activate/extra",
		"/v2/mappings/mapping:activate:extra",
		"/v2/mappings/mapping:unknown",
		"/v2/mappings/mapping/:activate",
	} {
		response := request(t, server, http.MethodGet, path, "", headers)
		if response.Code != http.StatusNotFound || !strings.Contains(response.Header().Get("Content-Type"), "application/json") || !strings.Contains(response.Body.String(), `"error":{"code":"not_found"`) || !strings.Contains(response.Body.String(), `"request_id":`) {
			t.Fatalf("path=%s status=%d content_type=%s body=%s", path, response.Code, response.Header().Get("Content-Type"), response.Body.String())
		}
	}
	// Exact colon action is still supported during the migration window.
	if id, action, hasAction, valid := parseMappingRoute("mapping:activate"); !valid || !hasAction || id != "mapping" || action != "activate" {
		t.Fatalf("exact colon route parse invalid id=%q action=%q has_action=%t valid=%t", id, action, hasAction, valid)
	}
}
