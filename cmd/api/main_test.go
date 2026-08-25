package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Chinsusu/proxy-server-local/internal/secret"
	"github.com/Chinsusu/proxy-server-local/pkg/auth"
	"github.com/Chinsusu/proxy-server-local/pkg/httpx"
)

func testLoginHandler(t *testing.T) http.Handler {
	t.Helper()
	hash, err := auth.HashPassword([]byte("correct horse battery staple"), auth.DefaultParams())
	if err != nil {
		t.Fatal(err)
	}
	return newLoginHandler("admin", []byte(hash), bytes.Repeat([]byte{9}, 32), httpx.NewLoginRateLimiter(5, time.Minute))
}

func TestLoginReturnsOnlySecureCookie(t *testing.T) {
	handler := testLoginHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{"Username":"admin","Password":"correct horse battery staple"}`))
	req.RemoteAddr = "127.0.0.1:1234"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	response := recorder.Result()
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status=%d", response.StatusCode)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 0 || bytes.Contains(bytes.ToLower(body), []byte("token")) {
		t.Fatalf("login exposed response body %q", body)
	}
	cookies := response.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies=%d headers=%v", len(cookies), response.Header.Values("Set-Cookie"))
	}
	cookie := cookies[0]
	if cookie.Name != "pgw_jwt" || cookie.Value == "" || cookie.Path != "/" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge != int(auth.MaxJWTTTL.Seconds()) || cookie.Expires.IsZero() {
		t.Fatalf("unsafe auth cookie: %+v", cookie)
	}
}

func TestLoginRejectsOversizedBodyWithoutCookie(t *testing.T) {
	handler := testLoginHandler(t)
	requestBody := bytes.Repeat([]byte("x"), maxLoginBodyBytes+1)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(requestBody))
	req.RemoteAddr = "127.0.0.1:1234"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", recorder.Code)
	}
	if got := recorder.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("oversized request received cookie %v", got)
	}
}

func TestLoginRejectsWhenGlobalArgonBudgetIsExhausted(t *testing.T) {
	handler := testLoginHandler(t)
	first, ok := auth.TryAcquirePasswordWork()
	if !ok {
		t.Fatal("first Argon2 budget slot unavailable")
	}
	defer first()
	second, ok := auth.TryAcquirePasswordWork()
	if !ok {
		t.Fatal("second Argon2 budget slot unavailable")
	}
	defer second()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{"username":"admin","password":"correct horse battery staple"}`))
	req.RemoteAddr = "127.0.0.1:1234"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "login verification temporarily unavailable") {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestLoginUsesVerifiedUIClientIdentityForRateLimit(t *testing.T) {
	hash, err := auth.HashPassword([]byte("correct horse battery staple"), auth.DefaultParams())
	if err != nil {
		t.Fatal(err)
	}
	proxyKey := bytes.Repeat([]byte{8}, 32)
	verifier, err := httpx.NewProxyIdentityVerifier(proxyKey)
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Close()
	limiter := httpx.NewLoginRateLimiter(2, time.Minute)
	handler := newLoginHandlerWithProxyIdentity("admin", []byte(hash), bytes.Repeat([]byte{9}, 32), limiter, verifier)
	requestFor := func(clientIP, password, nonce string) *httptest.ResponseRecorder {
		header, signErr := httpx.SignProxyIdentity(proxyKey, netip.MustParseAddr(clientIP), time.Now(), nonce)
		if signErr != nil {
			t.Fatal(signErr)
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{"username":"admin","password":"`+password+`"}`))
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header = header
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	if response := requestFor("198.51.100.1", "wrong", "nonce_client_one_01"); response.Code != http.StatusUnauthorized {
		t.Fatalf("first status=%d", response.Code)
	}
	if response := requestFor("198.51.100.1", "wrong", "nonce_client_one_02"); response.Code != http.StatusUnauthorized {
		t.Fatalf("second status=%d", response.Code)
	}
	if response := requestFor("198.51.100.2", "correct horse battery staple", "nonce_client_two_01"); response.Code != http.StatusNoContent {
		t.Fatalf("other client inherited limiter status=%d", response.Code)
	}
	if response := requestFor("198.51.100.1", "wrong", "nonce_client_one_03"); response.Code != http.StatusTooManyRequests {
		t.Fatalf("limited client status=%d", response.Code)
	}
}

func TestLoginRejectsSpoofedProxyIdentity(t *testing.T) {
	handler := testLoginHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{"username":"admin","password":"correct horse battery staple"}`))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set(httpx.ProxyClientIPHeader, "198.51.100.4")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusBadRequest || len(response.Header().Values("Set-Cookie")) != 0 {
		t.Fatalf("spoofed identity status=%d cookies=%v", response.Code, response.Header().Values("Set-Cookie"))
	}
}

func TestDecodeLoginRequestUsesStrictByteBackedPassword(t *testing.T) {
	username, password, err := decodeLoginRequest([]byte(`{"Username":"admin","Password":"p\n\uD83D\uDE00"}`))
	if err != nil || username != "admin" || !bytes.Equal(password, []byte("p\n😀")) {
		t.Fatalf("username=%q password=%q err=%v", username, password, err)
	}
	secret.Wipe(password)
	for _, input := range [][]byte{
		[]byte(`{"username":"admin","password":"one","password":"two"}`),
		[]byte(`{"username":"admin","Username":"admin","password":"two"}`),
		[]byte(`{"username":"admin","password":"one","PASSWORD":"two"}`),
		[]byte(`{"username":"admin","password":"\uD83D"}`),
		[]byte("{\"username\":\"admin\",\"password\":\"\xff\"}"),
		[]byte(`{"username":"admin","password":"ok" trailing}`),
		[]byte(`{"username":"admin","password":null}`),
		[]byte(`{"username":"admin","password":"ok","extra":true}`),
		[]byte(`{"username":"admin"}`),
	} {
		if _, value, err := decodeLoginRequest(input); err == nil || value != nil {
			t.Fatalf("unsafe login JSON accepted: %s", input)
		}
	}
}

func FuzzDecodeLoginRequestRejectsMalformedSecrets(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"username":"admin","password":"ok"}`),
		[]byte(`{"username":"admin","password":"\uD83D"}`),
		[]byte(`{"username":"admin","password":"a\"b"}`),
		[]byte(`{"username":"admin","password":"ok","Password":"again"}`),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > maxLoginBodyBytes {
			return
		}
		_, password, _ := decodeLoginRequest(body)
		secret.Wipe(password)
	})
}

func TestBoundedHTTPServerSetsResourceLimits(t *testing.T) {
	server := boundedHTTPServer("127.0.0.1:0", http.NotFoundHandler())
	if server.ReadHeaderTimeout != apiReadHeaderTimeout || server.ReadTimeout != apiReadTimeout || server.WriteTimeout != apiWriteTimeout || server.IdleTimeout != apiIdleTimeout || server.MaxHeaderBytes != apiMaxHeaderBytes {
		t.Fatalf("unexpected server limits: %+v", server)
	}
}

func TestBoundedHTTPServerClosesSlowHeaders(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := boundedHTTPServer("", http.NotFoundHandler())
	server.ReadHeaderTimeout = 20 * time.Millisecond
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.test\r\n"); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	if _, err := conn.Read(buffer); err == nil {
		t.Fatal("slow header remained readable after read-header timeout")
	}
	if err := server.Close(); err != nil && err != http.ErrServerClosed {
		t.Fatal(err)
	}
	if err := <-done; err != nil && err != http.ErrServerClosed {
		t.Fatal(err)
	}
}

func TestAdminPasswordHashHelperReadsOnlyBoundedStdin(t *testing.T) {
	var output bytes.Buffer
	handled, err := runAdminPasswordHashCommand([]string{"hash-admin-password"}, strings.NewReader("installer password\n"), &output)
	if err != nil || !handled {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	hash := strings.TrimSpace(output.String())
	if err := auth.ValidatePasswordHash(hash); err != nil {
		t.Fatalf("helper emitted invalid hash: %v", err)
	}
	verified, err := auth.VerifyPassword([]byte(hash), []byte("installer password"))
	if err != nil || !verified {
		t.Fatalf("helper hash did not verify: verified=%v err=%v", verified, err)
	}
	if handled, err := runAdminPasswordHashCommand([]string{"hash-admin-password"}, bytes.NewReader(bytes.Repeat([]byte{'a'}, maxAdminPasswordBytes+1)), io.Discard); !handled || err == nil {
		t.Fatalf("oversized stdin accepted: handled=%v err=%v", handled, err)
	}
	if handled, err := runAdminPasswordHashCommand([]string{"unknown"}, strings.NewReader("password"), io.Discard); handled || err != nil {
		t.Fatalf("unexpected command routing: handled=%v err=%v", handled, err)
	}
}

func TestLegacyImportCommandDryRunReportsChecksumWithoutSecrets(t *testing.T) {
	state := `{"proxies":{"p1":{"id":"p1","label":"legacy","type":"http","host":"proxy.example","port":8080,"username":"alice","password":"do-not-print","enabled":true,"status":"DOWN"}},"clients":{"c1":{"id":"c1","ip_cidr":"192.0.2.8","enabled":true}},"mappings":{"m1":{"id":"m1","client_id":"c1","proxy_id":"p1","protocol":"http","local_redirect_port":15001,"state":"APPLIED"}}}`
	path := t.TempDir() + string(os.PathSeparator) + "state.json"
	if err := os.WriteFile(path, []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	handled, err := runLegacyImportCommand([]string{"import-legacy-state", "--file", path, "--dry-run"}, &output)
	if err != nil || !handled {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	if bytes.Contains(output.Bytes(), []byte("do-not-print")) {
		t.Fatalf("secret leaked in report: %q", output.String())
	}
	var report struct {
		Checksum string `json:"checksum"`
		DryRun   bool   `json:"dry_run"`
		Proxies  int    `json:"proxies"`
	}
	if err := json.Unmarshal(output.Bytes(), &report); err != nil || report.Checksum == "" || !report.DryRun || report.Proxies != 1 {
		t.Fatalf("report=%q decoded=%+v err=%v", output.String(), report, err)
	}
}

func TestLegacyImportCommandRejectsUnsafeInputAndArguments(t *testing.T) {
	if handled, err := runLegacyImportCommand([]string{"import-legacy-state", "--file", "relative.json", "--dry-run"}, io.Discard); !handled || err == nil {
		t.Fatalf("relative input accepted handled=%v err=%v", handled, err)
	}
	path := t.TempDir() + string(os.PathSeparator) + "state.json"
	if err := os.WriteFile(path, []byte(`{}`), 0o666); err != nil {
		t.Fatal(err)
	}
	if handled, err := runLegacyImportCommand([]string{"import-legacy-state", "--file", path}, io.Discard); !handled || err == nil {
		t.Fatalf("missing real import paths accepted handled=%v err=%v", handled, err)
	}
}
