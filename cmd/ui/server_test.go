package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Chinsusu/proxy-server-local/pkg/httpx"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func newTestUI(t *testing.T, upstream http.Handler) (*secureUIServer, http.Handler, func()) {
	t.Helper()
	api := httptest.NewServer(upstream)
	base, err := parseAPIBase(api.URL)
	if err != nil {
		api.Close()
		t.Fatalf("parse test API URL: %v", err)
	}
	ui := newSecureUIServer(uiRuntimeConfig{
		Addr:                  "127.0.0.1:0",
		APIBase:               base,
		TrustLoopbackTLSProxy: true,
		ProxyIdentityToken:    bytes.Repeat([]byte("u"), 32),
	})
	return ui, ui.secureIngress(ui.routes()), api.Close
}

func browserRequest(method, target string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, target, body)
	req.Host = "ui.test"
	req.RemoteAddr = "127.0.0.1:40000"
	req.Header.Set("X-Forwarded-Proto", "https")
	// Test proxy contract: the trusted loopback TLS proxy replaces, rather
	// than appends, this value with exactly one canonical client address.
	req.Header.Set("X-Forwarded-For", "192.0.2.10")
	return req
}

func sessionRequest(method, target string, body io.Reader) *http.Request {
	req := browserRequest(method, target, body)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "backend-issued-session"})
	return req
}

func TestAgentRouteIsNotExposed(t *testing.T) {
	_, handler, closeAPI := newTestUI(t, http.NotFoundHandler())
	defer closeAPI()

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, browserRequest(http.MethodGet, "https://ui.test/agent/reconcile", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("agent path status = %d, want 404", response.Code)
	}
}

func TestTLSIngressFailsClosedAndTrustedProxyMustBeLoopback(t *testing.T) {
	_, handler, closeAPI := newTestUI(t, http.NotFoundHandler())
	defer closeAPI()

	plain := httptest.NewRequest(http.MethodGet, "http://ui.test/login", nil)
	plain.RemoteAddr = "198.51.100.10:40000"
	plain.Host = "ui.test"
	plain.Header.Set("X-Forwarded-Proto", "https")
	plainResponse := httptest.NewRecorder()
	handler.ServeHTTP(plainResponse, plain)
	if plainResponse.Code != http.StatusUpgradeRequired {
		t.Fatalf("non-loopback plaintext ingress status = %d, want 426", plainResponse.Code)
	}

	t.Setenv("PGW_UI_ADDR", ":8081")
	t.Setenv("PGW_UI_API", "http://127.0.0.1:8080")
	t.Setenv("PGW_UI_TLS_CERT_FILE", "")
	t.Setenv("PGW_UI_TLS_KEY_FILE", "")
	t.Setenv("PGW_UI_TRUST_LOOPBACK_TLS_PROXY", "")
	if _, err := loadUIRuntimeConfig(); err == nil {
		t.Fatal("plaintext default UI configuration was accepted")
	}

	t.Setenv("PGW_UI_TRUST_LOOPBACK_TLS_PROXY", "1")
	if _, err := loadUIRuntimeConfig(); err == nil {
		t.Fatal("public trusted-proxy listener was accepted")
	}

	t.Setenv("PGW_UI_ADDR", "127.0.0.1:8081")
	if config, err := loadUIRuntimeConfig(); err != nil || !config.TrustLoopbackTLSProxy {
		t.Fatalf("loopback trusted-proxy configuration rejected: config=%#v err=%v", config, err)
	}
	t.Setenv("PGW_UI_METRICS_ADDR", "0.0.0.0:9091")
	if _, err := loadUIRuntimeConfig(); err == nil {
		t.Fatal("public UI metrics listener was accepted")
	}
	t.Setenv("PGW_UI_METRICS_ADDR", "127.0.0.1:9091")
	if config, err := loadUIRuntimeConfig(); err != nil || config.MetricsAddr != "127.0.0.1:9091" {
		t.Fatalf("loopback metrics configuration rejected: config=%#v err=%v", config, err)
	}
}

func TestLoginRelaysOnlyValidatedBackendCookie(t *testing.T) {
	const backendToken = "backend-only-token"
	_, handler, closeAPI := newTestUI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/login" || r.Method != http.MethodPost {
			t.Fatalf("unexpected API request %s %s", r.Method, r.URL.Path)
		}
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    backendToken,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int((12 * time.Hour).Seconds()),
			Expires:  time.Now().UTC().Add(12 * time.Hour),
		})
		w.WriteHeader(http.StatusNoContent)
		_, _ = w.Write([]byte(`{"token":"must never reach the browser"}`))
	}))
	defer closeAPI()

	req := browserRequest(http.MethodPost, "https://ui.test/login", strings.NewReader(`{"username":"admin","password":"correct horse"}`))
	req.Header.Set("Origin", "https://ui.test")
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)

	if response.Code != http.StatusNoContent {
		t.Fatalf("login status = %d, want 204; body=%q", response.Code, response.Body.String())
	}
	if response.Body.Len() != 0 || strings.Contains(response.Body.String(), backendToken) {
		t.Fatalf("login response exposed upstream body: %q", response.Body.String())
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("relayed cookie count = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != sessionCookieName || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" || cookie.MaxAge != int((12*time.Hour).Seconds()) {
		t.Fatalf("unsafe relayed cookie: %#v", cookie)
	}
}

func TestLoginRejectsInsecureOrOversizedInput(t *testing.T) {
	var calls atomic.Int32
	_, handler, closeAPI := newTestUI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "insecure", Path: "/"})
		w.WriteHeader(http.StatusNoContent)
	}))
	defer closeAPI()

	insecure := browserRequest(http.MethodPost, "https://ui.test/login", strings.NewReader(`{"username":"admin","password":"password"}`))
	insecure.Header.Set("Origin", "https://ui.test")
	insecure.Header.Set("Content-Type", "application/json")
	insecureResponse := httptest.NewRecorder()
	handler.ServeHTTP(insecureResponse, insecure)
	if insecureResponse.Code != http.StatusBadGateway {
		t.Fatalf("insecure cookie status = %d, want 502", insecureResponse.Code)
	}

	overflow := strings.Repeat("x", maxLoginBodyBytes+1)
	oversized := browserRequest(http.MethodPost, "https://ui.test/login", strings.NewReader(overflow))
	oversized.Header.Set("Origin", "https://ui.test")
	oversized.Header.Set("Content-Type", "application/json")
	oversizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(oversizedResponse, oversized)
	if oversizedResponse.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized login status = %d, want 413", oversizedResponse.Code)
	}
	if calls.Load() != 1 {
		t.Fatalf("oversized login reached upstream; calls=%d", calls.Load())
	}
}

func TestLoginPasswordByteDecoderEscapesAndRejectsMissingOrNull(t *testing.T) {
	input := []byte(`{"username":"admin","password":"p\u00e4ss\n\uD834\uDD1E"}`)
	username, password, err := decodeLoginRequest(bytes.NewReader(input))
	if err != nil || username != "admin" {
		wipeLoginBytes("password", password)
		t.Fatal("escaped login request was not decoded")
	}
	expected := []byte{'p', 0xc3, 0xa4, 's', 's', '\n', 0xf0, 0x9d, 0x84, 0x9e}
	if !bytes.Equal(password, expected) {
		wipeLoginBytes("password", password)
		t.Fatal("escaped password bytes were not preserved")
	}
	payload, err := marshalLoginPayload(username, password)
	wipeLoginBytes("password", password)
	if err != nil || !bytes.Contains(payload, expected[:5]) || !bytes.Contains(payload, []byte(`\n`)) {
		wipeLoginBytes("upstream-payload", payload)
		t.Fatal("upstream login payload did not preserve escaped password semantics")
	}
	wipeLoginBytes("upstream-payload", payload)

	for _, body := range [][]byte{
		[]byte(`{"username":"admin"}`),
		[]byte(`{"username":"admin","password":null}`),
		[]byte(`{"username":null,"password":"x"}`),
		[]byte(`{"username":"admin","password":"x","password":"y"}`),
	} {
		_, decoded, decodeErr := decodeLoginRequest(bytes.NewReader(body))
		wipeLoginBytes("password", decoded)
		if decodeErr == nil {
			t.Fatal("invalid login JSON was accepted")
		}
	}
}

func TestLoginWipesOwnedBuffersOnSuccessErrorAndCancellation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		observed := observeLoginWipes(t)
		_, handler, closeAPI := newTestUI(t, hardenedLoginUpstream(t))
		defer closeAPI()
		serveLogin(t, handler, context.Background())
		observed.require(t, "request-body", "password-json", "password", "upstream-payload")
	})

	t.Run("upstream-error", func(t *testing.T) {
		observed := observeLoginWipes(t)
		ui, handler, closeAPI := newTestUI(t, http.NotFoundHandler())
		defer closeAPI()
		ui.client = &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("transport unavailable")
		})}
		serveLogin(t, handler, context.Background())
		observed.require(t, "request-body", "password-json", "password", "upstream-payload")
	})

	t.Run("canceled", func(t *testing.T) {
		observed := observeLoginWipes(t)
		ui, handler, closeAPI := newTestUI(t, http.NotFoundHandler())
		defer closeAPI()
		ui.client = &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			return nil, request.Context().Err()
		})}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		serveLogin(t, handler, ctx)
		observed.require(t, "request-body", "password-json", "password", "upstream-payload")
	})
}

func TestLoginChunkedOversizeWipesBufferedBody(t *testing.T) {
	observed := observeLoginWipes(t)
	_, handler, closeAPI := newTestUI(t, http.NotFoundHandler())
	defer closeAPI()
	req := browserRequest(http.MethodPost, "https://ui.test/login", io.NopCloser(strings.NewReader(strings.Repeat("x", maxLoginBodyBytes+1))))
	req.ContentLength = -1
	req.Header.Set("Origin", "https://ui.test")
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked oversized login status = %d, want 413", response.Code)
	}
	observed.require(t, "request-body")
}

func TestLoginByteDecoderIsSafeUnderConcurrentRequests(t *testing.T) {
	const workers = 32
	var group sync.WaitGroup
	errors := make(chan struct{}, workers)
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			_, password, err := decodeLoginRequest(bytes.NewReader([]byte(`{"username":"admin","password":"p\u00e4ss"}`)))
			if err != nil || len(password) == 0 {
				errors <- struct{}{}
				return
			}
			payload, err := marshalLoginPayload("admin", password)
			wipeLoginBytes("password", password)
			wipeLoginBytes("upstream-payload", payload)
			if err != nil {
				errors <- struct{}{}
			}
		}()
	}
	group.Wait()
	close(errors)
	if len(errors) != 0 {
		t.Fatal("concurrent byte-backed login decoding failed")
	}
}

type loginWipeObserver struct {
	mu      sync.Mutex
	seen    map[string]int
	allZero bool
}

func observeLoginWipes(t *testing.T) *loginWipeObserver {
	t.Helper()
	observer := &loginWipeObserver{seen: make(map[string]int), allZero: true}
	restore := setLoginWipeHookForTest(func(kind string, zeroed []byte) {
		observer.mu.Lock()
		defer observer.mu.Unlock()
		observer.seen[kind]++
		for _, value := range zeroed {
			if value != 0 {
				observer.allZero = false
			}
		}
	})
	t.Cleanup(restore)
	return observer
}

func (observer *loginWipeObserver) require(t *testing.T, kinds ...string) {
	t.Helper()
	observer.mu.Lock()
	defer observer.mu.Unlock()
	if !observer.allZero {
		t.Fatal("login wipe hook observed non-zero bytes")
	}
	for _, kind := range kinds {
		if observer.seen[kind] == 0 {
			t.Fatalf("expected login wipe hook for %s", kind)
		}
	}
}

func hardenedLoginUpstream(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    "backend-session",
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int((12 * time.Hour).Seconds()),
			Expires:  time.Now().UTC().Add(12 * time.Hour),
		})
		w.WriteHeader(http.StatusNoContent)
	})
}

func serveLogin(t *testing.T, handler http.Handler, ctx context.Context) {
	t.Helper()
	req := browserRequest(http.MethodPost, "https://ui.test/login", strings.NewReader(`{"username":"admin","password":"password"}`)).WithContext(ctx)
	req.Header.Set("Origin", "https://ui.test")
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
}

func TestAPIMutationsRequireSameOriginAndNeverTrustBrowserBearer(t *testing.T) {
	var calls atomic.Int32
	_, handler, closeAPI := newTestUI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if got := r.Header.Get("Authorization"); got != "Bearer backend-issued-session" {
			t.Fatalf("upstream authorization = %q", got)
		}
		if got := r.Header.Get("Cookie"); got != "" {
			t.Fatalf("browser cookie leaked upstream: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer closeAPI()

	for name, origin := range map[string]string{"missing": "", "cross-site": "https://attacker.test"} {
		t.Run(name, func(t *testing.T) {
			req := sessionRequest(http.MethodPost, "https://ui.test/api/v1/proxies", strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer browser-controlled")
			if origin != "" {
				req.Header.Set("Origin", origin)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", response.Code)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("cross-site mutation reached upstream; calls=%d", calls.Load())
	}

	req := sessionRequest(http.MethodPost, "https://ui.test/api/v1/proxies", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://ui.test")
	req.Header.Set("Authorization", "Bearer browser-controlled")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("same-origin mutation status = %d, want 200; body=%q", response.Code, response.Body.String())
	}
	if calls.Load() != 1 {
		t.Fatalf("same-origin mutation calls=%d, want 1", calls.Load())
	}
}

func TestAPIRejectsOversizedAndBoundedSlowResponses(t *testing.T) {
	var calls atomic.Int32
	ui, handler, closeAPI := newTestUI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Query().Get("mode") == "slow" {
			time.Sleep(100 * time.Millisecond)
			return
		}
		_, _ = w.Write(bytes.Repeat([]byte("x"), maxUpstreamResponseSize+1))
	}))
	defer closeAPI()

	oversizedRequest := sessionRequest(http.MethodPost, "https://ui.test/api/v1/proxies", strings.NewReader(strings.Repeat("x", maxBrowserBodyBytes+1)))
	oversizedRequest.Header.Set("Origin", "https://ui.test")
	oversizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(oversizedResponse, oversizedRequest)
	if oversizedResponse.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized API request status = %d, want 413", oversizedResponse.Code)
	}
	if calls.Load() != 0 {
		t.Fatalf("oversized API request reached upstream; calls=%d", calls.Load())
	}

	largeResponse := sessionRequest(http.MethodGet, "https://ui.test/api/v1/proxies", nil)
	largeResponseRecorder := httptest.NewRecorder()
	handler.ServeHTTP(largeResponseRecorder, largeResponse)
	if largeResponseRecorder.Code != http.StatusBadGateway {
		t.Fatalf("oversized upstream response status = %d, want 502", largeResponseRecorder.Code)
	}

	ui.client.Timeout = 10 * time.Millisecond
	slowResponse := sessionRequest(http.MethodGet, "https://ui.test/api/v1/proxies?mode=slow", nil)
	slowResponseRecorder := httptest.NewRecorder()
	handler.ServeHTTP(slowResponseRecorder, slowResponse)
	if slowResponseRecorder.Code != http.StatusBadGateway {
		t.Fatalf("slow upstream status = %d, want 502", slowResponseRecorder.Code)
	}
}

func TestLogoutAndServerTimeoutsAreHardened(t *testing.T) {
	ui, handler, closeAPI := newTestUI(t, http.NotFoundHandler())
	defer closeAPI()
	server := ui.httpServer()
	if server.ReadHeaderTimeout <= 0 || server.ReadTimeout <= 0 || server.WriteTimeout <= 0 || server.IdleTimeout <= 0 || server.MaxHeaderBytes == 0 {
		t.Fatalf("incomplete HTTP server timeout limits: %#v", server)
	}

	req := sessionRequest(http.MethodPost, "https://ui.test/logout", nil)
	req.Header.Set("Origin", "https://ui.test")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d, want 204", response.Code)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Path != "/" || cookies[0].MaxAge != -1 {
		t.Fatalf("logout did not clear the hardened cookie: %#v", cookies)
	}
}

func TestBrowserBundleDoesNotContainAgentRouteOrTokenStorage(t *testing.T) {
	bundle, err := os.ReadFile("../../web/static/app.js")
	if err != nil {
		t.Fatalf("read browser bundle: %v", err)
	}
	text := string(bundle)
	for _, forbidden := range []string{"'/agent/", "\"/agent/", "agentBase", "reconcileRules", "localStorage.setItem('pgw_jwt'", "sessionStorage", "Authorization", "Bearer "} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("browser bundle contains forbidden auth/control-plane material %q", forbidden)
		}
	}
	if !strings.Contains(text, "credentials: 'same-origin'") {
		t.Fatal("browser bundle does not explicitly use same-origin cookie credentials")
	}
	loginBundle, err := os.ReadFile("../../web/static/login.js")
	if err != nil {
		t.Fatalf("read login bundle: %v", err)
	}
	for _, forbidden := range []string{"localStorage", "sessionStorage", "Authorization", "Bearer ", "token"} {
		if strings.Contains(string(loginBundle), forbidden) || strings.Contains(embeddedLogin, forbidden) {
			t.Fatalf("login browser flow contains forbidden auth material %q", forbidden)
		}
	}
	if !strings.Contains(string(loginBundle), "credentials: 'same-origin'") {
		t.Fatal("login browser flow does not explicitly use same-origin cookies")
	}
}

func TestControlPlaneWorkflowDOMContract(t *testing.T) {
	_, handler, closeAPI := newTestUI(t, http.NotFoundHandler())
	defer closeAPI()

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, sessionRequest(http.MethodGet, "https://ui.test/", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("control-plane page status = %d, want 200", response.Code)
	}
	page := response.Body.String()
	for _, required := range []string{
		"skip-link", "main-content", "mapping-form", "<fieldset>", "<legend", "mapping-client-error",
		"aria-live=\"polite\"", "aria-live=\"assertive\"", "Create DRAFT", "web_only",
		"no direct fallback", "mappings-body", "Desired", "Applied generation", "Data-plane",
		"agent-state-value", "agent-ipv6-policy-value", "agent-lkg-value", "audit-timeline", "audit-more", "proxies-body",
	} {
		if !strings.Contains(page, required) {
			t.Fatalf("embedded v2 workflow is missing %q", required)
		}
	}
}

func TestV2WorkflowBundleContract(t *testing.T) {
	bundle, err := os.ReadFile("../../web/static/app.js")
	if err != nil {
		t.Fatalf("read browser bundle: %v", err)
	}
	text := string(bundle)
	for _, required := range []string{
		"/api/v2", "loadPaged('mappings'", "/agent/state", "/audit-events?limit=50",
		"Idempotency-Key", "If-Match", "normalizeIPv4", "web_only", "No direct fallback",
		"data_plane_state", "control-plane check", "error.status === 409 || error.status === 412",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("v2 browser workflow is missing %q", required)
		}
	}
	for _, forbidden := range []string{"innerHTML", "'/agent/", "\"/agent/", "Authorization", "Bearer ", "localStorage", "sessionStorage"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("v2 browser workflow contains forbidden material %q", forbidden)
		}
	}
}

func TestLoginRateLimitUsesCanonicalPeerAndBoundedEntries(t *testing.T) {
	var upstreamCalls atomic.Int32
	ui, handler, closeAPI := newTestUI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		verifier, err := httpx.NewProxyIdentityVerifier(bytes.Repeat([]byte("u"), 32))
		if err != nil {
			t.Fatal(err)
		}
		defer verifier.Close()
		clientIP, err := httpx.CanonicalLoginClientIP(r, verifier)
		if err != nil || clientIP == "" {
			t.Fatalf("login proxy identity was not authenticated: ip=%q err=%v", clientIP, err)
		}
		for _, forbidden := range []string{"X-Forwarded-For", "Forwarded", "Authorization", "Proxy-Authorization"} {
			if r.Header.Get(forbidden) != "" {
				t.Fatalf("untrusted browser header leaked upstream: %s", forbidden)
			}
		}
		http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "session", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 60, Expires: time.Now().Add(time.Minute)})
		w.WriteHeader(http.StatusNoContent)
	}))
	defer closeAPI()
	ui.limiter = newLoginRateLimiter(2, 2, time.Minute)

	login := func(client string) int {
		req := browserRequest(http.MethodPost, "https://ui.test/login", strings.NewReader(`{"username":"admin","password":"password"}`))
		req.Header.Set("Origin", "https://ui.test")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", client)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response.Code
	}
	if login("198.51.100.1") != http.StatusNoContent || login("198.51.100.1") != http.StatusNoContent || login("198.51.100.1") != http.StatusTooManyRequests {
		t.Fatal("one peer was not rate limited at the configured boundary")
	}
	if login("198.51.100.2") != http.StatusNoContent {
		t.Fatal("attacker A lockout blocked independent peer B")
	}
	if login("198.51.100.3") != http.StatusNoContent {
		t.Fatal("bounded limiter did not admit a new peer after eviction")
	}
	if upstreamCalls.Load() != 4 {
		t.Fatalf("upstream calls = %d, want 4", upstreamCalls.Load())
	}
	if len(ui.limiter.entries) > 2 {
		t.Fatalf("rate limiter exceeded bounded entry count: %d", len(ui.limiter.entries))
	}

	direct := newSecureUIServer(uiRuntimeConfig{TrustLoopbackTLSProxy: false})
	directRequest := httptest.NewRequest(http.MethodPost, "https://ui.test/login", nil)
	directRequest.RemoteAddr = "[::ffff:198.51.100.8]:40000"
	directRequest.Header.Set("X-Forwarded-For", "203.0.113.9")
	canonical, err := direct.browserClientIP(directRequest)
	if err != nil || canonical != netip.MustParseAddr("198.51.100.8") {
		t.Fatalf("spoofed XFF was trusted or IPv4-mapped address not normalized: %v %v", canonical, err)
	}
	ipv6, err := canonicalClientIP("2001:db8::1")
	if err != nil || ipv6.String() != "2001:db8::1" {
		t.Fatalf("IPv6 peer was not canonicalized: %v %v", ipv6, err)
	}
}

func TestBrowserAPIAllowlistRejectsInternalAndEncodedPaths(t *testing.T) {
	var calls atomic.Int32
	ui, handler, closeAPI := newTestUI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer closeAPI()
	for _, target := range []string{
		"https://ui.test/api/metrics", "https://ui.test/api/healthz", "https://ui.test/api/readyz", "https://ui.test/api/internal/agent/v1", "https://ui.test/api/agent/reconcile", "https://ui.test/api/v2/%2e%2e/metrics",
	} {
		req := sessionRequest(http.MethodGet, target, nil)
		response := httptest.NewRecorder()
		ui.handleAPI(response, req)
		if response.Code != http.StatusNotFound {
			t.Fatalf("blocked browser API route %q status = %d, want 404", target, response.Code)
		}
	}
	allowed := sessionRequest(http.MethodGet, "https://ui.test/api/v2/mappings?limit=50", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, allowed)
	if response.Code != http.StatusOK || calls.Load() != 1 {
		t.Fatalf("allowed v2 route was not proxied: status=%d calls=%d", response.Code, calls.Load())
	}
}

func TestCSPAndAssetsAreSelfHosted(t *testing.T) {
	_, handler, closeAPI := newTestUI(t, http.NotFoundHandler())
	defer closeAPI()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, browserRequest(http.MethodGet, "https://ui.test/login", nil))
	csp := response.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "style-src 'self'") || strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "https://") {
		t.Fatalf("CSP is not strict/self-hosted: %q", csp)
	}
	for _, file := range []string{"../../web/static/app.js", "../../web/static/login.js", "../../web/static/styles.css"} {
		contents, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read self-hosted asset %s: %v", file, err)
		}
		if strings.Contains(string(contents), "https://") || strings.Contains(string(contents), "unsafe-inline") {
			t.Fatalf("asset is not self-hosted/CSP safe: %s", file)
		}
	}
	for _, required := range []string{"for=\"login-username\"", "for=\"login-password\"", "/static/login.js"} {
		if !strings.Contains(embeddedLogin, required) {
			t.Fatalf("login accessibility/self-hosted contract missing %q", required)
		}
	}
}
