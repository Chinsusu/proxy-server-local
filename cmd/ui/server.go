package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/Chinsusu/proxy-server-local/internal/secret"
	"github.com/Chinsusu/proxy-server-local/pkg/httpx"
	"github.com/Chinsusu/proxy-server-local/pkg/observability"
)

const (
	sessionCookieName       = "pgw_jwt"
	maxBrowserBodyBytes     = 1 << 20
	maxLoginBodyBytes       = 16 << 10
	maxUpstreamResponseSize = 2 << 20
	maxErrorBodyBytes       = 16 << 10
)

// uiRuntimeConfig has deliberately no JWT signing or verification material.
// The API is the sole authority for a browser session; UI relays its hardened
// cookie over the management TLS boundary and uses it only for its upstream
// authorization header.
type uiRuntimeConfig struct {
	Addr                  string
	APIBase               *url.URL
	WebDir                string
	TLSCertFile           string
	TLSKeyFile            string
	TrustLoopbackTLSProxy bool
	MetricsAddr           string
	ProxyIdentityToken    []byte
}

type secureUIServer struct {
	config   uiRuntimeConfig
	client   *http.Client
	observer *observability.Observer
	limiter  *loginRateLimiter
}

type clientIPContextKey struct{}

// Login secrets live only in owned byte slices. Tests may observe the fact
// that a slice was wiped, but are never given its pre-wipe contents.
var loginWiper = struct {
	sync.Mutex
	hook func(kind string, zeroed []byte)
}{}

func wipeLoginBytes(kind string, value []byte) {
	for index := range value {
		value[index] = 0
	}
	loginWiper.Lock()
	hook := loginWiper.hook
	loginWiper.Unlock()
	if hook != nil {
		hook(kind, value)
	}
}

func setLoginWipeHookForTest(hook func(kind string, zeroed []byte)) func() {
	loginWiper.Lock()
	previous := loginWiper.hook
	loginWiper.hook = hook
	loginWiper.Unlock()
	return func() {
		loginWiper.Lock()
		loginWiper.hook = previous
		loginWiper.Unlock()
	}
}

func runSecureUI() {
	observer := observability.New("pgw-ui", os.Stdout)
	configuration, err := loadUIRuntimeConfig()
	if err != nil {
		observer.Logger.Log(context.Background(), "error", "startup_failed", map[string]any{"reason_code": "configuration"})
		os.Exit(1)
	}
	proxyIdentityToken, err := loadUIProxyIdentityToken()
	if err != nil {
		observer.Logger.Log(context.Background(), "error", "startup_failed", map[string]any{"reason_code": "ui_proxy_credential"})
		os.Exit(1)
	}
	configuration.ProxyIdentityToken = proxyIdentityToken

	ui := newSecureUIServer(configuration)
	ui.observer = observer
	server := ui.httpServer()
	metricsListener, err := observability.ListenLoopback(configuration.MetricsAddr)
	if err != nil {
		observer.Logger.Log(context.Background(), "error", "startup_failed", map[string]any{"reason_code": "metrics_listener"})
		os.Exit(1)
	}
	metricsServer := &http.Server{Handler: observer.Metrics.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
	go func() {
		if err := metricsServer.Serve(metricsListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			observer.Logger.Log(context.Background(), "error", "metrics_server_error", map[string]any{"error_code": "listen_failed"})
		}
	}()
	go shutdownOnSignal(server, metricsServer)

	if configuration.TrustLoopbackTLSProxy {
		observer.Logger.Log(context.Background(), "info", "server_start", map[string]any{"reason_code": "trusted_loopback_tls_proxy"})
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			observer.Logger.Log(context.Background(), "error", "server_failed", map[string]any{"reason_code": "listener"})
			os.Exit(1)
		}
		return
	}

	observer.Logger.Log(context.Background(), "info", "server_start", map[string]any{"reason_code": "tls"})
	if err := server.ListenAndServeTLS(configuration.TLSCertFile, configuration.TLSKeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
		observer.Logger.Log(context.Background(), "error", "server_failed", map[string]any{"reason_code": "tls_listener"})
		os.Exit(1)
	}
}

func loadUIProxyIdentityToken() ([]byte, error) {
	directory := strings.TrimSpace(os.Getenv("CREDENTIALS_DIRECTORY"))
	if directory == "" || (!filepath.IsAbs(directory) && !path.IsAbs(directory)) {
		return nil, errors.New("CREDENTIALS_DIRECTORY is required for ui_proxy_token")
	}
	token, err := secret.LoadTokenFile(filepath.Join(directory, "ui_proxy_token"))
	if err != nil {
		return nil, fmt.Errorf("load ui_proxy_token: %w", err)
	}
	if len(token) < 32 {
		wipeLoginBytes("ui-proxy-token", token)
		return nil, errors.New("ui_proxy_token must be at least 32 bytes")
	}
	return token, nil
}

func shutdownOnSignal(servers ...*http.Server) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	<-signals
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, server := range servers {
		if server == nil {
			continue
		}
		_ = server.Shutdown(ctx)
	}
}

func loadUIRuntimeConfig() (uiRuntimeConfig, error) {
	addr := strings.TrimSpace(os.Getenv("PGW_UI_ADDR"))
	if addr == "" {
		addr = ":8081"
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return uiRuntimeConfig{}, fmt.Errorf("PGW_UI_ADDR must be host:port: %w", err)
	}

	apiBase, err := parseAPIBase(os.Getenv("PGW_UI_API"))
	if err != nil {
		return uiRuntimeConfig{}, err
	}

	certFile := strings.TrimSpace(os.Getenv("PGW_UI_TLS_CERT_FILE"))
	keyFile := strings.TrimSpace(os.Getenv("PGW_UI_TLS_KEY_FILE"))
	proxyMode := strings.TrimSpace(os.Getenv("PGW_UI_TRUST_LOOPBACK_TLS_PROXY")) == "1"
	if (certFile == "") != (keyFile == "") {
		return uiRuntimeConfig{}, errors.New("PGW_UI_TLS_CERT_FILE and PGW_UI_TLS_KEY_FILE must be set together")
	}
	if certFile == "" && !proxyMode {
		return uiRuntimeConfig{}, errors.New("refusing plaintext browser ingress: configure TLS cert/key or PGW_UI_TRUST_LOOPBACK_TLS_PROXY=1")
	}
	if certFile != "" && proxyMode {
		return uiRuntimeConfig{}, errors.New("choose direct TLS or trusted loopback proxy mode, not both")
	}
	if certFile != "" {
		if err := validateTLSFiles(certFile, keyFile); err != nil {
			return uiRuntimeConfig{}, err
		}
	}
	if proxyMode && !isLoopbackListenAddress(addr) {
		return uiRuntimeConfig{}, errors.New("trusted TLS proxy mode requires PGW_UI_ADDR bound to loopback")
	}
	metricsAddr := strings.TrimSpace(os.Getenv("PGW_UI_METRICS_ADDR"))
	if metricsAddr == "" {
		metricsAddr = "127.0.0.1:9091"
	}
	if err := observability.ValidateLoopbackAddress(metricsAddr); err != nil {
		return uiRuntimeConfig{}, fmt.Errorf("PGW_UI_METRICS_ADDR: %w", err)
	}

	return uiRuntimeConfig{
		Addr:                  addr,
		APIBase:               apiBase,
		WebDir:                configuredWebDir(),
		TLSCertFile:           certFile,
		TLSKeyFile:            keyFile,
		TrustLoopbackTLSProxy: proxyMode,
		MetricsAddr:           metricsAddr,
	}, nil
}

func parseAPIBase(value string) (*url.URL, error) {
	if strings.TrimSpace(value) == "" {
		value = "http://127.0.0.1:8080"
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("PGW_UI_API must be an absolute http(s) URL without credentials, query, or fragment")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("PGW_UI_API must use http or https")
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return nil, errors.New("plaintext PGW_UI_API is permitted only for a loopback API listener")
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	return u, nil
}

func validateTLSFiles(certFile, keyFile string) error {
	for label, file := range map[string]string{"certificate": certFile, "private key": keyFile} {
		if !filepath.IsAbs(file) {
			return fmt.Errorf("TLS %s path must be absolute", label)
		}
		info, err := os.Lstat(file)
		if err != nil {
			return fmt.Errorf("stat TLS %s: %w", label, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("TLS %s must be a regular, non-symlink file", label)
		}
		if label == "private key" && info.Mode().Perm()&0o077 != 0 {
			return errors.New("TLS private key must not be group- or world-accessible")
		}
	}
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return fmt.Errorf("load TLS certificate/key: %w", err)
	}
	return nil
}

func configuredWebDir() string {
	if configured := strings.TrimSpace(os.Getenv("PGW_UI_WEB_DIR")); configured != "" {
		if filepath.IsAbs(configured) {
			if info, err := os.Stat(configured); err == nil && info.IsDir() {
				return configured
			}
		}
		return ""
	}
	for _, candidate := range []string{
		"/usr/local/share/pgw/web",
		"/opt/proxy-server-local/web",
		filepath.Join(getCurrentDir(), "web"),
	} {
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
	}
	return ""
}

func isLoopbackListenAddress(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return isLoopbackHost(strings.Trim(host, "[]"))
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func newSecureUIServer(configuration uiRuntimeConfig) *secureUIServer {
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return &secureUIServer{
		config:   configuration,
		observer: observability.NewDiscard("pgw-ui"),
		limiter:  newLoginRateLimiter(defaultLoginLimitEntries, defaultLoginLimitAttempts, defaultLoginLimitWindow),
		client: &http.Client{
			Transport: transport,
			Timeout:   20 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (s *secureUIServer) httpServer() *http.Server {
	return &http.Server{
		Addr:              s.config.Addr,
		Handler:           s.observer.WrapHTTP(s.secureIngress(s.routes())),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

func (s *secureUIServer) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/manage", s.handleManage)
	mux.HandleFunc("/proxies", s.handleProxies)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)
	mux.HandleFunc("/static/", s.handleStatic)
	mux.HandleFunc("/api/", s.handleAPI)
	return mux
}

func (s *secureUIServer) secureIngress(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.isTLSRequest(r) {
			http.Error(w, "TLS is required", http.StatusUpgradeRequired)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/login" {
			clientIP, err := s.browserClientIP(r)
			if err != nil {
				http.Error(w, "trusted proxy client address is invalid", http.StatusBadRequest)
				return
			}
			allowed, retryAfter := s.limiter.allow(clientIP)
			if !allowed {
				w.Header().Set("Retry-After", fmt.Sprintf("%d", max(1, int(retryAfter.Seconds()))))
				http.Error(w, "too many login attempts", http.StatusTooManyRequests)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), clientIPContextKey{}, clientIP))
		}
		stripClientProxyHeaders(r.Header)
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; form-action 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'")
		next.ServeHTTP(w, r)
	})
}

func (s *secureUIServer) browserClientIP(r *http.Request) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, err
	}
	if !s.config.TrustLoopbackTLSProxy {
		return canonicalClientIP(host)
	}
	// The only trusted-proxy contract is an exact, single X-Forwarded-For
	// address written by the loopback TLS proxy. It must replace rather than
	// append client input; comma chains are rejected instead of guessed at.
	if !isLoopbackHost(host) {
		return netip.Addr{}, errors.New("trusted proxy is not loopback")
	}
	forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if forwarded == "" || strings.Contains(forwarded, ",") {
		return netip.Addr{}, errors.New("trusted proxy must supply one client IP")
	}
	return canonicalClientIP(forwarded)
}

func canonicalClientIP(value string) (netip.Addr, error) {
	address, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(value), "[]"))
	if err != nil || !address.IsValid() || address.IsUnspecified() || address.Zone() != "" {
		return netip.Addr{}, errors.New("invalid client IP")
	}
	return address.Unmap(), nil
}

func clientIPFromContext(ctx context.Context) (netip.Addr, bool) {
	address, ok := ctx.Value(clientIPContextKey{}).(netip.Addr)
	return address, ok && address.IsValid()
}

func stripClientProxyHeaders(headers http.Header) {
	for header := range headers {
		canonical := strings.ToLower(header)
		if canonical == "forwarded" || canonical == "authorization" || canonical == "proxy-authorization" || strings.HasPrefix(canonical, "x-forwarded-") || strings.HasPrefix(canonical, "x-pgw-") || canonical == "x-real-ip" {
			headers.Del(header)
		}
	}
}

func (s *secureUIServer) isTLSRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if !s.config.TrustLoopbackTLSProxy || !remoteIsLoopback(r.RemoteAddr) {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

func remoteIsLoopback(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return false
	}
	return isLoopbackHost(host)
}

func (s *secureUIServer) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, http.MethodGet, http.MethodHead)
		return
	}
	if !sessionPresent(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.serveHTML(w, r, "dashboard.html")
}

func (s *secureUIServer) handleManage(w http.ResponseWriter, r *http.Request) {
	s.handleProtectedPage(w, r, "manage.html")
}

func (s *secureUIServer) handleProxies(w http.ResponseWriter, r *http.Request) {
	s.handleProtectedPage(w, r, "proxies.html")
}

func (s *secureUIServer) handleProtectedPage(w http.ResponseWriter, r *http.Request, file string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, http.MethodGet, http.MethodHead)
		return
	}
	if !sessionPresent(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.serveHTML(w, r, file)
}

func (s *secureUIServer) handleStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, http.MethodGet, http.MethodHead)
		return
	}
	relative := strings.TrimPrefix(r.URL.Path, "/static/")
	if relative == "" || !fs.ValidPath(relative) {
		http.NotFound(w, r)
		return
	}
	if s.config.WebDir == "" {
		http.Error(w, "static assets unavailable", http.StatusServiceUnavailable)
		return
	}
	root := filepath.Join(s.config.WebDir, "static")
	fullPath := filepath.Join(root, filepath.FromSlash(relative))
	if !isWithin(root, fullPath) {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, fullPath)
}

func (s *secureUIServer) serveHTML(w http.ResponseWriter, r *http.Request, filename string) {
	if s.config.WebDir != "" {
		fullPath := filepath.Join(s.config.WebDir, filename)
		if isWithin(s.config.WebDir, fullPath) {
			if info, err := os.Stat(fullPath); err == nil && info.Mode().IsRegular() {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				http.ServeFile(w, r, fullPath)
				return
			}
		}
	}
	s.serveEmbeddedHTML(w, filename)
}

func isWithin(root, candidate string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func (s *secureUIServer) serveEmbeddedHTML(w http.ResponseWriter, filename string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	switch filename {
	case "dashboard.html", "manage.html", "proxies.html":
		// The v2 control-plane view is one coherent workflow. Keeping the
		// historical paths as aliases avoids a stale page exposing v1 actions.
		_, _ = io.WriteString(w, embeddedControlPlane)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (s *secureUIServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, embeddedLogin)
		return
	case http.MethodPost:
		if !s.sameOrigin(r) {
			http.Error(w, "invalid request origin", http.StatusForbidden)
			return
		}
		if !isJSONContentType(r.Header.Get("Content-Type")) {
			http.Error(w, "content type must be application/json", http.StatusUnsupportedMediaType)
			return
		}
		s.login(w, r)
		return
	default:
		methodNotAllowed(w, http.MethodGet, http.MethodHead, http.MethodPost)
		return
	}
}

func (s *secureUIServer) login(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > maxLoginBodyBytes {
		_ = r.Body.Close()
		http.Error(w, "login request too large", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodyBytes)
	defer r.Body.Close()
	username, password, err := decodeLoginRequest(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "login request too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid login request", http.StatusBadRequest)
		return
	}
	defer wipeLoginBytes("password", password)
	payload, err := marshalLoginPayload(username, password)
	if err != nil {
		http.Error(w, "invalid login request", http.StatusBadRequest)
		return
	}
	defer wipeLoginBytes("upstream-payload", payload)
	target := s.apiURL("v1/auth/login", "")
	request, err := http.NewRequestWithContext(r.Context(), http.MethodPost, target.String(), bytes.NewReader(payload))
	if err != nil {
		http.Error(w, "login unavailable", http.StatusBadGateway)
		return
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	clientIP, ok := clientIPFromContext(r.Context())
	if !ok {
		http.Error(w, "login unavailable", http.StatusBadGateway)
		return
	}
	nonce, err := httpx.NewProxyNonce()
	if err != nil {
		http.Error(w, "login unavailable", http.StatusBadGateway)
		return
	}
	identity, err := httpx.SignProxyIdentity(s.config.ProxyIdentityToken, clientIP, time.Now().UTC(), nonce)
	if err != nil {
		http.Error(w, "login unavailable", http.StatusBadGateway)
		return
	}
	for header, values := range identity {
		request.Header[header] = append([]string(nil), values...)
	}
	response, err := s.client.Do(request)
	if err != nil {
		http.Error(w, "login unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxErrorBodyBytes))
	if response.StatusCode == http.StatusUnauthorized {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if response.StatusCode != http.StatusNoContent {
		http.Error(w, "login unavailable", http.StatusBadGateway)
		return
	}
	cookie, err := validatedSessionCookie(response)
	if err != nil {
		s.observer.Logger.Log(r.Context(), "warn", "auth_outcome", map[string]any{"outcome": "failure", "reason_code": "invalid_upstream_cookie"})
		http.Error(w, "login unavailable", http.StatusBadGateway)
		return
	}
	http.SetCookie(w, cookie)
	w.WriteHeader(http.StatusNoContent)
}

// decodeLoginRequest keeps the password in mutable bytes end-to-end. The
// standard decoder converts JSON strings to immutable Go strings, which would
// make password lifetime uncontrollable. We use the decoder only for object
// framing and raw values, then decode the password string ourselves.
func decodeLoginRequest(reader io.Reader) (string, []byte, error) {
	input, err := io.ReadAll(io.LimitReader(reader, maxLoginBodyBytes+1))
	defer wipeLoginBytes("request-body", input)
	if err != nil {
		return "", nil, err
	}
	if len(input) > maxLoginBodyBytes {
		return "", nil, errors.New("login request exceeds limit")
	}

	decoder := json.NewDecoder(bytes.NewReader(input))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return "", nil, errors.New("login request must be an object")
	}
	seen := make(map[string]struct{}, 2)
	usernamePresent := false
	passwordPresent := false
	username := ""
	var password []byte
	transferredPassword := false
	defer func() {
		if !transferredPassword {
			wipeLoginBytes("password", password)
		}
	}()
	for decoder.More() {
		keyToken, tokenErr := decoder.Token()
		if tokenErr != nil {
			return "", nil, tokenErr
		}
		key, ok := keyToken.(string)
		if !ok {
			return "", nil, errors.New("login request key is not a string")
		}
		if _, duplicate := seen[key]; duplicate {
			return "", nil, errors.New("duplicate login request member")
		}
		seen[key] = struct{}{}

		var raw json.RawMessage
		if decodeErr := decoder.Decode(&raw); decodeErr != nil {
			return "", nil, decodeErr
		}
		switch key {
		case "username":
			usernamePresent = true
			if decodeErr := json.Unmarshal(raw, &username); decodeErr != nil {
				wipeLoginBytes("username-json", raw)
				return "", nil, decodeErr
			}
			wipeLoginBytes("username-json", raw)
		case "password":
			passwordPresent = true
			password, err = decodeJSONStringBytes(raw)
			wipeLoginBytes("password-json", raw)
			if err != nil {
				return "", nil, err
			}
		default:
			wipeLoginBytes("unknown-login-json", raw)
			return "", nil, errors.New("unknown login request member")
		}
	}
	if closing, closeErr := decoder.Token(); closeErr != nil || closing != json.Delim('}') {
		return "", nil, errors.New("unterminated login request")
	}
	var trailing any
	if trailingErr := decoder.Decode(&trailing); trailingErr != io.EOF {
		return "", nil, errors.New("trailing login request data")
	}
	if !usernamePresent || !passwordPresent || strings.TrimSpace(username) == "" || len(username) > 256 || len(password) == 0 || len(password) > 4096 {
		return "", nil, errors.New("invalid login request")
	}
	transferredPassword = true
	return username, password, nil
}

// decodeJSONStringBytes parses one JSON string without materializing its value
// as a Go string. It rejects null and invalid/lone UTF-16 surrogate sequences.
func decodeJSONStringBytes(raw []byte) ([]byte, error) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil, errors.New("value must be a JSON string")
	}
	decoded := make([]byte, 0, len(raw)-2)
	for index := 1; index < len(raw)-1; index++ {
		value := raw[index]
		if value < 0x20 {
			wipeLoginBytes("password", decoded)
			return nil, errors.New("control character in JSON string")
		}
		if value != '\\' {
			decoded = append(decoded, value)
			continue
		}
		index++
		if index >= len(raw)-1 {
			wipeLoginBytes("password", decoded)
			return nil, errors.New("unterminated JSON escape")
		}
		switch escaped := raw[index]; escaped {
		case '"', '\\', '/':
			decoded = append(decoded, escaped)
		case 'b':
			decoded = append(decoded, '\b')
		case 'f':
			decoded = append(decoded, '\f')
		case 'n':
			decoded = append(decoded, '\n')
		case 'r':
			decoded = append(decoded, '\r')
		case 't':
			decoded = append(decoded, '\t')
		case 'u':
			if index+4 >= len(raw)-1 {
				wipeLoginBytes("password", decoded)
				return nil, errors.New("short unicode escape")
			}
			codePoint, ok := hexCodePoint(raw[index+1 : index+5])
			if !ok {
				wipeLoginBytes("password", decoded)
				return nil, errors.New("invalid unicode escape")
			}
			index += 4
			if codePoint >= 0xD800 && codePoint <= 0xDBFF {
				if index+6 >= len(raw)-1 || raw[index+1] != '\\' || raw[index+2] != 'u' {
					wipeLoginBytes("password", decoded)
					return nil, errors.New("unpaired high surrogate")
				}
				low, valid := hexCodePoint(raw[index+3 : index+7])
				if !valid || low < 0xDC00 || low > 0xDFFF {
					wipeLoginBytes("password", decoded)
					return nil, errors.New("invalid low surrogate")
				}
				codePoint = 0x10000 + ((codePoint - 0xD800) << 10) + (low - 0xDC00)
				index += 6
			} else if codePoint >= 0xDC00 && codePoint <= 0xDFFF {
				wipeLoginBytes("password", decoded)
				return nil, errors.New("unpaired low surrogate")
			}
			decoded = utf8.AppendRune(decoded, rune(codePoint))
		default:
			wipeLoginBytes("password", decoded)
			return nil, errors.New("invalid JSON escape")
		}
	}
	if !utf8.Valid(decoded) {
		wipeLoginBytes("password", decoded)
		return nil, errors.New("invalid UTF-8 JSON string")
	}
	return decoded, nil
}

func hexCodePoint(value []byte) (rune, bool) {
	if len(value) != 4 {
		return 0, false
	}
	var result rune
	for _, digit := range value {
		result <<= 4
		switch {
		case digit >= '0' && digit <= '9':
			result += rune(digit - '0')
		case digit >= 'a' && digit <= 'f':
			result += rune(digit-'a') + 10
		case digit >= 'A' && digit <= 'F':
			result += rune(digit-'A') + 10
		default:
			return 0, false
		}
	}
	return result, true
}

func marshalLoginPayload(username string, password []byte) ([]byte, error) {
	if !utf8.Valid(password) {
		return nil, errors.New("password must be valid UTF-8")
	}
	encodedUsername, err := json.Marshal(username)
	if err != nil {
		return nil, err
	}
	payload := make([]byte, 0, len(encodedUsername)+len(password)+32)
	payload = append(payload, `{"username":`...)
	payload = append(payload, encodedUsername...)
	payload = append(payload, `,"password":`...)
	payload = appendJSONString(payload, password)
	payload = append(payload, '}')
	return payload, nil
}

func appendJSONString(destination, value []byte) []byte {
	destination = append(destination, '"')
	for _, character := range value {
		switch character {
		case '"', '\\':
			destination = append(destination, '\\', character)
		case '\b':
			destination = append(destination, '\\', 'b')
		case '\f':
			destination = append(destination, '\\', 'f')
		case '\n':
			destination = append(destination, '\\', 'n')
		case '\r':
			destination = append(destination, '\\', 'r')
		case '\t':
			destination = append(destination, '\\', 't')
		default:
			if character < 0x20 {
				destination = append(destination, '\\', 'u', '0', '0', "0123456789abcdef"[character>>4], "0123456789abcdef"[character&0x0f])
			} else {
				destination = append(destination, character)
			}
		}
	}
	return append(destination, '"')
}

func validatedSessionCookie(response *http.Response) (*http.Cookie, error) {
	values := response.Header.Values("Set-Cookie")
	if len(values) != 1 {
		return nil, errors.New("expected exactly one session cookie")
	}
	cookies := response.Cookies()
	if len(cookies) != 1 {
		return nil, errors.New("malformed session cookie")
	}
	cookie := cookies[0]
	if cookie.Name != sessionCookieName || cookie.Value == "" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" {
		return nil, errors.New("session cookie misses required security attributes")
	}
	if cookie.MaxAge <= 0 || cookie.MaxAge > int((12*time.Hour).Seconds()) || cookie.Expires.IsZero() || !cookie.Expires.After(time.Now().UTC()) || cookie.Expires.After(time.Now().UTC().Add(12*time.Hour+time.Minute)) {
		return nil, errors.New("session cookie expiry is outside the allowed window")
	}
	return cookie, nil
}

func (s *secureUIServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if !s.sameOrigin(r) {
		http.Error(w, "invalid request origin", http.StatusForbidden)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(1, 0).UTC(),
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *secureUIServer) handleAPI(w http.ResponseWriter, r *http.Request) {
	if !isAllowedBrowserAPIRequest(r) {
		http.NotFound(w, r)
		return
	}
	if !sessionPresent(r) {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	if isStateChanging(r.Method) && !s.sameOrigin(r) {
		http.Error(w, "invalid request origin", http.StatusForbidden)
		return
	}
	if r.ContentLength > maxBrowserBodyBytes {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBrowserBodyBytes)
	defer r.Body.Close()

	relative := strings.TrimPrefix(r.URL.Path, "/api/")
	if relative == "" || !fs.ValidPath(relative) {
		http.NotFound(w, r)
		return
	}
	target := s.apiURL(relative, r.URL.RawQuery)
	request, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), r.Body)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	copySafeRequestHeaders(request.Header, r.Header)
	if cookie, err := r.Cookie(sessionCookieName); err == nil && cookie.Value != "" {
		request.Header.Set("Authorization", "Bearer "+cookie.Value)
	}

	response, err := s.client.Do(request)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	if response.ContentLength > maxUpstreamResponseSize {
		http.Error(w, "upstream response too large", http.StatusBadGateway)
		return
	}
	body, err := readBounded(response.Body, maxUpstreamResponseSize)
	if err != nil {
		http.Error(w, "upstream response invalid", http.StatusBadGateway)
		return
	}
	copySafeResponseHeaders(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(body)
}

// isAllowedBrowserAPIRequest is intentionally a route/method allowlist rather
// than a prefix check. Browser traffic has no reason to reach metrics,
// readiness, Agent/internal endpoints, or undocumented API mutations through
// the UI proxy. Encoded paths are refused to avoid different normalization at
// the UI and API layers.
func isAllowedBrowserAPIRequest(r *http.Request) bool {
	if r.URL.RawPath != "" || strings.Contains(strings.ToLower(r.URL.EscapedPath()), "%") || !strings.HasPrefix(r.URL.Path, "/api/") {
		return false
	}
	relative := strings.TrimPrefix(r.URL.Path, "/api/")
	if relative == "" || strings.Contains(relative, "//") {
		return false
	}
	parts := strings.Split(relative, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	method := r.Method
	if len(parts) >= 2 && parts[0] == "v2" {
		switch {
		case len(parts) == 2 && (parts[1] == "proxies" || parts[1] == "clients" || parts[1] == "egress-policies"):
			return method == http.MethodGet || (parts[1] == "clients" && method == http.MethodPost)
		case len(parts) == 2 && parts[1] == "mappings":
			return method == http.MethodGet || method == http.MethodPost
		case len(parts) == 2 && parts[1] == "audit-events":
			return method == http.MethodGet
		case len(parts) == 3 && parts[1] == "agent" && parts[2] == "state":
			return method == http.MethodGet
		case len(parts) == 3 && parts[1] == "mappings" && validBrowserID(parts[2]):
			return method == http.MethodGet || method == http.MethodDelete
		case len(parts) == 4 && parts[1] == "mappings" && validBrowserID(parts[2]) && (parts[3] == "activate" || parts[3] == "suspend"):
			return method == http.MethodPost
		default:
			return false
		}
	}
	if len(parts) >= 2 && parts[0] == "v1" {
		switch {
		case len(parts) == 2 && (parts[1] == "proxies" || parts[1] == "clients" || parts[1] == "mappings"):
			return method == http.MethodGet || method == http.MethodPost
		case len(parts) == 3 && parts[1] == "mappings" && parts[2] == "active":
			return method == http.MethodGet
		case len(parts) == 3 && (parts[1] == "proxies" || parts[1] == "clients" || parts[1] == "mappings") && validBrowserID(parts[2]):
			return method == http.MethodGet || method == http.MethodDelete
		case len(parts) == 4 && parts[1] == "proxies" && validBrowserID(parts[2]) && parts[3] == "check":
			return method == http.MethodPost
		default:
			return false
		}
	}
	return false
}

func validBrowserID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func (s *secureUIServer) apiURL(relative, query string) *url.URL {
	target := *s.config.APIBase
	target.Path = path.Join(s.config.APIBase.Path, "/", relative)
	target.RawPath = ""
	target.RawQuery = query
	return &target
}

func copySafeRequestHeaders(destination, source http.Header) {
	for _, header := range []string{"Accept", "Content-Type", "If-Match", "Idempotency-Key", "X-Request-ID"} {
		if values := source.Values(header); len(values) > 0 {
			destination[header] = append([]string(nil), values...)
		}
	}
}

func copySafeResponseHeaders(destination, source http.Header) {
	for _, header := range []string{"Content-Type", "Cache-Control", "ETag", "Location", "Retry-After", "X-Request-ID"} {
		if values := source.Values(header); len(values) > 0 {
			destination[header] = append([]string(nil), values...)
		}
	}
}

func readBounded(reader io.Reader, maximum int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maximum {
		return nil, errors.New("body exceeds limit")
	}
	return body, nil
}

func sessionPresent(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	return err == nil && cookie.Value != ""
}

func (s *secureUIServer) sameOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" || strings.Contains(origin, ",") {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	return strings.EqualFold(parsed.Host, r.Host)
}

func isStateChanging(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return false
	default:
		return true
	}
}

func isJSONContentType(contentType string) bool {
	mediaType := strings.TrimSpace(strings.Split(contentType, ";")[0])
	return strings.EqualFold(mediaType, "application/json")
}

func methodNotAllowed(w http.ResponseWriter, methods ...string) {
	w.Header().Set("Allow", strings.Join(methods, ", "))
	w.WriteHeader(http.StatusMethodNotAllowed)
}
