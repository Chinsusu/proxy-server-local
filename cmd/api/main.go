package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Chinsusu/proxy-server-local/internal/secret"
	"github.com/Chinsusu/proxy-server-local/pkg/auth"
	"github.com/Chinsusu/proxy-server-local/pkg/config"
	"github.com/Chinsusu/proxy-server-local/pkg/httpx"
	"github.com/Chinsusu/proxy-server-local/pkg/observability"
)

// main wires the SQLite-backed control plane and the migration-window v1
// facade. No legacy file store is opened, polled, or used by the API process.
func main() {
	observer := observability.New("pgw-api", os.Stdout)
	if handled, err := runLegacyImportCommand(os.Args[1:], os.Stdout); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, "pgw-api:", redactLegacyImportError(err))
			os.Exit(2)
		}
		return
	}
	if handled, err := runAdminPasswordHashCommand(os.Args[1:], os.Stdin, os.Stdout); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, "pgw-api hash-admin-password:", err)
			os.Exit(2)
		}
		return
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "pgw-api: unsupported arguments")
		os.Exit(2)
	}
	cfg, err := config.LoadAPI()
	if err != nil {
		observer.Logger.Log(context.Background(), "error", "startup_failed", map[string]any{"reason_code": "configuration"})
		os.Exit(1)
	}
	defer zeroBytes(cfg.JWTSecret)
	defer zeroBytes(cfg.AdminPassHash)
	defer zeroBytes(cfg.UIProxyToken)
	uiProxyVerifier, err := httpx.NewProxyIdentityVerifier(cfg.UIProxyToken)
	if err != nil {
		observer.Logger.Log(context.Background(), "error", "startup_failed", map[string]any{"reason_code": "ui_proxy_identity"})
		os.Exit(1)
	}
	defer uiProxyVerifier.Close()
	v2, repository, err := openV2Server(context.Background(), cfg, observer)
	if err != nil {
		observer.Logger.Log(context.Background(), "error", "startup_failed", map[string]any{"reason_code": "control_plane"})
		os.Exit(1)
	}
	defer func() {
		v2.Close()
		_ = repository.Close()
	}()
	stopAgentSocket, err := startAgentSocket(v2)
	if err != nil {
		observer.Logger.Log(context.Background(), "error", "startup_failed", map[string]any{"reason_code": "agent_socket"})
		os.Exit(1)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = stopAgentSocket(ctx)
	}()

	for _, result := range config.ValidateStartup() {
		if result.OK {
			observer.Logger.Log(context.Background(), "info", "startup_check", map[string]any{"outcome": "success"})
		} else {
			observer.Logger.Log(context.Background(), "warn", "startup_check", map[string]any{"outcome": "failure"})
		}
	}

	adminUser := strings.TrimSpace(os.Getenv("PGW_ADMIN_USER"))
	loginRL := httpx.NewLoginRateLimiter(5, 15*time.Minute)
	observer.Metrics.SetMigrationStatus("ready", true)
	if state, stateErr := repository.GetReconcileState(context.Background()); stateErr == nil {
		observer.Metrics.SetAgentState(state.PendingGeneration, state.AppliedGeneration, state.State)
	} else {
		observer.Metrics.ObserveDBError("agent_state_startup")
	}
	http.Handle("/metrics", observer.Metrics.Handler())
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	http.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if _, err := repository.GetReconcileState(r.Context()); err != nil {
			observer.Metrics.ObserveDBError("readiness")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	http.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	http.HandleFunc("/v1/auth/login", newLoginHandlerWithProxyIdentity(adminUser, cfg.AdminPassHash, cfg.JWTSecret, loginRL, uiProxyVerifier))

	server := boundedHTTPServer(cfg.Addr, observer.WrapHTTP(combinedAPIHandler(v2)))
	go func() {
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
		defer signal.Stop(signals)
		<-signals
		observer.Logger.Log(context.Background(), "info", "shutdown_requested", map[string]any{"reason_code": "signal"})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			observer.Logger.Log(context.Background(), "error", "shutdown_failed", map[string]any{"reason_code": "server"})
		}
	}()
	observer.Logger.Log(context.Background(), "info", "server_start", map[string]any{"reason_code": "loopback"})
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		observer.Logger.Log(context.Background(), "error", "server_failed", map[string]any{"reason_code": "listener"})
		os.Exit(1)
	}
}

const maxLoginBodyBytes = 1 << 20
const maxAdminPasswordBytes = 4096

func newLoginHandler(adminUser string, adminPassHash, jwtSecret []byte, loginRL *httpx.LoginRateLimiter) http.HandlerFunc {
	return newLoginHandlerWithProxyIdentity(adminUser, adminPassHash, jwtSecret, loginRL, nil)
}

func newLoginHandlerWithProxyIdentity(adminUser string, adminPassHash, jwtSecret []byte, loginRL *httpx.LoginRateLimiter, proxyVerifier *httpx.ProxyIdentityVerifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ip, err := httpx.CanonicalLoginClientIP(r, proxyVerifier)
		if err != nil {
			observeAuth(r, "failure", "invalid_proxy_identity")
			httpx.JSON(w, http.StatusBadRequest, map[string]string{"error": "invalid proxy identity"})
			return
		}
		reservationRelease, admitted, limited := loginRL.Reserve(ip)
		if !admitted {
			if !limited {
				observeAuth(r, "failure", "verification_inflight")
				httpx.JSON(w, http.StatusServiceUnavailable, map[string]string{"error": "login verification temporarily unavailable"})
				return
			}
			observeAuth(r, "rate_limited", "rate_limited")
			httpx.JSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many login attempts, try again later"})
			return
		}
		defer reservationRelease()
		r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodyBytes)
		defer r.Body.Close()
		body, err := io.ReadAll(r.Body)
		defer secret.Wipe(body)
		if err != nil {
			httpx.JSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
			return
		}
		username, password, err := decodeLoginRequest(body)
		if err != nil {
			httpx.JSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
			return
		}
		defer secret.Wipe(password)
		if adminUser == "" || len(adminPassHash) == 0 {
			httpx.JSON(w, http.StatusServiceUnavailable, map[string]string{"error": "admin not configured"})
			return
		}
		verified, verifyErr := auth.VerifyPasswordBytes(adminPassHash, password)
		if errors.Is(verifyErr, auth.ErrPasswordWorkBusy) {
			observeAuth(r, "failure", "verification_overloaded")
			httpx.JSON(w, http.StatusServiceUnavailable, map[string]string{"error": "login verification temporarily unavailable"})
			return
		}
		if username != adminUser || !verified {
			observeAuth(r, "failure", "invalid_credentials")
			loginRL.RecordFailure(ip)
			httpx.JSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
			return
		}
		loginRL.Reset(ip)
		observeAuth(r, "success", "authenticated")
		token, expiresAt, err := auth.SignJWT(adminUser, "admin", jwtSecret, auth.MaxJWTTTL)
		if err != nil {
			if observer := observability.FromContext(r.Context()); observer != nil {
				observer.Logger.Log(r.Context(), "error", "auth_outcome", map[string]any{"outcome": "failure", "reason_code": "signing_failed"})
			}
			httpx.JSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "pgw_jwt",
			Value:    token,
			Path:     "/",
			Expires:  expiresAt.UTC(),
			MaxAge:   int(auth.MaxJWTTTL.Seconds()),
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		token = ""
		w.WriteHeader(http.StatusNoContent)
	}
}

// decodeLoginRequest keeps the password in mutable bytes end-to-end. The
// decoder is used only for object framing; the password JSON token is decoded
// by secret.DecodeJSONStringBytes rather than into an immutable Go string.
func decodeLoginRequest(body []byte) (string, []byte, error) {
	fields, err := secret.StrictJSONObject(body, []string{"username", "password"})
	if err != nil {
		return "", nil, fmt.Errorf("login request must be an object")
	}
	var username string
	usernameRaw, usernameOK := fields["username"]
	passwordRaw, passwordOK := fields["password"]
	if !usernameOK || !passwordOK {
		return "", nil, fmt.Errorf("invalid login request")
	}
	if err := json.Unmarshal(usernameRaw, &username); err != nil {
		return "", nil, err
	}
	password, err := secret.DecodeJSONStringBytes(passwordRaw)
	transferred := false
	defer func() {
		if !transferred {
			secret.Wipe(password)
		}
	}()
	if err != nil {
		return "", nil, err
	}
	if strings.TrimSpace(username) == "" || len(username) > 256 || len(password) == 0 || len(password) > maxAdminPasswordBytes {
		return "", nil, fmt.Errorf("invalid login request")
	}
	transferred = true
	return username, password, nil
}

func observeAuth(r *http.Request, outcome, reason string) {
	if observer := observability.FromContext(r.Context()); observer != nil {
		observer.Metrics.ObserveAuth(outcome, reason)
		observer.Logger.Log(r.Context(), "info", "auth_outcome", map[string]any{"outcome": outcome, "reason_code": reason})
	}
}

// runAdminPasswordHashCommand implements the installer-only helper command.
// The password is read from bounded stdin, never an environment variable or
// argument. The only stdout output is the resulting Argon2id PHC value.
func runAdminPasswordHashCommand(args []string, input io.Reader, output io.Writer) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	if args[0] != "hash-admin-password" {
		return false, nil
	}
	var password []byte
	var err error
	switch {
	case len(args) == 1:
		password, err = io.ReadAll(io.LimitReader(input, maxAdminPasswordBytes+1))
	case len(args) == 3 && args[1] == "--file":
		password, err = secret.LoadRootOwnedAdminPasswordFile(args[2], maxAdminPasswordBytes)
	default:
		return true, fmt.Errorf("usage: pgw-api hash-admin-password [--file <absolute-path>]")
	}
	defer zeroBytes(password)
	if err != nil {
		return true, fmt.Errorf("read password: %w", err)
	}
	if len(password) > maxAdminPasswordBytes {
		return true, fmt.Errorf("password exceeds %d bytes", maxAdminPasswordBytes)
	}
	if len(password) > 0 && password[len(password)-1] == '\n' {
		password = password[:len(password)-1]
		if len(password) > 0 && password[len(password)-1] == '\r' {
			password = password[:len(password)-1]
		}
	}
	if len(password) == 0 {
		return true, fmt.Errorf("password is empty")
	}
	for _, value := range password {
		if value == 0 {
			return true, fmt.Errorf("password contains NUL")
		}
	}
	hash, err := auth.HashPasswordBytes(password, auth.DefaultParams())
	if err != nil {
		return true, fmt.Errorf("hash password: %w", err)
	}
	if err := auth.ValidatePasswordHash(hash); err != nil {
		return true, fmt.Errorf("validate generated password hash: %w", err)
	}
	if _, err := io.WriteString(output, hash+"\n"); err != nil {
		return true, fmt.Errorf("write password hash: %w", err)
	}
	return true, nil
}

const (
	apiReadHeaderTimeout = 5 * time.Second
	apiReadTimeout       = 15 * time.Second
	apiWriteTimeout      = 30 * time.Second
	apiIdleTimeout       = 60 * time.Second
	apiMaxHeaderBytes    = 16 << 10
)

func boundedHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: apiReadHeaderTimeout,
		ReadTimeout:       apiReadTimeout,
		WriteTimeout:      apiWriteTimeout,
		IdleTimeout:       apiIdleTimeout,
		MaxHeaderBytes:    apiMaxHeaderBytes,
	}
}

// authorizeRequest is intentionally limited to the admin JWT/cookie. The
// Agent service token is accepted only by internal/api on the Unix socket.
func authorizeRequest(r *http.Request, secret []byte) (string, bool) {
	token := bearerOrCookie(r)
	if token == "" {
		return "", false
	}
	claims, err := auth.ParseJWT(token, secret)
	if err != nil {
		return "", false
	}
	return claims.Role, true
}
