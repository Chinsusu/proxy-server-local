package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	internalapi "github.com/Chinsusu/proxy-server-local/internal/api"
	"github.com/Chinsusu/proxy-server-local/internal/application"
	"github.com/Chinsusu/proxy-server-local/internal/persistence/sqlite"
	"github.com/Chinsusu/proxy-server-local/internal/secret"
	"github.com/Chinsusu/proxy-server-local/pkg/auth"
	"github.com/Chinsusu/proxy-server-local/pkg/config"
	"github.com/Chinsusu/proxy-server-local/pkg/observability"
)

const (
	defaultDatabasePath    = "/var/lib/pgw/pgw.db"
	defaultAgentTokenPath  = "/etc/pgw/agent.token"
	defaultAgentSocketPath = "/run/pgw/api-agent.sock"
)

// openV2Server constructs the production control plane. No handler in this
// package is given authority to execute systemctl or nft; it only persists
// desired state for the separately privileged Agent.
func openV2Server(ctx context.Context, cfg config.API, observer *observability.Observer) (*internalapi.Server, *sqlite.Repository, error) {
	databasePath := strings.TrimSpace(os.Getenv("PGW_DATABASE_PATH"))
	if databasePath == "" {
		databasePath = defaultDatabasePath
	}
	keyPath := strings.TrimSpace(os.Getenv("PGW_SECRETS_KEY_PATH"))
	if keyPath == "" {
		keyPath = secret.DefaultKeyPath
	}
	agentTokenPath := strings.TrimSpace(os.Getenv("PGW_AGENT_TOKEN_FILE"))
	if agentTokenPath == "" {
		if credentialsDirectory := strings.TrimSpace(os.Getenv("CREDENTIALS_DIRECTORY")); credentialsDirectory != "" {
			agentTokenPath = filepath.Join(credentialsDirectory, "agent_service_token")
		}
	}
	if agentTokenPath == "" {
		agentTokenPath = defaultAgentTokenPath
	}
	agentToken, err := secret.LoadTokenFile(agentTokenPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load agent service token: %w", err)
	}
	repository, err := sqlite.Open(ctx, sqlite.Config{Path: databasePath, KeyProvider: secret.FileKeyProvider{Path: keyPath}, IPv6Policy: cfg.IPv6Policy})
	if err != nil {
		zeroBytes(agentToken)
		return nil, nil, err
	}
	server, err := internalapi.New(internalapi.Config{
		Service:    application.New(repository),
		AgentToken: agentToken,
		// The UDS listener is enabled by the deployment unit. Keeping the
		// TCP listener closed to internal paths is enforced by this handler and
		// its listener wiring in the Agent/API deployment follow-up.
		RequireAgentUDS: true,
		Observer:        observer,
		AdminAuth: func(r *http.Request) (string, bool) {
			role, ok := authorizeRequest(r, cfg.JWTSecret)
			if !ok || role != "admin" {
				return "", false
			}
			claims, err := auth.ParseJWT(bearerOrCookie(r), cfg.JWTSecret)
			if err != nil || claims.Subject == "" {
				return "admin", true
			}
			return claims.Subject, true
		},
	})
	zeroBytes(agentToken)
	if err != nil {
		_ = repository.Close()
		return nil, nil, err
	}
	return server, repository, nil
}

func bearerOrCookie(r *http.Request) string {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(h) >= 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	if cookie, err := r.Cookie("pgw_jwt"); err == nil {
		return cookie.Value
	}
	return ""
}

func combinedAPIHandler(v2 *internalapi.Server) http.Handler {
	legacy := http.DefaultServeMux
	v1 := v2.LegacyV1Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v2/") || strings.HasPrefix(r.URL.Path, "/internal/agent/") {
			v2.ServeHTTP(w, r)
			return
		}
		if internalapi.IsV1ControlPath(r.URL.Path) {
			v1.ServeHTTP(w, r)
			return
		}
		legacy.ServeHTTP(w, r)
	})
}

// startAgentSocket exposes the credential/ACK endpoints only on a Unix-domain
// socket. Its file mode is intentionally owner/group-only; deployment assigns
// pgw-api and pgw-agent to the same dedicated runtime group. The TCP listener
// serves public /v1 and /v2 paths but is rejected for /internal/agent paths.
var afterAgentSocketBind = func() error { return nil }

func startAgentSocket(handler http.Handler) (func(context.Context) error, error) {
	path := strings.TrimSpace(os.Getenv("PGW_AGENT_SOCKET"))
	if path == "" {
		path = defaultAgentSocketPath
	}
	if !filepath.IsAbs(path) || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
		return nil, fmt.Errorf("invalid agent socket path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create agent socket directory: %w", err)
	}
	if err := recoverStaleAgentSocket(path); err != nil {
		return nil, fmt.Errorf("prepare agent socket path: %w", err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen agent Unix socket: %w", err)
	}
	// Revalidate the just-bound pathname before chmod.  If the process dies at
	// this exact point the restrictive-umask socket remains recoverable only by
	// recoverStaleAgentSocket's owner/inode/live-connect checks.
	bound, err := validateBoundAgentSocket(path)
	if err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("revalidate bound agent Unix socket")
	}
	if err := afterAgentSocketBind(); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("agent Unix socket bind checkpoint: %w", err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("chmod agent Unix socket: %w", err)
	}
	if err := validatePublishedAgentSocket(path, bound); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("revalidate published agent Unix socket")
	}
	// Internal requests still receive the same bounded HTTP parser as the
	// loopback listener. UDS constrains the transport, not request resources.
	server := boundedHTTPServer("", handler)
	go func() { _ = server.Serve(listener) }()
	return func(ctx context.Context) error {
		err := server.Shutdown(ctx)
		removeErr := os.Remove(path)
		if err != nil {
			return err
		}
		if removeErr != nil && !os.IsNotExist(removeErr) {
			return removeErr
		}
		return nil
	}, nil
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
