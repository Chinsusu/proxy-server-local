package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/Chinsusu/proxy-server-local/internal/forwarder"
	"github.com/Chinsusu/proxy-server-local/pkg/observability"
)

// pgw-fwd receives all operational state from the Agent. In particular it
// intentionally does not call the API or accept proxy credentials in command
// line arguments or environment variables.
func main() {
	observer := observability.New("pgw-fwd", os.Stderr)
	configPath := os.Getenv("PGW_FWD_CONFIG")
	runtime, err := forwarder.ReadConfig(configPath)
	if err != nil {
		logEvent(observer, "error", "forwarder_startup", "failure", "config_invalid")
		os.Exit(1)
	}
	credentials, err := forwarder.ReadCredentials(os.Getenv("CREDENTIALS_DIRECTORY"))
	if err != nil {
		logEvent(observer, "error", "forwarder_startup", "failure", "credential_unavailable")
		os.Exit(1)
	}
	server, err := forwarder.NewServerWithObserver(runtime, credentials, forwarder.NewSystemdNotifier(), observer)
	if err != nil {
		credentials.Wipe()
		logEvent(observer, "error", "forwarder_startup", "failure", "config_invalid")
		os.Exit(1)
	}
	// NewServer now owns the buffers; drop this duplicate slice header.
	credentials = forwarder.Credentials{}
	defer server.CloseCredentials()
	if err := server.Start(); err != nil {
		server.CloseCredentials()
		os.Exit(1)
	}

	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve() }()
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)

	select {
	case <-signals:
		ctx, cancel := context.WithTimeout(context.Background(), runtime.DrainTimeout)
		err := server.Shutdown(ctx)
		cancel()
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			server.CloseCredentials()
			logEvent(observer, "error", "forwarder_shutdown", "failure", "shutdown")
			os.Exit(1)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			logEvent(observer, "warn", "forwarder_forced_close", "success", "deadline")
		}
	case err := <-serveResult:
		if err != nil {
			server.CloseCredentials()
			logEvent(observer, "error", "forwarder_accept", "failure", "listener_bind")
			os.Exit(1)
		}
	}
}

func logEvent(observer *observability.Observer, level, event, outcome, reason string) {
	observer.Logger.Log(context.Background(), level, event, map[string]any{
		"outcome":     outcome,
		"reason_code": reason,
	})
}
