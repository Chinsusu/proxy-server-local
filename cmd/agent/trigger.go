package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	agentcore "github.com/Chinsusu/proxy-server-local/internal/agent"
)

const (
	maxAgentHeaderBytes = 8 << 10
	maxTriggerBodyBytes = 1
)

type triggerAuthorizer interface {
	Authorized(string) bool
}

// reconcileTriggerGate serializes and coalesces trigger notifications before
// the control-plane fetch. A flood cannot turn into parallel or queued API
// calls while one fetch is pending or running.
type reconcileTriggerGate struct {
	mu              sync.Mutex
	notify          chan struct{}
	pending         bool
	running         bool
	lastHTTP        time.Time
	minimumInterval time.Duration
	telemetry       *agentcore.Telemetry
}

func newReconcileTriggerGate(minimumInterval time.Duration, telemetry ...*agentcore.Telemetry) *reconcileTriggerGate {
	var observed *agentcore.Telemetry
	if len(telemetry) > 0 {
		observed = telemetry[0]
	}
	return &reconcileTriggerGate{notify: make(chan struct{}, 1), minimumInterval: minimumInterval, telemetry: observed}
}

func (g *reconcileTriggerGate) Force() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.scheduleLocked() && g.telemetry != nil {
		g.telemetry.Metrics.ObserveCoalesced()
	}
}

func (g *reconcileTriggerGate) RequestHTTP(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.minimumInterval > 0 && !g.lastHTTP.IsZero() && now.Sub(g.lastHTTP) < g.minimumInterval {
		return false
	}
	g.lastHTTP = now
	if !g.scheduleLocked() && g.telemetry != nil {
		g.telemetry.Metrics.ObserveCoalesced()
		g.telemetry.Metrics.ObserveTrigger("coalesced")
	}
	return true
}

func (g *reconcileTriggerGate) scheduleLocked() bool {
	if g.pending || g.running {
		return false
	}
	g.pending = true
	g.notify <- struct{}{}
	return true
}

func (g *reconcileTriggerGate) Run(ctx context.Context, fetch func(context.Context) error, onError func(error)) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-g.notify:
			g.mu.Lock()
			g.pending = false
			g.running = true
			g.mu.Unlock()

			callContext, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := fetch(callContext)
			cancel()

			g.mu.Lock()
			g.running = false
			g.mu.Unlock()
			if err != nil && onError != nil {
				if g.telemetry != nil {
					g.telemetry.Metrics.ObserveTrigger("fetch_failure")
				}
				onError(err)
			}
		}
	}
}

func newAgentHandler(authorizer triggerAuthorizer, gate *reconcileTriggerGate, telemetry ...*agentcore.Telemetry) http.Handler {
	var observed *agentcore.Telemetry
	if len(telemetry) > 0 {
		observed = telemetry[0]
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/agent/reconcile", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			observeTrigger(r.Context(), observed, "method_not_allowed")
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if authorizer == nil || !authorizer.Authorized(r.Header.Get("Authorization")) {
			observeTrigger(r.Context(), observed, "unauthorized")
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.ContentLength > 0 {
			observeTrigger(r.Context(), observed, "body_rejected")
			http.Error(w, "request body is not allowed", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxTriggerBodyBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil || len(body) != 0 {
			observeTrigger(r.Context(), observed, "body_rejected")
			http.Error(w, "request body is not allowed", http.StatusBadRequest)
			return
		}
		if !gate.RequestHTTP(time.Now()) {
			observeTrigger(r.Context(), observed, "rate_limited")
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		observeTrigger(r.Context(), observed, "accepted")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("queued"))
	})
	mux.HandleFunc("/agent/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte("ok"))
		}
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodHead || observed == nil {
			return
		}
		_, _ = io.WriteString(w, strings.TrimSpace(observed.Observer.Metrics.Render())+"\n"+observed.Metrics.Render())
	})
	if observed != nil && observed.Observer != nil {
		return observed.Observer.WrapHTTP(mux)
	}
	return mux
}

func observeTrigger(ctx context.Context, telemetry *agentcore.Telemetry, outcome string) {
	if telemetry == nil {
		return
	}
	telemetry.Metrics.ObserveTrigger(outcome)
	level := "info"
	if outcome == "unauthorized" || outcome == "rate_limited" {
		level = "warn"
	}
	telemetry.Log(ctx, level, "reconcile_trigger", map[string]any{"outcome": outcome})
}
