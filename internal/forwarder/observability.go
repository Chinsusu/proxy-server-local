package forwarder

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Chinsusu/proxy-server-local/pkg/observability"
)

const (
	metricsLoopbackHost = "127.0.0.2"
)

type forwarderMetrics struct {
	active    atomic.Int64
	ready     atomic.Int64
	bytes     atomic.Uint64
	mu        sync.RWMutex
	counters  map[forwarderMetricKey]uint64
	proxyType string
}

type forwarderMetricKey struct{ operation, outcome, reason string }

func newForwarderMetrics(proxyType string) *forwarderMetrics {
	return &forwarderMetrics{counters: make(map[forwarderMetricKey]uint64), proxyType: metricProxyType(proxyType)}
}

func (m *forwarderMetrics) setActive(value int64) { m.active.Store(value) }
func (m *forwarderMetrics) setReady(value bool) {
	if value {
		m.ready.Store(1)
		return
	}
	m.ready.Store(0)
}
func (m *forwarderMetrics) addBytes(value int64) {
	if value > 0 {
		m.bytes.Add(uint64(value))
	}
}
func (m *forwarderMetrics) observe(operation, outcome, reason string) {
	key := forwarderMetricKey{metricOperation(operation), metricOutcome(outcome), metricReason(reason)}
	m.mu.Lock()
	m.counters[key]++
	m.mu.Unlock()
}

func (m *forwarderMetrics) render() string {
	m.mu.RLock()
	keys := make([]forwarderMetricKey, 0, len(m.counters))
	for key := range m.counters {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].operation+keys[i].outcome+keys[i].reason < keys[j].operation+keys[j].outcome+keys[j].reason
	})
	lines := []string{
		"# HELP pgw_forwarder_active_connections Active transparent forwarder connections.",
		"# TYPE pgw_forwarder_active_connections gauge",
		fmt.Sprintf("pgw_forwarder_active_connections%s %d", forwarderLabels(m.proxyType, "connection", "gauge", "none"), m.active.Load()),
		"# HELP pgw_forwarder_ready Forwarder readiness after both listeners bind.",
		"# TYPE pgw_forwarder_ready gauge",
		fmt.Sprintf("pgw_forwarder_ready%s %d", forwarderLabels(m.proxyType, "readiness", "gauge", "none"), m.ready.Load()),
		"# HELP pgw_forwarder_bytes_total Bytes copied after successful proxy setup.",
		"# TYPE pgw_forwarder_bytes_total counter",
		fmt.Sprintf("pgw_forwarder_bytes_total%s %d", forwarderLabels(m.proxyType, "copy", "total", "none"), m.bytes.Load()),
		"# HELP pgw_forwarder_events_total Bounded forwarder lifecycle and connection events.",
		"# TYPE pgw_forwarder_events_total counter",
	}
	for _, key := range keys {
		lines = append(lines, fmt.Sprintf("pgw_forwarder_events_total%s %d", forwarderLabels(m.proxyType, key.operation, key.outcome, key.reason), m.counters[key]))
	}
	m.mu.RUnlock()
	return strings.Join(lines, "\n") + "\n"
}

func forwarderLabels(proxyType, operation, outcome, reason string) string {
	return fmt.Sprintf(`{operation="%s",outcome="%s",proxy_type="%s",reason="%s",service="pgw-fwd"}`, operation, outcome, proxyType, reason)
}

func metricProxyType(value string) string {
	if value == "http" || value == "socks5" {
		return value
	}
	return "other"
}
func metricOperation(value string) string {
	switch value {
	case "connection", "handshake", "dial", "drain", "forced_close", "readiness", "copy":
		return value
	default:
		return "other"
	}
}
func metricOutcome(value string) string {
	switch value {
	case "accepted", "success", "failure", "started", "completed", "total", "gauge":
		return value
	default:
		return "other"
	}
}
func metricReason(value string) string {
	switch value {
	case "none", "ready", "shutdown", "deadline", "connection_limit", "original_destination", "credential_unavailable", "dial_timeout", "dial_failed", "handshake_timeout", "handshake_failed", "proxy_rejected", "copy_failed", "preface_write", "metrics_bind", "listener_bind", "notify_failed", "config_invalid":
		return value
	default:
		return "other"
	}
}

func metricsAddress(dataAddress string) (string, error) {
	host, port, err := net.SplitHostPort(dataAddress)
	if err != nil {
		return "", fmt.Errorf("transparent listener address is invalid")
	}
	if host == metricsLoopbackHost {
		return "", fmt.Errorf("metrics listener collides with transparent listener")
	}
	if err := observability.ValidateLoopbackAddress(net.JoinHostPort(metricsLoopbackHost, port)); err != nil {
		return "", err
	}
	return net.JoinHostPort(metricsLoopbackHost, port), nil
}

func (m *forwarderMetrics) handler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/metrics" || (request.Method != http.MethodGet && request.Method != http.MethodHead) {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		writer.Header().Set("Cache-Control", "no-store")
		if request.Method == http.MethodHead {
			return
		}
		_, _ = io.WriteString(writer, m.render())
	})
}

func newMetricsHTTPServer(metrics *forwarderMetrics) *http.Server {
	return &http.Server{
		Handler:           metrics.handler(),
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       10 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
}
