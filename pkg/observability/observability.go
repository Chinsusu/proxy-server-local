// Package observability provides the small, shared logging and metrics
// boundary for PGW processes. It intentionally uses only the standard library:
// log entries and metric labels are allow-listed so request data and resource
// identifiers cannot become an accidental secret or high-cardinality sink.
package observability

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	requestIDHeader = "X-Request-ID"
	maxRequestIDLen = 64
)

type contextKey struct{}

// Observer is safe for concurrent handlers. Output is one JSON object per
// line; Prometheus data is deliberately kept in a separate registry.
type Observer struct {
	Service string
	Logger  *Logger
	Metrics *Registry
}

func New(service string, output io.Writer) *Observer {
	service = boundedService(service)
	return &Observer{Service: service, Logger: NewLogger(service, output), Metrics: NewRegistry(service)}
}

func NewDiscard(service string) *Observer { return New(service, io.Discard) }

func boundedService(value string) string {
	if validLabel(value, 48) {
		return value
	}
	return "pgw"
}

// WithRequest attaches a valid caller request ID, or generates a fresh
// opaque ID. The request path/query/body is intentionally not retained.
func WithRequest(ctx context.Context, header string, observer *Observer) (context.Context, string) {
	id := strings.TrimSpace(header)
	if !validRequestID(id) {
		id = newRequestID()
	}
	return context.WithValue(ctx, contextKey{}, requestContext{id: id, observer: observer}), id
}

type requestContext struct {
	id       string
	observer *Observer
}

func RequestID(ctx context.Context) string {
	if value, ok := ctx.Value(contextKey{}).(requestContext); ok {
		return value.id
	}
	return ""
}

func FromContext(ctx context.Context) *Observer {
	if value, ok := ctx.Value(contextKey{}).(requestContext); ok {
		return value.observer
	}
	return nil
}

func validRequestID(value string) bool { return validLabel(value, maxRequestIDLen) && len(value) >= 8 }

func newRequestID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err == nil {
		return hex.EncodeToString(bytes)
	}
	// crypto/rand failure is exceptional. Keep the fallback bounded and opaque;
	// it never incorporates request-controlled data.
	return strconv.FormatInt(time.Now().UnixNano(), 36) + "-pgw"
}

func validLabel(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' || character == '-') {
			return false
		}
	}
	return true
}

// Logger writes a fixed JSON schema. Fields are redacted and restricted to
// low-cardinality operational values. Callers must never pass request bodies.
type Logger struct {
	service string
	output  io.Writer
	mu      sync.Mutex
	now     func() time.Time
}

func NewLogger(service string, output io.Writer) *Logger {
	if output == nil {
		output = io.Discard
	}
	return &Logger{service: boundedService(service), output: output, now: time.Now}
}

var permittedLogFields = map[string]int{
	"method": 12, "route": 128, "status_class": 3, "status": 3, "duration_ms": 16,
	"mapping_id": 128, "proxy_id": 128, "generation": 20, "reason_code": 64,
	"outcome": 32, "state": 32, "error_code": 64,
}

func (l *Logger) Log(ctx context.Context, level, event string, fields map[string]any) {
	entry := map[string]any{
		"timestamp": l.now().UTC().Format(time.RFC3339Nano),
		"level":     enum(level, "info", "warn", "error"),
		"service":   l.service,
		"event":     safeEvent(event),
	}
	if id := RequestID(ctx); id != "" {
		entry["request_id"] = id
	}
	for key, value := range fields {
		maximum, allowed := permittedLogFields[key]
		if !allowed || sensitiveKey(key) {
			continue
		}
		if normalized, ok := safeField(value, maximum); ok {
			entry[key] = normalized
		}
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		return
	}
	l.mu.Lock()
	_, _ = l.output.Write(append(encoded, '\n'))
	l.mu.Unlock()
}

func safeEvent(value string) string {
	if validLabel(value, 64) {
		return value
	}
	return "invalid_event"
}

func enum(value string, values ...string) string {
	for _, allowed := range values {
		if value == allowed {
			return value
		}
	}
	return "info"
}

func safeField(value any, maximum int) (any, bool) {
	switch typed := value.(type) {
	case string:
		if len(typed) > maximum || looksSensitive(typed) {
			return "[REDACTED]", true
		}
		return typed, true
	case int:
		return typed, true
	case int64:
		return typed, true
	case bool:
		return typed, true
	case time.Duration:
		return typed.Milliseconds(), true
	default:
		return nil, false
	}
}

func sensitiveKey(value string) bool {
	key := strings.ToLower(value)
	for _, marker := range []string{"password", "secret", "token", "jwt", "authorization", "cookie", "credential", "cipher", "key"} {
		if strings.Contains(key, marker) {
			return true
		}
	}
	return false
}

func looksSensitive(value string) bool {
	lower := strings.ToLower(value)
	if strings.Contains(lower, "password") || strings.Contains(lower, "bearer ") || strings.Contains(lower, "authorization") || strings.Contains(lower, "ciphertext") || strings.Contains(lower, "credential") {
		return true
	}
	if index := strings.Index(value, "eyJ"); index >= 0 && len(value)-index >= 8 {
		// Compact JWTs conventionally begin with a base64url JSON header. This
		// catches tokens even when an upstream error adds a harmless prefix.
		return true
	}
	return false
}

// WrapHTTP supplies the request ID, emits an access event using a route
// template, and records only bounded metric labels.
func (o *Observer) WrapHTTP(next http.Handler) http.Handler {
	if o == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, requestID := WithRequest(r.Context(), r.Header.Get(requestIDHeader), o)
		w.Header().Set(requestIDHeader, requestID)
		request := r.WithContext(ctx)
		request.Header = r.Header.Clone()
		request.Header.Set(requestIDHeader, requestID)
		started := time.Now()
		recorder := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, request)
		duration := time.Since(started)
		route := RouteTemplate(r.URL.Path)
		statusClass := statusClass(recorder.status)
		o.Metrics.ObserveHTTPRequest(r.Method, route, recorder.status, duration)
		if o.Service == "pgw-ui" && strings.HasPrefix(route, "/api/") {
			o.Metrics.ObserveUIProxy(route, recorder.status)
		}
		o.Logger.Log(ctx, "info", "http_request", map[string]any{
			"method": r.Method, "route": route, "status": recorder.status,
			"status_class": statusClass, "duration_ms": duration,
		})
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(status int) {
	if !w.wrote {
		w.status, w.wrote = status, true
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *statusWriter) Write(value []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(value)
}

// RouteTemplate deliberately never returns a raw path. The list covers all
// public v1/v2 and UDS agent routes; unknown paths collapse to /other.
func RouteTemplate(path string) string {
	switch {
	case path == "/", path == "/login", path == "/logout", path == "/manage", path == "/proxies", path == "/metrics", path == "/healthz", path == "/readyz", path == "/v1/health", path == "/v1/auth/login":
		return path
	case strings.HasPrefix(path, "/static/"):
		return "/static/{asset}"
	case strings.HasPrefix(path, "/api/"):
		return "/api/{route}"
	case path == "/v1/proxies", path == "/v1/clients", path == "/v1/mappings", path == "/v1/mappings/active":
		return path
	case strings.HasPrefix(path, "/v1/proxies/"):
		return "/v1/proxies/{id}"
	case strings.HasPrefix(path, "/v1/clients/"):
		return "/v1/clients/{id}"
	case strings.HasPrefix(path, "/v1/mappings/"):
		return "/v1/mappings/{id}"
	case path == "/v2/proxies", path == "/v2/clients", path == "/v2/egress-policies", path == "/v2/mappings", path == "/v2/agent/state", path == "/v2/audit-events":
		return path
	case strings.HasPrefix(path, "/v2/proxies/"):
		return "/v2/proxies/{id}"
	case strings.HasPrefix(path, "/v2/clients/"):
		return "/v2/clients/{id}"
	case strings.HasPrefix(path, "/v2/egress-policies/"):
		return "/v2/egress-policies/{id}"
	case strings.HasPrefix(path, "/v2/mappings/"):
		return "/v2/mappings/{id_or_action}"
	case path == "/internal/agent/v1/snapshot", path == "/internal/agent/v1/ack", path == "/internal/agent/v1/state":
		return path
	case strings.HasPrefix(path, "/internal/agent/v1/mappings/"):
		return "/internal/agent/v1/mappings/{id}/credential"
	default:
		return "/other"
	}
}

func canonicalMethod(value string) string {
	switch value {
	case http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodDelete, http.MethodHead:
		return value
	default:
		return "OTHER"
	}
}
func statusClass(status int) string {
	if status < 100 || status > 599 {
		return "other"
	}
	return strconv.Itoa(status/100) + "xx"
}

// Registry is a bounded in-process Prometheus registry. It has no resource
// ID labels and is safe to scrape while requests are being recorded.
type Registry struct {
	service        string
	mu             sync.RWMutex
	http           map[httpKey]httpValue
	auth           map[authKey]uint64
	db             map[string]uint64
	ui             map[uiKey]uint64
	migrate        map[string]float64
	agent          agentValue
	agentSet       bool
	controlPlane   bool
	agentCollector bool
}
type httpKey struct{ method, route, status string }
type httpValue struct {
	count   uint64
	seconds float64
}
type authKey struct{ outcome, reason string }
type uiKey struct{ route, status string }
type agentValue struct {
	pending, applied int64
	state            string
}

func NewRegistry(service string) *Registry {
	bounded := boundedService(service)
	return &Registry{service: bounded, http: make(map[httpKey]httpValue), auth: make(map[authKey]uint64), db: make(map[string]uint64), ui: make(map[uiKey]uint64), migrate: make(map[string]float64), agent: agentValue{state: "unknown"}, controlPlane: bounded == "pgw-api", agentCollector: bounded == "pgw-api" || bounded == "pgw-agent"}
}

func (r *Registry) ObserveHTTPRequest(method, route string, status int, duration time.Duration) {
	if r == nil {
		return
	}
	key := httpKey{canonicalMethod(method), RouteTemplate(route), statusClass(status)}
	r.mu.Lock()
	value := r.http[key]
	value.count++
	value.seconds += duration.Seconds()
	r.http[key] = value
	r.mu.Unlock()
}
func (r *Registry) ObserveAuth(outcome, reason string) {
	if r == nil {
		return
	}
	if outcome != "success" && outcome != "failure" && outcome != "rate_limited" {
		outcome = "failure"
	}
	if !validLabel(reason, 48) {
		reason = "other"
	}
	r.mu.Lock()
	r.auth[authKey{outcome, reason}]++
	r.mu.Unlock()
}
func (r *Registry) ObserveDBError(reason string) {
	if r == nil {
		return
	}
	if !validLabel(reason, 48) {
		reason = "other"
	}
	r.mu.Lock()
	r.db[reason]++
	r.mu.Unlock()
}
func (r *Registry) ObserveUIProxy(route string, status int) {
	if r == nil {
		return
	}
	key := uiKey{route: RouteTemplate(route), status: statusClass(status)}
	r.mu.Lock()
	r.ui[key]++
	r.mu.Unlock()
}
func (r *Registry) SetMigrationStatus(status string, value bool) {
	if r == nil {
		return
	}
	if !validLabel(status, 32) {
		status = "other"
	}
	r.mu.Lock()
	if value {
		r.migrate[status] = 1
	} else {
		r.migrate[status] = 0
	}
	r.mu.Unlock()
}
func (r *Registry) SetAgentState(pending, applied int64, state string) {
	if r == nil {
		return
	}
	if !validLabel(strings.ToLower(state), 32) {
		state = "unknown"
	} else {
		state = strings.ToLower(state)
	}
	r.mu.Lock()
	r.agent = agentValue{pending: pending, applied: applied, state: state}
	r.agentSet = true
	r.mu.Unlock()
}

func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = io.WriteString(w, r.Render())
	})
}

func (r *Registry) Render() string {
	if r == nil {
		return ""
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var lines []string
	lines = append(lines, "# HELP pgw_http_requests_total Completed HTTP requests.", "# TYPE pgw_http_requests_total counter", "# HELP pgw_http_request_duration_seconds HTTP request duration in seconds.", "# TYPE pgw_http_request_duration_seconds histogram")
	for key, value := range r.http {
		labels := labelsOf(map[string]string{"service": r.service, "method": key.method, "route": key.route, "status_class": key.status})
		lines = append(lines, fmt.Sprintf("pgw_http_requests_total%s %d", labels, value.count), fmt.Sprintf("pgw_http_request_duration_seconds_sum%s %.9f", labels, value.seconds), fmt.Sprintf("pgw_http_request_duration_seconds_count%s %d", labels, value.count))
	}
	if r.controlPlane {
		lines = append(lines, "# HELP pgw_auth_attempts_total Authentication outcomes.", "# TYPE pgw_auth_attempts_total counter")
		for key, value := range r.auth {
			lines = append(lines, fmt.Sprintf("pgw_auth_attempts_total%s %d", labelsOf(map[string]string{"service": r.service, "outcome": key.outcome, "reason": key.reason}), value))
		}
		lines = append(lines, "# HELP pgw_db_errors_total Database operation errors.", "# TYPE pgw_db_errors_total counter")
		for reason, value := range r.db {
			lines = append(lines, fmt.Sprintf("pgw_db_errors_total%s %d", labelsOf(map[string]string{"service": r.service, "reason": reason}), value))
		}
		lines = append(lines, "# HELP pgw_schema_migration_ready Schema migration readiness.", "# TYPE pgw_schema_migration_ready gauge")
		for status, value := range r.migrate {
			lines = append(lines, fmt.Sprintf("pgw_schema_migration_ready%s %.0f", labelsOf(map[string]string{"service": r.service, "status": status}), value))
		}
	}
	if r.service == "pgw-ui" {
		lines = append(lines, "# HELP pgw_ui_proxy_requests_total UI-to-API proxy requests.", "# TYPE pgw_ui_proxy_requests_total counter")
		for key, value := range r.ui {
			lines = append(lines, fmt.Sprintf("pgw_ui_proxy_requests_total%s %d", labelsOf(map[string]string{"service": r.service, "route": key.route, "status_class": key.status}), value))
		}
	}
	if r.agentCollector && r.agentSet {
		lines = append(lines, "# HELP pgw_agent_generation_pending Agent pending generation.", "# TYPE pgw_agent_generation_pending gauge", fmt.Sprintf("pgw_agent_generation_pending%s %d", labelsOf(map[string]string{"service": r.service}), r.agent.pending), "# HELP pgw_agent_generation_applied Agent applied generation.", "# TYPE pgw_agent_generation_applied gauge", fmt.Sprintf("pgw_agent_generation_applied%s %d", labelsOf(map[string]string{"service": r.service}), r.agent.applied), "# HELP pgw_agent_state Agent reconcile state (one active state has value 1).", "# TYPE pgw_agent_state gauge")
		for _, state := range []string{"unknown", "pending", "applying", "applied", "verified", "failed", "rolled_back"} {
			value := 0
			if r.agent.state == state {
				value = 1
			}
			lines = append(lines, fmt.Sprintf("pgw_agent_state%s %d", labelsOf(map[string]string{"service": r.service, "state": state}), value))
		}
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n") + "\n"
}

func labelsOf(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"=\""+strings.ReplaceAll(strings.ReplaceAll(values[key], "\\", "\\\\"), "\"", "\\\"")+"\"")
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// ListenLoopback creates a metrics listener only on an explicit numeric
// loopback address. Metrics endpoints must never share browser/TLS ingress.
func ListenLoopback(addr string) (net.Listener, error) {
	if err := ValidateLoopbackAddress(addr); err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	return net.Listen("tcp", net.JoinHostPort(ip.String(), port))
}

// ValidateLoopbackAddress validates without opening a listener. It is used at
// startup before a process claims its dedicated metrics port.
func ValidateLoopbackAddress(addr string) error {
	host, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("metrics address must be explicit numeric loopback host:port")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("metrics address must be numeric loopback")
	}
	return nil
}
