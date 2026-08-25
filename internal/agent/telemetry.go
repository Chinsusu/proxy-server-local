package agent

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Chinsusu/proxy-server-local/pkg/observability"
)

// Telemetry is the Agent's bounded observability boundary. Resource IDs are
// permitted in structured logs only; metric labels are fixed enums.
type Telemetry struct {
	Observer *observability.Observer
	Metrics  *AgentMetrics
}

func NewTelemetry(observer *observability.Observer) *Telemetry {
	if observer == nil {
		observer = observability.NewDiscard("pgw-agent")
	}
	return &Telemetry{Observer: observer, Metrics: NewAgentMetrics()}
}

func (t *Telemetry) Log(ctx context.Context, level, event string, fields map[string]any) {
	if t != nil && t.Observer != nil {
		t.Observer.Logger.Log(ctx, level, event, fields)
	}
}

func (t *Telemetry) SetState(pending, applied int64, state string) {
	if t != nil && t.Observer != nil {
		t.Observer.Metrics.SetAgentState(pending, applied, state)
	}
	if t != nil && t.Metrics != nil {
		t.Metrics.SetGeneration(pending, applied)
	}
}

type metricKey struct{ operation, outcome string }
type reconcileMetric struct {
	count   uint64
	seconds float64
}

// AgentMetrics contains Agent-specific Prometheus series. All label values
// pass closed whitelists so callers cannot introduce identifiers or secrets.
type AgentMetrics struct {
	mu        sync.RWMutex
	reconcile map[metricKey]reconcileMetric
	nft       map[metricKey]uint64
	lkg       map[metricKey]uint64
	forwarder map[metricKey]uint64
	trigger   map[string]uint64
	coalesced uint64
	pending   int64
	applied   int64
}

func NewAgentMetrics() *AgentMetrics {
	return &AgentMetrics{reconcile: map[metricKey]reconcileMetric{}, nft: map[metricKey]uint64{}, lkg: map[metricKey]uint64{}, forwarder: map[metricKey]uint64{}, trigger: map[string]uint64{}}
}

var allowedOutcomes = setOf("success", "failure", "rolled_back", "unknown")
var allowedReasons = setOf(
	"none", "startup_recovery_failed", "snapshot_fetch_failed", "generation_mismatch",
	"invalid_desired_hash", "invalid_desired_snapshot", "base_firewall_unavailable",
	"render_failed", "lkg_unavailable", "candidate_check_failed", "forwarder_rollback_failed",
	"forwarder_not_ready", "dynamic_apply_failed", "rolled_back", "runtime_rollback_failed",
	"runtime_journal_update_failed", "lkg_write_and_rollback_failed", "runtime_restore_cleanup_failed",
	"forwarder_drain_incomplete", "lkg_finalize_failed", "ack_failed", "other",
)
var allowedNFTOperations = setOf("verify_base", "check", "apply", "readback", "rollback", "quarantine", "other")
var allowedLKGOperations = setOf("load", "save", "journal_save", "journal_clear", "rollback", "recovery", "other")
var allowedForwarderOperations = setOf("prepare", "start", "restart", "ready", "drain", "stop", "capture", "restore", "cleanup", "other")
var allowedTriggerOutcomes = setOf("accepted", "coalesced", "unauthorized", "rate_limited", "method_not_allowed", "body_rejected", "fetch_failure", "other")

func setOf(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}
func boundedEnum(value string, allowed map[string]struct{}) string {
	value = strings.ToLower(value)
	if _, ok := allowed[value]; ok {
		return value
	}
	return "other"
}

func (m *AgentMetrics) ObserveReconcile(outcome, reason string, duration time.Duration) {
	if m == nil {
		return
	}
	key := metricKey{boundedEnum(reason, allowedReasons), boundedEnum(outcome, allowedOutcomes)}
	m.mu.Lock()
	value := m.reconcile[key]
	value.count++
	value.seconds += duration.Seconds()
	m.reconcile[key] = value
	m.mu.Unlock()
}
func (m *AgentMetrics) ObserveNFT(operation, outcome string) {
	if m == nil {
		return
	}
	m.observe(&m.nft, operation, outcome, allowedNFTOperations)
}
func (m *AgentMetrics) ObserveLKG(operation, outcome string) {
	if m == nil {
		return
	}
	m.observe(&m.lkg, operation, outcome, allowedLKGOperations)
}
func (m *AgentMetrics) ObserveForwarder(operation, outcome string) {
	if m == nil {
		return
	}
	m.observe(&m.forwarder, operation, outcome, allowedForwarderOperations)
}
func (m *AgentMetrics) observe(target *map[metricKey]uint64, operation, outcome string, operations map[string]struct{}) {
	if m == nil {
		return
	}
	key := metricKey{boundedEnum(operation, operations), boundedEnum(outcome, allowedOutcomes)}
	m.mu.Lock()
	(*target)[key]++
	m.mu.Unlock()
}
func (m *AgentMetrics) ObserveTrigger(outcome string) {
	if m == nil {
		return
	}
	outcome = boundedEnum(outcome, allowedTriggerOutcomes)
	m.mu.Lock()
	m.trigger[outcome]++
	m.mu.Unlock()
}
func (m *AgentMetrics) ObserveCoalesced() {
	if m != nil {
		m.mu.Lock()
		m.coalesced++
		m.mu.Unlock()
	}
}
func (m *AgentMetrics) SetGeneration(pending, applied int64) {
	if m != nil {
		m.mu.Lock()
		m.pending, m.applied = pending, applied
		m.mu.Unlock()
	}
}
func (m *AgentMetrics) Generation() (pending, applied int64) {
	if m == nil {
		return 0, 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.pending, m.applied
}

func metricLabels(values ...string) string {
	parts := make([]string, 0, len(values)/2)
	for index := 0; index < len(values); index += 2 {
		parts = append(parts, values[index]+"=\""+values[index+1]+"\"")
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// Render is deterministic and safe for concurrent scrapes.
func (m *AgentMetrics) Render() string {
	if m == nil {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	lines := []string{
		"# HELP pgw_agent_reconcile_total Agent reconciliation outcomes.", "# TYPE pgw_agent_reconcile_total counter",
		"# HELP pgw_agent_reconcile_duration_seconds Reconciliation duration.", "# TYPE pgw_agent_reconcile_duration_seconds summary",
		"# HELP pgw_agent_queue_coalesced_total Coalesced generation notifications.", "# TYPE pgw_agent_queue_coalesced_total counter",
		fmt.Sprintf("pgw_agent_queue_coalesced_total %d", m.coalesced),
		"# HELP pgw_agent_reconcile_generation_lag Pending minus applied generation.", "# TYPE pgw_agent_reconcile_generation_lag gauge",
		fmt.Sprintf("pgw_agent_reconcile_generation_lag %d", max64(0, m.pending-m.applied)),
	}
	for key, value := range m.reconcile {
		labels := metricLabels("outcome", key.outcome, "reason", key.operation)
		lines = append(lines, fmt.Sprintf("pgw_agent_reconcile_total%s %d", labels, value.count), fmt.Sprintf("pgw_agent_reconcile_duration_seconds_sum%s %.9f", labels, value.seconds), fmt.Sprintf("pgw_agent_reconcile_duration_seconds_count%s %d", labels, value.count))
	}
	appendOps := func(name, help string, values map[metricKey]uint64) {
		lines = append(lines, "# HELP "+name+" "+help, "# TYPE "+name+" counter")
		for key, value := range values {
			lines = append(lines, fmt.Sprintf("%s%s %d", name, metricLabels("operation", key.operation, "outcome", key.outcome), value))
		}
	}
	appendOps("pgw_agent_nft_operations_total", "nftables operations.", m.nft)
	appendOps("pgw_agent_lkg_operations_total", "LKG and recovery operations.", m.lkg)
	appendOps("pgw_agent_forwarder_lifecycle_total", "Forwarder lifecycle operations.", m.forwarder)
	lines = append(lines, "# HELP pgw_agent_trigger_total Trigger request outcomes.", "# TYPE pgw_agent_trigger_total counter")
	for outcome, value := range m.trigger {
		lines = append(lines, fmt.Sprintf("pgw_agent_trigger_total%s %d", metricLabels("outcome", outcome), value))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n") + "\n"
}

func max64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}
