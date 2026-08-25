package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/Chinsusu/proxy-server-local/internal/domain"
	"github.com/Chinsusu/proxy-server-local/pkg/nft"
	"github.com/Chinsusu/proxy-server-local/pkg/types"
)

const lkgVersion = 1

type Config struct {
	LANInterface       string
	WANInterface       string
	ForwarderPortStart int
	ForwarderPortEnd   int
	DrainTimeout       time.Duration
	Telemetry          *Telemetry
}

type Reconciler struct {
	config     Config
	control    ControlPlane
	dataPlane  DataPlane
	forwarders Forwarders
	lkg        LKGStore
	telemetry  *Telemetry
}

func NewReconciler(config Config, control ControlPlane, dataPlane DataPlane, forwarders Forwarders, lkg LKGStore) (*Reconciler, error) {
	if control == nil || dataPlane == nil || forwarders == nil || lkg == nil {
		return nil, fmt.Errorf("agent: all reconciler dependencies are required")
	}
	if config.ForwarderPortStart == 0 && config.ForwarderPortEnd == 0 {
		config.ForwarderPortStart = nft.DefaultForwarderPortStart
		config.ForwarderPortEnd = nft.DefaultForwarderPortEnd
	}
	if config.ForwarderPortStart < 1 || config.ForwarderPortEnd > 65535 || config.ForwarderPortStart > config.ForwarderPortEnd {
		return nil, fmt.Errorf("agent: invalid forwarder port range")
	}
	if config.DrainTimeout <= 0 || config.DrainTimeout > 30*time.Second {
		config.DrainTimeout = 30 * time.Second
	}
	return &Reconciler{config: config, control: control, dataPlane: dataPlane, forwarders: forwarders, lkg: lkg, telemetry: config.Telemetry}, nil
}

func (r *Reconciler) Reconcile(ctx context.Context, generation int64) error {
	started := time.Now()
	r.setState(generation, -1, "applying")
	r.log(ctx, "info", "reconcile_started", map[string]any{"generation": generation, "state": "applying"})
	err := r.reconcile(ctx, generation)
	outcome, reason := "success", "none"
	if err != nil {
		outcome, reason = "failure", reasonOf(err)
		if reason == "rolled_back" {
			outcome = "rolled_back"
		} else if reason == "runtime_restore_cleanup_failed" || reason == "forwarder_drain_incomplete" || reason == "lkg_finalize_failed" {
			outcome = "unknown"
		}
		_, applied := r.currentGeneration()
		r.setState(generation, applied, outcome)
	} else {
		r.setState(generation, generation, "verified")
	}
	if r.telemetry != nil {
		r.telemetry.Metrics.ObserveReconcile(outcome, reason, time.Since(started))
	}
	r.log(ctx, map[bool]string{true: "error", false: "info"}[err != nil], "reconcile_completed", map[string]any{"generation": generation, "outcome": outcome, "reason_code": reason, "duration_ms": time.Since(started)})
	return err
}

func (r *Reconciler) reconcile(ctx context.Context, generation int64) error {
	if err := r.startupRecover(ctx); err != nil {
		r.observeLKG("recovery", "failure")
		return coded("startup_recovery_failed", fmt.Errorf("recover interrupted runtime transition before API reconciliation: %w", err))
	}
	r.observeLKG("recovery", "success")
	snapshot, err := r.control.FetchSnapshot(ctx, generation)
	if err != nil {
		return coded("snapshot_fetch_failed", fmt.Errorf("fetch immutable desired snapshot: %w", err))
	}
	if snapshot.Generation != generation {
		return coded("generation_mismatch", fmt.Errorf("immutable snapshot generation mismatch: requested %d, received %d", generation, snapshot.Generation))
	}
	r.log(ctx, "info", "snapshot_fetched", map[string]any{"generation": snapshot.Generation, "outcome": "success"})
	if err := domain.ValidateDesiredSnapshot(snapshot); err != nil {
		r.log(ctx, "error", "snapshot_validation_completed", map[string]any{"generation": snapshot.Generation, "outcome": "failure", "reason_code": "invalid_desired_hash"})
		return r.fail(ctx, snapshot, "invalid_desired_hash", err)
	}
	active, err := validateAndSelect(snapshot, r.config)
	if err != nil {
		r.log(ctx, "error", "snapshot_validation_completed", map[string]any{"generation": snapshot.Generation, "outcome": "failure", "reason_code": "invalid_desired_snapshot"})
		return r.fail(ctx, snapshot, "invalid_desired_snapshot", err)
	}
	r.log(ctx, "info", "snapshot_validation_completed", map[string]any{"generation": snapshot.Generation, "outcome": "success"})
	if err := r.dataPlane.VerifyBase(ctx); err != nil {
		r.observeNFT("verify_base", "failure")
		r.log(ctx, "error", "nft_operation_completed", map[string]any{"generation": snapshot.Generation, "state": "verify_base", "outcome": "failure", "reason_code": "base_firewall_unavailable"})
		return r.fail(ctx, snapshot, "base_firewall_unavailable", err)
	}
	r.observeNFT("verify_base", "success")
	r.log(ctx, "info", "nft_operation_completed", map[string]any{"generation": snapshot.Generation, "state": "verify_base", "outcome": "success"})

	candidate, err := renderCandidate(r.config, active)
	if err != nil {
		return r.fail(ctx, snapshot, "render_failed", err)
	}
	previous, err := r.loadOrBootstrap(ctx)
	if err != nil {
		return r.fail(ctx, snapshot, "lkg_unavailable", err)
	}
	if err := r.dataPlane.Check(ctx, candidate); err != nil {
		r.observeNFT("check", "failure")
		r.log(ctx, "error", "nft_operation_completed", map[string]any{"generation": snapshot.Generation, "state": "check", "outcome": "failure", "reason_code": "candidate_check_failed"})
		return r.fail(ctx, snapshot, "candidate_check_failed", err)
	}
	r.observeNFT("check", "success")
	r.log(ctx, "info", "nft_operation_completed", map[string]any{"generation": snapshot.Generation, "state": "check", "outcome": "success"})

	current := runtimeRecords(active)
	prepared, transition, err := r.prepareForwarders(ctx, snapshot, active, previous)
	if err != nil {
		rollbackErr := r.rollbackReconcile(context.WithoutCancel(ctx), prepared, transition, previous)
		if rollbackErr != nil {
			return r.fail(ctx, snapshot, "forwarder_rollback_failed", errors.Join(err, rollbackErr))
		}
		return r.fail(ctx, snapshot, "forwarder_not_ready", err)
	}

	rollbackRules := previous.Rules
	if transition != nil && transition.quarantined {
		rollbackRules = transition.quiescedRules
	}
	appliedHash, rolledBack, err := r.dataPlane.Apply(ctx, candidate, rollbackRules)
	if err != nil {
		r.observeNFT("apply", "failure")
		r.log(ctx, "error", "nft_operation_completed", map[string]any{"generation": snapshot.Generation, "state": "apply", "outcome": "failure", "reason_code": "dynamic_apply_failed"})
		if rolledBack {
			r.observeNFT("rollback", "success")
		}
		runtimeRollbackErr := r.rollbackReconcile(context.WithoutCancel(ctx), prepared, transition, previous)
		reason := "dynamic_apply_failed"
		if (rolledBack || transition != nil) && runtimeRollbackErr == nil {
			reason = "ROLLED_BACK"
		} else if runtimeRollbackErr != nil {
			reason = "runtime_rollback_failed"
		}
		return r.fail(ctx, snapshot, reason, errors.Join(err, runtimeRollbackErr))
	}
	r.observeNFT("apply", "success")
	r.log(ctx, "info", "nft_operation_completed", map[string]any{"generation": snapshot.Generation, "state": "apply", "outcome": "success"})
	if transition != nil {
		transition.journal.Phase = TransitionNFTApplied
		if err := r.lkg.SaveTransition(transition.journal); err != nil {
			r.observeLKG("journal_save", "failure")
			rollbackErr := r.rollbackReconcile(context.WithoutCancel(ctx), prepared, transition, previous)
			return r.fail(ctx, snapshot, "runtime_journal_update_failed", errors.Join(err, rollbackErr))
		}
		r.observeLKG("journal_save", "success")
	}

	pendingStops := removedRuntimes(previous.Metadata, current)
	next := makeLKG(snapshot, candidate, appliedHash, current, pendingStops)
	if err := r.lkg.Save(next); err != nil {
		r.observeLKG("save", "failure")
		r.log(ctx, "error", "lkg_operation_completed", map[string]any{"generation": snapshot.Generation, "state": "save", "outcome": "failure", "reason_code": "lkg_write_and_rollback_failed"})
		var rollbackErr error
		if transition == nil {
			rollbackErr = r.rollbackCommittedWithoutTransition(context.WithoutCancel(ctx), prepared, previous)
		} else {
			rollbackErr = r.rollbackReconcile(context.WithoutCancel(ctx), prepared, transition, previous)
		}
		if rollbackErr != nil {
			return r.fail(ctx, snapshot, "lkg_write_and_rollback_failed", errors.Join(err, rollbackErr))
		}
		return r.fail(ctx, snapshot, "ROLLED_BACK", err)
	}
	r.observeLKG("save", "success")
	r.log(ctx, "info", "lkg_operation_completed", map[string]any{"generation": snapshot.Generation, "state": "save", "outcome": "success"})
	if transition != nil {
		transition.journal.Phase = TransitionLKGStored
		if err := r.lkg.SaveTransition(transition.journal); err != nil {
			r.observeLKG("journal_save", "failure")
			rollbackErr := r.rollbackReconcile(context.WithoutCancel(ctx), prepared, transition, previous)
			return r.fail(ctx, snapshot, "runtime_journal_update_failed", errors.Join(err, rollbackErr))
		}
		r.observeLKG("journal_save", "success")
	}
	if err := r.finalizePrepared(ctx, prepared, transition); err != nil {
		ackErr := r.control.Acknowledge(ctx, domain.AgentAck{
			Generation: snapshot.Generation, DesiredHash: snapshot.DesiredHash, AppliedHash: appliedHash,
			Status: domain.DataPlaneUnknown, ReasonCode: "runtime_restore_cleanup_failed",
		})
		r.log(ctx, "error", "ack_completed", map[string]any{"generation": snapshot.Generation, "outcome": ackOutcome(ackErr), "reason_code": "runtime_restore_cleanup_failed", "state": "unknown"})
		return coded("runtime_restore_cleanup_failed", errors.Join(err, ackErr))
	}

	if len(pendingStops) > 0 {
		failedStops := r.stopRecords(context.WithoutCancel(ctx), pendingStops)
		if len(failedStops) > 0 {
			next.Metadata.PendingStops = failedStops
			if saveErr := r.lkg.Save(next); saveErr != nil {
				err = errors.Join(fmt.Errorf("stop retired forwarders"), saveErr)
			} else {
				err = fmt.Errorf("stop retired forwarders")
			}
			ackErr := r.control.Acknowledge(ctx, domain.AgentAck{
				Generation: snapshot.Generation, DesiredHash: snapshot.DesiredHash, AppliedHash: appliedHash,
				Status: domain.DataPlaneUnknown, ReasonCode: "forwarder_drain_incomplete",
			})
			r.log(ctx, "error", "ack_completed", map[string]any{"generation": snapshot.Generation, "outcome": ackOutcome(ackErr), "reason_code": "forwarder_drain_incomplete", "state": "unknown"})
			return coded("forwarder_drain_incomplete", errors.Join(err, ackErr))
		}
		next.Metadata.PendingStops = nil
		if err := r.lkg.Save(next); err != nil {
			ackErr := r.control.Acknowledge(ctx, domain.AgentAck{
				Generation: snapshot.Generation, DesiredHash: snapshot.DesiredHash, AppliedHash: appliedHash,
				Status: domain.DataPlaneUnknown, ReasonCode: "lkg_finalize_failed",
			})
			r.log(ctx, "error", "ack_completed", map[string]any{"generation": snapshot.Generation, "outcome": ackOutcome(ackErr), "reason_code": "lkg_finalize_failed", "state": "unknown"})
			return coded("lkg_finalize_failed", errors.Join(err, ackErr))
		}
	}
	if err := r.control.Acknowledge(ctx, domain.AgentAck{
		Generation: snapshot.Generation, DesiredHash: snapshot.DesiredHash, AppliedHash: appliedHash,
		Status: domain.DataPlaneVerified,
	}); err != nil {
		return coded("ack_failed", fmt.Errorf("ack verified generation %d: %w", snapshot.Generation, err))
	}
	r.log(ctx, "info", "ack_completed", map[string]any{"generation": snapshot.Generation, "outcome": "success", "state": "verified"})
	return nil
}

// StartupRecover resolves any interrupted local runtime transition using only
// nftables, systemd, /run state, and the durable LKG store. It never contacts
// the API and never emits an ACK; normal reconciliation reports state later.
func (r *Reconciler) StartupRecover(ctx context.Context) error {
	started := time.Now()
	r.log(ctx, "info", "startup_recovery_started", nil)
	err := r.startupRecover(ctx)
	outcome := "success"
	if err != nil {
		outcome = "failure"
		pending, applied := r.currentGeneration()
		r.setState(pending, applied, "failed")
	} else if current, loadErr := r.lkg.Load(); loadErr == nil {
		pending, _ := r.currentGeneration()
		r.setState(pending, current.Metadata.Generation, "unknown")
	}
	r.observeLKG("recovery", outcome)
	r.log(ctx, map[bool]string{true: "error", false: "info"}[err != nil], "startup_recovery_completed", map[string]any{"outcome": outcome, "duration_ms": time.Since(started)})
	return err
}

func (r *Reconciler) startupRecover(ctx context.Context) error { return r.recoverTransition(ctx) }

func (r *Reconciler) fail(ctx context.Context, snapshot domain.DesiredSnapshot, reason string, cause error) error {
	normalized := normalizeReason(reason)
	ackErr := r.control.Acknowledge(ctx, domain.AgentAck{
		Generation: snapshot.Generation, DesiredHash: snapshot.DesiredHash,
		Status: domain.DataPlaneFailed, ReasonCode: reason,
	})
	ackOutcome := "success"
	if ackErr != nil {
		ackOutcome = "failure"
	}
	r.log(ctx, map[bool]string{true: "error", false: "warn"}[ackErr != nil], "ack_completed", map[string]any{"generation": snapshot.Generation, "outcome": ackOutcome, "reason_code": normalized, "state": "failed"})
	return coded(normalized, errors.Join(cause, ackErr))
}

type reconcileCodedError struct {
	reason string
	err    error
}

func (e reconcileCodedError) Error() string { return e.err.Error() }
func (e reconcileCodedError) Unwrap() error { return e.err }
func coded(reason string, err error) error {
	return reconcileCodedError{reason: normalizeReason(reason), err: err}
}
func reasonOf(err error) string {
	var target reconcileCodedError
	if errors.As(err, &target) {
		return target.reason
	}
	return "other"
}
func normalizeReason(reason string) string {
	reason = strings.ToLower(reason)
	if reason == "rolled_back" {
		return reason
	}
	return boundedEnum(reason, allowedReasons)
}

func ackOutcome(err error) string {
	if err != nil {
		return "failure"
	}
	return "success"
}

func (r *Reconciler) log(ctx context.Context, level, event string, fields map[string]any) {
	if r.telemetry != nil {
		r.telemetry.Log(ctx, level, event, fields)
	}
}
func (r *Reconciler) observeNFT(operation, outcome string) {
	if r.telemetry != nil {
		r.telemetry.Metrics.ObserveNFT(operation, outcome)
	}
}
func (r *Reconciler) observeLKG(operation, outcome string) {
	if r.telemetry != nil {
		r.telemetry.Metrics.ObserveLKG(operation, outcome)
	}
}
func (r *Reconciler) observeForwarder(operation, outcome string) {
	if r.telemetry != nil {
		r.telemetry.Metrics.ObserveForwarder(operation, outcome)
	}
}
func (r *Reconciler) setState(pending, applied int64, state string) {
	if r.telemetry == nil {
		return
	}
	if applied < 0 {
		_, applied = r.telemetry.Metrics.Generation()
	}
	r.telemetry.SetState(pending, applied, state)
}

func (r *Reconciler) currentGeneration() (pending, applied int64) {
	if r.telemetry == nil {
		return 0, 0
	}
	return r.telemetry.Metrics.Generation()
}

func (r *Reconciler) recoverTransition(ctx context.Context) error {
	if err := r.dataPlane.VerifyBase(ctx); err != nil {
		return err
	}
	journal, err := r.lkg.LoadTransition()
	if errors.Is(err, ErrTransitionNotFound) {
		return r.forwarders.CleanupOrphans(ctx)
	}
	if err != nil {
		_, quarantineErr := r.quarantineDynamic(ctx)
		return errors.Join(err, quarantineErr)
	}
	if _, err := r.quarantineDynamic(ctx); err != nil {
		return fmt.Errorf("quarantine interrupted runtime transition: %w", err)
	}

	restoreErr := r.restoreJournalRuntimes(ctx, journal)
	if restoreErr == nil {
		restoreErr = r.verifyRuntimeRecords(ctx, journal.PreviousLKG.Metadata.Runtimes)
	}
	if restoreErr != nil {
		if failClosedErr := r.recoverJournalFailClosed(ctx, journal); failClosedErr != nil {
			return errors.Join(restoreErr, failClosedErr)
		}
		return nil
	}
	appliedHash, err := r.dataPlane.Rollback(ctx, journal.PreviousLKG.Rules)
	if err != nil {
		return fmt.Errorf("recover previous dynamic LKG: %w", err)
	}
	if isSHA256(journal.PreviousAppliedHash) && appliedHash != journal.PreviousAppliedHash {
		return fmt.Errorf("recovered previous dynamic LKG hash mismatch")
	}
	if err := r.lkg.Save(journal.PreviousLKG); err != nil {
		return fmt.Errorf("recover durable previous LKG: %w", err)
	}
	journal.Phase = TransitionRestored
	if err := r.lkg.SaveTransition(journal); err != nil {
		return err
	}
	if err := r.lkg.ClearTransition(); err != nil {
		return err
	}
	return r.forwarders.CleanupOrphans(ctx)
}

func (r *Reconciler) restoreJournalRuntimes(ctx context.Context, journal RuntimeTransitionJournal) error {
	var recoveryErrors []error
	for index := len(journal.Entries) - 1; index >= 0; index-- {
		entry := journal.Entries[index]
		if entry.RestorePath != "" {
			point := &RestorePoint{
				port: entry.Port, directory: entry.RestorePath, integrity: entry.RestoreIntegrity,
				old:  RuntimeRecord{MappingID: entry.OldMappingID, Port: entry.Port, SpecHash: entry.OldSpecHash},
				next: RuntimeRecord{MappingID: entry.MappingID, Port: entry.Port, SpecHash: entry.NewSpecHash},
			}
			if err := r.forwarders.Restore(ctx, point); err != nil {
				recoveryErrors = append(recoveryErrors, fmt.Errorf("recover previous forwarder port %d: %w", entry.Port, err))
			}
			continue
		}
		stopCtx, cancel := context.WithTimeout(ctx, r.config.DrainTimeout)
		err := r.forwarders.Stop(stopCtx, entry.Port)
		cancel()
		if err != nil {
			recoveryErrors = append(recoveryErrors, fmt.Errorf("remove interrupted added forwarder port %d: %w", entry.Port, err))
		}
	}
	return errors.Join(recoveryErrors...)
}

func (r *Reconciler) verifyRuntimeRecords(ctx context.Context, records []RuntimeRecord) error {
	for _, record := range records {
		ready, err := r.forwarders.Ready(ctx, record.Port)
		if err != nil || !ready {
			return fmt.Errorf("previous forwarder port %d is not ready", record.Port)
		}
		matches, err := r.forwarders.Matches(ctx, record)
		if err != nil || !matches {
			return fmt.Errorf("previous forwarder port %d does not match durable LKG", record.Port)
		}
	}
	return nil
}

func (r *Reconciler) recoverJournalFailClosed(ctx context.Context, journal RuntimeTransitionJournal) error {
	emptyHash, err := r.quarantineDynamic(ctx)
	if err != nil {
		return err
	}
	var stopErrors []error
	seen := map[int]struct{}{}
	ports := make([]int, 0, len(journal.Entries)+len(journal.PreviousLKG.Metadata.Runtimes))
	for _, entry := range journal.Entries {
		ports = append(ports, entry.Port)
	}
	for _, record := range journal.PreviousLKG.Metadata.Runtimes {
		ports = append(ports, record.Port)
	}
	for _, port := range ports {
		if _, exists := seen[port]; exists {
			continue
		}
		seen[port] = struct{}{}
		stopCtx, cancel := context.WithTimeout(ctx, r.config.DrainTimeout)
		err := r.forwarders.Stop(stopCtx, port)
		cancel()
		if err != nil {
			stopErrors = append(stopErrors, fmt.Errorf("stop unsafe runtime port %d: %w", port, err))
		}
	}
	if err := errors.Join(stopErrors...); err != nil {
		return err
	}
	emptyRules, err := renderCandidate(r.config, nil)
	if err != nil {
		return err
	}
	safe := makeLKG(domain.DesiredSnapshot{}, emptyRules, emptyHash, nil, nil)
	if err := r.lkg.Save(safe); err != nil {
		return fmt.Errorf("persist fail-close recovery LKG: %w", err)
	}
	if err := r.lkg.ClearTransition(); err != nil {
		return err
	}
	return r.forwarders.CleanupOrphans(ctx)
}

func (r *Reconciler) quarantineDynamic(ctx context.Context) (string, error) {
	emptyRules, err := renderCandidate(r.config, nil)
	if err != nil {
		return "", err
	}
	if err := r.dataPlane.Check(ctx, emptyRules); err != nil {
		return "", err
	}
	appliedHash, _, err := r.dataPlane.Apply(ctx, emptyRules, emptyRules)
	if err != nil {
		return "", err
	}
	return appliedHash, nil
}

func validateAndSelect(snapshot domain.DesiredSnapshot, config Config) ([]domain.AgentMapping, error) {
	ids := make(map[string]struct{}, len(snapshot.Mappings))
	clients := make(map[string]string)
	ports := make(map[int]string)
	active := make([]domain.AgentMapping, 0, len(snapshot.Mappings))
	for _, mapping := range snapshot.Mappings {
		if _, exists := ids[mapping.ID]; exists {
			return nil, fmt.Errorf("duplicate mapping id %q", mapping.ID)
		}
		ids[mapping.ID] = struct{}{}
		if mapping.DesiredState != domain.DesiredActive {
			continue
		}
		prefix, err := netip.ParsePrefix(mapping.ClientIPCIDR)
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 || prefix != prefix.Masked() {
			return nil, fmt.Errorf("mapping %q client must be a canonical IPv4 /32", mapping.ID)
		}
		if mapping.PolicyKind != domain.EgressPolicyWebOnly {
			return nil, fmt.Errorf("mapping %q policy %q is not enabled in P0", mapping.ID, mapping.PolicyKind)
		}
		if mapping.LocalRedirectPort < config.ForwarderPortStart || mapping.LocalRedirectPort > config.ForwarderPortEnd {
			return nil, fmt.Errorf("mapping %q redirect port is outside protected range", mapping.ID)
		}
		if prior, exists := clients[mapping.ClientIPCIDR]; exists {
			return nil, fmt.Errorf("active mappings %q and %q share a client", prior, mapping.ID)
		}
		if prior, exists := ports[mapping.LocalRedirectPort]; exists {
			return nil, fmt.Errorf("active mappings %q and %q share redirect port %d", prior, mapping.ID, mapping.LocalRedirectPort)
		}
		clients[mapping.ClientIPCIDR] = mapping.ID
		ports[mapping.LocalRedirectPort] = mapping.ID
		active = append(active, mapping)
	}
	sort.Slice(active, func(i, j int) bool { return active[i].ID < active[j].ID })
	return active, nil
}

func renderCandidate(config Config, active []domain.AgentMapping) (string, error) {
	views := make([]types.MappingView, 0, len(active))
	for _, mapping := range active {
		views = append(views, types.MappingView{
			ID: mapping.ID, Client: types.Client{ID: mapping.ID, IPCidr: mapping.ClientIPCIDR, Enabled: true},
			State: "APPLIED", LocalRedirectPort: mapping.LocalRedirectPort,
		})
	}
	return nft.RenderDynamic(nft.RenderConfig{
		LANInterface: config.LANInterface, WANInterface: config.WANInterface,
		ForwarderPortStart: config.ForwarderPortStart, ForwarderPortEnd: config.ForwarderPortEnd,
	}, views)
}

func (r *Reconciler) loadOrBootstrap(ctx context.Context) (LKG, error) {
	previous, err := r.lkg.Load()
	if err == nil {
		pending, _ := r.currentGeneration()
		r.setState(pending, previous.Metadata.Generation, "applying")
		return previous, nil
	}
	if !errors.Is(err, ErrLKGNotFound) {
		return LKG{}, err
	}
	empty, renderErr := renderCandidate(r.config, nil)
	if renderErr != nil {
		return LKG{}, renderErr
	}
	if err := r.dataPlane.Check(ctx, empty); err != nil {
		return LKG{}, fmt.Errorf("check fail-close bootstrap: %w", err)
	}
	appliedHash, _, err := r.dataPlane.Apply(ctx, empty, empty)
	if err != nil {
		return LKG{}, fmt.Errorf("apply fail-close bootstrap: %w", err)
	}
	bootstrap := makeLKG(domain.DesiredSnapshot{}, empty, appliedHash, nil, nil)
	if err := r.lkg.Save(bootstrap); err != nil {
		return LKG{}, err
	}
	pending, _ := r.currentGeneration()
	r.setState(pending, bootstrap.Metadata.Generation, "applying")
	return bootstrap, nil
}

type preparedForwarder struct {
	mapping   domain.AgentMapping
	record    RuntimeRecord
	restore   *RestorePoint
	added     bool
	replace   bool
	attempted bool
	activated bool
	journaled bool
}

type runtimeTransition struct {
	journal       RuntimeTransitionJournal
	quiescedRules string
	quarantined   bool
}

func (r *Reconciler) prepareForwarders(ctx context.Context, snapshot domain.DesiredSnapshot, active []domain.AgentMapping, previous LKG) ([]preparedForwarder, *runtimeTransition, error) {
	priorByID := recordsByID(previous.Metadata.Runtimes)
	priorByPort := recordsByPort(previous.Metadata.Runtimes)
	prepared := make([]preparedForwarder, 0, len(active))
	for _, mapping := range active {
		record := runtimeRecord(mapping)
		old, existed := priorByID[mapping.ID]
		durablyRepresented := existed && old == record
		if durablyRepresented {
			ready, err := r.forwarders.Ready(ctx, record.Port)
			if err == nil && ready {
				matches, matchErr := r.forwarders.Matches(ctx, record)
				if matchErr == nil && matches {
					continue
				}
			}
		}
		occupied, portOccupied := priorByPort[record.Port]
		step := preparedForwarder{
			mapping: mapping, record: record, added: !portOccupied, replace: portOccupied,
			journaled: !durablyRepresented,
		}
		if portOccupied && occupied != record {
			r.log(ctx, "info", "forwarder_capture_started", map[string]any{"generation": snapshot.Generation, "mapping_id": mapping.ID, "proxy_id": mapping.ProxyID})
			restore, err := r.forwarders.Capture(ctx, occupied, record)
			if err != nil {
				r.observeForwarder("capture", "failure")
				return prepared, nil, fmt.Errorf("mapping %q capture previous runtime: %w", mapping.ID, err)
			}
			r.observeForwarder("capture", "success")
			step.restore = restore
		}
		prepared = append(prepared, step)
	}

	var transition *runtimeTransition
	entries := make([]RuntimeTransitionEntry, 0, len(prepared))
	hasDestructiveReplacement := false
	for _, step := range prepared {
		if !step.journaled {
			continue
		}
		entry := RuntimeTransitionEntry{MappingID: step.record.MappingID, Port: step.record.Port, NewSpecHash: step.record.SpecHash}
		if step.restore != nil {
			hasDestructiveReplacement = true
			entry.OldMappingID = step.restore.old.MappingID
			entry.OldSpecHash = step.restore.old.SpecHash
			entry.RestorePath = step.restore.directory
			entry.RestoreIntegrity = step.restore.integrity
		}
		entries = append(entries, entry)
	}
	if len(entries) > 0 {
		journal := newTransitionJournal(snapshot.Generation, previous, entries)
		if err := r.lkg.SaveTransition(journal); err != nil {
			r.observeLKG("journal_save", "failure")
			return prepared, nil, fmt.Errorf("persist runtime transition before replacement: %w", err)
		}
		r.observeLKG("journal_save", "success")
		transition = &runtimeTransition{journal: journal}
		if hasDestructiveReplacement {
			quiescedRules, err := renderCandidate(r.config, nil)
			if err != nil {
				return prepared, transition, err
			}
			transition.quiescedRules = quiescedRules
			if err := r.dataPlane.Check(ctx, quiescedRules); err != nil {
				r.observeNFT("quarantine", "failure")
				return prepared, transition, fmt.Errorf("check fail-close transition rules: %w", err)
			}
			if _, _, err := r.dataPlane.Apply(ctx, quiescedRules, previous.Rules); err != nil {
				r.observeNFT("quarantine", "failure")
				return prepared, transition, fmt.Errorf("remove redirects before runtime replacement: %w", err)
			}
			r.observeNFT("quarantine", "success")
			transition.quarantined = true
			transition.journal.Phase = TransitionRedirectsRemoved
			if err := r.lkg.SaveTransition(transition.journal); err != nil {
				r.observeLKG("journal_save", "failure")
				return prepared, transition, fmt.Errorf("persist redirect-removal transition: %w", err)
			}
			r.observeLKG("journal_save", "success")
		}
	}

	for index := range prepared {
		step := &prepared[index]
		mapping := step.mapping
		credential, err := r.control.FetchCredential(ctx, mapping.ID)
		if err != nil {
			return prepared, transition, fmt.Errorf("mapping %q credential: %w", mapping.ID, err)
		}
		if err := domain.ValidateAgentCredential(mapping, credential); err != nil {
			zero(credential.Password)
			return prepared, transition, fmt.Errorf("mapping %q credential validation: %w", mapping.ID, err)
		}
		step.attempted = true
		operation := "start"
		if step.replace {
			operation = "restart"
		}
		r.log(ctx, "info", "forwarder_prepare_started", map[string]any{"generation": snapshot.Generation, "mapping_id": mapping.ID, "proxy_id": mapping.ProxyID, "state": operation})
		err = r.forwarders.Activate(ctx, mapping, credential, step.replace)
		zero(credential.Password)
		if err != nil {
			return prepared, transition, fmt.Errorf("mapping %q forwarder: %w", mapping.ID, err)
		}
		r.log(ctx, "info", "forwarder_ready", map[string]any{"generation": snapshot.Generation, "mapping_id": mapping.ID, "proxy_id": mapping.ProxyID, "outcome": "success"})
		step.activated = true
	}
	if transition != nil {
		transition.journal.Phase = TransitionForwardersChanged
		if err := r.lkg.SaveTransition(transition.journal); err != nil {
			r.observeLKG("journal_save", "failure")
			return prepared, transition, fmt.Errorf("persist forwarder replacement transition: %w", err)
		}
		r.observeLKG("journal_save", "success")
	}
	return prepared, transition, nil
}

func (r *Reconciler) rollbackPrepared(ctx context.Context, prepared []preparedForwarder) error {
	var rollbackErrors []error
	for index := len(prepared) - 1; index >= 0; index-- {
		step := prepared[index]
		if step.restore != nil {
			if step.attempted {
				if err := r.forwarders.Restore(ctx, step.restore); err != nil {
					r.observeForwarder("restore", "failure")
					rollbackErrors = append(rollbackErrors, fmt.Errorf("restore forwarder port %d: %w", step.record.Port, err))
				} else {
					r.observeForwarder("restore", "success")
				}
			} else if err := r.forwarders.Discard(step.restore); err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("discard unused restore point for port %d: %w", step.record.Port, err))
			}
			continue
		}
		if step.added && step.attempted {
			r.observeForwarder("drain", "success")
			stopCtx, cancel := context.WithTimeout(ctx, r.config.DrainTimeout)
			err := r.forwarders.Stop(stopCtx, step.record.Port)
			cancel()
			if err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("stop orphan forwarder port %d: %w", step.record.Port, err))
			}
		}
	}
	return errors.Join(rollbackErrors...)
}

func (r *Reconciler) discardPrepared(prepared []preparedForwarder) error {
	var discardErrors []error
	for _, step := range prepared {
		if step.restore != nil {
			if err := r.forwarders.Discard(step.restore); err != nil {
				discardErrors = append(discardErrors, err)
			}
		}
	}
	return errors.Join(discardErrors...)
}

func (r *Reconciler) rollbackReconcile(ctx context.Context, prepared []preparedForwarder, transition *runtimeTransition, previous LKG) error {
	if transition == nil {
		return r.rollbackPrepared(ctx, prepared)
	}
	var rollbackErrors []error
	if transition.quiescedRules == "" {
		var err error
		transition.quiescedRules, err = renderCandidate(r.config, nil)
		if err != nil {
			rollbackErrors = append(rollbackErrors, err)
		}
	}
	if transition.quiescedRules != "" {
		if _, err := r.dataPlane.Rollback(ctx, transition.quiescedRules); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("quarantine redirects before runtime rollback: %w", err))
		}
	}
	if len(rollbackErrors) == 0 {
		if err := r.rollbackPrepared(ctx, prepared); err != nil {
			rollbackErrors = append(rollbackErrors, err)
		}
	}
	if len(rollbackErrors) == 0 {
		if err := r.verifyRuntimeRecords(ctx, previous.Metadata.Runtimes); err != nil {
			rollbackErrors = append(rollbackErrors, err)
		}
	}
	if len(rollbackErrors) == 0 {
		appliedHash, err := r.dataPlane.Rollback(ctx, previous.Rules)
		if err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("restore previous dynamic LKG: %w", err))
		} else if isSHA256(previous.Metadata.AppliedHash) && appliedHash != previous.Metadata.AppliedHash {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("restored dynamic LKG hash mismatch"))
		}
	}
	if len(rollbackErrors) == 0 {
		if err := r.lkg.Save(previous); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("restore durable previous LKG: %w", err))
		}
	}
	if len(rollbackErrors) == 0 {
		transition.journal.Phase = TransitionRestored
		if err := r.lkg.SaveTransition(transition.journal); err != nil {
			rollbackErrors = append(rollbackErrors, err)
		}
	}
	if len(rollbackErrors) == 0 {
		if err := r.lkg.ClearTransition(); err != nil {
			rollbackErrors = append(rollbackErrors, err)
		}
	}
	if len(rollbackErrors) == 0 {
		if err := r.forwarders.CleanupOrphans(ctx); err != nil {
			rollbackErrors = append(rollbackErrors, err)
		}
	}
	return errors.Join(rollbackErrors...)
}

func (r *Reconciler) rollbackCommittedWithoutTransition(ctx context.Context, prepared []preparedForwarder, previous LKG) error {
	var rollbackErrors []error
	if err := r.verifyRuntimeRecords(ctx, previous.Metadata.Runtimes); err != nil {
		rollbackErrors = append(rollbackErrors, err)
	}
	if len(rollbackErrors) == 0 {
		appliedHash, err := r.dataPlane.Rollback(ctx, previous.Rules)
		if err != nil {
			rollbackErrors = append(rollbackErrors, err)
		} else if isSHA256(previous.Metadata.AppliedHash) && appliedHash != previous.Metadata.AppliedHash {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("restored dynamic LKG hash mismatch"))
		}
	}
	if err := r.rollbackPrepared(ctx, prepared); err != nil {
		rollbackErrors = append(rollbackErrors, err)
	}
	if len(rollbackErrors) == 0 {
		if err := r.lkg.Save(previous); err != nil {
			rollbackErrors = append(rollbackErrors, err)
		}
	}
	return errors.Join(rollbackErrors...)
}

func (r *Reconciler) finalizePrepared(ctx context.Context, prepared []preparedForwarder, transition *runtimeTransition) error {
	if err := r.discardPrepared(prepared); err != nil {
		return err
	}
	if transition != nil {
		if err := r.lkg.ClearTransition(); err != nil {
			return err
		}
	}
	return r.forwarders.CleanupOrphans(ctx)
}

func (r *Reconciler) stopRecords(ctx context.Context, records []RuntimeRecord) []RuntimeRecord {
	failed := make([]RuntimeRecord, 0)
	seen := map[int]struct{}{}
	for _, record := range records {
		if _, exists := seen[record.Port]; exists {
			continue
		}
		seen[record.Port] = struct{}{}
		r.log(ctx, "info", "forwarder_drain_started", map[string]any{"mapping_id": record.MappingID, "state": "draining"})
		stopCtx, cancel := context.WithTimeout(ctx, r.config.DrainTimeout)
		r.observeForwarder("drain", "success")
		err := r.forwarders.Stop(stopCtx, record.Port)
		cancel()
		if err != nil {
			r.log(ctx, "error", "forwarder_stop_completed", map[string]any{"mapping_id": record.MappingID, "outcome": "failure", "reason_code": "forwarder_drain_incomplete"})
			failed = append(failed, record)
		} else {
			r.log(ctx, "info", "forwarder_stop_completed", map[string]any{"mapping_id": record.MappingID, "outcome": "success"})
		}
	}
	return failed
}

func makeLKG(snapshot domain.DesiredSnapshot, rules, appliedHash string, runtimes, pending []RuntimeRecord) LKG {
	return LKG{Rules: rules, Metadata: LKGMetadata{
		Version: lkgVersion, Generation: snapshot.Generation, DesiredHash: snapshot.DesiredHash,
		AppliedHash: appliedHash, RulesSHA256: scriptHash(rules),
		Runtimes: append([]RuntimeRecord(nil), runtimes...), PendingStops: append([]RuntimeRecord(nil), pending...),
	}}
}

func runtimeRecords(mappings []domain.AgentMapping) []RuntimeRecord {
	records := make([]RuntimeRecord, 0, len(mappings))
	for _, mapping := range mappings {
		records = append(records, runtimeRecord(mapping))
	}
	return records
}

func runtimeRecord(mapping domain.AgentMapping) RuntimeRecord {
	canonical, _ := json.Marshal(struct {
		ID, ProxyID, ProxyType, ProxyHost string
		ProxyPort, LocalPort              int
		ProxyRevision, CredentialRevision int64
	}{mapping.ID, mapping.ProxyID, string(mapping.ProxyType), mapping.ProxyHost, mapping.ProxyPort, mapping.LocalRedirectPort, mapping.ProxyRevision, mapping.CredentialRevision})
	return RuntimeRecord{MappingID: mapping.ID, Port: mapping.LocalRedirectPort, SpecHash: scriptHash(string(canonical))}
}

func removedRuntimes(previous LKGMetadata, current []RuntimeRecord) []RuntimeRecord {
	keep := recordsByID(current)
	keepPorts := recordsByPort(current)
	removed := append([]RuntimeRecord(nil), previous.PendingStops...)
	for _, record := range previous.Runtimes {
		if _, reused := keepPorts[record.Port]; reused {
			continue
		}
		if wanted, exists := keep[record.MappingID]; !exists || wanted.Port != record.Port {
			removed = append(removed, record)
		}
	}
	sort.Slice(removed, func(i, j int) bool { return removed[i].Port < removed[j].Port })
	return removed
}

func recordsByID(records []RuntimeRecord) map[string]RuntimeRecord {
	result := make(map[string]RuntimeRecord, len(records))
	for _, record := range records {
		result[record.MappingID] = record
	}
	return result
}

func recordsByPort(records []RuntimeRecord) map[int]RuntimeRecord {
	result := make(map[int]RuntimeRecord, len(records))
	for _, record := range records {
		result[record.Port] = record
	}
	return result
}

func scriptHash(value string) string {
	hash := sha256.Sum256([]byte(strings.ReplaceAll(value, "\r\n", "\n")))
	return hex.EncodeToString(hash[:])
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
