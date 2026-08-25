// Package agent implements the privileged PGW reconciliation state machine.
// It contains no HTTP handlers and invokes neither nft nor systemd directly;
// production adapters live in cmd/agent and tests use deterministic fakes.
package agent

import (
	"context"
	"errors"

	"github.com/Chinsusu/proxy-server-local/internal/domain"
)

var ErrLKGNotFound = errors.New("agent: last-known-good ruleset not found")
var ErrTransitionNotFound = errors.New("agent: runtime transition journal not found")

// ControlPlane is the narrow, authenticated API available to the Agent. Every
// method must use the protected Unix socket; no internal Agent endpoint is
// permitted over TCP.
type ControlPlane interface {
	FetchLatest(context.Context) (domain.DesiredSnapshot, error)
	FetchSnapshot(context.Context, int64) (domain.DesiredSnapshot, error)
	FetchCredential(context.Context, string) (domain.AgentCredential, error)
	Acknowledge(context.Context, domain.AgentAck) error
}

// DataPlane owns only inet pgw_dynamic. VerifyBase must be read-only and every
// implementation must leave inet pgw_base untouched, including rollback.
type DataPlane interface {
	VerifyBase(context.Context) error
	Check(context.Context, string) error
	Apply(context.Context, string, string) (appliedHash string, rolledBack bool, err error)
	Rollback(context.Context, string) (appliedHash string, err error)
}

// Forwarders manages per-port pgw-fwd systemd units. Activate returns only
// after systemd reports ActiveState=active and SubState=running following the
// unit's Type=notify READY=1 transition. It must never probe the TCP listener.
type Forwarders interface {
	Ready(context.Context, int) (bool, error)
	Matches(context.Context, RuntimeRecord) (bool, error)
	Capture(context.Context, RuntimeRecord, RuntimeRecord) (*RestorePoint, error)
	Activate(context.Context, domain.AgentMapping, domain.AgentCredential, bool) error
	Restore(context.Context, *RestorePoint) error
	Discard(*RestorePoint) error
	CleanupOrphans(context.Context) error
	Stop(context.Context, int) error
}

// RestorePoint is opaque outside package agent. It refers to short-lived,
// mode-protected runtime material under /run/pgw and is never serialized into
// LKG metadata, logs, API responses, or process arguments.
type RestorePoint struct {
	port      int
	directory string
	old       RuntimeRecord
	next      RuntimeRecord
	integrity string
}

type LKGStore interface {
	Load() (LKG, error)
	Save(LKG) error
	LoadTransition() (RuntimeTransitionJournal, error)
	SaveTransition(RuntimeTransitionJournal) error
	ClearTransition() error
}

type RuntimeRecord struct {
	MappingID string `json:"mapping_id"`
	Port      int    `json:"port"`
	SpecHash  string `json:"spec_hash"`
}

// LKG contains no credentials. Rules is the complete add-only pgw_dynamic nft
// script and Metadata is integrity-bound to it by RulesSHA256.
type LKG struct {
	Rules    string      `json:"rules"`
	Metadata LKGMetadata `json:"metadata"`
}

type LKGMetadata struct {
	Version      int             `json:"version"`
	Generation   int64           `json:"generation"`
	DesiredHash  string          `json:"desired_hash"`
	AppliedHash  string          `json:"applied_hash"`
	RulesSHA256  string          `json:"rules_sha256"`
	Runtimes     []RuntimeRecord `json:"runtimes"`
	PendingStops []RuntimeRecord `json:"pending_stops,omitempty"`
}
