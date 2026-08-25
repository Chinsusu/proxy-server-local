// Package domain contains the control-plane model shared by persistence and
// future API/agent adapters. It deliberately has no transport-specific types.
package domain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

type ProxyType string

const (
	ProxyHTTP   ProxyType = "http"
	ProxySOCKS5 ProxyType = "socks5"
)

func (t ProxyType) Valid() bool { return t == ProxyHTTP || t == ProxySOCKS5 }

type ProxyStatus string

const (
	ProxyStatusOK       ProxyStatus = "OK"
	ProxyStatusDegraded ProxyStatus = "DEGRADED"
	ProxyStatusDown     ProxyStatus = "DOWN"
)

type DesiredState string

const (
	DesiredDraft     DesiredState = "DRAFT"
	DesiredActive    DesiredState = "ACTIVE"
	DesiredSuspended DesiredState = "SUSPENDED"
	DesiredDeleted   DesiredState = "DELETED"
)

func (s DesiredState) Valid() bool {
	return s == DesiredDraft || s == DesiredActive || s == DesiredSuspended || s == DesiredDeleted
}

type DataPlaneState string

const (
	DataPlaneVerified DataPlaneState = "VERIFIED"
	DataPlaneUnknown  DataPlaneState = "UNKNOWN"
	DataPlaneFailed   DataPlaneState = "FAILED"
)

func (s DataPlaneState) Valid() bool {
	return s == DataPlaneVerified || s == DataPlaneUnknown || s == DataPlaneFailed
}

type EgressPolicyKind string

const EgressPolicyWebOnly EgressPolicyKind = "web_only"

func (p EgressPolicyKind) Valid() bool { return p == EgressPolicyWebOnly }

// IPv6Policy is an explicit part of the desired data-plane contract. PGW P0
// has no IPv6 forwarding capability: the sole valid value is deny. Keeping
// this in the signed snapshot prevents a permissive default from appearing
// when configuration or a future schema evolves.
type IPv6Policy string

const IPv6PolicyDeny IPv6Policy = "deny"

func (p IPv6Policy) Valid() bool { return p == IPv6PolicyDeny }

func NormalizeIPv6Policy(value string) (IPv6Policy, error) {
	policy := IPv6Policy(strings.TrimSpace(value))
	if !policy.Valid() {
		return "", &ValidationError{Field: "ipv6_policy", Message: "must be deny"}
	}
	return policy, nil
}

// Proxy is a public/read model. It never includes a password or encrypted
// ciphertext; callers can only learn whether a password has been configured.
type Proxy struct {
	ID                 string      `json:"id"`
	Label              string      `json:"label,omitempty"`
	Type               ProxyType   `json:"type"`
	Host               string      `json:"host"`
	Port               int         `json:"port"`
	Username           string      `json:"username,omitempty"`
	PasswordConfigured bool        `json:"password_configured"`
	Enabled            bool        `json:"enabled"`
	Status             ProxyStatus `json:"status"`
	LatencyMS          *int        `json:"latency_ms,omitempty"`
	ExitIP             string      `json:"exit_ip,omitempty"`
	LastCheckedAt      *time.Time  `json:"last_checked_at,omitempty"`
	Version            int64       `json:"version"`
	ProxyRevision      int64       `json:"proxy_revision"`
	CredentialRevision int64       `json:"credential_revision"`
	CreatedAt          time.Time   `json:"created_at"`
	UpdatedAt          time.Time   `json:"updated_at"`
}

type ProxyCredential struct {
	ProxyID  string `json:"-"`
	Username string `json:"-"`
	Password []byte `json:"-"`
}

type Client struct {
	ID        string    `json:"id"`
	IPCIDR    string    `json:"ip_cidr"`
	Note      string    `json:"note,omitempty"`
	Enabled   bool      `json:"enabled"`
	Version   int64     `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type EgressPolicy struct {
	ID        string           `json:"id"`
	Name      string           `json:"name"`
	Kind      EgressPolicyKind `json:"kind"`
	Enabled   bool             `json:"enabled"`
	Version   int64            `json:"version"`
	CreatedAt time.Time        `json:"created_at"`
	UpdatedAt time.Time        `json:"updated_at"`
}

type Mapping struct {
	ID                string         `json:"id"`
	ClientID          string         `json:"client_id"`
	ProxyID           string         `json:"proxy_id"`
	PolicyID          string         `json:"policy_id"`
	LocalRedirectPort int            `json:"local_redirect_port"`
	DesiredState      DesiredState   `json:"desired_state"`
	DesiredGeneration int64          `json:"desired_generation"`
	AppliedGeneration int64          `json:"applied_generation"`
	DesiredHash       string         `json:"desired_hash,omitempty"`
	AppliedHash       string         `json:"applied_hash,omitempty"`
	DataPlaneState    DataPlaneState `json:"data_plane_state"`
	Version           int64          `json:"version"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
}

type Node struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	TokenID   string    `json:"token_id,omitempty"`
	Enabled   bool      `json:"enabled"`
	Version   int64     `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type ReconcileState struct {
	NodeID            string    `json:"node_id"`
	PendingGeneration int64     `json:"pending_generation"`
	AppliedGeneration int64     `json:"applied_generation"`
	RulesetHash       string    `json:"ruleset_hash,omitempty"`
	State             string    `json:"state"`
	LastError         string    `json:"last_error,omitempty"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type AuditEvent struct {
	ID        int64           `json:"id"`
	Actor     string          `json:"actor,omitempty"`
	Action    string          `json:"action"`
	Entity    string          `json:"entity"`
	EntityID  string          `json:"entity_id,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

// AgentMapping is the non-secret desired-data-plane contract. It is shared by
// the API and Agent so the Agent can independently verify a snapshot before it
// touches nftables or a forwarder. Credentials are deliberately absent.
type AgentMapping struct {
	ID                 string           `json:"id"`
	ClientIPCIDR       string           `json:"client_ip_cidr"`
	ProxyID            string           `json:"proxy_id"`
	ProxyType          ProxyType        `json:"proxy_type"`
	ProxyHost          string           `json:"proxy_host"`
	ProxyPort          int              `json:"proxy_port"`
	ProxyRevision      int64            `json:"proxy_revision"`
	CredentialRevision int64            `json:"credential_revision"`
	LocalRedirectPort  int              `json:"local_redirect_port"`
	PolicyKind         EgressPolicyKind `json:"policy_kind"`
	DesiredState       DesiredState     `json:"desired_state"`
}

// DesiredSnapshot is immutable for a generation. DesiredHash is SHA-256 over
// the canonical contract described by desiredSnapshotHashInput; it is not part
// of its own preimage.
type DesiredSnapshot struct {
	Generation  int64          `json:"generation"`
	DesiredHash string         `json:"desired_hash"`
	IPv6Policy  IPv6Policy     `json:"ipv6_policy"`
	Mappings    []AgentMapping `json:"mappings"`
}

// AgentCredential is transport-only data returned to the privileged Agent via
// a Unix socket. It must never be marshalled into an audit event, log, or
// public API response.
type AgentCredential struct {
	MappingID          string `json:"mapping_id"`
	ProxyID            string `json:"proxy_id"`
	ProxyRevision      int64  `json:"proxy_revision"`
	CredentialRevision int64  `json:"credential_revision"`
	AuthConfigured     bool   `json:"auth_configured"`
	Username           string `json:"username"`
	Password           []byte `json:"password"`
}

// AgentAck is the Agent's report for a single desired generation. FAILED and
// UNKNOWN ACKs record the data-plane outcome but never advance applied state.
type AgentAck struct {
	Generation  int64          `json:"generation"`
	DesiredHash string         `json:"desired_hash"`
	AppliedHash string         `json:"applied_hash,omitempty"`
	Status      DataPlaneState `json:"status"`
	ReasonCode  string         `json:"reason_code,omitempty"`
}

type desiredSnapshotHashInput struct {
	Generation int64          `json:"generation"`
	IPv6Policy IPv6Policy     `json:"ipv6_policy"`
	Mappings   []AgentMapping `json:"mappings"`
}

// BuildDesiredSnapshot uses an ordered struct (not a map) and mapping ID sort
// so the JSON byte stream and lower-case hexadecimal SHA-256 are stable across
// API and Agent processes.
func BuildDesiredSnapshot(generation int64, mappings []AgentMapping) (DesiredSnapshot, error) {
	return BuildDesiredSnapshotWithIPv6Policy(generation, IPv6PolicyDeny, mappings)
}

// BuildDesiredSnapshotWithIPv6Policy is the canonical signed contract used
// by the API and Agent. It rejects any future permissive policy until there is
// a separately designed IPv6 data plane.
func BuildDesiredSnapshotWithIPv6Policy(generation int64, ipv6Policy IPv6Policy, mappings []AgentMapping) (DesiredSnapshot, error) {
	if generation < 0 {
		return DesiredSnapshot{}, &ValidationError{Field: "generation", Message: "must not be negative"}
	}
	if !ipv6Policy.Valid() {
		return DesiredSnapshot{}, &ValidationError{Field: "ipv6_policy", Message: "must be deny"}
	}
	copyMappings := append([]AgentMapping(nil), mappings...)
	sort.Slice(copyMappings, func(i, j int) bool { return copyMappings[i].ID < copyMappings[j].ID })
	for _, mapping := range copyMappings {
		if err := ValidateAgentMapping(mapping); err != nil {
			return DesiredSnapshot{}, err
		}
	}
	canonical, err := json.Marshal(desiredSnapshotHashInput{Generation: generation, IPv6Policy: ipv6Policy, Mappings: copyMappings})
	if err != nil {
		return DesiredSnapshot{}, fmt.Errorf("canonical desired snapshot: %w", err)
	}
	hash := sha256.Sum256(canonical)
	return DesiredSnapshot{Generation: generation, DesiredHash: hex.EncodeToString(hash[:]), IPv6Policy: ipv6Policy, Mappings: copyMappings}, nil
}

func ValidateDesiredSnapshot(snapshot DesiredSnapshot) error {
	canonical, err := BuildDesiredSnapshotWithIPv6Policy(snapshot.Generation, snapshot.IPv6Policy, snapshot.Mappings)
	if err != nil {
		return err
	}
	if snapshot.DesiredHash == "" || snapshot.DesiredHash != canonical.DesiredHash {
		return &ConflictError{Constraint: "desired_hash", Message: "desired snapshot hash does not match canonical content"}
	}
	return nil
}

// NormalizeIPv4HostCIDR rejects non-host CIDRs. Legacy state imports and all
// future write paths must use this so an accidentally broad network cannot be
// redirected through a mapping.
func NormalizeIPv4HostCIDR(value string) (string, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return "", &ValidationError{Field: "ip_cidr", Message: "is required"}
	}
	if !strings.Contains(v, "/") {
		v += "/32"
	}
	prefix, err := netip.ParsePrefix(v)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 {
		return "", &ValidationError{Field: "ip_cidr", Message: "must be an IPv4 /32 host CIDR"}
	}
	return prefix.Masked().String(), nil
}

func ValidateProxy(t ProxyType, host string, port int) error {
	if !t.Valid() {
		return &ValidationError{Field: "type", Message: "must be http or socks5"}
	}
	if err := ValidateProxyHost(host); err != nil {
		return err
	}
	if port < 1 || port > 65535 {
		return &ValidationError{Field: "port", Message: "must be between 1 and 65535"}
	}
	return nil
}

// ValidateProxyAuthentication keeps endpoint creation, Agent credential
// retrieval, and Forwarder startup on one explicit optional-auth contract.
// An authentication record exists only when configured is true; an empty
// password is valid, but a configured credential always has a username.
func ValidateProxyAuthentication(proxyType ProxyType, username string, password []byte, configured bool) error {
	if !configured {
		if username != "" || len(password) != 0 {
			return &ValidationError{Field: "credential", Message: "no-auth proxy must not contain username or password"}
		}
		return nil
	}
	if username == "" {
		return &ValidationError{Field: "username", Message: "is required when authentication is configured"}
	}
	// systemd credential files and the Forwarder reject NUL because it can
	// truncate or invalidate secret transport. Keep this at the shared domain
	// boundary so HTTP/SOCKS credentials cannot be committed and later fail at
	// forwarder readiness. Other controls remain allowed in credentials because
	// they are opaque authentication bytes and the Forwarder preserves them.
	if strings.IndexByte(username, 0) >= 0 || bytes.IndexByte(password, 0) >= 0 {
		return &ValidationError{Field: "credential", Message: "must not contain NUL bytes"}
	}
	max := 4096
	if proxyType == ProxySOCKS5 {
		max = 255
	}
	if len(username) > max || len(password) > max {
		return &ValidationError{Field: "credential", Message: "exceeds proxy authentication size limit"}
	}
	return nil
}

const (
	ForwarderPortStart = 15001
	ForwarderPortEnd   = 15999
)

func ValidateControlID(field, value string) error {
	if len(value) == 0 || len(value) > 128 {
		return &ValidationError{Field: field, Message: "must be 1 to 128 characters from [A-Za-z0-9_-]"}
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '_' || character == '-' {
			continue
		}
		return &ValidationError{Field: field, Message: "must be 1 to 128 characters from [A-Za-z0-9_-]"}
	}
	return nil
}

func ValidateProxyHost(host string) error {
	if host == "" || strings.TrimSpace(host) != host || len(host) > 253 {
		return &ValidationError{Field: "host", Message: "must be a non-empty host up to 253 bytes without surrounding whitespace"}
	}
	for _, character := range host {
		if character <= 0x20 || character == 0x7f || character == '/' || character == '\\' || character == '@' {
			return &ValidationError{Field: "host", Message: "must not contain whitespace, control characters, or endpoint delimiters"}
		}
	}
	return nil
}

func ValidateAgentMapping(mapping AgentMapping) error {
	if err := ValidateControlID("mapping_id", mapping.ID); err != nil {
		return err
	}
	if err := ValidateControlID("proxy_id", mapping.ProxyID); err != nil {
		return err
	}
	if mapping.ClientIPCIDR == "" || !mapping.ProxyType.Valid() || !mapping.PolicyKind.Valid() || !mapping.DesiredState.Valid() {
		return &ValidationError{Field: "snapshot", Message: "contains an invalid mapping"}
	}
	if err := ValidateProxy(mapping.ProxyType, mapping.ProxyHost, mapping.ProxyPort); err != nil {
		return err
	}
	if mapping.LocalRedirectPort < ForwarderPortStart || mapping.LocalRedirectPort > ForwarderPortEnd {
		return &ValidationError{Field: "local_redirect_port", Message: "must be between 15001 and 15999"}
	}
	if mapping.ProxyRevision < 1 || mapping.CredentialRevision < 1 {
		return &ValidationError{Field: "snapshot", Message: "requires proxy and credential revisions"}
	}
	return nil
}

func ValidateAgentCredential(mapping AgentMapping, credential AgentCredential) error {
	if credential.MappingID != mapping.ID || credential.ProxyID != mapping.ProxyID || credential.ProxyRevision != mapping.ProxyRevision || credential.CredentialRevision != mapping.CredentialRevision {
		return &ConflictError{Constraint: "credential_revision", Message: "credential does not match mapping revision"}
	}
	return ValidateProxyAuthentication(mapping.ProxyType, credential.Username, credential.Password, credential.AuthConfigured)
}

type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	if e.Field == "" {
		return "validation: " + e.Message
	}
	return fmt.Sprintf("validation: %s %s", e.Field, e.Message)
}

type NotFoundError struct {
	Entity string
	ID     string
}

func (e *NotFoundError) Error() string { return fmt.Sprintf("%s %q not found", e.Entity, e.ID) }

type ConflictError struct {
	Constraint string
	Message    string
}

func (e *ConflictError) Error() string {
	if e.Message != "" {
		return "conflict: " + e.Message
	}
	return "conflict: " + e.Constraint
}
