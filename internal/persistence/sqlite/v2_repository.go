package sqlite

// This file contains the API/Agent-facing repository operations. Keeping them
// here (rather than letting HTTP handlers issue SQL) is intentional: every
// desired-state mutation, generation bump, and audit row has one transaction
// boundary and the Agent only sees immutable snapshots.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/Chinsusu/proxy-server-local/internal/domain"
)

type Page[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

type PatchProxyInput struct {
	Label              *string
	Type               *domain.ProxyType
	Host               *string
	Port               *int
	Enabled            *bool
	Username           *string
	Password           *[]byte
	PasswordConfigured *bool
	Actor              string
}

type PatchClientInput struct {
	Note    *string
	Enabled *bool
	Actor   string
}

type PatchMappingInput struct {
	LocalRedirectPort *int
	PolicyID          *string
	Actor             string
}

func pageLimit(limit int) int {
	if limit <= 0 {
		return 50
	}
	if limit > 200 {
		return 200
	}
	return limit
}

func (r *Repository) ListProxiesPage(ctx context.Context, after string, limit int) (Page[domain.Proxy], error) {
	limit = pageLimit(limit)
	rows, err := r.db.QueryContext(ctx, proxySelect+` WHERE p.deleted_at IS NULL AND p.id > ? ORDER BY p.id LIMIT ?`, after, limit+1)
	if err != nil {
		return Page[domain.Proxy]{}, fmt.Errorf("sqlite: list proxies page: %w", err)
	}
	defer rows.Close()
	result := Page[domain.Proxy]{Items: make([]domain.Proxy, 0, limit)}
	for rows.Next() {
		item, err := scanProxy(rows, "")
		if err != nil {
			return Page[domain.Proxy]{}, err
		}
		if len(result.Items) == limit {
			result.NextCursor = item.ID
			break
		}
		result.Items = append(result.Items, item)
	}
	if err := rows.Err(); err != nil {
		return Page[domain.Proxy]{}, fmt.Errorf("sqlite: iterate proxy page: %w", err)
	}
	if result.NextCursor != "" && len(result.Items) > 0 {
		result.NextCursor = result.Items[len(result.Items)-1].ID
	}
	return result, nil
}

func (r *Repository) GetClient(ctx context.Context, id string) (domain.Client, error) {
	return scanClient(r.db.QueryRowContext(ctx, `SELECT id, ip_cidr, note, enabled, version, created_at, updated_at FROM clients WHERE id = ? AND deleted_at IS NULL`, id), id)
}

func (r *Repository) ListClientsPage(ctx context.Context, after string, limit int) (Page[domain.Client], error) {
	limit = pageLimit(limit)
	rows, err := r.db.QueryContext(ctx, `SELECT id, ip_cidr, note, enabled, version, created_at, updated_at FROM clients WHERE deleted_at IS NULL AND id > ? ORDER BY id LIMIT ?`, after, limit+1)
	if err != nil {
		return Page[domain.Client]{}, fmt.Errorf("sqlite: list clients page: %w", err)
	}
	defer rows.Close()
	result := Page[domain.Client]{Items: make([]domain.Client, 0, limit)}
	for rows.Next() {
		item, err := scanClient(rows, "")
		if err != nil {
			return Page[domain.Client]{}, err
		}
		if len(result.Items) == limit {
			result.NextCursor = item.ID
			break
		}
		result.Items = append(result.Items, item)
	}
	if err := rows.Err(); err != nil {
		return Page[domain.Client]{}, fmt.Errorf("sqlite: iterate client page: %w", err)
	}
	if result.NextCursor != "" && len(result.Items) > 0 {
		result.NextCursor = result.Items[len(result.Items)-1].ID
	}
	return result, nil
}

func (r *Repository) ListMappingsPage(ctx context.Context, after string, limit int) (Page[domain.Mapping], error) {
	limit = pageLimit(limit)
	rows, err := r.db.QueryContext(ctx, mappingSelect+` WHERE id > ? ORDER BY id LIMIT ?`, after, limit+1)
	if err != nil {
		return Page[domain.Mapping]{}, fmt.Errorf("sqlite: list mappings page: %w", err)
	}
	defer rows.Close()
	result := Page[domain.Mapping]{Items: make([]domain.Mapping, 0, limit)}
	for rows.Next() {
		item, err := scanMapping(rows, "")
		if err != nil {
			return Page[domain.Mapping]{}, err
		}
		if len(result.Items) == limit {
			result.NextCursor = item.ID
			break
		}
		result.Items = append(result.Items, item)
	}
	if err := rows.Err(); err != nil {
		return Page[domain.Mapping]{}, fmt.Errorf("sqlite: iterate mapping page: %w", err)
	}
	if result.NextCursor != "" && len(result.Items) > 0 {
		result.NextCursor = result.Items[len(result.Items)-1].ID
	}
	return result, nil
}

func (r *Repository) GetPolicy(ctx context.Context, id string) (domain.EgressPolicy, error) {
	return scanPolicy(r.db.QueryRowContext(ctx, `SELECT id, name, kind, enabled, version, created_at, updated_at FROM egress_policies WHERE id = ?`, id), id)
}

func (r *Repository) ListPoliciesPage(ctx context.Context, after string, limit int) (Page[domain.EgressPolicy], error) {
	limit = pageLimit(limit)
	rows, err := r.db.QueryContext(ctx, `SELECT id, name, kind, enabled, version, created_at, updated_at FROM egress_policies WHERE id > ? ORDER BY id LIMIT ?`, after, limit+1)
	if err != nil {
		return Page[domain.EgressPolicy]{}, fmt.Errorf("sqlite: list policies page: %w", err)
	}
	defer rows.Close()
	result := Page[domain.EgressPolicy]{Items: make([]domain.EgressPolicy, 0, limit)}
	for rows.Next() {
		item, err := scanPolicy(rows, "")
		if err != nil {
			return Page[domain.EgressPolicy]{}, err
		}
		if len(result.Items) == limit {
			result.NextCursor = item.ID
			break
		}
		result.Items = append(result.Items, item)
	}
	if err := rows.Err(); err != nil {
		return Page[domain.EgressPolicy]{}, fmt.Errorf("sqlite: iterate policy page: %w", err)
	}
	if result.NextCursor != "" && len(result.Items) > 0 {
		result.NextCursor = result.Items[len(result.Items)-1].ID
	}
	return result, nil
}

func (r *Repository) ListAuditPage(ctx context.Context, after int64, limit int) (Page[domain.AuditEvent], error) {
	limit = pageLimit(limit)
	rows, err := r.db.QueryContext(ctx, `SELECT id, actor, action, entity, entity_id, payload, created_at FROM audit_events WHERE id > ? ORDER BY id LIMIT ?`, after, limit+1)
	if err != nil {
		return Page[domain.AuditEvent]{}, fmt.Errorf("sqlite: list audit page: %w", err)
	}
	defer rows.Close()
	result := Page[domain.AuditEvent]{Items: make([]domain.AuditEvent, 0, limit)}
	for rows.Next() {
		var item domain.AuditEvent
		var created int64
		if err := rows.Scan(&item.ID, &item.Actor, &item.Action, &item.Entity, &item.EntityID, &item.Payload, &created); err != nil {
			return Page[domain.AuditEvent]{}, err
		}
		item.CreatedAt = fromUnixMilli(created)
		if len(result.Items) == limit {
			result.NextCursor = fmt.Sprint(item.ID)
			break
		}
		result.Items = append(result.Items, item)
	}
	if err := rows.Err(); err != nil {
		return Page[domain.AuditEvent]{}, fmt.Errorf("sqlite: iterate audit page: %w", err)
	}
	if result.NextCursor != "" && len(result.Items) > 0 {
		result.NextCursor = fmt.Sprint(result.Items[len(result.Items)-1].ID)
	}
	return result, nil
}

// RecordProxyHealth records bounded compatibility probes without ever storing
// probe credentials or transport error text. Health telemetry is operational
// metadata only; it deliberately does not alter proxy/credential revisions.
func (r *Repository) RecordProxyHealth(ctx context.Context, proxyID string, status domain.ProxyStatus, latencyMS int, exitIP, reasonCode string) error {
	if status != domain.ProxyStatusOK && status != domain.ProxyStatusDegraded && status != domain.ProxyStatusDown {
		return &domain.ValidationError{Field: "status", Message: "invalid proxy health status"}
	}
	if latencyMS < 0 {
		latencyMS = 0
	}
	return r.WithinImmediate(ctx, func(ctx context.Context, uow *UnitOfWork) error {
		now := unixMilli(uow.repo.now())
		result, err := uow.tx.ExecContext(ctx, `UPDATE proxies SET status = ?, latency_ms = ?, exit_ip = ?, last_checked_at = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL`, status, latencyMS, exitIP, now, now, proxyID)
		if err != nil {
			return fmt.Errorf("sqlite: update proxy health: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if affected == 0 {
			return &domain.NotFoundError{Entity: "proxy", ID: proxyID}
		}
		if _, err := uow.tx.ExecContext(ctx, `INSERT INTO proxy_health_snapshots(proxy_id, status, latency_ms, exit_ip, reason_code, checked_at) VALUES (?, ?, ?, ?, ?, ?)`, proxyID, status, latencyMS, exitIP, safeReasonCode(reasonCode), now); err != nil {
			return fmt.Errorf("sqlite: insert proxy health snapshot: %w", err)
		}
		return uow.audit(ctx, "system", "proxy.health_check", "proxy", proxyID, auditJSON(map[string]any{"status": status, "latency_ms": latencyMS, "reason_code": safeReasonCode(reasonCode)}))
	})
}

// DesiredSnapshot returns exactly the complete active desired state at the
// current pending generation. Reconciliation always replaces the dynamic table
// from this complete set, so suspended/deleted mappings are correctly removed.
func (r *Repository) DesiredSnapshot(ctx context.Context) (domain.DesiredSnapshot, error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return domain.DesiredSnapshot{}, fmt.Errorf("sqlite: begin desired snapshot read: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var generation int64
	err = tx.QueryRowContext(ctx, `SELECT pending_generation FROM reconcile_states WHERE node_id = ?`, controlPlaneNodeID).Scan(&generation)
	if errors.Is(err, sql.ErrNoRows) {
		generation = 0
	} else if err != nil {
		return domain.DesiredSnapshot{}, fmt.Errorf("sqlite: read desired generation: %w", err)
	}
	snapshot, err := r.desiredSnapshotFor(ctx, tx, generation)
	if err != nil {
		return domain.DesiredSnapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		return domain.DesiredSnapshot{}, fmt.Errorf("sqlite: commit desired snapshot read: %w", err)
	}
	return snapshot, nil
}

func (r *Repository) ActivateMappingIfVersion(ctx context.Context, mappingID string, version int64, actor string) (domain.Mapping, error) {
	var result domain.Mapping
	err := r.WithinImmediate(ctx, func(ctx context.Context, uow *UnitOfWork) error {
		if err := uow.requireMappingVersion(ctx, mappingID, version); err != nil {
			return err
		}
		var err error
		result, err = uow.ActivateMapping(ctx, mappingID, actor)
		return err
	})
	return result, err
}

func (r *Repository) SuspendMappingIfVersion(ctx context.Context, mappingID string, version int64, actor string) (domain.Mapping, error) {
	var result domain.Mapping
	err := r.WithinImmediate(ctx, func(ctx context.Context, uow *UnitOfWork) error {
		if err := uow.requireMappingVersion(ctx, mappingID, version); err != nil {
			return err
		}
		var err error
		result, err = uow.transitionMapping(ctx, mappingID, domain.DesiredSuspended, actor)
		return err
	})
	return result, err
}

func (r *Repository) DeleteMappingIfVersion(ctx context.Context, mappingID string, version int64, actor string) (domain.Mapping, error) {
	var result domain.Mapping
	err := r.WithinImmediate(ctx, func(ctx context.Context, uow *UnitOfWork) error {
		if err := uow.requireMappingVersion(ctx, mappingID, version); err != nil {
			return err
		}
		var err error
		result, err = uow.transitionMapping(ctx, mappingID, domain.DesiredDeleted, actor)
		return err
	})
	return result, err
}

func (r *Repository) PatchMappingIfVersion(ctx context.Context, mappingID string, version int64, input PatchMappingInput) (domain.Mapping, error) {
	var result domain.Mapping
	err := r.WithinImmediate(ctx, func(ctx context.Context, uow *UnitOfWork) error {
		var err error
		result, err = uow.PatchMappingIfVersion(ctx, mappingID, version, input)
		return err
	})
	return result, err
}

func (r *Repository) DeleteProxyIfVersion(ctx context.Context, id string, version int64, actor string) error {
	return r.WithinImmediate(ctx, func(ctx context.Context, uow *UnitOfWork) error {
		return uow.DeleteProxyIfVersion(ctx, id, version, actor)
	})
}

func (r *Repository) DeleteClientIfVersion(ctx context.Context, id string, version int64, actor string) error {
	return r.WithinImmediate(ctx, func(ctx context.Context, uow *UnitOfWork) error {
		return uow.DeleteClientIfVersion(ctx, id, version, actor)
	})
}

func (r *Repository) PatchProxyIfVersion(ctx context.Context, id string, version int64, input PatchProxyInput) (domain.Proxy, error) {
	var result domain.Proxy
	err := r.WithinImmediate(ctx, func(ctx context.Context, uow *UnitOfWork) error {
		var err error
		result, err = uow.PatchProxyIfVersion(ctx, id, version, input)
		return err
	})
	return result, err
}

func (r *Repository) PatchClientIfVersion(ctx context.Context, id string, version int64, input PatchClientInput) (domain.Client, error) {
	var result domain.Client
	err := r.WithinImmediate(ctx, func(ctx context.Context, uow *UnitOfWork) error {
		var err error
		result, err = uow.PatchClientIfVersion(ctx, id, version, input)
		return err
	})
	return result, err
}

func (r *Repository) desiredSnapshotFor(ctx context.Context, query sqlExecutor, generation int64) (domain.DesiredSnapshot, error) {
	rows, err := query.QueryContext(ctx, `SELECT m.id, c.ip_cidr, p.id, p.type, p.host, p.port, p.proxy_revision, p.credential_revision, m.local_redirect_port, e.kind, m.desired_state
        FROM mappings m
        JOIN clients c ON c.id = m.client_id
        JOIN proxies p ON p.id = m.proxy_id
        JOIN egress_policies e ON e.id = m.policy_id
        WHERE m.desired_state = 'ACTIVE' AND c.deleted_at IS NULL AND p.deleted_at IS NULL
        ORDER BY m.id`)
	if err != nil {
		return domain.DesiredSnapshot{}, fmt.Errorf("sqlite: build desired snapshot: %w", err)
	}
	defer rows.Close()
	mappings := make([]domain.AgentMapping, 0)
	for rows.Next() {
		var item domain.AgentMapping
		if err := rows.Scan(&item.ID, &item.ClientIPCIDR, &item.ProxyID, &item.ProxyType, &item.ProxyHost, &item.ProxyPort, &item.ProxyRevision, &item.CredentialRevision, &item.LocalRedirectPort, &item.PolicyKind, &item.DesiredState); err != nil {
			return domain.DesiredSnapshot{}, err
		}
		mappings = append(mappings, item)
	}
	if err := rows.Err(); err != nil {
		return domain.DesiredSnapshot{}, err
	}
	return domain.BuildDesiredSnapshotWithIPv6Policy(generation, r.ipv6Policy, mappings)
}

func (u *UnitOfWork) PatchMappingIfVersion(ctx context.Context, mappingID string, version int64, input PatchMappingInput) (domain.Mapping, error) {
	mapping, err := u.mappingByID(ctx, mappingID)
	if err != nil {
		return domain.Mapping{}, err
	}
	if mapping.Version != version {
		return domain.Mapping{}, &domain.ConflictError{Constraint: "resource_version", Message: "mapping has changed"}
	}
	if mapping.DesiredState == domain.DesiredActive {
		return domain.Mapping{}, &domain.ConflictError{Constraint: "mapping_state", Message: "suspend an ACTIVE mapping before patching it"}
	}
	port, policyID := mapping.LocalRedirectPort, mapping.PolicyID
	if input.LocalRedirectPort != nil {
		port = *input.LocalRedirectPort
	}
	if input.PolicyID != nil {
		policyID = *input.PolicyID
	}
	if port < domain.ForwarderPortStart || port > domain.ForwarderPortEnd {
		return domain.Mapping{}, &domain.ValidationError{Field: "local_redirect_port", Message: "must be between 15001 and 15999"}
	}
	if err := u.requirePolicy(ctx, policyID); err != nil {
		return domain.Mapping{}, err
	}
	now := unixMilli(u.repo.now())
	if _, err := u.tx.ExecContext(ctx, `UPDATE mappings SET local_redirect_port = ?, policy_id = ?, version = version + 1, updated_at = ? WHERE id = ? AND version = ?`, port, policyID, now, mappingID, version); err != nil {
		return domain.Mapping{}, fmt.Errorf("sqlite: patch mapping: %w", err)
	}
	if err := u.audit(ctx, input.Actor, "mapping.patch", "mapping", mappingID, []byte(`{}`)); err != nil {
		return domain.Mapping{}, err
	}
	return u.mappingByID(ctx, mappingID)
}

func (u *UnitOfWork) DeleteProxyIfVersion(ctx context.Context, id string, version int64, actor string) error {
	proxy, err := u.proxyByID(ctx, id)
	if err != nil {
		return err
	}
	if proxy.Version != version {
		return &domain.ConflictError{Constraint: "resource_version", Message: "proxy has changed"}
	}
	if err := u.cascadeMappingsToDeleted(ctx, "proxy_id", id, actor, "proxy.delete"); err != nil {
		return err
	}
	now := unixMilli(u.repo.now())
	if _, err := u.tx.ExecContext(ctx, `UPDATE proxies SET enabled = 0, deleted_at = ?, version = version + 1, updated_at = ? WHERE id = ? AND version = ?`, now, now, id, version); err != nil {
		return fmt.Errorf("sqlite: soft delete proxy: %w", err)
	}
	return u.audit(ctx, actor, "proxy.delete", "proxy", id, auditJSON(map[string]bool{"soft_deleted": true}))
}

func (u *UnitOfWork) DeleteClientIfVersion(ctx context.Context, id string, version int64, actor string) error {
	client, err := u.clientByID(ctx, id)
	if err != nil {
		return err
	}
	if client.Version != version {
		return &domain.ConflictError{Constraint: "resource_version", Message: "client has changed"}
	}
	if err := u.cascadeMappingsToDeleted(ctx, "client_id", id, actor, "client.delete"); err != nil {
		return err
	}
	now := unixMilli(u.repo.now())
	if _, err := u.tx.ExecContext(ctx, `UPDATE clients SET enabled = 0, deleted_at = ?, version = version + 1, updated_at = ? WHERE id = ? AND version = ?`, now, now, id, version); err != nil {
		return fmt.Errorf("sqlite: soft delete client: %w", err)
	}
	return u.audit(ctx, actor, "client.delete", "client", id, auditJSON(map[string]bool{"soft_deleted": true}))
}

// cascadeMappingsToDeleted preserves mapping history while removing every
// affected source from the immutable desired snapshot in the same transaction
// as a parent proxy/client deletion. The allow-listed column is never derived
// from a request, so the SQL remains static and injectable values are bound.
func (u *UnitOfWork) cascadeMappingsToDeleted(ctx context.Context, column, parentID, actor, action string) error {
	if column != "proxy_id" && column != "client_id" {
		return fmt.Errorf("sqlite: invalid cascade column")
	}
	query := `SELECT id FROM mappings WHERE ` + column + ` = ? AND desired_state != 'DELETED' ORDER BY id`
	rows, err := u.tx.QueryContext(ctx, query, parentID)
	if err != nil {
		return fmt.Errorf("sqlite: list cascade mappings: %w", err)
	}
	var ids []string
	for rows.Next() {
		var mappingID string
		if err := rows.Scan(&mappingID); err != nil {
			_ = rows.Close()
			return err
		}
		ids = append(ids, mappingID)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	now := unixMilli(u.repo.now())
	if _, err := u.tx.ExecContext(ctx, `INSERT INTO reconcile_states
        (node_id, pending_generation, applied_generation, ruleset_hash, state, last_error, updated_at)
        VALUES (?, 1, 0, '', 'PENDING', '', ?)
        ON CONFLICT(node_id) DO UPDATE SET pending_generation = pending_generation + 1, state = 'PENDING', updated_at = excluded.updated_at`, controlPlaneNodeID, now); err != nil {
		return fmt.Errorf("sqlite: bump desired generation for cascade: %w", err)
	}
	var generation int64
	if err := u.tx.QueryRowContext(ctx, `SELECT pending_generation FROM reconcile_states WHERE node_id = ?`, controlPlaneNodeID).Scan(&generation); err != nil {
		return fmt.Errorf("sqlite: read cascade generation: %w", err)
	}
	for _, mappingID := range ids {
		if _, err := u.tx.ExecContext(ctx, `UPDATE mappings SET desired_state = 'DELETED', desired_generation = ?, data_plane_state = 'UNKNOWN', version = version + 1, updated_at = ? WHERE id = ?`, generation, now, mappingID); err != nil {
			return fmt.Errorf("sqlite: cascade delete mapping: %w", err)
		}
		if err := u.audit(ctx, actor, "mapping.delete", "mapping", mappingID, auditJSON(map[string]any{"cascade_from": action, "desired_generation": generation})); err != nil {
			return err
		}
	}
	snapshot, err := u.repo.desiredSnapshotFor(ctx, u.tx, generation)
	if err != nil {
		return err
	}
	if _, err := u.tx.ExecContext(ctx, `UPDATE mappings SET desired_hash = ? WHERE desired_state != 'DELETED'`, snapshot.DesiredHash); err != nil {
		return fmt.Errorf("sqlite: record cascade desired snapshot hash: %w", err)
	}
	return nil
}

func (u *UnitOfWork) PatchProxyIfVersion(ctx context.Context, id string, version int64, input PatchProxyInput) (domain.Proxy, error) {
	proxy, err := u.proxyByID(ctx, id)
	if err != nil {
		return domain.Proxy{}, err
	}
	if proxy.Version != version {
		return domain.Proxy{}, &domain.ConflictError{Constraint: "resource_version", Message: "proxy has changed"}
	}
	var active int
	if err := u.tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM mappings WHERE proxy_id = ? AND desired_state = 'ACTIVE'`, id).Scan(&active); err != nil {
		return domain.Proxy{}, err
	}
	if active != 0 {
		return domain.Proxy{}, &domain.ConflictError{Constraint: "mapping_state", Message: "suspend active mappings before patching a proxy"}
	}
	label, proxyType, host, port, username, enabled := proxy.Label, proxy.Type, proxy.Host, proxy.Port, proxy.Username, proxy.Enabled
	configured := proxy.PasswordConfigured
	if input.Label != nil {
		label = *input.Label
	}
	if input.Type != nil {
		proxyType = *input.Type
	}
	if input.Host != nil {
		host = *input.Host
	}
	if input.Port != nil {
		port = *input.Port
	}
	if input.Username != nil {
		username = *input.Username
	}
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	if input.PasswordConfigured != nil {
		configured = *input.PasswordConfigured
	}
	if input.Password != nil {
		configured = true
	}
	if !configured {
		username = ""
	}
	if err := domain.ValidateProxy(proxyType, host, port); err != nil {
		return domain.Proxy{}, err
	}
	if configured && !proxy.PasswordConfigured && input.Password == nil {
		return domain.Proxy{}, &domain.ValidationError{Field: "password", Message: "must be supplied when enabling proxy authentication"}
	}
	if input.Password != nil {
		if err := domain.ValidateProxyAuthentication(proxyType, username, *input.Password, configured); err != nil {
			return domain.Proxy{}, err
		}
	} else if !configured {
		if err := domain.ValidateProxyAuthentication(proxyType, username, nil, false); err != nil {
			return domain.Proxy{}, err
		}
	}
	endpointChanged := proxyType != proxy.Type || host != proxy.Host || port != proxy.Port
	authChanged := configured != proxy.PasswordConfigured || username != proxy.Username || input.Password != nil
	now := unixMilli(u.repo.now())
	if _, err := u.tx.ExecContext(ctx, `UPDATE proxies SET label = ?, type = ?, host = ?, port = ?, username = ?, enabled = ?,
        proxy_revision = proxy_revision + ?, credential_revision = credential_revision + ?, version = version + 1, updated_at = ? WHERE id = ? AND version = ?`,
		label, proxyType, host, port, username, boolInt(enabled), boolInt(endpointChanged), boolInt(authChanged), now, id, version); err != nil {
		return domain.Proxy{}, fmt.Errorf("sqlite: patch proxy: %w", err)
	}
	if input.Password != nil {
		envelope, err := u.repo.cipher.Seal(*input.Password, []byte(id))
		if err != nil {
			return domain.Proxy{}, err
		}
		if _, err := u.tx.ExecContext(ctx, `INSERT INTO proxy_secrets(proxy_id, envelope_version, nonce, ciphertext, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(proxy_id) DO UPDATE SET envelope_version = excluded.envelope_version, nonce = excluded.nonce, ciphertext = excluded.ciphertext, updated_at = excluded.updated_at`, id, envelope.Version, envelope.Nonce, envelope.Ciphertext, now, now); err != nil {
			return domain.Proxy{}, mapWriteError(err, "proxy secret")
		}
	} else if !configured {
		if _, err := u.tx.ExecContext(ctx, `DELETE FROM proxy_secrets WHERE proxy_id = ?`, id); err != nil {
			return domain.Proxy{}, fmt.Errorf("sqlite: clear proxy secret: %w", err)
		}
	}
	if configured {
		if err := u.validateProxyCredentialsForActivation(ctx, id); err != nil {
			return domain.Proxy{}, err
		}
	}
	if err := u.audit(ctx, input.Actor, "proxy.patch", "proxy", id, auditJSON(map[string]any{
		"proxy_revision_changed": endpointChanged, "credential_revision_changed": authChanged,
	})); err != nil {
		return domain.Proxy{}, err
	}
	return u.proxyByID(ctx, id)
}

func (u *UnitOfWork) PatchClientIfVersion(ctx context.Context, id string, version int64, input PatchClientInput) (domain.Client, error) {
	client, err := u.clientByID(ctx, id)
	if err != nil {
		return domain.Client{}, err
	}
	if client.Version != version {
		return domain.Client{}, &domain.ConflictError{Constraint: "resource_version", Message: "client has changed"}
	}
	var active int
	if err := u.tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM mappings WHERE client_id = ? AND desired_state = 'ACTIVE'`, id).Scan(&active); err != nil {
		return domain.Client{}, err
	}
	if active != 0 {
		return domain.Client{}, &domain.ConflictError{Constraint: "mapping_state", Message: "suspend active mappings before patching a client"}
	}
	note, enabled := client.Note, client.Enabled
	if input.Note != nil {
		note = *input.Note
	}
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	now := unixMilli(u.repo.now())
	if _, err := u.tx.ExecContext(ctx, `UPDATE clients SET note = ?, enabled = ?, version = version + 1, updated_at = ? WHERE id = ? AND version = ?`, note, boolInt(enabled), now, id, version); err != nil {
		return domain.Client{}, fmt.Errorf("sqlite: patch client: %w", err)
	}
	if err := u.audit(ctx, input.Actor, "client.patch", "client", id, []byte(`{}`)); err != nil {
		return domain.Client{}, err
	}
	return u.clientByID(ctx, id)
}

// GetActiveMappingCredential is deliberately narrow: callers must prove that
// a mapping is currently ACTIVE before the proxy password is decrypted.
func (r *Repository) GetActiveMappingCredential(ctx context.Context, mappingID string) (domain.AgentCredential, error) {
	var proxyID string
	err := r.db.QueryRowContext(ctx, `SELECT m.proxy_id FROM mappings m JOIN proxies p ON p.id = m.proxy_id WHERE m.id = ? AND m.desired_state = 'ACTIVE' AND p.deleted_at IS NULL`, mappingID).Scan(&proxyID)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.AgentCredential{}, &domain.NotFoundError{Entity: "active mapping", ID: mappingID}
	}
	if err != nil {
		return domain.AgentCredential{}, fmt.Errorf("sqlite: active mapping credential lookup: %w", err)
	}
	credential, err := r.GetProxyCredential(ctx, proxyID)
	if err != nil {
		return domain.AgentCredential{}, err
	}
	proxy, err := r.GetProxy(ctx, proxyID)
	if err != nil {
		zero(credential.Password)
		return domain.AgentCredential{}, err
	}
	return domain.AgentCredential{
		MappingID: mappingID, ProxyID: proxyID,
		ProxyRevision: proxy.ProxyRevision, CredentialRevision: proxy.CredentialRevision,
		AuthConfigured: proxy.PasswordConfigured, Username: credential.Username, Password: credential.Password,
	}, nil
}

// AcknowledgeAgent records only the currently pending generation. A stale
// Agent can never overwrite status or hashes from a newer desired snapshot.
func (r *Repository) AcknowledgeAgent(ctx context.Context, ack domain.AgentAck, actor string) (domain.ReconcileState, error) {
	if ack.Generation < 0 || !ack.Status.Valid() {
		return domain.ReconcileState{}, &domain.ValidationError{Field: "ack", Message: "invalid generation or status"}
	}
	var result domain.ReconcileState
	err := r.WithinImmediate(ctx, func(ctx context.Context, uow *UnitOfWork) error {
		var pending, priorApplied int64
		var priorHash string
		if err := uow.tx.QueryRowContext(ctx, `SELECT pending_generation, applied_generation, ruleset_hash FROM reconcile_states WHERE node_id = ?`, controlPlaneNodeID).Scan(&pending, &priorApplied, &priorHash); errors.Is(err, sql.ErrNoRows) {
			pending = 0
		} else if err != nil {
			return fmt.Errorf("sqlite: read pending generation: %w", err)
		}
		if ack.Generation != pending {
			return &domain.ConflictError{Constraint: "generation", Message: "stale agent acknowledgement"}
		}
		snapshot, err := uow.repo.desiredSnapshotFor(ctx, uow.tx, pending)
		if err != nil {
			return err
		}
		if ack.DesiredHash == "" || ack.DesiredHash != snapshot.DesiredHash {
			return &domain.ConflictError{Constraint: "desired_hash", Message: "agent acknowledgement does not match desired snapshot"}
		}
		now := unixMilli(uow.repo.now())
		state := string(ack.Status)
		// A failed verification must retain the last-known-good applied
		// generation/hash; only a VERIFIED ACK may advance it.
		appliedGeneration, appliedHash := priorApplied, priorHash
		if ack.Status == domain.DataPlaneVerified {
			if strings.TrimSpace(ack.AppliedHash) == "" {
				return &domain.ValidationError{Field: "applied_hash", Message: "is required for VERIFIED acknowledgement"}
			}
			appliedGeneration, appliedHash = pending, ack.AppliedHash
			if err := uow.updateSnapshotMappings(ctx, snapshot.Mappings, `applied_generation = ?, applied_hash = ?, data_plane_state = 'VERIFIED', version = version + 1, updated_at = ?`, pending, ack.AppliedHash, now); err != nil {
				return fmt.Errorf("sqlite: apply mapping acknowledgement: %w", err)
			}
		} else {
			if err := uow.updateSnapshotMappings(ctx, snapshot.Mappings, `data_plane_state = ?, version = version + 1, updated_at = ?`, ack.Status, now); err != nil {
				return fmt.Errorf("sqlite: record mapping acknowledgement: %w", err)
			}
		}
		if _, err := uow.tx.ExecContext(ctx, `INSERT INTO reconcile_states(node_id, pending_generation, applied_generation, ruleset_hash, state, last_error, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(node_id) DO UPDATE SET applied_generation = excluded.applied_generation, ruleset_hash = excluded.ruleset_hash, state = excluded.state, last_error = excluded.last_error, updated_at = excluded.updated_at`,
			controlPlaneNodeID, pending, appliedGeneration, appliedHash, state, safeReasonCode(ack.ReasonCode), now); err != nil {
			return fmt.Errorf("sqlite: record reconcile acknowledgement: %w", err)
		}
		if err := uow.audit(ctx, actor, "agent.ack", "reconcile", controlPlaneNodeID, auditJSON(map[string]any{"generation": pending, "status": ack.Status, "reason_code": safeReasonCode(ack.ReasonCode)})); err != nil {
			return err
		}
		return nil
	})
	if err == nil {
		result, err = r.GetReconcileState(ctx)
	}
	return result, err
}

// updateSnapshotMappings changes only mapping IDs the Agent actually received
// in the acknowledged immutable snapshot. Draft, suspended, and historical
// deleted mappings must never acquire an applied generation from another
// mapping's reconciliation.
func (u *UnitOfWork) updateSnapshotMappings(ctx context.Context, mappings []domain.AgentMapping, setClause string, values ...any) error {
	if len(mappings) == 0 {
		return nil
	}
	placeholders := make([]string, 0, len(mappings))
	args := append([]any(nil), values...)
	for _, mapping := range mappings {
		placeholders = append(placeholders, "?")
		args = append(args, mapping.ID)
	}
	query := `UPDATE mappings SET ` + setClause + ` WHERE desired_state = 'ACTIVE' AND id IN (` + strings.Join(placeholders, ",") + `)`
	if _, err := u.tx.ExecContext(ctx, query, args...); err != nil {
		return err
	}
	return nil
}

func safeReasonCode(value string) string {
	value = strings.TrimSpace(value)
	if len(value) == 0 {
		return ""
	}
	if len(value) > 128 {
		return "invalid_reason_code"
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-' {
			continue
		}
		return "invalid_reason_code"
	}
	return value
}

func (u *UnitOfWork) requireMappingVersion(ctx context.Context, id string, version int64) error {
	mapping, err := u.mappingByID(ctx, id)
	if err != nil {
		return err
	}
	if mapping.Version != version {
		return &domain.ConflictError{Constraint: "resource_version", Message: "mapping has changed"}
	}
	return nil
}

// RequireMappingVersion is exported solely for the application transaction
// composer. It keeps If-Match validation in the same SQLite transaction as the
// state transition and idempotency record.
func (u *UnitOfWork) RequireMappingVersion(ctx context.Context, id string, version int64) error {
	return u.requireMappingVersion(ctx, id, version)
}

// TransitionMapping is the transaction-scoped counterpart to suspend/delete.
// Callers must validate the version first when it is a user mutation.
func (u *UnitOfWork) TransitionMapping(ctx context.Context, id string, desired domain.DesiredState, actor string) (domain.Mapping, error) {
	if desired != domain.DesiredSuspended && desired != domain.DesiredDeleted {
		return domain.Mapping{}, &domain.ValidationError{Field: "desired_state", Message: "must be SUSPENDED or DELETED"}
	}
	return u.transitionMapping(ctx, id, desired, actor)
}

func (r *Repository) EnsureIdempotency(ctx context.Context, scope, key, requestHash string, response []byte) ([]byte, bool, error) {
	if strings.TrimSpace(scope) == "" || strings.TrimSpace(key) == "" || strings.TrimSpace(requestHash) == "" {
		return nil, false, &domain.ValidationError{Field: "idempotency_key", Message: "is required"}
	}
	var stored []byte
	var replay bool
	err := r.WithinImmediate(ctx, func(ctx context.Context, uow *UnitOfWork) error {
		var existingHash string
		err := uow.tx.QueryRowContext(ctx, `SELECT request_hash, response FROM idempotency_keys WHERE scope = ? AND key = ?`, scope, key).Scan(&existingHash, &stored)
		if err == nil {
			if existingHash != requestHash {
				return &domain.ConflictError{Constraint: "idempotency_key", Message: "key was already used for a different request"}
			}
			replay = true
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("sqlite: read idempotency key: %w", err)
		}
		if _, err := uow.tx.ExecContext(ctx, `INSERT INTO idempotency_keys(scope, key, request_hash, response, created_at) VALUES(?, ?, ?, ?, ?)`, scope, key, requestHash, response, unixMilli(uow.repo.now())); err != nil {
			return mapWriteError(err, "idempotency key")
		}
		stored = append([]byte(nil), response...)
		return nil
	})
	return stored, replay, err
}

// ExecuteIdempotent serializes a retryable mutation with its response. The
// mutation callback runs only after a matching key is known not to exist and
// its response is committed in the same immediate transaction. A retry cannot
// create a second proxy/client/mapping even if it races another API request.
func (r *Repository) ExecuteIdempotent(ctx context.Context, scope, key, requestHash string, fn func(context.Context, *UnitOfWork) ([]byte, error)) ([]byte, bool, error) {
	if strings.TrimSpace(scope) == "" || strings.TrimSpace(key) == "" || strings.TrimSpace(requestHash) == "" {
		return nil, false, &domain.ValidationError{Field: "idempotency_key", Message: "is required"}
	}
	var response []byte
	var replay bool
	err := r.WithinImmediate(ctx, func(ctx context.Context, uow *UnitOfWork) error {
		var storedHash string
		err := uow.tx.QueryRowContext(ctx, `SELECT request_hash, response FROM idempotency_keys WHERE scope = ? AND key = ?`, scope, key).Scan(&storedHash, &response)
		if err == nil {
			if storedHash != requestHash {
				return &domain.ConflictError{Constraint: "idempotency_key", Message: "key was already used for a different request"}
			}
			replay = true
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("sqlite: read idempotency key: %w", err)
		}
		response, err = fn(ctx, uow)
		if err != nil {
			return err
		}
		if _, err := uow.tx.ExecContext(ctx, `INSERT INTO idempotency_keys(scope, key, request_hash, response, created_at) VALUES(?, ?, ?, ?, ?)`, scope, key, requestHash, response, unixMilli(uow.repo.now())); err != nil {
			return mapWriteError(err, "idempotency key")
		}
		return nil
	})
	return response, replay, err
}

func scanClient(row scanner, missingID string) (domain.Client, error) {
	var client domain.Client
	var enabled int
	var created, updated int64
	err := row.Scan(&client.ID, &client.IPCIDR, &client.Note, &enabled, &client.Version, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Client{}, &domain.NotFoundError{Entity: "client", ID: missingID}
	}
	if err != nil {
		return domain.Client{}, fmt.Errorf("sqlite: scan client: %w", err)
	}
	client.Enabled = enabled != 0
	client.CreatedAt, client.UpdatedAt = fromUnixMilli(created), fromUnixMilli(updated)
	return client, nil
}

func scanPolicy(row scanner, missingID string) (domain.EgressPolicy, error) {
	var policy domain.EgressPolicy
	var enabled int
	var created, updated int64
	err := row.Scan(&policy.ID, &policy.Name, &policy.Kind, &enabled, &policy.Version, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.EgressPolicy{}, &domain.NotFoundError{Entity: "egress policy", ID: missingID}
	}
	if err != nil {
		return domain.EgressPolicy{}, fmt.Errorf("sqlite: scan egress policy: %w", err)
	}
	policy.Enabled = enabled != 0
	policy.CreatedAt, policy.UpdatedAt = fromUnixMilli(created), fromUnixMilli(updated)
	return policy, nil
}
