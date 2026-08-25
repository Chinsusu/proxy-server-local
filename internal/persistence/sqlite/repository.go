// Package sqlite is the production persistence boundary for PGW's
// control-plane. It uses modernc.org/sqlite, so builds remain CGO-free.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Chinsusu/proxy-server-local/internal/domain"
	"github.com/Chinsusu/proxy-server-local/internal/secret"
	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

const controlPlaneNodeID = "_control_plane"

type Config struct {
	Path        string
	KeyProvider secret.KeyProvider
	Clock       func() time.Time
	IPv6Policy  domain.IPv6Policy
}

type Repository struct {
	db         *sql.DB
	cipher     *secret.AESGCM
	now        func() time.Time
	lock       *databaseLock
	ipv6Policy domain.IPv6Policy
}

// Open configures SQLite before any data access: WAL for crash-safe concurrent
// readers, foreign keys for referential integrity, and a five-second busy
// timeout for short write contention. It migrates before returning.
func Open(ctx context.Context, cfg Config) (*Repository, error) {
	if strings.TrimSpace(cfg.Path) == "" {
		return nil, &domain.ValidationError{Field: "path", Message: "is required"}
	}
	if cfg.KeyProvider == nil {
		return nil, &domain.ValidationError{Field: "key_provider", Message: "is required"}
	}
	ipv6Policy := cfg.IPv6Policy
	if ipv6Policy == "" {
		ipv6Policy = domain.IPv6PolicyDeny
	}
	if !ipv6Policy.Valid() {
		return nil, &domain.ValidationError{Field: "ipv6_policy", Message: "must be deny"}
	}
	if cfg.Path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(cfg.Path), 0o750); err != nil {
			return nil, fmt.Errorf("sqlite: create database directory: %w", err)
		}
		if err := secureSQLiteParent(cfg.Path); err != nil {
			return nil, fmt.Errorf("sqlite: insecure database directory: %w", err)
		}
		if err := precreateSecureDatabase(cfg.Path); err != nil {
			return nil, fmt.Errorf("sqlite: prepare database file: %w", err)
		}
	}
	var lock *databaseLock
	if cfg.Path != ":memory:" {
		var err error
		lock, err = acquireDatabaseSharedLock(cfg.Path)
		if err != nil {
			return nil, fmt.Errorf("sqlite: acquire repository database lock: %w", err)
		}
	}
	key, err := cfg.KeyProvider.Key(ctx)
	if err != nil {
		if lock != nil {
			_ = lock.Close()
		}
		return nil, fmt.Errorf("sqlite: load master key: %w", err)
	}
	cipher, err := secret.NewAESGCM(key)
	zero(key)
	if err != nil {
		if lock != nil {
			_ = lock.Close()
		}
		return nil, err
	}
	dsn, err := databaseURI(cfg.Path)
	if err != nil {
		if lock != nil {
			_ = lock.Close()
		}
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open database: %w", err)
	}
	if cfg.Path == ":memory:" {
		// A plain :memory: DSN creates one database per connection. Keep exactly
		// one connection so migrations, transactions and reads use the same DB.
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
	}
	// The DSN pragmas are evaluated for each new connection. These calls make
	// startup fail early when the filesystem cannot support the required mode.
	if cfg.Path != ":memory:" {
		var journalMode string
		if err := db.QueryRowContext(ctx, "PRAGMA journal_mode = WAL").Scan(&journalMode); err != nil {
			_ = db.Close()
			if lock != nil {
				_ = lock.Close()
			}
			return nil, fmt.Errorf("sqlite: enable WAL: %w", err)
		}
		if !strings.EqualFold(journalMode, "wal") {
			_ = db.Close()
			if lock != nil {
				_ = lock.Close()
			}
			return nil, fmt.Errorf("sqlite: WAL requested but SQLite reported journal_mode=%q", journalMode)
		}
	}
	for _, pragma := range []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 5000",
	} {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			_ = db.Close()
			if lock != nil {
				_ = lock.Close()
			}
			return nil, fmt.Errorf("sqlite: %s: %w", pragma, err)
		}
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		if lock != nil {
			_ = lock.Close()
		}
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	if err := Migrate(ctx, db); err != nil {
		_ = db.Close()
		if cfg.Path != ":memory:" {
			_ = secureSQLiteSidecars(cfg.Path)
		}
		if lock != nil {
			_ = lock.Close()
		}
		return nil, err
	}
	if err := validateExactSchema(ctx, db, true); err != nil {
		_ = db.Close()
		if lock != nil {
			_ = lock.Close()
		}
		return nil, fmt.Errorf("sqlite: validate schema: %w", err)
	}
	if cfg.Path != ":memory:" {
		if err := secureSQLiteSidecars(cfg.Path); err != nil {
			_ = db.Close()
			if lock != nil {
				_ = lock.Close()
			}
			return nil, fmt.Errorf("sqlite: secure database files: %w", err)
		}
	}
	now := cfg.Clock
	if now == nil {
		now = time.Now
	}
	return &Repository{db: db, cipher: cipher, now: now, lock: lock, ipv6Policy: ipv6Policy}, nil
}

// IPv6Policy is process configuration that is bound into each desired
// snapshot. It is intentionally read-only: no API mutation can make IPv6
// forwarding permissive.
func (r *Repository) IPv6Policy() domain.IPv6Policy { return r.ipv6Policy }

func databaseURI(path string) (string, error) {
	if path == ":memory:" {
		return "file::memory:?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)", nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("sqlite: canonicalize database path: %w", err)
	}
	uriPath := filepath.ToSlash(abs)
	if volume := filepath.VolumeName(abs); volume != "" && !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath // file:///C:/... is a local SQLite URI.
	}
	uri := &url.URL{Scheme: "file", Path: uriPath}
	query := url.Values{}
	query.Add("_pragma", "journal_mode(WAL)")
	query.Add("_pragma", "foreign_keys(1)")
	query.Add("_pragma", "busy_timeout(5000)")
	uri.RawQuery = query.Encode()
	return uri.String(), nil
}

func immutableReadURI(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("sqlite: canonicalize database path: %w", err)
	}
	uriPath := filepath.ToSlash(abs)
	if volume := filepath.VolumeName(abs); volume != "" && !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	uri := &url.URL{Scheme: "file", Path: uriPath}
	query := url.Values{}
	query.Set("mode", "ro")
	query.Set("immutable", "1")
	uri.RawQuery = query.Encode()
	return uri.String(), nil
}

// sqliteDSN remains test-only compatibility glue. Production callers must use
// databaseURI and handle canonicalization errors.
func sqliteDSN(path string) string {
	uri, err := databaseURI(path)
	if err != nil {
		panic(err)
	}
	return uri
}

func (r *Repository) Close() error {
	err := r.db.Close()
	if r.lock != nil {
		if lockErr := r.lock.Close(); err == nil {
			err = lockErr
		}
		r.lock = nil
	}
	return err
}

func (r *Repository) DB() *sql.DB { return r.db }

type UnitOfWork struct {
	repo *Repository
	tx   sqlExecutor
}

type sqlExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// WithinTx is the only mutation entry point exposed to future application
// services that need to combine independent repository operations atomically.
func (r *Repository) WithinTx(ctx context.Context, fn func(context.Context, *UnitOfWork) error) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	uow := &UnitOfWork{repo: r, tx: tx}
	if err := fn(ctx, uow); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: commit transaction: %w", err)
	}
	return nil
}

// WithinImmediate acquires SQLite's write reservation before the callback runs.
// It serializes imports and similar write-once operations so a concurrent retry
// sees the committed idempotency record instead of racing to insert it.
func (r *Repository) WithinImmediate(ctx context.Context, fn func(context.Context, *UnitOfWork) error) error {
	const attempts = 6
	for attempt := 0; attempt < attempts; attempt++ {
		err := r.withImmediateOnce(ctx, fn)
		if err == nil || !isBusyError(err) || attempt == attempts-1 {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 15 * time.Millisecond):
		}
	}
	return nil
}

func (r *Repository) withImmediateOnce(ctx context.Context, fn func(context.Context, *UnitOfWork) error) (err error) {
	conn, err := r.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("sqlite: acquire immediate transaction connection: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("sqlite: begin immediate transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	if err = fn(ctx, &UnitOfWork{repo: r, tx: conn}); err != nil {
		return err
	}
	if _, err = conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("sqlite: commit immediate transaction: %w", err)
	}
	committed = true
	return nil
}

type CreateProxyInput struct {
	ID                 string
	Label              string
	Type               domain.ProxyType
	Host               string
	Port               int
	Username           string
	Password           []byte `json:"-"`
	PasswordConfigured bool
	Enabled            bool
	Actor              string
}

func (r *Repository) CreateProxy(ctx context.Context, input CreateProxyInput) (domain.Proxy, error) {
	var proxy domain.Proxy
	err := r.WithinTx(ctx, func(ctx context.Context, uow *UnitOfWork) error {
		var err error
		proxy, err = uow.CreateProxy(ctx, input)
		return err
	})
	return proxy, err
}

func (u *UnitOfWork) CreateProxy(ctx context.Context, input CreateProxyInput) (domain.Proxy, error) {
	if err := domain.ValidateProxy(input.Type, input.Host, input.Port); err != nil {
		return domain.Proxy{}, err
	}
	configured := input.PasswordConfigured || input.Username != "" || len(input.Password) != 0
	if err := domain.ValidateProxyAuthentication(input.Type, input.Username, input.Password, configured); err != nil {
		return domain.Proxy{}, err
	}
	id := input.ID
	if id == "" {
		id = uuid.NewString()
	}
	if err := domain.ValidateControlID("proxy_id", id); err != nil {
		return domain.Proxy{}, err
	}
	now := unixMilli(u.repo.now())
	if _, err := u.tx.ExecContext(ctx, `INSERT INTO proxies
        (id, label, type, host, port, username, enabled, status, version, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'DOWN', 1, ?, ?)`,
		id, input.Label, input.Type, input.Host, input.Port, input.Username, boolInt(input.Enabled), now, now); err != nil {
		return domain.Proxy{}, mapWriteError(err, "proxy")
	}
	if configured {
		envelope, err := u.repo.cipher.Seal(input.Password, []byte(id))
		if err != nil {
			return domain.Proxy{}, err
		}
		if _, err := u.tx.ExecContext(ctx, `INSERT INTO proxy_secrets
            (proxy_id, envelope_version, nonce, ciphertext, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)`, id, envelope.Version, envelope.Nonce, envelope.Ciphertext, now, now); err != nil {
			return domain.Proxy{}, mapWriteError(err, "proxy secret")
		}
	}
	if err := u.audit(ctx, input.Actor, "proxy.create", "proxy", id,
		auditJSON(map[string]bool{"password_configured": configured})); err != nil {
		return domain.Proxy{}, err
	}
	return u.proxyByID(ctx, id)
}

func (r *Repository) GetProxy(ctx context.Context, id string) (domain.Proxy, error) {
	return scanProxy(r.db.QueryRowContext(ctx, proxySelect+` WHERE p.id = ? AND p.deleted_at IS NULL`, id), id)
}

func (r *Repository) ListProxies(ctx context.Context, limit int) ([]domain.Proxy, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := r.db.QueryContext(ctx, proxySelect+` WHERE p.deleted_at IS NULL ORDER BY p.id LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list proxies: %w", err)
	}
	defer rows.Close()
	result := make([]domain.Proxy, 0)
	for rows.Next() {
		proxy, err := scanProxy(rows, "")
		if err != nil {
			return nil, err
		}
		result = append(result, proxy)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate proxies: %w", err)
	}
	return result, nil
}

func (r *Repository) GetProxyCredential(ctx context.Context, proxyID string) (domain.ProxyCredential, error) {
	var username string
	var version sql.NullInt64
	var nonce, ciphertext []byte
	err := r.db.QueryRowContext(ctx, `SELECT p.username, s.envelope_version, s.nonce, s.ciphertext
        FROM proxies p LEFT JOIN proxy_secrets s ON s.proxy_id = p.id WHERE p.id = ? AND p.deleted_at IS NULL`, proxyID).
		Scan(&username, &version, &nonce, &ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ProxyCredential{}, &domain.NotFoundError{Entity: "proxy credential", ID: proxyID}
	}
	if err != nil {
		return domain.ProxyCredential{}, fmt.Errorf("sqlite: get proxy credential: %w", err)
	}
	if !version.Valid {
		return domain.ProxyCredential{ProxyID: proxyID}, nil
	}
	plain, err := r.cipher.Open(secret.Envelope{Version: uint8(version.Int64), Nonce: nonce, Ciphertext: ciphertext}, []byte(proxyID))
	if err != nil {
		return domain.ProxyCredential{}, fmt.Errorf("sqlite: decrypt proxy credential: %w", err)
	}
	return domain.ProxyCredential{ProxyID: proxyID, Username: username, Password: plain}, nil
}

type CreateClientInput struct {
	ID      string
	IPCIDR  string
	Note    string
	Enabled bool
	Actor   string
}

func (r *Repository) CreateClient(ctx context.Context, input CreateClientInput) (domain.Client, error) {
	var client domain.Client
	err := r.WithinTx(ctx, func(ctx context.Context, uow *UnitOfWork) error {
		var err error
		client, err = uow.CreateClient(ctx, input)
		return err
	})
	return client, err
}

func (u *UnitOfWork) CreateClient(ctx context.Context, input CreateClientInput) (domain.Client, error) {
	cidr, err := domain.NormalizeIPv4HostCIDR(input.IPCIDR)
	if err != nil {
		return domain.Client{}, err
	}
	id := input.ID
	if id == "" {
		id = uuid.NewString()
	}
	if err := domain.ValidateControlID("client_id", id); err != nil {
		return domain.Client{}, err
	}
	now := unixMilli(u.repo.now())
	if _, err := u.tx.ExecContext(ctx, `INSERT INTO clients
        (id, ip_cidr, note, enabled, version, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?)`,
		id, cidr, input.Note, boolInt(input.Enabled), now, now); err != nil {
		return domain.Client{}, mapWriteError(err, "client")
	}
	if err := u.audit(ctx, input.Actor, "client.create", "client", id, []byte(`{}`)); err != nil {
		return domain.Client{}, err
	}
	return u.clientByID(ctx, id)
}

type CreateMappingInput struct {
	ID                string
	ClientID          string
	ProxyID           string
	PolicyID          string
	LocalRedirectPort int
	Actor             string
}

func (r *Repository) CreateMapping(ctx context.Context, input CreateMappingInput) (domain.Mapping, error) {
	var mapping domain.Mapping
	err := r.WithinTx(ctx, func(ctx context.Context, uow *UnitOfWork) error {
		var err error
		mapping, err = uow.CreateMapping(ctx, input)
		return err
	})
	return mapping, err
}

func (u *UnitOfWork) CreateMapping(ctx context.Context, input CreateMappingInput) (domain.Mapping, error) {
	if input.LocalRedirectPort < domain.ForwarderPortStart || input.LocalRedirectPort > domain.ForwarderPortEnd {
		return domain.Mapping{}, &domain.ValidationError{Field: "local_redirect_port", Message: "must be between 15001 and 15999"}
	}
	if err := domain.ValidateControlID("proxy_id", input.ProxyID); err != nil {
		return domain.Mapping{}, err
	}
	if err := u.requireClient(ctx, input.ClientID); err != nil {
		return domain.Mapping{}, err
	}
	if err := u.requireProxy(ctx, input.ProxyID); err != nil {
		return domain.Mapping{}, err
	}
	policyID := input.PolicyID
	if policyID == "" {
		policyID = "default-web-only"
	}
	if err := u.requirePolicy(ctx, policyID); err != nil {
		return domain.Mapping{}, err
	}
	id := input.ID
	if id == "" {
		id = uuid.NewString()
	}
	if err := domain.ValidateControlID("mapping_id", id); err != nil {
		return domain.Mapping{}, err
	}
	now := unixMilli(u.repo.now())
	if _, err := u.tx.ExecContext(ctx, `INSERT INTO mappings
        (id, client_id, proxy_id, policy_id, local_redirect_port, desired_state,
         desired_generation, applied_generation, data_plane_state, version, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 'DRAFT', 0, 0, 'UNKNOWN', 1, ?, ?)`,
		id, input.ClientID, input.ProxyID, policyID, input.LocalRedirectPort, now, now); err != nil {
		return domain.Mapping{}, mapWriteError(err, "mapping")
	}
	if err := u.audit(ctx, input.Actor, "mapping.create", "mapping", id, []byte(`{}`)); err != nil {
		return domain.Mapping{}, err
	}
	return u.mappingByID(ctx, id)
}

// AllocateLegacyRedirectPort preserves the former v1 create payload, which
// omitted local_redirect_port. It runs inside the same immediate transaction
// as creation/activation and reserves the lowest unused PGW forwarder port.
func (u *UnitOfWork) AllocateLegacyRedirectPort(ctx context.Context) (int, error) {
	for port := domain.ForwarderPortStart; port <= domain.ForwarderPortEnd; port++ {
		var found int
		err := u.tx.QueryRowContext(ctx, `SELECT 1 FROM mappings WHERE local_redirect_port = ? AND desired_state != 'DELETED' LIMIT 1`, port).Scan(&found)
		if errors.Is(err, sql.ErrNoRows) {
			return port, nil
		}
		if err != nil {
			return 0, fmt.Errorf("sqlite: allocate legacy redirect port: %w", err)
		}
	}
	return 0, &domain.ConflictError{Constraint: "local_redirect_port", Message: "no redirect ports are available"}
}

// ActivateMapping atomically validates the complete mapping, enforces the one
// primary ACTIVE mapping per client invariant, bumps the desired generation,
// and writes the audit record. No caller can observe a partially activated
// mapping or an activation without a generation for the Agent to reconcile.
func (r *Repository) ActivateMapping(ctx context.Context, mappingID, actor string) (domain.Mapping, error) {
	var mapping domain.Mapping
	err := r.WithinImmediate(ctx, func(ctx context.Context, uow *UnitOfWork) error {
		var err error
		mapping, err = uow.ActivateMapping(ctx, mappingID, actor)
		return err
	})
	return mapping, err
}

func (u *UnitOfWork) ActivateMapping(ctx context.Context, mappingID, actor string) (domain.Mapping, error) {
	mapping, err := u.mappingByID(ctx, mappingID)
	if err != nil {
		return domain.Mapping{}, err
	}
	if mapping.DesiredState == domain.DesiredDeleted {
		return domain.Mapping{}, &domain.ConflictError{Constraint: "mapping_state", Message: "deleted mapping cannot be activated"}
	}
	if err := u.requireEnabledClient(ctx, mapping.ClientID); err != nil {
		return domain.Mapping{}, err
	}
	if err := u.requireEnabledProxy(ctx, mapping.ProxyID); err != nil {
		return domain.Mapping{}, err
	}
	if err := u.validateProxyCredentialsForActivation(ctx, mapping.ProxyID); err != nil {
		return domain.Mapping{}, err
	}
	if err := u.requireEnabledPolicy(ctx, mapping.PolicyID); err != nil {
		return domain.Mapping{}, err
	}
	var activeID string
	err = u.tx.QueryRowContext(ctx, `SELECT id FROM mappings WHERE client_id = ? AND desired_state = 'ACTIVE' AND id <> ?`, mapping.ClientID, mappingID).Scan(&activeID)
	if err == nil {
		return domain.Mapping{}, &domain.ConflictError{Constraint: "one_active_mapping_per_client", Message: "client already has an ACTIVE primary mapping"}
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return domain.Mapping{}, fmt.Errorf("sqlite: check active mapping: %w", err)
	}
	now := unixMilli(u.repo.now())
	if _, err := u.tx.ExecContext(ctx, `INSERT INTO reconcile_states
        (node_id, pending_generation, applied_generation, ruleset_hash, state, last_error, updated_at)
        VALUES (?, 1, 0, '', 'PENDING', '', ?)
        ON CONFLICT(node_id) DO UPDATE SET pending_generation = pending_generation + 1, state = 'PENDING', updated_at = excluded.updated_at`,
		controlPlaneNodeID, now); err != nil {
		return domain.Mapping{}, fmt.Errorf("sqlite: bump desired generation: %w", err)
	}
	var generation int64
	if err := u.tx.QueryRowContext(ctx, `SELECT pending_generation FROM reconcile_states WHERE node_id = ?`, controlPlaneNodeID).Scan(&generation); err != nil {
		return domain.Mapping{}, fmt.Errorf("sqlite: read desired generation: %w", err)
	}
	if _, err := u.tx.ExecContext(ctx, `UPDATE mappings SET desired_state = 'ACTIVE', desired_generation = ?,
        data_plane_state = 'UNKNOWN', version = version + 1, updated_at = ? WHERE id = ?`, generation, now, mappingID); err != nil {
		return domain.Mapping{}, mapWriteError(err, "mapping")
	}
	snapshot, err := u.repo.desiredSnapshotFor(ctx, u.tx, generation)
	if err != nil {
		return domain.Mapping{}, err
	}
	if _, err := u.tx.ExecContext(ctx, `UPDATE mappings SET desired_hash = ? WHERE desired_state != 'DELETED'`, snapshot.DesiredHash); err != nil {
		return domain.Mapping{}, fmt.Errorf("sqlite: record desired snapshot hash: %w", err)
	}
	payload := auditJSON(map[string]int64{"desired_generation": generation})
	if err := u.audit(ctx, actor, "mapping.activate", "mapping", mappingID, payload); err != nil {
		return domain.Mapping{}, err
	}
	return u.mappingByID(ctx, mappingID)
}

func (r *Repository) SuspendMapping(ctx context.Context, mappingID, actor string) (domain.Mapping, error) {
	var mapping domain.Mapping
	err := r.WithinTx(ctx, func(ctx context.Context, uow *UnitOfWork) error {
		var err error
		mapping, err = uow.transitionMapping(ctx, mappingID, domain.DesiredSuspended, actor)
		return err
	})
	return mapping, err
}

func (u *UnitOfWork) transitionMapping(ctx context.Context, mappingID string, desired domain.DesiredState, actor string) (domain.Mapping, error) {
	if _, err := u.mappingByID(ctx, mappingID); err != nil {
		return domain.Mapping{}, err
	}
	now := unixMilli(u.repo.now())
	if _, err := u.tx.ExecContext(ctx, `INSERT INTO reconcile_states
        (node_id, pending_generation, applied_generation, ruleset_hash, state, last_error, updated_at)
        VALUES (?, 1, 0, '', 'PENDING', '', ?)
        ON CONFLICT(node_id) DO UPDATE SET pending_generation = pending_generation + 1, state = 'PENDING', updated_at = excluded.updated_at`, controlPlaneNodeID, now); err != nil {
		return domain.Mapping{}, fmt.Errorf("sqlite: bump desired generation: %w", err)
	}
	var generation int64
	if err := u.tx.QueryRowContext(ctx, `SELECT pending_generation FROM reconcile_states WHERE node_id = ?`, controlPlaneNodeID).Scan(&generation); err != nil {
		return domain.Mapping{}, fmt.Errorf("sqlite: read desired generation: %w", err)
	}
	if _, err := u.tx.ExecContext(ctx, `UPDATE mappings SET desired_state = ?, desired_generation = ?,
        data_plane_state = 'UNKNOWN', version = version + 1, updated_at = ? WHERE id = ?`, desired, generation, now, mappingID); err != nil {
		return domain.Mapping{}, mapWriteError(err, "mapping")
	}
	snapshot, err := u.repo.desiredSnapshotFor(ctx, u.tx, generation)
	if err != nil {
		return domain.Mapping{}, err
	}
	if _, err := u.tx.ExecContext(ctx, `UPDATE mappings SET desired_hash = ? WHERE desired_state != 'DELETED'`, snapshot.DesiredHash); err != nil {
		return domain.Mapping{}, fmt.Errorf("sqlite: record desired snapshot hash: %w", err)
	}
	if err := u.audit(ctx, actor, "mapping."+strings.ToLower(string(desired)), "mapping", mappingID,
		auditJSON(map[string]int64{"desired_generation": generation})); err != nil {
		return domain.Mapping{}, err
	}
	return u.mappingByID(ctx, mappingID)
}

func (r *Repository) GetMapping(ctx context.Context, id string) (domain.Mapping, error) {
	return scanMapping(r.db.QueryRowContext(ctx, mappingSelect+` WHERE id = ?`, id), id)
}

func (r *Repository) GetReconcileState(ctx context.Context) (domain.ReconcileState, error) {
	var state domain.ReconcileState
	var updated int64
	err := r.db.QueryRowContext(ctx, `SELECT node_id, pending_generation, applied_generation, ruleset_hash, state, last_error, updated_at
        FROM reconcile_states WHERE node_id = ?`, controlPlaneNodeID).Scan(
		&state.NodeID, &state.PendingGeneration, &state.AppliedGeneration, &state.RulesetHash, &state.State, &state.LastError, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ReconcileState{NodeID: controlPlaneNodeID, State: "UNKNOWN"}, nil
	}
	if err != nil {
		return domain.ReconcileState{}, fmt.Errorf("sqlite: get reconcile state: %w", err)
	}
	state.UpdatedAt = fromUnixMilli(updated)
	return state, nil
}

func (u *UnitOfWork) audit(ctx context.Context, actor, action, entity, entityID string, payload []byte) error {
	if len(payload) == 0 {
		payload = []byte(`{}`)
	}
	_, err := u.tx.ExecContext(ctx, `INSERT INTO audit_events (actor, action, entity, entity_id, payload, created_at)
        VALUES (?, ?, ?, ?, ?, ?)`, actor, action, entity, entityID, payload, unixMilli(u.repo.now()))
	if err != nil {
		return fmt.Errorf("sqlite: append audit event: %w", err)
	}
	return nil
}

func auditJSON(value any) []byte {
	payload, err := json.Marshal(value)
	if err != nil {
		// Audit payloads here are only fixed primitive metadata. Retain valid JSON
		// even if a future caller gives an unsupported value.
		return []byte(`{"encoding_error":true}`)
	}
	return payload
}

func (u *UnitOfWork) requireClient(ctx context.Context, id string) error {
	var enabled int
	err := u.tx.QueryRowContext(ctx, `SELECT enabled FROM clients WHERE id = ? AND deleted_at IS NULL`, id).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return &domain.NotFoundError{Entity: "client", ID: id}
	}
	if err != nil {
		return fmt.Errorf("sqlite: get client: %w", err)
	}
	return nil
}

func (u *UnitOfWork) requireEnabledClient(ctx context.Context, id string) error {
	var enabled int
	err := u.tx.QueryRowContext(ctx, `SELECT enabled FROM clients WHERE id = ? AND deleted_at IS NULL`, id).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return &domain.NotFoundError{Entity: "client", ID: id}
	}
	if err != nil {
		return fmt.Errorf("sqlite: get client: %w", err)
	}
	if enabled == 0 {
		return &domain.ConflictError{Constraint: "client_enabled", Message: "client is disabled"}
	}
	return nil
}

func (u *UnitOfWork) requireProxy(ctx context.Context, id string) error {
	var enabled int
	err := u.tx.QueryRowContext(ctx, `SELECT enabled FROM proxies WHERE id = ? AND deleted_at IS NULL`, id).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return &domain.NotFoundError{Entity: "proxy", ID: id}
	}
	if err != nil {
		return fmt.Errorf("sqlite: get proxy: %w", err)
	}
	return nil
}

func (u *UnitOfWork) requireEnabledProxy(ctx context.Context, id string) error {
	var enabled int
	err := u.tx.QueryRowContext(ctx, `SELECT enabled FROM proxies WHERE id = ? AND deleted_at IS NULL`, id).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return &domain.NotFoundError{Entity: "proxy", ID: id}
	}
	if err != nil {
		return fmt.Errorf("sqlite: get proxy: %w", err)
	}
	if enabled == 0 {
		return &domain.ConflictError{Constraint: "proxy_enabled", Message: "proxy is disabled"}
	}
	return nil
}

// validateProxyCredentialsForActivation validates the exact ciphertext that
// will be handed to the Agent. In particular RFC 1929 limits SOCKS5 auth
// fields to 255 bytes; accepting a value that the forwarder cannot consume
// would otherwise create a mapping that can never become VERIFIED.
func (u *UnitOfWork) validateProxyCredentialsForActivation(ctx context.Context, id string) error {
	var proxyType domain.ProxyType
	var username string
	var envelopeVersion sql.NullInt64
	var nonce, ciphertext []byte
	err := u.tx.QueryRowContext(ctx, `SELECT p.type, p.username, s.envelope_version, s.nonce, s.ciphertext
        FROM proxies p LEFT JOIN proxy_secrets s ON s.proxy_id = p.id
        WHERE p.id = ? AND p.deleted_at IS NULL`, id).Scan(&proxyType, &username, &envelopeVersion, &nonce, &ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		return &domain.NotFoundError{Entity: "proxy", ID: id}
	}
	if err != nil {
		return fmt.Errorf("sqlite: read proxy credential for activation: %w", err)
	}
	if !envelopeVersion.Valid {
		return domain.ValidateProxyAuthentication(proxyType, username, nil, false)
	}
	password, err := u.repo.cipher.Open(secret.Envelope{Version: uint8(envelopeVersion.Int64), Nonce: nonce, Ciphertext: ciphertext}, []byte(id))
	if err != nil {
		return fmt.Errorf("sqlite: decrypt proxy credential for activation: %w", err)
	}
	defer zero(password)
	return domain.ValidateProxyAuthentication(proxyType, username, password, true)
}

func (u *UnitOfWork) requirePolicy(ctx context.Context, id string) error {
	var enabled int
	err := u.tx.QueryRowContext(ctx, `SELECT enabled FROM egress_policies WHERE id = ?`, id).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return &domain.NotFoundError{Entity: "egress policy", ID: id}
	}
	if err != nil {
		return fmt.Errorf("sqlite: get egress policy: %w", err)
	}
	return nil
}

func (u *UnitOfWork) requireEnabledPolicy(ctx context.Context, id string) error {
	var enabled int
	err := u.tx.QueryRowContext(ctx, `SELECT enabled FROM egress_policies WHERE id = ?`, id).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return &domain.NotFoundError{Entity: "egress policy", ID: id}
	}
	if err != nil {
		return fmt.Errorf("sqlite: get egress policy: %w", err)
	}
	if enabled == 0 {
		return &domain.ConflictError{Constraint: "policy_enabled", Message: "egress policy is disabled"}
	}
	return nil
}

const proxySelect = `SELECT p.id, p.label, p.type, p.host, p.port, p.username,
    EXISTS(SELECT 1 FROM proxy_secrets s WHERE s.proxy_id = p.id), p.enabled, p.status,
    p.latency_ms, p.exit_ip, p.last_checked_at, p.version, p.proxy_revision, p.credential_revision, p.created_at, p.updated_at
    FROM proxies p`

type scanner interface{ Scan(...any) error }

func scanProxy(row scanner, missingID string) (domain.Proxy, error) {
	var proxy domain.Proxy
	var configured, enabled int
	var latency, lastChecked sql.NullInt64
	var created, updated int64
	err := row.Scan(&proxy.ID, &proxy.Label, &proxy.Type, &proxy.Host, &proxy.Port, &proxy.Username,
		&configured, &enabled, &proxy.Status, &latency, &proxy.ExitIP, &lastChecked, &proxy.Version, &proxy.ProxyRevision, &proxy.CredentialRevision, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Proxy{}, &domain.NotFoundError{Entity: "proxy", ID: missingID}
	}
	if err != nil {
		return domain.Proxy{}, fmt.Errorf("sqlite: scan proxy: %w", err)
	}
	proxy.PasswordConfigured = configured != 0
	proxy.Enabled = enabled != 0
	if latency.Valid {
		v := int(latency.Int64)
		proxy.LatencyMS = &v
	}
	if lastChecked.Valid {
		v := fromUnixMilli(lastChecked.Int64)
		proxy.LastCheckedAt = &v
	}
	proxy.CreatedAt, proxy.UpdatedAt = fromUnixMilli(created), fromUnixMilli(updated)
	return proxy, nil
}

const mappingSelect = `SELECT id, client_id, proxy_id, policy_id, local_redirect_port, desired_state,
    desired_generation, applied_generation, desired_hash, applied_hash, data_plane_state, version, created_at, updated_at FROM mappings`

func scanMapping(row scanner, missingID string) (domain.Mapping, error) {
	var mapping domain.Mapping
	var created, updated int64
	err := row.Scan(&mapping.ID, &mapping.ClientID, &mapping.ProxyID, &mapping.PolicyID, &mapping.LocalRedirectPort,
		&mapping.DesiredState, &mapping.DesiredGeneration, &mapping.AppliedGeneration, &mapping.DesiredHash,
		&mapping.AppliedHash, &mapping.DataPlaneState, &mapping.Version, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Mapping{}, &domain.NotFoundError{Entity: "mapping", ID: missingID}
	}
	if err != nil {
		return domain.Mapping{}, fmt.Errorf("sqlite: scan mapping: %w", err)
	}
	mapping.CreatedAt, mapping.UpdatedAt = fromUnixMilli(created), fromUnixMilli(updated)
	return mapping, nil
}

func (u *UnitOfWork) proxyByID(ctx context.Context, id string) (domain.Proxy, error) {
	return scanProxy(u.tx.QueryRowContext(ctx, proxySelect+` WHERE p.id = ? AND p.deleted_at IS NULL`, id), id)
}

func (u *UnitOfWork) clientByID(ctx context.Context, id string) (domain.Client, error) {
	var client domain.Client
	var enabled int
	var created, updated int64
	err := u.tx.QueryRowContext(ctx, `SELECT id, ip_cidr, note, enabled, version, created_at, updated_at FROM clients WHERE id = ? AND deleted_at IS NULL`, id).
		Scan(&client.ID, &client.IPCIDR, &client.Note, &enabled, &client.Version, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Client{}, &domain.NotFoundError{Entity: "client", ID: id}
	}
	if err != nil {
		return domain.Client{}, fmt.Errorf("sqlite: scan client: %w", err)
	}
	client.Enabled = enabled != 0
	client.CreatedAt, client.UpdatedAt = fromUnixMilli(created), fromUnixMilli(updated)
	return client, nil
}

func (u *UnitOfWork) mappingByID(ctx context.Context, id string) (domain.Mapping, error) {
	return scanMapping(u.tx.QueryRowContext(ctx, mappingSelect+` WHERE id = ?`, id), id)
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func unixMilli(value time.Time) int64     { return value.UTC().UnixMilli() }
func fromUnixMilli(value int64) time.Time { return time.UnixMilli(value).UTC() }

func mapWriteError(err error, entity string) error {
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "unique constraint") || strings.Contains(message, "constraint failed") {
		return &domain.ConflictError{Constraint: entity, Message: entity + " conflicts with existing data"}
	}
	return fmt.Errorf("sqlite: write %s: %w", entity, err)
}

func isBusyError(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "database is locked") || strings.Contains(message, "database is busy") || strings.Contains(message, "sqlite_busy")
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
