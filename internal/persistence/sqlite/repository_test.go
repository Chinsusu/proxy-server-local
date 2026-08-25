package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Chinsusu/proxy-server-local/internal/domain"
)

type testKeyProvider []byte

func (p testKeyProvider) Key(context.Context) ([]byte, error) { return append([]byte(nil), p...), nil }

func openTestRepository(t *testing.T) *Repository {
	t.Helper()
	return openTestRepositoryAt(t, filepath.Join(t.TempDir(), "pgw.db"))
}

func openTestRepositoryAt(t *testing.T, path string) *Repository {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("persistent SQLite requires the production ACL/lock provider on Windows")
	}
	now := time.Date(2026, 8, 24, 1, 2, 3, 0, time.UTC)
	repository, err := Open(context.Background(), Config{
		Path:        path,
		KeyProvider: testKeyProvider(bytes.Repeat([]byte{9}, 32)),
		Clock:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repository.Close() })
	return repository
}

func TestOpenConfiguresSQLiteAndMigratesFullSchema(t *testing.T) {
	repository := openTestRepository(t)
	ctx := context.Background()
	version, err := SchemaVersion(ctx, repository.DB())
	if err != nil || version != 5 {
		t.Fatalf("schema version=%d err=%v", version, err)
	}
	var foreignKeys, busyTimeout int
	var journalMode string
	if err := repository.DB().QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil || foreignKeys != 1 {
		t.Fatalf("foreign_keys=%d err=%v", foreignKeys, err)
	}
	if err := repository.DB().QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&busyTimeout); err != nil || busyTimeout != 5000 {
		t.Fatalf("busy_timeout=%d err=%v", busyTimeout, err)
	}
	if err := repository.DB().QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&journalMode); err != nil || strings.ToLower(journalMode) != "wal" {
		t.Fatalf("journal_mode=%q err=%v", journalMode, err)
	}
	for _, table := range []string{"proxies", "proxy_secrets", "proxy_capabilities", "proxy_health_snapshots", "clients", "egress_policies", "mappings", "nodes", "reconcile_states", "audit_events", "idempotency_keys", "schema_migrations"} {
		var name string
		err := repository.DB().QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&name)
		if err != nil || name != table {
			t.Fatalf("table %s missing: %v", table, err)
		}
	}
	if _, err := repository.DB().ExecContext(ctx, `INSERT INTO schema_migrations (version, name, applied_at) VALUES (99, 'future', 0)`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, repository.DB()); !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("future schema migration error=%v", err)
	}
}

func TestOpenRejectsPermissiveIPv6Policy(t *testing.T) {
	_, err := Open(context.Background(), Config{
		Path:        ":memory:",
		KeyProvider: testKeyProvider(bytes.Repeat([]byte{2}, 32)),
		IPv6Policy:  domain.IPv6Policy("allow"),
	})
	if err == nil {
		t.Fatal("permissive IPv6 policy accepted")
	}
}

func TestFailedMigrationLeavesOnlySecureSQLiteArtifacts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("persistent SQLite path fails closed on Windows")
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "failed-migration.db")
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL)`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO schema_migrations(version, name, applied_at) VALUES(999, 'future', 0)`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, Config{Path: path, KeyProvider: testKeyProvider(bytes.Repeat([]byte{4}, 32))}); !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("failed migration error=%v", err)
	}
	for _, artifact := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Lstat(artifact)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("migration artifact secure=%t err=%v", err == nil && info.Mode().IsRegular() && info.Mode().Perm() == 0o600, err)
		}
	}
}

func TestConcurrentMigrateSerializesAndRereadsLedger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concurrent-migrate.db")
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errs <- Migrate(context.Background(), db)
		}()
	}
	close(start)
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil || count != 5 {
		t.Fatalf("migration rows=%d err=%v", count, err)
	}
	if err := validateExactSchema(context.Background(), db, true); err != nil {
		t.Fatalf("canonical schema validation: %v", err)
	}
}

func TestProxySecretsAreEncryptedAndPublicReadIsRedacted(t *testing.T) {
	repository := openTestRepository(t)
	ctx := context.Background()
	proxy, err := repository.CreateProxy(ctx, CreateProxyInput{
		ID: "proxy-1", Type: domain.ProxyHTTP, Host: "proxy.example", Port: 8080,
		Username: "alice", Password: []byte("canary-secret"), Enabled: true, Actor: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !proxy.PasswordConfigured || proxy.Username != "alice" {
		t.Fatalf("public proxy configured=%t username_match=%t", proxy.PasswordConfigured, proxy.Username == "alice")
	}
	encoded, err := json.Marshal(proxy)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "canary-secret") || strings.Contains(string(encoded), "ciphertext") {
		t.Fatalf("public DTO leaked secret=%t ciphertext_field=%t encoded_length=%d", strings.Contains(string(encoded), "canary-secret"), strings.Contains(string(encoded), "ciphertext"), len(encoded))
	}
	var ciphertext []byte
	if err := repository.DB().QueryRowContext(ctx, `SELECT ciphertext FROM proxy_secrets WHERE proxy_id = ?`, proxy.ID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte("canary-secret")) {
		t.Fatal("database ciphertext contains plaintext")
	}
	backupPath := filepath.Join(t.TempDir(), "secret-free.db")
	if _, err := repository.Backup(ctx, backupPath); err != nil {
		t.Fatal(err)
	}
	backupBytes, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(backupBytes, []byte("canary-secret")) {
		t.Fatal("backup contains plaintext")
	}
	rows, err := repository.DB().QueryContext(ctx, `SELECT payload FROM audit_events`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(payload, []byte("canary-secret")) {
			t.Fatal("audit event contains secret canary")
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	credential, err := repository.GetProxyCredential(ctx, proxy.ID)
	defer zero(credential.Password)
	if err != nil || string(credential.Password) != "canary-secret" || credential.Username != "alice" {
		t.Fatalf("credential retrieval failed: configured=%t username_match=%t err=%v", credential.Password != nil, credential.Username == "alice", err)
	}
	if _, err := repository.GetProxyCredential(ctx, "missing"); err == nil {
		t.Fatal("missing credential unexpectedly succeeded")
	} else {
		var notFound *domain.NotFoundError
		if !errors.As(err, &notFound) {
			t.Fatalf("wanted typed not found, got %T %v", err, err)
		}
	}
}

func TestActivationIsAtomicAndEnforcesOneActivePrimary(t *testing.T) {
	repository := openTestRepository(t)
	ctx := context.Background()
	proxy, err := repository.CreateProxy(ctx, CreateProxyInput{ID: "p", Type: domain.ProxyHTTP, Host: "proxy", Port: 8080, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	client, err := repository.CreateClient(ctx, CreateClientInput{ID: "c", IPCIDR: "192.168.2.101", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	first, err := repository.CreateMapping(ctx, CreateMappingInput{ID: "m1", ClientID: client.ID, ProxyID: proxy.ID, LocalRedirectPort: 15001})
	if err != nil || first.DesiredState != domain.DesiredDraft {
		t.Fatalf("mapping desired_state=%q err=%v", first.DesiredState, err)
	}
	active, err := repository.ActivateMapping(ctx, first.ID, "admin-1")
	if err != nil {
		t.Fatal(err)
	}
	if active.DesiredState != domain.DesiredActive || active.DesiredGeneration != 1 || active.DataPlaneState != domain.DataPlaneUnknown {
		t.Fatalf("activation state=%q generation=%d dataplane=%q", active.DesiredState, active.DesiredGeneration, active.DataPlaneState)
	}
	second, err := repository.CreateMapping(ctx, CreateMappingInput{ID: "m2", ClientID: client.ID, ProxyID: proxy.ID, LocalRedirectPort: 15002})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.ActivateMapping(ctx, second.ID, "admin-1"); err == nil {
		t.Fatal("second active mapping succeeded")
	} else {
		var conflict *domain.ConflictError
		if !errors.As(err, &conflict) {
			t.Fatalf("want conflict, got %T %v", err, err)
		}
	}
	second, err = repository.GetMapping(ctx, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if second.DesiredState != domain.DesiredDraft || second.DesiredGeneration != 0 {
		t.Fatalf("failed activation persisted state=%q generation=%d", second.DesiredState, second.DesiredGeneration)
	}
	state, err := repository.GetReconcileState(ctx)
	if err != nil || state.PendingGeneration != 1 {
		t.Fatalf("reconcile pending_generation=%d err=%v", state.PendingGeneration, err)
	}
	var auditCount int
	if err := repository.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events WHERE action = 'mapping.activate' AND entity_id = 'm1'`).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("activation audit count=%d err=%v", auditCount, err)
	}
}

func TestActivationValidationRollbackLeavesNoGeneration(t *testing.T) {
	repository := openTestRepository(t)
	ctx := context.Background()
	proxy, err := repository.CreateProxy(ctx, CreateProxyInput{ID: "p", Type: domain.ProxyHTTP, Host: "proxy", Port: 8080, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	client, err := repository.CreateClient(ctx, CreateClientInput{ID: "disabled", IPCIDR: "192.168.2.102/32", Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	mapping, err := repository.CreateMapping(ctx, CreateMappingInput{ID: "m", ClientID: client.ID, ProxyID: proxy.ID, LocalRedirectPort: 15001})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.ActivateMapping(ctx, mapping.ID, "admin"); err == nil {
		t.Fatal("disabled client activation succeeded")
	}
	state, err := repository.GetReconcileState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.PendingGeneration != 0 {
		t.Fatalf("generation advanced after failed validation: %d", state.PendingGeneration)
	}
}

func TestConcurrentActivationEnforcesOneActiveRedirectPort(t *testing.T) {
	repository := openTestRepository(t)
	ctx := context.Background()
	proxy, err := repository.CreateProxy(ctx, CreateProxyInput{ID: "p", Type: domain.ProxyHTTP, Host: "proxy", Port: 8080, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	firstClient, err := repository.CreateClient(ctx, CreateClientInput{ID: "c1", IPCIDR: "192.168.2.103", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	secondClient, err := repository.CreateClient(ctx, CreateClientInput{ID: "c2", IPCIDR: "192.168.2.104", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	first, err := repository.CreateMapping(ctx, CreateMappingInput{ID: "m1", ClientID: firstClient.ID, ProxyID: proxy.ID, LocalRedirectPort: 15017})
	if err != nil {
		t.Fatal(err)
	}
	second, err := repository.CreateMapping(ctx, CreateMappingInput{ID: "m2", ClientID: secondClient.ID, ProxyID: proxy.ID, LocalRedirectPort: 15017})
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wait sync.WaitGroup
	for _, mapping := range []string{first.ID, second.ID} {
		wait.Add(1)
		go func(mappingID string) {
			defer wait.Done()
			<-start
			_, err := repository.ActivateMapping(ctx, mappingID, "race-test")
			errs <- err
		}(mapping)
	}
	close(start)
	wait.Wait()
	close(errs)
	successes, conflicts := 0, 0
	for err := range errs {
		if err == nil {
			successes++
			continue
		}
		var conflict *domain.ConflictError
		if errors.As(err, &conflict) {
			conflicts++
			continue
		}
		t.Fatalf("unexpected concurrent activation error: %v", err)
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
}

func TestBackupIntegrityAndRestoreGate(t *testing.T) {
	repository := openTestRepository(t)
	ctx := context.Background()
	if _, err := repository.CreateProxy(ctx, CreateProxyInput{Type: domain.ProxyHTTP, Host: "proxy", Port: 8080, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(t.TempDir(), "pgw.backup.db")
	metadata, err := repository.Backup(ctx, backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.SHA256 == "" || metadata.Bytes == 0 || metadata.SchemaVersion != 5 {
		t.Fatalf("metadata sha_present=%t bytes=%d schema_version=%d", metadata.SHA256 != "", metadata.Bytes, metadata.SchemaVersion)
	}
	if err := CheckIntegrity(ctx, backupPath); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	if err := Restore(ctx, backupPath, filepath.Join(t.TempDir(), "restored.db"), RestoreOptions{}); !errors.Is(err, ErrServicesNotStopped) {
		t.Fatalf("restore gate err=%v", err)
	}
	restored := filepath.Join(t.TempDir(), "restored.db")
	if err := Restore(ctx, backupPath, restored, RestoreOptions{ServicesStopped: true, ExpectedSHA256: metadata.SHA256}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(restored); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreProvenanceRejectsEmptyLedgerBeforeMigration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("persistent restore validation fails closed on Windows")
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "empty-ledger.db")
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, db); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM schema_migrations`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	checksum := checksumForTest(t, path)
	if err := verifyTrustedBackup(ctx, path, checksum); err == nil {
		t.Fatal("restore accepted an empty migration ledger")
	}
}

func TestRestoreProvenanceAcceptsPreChecksumPrefixAndUpgradesStaging(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("persistent restore validation fails closed on Windows")
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "pre-v3-prefix.db")
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	migrations, err := knownMigrations()
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL)`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, migrations[0].sql); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO schema_migrations(version, name, applied_at) VALUES(?, ?, 0)`, migrations[0].version, migrations[0].name); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, migrations[1].sql); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO schema_migrations(version, name, applied_at) VALUES(?, ?, 0)`, migrations[1].version, migrations[1].name); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	checksum := checksumForTest(t, path)
	if err := verifyTrustedBackup(ctx, path, checksum); err != nil {
		t.Fatalf("pre-checksum prefix was not upgraded: %v", err)
	}
	upgraded, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	version, err := SchemaVersion(ctx, upgraded)
	if err != nil || version != len(migrations) {
		t.Fatalf("upgraded provenance version=%d err=%v", version, err)
	}
}

func TestMigrationLedgerRejectsChecksumEraEntryWithoutChecksum(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE schema_migrations SET checksum = '' WHERE version = 3`); err != nil {
		t.Fatal(err)
	}
	migrations, err := knownMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateMigrationLedger(ctx, db, migrations); err == nil {
		t.Fatal("checksum-era ledger entry without checksum was accepted")
	}
}

func TestCheckIntegrityRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink and persistent-path policy differ")
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "target.db")
	if err := os.WriteFile(target, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link.db")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := CheckIntegrity(context.Background(), link); err == nil {
		t.Fatal("integrity accepted symlink target")
	}
}

func TestRepositoryOpenRejectsDatabaseSymlinkWithoutTouchingTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("persistent SQLite path fails closed on Windows")
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "target.db")
	original := []byte("not-a-sqlite-database")
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "database.db")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_, err := Open(context.Background(), Config{Path: link, KeyProvider: testKeyProvider(bytes.Repeat([]byte{3}, 32))})
	if err == nil {
		t.Fatal("repository opened a symlink database path")
	}
	after, readErr := os.ReadFile(target)
	if readErr != nil || !bytes.Equal(original, after) {
		t.Fatalf("symlink target changed unchanged=%t err=%v", bytes.Equal(original, after), readErr)
	}
	if info, statErr := os.Lstat(link); statErr != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("database symlink changed is_symlink=%t err=%v", statErr == nil && info.Mode()&os.ModeSymlink != 0, statErr)
	}
	for _, path := range []string{target + "-wal", target + "-shm", link + "-wal", link + "-shm"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("unexpected sidecar created")
		}
	}
}

func TestCheckIntegrityDoesNotModifySourceOrSidecars(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("persistent integrity path fails closed on Windows")
	}
	path := filepath.Join(t.TempDir(), "source.db")
	createMarkerDatabase(t, path, "source")
	if err := os.WriteFile(path+"-wal", []byte("sentinel-sidecar"), 0o600); err != nil {
		t.Fatal(err)
	}
	beforeMain, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	beforeWAL, err := os.ReadFile(path + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckIntegrity(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	afterMain, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(beforeMain, afterMain) {
		t.Fatalf("integrity modified source bytes unchanged=%t err=%v", bytes.Equal(beforeMain, afterMain), err)
	}
	afterWAL, err := os.ReadFile(path + "-wal")
	if err != nil || !bytes.Equal(beforeWAL, afterWAL) {
		t.Fatalf("integrity modified source sidecar unchanged=%t err=%v", bytes.Equal(beforeWAL, afterWAL), err)
	}
}

func TestCheckIntegrityPathSwapNeverCreatesSourceSidecars(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("persistent integrity path fails closed on Windows")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "live.db")
	other := filepath.Join(directory, "other.db")
	createMarkerDatabase(t, path, "one")
	createMarkerDatabase(t, other, "two")
	stop := make(chan struct{})
	done := make(chan struct{})
	swapErr := make(chan error, 1)
	go func() {
		defer close(done)
		temporary := filepath.Join(directory, "swap.db")
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := os.Rename(path, temporary); err != nil {
				swapErr <- err
				return
			}
			if err := os.Rename(other, path); err != nil {
				swapErr <- err
				return
			}
			if err := os.Rename(temporary, other); err != nil {
				swapErr <- err
				return
			}
		}
	}()
	for range 30 {
		// A racing path may disappear or be rejected as changed; success is also
		// safe because it validates the private copy from one opened descriptor.
		_ = CheckIntegrity(context.Background(), path)
	}
	close(stop)
	<-done
	select {
	case err := <-swapErr:
		t.Fatalf("path swap failed: %v", err)
	default:
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("live path missing after swap: %v", err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Lstat(path + suffix); !os.IsNotExist(err) {
			t.Fatalf("integrity created or retained unexpected source sidecar %s", suffix)
		}
	}
}

func TestBackupPublicationDoesNotClobberConcurrentWriter(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("persistent backups fail closed on Windows pending ACL support")
	}
	repository := openTestRepository(t)
	destination := filepath.Join(t.TempDir(), "contended-backup.db")
	start := make(chan struct{})
	type backupResult struct {
		metadata BackupMetadata
		err      error
	}
	results := make(chan backupResult, 2)
	for range 2 {
		go func() {
			<-start
			metadata, err := repository.Backup(context.Background(), destination)
			results <- backupResult{metadata: metadata, err: err}
		}()
	}
	close(start)
	successes, exists := 0, 0
	var success BackupMetadata
	for range 2 {
		result := <-results
		if result.err == nil {
			successes++
			success = result.metadata
		} else if errors.Is(result.err, ErrBackupExists) {
			exists++
		} else {
			t.Fatalf("unexpected concurrent backup error: %v", result.err)
		}
	}
	if successes != 1 || exists != 1 {
		t.Fatalf("backup publication successes=%d exists=%d", successes, exists)
	}
	checksum, bytes, err := fileChecksum(destination)
	if err != nil || checksum != success.SHA256 || bytes != success.Bytes {
		t.Fatalf("published backup metadata mismatch checksum_match=%t bytes_match=%t err=%v", checksum == success.SHA256, bytes == success.Bytes, err)
	}
}

func TestMemoryRepositoryBackupFailsClosedOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only fail-closed contract")
	}
	repository, err := Open(context.Background(), Config{Path: ":memory:", KeyProvider: testKeyProvider(bytes.Repeat([]byte{7}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	if _, err := repository.Backup(context.Background(), filepath.Join(t.TempDir(), "memory.db")); !errors.Is(err, ErrDatabaseLocked) {
		t.Fatalf("in-memory backup error=%v", err)
	}
}

func TestRestoreReplacementFailurePreservesLiveDatabaseAndStaleSidecars(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("existing destination replacement is intentionally fail-closed on Windows")
	}
	ctx := context.Background()
	sourceRepository := openTestRepositoryAt(t, filepath.Join(t.TempDir(), "source.db"))
	if _, err := sourceRepository.CreateProxy(ctx, CreateProxyInput{ID: "source", Type: domain.ProxyHTTP, Host: "source-proxy", Port: 8080, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	sourceBackup := filepath.Join(t.TempDir(), "source.backup.db")
	sourceMetadata, err := sourceRepository.Backup(ctx, sourceBackup)
	if err != nil {
		t.Fatal(err)
	}

	destination := filepath.Join(t.TempDir(), "live.db")
	liveRepository := openTestRepositoryAt(t, destination)
	if _, err := liveRepository.CreateProxy(ctx, CreateProxyInput{ID: "live", Type: domain.ProxyHTTP, Host: "live-proxy", Port: 8080, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := liveRepository.Close(); err != nil {
		t.Fatal(err)
	}
	originalReplace := atomicReplaceForRestore
	atomicReplaceForRestore = func(string, string) error { return errors.New("injected rename failure") }
	t.Cleanup(func() { atomicReplaceForRestore = originalReplace })
	if err := Restore(ctx, sourceBackup, destination, RestoreOptions{ServicesStopped: true, AllowReplace: true, ExpectedSHA256: sourceMetadata.SHA256}); err == nil {
		t.Fatal("restore with injected replacement failure succeeded")
	}
	if err := CheckIntegrity(ctx, destination); err != nil {
		t.Fatalf("live destination damaged after failed restore: %v", err)
	}
	liveRepository = openTestRepositoryAt(t, destination)
	if _, err := liveRepository.GetProxy(ctx, "live"); err != nil {
		t.Fatalf("live record lost after failed restore: %v", err)
	}
	_ = liveRepository.Close()

	atomicReplaceForRestore = originalReplace
	if err := Restore(ctx, sourceBackup, destination, RestoreOptions{ServicesStopped: true, AllowReplace: true, ExpectedSHA256: sourceMetadata.SHA256}); err != nil {
		t.Fatal(err)
	}
	restoredRepository := openTestRepositoryAt(t, destination)
	if _, err := restoredRepository.GetProxy(ctx, "source"); err != nil {
		t.Fatalf("source database was not restored: %v", err)
	}
	if _, err := restoredRepository.GetProxy(ctx, "live"); err == nil {
		t.Fatal("old live database survived successful restore")
	}
}

func TestLiveRepositoryBlocksRestoreUntilClose(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows persistent database path fails closed")
	}
	ctx := context.Background()
	sourceRepository := openTestRepositoryAt(t, filepath.Join(t.TempDir(), "source.db"))
	if _, err := sourceRepository.CreateProxy(ctx, CreateProxyInput{Type: domain.ProxyHTTP, Host: "source", Port: 8080, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	sourceBackup := filepath.Join(t.TempDir(), "source.backup.db")
	metadata, err := sourceRepository.Backup(ctx, sourceBackup)
	if err != nil {
		t.Fatal(err)
	}
	if err := sourceRepository.Close(); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "destination.db")
	live := openTestRepositoryAt(t, destination)
	if err := Restore(ctx, sourceBackup, destination, RestoreOptions{ServicesStopped: true, AllowReplace: true, ExpectedSHA256: metadata.SHA256}); !errors.Is(err, ErrDatabaseLocked) {
		t.Fatalf("restore with live repository err=%v, want ErrDatabaseLocked", err)
	}
	if err := live.Close(); err != nil {
		t.Fatal(err)
	}
	if err := Restore(ctx, sourceBackup, destination, RestoreOptions{ServicesStopped: true, AllowReplace: true, ExpectedSHA256: metadata.SHA256}); err != nil {
		t.Fatalf("restore after repository close: %v", err)
	}
}

// TestRestoreCrashHelper is executed in subprocesses so os.Exit leaves the
// database exactly as a power loss would: no deferred Close/checkpoint runs.
func TestRestoreCrashHelper(t *testing.T) {
	mode := os.Getenv("PGW_RESTORE_CRASH_MODE")
	if mode == "" {
		return
	}
	path := os.Getenv("PGW_RESTORE_CRASH_DESTINATION")
	switch mode {
	case "write_wal":
		db, err := sql.Open("sqlite", sqliteDSN(path))
		if err != nil {
			os.Exit(10)
		}
		if _, err = db.Exec(`PRAGMA journal_mode = WAL`); err != nil {
			os.Exit(11)
		}
		if _, err = db.Exec(`PRAGMA wal_autocheckpoint = 0`); err != nil {
			os.Exit(11)
		}
		if _, err = db.Exec(`CREATE TABLE marker(value TEXT NOT NULL)`); err != nil {
			os.Exit(11)
		}
		if _, err = db.Exec(`INSERT INTO marker(value) VALUES ('old')`); err != nil {
			os.Exit(11)
		}
		// Deliberately no db.Close(): the process exits with a real committed WAL
		// that has not been checkpointed into the destination main database.
		os.Exit(0)
	case "crash_during_restore":
		restoreCrashFailpoint = func() { os.Exit(97) }
		if err := Restore(context.Background(), os.Getenv("PGW_RESTORE_CRASH_SOURCE"), path, RestoreOptions{ServicesStopped: true, AllowReplace: true, ExpectedSHA256: os.Getenv("PGW_RESTORE_CRASH_SHA256")}); err != nil {
			os.Exit(12)
		}
		os.Exit(13)
	default:
		os.Exit(14)
	}
}

func TestRestoreCrashBoundaryRetainsCompleteCheckpointedDatabase(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX atomic replacement crash boundary")
	}
	directory := t.TempDir()
	source := filepath.Join(directory, "source.backup.db")
	destination := filepath.Join(directory, "destination.db")
	sourceRepository := openTestRepositoryAt(t, filepath.Join(directory, "source.db"))
	if _, err := sourceRepository.CreateProxy(context.Background(), CreateProxyInput{Type: domain.ProxyHTTP, Host: "source", Port: 8080, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := sourceRepository.Backup(context.Background(), source); err != nil {
		t.Fatal(err)
	}
	runRestoreCrashHelper(t, "write_wal", "", destination, 0)
	if _, err := os.Stat(destination + "-wal"); err != nil {
		t.Fatalf("expected uncheckpointed WAL: %v", err)
	}
	runRestoreCrashHelper(t, "crash_during_restore", source, destination, 97)
	// A new process represents restart. The crash occurred after sidecars were
	// quarantined but after checkpoint; it must see a complete old or new DB,
	// never an old main database missing its committed WAL.
	db, err := sql.Open("sqlite", sqliteDSN(destination))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var marker string
	if err := db.QueryRow(`SELECT value FROM marker`).Scan(&marker); err != nil {
		t.Fatalf("restart database is incomplete: %v", err)
	}
	if marker != "old" {
		t.Fatalf("unexpected/stale marker after crash: %q", marker)
	}
}

func createMarkerDatabase(t *testing.T, path, value string) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA journal_mode = WAL`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE marker(value TEXT NOT NULL)`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO marker(value) VALUES (?)`, value); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := CheckIntegrity(context.Background(), path); err != nil {
		t.Fatal(err)
	}
}

func runRestoreCrashHelper(t *testing.T, mode, source, destination string, expectedExit int) {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestRestoreCrashHelper$")
	environment := append(os.Environ(),
		"PGW_RESTORE_CRASH_MODE="+mode,
		"PGW_RESTORE_CRASH_SOURCE="+source,
		"PGW_RESTORE_CRASH_DESTINATION="+destination,
	)
	if source != "" {
		environment = append(environment, "PGW_RESTORE_CRASH_SHA256="+checksumForTest(t, source))
	}
	command.Env = environment
	err := command.Run()
	if expectedExit == 0 {
		if err != nil {
			t.Fatalf("helper %s: %v", mode, err)
		}
		return
	}
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != expectedExit {
		t.Fatalf("helper %s exit=%v, want %d", mode, err, expectedExit)
	}
}

func checksumForTest(t *testing.T, path string) string {
	t.Helper()
	checksum, _, err := fileChecksum(path)
	if err != nil {
		t.Fatal(err)
	}
	return checksum
}
