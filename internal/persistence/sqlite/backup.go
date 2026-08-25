package sqlite

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

var (
	ErrBackupExists       = errors.New("sqlite: backup destination already exists")
	ErrServicesNotStopped = errors.New("sqlite: restore requires explicitly confirmed stopped services")
	ErrRestoreChecksum    = errors.New("sqlite: restore backup checksum is required or does not match")
)

type BackupMetadata struct {
	Path          string    `json:"path"`
	SHA256        string    `json:"sha256"`
	Bytes         int64     `json:"bytes"`
	SchemaVersion int       `json:"schema_version"`
	CreatedAt     time.Time `json:"created_at"`
}

// Backup obtains SQLite's own consistent snapshot using VACUUM INTO, verifies
// the resulting database before publishing it without replacing an existing
// destination, then
// returns a content checksum for release evidence.
func (r *Repository) Backup(ctx context.Context, destination string) (BackupMetadata, error) {
	if err := persistentOperationsAllowed(); err != nil {
		return BackupMetadata{}, err
	}
	if strings.TrimSpace(destination) == "" {
		return BackupMetadata{}, fmt.Errorf("sqlite: backup destination is required")
	}
	if _, err := os.Lstat(destination); err == nil {
		return BackupMetadata{}, ErrBackupExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return BackupMetadata{}, fmt.Errorf("sqlite: inspect backup destination: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o750); err != nil {
		return BackupMetadata{}, fmt.Errorf("sqlite: create backup directory: %w", err)
	}
	if err := secureSQLiteParent(destination); err != nil {
		return BackupMetadata{}, fmt.Errorf("sqlite: insecure backup directory: %w", err)
	}
	stageDir := filepath.Join(filepath.Dir(destination), ".pgw-backup-stage-"+uuid.NewString())
	if err := os.Mkdir(stageDir, 0o700); err != nil {
		return BackupMetadata{}, fmt.Errorf("sqlite: create private backup staging: %w", err)
	}
	defer os.RemoveAll(stageDir)
	temporary := filepath.Join(stageDir, "backup.db")
	statement := "VACUUM INTO '" + strings.ReplaceAll(filepath.ToSlash(temporary), "'", "''") + "'"
	if _, err := r.db.ExecContext(ctx, statement); err != nil {
		return BackupMetadata{}, fmt.Errorf("sqlite: create consistent backup: %w", err)
	}
	if err := CheckIntegrity(ctx, temporary); err != nil {
		_ = os.Remove(temporary)
		return BackupMetadata{}, err
	}
	if err := secureSQLiteFile(temporary); err != nil {
		_ = os.Remove(temporary)
		return BackupMetadata{}, fmt.Errorf("sqlite: secure backup file: %w", err)
	}
	if err := syncFile(temporary); err != nil {
		return BackupMetadata{}, fmt.Errorf("sqlite: sync staged backup: %w", err)
	}
	if err := syncDirectory(stageDir); err != nil {
		return BackupMetadata{}, fmt.Errorf("sqlite: sync staged backup directory: %w", err)
	}
	checksum, bytes, err := fileChecksum(temporary)
	if err != nil {
		_ = os.Remove(temporary)
		return BackupMetadata{}, err
	}
	if err := publishBackupNoClobber(temporary, destination); err != nil {
		return BackupMetadata{}, fmt.Errorf("sqlite: publish backup: %w", err)
	}
	if err := secureSQLiteFile(destination); err != nil {
		return BackupMetadata{}, fmt.Errorf("sqlite: secure published backup: %w", err)
	}
	if err := syncFile(destination); err != nil {
		return BackupMetadata{}, fmt.Errorf("sqlite: sync published backup: %w", err)
	}
	if err := syncDirectory(filepath.Dir(destination)); err != nil {
		return BackupMetadata{}, fmt.Errorf("sqlite: sync published backup directory: %w", err)
	}
	version, err := SchemaVersion(ctx, r.db)
	if err != nil {
		return BackupMetadata{}, err
	}
	return BackupMetadata{Path: destination, SHA256: checksum, Bytes: bytes, SchemaVersion: version, CreatedAt: r.now().UTC()}, nil
}

func CheckIntegrity(ctx context.Context, path string) error {
	snapshot, cleanup, err := snapshotIntegrityTarget(ctx, path)
	if err != nil {
		return err
	}
	defer cleanup()
	uri, err := immutableReadURI(snapshot)
	if err != nil {
		return err
	}
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return fmt.Errorf("sqlite: open integrity target: %w", err)
	}
	defer db.Close()
	var result string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&result); err != nil {
		return fmt.Errorf("sqlite: integrity check: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("sqlite: integrity check failed: %s", result)
	}
	return nil
}

type RestoreOptions struct {
	ServicesStopped bool
	AllowReplace    bool
	ExpectedSHA256  string
}

// atomicReplaceForRestore is a seam for failure-injection tests. Its platform
// implementation never removes a live destination before a replacement has
// been fully staged and verified.
var atomicReplaceForRestore = atomicReplace

// restoreCrashFailpoint is test-only fault injection. It intentionally has no
// production configuration surface; a subprocess exits at this point to test
// the on-disk crash boundary rather than an in-process error path.
var restoreCrashFailpoint func()

// Restore intentionally has no service-manager integration. The caller must
// explicitly attest that API and Agent services are stopped; this avoids a
// silent online replacement of a database that another process has open.
func Restore(ctx context.Context, source, destination string, options RestoreOptions) error {
	if !options.ServicesStopped {
		return ErrServicesNotStopped
	}
	destinationExists := false
	if _, err := os.Lstat(destination); err == nil {
		destinationExists = true
	}
	if destinationExists && !options.AllowReplace {
		return ErrBackupExists
	} else if _, err := os.Lstat(destination); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("sqlite: inspect restore destination: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o750); err != nil {
		return fmt.Errorf("sqlite: create restore directory: %w", err)
	}
	if err := secureSQLiteParent(destination); err != nil {
		return fmt.Errorf("sqlite: insecure restore directory: %w", err)
	}
	databaseLock, err := acquireDatabaseExclusiveLock(destination)
	if err != nil {
		return fmt.Errorf("sqlite: acquire exclusive database lock for restore: %w", err)
	}
	defer databaseLock.Close()
	operationID := uuid.NewString()
	stageDirectory := destination + ".restore-stage-" + operationID
	if err := os.Mkdir(stageDirectory, 0o700); err != nil {
		return fmt.Errorf("sqlite: create private restore staging: %w", err)
	}
	staged := filepath.Join(stageDirectory, "database.db")
	rollback := destination + ".restore-rollback-" + operationID
	defer func() { _ = os.RemoveAll(stageDirectory) }()
	if err := copySourceNofollow(source, staged); err != nil {
		return err
	}
	// Hash and validate the exact immutable staged bytes. The source path is
	// never reopened after staging, preventing source-swap/TOCTOU attacks.
	if err := verifyTrustedBackup(ctx, staged, options.ExpectedSHA256); err != nil {
		return err
	}
	if err := secureSQLiteFile(staged); err != nil {
		return fmt.Errorf("sqlite: secure staged restore: %w", err)
	}
	if err := syncDirectory(filepath.Dir(destination)); err != nil {
		return fmt.Errorf("sqlite: sync staged restore directory: %w", err)
	}

	if !destinationExists {
		// No live database exists, so stale sidecars cannot contain a valid
		// companion WAL. Remove them before publishing the staged database.
		if err := removeSidecars(destination); err != nil {
			return err
		}
		if err := atomicReplaceForRestore(staged, destination); err != nil {
			return fmt.Errorf("sqlite: publish initial restore: %w", err)
		}
		if err := syncFile(destination); err != nil {
			return fmt.Errorf("sqlite: sync restored database: %w", err)
		}
		if err := secureSQLiteSidecars(destination); err != nil {
			return fmt.Errorf("sqlite: secure restored database: %w", err)
		}
		if err := syncDirectory(filepath.Dir(destination)); err != nil {
			return fmt.Errorf("sqlite: sync restored directory: %w", err)
		}
		return nil
	}

	// The old main database must be self-contained before sidecars are moved.
	// Otherwise an interruption between sidecar quarantine and atomic rename
	// could restart with an old main file whose latest committed WAL is absent.
	if err := checkpointAndVerify(ctx, destination); err != nil {
		return err
	}
	if err := syncFile(destination); err != nil {
		return fmt.Errorf("sqlite: sync checkpointed destination: %w", err)
	}
	if err := secureSQLiteSidecars(destination); err != nil {
		return fmt.Errorf("sqlite: secure checkpointed destination: %w", err)
	}
	if err := syncDirectory(filepath.Dir(destination)); err != nil {
		return fmt.Errorf("sqlite: sync checkpointed destination directory: %w", err)
	}

	// Preserve the complete old database before changing the live pathname.
	// A hard-link is O(1) and protects the old inode across POSIX rename; copy
	// is a safe fallback for filesystems that disallow links.
	if err := makeRollbackCopy(destination, rollback); err != nil {
		return err
	}
	defer func() { _ = os.Remove(rollback) }()
	if err := syncFile(rollback); err != nil {
		return fmt.Errorf("sqlite: sync rollback database: %w", err)
	}
	moves, err := moveSidecars(destination, rollback)
	if err != nil {
		return err
	}
	restoreOldSidecars := true
	defer func() {
		if restoreOldSidecars {
			_ = restoreSidecars(moves)
		}
	}()
	if err := syncDirectory(filepath.Dir(destination)); err != nil {
		return fmt.Errorf("sqlite: sync sidecar move: %w", err)
	}
	if restoreCrashFailpoint != nil {
		restoreCrashFailpoint()
	}

	// POSIX rename replaces the path atomically; the old database remains at
	// rollback, so an fsync failure can be rolled back without ever deleting
	// the live database first.
	if err := atomicReplaceForRestore(staged, destination); err != nil {
		return fmt.Errorf("sqlite: atomically replace restore target: %w", err)
	}
	if err := syncFile(destination); err != nil {
		return rollbackRestore(destination, rollback, moves, err)
	}
	if err := secureSQLiteSidecars(destination); err != nil {
		return rollbackRestore(destination, rollback, moves, err)
	}
	if err := syncDirectory(filepath.Dir(destination)); err != nil {
		return rollbackRestore(destination, rollback, moves, err)
	}

	// New database is durable. The old sidecars must never remain under the
	// destination name; discard preserved copies only after the successful swap.
	restoreOldSidecars = false
	if err := removeSidecars(rollback); err != nil {
		return err
	}
	if err := os.Remove(rollback); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("sqlite: remove rollback database: %w", err)
	}
	if err := syncDirectory(filepath.Dir(destination)); err != nil {
		return fmt.Errorf("sqlite: sync restore cleanup: %w", err)
	}
	return nil
}

func acquireRestoreLock(destination string) (func(), error) {
	lockPath := destination + ".restore.lock"
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("sqlite: acquire exclusive restore lock: %w", err)
	}
	if err := lock.Sync(); err != nil {
		_ = lock.Close()
		_ = os.Remove(lockPath)
		return nil, fmt.Errorf("sqlite: sync restore lock: %w", err)
	}
	return func() { _ = lock.Close(); _ = os.Remove(lockPath) }, nil
}

func verifyTrustedBackup(ctx context.Context, path, expectedSHA256 string) error {
	expected := strings.ToLower(strings.TrimSpace(expectedSHA256))
	if len(expected) != sha256.Size*2 {
		return ErrRestoreChecksum
	}
	actual, _, err := fileChecksum(path)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) != 1 {
		return ErrRestoreChecksum
	}
	if err := CheckIntegrity(ctx, path); err != nil {
		return err
	}
	// A trusted older prefix is upgraded only in private staging; publication
	// always requires the resulting current schema/provenance below.
	uri, err := databaseURI(path)
	if err != nil {
		return err
	}
	upgrade, err := sql.Open("sqlite", uri)
	if err != nil {
		return fmt.Errorf("sqlite: open staged backup for migration: %w", err)
	}
	migrations, err := knownMigrations()
	if err == nil {
		var ledgerCount int
		err = upgrade.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&ledgerCount)
		if err == nil && ledgerCount == 0 {
			err = errors.New("restore backup migration ledger is empty")
		}
		if err == nil {
			err = validateMigrationLedger(ctx, upgrade, migrations)
		}
	}
	if err == nil {
		err = Migrate(ctx, upgrade)
	}
	closeUpgrade := upgrade.Close()
	if err != nil {
		return fmt.Errorf("sqlite: untrusted backup migration prefix: %w", err)
	}
	if closeUpgrade != nil {
		return closeUpgrade
	}
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return fmt.Errorf("sqlite: open backup provenance: %w", err)
	}
	defer db.Close()
	migrations, err = knownMigrations()
	if err != nil {
		return err
	}
	if err := validateMigrationLedger(ctx, db, migrations); err != nil {
		return fmt.Errorf("sqlite: untrusted backup migration ledger: %w", err)
	}
	if err := validateExactSchema(ctx, db, true); err != nil {
		return fmt.Errorf("sqlite: untrusted backup schema: %w", err)
	}
	var migrationCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&migrationCount); err != nil || migrationCount != len(migrations) {
		return fmt.Errorf("sqlite: untrusted backup incomplete migration ledger")
	}
	for _, object := range []struct{ kind, name string }{
		{"table", "proxies"}, {"table", "proxy_secrets"}, {"table", "proxy_capabilities"}, {"table", "proxy_health_snapshots"},
		{"table", "clients"}, {"table", "egress_policies"}, {"table", "mappings"}, {"table", "nodes"},
		{"table", "reconcile_states"}, {"table", "audit_events"}, {"table", "idempotency_keys"}, {"table", "schema_migrations"},
		{"index", "idx_mappings_one_active_per_client"}, {"index", "idx_mappings_one_active_per_redirect_port"},
	} {
		var name string
		if err := db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type = ? AND name = ?`, object.kind, object.name).Scan(&name); err != nil {
			return fmt.Errorf("sqlite: untrusted backup missing %s %s: %w", object.kind, object.name, err)
		}
	}
	rows, err := db.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return fmt.Errorf("sqlite: backup foreign key check: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return errors.New("sqlite: untrusted backup foreign key violation")
	}
	var badSecrets int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM proxy_secrets WHERE envelope_version <> ? OR length(nonce) <> 12`, 1).Scan(&badSecrets); err != nil {
		return fmt.Errorf("sqlite: validate backup secret envelopes: %w", err)
	}
	if badSecrets != 0 {
		return errors.New("sqlite: untrusted backup secret envelope")
	}
	return nil
}

func checkpointAndVerify(ctx context.Context, path string) error {
	uri, err := databaseURI(path)
	if err != nil {
		return err
	}
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return fmt.Errorf("sqlite: open destination for WAL checkpoint: %w", err)
	}
	var busy, logFrames, checkpointedFrames int
	err = db.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &checkpointedFrames)
	closeErr := db.Close()
	if err != nil {
		return fmt.Errorf("sqlite: checkpoint destination WAL: %w", err)
	}
	if busy != 0 {
		return fmt.Errorf("sqlite: destination WAL checkpoint remained busy (log=%d checkpointed=%d)", logFrames, checkpointedFrames)
	}
	if closeErr != nil {
		return fmt.Errorf("sqlite: close checkpoint destination: %w", closeErr)
	}
	if err := CheckIntegrity(ctx, path); err != nil {
		return fmt.Errorf("sqlite: checkpointed destination verification: %w", err)
	}
	return nil
}

func copyAndSync(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("sqlite: open restore source: %w", err)
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("sqlite: create staged restore: %w", err)
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		_ = os.Remove(destination)
		return fmt.Errorf("sqlite: copy staged restore: %w", err)
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		_ = os.Remove(destination)
		return fmt.Errorf("sqlite: sync staged restore: %w", err)
	}
	if err := output.Close(); err != nil {
		_ = os.Remove(destination)
		return fmt.Errorf("sqlite: close staged restore: %w", err)
	}
	return nil
}

func makeRollbackCopy(live, rollback string) error {
	if err := os.Link(live, rollback); err == nil {
		return nil
	}
	if err := copyAndSync(live, rollback); err != nil {
		return fmt.Errorf("sqlite: create rollback copy: %w", err)
	}
	return nil
}

type sidecarMove struct{ from, to string }

func moveSidecars(live, rollback string) ([]sidecarMove, error) {
	moves := make([]sidecarMove, 0, 2)
	for _, suffix := range []string{"-wal", "-shm"} {
		from, to := live+suffix, rollback+suffix
		if _, err := os.Lstat(from); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			_ = restoreSidecars(moves)
			return nil, fmt.Errorf("sqlite: inspect %s sidecar: %w", suffix, err)
		}
		if err := os.Rename(from, to); err != nil {
			_ = restoreSidecars(moves)
			return nil, fmt.Errorf("sqlite: preserve %s sidecar: %w", suffix, err)
		}
		moves = append(moves, sidecarMove{from: from, to: to})
	}
	return moves, nil
}

func restoreSidecars(moves []sidecarMove) error {
	var first error
	for index := len(moves) - 1; index >= 0; index-- {
		move := moves[index]
		if err := os.Rename(move.to, move.from); err != nil && !errors.Is(err, os.ErrNotExist) && first == nil {
			first = err
		}
	}
	return first
}

func removeSidecars(path string) error {
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Remove(path + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("sqlite: remove stale %s sidecar: %w", suffix, err)
		}
	}
	return nil
}

func rollbackRestore(destination, rollback string, moves []sidecarMove, cause error) error {
	if err := atomicReplaceForRestore(rollback, destination); err != nil {
		return fmt.Errorf("sqlite: restore durability failed (%v); rollback replacement failed: %w", cause, err)
	}
	if err := restoreSidecars(moves); err != nil {
		return fmt.Errorf("sqlite: restore durability failed (%v); rollback sidecars failed: %w", cause, err)
	}
	if err := syncDirectory(filepath.Dir(destination)); err != nil {
		return fmt.Errorf("sqlite: restore durability failed (%v); rollback sync failed: %w", cause, err)
	}
	return fmt.Errorf("sqlite: restored rollback after durability failure: %w", cause)
}

func fileChecksum(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("sqlite: open checksum file: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	bytes, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, fmt.Errorf("sqlite: hash backup: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), bytes, nil
}
