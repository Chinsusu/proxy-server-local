package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

type migration struct {
	version  int
	name     string
	sql      string
	checksum string
}

func knownMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return nil, fmt.Errorf("sqlite: read embedded migrations: %w", err)
	}
	migrations := make([]migration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(entry.Name(), "_")
		if !ok {
			return nil, fmt.Errorf("sqlite: migration %q must start with an integer version", entry.Name())
		}
		version, err := strconv.Atoi(prefix)
		if err != nil || version < 1 {
			return nil, fmt.Errorf("sqlite: invalid migration version %q", entry.Name())
		}
		contents, err := migrationFiles.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("sqlite: read migration %q: %w", entry.Name(), err)
		}
		hash := sha256.Sum256(contents)
		migrations = append(migrations, migration{version: version, name: entry.Name(), sql: string(contents), checksum: fmt.Sprintf("%x", hash)})
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].version < migrations[j].version })
	for i := 1; i < len(migrations); i++ {
		if migrations[i-1].version == migrations[i].version {
			return nil, fmt.Errorf("sqlite: duplicate migration version %d", migrations[i].version)
		}
	}
	return migrations, nil
}

var ErrSchemaTooNew = errors.New("sqlite: database schema is newer than this binary")

// Migrate serializes and applies embedded migrations in order in one immediate
// transaction. A crash can leave only the prior complete schema version.
func Migrate(ctx context.Context, db *sql.DB) error {
	const attempts = 6
	for attempt := 0; attempt < attempts; attempt++ {
		err := migrateOnce(ctx, db)
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

func migrateOnce(ctx context.Context, db *sql.DB) error {
	migrations, err := knownMigrations()
	if err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at INTEGER NOT NULL
    )`); err != nil {
		return fmt.Errorf("sqlite: create migration ledger: %w", err)
	}
	// BEGIN IMMEDIATE gives exactly one migrator the write reservation. Re-read
	// the ledger only after acquiring it: another API process may have migrated
	// while this process was waiting to start.
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("sqlite: acquire migration connection: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("sqlite: begin immediate migration lock: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	var current sql.NullInt64
	if err := conn.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&current); err != nil {
		return fmt.Errorf("sqlite: inspect schema version: %w", err)
	}
	maxKnown := 0
	if len(migrations) > 0 {
		maxKnown = migrations[len(migrations)-1].version
	}
	if current.Valid && int(current.Int64) > maxKnown {
		return fmt.Errorf("%w: database=%d binary=%d", ErrSchemaTooNew, current.Int64, maxKnown)
	}
	if hasChecksum, err := migrationChecksumColumn(ctx, conn); err != nil {
		return err
	} else if hasChecksum {
		if err := validateMigrationLedger(ctx, conn, migrations); err != nil {
			return err
		}
	}
	for _, m := range migrations {
		if current.Valid && m.version <= int(current.Int64) {
			continue
		}
		if _, err = conn.ExecContext(ctx, m.sql); err == nil {
			_, err = conn.ExecContext(ctx,
				`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, unixepoch() * 1000)`,
				m.version, m.name)
		}
		if err != nil {
			return fmt.Errorf("sqlite: apply migration %d (%s): %w", m.version, m.name, err)
		}
	}
	if hasChecksum, err := migrationChecksumColumn(ctx, conn); err != nil {
		return err
	} else if hasChecksum {
		for _, migration := range migrations {
			if _, err := conn.ExecContext(ctx, `UPDATE schema_migrations SET checksum = ? WHERE version = ?`, migration.checksum, migration.version); err != nil {
				return fmt.Errorf("sqlite: record migration checksum %d: %w", migration.version, err)
			}
		}
		if err := validateMigrationLedger(ctx, conn, migrations); err != nil {
			return err
		}
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("sqlite: commit migrations: %w", err)
	}
	committed = true
	return nil
}

func migrationChecksumColumn(ctx context.Context, query sqlExecutor) (bool, error) {
	rows, err := query.QueryContext(ctx, `PRAGMA table_info(schema_migrations)`)
	if err != nil {
		return false, fmt.Errorf("sqlite: inspect migration ledger: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var defaultValue any
		var primary int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &primary); err != nil {
			return false, err
		}
		if name == "checksum" {
			return true, nil
		}
	}
	return false, rows.Err()
}

func validateMigrationLedger(ctx context.Context, query sqlExecutor, migrations []migration) error {
	hasChecksum, err := migrationChecksumColumn(ctx, query)
	if err != nil {
		return err
	}
	statement := `SELECT version, name FROM schema_migrations ORDER BY version`
	if hasChecksum {
		statement = `SELECT version, name, checksum FROM schema_migrations ORDER BY version`
	}
	rows, err := query.QueryContext(ctx, statement)
	if err != nil {
		return fmt.Errorf("sqlite: read migration provenance: %w", err)
	}
	defer rows.Close()
	position := 0
	for rows.Next() {
		if position >= len(migrations) {
			return ErrSchemaTooNew
		}
		var version int
		var name, checksum string
		if hasChecksum {
			err = rows.Scan(&version, &name, &checksum)
		} else {
			err = rows.Scan(&version, &name)
		}
		if err != nil {
			return err
		}
		expected := migrations[position]
		if version != expected.version || name != expected.name || (hasChecksum && checksum != expected.checksum) {
			return fmt.Errorf("sqlite: migration provenance mismatch at version %d", version)
		}
		if !hasChecksum && version >= 3 {
			return fmt.Errorf("sqlite: migration ledger claims checksum-era version %d without checksum", version)
		}
		position++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return nil
}

func SchemaVersion(ctx context.Context, db *sql.DB) (int, error) {
	var version sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		return 0, fmt.Errorf("sqlite: schema version: %w", err)
	}
	if !version.Valid {
		return 0, nil
	}
	return int(version.Int64), nil
}
