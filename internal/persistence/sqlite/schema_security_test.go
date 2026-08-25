package sqlite

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

func TestNormalizeSQLPreservesQuotedLiteralsAndIdentifiers(t *testing.T) {
	upper := normalizeSQL(`CREATE TABLE x (state TEXT CHECK(state = 'ACTIVE'))`)
	lower := normalizeSQL(`CREATE TABLE x (state TEXT CHECK(state = 'active'))`)
	if upper == lower {
		t.Fatal("literal case was normalized")
	}
	if got := normalizeSQL(`CREATE TABLE "A B" (x TEXT DEFAULT 'a  b')`); !strings.Contains(got, `"A B"`) || !strings.Contains(got, `'a  b'`) {
		t.Fatal("quoted whitespace was normalized")
	}
}

func TestSchemaMigrationsDDLNormalizationAllowsOnlyBootstrapIfNotExists(t *testing.T) {
	base := normalizeSchemaMigrationsBootstrapDDL(`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL, checksum TEXT NOT NULL DEFAULT '')`)
	legacy := normalizeSchemaMigrationsBootstrapDDL(`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL, checksum TEXT NOT NULL DEFAULT '')`)
	if base != legacy {
		t.Fatal("legitimate bootstrap IF NOT EXISTS difference was not normalized")
	}
	for _, altered := range []string{
		`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY CHECK(version > 0), name TEXT NOT NULL, applied_at INTEGER NOT NULL, checksum TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL, checksum TEXT NOT NULL DEFAULT '') STRICT`,
		`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL, checksum TEXT NOT NULL DEFAULT '') WITHOUT ROWID`,
	} {
		if base == normalizeSchemaMigrationsBootstrapDDL(altered) {
			t.Fatal("unsafe schema_migrations DDL difference was normalized")
		}
	}
}

func TestExactSchemaRejectsHostileObjectsAndWeakenedIndex(t *testing.T) {
	ctx := context.Background()
	for _, mutation := range []string{
		`CREATE TRIGGER sqliteXevil AFTER INSERT ON clients BEGIN SELECT 1; END`,
		`DROP INDEX idx_mappings_one_active_per_redirect_port`,
	} {
		db, err := sql.Open("sqlite", ":memory:")
		if err != nil {
			t.Fatal(err)
		}
		db.SetMaxOpenConns(1)
		if err := Migrate(ctx, db); err != nil {
			_ = db.Close()
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, mutation); err != nil {
			_ = db.Close()
			t.Fatal(err)
		}
		if err := validateExactSchema(ctx, db, true); err == nil {
			_ = db.Close()
			t.Fatal("schema drift was accepted")
		}
		_ = db.Close()
	}
}
