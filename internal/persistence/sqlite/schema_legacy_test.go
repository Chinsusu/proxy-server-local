package sqlite

import (
	"context"
	"database/sql"
	"testing"
)

func TestPreChecksumPrefixMigrateMatchesCanonicalSchema(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	migrations, err := knownMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations[:2] {
		if _, err := db.ExecContext(ctx, migration.sql); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO schema_migrations(version, name, applied_at) VALUES(?, ?, 0)`, migration.version, migration.name); err != nil {
			t.Fatal(err)
		}
	}
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	expected, err := canonicalSchemaSignature(ctx)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := schemaSignature(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if len(expected) != len(actual) {
		t.Fatalf("schema signature length actual=%d expected=%d", len(actual), len(expected))
	}
	for index := range expected {
		if expected[index] != actual[index] {
			t.Fatalf("schema signature mismatch index=%d actual_length=%d expected_length=%d", index, len(actual[index]), len(expected[index]))
		}
	}
}
