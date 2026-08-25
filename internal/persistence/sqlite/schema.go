package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
)

// validateExactSchema compares the database's complete user-visible SQLite
// schema to one built from the embedded migrations. This catches a database
// that merely has the expected object names but weakened constraints, indexes,
// predicates, foreign keys, or hostile triggers/views.
func validateExactSchema(ctx context.Context, db *sql.DB, requireLedger bool) error {
	if requireLedger {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil || count == 0 {
			return fmt.Errorf("sqlite: migration ledger is empty or unavailable")
		}
	}
	expected, err := canonicalSchemaSignature(ctx)
	if err != nil {
		return err
	}
	actual, err := schemaSignature(ctx, db)
	if err != nil {
		return err
	}
	if strings.Join(actual, "\n") != strings.Join(expected, "\n") {
		return fmt.Errorf("sqlite: schema does not exactly match embedded migrations")
	}
	return nil
}

func canonicalSchemaSignature(ctx context.Context) ([]string, error) {
	// A private in-memory database prevents a caller-controlled shared-cache
	// name from contaminating the canonical schema used for comparison.
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if err := Migrate(ctx, db); err != nil {
		return nil, err
	}
	return schemaSignature(ctx, db)
}

func schemaSignature(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master
        WHERE substr(name, 1, 7) != 'sqlite_' AND type IN ('table', 'index', 'view', 'trigger') ORDER BY type, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []string
	var tables []string
	for rows.Next() {
		var typ, name, table, definition string
		if err := rows.Scan(&typ, &name, &table, &definition); err != nil {
			return nil, err
		}
		// schema_migrations is bootstrap-created before the first embedded SQL
		// file runs. Older trusted installations legitimately differ only by
		// CREATE TABLE's IF NOT EXISTS spelling. Normalize just that token rather
		// than discarding the DDL: CHECK/STRICT/WITHOUT ROWID and every other
		// structural difference remain part of the exact signature.
		if typ == "table" && name == "schema_migrations" {
			definition = normalizeSchemaMigrationsBootstrapDDL(definition)
		}
		values = append(values, "object|"+typ+"|"+name+"|"+table+"|"+normalizeSQL(definition))
		if typ == "table" {
			tables = append(tables, name)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, table := range tables {
		var schema, name, typ string
		var columns, withoutRowID, strict int
		if err := db.QueryRowContext(ctx, `SELECT schema, name, type, ncol, wr, strict FROM pragma_table_list WHERE name = ?`, table).
			Scan(&schema, &name, &typ, &columns, &withoutRowID, &strict); err != nil {
			return nil, err
		}
		values = append(values, fmt.Sprintf("table_list|%s|%s|%s|%d|%d|%d", schema, name, typ, columns, withoutRowID, strict))
		for _, pragma := range []string{"table_xinfo", "foreign_key_list", "index_list"} {
			result, err := pragmaSignature(ctx, db, pragma, table)
			if err != nil {
				return nil, err
			}
			values = append(values, result...)
		}
		indexRows, err := db.QueryContext(ctx, `SELECT name FROM pragma_index_list(?) WHERE origin != 'pk'`, table)
		if err != nil {
			return nil, err
		}
		indexes := make([]string, 0)
		for indexRows.Next() {
			var index string
			if err := indexRows.Scan(&index); err != nil {
				indexRows.Close()
				return nil, err
			}
			indexes = append(indexes, index)
		}
		if err := indexRows.Close(); err != nil {
			return nil, err
		}
		for _, index := range indexes {
			result, err := pragmaSignature(ctx, db, "index_xinfo", index)
			if err != nil {
				return nil, err
			}
			values = append(values, result...)
		}
	}
	sort.Strings(values)
	return values, nil
}

func normalizeSchemaMigrationsBootstrapDDL(definition string) string {
	normalized := normalizeSQL(definition)
	normalized = strings.Replace(normalized, "CREATE TABLE IF NOT EXISTS schema_migrations", "CREATE TABLE schema_migrations", 1)
	return removeInsignificantDDLSpacing(normalized)
}

// removeInsignificantDDLSpacing is restricted to the bootstrap migration
// ledger. It preserves quoted content while accepting SQLite's harmless
// formatting difference between CREATE TABLE from the old bootstrap and the
// current migration runner (spaces adjacent to parentheses/commas).
func removeInsignificantDDLSpacing(value string) string {
	var output strings.Builder
	for index := 0; index < len(value); {
		character := value[index]
		if character == '\'' || character == '"' || character == '`' || character == '[' {
			closing := character
			if character == '[' {
				closing = ']'
			}
			output.WriteByte(character)
			index++
			for index < len(value) {
				current := value[index]
				output.WriteByte(current)
				index++
				if current != closing {
					continue
				}
				if closing != ']' && index < len(value) && value[index] == closing {
					output.WriteByte(value[index])
					index++
					continue
				}
				break
			}
			continue
		}
		if character == ' ' {
			next := index + 1
			for next < len(value) && value[next] == ' ' {
				next++
			}
			previous := byte(0)
			if output.Len() > 0 {
				// output contains only ASCII outside literals at this point, and
				// punctuation is one byte.
				text := output.String()
				previous = text[len(text)-1]
			}
			if previous == '(' || previous == ',' || next == len(value) || value[next] == ')' || value[next] == ',' {
				index = next
				continue
			}
			output.WriteByte(' ')
			index = next
			continue
		}
		output.WriteByte(character)
		index++
	}
	return output.String()
}

func pragmaSignature(ctx context.Context, db *sql.DB, pragma, name string) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT * FROM pragma_`+pragma+`(?)`, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	values := make([]string, 0)
	for rows.Next() {
		raw := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for i := range raw {
			pointers[i] = &raw[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			return nil, err
		}
		parts := []string{"pragma", pragma, name}
		for _, value := range raw {
			parts = append(parts, fmt.Sprint(value))
		}
		values = append(values, strings.Join(parts, "|"))
	}
	return values, rows.Err()
}

// normalizeSQL changes whitespace only outside quoted SQL literals/identifiers.
// It intentionally preserves case and content in quoted values: a CHECK for
// 'ACTIVE' must never compare equal to a hostile replacement using 'active'.
func normalizeSQL(value string) string {
	var output strings.Builder
	space := false
	for index := 0; index < len(value); {
		character := value[index]
		if character == ' ' || character == '\t' || character == '\r' || character == '\n' {
			space = output.Len() > 0
			index++
			continue
		}
		if space {
			output.WriteByte(' ')
			space = false
		}
		if character == '\'' || character == '"' || character == '`' || character == '[' {
			closing := character
			if character == '[' {
				closing = ']'
			}
			output.WriteByte(character)
			index++
			for index < len(value) {
				current := value[index]
				output.WriteByte(current)
				index++
				if current != closing {
					continue
				}
				// SQL escapes quotes by doubling them; retain both exactly.
				if closing != ']' && index < len(value) && value[index] == closing {
					output.WriteByte(value[index])
					index++
					continue
				}
				break
			}
			continue
		}
		output.WriteByte(character)
		index++
	}
	return output.String()
}
