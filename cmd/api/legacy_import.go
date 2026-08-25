package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Chinsusu/proxy-server-local/internal/domain"
	"github.com/Chinsusu/proxy-server-local/internal/persistence/sqlite"
	"github.com/Chinsusu/proxy-server-local/internal/secret"
)

// importDryRunKey is deliberately process-local, fixed public test material.
// A dry run never persists a credential, and therefore must neither require
// nor load the production master key. The real import always uses the supplied
// owner-validated key file.
type importDryRunKey struct{}

func (importDryRunKey) Key(context.Context) ([]byte, error) {
	return bytes.Repeat([]byte{0xA5}, secret.KeySize), nil
}

// importFDKey reads a root-opened, inherited raw key descriptor. It exists so
// an installer never has to copy the master key into a lower-privilege or
// persistent staging path. Production generation writes exactly 32 raw bytes.
type importFDKey struct{ file *os.File }

func (k importFDKey) Key(context.Context) ([]byte, error) {
	if k.file == nil {
		return nil, fmt.Errorf("missing key descriptor")
	}
	value, err := io.ReadAll(io.LimitReader(k.file, secret.KeySize+1))
	if err != nil || len(value) != secret.KeySize {
		zeroBytes(value)
		return nil, fmt.Errorf("invalid inherited key descriptor")
	}
	return value, nil
}

// runLegacyImportCommand is the only supported offline v1 state importer.
// It emits a bounded JSON report (counts/checksum only) and deliberately
// leaves parsing/validation errors to the caller rather than printing them;
// legacy state can contain credentials.
func runLegacyImportCommand(args []string, output io.Writer) (bool, error) {
	if len(args) == 0 || args[0] != "import-legacy-state" {
		return false, nil
	}
	flags := flag.NewFlagSet("import-legacy-state", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	statePath := flags.String("file", "", "legacy state.json")
	stateFD := flags.Int("state-fd", -1, "inherited legacy state descriptor")
	databasePath := flags.String("database", "", "SQLite database")
	keyPath := flags.String("key-file", "", "master key file")
	keyFD := flags.Int("key-fd", -1, "inherited raw master-key descriptor")
	reportFD := flags.Int("report-fd", -1, "inherited report descriptor")
	dryRun := flags.Bool("dry-run", false, "validate only")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return true, fmt.Errorf("usage: pgw-api import-legacy-state --file <absolute-state.json> [--dry-run | --database <absolute-pgw.db> --key-file <absolute-secrets.key>]")
	}
	if (*statePath == "") == (*stateFD < 0) || (*statePath != "" && !filepath.IsAbs(*statePath)) {
		return true, fmt.Errorf("legacy state file must be an absolute path")
	}
	if *stateFD >= 0 && *stateFD < 3 || *keyFD >= 0 && *keyFD < 3 || *reportFD >= 0 && *reportFD < 3 {
		return true, fmt.Errorf("inherited descriptors must be non-standard descriptors")
	}
	if !*dryRun && (!filepath.IsAbs(*databasePath) || (*keyPath == "") == (*keyFD < 0) || (*keyPath != "" && !filepath.IsAbs(*keyPath))) {
		return true, fmt.Errorf("real import requires an absolute --database and exactly one key source")
	}
	var state *os.File
	var err error
	if *stateFD >= 0 {
		state, err = openLegacyStateFD(*stateFD)
	} else {
		state, err = openLegacyStateFile(*statePath)
	}
	if err != nil {
		return true, fmt.Errorf("open legacy state")
	}
	defer state.Close()

	cfg := sqlite.Config{Path: ":memory:", KeyProvider: importDryRunKey{}, IPv6Policy: domain.IPv6PolicyDeny}
	if !*dryRun {
		var provider secret.KeyProvider
		if *keyFD >= 0 {
			keyFile, fdErr := openLegacyKeyFD(*keyFD)
			if fdErr != nil {
				return true, fmt.Errorf("open inherited key")
			}
			defer keyFile.Close()
			provider = importFDKey{file: keyFile}
		} else {
			provider = secret.FileKeyProvider{Path: *keyPath}
		}
		cfg = sqlite.Config{
			Path:        *databasePath,
			KeyProvider: provider,
			IPv6Policy:  domain.IPv6PolicyDeny,
		}
	}
	repository, err := sqlite.Open(context.Background(), cfg)
	if err != nil {
		return true, fmt.Errorf("open import destination")
	}
	defer repository.Close()
	report, err := repository.ImportState(context.Background(), state, sqlite.ImportOptions{DryRun: *dryRun, Actor: "operator"})
	if err != nil {
		return true, fmt.Errorf("validate or import legacy state")
	}
	if *reportFD >= 0 {
		report, fdErr := openLegacyReportFD(*reportFD)
		if fdErr != nil {
			return true, fmt.Errorf("open inherited report")
		}
		defer report.Close()
		output = report
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(report); err != nil {
		return true, fmt.Errorf("write import report")
	}
	return true, nil
}

func redactLegacyImportError(err error) string {
	if err == nil {
		return ""
	}
	// This is intentionally a code-like value, not err.Error(): a malformed
	// legacy document may include a password near the parse failure.
	return strings.TrimSpace("legacy_import_failed")
}
