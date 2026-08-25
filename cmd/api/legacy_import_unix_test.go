//go:build !windows

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestLegacyImportCommandRealImportIsAtomicAndIdempotent(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "state.json")
	keyPath := filepath.Join(directory, "secrets.key")
	databasePath := filepath.Join(directory, "pgw.db")
	state := []byte(`{"proxies":{"p1":{"id":"p1","type":"http","host":"proxy.example","port":8080,"username":"alice","password":"do-not-print","enabled":true,"status":"DOWN"}},"clients":{"c1":{"id":"c1","ip_cidr":"192.0.2.8","enabled":true}},"mappings":{"m1":{"id":"m1","client_id":"c1","proxy_id":"p1","protocol":"http","local_redirect_port":15001,"state":"APPLIED"}}}`)
	if err := os.WriteFile(statePath, state, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{7}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func() map[string]any {
		var output bytes.Buffer
		handled, err := runLegacyImportCommand([]string{"import-legacy-state", "--file", statePath, "--database", databasePath, "--key-file", keyPath}, &output)
		if err != nil || !handled {
			t.Fatalf("handled=%v err=%v", handled, err)
		}
		if bytes.Contains(output.Bytes(), []byte("do-not-print")) {
			t.Fatalf("secret leaked in report: %q", output.String())
		}
		var report map[string]any
		if err := json.Unmarshal(output.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		return report
	}
	if report := run(); report["dry_run"] != false || report["already_imported"] != false || report["checksum"] == "" {
		t.Fatalf("first report=%v", report)
	}
	if report := run(); report["already_imported"] != true {
		t.Fatalf("idempotent report=%v", report)
	}
}

func TestLegacyImportCommandUsesInheritedDescriptors(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "sealed-state.json")
	keyPath := filepath.Join(directory, "secrets.key")
	reportPath := filepath.Join(directory, "report.json")
	databasePath := filepath.Join(directory, "pgw.db")
	if err := os.WriteFile(statePath, []byte(`{"proxies":{},"clients":{},"mappings":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{3}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	state, err := os.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	key, err := os.Open(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	report, err := os.OpenFile(reportPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer report.Close()
	_, err = runLegacyImportCommand([]string{"import-legacy-state", "--state-fd", strconv.Itoa(int(state.Fd())), "--database", databasePath, "--key-fd", strconv.Itoa(int(key.Fd())), "--report-fd", strconv.Itoa(int(report.Fd()))}, bytes.NewBuffer(nil))
	if err != nil {
		t.Fatalf("descriptor import failed: %v", err)
	}
	payload, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil || decoded["dry_run"] != false || decoded["checksum"] == "" {
		t.Fatalf("report=%q decoded=%v err=%v", payload, decoded, err)
	}
}
