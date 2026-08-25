package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseTrustStrict(t *testing.T) {
	t.Parallel()
	input := "format pgw-trust-v1\nrelease_id release-20260824\nmanifest_sha256 " + strings.Repeat("a", 64) + "\n"
	got, err := parseTrust(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseTrust: %v", err)
	}
	if got.ReleaseID != "release-20260824" {
		t.Fatalf("release id = %q", got.ReleaseID)
	}
	for _, bad := range []string{
		input + "release_root /tmp/evil\n",
		strings.Replace(input, "release-20260824", "../../tmp", 1),
		strings.Replace(input, strings.Repeat("a", 64), strings.Repeat("A", 64), 1),
	} {
		if _, err := parseTrust(strings.NewReader(bad)); err == nil {
			t.Fatalf("unsafe trust manifest accepted: %q", bad)
		}
	}
}

func TestParseReleaseRequiresExactAllowlist(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString("format pgw-release-v1\n")
	for _, name := range requiredReleaseEntries {
		mode := "0644"
		if strings.HasPrefix(name, "artifacts/") || strings.HasSuffix(name, ".sh") {
			mode = "0755"
		}
		fmt.Fprintf(&b, "file %s %s %s\n", strings.Repeat("b", 64), mode, name)
	}
	entries, err := parseRelease(strings.NewReader(b.String()))
	if err != nil || len(entries) != len(requiredReleaseEntries) {
		t.Fatalf("parseRelease = %d, %v", len(entries), err)
	}
	for _, mutation := range []string{
		b.String() + "file " + strings.Repeat("c", 64) + " 0644 extra\n",
		strings.Replace(b.String(), "deploy/nftables.conf", "../nftables.conf", 1),
		strings.Replace(b.String(), " 0644 deploy/nftables.conf", " 0666 deploy/nftables.conf", 1),
	} {
		if _, err := parseRelease(strings.NewReader(mutation)); err == nil {
			t.Fatal("unsafe release manifest accepted")
		}
	}
}

func TestReleaseAllowlistPinsRehearsalOrchestration(t *testing.T) {
	t.Parallel()
	required := map[string]bool{
		"deploy/rehearse-release.sh":                 false,
		"deploy/tests/installer_harness.sh":          false,
		"deploy/tests/installer_transaction_test.sh": false,
		"deploy/tests/release_launcher_root_test.sh": false,
		"deploy/tests/lifecycle_fake.sh":             false,
		"deploy/tests/release_snapshot.py":           false,
		"deploy/tests/restore_crash_driver.py":       false,
	}
	seen := make(map[string]bool, len(requiredReleaseEntries))
	for _, name := range requiredReleaseEntries {
		if seen[name] {
			t.Fatalf("duplicate release allowlist entry %q", name)
		}
		seen[name] = true
		if _, ok := required[name]; ok {
			required[name] = true
		}
	}
	for name, present := range required {
		if !present {
			t.Errorf("rehearsal provenance path omitted: %s", name)
		}
	}
}

func TestForbiddenCallerEnvironment(t *testing.T) {
	t.Parallel()
	if got := forbiddenCallerEnvironment([]string{"PATH=/tmp/hostile", "LANG=C"}); got != "" {
		t.Fatalf("safe environment rejected: %s", got)
	}
	for _, name := range []string{
		"PGW_SOURCE_DIR", "PGW_GO_BINARY", "PGW_REVIEWED_CHECKOUT", "PGW_REVIEWED_COMMIT",
		"BASH_ENV", "ENV", "LD_PRELOAD", "LD_LIBRARY_PATH", "GOTOOLCHAIN", "GOROOT",
	} {
		if got := forbiddenCallerEnvironment([]string{name + "=hostile"}); got != name {
			t.Fatalf("%s rejection = %q", name, got)
		}
	}
}
