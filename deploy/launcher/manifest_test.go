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

func TestParseSelfManagedVersionStrict(t *testing.T) {
	t.Parallel()
	input := strings.Join([]string{
		"format pgw-version-v2",
		"release_id release-20260826",
		"candidate_only false",
		"promotion_authority self-managed-manifest-sha256",
		"source_commit " + strings.Repeat("a", 40),
		"source_tree " + strings.Repeat("b", 40),
		"source_dirty false",
		"source_commit_time 2026-08-26T00:00:00Z",
		"go_module example.invalid/pgw",
		"go_version go1.26.7",
		"target linux/amd64",
		"cgo_enabled 0",
		"build_flags -trimpath,-buildvcs=false,-ldflags=-s_-w",
		"module_verification same-run-offline",
		"deterministic_rebuilds 2",
		"release_manifest_sha256 " + strings.Repeat("c", 64),
		"launcher_sha256 " + strings.Repeat("d", 64),
	}, "\n") + "\n"
	got, err := parseSelfManagedVersion(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseSelfManagedVersion: %v", err)
	}
	if got.ReleaseID != "release-20260826" || got.ManifestSHA256 != strings.Repeat("c", 64) {
		t.Fatalf("unexpected self-managed version: %#v", got)
	}
	for _, mutation := range []string{
		strings.Replace(input, "candidate_only false", "candidate_only true", 1),
		strings.Replace(input, "source_dirty false", "source_dirty true", 1),
		strings.Replace(input, "launcher_sha256 "+strings.Repeat("d", 64), "launcher_sha256 "+strings.Repeat("D", 64), 1),
		input + "unexpected value\n",
	} {
		if _, err := parseSelfManagedVersion(strings.NewReader(mutation)); err == nil {
			t.Fatalf("unsafe self-managed version accepted: %q", mutation)
		}
	}
}
