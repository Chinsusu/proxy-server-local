package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"
)

const (
	trustFormat                   = "pgw-trust-v1"
	releaseFormat                 = "pgw-release-v1"
	selfManagedPromotionAuthority = "self-managed-manifest-sha256"
)

var (
	safeReleaseID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	safeEntryPath = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/@+-]{0,255}$`)
)

func forbiddenCallerEnvironment(environ []string) string {
	for _, item := range environ {
		name := strings.SplitN(item, "=", 2)[0]
		if name == "BASH_ENV" || name == "ENV" || name == "CDPATH" || name == "GLOBIGNORE" ||
			strings.HasPrefix(name, "LD_") || strings.HasPrefix(name, "DYLD_") || strings.HasPrefix(name, "PGW_") ||
			name == "GOENV" || name == "GOTOOLCHAIN" || name == "GOROOT" || name == "GOPATH" {
			return name
		}
	}
	return ""
}

type trustRecord struct {
	ReleaseID      string
	ManifestSHA256 string
}

type releaseEntry struct {
	Path   string
	SHA256 string
	Mode   uint32
}

type selfManagedVersion struct {
	ReleaseID      string
	ManifestSHA256 string
	LauncherSHA256 string
}

var requiredReleaseEntries = []string{
	"deploy/install-pgw.sh",
	"deploy/rehearse-release.sh",
	"artifacts/pgw-api", "artifacts/pgw-agent", "artifacts/pgw-fwd", "artifacts/pgw-ui", "artifacts/pgw-health", "artifacts/pgw-snapshot-crypt",
	"deploy/install-pgw-base.sh", "deploy/pgw-verify-base.sh", "deploy/nftables.conf", "deploy/sysctl-pgw.conf",
	"deploy/pgw-verify-ui-bind.sh",
	"deploy/restore_snapshot.py",
	"deploy/snapshot_payload.py",
	"deploy/tests/installer_harness.sh", "deploy/tests/installer_transaction_test.sh",
	"deploy/tests/release_launcher_root_test.sh", "deploy/tests/lifecycle_fake.sh",
	"deploy/tests/release_snapshot.py", "deploy/tests/restore_crash_driver.py",
	"deploy/sysusers.d/pgw.conf", "deploy/tmpfiles.d/pgw.conf",
	"deploy/polkit-1/rules.d/50-pgw-agent-forwarder.rules",
	"deploy/systemd/pgw-api.service", "deploy/systemd/pgw-agent.service", "deploy/systemd/pgw-fwd@.service",
	"deploy/systemd/pgw-ui.service", "deploy/systemd/pgw-health.service",
	"deploy/systemd/nftables.service.d/pgw.conf", "deploy/systemd/systemd-sysctl.service.d/pgw.conf",
	"deploy/ui-assets.sha256", "web/static/app.js", "web/static/styles.css", "web/static/login.js", "web/static/layout.css",
}

func parseTrust(r io.Reader) (trustRecord, error) {
	values, err := parseKeyValue(r, 8)
	if err != nil {
		return trustRecord{}, err
	}
	if len(values) != 3 || values["format"] != trustFormat {
		return trustRecord{}, errors.New("invalid trust manifest format")
	}
	record := trustRecord{ReleaseID: values["release_id"], ManifestSHA256: values["manifest_sha256"]}
	if !safeReleaseID.MatchString(record.ReleaseID) {
		return trustRecord{}, errors.New("invalid release id")
	}
	if !validDigest(record.ManifestSHA256) {
		return trustRecord{}, errors.New("invalid pinned manifest digest")
	}
	return record, nil
}

func parseRelease(r io.Reader) ([]releaseEntry, error) {
	scanner := bufio.NewScanner(io.LimitReader(r, 256*1024+1))
	scanner.Buffer(make([]byte, 4096), 256*1024)
	lineNumber := 0
	formatSeen := false
	entries := make([]releaseEntry, 0, len(requiredReleaseEntries))
	seen := make(map[string]bool)
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if lineNumber == 1 {
			if line != "format "+releaseFormat {
				return nil, errors.New("invalid release manifest format")
			}
			formatSeen = true
			continue
		}
		parts := strings.Split(line, " ")
		if len(parts) != 4 || parts[0] != "file" || !validDigest(parts[1]) || !safeRelative(parts[3]) {
			return nil, fmt.Errorf("invalid release manifest line %d", lineNumber)
		}
		mode, err := strconv.ParseUint(parts[2], 8, 32)
		if err != nil || mode&^0o777 != 0 || mode&0o022 != 0 {
			return nil, fmt.Errorf("unsafe release mode on line %d", lineNumber)
		}
		if seen[parts[3]] {
			return nil, fmt.Errorf("duplicate release entry %q", parts[3])
		}
		seen[parts[3]] = true
		entries = append(entries, releaseEntry{Path: parts[3], SHA256: parts[1], Mode: uint32(mode)})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if !formatSeen {
		return nil, errors.New("empty release manifest")
	}
	for _, required := range requiredReleaseEntries {
		if !seen[required] {
			return nil, fmt.Errorf("release manifest missing %q", required)
		}
	}
	if len(entries) != len(requiredReleaseEntries) {
		return nil, errors.New("release manifest contains unapproved entries")
	}
	return entries, nil
}

// parseSelfManagedVersion accepts only a clean, locally reproducible release
// candidate. It intentionally contains no GitHub, OIDC, or approval identity:
// the gateway owner selects the candidate by its recorded digests.
func parseSelfManagedVersion(r io.Reader) (selfManagedVersion, error) {
	values, err := parseKeyValue(r, 20)
	if err != nil {
		return selfManagedVersion{}, err
	}
	if len(values) != 17 || values["format"] != "pgw-version-v2" ||
		values["candidate_only"] != "false" ||
		values["promotion_authority"] != selfManagedPromotionAuthority ||
		values["source_dirty"] != "false" {
		return selfManagedVersion{}, errors.New("invalid self-managed version manifest")
	}
	for _, key := range []string{
		"release_id", "source_commit", "source_tree", "source_commit_time", "go_module", "go_version",
		"target", "cgo_enabled", "build_flags", "module_verification", "deterministic_rebuilds",
		"release_manifest_sha256", "launcher_sha256",
	} {
		if values[key] == "" {
			return selfManagedVersion{}, fmt.Errorf("self-managed version manifest missing %q", key)
		}
	}
	if !safeReleaseID.MatchString(values["release_id"]) || values["target"] != "linux/amd64" ||
		values["cgo_enabled"] != "0" || values["deterministic_rebuilds"] != "2" ||
		!validDigest(values["release_manifest_sha256"]) || !validDigest(values["launcher_sha256"]) {
		return selfManagedVersion{}, errors.New("invalid self-managed version identity")
	}
	return selfManagedVersion{
		ReleaseID:      values["release_id"],
		ManifestSHA256: values["release_manifest_sha256"],
		LauncherSHA256: values["launcher_sha256"],
	}, nil
}

func parseKeyValue(r io.Reader, maxLines int) (map[string]string, error) {
	scanner := bufio.NewScanner(io.LimitReader(r, 64*1024+1))
	values := make(map[string]string)
	for line := 1; scanner.Scan(); line++ {
		if line > maxLines {
			return nil, errors.New("manifest has too many lines")
		}
		parts := strings.Split(scanner.Text(), " ")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" || values[parts[0]] != "" {
			return nil, fmt.Errorf("invalid manifest line %d", line)
		}
		values[parts[0]] = parts[1]
	}
	return values, scanner.Err()
}

func safeRelative(name string) bool {
	return safeEntryPath.MatchString(name) && !strings.Contains(name, "//") && path.Clean(name) == name && name != "."
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
