//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestParseAdoptArguments(t *testing.T) {
	t.Parallel()
	assembly, dryRun, installerArgs, err := parseAdoptArguments([]string{"/opt/pgw/inbox/release", "--dry-run"})
	if err != nil || assembly != "/opt/pgw/inbox/release" || !dryRun || len(installerArgs) != 0 {
		t.Fatalf("dry-run adoption parse = %q, %t, %#v, %v", assembly, dryRun, installerArgs, err)
	}
	assembly, dryRun, installerArgs, err = parseAdoptArguments([]string{"/opt/pgw/inbox/release", "--migrate-legacy", "--lan", "ens19", "--wan", "eth0"})
	if err != nil || assembly != "/opt/pgw/inbox/release" || dryRun || len(installerArgs) != 5 {
		t.Fatalf("apply adoption parse = %q, %t, %#v, %v", assembly, dryRun, installerArgs, err)
	}
	for _, args := range [][]string{
		nil,
		{"relative"},
		{"/opt/pgw/inbox/release", "--dry-run", "--migrate-legacy"},
		{"/opt/pgw/inbox/release", "--rollback", "/var/backups/pgw/old"},
		{"/opt/pgw/inbox/release", "--lan"},
	} {
		if _, _, _, err := parseAdoptArguments(args); err == nil {
			t.Fatalf("unsafe adoption arguments accepted: %#v", args)
		}
	}
}

func TestSecureReleaseOpenRejectsSymlinkWritableAndBindsDescriptor(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership fixture requires an isolated root CI runner")
	}
	root, err := os.MkdirTemp("/var/lib", "pgw-launcher-test.")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(root, "good")
	if err := os.Mkdir(good, 0o700); err != nil {
		t.Fatal(err)
	}
	fileName := filepath.Join(good, "payload")
	if err := os.WriteFile(fileName, []byte("trusted"), 0o600); err != nil {
		t.Fatal(err)
	}
	rootFD, err := secureOpenDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer os.NewFile(uintptr(rootFD), "root").Close()
	file, err := secureOpenRelative(rootFD, "good/payload", 0o600, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := os.Rename(fileName, fileName+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fileName, []byte("swapped"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest, err := hashAndRewind(file)
	want := sha256.Sum256([]byte("trusted"))
	if err != nil || digest != hex.EncodeToString(want[:]) {
		t.Fatalf("opened descriptor followed path swap: %q, %v", digest, err)
	}

	if err := os.Symlink("good", filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := secureOpenRelative(rootFD, "linked/payload", 0o600, 64); err == nil {
		t.Fatal("symlink ancestor accepted")
	}
	unsafe := filepath.Join(root, "unsafe")
	if err := os.Mkdir(unsafe, 0o770); err != nil {
		t.Fatal(err)
	}
	// Mkdir is subject to the runner's umask. Force and verify the unsafe mode
	// so the rejection assertion cannot silently become a safe 0750 fixture.
	if err := os.Chmod(unsafe, 0o770); err != nil {
		t.Fatal(err)
	}
	unsafeInfo, err := os.Stat(unsafe)
	if err != nil {
		t.Fatal(err)
	}
	if got := unsafeInfo.Mode().Perm(); got != 0o770 {
		t.Fatalf("unsafe fixture mode = %#o, want 0770", got)
	}
	if err := os.WriteFile(filepath.Join(unsafe, "payload"), []byte("bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := secureOpenRelative(rootFD, "unsafe/payload", 0o600, 64); err == nil {
		t.Fatal("group-writable ancestor accepted")
	}
}

func TestVerifiedInstallerUsesRootCWDAndIsolatedPython(t *testing.T) {
	if _, err := os.Stat("/usr/bin/python3"); err != nil {
		t.Skip("fixed production Python is unavailable")
	}
	attacker := t.TempDir()
	sentinel := filepath.Join(attacker, "imported")
	module := "from pathlib import Path\nPath(" + strconv.Quote(sentinel) + ").write_text('owned')\n"
	if err := os.WriteFile(filepath.Join(attacker, "pgw_cwd_probe.py"), []byte(module), 0o600); err != nil {
		t.Fatal(err)
	}
	script, err := os.CreateTemp("", "pgw-launcher-script.*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(script.Name())
	defer script.Close()
	content := "#!/bin/bash\nset -eu\n[[ \"$PWD\" == / ]]\n/usr/bin/python3 -I - <<'PY'\nimport importlib.util\nassert importlib.util.find_spec('pgw_cwd_probe') is None\nPY\n"
	if _, err := script.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if _, err := script.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(attacker); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	if err := runVerifiedInstaller(3, []*os.File{script}, nil, []string{"PATH=" + fixedPath, "LANG=C", "LC_ALL=C"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("hostile caller-CWD module executed: %v", err)
	}
}
