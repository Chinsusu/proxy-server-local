//go:build unix

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSecureWriteRejectsSymlinkTargetWithoutTouchingReferent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "rules")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(t.TempDir(), "sentinel")
	if err := os.WriteFile(sentinel, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sentinel, filepath.Join(root, lkgRulesFile)); err != nil {
		t.Fatal(err)
	}
	if err := secureWriteFileAtomic(root, lkgRulesFile, []byte("attacker wins"), 0o640); err == nil {
		t.Fatal("secure write accepted symlink target")
	}
	assertFileContent(t, sentinel, "unchanged")
}

func TestSecureDirectoryRejectsSymlinkAndUnsafeModeComponents(t *testing.T) {
	base := t.TempDir()
	realDirectory := filepath.Join(base, "real")
	if err := os.Mkdir(realDirectory, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(realDirectory, link); err != nil {
		t.Fatal(err)
	}
	if err := secureEnsureDirectory(filepath.Join(link, "rules"), 0o750); err == nil {
		t.Fatal("secure directory traversal accepted symlink component")
	}

	unsafe := filepath.Join(base, "unsafe")
	if err := os.Mkdir(unsafe, 0o770); err != nil {
		t.Fatal(err)
	}
	// Mkdir is subject to the process umask. Force the adversarial mode and
	// verify the fixture before exercising the product validation.
	if err := os.Chmod(unsafe, 0o770); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(unsafe)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o770 {
		t.Fatalf("unsafe fixture mode = %#o, want 0770", got)
	}
	if err := secureEnsureDirectory(filepath.Join(unsafe, "rules"), 0o750); err == nil {
		t.Fatal("secure directory traversal accepted group-writable component")
	}
}

func TestSecureDirectoryRejectsUnexpectedOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("owner mismatch requires root")
	}
	base := t.TempDir()
	untrusted := filepath.Join(base, "untrusted")
	if err := os.Mkdir(untrusted, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(untrusted, 65534, 65534); err != nil {
		t.Skipf("cannot create mismatched-owner fixture: %v", err)
	}
	defer os.Chown(untrusted, 0, 0)
	if err := secureValidateDirectory(untrusted); err == nil {
		t.Fatal("secure directory validation accepted unexpected owner")
	}
}

func TestSecureSetOwnerModePreservesEffectiveOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "forwarder.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := secureSetOwnerMode(path, -1, os.Getegid(), 0o640, false); err != nil {
		t.Fatalf("secureSetOwnerMode: %v", err)
	}
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		t.Fatal(err)
	}
	if stat.Uid != uint32(os.Geteuid()) {
		t.Fatalf("owner uid = %d, want effective uid %d", stat.Uid, os.Geteuid())
	}
	if stat.Mode&0o777 != 0o640 {
		t.Fatalf("mode = %#o, want 0640", stat.Mode&0o777)
	}
}

func TestSecureTokenReadRejectsModeAndSymlink(t *testing.T) {
	root := t.TempDir()
	token := filepath.Join(root, "agent.token")
	if err := os.WriteFile(token, []byte("secret"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := secureReadToken(token, 1024); err == nil {
		t.Fatal("token loader accepted mode 0640")
	}
	if err := os.Chmod(token, 0o600); err != nil {
		t.Fatal(err)
	}
	material, err := secureReadToken(token, 1024)
	if err != nil {
		t.Fatalf("read secure token: %v", err)
	}
	zero(material)
	link := filepath.Join(root, "linked.token")
	if err := os.Symlink(token, link); err != nil {
		t.Fatal(err)
	}
	if _, err := secureReadToken(link, 1024); err == nil {
		t.Fatal("token loader accepted symlink")
	}
}

func TestSecureAtomicWriteResistsComponentSwap(t *testing.T) {
	if runtime.GOOS == "aix" {
		t.Skip("rename behavior differs")
	}
	base := t.TempDir()
	trusted := filepath.Join(base, "trusted")
	parked := filepath.Join(base, "parked")
	attacker := filepath.Join(base, "attacker")
	if err := os.Mkdir(trusted, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(attacker, 0o750); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(attacker, "state")
	if err := os.WriteFile(sentinel, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}

	var workers sync.WaitGroup
	stop := make(chan struct{})
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := os.Rename(trusted, parked); err != nil {
				continue
			}
			_ = os.Symlink(attacker, trusted)
			_ = os.Remove(trusted)
			_ = os.Rename(parked, trusted)
		}
	}()
	for index := 0; index < 100; index++ {
		_ = secureWriteFileAtomic(trusted, "state", []byte("safe"), 0o600)
	}
	close(stop)
	workers.Wait()
	assertFileContent(t, sentinel, "sentinel")
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if string(content) != want {
		t.Fatalf("%s content = %q, want %q", path, content, want)
	}
}
