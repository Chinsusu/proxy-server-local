//go:build !windows

package secret

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// LoadRootOwnedAdminPasswordFile opens passwordPath once through root-owned,
// non-writable directory descriptors and reads the exact opened inode. It is
// deliberately narrower than LoadTokenFile: installers run this helper as
// root and may only supply a root-owned 0400/0600 file. No path is inspected
// and then reopened, so symlink/component replacement cannot swap the bytes
// that are hashed.
func LoadRootOwnedAdminPasswordFile(passwordPath string, limit int64) ([]byte, error) {
	file, err := openRootOwnedAdminPasswordFile(passwordPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		wipe(contents)
		return nil, fmt.Errorf("secret: read admin password file: %w", err)
	}
	if len(contents) == 0 || int64(len(contents)) > limit {
		wipe(contents)
		return nil, ErrUnsafeAdminPasswordFile
	}
	return contents, nil
}

// openRootOwnedAdminPasswordFile exists separately so Unix tests can prove
// that a replacement after the open does not affect the descriptor's bytes.
func openRootOwnedAdminPasswordFile(passwordPath string) (*os.File, error) {
	return openRootOwnedAdminPasswordFileWithDirectoryOpen(passwordPath, nil)
}

// openRootOwnedAdminPasswordFileWithDirectoryOpen keeps the traversal
// boundary independently testable: a test can replace a pathname component
// after its descriptor is open and verify final resolution remains below that
// descriptor. Production always supplies a nil callback.
func openRootOwnedAdminPasswordFileWithDirectoryOpen(passwordPath string, afterDirectoryOpen func(string)) (*os.File, error) {
	if passwordPath == "" || !filepath.IsAbs(passwordPath) || filepath.Clean(passwordPath) != passwordPath {
		return nil, ErrUnsafeAdminPasswordFile
	}
	components := strings.Split(strings.TrimPrefix(passwordPath, string(filepath.Separator)), string(filepath.Separator))
	if len(components) == 0 || components[len(components)-1] == "" {
		return nil, ErrUnsafeAdminPasswordFile
	}
	parentFD, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("secret: open root directory: %w", err)
	}
	parent := os.NewFile(uintptr(parentFD), string(filepath.Separator))
	defer func() { _ = parent.Close() }()
	if err := validateRootOwnedDirectory(parent); err != nil {
		return nil, err
	}
	for _, component := range components[:len(components)-1] {
		if component == "" || component == "." || component == ".." {
			return nil, ErrUnsafeAdminPasswordFile
		}
		fd, openErr := unix.Openat(int(parent.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			return nil, ErrUnsafeAdminPasswordFile
		}
		next := os.NewFile(uintptr(fd), component)
		if err := validateRootOwnedDirectory(next); err != nil {
			next.Close()
			return nil, err
		}
		parent.Close()
		parent = next
		if afterDirectoryOpen != nil {
			afterDirectoryOpen(component)
		}
	}
	name := components[len(components)-1]
	if name == "." || name == ".." {
		return nil, ErrUnsafeAdminPasswordFile
	}
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrUnsafeAdminPasswordFile
	}
	file := os.NewFile(uintptr(fd), name)
	if err := validateRootOwnedAdminPasswordFile(file); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func validateRootOwnedDirectory(file *os.File) error {
	info, err := file.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || !ownedByRoot(info) {
		return ErrUnsafeAdminPasswordFile
	}
	return nil
}

func validateRootOwnedAdminPasswordFile(file *os.File) error {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !ownedByRoot(info) {
		return ErrUnsafeAdminPasswordFile
	}
	if mode := info.Mode().Perm(); mode != 0o400 && mode != 0o600 {
		return ErrUnsafeAdminPasswordFile
	}
	return nil
}

func ownedByRoot(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0
}
