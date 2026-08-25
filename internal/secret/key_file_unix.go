//go:build !windows

package secret

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func secureReadKeyFile(path string, limit int64) ([]byte, error) {
	// systemd LoadCredential material is intentionally owner-read-only (0400),
	// while the persistent /etc fallback is owner-read/write (0600). Both are
	// exact owner-only modes; every other permission set is rejected.
	return secureReadFile(path, limit, true, ErrUnsafeKeyFile)
}

func secureReadTokenFile(path string, limit int64) ([]byte, error) {
	return secureReadFile(path, limit, true, ErrUnsafeTokenFile)
}

func secureReadFile(path string, limit int64, allowReadOnly bool, unsafeErr error) ([]byte, error) {
	parent := filepath.Dir(path)
	parentInfo, err := os.Stat(parent)
	if err != nil {
		return nil, fmt.Errorf("secret: stat key parent: %w", err)
	}
	if !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o022 != 0 || !ownedByEffectiveUser(parentInfo) {
		return nil, unsafeErr
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("secret: securely open key file: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat() // fstat the exact inode opened above.
	if err != nil {
		return nil, fmt.Errorf("secret: fstat key file: %w", err)
	}
	if !info.Mode().IsRegular() || !ownedByEffectiveUser(info) {
		return nil, unsafeErr
	}
	mode := info.Mode().Perm()
	if mode != 0o600 && (!allowReadOnly || mode != 0o400) {
		return nil, unsafeErr
	}
	contents, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		wipe(contents)
		return nil, fmt.Errorf("secret: read key file: %w", err)
	}
	if int64(len(contents)) > limit {
		wipe(contents)
		return nil, ErrInvalidKey
	}
	return contents, nil
}

func ownedByEffectiveUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}
