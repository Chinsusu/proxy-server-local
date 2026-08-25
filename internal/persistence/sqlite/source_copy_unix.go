//go:build !windows

package sqlite

import (
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func copySourceNofollow(source, destination string) error {
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Lstat(source + suffix); err == nil {
			return fmt.Errorf("sqlite: restore source has live %s sidecar", suffix)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	fd, err := unix.Open(source, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("sqlite: securely open restore source: %w", err)
	}
	input := os.NewFile(uintptr(fd), source)
	defer input.Close()
	info, err := input.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("sqlite: unsafe restore source")
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		_ = os.Remove(destination)
		return err
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		_ = os.Remove(destination)
		return err
	}
	return output.Close()
}
