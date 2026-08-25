//go:build !windows

package sqlite

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func secureSQLiteParent(path string) error {
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("unsafe SQLite parent directory")
	}
	return nil
}

func secureSQLiteFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("unsafe SQLite file type")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	info, err = os.Stat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("unsafe SQLite file permissions")
	}
	return nil
}

func secureSQLiteSidecars(path string) error {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if _, err := os.Stat(path + suffix); err == nil {
			if err := secureSQLiteFile(path + suffix); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
