//go:build !windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// openLegacyStateFile opens the input exactly once without following a
// symlink, then validates the opened inode. That makes the migration input
// safe even when the legacy directory contains attacker-controlled names.
func openLegacyStateFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("unsafe legacy state file")
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect legacy state file")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		_ = file.Close()
		return nil, fmt.Errorf("unsafe legacy state file")
	}
	return file, nil
}
