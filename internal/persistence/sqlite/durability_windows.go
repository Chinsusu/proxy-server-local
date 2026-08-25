//go:build windows

package sqlite

import (
	"errors"
	"os"
)

var errAtomicReplaceUnsupported = errors.New("atomic replacement of an existing database is unsupported on Windows")

func atomicReplace(staged, destination string) error {
	if _, err := os.Lstat(destination); err == nil {
		// Fail closed rather than delete a live target before a replacement has
		// been secured. A Windows MoveFileEx/ACL-aware implementation can later
		// provide the same atomic contract as POSIX rename.
		return errAtomicReplaceUnsupported
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(staged, destination)
}

func syncFile(path string) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

// Windows does not support opening a directory with os.Open for fsync. The
// file handle has been synced; destination replacement remains fail-closed.
func syncDirectory(string) error { return nil }
