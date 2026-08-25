//go:build !windows

package sqlite

import (
	"os"
)

func atomicReplace(staged, destination string) error {
	// POSIX rename atomically replaces destination without an unlink window.
	return os.Rename(staged, destination)
}

func syncFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
