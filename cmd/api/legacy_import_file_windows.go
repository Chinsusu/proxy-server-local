//go:build windows

package main

import (
	"fmt"
	"os"
)

// Persistent SQLite operations already fail closed on Windows. Keep dry-run
// development tests portable while still rejecting links and changed files.
func openLegacyStateFile(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("unsafe legacy state file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open legacy state file")
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, fmt.Errorf("legacy state file changed during open")
	}
	return file, nil
}
