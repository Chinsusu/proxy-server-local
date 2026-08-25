//go:build !linux

package forwarder

import (
	"errors"
	"os"
)

// Production forwarding is Linux-only. This fallback keeps developer tooling
// portable while refusing symbolic links before opening a regular file.
func openSafeRead(path string) (*os.File, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.New("symbolic links are not accepted")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	openedInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	return file, openedInfo, nil
}
