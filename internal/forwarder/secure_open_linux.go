//go:build linux

package forwarder

import (
	"os"
	"syscall"
)

// openSafeRead binds validation to the opened descriptor. O_NOFOLLOW prevents
// a compromised runtime path from swapping a credential or config file for a
// symlink between validation and open.
func openSafeRead(path string) (*os.File, os.FileInfo, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	return file, info, nil
}
