//go:build !windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func inheritedRegularFile(fd int, writable bool) (*os.File, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("inherited descriptor is not a regular file")
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || (writable && flags&unix.O_ACCMODE == unix.O_RDONLY) || (!writable && flags&unix.O_ACCMODE == unix.O_WRONLY) {
		return nil, fmt.Errorf("inherited descriptor access mode is invalid")
	}
	return os.NewFile(uintptr(fd), "inherited"), nil
}

func openLegacyStateFD(fd int) (*os.File, error)  { return inheritedRegularFile(fd, false) }
func openLegacyKeyFD(fd int) (*os.File, error)    { return inheritedRegularFile(fd, false) }
func openLegacyReportFD(fd int) (*os.File, error) { return inheritedRegularFile(fd, true) }
