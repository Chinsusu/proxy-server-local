//go:build windows

package main

import (
	"fmt"
	"os"
)

func inheritedRegularFile(fd int, _ bool) (*os.File, error) {
	file := os.NewFile(uintptr(fd), "inherited")
	if file == nil {
		return nil, fmt.Errorf("invalid inherited descriptor")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("inherited descriptor is not a regular file")
	}
	return file, nil
}

func openLegacyStateFD(fd int) (*os.File, error)  { return inheritedRegularFile(fd, false) }
func openLegacyKeyFD(fd int) (*os.File, error)    { return inheritedRegularFile(fd, false) }
func openLegacyReportFD(fd int) (*os.File, error) { return inheritedRegularFile(fd, true) }
