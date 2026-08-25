//go:build windows

package main

import (
	"fmt"
	"os"
)

// Windows has no Unix-domain socket ownership primitive equivalent to the
// deployment contract. Refuse an existing path rather than guessing whether
// it is stale.
func recoverStaleAgentSocket(path string) error {
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect socket: %w", err)
	}
	return fmt.Errorf("refusing to replace an existing agent socket")
}

func validateBoundAgentSocket(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect bound socket: %w", err)
	}
	return info, nil
}

func validatePublishedAgentSocket(path string, bound os.FileInfo) error {
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(bound, current) {
		return fmt.Errorf("published socket changed or is unavailable")
	}
	return nil
}
