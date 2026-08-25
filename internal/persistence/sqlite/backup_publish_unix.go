//go:build !windows

package sqlite

import (
	"errors"
	"os"
)

// publishBackupNoClobber uses link(2), whose destination creation is atomic.
// Staging is deliberately created below the destination directory, so this is
// same-filesystem. Unlike rename, link never replaces another writer's backup.
func publishBackupNoClobber(staged, destination string) error {
	if err := os.Link(staged, destination); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrBackupExists
		}
		return err
	}
	if err := os.Remove(staged); err != nil {
		return err
	}
	return nil
}
