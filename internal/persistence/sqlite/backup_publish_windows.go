//go:build windows

package sqlite

// Persistent backup publication is intentionally unsupported until an
// ACL-aware Windows implementation can make the publication directory safe.
func publishBackupNoClobber(_, _ string) error { return ErrDatabaseLocked }
