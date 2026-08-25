//go:build windows

package sqlite

import "context"

// Persistent file checks fail closed on Windows until the ACL-aware file and
// lock provider is implemented.
func snapshotIntegrityTarget(context.Context, string) (string, func(), error) {
	return "", nil, ErrDatabaseLocked
}
