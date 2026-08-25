//go:build windows

package sqlite

import "errors"

var ErrDatabaseLocked = errors.New("persistent SQLite operations require an ACL/lock provider on Windows")

type databaseLock struct{}

func precreateSecureDatabase(string) error                       { return ErrDatabaseLocked }
func persistentOperationsAllowed() error                         { return ErrDatabaseLocked }
func acquireDatabaseSharedLock(string) (*databaseLock, error)    { return nil, ErrDatabaseLocked }
func acquireDatabaseExclusiveLock(string) (*databaseLock, error) { return nil, ErrDatabaseLocked }
func (*databaseLock) Close() error                               { return nil }
