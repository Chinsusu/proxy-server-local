//go:build !windows

package sqlite

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

var ErrDatabaseLocked = errors.New("database is in use by a running PGW repository")

type databaseLock struct{ file *os.File }

func precreateSecureDatabase(path string) error {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || int(stat.Uid) != os.Geteuid() {
		_ = file.Close()
		return errors.New("unsafe SQLite database file")
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return secureSQLiteFile(path)
}
func persistentOperationsAllowed() error { return nil }
func acquireDatabaseSharedLock(path string) (*databaseLock, error) {
	return acquireDatabaseLock(path, unix.LOCK_SH|unix.LOCK_NB)
}
func acquireDatabaseExclusiveLock(path string) (*databaseLock, error) {
	return acquireDatabaseLock(path, unix.LOCK_EX|unix.LOCK_NB)
}
func acquireDatabaseLock(path string, mode int) (*databaseLock, error) {
	file, err := os.OpenFile(path+".pgw.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := secureSQLiteFile(path + ".pgw.lock"); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), mode); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrDatabaseLocked
		}
		return nil, err
	}
	return &databaseLock{file: file}, nil
}
func (l *databaseLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	_ = unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	err := l.file.Close()
	l.file = nil
	return err
}
