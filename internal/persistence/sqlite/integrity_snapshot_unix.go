//go:build !windows

package sqlite

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// snapshotIntegrityTarget copies bytes from one O_NOFOLLOW-open descriptor to
// a private, same-filesystem artifact. SQLite subsequently opens only that
// artifact, so a caller cannot swap the original path between validation and
// integrity_check.
func snapshotIntegrityTarget(ctx context.Context, path string) (string, func(), error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	parent := filepath.Dir(path)
	if err := secureSQLiteParent(path); err != nil {
		return "", nil, fmt.Errorf("sqlite: insecure integrity parent: %w", err)
	}
	initial, err := os.Lstat(path)
	if err != nil {
		return "", nil, fmt.Errorf("sqlite: integrity target: %w", err)
	}
	if initial.Mode()&os.ModeSymlink != 0 || !initial.Mode().IsRegular() {
		return "", nil, fmt.Errorf("sqlite: integrity target is not a regular non-symlink file")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", nil, fmt.Errorf("sqlite: securely open integrity target: %w", err)
	}
	source := os.NewFile(uintptr(fd), path)
	defer source.Close()
	opened, err := source.Stat()
	if err != nil {
		return "", nil, fmt.Errorf("sqlite: stat integrity target: %w", err)
	}
	before, okBefore := initial.Sys().(*syscall.Stat_t)
	after, okAfter := opened.Sys().(*syscall.Stat_t)
	if !okBefore || !okAfter || !opened.Mode().IsRegular() || before.Dev != after.Dev || before.Ino != after.Ino {
		return "", nil, fmt.Errorf("sqlite: integrity target changed while opening")
	}
	stageDir, err := os.MkdirTemp(parent, ".pgw-integrity-stage-")
	if err != nil {
		return "", nil, fmt.Errorf("sqlite: create integrity staging: %w", err)
	}
	cleanup := func() {
		_ = os.RemoveAll(stageDir)
		_ = syncDirectory(parent)
	}
	if err := os.Chmod(stageDir, 0o700); err != nil {
		cleanup()
		return "", nil, err
	}
	snapshot := filepath.Join(stageDir, "database.db")
	out, err := os.OpenFile(snapshot, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	if _, err := copyWithContext(ctx, out, source); err != nil {
		_ = out.Close()
		cleanup()
		return "", nil, fmt.Errorf("sqlite: copy integrity snapshot: %w", err)
	}
	if err := out.Chmod(0o600); err != nil {
		_ = out.Close()
		cleanup()
		return "", nil, err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		cleanup()
		return "", nil, err
	}
	if err := out.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	if err := secureSQLiteFile(snapshot); err != nil {
		cleanup()
		return "", nil, err
	}
	if err := syncDirectory(stageDir); err != nil {
		cleanup()
		return "", nil, err
	}
	return snapshot, cleanup, nil
}

func copyWithContext(ctx context.Context, destination io.Writer, source io.Reader) (int64, error) {
	buffer := make([]byte, 32<<10)
	defer zero(buffer)
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		read, readErr := source.Read(buffer)
		if read > 0 {
			count, writeErr := destination.Write(buffer[:read])
			written += int64(count)
			if writeErr != nil {
				return written, writeErr
			}
			if count != read {
				return written, io.ErrShortWrite
			}
		}
		if readErr == io.EOF {
			return written, nil
		}
		if readErr != nil {
			return written, readErr
		}
	}
}
