//go:build linux

package snapshotcrypto

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func platformLoadKeyFile(name string) (key Key, resultErr error) {
	if !cleanAbsolutePath(name) {
		return key, fmt.Errorf("%w: key path must be clean and absolute", ErrUnsafePath)
	}
	directory, base, err := openTrustedParentDirectory(name, nil)
	if err != nil {
		return key, fmt.Errorf("open key parent: %w", err)
	}
	defer func() {
		if err := unix.Close(directory); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close key parent: %w", err))
		}
		if resultErr != nil {
			key.Destroy()
		}
	}()
	fd, err := unix.Openat(directory, base, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return key, fmt.Errorf("securely open snapshot key: %w", err)
	}
	file := os.NewFile(uintptr(fd), name)
	defer func() {
		if err := file.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close snapshot key: %w", err))
		}
	}()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return key, fmt.Errorf("inspect snapshot key: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || uint32(stat.Mode)&0o7777 != 0o600 || stat.Size != KeySize {
		return key, errors.New("snapshot key must be owned by the caller and be a mode-0600 regular file containing exactly 32 bytes")
	}
	before, err := sourceState(fd)
	if err != nil {
		return key, fmt.Errorf("capture snapshot key identity: %w", err)
	}
	if _, err := io.ReadFull(file, key[:]); err != nil {
		key.Destroy()
		return key, fmt.Errorf("read snapshot key: %w", err)
	}
	var extra [1]byte
	if count, err := file.Read(extra[:]); count != 0 || !errors.Is(err, io.EOF) {
		key.Destroy()
		return key, ErrInvalidKey
	}
	after, err := sourceState(fd)
	if err != nil || before != after {
		key.Destroy()
		return key, errors.New("snapshot key changed while reading")
	}
	return key, nil
}
