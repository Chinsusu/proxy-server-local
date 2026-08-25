//go:build unix

package agent

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func secureEnsureDirectory(path string, mode os.FileMode) error {
	fd, err := openTrustedDirectory(path, true, uint32(mode.Perm()))
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Fchmod(fd, uint32(mode.Perm())); err != nil {
		return fmt.Errorf("agent: secure directory mode: %w", err)
	}
	return unix.Fsync(fd)
}

func secureValidateDirectory(path string) error {
	fd, err := openTrustedDirectory(path, false, 0)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

func secureReadRegular(path string, limit int64) ([]byte, error) {
	return secureReadRegularModes(path, limit, false)
}

func secureReadToken(path string, limit int64) ([]byte, error) {
	return secureReadRegularModes(path, limit, true)
}

func secureReadRegularModes(path string, limit int64, tokenMode bool) ([]byte, error) {
	directory, name, err := secureParent(path)
	if err != nil {
		return nil, err
	}
	defer unix.Close(directory)
	fd, err := unix.Openat(directory, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("agent: create secure file descriptor")
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if err := validateRegularStat(stat, tokenMode); err != nil {
		return nil, err
	}
	if stat.Size < 0 || stat.Size > limit {
		return nil, fmt.Errorf("agent: unsafe or oversized file")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		zero(data)
		return nil, fmt.Errorf("agent: unsafe or oversized file")
	}
	return data, nil
}

func secureWriteFileAtomic(directory, name string, content []byte, mode os.FileMode) error {
	if !safeLeaf(name) {
		return fmt.Errorf("agent: unsafe file name")
	}
	dirfd, err := openTrustedDirectory(directory, false, 0)
	if err != nil {
		return err
	}
	defer unix.Close(dirfd)
	if err := validateExistingTarget(dirfd, name); err != nil {
		return err
	}
	temporary, fd, err := createTemporaryAt(dirfd, ".pgw-tmp-", uint32(mode.Perm()))
	if err != nil {
		return err
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = unix.Unlinkat(dirfd, temporary, 0)
		}
	}()
	file := os.NewFile(uintptr(fd), temporary)
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("agent: create temporary file descriptor")
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := unix.Renameat(dirfd, temporary, dirfd, name); err != nil {
		return err
	}
	removeTemporary = false
	return unix.Fsync(dirfd)
}

func secureRemoveFile(directory, name string) error {
	if !safeLeaf(name) {
		return fmt.Errorf("agent: unsafe file name")
	}
	dirfd, err := openTrustedDirectory(directory, false, 0)
	if err != nil {
		return err
	}
	defer unix.Close(dirfd)
	var stat unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if err := validateRegularStat(stat, false); err != nil {
		return err
	}
	if err := unix.Unlinkat(dirfd, name, 0); err != nil {
		return err
	}
	return unix.Fsync(dirfd)
}

func secureMkdirTemp(directory, prefix string, mode os.FileMode) (string, error) {
	if !safeLeaf(prefix) {
		return "", fmt.Errorf("agent: unsafe temporary directory prefix")
	}
	dirfd, err := openTrustedDirectory(directory, false, 0)
	if err != nil {
		return "", err
	}
	defer unix.Close(dirfd)
	for attempts := 0; attempts < 128; attempts++ {
		random := make([]byte, 12)
		if _, err := rand.Read(random); err != nil {
			return "", err
		}
		name := prefix + hex.EncodeToString(random)
		zero(random)
		if err := unix.Mkdirat(dirfd, name, uint32(mode.Perm())); err != nil {
			if errors.Is(err, unix.EEXIST) {
				continue
			}
			return "", err
		}
		if err := unix.Fsync(dirfd); err != nil {
			_ = unix.Unlinkat(dirfd, name, unix.AT_REMOVEDIR)
			return "", err
		}
		return filepath.Join(directory, name), nil
	}
	return "", fmt.Errorf("agent: cannot allocate secure temporary directory")
}

func secureRemoveTree(path string) error {
	parent, name, err := secureParent(path)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	if err := removeTreeAt(parent, name); err != nil {
		return err
	}
	return unix.Fsync(parent)
}

func secureRemoveChildren(directory, prefix string) error {
	dirfd, err := openTrustedDirectory(directory, false, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(dirfd)
	duplicate, err := unix.Dup(dirfd)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(duplicate), directory)
	entries, err := file.ReadDir(-1)
	_ = file.Close()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) || !safeLeaf(entry.Name()) {
			continue
		}
		if err := removeTreeAt(dirfd, entry.Name()); err != nil {
			return err
		}
	}
	return unix.Fsync(dirfd)
}

func secureWipeFile(path string) error {
	directory, name, err := secureParent(path)
	if err != nil {
		return err
	}
	defer unix.Close(directory)
	fd, err := unix.Openat(directory, name, unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if err := validateRegularStat(stat, false); err != nil {
		return err
	}
	return wipeRegularFD(fd, stat.Size)
}

func secureSetOwnerMode(path string, uid, gid int, mode os.FileMode, directory bool) error {
	parent, name, err := secureParent(path)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if directory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Openat(parent, name, flags, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if directory && stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("agent: expected directory")
	}
	if !directory && stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("agent: expected regular file")
	}
	if err := unix.Fchown(fd, uid, gid); err != nil {
		return err
	}
	return unix.Fchmod(fd, uint32(mode.Perm()))
}

func secureValidateExisting(path string) error {
	parent, name, err := secureParent(path)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT == unix.S_IFDIR {
		return validateDirectoryStat(stat, false)
	}
	return validateRegularStat(stat, false)
}

func openTrustedDirectory(path string, create bool, createMode uint32) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, fmt.Errorf("agent: trusted directory must be an absolute clean path")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	var rootStat unix.Stat_t
	if err := unix.Fstat(fd, &rootStat); err != nil || validateDirectoryStat(rootStat, true) != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("agent: unsafe filesystem root")
	}
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(components) == 1 && components[0] == "" {
		return fd, nil
	}
	for index, component := range components {
		if !safeLeaf(component) {
			_ = unix.Close(fd)
			return -1, fmt.Errorf("agent: unsafe trusted directory component")
		}
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr != nil && create && errors.Is(openErr, unix.ENOENT) {
			mode := createMode
			if index != len(components)-1 || mode == 0 {
				mode = 0o750
			}
			if err := unix.Mkdirat(fd, component, mode); err != nil && !errors.Is(err, unix.EEXIST) {
				_ = unix.Close(fd)
				return -1, err
			}
			if err := unix.Fsync(fd); err != nil {
				_ = unix.Close(fd)
				return -1, err
			}
			next, openErr = unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		if openErr != nil {
			_ = unix.Close(fd)
			return -1, openErr
		}
		var stat unix.Stat_t
		statErr := unix.Fstat(next, &stat)
		validationErr := validateDirectoryStat(stat, index != len(components)-1)
		_ = unix.Close(fd)
		if statErr != nil || validationErr != nil {
			_ = unix.Close(next)
			if statErr != nil {
				return -1, statErr
			}
			return -1, validationErr
		}
		fd = next
	}
	return fd, nil
}

func secureParent(path string) (int, string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, "", fmt.Errorf("agent: privileged file path must be absolute and clean")
	}
	name := filepath.Base(path)
	if !safeLeaf(name) {
		return -1, "", fmt.Errorf("agent: unsafe privileged file name")
	}
	fd, err := openTrustedDirectory(filepath.Dir(path), false, 0)
	return fd, name, err
}

func validateDirectoryStat(stat unix.Stat_t, ancestor bool) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || !trustedOwner(stat.Uid) {
		return fmt.Errorf("agent: untrusted directory owner or type")
	}
	if stat.Mode&0o022 != 0 {
		if ancestor && stat.Uid == 0 && stat.Mode&unix.S_ISVTX != 0 {
			return nil
		}
		return fmt.Errorf("agent: group/world-writable privileged directory")
	}
	return nil
}

func validateRegularStat(stat unix.Stat_t, tokenMode bool) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || !trustedOwner(stat.Uid) {
		return fmt.Errorf("agent: untrusted file owner or type")
	}
	permissions := stat.Mode & 0o777
	if tokenMode {
		if permissions != 0o400 && permissions != 0o600 {
			return fmt.Errorf("agent: service token must have mode 0400 or 0600")
		}
	} else if permissions&0o022 != 0 {
		return fmt.Errorf("agent: group/world-writable privileged file")
	}
	return nil
}

func trustedOwner(uid uint32) bool {
	return uid == 0 || uid == uint32(os.Geteuid())
}

func validateExistingTarget(dirfd int, name string) error {
	var stat unix.Stat_t
	err := unix.Fstatat(dirfd, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	return validateRegularStat(stat, false)
}

func createTemporaryAt(dirfd int, prefix string, mode uint32) (string, int, error) {
	for attempts := 0; attempts < 128; attempts++ {
		random := make([]byte, 12)
		if _, err := rand.Read(random); err != nil {
			return "", -1, err
		}
		name := prefix + hex.EncodeToString(random)
		zero(random)
		fd, err := unix.Openat(dirfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, mode)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		return name, fd, err
	}
	return "", -1, fmt.Errorf("agent: cannot allocate secure temporary file")
}

func removeTreeAt(parent int, name string) error {
	if !safeLeaf(name) {
		return fmt.Errorf("agent: unsafe removal target")
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(parent, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		if err := validateRegularStat(stat, false); err != nil {
			return err
		}
		fd, err := unix.Openat(parent, name, unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		var opened unix.Stat_t
		if err := unix.Fstat(fd, &opened); err != nil {
			_ = unix.Close(fd)
			return err
		}
		if err := validateRegularStat(opened, false); err != nil {
			_ = unix.Close(fd)
			return err
		}
		if !sameFileStat(stat, opened) {
			_ = unix.Close(fd)
			return fmt.Errorf("agent: removal target changed during validation")
		}
		if err := wipeRegularFD(fd, opened.Size); err != nil {
			_ = unix.Close(fd)
			return err
		}
		if err := unix.Close(fd); err != nil {
			return err
		}
		return unix.Unlinkat(parent, name, 0)
	case unix.S_IFDIR:
		if err := validateDirectoryStat(stat, false); err != nil {
			return err
		}
		dirfd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		var opened unix.Stat_t
		if err := unix.Fstat(dirfd, &opened); err != nil {
			_ = unix.Close(dirfd)
			return err
		}
		if err := validateDirectoryStat(opened, false); err != nil {
			_ = unix.Close(dirfd)
			return err
		}
		if !sameFileStat(stat, opened) {
			_ = unix.Close(dirfd)
			return fmt.Errorf("agent: removal target changed during validation")
		}
		duplicate, err := unix.Dup(dirfd)
		if err != nil {
			_ = unix.Close(dirfd)
			return err
		}
		file := os.NewFile(uintptr(duplicate), name)
		entries, err := file.Readdirnames(-1)
		_ = file.Close()
		if err != nil {
			_ = unix.Close(dirfd)
			return err
		}
		for _, entry := range entries {
			if err := removeTreeAt(dirfd, entry); err != nil {
				_ = unix.Close(dirfd)
				return err
			}
		}
		if err := unix.Fsync(dirfd); err != nil {
			_ = unix.Close(dirfd)
			return err
		}
		_ = unix.Close(dirfd)
		return unix.Unlinkat(parent, name, unix.AT_REMOVEDIR)
	default:
		return fmt.Errorf("agent: refuse non-regular removal target")
	}
}

func sameFileStat(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino
}

func wipeRegularFD(fd int, size int64) error {
	remaining := size
	zeros := make([]byte, 4096)
	var offset int64
	for remaining > 0 {
		chunk := int64(len(zeros))
		if remaining < chunk {
			chunk = remaining
		}
		if _, err := unix.Pwrite(fd, zeros[:int(chunk)], offset); err != nil {
			return err
		}
		offset += chunk
		remaining -= chunk
	}
	return unix.Fsync(fd)
}

func safeLeaf(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, `/\\`)
}
