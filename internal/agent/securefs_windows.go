//go:build windows

package agent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func secureEnsureDirectory(path string, mode os.FileMode) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("agent: trusted directory must be absolute and clean")
	}
	if err := validateWindowsAncestors(path, true); err != nil {
		return err
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func secureValidateDirectory(path string) error { return validateWindowsAncestors(path, false) }

func secureReadRegular(path string, limit int64) ([]byte, error) {
	if err := validateWindowsAncestors(filepath.Dir(path), false); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > limit {
		return nil, fmt.Errorf("agent: unsafe or oversized file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, limit+1))
}

func secureWriteFileAtomic(directory, name string, content []byte, mode os.FileMode) error {
	if !safeLeaf(name) {
		return fmt.Errorf("agent: unsafe file name")
	}
	if err := secureValidateDirectory(directory); err != nil {
		return err
	}
	target := filepath.Join(directory, name)
	if info, err := os.Lstat(target); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return fmt.Errorf("agent: unsafe target")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".pgw-tmp-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, target)
}

func secureRemoveFile(directory, name string) error {
	path := filepath.Join(directory, name)
	if err := secureValidateExisting(path); err != nil {
		return err
	}
	return os.Remove(path)
}

func secureMkdirTemp(directory, prefix string, mode os.FileMode) (string, error) {
	if err := secureValidateDirectory(directory); err != nil {
		return "", err
	}
	path, err := os.MkdirTemp(directory, prefix)
	if err != nil {
		return "", err
	}
	return path, os.Chmod(path, mode)
}

func secureRemoveTree(path string) error {
	if err := secureValidateExisting(path); err != nil {
		return err
	}
	return os.RemoveAll(path)
}

func secureRemoveChildren(directory, prefix string) error {
	if err := secureValidateDirectory(directory); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) {
			if err := secureRemoveTree(filepath.Join(directory, entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

func secureWipeFile(path string) error {
	if err := secureValidateExisting(path); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() > 0 {
		if _, err := file.WriteAt(make([]byte, int(info.Size())), 0); err != nil {
			return err
		}
	}
	return file.Sync()
}

func secureSetOwnerMode(path string, _, _ int, mode os.FileMode, _ bool) error {
	if err := secureValidateExisting(path); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func secureValidateExisting(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("agent: privileged path must be absolute and clean")
	}
	if err := validateWindowsAncestors(filepath.Dir(path), false); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("agent: refusing symlink")
	}
	return nil
}

func validateWindowsAncestors(path string, allowMissing bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("agent: privileged path must be absolute and clean")
	}
	current := filepath.VolumeName(path) + string(filepath.Separator)
	relative := strings.TrimPrefix(path, current)
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) && allowMissing {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("agent: unsafe path component")
		}
	}
	return nil
}

func safeLeaf(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, `/\\`)
}
