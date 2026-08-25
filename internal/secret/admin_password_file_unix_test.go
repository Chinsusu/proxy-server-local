//go:build !windows

package secret

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func rootOwnedPasswordTestDirectory(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root-owned admin password file tests require root")
	}
	directory, err := os.MkdirTemp(".", ".pgw-password-file-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	absolute, err := filepath.Abs(directory)
	if err != nil {
		t.Fatal(err)
	}
	return absolute
}

func writeRootOwnedPasswordTestFile(t *testing.T, directory, name string, value []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, value, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadRootOwnedAdminPasswordFileRejectsUnsafePaths(t *testing.T) {
	directory := rootOwnedPasswordTestDirectory(t)
	valid := writeRootOwnedPasswordTestFile(t, directory, "password", []byte("first-password"), 0o400)
	value, err := LoadRootOwnedAdminPasswordFile(valid, 4096)
	if err != nil || !bytes.Equal(value, []byte("first-password")) {
		t.Fatalf("value=%q err=%v", value, err)
	}
	wipe(value)

	link := filepath.Join(directory, "password-link")
	if err := os.Symlink(valid, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRootOwnedAdminPasswordFile(link, 4096); !errors.Is(err, ErrUnsafeAdminPasswordFile) {
		t.Fatalf("final symlink err=%v", err)
	}
	componentLink := filepath.Join(directory, "component-link")
	if err := os.Symlink(directory, componentLink); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRootOwnedAdminPasswordFile(filepath.Join(componentLink, "password"), 4096); !errors.Is(err, ErrUnsafeAdminPasswordFile) {
		t.Fatalf("component symlink err=%v", err)
	}
	if err := os.Chmod(valid, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRootOwnedAdminPasswordFile(valid, 4096); !errors.Is(err, ErrUnsafeAdminPasswordFile) {
		t.Fatalf("mode err=%v", err)
	}
	if err := os.Chmod(valid, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(valid, 1, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRootOwnedAdminPasswordFile(valid, 4096); !errors.Is(err, ErrUnsafeAdminPasswordFile) {
		t.Fatalf("owner err=%v", err)
	}
}

func TestRootOwnedAdminPasswordFileDescriptorSurvivesReplacement(t *testing.T) {
	directory := rootOwnedPasswordTestDirectory(t)
	path := writeRootOwnedPasswordTestFile(t, directory, "password", []byte("original-password"), 0o600)
	file, err := openRootOwnedAdminPasswordFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	replacement := filepath.Join(directory, "replacement")
	writeRootOwnedPasswordTestFile(t, directory, "replacement", []byte("replacement-password"), 0o600)
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	value, err := io.ReadAll(file)
	if err != nil || !bytes.Equal(value, []byte("original-password")) {
		t.Fatalf("descriptor bytes=%q err=%v", value, err)
	}
	wipe(value)
}

func TestRootOwnedAdminPasswordFileDescriptorSurvivesComponentSwap(t *testing.T) {
	directory := rootOwnedPasswordTestDirectory(t)
	container := filepath.Join(directory, "container")
	if err := os.Mkdir(container, 0o700); err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(container, "original")
	replacement := filepath.Join(container, "replacement")
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(replacement, 0o700); err != nil {
		t.Fatal(err)
	}
	writeRootOwnedPasswordTestFile(t, original, "password", []byte("original-component-password"), 0o400)
	writeRootOwnedPasswordTestFile(t, replacement, "password", []byte("replacement-component-password"), 0o400)
	target := filepath.Join(original, "password")
	swapped := false
	file, err := openRootOwnedAdminPasswordFileWithDirectoryOpen(target, func(component string) {
		if component != "original" || swapped {
			return
		}
		swapped = true
		if err := os.Rename(original, filepath.Join(container, "original-old")); err != nil {
			t.Fatalf("rename original: %v", err)
		}
		if err := os.Rename(replacement, original); err != nil {
			t.Fatalf("install replacement: %v", err)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if !swapped {
		t.Fatal("component-swap hook did not run")
	}
	value, err := io.ReadAll(file)
	if err != nil || !bytes.Equal(value, []byte("original-component-password")) {
		t.Fatalf("descriptor bytes=%q err=%v", value, err)
	}
	wipe(value)
}

func TestLoadRootOwnedAdminPasswordFileBoundsAndEmpty(t *testing.T) {
	directory := rootOwnedPasswordTestDirectory(t)
	empty := writeRootOwnedPasswordTestFile(t, directory, "empty", nil, 0o400)
	if _, err := LoadRootOwnedAdminPasswordFile(empty, 16); !errors.Is(err, ErrUnsafeAdminPasswordFile) {
		t.Fatalf("empty err=%v", err)
	}
	large := writeRootOwnedPasswordTestFile(t, directory, "large", bytes.Repeat([]byte{'a'}, 17), 0o400)
	if _, err := LoadRootOwnedAdminPasswordFile(large, 16); !errors.Is(err, ErrUnsafeAdminPasswordFile) {
		t.Fatalf("large err=%v", err)
	}
}
