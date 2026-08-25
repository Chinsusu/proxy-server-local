//go:build linux

package snapshotcrypto

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxKeyFilePolicy(t *testing.T) {
	directory := trustedRootTemp(t)
	keyPath := filepath.Join(directory, "snapshot.key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{7}, KeySize), 0o600); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		key, err := LoadKeyFile(keyPath)
		if err != nil || key[0] != 7 {
			t.Fatalf("root-owned mode-0600 key rejected: %v", err)
		}
		key.Destroy()
	} else if _, err := LoadKeyFile(keyPath); err == nil {
		t.Fatal("non-root-owned key was accepted")
	}
	if err := os.Chmod(keyPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyFile(keyPath); err == nil {
		t.Fatal("mode-0640 key was accepted")
	}
}

func TestLinuxKeyFileRejectsSymlink(t *testing.T) {
	directory := trustedRootTemp(t)
	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "link")
	if err := os.WriteFile(target, bytes.Repeat([]byte{7}, KeySize), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := LoadKeyFile(link); err == nil {
		t.Fatal("symlink key was accepted")
	}
}
