//go:build !windows

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const (
	agentSocketMode = 0o660
	// systemd runs pgw-api with UMask=0027. Unix bind(2) requests 0777,
	// so the only recoverable pre-chmod mode is exactly 0750. This is not a
	// generic "restrictive" range: accepting another mode would turn stale
	// recovery into authorization policy.
	agentSocketPreChmodMode = 0o750
)

// recoverStaleAgentSocket removes only the exact socket this process is
// expected to own. A protected parent plus inode revalidation keeps an
// untrusted path replacement from turning stale-socket recovery into a
// general unlink primitive.
func recoverStaleAgentSocket(path string) error {
	if err := validateAgentSocketParent(filepath.Dir(path)); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect socket: %w", err)
	}
	if err := validateRecoverableAgentSocket(path, info); err != nil {
		return err
	}
	connection, dialErr := net.DialTimeout("unix", path, 250*time.Millisecond)
	if dialErr == nil {
		_ = connection.Close()
		return fmt.Errorf("refusing to replace a live agent socket")
	}
	if !staleAgentSocketError(dialErr) {
		return fmt.Errorf("refusing to replace an unproven socket: %w", dialErr)
	}
	current, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reinspect socket: %w", err)
	}
	if !os.SameFile(info, current) || validateRecoverableAgentSocket(path, current) != nil {
		return fmt.Errorf("agent socket changed during stale recovery")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale agent socket: %w", err)
	}
	return nil
}

func validateAgentSocketIdentity(path string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing unexpected agent socket type or mode at %q", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("refusing agent socket not owned by the service account")
	}
	return nil
}

func validateAgentSocketMode(path string, info os.FileInfo, allowed ...os.FileMode) error {
	if err := validateAgentSocketIdentity(path, info); err != nil {
		return err
	}
	for _, mode := range allowed {
		if info.Mode().Perm() == mode {
			return nil
		}
	}
	return fmt.Errorf("refusing unexpected agent socket mode at %q", path)
}

// validateRecoverableAgentSocket accepts exactly two lifecycle states: a
// published stale 0660 socket or the 0750 socket left by SIGKILL between bind
// and chmod under systemd UMask=0027. It deliberately does not accept a broad
// class of owner-only modes.
func validateRecoverableAgentSocket(path string, info os.FileInfo) error {
	return validateAgentSocketMode(path, info, agentSocketMode, agentSocketPreChmodMode)
}

func validateBoundAgentSocket(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil || validateAgentSocketMode(path, info, agentSocketPreChmodMode) != nil {
		return nil, fmt.Errorf("bound agent socket changed or is unsafe")
	}
	return info, nil
}

func validatePublishedAgentSocket(path string, bound os.FileInfo) error {
	published, err := os.Lstat(path)
	if err != nil || !os.SameFile(bound, published) || validateAgentSocketMode(path, published, agentSocketMode) != nil {
		return fmt.Errorf("published agent socket changed or is unsafe")
	}
	return nil
}

func validateAgentSocketParent(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect agent socket directory: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("refusing unsafe agent socket directory")
	}
	return nil
}

func staleAgentSocketError(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENOTCONN) || errors.Is(err, syscall.ENOENT)
}
