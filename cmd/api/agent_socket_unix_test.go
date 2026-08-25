//go:build !windows

package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestStartAgentSocketPublishesConnectsAndCleansUp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api-agent.sock")
	t.Setenv("PGW_AGENT_SOCKET", path)
	// Match pgw-api.service's UMask=0027. bind(2)'s requested 0777 socket
	// mode is therefore actually 0750 until startAgentSocket publishes 0660.
	previousUmask := syscall.Umask(0o027)
	defer syscall.Umask(previousUmask)
	stop, err := startAgentSocket(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/agent/ping" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, "agent-ok")
	}))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != agentSocketMode {
		t.Fatalf("published mode = %v, want socket 0660", info.Mode())
	}
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}}
	defer client.CloseIdleConnections()
	response, err := client.Get("http://agent/internal/agent/ping")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "agent-ok" {
		t.Fatalf("UDS response = %d %q, err=%v", response.StatusCode, body, err)
	}
	if err := stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("published socket remained after shutdown: %v", err)
	}
}

func TestRecoverStaleAgentSocketUnlinksOnlyOwnedStaleSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api-agent.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, agentSocketMode); err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("closed listener did not leave a stale socket: %v", err)
	}
	if err := recoverStaleAgentSocket(path); err != nil {
		t.Fatalf("stale socket recovery failed: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("stale socket remains or wrong target removed: %v", err)
	}
}

func TestRecoverStaleAgentSocketAcceptsRestrictivePreChmodCrashSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api-agent.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate SIGKILL after bind but before startAgentSocket's chmod(0660).
	if err := os.Chmod(path, agentSocketPreChmodMode); err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := recoverStaleAgentSocket(path); err != nil {
		t.Fatalf("restrictive pre-chmod stale socket was not recoverable: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("pre-chmod stale socket remains: %v", err)
	}
}

func TestRecoverStaleAgentSocketAcceptsPublished0660Socket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api-agent.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, agentSocketMode); err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := recoverStaleAgentSocket(path); err != nil {
		t.Fatalf("published stale socket was not recoverable: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("published stale socket remains: %v", err)
	}
}

func TestRecoverStaleAgentSocketRefusesLiveRegularSymlinkAndWrongMode(t *testing.T) {
	t.Run("live", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "api-agent.sock")
		listener, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		if err := os.Chmod(path, agentSocketMode); err != nil {
			t.Fatal(err)
		}
		if err := recoverStaleAgentSocket(path); err == nil {
			t.Fatal("live socket was accepted for removal")
		}
		if _, err := os.Lstat(path); err != nil {
			t.Fatal("live socket was removed")
		}
	})
	for _, setup := range []struct {
		name string
		make func(t *testing.T, path string)
	}{
		{"regular", func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("not a socket"), agentSocketMode); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink", func(t *testing.T, path string) {
			if err := os.Symlink("target", path); err != nil {
				t.Fatal(err)
			}
		}},
		{"unexpected_0770", func(t *testing.T, path string) {
			listener, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			if err := os.Chmod(path, 0o770); err != nil {
				t.Fatal(err)
			}
		}},
		{"unexpected_0700", func(t *testing.T, path string) {
			listener, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			if err := os.Chmod(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(setup.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "api-agent.sock")
			setup.make(t, path)
			if err := recoverStaleAgentSocket(path); err == nil {
				t.Fatalf("%s path was accepted for removal", setup.name)
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("%s path was removed: %v", setup.name, err)
			}
		})
	}
}

func TestValidateBoundAgentSocketRequiresUMask0027Mode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api-agent.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(path, agentSocketPreChmodMode); err != nil {
		t.Fatal(err)
	}
	if _, err := validateBoundAgentSocket(path); err != nil {
		t.Fatalf("0750 pre-chmod mode rejected: %v", err)
	}
	if err := os.Chmod(path, agentSocketMode); err != nil {
		t.Fatal(err)
	}
	if _, err := validateBoundAgentSocket(path); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("0660 was incorrectly accepted as a pre-chmod mode: %v", err)
	}
}

func TestRecoverStaleAgentSocketRefusesForeignOwnedSocket(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires permission to create a foreign-owned socket")
	}
	path := filepath.Join(t.TempDir(), "api-agent.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(path, agentSocketMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 65534, -1); err != nil {
		t.Fatal(err)
	}
	if err := recoverStaleAgentSocket(path); err == nil {
		t.Fatal("foreign-owned socket was accepted for removal")
	}
}
