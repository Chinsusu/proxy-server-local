//go:build linux

package e2e

import (
	"bytes"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

const (
	labTimeout         = 60 * time.Second
	cleanupGracePeriod = 10 * time.Second
)

func TestLegacyWebOnlyNamespace(t *testing.T) {
	if os.Getenv("PGW_RUN_NETNS_E2E") != "1" {
		t.Skip("set PGW_RUN_NETNS_E2E=1 on an isolated Linux runner")
	}
	if os.Geteuid() != 0 {
		t.Fatal("PGW_RUN_NETNS_E2E=1 requires root for network namespaces")
	}

	command := exec.Command("bash", "./netns_legacy_web_only.sh")
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatalf("start namespace lab: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- command.Wait()
	}()

	timeout := time.NewTimer(labTimeout)
	defer timeout.Stop()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("namespace lab failed: %v\n%s", err, output.Bytes())
		}
		t.Logf("namespace evidence:\n%s", output.Bytes())
	case <-timeout.C:
		terminateErr := syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
		grace := time.NewTimer(cleanupGracePeriod)
		defer grace.Stop()
		select {
		case err := <-done:
			t.Fatalf(
				"namespace lab timed out after %s; process group terminated during %s cleanup grace (SIGTERM error: %v, wait: %v)\n%s",
				labTimeout, cleanupGracePeriod, terminateErr, err, output.Bytes(),
			)
		case <-grace.C:
			killErr := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			err := <-done
			t.Fatalf(
				"namespace lab timed out after %s and exceeded %s cleanup grace; process group force-killed (SIGTERM error: %v, SIGKILL error: %v, wait: %v)\n%s",
				labTimeout, cleanupGracePeriod, terminateErr, killErr, err, output.Bytes(),
			)
		}
	}
}
