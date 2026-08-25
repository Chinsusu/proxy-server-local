package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeSystemd struct {
	mu         sync.Mutex
	events     []string
	stateCalls int
	readyAfter int
	startErr   error
	trace      *[]string
}

func (f *fakeSystemd) record(event string) {
	f.events = append(f.events, event)
	if f.trace != nil {
		*f.trace = append(*f.trace, event)
	}
}

func (f *fakeSystemd) Start(_ context.Context, unit string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("start:" + unit)
	return f.startErr
}
func (f *fakeSystemd) Restart(_ context.Context, unit string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("restart:" + unit)
	return f.startErr
}
func (f *fakeSystemd) Stop(_ context.Context, unit string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("stop:" + unit)
	return nil
}
func (f *fakeSystemd) State(_ context.Context, unit string) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("state:" + unit)
	f.stateCalls++
	if f.stateCalls >= f.readyAfter {
		return "active", "running", nil
	}
	return "activating", "start", nil
}

func TestRuntimeManagerPublishesContractThenUsesSystemdReadiness(t *testing.T) {
	root := filepath.Join(t.TempDir(), "forwarders")
	systemd := &fakeSystemd{readyAfter: 2}
	manager, err := NewRuntimeManager(RuntimeConfig{Root: root, ListenHost: "192.168.2.1", PortStart: 15001, PortEnd: 15999, ReadyTimeout: time.Second, PollInterval: time.Millisecond, skipOwnership: true}, systemd)
	if err != nil {
		t.Fatal(err)
	}
	mapping := activeMapping("m1", "192.168.2.101/32", 15001)
	credential := credentialFor(mapping, true)
	credential.Password = []byte("canary-secret")
	if err := manager.Activate(context.Background(), mapping, credential, false); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	directory := filepath.Join(root, "15001")
	configBytes, err := os.ReadFile(filepath.Join(directory, "forwarder.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(configBytes), "alice") || strings.Contains(string(configBytes), "canary-secret") {
		t.Fatal("forwarder config leaked a credential")
	}
	var config forwarderConfig
	if err := json.Unmarshal(configBytes, &config); err != nil {
		t.Fatal(err)
	}
	if config.Version != 1 || config.MappingID != "m1" || config.ListenAddress != "192.168.2.1:15001" || config.ProxyType != "http" {
		t.Fatalf("config = %+v", config)
	}
	password, err := os.ReadFile(filepath.Join(directory, "credentials", "proxy_password"))
	if err != nil || string(password) != "canary-secret" {
		t.Fatalf("password material mismatch without printing secret: len=%d err=%v", len(password), err)
	}
	if len(systemd.events) < 3 || systemd.events[0] != "start:pgw-fwd@15001.service" || !strings.HasPrefix(systemd.events[1], "state:") {
		t.Fatalf("systemd events = %v", systemd.events)
	}
	if err := manager.Stop(context.Background(), 15001); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime directory remains after stop: %v", err)
	}
}

func TestRuntimeManagerFailureScrubsRuntimeDirectory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "forwarders")
	systemd := &fakeSystemd{readyAfter: 1, startErr: errors.New("start rejected")}
	manager, err := NewRuntimeManager(RuntimeConfig{Root: root, ListenHost: "192.168.2.1", PortStart: 15001, PortEnd: 15999, skipOwnership: true}, systemd)
	if err != nil {
		t.Fatal(err)
	}
	mapping := activeMapping("m1", "192.168.2.101/32", 15001)
	credential := credentialFor(mapping, true)
	if err := manager.Activate(context.Background(), mapping, credential, false); err == nil {
		t.Fatal("Activate unexpectedly succeeded")
	}
	if _, err := os.Stat(filepath.Join(root, "15001")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("credential runtime remains after failure: %v", err)
	}
}

func TestRuntimeManagerRejectsUnsafeMappingIDAndPort(t *testing.T) {
	manager, err := NewRuntimeManager(RuntimeConfig{Root: filepath.Join(t.TempDir(), "forwarders"), ListenHost: "192.168.2.1", PortStart: 15001, PortEnd: 15999, skipOwnership: true}, &fakeSystemd{readyAfter: 1})
	if err != nil {
		t.Fatal(err)
	}
	mapping := activeMapping("bad.id", "192.168.2.101/32", 15001)
	credential := credentialFor(mapping, false)
	if err := manager.Activate(context.Background(), mapping, credential, false); err == nil {
		t.Fatal("unsafe mapping ID accepted")
	}
	mapping = activeMapping("m1", "192.168.2.101/32", 14000)
	credential.MappingID = "m1"
	if err := manager.Activate(context.Background(), mapping, credential, false); err == nil {
		t.Fatal("out-of-range port accepted")
	}
}

func TestRuntimeManagerNoAuthPublishesOnlyZeroByteSystemdPlaceholders(t *testing.T) {
	root := filepath.Join(t.TempDir(), "forwarders")
	manager, err := NewRuntimeManager(RuntimeConfig{Root: root, ListenHost: "192.168.2.1", PortStart: 15001, PortEnd: 15999, ReadyTimeout: time.Second, PollInterval: time.Millisecond, skipOwnership: true}, &fakeSystemd{readyAfter: 1})
	if err != nil {
		t.Fatal(err)
	}
	mapping := activeMapping("m1", "192.168.2.101/32", 15001)
	if err := manager.Activate(context.Background(), mapping, credentialFor(mapping, false), false); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"proxy_username", "proxy_password"} {
		info, err := os.Stat(filepath.Join(root, "15001", "credentials", name))
		if err != nil {
			t.Fatalf("stat no-auth placeholder %s: %v", name, err)
		}
		if info.Size() != 0 {
			t.Fatalf("no-auth placeholder %s size=%d, want zero", name, info.Size())
		}
	}
}

func TestRuntimeManagerCaptureReplaceAndRestoreSamePort(t *testing.T) {
	root := filepath.Join(t.TempDir(), "forwarders")
	systemd := &fakeSystemd{readyAfter: 1}
	manager, err := NewRuntimeManager(RuntimeConfig{
		Root: root, ListenHost: "192.168.2.1", PortStart: 15001, PortEnd: 15999,
		ReadyTimeout: time.Second, PollInterval: time.Millisecond, skipOwnership: true,
	}, systemd)
	if err != nil {
		t.Fatal(err)
	}
	oldMapping := activeMapping("m1", "192.168.2.101/32", 15001)
	oldCredential := credentialFor(oldMapping, true)
	oldCredential.Password = []byte("old-secret")
	if err := manager.Activate(context.Background(), oldMapping, oldCredential, false); err != nil {
		t.Fatal(err)
	}
	newMapping := oldMapping
	newMapping.ProxyHost = "new.proxy.example"
	newMapping.ProxyRevision++
	newMapping.CredentialRevision++
	oldRecord, newRecord := runtimeRecord(oldMapping), runtimeRecord(newMapping)
	point, err := manager.Capture(context.Background(), oldRecord, newRecord)
	if err != nil {
		t.Fatal(err)
	}
	newCredential := credentialFor(newMapping, true)
	newCredential.Password = []byte("new-secret")
	if err := manager.Activate(context.Background(), newMapping, newCredential, true); err != nil {
		t.Fatal(err)
	}
	if err := manager.Restore(context.Background(), point); err != nil {
		t.Fatal(err)
	}

	configBytes, err := os.ReadFile(filepath.Join(root, "15001", "forwarder.json"))
	if err != nil {
		t.Fatal(err)
	}
	var restored forwarderConfig
	if err := json.Unmarshal(configBytes, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.ProxyHost != oldMapping.ProxyHost || restored.MappingID != oldMapping.ID {
		t.Fatalf("restored runtime identity = mapping %q proxy %q", restored.MappingID, restored.ProxyHost)
	}
	password, err := os.ReadFile(filepath.Join(root, "15001", "credentials", "proxy_password"))
	if err != nil {
		t.Fatal(err)
	}
	if string(password) != "old-secret" {
		t.Fatalf("restored credential length=%d, want previous material", len(password))
	}
	if _, err := os.Stat(point.directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("restore staging directory remains: %v", err)
	}
	if strings.Count(strings.Join(systemd.events, "\n"), "restart:pgw-fwd@15001.service") != 2 {
		t.Fatalf("systemd events = %v, want replacement and restoration restart", systemd.events)
	}
}

func TestRuntimeManagerRejectsTamperedRestorePointBeforeRestart(t *testing.T) {
	root := filepath.Join(t.TempDir(), "forwarders")
	systemd := &fakeSystemd{readyAfter: 1}
	manager, err := NewRuntimeManager(RuntimeConfig{
		Root: root, ListenHost: "192.168.2.1", PortStart: 15001, PortEnd: 15999,
		ReadyTimeout: time.Second, PollInterval: time.Millisecond, skipOwnership: true,
	}, systemd)
	if err != nil {
		t.Fatal(err)
	}
	oldMapping := activeMapping("m1", "192.168.2.101/32", 15001)
	oldCredential := credentialFor(oldMapping, true)
	if err := manager.Activate(context.Background(), oldMapping, oldCredential, false); err != nil {
		t.Fatal(err)
	}
	newMapping := oldMapping
	newMapping.ProxyRevision++
	point, err := manager.Capture(context.Background(), runtimeRecord(oldMapping), runtimeRecord(newMapping))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(point.directory, "proxy_password"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	restartsBefore := strings.Count(strings.Join(systemd.events, "\n"), "restart:pgw-fwd@15001.service")
	if err := manager.Restore(context.Background(), point); err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("tampered restore error = %v", err)
	}
	restartsAfter := strings.Count(strings.Join(systemd.events, "\n"), "restart:pgw-fwd@15001.service")
	if restartsAfter != restartsBefore {
		t.Fatal("tampered restore material reached systemd restart")
	}
	if err := manager.Discard(point); err != nil {
		t.Fatal(err)
	}
}
