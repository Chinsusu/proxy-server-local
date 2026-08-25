package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Chinsusu/proxy-server-local/internal/domain"
)

type crashPlane struct {
	current string
	trace   *[]string
}

type offlineControl struct{ calls int }

func (c *offlineControl) FetchLatest(context.Context) (domain.DesiredSnapshot, error) {
	c.calls++
	return domain.DesiredSnapshot{}, errors.New("API offline")
}
func (c *offlineControl) FetchSnapshot(context.Context, int64) (domain.DesiredSnapshot, error) {
	c.calls++
	return domain.DesiredSnapshot{}, errors.New("API offline")
}
func (c *offlineControl) FetchCredential(context.Context, string) (domain.AgentCredential, error) {
	c.calls++
	return domain.AgentCredential{}, errors.New("API offline")
}
func (c *offlineControl) Acknowledge(context.Context, domain.AgentAck) error {
	c.calls++
	return errors.New("API offline")
}

func (p *crashPlane) VerifyBase(context.Context) error {
	*p.trace = append(*p.trace, "nft:base")
	return nil
}

func (p *crashPlane) Check(_ context.Context, candidate string) error {
	*p.trace = append(*p.trace, "nft:check:"+rulesKind(candidate))
	return nil
}

func (p *crashPlane) Apply(_ context.Context, candidate, _ string) (string, bool, error) {
	*p.trace = append(*p.trace, "nft:apply:"+rulesKind(candidate))
	p.current = candidate
	return scriptHash(candidate), false, nil
}

func (p *crashPlane) Rollback(_ context.Context, rules string) (string, error) {
	*p.trace = append(*p.trace, "nft:rollback:"+rulesKind(rules))
	p.current = rules
	return scriptHash(rules), nil
}

func rulesKind(rules string) string {
	if strings.Contains(rules, " redirect to :") {
		return "mapped"
	}
	return "empty"
}

type crashFixture struct {
	oldMapping domain.AgentMapping
	newMapping domain.AgentMapping
	previous   LKG
	next       LKG
	store      FileLKGStore
	runtime    RuntimeConfig
}

func buildCrashFixture(root string) (crashFixture, error) {
	oldMapping := activeMapping("m1", "192.168.2.101/32", 15001)
	newMapping := oldMapping
	newMapping.ProxyHost = "rotated.proxy.example"
	newMapping.ProxyRevision++
	newMapping.CredentialRevision++
	oldSnapshot, err := domain.BuildDesiredSnapshot(1, []domain.AgentMapping{oldMapping})
	if err != nil {
		return crashFixture{}, err
	}
	newSnapshot, err := domain.BuildDesiredSnapshot(2, []domain.AgentMapping{newMapping})
	if err != nil {
		return crashFixture{}, err
	}
	oldRules, err := renderCandidate(testConfig(), []domain.AgentMapping{oldMapping})
	if err != nil {
		return crashFixture{}, err
	}
	newRules, err := renderCandidate(testConfig(), []domain.AgentMapping{newMapping})
	if err != nil {
		return crashFixture{}, err
	}
	previous := makeLKG(oldSnapshot, oldRules, scriptHash(oldRules), runtimeRecords([]domain.AgentMapping{oldMapping}), nil)
	next := makeLKG(newSnapshot, newRules, scriptHash(newRules), runtimeRecords([]domain.AgentMapping{newMapping}), nil)
	return crashFixture{
		oldMapping: oldMapping, newMapping: newMapping, previous: previous, next: next,
		store: FileLKGStore{Directory: filepath.Join(root, "var", "lib", "pgw", "rules")},
		runtime: RuntimeConfig{
			Root: filepath.Join(root, "run", "pgw", "forwarders"), RollbackRoot: filepath.Join(root, "run", "pgw", "agent-rollback"),
			ListenHost: "192.168.2.1", PortStart: 15001, PortEnd: 15999,
			ReadyTimeout: time.Second, PollInterval: time.Millisecond, skipOwnership: true,
		},
	}, nil
}

func TestRuntimeTransitionCrashRecoverySubprocess(t *testing.T) {
	if os.Getenv("PGW_CRASH_HELPER") == "1" {
		if err := writeCrashFixture(os.Getenv("PGW_CRASH_ROOT"), os.Getenv("PGW_CRASH_PHASE")); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(92)
		}
		os.Exit(91)
	}

	phases := []string{"after_journal", "after_redirect_removal", "after_restart", "after_nft_apply", "before_lkg_save", "after_lkg_save"}
	for _, phase := range phases {
		t.Run(phase, func(t *testing.T) {
			root := t.TempDir()
			command := exec.Command(os.Args[0], "-test.run=^TestRuntimeTransitionCrashRecoverySubprocess$")
			command.Env = append(os.Environ(), "PGW_CRASH_HELPER=1", "PGW_CRASH_ROOT="+root, "PGW_CRASH_PHASE="+phase)
			output, err := command.CombinedOutput()
			var exitError *exec.ExitError
			if !errors.As(err, &exitError) || exitError.ExitCode() != 91 {
				t.Fatalf("crash helper exit=%v output=%s", err, output)
			}

			fixture, err := buildCrashFixture(root)
			if err != nil {
				t.Fatal(err)
			}
			journalBytes, err := os.ReadFile(filepath.Join(fixture.store.Directory, transitionJournalFile))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(journalBytes, []byte("old-secret")) || bytes.Contains(journalBytes, []byte("new-secret")) {
				t.Fatal("durable transition journal contains credential material")
			}
			journal, err := fixture.store.LoadTransition()
			if err != nil {
				t.Fatal(err)
			}
			if journal.Phase == "" || len(journal.Entries) != 1 {
				t.Fatalf("journal phase=%q entries=%d", journal.Phase, len(journal.Entries))
			}

			trace := []string{}
			systemd := &fakeSystemd{readyAfter: 1, trace: &trace}
			manager, err := NewRuntimeManager(fixture.runtime, systemd)
			if err != nil {
				t.Fatal(err)
			}
			current := fixture.previous.Rules
			switch phase {
			case "after_redirect_removal", "after_restart":
				current, _ = renderCandidate(testConfig(), nil)
			case "after_nft_apply", "before_lkg_save", "after_lkg_save":
				current = fixture.next.Rules
			}
			plane := &crashPlane{current: current, trace: &trace}
			reconciler := &Reconciler{config: testConfig(), dataPlane: plane, forwarders: manager, lkg: fixture.store}
			if err := reconciler.recoverTransition(context.Background()); err != nil {
				t.Fatalf("recover phase %s: %v; trace=%v", phase, err, trace)
			}

			quiesceIndex := traceIndex(trace, "nft:apply:empty")
			restoreIndex := traceIndex(trace, "restart:pgw-fwd@15001.service")
			oldRulesIndex := traceIndex(trace, "nft:rollback:mapped")
			if quiesceIndex < 0 || restoreIndex < 0 || oldRulesIndex < 0 || !(quiesceIndex < restoreIndex && restoreIndex < oldRulesIndex) {
				t.Fatalf("unsafe recovery ordering: %v", trace)
			}
			if plane.current != fixture.previous.Rules {
				t.Fatal("recovery did not finish on the previous dynamic rules")
			}
			configBytes, err := os.ReadFile(filepath.Join(fixture.runtime.Root, "15001", "forwarder.json"))
			if err != nil || !bytes.Contains(configBytes, []byte(fixture.oldMapping.ProxyHost)) || bytes.Contains(configBytes, []byte(fixture.newMapping.ProxyHost)) {
				t.Fatalf("runtime was not restored to previous proxy: err=%v", err)
			}
			if _, err := fixture.store.LoadTransition(); !errors.Is(err, ErrTransitionNotFound) {
				t.Fatalf("transition journal remains after recovery: %v", err)
			}
			entries, err := os.ReadDir(fixture.runtime.RollbackRoot)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("orphan restore points remain: %d", len(entries))
			}
			restoredLKG, err := fixture.store.Load()
			if err != nil || restoredLKG.Metadata.Generation != fixture.previous.Metadata.Generation {
				t.Fatalf("durable previous LKG not restored: generation=%d err=%v", restoredLKG.Metadata.Generation, err)
			}
		})
	}
}

func writeCrashFixture(root, phase string) error {
	fixture, err := buildCrashFixture(root)
	if err != nil {
		return err
	}
	if err := fixture.store.Save(fixture.previous); err != nil {
		return err
	}
	systemd := &fakeSystemd{readyAfter: 1}
	manager, err := NewRuntimeManager(fixture.runtime, systemd)
	if err != nil {
		return err
	}
	oldCredential := credentialFor(fixture.oldMapping, true)
	oldCredential.Password = []byte("old-secret")
	if err := manager.Activate(context.Background(), fixture.oldMapping, oldCredential, false); err != nil {
		return err
	}
	oldRecord, newRecord := runtimeRecord(fixture.oldMapping), runtimeRecord(fixture.newMapping)
	point, err := manager.Capture(context.Background(), oldRecord, newRecord)
	if err != nil {
		return err
	}
	journal := newTransitionJournal(2, fixture.previous, []RuntimeTransitionEntry{{
		MappingID: fixture.newMapping.ID, Port: newRecord.Port, OldMappingID: oldRecord.MappingID,
		OldSpecHash: oldRecord.SpecHash, NewSpecHash: newRecord.SpecHash,
		RestorePath: point.directory, RestoreIntegrity: point.integrity,
	}})
	if err := fixture.store.SaveTransition(journal); err != nil {
		return err
	}
	if phase == "after_journal" {
		return nil
	}
	journal.Phase = TransitionRedirectsRemoved
	if err := fixture.store.SaveTransition(journal); err != nil {
		return err
	}
	if phase == "after_redirect_removal" {
		return nil
	}
	newCredential := credentialFor(fixture.newMapping, true)
	newCredential.Password = []byte("new-secret")
	if err := manager.Activate(context.Background(), fixture.newMapping, newCredential, true); err != nil {
		return err
	}
	journal.Phase = TransitionForwardersChanged
	if err := fixture.store.SaveTransition(journal); err != nil {
		return err
	}
	if phase == "after_restart" {
		return nil
	}
	journal.Phase = TransitionNFTApplied
	if err := fixture.store.SaveTransition(journal); err != nil {
		return err
	}
	if phase == "after_nft_apply" || phase == "before_lkg_save" {
		return nil
	}
	if phase != "after_lkg_save" {
		return fmt.Errorf("unknown crash phase %q", phase)
	}
	return fixture.store.Save(fixture.next)
}

func traceIndex(trace []string, want string) int {
	for index, value := range trace {
		if value == want {
			return index
		}
	}
	return -1
}

func TestRuntimeTransitionJournalRejectsTampering(t *testing.T) {
	root := t.TempDir()
	fixture, err := buildCrashFixture(root)
	if err != nil {
		t.Fatal(err)
	}
	pointPath := filepath.Join(fixture.runtime.RollbackRoot, ".restore-test")
	journal := newTransitionJournal(2, fixture.previous, []RuntimeTransitionEntry{{
		MappingID: fixture.newMapping.ID, Port: 15001, OldMappingID: fixture.oldMapping.ID,
		OldSpecHash: runtimeRecord(fixture.oldMapping).SpecHash, NewSpecHash: runtimeRecord(fixture.newMapping).SpecHash,
		RestorePath: pointPath, RestoreIntegrity: strings.Repeat("a", 64),
	}})
	if err := fixture.store.SaveTransition(journal); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(fixture.store.Directory, transitionJournalFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte(`"phase": "PREPARED"`), []byte(`"phase": "NFT_APPLIED"`), 1)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.LoadTransition(); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("tampered transition journal error = %v", err)
	}
}

func TestNewRuntimeCrashRecoverySubprocess(t *testing.T) {
	if os.Getenv("PGW_NEW_CRASH_HELPER") == "1" {
		if err := writeNewRuntimeCrashFixture(os.Getenv("PGW_CRASH_ROOT"), os.Getenv("PGW_CRASH_PHASE")); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(92)
		}
		os.Exit(91)
	}

	cases := []struct {
		phase string
		state domain.DesiredState
	}{
		{phase: "after_start_ready", state: domain.DesiredSuspended},
		{phase: "before_nft_lkg", state: domain.DesiredDeleted},
	}
	for _, testCase := range cases {
		t.Run(testCase.phase+"_then_"+string(testCase.state), func(t *testing.T) {
			root := t.TempDir()
			command := exec.Command(os.Args[0], "-test.run=^TestNewRuntimeCrashRecoverySubprocess$")
			command.Env = append(os.Environ(), "PGW_NEW_CRASH_HELPER=1", "PGW_CRASH_ROOT="+root, "PGW_CRASH_PHASE="+testCase.phase)
			output, err := command.CombinedOutput()
			var exitError *exec.ExitError
			if !errors.As(err, &exitError) || exitError.ExitCode() != 91 {
				t.Fatalf("crash helper exit=%v output=%s", err, output)
			}

			fixture, added, err := buildNewRuntimeCrashFixture(root)
			if err != nil {
				t.Fatal(err)
			}
			journalBytes, err := os.ReadFile(filepath.Join(fixture.store.Directory, transitionJournalFile))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(journalBytes, []byte("new-port-secret")) {
				t.Fatal("new-runtime transition journal contains credential material")
			}
			journal, err := fixture.store.LoadTransition()
			if err != nil || len(journal.Entries) != 1 || journal.Entries[0].RestorePath != "" {
				t.Fatalf("new-runtime journal invalid: entries=%d err=%v", len(journal.Entries), err)
			}

			trace := []string{}
			systemd := &fakeSystemd{readyAfter: 1, trace: &trace}
			manager, err := NewRuntimeManager(fixture.runtime, systemd)
			if err != nil {
				t.Fatal(err)
			}
			plane := &crashPlane{current: fixture.previous.Rules, trace: &trace}
			offline := &offlineControl{}
			reconciler, err := NewReconciler(testConfig(), offline, plane, manager, fixture.store)
			if err != nil {
				t.Fatal(err)
			}
			if err := reconciler.StartupRecover(context.Background()); err != nil {
				t.Fatalf("local startup recovery: %v; trace=%v", err, trace)
			}
			if offline.calls != 0 {
				t.Fatalf("startup recovery contacted offline API %d times", offline.calls)
			}
			quiesceIndex := traceIndex(trace, "nft:apply:empty")
			stopIndex := traceIndex(trace, "stop:pgw-fwd@15002.service")
			oldRulesIndex := traceIndex(trace, "nft:rollback:mapped")
			if quiesceIndex < 0 || stopIndex < 0 || oldRulesIndex < 0 || !(quiesceIndex < stopIndex && stopIndex < oldRulesIndex) {
				t.Fatalf("unsafe new-runtime recovery ordering: %v", trace)
			}
			if _, err := os.Stat(filepath.Join(fixture.runtime.Root, "15002")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("new runtime or credentials remain after startup recovery: %v", err)
			}
			if _, err := fixture.store.LoadTransition(); !errors.Is(err, ErrTransitionNotFound) {
				t.Fatalf("new-runtime journal remains: %v", err)
			}

			later := added
			later.DesiredState = testCase.state
			snapshot, err := domain.BuildDesiredSnapshot(3, []domain.AgentMapping{fixture.oldMapping, later})
			if err != nil {
				t.Fatal(err)
			}
			events := []string{}
			control := &fakeControl{snapshot: snapshot, credentials: map[string]domain.AgentCredential{}, events: &events}
			normal, err := NewReconciler(testConfig(), control, plane, manager, fixture.store)
			if err != nil {
				t.Fatal(err)
			}
			if err := normal.Reconcile(context.Background(), 3); err != nil {
				t.Fatalf("reconcile later %s state: %v", testCase.state, err)
			}
			if _, err := os.Stat(filepath.Join(fixture.runtime.Root, "15002")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("suspended/deleted runtime was rebuilt: %v", err)
			}
			if len(control.acks) != 1 || control.acks[0].Status != domain.DataPlaneVerified {
				t.Fatalf("later reconciliation ACKs = %+v", control.acks)
			}
		})
	}
}

func buildNewRuntimeCrashFixture(root string) (crashFixture, domain.AgentMapping, error) {
	fixture, err := buildCrashFixture(root)
	if err != nil {
		return crashFixture{}, domain.AgentMapping{}, err
	}
	added := activeMapping("m2", "192.168.2.102/32", 15002)
	added.ProxyID = "p2"
	added.ProxyHost = "new-port.proxy.example"
	return fixture, added, nil
}

func writeNewRuntimeCrashFixture(root, phase string) error {
	fixture, added, err := buildNewRuntimeCrashFixture(root)
	if err != nil {
		return err
	}
	if err := fixture.store.Save(fixture.previous); err != nil {
		return err
	}
	systemd := &fakeSystemd{readyAfter: 1}
	manager, err := NewRuntimeManager(fixture.runtime, systemd)
	if err != nil {
		return err
	}
	if err := manager.Activate(context.Background(), fixture.oldMapping, credentialFor(fixture.oldMapping, false), false); err != nil {
		return err
	}
	newRecord := runtimeRecord(added)
	journal := newTransitionJournal(2, fixture.previous, []RuntimeTransitionEntry{{
		MappingID: added.ID, Port: added.LocalRedirectPort, NewSpecHash: newRecord.SpecHash,
	}})
	if err := fixture.store.SaveTransition(journal); err != nil {
		return err
	}
	credential := credentialFor(added, true)
	credential.Password = []byte("new-port-secret")
	if err := manager.Activate(context.Background(), added, credential, false); err != nil {
		return err
	}
	if phase == "after_start_ready" {
		return nil
	}
	if phase != "before_nft_lkg" {
		return fmt.Errorf("unknown new-runtime crash phase %q", phase)
	}
	journal.Phase = TransitionForwardersChanged
	return fixture.store.SaveTransition(journal)
}
