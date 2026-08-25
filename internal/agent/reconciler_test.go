package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Chinsusu/proxy-server-local/internal/domain"
)

type fakeControl struct {
	snapshot    domain.DesiredSnapshot
	credentials map[string]domain.AgentCredential
	acks        []domain.AgentAck
	events      *[]string
}

func (f *fakeControl) FetchSnapshot(_ context.Context, generation int64) (domain.DesiredSnapshot, error) {
	*f.events = append(*f.events, fmt.Sprintf("snapshot:%d", generation))
	return f.snapshot, nil
}
func (f *fakeControl) FetchLatest(_ context.Context) (domain.DesiredSnapshot, error) {
	*f.events = append(*f.events, "snapshot:latest")
	return f.snapshot, nil
}
func (f *fakeControl) FetchCredential(_ context.Context, id string) (domain.AgentCredential, error) {
	*f.events = append(*f.events, "credential:"+id)
	credential, ok := f.credentials[id]
	if !ok {
		return domain.AgentCredential{}, errors.New("missing credential")
	}
	credential.Password = append([]byte(nil), credential.Password...)
	return credential, nil
}
func (f *fakeControl) Acknowledge(_ context.Context, ack domain.AgentAck) error {
	*f.events = append(*f.events, "ack:"+string(ack.Status)+":"+ack.ReasonCode)
	f.acks = append(f.acks, ack)
	return nil
}

type fakePlane struct {
	events      *[]string
	applyErr    error
	applyErrAt  int
	applyCalls  int
	rolledBack  bool
	rollbackErr error
	appliedHash string
}

func (f *fakePlane) VerifyBase(context.Context) error {
	*f.events = append(*f.events, "base")
	return nil
}
func (f *fakePlane) Check(context.Context, string) error {
	*f.events = append(*f.events, "nft-check")
	return nil
}
func (f *fakePlane) Apply(_ context.Context, candidate, rollback string) (string, bool, error) {
	*f.events = append(*f.events, "nft-apply")
	f.applyCalls++
	if strings.Contains(candidate, "pgw_base") || strings.Contains(rollback, "pgw_base") {
		return "", false, errors.New("base ownership violation")
	}
	if f.applyErrAt == 0 || f.applyCalls == f.applyErrAt {
		return f.appliedHash, f.rolledBack, f.applyErr
	}
	return f.appliedHash, false, nil
}
func (f *fakePlane) Rollback(context.Context, string) (string, error) {
	*f.events = append(*f.events, "nft-rollback")
	return strings.Repeat("0", 64), f.rollbackErr
}

type fakeForwarders struct {
	events       *[]string
	ready        map[int]bool
	stopError    map[int]error
	seenPassword []byte
	restoreError error
}

func (f *fakeForwarders) Ready(_ context.Context, port int) (bool, error) {
	*f.events = append(*f.events, fmt.Sprintf("ready:%d", port))
	return f.ready[port], nil
}
func (f *fakeForwarders) Matches(_ context.Context, record RuntimeRecord) (bool, error) {
	return f.ready[record.Port], nil
}
func (f *fakeForwarders) Capture(_ context.Context, old, next RuntimeRecord) (*RestorePoint, error) {
	*f.events = append(*f.events, fmt.Sprintf("capture:%d", old.Port))
	return &RestorePoint{port: old.Port, directory: "fake", old: old, next: next}, nil
}
func (f *fakeForwarders) Activate(_ context.Context, mapping domain.AgentMapping, credential domain.AgentCredential, replace bool) error {
	*f.events = append(*f.events, fmt.Sprintf("activate:%s:%t", mapping.ID, replace))
	if string(credential.Password) != "secret" {
		return errors.New("credential mismatch")
	}
	f.seenPassword = credential.Password
	f.ready[mapping.LocalRedirectPort] = true
	return nil
}
func (f *fakeForwarders) Restore(_ context.Context, point *RestorePoint) error {
	*f.events = append(*f.events, fmt.Sprintf("restore:%d", point.port))
	return f.restoreError
}
func (f *fakeForwarders) Discard(point *RestorePoint) error {
	*f.events = append(*f.events, fmt.Sprintf("discard:%d", point.port))
	return nil
}
func (f *fakeForwarders) CleanupOrphans(context.Context) error { return nil }
func (f *fakeForwarders) Stop(_ context.Context, port int) error {
	*f.events = append(*f.events, fmt.Sprintf("stop:%d", port))
	return f.stopError[port]
}

type memoryLKG struct {
	value           LKG
	err             error
	saveErr         error
	saveErrAt       int
	saveCalls       int
	journal         *RuntimeTransitionJournal
	journalLoadErr  error
	journalSaveErr  error
	journalClearErr error
	events          *[]string
	mu              sync.Mutex
}

func (m *memoryLKG) LoadTransition() (RuntimeTransitionJournal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.journalLoadErr != nil {
		return RuntimeTransitionJournal{}, m.journalLoadErr
	}
	if m.journal == nil {
		return RuntimeTransitionJournal{}, ErrTransitionNotFound
	}
	return *m.journal, nil
}
func (m *memoryLKG) SaveTransition(value RuntimeTransitionJournal) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.events != nil {
		*m.events = append(*m.events, "journal-save:"+string(value.Phase))
	}
	if m.journalSaveErr != nil {
		return m.journalSaveErr
	}
	copyValue := value
	m.journal = &copyValue
	return nil
}
func (m *memoryLKG) ClearTransition() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.events != nil {
		*m.events = append(*m.events, "journal-clear")
	}
	if m.journalClearErr != nil {
		return m.journalClearErr
	}
	m.journal = nil
	return nil
}

func (m *memoryLKG) Load() (LKG, error) { m.mu.Lock(); defer m.mu.Unlock(); return m.value, m.err }
func (m *memoryLKG) Save(value LKG) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	*m.events = append(*m.events, "lkg-save")
	m.saveCalls++
	if m.saveErr != nil && (m.saveErrAt == 0 || m.saveCalls == m.saveErrAt) {
		return m.saveErr
	}
	m.value = value
	m.err = nil
	return nil
}

func TestReconcileActivationOrderingAndVerifiedACK(t *testing.T) {
	events := []string{}
	snapshot := mustSnapshot(t, 7, activeMapping("m1", "192.168.2.101/32", 15001))
	control := &fakeControl{snapshot: snapshot, credentials: credentialMap(), events: &events}
	plane := &fakePlane{events: &events, appliedHash: strings.Repeat("a", 64)}
	forwarders := &fakeForwarders{events: &events, ready: map[int]bool{}, stopError: map[int]error{}}
	store := &memoryLKG{value: emptyLKG(t), events: &events}
	reconciler := newTestReconciler(t, control, plane, forwarders, store)
	if err := reconciler.Reconcile(context.Background(), 7); err != nil {
		t.Fatalf("Reconcile: %v; events=%v", err, events)
	}
	wantOrder := []string{"snapshot:7", "base", "nft-check", "credential:m1", "activate:m1:false", "nft-apply", "lkg-save", "ack:VERIFIED:"}
	assertSubsequence(t, events, wantOrder)
	if len(control.acks) != 1 || control.acks[0].Generation != 7 || control.acks[0].AppliedHash != strings.Repeat("a", 64) {
		t.Fatalf("ACKs = %+v", control.acks)
	}
	if len(store.value.Metadata.Runtimes) != 1 || store.value.Metadata.Runtimes[0].MappingID != "m1" {
		t.Fatalf("LKG runtimes = %+v", store.value.Metadata.Runtimes)
	}
	for _, value := range forwarders.seenPassword {
		if value != 0 {
			t.Fatal("Agent did not zero credential buffer after materialization")
		}
	}
}

func TestReconcileNewRuntimeJournalIsDurableBeforeStart(t *testing.T) {
	events := []string{}
	snapshot := mustSnapshot(t, 14, activeMapping("m1", "192.168.2.101/32", 15001))
	control := &fakeControl{snapshot: snapshot, credentials: credentialMap(), events: &events}
	plane := &fakePlane{events: &events, appliedHash: strings.Repeat("d", 64)}
	forwarders := &fakeForwarders{events: &events, ready: map[int]bool{}, stopError: map[int]error{}}
	store := &memoryLKG{value: emptyLKG(t), events: &events}
	if err := newTestReconciler(t, control, plane, forwarders, store).Reconcile(context.Background(), 14); err != nil {
		t.Fatalf("Reconcile: %v; events=%v", err, events)
	}
	assertSubsequence(t, events, []string{
		"journal-save:PREPARED", "credential:m1", "activate:m1:false",
		"journal-save:FORWARDERS_CHANGED", "nft-apply", "lkg-save",
		"journal-save:LKG_STORED", "journal-clear", "ack:VERIFIED:",
	})
}

func TestReconcileSuspendRemovesRedirectBeforeDraining(t *testing.T) {
	events := []string{}
	mapping := activeMapping("m1", "192.168.2.101/32", 15001)
	prior := emptyLKG(t)
	prior.Metadata.Runtimes = []RuntimeRecord{runtimeRecord(mapping)}
	suspended := mapping
	suspended.DesiredState = domain.DesiredSuspended
	snapshot := mustSnapshot(t, 8, suspended)
	control := &fakeControl{snapshot: snapshot, credentials: credentialMap(), events: &events}
	plane := &fakePlane{events: &events, appliedHash: strings.Repeat("b", 64)}
	forwarders := &fakeForwarders{events: &events, ready: map[int]bool{15001: true}, stopError: map[int]error{}}
	store := &memoryLKG{value: prior, events: &events}
	if err := newTestReconciler(t, control, plane, forwarders, store).Reconcile(context.Background(), 8); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	assertSubsequence(t, events, []string{"nft-check", "nft-apply", "lkg-save", "stop:15001", "ack:VERIFIED:"})
}

func TestReconcileApplyFailureStopsOnlyNewForwarderAndReportsRollback(t *testing.T) {
	events := []string{}
	snapshot := mustSnapshot(t, 9, activeMapping("m1", "192.168.2.101/32", 15001))
	control := &fakeControl{snapshot: snapshot, credentials: credentialMap(), events: &events}
	plane := &fakePlane{events: &events, applyErr: errors.New("nft rejected"), rolledBack: true}
	forwarders := &fakeForwarders{events: &events, ready: map[int]bool{}, stopError: map[int]error{}}
	store := &memoryLKG{value: emptyLKG(t), events: &events}
	err := newTestReconciler(t, control, plane, forwarders, store).Reconcile(context.Background(), 9)
	if err == nil {
		t.Fatal("Reconcile unexpectedly succeeded")
	}
	assertSubsequence(t, events, []string{"activate:m1:false", "nft-apply", "stop:15001", "ack:FAILED:ROLLED_BACK"})
}

func TestReconcileSamePortRevisionFailureRestoresPreviousForwarderBeforeRolledBackACK(t *testing.T) {
	events := []string{}
	oldMapping := activeMapping("m1", "192.168.2.101/32", 15001)
	prior := emptyLKG(t)
	prior.Metadata.Runtimes = []RuntimeRecord{runtimeRecord(oldMapping)}
	rotated := oldMapping
	rotated.ProxyHost = "new-proxy.example"
	rotated.ProxyRevision = 2
	rotated.CredentialRevision = 2
	snapshot := mustSnapshot(t, 11, rotated)
	credentials := map[string]domain.AgentCredential{"m1": credentialFor(rotated, true)}
	control := &fakeControl{snapshot: snapshot, credentials: credentials, events: &events}
	plane := &fakePlane{events: &events, applyErr: errors.New("readback mismatch"), applyErrAt: 2, rolledBack: true}
	forwarders := &fakeForwarders{events: &events, ready: map[int]bool{15001: true}, stopError: map[int]error{}}
	store := &memoryLKG{value: prior, events: &events}
	err := newTestReconciler(t, control, plane, forwarders, store).Reconcile(context.Background(), 11)
	if err == nil {
		t.Fatal("Reconcile unexpectedly succeeded")
	}
	assertSubsequence(t, events, []string{"capture:15001", "credential:m1", "activate:m1:true", "nft-apply", "restore:15001", "ack:FAILED:ROLLED_BACK"})
}

func TestReconcilePortChangeFailureStopsNewPortAndKeepsOldRuntime(t *testing.T) {
	events := []string{}
	oldMapping := activeMapping("m1", "192.168.2.101/32", 15001)
	prior := emptyLKG(t)
	prior.Metadata.Runtimes = []RuntimeRecord{runtimeRecord(oldMapping)}
	moved := oldMapping
	moved.LocalRedirectPort = 15002
	moved.ProxyRevision = 2
	snapshot := mustSnapshot(t, 12, moved)
	control := &fakeControl{snapshot: snapshot, credentials: map[string]domain.AgentCredential{"m1": credentialFor(moved, true)}, events: &events}
	plane := &fakePlane{events: &events, applyErr: errors.New("apply failure"), rolledBack: true}
	forwarders := &fakeForwarders{events: &events, ready: map[int]bool{15001: true}, stopError: map[int]error{}}
	store := &memoryLKG{value: prior, events: &events}
	err := newTestReconciler(t, control, plane, forwarders, store).Reconcile(context.Background(), 12)
	if err == nil {
		t.Fatal("Reconcile unexpectedly succeeded")
	}
	assertSubsequence(t, events, []string{"activate:m1:false", "nft-apply", "stop:15002", "ack:FAILED:ROLLED_BACK"})
	for _, event := range events {
		if event == "stop:15001" {
			t.Fatal("old runtime was stopped during failed port move")
		}
	}
}

func TestReconcileMissingCrashRestorePointFailsClosedThenRebuildsDesired(t *testing.T) {
	events := []string{}
	oldMapping := activeMapping("m1", "192.168.2.101/32", 15001)
	rotated := oldMapping
	rotated.ProxyHost = "rotated.proxy.example"
	rotated.ProxyRevision++
	rotated.CredentialRevision++
	previous := emptyLKG(t)
	previous.Metadata.Runtimes = []RuntimeRecord{runtimeRecord(oldMapping)}
	previous.Metadata.RulesSHA256 = scriptHash(previous.Rules)
	entry := RuntimeTransitionEntry{
		MappingID: rotated.ID, Port: 15001, OldMappingID: oldMapping.ID,
		OldSpecHash: runtimeRecord(oldMapping).SpecHash, NewSpecHash: runtimeRecord(rotated).SpecHash,
		RestorePath: "C:\\missing\\.restore-point", RestoreIntegrity: strings.Repeat("a", 64),
	}
	journal := newTransitionJournal(13, previous, []RuntimeTransitionEntry{entry})
	snapshot := mustSnapshot(t, 13, rotated)
	control := &fakeControl{snapshot: snapshot, credentials: map[string]domain.AgentCredential{"m1": credentialFor(rotated, true)}, events: &events}
	plane := &fakePlane{events: &events, appliedHash: strings.Repeat("b", 64)}
	forwarders := &fakeForwarders{
		events: &events, ready: map[int]bool{15001: true}, stopError: map[int]error{},
		restoreError: errors.New("restore point missing after reboot"),
	}
	store := &memoryLKG{value: previous, journal: &journal, events: &events}
	if err := newTestReconciler(t, control, plane, forwarders, store).Reconcile(context.Background(), 13); err != nil {
		t.Fatalf("Reconcile: %v; events=%v", err, events)
	}
	assertSubsequence(t, events, []string{
		"nft-apply", "restore:15001", "nft-apply", "stop:15001", "lkg-save",
		"credential:m1", "activate:m1:false", "nft-apply", "lkg-save", "ack:VERIFIED:",
	})
	for _, event := range events {
		if event == "nft-rollback" {
			t.Fatal("missing restore point caused unsafe publication of the previous redirect")
		}
	}
	if store.journal != nil {
		t.Fatal("resolved fail-close transition journal remains")
	}
}

func TestReconcileLKGFailureRollsBackBeforeFailedACK(t *testing.T) {
	events := []string{}
	snapshot := mustSnapshot(t, 10, activeMapping("m1", "192.168.2.101/32", 15001))
	control := &fakeControl{snapshot: snapshot, credentials: credentialMap(), events: &events}
	plane := &fakePlane{events: &events, appliedHash: strings.Repeat("c", 64)}
	forwarders := &fakeForwarders{events: &events, ready: map[int]bool{}, stopError: map[int]error{}}
	store := &memoryLKG{value: emptyLKG(t), saveErr: errors.New("disk full"), saveErrAt: 1, events: &events}
	err := newTestReconciler(t, control, plane, forwarders, store).Reconcile(context.Background(), 10)
	if err == nil {
		t.Fatal("Reconcile unexpectedly succeeded")
	}
	assertSubsequence(t, events, []string{"nft-apply", "lkg-save", "nft-rollback", "stop:15001", "ack:FAILED:ROLLED_BACK"})
}

func TestValidateAndSelectRejectsDuplicateActiveClientAndPort(t *testing.T) {
	first := activeMapping("m1", "192.168.2.101/32", 15001)
	for name, second := range map[string]domain.AgentMapping{
		"client": activeMapping("m2", "192.168.2.101/32", 15002),
		"port":   activeMapping("m2", "192.168.2.102/32", 15001),
	} {
		t.Run(name, func(t *testing.T) {
			snapshot := mustSnapshot(t, 1, first, second)
			if _, err := validateAndSelect(snapshot, testConfig()); err == nil {
				t.Fatal("invalid active snapshot accepted")
			}
		})
	}
}

func newTestReconciler(t *testing.T, control ControlPlane, plane DataPlane, forwarders Forwarders, store LKGStore) *Reconciler {
	t.Helper()
	reconciler, err := NewReconciler(testConfig(), control, plane, forwarders, store)
	if err != nil {
		t.Fatal(err)
	}
	return reconciler
}

func testConfig() Config {
	return Config{LANInterface: "lan0", WANInterface: "wan0", ForwarderPortStart: 15001, ForwarderPortEnd: 15999, DrainTimeout: time.Second}
}

func activeMapping(id, cidr string, port int) domain.AgentMapping {
	return domain.AgentMapping{ID: id, ClientIPCIDR: cidr, ProxyID: "p1", ProxyType: domain.ProxyHTTP, ProxyHost: "proxy.example", ProxyPort: 8080, ProxyRevision: 1, CredentialRevision: 1, LocalRedirectPort: port, PolicyKind: domain.EgressPolicyWebOnly, DesiredState: domain.DesiredActive}
}

func mustSnapshot(t *testing.T, generation int64, mappings ...domain.AgentMapping) domain.DesiredSnapshot {
	t.Helper()
	snapshot, err := domain.BuildDesiredSnapshot(generation, mappings)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func emptyLKG(t *testing.T) LKG {
	t.Helper()
	rules, err := renderCandidate(testConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return makeLKG(domain.DesiredSnapshot{}, rules, strings.Repeat("0", 64), nil, nil)
}

func credentialMap() map[string]domain.AgentCredential {
	mapping := activeMapping("m1", "192.168.2.101/32", 15001)
	return map[string]domain.AgentCredential{"m1": credentialFor(mapping, true)}
}

func credentialFor(mapping domain.AgentMapping, auth bool) domain.AgentCredential {
	credential := domain.AgentCredential{MappingID: mapping.ID, ProxyID: mapping.ProxyID, ProxyRevision: mapping.ProxyRevision, CredentialRevision: mapping.CredentialRevision, AuthConfigured: auth}
	if auth {
		credential.Username = "alice"
		credential.Password = []byte("secret")
	}
	return credential
}

func assertSubsequence(t *testing.T, got, want []string) {
	t.Helper()
	index := 0
	for _, event := range got {
		if index < len(want) && event == want[index] {
			index++
		}
	}
	if index != len(want) {
		t.Fatalf("events %v do not contain ordered subsequence %v", got, want)
	}
}
