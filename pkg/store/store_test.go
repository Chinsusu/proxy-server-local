package store

import (
	"testing"
	"time"

	"github.com/Chinsusu/proxy-server-local/pkg/types"
)

// --- helpers ---

func seedProxy(s Store) types.Proxy {
	return s.CreateProxy(types.Proxy{
		Label:   "test-http",
		Type:    "http",
		Host:    "1.2.3.4",
		Port:    8080,
		Enabled: true,
	})
}

func seedClient(s Store) types.Client {
	return s.CreateClient(types.Client{
		IPCidr:  "192.168.2.10/32",
		Enabled: true,
	})
}

// --- Proxy tests ---

func testCreateProxy(t *testing.T, s Store) {
	p := seedProxy(s)
	if p.ID == "" {
		t.Fatal("expected generated ID")
	}
	if p.Status != types.StatusDown {
		t.Fatalf("expected status DOWN, got %s", p.Status)
	}
	ps := s.ListProxies()
	found := false
	for _, pp := range ps {
		if pp.ID == p.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("created proxy not found in ListProxies")
	}
}

func testDeleteProxy_CascadesMappings(t *testing.T, s Store) {
	p := seedProxy(s)
	c := seedClient(s)
	mv, ok := s.CreateMapping(types.Mapping{ClientID: c.ID, ProxyID: p.ID, LocalRedirectPort: 15001})
	if !ok {
		t.Fatal("CreateMapping failed")
	}

	s.DeleteProxy(p.ID)

	// proxy should be gone
	for _, pp := range s.ListProxies() {
		if pp.ID == p.ID {
			t.Fatal("proxy should be deleted")
		}
	}
	// mapping should also be gone (cascade)
	for _, m := range s.ListMappings() {
		if m.ID == mv.ID {
			t.Fatal("mapping should be cascade-deleted")
		}
	}
}

// --- Client tests ---

func testDeleteClient_CascadesMappings(t *testing.T, s Store) {
	p := seedProxy(s)
	c := seedClient(s)
	mv, ok := s.CreateMapping(types.Mapping{ClientID: c.ID, ProxyID: p.ID, LocalRedirectPort: 15001})
	if !ok {
		t.Fatal("CreateMapping failed")
	}

	s.DeleteClient(c.ID)

	for _, cc := range s.ListClients() {
		if cc.ID == c.ID {
			t.Fatal("client should be deleted")
		}
	}
	for _, m := range s.ListMappings() {
		if m.ID == mv.ID {
			t.Fatal("mapping should be cascade-deleted")
		}
	}
}

// --- Mapping tests ---

func testListMappings_IncludesPendingMappings(t *testing.T, s Store) {
	p := seedProxy(s)
	c := seedClient(s)
	mv, ok := s.CreateMapping(types.Mapping{ClientID: c.ID, ProxyID: p.ID, LocalRedirectPort: 15001})
	if !ok {
		t.Fatal("CreateMapping failed")
	}
	// mapping is PENDING, LastAppliedAt is nil — this is the regression test
	if mv.State != "PENDING" {
		t.Fatalf("expected state PENDING, got %s", mv.State)
	}

	// ListMappings MUST return this mapping
	mvs := s.ListMappings()
	found := false
	for _, m := range mvs {
		if m.ID == mv.ID {
			found = true
			if m.State != "PENDING" {
				t.Fatalf("expected state PENDING, got %s", m.State)
			}
		}
	}
	if !found {
		t.Fatal("REGRESSION: PENDING mapping not returned by ListMappings (LastAppliedAt is nil)")
	}
}

func testCreateMapping_InvalidRefs(t *testing.T, s Store) {
	_, ok := s.CreateMapping(types.Mapping{ClientID: "bad-id", ProxyID: "bad-id"})
	if ok {
		t.Fatal("CreateMapping should fail with invalid client/proxy IDs")
	}
}

func testUpdateMappingState(t *testing.T, s Store) {
	p := seedProxy(s)
	c := seedClient(s)
	mv, _ := s.CreateMapping(types.Mapping{ClientID: c.ID, ProxyID: p.ID, LocalRedirectPort: 15001})

	ok := s.UpdateMappingState(mv.ID, "APPLIED", 15002)
	if !ok {
		t.Fatal("UpdateMappingState failed")
	}

	mvs := s.ListMappings()
	for _, m := range mvs {
		if m.ID == mv.ID {
			if m.State != "APPLIED" {
				t.Fatalf("expected state APPLIED, got %s", m.State)
			}
			if m.LocalRedirectPort != 15002 {
				t.Fatalf("expected port 15002, got %d", m.LocalRedirectPort)
			}
			return
		}
	}
	t.Fatal("mapping not found after state update")
}

func testDeleteMapping(t *testing.T, s Store) {
	p := seedProxy(s)
	c := seedClient(s)
	mv, _ := s.CreateMapping(types.Mapping{ClientID: c.ID, ProxyID: p.ID, LocalRedirectPort: 15001})

	ok := s.DeleteMapping(mv.ID)
	if !ok {
		t.Fatal("DeleteMapping failed")
	}
	// delete non-existent should return false
	if s.DeleteMapping(mv.ID) {
		t.Fatal("DeleteMapping should return false for non-existent")
	}
}

// --- Telemetry tests ---

func testSetProxyTelemetry(t *testing.T, s Store) {
	p := seedProxy(s)
	s.SetProxyTelemetry(p.ID, types.StatusOK, 42, "1.2.3.4")

	for _, pp := range s.ListProxies() {
		if pp.ID == p.ID {
			if pp.Status != types.StatusOK {
				t.Fatalf("expected status OK, got %s", pp.Status)
			}
			if pp.LatencyMs == nil || *pp.LatencyMs != 42 {
				t.Fatalf("expected latency 42, got %v", pp.LatencyMs)
			}
			if pp.ExitIP == nil || *pp.ExitIP != "1.2.3.4" {
				t.Fatalf("expected exit_ip 1.2.3.4, got %v", pp.ExitIP)
			}
			if pp.LastCheckedAt == nil {
				t.Fatal("expected LastCheckedAt set")
			}
			return
		}
	}
	t.Fatal("proxy not found")
}

func testListMappings_SortOrder(t *testing.T, s Store) {
	p := seedProxy(s)
	c1 := s.CreateClient(types.Client{IPCidr: "192.168.2.20/32", Enabled: true})
	c2 := s.CreateClient(types.Client{IPCidr: "192.168.2.10/32", Enabled: true})

	m1, _ := s.CreateMapping(types.Mapping{ClientID: c1.ID, ProxyID: p.ID, LocalRedirectPort: 15001})
	m2, _ := s.CreateMapping(types.Mapping{ClientID: c2.ID, ProxyID: p.ID, LocalRedirectPort: 15002})

	// Mark m1 as APPLIED (sets LastAppliedAt)
	s.UpdateMappingState(m1.ID, "APPLIED", 15001)

	mvs := s.ListMappings()
	if len(mvs) < 2 {
		t.Fatalf("expected at least 2 mappings, got %d", len(mvs))
	}
	// m1 has LastAppliedAt (has=true), m2 doesn't — m1 should come first
	if mvs[0].ID != m1.ID {
		t.Fatalf("expected m1 (with LastAppliedAt) first, got %s", mvs[0].ID)
	}
	_ = m2
	_ = time.Now // prevent lint
}

// --- Run all tests for both stores ---

func TestMemoryStore(t *testing.T) {
	tests := []struct {
		name string
		fn   func(*testing.T, Store)
	}{
		{"CreateProxy", testCreateProxy},
		{"DeleteProxy_CascadesMappings", testDeleteProxy_CascadesMappings},
		{"DeleteClient_CascadesMappings", testDeleteClient_CascadesMappings},
		{"ListMappings_IncludesPendingMappings", testListMappings_IncludesPendingMappings},
		{"CreateMapping_InvalidRefs", testCreateMapping_InvalidRefs},
		{"UpdateMappingState", testUpdateMappingState},
		{"DeleteMapping", testDeleteMapping},
		{"SetProxyTelemetry", testSetProxyTelemetry},
		{"ListMappings_SortOrder", testListMappings_SortOrder},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewMemory()
			tc.fn(t, s)
		})
	}
}

func TestFileStore(t *testing.T) {
	tests := []struct {
		name string
		fn   func(*testing.T, Store)
	}{
		{"CreateProxy", testCreateProxy},
		{"DeleteProxy_CascadesMappings", testDeleteProxy_CascadesMappings},
		{"DeleteClient_CascadesMappings", testDeleteClient_CascadesMappings},
		{"ListMappings_IncludesPendingMappings", testListMappings_IncludesPendingMappings},
		{"CreateMapping_InvalidRefs", testCreateMapping_InvalidRefs},
		{"UpdateMappingState", testUpdateMappingState},
		{"DeleteMapping", testDeleteMapping},
		{"SetProxyTelemetry", testSetProxyTelemetry},
		{"ListMappings_SortOrder", testListMappings_SortOrder},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			s := NewFile(tmp + "/test-state.json")
			tc.fn(t, s)
		})
	}
}
