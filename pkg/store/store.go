// pkg/store/store.go
package store

import (
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Chinsusu/proxy-server-local/pkg/types"
)

type Store interface {
	// Proxies
	ListProxies() []types.Proxy
	CreateProxy(p types.Proxy) types.Proxy
	UpdateProxy(p types.Proxy) (types.Proxy, bool)
	DeleteProxy(id string) bool

	// Clients
	ListClients() []types.Client
	CreateClient(c types.Client) types.Client
	DeleteClient(id string) bool // NEW

	// Mappings
	ListMappings() []types.MappingView
	CreateMapping(m types.Mapping) (types.MappingView, bool)
	DeleteMapping(id string) bool // NEW
	// UpdateMappingState updates mapping.state and optionally its local redirect port
	UpdateMappingState(id string, state string, localPort int) bool

	// Telemetry
	SetProxyTelemetry(id string, status types.ProxyStatus, latency int, exitIP string)
}

type memoryStore struct {
	mu       sync.RWMutex
	proxies  map[string]types.Proxy
	clients  map[string]types.Client
	mappings map[string]types.Mapping
}

func NewMemory() Store {
	ms := &memoryStore{
		proxies:  make(map[string]types.Proxy),
		clients:  make(map[string]types.Client),
		mappings: make(map[string]types.Mapping),
	}

	// Seed demo (có thể bỏ)
	pid := uuid.New().String()
	ms.proxies[pid] = types.Proxy{
		ID:      pid,
		Label:   "demo-http",
		Type:    "http",
		Host:    "127.0.0.1",
		Port:    8088,
		Enabled: true,
		Status:  types.StatusDown,
	}
	cid := uuid.New().String()
	ms.clients[cid] = types.Client{
		ID:      cid,
		IPCidr:  "192.168.2.3/32",
		Enabled: true,
	}
	return ms
}

// ---------- Proxies ----------

func (s *memoryStore) ListProxies() []types.Proxy {
	s.mu.RLock(); defer s.mu.RUnlock()
	out := make([]types.Proxy, 0, len(s.proxies))
	for _, v := range s.proxies { out = append(out, v) }
	return out
}

func (s *memoryStore) CreateProxy(p types.Proxy) types.Proxy {
	s.mu.Lock(); defer s.mu.Unlock()
	if p.ID == "" { p.ID = uuid.New().String() }
	p.Status = types.StatusDown
	s.proxies[p.ID] = p
	return p
}

func (s *memoryStore) UpdateProxy(p types.Proxy) (types.Proxy, bool) {
	s.mu.Lock(); defer s.mu.Unlock()
	if _, ok := s.proxies[p.ID]; !ok { return types.Proxy{}, false }
	s.proxies[p.ID] = p
	return p, true
}

func (s *memoryStore) DeleteProxy(id string) bool {
	s.mu.Lock(); defer s.mu.Unlock()
	if _, ok := s.proxies[id]; !ok { return false }
	delete(s.proxies, id)
	// tuỳ chọn: xoá các mapping tham chiếu tới proxy này
	for mid, m := range s.mappings {
		if m.ProxyID == id { delete(s.mappings, mid) }
	}
	return true
}

// ---------- Clients ----------

func (s *memoryStore) ListClients() []types.Client {
	s.mu.RLock(); defer s.mu.RUnlock()
	out := make([]types.Client, 0, len(s.clients))
	for _, v := range s.clients { out = append(out, v) }
	return out
}

func (s *memoryStore) CreateClient(c types.Client) types.Client {
	s.mu.Lock(); defer s.mu.Unlock()
	if c.ID == "" { c.ID = uuid.New().String() }
	s.clients[c.ID] = c
	return c
}

func (s *memoryStore) DeleteClient(id string) bool {
	s.mu.Lock(); defer s.mu.Unlock()
	if _, ok := s.clients[id]; !ok { return false }
	delete(s.clients, id)
	// cascade: xoá mapping của client này
	for mid, m := range s.mappings {
		if m.ClientID == id { delete(s.mappings, mid) }
	}
	return true
}

// ---------- Mappings ----------

func (s *memoryStore) ListMappings() []types.MappingView {
	s.mu.RLock(); defer s.mu.RUnlock()
	type rec struct {
		mv  types.MappingView
		ts  time.Time
		has bool
	}
	tmp := []rec{}
	for _, m := range s.mappings {
		cv, okc := s.clients[m.ClientID]
		pv, okp := s.proxies[m.ProxyID]
		if !okc || !okp { continue }
		r := rec{
			mv: types.MappingView{
				ID:                m.ID,
				Client:            cv,
				Proxy:             pv,
				State:             m.State,
				LocalRedirectPort: m.LocalRedirectPort,
			},
		}
		if m.LastAppliedAt != nil {
			r.ts = *m.LastAppliedAt
			r.has = true
		tmp = append(tmp, r)
	}
}
	sort.SliceStable(tmp, func(i, j int) bool {
		if tmp[i].has && tmp[j].has {
			return tmp[i].ts.After(tmp[j].ts)
		}
		if tmp[i].has != tmp[j].has {
			return tmp[i].has
		}
		return tmp[i].mv.ID < tmp[j].mv.ID
	})
	out := make([]types.MappingView, len(tmp))
	for i := range tmp { out[i] = tmp[i].mv }
	return out
}

func (s *memoryStore) CreateMapping(m types.Mapping) (types.MappingView, bool) {
	s.mu.Lock(); defer s.mu.Unlock()
	if m.ID == "" { m.ID = uuid.New().String() }
	if _, ok := s.clients[m.ClientID]; !ok { return types.MappingView{}, false }
	if _, ok := s.proxies[m.ProxyID]; !ok { return types.MappingView{}, false }
	m.State = "PENDING"
	s.mappings[m.ID] = m

	cv := s.clients[m.ClientID]
	pv := s.proxies[m.ProxyID]
	return types.MappingView{
		ID:                m.ID,
		Client:            cv,
		Proxy:             pv,
		State:             m.State,
		LocalRedirectPort: m.LocalRedirectPort,
	}, true
}

func (s *memoryStore) DeleteMapping(id string) bool {
	s.mu.Lock(); defer s.mu.Unlock()
	if _, ok := s.mappings[id]; !ok { return false }
	delete(s.mappings, id)
	return true
}

// UpdateMappingState implements state update for a mapping in memory store.
func (s *memoryStore) UpdateMappingState(id string, state string, localPort int) bool {
	s.mu.Lock(); defer s.mu.Unlock()
	m, ok := s.mappings[id]
	if !ok { return false }
	if state != "" {
		m.State = state
		if state == "APPLIED" || state == "FAILED" {
			now := time.Now()
			m.LastAppliedAt = &now
		}
	}
	if localPort > 0 { m.LocalRedirectPort = localPort }
	s.mappings[id] = m
	return true
}

// ---------- Telemetry ----------

func (s *memoryStore) SetProxyTelemetry(id string, status types.ProxyStatus, latency int, exitIP string) {
	s.mu.Lock(); defer s.mu.Unlock()
	p, ok := s.proxies[id]; if !ok { return }
	now := time.Now()
	p.Status = status
	if latency > 0 { p.LatencyMs = &latency } else { p.LatencyMs = nil }
	if exitIP != "" { p.ExitIP = &exitIP } else { p.ExitIP = nil }
	p.LastCheckedAt = &now
	s.proxies[id] = p
}
