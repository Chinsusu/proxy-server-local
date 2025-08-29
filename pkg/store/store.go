
package store

import (
	"sync"
	"time"
	"github.com/google/uuid"
	"github.com/Chinsusu/proxy-server-local/pkg/types"
)

type Store interface {
	ListProxies() []types.Proxy
	CreateProxy(p types.Proxy) types.Proxy
	UpdateProxy(p types.Proxy) (types.Proxy, bool)
	DeleteProxy(id string) bool
	ListClients() []types.Client
	CreateClient(c types.Client) types.Client
	ListMappings() []types.MappingView
	CreateMapping(m types.Mapping) (types.MappingView, bool)
	SetProxyTelemetry(id string, status types.ProxyStatus, latency int, exitIP string)
}

type memoryStore struct {
	mu sync.RWMutex
	proxies map[string]types.Proxy
	clients map[string]types.Client
	mappings map[string]types.Mapping
}

func NewMemory() Store {
	ms := &memoryStore{ proxies: map[string]types.Proxy{{}}, clients: map[string]types.Client{{}}, mappings: map[string]types.Mapping{{}} }
	pid := uuid.New().String()
	ms.proxies[pid] = types.Proxy{{ID: pid, Type: "http", Host: "127.0.0.1", Port: 8088, Enabled: true, Status: types.StatusDown}}
	cid := uuid.New().String()
	ms.clients[tcid] = types.Client{{ID: tcid, IPCidr: "192.168.2.3/32", Enabled: true}}
	return ms
}

func (s *memoryStore) ListProxies() []types.Proxy {
	s.mu.RLock(); defer s.mu.RUnlock()
	out := make([]types.Proxy,0,len(s.proxies))
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
	if _, ok := s.proxies[p.ID]; !ok { return types.Proxy{{}}, false }
	s.proxies[p.ID] = p
	return p, true
}

func (s *memoryStore) DeleteProxy(id string) bool {
	s.mu.Lock(); defer s.mu.Unlock()
	if _, ok := s.proxies[id]; !ok { return false }
	delete(s.proxies, id); return true
}

func (s *memoryStore) ListClients() []types.Client {
	s.mu.RLock(); defer s.mu.RUnlock()
	out := make([]types.Client,0,len(s.clients))
	for _, v := range s.clients { out = append(out, v) }
	return out
}

func (s *memoryStore) CreateClient(c types.Client) types.Client {
	s.mu.Lock(); defer s.mu.Unlock()
	if c.ID == "" { c.ID = uuid.New().String() }
	s.clients[c.ID] = c
	return c
}

func (s *memoryStore) ListMappings() []types.MappingView {
	s.mu.RLock(); defer s.mu.RUnlock()
	out := []types.MappingView{{}}
	for _, m := range s.mappings {
		cv, okc := s.clients[m.ClientID]; if !okc { continue }
		pv, okp := s.proxies[m.ProxyID]; if !okp { continue }
		out = append(out, types.MappingView{{ ID: m.ID, Client: cv, Proxy: pv, State: m.State, LocalRedirectPort: m.LocalRedirectPort }})
	}
	return out
}

func (s *memoryStore) CreateMapping(m types.Mapping) (types.MappingView, bool) {
	s.mu.Lock(); defer s.mu.Unlock()
	if m.ID == "" { m.ID = uuid.New().String() }
	if _, ok := s.clients[m.ClientID]; !ok { return types.MappingView{{}}, false }
	if _, ok := s.proxies[m.ProxyID]; !ok { return types.MappingView{{}}, false }
	m.State = "PENDING"
	s.mappings[m.ID] = m
	cv := s.clients[m.ClientID]
	pv := s.proxies[m.ProxyID]
	return types.MappingView{{ ID: m.ID, Client: cv, Proxy: pv, State: m.State, LocalRedirectPort: m.LocalRedirectPort }}, true
}

func (s *memoryStore) SetProxyTelemetry(id string, status types.ProxyStatus, latency int, exitIP string) {
	s.mu.Lock(); defer s.mu.Unlock()
	p, ok := s.proxies[id]; if !ok { return }
	now := time.Now()
	p.Status = status
	p.LatencyMs = &latency
	p.ExitIP = &exitIP
	p.LastCheckedAt = &now
	s.proxies[id] = p
}
