// pkg/store/file.go
package store

import (
	"encoding/json"
	"sort"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/Chinsusu/proxy-server-local/pkg/types"
)

type fileState struct {
	Proxies  map[string]types.Proxy   `json:"proxies"`
	Clients  map[string]types.Client  `json:"clients"`
	Mappings map[string]types.Mapping `json:"mappings"`
}

type fileStore struct {
	mu    sync.RWMutex
	path  string
	state fileState
}

func NewFile(path string) Store {
	_ = os.MkdirAll(filepath.Dir(path), 0o750)
	fs := &fileStore{path: path}
	if err := fs.load(); err != nil {
		fs.state = fileState{
			Proxies:  map[string]types.Proxy{},
			Clients:  map[string]types.Client{},
			Mappings: map[string]types.Mapping{},
		}
		_ = fs.save()
	}
	return fs
}

func (s *fileStore) load() error {
	b, err := os.ReadFile(s.path)
	if err != nil { return err }
	var st fileState
	if err := json.Unmarshal(b, &st); err != nil { return err }
	if st.Proxies == nil { st.Proxies = map[string]types.Proxy{} }
	if st.Clients == nil { st.Clients = map[string]types.Client{} }
	if st.Mappings == nil { st.Mappings = map[string]types.Mapping{} }
	s.state = st
	return nil
}

func (s *fileStore) save() error {
	tmp := s.path + ".tmp"
	b, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil { return err }
	if err := os.WriteFile(tmp, b, 0o640); err != nil { return err }
	return os.Rename(tmp, s.path)
}

// ---------- Proxies ----------

func (s *fileStore) ListProxies() []types.Proxy {
	s.mu.RLock(); defer s.mu.RUnlock()
	out := make([]types.Proxy, 0, len(s.state.Proxies))
	for _, v := range s.state.Proxies { out = append(out, v) }
	return out
}

func (s *fileStore) CreateProxy(p types.Proxy) types.Proxy {
	s.mu.Lock(); defer s.mu.Unlock()
	if p.ID == "" { p.ID = uuid.New().String() }
	p.Status = types.StatusDown
	if s.state.Proxies == nil { s.state.Proxies = map[string]types.Proxy{} }
	s.state.Proxies[p.ID] = p
	_ = s.save()
	return p
}

func (s *fileStore) UpdateProxy(p types.Proxy) (types.Proxy, bool) {
	s.mu.Lock(); defer s.mu.Unlock()
	if _, ok := s.state.Proxies[p.ID]; !ok { return types.Proxy{}, false }
	s.state.Proxies[p.ID] = p
	_ = s.save()
	return p, true
}

func (s *fileStore) DeleteProxy(id string) bool {
	s.mu.Lock(); defer s.mu.Unlock()
	if _, ok := s.state.Proxies[id]; !ok { return false }
	delete(s.state.Proxies, id)
	// cascade: xoá mapping tham chiếu tới proxy này
	for mid, m := range s.state.Mappings {
		if m.ProxyID == id { delete(s.state.Mappings, mid) }
	}
	_ = s.save()
	return true
}

// ---------- Clients ----------

func (s *fileStore) ListClients() []types.Client {
	s.mu.RLock(); defer s.mu.RUnlock()
	out := make([]types.Client, 0, len(s.state.Clients))
	for _, v := range s.state.Clients { out = append(out, v) }
	return out
}

func (s *fileStore) CreateClient(c types.Client) types.Client {
	s.mu.Lock(); defer s.mu.Unlock()
	if c.ID == "" { c.ID = uuid.New().String() }
	if s.state.Clients == nil { s.state.Clients = map[string]types.Client{} }
	s.state.Clients[c.ID] = c
	_ = s.save()
	return c
}

func (s *fileStore) DeleteClient(id string) bool {
	s.mu.Lock(); defer s.mu.Unlock()
	if _, ok := s.state.Clients[id]; !ok { return false }
	delete(s.state.Clients, id)
	// cascade: xoá mapping của client này
	for mid, m := range s.state.Mappings {
		if m.ClientID == id { delete(s.state.Mappings, mid) }
	}
	_ = s.save()
	return true
}

// ---------- Mappings ----------

func (s *fileStore) ListMappings() []types.MappingView {
	s.mu.RLock(); defer s.mu.RUnlock()
	type rec struct{
		mv types.MappingView
		ts time.Time
		has bool
	}
	tmp := []rec{}
	for _, m := range s.state.Mappings {
		cv, okc := s.state.Clients[m.ClientID]
		pv, okp := s.state.Proxies[m.ProxyID]
		if !okc || !okp { continue }
		r := rec{ mv: types.MappingView{
			ID: m.ID,
			Client: cv,
			Proxy: pv,
			State: m.State,
			LocalRedirectPort: m.LocalRedirectPort,
		}}
		if m.LastAppliedAt != nil { r.ts = *m.LastAppliedAt; r.has = true }
		tmp = append(tmp, r)
	}
	sort.SliceStable(tmp, func(i,j int) bool {
		if tmp[i].has && tmp[j].has { return tmp[i].ts.After(tmp[j].ts) }
		if tmp[i].has != tmp[j].has { return tmp[i].has }
		return tmp[i].mv.ID < tmp[j].mv.ID
	})
	out := make([]types.MappingView, len(tmp))
	for i := range tmp { out[i] = tmp[i].mv }
	return out
}

func (s *fileStore) CreateMapping(m types.Mapping) (types.MappingView, bool) {
	s.mu.Lock(); defer s.mu.Unlock()
	if _, ok := s.state.Clients[m.ClientID]; !ok { return types.MappingView{}, false }
	if _, ok := s.state.Proxies[m.ProxyID]; !ok { return types.MappingView{}, false }
	if m.ID == "" { m.ID = uuid.New().String() }
	m.State = "PENDING"
	if s.state.Mappings == nil { s.state.Mappings = map[string]types.Mapping{} }
	s.state.Mappings[m.ID] = m
	_ = s.save()

	cv := s.state.Clients[m.ClientID]
	pv := s.state.Proxies[m.ProxyID]
	return types.MappingView{
		ID:                m.ID,
		Client:            cv,
		Proxy:             pv,
		State:             m.State,
		LocalRedirectPort: m.LocalRedirectPort,
	}, true
}

// ---------- Telemetry ----------

func (s *fileStore) SetProxyTelemetry(id string, status types.ProxyStatus, latency int, exitIP string) {
	s.mu.Lock(); defer s.mu.Unlock()
	p, ok := s.state.Proxies[id]; if !ok { return }
	now := time.Now()
	p.Status = status
	if latency > 0 { p.LatencyMs = &latency } else { p.LatencyMs = nil }
	if exitIP != "" { p.ExitIP = &exitIP } else { p.ExitIP = nil }
	p.LastCheckedAt = &now
	s.state.Proxies[id] = p
	_ = s.save()
}

// DeleteMapping removes a mapping by id.
func (s *fileStore) DeleteMapping(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Mappings[id]; !ok {
		return false
	}
	delete(s.state.Mappings, id)
	_ = s.save()
	return true
}

// UpdateMappingState updates mapping state and optionally local port, then persists to disk.
func (s *fileStore) UpdateMappingState(id string, state string, localPort int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.state.Mappings[id]
	if !ok {
		return false
	}
	if state != "" {
		m.State = state
		if state == "APPLIED" || state == "FAILED" {
			now := time.Now()
			m.LastAppliedAt = &now
		}
	}
	if localPort > 0 {
		m.LocalRedirectPort = localPort
	}
	s.state.Mappings[id] = m
	_ = s.save()
	return true
}
