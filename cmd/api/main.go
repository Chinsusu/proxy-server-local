package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Chinsusu/proxy-server-local/pkg/auth"
	"github.com/Chinsusu/proxy-server-local/pkg/check"
	"github.com/Chinsusu/proxy-server-local/pkg/config"
	"github.com/Chinsusu/proxy-server-local/pkg/httpx"
	"github.com/Chinsusu/proxy-server-local/pkg/logging"
	"github.com/Chinsusu/proxy-server-local/pkg/store"
	"github.com/Chinsusu/proxy-server-local/pkg/types"
)

func main() {
	cfg := config.LoadAPI()

	adminUser := strings.TrimSpace(os.Getenv("PGW_ADMIN_USER"))
	adminPassHash := strings.TrimSpace(os.Getenv("PGW_ADMIN_PASS_HASH"))
	adminPass := strings.TrimSpace(os.Getenv("PGW_ADMIN_PASS"))
	// if plain password provided and no hash, derive once at startup
	if adminPassHash == "" && adminPass != "" {
		if h, err := auth.HashPassword(adminPass, auth.DefaultParams()); err == nil {
			adminPassHash = h
		}
	}

	checkAdmin := func(u, p string) bool {
		if u == "" || p == "" || u != adminUser || adminPassHash == "" {
			return false
		}
		ok, _ := auth.VerifyPassword(adminPassHash, p)
		return ok
	}

	// choose store
	var st store.Store
	switch os.Getenv("PGW_STORE") {
	case "file":
		path := os.Getenv("PGW_STORE_PATH")
		if path == "" {
			path = "/var/lib/pgw/state.json"
		}
		st = store.NewFile(path)
	default:
		st = store.NewMemory()
	}

	// background health
	interval := config.LoadHealth().Interval
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			runHealthTick(st)
			<-t.C
		}
	}()

	http.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// ---- Auth ----
	http.HandleFunc("/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		var req struct{ Username, Password string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpx.JSON(w, 400, map[string]string{"error": "bad json"})
			return
		}
		if adminUser == "" || adminPassHash == "" {
			httpx.JSON(w, 503, map[string]string{"error": "admin not configured"})
			return
		}
		if !checkAdmin(req.Username, req.Password) {
			httpx.JSON(w, 401, map[string]string{"error": "invalid credentials"})
			return
		}
		tok, exp, err := auth.SignJWT(adminUser, "admin", cfg.JWTSecret, 12*time.Hour)
		if err != nil {
			logging.Error.Println("sign jwt:", err)
			httpx.JSON(w, 500, map[string]string{"error": "internal"})
			return
		}
		httpx.JSON(w, 200, map[string]any{"token": tok, "role": "admin", "expires_at": exp.UTC().Format(time.RFC3339)})
	})

	// ---- Proxies ----
	http.HandleFunc("/v1/proxies", func(w http.ResponseWriter, r *http.Request) {
		role, ok := authorizeRequest(r, cfg.JWTSecret)
		if !ok {
			httpx.JSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		if r.Method != http.MethodGet && !(r.Method == http.MethodPost && role == "agent") && role != "admin" {
			httpx.JSON(w, 403, map[string]string{"error": "forbidden"})
			return
		}

		switch r.Method {
		case http.MethodGet:
			// Return proxies in a stable order: host asc, port asc, id asc
			ps := st.ListProxies()
			sort.SliceStable(ps, func(i, j int) bool {
				hi, hj := ps[i].Host, ps[j].Host
				if hi != hj {
					return hi < hj
				}
				if ps[i].Port != ps[j].Port {
					return ps[i].Port < ps[j].Port
				}
				return ps[i].ID < ps[j].ID
			})
			httpx.JSON(w, 200, ps)
		case http.MethodPost:
			logging.Info.Printf("[DEBUG] POST /v1/mappings called")
			var p types.Proxy
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				httpx.JSON(w, 400, map[string]string{"error": "bad json"})
				return
			}
			p = st.CreateProxy(p)
			httpx.JSON(w, 201, p)
		default:
			w.WriteHeader(405)
		}
	})

	http.HandleFunc("/v1/proxies/", func(w http.ResponseWriter, r *http.Request) {
		role, ok := authorizeRequest(r, cfg.JWTSecret)
		if !ok {
			httpx.JSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		if r.Method != http.MethodGet && role != "admin" && role != "agent" {
			httpx.JSON(w, 403, map[string]string{"error": "forbidden"})
			return
		}

		path := strings.TrimPrefix(r.URL.Path, "/v1/proxies/")
		// POST /v1/proxies/{id}/check
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/check") {
			id := strings.TrimSuffix(path, "/check")
			var target types.Proxy
			found := false
			for _, p := range st.ListProxies() {
				if p.ID == id {
					target = p
					found = true
					break
				}
			}
			if !found {
				httpx.JSON(w, 404, map[string]string{"error": "not found"})
				return
			}
			if target.Type != "http" {
				httpx.JSON(w, 400, map[string]string{"error": "only http supported in this patch"})
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			res := check.CheckHTTP(ctx, target.Host, target.Port, target.Username, target.Password)
			cancel()
			if res.Err != nil {
				st.SetProxyTelemetry(target.ID, types.StatusDown, 0, "")
				httpx.JSON(w, 200, res)
				return
			}
			st.SetProxyTelemetry(target.ID, res.Status, res.LatencyMs, res.ExitIP)
			httpx.JSON(w, 200, res)
			return
		}

		// DELETE /v1/proxies/{id}
		if r.Method == http.MethodDelete && path != "" && !strings.Contains(path, "/") {
			id := path
			// collect ports of mappings referencing this proxy (before delete)
			ports := map[int]struct{}{}
			for _, mv := range st.ListMappings() {
				if mv.Proxy.ID == id && mv.LocalRedirectPort > 0 {
					ports[mv.LocalRedirectPort] = struct{}{}
				}
			}
			if ok := st.DeleteProxy(id); !ok {
				httpx.JSON(w, 404, map[string]string{"error": "not found"})
				return
			}
			w.WriteHeader(204)

			// async cleanup per port, then reconcile
			go func() {
				for port := range ports {
					stillUsed := false
					for _, mv := range st.ListMappings() {
						if mv.LocalRedirectPort == port {
							stillUsed = true
							break
						}
					}
					if !stillUsed {
						_ = os.Remove(fmt.Sprintf("/var/lib/pgw/ports/%d", port))
						_ = exec.Command("systemctl", "stop", fmt.Sprintf("pgw-fwd@%d", port)).Run()
					}
				}
				_ = reconcileNow()
			}()
			return
		}

		w.WriteHeader(404)
	})

	// ---- Clients ----
	http.HandleFunc("/v1/clients", func(w http.ResponseWriter, r *http.Request) {
		role, ok := authorizeRequest(r, cfg.JWTSecret)
		if !ok {
			httpx.JSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		if r.Method != http.MethodGet && role != "admin" {
			httpx.JSON(w, 403, map[string]string{"error": "forbidden"})
			return
		}

		switch r.Method {
		case http.MethodGet:
			httpx.JSON(w, 200, st.ListClients())

		case http.MethodPost:
			logging.Info.Printf("[DEBUG] POST /v1/mappings called")
			var c types.Client
			if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
				httpx.JSON(w, 400, map[string]string{"error": "bad json"})
				return
			}
			// enforce /32, normalise IP-only to /32
			norm, err := normalizeIPv4HostCIDR(c.IPCidr)
			if err != nil {
				httpx.JSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
			c.IPCidr = norm

			c = st.CreateClient(c)
			httpx.JSON(w, 201, c)

		default:
			w.WriteHeader(405)
		}
	})

	// DELETE /v1/clients/{id}  (cascade delete mappings of this client)
	http.HandleFunc("/v1/clients/", func(w http.ResponseWriter, r *http.Request) {
		role, ok := authorizeRequest(r, cfg.JWTSecret)
		if !ok {
			httpx.JSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		if r.Method != http.MethodGet && role != "admin" {
			httpx.JSON(w, 403, map[string]string{"error": "forbidden"})
			return
		}

		if r.Method != http.MethodDelete {
			w.WriteHeader(405)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/v1/clients/")
		if id == "" || id == "/v1/clients" {
			w.WriteHeader(404)
			return
		}
		if ok := st.DeleteClient(id); !ok {
			httpx.JSON(w, 404, map[string]string{"error": "not found"})
			return
		}
		w.WriteHeader(204)
	})

	// ---- Mappings ----
	http.HandleFunc("/v1/mappings", func(w http.ResponseWriter, r *http.Request) {
		role, ok := authorizeRequest(r, cfg.JWTSecret)
		if !ok {
			httpx.JSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		if r.Method != http.MethodGet && role != "admin" {
			httpx.JSON(w, 403, map[string]string{"error": "forbidden"})
			return
		}

		switch r.Method {
		case http.MethodGet:
			// compute derived state before returning
			views := st.ListMappings()
			for i := range views {
				// do not override explicit FAILED state
				if strings.ToUpper(views[i].State) == "FAILED" {
					continue
				}
				if ds := deriveMappingState(views[i]); ds != "" {
					views[i].State = ds
				}
			}
			// sort by client IPv4 ascending
			sort.SliceStable(views, func(i, j int) bool {
				ki := ipv4Key(views[i].Client.IPCidr)
				kj := ipv4Key(views[j].Client.IPCidr)
				if ki != kj {
					return ki < kj
				}
				return views[i].ID < views[j].ID
			})
			httpx.JSON(w, 200, views)
		case http.MethodPost:
			logging.Info.Printf("[DEBUG] POST /v1/mappings called")
			var m types.Mapping
			if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
				httpx.JSON(w, 400, map[string]string{"error": "bad json"})
				return
			}

			// Enforce unique proxy mapping: one mapping per proxy
			for _, mv := range st.ListMappings() {
				if mv.Proxy.ID == m.ProxyID {
					httpx.JSON(w, 409, map[string]string{"error": "proxy already mapped"})
					return
				}
			}
			if m.Protocol == "" {
				m.Protocol = "http"
			}
			port, err := choosePortForClient(st, m.ClientID, m.LocalRedirectPort)
			if err != nil {
				httpx.JSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
			m.LocalRedirectPort = port
			mv, ok := st.CreateMapping(m)
			if !ok {
				httpx.JSON(w, 400, map[string]string{"error": "invalid client/proxy"})
				return
			}

			// Health-check upstream before applying
			if mv.Proxy.Type != "http" {
				_ = st.UpdateMappingState(mv.ID, "FAILED", mv.LocalRedirectPort)
				mv.State = "FAILED"
				logging.Info.Printf("[DEBUG] Sending JSON response for mapping %s", mv.ID)
				httpx.JSON(w, 201, mv)
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			res := check.CheckHTTP(ctx, mv.Proxy.Host, mv.Proxy.Port, mv.Proxy.Username, mv.Proxy.Password)
			cancel()
			if res.Err != nil {
				st.SetProxyTelemetry(mv.Proxy.ID, types.StatusDown, 0, "")
				_ = st.UpdateMappingState(mv.ID, "FAILED", mv.LocalRedirectPort)
				mv.State = "FAILED"
				logging.Info.Printf("[DEBUG] Sending JSON response for mapping %s", mv.ID)
				httpx.JSON(w, 201, mv)
				return
			}
			st.SetProxyTelemetry(mv.Proxy.ID, res.Status, res.LatencyMs, res.ExitIP)

			// First-use: ensure flag + start forwarder (best-effort)
			if mv.LocalRedirectPort > 0 {
				_ = os.MkdirAll("/var/lib/pgw/ports", 0o755)
				_ = os.WriteFile(fmt.Sprintf("/var/lib/pgw/ports/%d", mv.LocalRedirectPort), []byte(""), 0o644)
				// Restart regardless of preUsed to ensure the forwarder switches to the new upstream mapping.
				_ = exec.Command("systemctl", "restart", fmt.Sprintf("pgw-fwd@%d", mv.LocalRedirectPort)).Run()
			}

			// Apply: reconcile then mark APPLIED
			go func(mv types.MappingView) {
				if mv.LocalRedirectPort <= 0 {
					return
				}
				_ = reconcileNow()
				time.Sleep(200 * time.Millisecond)
				if ds := deriveMappingState(mv); ds == "APPLIED" {
					_ = st.UpdateMappingState(mv.ID, "APPLIED", mv.LocalRedirectPort)
				}
			}(mv)

			logging.Info.Printf("[DEBUG] Sending JSON response for mapping %s", mv.ID)
			httpx.JSON(w, 201, mv)

		}

	})

	// GET /v1/mappings/active -> same as GET /v1/mappings (kept for backward-compat)
	http.HandleFunc("/v1/mappings/active", func(w http.ResponseWriter, r *http.Request) {
		role, ok := authorizeRequest(r, cfg.JWTSecret)
		if !ok {
			httpx.JSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		if r.Method != http.MethodGet && role != "admin" {
			httpx.JSON(w, 403, map[string]string{"error": "forbidden"})
			return
		}

		if r.Method != http.MethodGet {
			w.WriteHeader(405)
			return
		}
		views := st.ListMappings()
		for i := range views {
			if strings.ToUpper(views[i].State) == "FAILED" {
				continue
			}
			if ds := deriveMappingState(views[i]); ds != "" {
				views[i].State = ds
				// sort by client IPv4 ascending
				sort.SliceStable(views, func(i, j int) bool {
					ki := ipv4Key(views[i].Client.IPCidr)
					kj := ipv4Key(views[j].Client.IPCidr)
					if ki != kj {
						return ki < kj
					}
					return views[i].ID < views[j].ID
				})
			}
		}
		httpx.JSON(w, 200, views)
	})

	// Update mapping state: POST /v1/mappings/{id}/state
	http.HandleFunc("/v1/mappings/state/", func(w http.ResponseWriter, r *http.Request) {

		role, ok := authorizeRequest(r, cfg.JWTSecret)
		if !ok {
			httpx.JSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		if r.Method != http.MethodGet && role != "admin" && role != "agent" {
			httpx.JSON(w, 403, map[string]string{"error": "forbidden"})
			return
		}

		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) != 4 || parts[0] != "v1" || parts[1] != "mappings" || parts[2] != "state" {
			w.WriteHeader(404)
			return
		}
		id := parts[3]
		var req struct {
			State     string `json:"state"`
			LocalPort int    `json:"local_redirect_port"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpx.JSON(w, 400, map[string]string{"error": "bad json"})
			return
		}
		if req.State != "PENDING" && req.State != "APPLIED" && req.State != "FAILED" {
			httpx.JSON(w, 400, map[string]string{"error": "invalid state"})
			return
		}
		if ok := st.UpdateMappingState(id, req.State, req.LocalPort); !ok {
			httpx.JSON(w, 404, map[string]string{"error": "not found"})
			return
		}
		w.WriteHeader(204)
	})

	// DELETE /v1/mappings/{id} (hard delete + cleanup)
	http.HandleFunc("/v1/mappings/", func(w http.ResponseWriter, r *http.Request) {
		role, ok := authorizeRequest(r, cfg.JWTSecret)
		if !ok {
			httpx.JSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		if r.Method != http.MethodGet && role != "admin" {
			httpx.JSON(w, 403, map[string]string{"error": "forbidden"})
			return
		}

		// Skip exact /v1/mappings to avoid conflict with main handler
		if r.URL.Path == "/v1/mappings" {
			return
		}
		if r.Method != http.MethodDelete {
			w.WriteHeader(405)
			return
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) != 3 || parts[0] != "v1" || parts[1] != "mappings" {
			w.WriteHeader(404)
			return
		}
		id := parts[2]
		if id == "" {
			w.WriteHeader(400)
			return
		}

		// capture port before delete
		port := 0
		for _, mv := range st.ListMappings() {
			if mv.ID == id {
				port = mv.LocalRedirectPort
				break
			}
		}

		if ok := st.DeleteMapping(id); !ok {
			httpx.JSON(w, 404, map[string]string{"error": "not found"})
			return
		}
		w.WriteHeader(204)

		if port > 0 {
			go func(port int) {
				// if no remaining mapping uses this port, cleanup flag and stop forwarder
				stillUsed := false
				for _, mv := range st.ListMappings() {
					if mv.LocalRedirectPort == port {
						stillUsed = true
						break
					}
				}
				if !stillUsed {
					_ = os.Remove(fmt.Sprintf("/var/lib/pgw/ports/%d", port))
					_ = exec.Command("systemctl", "stop", fmt.Sprintf("pgw-fwd@%d", port)).Run()
				}
				_ = reconcileNow()
			}(port)
		}
	})

	logging.Info.Printf("pgw-api listening on %s\n", cfg.Addr)
	if err := http.ListenAndServe(cfg.Addr, nil); err != nil {
		logging.Error.Println(err)
		os.Exit(1)
	}
}

// reconcileNow tells local agent to apply nft rules. Best-effort.
func reconcileNow() error {
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:9090/agent/reconcile", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("agent %s", resp.Status)
	}
	return nil
}

func runHealthTick(st store.Store) {
	for _, p := range st.ListProxies() {
		if p.Type != "http" {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		res := check.CheckHTTP(ctx, p.Host, p.Port, p.Username, p.Password)
		cancel()
		if res.Err != nil {
			st.SetProxyTelemetry(p.ID, types.StatusDown, 0, "")
		} else {
			st.SetProxyTelemetry(p.ID, res.Status, res.LatencyMs, res.ExitIP)
		}
	}
}

// deriveMappingState inspects system state to infer mapping status.
// Returns "APPLIED" or "" (keep stored state).
func deriveMappingState(mv types.MappingView) string {
	if mv.LocalRedirectPort <= 0 {
		return ""
	}
	portOK := false
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", mv.LocalRedirectPort), 200*time.Millisecond)
	if err == nil {
		portOK = true
		_ = c.Close()
	}
	// nft rule check: best effort
	nftOK := false
	if out, err := exec.Command("nft", "list", "table", "ip", "pgw").Output(); err == nil {
		ip := mv.Client.IPCidr
		if i := strings.Index(ip, "/"); i >= 0 {
			ip = ip[:i]
		}
		to := fmt.Sprintf("redirect to :%d", mv.LocalRedirectPort)
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "ip saddr "+ip) && strings.Contains(line, to) {
				nftOK = true
				break
			}
		}
	}
	if portOK && nftOK {
		return "APPLIED"
	}
	return ""
}

// choosePortForClient ensures one-port-per-proxy:
// choosePortForClient ensures one-port-per-client:
// - If requested>0: allow only if unused or already bound to this client.
// - If requested==0: reuse existing port of this client if any; otherwise allocate a free port in [base..max].
func choosePortForClient(st store.Store, clientID string, requested int) (int, error) {
	// map of port -> clientID (first seen)
	used := map[int]string{}
	existing := 0
	for _, mv := range st.ListMappings() {
		if mv.LocalRedirectPort <= 0 {
			continue
		}
		if _, ok := used[mv.LocalRedirectPort]; !ok {
			used[mv.LocalRedirectPort] = mv.Client.ID
		}
		if mv.Client.ID == clientID && existing == 0 {
			existing = mv.LocalRedirectPort
		}
	}
	if requested > 0 {
		if cid, ok := used[requested]; ok && cid != clientID {
			return 0, fmt.Errorf("port %d is already used by another client", requested)
		}
		return requested, nil
	}
	if existing > 0 {
		return existing, nil
	}
	base := 15001
	max := 15999
	if v := os.Getenv("PGW_FWD_BASE_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			base = n
		}
	}
	if v := os.Getenv("PGW_FWD_MAX_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > base {
			max = n
		}
	}
	for p := base; p <= max; p++ {
		if _, ok := used[p]; !ok {
			return p, nil
		}
	}
	return 0, fmt.Errorf("no free port available in range %d-%d", base, max)
}

// ipv4Key converts CIDR or IPv4 string to a sortable uint32 key (invalid → MaxUint32)
func ipv4Key(cidr string) uint32 {
	ip := cidr
	if i := strings.Index(ip, "/"); i >= 0 {
		ip = ip[:i]
	}
	p := net.ParseIP(ip)
	if p == nil {
		return ^uint32(0)
	}
	v4 := p.To4()
	if v4 == nil {
		return ^uint32(0)
	}
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
}

// authorizeRequest extracts JWT from Authorization Bearer or pgw_jwt cookie, verifies and returns role.
func authorizeRequest(r *http.Request, secret string) (string, bool) {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	var tok string
	if len(h) >= 7 && strings.ToLower(h[:7]) == "bearer " {
		tok = strings.TrimSpace(h[7:])
	}
	if tok == "" {
		if c, err := r.Cookie("pgw_jwt"); err == nil {
			tok = c.Value
		}
	}
	if tok == "" {
		return "", false
	}
	if at := os.Getenv("PGW_AGENT_TOKEN"); at != "" && tok == at {
		return "agent", true
	}
	cl, err := auth.ParseJWT(tok, secret)
	if err != nil {
		return "", false
	}
	return cl.Role, true
}
