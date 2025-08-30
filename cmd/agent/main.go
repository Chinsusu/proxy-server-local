package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Chinsusu/proxy-server-local/pkg/config"
	"github.com/Chinsusu/proxy-server-local/pkg/logging"
	"github.com/Chinsusu/proxy-server-local/pkg/types"
)

type cfgAgent struct {
	APIBase   string
	LANIF     string
	WANIF     string
	Interval  time.Duration
	NftBinary string
	Addr      string
}

var reconMu sync.Mutex

func loadCfg() cfgAgent {
	ag := config.LoadAgent()
	interval := 15 * time.Second
	if v := os.Getenv("PGW_AGENT_RECONCILE"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			interval = d
		}
	}
	apiBase := os.Getenv("PGW_API_BASE")
	if apiBase == "" {
		apiBase = "http://127.0.0.1:8080"
	}
	nft := "/usr/sbin/nft"
	if _, err := os.Stat(nft); err != nil {
		nft = "nft"
	}
	return cfgAgent{
		APIBase:   strings.TrimRight(apiBase, "/"),
		LANIF:     ag.LANIF,
		WANIF:     ag.WANIF,
		Interval:  interval,
		NftBinary: nft,
		Addr:      ag.Addr,
	}
}

func main() {
	cfg := loadCfg()

	http.HandleFunc("/agent/reconcile", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodPost, http.MethodHead:
			if r.Method != http.MethodHead {
				if err := reconcile(cfg); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				_, _ = w.Write([]byte("ok"))
				return
			}
			// HEAD: chỉ trả status
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})


	// tick định kỳ
	go func() {
		t := time.NewTicker(cfg.Interval)
		defer t.Stop()
		for {
			if err := reconcile(cfg); err != nil {
				logging.Error.Println("periodic reconcile error:", err)
			}
			<-t.C
		}
	}()

	logging.Info.Printf("pgw-agent listening on %s (WAN=%s LAN=%s) API=%s every=%s\n",
		cfg.Addr, cfg.WANIF, cfg.LANIF, cfg.APIBase, cfg.Interval)

	if err := http.ListenAndServe(cfg.Addr, nil); err != nil {
		logging.Error.Println(err)
		os.Exit(1)
	}
}

func reconcile(cfg cfgAgent) error {
	reconMu.Lock()
	defer reconMu.Unlock()

	// Xoá bảng cũ (nếu có) bằng lệnh riêng, bỏ qua lỗi nếu chưa tồn tại
	_ = runCmdIgnoreErr(cfg.NftBinary, "delete", "table", "ip", "pgw")
	_ = runCmdIgnoreErr(cfg.NftBinary, "delete", "table", "inet", "pgw_filter")

	mvs, err := fetchMappings(cfg.APIBase)
	if err != nil {
		return fmt.Errorf("fetch mappings: %w", err)
	}
	script := renderRules(cfg, mvs)

	// Add mới tất cả trong 1 shot
	// Determine the set of mapping IDs that were considered (have valid local port)
	type item struct{ id string; port int }
	selected := []item{}
	for _, mv := range mvs {
		if mv.LocalRedirectPort > 0 {
			selected = append(selected, item{id: mv.ID, port: mv.LocalRedirectPort})
		}
	}

	if err := runCmdWithInput(cfg.NftBinary, script); err != nil {
		// mark failed for all selected mappings
		for _, it := range selected {
			_ = updateMappingState(cfg.APIBase, it.id, "FAILED", it.port)
		}
		return fmt.Errorf("nft apply: %w", err)
	}
	// success → mark applied
	for _, it := range selected {
		_ = updateMappingState(cfg.APIBase, it.id, "APPLIED", it.port)
	}
	return nil
}

func fetchMappings(apiBase string) ([]types.MappingView, error) {
	req, _ := http.NewRequest(http.MethodGet, apiBase+"/v1/mappings", nil)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("api %s: %s", resp.Status, string(b))
	}
	var mvs []types.MappingView
	if err := json.NewDecoder(resp.Body).Decode(&mvs); err != nil {
		return nil, err
	}
	return mvs, nil
}

type rule struct {
	Prefix string // "192.168.2.0/24"
	Bits   int
	Port   int
}

// renderRules: dedup + loại prefix con nếu đã có prefix cha (cùng port).
// Sinh script chỉ "add ..." (không có delete), vì delete đã chạy trước.
func renderRules(cfg cfgAgent, mvs []types.MappingView) string {
	// Thu thập và dedup theo (prefix|port)
	seen := map[string]bool{}
	all := []rule{}
	for _, mv := range mvs {
		pfx, bits, ok := parseIPv4Prefix(mv.Client.IPCidr)
		if !ok || mv.LocalRedirectPort <= 0 {
			continue
		}
		key := fmt.Sprintf("%s|%d", pfx, mv.LocalRedirectPort)
		if !seen[key] {
			seen[key] = true
			all = append(all, rule{Prefix: pfx, Bits: bits, Port: mv.LocalRedirectPort})
		}
	}

	// Nhóm theo port rồi bỏ prefix con
	group := map[int][]rule{}
	for _, r := range all {
		group[r.Port] = append(group[r.Port], r)
	}

	pruned := []rule{}
	for port, lst := range group {
		// Xét từ cha -> con (/0 → /32)
		sort.Slice(lst, func(i, j int) bool {
			if lst[i].Bits != lst[j].Bits {
				return lst[i].Bits < lst[j].Bits
			}
			return lst[i].Prefix < lst[j].Prefix
		})
		kept := []netip.Prefix{}
		for _, r := range lst {
			p, _ := netip.ParsePrefix(r.Prefix)
			covered := false
			for _, k := range kept {
				if k.Bits() <= p.Bits() && k.Contains(p.Addr()) {
					covered = true
					break
				}
			}
			if !covered {
				kept = append(kept, p)
				pruned = append(pruned, rule{Prefix: r.Prefix, Bits: r.Bits, Port: port})
			}
		}
	}

	// Render ổn định (port ↑, bits ↓)
	sort.Slice(pruned, func(i, j int) bool {
		if pruned[i].Port != pruned[j].Port {
			return pruned[i].Port < pruned[j].Port
		}
		if pruned[i].Bits != pruned[j].Bits {
			return pruned[i].Bits > pruned[j].Bits
		}
		return pruned[i].Prefix < pruned[j].Prefix
	})

	var b strings.Builder

	// NAT
	fmt.Fprintln(&b, "add table ip pgw")
	fmt.Fprintln(&b, "add chain ip pgw prerouting { type nat hook prerouting priority dstnat; policy accept; }")
	for _, r := range pruned {
		fmt.Fprintf(&b, "add rule ip pgw prerouting iifname \"%s\" ip saddr %s tcp dport {80,443} redirect to :%d\n", cfg.LANIF, r.Prefix, r.Port)
	}

	// FILTER
	fmt.Fprintln(&b, "add table inet pgw_filter")
	fmt.Fprintln(&b, "add chain inet pgw_filter forward { type filter hook forward priority 0; policy accept; }")
	fmt.Fprintln(&b, "add rule inet pgw_filter forward ct state established,related accept")
	for _, r := range pruned {
		fmt.Fprintf(&b, "add rule inet pgw_filter forward ip saddr %s oifname \"%s\" drop\n", r.Prefix, cfg.WANIF)
		fmt.Fprintf(&b, "add rule inet pgw_filter forward ip saddr %s meta l4proto udp drop\n", r.Prefix)
	}
	fmt.Fprintln(&b, "add chain inet pgw_filter input { type filter hook input priority 0; policy accept; }")
	for _, r := range pruned {
		fmt.Fprintf(&b, "add rule inet pgw_filter input iifname \"%s\" ip saddr %s udp dport 53 accept\n", cfg.LANIF, r.Prefix)
		fmt.Fprintf(&b, "add rule inet pgw_filter input iifname \"%s\" ip saddr %s tcp dport 53 accept\n", cfg.LANIF, r.Prefix)
		fmt.Fprintf(&b, "add rule inet pgw_filter input iifname \"%s\" ip saddr %s tcp dport %d accept\n", cfg.LANIF, r.Prefix, r.Port)
	}

	return b.String()
}

func parseIPv4Prefix(cidr string) (string, int, bool) {
	pfx, err := netip.ParsePrefix(cidr)
	if err != nil || !pfx.Addr().Is4() {
		return "", 0, false
	}
	pfx = pfx.Masked()
	return pfx.String(), pfx.Bits(), true
}

func runCmdIgnoreErr(bin string, args ...string) error {
	cmd := exec.Command(bin, args...)
	_ = cmd.Run()
	return nil
}

func runCmdWithInput(bin string, script string) error {
	cmd := exec.Command(bin, "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("nft -f - failed: %v; output=%s", err, out.String())
	}
	return nil
}

// updateMappingState calls API to set mapping state.
func updateMappingState(apiBase, id, state string, port int) error {
	body := struct{
		State string `json:"state"`
		LocalPort int `json:"local_redirect_port"`
	}{State: state, LocalPort: port}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, strings.TrimRight(apiBase, "/")+"/v1/mappings/state/"+id,  bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		bb, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("api %s: %s", resp.Status, string(bb))
	}
	return nil
}
