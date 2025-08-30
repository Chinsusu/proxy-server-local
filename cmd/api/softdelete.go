//go:build pgw_softdelete
// +build pgw_softdelete

package main


import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/Chinsusu/proxy-server-local/pkg/types"
)

var (
	deletedMu  sync.RWMutex
	deletedIDs = map[string]struct{}{}
)

func apiBaseURL() string {
	addr := os.Getenv("PGW_API_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	if strings.HasPrefix(addr, ":") {
		return "http://127.0.0.1" + addr
	}
	// fallback
	return "http://" + addr
}

func init() {
	http.HandleFunc("/v1/mappings/active", handleActiveMappings)
	http.HandleFunc("/v1/mappings/", handleMappingItem) // /v1/mappings/{id}
}

func handleActiveMappings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	resp, err := http.Get(apiBaseURL() + "/v1/mappings")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		http.Error(w, string(b), resp.StatusCode)
		return
	}
	var mvs []types.MappingView
	if err := json.NewDecoder(resp.Body).Decode(&mvs); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	deletedMu.RLock()
	out := make([]types.MappingView, 0, len(mvs))
	for _, mv := range mvs {
		if _, gone := deletedIDs[mv.ID]; !gone {
			out = append(out, mv)
		}
	}
	deletedMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func handleMappingItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.NotFound(w, r)
		return
	}
	// path: /v1/mappings/{id}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 3 || parts[0] != "v1" || parts[1] != "mappings" {
		http.NotFound(w, r)
		return
	}
	id := parts[2]
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	deletedMu.Lock()
	deletedIDs[id] = struct{}{}
	deletedMu.Unlock()
	w.WriteHeader(http.StatusNoContent)
	fmt.Fprint(w, "")
}