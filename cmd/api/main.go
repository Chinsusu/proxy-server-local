
package main

import (
	"encoding/json"
	"net/http"
	"os"
	"github.com/Chinsusu/proxy-server-local/pkg/config"
	"github.com/Chinsusu/proxy-server-local/pkg/logging"
	"github.com/Chinsusu/proxy-server-local/pkg/store"
	"github.com/Chinsusu/proxy-server-local/pkg/types"
	"github.com/Chinsusu/proxy-server-local/pkg/httpx"
)

func main() {
	cfg := config.LoadAPI()
	st := store.NewMemory()

	http.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK); w.Write([]byte("ok"))
	})

	http.HandleFunc("/v1/proxies", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			httpx.JSON(w, 200, st.ListProxies())
		case http.MethodPost:
			var p types.Proxy
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil { httpx.JSON(w, 400, map[string]string{"error":"bad json"}); return }
			p = st.CreateProxy(p)
			httpx.JSON(w, 201, p)
		default:
			w.WriteHeader(405)
		}
	})

	http.HandleFunc("/v1/clients", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			httpx.JSON(w, 200, st.ListClients())
		case http.MethodPost:
			var c types.Client
			if err := json.NewDecoder(r.Body).Decode(&c); err != nil { httpx.JSON(w, 400, map[string]string{"error":"bad json"}); return }
			c = st.CreateClient(c)
			httpx.JSON(w, 201, c)
		default:
			w.WriteHeader(405)
		}
	})

	http.HandleFunc("/v1/mappings", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			httpx.JSON(w, 200, st.ListMappings())
		case http.MethodPost:
			var m types.Mapping
			if err := json.NewDecoder(r.Body).Decode(&m); err != nil { httpx.JSON(w, 400, map[string]string{"error":"bad json"}); return }
			mv, ok := st.CreateMapping(m); if !ok { httpx.JSON(w, 400, map[string]string{"error":"invalid client/proxy"}); return }
			httpx.JSON(w, 201, mv)
		default:
			w.WriteHeader(405)
		}
	})

	logging.Info.Printf("pgw-api listening on %s\n", cfg.Addr)
	if err := http.ListenAndServe(cfg.Addr, nil); err != nil {
		logging.Error.Println(err); os.Exit(1)
	}
}
