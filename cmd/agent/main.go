
package main

import (
	"net/http"
	"os"
	"github.com/Chinsusu/proxy-server-local/pkg/config"
	"github.com/Chinsusu/proxy-server-local/pkg/logging"
)

func main() {
	cfg := config.LoadAgent()
	http.HandleFunc("/agent/reconcile", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("reconcile triggered (skeleton)"))
	})
	logging.Info.Printf("pgw-agent listening on %s (WAN=%s LAN=%s)\n", cfg.Addr, cfg.WANIF, cfg.LANIF)
	if err := http.ListenAndServe(cfg.Addr, nil); err != nil { logging.Error.Println(err); os.Exit(1) }
}
