cat > cmd/ui/main.go <<'EOF'
package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/Chinsusu/proxy-server-local/pkg/config"
	"github.com/Chinsusu/proxy-server-local/pkg/logging"
)

const index = `<!doctype html>
<html><head><meta charset="utf-8"><title>PGW UI (Skeleton)</title></head>
<body style="font-family:system-ui;margin:2rem">
<h1>Proxy Gateway Manager — UI (Skeleton)</h1>
<p>Tabs (demo): <a href="/dashboard">Dashboard</a> | <a href="/mappings">Proxy Mappings</a> | <a href="/config">Configuration</a> | <a href="/auth">Authentication</a></p>
<p>Try API: <code>curl http://127.0.0.1:8080/v1/health</code></p>
</body></html>`

func main() {
	cfg := config.LoadUI()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, index) })
	logging.Info.Printf("pgw-ui listening on %s\n", cfg.Addr)
	if err := http.ListenAndServe(cfg.Addr, nil); err != nil {
		logging.Error.Println(err)
		os.Exit(1)
	}
}
EOF

# format + build lại
gofmt -w cmd/ui/main.go
export PATH=/usr/local/go/bin:/snap/bin:$PATH
go mod tidy
make build

# chạy UI
make run-ui   # UI skeleton lắng nghe :8081
