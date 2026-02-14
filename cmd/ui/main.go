package main

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Chinsusu/proxy-server-local/pkg/config"
	"log"
	"encoding/json"
	"time"
	"github.com/Chinsusu/proxy-server-local/pkg/auth"
)

var (
	baseAPI   string
	jwtSecret string
	baseAgent string
	webDir    string
)

func main() {
	cfg := config.LoadUI()
	addr := cfg.Addr
	if strings.TrimSpace(addr) == "" {
		addr = ":8081"
	}

	// Get upstream services from ENV
	baseAPI = strings.TrimSpace(os.Getenv("PGW_UI_API"))
	if baseAPI == "" {
		baseAPI = "http://127.0.0.1:8080"
	}

	baseAgent = strings.TrimSpace(os.Getenv("PGW_UI_AGENT"))
	if baseAgent == "" {
		baseAgent = "http://127.0.0.1:9090/agent"
	}

	jwtSecret = cfg.JWTSecret

	// Determine web directory path
	webDir = "/usr/local/share/pgw/web"
	if _, err := os.Stat(webDir); os.IsNotExist(err) {
		// Fallback to embedded templates if web directory doesn't exist
		webDir = ""
	}

	// Setup routes
	http.HandleFunc("/", handleRoot)
	http.HandleFunc("/manage", handleManage)
	http.HandleFunc("/proxies", handleProxies)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/static/", handleStatic)

	// API proxy
	http.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		proxyRequest(w, r, "/api/", baseAPI)
	})

	// Agent proxy
	http.HandleFunc("/agent/", func(w http.ResponseWriter, r *http.Request) {
		proxyRequest(w, r, "/agent/", baseAgent)
	})

	server := &http.Server{Addr: addr}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
		sig := <-sigCh
		log.Printf("[INFO] received %s, shutting down...", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("[ERROR] shutdown: %v", err)
		}
	}()

	log.Printf("[INFO] pgw-ui listening on %s (API=%s, AGENT=%s)",
		addr, baseAPI, baseAgent)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[ERROR] Failed to start server: %v", err)
	}
}

func getCurrentDir() string {
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if !uiAuthorized(r) { http.Redirect(w, r, "/login", http.StatusFound); return }
	serveHTML(w, r, "dashboard.html")
}

func handleProxies(w http.ResponseWriter, r *http.Request) {
	if !uiAuthorized(r) { http.Redirect(w, r, "/login", http.StatusFound); return }
	serveHTML(w, r, "proxies.html")
}

func handleManage(w http.ResponseWriter, r *http.Request) {
	if !uiAuthorized(r) { http.Redirect(w, r, "/login", http.StatusFound); return }
	serveHTML(w, r, "manage.html")
}

func handleStatic(w http.ResponseWriter, r *http.Request) {
	// Remove /static/ prefix
	filePath := strings.TrimPrefix(r.URL.Path, "/static/")

	if webDir != "" {
		// Serve from file system
		fullPath := filepath.Join(webDir, "static", filePath)

		// Security check: ensure path is within webDir
		if !strings.HasPrefix(filepath.Clean(fullPath), filepath.Clean(webDir)) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Set appropriate content type
		switch filepath.Ext(filePath) {
		case ".css":
			w.Header().Set("Content-Type", "text/css")
		case ".js":
			w.Header().Set("Content-Type", "application/javascript")
		case ".json":
			w.Header().Set("Content-Type", "application/json")
		}

		http.ServeFile(w, r, fullPath)
	} else {
		// Serve embedded files
		serveEmbeddedStatic(w, r, filePath)
	}
}

func serveHTML(w http.ResponseWriter, r *http.Request, filename string) {
	if webDir != "" {
		// Serve from file system
		fullPath := filepath.Join(webDir, filename)

		if _, err := os.Stat(fullPath); err == nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			http.ServeFile(w, r, fullPath)
			return
		}
	}

	// Fallback to embedded templates
	serveEmbeddedHTML(w, r, filename)
}

func serveEmbeddedHTML(w http.ResponseWriter, r *http.Request, filename string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	switch filename {

	case "dashboard.html":
		io.WriteString(w, embeddedDashboard)
	case "manage.html":
		io.WriteString(w, embeddedManage)
    case "proxies.html":
        io.WriteString(w, embeddedProxies)
	default:
		http.NotFound(w, r)
	}
}

func serveEmbeddedStatic(w http.ResponseWriter, r *http.Request, filename string) {
	switch filename {
	case "styles.css":
		w.Header().Set("Content-Type", "text/css")
		io.WriteString(w, embeddedCSS)
	case "app.js":
		w.Header().Set("Content-Type", "application/javascript")
		data, err := base64.StdEncoding.DecodeString(embeddedJSBase64)
		if err != nil {
			http.Error(w, "embedded js decode error", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(data)
	default:
		http.NotFound(w, r)
	}
}

func proxyRequest(w http.ResponseWriter, r *http.Request, prefix, upstream string) {
	u, err := url.Parse(upstream)
	if err != nil {
		http.Error(w, "Invalid upstream URL", http.StatusInternalServerError)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, prefix)
	targetURL := strings.TrimSuffix(u.String(), "/") + "/" + strings.TrimPrefix(path, "/")
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusBadGateway)
		return
	}
	req.Header = r.Header.Clone()
	if req.Header.Get("Authorization") == "" {
		if c, err := r.Cookie("pgw_jwt"); err == nil && c.Value != "" {
			req.Header.Set("Authorization", "Bearer "+c.Value)
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "Upstream unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}



// ----- UI auth -----
func uiAuthorized(r *http.Request) bool {
    c, err := r.Cookie("pgw_jwt")
    if err != nil || c.Value == "" { return false }
    cl, err := auth.ParseJWT(c.Value, jwtSecret)
    if err != nil { return false }
    return cl != nil && cl.ExpiresAt != nil && cl.ExpiresAt.Time.After(time.Now())
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodGet:
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        io.WriteString(w, embeddedLogin)
    case http.MethodPost:
        var reqBody struct{ Username, Password string }
        if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil { http.Error(w, "bad json", 400); return }
        api := strings.TrimSuffix(baseAPI, "/") + "/v1/auth/login"
        jr, _ := http.NewRequest(http.MethodPost, api, strings.NewReader(string(mustJSON(reqBody))))
        jr.Header.Set("Content-Type", "application/json")
        resp, err := http.DefaultClient.Do(jr)
        if err != nil { http.Error(w, "upstream", 502); return }
        defer resp.Body.Close()
        if resp.StatusCode != 200 { w.WriteHeader(resp.StatusCode); io.Copy(w, resp.Body); return }
        var out struct{ Token string `json:"token"` }
        if err := json.NewDecoder(resp.Body).Decode(&out); err != nil { http.Error(w, "bad upstream", 502); return }
        http.SetCookie(w, &http.Cookie{Name: "pgw_jwt", Value: out.Token, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
        w.WriteHeader(204)
    default:
        w.WriteHeader(405)
    }
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
    http.SetCookie(w, &http.Cookie{Name: "pgw_jwt", Value: "", Path: "/", Expires: time.Unix(0,0), MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
    http.Redirect(w, r, "/login", http.StatusFound)
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

const embeddedLogin = `
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>PGW Login</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"></head>
<body class="bg-dark text-light"><div class="container py-5" style="max-width:480px">
  <h3 class="mb-3">PGW Login</h3>
  <div id="alert" class="alert alert-danger d-none"></div>
  <form id="f" class="card card-body bg-secondary-subtle">
    <div class="mb-3"><label class="form-label">Username</label><input class="form-control" name="u" required></div>
    <div class="mb-3"><label class="form-label">Password</label><input type="password" class="form-control" name="p" required></div>
    <button class="btn btn-primary w-100" type="submit">Sign in</button>
  </form>
</div>
<script>
const f=document.getElementById("f");
f.addEventListener('submit', async (e)=>{e.preventDefault();
  const b={username:f.u.value,password:f.p.value};
  const r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});
  if(r.status===204){window.location.replace('/');return;}
  const t=await r.text(); const a=document.getElementById('alert'); a.classList.remove('d-none'); a.textContent=t||'Login failed';
});
</script>
</body></html>`

// Embedded templates (fallback when web directory doesn't exist)
const embeddedDashboard = `
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PGW Dashboard</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="/static/styles.css?v=1756567003">
</head>
<body>
  <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
    <div class="container">
      <a class="navbar-brand" href="/">🔒 Proxy Gateway</a>
      <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#pgwNav" aria-controls="pgwNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="pgwNav">
        <ul class="navbar-nav ms-auto">
          <li class="nav-item"><a class="nav-link active" href="/">Dashboard</a></li>
          <li class="nav-item"><a class="nav-link" href="/proxies">Proxies</a></li>
          <li class="nav-item"><a class="nav-link" href="/manage">Mappings</a></li>
        </ul>
      </div>
    </div>
  </nav>

  <div class="container py-4">
    <div id="alerts"></div>

    <div id="loading-indicator" class="d-flex align-items-center mb-3">
      <div class="spinner-border text-primary me-2" role="status" style="width:1.5rem;height:1.5rem;"><span class="visually-hidden">Loading...</span></div>
      <span>Loading...</span>
    </div>

    <div class="row g-3 mb-4">
      <div class="col-12 col-md-3">
        <div class="card text-center">
          <div class="card-body">
            <div class="fs-3 fw-bold text-primary" id="stat-proxies">—</div>
            <div class="text-muted">Total Proxies</div>
          </div>
        </div>
      </div>
      <div class="col-12 col-md-3">
        <div class="card text-center">
          <div class="card-body">
            <div class="fs-3 fw-bold text-success" id="stat-proxies-ok">—</div>
            <div class="text-muted">Healthy Proxies</div>
          </div>
        </div>
      </div>
      <div class="col-12 col-md-3">
        <div class="card text-center">
          <div class="card-body">
            <div class="fs-3 fw-bold text-primary" id="stat-mappings">—</div>
            <div class="text-muted">Active Mappings</div>
          </div>
        </div>
      </div>
      <div class="col-12 col-md-3">
        <div class="card text-center">
          <div class="card-body">
            <div class="fs-5 fw-semibold" id="last-refresh">—</div>
            <div class="text-muted">Last Updated</div>
          </div>
        </div>
      </div>
    </div>

    <div class="card mb-4">
      <div class="card-header">
        <h5 class="mb-0">System Overview</h5>
      </div>
      <div class="card-body">
        <div class="row g-2">
          <div class="col-12 col-md-4 d-flex justify-content-between">
            <span class="fw-semibold">API Service</span>
            <span class="badge text-bg-secondary" id="api-status">Checking...</span>
          </div>
          <div class="col-12 col-md-4 d-flex justify-content-between">
            <span class="fw-semibold">Agent Service</span>
            <span class="badge text-bg-secondary" id="agent-status">Checking...</span>
          </div>
          <div class="col-12 col-md-4 d-flex justify-content-between">
            <span class="fw-semibold">Forwarder Service</span>
            <span class="badge text-bg-secondary" id="fwd-status">Checking...</span>
          </div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-header d-flex justify-content-between align-items-center">
        <h5 class="mb-0">Status</h5>
      </div>
      <div class="table-responsive">
        <table class="table table-striped table-hover align-middle mb-0">
          <thead class="table-light">
            <tr>
              <th>Proxy</th>
              <th>Status</th>
              <th>Latency</th>
              <th>Exit IP</th>
              <th>Last Check</th>
            </tr>
          </thead>
          <tbody id="tbody-proxy-summary">
            <tr><td colspan="5" class="text-center">Loading...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script src="/static/app.js?v=1756567003"></script>
</body>
</html>`

// Embedded templates (fallback when web directory doesn't exist)
const embeddedManage = `
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PGW Mapping Management</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="/static/styles.css?v=1756567003">
</head>
<body>
  <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
    <div class="container">
      <a class="navbar-brand" href="/">🔒 Proxy Gateway</a>
      <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#pgwNav" aria-controls="pgwNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="pgwNav">
        <ul class="navbar-nav ms-auto">
          <li class="nav-item"><a class="nav-link" href="/">Dashboard</a></li>
          <li class="nav-item"><a class="nav-link" href="/proxies">Proxies</a></li>
          <li class="nav-item"><a class="nav-link active" href="/manage">Mappings</a></li>
        </ul>
      </div>
    </div>
  </nav>

  <div class="container py-4">
    <div id="alerts"></div>

    <div class="card mb-4">
      <div class="card-header">
        <h5 class="mb-0">Create Client-Proxy Mapping</h5>
      </div>
      <div class="card-body">
        <form id="form-mapping" class="row g-3 align-items-end">
          <div class="col-12 col-lg-3">
            <label class="form-label">Client IP Address</label>
            <input type="text" name="client_ip" class="form-control" placeholder="192.168.1.100" required>
          </div>
          <div class="col-12 col-lg-3">
            <label class="form-label">Proxy Server</label>
            <select name="proxy_id" id="select-proxy" class="form-select" required>
              <option value="">Select proxy server...</option>
            </select>
          </div>
          <div class="col-12 col-lg-3 d-grid d-md-block">
            <label class="form-label invisible">&nbsp;</label>
            <button type="submit" class="btn btn-primary btn-sm text-nowrap">Create Mapping</button>
          </div>
        </form>
      </div>
    </div>

    <div class="card">
      <div class="card-header d-flex justify-content-between align-items-center">
        <h5 class="mb-0">Active Client Mappings</h5>
        <span class="text-muted" id="mapping-count">— mappings</span>
      </div>
      <div class="table-responsive">
        <table class="table table-striped table-hover align-middle mb-0 mappings-table">
          <thead class="table-light">
            <tr>
              <th data-k="id" class="sortable">ID</th>
              <th data-k="client" class="sortable">Client IP/CIDR</th>
              <th data-k="proxy" class="sortable">Proxy Server</th>
              <th data-k="state" class="sortable">State</th>
              <th data-k="port" class="sortable">Local Port</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="tbody-mappings">
            <tr>
              <td colspan="6" class="text-center">Loading...</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script src="/static/app.js?v=1756567003"></script>
</body>
</html>`

const embeddedProxies = `
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PGW Proxy Management</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="/static/styles.css?v=1756567003">
</head>
<body>
  <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
    <div class="container">
      <a class="navbar-brand" href="/">🔒 Proxy Gateway</a>
      <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#pgwNav" aria-controls="pgwNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="pgwNav">
        <ul class="navbar-nav ms-auto">
          <li class="nav-item"><a class="nav-link" href="/">Dashboard</a></li>
          <li class="nav-item"><a class="nav-link active" href="/proxies">Proxies</a></li>
          <li class="nav-item"><a class="nav-link" href="/manage">Mappings</a></li>
        </ul>
      </div>
    </div>
  </nav>

  <div class="container py-4">
    <div id="alerts"></div>

    <div class="card mb-4">
      <div class="card-header">
        <h5 class="mb-0">Add New Proxy Server</h5>
      </div>
      <div class="card-body">
        <form id="form-proxy" class="row g-3 align-items-end">
          <div class="col-6 col-lg-2">
            <label class="form-label">Type</label>
            <select name="type" class="form-select" required>
              <option value="http">HTTP</option>
              <option value="https">HTTPS</option>
            </select>
          </div>
          <div class="col-12 col-lg-3">
            <label class="form-label">Host</label>
            <input type="text" name="host" class="form-control" placeholder="proxy.example.com" required>
          </div>
          <div class="col-6 col-lg-2">
            <label class="form-label">Port</label>
            <input type="number" name="port" class="form-control" placeholder="8080" required>
          </div>
          <div class="col-6 col-lg-2">
            <label class="form-label">Username</label>
            <input type="text" name="username" class="form-control" placeholder="Optional">
          </div>
          <div class="col-6 col-lg-2">
            <label class="form-label">Password</label>
            <input type="password" name="password" class="form-control" placeholder="Optional">
          </div>
          <div class="col-12 col-lg-1 d-grid">
            <label class="form-label invisible">&nbsp;</label>
            <button type="submit" class="btn btn-primary btn-sm text-nowrap">Add Proxy</button>
          </div>
        </form>

        <div class="row g-3 align-items-center mt-2">
          <div class="col-12 col-md-10">
            <label class="form-label">Bulk import (IP:PORT:USER:PASSWORD, one per line)</label>
            <textarea id="import-proxies" class="form-control" rows="4" placeholder="192.0.2.10:8080:alice:s3cret&#10;198.51.100.22:3128:bob:pass123"></textarea>
            <div class="form-text">Format fixed to HTTP proxies. Invalid lines will be skipped.</div>
          </div>
          <div class="col-12 col-lg-1 d-grid">
            <button id="btn-import-proxies" class="btn btn-secondary btn-sm text-nowrap">Import</button>
          </div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-header d-flex justify-content-between align-items-center">
        <h5 class="mb-0">Proxy Servers</h5>
        <span class="text-muted" id="proxy-count">— proxies</span>
      </div>
      <div class="table-responsive">
        <table class="table table-striped table-hover align-middle mb-0 proxies-table">
          <thead class="table-light">
            <tr>
              <th data-k="id" class="sortable">ID</th>
              <th data-k="type" class="sortable">Type</th>
              <th data-k="address" class="sortable">Address</th>
              <th data-k="status" class="sortable">Status</th>
              <th data-k="latency" class="sortable">Latency</th>
              <th data-k="exit" class="sortable">Exit IP</th>
              <th data-k="last" class="sortable">Last Check</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="tbody-proxies">
            <tr><td colspan="8" class="text-center">Loading...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script src="/static/app.js?v=1756567003"></script>
</body>
</html>`

// Embedded assets - minimal versions
const embeddedCSS = `
/* PGW minimal overrides for Bootstrap */
.sortable { cursor: pointer; }

#loading-indicator { display: none; align-items: center; gap: .5rem; }

/***** Utilities *****/
.text-muted { opacity: .8; }
.table-nowrap { white-space: nowrap; }

/* Keep alerts visible above content */
#alerts .alert { margin-bottom: .75rem; }

/* Overlay toast container to avoid layout shifts */
#alerts { position: fixed; top: 1rem; right: 1rem; z-index: 1080; display: flex; flex-direction: column; gap: .5rem; pointer-events: none; }
#alerts .toast { pointer-events: auto; }
`

const embeddedJSBase64 = `Y2xhc3MgUEdXTWFuYWdlciB7CiAgY29uc3RydWN0b3IoKSB7CiAgICB0aGlzLmFwaUJhc2UgPSAnL2FwaSc7CiAgICB0aGlzLmFnZW50QmFzZSA9ICcvYWdlbnQnOwogICAgdGhpcy5wcm94aWVzID0gW107CiAgICB0aGlzLmNsaWVudHMgPSBbXTsKICAgIHRoaXMubWFwcGluZ3MgPSBbXTsKICAgIHRoaXMubG9hZGluZyA9IGZhbHNlOwogICAgLy8gc29ydGluZyBzdGF0ZSAocGVyc2lzdGVkKQogICAgdGhpcy5wU29ydCA9ICdhZGRyZXNzJzsgdGhpcy5wQXNjID0gdHJ1ZTsKICAgIHRoaXMubVNvcnQgPSAnY2xpZW50JzsgdGhpcy5tQXNjID0gdHJ1ZTsKICAgIHRyeSB7CiAgICAgIGNvbnN0IHNwID0gSlNPTi5wYXJzZShsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgncGd3X3NvcnRfcDInKSB8fCAne30nKTsKICAgICAgaWYgKHNwICYmIHNwLmspIHsgdGhpcy5wU29ydCA9IHNwLms7IHRoaXMucEFzYyA9ICEhc3AuYTsgfQogICAgICBjb25zdCBzbSA9IEpTT04ucGFyc2UobG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Bnd19zb3J0X20yJykgfHwgJ3t9Jyk7CiAgICAgIGlmIChzbSAmJiBzbS5rKSB7IHRoaXMubVNvcnQgPSBzbS5rOyB0aGlzLm1Bc2MgPSAhIXNtLmE7IH0KICAgIH0gY2F0Y2ggKF8pIHsgfQoKICAgIHRoaXMuaW5pdCgpOwogIH0KCiAgaW5pdCgpIHsKICAgIHRoaXMuYmluZEV2ZW50cygpOwogICAgdGhpcy5sb2FkRGF0YSgpOwoKICAgIC8vIEF1dG8gcmVmcmVzaCBldmVyeSAzMCBzZWNvbmRzCiAgICBzZXRJbnRlcnZhbCgoKSA9PiB0aGlzLmxvYWREYXRhKCksIDMwMDAwKTsKICB9CgogIGJpbmRFdmVudHMoKSB7CiAgICAvLyBSZWZyZXNoIGJ1dHRvbgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2J0bi1yZWZyZXNoJyk/LmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogICAgICB0aGlzLmxvYWREYXRhKCk7CiAgICB9KTsKCiAgICAvLyBIZWFsdGggY2hlY2sgYWxsIHByb3hpZXMKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdidG4taGVhbHRoLWFsbCcpPy5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHsKICAgICAgdGhpcy5oZWFsdGhDaGVja0FsbCgpOwogICAgfSk7CgogICAgLy8gUmVjb25jaWxlIHJ1bGVzCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYnRuLXJlY29uY2lsZScpPy5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHsKICAgICAgdGhpcy5yZWNvbmNpbGVSdWxlcygpOwogICAgfSk7CgogICAgLy8gQ3JlYXRlIHByb3h5IGZvcm0KICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdmb3JtLXByb3h5Jyk/LmFkZEV2ZW50TGlzdGVuZXIoJ3N1Ym1pdCcsIChlKSA9PiB7CiAgICAgIGUucHJldmVudERlZmF1bHQoKTsKICAgICAgdGhpcy5jcmVhdGVQcm94eSgpOwogICAgfSk7CgoKICAgIC8vIEltcG9ydCBwcm94aWVzIChidWxrKQogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1pbXBvcnQtcHJveGllcyIpPy5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7CiAgICAgIGUucHJldmVudERlZmF1bHQoKTsKICAgICAgdGhpcy5pbXBvcnRQcm94aWVzKCk7CiAgICB9KTsKICAgIC8vIENyZWF0ZSBtYXBwaW5nIGZvcm0KICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdmb3JtLW1hcHBpbmcnKT8uYWRkRXZlbnRMaXN0ZW5lcignc3VibWl0JywgKGUpID0+IHsKICAgICAgZS5wcmV2ZW50RGVmYXVsdCgpOwogICAgICB0aGlzLmNyZWF0ZU1hcHBpbmcoKTsKICAgIH0pOwogIH0KCiAgYXN5bmMgYXBpQ2FsbCh1cmwsIG9wdGlvbnMgPSB7fSkgewogICAgdHJ5IHsKICAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBmZXRjaCh1cmwsIHsKICAgICAgICBoZWFkZXJzOiB7CiAgICAgICAgICAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nLAogICAgICAgICAgLi4ub3B0aW9ucy5oZWFkZXJzCiAgICAgICAgfSwKICAgICAgICAuLi5vcHRpb25zCiAgICAgIH0pOwoKICAgICAgaWYgKCFyZXNwb25zZS5vaykgewogICAgICAgIHRocm93IG5ldyBFcnJvcihgSFRUUCAke3Jlc3BvbnNlLnN0YXR1c306ICR7cmVzcG9uc2Uuc3RhdHVzVGV4dH1gKTsKICAgICAgfQoKICAgICAgaWYgKHJlc3BvbnNlLnN0YXR1cyA9PT0gMjA0KSB7CiAgICAgICAgcmV0dXJuIG51bGw7CiAgICAgIH0KCiAgICAgIHJldHVybiBhd2FpdCByZXNwb25zZS5qc29uKCk7CiAgICB9IGNhdGNoIChlcnJvcikgewogICAgICBjb25zb2xlLmVycm9yKCdBUEkgY2FsbCBmYWlsZWQ6JywgZXJyb3IpOwogICAgICB0aGlzLnNob3dBbGVydCgnQVBJIGNhbGwgZmFpbGVkOiAnICsgZXJyb3IubWVzc2FnZSwgJ2RhbmdlcicpOwogICAgICB0aHJvdyBlcnJvcjsKICAgIH0KICB9CgogIGFzeW5jIGxvYWREYXRhKCkgewogICAgaWYgKHRoaXMubG9hZGluZykgcmV0dXJuOwoKICAgIHRoaXMubG9hZGluZyA9IHRydWU7CiAgICBsZXQgX3NwaW5uZXJUTyA9IHNldFRpbWVvdXQoKCkgPT4gdGhpcy5zaG93TG9hZGluZyh0cnVlKSwgNzAwKTsKCiAgICB0cnkgewogICAgICBjb25zdCBbcHJveGllcywgY2xpZW50cywgbWFwcGluZ3NdID0gYXdhaXQgUHJvbWlzZS5hbGwoWwogICAgICAgIHRoaXMuYXBpQ2FsbChgJHt0aGlzLmFwaUJhc2V9L3YxL3Byb3hpZXNgKSwKICAgICAgICB0aGlzLmFwaUNhbGwoYCR7dGhpcy5hcGlCYXNlfS92MS9jbGllbnRzYCksCiAgICAgICAgdGhpcy5hcGlDYWxsKGAke3RoaXMuYXBpQmFzZX0vdjEvbWFwcGluZ3MvYWN0aXZlYCkKICAgICAgXSk7CgogICAgICB0aGlzLnByb3hpZXMgPSBwcm94aWVzIHx8IFtdOwogICAgICB0aGlzLmNsaWVudHMgPSBjbGllbnRzIHx8IFtdOwogICAgICB0aGlzLm1hcHBpbmdzID0gbWFwcGluZ3MgfHwgW107CgogICAgICB0aGlzLnJlbmRlclN0YXRzKCk7CiAgICAgIHRoaXMucmVuZGVyUHJveGllcygpOwogICAgICB0aGlzLnJlbmRlclByb3h5U3VtbWFyeSgpOwogICAgICB0aGlzLnJlbmRlck1hcHBpbmdzKCk7CiAgICAgIHRoaXMucmVuZGVyQ2xpZW50cygpOwogICAgICB0aGlzLnVwZGF0ZUNvdW50cygpOwogICAgICB0aGlzLnVwZGF0ZUxhc3RSZWZyZXNoKCk7CiAgICAgIHRoaXMuY2hlY2tTZXJ2aWNlcygpOwoKICAgIH0gY2F0Y2ggKGVycm9yKSB7CiAgICAgIGNvbnNvbGUuZXJyb3IoJ0ZhaWxlZCB0byBsb2FkIGRhdGE6JywgZXJyb3IpOwogICAgfSBmaW5hbGx5IHsKICAgICAgdGhpcy5sb2FkaW5nID0gZmFsc2U7CiAgICAgIGNsZWFyVGltZW91dChfc3Bpbm5lclRPKTsKICAgICAgdGhpcy5zaG93TG9hZGluZyhmYWxzZSk7CiAgICB9CiAgfQoKICBhc3luYyBjaGVja1NlcnZpY2VzKCkgewogICAgLy8gQVBJIGhlYWx0aAogICAgY29uc3QgYXBpRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYXBpLXN0YXR1cycpOwogICAgaWYgKGFwaUVsKSB7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgciA9IGF3YWl0IGZldGNoKGAke3RoaXMuYXBpQmFzZX0vdjEvaGVhbHRoYCwgeyBtZXRob2Q6ICdHRVQnIH0pOwogICAgICAgIGlmIChyLm9rKSB7CiAgICAgICAgICBhcGlFbC50ZXh0Q29udGVudCA9ICdSdW5uaW5nJzsKICAgICAgICAgIGFwaUVsLmNsYXNzTmFtZSA9ICdiYWRnZSB0ZXh0LWJnLXN1Y2Nlc3MnOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICBhcGlFbC50ZXh0Q29udGVudCA9ICdFcnJvcic7CiAgICAgICAgICBhcGlFbC5jbGFzc05hbWUgPSAnYmFkZ2UgdGV4dC1iZy13YXJuaW5nJzsKICAgICAgICB9CiAgICAgIH0gY2F0Y2ggewogICAgICAgIGFwaUVsLnRleHRDb250ZW50ID0gJ0Rvd24nOwogICAgICAgIGFwaUVsLmNsYXNzTmFtZSA9ICdiYWRnZSB0ZXh0LWJnLWRhbmdlcic7CiAgICAgIH0KICAgIH0KCiAgICAvLyBBZ2VudCBoZWFsdGgKICAgIGNvbnN0IGFnZW50RWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYWdlbnQtc3RhdHVzJyk7CiAgICBpZiAoYWdlbnRFbCkgewogICAgICB0cnkgewogICAgICAgIGNvbnN0IHIgPSBhd2FpdCBmZXRjaChgJHt0aGlzLmFnZW50QmFzZX0vaGVhbHRoYCwgeyBtZXRob2Q6ICdIRUFEJyB9KTsKICAgICAgICBpZiAoci5vaykgewogICAgICAgICAgYWdlbnRFbC50ZXh0Q29udGVudCA9ICdSdW5uaW5nJzsKICAgICAgICAgIGFnZW50RWwuY2xhc3NOYW1lID0gJ2JhZGdlIHRleHQtYmctc3VjY2Vzcyc7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIGFnZW50RWwudGV4dENvbnRlbnQgPSAnRXJyb3InOwogICAgICAgICAgYWdlbnRFbC5jbGFzc05hbWUgPSAnYmFkZ2UgdGV4dC1iZy13YXJuaW5nJzsKICAgICAgICB9CiAgICAgIH0gY2F0Y2ggewogICAgICAgIGFnZW50RWwudGV4dENvbnRlbnQgPSAnRG93bic7CiAgICAgICAgYWdlbnRFbC5jbGFzc05hbWUgPSAnYmFkZ2UgdGV4dC1iZy1kYW5nZXInOwogICAgICB9CiAgICB9CgogICAgLy8gRm9yd2FyZGVyIHN0YXR1czogaW5mZXJyZWQgZnJvbSBhcHBsaWVkIG1hcHBpbmdzCiAgICBjb25zdCBmd2RFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdmd2Qtc3RhdHVzJyk7CiAgICBpZiAoZndkRWwpIHsKICAgICAgY29uc3QgYXBwbGllZCA9ICh0aGlzLm1hcHBpbmdzIHx8IFtdKS5maWx0ZXIobSA9PiBtLnN0YXRlID09PSAnQVBQTElFRCcpLmxlbmd0aDsKICAgICAgaWYgKGFwcGxpZWQgPiAwKSB7CiAgICAgICAgZndkRWwudGV4dENvbnRlbnQgPSBgJHthcHBsaWVkfSBhY3RpdmVgOwogICAgICAgIGZ3ZEVsLmNsYXNzTmFtZSA9ICdiYWRnZSB0ZXh0LWJnLXN1Y2Nlc3MnOwogICAgICB9IGVsc2UgaWYgKCh0aGlzLm1hcHBpbmdzIHx8IFtdKS5sZW5ndGggPiAwKSB7CiAgICAgICAgZndkRWwudGV4dENvbnRlbnQgPSAnUGVuZGluZyc7CiAgICAgICAgZndkRWwuY2xhc3NOYW1lID0gJ2JhZGdlIHRleHQtYmctd2FybmluZyc7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgZndkRWwudGV4dENvbnRlbnQgPSAnTm8gbWFwcGluZ3MnOwogICAgICAgIGZ3ZEVsLmNsYXNzTmFtZSA9ICdiYWRnZSB0ZXh0LWJnLXNlY29uZGFyeSc7CiAgICAgIH0KICAgIH0KICB9CgogIHJlbmRlclN0YXRzKCkgewogICAgY29uc3Qgb2tQcm94aWVzID0gdGhpcy5wcm94aWVzLmZpbHRlcihwID0+IHAuc3RhdHVzID09PSAnT0snKS5sZW5ndGg7CiAgICBjb25zdCBhY3RpdmVNYXBwaW5ncyA9IHRoaXMubWFwcGluZ3MuZmlsdGVyKG0gPT4gbS5jbGllbnQ/LmVuYWJsZWQgJiYgbS5wcm94eT8uZW5hYmxlZCkubGVuZ3RoOwoKICAgIHRoaXMudXBkYXRlRWxlbWVudCgnc3RhdC1wcm94aWVzJywgdGhpcy5wcm94aWVzLmxlbmd0aCk7CiAgICB0aGlzLnVwZGF0ZUVsZW1lbnQoJ3N0YXQtcHJveGllcy1vaycsIG9rUHJveGllcyk7CiAgICB0aGlzLnVwZGF0ZUVsZW1lbnQoJ3N0YXQtY2xpZW50cycsIHRoaXMuY2xpZW50cy5sZW5ndGgpOwogICAgdGhpcy51cGRhdGVFbGVtZW50KCdzdGF0LW1hcHBpbmdzJywgYWN0aXZlTWFwcGluZ3MpOwogIH0KCiAgcmVuZGVyUHJveGllcygpIHsKICAgIGNvbnN0IHRib2R5ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3Rib2R5LXByb3hpZXMnKTsKICAgIGlmICghdGJvZHkpIHJldHVybjsKICAgIC8vIHNvcnQKICAgIGNvbnN0IGtleSA9IHRoaXMucFNvcnQsIGFzYyA9IHRoaXMucEFzYzsKICAgIGNvbnN0IHZhbCA9IChwKSA9PiB7CiAgICAgIGlmIChrZXkgPT09ICdpZCcpIHJldHVybiAocC5pZCB8fCAnJyk7CiAgICAgIGlmIChrZXkgPT09ICd0eXBlJykgcmV0dXJuIChwLnR5cGUgfHwgJycpOwogICAgICBpZiAoa2V5ID09PSAnYWRkcmVzcycpIHJldHVybiAoKHAuaG9zdCB8fCAnJykgKyAnOicgKyBwLnBvcnQpLnRvTG93ZXJDYXNlKCk7CiAgICAgIGlmIChrZXkgPT09ICdzdGF0dXMnKSByZXR1cm4gKHAuc3RhdHVzIHx8ICcnKTsKICAgICAgaWYgKGtleSA9PT0gJ2xhdGVuY3knKSByZXR1cm4gKHAubGF0ZW5jeV9tcyA9PSBudWxsID8gSW5maW5pdHkgOiBwLmxhdGVuY3lfbXMpOwogICAgICBpZiAoa2V5ID09PSAnZXhpdCcpIHJldHVybiAocC5leGl0X2lwIHx8ICcnKTsKICAgICAgaWYgKGtleSA9PT0gJ2xhc3QnKSByZXR1cm4gKHAubGFzdF9jaGVja2VkX2F0IHx8ICcnKTsKICAgICAgcmV0dXJuICgocC5ob3N0IHx8ICcnKSArICc6JyArIHAucG9ydCkudG9Mb3dlckNhc2UoKTsKICAgIH07CiAgICBjb25zdCBzb3J0ZWQgPSAodGhpcy5wcm94aWVzIHx8IFtdKS5zbGljZSgpLnNvcnQoKGEsIGIpID0+IHsgY29uc3QgdmEgPSB2YWwoYSksIHZiID0gdmFsKGIpOyBpZiAodmEgPCB2YikgcmV0dXJuIGFzYyA/IC0xIDogMTsgaWYgKHZhID4gdmIpIHJldHVybiBhc2MgPyAxIDogLTE7IHJldHVybiAwOyB9KTsKICAgIC8vIGhlYWRlciBpY29ucyArIGNsaWNrCiAgICBjb25zdCB0aGVhZCA9IHRib2R5LnBhcmVudEVsZW1lbnQ/LnF1ZXJ5U2VsZWN0b3IoJ3RoZWFkJyk7CiAgICBpZiAodGhlYWQpIHsKICAgICAgY29uc3QgYXJyb3cgPSBhc2MgPyAnIFxcdTI1QjInIDogJyBcXHUyNUJDJzsKICAgICAgdGhlYWQuaW5uZXJIVE1MID0gJzx0cj4nCiAgICAgICAgKyAnPHRoIGRhdGEtaz0iaWQiIGNsYXNzPSJzb3J0YWJsZSI+SUQnICsgKGtleSA9PT0gJ2lkJyA/IGFycm93IDogJycpICsgJzwvdGg+JwogICAgICAgICsgJzx0aCBkYXRhLWs9InR5cGUiIGNsYXNzPSJzb3J0YWJsZSI+VHlwZScgKyAoa2V5ID09PSAndHlwZScgPyBhcnJvdyA6ICcnKSArICc8L3RoPicKICAgICAgICArICc8dGggZGF0YS1rPSJhZGRyZXNzIiBjbGFzcz0ic29ydGFibGUiPkFkZHJlc3MnICsgKGtleSA9PT0gJ2FkZHJlc3MnID8gYXJyb3cgOiAnJykgKyAnPC90aD4nCiAgICAgICAgKyAnPHRoIGRhdGEtaz0ic3RhdHVzIiBjbGFzcz0ic29ydGFibGUiPlN0YXR1cycgKyAoa2V5ID09PSAnc3RhdHVzJyA/IGFycm93IDogJycpICsgJzwvdGg+JwogICAgICAgICsgJzx0aCBkYXRhLWs9ImxhdGVuY3kiIGNsYXNzPSJzb3J0YWJsZSI+TGF0ZW5jeScgKyAoa2V5ID09PSAnbGF0ZW5jeScgPyBhcnJvdyA6ICcnKSArICc8L3RoPicKICAgICAgICArICc8dGggZGF0YS1rPSJleGl0IiBjbGFzcz0ic29ydGFibGUiPkV4aXQgSVAnICsgKGtleSA9PT0gJ2V4aXQnID8gYXJyb3cgOiAnJykgKyAnPC90aD4nCiAgICAgICAgKyAnPHRoIGRhdGEtaz0ibGFzdCIgY2xhc3M9InNvcnRhYmxlIj5MYXN0IENoZWNrJyArIChrZXkgPT09ICdsYXN0JyA/IGFycm93IDogJycpICsgJzwvdGg+JwogICAgICAgICsgJzx0aD5BY3Rpb25zPC90aD4nCiAgICAgICAgKyAnPC90cj4nOwogICAgICB0aGVhZC5xdWVyeVNlbGVjdG9yQWxsKCd0aC5zb3J0YWJsZScpLmZvckVhY2goKHRoKSA9PiB7CiAgICAgICAgdGguc3R5bGUuY3Vyc29yID0gJ3BvaW50ZXInOyB0aC5vbmNsaWNrID0gKCkgPT4gewogICAgICAgICAgY29uc3QgayA9IHRoLmdldEF0dHJpYnV0ZSgnZGF0YS1rJyk7CiAgICAgICAgICBpZiAodGhpcy5wU29ydCA9PT0gaykgdGhpcy5wQXNjID0gIXRoaXMucEFzYzsgZWxzZSB7IHRoaXMucFNvcnQgPSBrOyB0aGlzLnBBc2MgPSB0cnVlOyB9CiAgICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgncGd3X3NvcnRfcDInLCBKU09OLnN0cmluZ2lmeSh7IGs6IHRoaXMucFNvcnQsIGE6IHRoaXMucEFzYyB9KSk7CiAgICAgICAgICB0aGlzLnJlbmRlclByb3hpZXMoKTsKICAgICAgICB9OwogICAgICB9KTsKICAgIH0KCiAgICB0Ym9keS5pbm5lckhUTUwgPSAnJzsKCiAgICBpZiAoc29ydGVkLmxlbmd0aCA9PT0gMCkgewogICAgICB0Ym9keS5pbm5lckhUTUwgPSAnPHRyPjx0ZCBjb2xzcGFuPSI4IiBjbGFzcz0idGV4dC1jZW50ZXIiPk5vIHByb3hpZXMgY29uZmlndXJlZDwvdGQ+PC90cj4nOwogICAgICByZXR1cm47CiAgICB9CgogICAgc29ydGVkLmZvckVhY2gocHJveHkgPT4gewogICAgICBjb25zdCByb3cgPSB0aGlzLmNyZWF0ZVByb3h5Um93KHByb3h5KTsKICAgICAgdGJvZHkuYXBwZW5kQ2hpbGQocm93KTsKICAgIH0pOwogIH0KCiAgcmVuZGVyUHJveHlTdW1tYXJ5KCkgewogICAgY29uc3QgdGJvZHkgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGJvZHktcHJveHktc3VtbWFyeScpOwogICAgaWYgKCF0Ym9keSkgcmV0dXJuOwoKICAgIHRib2R5LmlubmVySFRNTCA9ICcnOwoKICAgIGlmICh0aGlzLnByb3hpZXMubGVuZ3RoID09PSAwKSB7CiAgICAgIHRib2R5LmlubmVySFRNTCA9ICc8dHI+PHRkIGNvbHNwYW49IjUiIGNsYXNzPSJ0ZXh0LWNlbnRlciI+Tm8gcHJveGllcyBjb25maWd1cmVkPC90ZD48L3RyPic7CiAgICAgIHJldHVybjsKICAgIH0KCiAgICB0aGlzLnByb3hpZXMuZm9yRWFjaChwcm94eSA9PiB7CiAgICAgIGNvbnN0IHRyID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgndHInKTsKICAgICAgY29uc3Qgc3RhdHVzQmFkZ2UgPSB0aGlzLmNyZWF0ZVN0YXR1c0JhZGdlKHByb3h5LnN0YXR1cyk7CiAgICAgIGNvbnN0IGxhdGVuY3lCYWRnZSA9IHRoaXMuY3JlYXRlTGF0ZW5jeUJhZGdlKHByb3h5LmxhdGVuY3lfbXMpOwogICAgICBjb25zdCBsYXN0Q2hlY2tlZCA9IHByb3h5Lmxhc3RfY2hlY2tlZF9hdAogICAgICAgID8gbmV3IERhdGUocHJveHkubGFzdF9jaGVja2VkX2F0KS50b0xvY2FsZVRpbWVTdHJpbmcoKQogICAgICAgIDogJ+KAlCc7CgogICAgICB0ci5pbm5lckhUTUwgPSBgCiAgICAgICAgPHRkPiR7cHJveHkuaG9zdH06JHtwcm94eS5wb3J0fTwvdGQ+CiAgICAgICAgPHRkPiR7c3RhdHVzQmFkZ2V9PC90ZD4KICAgICAgICA8dGQ+JHtsYXRlbmN5QmFkZ2V9PC90ZD4KICAgICAgICA8dGQ+JHtwcm94eS5leGl0X2lwIHx8ICfigJQnfTwvdGQ+CiAgICAgICAgPHRkPiR7bGFzdENoZWNrZWR9PC90ZD4KICAgICAgYDsKICAgICAgdGJvZHkuYXBwZW5kQ2hpbGQodHIpOwogICAgfSk7CiAgfQoKICBjcmVhdGVQcm94eVJvdyhwcm94eSkgewogICAgY29uc3QgdHIgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCd0cicpOwoKICAgIGNvbnN0IHN0YXR1c0JhZGdlID0gdGhpcy5jcmVhdGVTdGF0dXNCYWRnZShwcm94eS5zdGF0dXMpOwogICAgY29uc3QgbGF0ZW5jeUJhZGdlID0gdGhpcy5jcmVhdGVMYXRlbmN5QmFkZ2UocHJveHkubGF0ZW5jeV9tcyk7CiAgICBjb25zdCBsYXN0Q2hlY2tlZCA9IHByb3h5Lmxhc3RfY2hlY2tlZF9hdAogICAgICA/IG5ldyBEYXRlKHByb3h5Lmxhc3RfY2hlY2tlZF9hdCkudG9Mb2NhbGVUaW1lU3RyaW5nKCkKICAgICAgOiAn4oCUJzsKCiAgICB0ci5pbm5lckhUTUwgPSBgCiAgICAgIDx0ZD48Y29kZT4ke3Byb3h5LmlkLnNsaWNlKDAsIDgpfTwvY29kZT48L3RkPgogICAgICA8dGQ+JHtwcm94eS50eXBlfTwvdGQ+CiAgICAgIDx0ZD4ke3Byb3h5Lmhvc3R9OiR7cHJveHkucG9ydH08L3RkPgogICAgICA8dGQ+JHtzdGF0dXNCYWRnZX08L3RkPgogICAgICA8dGQ+JHtsYXRlbmN5QmFkZ2V9PC90ZD4KICAgICAgPHRkPiR7cHJveHkuZXhpdF9pcCB8fCAn4oCUJ308L3RkPgogICAgICA8dGQ+JHtsYXN0Q2hlY2tlZH08L3RkPgogICAgICA8dGQ+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1zbSBidG4tc2Vjb25kYXJ5IiBvbmNsaWNrPSJwZ3cuY2hlY2tQcm94eUhlYWx0aCgnJHtwcm94eS5pZH0nKSIgZGF0YS10b29sdGlwPSJIZWFsdGggY2hlY2siPgogICAgICAgICAgQ2hlY2sKICAgICAgICA8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXNtIGJ0bi1kYW5nZXIiIG9uY2xpY2s9InBndy5kZWxldGVQcm94eSgnJHtwcm94eS5pZH0nKSIgZGF0YS10b29sdGlwPSJEZWxldGUgcHJveHkiPgogICAgICAgICAgw5cKICAgICAgICA8L2J1dHRvbj4KICAgICAgPC90ZD4KICAgIGA7CgogICAgcmV0dXJuIHRyOwogIH0KCiAgY3JlYXRlU3RhdHVzQmFkZ2Uoc3RhdHVzKSB7CiAgICBjb25zdCBzdGF0dXNDbGFzcyA9IHsKICAgICAgJ09LJzogJ3RleHQtYmctc3VjY2VzcycsCiAgICAgICdERUdSQURFRCc6ICd0ZXh0LWJnLXdhcm5pbmcnLAogICAgICAnRE9XTic6ICd0ZXh0LWJnLWRhbmdlcicKICAgIH1bc3RhdHVzXSB8fCAndGV4dC1iZy1zZWNvbmRhcnknOwoKICAgIHJldHVybiBgPHNwYW4gY2xhc3M9ImJhZGdlICR7c3RhdHVzQ2xhc3N9Ij4ke3N0YXR1cyB8fCAnVW5rbm93bid9PC9zcGFuPmA7CiAgfQoKICBjcmVhdGVMYXRlbmN5QmFkZ2UobXMpIHsKICAgIGlmIChtcyA9PSBudWxsIHx8IGlzTmFOKG1zKSkgcmV0dXJuICfigJQnOwogICAgbGV0IGNscyA9ICd0ZXh0LWJnLWRhbmdlcic7CiAgICBpZiAobXMgPCAzMDApIGNscyA9ICd0ZXh0LWJnLXN1Y2Nlc3MnOwogICAgZWxzZSBpZiAobXMgPCA5MDApIGNscyA9ICd0ZXh0LWJnLXdhcm5pbmcnOwogICAgcmV0dXJuIGA8c3BhbiBjbGFzcz0iYmFkZ2UgJHtjbHN9Ij4ke21zfW1zPC9zcGFuPmA7CiAgfQoKCiAgcmVuZGVyTWFwcGluZ3MoKSB7CiAgICBjb25zdCB0Ym9keSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0Ym9keS1tYXBwaW5ncycpOwogICAgaWYgKCF0Ym9keSkgcmV0dXJuOwogICAgLy8gc29ydAogICAgY29uc3Qga2V5ID0gdGhpcy5tU29ydCwgYXNjID0gdGhpcy5tQXNjOwogICAgY29uc3QgdmFsID0gKG0pID0+IHsKICAgICAgaWYgKGtleSA9PT0gJ2lkJykgcmV0dXJuIChtLmlkIHx8ICcnKTsKICAgICAgaWYgKGtleSA9PT0gJ2NsaWVudCcpIHJldHVybiAoKG0uY2xpZW50Py5pcF9jaWRyKSB8fCAnJyk7CiAgICAgIGlmIChrZXkgPT09ICdwcm94eScpIHsgY29uc3QgcCA9IG0ucHJveHkgfHwge307IHJldHVybiAoKHAuaG9zdCB8fCAnJykgKyAnOicgKyAocC5wb3J0ID8/ICcnKSk7IH0KICAgICAgaWYgKGtleSA9PT0gJ3N0YXRlJykgcmV0dXJuIChtLnN0YXRlIHx8ICcnKTsKICAgICAgaWYgKGtleSA9PT0gJ3BvcnQnKSByZXR1cm4gKG0ubG9jYWxfcmVkaXJlY3RfcG9ydCA/PyAwKTsKICAgICAgcmV0dXJuICgobS5jbGllbnQ/LmlwX2NpZHIpIHx8ICcnKTsKICAgIH07CiAgICBjb25zdCBzb3J0ZWQgPSAodGhpcy5tYXBwaW5ncyB8fCBbXSkuc2xpY2UoKS5zb3J0KChhLCBiKSA9PiB7IGNvbnN0IHZhID0gdmFsKGEpLCB2YiA9IHZhbChiKTsgaWYgKHZhIDwgdmIpIHJldHVybiBhc2MgPyAtMSA6IDE7IGlmICh2YSA+IHZiKSByZXR1cm4gYXNjID8gMSA6IC0xOyByZXR1cm4gMDsgfSk7CiAgICAvLyBoZWFkZXIgaWNvbnMgKyBjbGljawogICAgY29uc3QgdGhlYWQgPSB0Ym9keS5wYXJlbnRFbGVtZW50Py5xdWVyeVNlbGVjdG9yKCd0aGVhZCcpOwogICAgaWYgKHRoZWFkKSB7CiAgICAgIGNvbnN0IGFycm93ID0gYXNjID8gJyBcXHUyNUIyJyA6ICcgXFx1MjVCQyc7CiAgICAgIHRoZWFkLmlubmVySFRNTCA9ICc8dHI+JwogICAgICAgICsgJzx0aCBkYXRhLWs9ImlkIiBjbGFzcz0ic29ydGFibGUiPklEJyArIChrZXkgPT09ICdpZCcgPyBhcnJvdyA6ICcnKSArICc8L3RoPicKICAgICAgICArICc8dGggZGF0YS1rPSJjbGllbnQiIGNsYXNzPSJzb3J0YWJsZSI+Q2xpZW50IElQL0NJRFInICsgKGtleSA9PT0gJ2NsaWVudCcgPyBhcnJvdyA6ICcnKSArICc8L3RoPicKICAgICAgICArICc8dGggZGF0YS1rPSJwcm94eSIgY2xhc3M9InNvcnRhYmxlIj5Qcm94eSBTZXJ2ZXInICsgKGtleSA9PT0gJ3Byb3h5JyA/IGFycm93IDogJycpICsgJzwvdGg+JwogICAgICAgICsgJzx0aCBkYXRhLWs9InN0YXRlIiBjbGFzcz0ic29ydGFibGUiPlN0YXRlJyArIChrZXkgPT09ICdzdGF0ZScgPyBhcnJvdyA6ICcnKSArICc8L3RoPicKICAgICAgICArICc8dGggZGF0YS1rPSJwb3J0IiBjbGFzcz0ic29ydGFibGUiPkxvY2FsIFBvcnQnICsgKGtleSA9PT0gJ3BvcnQnID8gYXJyb3cgOiAnJykgKyAnPC90aD4nCiAgICAgICAgKyAnPHRoPkFjdGlvbnM8L3RoPicKICAgICAgICArICc8L3RyPic7CiAgICAgIHRoZWFkLnF1ZXJ5U2VsZWN0b3JBbGwoJ3RoLnNvcnRhYmxlJykuZm9yRWFjaCgodGgpID0+IHsKICAgICAgICB0aC5zdHlsZS5jdXJzb3IgPSAncG9pbnRlcic7IHRoLm9uY2xpY2sgPSAoKSA9PiB7CiAgICAgICAgICBjb25zdCBrID0gdGguZ2V0QXR0cmlidXRlKCdkYXRhLWsnKTsKICAgICAgICAgIGlmICh0aGlzLm1Tb3J0ID09PSBrKSB0aGlzLm1Bc2MgPSAhdGhpcy5tQXNjOyBlbHNlIHsgdGhpcy5tU29ydCA9IGs7IHRoaXMubUFzYyA9IHRydWU7IH0KICAgICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCdwZ3dfc29ydF9tMicsIEpTT04uc3RyaW5naWZ5KHsgazogdGhpcy5tU29ydCwgYTogdGhpcy5tQXNjIH0pKTsKICAgICAgICAgIHRoaXMucmVuZGVyTWFwcGluZ3MoKTsKICAgICAgICB9OwogICAgICB9KTsKICAgIH0KCiAgICB0Ym9keS5pbm5lckhUTUwgPSAnJzsKCiAgICBpZiAoc29ydGVkLmxlbmd0aCA9PT0gMCkgewogICAgICB0Ym9keS5pbm5lckhUTUwgPSAnPHRyPjx0ZCBjb2xzcGFuPSI2IiBjbGFzcz0idGV4dC1jZW50ZXIiPk5vIG1hcHBpbmdzIGNvbmZpZ3VyZWQ8L3RkPjwvdHI+JzsKICAgICAgcmV0dXJuOwogICAgfQoKICAgIHNvcnRlZC5mb3JFYWNoKG1hcHBpbmcgPT4gewogICAgICBjb25zdCByb3cgPSB0aGlzLmNyZWF0ZU1hcHBpbmdSb3cobWFwcGluZyk7CiAgICAgIHRib2R5LmFwcGVuZENoaWxkKHJvdyk7CiAgICB9KTsKICB9CgogIGNyZWF0ZU1hcHBpbmdSb3cobWFwcGluZykgewogICAgY29uc3QgdHIgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCd0cicpOwoKICAgIGNvbnN0IHByb3h5QWRkcmVzcyA9IG1hcHBpbmcucHJveHkKICAgICAgPyBgJHttYXBwaW5nLnByb3h5Lmhvc3R9OiR7bWFwcGluZy5wcm94eS5wb3J0fWAKICAgICAgOiAn4oCUJzsKCiAgICBjb25zdCBzdGF0ZUJhZGdlID0gdGhpcy5jcmVhdGVTdGF0dXNCYWRnZShtYXBwaW5nLnN0YXRlIHx8ICdQRU5ESU5HJyk7CgogICAgdHIuaW5uZXJIVE1MID0gYAogICAgICA8dGQ+PGNvZGU+JHttYXBwaW5nLmlkLnNsaWNlKDAsIDgpfTwvY29kZT48L3RkPgogICAgICA8dGQ+JHttYXBwaW5nLmNsaWVudD8uaXBfY2lkciB8fCAn4oCUJ308L3RkPgogICAgICA8dGQ+JHtwcm94eUFkZHJlc3N9PC90ZD4KICAgICAgPHRkPiR7c3RhdGVCYWRnZX08L3RkPgogICAgICA8dGQ+JHttYXBwaW5nLmxvY2FsX3JlZGlyZWN0X3BvcnQgfHwgJ+KAlCd9PC90ZD4KICAgICAgPHRkPgogICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tc20gYnRuLWRhbmdlciIgb25jbGljaz0icGd3LmRlbGV0ZU1hcHBpbmcoJyR7bWFwcGluZy5pZH0nKSI+CiAgICAgICAgICBEZWxldGUKICAgICAgICA8L2J1dHRvbj4KICAgICAgPC90ZD4KICAgIGA7CgogICAgcmV0dXJuIHRyOwogIH0KCiAgcmVuZGVyQ2xpZW50cygpIHsKICAgIGNvbnN0IHNlbGVjdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzZWxlY3QtcHJveHknKTsKICAgIGlmICghc2VsZWN0KSByZXR1cm47CgogICAgc2VsZWN0LmlubmVySFRNTCA9ICc8b3B0aW9uIHZhbHVlPSIiPlNlbGVjdCBwcm94eSBzZXJ2ZXIuLi48L29wdGlvbj4nOwoKICAgIGNvbnN0IHVzZWQgPSBuZXcgU2V0KCh0aGlzLm1hcHBpbmdzIHx8IFtdKS5tYXAobSA9PiBtICYmIG0ucHJveHkgPyBtLnByb3h5LmlkIDogbnVsbCkuZmlsdGVyKEJvb2xlYW4pKTsKICAgIGNvbnN0IGF2YWlsYWJsZSA9ICh0aGlzLnByb3hpZXMgfHwgW10pLmZpbHRlcihwID0+ICF1c2VkLmhhcyhwLmlkKSk7CgogICAgaWYgKCFhdmFpbGFibGUgfHwgYXZhaWxhYmxlLmxlbmd0aCA9PT0gMCkgewogICAgICBjb25zdCBvcHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdvcHRpb24nKTsKICAgICAgb3B0LmRpc2FibGVkID0gdHJ1ZTsKICAgICAgb3B0LnRleHRDb250ZW50ID0gJ05vIGF2YWlsYWJsZSBwcm94aWVzIChhbGwgbWFwcGVkKSc7CiAgICAgIHNlbGVjdC5hcHBlbmRDaGlsZChvcHQpOwogICAgICByZXR1cm47CiAgICB9CgogICAgYXZhaWxhYmxlLmZvckVhY2gocHJveHkgPT4gewogICAgICBjb25zdCBvcHRpb24gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdvcHRpb24nKTsKICAgICAgb3B0aW9uLnZhbHVlID0gcHJveHkuaWQ7CiAgICAgIGNvbnN0IHN0YXR1c0luZGljYXRvciA9IHByb3h5LnN0YXR1cyA9PT0gJ09LJyA/ICfinJMnIDogcHJveHkuc3RhdHVzID09PSAnREVHUkFERUQnID8gJ+KaoCcgOiAn4pyXJzsKICAgICAgb3B0aW9uLnRleHRDb250ZW50ID0gYCR7c3RhdHVzSW5kaWNhdG9yfSAke3Byb3h5Lmhvc3R9OiR7cHJveHkucG9ydH0gKCR7cHJveHkudHlwZX0pYDsKICAgICAgc2VsZWN0LmFwcGVuZENoaWxkKG9wdGlvbik7CiAgICB9KTsKICB9CiAgZGV0ZWN0UHJveHlUeXBlKG9yaWdpbmFsTGluZSwgaG9zdCwgcG9ydCkgewogICAgLy8gQ2hlY2sgZm9yIGV4cGxpY2l0IHR5cGUgcHJlZml4CiAgICBpZiAob3JpZ2luYWxMaW5lLmluY2x1ZGVzKCJzb2NrczU6Ly8iKSkgcmV0dXJuICJzb2NrczUiOwogICAgaWYgKG9yaWdpbmFsTGluZS5pbmNsdWRlcygiaHR0cDovLyIpKSByZXR1cm4gImh0dHAiOwoKICAgIC8vIEF1dG8tZGV0ZWN0IGJhc2VkIG9uIGNvbW1vbiBTT0NLUzUgcG9ydHMKICAgIGNvbnN0IHNvY2tzQ29tbW9uUG9ydHMgPSBbMTA4MCwgOTA1MCwgOTE1MF07CiAgICBpZiAoc29ja3NDb21tb25Qb3J0cy5pbmNsdWRlcyhwb3J0KSkgcmV0dXJuICJzb2NrczUiOwoKICAgIC8vIERlZmF1bHQgdG8gSFRUUAogICAgcmV0dXJuICJodHRwIjsKICB9CgogIHBhcnNlUHJveHlMaW5lKGxpbmUpIHsKICAgIGNvbnN0IGNsZWFuTGluZSA9IGxpbmUucmVwbGFjZSgvXihodHRwcz98c29ja3M1KTpcL1wvLywgJycpOyBjb25zdCBtID0gY2xlYW5MaW5lLnRyaW0oKS5tYXRjaCgvXihbXjpcc10rKTooXGR7MSw1fSk6KFteOl0qKTooW146XSopJC8pOwogICAgaWYgKCFtKSByZXR1cm4gbnVsbDsKICAgIGNvbnN0IGhvc3QgPSBtWzFdOwogICAgY29uc3QgcG9ydCA9IHBhcnNlSW50KG1bMl0sIDEwKTsKICAgIGNvbnN0IHVzZXJuYW1lID0gbVszXSB8fCAiIjsKICAgIGNvbnN0IHBhc3N3b3JkID0gbVs0XSB8fCAiIjsKICAgIGlmICghaG9zdCB8fCAhcG9ydCB8fCBwb3J0IDw9IDAgfHwgcG9ydCA+IDY1NTM1KSByZXR1cm4gbnVsbDsKICAgIHJldHVybiB7IHR5cGU6IHRoaXMuZGV0ZWN0UHJveHlUeXBlKGxpbmUsIGhvc3QsIHBvcnQpLCBob3N0LCBwb3J0LCB1c2VybmFtZSwgcGFzc3dvcmQsIGVuYWJsZWQ6IHRydWUgfTsKICB9CgogIGFzeW5jIGltcG9ydFByb3hpZXMoKSB7CiAgICBjb25zdCB0ZXh0YXJlYSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbXBvcnQtcHJveGllcyIpOwogICAgaWYgKCF0ZXh0YXJlYSkgcmV0dXJuOwogICAgY29uc3QgcmF3ID0gdGV4dGFyZWEudmFsdWUgfHwgIiI7CiAgICBjb25zdCBsaW5lcyA9IHJhdy5zcGxpdCgvXHI/XG4vKS5tYXAobCA9PiBsLnRyaW0oKSkuZmlsdGVyKEJvb2xlYW4pOwogICAgaWYgKGxpbmVzLmxlbmd0aCA9PT0gMCkgewogICAgICB0aGlzLnNob3dBbGVydCgiTm8gcHJveGllcyB0byBpbXBvcnQiLCAid2FybmluZyIpOwogICAgICByZXR1cm47CiAgICB9CgogICAgbGV0IG9rID0gMCwgc2tpcHBlZCA9IDA7CiAgICBmb3IgKGNvbnN0IFtpZHgsIGxpbmVdIG9mIGxpbmVzLmVudHJpZXMoKSkgewogICAgICBpZiAobGluZS5zdGFydHNXaXRoKCIjIikpIHsgc2tpcHBlZCsrOyBjb250aW51ZTsgfQogICAgICBjb25zdCBkYXRhID0gdGhpcy5wYXJzZVByb3h5TGluZShsaW5lKTsKICAgICAgaWYgKCFkYXRhKSB7IHNraXBwZWQrKzsgY29udGludWU7IH0KICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBjcmVhdGVkID0gYXdhaXQgdGhpcy5hcGlDYWxsKGAke3RoaXMuYXBpQmFzZX0vdjEvcHJveGllc2AsIHsgbWV0aG9kOiAiUE9TVCIsIGJvZHk6IEpTT04uc3RyaW5naWZ5KGRhdGEpIH0pOwogICAgICAgIG9rKys7CiAgICAgICAgc2V0VGltZW91dCgoKSA9PiB0aGlzLmNoZWNrUHJveHlIZWFsdGgoY3JlYXRlZC5pZCksIDUwMCk7CiAgICAgIH0gY2F0Y2ggKGUpIHsKICAgICAgICBjb25zb2xlLmVycm9yKCJJbXBvcnQgZmFpbGVkIGZvciBsaW5lIiwgaWR4ICsgMSwgbGluZSwgZSk7CiAgICAgICAgc2tpcHBlZCsrOwogICAgICB9CiAgICB9CgogICAgdGhpcy5zaG93QWxlcnQoYEltcG9ydGVkICR7b2t9IHByb3hpZXMke3NraXBwZWQgPyBgLCBza2lwcGVkICR7c2tpcHBlZH1gIDogIiJ9YCwgb2sgPiAwID8gInN1Y2Nlc3MiIDogIndhcm5pbmciKTsKICAgIGlmIChvayA+IDApIHRoaXMubG9hZERhdGEoKTsKICB9CgoKICB1cGRhdGVDb3VudHMoKSB7CiAgICB0aGlzLnVwZGF0ZUVsZW1lbnQoJ3Byb3h5LWNvdW50JywgYCR7dGhpcy5wcm94aWVzLmxlbmd0aH0gcHJveGllc2ApOwogICAgdGhpcy51cGRhdGVFbGVtZW50KCdtYXBwaW5nLWNvdW50JywgYCR7dGhpcy5tYXBwaW5ncy5sZW5ndGh9IG1hcHBpbmdzYCk7CiAgfQoKICBhc3luYyBjcmVhdGVQcm94eSgpIHsKICAgIGNvbnN0IGZvcm0gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZm9ybS1wcm94eScpOwogICAgY29uc3QgZm9ybURhdGEgPSBuZXcgRm9ybURhdGEoZm9ybSk7CgogICAgY29uc3QgcHJveHlEYXRhID0gewogICAgICB0eXBlOiBmb3JtRGF0YS5nZXQoJ3R5cGUnKSwKICAgICAgaG9zdDogZm9ybURhdGEuZ2V0KCdob3N0JyksCiAgICAgIHBvcnQ6IHBhcnNlSW50KGZvcm1EYXRhLmdldCgncG9ydCcpKSwKICAgICAgdXNlcm5hbWU6IGZvcm1EYXRhLmdldCgndXNlcm5hbWUnKSB8fCAnJywKICAgICAgcGFzc3dvcmQ6IGZvcm1EYXRhLmdldCgncGFzc3dvcmQnKSB8fCAnJywKICAgICAgZW5hYmxlZDogdHJ1ZQogICAgfTsKCiAgICB0cnkgewogICAgICBjb25zdCBuZXdQcm94eSA9IGF3YWl0IHRoaXMuYXBpQ2FsbChgJHt0aGlzLmFwaUJhc2V9L3YxL3Byb3hpZXNgLCB7CiAgICAgICAgbWV0aG9kOiAnUE9TVCcsCiAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkocHJveHlEYXRhKQogICAgICB9KTsKCiAgICAgIHRoaXMuc2hvd0FsZXJ0KCdQcm94eSBjcmVhdGVkIHN1Y2Nlc3NmdWxseScsICdzdWNjZXNzJyk7CiAgICAgIGZvcm0ucmVzZXQoKTsKICAgICAgdGhpcy5sb2FkRGF0YSgpOwoKICAgICAgLy8gQXV0byBoZWFsdGggY2hlY2sgdGhlIG5ldyBwcm94eQogICAgICBzZXRUaW1lb3V0KCgpID0+IHRoaXMuY2hlY2tQcm94eUhlYWx0aChuZXdQcm94eS5pZCksIDEwMDApOwoKICAgIH0gY2F0Y2ggKGVycm9yKSB7CiAgICAgIGNvbnNvbGUuZXJyb3IoJ0ZhaWxlZCB0byBjcmVhdGUgcHJveHk6JywgZXJyb3IpOwogICAgfQogIH0KCiAgYXN5bmMgY3JlYXRlTWFwcGluZygpIHsKICAgIGNvbnN0IGZvcm0gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZm9ybS1tYXBwaW5nJyk7CiAgICBjb25zdCBmb3JtRGF0YSA9IG5ldyBGb3JtRGF0YShmb3JtKTsKCiAgICBjb25zdCBjbGllbnRJUCA9IChmb3JtRGF0YS5nZXQoJ2NsaWVudF9pcCcpIHx8ICcnKS50cmltKCk7CiAgICBjb25zdCBwcm94eUlkID0gZm9ybURhdGEuZ2V0KCdwcm94eV9pZCcpOwoKICAgIC8vIEZyb250ZW5kIHZhbGlkYXRpb246IElQdjQgb25seSwgZm9yYmlkIENJRFIKICAgIGNvbnN0IGlwdjRSZSA9IC9eKDI1WzAtNV18MlswLTRdXGR8WzAxXT9cZFxkPylcLigyNVswLTVdfDJbMC00XVxkfFswMV0/XGRcZD8pXC4oMjVbMC01XXwyWzAtNF1cZHxbMDFdP1xkXGQ/KVwuKDI1WzAtNV18MlswLTRdXGR8WzAxXT9cZFxkPykkLzsKICAgIGlmIChjbGllbnRJUC5pbmNsdWRlcygnLycpKSB7CiAgICAgIHRoaXMuc2hvd0FsZXJ0KCdDSURSIGlzIG5vdCBhbGxvd2VkLiBQbGVhc2UgZW50ZXIgYSBzaW5nbGUgSVB2NCBhZGRyZXNzIChlLmcuLCAxOTIuMTY4LjIuMykuJywgJ3dhcm5pbmcnKTsKICAgICAgcmV0dXJuOwogICAgfQogICAgaWYgKGNsaWVudElQICYmICFpcHY0UmUudGVzdChjbGllbnRJUCkpIHsKICAgICAgdGhpcy5zaG93QWxlcnQoJ0ludmFsaWQgSVB2NCBhZGRyZXNzIGZvcm1hdC4nLCAnd2FybmluZycpOwogICAgICByZXR1cm47CiAgICB9CgogICAgaWYgKCFjbGllbnRJUCB8fCAhcHJveHlJZCkgewogICAgICB0aGlzLnNob3dBbGVydCgnUGxlYXNlIGZpbGwgYWxsIHJlcXVpcmVkIGZpZWxkcycsICd3YXJuaW5nJyk7CiAgICAgIHJldHVybjsKICAgIH0KCiAgICB0cnkgewogICAgICAvLyBGaXJzdCBjcmVhdGUgY2xpZW50IGlmIG5vdCBleGlzdHMKICAgICAgbGV0IGNsaWVudElkOwogICAgICBjb25zdCBleGlzdGluZ0NsaWVudCA9IHRoaXMuY2xpZW50cy5maW5kKGMgPT4gYy5pcF9jaWRyID09PSBgJHtjbGllbnRJUH0vMzJgKTsKCiAgICAgIGlmIChleGlzdGluZ0NsaWVudCkgewogICAgICAgIGNsaWVudElkID0gZXhpc3RpbmdDbGllbnQuaWQ7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgY29uc3QgY2xpZW50ID0gYXdhaXQgdGhpcy5hcGlDYWxsKGAke3RoaXMuYXBpQmFzZX0vdjEvY2xpZW50c2AsIHsKICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLAogICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoewogICAgICAgICAgICBpcF9jaWRyOiBjbGllbnRJUCwgLy8gQVBJIHdpbGwgYXV0by1hZGQgLzMyCiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUKICAgICAgICAgIH0pCiAgICAgICAgfSk7CiAgICAgICAgY2xpZW50SWQgPSBjbGllbnQuaWQ7CiAgICAgIH0KCiAgICAgIC8vIENyZWF0ZSBtYXBwaW5nCiAgICAgIGF3YWl0IHRoaXMuYXBpQ2FsbChgJHt0aGlzLmFwaUJhc2V9L3YxL21hcHBpbmdzYCwgewogICAgICAgIG1ldGhvZDogJ1BPU1QnLAogICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsKICAgICAgICAgIGNsaWVudF9pZDogY2xpZW50SWQsCiAgICAgICAgICBwcm94eV9pZDogcHJveHlJZAogICAgICAgIH0pCiAgICAgIH0pOwoKICAgICAgdGhpcy5zaG93QWxlcnQoJ01hcHBpbmcgY3JlYXRlZCBzdWNjZXNzZnVsbHknLCAnc3VjY2VzcycpOwogICAgICBmb3JtLnJlc2V0KCk7CiAgICAgIHRoaXMubG9hZERhdGEoKTsKCiAgICAgIC8vIEF1dG8gcmVjb25jaWxlIGFmdGVyIGNyZWF0aW5nIG1hcHBpbmcKICAgICAgc2V0VGltZW91dCgoKSA9PiB0aGlzLnJlY29uY2lsZVJ1bGVzKCksIDEwMDApOwoKICAgIH0gY2F0Y2ggKGVycm9yKSB7CiAgICAgIGNvbnNvbGUuZXJyb3IoJ0ZhaWxlZCB0byBjcmVhdGUgbWFwcGluZzonLCBlcnJvcik7CiAgICB9CiAgfQoKICBhc3luYyBjaGVja1Byb3h5SGVhbHRoKHByb3h5SWQpIHsKICAgIHRyeSB7CiAgICAgIGF3YWl0IHRoaXMuYXBpQ2FsbChgJHt0aGlzLmFwaUJhc2V9L3YxL3Byb3hpZXMvJHtwcm94eUlkfS9jaGVja2AsIHsKICAgICAgICBtZXRob2Q6ICdQT1NUJwogICAgICB9KTsKCiAgICAgIHRoaXMuc2hvd0FsZXJ0KCdIZWFsdGggY2hlY2sgY29tcGxldGVkJywgJ3N1Y2Nlc3MnKTsKICAgICAgdGhpcy5sb2FkRGF0YSgpOwogICAgfSBjYXRjaCAoZXJyb3IpIHsKICAgICAgY29uc29sZS5lcnJvcignSGVhbHRoIGNoZWNrIGZhaWxlZDonLCBlcnJvcik7CiAgICB9CiAgfQoKICBhc3luYyBoZWFsdGhDaGVja0FsbCgpIHsKICAgIGlmICh0aGlzLnByb3hpZXMubGVuZ3RoID09PSAwKSB7CiAgICAgIHRoaXMuc2hvd0FsZXJ0KCdObyBwcm94aWVzIHRvIGNoZWNrJywgJ3dhcm5pbmcnKTsKICAgICAgcmV0dXJuOwogICAgfQoKICAgIHRoaXMuc2hvd0FsZXJ0KCdSdW5uaW5nIGhlYWx0aCBjaGVja3MuLi4nLCAnaW5mbycpOwoKICAgIGNvbnN0IGNoZWNrUHJvbWlzZXMgPSB0aGlzLnByb3hpZXMubWFwKHByb3h5ID0+CiAgICAgIHRoaXMuY2hlY2tQcm94eUhlYWx0aChwcm94eS5pZCkuY2F0Y2goZSA9PiBjb25zb2xlLmVycm9yKGBIZWFsdGggY2hlY2sgZmFpbGVkIGZvciAke3Byb3h5LmlkfTpgLCBlKSkKICAgICk7CgogICAgdHJ5IHsKICAgICAgYXdhaXQgUHJvbWlzZS5hbGwoY2hlY2tQcm9taXNlcyk7CiAgICAgIHRoaXMuc2hvd0FsZXJ0KCdBbGwgaGVhbHRoIGNoZWNrcyBjb21wbGV0ZWQnLCAnc3VjY2VzcycpOwogICAgfSBjYXRjaCAoZXJyb3IpIHsKICAgICAgY29uc29sZS5lcnJvcignU29tZSBoZWFsdGggY2hlY2tzIGZhaWxlZDonLCBlcnJvcik7CiAgICB9CiAgfQoKICBhc3luYyBkZWxldGVQcm94eShwcm94eUlkKSB7CiAgICBpZiAoIWNvbmZpcm0oJ0FyZSB5b3Ugc3VyZSB5b3Ugd2FudCB0byBkZWxldGUgdGhpcyBwcm94eT8gVGhpcyB3aWxsIGFsc28gcmVtb3ZlIGFueSBhc3NvY2lhdGVkIG1hcHBpbmdzLicpKSB7CiAgICAgIHJldHVybjsKICAgIH0KCiAgICB0cnkgewogICAgICBhd2FpdCB0aGlzLmFwaUNhbGwoYCR7dGhpcy5hcGlCYXNlfS92MS9wcm94aWVzLyR7cHJveHlJZH1gLCB7CiAgICAgICAgbWV0aG9kOiAnREVMRVRFJwogICAgICB9KTsKCiAgICAgIHRoaXMuc2hvd0FsZXJ0KCdQcm94eSBkZWxldGVkIHN1Y2Nlc3NmdWxseScsICdzdWNjZXNzJyk7CiAgICAgIHRoaXMubG9hZERhdGEoKTsKICAgIH0gY2F0Y2ggKGVycm9yKSB7CiAgICAgIGNvbnNvbGUuZXJyb3IoJ0ZhaWxlZCB0byBkZWxldGUgcHJveHk6JywgZXJyb3IpOwogICAgfQogIH0KCiAgYXN5bmMgZGVsZXRlTWFwcGluZyhtYXBwaW5nSWQpIHsKICAgIGlmICghY29uZmlybSgnQXJlIHlvdSBzdXJlIHlvdSB3YW50IHRvIGRlbGV0ZSB0aGlzIG1hcHBpbmc/JykpIHsKICAgICAgcmV0dXJuOwogICAgfQoKICAgIHRyeSB7CiAgICAgIGF3YWl0IHRoaXMuYXBpQ2FsbChgJHt0aGlzLmFwaUJhc2V9L3YxL21hcHBpbmdzLyR7bWFwcGluZ0lkfWAsIHsKICAgICAgICBtZXRob2Q6ICdERUxFVEUnCiAgICAgIH0pOwoKICAgICAgdGhpcy5zaG93QWxlcnQoJ01hcHBpbmcgZGVsZXRlZCBzdWNjZXNzZnVsbHknLCAnc3VjY2VzcycpOwogICAgICB0aGlzLmxvYWREYXRhKCk7CgogICAgICAvLyBBdXRvIHJlY29uY2lsZSBhZnRlciBkZWxldGluZyBtYXBwaW5nCiAgICAgIHNldFRpbWVvdXQoKCkgPT4gdGhpcy5yZWNvbmNpbGVSdWxlcygpLCAxMDAwKTsKCiAgICB9IGNhdGNoIChlcnJvcikgewogICAgICBjb25zb2xlLmVycm9yKCdGYWlsZWQgdG8gZGVsZXRlIG1hcHBpbmc6JywgZXJyb3IpOwogICAgfQogIH0KCiAgYXN5bmMgcmVjb25jaWxlUnVsZXMoKSB7CiAgICB0cnkgewogICAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGZldGNoKGAke3RoaXMuYWdlbnRCYXNlfS9yZWNvbmNpbGVgKTsKCiAgICAgIGlmIChyZXNwb25zZS5vaykgewogICAgICAgIHRoaXMuc2hvd0FsZXJ0KCdSdWxlcyByZWNvbmNpbGVkIHN1Y2Nlc3NmdWxseScsICdzdWNjZXNzJyk7CiAgICAgICAgdGhpcy51cGRhdGVFbGVtZW50KCdsYXN0LXJlY29uY2lsZScsIG5ldyBEYXRlKCkudG9Mb2NhbGVUaW1lU3RyaW5nKCkpOwogICAgICAgIHRoaXMubG9hZERhdGEoKTsKICAgICAgfSBlbHNlIHsKICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ1JlY29uY2lsZSBmYWlsZWQnKTsKICAgICAgfQogICAgfSBjYXRjaCAoZXJyb3IpIHsKICAgICAgY29uc29sZS5lcnJvcignUmVjb25jaWxlIGZhaWxlZDonLCBlcnJvcik7CiAgICAgIHRoaXMuc2hvd0FsZXJ0KCdGYWlsZWQgdG8gcmVjb25jaWxlIHJ1bGVzJywgJ2RhbmdlcicpOwogICAgfQogIH0KCiAgZXhwb3J0UHJveGllcygpIHsKICAgIGlmICh0aGlzLnByb3hpZXMubGVuZ3RoID09PSAwKSB7CiAgICAgIHRoaXMuc2hvd0FsZXJ0KCdObyBwcm94aWVzIHRvIGV4cG9ydCcsICd3YXJuaW5nJyk7CiAgICAgIHJldHVybjsKICAgIH0KCiAgICBjb25zdCBjc3ZDb250ZW50ID0gWwogICAgICAnSUQsVHlwZSxIb3N0LFBvcnQsU3RhdHVzLExhdGVuY3ksRXhpdCBJUCxMYXN0IENoZWNrJywKICAgICAgLi4udGhpcy5wcm94aWVzLm1hcChwID0+IFsKICAgICAgICBwLmlkLAogICAgICAgIHAudHlwZSwKICAgICAgICBwLmhvc3QsCiAgICAgICAgcC5wb3J0LAogICAgICAgIHAuc3RhdHVzIHx8ICdVbmtub3duJywKICAgICAgICBwLmxhdGVuY3lfbXMgfHwgJycsCiAgICAgICAgcC5leGl0X2lwIHx8ICcnLAogICAgICAgIHAubGFzdF9jaGVja2VkX2F0IHx8ICcnCiAgICAgIF0uam9pbignLCcpKQogICAgXS5qb2luKCdcbicpOwoKICAgIHRoaXMuZG93bmxvYWRGaWxlKGNzdkNvbnRlbnQsICdwZ3ctcHJveGllcy5jc3YnLCAndGV4dC9jc3YnKTsKICB9CgogIGV4cG9ydE1hcHBpbmdzKCkgewogICAgaWYgKHRoaXMubWFwcGluZ3MubGVuZ3RoID09PSAwKSB7CiAgICAgIHRoaXMuc2hvd0FsZXJ0KCdObyBtYXBwaW5ncyB0byBleHBvcnQnLCAnd2FybmluZycpOwogICAgICByZXR1cm47CiAgICB9CgogICAgY29uc3QgY3N2Q29udGVudCA9IFsKICAgICAgJ0lELENsaWVudCBJUCxQcm94eSBIb3N0LFByb3h5IFBvcnQsU3RhdGUsTG9jYWwgUG9ydCcsCiAgICAgIC4uLnRoaXMubWFwcGluZ3MubWFwKG0gPT4gWwogICAgICAgIG0uaWQsCiAgICAgICAgbS5jbGllbnQ/LmlwX2NpZHIgfHwgJycsCiAgICAgICAgbS5wcm94eT8uaG9zdCB8fCAnJywKICAgICAgICBtLnByb3h5Py5wb3J0IHx8ICcnLAogICAgICAgIG0uc3RhdGUgfHwgJ1BFTkRJTkcnLAogICAgICAgIG0ubG9jYWxfcmVkaXJlY3RfcG9ydCB8fCAnJwogICAgICBdLmpvaW4oJywnKSkKICAgIF0uam9pbignXG4nKTsKCiAgICB0aGlzLmRvd25sb2FkRmlsZShjc3ZDb250ZW50LCAncGd3LW1hcHBpbmdzLmNzdicsICd0ZXh0L2NzdicpOwogIH0KCiAgZG93bmxvYWRGaWxlKGNvbnRlbnQsIGZpbGVuYW1lLCBtaW1lVHlwZSkgewogICAgY29uc3QgYmxvYiA9IG5ldyBCbG9iKFtjb250ZW50XSwgeyB0eXBlOiBtaW1lVHlwZSB9KTsKICAgIGNvbnN0IHVybCA9IHdpbmRvdy5VUkwuY3JlYXRlT2JqZWN0VVJMKGJsb2IpOwogICAgY29uc3QgYSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2EnKTsKICAgIGEuaHJlZiA9IHVybDsKICAgIGEuZG93bmxvYWQgPSBmaWxlbmFtZTsKICAgIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7CiAgICBhLmNsaWNrKCk7CiAgICBkb2N1bWVudC5ib2R5LnJlbW92ZUNoaWxkKGEpOwogICAgd2luZG93LlVSTC5yZXZva2VPYmplY3RVUkwodXJsKTsKCiAgICB0aGlzLnNob3dBbGVydChgJHtmaWxlbmFtZX0gZG93bmxvYWRlZGAsICdzdWNjZXNzJyk7CiAgfQoKICBzaG93QWxlcnQobWVzc2FnZSwgdHlwZSA9ICdpbmZvJykgewogICAgY29uc3QgY29udGFpbmVyID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2FsZXJ0cycpOwogICAgaWYgKCFjb250YWluZXIpIHJldHVybjsKCiAgICAvLyBFbnN1cmUgY29udGFpbmVyIGlzIG92ZXJsYXkgYW5kIHRvYXN0LXJlYWR5IChDU1MgaGFuZGxlcyBwb3NpdGlvbmluZykKICAgIGNvbnRhaW5lci5jbGFzc0xpc3QuYWRkKCd0b2FzdC1zdGFjaycpOwoKICAgIGNvbnN0IGJzVHlwZSA9IFsnc3VjY2VzcycsICdkYW5nZXInLCAnd2FybmluZycsICdpbmZvJywgJ3ByaW1hcnknLCAnc2Vjb25kYXJ5J10uaW5jbHVkZXModHlwZSkgPyB0eXBlIDogJ2luZm8nOwogICAgY29uc3QgdG9hc3QgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgIHRvYXN0LmNsYXNzTmFtZSA9IGB0b2FzdCBhbGlnbi1pdGVtcy1jZW50ZXIgdGV4dC1iZy0ke2JzVHlwZX0gYm9yZGVyLTBgOwogICAgdG9hc3Quc2V0QXR0cmlidXRlKCdyb2xlJywgJ2FsZXJ0Jyk7CiAgICB0b2FzdC5zZXRBdHRyaWJ1dGUoJ2FyaWEtbGl2ZScsICdhc3NlcnRpdmUnKTsKICAgIHRvYXN0LnNldEF0dHJpYnV0ZSgnYXJpYS1hdG9taWMnLCAndHJ1ZScpOwoKICAgIGNvbnN0IGlubmVyID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICBpbm5lci5jbGFzc05hbWUgPSAnZC1mbGV4JzsKICAgIGNvbnN0IGJvZHkgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgIGJvZHkuY2xhc3NOYW1lID0gJ3RvYXN0LWJvZHknOwogICAgYm9keS50ZXh0Q29udGVudCA9IG1lc3NhZ2U7CiAgICBjb25zdCBidG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdidXR0b24nKTsKICAgIGJ0bi50eXBlID0gJ2J1dHRvbic7CiAgICBidG4uY2xhc3NOYW1lID0gJ2J0bi1jbG9zZSBidG4tY2xvc2Utd2hpdGUgbWUtMiBtLWF1dG8nOwogICAgYnRuLnNldEF0dHJpYnV0ZSgnZGF0YS1icy1kaXNtaXNzJywgJ3RvYXN0Jyk7CiAgICBidG4uc2V0QXR0cmlidXRlKCdhcmlhLWxhYmVsJywgJ0Nsb3NlJyk7CgogICAgaW5uZXIuYXBwZW5kQ2hpbGQoYm9keSk7CiAgICBpbm5lci5hcHBlbmRDaGlsZChidG4pOwogICAgdG9hc3QuYXBwZW5kQ2hpbGQoaW5uZXIpOwoKICAgIGNvbnRhaW5lci5hcHBlbmRDaGlsZCh0b2FzdCk7CgogICAgY29uc3QgaW5zdCA9IGJvb3RzdHJhcC5Ub2FzdC5nZXRPckNyZWF0ZUluc3RhbmNlKHRvYXN0LCB7IGRlbGF5OiAzNTAwIH0pOwogICAgaW5zdC5zaG93KCk7CiAgICB0b2FzdC5hZGRFdmVudExpc3RlbmVyKCdoaWRkZW4uYnMudG9hc3QnLCAoKSA9PiB0b2FzdC5yZW1vdmUoKSk7CiAgfQoKICBzaG93TG9hZGluZyhzaG93KSB7CiAgICBjb25zdCBsb2FkaW5nRWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbG9hZGluZy1pbmRpY2F0b3InKTsKICAgIGlmIChsb2FkaW5nRWwpIHsKICAgICAgbG9hZGluZ0VsLnN0eWxlLmRpc3BsYXkgPSBzaG93ID8gJ2ZsZXgnIDogJ25vbmUnOwogICAgfQogIH0KCiAgdXBkYXRlRWxlbWVudChpZCwgdmFsdWUpIHsKICAgIGNvbnN0IGVsZW1lbnQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChpZCk7CiAgICBpZiAoZWxlbWVudCkgewogICAgICBlbGVtZW50LnRleHRDb250ZW50ID0gdmFsdWU7CiAgICB9CiAgfQoKICB1cGRhdGVMYXN0UmVmcmVzaCgpIHsKICAgIHRoaXMudXBkYXRlRWxlbWVudCgnbGFzdC1yZWZyZXNoJywgbmV3IERhdGUoKS50b0xvY2FsZVRpbWVTdHJpbmcoKSk7CiAgfQp9CgovLyBJbml0aWFsaXplIHdoZW4gRE9NIGlzIGxvYWRlZApkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdET01Db250ZW50TG9hZGVkJywgKCkgPT4gewogIHdpbmRvdy5wZ3cgPSBuZXcgUEdXTWFuYWdlcigpOwp9KTsKCi8vIFNldCBhY3RpdmUgbmF2aWdhdGlvbgpkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdET01Db250ZW50TG9hZGVkJywgKCkgPT4gewogIGNvbnN0IGN1cnJlbnRQYXRoID0gd2luZG93LmxvY2F0aW9uLnBhdGhuYW1lOwogIGNvbnN0IG5hdkxpbmtzID0gZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgnLm5hdi1saW5rJyk7CgogIG5hdkxpbmtzLmZvckVhY2gobGluayA9PiB7CiAgICBsaW5rLmNsYXNzTGlzdC5yZW1vdmUoJ2FjdGl2ZScpOwogICAgaWYgKGxpbmsuZ2V0QXR0cmlidXRlKCdocmVmJykgPT09IGN1cnJlbnRQYXRoKSB7CiAgICAgIGxpbmsuY2xhc3NMaXN0LmFkZCgnYWN0aXZlJyk7CiAgICB9CiAgfSk7Cn0pOwo=`
