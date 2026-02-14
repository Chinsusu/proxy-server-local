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
  <link rel="stylesheet" href="/static/styles.css?v=1771068456">
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
  <script src="/static/app.js?v=1771068456"></script>
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
  <link rel="stylesheet" href="/static/styles.css?v=1771068456">
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
  <script src="/static/app.js?v=1771068456"></script>
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
  <link rel="stylesheet" href="/static/styles.css?v=1771068456">
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
  <script src="/static/app.js?v=1771068456"></script>
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

const embeddedJSBase64 = `Y2xhc3MgUEdXTWFuYWdlciB7CiAgY29uc3RydWN0b3IoKSB7CiAgICB0aGlzLmFwaUJhc2UgPSAnL2FwaSc7CiAgICB0aGlzLmFnZW50QmFzZSA9ICcvYWdlbnQnOwogICAgdGhpcy5wcm94aWVzID0gW107CiAgICB0aGlzLmNsaWVudHMgPSBbXTsKICAgIHRoaXMubWFwcGluZ3MgPSBbXTsKICAgIHRoaXMubG9hZGluZyA9IGZhbHNlOwogICAgLy8gc29ydGluZyBzdGF0ZSAocGVyc2lzdGVkKQogICAgdGhpcy5wU29ydCA9ICdhZGRyZXNzJzsgdGhpcy5wQXNjID0gdHJ1ZTsKICAgIHRoaXMubVNvcnQgPSAnY2xpZW50JzsgdGhpcy5tQXNjID0gdHJ1ZTsKICAgIHRyeSB7CiAgICAgIGNvbnN0IHNwID0gSlNPTi5wYXJzZShsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgncGd3X3NvcnRfcDInKSB8fCAne30nKTsKICAgICAgaWYgKHNwICYmIHNwLmspIHsgdGhpcy5wU29ydCA9IHNwLms7IHRoaXMucEFzYyA9ICEhc3AuYTsgfQogICAgICBjb25zdCBzbSA9IEpTT04ucGFyc2UobG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Bnd19zb3J0X20yJykgfHwgJ3t9Jyk7CiAgICAgIGlmIChzbSAmJiBzbS5rKSB7IHRoaXMubVNvcnQgPSBzbS5rOyB0aGlzLm1Bc2MgPSAhIXNtLmE7IH0KICAgIH0gY2F0Y2ggKF8pIHsgfQoKICAgIHRoaXMuaW5pdCgpOwogIH0KCiAgaW5pdCgpIHsKICAgIHRoaXMuYmluZEV2ZW50cygpOwogICAgdGhpcy5sb2FkRGF0YSgpOwoKICAgIC8vIEF1dG8gcmVmcmVzaCBldmVyeSAzMCBzZWNvbmRzCiAgICBzZXRJbnRlcnZhbCgoKSA9PiB0aGlzLmxvYWREYXRhKCksIDMwMDAwKTsKICB9CgogIGJpbmRFdmVudHMoKSB7CiAgICAvLyBSZWZyZXNoIGJ1dHRvbgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2J0bi1yZWZyZXNoJyk/LmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogICAgICB0aGlzLmxvYWREYXRhKCk7CiAgICB9KTsKCiAgICAvLyBIZWFsdGggY2hlY2sgYWxsIHByb3hpZXMKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdidG4taGVhbHRoLWFsbCcpPy5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHsKICAgICAgdGhpcy5oZWFsdGhDaGVja0FsbCgpOwogICAgfSk7CgogICAgLy8gUmVjb25jaWxlIHJ1bGVzCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYnRuLXJlY29uY2lsZScpPy5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHsKICAgICAgdGhpcy5yZWNvbmNpbGVSdWxlcygpOwogICAgfSk7CgogICAgLy8gQ3JlYXRlIHByb3h5IGZvcm0KICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdmb3JtLXByb3h5Jyk/LmFkZEV2ZW50TGlzdGVuZXIoJ3N1Ym1pdCcsIChlKSA9PiB7CiAgICAgIGUucHJldmVudERlZmF1bHQoKTsKICAgICAgdGhpcy5jcmVhdGVQcm94eSgpOwogICAgfSk7CgoKICAgIC8vIEltcG9ydCBwcm94aWVzIChidWxrKQogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJ0bi1pbXBvcnQtcHJveGllcyIpPy5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsIChlKSA9PiB7CiAgICAgIGUucHJldmVudERlZmF1bHQoKTsKICAgICAgdGhpcy5pbXBvcnRQcm94aWVzKCk7CiAgICB9KTsKICAgIC8vIENyZWF0ZSBtYXBwaW5nIGZvcm0KICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdmb3JtLW1hcHBpbmcnKT8uYWRkRXZlbnRMaXN0ZW5lcignc3VibWl0JywgKGUpID0+IHsKICAgICAgZS5wcmV2ZW50RGVmYXVsdCgpOwogICAgICB0aGlzLmNyZWF0ZU1hcHBpbmcoKTsKICAgIH0pOwogIH0KCiAgYXN5bmMgYXBpQ2FsbCh1cmwsIG9wdGlvbnMgPSB7fSkgewogICAgdHJ5IHsKICAgICAgY29uc3QgY29udHJvbGxlciA9IG5ldyBBYm9ydENvbnRyb2xsZXIoKTsKICAgICAgY29uc3QgdGltZW91dCA9IHNldFRpbWVvdXQoKCkgPT4gY29udHJvbGxlci5hYm9ydCgpLCAxMDAwMCk7CiAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZmV0Y2godXJsLCB7CiAgICAgICAgaGVhZGVyczogewogICAgICAgICAgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJywKICAgICAgICAgIC4uLm9wdGlvbnMuaGVhZGVycwogICAgICAgIH0sCiAgICAgICAgc2lnbmFsOiBjb250cm9sbGVyLnNpZ25hbCwKICAgICAgICAuLi5vcHRpb25zCiAgICAgIH0pOwogICAgICBjbGVhclRpbWVvdXQodGltZW91dCk7CgogICAgICAvLyBBdXRvLXJlZGlyZWN0IHRvIGxvZ2luIG9uIDQwMSBVbmF1dGhvcml6ZWQKICAgICAgaWYgKHJlc3BvbnNlLnN0YXR1cyA9PT0gNDAxKSB7CiAgICAgICAgd2luZG93LmxvY2F0aW9uLmhyZWYgPSAnL2xvZ2luJzsKICAgICAgICByZXR1cm4gbnVsbDsKICAgICAgfQoKICAgICAgaWYgKCFyZXNwb25zZS5vaykgewogICAgICAgIHRocm93IG5ldyBFcnJvcihgSFRUUCAke3Jlc3BvbnNlLnN0YXR1c306ICR7cmVzcG9uc2Uuc3RhdHVzVGV4dH1gKTsKICAgICAgfQoKICAgICAgaWYgKHJlc3BvbnNlLnN0YXR1cyA9PT0gMjA0KSB7CiAgICAgICAgcmV0dXJuIG51bGw7CiAgICAgIH0KCiAgICAgIHJldHVybiBhd2FpdCByZXNwb25zZS5qc29uKCk7CiAgICB9IGNhdGNoIChlcnJvcikgewogICAgICBpZiAoZXJyb3IubmFtZSA9PT0gJ0Fib3J0RXJyb3InKSB7CiAgICAgICAgY29uc29sZS5lcnJvcignQVBJIGNhbGwgdGltZWQgb3V0OicsIHVybCk7CiAgICAgICAgdGhpcy5zaG93QWxlcnQoJ0FQSSByZXF1ZXN0IHRpbWVkIG91dCDigJQgaXMgdGhlIHNlcnZlciBydW5uaW5nPycsICd3YXJuaW5nJyk7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgY29uc29sZS5lcnJvcignQVBJIGNhbGwgZmFpbGVkOicsIGVycm9yKTsKICAgICAgICB0aGlzLnNob3dBbGVydCgnQVBJIGNhbGwgZmFpbGVkOiAnICsgZXJyb3IubWVzc2FnZSwgJ2RhbmdlcicpOwogICAgICB9CiAgICAgIHRocm93IGVycm9yOwogICAgfQogIH0KCiAgYXN5bmMgbG9hZERhdGEoKSB7CiAgICBpZiAodGhpcy5sb2FkaW5nKSByZXR1cm47CgogICAgdGhpcy5sb2FkaW5nID0gdHJ1ZTsKICAgIGxldCBfc3Bpbm5lclRPID0gc2V0VGltZW91dCgoKSA9PiB0aGlzLnNob3dMb2FkaW5nKHRydWUpLCA3MDApOwoKICAgIHRyeSB7CiAgICAgIGNvbnN0IFtwcm94aWVzLCBjbGllbnRzLCBtYXBwaW5nc10gPSBhd2FpdCBQcm9taXNlLmFsbChbCiAgICAgICAgdGhpcy5hcGlDYWxsKGAke3RoaXMuYXBpQmFzZX0vdjEvcHJveGllc2ApLAogICAgICAgIHRoaXMuYXBpQ2FsbChgJHt0aGlzLmFwaUJhc2V9L3YxL2NsaWVudHNgKSwKICAgICAgICB0aGlzLmFwaUNhbGwoYCR7dGhpcy5hcGlCYXNlfS92MS9tYXBwaW5ncy9hY3RpdmVgKQogICAgICBdKTsKCiAgICAgIHRoaXMucHJveGllcyA9IHByb3hpZXMgfHwgW107CiAgICAgIHRoaXMuY2xpZW50cyA9IGNsaWVudHMgfHwgW107CiAgICAgIHRoaXMubWFwcGluZ3MgPSBtYXBwaW5ncyB8fCBbXTsKCiAgICAgIHRoaXMucmVuZGVyU3RhdHMoKTsKICAgICAgdGhpcy5yZW5kZXJQcm94aWVzKCk7CiAgICAgIHRoaXMucmVuZGVyUHJveHlTdW1tYXJ5KCk7CiAgICAgIHRoaXMucmVuZGVyTWFwcGluZ3MoKTsKICAgICAgdGhpcy5yZW5kZXJDbGllbnRzKCk7CiAgICAgIHRoaXMudXBkYXRlQ291bnRzKCk7CiAgICAgIHRoaXMudXBkYXRlTGFzdFJlZnJlc2goKTsKICAgICAgdGhpcy5jaGVja1NlcnZpY2VzKCk7CgogICAgfSBjYXRjaCAoZXJyb3IpIHsKICAgICAgY29uc29sZS5lcnJvcignRmFpbGVkIHRvIGxvYWQgZGF0YTonLCBlcnJvcik7CiAgICB9IGZpbmFsbHkgewogICAgICB0aGlzLmxvYWRpbmcgPSBmYWxzZTsKICAgICAgY2xlYXJUaW1lb3V0KF9zcGlubmVyVE8pOwogICAgICB0aGlzLnNob3dMb2FkaW5nKGZhbHNlKTsKICAgIH0KICB9CgogIGFzeW5jIGNoZWNrU2VydmljZXMoKSB7CiAgICAvLyBBUEkgaGVhbHRoCiAgICBjb25zdCBhcGlFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdhcGktc3RhdHVzJyk7CiAgICBpZiAoYXBpRWwpIHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCByID0gYXdhaXQgZmV0Y2goYCR7dGhpcy5hcGlCYXNlfS92MS9oZWFsdGhgLCB7IG1ldGhvZDogJ0dFVCcgfSk7CiAgICAgICAgaWYgKHIub2spIHsKICAgICAgICAgIGFwaUVsLnRleHRDb250ZW50ID0gJ1J1bm5pbmcnOwogICAgICAgICAgYXBpRWwuY2xhc3NOYW1lID0gJ2JhZGdlIHRleHQtYmctc3VjY2Vzcyc7CiAgICAgICAgfSBlbHNlIHsKICAgICAgICAgIGFwaUVsLnRleHRDb250ZW50ID0gJ0Vycm9yJzsKICAgICAgICAgIGFwaUVsLmNsYXNzTmFtZSA9ICdiYWRnZSB0ZXh0LWJnLXdhcm5pbmcnOwogICAgICAgIH0KICAgICAgfSBjYXRjaCB7CiAgICAgICAgYXBpRWwudGV4dENvbnRlbnQgPSAnRG93bic7CiAgICAgICAgYXBpRWwuY2xhc3NOYW1lID0gJ2JhZGdlIHRleHQtYmctZGFuZ2VyJzsKICAgICAgfQogICAgfQoKICAgIC8vIEFnZW50IGhlYWx0aAogICAgY29uc3QgYWdlbnRFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdhZ2VudC1zdGF0dXMnKTsKICAgIGlmIChhZ2VudEVsKSB7CiAgICAgIHRyeSB7CiAgICAgICAgY29uc3QgciA9IGF3YWl0IGZldGNoKGAke3RoaXMuYWdlbnRCYXNlfS9oZWFsdGhgLCB7IG1ldGhvZDogJ0hFQUQnIH0pOwogICAgICAgIGlmIChyLm9rKSB7CiAgICAgICAgICBhZ2VudEVsLnRleHRDb250ZW50ID0gJ1J1bm5pbmcnOwogICAgICAgICAgYWdlbnRFbC5jbGFzc05hbWUgPSAnYmFkZ2UgdGV4dC1iZy1zdWNjZXNzJzsKICAgICAgICB9IGVsc2UgewogICAgICAgICAgYWdlbnRFbC50ZXh0Q29udGVudCA9ICdFcnJvcic7CiAgICAgICAgICBhZ2VudEVsLmNsYXNzTmFtZSA9ICdiYWRnZSB0ZXh0LWJnLXdhcm5pbmcnOwogICAgICAgIH0KICAgICAgfSBjYXRjaCB7CiAgICAgICAgYWdlbnRFbC50ZXh0Q29udGVudCA9ICdEb3duJzsKICAgICAgICBhZ2VudEVsLmNsYXNzTmFtZSA9ICdiYWRnZSB0ZXh0LWJnLWRhbmdlcic7CiAgICAgIH0KICAgIH0KCiAgICAvLyBGb3J3YXJkZXIgc3RhdHVzOiBpbmZlcnJlZCBmcm9tIGFwcGxpZWQgbWFwcGluZ3MKICAgIGNvbnN0IGZ3ZEVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2Z3ZC1zdGF0dXMnKTsKICAgIGlmIChmd2RFbCkgewogICAgICBjb25zdCBhcHBsaWVkID0gKHRoaXMubWFwcGluZ3MgfHwgW10pLmZpbHRlcihtID0+IG0uc3RhdGUgPT09ICdBUFBMSUVEJykubGVuZ3RoOwogICAgICBpZiAoYXBwbGllZCA+IDApIHsKICAgICAgICBmd2RFbC50ZXh0Q29udGVudCA9IGAke2FwcGxpZWR9IGFjdGl2ZWA7CiAgICAgICAgZndkRWwuY2xhc3NOYW1lID0gJ2JhZGdlIHRleHQtYmctc3VjY2Vzcyc7CiAgICAgIH0gZWxzZSBpZiAoKHRoaXMubWFwcGluZ3MgfHwgW10pLmxlbmd0aCA+IDApIHsKICAgICAgICBmd2RFbC50ZXh0Q29udGVudCA9ICdQZW5kaW5nJzsKICAgICAgICBmd2RFbC5jbGFzc05hbWUgPSAnYmFkZ2UgdGV4dC1iZy13YXJuaW5nJzsKICAgICAgfSBlbHNlIHsKICAgICAgICBmd2RFbC50ZXh0Q29udGVudCA9ICdObyBtYXBwaW5ncyc7CiAgICAgICAgZndkRWwuY2xhc3NOYW1lID0gJ2JhZGdlIHRleHQtYmctc2Vjb25kYXJ5JzsKICAgICAgfQogICAgfQogIH0KCiAgcmVuZGVyU3RhdHMoKSB7CiAgICBjb25zdCBva1Byb3hpZXMgPSB0aGlzLnByb3hpZXMuZmlsdGVyKHAgPT4gcC5zdGF0dXMgPT09ICdPSycpLmxlbmd0aDsKICAgIGNvbnN0IGFjdGl2ZU1hcHBpbmdzID0gdGhpcy5tYXBwaW5ncy5maWx0ZXIobSA9PiBtLmNsaWVudD8uZW5hYmxlZCAmJiBtLnByb3h5Py5lbmFibGVkKS5sZW5ndGg7CgogICAgdGhpcy51cGRhdGVFbGVtZW50KCdzdGF0LXByb3hpZXMnLCB0aGlzLnByb3hpZXMubGVuZ3RoKTsKICAgIHRoaXMudXBkYXRlRWxlbWVudCgnc3RhdC1wcm94aWVzLW9rJywgb2tQcm94aWVzKTsKICAgIHRoaXMudXBkYXRlRWxlbWVudCgnc3RhdC1jbGllbnRzJywgdGhpcy5jbGllbnRzLmxlbmd0aCk7CiAgICB0aGlzLnVwZGF0ZUVsZW1lbnQoJ3N0YXQtbWFwcGluZ3MnLCBhY3RpdmVNYXBwaW5ncyk7CiAgfQoKICByZW5kZXJQcm94aWVzKCkgewogICAgY29uc3QgdGJvZHkgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGJvZHktcHJveGllcycpOwogICAgaWYgKCF0Ym9keSkgcmV0dXJuOwogICAgLy8gc29ydAogICAgY29uc3Qga2V5ID0gdGhpcy5wU29ydCwgYXNjID0gdGhpcy5wQXNjOwogICAgY29uc3QgdmFsID0gKHApID0+IHsKICAgICAgaWYgKGtleSA9PT0gJ2lkJykgcmV0dXJuIChwLmlkIHx8ICcnKTsKICAgICAgaWYgKGtleSA9PT0gJ3R5cGUnKSByZXR1cm4gKHAudHlwZSB8fCAnJyk7CiAgICAgIGlmIChrZXkgPT09ICdhZGRyZXNzJykgcmV0dXJuICgocC5ob3N0IHx8ICcnKSArICc6JyArIHAucG9ydCkudG9Mb3dlckNhc2UoKTsKICAgICAgaWYgKGtleSA9PT0gJ3N0YXR1cycpIHJldHVybiAocC5zdGF0dXMgfHwgJycpOwogICAgICBpZiAoa2V5ID09PSAnbGF0ZW5jeScpIHJldHVybiAocC5sYXRlbmN5X21zID09IG51bGwgPyBJbmZpbml0eSA6IHAubGF0ZW5jeV9tcyk7CiAgICAgIGlmIChrZXkgPT09ICdleGl0JykgcmV0dXJuIChwLmV4aXRfaXAgfHwgJycpOwogICAgICBpZiAoa2V5ID09PSAnbGFzdCcpIHJldHVybiAocC5sYXN0X2NoZWNrZWRfYXQgfHwgJycpOwogICAgICByZXR1cm4gKChwLmhvc3QgfHwgJycpICsgJzonICsgcC5wb3J0KS50b0xvd2VyQ2FzZSgpOwogICAgfTsKICAgIGNvbnN0IHNvcnRlZCA9ICh0aGlzLnByb3hpZXMgfHwgW10pLnNsaWNlKCkuc29ydCgoYSwgYikgPT4geyBjb25zdCB2YSA9IHZhbChhKSwgdmIgPSB2YWwoYik7IGlmICh2YSA8IHZiKSByZXR1cm4gYXNjID8gLTEgOiAxOyBpZiAodmEgPiB2YikgcmV0dXJuIGFzYyA/IDEgOiAtMTsgcmV0dXJuIDA7IH0pOwogICAgLy8gaGVhZGVyIGljb25zICsgY2xpY2sKICAgIGNvbnN0IHRoZWFkID0gdGJvZHkucGFyZW50RWxlbWVudD8ucXVlcnlTZWxlY3RvcigndGhlYWQnKTsKICAgIGlmICh0aGVhZCkgewogICAgICBjb25zdCBhcnJvdyA9IGFzYyA/ICcgXFx1MjVCMicgOiAnIFxcdTI1QkMnOwogICAgICB0aGVhZC5pbm5lckhUTUwgPSAnPHRyPicKICAgICAgICArICc8dGggZGF0YS1rPSJpZCIgY2xhc3M9InNvcnRhYmxlIj5JRCcgKyAoa2V5ID09PSAnaWQnID8gYXJyb3cgOiAnJykgKyAnPC90aD4nCiAgICAgICAgKyAnPHRoIGRhdGEtaz0idHlwZSIgY2xhc3M9InNvcnRhYmxlIj5UeXBlJyArIChrZXkgPT09ICd0eXBlJyA/IGFycm93IDogJycpICsgJzwvdGg+JwogICAgICAgICsgJzx0aCBkYXRhLWs9ImFkZHJlc3MiIGNsYXNzPSJzb3J0YWJsZSI+QWRkcmVzcycgKyAoa2V5ID09PSAnYWRkcmVzcycgPyBhcnJvdyA6ICcnKSArICc8L3RoPicKICAgICAgICArICc8dGggZGF0YS1rPSJzdGF0dXMiIGNsYXNzPSJzb3J0YWJsZSI+U3RhdHVzJyArIChrZXkgPT09ICdzdGF0dXMnID8gYXJyb3cgOiAnJykgKyAnPC90aD4nCiAgICAgICAgKyAnPHRoIGRhdGEtaz0ibGF0ZW5jeSIgY2xhc3M9InNvcnRhYmxlIj5MYXRlbmN5JyArIChrZXkgPT09ICdsYXRlbmN5JyA/IGFycm93IDogJycpICsgJzwvdGg+JwogICAgICAgICsgJzx0aCBkYXRhLWs9ImV4aXQiIGNsYXNzPSJzb3J0YWJsZSI+RXhpdCBJUCcgKyAoa2V5ID09PSAnZXhpdCcgPyBhcnJvdyA6ICcnKSArICc8L3RoPicKICAgICAgICArICc8dGggZGF0YS1rPSJsYXN0IiBjbGFzcz0ic29ydGFibGUiPkxhc3QgQ2hlY2snICsgKGtleSA9PT0gJ2xhc3QnID8gYXJyb3cgOiAnJykgKyAnPC90aD4nCiAgICAgICAgKyAnPHRoPkFjdGlvbnM8L3RoPicKICAgICAgICArICc8L3RyPic7CiAgICAgIHRoZWFkLnF1ZXJ5U2VsZWN0b3JBbGwoJ3RoLnNvcnRhYmxlJykuZm9yRWFjaCgodGgpID0+IHsKICAgICAgICB0aC5zdHlsZS5jdXJzb3IgPSAncG9pbnRlcic7IHRoLm9uY2xpY2sgPSAoKSA9PiB7CiAgICAgICAgICBjb25zdCBrID0gdGguZ2V0QXR0cmlidXRlKCdkYXRhLWsnKTsKICAgICAgICAgIGlmICh0aGlzLnBTb3J0ID09PSBrKSB0aGlzLnBBc2MgPSAhdGhpcy5wQXNjOyBlbHNlIHsgdGhpcy5wU29ydCA9IGs7IHRoaXMucEFzYyA9IHRydWU7IH0KICAgICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCdwZ3dfc29ydF9wMicsIEpTT04uc3RyaW5naWZ5KHsgazogdGhpcy5wU29ydCwgYTogdGhpcy5wQXNjIH0pKTsKICAgICAgICAgIHRoaXMucmVuZGVyUHJveGllcygpOwogICAgICAgIH07CiAgICAgIH0pOwogICAgfQoKICAgIHRib2R5LmlubmVySFRNTCA9ICcnOwoKICAgIGlmIChzb3J0ZWQubGVuZ3RoID09PSAwKSB7CiAgICAgIHRib2R5LmlubmVySFRNTCA9ICc8dHI+PHRkIGNvbHNwYW49IjgiIGNsYXNzPSJ0ZXh0LWNlbnRlciI+Tm8gcHJveGllcyBjb25maWd1cmVkPC90ZD48L3RyPic7CiAgICAgIHJldHVybjsKICAgIH0KCiAgICBzb3J0ZWQuZm9yRWFjaChwcm94eSA9PiB7CiAgICAgIGNvbnN0IHJvdyA9IHRoaXMuY3JlYXRlUHJveHlSb3cocHJveHkpOwogICAgICB0Ym9keS5hcHBlbmRDaGlsZChyb3cpOwogICAgfSk7CiAgfQoKICByZW5kZXJQcm94eVN1bW1hcnkoKSB7CiAgICBjb25zdCB0Ym9keSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0Ym9keS1wcm94eS1zdW1tYXJ5Jyk7CiAgICBpZiAoIXRib2R5KSByZXR1cm47CgogICAgdGJvZHkuaW5uZXJIVE1MID0gJyc7CgogICAgaWYgKHRoaXMucHJveGllcy5sZW5ndGggPT09IDApIHsKICAgICAgdGJvZHkuaW5uZXJIVE1MID0gJzx0cj48dGQgY29sc3Bhbj0iNSIgY2xhc3M9InRleHQtY2VudGVyIj5ObyBwcm94aWVzIGNvbmZpZ3VyZWQ8L3RkPjwvdHI+JzsKICAgICAgcmV0dXJuOwogICAgfQoKICAgIHRoaXMucHJveGllcy5mb3JFYWNoKHByb3h5ID0+IHsKICAgICAgY29uc3QgdHIgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCd0cicpOwogICAgICBjb25zdCBzdGF0dXNCYWRnZSA9IHRoaXMuY3JlYXRlU3RhdHVzQmFkZ2UocHJveHkuc3RhdHVzKTsKICAgICAgY29uc3QgbGF0ZW5jeUJhZGdlID0gdGhpcy5jcmVhdGVMYXRlbmN5QmFkZ2UocHJveHkubGF0ZW5jeV9tcyk7CiAgICAgIGNvbnN0IGxhc3RDaGVja2VkID0gcHJveHkubGFzdF9jaGVja2VkX2F0CiAgICAgICAgPyBuZXcgRGF0ZShwcm94eS5sYXN0X2NoZWNrZWRfYXQpLnRvTG9jYWxlVGltZVN0cmluZygpCiAgICAgICAgOiAn4oCUJzsKCiAgICAgIHRyLmlubmVySFRNTCA9IGAKICAgICAgICA8dGQ+JHtwcm94eS5ob3N0fToke3Byb3h5LnBvcnR9PC90ZD4KICAgICAgICA8dGQ+JHtzdGF0dXNCYWRnZX08L3RkPgogICAgICAgIDx0ZD4ke2xhdGVuY3lCYWRnZX08L3RkPgogICAgICAgIDx0ZD4ke3Byb3h5LmV4aXRfaXAgfHwgJ+KAlCd9PC90ZD4KICAgICAgICA8dGQ+JHtsYXN0Q2hlY2tlZH08L3RkPgogICAgICBgOwogICAgICB0Ym9keS5hcHBlbmRDaGlsZCh0cik7CiAgICB9KTsKICB9CgogIGNyZWF0ZVByb3h5Um93KHByb3h5KSB7CiAgICBjb25zdCB0ciA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ3RyJyk7CgogICAgY29uc3Qgc3RhdHVzQmFkZ2UgPSB0aGlzLmNyZWF0ZVN0YXR1c0JhZGdlKHByb3h5LnN0YXR1cyk7CiAgICBjb25zdCBsYXRlbmN5QmFkZ2UgPSB0aGlzLmNyZWF0ZUxhdGVuY3lCYWRnZShwcm94eS5sYXRlbmN5X21zKTsKICAgIGNvbnN0IGxhc3RDaGVja2VkID0gcHJveHkubGFzdF9jaGVja2VkX2F0CiAgICAgID8gbmV3IERhdGUocHJveHkubGFzdF9jaGVja2VkX2F0KS50b0xvY2FsZVRpbWVTdHJpbmcoKQogICAgICA6ICfigJQnOwoKICAgIHRyLmlubmVySFRNTCA9IGAKICAgICAgPHRkPjxjb2RlPiR7cHJveHkuaWQuc2xpY2UoMCwgOCl9PC9jb2RlPjwvdGQ+CiAgICAgIDx0ZD4ke3Byb3h5LnR5cGV9PC90ZD4KICAgICAgPHRkPiR7cHJveHkuaG9zdH06JHtwcm94eS5wb3J0fTwvdGQ+CiAgICAgIDx0ZD4ke3N0YXR1c0JhZGdlfTwvdGQ+CiAgICAgIDx0ZD4ke2xhdGVuY3lCYWRnZX08L3RkPgogICAgICA8dGQ+JHtwcm94eS5leGl0X2lwIHx8ICfigJQnfTwvdGQ+CiAgICAgIDx0ZD4ke2xhc3RDaGVja2VkfTwvdGQ+CiAgICAgIDx0ZD4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXNtIGJ0bi1zZWNvbmRhcnkiIG9uY2xpY2s9InBndy5jaGVja1Byb3h5SGVhbHRoKCcke3Byb3h5LmlkfScpIiBkYXRhLXRvb2x0aXA9IkhlYWx0aCBjaGVjayI+CiAgICAgICAgICBDaGVjawogICAgICAgIDwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tc20gYnRuLWRhbmdlciIgb25jbGljaz0icGd3LmRlbGV0ZVByb3h5KCcke3Byb3h5LmlkfScpIiBkYXRhLXRvb2x0aXA9IkRlbGV0ZSBwcm94eSI+CiAgICAgICAgICDDlwogICAgICAgIDwvYnV0dG9uPgogICAgICA8L3RkPgogICAgYDsKCiAgICByZXR1cm4gdHI7CiAgfQoKICBjcmVhdGVTdGF0dXNCYWRnZShzdGF0dXMpIHsKICAgIGNvbnN0IHN0YXR1c0NsYXNzID0gewogICAgICAnT0snOiAndGV4dC1iZy1zdWNjZXNzJywKICAgICAgJ0RFR1JBREVEJzogJ3RleHQtYmctd2FybmluZycsCiAgICAgICdET1dOJzogJ3RleHQtYmctZGFuZ2VyJwogICAgfVtzdGF0dXNdIHx8ICd0ZXh0LWJnLXNlY29uZGFyeSc7CgogICAgcmV0dXJuIGA8c3BhbiBjbGFzcz0iYmFkZ2UgJHtzdGF0dXNDbGFzc30iPiR7c3RhdHVzIHx8ICdVbmtub3duJ308L3NwYW4+YDsKICB9CgogIGNyZWF0ZUxhdGVuY3lCYWRnZShtcykgewogICAgaWYgKG1zID09IG51bGwgfHwgaXNOYU4obXMpKSByZXR1cm4gJ+KAlCc7CiAgICBsZXQgY2xzID0gJ3RleHQtYmctZGFuZ2VyJzsKICAgIGlmIChtcyA8IDMwMCkgY2xzID0gJ3RleHQtYmctc3VjY2Vzcyc7CiAgICBlbHNlIGlmIChtcyA8IDkwMCkgY2xzID0gJ3RleHQtYmctd2FybmluZyc7CiAgICByZXR1cm4gYDxzcGFuIGNsYXNzPSJiYWRnZSAke2Nsc30iPiR7bXN9bXM8L3NwYW4+YDsKICB9CgoKICByZW5kZXJNYXBwaW5ncygpIHsKICAgIGNvbnN0IHRib2R5ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3Rib2R5LW1hcHBpbmdzJyk7CiAgICBpZiAoIXRib2R5KSByZXR1cm47CiAgICAvLyBzb3J0CiAgICBjb25zdCBrZXkgPSB0aGlzLm1Tb3J0LCBhc2MgPSB0aGlzLm1Bc2M7CiAgICBjb25zdCB2YWwgPSAobSkgPT4gewogICAgICBpZiAoa2V5ID09PSAnaWQnKSByZXR1cm4gKG0uaWQgfHwgJycpOwogICAgICBpZiAoa2V5ID09PSAnY2xpZW50JykgcmV0dXJuICgobS5jbGllbnQ/LmlwX2NpZHIpIHx8ICcnKTsKICAgICAgaWYgKGtleSA9PT0gJ3Byb3h5JykgeyBjb25zdCBwID0gbS5wcm94eSB8fCB7fTsgcmV0dXJuICgocC5ob3N0IHx8ICcnKSArICc6JyArIChwLnBvcnQgPz8gJycpKTsgfQogICAgICBpZiAoa2V5ID09PSAnc3RhdGUnKSByZXR1cm4gKG0uc3RhdGUgfHwgJycpOwogICAgICBpZiAoa2V5ID09PSAncG9ydCcpIHJldHVybiAobS5sb2NhbF9yZWRpcmVjdF9wb3J0ID8/IDApOwogICAgICByZXR1cm4gKChtLmNsaWVudD8uaXBfY2lkcikgfHwgJycpOwogICAgfTsKICAgIGNvbnN0IHNvcnRlZCA9ICh0aGlzLm1hcHBpbmdzIHx8IFtdKS5zbGljZSgpLnNvcnQoKGEsIGIpID0+IHsgY29uc3QgdmEgPSB2YWwoYSksIHZiID0gdmFsKGIpOyBpZiAodmEgPCB2YikgcmV0dXJuIGFzYyA/IC0xIDogMTsgaWYgKHZhID4gdmIpIHJldHVybiBhc2MgPyAxIDogLTE7IHJldHVybiAwOyB9KTsKICAgIC8vIGhlYWRlciBpY29ucyArIGNsaWNrCiAgICBjb25zdCB0aGVhZCA9IHRib2R5LnBhcmVudEVsZW1lbnQ/LnF1ZXJ5U2VsZWN0b3IoJ3RoZWFkJyk7CiAgICBpZiAodGhlYWQpIHsKICAgICAgY29uc3QgYXJyb3cgPSBhc2MgPyAnIFxcdTI1QjInIDogJyBcXHUyNUJDJzsKICAgICAgdGhlYWQuaW5uZXJIVE1MID0gJzx0cj4nCiAgICAgICAgKyAnPHRoIGRhdGEtaz0iaWQiIGNsYXNzPSJzb3J0YWJsZSI+SUQnICsgKGtleSA9PT0gJ2lkJyA/IGFycm93IDogJycpICsgJzwvdGg+JwogICAgICAgICsgJzx0aCBkYXRhLWs9ImNsaWVudCIgY2xhc3M9InNvcnRhYmxlIj5DbGllbnQgSVAvQ0lEUicgKyAoa2V5ID09PSAnY2xpZW50JyA/IGFycm93IDogJycpICsgJzwvdGg+JwogICAgICAgICsgJzx0aCBkYXRhLWs9InByb3h5IiBjbGFzcz0ic29ydGFibGUiPlByb3h5IFNlcnZlcicgKyAoa2V5ID09PSAncHJveHknID8gYXJyb3cgOiAnJykgKyAnPC90aD4nCiAgICAgICAgKyAnPHRoIGRhdGEtaz0ic3RhdGUiIGNsYXNzPSJzb3J0YWJsZSI+U3RhdGUnICsgKGtleSA9PT0gJ3N0YXRlJyA/IGFycm93IDogJycpICsgJzwvdGg+JwogICAgICAgICsgJzx0aCBkYXRhLWs9InBvcnQiIGNsYXNzPSJzb3J0YWJsZSI+TG9jYWwgUG9ydCcgKyAoa2V5ID09PSAncG9ydCcgPyBhcnJvdyA6ICcnKSArICc8L3RoPicKICAgICAgICArICc8dGg+QWN0aW9uczwvdGg+JwogICAgICAgICsgJzwvdHI+JzsKICAgICAgdGhlYWQucXVlcnlTZWxlY3RvckFsbCgndGguc29ydGFibGUnKS5mb3JFYWNoKCh0aCkgPT4gewogICAgICAgIHRoLnN0eWxlLmN1cnNvciA9ICdwb2ludGVyJzsgdGgub25jbGljayA9ICgpID0+IHsKICAgICAgICAgIGNvbnN0IGsgPSB0aC5nZXRBdHRyaWJ1dGUoJ2RhdGEtaycpOwogICAgICAgICAgaWYgKHRoaXMubVNvcnQgPT09IGspIHRoaXMubUFzYyA9ICF0aGlzLm1Bc2M7IGVsc2UgeyB0aGlzLm1Tb3J0ID0gazsgdGhpcy5tQXNjID0gdHJ1ZTsgfQogICAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ3Bnd19zb3J0X20yJywgSlNPTi5zdHJpbmdpZnkoeyBrOiB0aGlzLm1Tb3J0LCBhOiB0aGlzLm1Bc2MgfSkpOwogICAgICAgICAgdGhpcy5yZW5kZXJNYXBwaW5ncygpOwogICAgICAgIH07CiAgICAgIH0pOwogICAgfQoKICAgIHRib2R5LmlubmVySFRNTCA9ICcnOwoKICAgIGlmIChzb3J0ZWQubGVuZ3RoID09PSAwKSB7CiAgICAgIHRib2R5LmlubmVySFRNTCA9ICc8dHI+PHRkIGNvbHNwYW49IjYiIGNsYXNzPSJ0ZXh0LWNlbnRlciI+Tm8gbWFwcGluZ3MgY29uZmlndXJlZDwvdGQ+PC90cj4nOwogICAgICByZXR1cm47CiAgICB9CgogICAgc29ydGVkLmZvckVhY2gobWFwcGluZyA9PiB7CiAgICAgIGNvbnN0IHJvdyA9IHRoaXMuY3JlYXRlTWFwcGluZ1JvdyhtYXBwaW5nKTsKICAgICAgdGJvZHkuYXBwZW5kQ2hpbGQocm93KTsKICAgIH0pOwogIH0KCiAgY3JlYXRlTWFwcGluZ1JvdyhtYXBwaW5nKSB7CiAgICBjb25zdCB0ciA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ3RyJyk7CgogICAgY29uc3QgcHJveHlBZGRyZXNzID0gbWFwcGluZy5wcm94eQogICAgICA/IGAke21hcHBpbmcucHJveHkuaG9zdH06JHttYXBwaW5nLnByb3h5LnBvcnR9YAogICAgICA6ICfigJQnOwoKICAgIGNvbnN0IHN0YXRlQmFkZ2UgPSB0aGlzLmNyZWF0ZVN0YXR1c0JhZGdlKG1hcHBpbmcuc3RhdGUgfHwgJ1BFTkRJTkcnKTsKCiAgICB0ci5pbm5lckhUTUwgPSBgCiAgICAgIDx0ZD48Y29kZT4ke21hcHBpbmcuaWQuc2xpY2UoMCwgOCl9PC9jb2RlPjwvdGQ+CiAgICAgIDx0ZD4ke21hcHBpbmcuY2xpZW50Py5pcF9jaWRyIHx8ICfigJQnfTwvdGQ+CiAgICAgIDx0ZD4ke3Byb3h5QWRkcmVzc308L3RkPgogICAgICA8dGQ+JHtzdGF0ZUJhZGdlfTwvdGQ+CiAgICAgIDx0ZD4ke21hcHBpbmcubG9jYWxfcmVkaXJlY3RfcG9ydCB8fCAn4oCUJ308L3RkPgogICAgICA8dGQ+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1zbSBidG4tZGFuZ2VyIiBvbmNsaWNrPSJwZ3cuZGVsZXRlTWFwcGluZygnJHttYXBwaW5nLmlkfScpIj4KICAgICAgICAgIERlbGV0ZQogICAgICAgIDwvYnV0dG9uPgogICAgICA8L3RkPgogICAgYDsKCiAgICByZXR1cm4gdHI7CiAgfQoKICByZW5kZXJDbGllbnRzKCkgewogICAgY29uc3Qgc2VsZWN0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3NlbGVjdC1wcm94eScpOwogICAgaWYgKCFzZWxlY3QpIHJldHVybjsKCiAgICBzZWxlY3QuaW5uZXJIVE1MID0gJzxvcHRpb24gdmFsdWU9IiI+U2VsZWN0IHByb3h5IHNlcnZlci4uLjwvb3B0aW9uPic7CgogICAgY29uc3QgdXNlZCA9IG5ldyBTZXQoKHRoaXMubWFwcGluZ3MgfHwgW10pLm1hcChtID0+IG0gJiYgbS5wcm94eSA/IG0ucHJveHkuaWQgOiBudWxsKS5maWx0ZXIoQm9vbGVhbikpOwogICAgY29uc3QgYXZhaWxhYmxlID0gKHRoaXMucHJveGllcyB8fCBbXSkuZmlsdGVyKHAgPT4gIXVzZWQuaGFzKHAuaWQpKTsKCiAgICBpZiAoIWF2YWlsYWJsZSB8fCBhdmFpbGFibGUubGVuZ3RoID09PSAwKSB7CiAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ29wdGlvbicpOwogICAgICBvcHQuZGlzYWJsZWQgPSB0cnVlOwogICAgICBvcHQudGV4dENvbnRlbnQgPSAnTm8gYXZhaWxhYmxlIHByb3hpZXMgKGFsbCBtYXBwZWQpJzsKICAgICAgc2VsZWN0LmFwcGVuZENoaWxkKG9wdCk7CiAgICAgIHJldHVybjsKICAgIH0KCiAgICBhdmFpbGFibGUuZm9yRWFjaChwcm94eSA9PiB7CiAgICAgIGNvbnN0IG9wdGlvbiA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ29wdGlvbicpOwogICAgICBvcHRpb24udmFsdWUgPSBwcm94eS5pZDsKICAgICAgY29uc3Qgc3RhdHVzSW5kaWNhdG9yID0gcHJveHkuc3RhdHVzID09PSAnT0snID8gJ+KckycgOiBwcm94eS5zdGF0dXMgPT09ICdERUdSQURFRCcgPyAn4pqgJyA6ICfinJcnOwogICAgICBvcHRpb24udGV4dENvbnRlbnQgPSBgJHtzdGF0dXNJbmRpY2F0b3J9ICR7cHJveHkuaG9zdH06JHtwcm94eS5wb3J0fSAoJHtwcm94eS50eXBlfSlgOwogICAgICBzZWxlY3QuYXBwZW5kQ2hpbGQob3B0aW9uKTsKICAgIH0pOwogIH0KICBkZXRlY3RQcm94eVR5cGUob3JpZ2luYWxMaW5lLCBob3N0LCBwb3J0KSB7CiAgICAvLyBDaGVjayBmb3IgZXhwbGljaXQgdHlwZSBwcmVmaXgKICAgIGlmIChvcmlnaW5hbExpbmUuaW5jbHVkZXMoInNvY2tzNTovLyIpKSByZXR1cm4gInNvY2tzNSI7CiAgICBpZiAob3JpZ2luYWxMaW5lLmluY2x1ZGVzKCJodHRwOi8vIikpIHJldHVybiAiaHR0cCI7CgogICAgLy8gQXV0by1kZXRlY3QgYmFzZWQgb24gY29tbW9uIFNPQ0tTNSBwb3J0cwogICAgY29uc3Qgc29ja3NDb21tb25Qb3J0cyA9IFsxMDgwLCA5MDUwLCA5MTUwXTsKICAgIGlmIChzb2Nrc0NvbW1vblBvcnRzLmluY2x1ZGVzKHBvcnQpKSByZXR1cm4gInNvY2tzNSI7CgogICAgLy8gRGVmYXVsdCB0byBIVFRQCiAgICByZXR1cm4gImh0dHAiOwogIH0KCiAgcGFyc2VQcm94eUxpbmUobGluZSkgewogICAgY29uc3QgY2xlYW5MaW5lID0gbGluZS5yZXBsYWNlKC9eKGh0dHBzP3xzb2NrczUpOlwvXC8vLCAnJyk7IGNvbnN0IG0gPSBjbGVhbkxpbmUudHJpbSgpLm1hdGNoKC9eKFteOlxzXSspOihcZHsxLDV9KTooW146XSopOihbXjpdKikkLyk7CiAgICBpZiAoIW0pIHJldHVybiBudWxsOwogICAgY29uc3QgaG9zdCA9IG1bMV07CiAgICBjb25zdCBwb3J0ID0gcGFyc2VJbnQobVsyXSwgMTApOwogICAgY29uc3QgdXNlcm5hbWUgPSBtWzNdIHx8ICIiOwogICAgY29uc3QgcGFzc3dvcmQgPSBtWzRdIHx8ICIiOwogICAgaWYgKCFob3N0IHx8ICFwb3J0IHx8IHBvcnQgPD0gMCB8fCBwb3J0ID4gNjU1MzUpIHJldHVybiBudWxsOwogICAgcmV0dXJuIHsgdHlwZTogdGhpcy5kZXRlY3RQcm94eVR5cGUobGluZSwgaG9zdCwgcG9ydCksIGhvc3QsIHBvcnQsIHVzZXJuYW1lLCBwYXNzd29yZCwgZW5hYmxlZDogdHJ1ZSB9OwogIH0KCiAgYXN5bmMgaW1wb3J0UHJveGllcygpIHsKICAgIGNvbnN0IHRleHRhcmVhID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImltcG9ydC1wcm94aWVzIik7CiAgICBpZiAoIXRleHRhcmVhKSByZXR1cm47CiAgICBjb25zdCByYXcgPSB0ZXh0YXJlYS52YWx1ZSB8fCAiIjsKICAgIGNvbnN0IGxpbmVzID0gcmF3LnNwbGl0KC9ccj9cbi8pLm1hcChsID0+IGwudHJpbSgpKS5maWx0ZXIoQm9vbGVhbik7CiAgICBpZiAobGluZXMubGVuZ3RoID09PSAwKSB7CiAgICAgIHRoaXMuc2hvd0FsZXJ0KCJObyBwcm94aWVzIHRvIGltcG9ydCIsICJ3YXJuaW5nIik7CiAgICAgIHJldHVybjsKICAgIH0KCiAgICBsZXQgb2sgPSAwLCBza2lwcGVkID0gMDsKICAgIGZvciAoY29uc3QgW2lkeCwgbGluZV0gb2YgbGluZXMuZW50cmllcygpKSB7CiAgICAgIGlmIChsaW5lLnN0YXJ0c1dpdGgoIiMiKSkgeyBza2lwcGVkKys7IGNvbnRpbnVlOyB9CiAgICAgIGNvbnN0IGRhdGEgPSB0aGlzLnBhcnNlUHJveHlMaW5lKGxpbmUpOwogICAgICBpZiAoIWRhdGEpIHsgc2tpcHBlZCsrOyBjb250aW51ZTsgfQogICAgICB0cnkgewogICAgICAgIGNvbnN0IGNyZWF0ZWQgPSBhd2FpdCB0aGlzLmFwaUNhbGwoYCR7dGhpcy5hcGlCYXNlfS92MS9wcm94aWVzYCwgeyBtZXRob2Q6ICJQT1NUIiwgYm9keTogSlNPTi5zdHJpbmdpZnkoZGF0YSkgfSk7CiAgICAgICAgb2srKzsKICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHRoaXMuY2hlY2tQcm94eUhlYWx0aChjcmVhdGVkLmlkKSwgNTAwKTsKICAgICAgfSBjYXRjaCAoZSkgewogICAgICAgIGNvbnNvbGUuZXJyb3IoIkltcG9ydCBmYWlsZWQgZm9yIGxpbmUiLCBpZHggKyAxLCBsaW5lLCBlKTsKICAgICAgICBza2lwcGVkKys7CiAgICAgIH0KICAgIH0KCiAgICB0aGlzLnNob3dBbGVydChgSW1wb3J0ZWQgJHtva30gcHJveGllcyR7c2tpcHBlZCA/IGAsIHNraXBwZWQgJHtza2lwcGVkfWAgOiAiIn1gLCBvayA+IDAgPyAic3VjY2VzcyIgOiAid2FybmluZyIpOwogICAgaWYgKG9rID4gMCkgdGhpcy5sb2FkRGF0YSgpOwogIH0KCgogIHVwZGF0ZUNvdW50cygpIHsKICAgIHRoaXMudXBkYXRlRWxlbWVudCgncHJveHktY291bnQnLCBgJHt0aGlzLnByb3hpZXMubGVuZ3RofSBwcm94aWVzYCk7CiAgICB0aGlzLnVwZGF0ZUVsZW1lbnQoJ21hcHBpbmctY291bnQnLCBgJHt0aGlzLm1hcHBpbmdzLmxlbmd0aH0gbWFwcGluZ3NgKTsKICB9CgogIGFzeW5jIGNyZWF0ZVByb3h5KCkgewogICAgY29uc3QgZm9ybSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdmb3JtLXByb3h5Jyk7CiAgICBjb25zdCBmb3JtRGF0YSA9IG5ldyBGb3JtRGF0YShmb3JtKTsKCiAgICBjb25zdCBwcm94eURhdGEgPSB7CiAgICAgIHR5cGU6IGZvcm1EYXRhLmdldCgndHlwZScpLAogICAgICBob3N0OiBmb3JtRGF0YS5nZXQoJ2hvc3QnKSwKICAgICAgcG9ydDogcGFyc2VJbnQoZm9ybURhdGEuZ2V0KCdwb3J0JykpLAogICAgICB1c2VybmFtZTogZm9ybURhdGEuZ2V0KCd1c2VybmFtZScpIHx8ICcnLAogICAgICBwYXNzd29yZDogZm9ybURhdGEuZ2V0KCdwYXNzd29yZCcpIHx8ICcnLAogICAgICBlbmFibGVkOiB0cnVlCiAgICB9OwoKICAgIHRyeSB7CiAgICAgIGNvbnN0IG5ld1Byb3h5ID0gYXdhaXQgdGhpcy5hcGlDYWxsKGAke3RoaXMuYXBpQmFzZX0vdjEvcHJveGllc2AsIHsKICAgICAgICBtZXRob2Q6ICdQT1NUJywKICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShwcm94eURhdGEpCiAgICAgIH0pOwoKICAgICAgdGhpcy5zaG93QWxlcnQoJ1Byb3h5IGNyZWF0ZWQgc3VjY2Vzc2Z1bGx5JywgJ3N1Y2Nlc3MnKTsKICAgICAgZm9ybS5yZXNldCgpOwogICAgICB0aGlzLmxvYWREYXRhKCk7CgogICAgICAvLyBBdXRvIGhlYWx0aCBjaGVjayB0aGUgbmV3IHByb3h5CiAgICAgIHNldFRpbWVvdXQoKCkgPT4gdGhpcy5jaGVja1Byb3h5SGVhbHRoKG5ld1Byb3h5LmlkKSwgMTAwMCk7CgogICAgfSBjYXRjaCAoZXJyb3IpIHsKICAgICAgY29uc29sZS5lcnJvcignRmFpbGVkIHRvIGNyZWF0ZSBwcm94eTonLCBlcnJvcik7CiAgICB9CiAgfQoKICBhc3luYyBjcmVhdGVNYXBwaW5nKCkgewogICAgY29uc3QgZm9ybSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdmb3JtLW1hcHBpbmcnKTsKICAgIGNvbnN0IGZvcm1EYXRhID0gbmV3IEZvcm1EYXRhKGZvcm0pOwoKICAgIGNvbnN0IGNsaWVudElQID0gKGZvcm1EYXRhLmdldCgnY2xpZW50X2lwJykgfHwgJycpLnRyaW0oKTsKICAgIGNvbnN0IHByb3h5SWQgPSBmb3JtRGF0YS5nZXQoJ3Byb3h5X2lkJyk7CgogICAgLy8gRnJvbnRlbmQgdmFsaWRhdGlvbjogSVB2NCBvbmx5LCBmb3JiaWQgQ0lEUgogICAgY29uc3QgaXB2NFJlID0gL14oMjVbMC01XXwyWzAtNF1cZHxbMDFdP1xkXGQ/KVwuKDI1WzAtNV18MlswLTRdXGR8WzAxXT9cZFxkPylcLigyNVswLTVdfDJbMC00XVxkfFswMV0/XGRcZD8pXC4oMjVbMC01XXwyWzAtNF1cZHxbMDFdP1xkXGQ/KSQvOwogICAgaWYgKGNsaWVudElQLmluY2x1ZGVzKCcvJykpIHsKICAgICAgdGhpcy5zaG93QWxlcnQoJ0NJRFIgaXMgbm90IGFsbG93ZWQuIFBsZWFzZSBlbnRlciBhIHNpbmdsZSBJUHY0IGFkZHJlc3MgKGUuZy4sIDE5Mi4xNjguMi4zKS4nLCAnd2FybmluZycpOwogICAgICByZXR1cm47CiAgICB9CiAgICBpZiAoY2xpZW50SVAgJiYgIWlwdjRSZS50ZXN0KGNsaWVudElQKSkgewogICAgICB0aGlzLnNob3dBbGVydCgnSW52YWxpZCBJUHY0IGFkZHJlc3MgZm9ybWF0LicsICd3YXJuaW5nJyk7CiAgICAgIHJldHVybjsKICAgIH0KCiAgICBpZiAoIWNsaWVudElQIHx8ICFwcm94eUlkKSB7CiAgICAgIHRoaXMuc2hvd0FsZXJ0KCdQbGVhc2UgZmlsbCBhbGwgcmVxdWlyZWQgZmllbGRzJywgJ3dhcm5pbmcnKTsKICAgICAgcmV0dXJuOwogICAgfQoKICAgIHRyeSB7CiAgICAgIC8vIEZpcnN0IGNyZWF0ZSBjbGllbnQgaWYgbm90IGV4aXN0cwogICAgICBsZXQgY2xpZW50SWQ7CiAgICAgIGNvbnN0IGV4aXN0aW5nQ2xpZW50ID0gdGhpcy5jbGllbnRzLmZpbmQoYyA9PiBjLmlwX2NpZHIgPT09IGAke2NsaWVudElQfS8zMmApOwoKICAgICAgaWYgKGV4aXN0aW5nQ2xpZW50KSB7CiAgICAgICAgY2xpZW50SWQgPSBleGlzdGluZ0NsaWVudC5pZDsKICAgICAgfSBlbHNlIHsKICAgICAgICBjb25zdCBjbGllbnQgPSBhd2FpdCB0aGlzLmFwaUNhbGwoYCR7dGhpcy5hcGlCYXNlfS92MS9jbGllbnRzYCwgewogICAgICAgICAgbWV0aG9kOiAnUE9TVCcsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7CiAgICAgICAgICAgIGlwX2NpZHI6IGNsaWVudElQLCAvLyBBUEkgd2lsbCBhdXRvLWFkZCAvMzIKICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZQogICAgICAgICAgfSkKICAgICAgICB9KTsKICAgICAgICBjbGllbnRJZCA9IGNsaWVudC5pZDsKICAgICAgfQoKICAgICAgLy8gQ3JlYXRlIG1hcHBpbmcKICAgICAgYXdhaXQgdGhpcy5hcGlDYWxsKGAke3RoaXMuYXBpQmFzZX0vdjEvbWFwcGluZ3NgLCB7CiAgICAgICAgbWV0aG9kOiAnUE9TVCcsCiAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoewogICAgICAgICAgY2xpZW50X2lkOiBjbGllbnRJZCwKICAgICAgICAgIHByb3h5X2lkOiBwcm94eUlkCiAgICAgICAgfSkKICAgICAgfSk7CgogICAgICB0aGlzLnNob3dBbGVydCgnTWFwcGluZyBjcmVhdGVkIHN1Y2Nlc3NmdWxseScsICdzdWNjZXNzJyk7CiAgICAgIGZvcm0ucmVzZXQoKTsKICAgICAgdGhpcy5sb2FkRGF0YSgpOwoKICAgICAgLy8gQXV0byByZWNvbmNpbGUgYWZ0ZXIgY3JlYXRpbmcgbWFwcGluZwogICAgICBzZXRUaW1lb3V0KCgpID0+IHRoaXMucmVjb25jaWxlUnVsZXMoKSwgMTAwMCk7CgogICAgfSBjYXRjaCAoZXJyb3IpIHsKICAgICAgY29uc29sZS5lcnJvcignRmFpbGVkIHRvIGNyZWF0ZSBtYXBwaW5nOicsIGVycm9yKTsKICAgIH0KICB9CgogIGFzeW5jIGNoZWNrUHJveHlIZWFsdGgocHJveHlJZCkgewogICAgdHJ5IHsKICAgICAgYXdhaXQgdGhpcy5hcGlDYWxsKGAke3RoaXMuYXBpQmFzZX0vdjEvcHJveGllcy8ke3Byb3h5SWR9L2NoZWNrYCwgewogICAgICAgIG1ldGhvZDogJ1BPU1QnCiAgICAgIH0pOwoKICAgICAgdGhpcy5zaG93QWxlcnQoJ0hlYWx0aCBjaGVjayBjb21wbGV0ZWQnLCAnc3VjY2VzcycpOwogICAgICB0aGlzLmxvYWREYXRhKCk7CiAgICB9IGNhdGNoIChlcnJvcikgewogICAgICBjb25zb2xlLmVycm9yKCdIZWFsdGggY2hlY2sgZmFpbGVkOicsIGVycm9yKTsKICAgIH0KICB9CgogIGFzeW5jIGhlYWx0aENoZWNrQWxsKCkgewogICAgaWYgKHRoaXMucHJveGllcy5sZW5ndGggPT09IDApIHsKICAgICAgdGhpcy5zaG93QWxlcnQoJ05vIHByb3hpZXMgdG8gY2hlY2snLCAnd2FybmluZycpOwogICAgICByZXR1cm47CiAgICB9CgogICAgdGhpcy5zaG93QWxlcnQoJ1J1bm5pbmcgaGVhbHRoIGNoZWNrcy4uLicsICdpbmZvJyk7CgogICAgY29uc3QgY2hlY2tQcm9taXNlcyA9IHRoaXMucHJveGllcy5tYXAocHJveHkgPT4KICAgICAgdGhpcy5jaGVja1Byb3h5SGVhbHRoKHByb3h5LmlkKS5jYXRjaChlID0+IGNvbnNvbGUuZXJyb3IoYEhlYWx0aCBjaGVjayBmYWlsZWQgZm9yICR7cHJveHkuaWR9OmAsIGUpKQogICAgKTsKCiAgICB0cnkgewogICAgICBhd2FpdCBQcm9taXNlLmFsbChjaGVja1Byb21pc2VzKTsKICAgICAgdGhpcy5zaG93QWxlcnQoJ0FsbCBoZWFsdGggY2hlY2tzIGNvbXBsZXRlZCcsICdzdWNjZXNzJyk7CiAgICB9IGNhdGNoIChlcnJvcikgewogICAgICBjb25zb2xlLmVycm9yKCdTb21lIGhlYWx0aCBjaGVja3MgZmFpbGVkOicsIGVycm9yKTsKICAgIH0KICB9CgogIGFzeW5jIGRlbGV0ZVByb3h5KHByb3h5SWQpIHsKICAgIGlmICghY29uZmlybSgnQXJlIHlvdSBzdXJlIHlvdSB3YW50IHRvIGRlbGV0ZSB0aGlzIHByb3h5PyBUaGlzIHdpbGwgYWxzbyByZW1vdmUgYW55IGFzc29jaWF0ZWQgbWFwcGluZ3MuJykpIHsKICAgICAgcmV0dXJuOwogICAgfQoKICAgIHRyeSB7CiAgICAgIGF3YWl0IHRoaXMuYXBpQ2FsbChgJHt0aGlzLmFwaUJhc2V9L3YxL3Byb3hpZXMvJHtwcm94eUlkfWAsIHsKICAgICAgICBtZXRob2Q6ICdERUxFVEUnCiAgICAgIH0pOwoKICAgICAgdGhpcy5zaG93QWxlcnQoJ1Byb3h5IGRlbGV0ZWQgc3VjY2Vzc2Z1bGx5JywgJ3N1Y2Nlc3MnKTsKICAgICAgdGhpcy5sb2FkRGF0YSgpOwogICAgfSBjYXRjaCAoZXJyb3IpIHsKICAgICAgY29uc29sZS5lcnJvcignRmFpbGVkIHRvIGRlbGV0ZSBwcm94eTonLCBlcnJvcik7CiAgICB9CiAgfQoKICBhc3luYyBkZWxldGVNYXBwaW5nKG1hcHBpbmdJZCkgewogICAgaWYgKCFjb25maXJtKCdBcmUgeW91IHN1cmUgeW91IHdhbnQgdG8gZGVsZXRlIHRoaXMgbWFwcGluZz8nKSkgewogICAgICByZXR1cm47CiAgICB9CgogICAgdHJ5IHsKICAgICAgYXdhaXQgdGhpcy5hcGlDYWxsKGAke3RoaXMuYXBpQmFzZX0vdjEvbWFwcGluZ3MvJHttYXBwaW5nSWR9YCwgewogICAgICAgIG1ldGhvZDogJ0RFTEVURScKICAgICAgfSk7CgogICAgICB0aGlzLnNob3dBbGVydCgnTWFwcGluZyBkZWxldGVkIHN1Y2Nlc3NmdWxseScsICdzdWNjZXNzJyk7CiAgICAgIHRoaXMubG9hZERhdGEoKTsKCiAgICAgIC8vIEF1dG8gcmVjb25jaWxlIGFmdGVyIGRlbGV0aW5nIG1hcHBpbmcKICAgICAgc2V0VGltZW91dCgoKSA9PiB0aGlzLnJlY29uY2lsZVJ1bGVzKCksIDEwMDApOwoKICAgIH0gY2F0Y2ggKGVycm9yKSB7CiAgICAgIGNvbnNvbGUuZXJyb3IoJ0ZhaWxlZCB0byBkZWxldGUgbWFwcGluZzonLCBlcnJvcik7CiAgICB9CiAgfQoKICBhc3luYyByZWNvbmNpbGVSdWxlcygpIHsKICAgIHRyeSB7CiAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZmV0Y2goYCR7dGhpcy5hZ2VudEJhc2V9L3JlY29uY2lsZWApOwoKICAgICAgaWYgKHJlc3BvbnNlLm9rKSB7CiAgICAgICAgdGhpcy5zaG93QWxlcnQoJ1J1bGVzIHJlY29uY2lsZWQgc3VjY2Vzc2Z1bGx5JywgJ3N1Y2Nlc3MnKTsKICAgICAgICB0aGlzLnVwZGF0ZUVsZW1lbnQoJ2xhc3QtcmVjb25jaWxlJywgbmV3IERhdGUoKS50b0xvY2FsZVRpbWVTdHJpbmcoKSk7CiAgICAgICAgdGhpcy5sb2FkRGF0YSgpOwogICAgICB9IGVsc2UgewogICAgICAgIHRocm93IG5ldyBFcnJvcignUmVjb25jaWxlIGZhaWxlZCcpOwogICAgICB9CiAgICB9IGNhdGNoIChlcnJvcikgewogICAgICBjb25zb2xlLmVycm9yKCdSZWNvbmNpbGUgZmFpbGVkOicsIGVycm9yKTsKICAgICAgdGhpcy5zaG93QWxlcnQoJ0ZhaWxlZCB0byByZWNvbmNpbGUgcnVsZXMnLCAnZGFuZ2VyJyk7CiAgICB9CiAgfQoKICBleHBvcnRQcm94aWVzKCkgewogICAgaWYgKHRoaXMucHJveGllcy5sZW5ndGggPT09IDApIHsKICAgICAgdGhpcy5zaG93QWxlcnQoJ05vIHByb3hpZXMgdG8gZXhwb3J0JywgJ3dhcm5pbmcnKTsKICAgICAgcmV0dXJuOwogICAgfQoKICAgIGNvbnN0IGNzdkNvbnRlbnQgPSBbCiAgICAgICdJRCxUeXBlLEhvc3QsUG9ydCxTdGF0dXMsTGF0ZW5jeSxFeGl0IElQLExhc3QgQ2hlY2snLAogICAgICAuLi50aGlzLnByb3hpZXMubWFwKHAgPT4gWwogICAgICAgIHAuaWQsCiAgICAgICAgcC50eXBlLAogICAgICAgIHAuaG9zdCwKICAgICAgICBwLnBvcnQsCiAgICAgICAgcC5zdGF0dXMgfHwgJ1Vua25vd24nLAogICAgICAgIHAubGF0ZW5jeV9tcyB8fCAnJywKICAgICAgICBwLmV4aXRfaXAgfHwgJycsCiAgICAgICAgcC5sYXN0X2NoZWNrZWRfYXQgfHwgJycKICAgICAgXS5qb2luKCcsJykpCiAgICBdLmpvaW4oJ1xuJyk7CgogICAgdGhpcy5kb3dubG9hZEZpbGUoY3N2Q29udGVudCwgJ3Bndy1wcm94aWVzLmNzdicsICd0ZXh0L2NzdicpOwogIH0KCiAgZXhwb3J0TWFwcGluZ3MoKSB7CiAgICBpZiAodGhpcy5tYXBwaW5ncy5sZW5ndGggPT09IDApIHsKICAgICAgdGhpcy5zaG93QWxlcnQoJ05vIG1hcHBpbmdzIHRvIGV4cG9ydCcsICd3YXJuaW5nJyk7CiAgICAgIHJldHVybjsKICAgIH0KCiAgICBjb25zdCBjc3ZDb250ZW50ID0gWwogICAgICAnSUQsQ2xpZW50IElQLFByb3h5IEhvc3QsUHJveHkgUG9ydCxTdGF0ZSxMb2NhbCBQb3J0JywKICAgICAgLi4udGhpcy5tYXBwaW5ncy5tYXAobSA9PiBbCiAgICAgICAgbS5pZCwKICAgICAgICBtLmNsaWVudD8uaXBfY2lkciB8fCAnJywKICAgICAgICBtLnByb3h5Py5ob3N0IHx8ICcnLAogICAgICAgIG0ucHJveHk/LnBvcnQgfHwgJycsCiAgICAgICAgbS5zdGF0ZSB8fCAnUEVORElORycsCiAgICAgICAgbS5sb2NhbF9yZWRpcmVjdF9wb3J0IHx8ICcnCiAgICAgIF0uam9pbignLCcpKQogICAgXS5qb2luKCdcbicpOwoKICAgIHRoaXMuZG93bmxvYWRGaWxlKGNzdkNvbnRlbnQsICdwZ3ctbWFwcGluZ3MuY3N2JywgJ3RleHQvY3N2Jyk7CiAgfQoKICBkb3dubG9hZEZpbGUoY29udGVudCwgZmlsZW5hbWUsIG1pbWVUeXBlKSB7CiAgICBjb25zdCBibG9iID0gbmV3IEJsb2IoW2NvbnRlbnRdLCB7IHR5cGU6IG1pbWVUeXBlIH0pOwogICAgY29uc3QgdXJsID0gd2luZG93LlVSTC5jcmVhdGVPYmplY3RVUkwoYmxvYik7CiAgICBjb25zdCBhID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnYScpOwogICAgYS5ocmVmID0gdXJsOwogICAgYS5kb3dubG9hZCA9IGZpbGVuYW1lOwogICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChhKTsKICAgIGEuY2xpY2soKTsKICAgIGRvY3VtZW50LmJvZHkucmVtb3ZlQ2hpbGQoYSk7CiAgICB3aW5kb3cuVVJMLnJldm9rZU9iamVjdFVSTCh1cmwpOwoKICAgIHRoaXMuc2hvd0FsZXJ0KGAke2ZpbGVuYW1lfSBkb3dubG9hZGVkYCwgJ3N1Y2Nlc3MnKTsKICB9CgogIHNob3dBbGVydChtZXNzYWdlLCB0eXBlID0gJ2luZm8nKSB7CiAgICBjb25zdCBjb250YWluZXIgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYWxlcnRzJyk7CiAgICBpZiAoIWNvbnRhaW5lcikgcmV0dXJuOwoKICAgIC8vIEVuc3VyZSBjb250YWluZXIgaXMgb3ZlcmxheSBhbmQgdG9hc3QtcmVhZHkgKENTUyBoYW5kbGVzIHBvc2l0aW9uaW5nKQogICAgY29udGFpbmVyLmNsYXNzTGlzdC5hZGQoJ3RvYXN0LXN0YWNrJyk7CgogICAgY29uc3QgYnNUeXBlID0gWydzdWNjZXNzJywgJ2RhbmdlcicsICd3YXJuaW5nJywgJ2luZm8nLCAncHJpbWFyeScsICdzZWNvbmRhcnknXS5pbmNsdWRlcyh0eXBlKSA/IHR5cGUgOiAnaW5mbyc7CiAgICBjb25zdCB0b2FzdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwogICAgdG9hc3QuY2xhc3NOYW1lID0gYHRvYXN0IGFsaWduLWl0ZW1zLWNlbnRlciB0ZXh0LWJnLSR7YnNUeXBlfSBib3JkZXItMGA7CiAgICB0b2FzdC5zZXRBdHRyaWJ1dGUoJ3JvbGUnLCAnYWxlcnQnKTsKICAgIHRvYXN0LnNldEF0dHJpYnV0ZSgnYXJpYS1saXZlJywgJ2Fzc2VydGl2ZScpOwogICAgdG9hc3Quc2V0QXR0cmlidXRlKCdhcmlhLWF0b21pYycsICd0cnVlJyk7CgogICAgY29uc3QgaW5uZXIgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgIGlubmVyLmNsYXNzTmFtZSA9ICdkLWZsZXgnOwogICAgY29uc3QgYm9keSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwogICAgYm9keS5jbGFzc05hbWUgPSAndG9hc3QtYm9keSc7CiAgICBib2R5LnRleHRDb250ZW50ID0gbWVzc2FnZTsKICAgIGNvbnN0IGJ0biA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2J1dHRvbicpOwogICAgYnRuLnR5cGUgPSAnYnV0dG9uJzsKICAgIGJ0bi5jbGFzc05hbWUgPSAnYnRuLWNsb3NlIGJ0bi1jbG9zZS13aGl0ZSBtZS0yIG0tYXV0byc7CiAgICBidG4uc2V0QXR0cmlidXRlKCdkYXRhLWJzLWRpc21pc3MnLCAndG9hc3QnKTsKICAgIGJ0bi5zZXRBdHRyaWJ1dGUoJ2FyaWEtbGFiZWwnLCAnQ2xvc2UnKTsKCiAgICBpbm5lci5hcHBlbmRDaGlsZChib2R5KTsKICAgIGlubmVyLmFwcGVuZENoaWxkKGJ0bik7CiAgICB0b2FzdC5hcHBlbmRDaGlsZChpbm5lcik7CgogICAgY29udGFpbmVyLmFwcGVuZENoaWxkKHRvYXN0KTsKCiAgICBjb25zdCBpbnN0ID0gYm9vdHN0cmFwLlRvYXN0LmdldE9yQ3JlYXRlSW5zdGFuY2UodG9hc3QsIHsgZGVsYXk6IDM1MDAgfSk7CiAgICBpbnN0LnNob3coKTsKICAgIHRvYXN0LmFkZEV2ZW50TGlzdGVuZXIoJ2hpZGRlbi5icy50b2FzdCcsICgpID0+IHRvYXN0LnJlbW92ZSgpKTsKICB9CgogIHNob3dMb2FkaW5nKHNob3cpIHsKICAgIGNvbnN0IGxvYWRpbmdFbCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdsb2FkaW5nLWluZGljYXRvcicpOwogICAgaWYgKGxvYWRpbmdFbCkgewogICAgICBsb2FkaW5nRWwuc3R5bGUuZGlzcGxheSA9IHNob3cgPyAnZmxleCcgOiAnbm9uZSc7CiAgICB9CiAgfQoKICB1cGRhdGVFbGVtZW50KGlkLCB2YWx1ZSkgewogICAgY29uc3QgZWxlbWVudCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKGlkKTsKICAgIGlmIChlbGVtZW50KSB7CiAgICAgIGVsZW1lbnQudGV4dENvbnRlbnQgPSB2YWx1ZTsKICAgIH0KICB9CgogIHVwZGF0ZUxhc3RSZWZyZXNoKCkgewogICAgdGhpcy51cGRhdGVFbGVtZW50KCdsYXN0LXJlZnJlc2gnLCBuZXcgRGF0ZSgpLnRvTG9jYWxlVGltZVN0cmluZygpKTsKICB9Cn0KCi8vIEluaXRpYWxpemUgd2hlbiBET00gaXMgbG9hZGVkCmRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ0RPTUNvbnRlbnRMb2FkZWQnLCAoKSA9PiB7CiAgd2luZG93LnBndyA9IG5ldyBQR1dNYW5hZ2VyKCk7Cn0pOwoKLy8gU2V0IGFjdGl2ZSBuYXZpZ2F0aW9uCmRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ0RPTUNvbnRlbnRMb2FkZWQnLCAoKSA9PiB7CiAgY29uc3QgY3VycmVudFBhdGggPSB3aW5kb3cubG9jYXRpb24ucGF0aG5hbWU7CiAgY29uc3QgbmF2TGlua3MgPSBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCcubmF2LWxpbmsnKTsKCiAgbmF2TGlua3MuZm9yRWFjaChsaW5rID0+IHsKICAgIGxpbmsuY2xhc3NMaXN0LnJlbW92ZSgnYWN0aXZlJyk7CiAgICBpZiAobGluay5nZXRBdHRyaWJ1dGUoJ2hyZWYnKSA9PT0gY3VycmVudFBhdGgpIHsKICAgICAgbGluay5jbGFzc0xpc3QuYWRkKCdhY3RpdmUnKTsKICAgIH0KICB9KTsKfSk7Cg==`
