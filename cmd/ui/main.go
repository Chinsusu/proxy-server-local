package main

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/Chinsusu/proxy-server-local/pkg/config"
	"log"
)

var (
	baseAPI   string
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
	http.HandleFunc("/static/", handleStatic)

	// API proxy
	http.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		proxyRequest(w, r, "/api/", baseAPI)
	})

	// Agent proxy
	http.HandleFunc("/agent/", func(w http.ResponseWriter, r *http.Request) {
		proxyRequest(w, r, "/agent/", baseAgent)
	})

	log.Printf("[INFO] pgw-ui listening on %s (API=%s, AGENT=%s)",
		addr, baseAPI, baseAgent)
	if err := http.ListenAndServe(addr, nil); err != nil {
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
	serveHTML(w, r, "dashboard.html")
}

func handleProxies(w http.ResponseWriter, r *http.Request) {
	serveHTML(w, r, "proxies.html")
}

func handleManage(w http.ResponseWriter, r *http.Request) {
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
          <div class="col-12 col-md-4">
            <label class="form-label">Client IP Address</label>
            <input type="text" name="client_ip" class="form-control" placeholder="192.168.1.100" required>
            <div class="form-text">IP will automatically get /32 suffix for strict routing</div>
          </div>
          <div class="col-12 col-md-4">
            <label class="form-label">Proxy Server</label>
            <select name="proxy_id" id="select-proxy" class="form-select" required>
              <option value="">Select proxy server...</option>
            </select>
          </div>
          <div class="col-12 col-md-4 d-grid d-md-block">
            <label class="form-label invisible">&nbsp;</label>
            <button type="submit" class="btn btn-primary">Create Mapping</button>
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
          <div class="col-6 col-md-2">
            <label class="form-label">Type</label>
            <select name="type" class="form-select" required>
              <option value="http">HTTP</option>
              <option value="https">HTTPS</option>
            </select>
          </div>
          <div class="col-12 col-md-4">
            <label class="form-label">Host</label>
            <input type="text" name="host" class="form-control" placeholder="proxy.example.com" required>
          </div>
          <div class="col-6 col-md-2">
            <label class="form-label">Port</label>
            <input type="number" name="port" class="form-control" placeholder="8080" required>
          </div>
          <div class="col-6 col-md-2">
            <label class="form-label">Username</label>
            <input type="text" name="username" class="form-control" placeholder="Optional">
          </div>
          <div class="col-6 col-md-2">
            <label class="form-label">Password</label>
            <input type="password" name="password" class="form-control" placeholder="Optional">
          </div>
          <div class="col-12 col-md-2 d-grid">
            <label class="form-label invisible">&nbsp;</label>
            <button type="submit" class="btn btn-primary">Add Proxy</button>
          </div>
        </form>

        <div class="row g-3 align-items-end mt-2">
          <div class="col-12 col-md-10">
            <label class="form-label">Bulk import (IP:PORT:USER:PASSWORD, one per line)</label>
            <textarea id="import-proxies" class="form-control" rows="4" placeholder="192.0.2.10:8080:alice:s3cret&#10;198.51.100.22:3128:bob:pass123"></textarea>
            <div class="form-text">Format fixed to HTTP proxies. Invalid lines will be skipped.</div>
          </div>
          <div class="col-12 col-md-2 d-grid">
            <label class="form-label invisible">&nbsp;</label>
            <button id="btn-import-proxies" class="btn btn-secondary">Import</button>
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

const embeddedJSBase64 = `Y2xhc3MgUEdXTWFuYWdlciB7CiAgY29uc3RydWN0b3IoKSB7CiAgICB0aGlzLmFwaUJhc2UgPSAnL2FwaSc7CiAgICB0aGlzLmFnZW50QmFzZSA9ICcvYWdlbnQnOwogICAgdGhpcy5wcm94aWVzID0gW107CiAgICB0aGlzLmNsaWVudHMgPSBbXTsKICAgIHRoaXMubWFwcGluZ3MgPSBbXTsKICAgIHRoaXMubG9hZGluZyA9IGZhbHNlOwogICAgLy8gc29ydGluZyBzdGF0ZSAocGVyc2lzdGVkKQogICAgdGhpcy5wU29ydCA9ICdhZGRyZXNzJzsgdGhpcy5wQXNjID0gdHJ1ZTsKICAgIHRoaXMubVNvcnQgPSAnY2xpZW50JzsgIHRoaXMubUFzYyA9IHRydWU7CiAgICB0cnkgewogICAgICBjb25zdCBzcCA9IEpTT04ucGFyc2UobG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Bnd19zb3J0X3AyJyl8fCd7fScpOwogICAgICBpZiAoc3AgJiYgc3AuaykgeyB0aGlzLnBTb3J0ID0gc3AuazsgdGhpcy5wQXNjID0gISFzcC5hOyB9CiAgICAgIGNvbnN0IHNtID0gSlNPTi5wYXJzZShsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgncGd3X3NvcnRfbTInKXx8J3t9Jyk7CiAgICAgIGlmIChzbSAmJiBzbS5rKSB7IHRoaXMubVNvcnQgPSBzbS5rOyB0aGlzLm1Bc2MgPSAhIXNtLmE7IH0KICAgIH0gY2F0Y2ggKF8pIHt9CiAgICAKICAgIHRoaXMuaW5pdCgpOwogIH0KCiAgaW5pdCgpIHsKICAgIHRoaXMuYmluZEV2ZW50cygpOwogICAgdGhpcy5sb2FkRGF0YSgpOwogICAgCiAgICAvLyBBdXRvIHJlZnJlc2ggZXZlcnkgMzAgc2Vjb25kcwogICAgc2V0SW50ZXJ2YWwoKCkgPT4gdGhpcy5sb2FkRGF0YSgpLCAzMDAwMCk7CiAgfQoKICBiaW5kRXZlbnRzKCkgewogICAgLy8gUmVmcmVzaCBidXR0b24KICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdidG4tcmVmcmVzaCcpPy5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHsKICAgICAgdGhpcy5sb2FkRGF0YSgpOwogICAgfSk7CgogICAgLy8gSGVhbHRoIGNoZWNrIGFsbCBwcm94aWVzCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYnRuLWhlYWx0aC1hbGwnKT8uYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB7CiAgICAgIHRoaXMuaGVhbHRoQ2hlY2tBbGwoKTsKICAgIH0pOwoKICAgIC8vIFJlY29uY2lsZSBydWxlcwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2J0bi1yZWNvbmNpbGUnKT8uYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB7CiAgICAgIHRoaXMucmVjb25jaWxlUnVsZXMoKTsKICAgIH0pOwoKICAgIC8vIENyZWF0ZSBwcm94eSBmb3JtCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZm9ybS1wcm94eScpPy5hZGRFdmVudExpc3RlbmVyKCdzdWJtaXQnLCAoZSkgPT4gewogICAgICBlLnByZXZlbnREZWZhdWx0KCk7CiAgICAgIHRoaXMuY3JlYXRlUHJveHkoKTsKICAgIH0pOwoKCiAgICAvLyBJbXBvcnQgcHJveGllcyAoYnVsaykKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJidG4taW1wb3J0LXByb3hpZXMiKT8uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoZSkgPT4gewogICAgICBlLnByZXZlbnREZWZhdWx0KCk7CiAgICAgIHRoaXMuaW1wb3J0UHJveGllcygpOwogICAgfSk7CiAgICAvLyBDcmVhdGUgbWFwcGluZyBmb3JtCiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZm9ybS1tYXBwaW5nJyk/LmFkZEV2ZW50TGlzdGVuZXIoJ3N1Ym1pdCcsIChlKSA9PiB7CiAgICAgIGUucHJldmVudERlZmF1bHQoKTsKICAgICAgdGhpcy5jcmVhdGVNYXBwaW5nKCk7CiAgICB9KTsKICB9CgogIGFzeW5jIGFwaUNhbGwodXJsLCBvcHRpb25zID0ge30pIHsKICAgIHRyeSB7CiAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZmV0Y2godXJsLCB7CiAgICAgICAgaGVhZGVyczogewogICAgICAgICAgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJywKICAgICAgICAgIC4uLm9wdGlvbnMuaGVhZGVycwogICAgICAgIH0sCiAgICAgICAgLi4ub3B0aW9ucwogICAgICB9KTsKCiAgICAgIGlmICghcmVzcG9uc2Uub2spIHsKICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYEhUVFAgJHtyZXNwb25zZS5zdGF0dXN9OiAke3Jlc3BvbnNlLnN0YXR1c1RleHR9YCk7CiAgICAgIH0KCiAgICAgIGlmIChyZXNwb25zZS5zdGF0dXMgPT09IDIwNCkgewogICAgICAgIHJldHVybiBudWxsOwogICAgICB9CgogICAgICByZXR1cm4gYXdhaXQgcmVzcG9uc2UuanNvbigpOwogICAgfSBjYXRjaCAoZXJyb3IpIHsKICAgICAgY29uc29sZS5lcnJvcignQVBJIGNhbGwgZmFpbGVkOicsIGVycm9yKTsKICAgICAgdGhpcy5zaG93QWxlcnQoJ0FQSSBjYWxsIGZhaWxlZDogJyArIGVycm9yLm1lc3NhZ2UsICdkYW5nZXInKTsKICAgICAgdGhyb3cgZXJyb3I7CiAgICB9CiAgfQoKICBhc3luYyBsb2FkRGF0YSgpIHsKICAgIGlmICh0aGlzLmxvYWRpbmcpIHJldHVybjsKICAgIAogICAgdGhpcy5sb2FkaW5nID0gdHJ1ZTsKICAgIHRoaXMuc2hvd0xvYWRpbmcodHJ1ZSk7CgogICAgdHJ5IHsKICAgICAgY29uc3QgW3Byb3hpZXMsIGNsaWVudHMsIG1hcHBpbmdzXSA9IGF3YWl0IFByb21pc2UuYWxsKFsKICAgICAgICB0aGlzLmFwaUNhbGwoYCR7dGhpcy5hcGlCYXNlfS92MS9wcm94aWVzYCksCiAgICAgICAgdGhpcy5hcGlDYWxsKGAke3RoaXMuYXBpQmFzZX0vdjEvY2xpZW50c2ApLAogICAgICAgIHRoaXMuYXBpQ2FsbChgJHt0aGlzLmFwaUJhc2V9L3YxL21hcHBpbmdzL2FjdGl2ZWApCiAgICAgIF0pOwoKICAgICAgdGhpcy5wcm94aWVzID0gcHJveGllcyB8fCBbXTsKICAgICAgdGhpcy5jbGllbnRzID0gY2xpZW50cyB8fCBbXTsKICAgICAgdGhpcy5tYXBwaW5ncyA9IG1hcHBpbmdzIHx8IFtdOwoKICAgICAgdGhpcy5yZW5kZXJTdGF0cygpOwogICAgICB0aGlzLnJlbmRlclByb3hpZXMoKTsKICAgICAgdGhpcy5yZW5kZXJQcm94eVN1bW1hcnkoKTsKICAgICAgdGhpcy5yZW5kZXJNYXBwaW5ncygpOwogICAgICB0aGlzLnJlbmRlckNsaWVudHMoKTsKICAgICAgdGhpcy51cGRhdGVDb3VudHMoKTsKICAgICAgdGhpcy51cGRhdGVMYXN0UmVmcmVzaCgpOwoKICAgIH0gY2F0Y2ggKGVycm9yKSB7CiAgICAgIGNvbnNvbGUuZXJyb3IoJ0ZhaWxlZCB0byBsb2FkIGRhdGE6JywgZXJyb3IpOwogICAgfSBmaW5hbGx5IHsKICAgICAgdGhpcy5sb2FkaW5nID0gZmFsc2U7CiAgICAgIHRoaXMuc2hvd0xvYWRpbmcoZmFsc2UpOwogICAgfQogIH0KCiAgcmVuZGVyU3RhdHMoKSB7CiAgICBjb25zdCBva1Byb3hpZXMgPSB0aGlzLnByb3hpZXMuZmlsdGVyKHAgPT4gcC5zdGF0dXMgPT09ICdPSycpLmxlbmd0aDsKICAgIGNvbnN0IGFjdGl2ZU1hcHBpbmdzID0gdGhpcy5tYXBwaW5ncy5maWx0ZXIobSA9PiBtLmNsaWVudD8uZW5hYmxlZCAmJiBtLnByb3h5Py5lbmFibGVkKS5sZW5ndGg7CiAgICAKICAgIHRoaXMudXBkYXRlRWxlbWVudCgnc3RhdC1wcm94aWVzJywgdGhpcy5wcm94aWVzLmxlbmd0aCk7CiAgICB0aGlzLnVwZGF0ZUVsZW1lbnQoJ3N0YXQtcHJveGllcy1vaycsIG9rUHJveGllcyk7CiAgICB0aGlzLnVwZGF0ZUVsZW1lbnQoJ3N0YXQtY2xpZW50cycsIHRoaXMuY2xpZW50cy5sZW5ndGgpOwogICAgdGhpcy51cGRhdGVFbGVtZW50KCdzdGF0LW1hcHBpbmdzJywgYWN0aXZlTWFwcGluZ3MpOwogIH0KCiAgcmVuZGVyUHJveGllcygpIHsKICAgIGNvbnN0IHRib2R5ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3Rib2R5LXByb3hpZXMnKTsKICAgIGlmICghdGJvZHkpIHJldHVybjsKICAgIC8vIHNvcnQKICAgIGNvbnN0IGtleSA9IHRoaXMucFNvcnQsIGFzYyA9IHRoaXMucEFzYzsKICAgIGNvbnN0IHZhbCA9IChwKSA9PiB7CiAgICAgIGlmIChrZXk9PT0naWQnKSByZXR1cm4gKHAuaWR8fCcnKTsKICAgICAgaWYgKGtleT09PSd0eXBlJykgcmV0dXJuIChwLnR5cGV8fCcnKTsKICAgICAgaWYgKGtleT09PSdhZGRyZXNzJykgcmV0dXJuICgocC5ob3N0fHwnJykrJzonK3AucG9ydCkudG9Mb3dlckNhc2UoKTsKICAgICAgaWYgKGtleT09PSdzdGF0dXMnKSByZXR1cm4gKHAuc3RhdHVzfHwnJyk7CiAgICAgIGlmIChrZXk9PT0nbGF0ZW5jeScpIHJldHVybiAocC5sYXRlbmN5X21zPT1udWxsP0luZmluaXR5OnAubGF0ZW5jeV9tcyk7CiAgICAgIGlmIChrZXk9PT0nZXhpdCcpIHJldHVybiAocC5leGl0X2lwfHwnJyk7CiAgICAgIGlmIChrZXk9PT0nbGFzdCcpIHJldHVybiAocC5sYXN0X2NoZWNrZWRfYXR8fCcnKTsKICAgICAgcmV0dXJuICgocC5ob3N0fHwnJykrJzonK3AucG9ydCkudG9Mb3dlckNhc2UoKTsKICAgIH07CiAgICBjb25zdCBzb3J0ZWQgPSAodGhpcy5wcm94aWVzfHxbXSkuc2xpY2UoKS5zb3J0KChhLGIpPT57IGNvbnN0IHZhPXZhbChhKSwgdmI9dmFsKGIpOyBpZiAodmE8dmIpIHJldHVybiBhc2M/LTE6MTsgaWYgKHZhPnZiKSByZXR1cm4gYXNjPzE6LTE7IHJldHVybiAwOyB9KTsKICAgIC8vIGhlYWRlciBpY29ucyArIGNsaWNrCiAgICBjb25zdCB0aGVhZCA9IHRib2R5LnBhcmVudEVsZW1lbnQ/LnF1ZXJ5U2VsZWN0b3IoJ3RoZWFkJyk7CiAgICBpZiAodGhlYWQpIHsKICAgICAgY29uc3QgYXJyb3cgPSBhc2MgPyAnIFxcdTI1QjInIDogJyBcXHUyNUJDJzsKICAgICAgdGhlYWQuaW5uZXJIVE1MID0gJzx0cj4nCiAgICAgICAgKyAnPHRoIGRhdGEtaz0iaWQiIGNsYXNzPSJzb3J0YWJsZSI+SUQnKyhrZXk9PT0naWQnP2Fycm93OicnKSsnPC90aD4nCiAgICAgICAgKyAnPHRoIGRhdGEtaz0idHlwZSIgY2xhc3M9InNvcnRhYmxlIj5UeXBlJysoa2V5PT09J3R5cGUnP2Fycm93OicnKSsnPC90aD4nCiAgICAgICAgKyAnPHRoIGRhdGEtaz0iYWRkcmVzcyIgY2xhc3M9InNvcnRhYmxlIj5BZGRyZXNzJysoa2V5PT09J2FkZHJlc3MnP2Fycm93OicnKSsnPC90aD4nCiAgICAgICAgKyAnPHRoIGRhdGEtaz0ic3RhdHVzIiBjbGFzcz0ic29ydGFibGUiPlN0YXR1cycrKGtleT09PSdzdGF0dXMnP2Fycm93OicnKSsnPC90aD4nCiAgICAgICAgKyAnPHRoIGRhdGEtaz0ibGF0ZW5jeSIgY2xhc3M9InNvcnRhYmxlIj5MYXRlbmN5Jysoa2V5PT09J2xhdGVuY3knP2Fycm93OicnKSsnPC90aD4nCiAgICAgICAgKyAnPHRoIGRhdGEtaz0iZXhpdCIgY2xhc3M9InNvcnRhYmxlIj5FeGl0IElQJysoa2V5PT09J2V4aXQnP2Fycm93OicnKSsnPC90aD4nCiAgICAgICAgKyAnPHRoIGRhdGEtaz0ibGFzdCIgY2xhc3M9InNvcnRhYmxlIj5MYXN0IENoZWNrJysoa2V5PT09J2xhc3QnP2Fycm93OicnKSsnPC90aD4nCiAgICAgICAgKyAnPHRoPkFjdGlvbnM8L3RoPicKICAgICAgICArICc8L3RyPic7CiAgICAgIHRoZWFkLnF1ZXJ5U2VsZWN0b3JBbGwoJ3RoLnNvcnRhYmxlJykuZm9yRWFjaCgodGgpPT57CiAgICAgICAgdGguc3R5bGUuY3Vyc29yPSdwb2ludGVyJzsgdGgub25jbGljaz0oKT0+ewogICAgICAgICAgY29uc3Qgaz10aC5nZXRBdHRyaWJ1dGUoJ2RhdGEtaycpOwogICAgICAgICAgaWYgKHRoaXMucFNvcnQ9PT1rKSB0aGlzLnBBc2M9IXRoaXMucEFzYzsgZWxzZSB7IHRoaXMucFNvcnQ9azsgdGhpcy5wQXNjPXRydWU7IH0KICAgICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCdwZ3dfc29ydF9wMicsIEpTT04uc3RyaW5naWZ5KHtrOnRoaXMucFNvcnQsYTp0aGlzLnBBc2N9KSk7CiAgICAgICAgICB0aGlzLnJlbmRlclByb3hpZXMoKTsKICAgICAgICB9OwogICAgICB9KTsKICAgIH0KCiAgICB0Ym9keS5pbm5lckhUTUwgPSAnJzsKCiAgICBpZiAoc29ydGVkLmxlbmd0aCA9PT0gMCkgewogICAgICB0Ym9keS5pbm5lckhUTUwgPSAnPHRyPjx0ZCBjb2xzcGFuPSI4IiBjbGFzcz0idGV4dC1jZW50ZXIiPk5vIHByb3hpZXMgY29uZmlndXJlZDwvdGQ+PC90cj4nOwogICAgICByZXR1cm47CiAgICB9CgogICAgc29ydGVkLmZvckVhY2gocHJveHkgPT4gewogICAgICBjb25zdCByb3cgPSB0aGlzLmNyZWF0ZVByb3h5Um93KHByb3h5KTsKICAgICAgdGJvZHkuYXBwZW5kQ2hpbGQocm93KTsKICAgIH0pOwogIH0KCiAgcmVuZGVyUHJveHlTdW1tYXJ5KCkgewogICAgY29uc3QgdGJvZHkgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGJvZHktcHJveHktc3VtbWFyeScpOwogICAgaWYgKCF0Ym9keSkgcmV0dXJuOwoKICAgIHRib2R5LmlubmVySFRNTCA9ICcnOwoKICAgIGlmICh0aGlzLnByb3hpZXMubGVuZ3RoID09PSAwKSB7CiAgICAgIHRib2R5LmlubmVySFRNTCA9ICc8dHI+PHRkIGNvbHNwYW49IjUiIGNsYXNzPSJ0ZXh0LWNlbnRlciI+Tm8gcHJveGllcyBjb25maWd1cmVkPC90ZD48L3RyPic7CiAgICAgIHJldHVybjsKICAgIH0KCiAgICB0aGlzLnByb3hpZXMuZm9yRWFjaChwcm94eSA9PiB7CiAgICAgIGNvbnN0IHRyID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgndHInKTsKICAgICAgY29uc3Qgc3RhdHVzQmFkZ2UgPSB0aGlzLmNyZWF0ZVN0YXR1c0JhZGdlKHByb3h5LnN0YXR1cyk7CiAgICAgIGNvbnN0IGxhdGVuY3lUZXh0ID0gcHJveHkubGF0ZW5jeV9tcyAhPT0gbnVsbCA/IGAke3Byb3h5LmxhdGVuY3lfbXN9bXNgIDogJ+KAlCc7CiAgICAgIGNvbnN0IGxhc3RDaGVja2VkID0gcHJveHkubGFzdF9jaGVja2VkX2F0IAogICAgICAgID8gbmV3IERhdGUocHJveHkubGFzdF9jaGVja2VkX2F0KS50b0xvY2FsZVRpbWVTdHJpbmcoKQogICAgICAgIDogJ+KAlCc7CgogICAgICB0ci5pbm5lckhUTUwgPSBgCiAgICAgICAgPHRkPiR7cHJveHkuaG9zdH06JHtwcm94eS5wb3J0fTwvdGQ+CiAgICAgICAgPHRkPiR7c3RhdHVzQmFkZ2V9PC90ZD4KICAgICAgICA8dGQ+JHtsYXRlbmN5VGV4dH08L3RkPgogICAgICAgIDx0ZD4ke3Byb3h5LmV4aXRfaXAgfHwgJ+KAlCd9PC90ZD4KICAgICAgICA8dGQ+JHtsYXN0Q2hlY2tlZH08L3RkPgogICAgICBgOwogICAgICB0Ym9keS5hcHBlbmRDaGlsZCh0cik7CiAgICB9KTsKICB9CgogIGNyZWF0ZVByb3h5Um93KHByb3h5KSB7CiAgICBjb25zdCB0ciA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ3RyJyk7CiAgICAKICAgIGNvbnN0IHN0YXR1c0JhZGdlID0gdGhpcy5jcmVhdGVTdGF0dXNCYWRnZShwcm94eS5zdGF0dXMpOwogICAgY29uc3QgbGF0ZW5jeVRleHQgPSBwcm94eS5sYXRlbmN5X21zICE9PSBudWxsID8gYCR7cHJveHkubGF0ZW5jeV9tc31tc2AgOiAn4oCUJzsKICAgIGNvbnN0IGxhc3RDaGVja2VkID0gcHJveHkubGFzdF9jaGVja2VkX2F0IAogICAgICA/IG5ldyBEYXRlKHByb3h5Lmxhc3RfY2hlY2tlZF9hdCkudG9Mb2NhbGVUaW1lU3RyaW5nKCkKICAgICAgOiAn4oCUJzsKCiAgICB0ci5pbm5lckhUTUwgPSBgCiAgICAgIDx0ZD48Y29kZT4ke3Byb3h5LmlkLnNsaWNlKDAsIDgpfTwvY29kZT48L3RkPgogICAgICA8dGQ+JHtwcm94eS50eXBlfTwvdGQ+CiAgICAgIDx0ZD4ke3Byb3h5Lmhvc3R9OiR7cHJveHkucG9ydH08L3RkPgogICAgICA8dGQ+JHtzdGF0dXNCYWRnZX08L3RkPgogICAgICA8dGQ+JHtsYXRlbmN5VGV4dH08L3RkPgogICAgICA8dGQ+JHtwcm94eS5leGl0X2lwIHx8ICfigJQnfTwvdGQ+CiAgICAgIDx0ZD4ke2xhc3RDaGVja2VkfTwvdGQ+CiAgICAgIDx0ZD4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXNtIGJ0bi1zZWNvbmRhcnkiIG9uY2xpY2s9InBndy5jaGVja1Byb3h5SGVhbHRoKCcke3Byb3h5LmlkfScpIiBkYXRhLXRvb2x0aXA9IkhlYWx0aCBjaGVjayI+CiAgICAgICAgICBDaGVjawogICAgICAgIDwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tc20gYnRuLWRhbmdlciIgb25jbGljaz0icGd3LmRlbGV0ZVByb3h5KCcke3Byb3h5LmlkfScpIiBkYXRhLXRvb2x0aXA9IkRlbGV0ZSBwcm94eSI+CiAgICAgICAgICDDlwogICAgICAgIDwvYnV0dG9uPgogICAgICA8L3RkPgogICAgYDsKCiAgICByZXR1cm4gdHI7CiAgfQoKICBjcmVhdGVTdGF0dXNCYWRnZShzdGF0dXMpIHsKICAgIGNvbnN0IHN0YXR1c0NsYXNzID0gewogICAgICAnT0snOiAndGV4dC1iZy1zdWNjZXNzJywKICAgICAgJ0RFR1JBREVEJzogJ3RleHQtYmctd2FybmluZycsCiAgICAgICdET1dOJzogJ3RleHQtYmctZGFuZ2VyJwogICAgfVtzdGF0dXNdIHx8ICd0ZXh0LWJnLXNlY29uZGFyeSc7CgogICAgcmV0dXJuIGA8c3BhbiBjbGFzcz0iYmFkZ2UgJHtzdGF0dXNDbGFzc30iPiR7c3RhdHVzIHx8ICdVbmtub3duJ308L3NwYW4+YDsKICB9CgogIHJlbmRlck1hcHBpbmdzKCkgewogICAgY29uc3QgdGJvZHkgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGJvZHktbWFwcGluZ3MnKTsKICAgIGlmICghdGJvZHkpIHJldHVybjsKICAgIC8vIHNvcnQKICAgIGNvbnN0IGtleSA9IHRoaXMubVNvcnQsIGFzYyA9IHRoaXMubUFzYzsKICAgIGNvbnN0IHZhbCA9IChtKSA9PiB7CiAgICAgIGlmIChrZXk9PT0naWQnKSByZXR1cm4gKG0uaWR8fCcnKTsKICAgICAgaWYgKGtleT09PSdjbGllbnQnKSByZXR1cm4gKChtLmNsaWVudD8uaXBfY2lkcil8fCcnKTsKICAgICAgaWYgKGtleT09PSdwcm94eScpIHsgY29uc3QgcD1tLnByb3h5fHx7fTsgcmV0dXJuICgocC5ob3N0fHwnJykrJzonKyhwLnBvcnQ/PycnKSk7IH0KICAgICAgaWYgKGtleT09PSdzdGF0ZScpIHJldHVybiAobS5zdGF0ZXx8JycpOwogICAgICBpZiAoa2V5PT09J3BvcnQnKSByZXR1cm4gKG0ubG9jYWxfcmVkaXJlY3RfcG9ydD8/MCk7CiAgICAgIHJldHVybiAoKG0uY2xpZW50Py5pcF9jaWRyKXx8JycpOwogICAgfTsKICAgIGNvbnN0IHNvcnRlZCA9ICh0aGlzLm1hcHBpbmdzfHxbXSkuc2xpY2UoKS5zb3J0KChhLGIpPT57IGNvbnN0IHZhPXZhbChhKSwgdmI9dmFsKGIpOyBpZiAodmE8dmIpIHJldHVybiBhc2M/LTE6MTsgaWYgKHZhPnZiKSByZXR1cm4gYXNjPzE6LTE7IHJldHVybiAwOyB9KTsKICAgIC8vIGhlYWRlciBpY29ucyArIGNsaWNrCiAgICBjb25zdCB0aGVhZCA9IHRib2R5LnBhcmVudEVsZW1lbnQ/LnF1ZXJ5U2VsZWN0b3IoJ3RoZWFkJyk7CiAgICBpZiAodGhlYWQpIHsKICAgICAgY29uc3QgYXJyb3cgPSBhc2MgPyAnIFxcdTI1QjInIDogJyBcXHUyNUJDJzsKICAgICAgdGhlYWQuaW5uZXJIVE1MID0gJzx0cj4nCiAgICAgICAgKyAnPHRoIGRhdGEtaz0iaWQiIGNsYXNzPSJzb3J0YWJsZSI+SUQnKyhrZXk9PT0naWQnP2Fycm93OicnKSsnPC90aD4nCiAgICAgICAgKyAnPHRoIGRhdGEtaz0iY2xpZW50IiBjbGFzcz0ic29ydGFibGUiPkNsaWVudCBJUC9DSURSJysoa2V5PT09J2NsaWVudCc/YXJyb3c6JycpKyc8L3RoPicKICAgICAgICArICc8dGggZGF0YS1rPSJwcm94eSIgY2xhc3M9InNvcnRhYmxlIj5Qcm94eSBTZXJ2ZXInKyhrZXk9PT0ncHJveHknP2Fycm93OicnKSsnPC90aD4nCiAgICAgICAgKyAnPHRoIGRhdGEtaz0ic3RhdGUiIGNsYXNzPSJzb3J0YWJsZSI+U3RhdGUnKyhrZXk9PT0nc3RhdGUnP2Fycm93OicnKSsnPC90aD4nCiAgICAgICAgKyAnPHRoIGRhdGEtaz0icG9ydCIgY2xhc3M9InNvcnRhYmxlIj5Mb2NhbCBQb3J0Jysoa2V5PT09J3BvcnQnP2Fycm93OicnKSsnPC90aD4nCiAgICAgICAgKyAnPHRoPkFjdGlvbnM8L3RoPicKICAgICAgICArICc8L3RyPic7CiAgICAgIHRoZWFkLnF1ZXJ5U2VsZWN0b3JBbGwoJ3RoLnNvcnRhYmxlJykuZm9yRWFjaCgodGgpPT57CiAgICAgICAgdGguc3R5bGUuY3Vyc29yPSdwb2ludGVyJzsgdGgub25jbGljaz0oKT0+ewogICAgICAgICAgY29uc3Qgaz10aC5nZXRBdHRyaWJ1dGUoJ2RhdGEtaycpOwogICAgICAgICAgaWYgKHRoaXMubVNvcnQ9PT1rKSB0aGlzLm1Bc2M9IXRoaXMubUFzYzsgZWxzZSB7IHRoaXMubVNvcnQ9azsgdGhpcy5tQXNjPXRydWU7IH0KICAgICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCdwZ3dfc29ydF9tMicsIEpTT04uc3RyaW5naWZ5KHtrOnRoaXMubVNvcnQsYTp0aGlzLm1Bc2N9KSk7CiAgICAgICAgICB0aGlzLnJlbmRlck1hcHBpbmdzKCk7CiAgICAgICAgfTsKICAgICAgfSk7CiAgICB9CgogICAgdGJvZHkuaW5uZXJIVE1MID0gJyc7CgogICAgaWYgKHNvcnRlZC5sZW5ndGggPT09IDApIHsKICAgICAgdGJvZHkuaW5uZXJIVE1MID0gJzx0cj48dGQgY29sc3Bhbj0iNiIgY2xhc3M9InRleHQtY2VudGVyIj5ObyBtYXBwaW5ncyBjb25maWd1cmVkPC90ZD48L3RyPic7CiAgICAgIHJldHVybjsKICAgIH0KCiAgICBzb3J0ZWQuZm9yRWFjaChtYXBwaW5nID0+IHsKICAgICAgY29uc3Qgcm93ID0gdGhpcy5jcmVhdGVNYXBwaW5nUm93KG1hcHBpbmcpOwogICAgICB0Ym9keS5hcHBlbmRDaGlsZChyb3cpOwogICAgfSk7CiAgfQoKICBjcmVhdGVNYXBwaW5nUm93KG1hcHBpbmcpIHsKICAgIGNvbnN0IHRyID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgndHInKTsKICAgIAogICAgY29uc3QgcHJveHlBZGRyZXNzID0gbWFwcGluZy5wcm94eSAKICAgICAgPyBgJHttYXBwaW5nLnByb3h5Lmhvc3R9OiR7bWFwcGluZy5wcm94eS5wb3J0fWAKICAgICAgOiAn4oCUJzsKICAgIAogICAgY29uc3Qgc3RhdGVCYWRnZSA9IHRoaXMuY3JlYXRlU3RhdHVzQmFkZ2UobWFwcGluZy5zdGF0ZSB8fCAnUEVORElORycpOwoKICAgIHRyLmlubmVySFRNTCA9IGAKICAgICAgPHRkPjxjb2RlPiR7bWFwcGluZy5pZC5zbGljZSgwLCA4KX08L2NvZGU+PC90ZD4KICAgICAgPHRkPiR7bWFwcGluZy5jbGllbnQ/LmlwX2NpZHIgfHwgJ+KAlCd9PC90ZD4KICAgICAgPHRkPiR7cHJveHlBZGRyZXNzfTwvdGQ+CiAgICAgIDx0ZD4ke3N0YXRlQmFkZ2V9PC90ZD4KICAgICAgPHRkPiR7bWFwcGluZy5sb2NhbF9yZWRpcmVjdF9wb3J0IHx8ICfigJQnfTwvdGQ+CiAgICAgIDx0ZD4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXNtIGJ0bi1kYW5nZXIiIG9uY2xpY2s9InBndy5kZWxldGVNYXBwaW5nKCcke21hcHBpbmcuaWR9JykiPgogICAgICAgICAgRGVsZXRlCiAgICAgICAgPC9idXR0b24+CiAgICAgIDwvdGQ+CiAgICBgOwoKICAgIHJldHVybiB0cjsKICB9CgogIHJlbmRlckNsaWVudHMoKSB7CiAgICBjb25zdCBzZWxlY3QgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc2VsZWN0LXByb3h5Jyk7CiAgICBpZiAoIXNlbGVjdCkgcmV0dXJuOwoKICAgIHNlbGVjdC5pbm5lckhUTUwgPSAnPG9wdGlvbiB2YWx1ZT0iIj5TZWxlY3QgcHJveHkgc2VydmVyLi4uPC9vcHRpb24+JzsKCiAgICBpZiAoIXRoaXMucHJveGllcyB8fCB0aGlzLnByb3hpZXMubGVuZ3RoID09PSAwKSB7CiAgICAgIGNvbnN0IG9wdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ29wdGlvbicpOwogICAgICBvcHQuZGlzYWJsZWQgPSB0cnVlOwogICAgICBvcHQudGV4dENvbnRlbnQgPSAnTm8gYXZhaWxhYmxlIHByb3hpZXMnOwogICAgICBzZWxlY3QuYXBwZW5kQ2hpbGQob3B0KTsKICAgICAgcmV0dXJuOwogICAgfQoKICAgICh0aGlzLnByb3hpZXMgfHwgW10pLmZvckVhY2gocHJveHkgPT4gewogICAgICBjb25zdCBvcHRpb24gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdvcHRpb24nKTsKICAgICAgb3B0aW9uLnZhbHVlID0gcHJveHkuaWQ7CiAgICAgIGNvbnN0IHN0YXR1c0luZGljYXRvciA9IHByb3h5LnN0YXR1cyA9PT0gJ09LJyA/ICfinJMnIDogcHJveHkuc3RhdHVzID09PSAnREVHUkFERUQnID8gJ+KaoCcgOiAn4pyXJzsKICAgICAgb3B0aW9uLnRleHRDb250ZW50ID0gYCR7c3RhdHVzSW5kaWNhdG9yfSAke3Byb3h5Lmhvc3R9OiR7cHJveHkucG9ydH0gKCR7cHJveHkudHlwZX0pYDsKICAgICAgc2VsZWN0LmFwcGVuZENoaWxkKG9wdGlvbik7CiAgICB9KTsKICB9CiAgcGFyc2VQcm94eUxpbmUobGluZSkgewogICAgY29uc3QgbSA9IGxpbmUudHJpbSgpLm1hdGNoKC9eKFteOlxzXSspOihcZHsxLDV9KTooW146XSopOihbXjpdKikkLyk7CiAgICBpZiAoIW0pIHJldHVybiBudWxsOwogICAgY29uc3QgaG9zdCA9IG1bMV07CiAgICBjb25zdCBwb3J0ID0gcGFyc2VJbnQobVsyXSwgMTApOwogICAgY29uc3QgdXNlcm5hbWUgPSBtWzNdIHx8ICIiOwogICAgY29uc3QgcGFzc3dvcmQgPSBtWzRdIHx8ICIiOwogICAgaWYgKCFob3N0IHx8ICFwb3J0IHx8IHBvcnQgPD0gMCB8fCBwb3J0ID4gNjU1MzUpIHJldHVybiBudWxsOwogICAgcmV0dXJuIHsgdHlwZTogImh0dHAiLCBob3N0LCBwb3J0LCB1c2VybmFtZSwgcGFzc3dvcmQsIGVuYWJsZWQ6IHRydWUgfTsKICB9CgogIGFzeW5jIGltcG9ydFByb3hpZXMoKSB7CiAgICBjb25zdCB0ZXh0YXJlYSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJpbXBvcnQtcHJveGllcyIpOwogICAgaWYgKCF0ZXh0YXJlYSkgcmV0dXJuOwogICAgY29uc3QgcmF3ID0gdGV4dGFyZWEudmFsdWUgfHwgIiI7CiAgICBjb25zdCBsaW5lcyA9IHJhdy5zcGxpdCgvXHI/XG4vKS5tYXAobCA9PiBsLnRyaW0oKSkuZmlsdGVyKEJvb2xlYW4pOwogICAgaWYgKGxpbmVzLmxlbmd0aCA9PT0gMCkgewogICAgICB0aGlzLnNob3dBbGVydCgiTm8gcHJveGllcyB0byBpbXBvcnQiLCAid2FybmluZyIpOwogICAgICByZXR1cm47CiAgICB9CgogICAgbGV0IG9rID0gMCwgc2tpcHBlZCA9IDA7CiAgICBmb3IgKGNvbnN0IFtpZHgsIGxpbmVdIG9mIGxpbmVzLmVudHJpZXMoKSkgewogICAgICBpZiAobGluZS5zdGFydHNXaXRoKCIjIikpIHsgc2tpcHBlZCsrOyBjb250aW51ZTsgfQogICAgICBjb25zdCBkYXRhID0gdGhpcy5wYXJzZVByb3h5TGluZShsaW5lKTsKICAgICAgaWYgKCFkYXRhKSB7IHNraXBwZWQrKzsgY29udGludWU7IH0KICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBjcmVhdGVkID0gYXdhaXQgdGhpcy5hcGlDYWxsKGAke3RoaXMuYXBpQmFzZX0vdjEvcHJveGllc2AsIHsgbWV0aG9kOiAiUE9TVCIsIGJvZHk6IEpTT04uc3RyaW5naWZ5KGRhdGEpIH0pOwogICAgICAgIG9rKys7CiAgICAgICAgc2V0VGltZW91dCgoKSA9PiB0aGlzLmNoZWNrUHJveHlIZWFsdGgoY3JlYXRlZC5pZCksIDUwMCk7CiAgICAgIH0gY2F0Y2ggKGUpIHsKICAgICAgICBjb25zb2xlLmVycm9yKCJJbXBvcnQgZmFpbGVkIGZvciBsaW5lIiwgaWR4KzEsIGxpbmUsIGUpOwogICAgICAgIHNraXBwZWQrKzsKICAgICAgfQogICAgfQoKICAgIHRoaXMuc2hvd0FsZXJ0KGBJbXBvcnRlZCAke29rfSBwcm94aWVzJHtza2lwcGVkP2AsIHNraXBwZWQgJHtza2lwcGVkfWA6IiJ9YCwgb2s+MCA/ICJzdWNjZXNzIiA6ICJ3YXJuaW5nIik7CiAgICBpZiAob2s+MCkgdGhpcy5sb2FkRGF0YSgpOwogIH0KCgogIHVwZGF0ZUNvdW50cygpIHsKICAgIHRoaXMudXBkYXRlRWxlbWVudCgncHJveHktY291bnQnLCBgJHt0aGlzLnByb3hpZXMubGVuZ3RofSBwcm94aWVzYCk7CiAgICB0aGlzLnVwZGF0ZUVsZW1lbnQoJ21hcHBpbmctY291bnQnLCBgJHt0aGlzLm1hcHBpbmdzLmxlbmd0aH0gbWFwcGluZ3NgKTsKICB9CgogIGFzeW5jIGNyZWF0ZVByb3h5KCkgewogICAgY29uc3QgZm9ybSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdmb3JtLXByb3h5Jyk7CiAgICBjb25zdCBmb3JtRGF0YSA9IG5ldyBGb3JtRGF0YShmb3JtKTsKCiAgICBjb25zdCBwcm94eURhdGEgPSB7CiAgICAgIHR5cGU6IGZvcm1EYXRhLmdldCgndHlwZScpLAogICAgICBob3N0OiBmb3JtRGF0YS5nZXQoJ2hvc3QnKSwKICAgICAgcG9ydDogcGFyc2VJbnQoZm9ybURhdGEuZ2V0KCdwb3J0JykpLAogICAgICB1c2VybmFtZTogZm9ybURhdGEuZ2V0KCd1c2VybmFtZScpIHx8ICcnLAogICAgICBwYXNzd29yZDogZm9ybURhdGEuZ2V0KCdwYXNzd29yZCcpIHx8ICcnLAogICAgICBlbmFibGVkOiB0cnVlCiAgICB9OwoKICAgIHRyeSB7CiAgICAgIGNvbnN0IG5ld1Byb3h5ID0gYXdhaXQgdGhpcy5hcGlDYWxsKGAke3RoaXMuYXBpQmFzZX0vdjEvcHJveGllc2AsIHsKICAgICAgICBtZXRob2Q6ICdQT1NUJywKICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShwcm94eURhdGEpCiAgICAgIH0pOwoKICAgICAgdGhpcy5zaG93QWxlcnQoJ1Byb3h5IGNyZWF0ZWQgc3VjY2Vzc2Z1bGx5JywgJ3N1Y2Nlc3MnKTsKICAgICAgZm9ybS5yZXNldCgpOwogICAgICB0aGlzLmxvYWREYXRhKCk7CiAgICAgIAogICAgICAvLyBBdXRvIGhlYWx0aCBjaGVjayB0aGUgbmV3IHByb3h5CiAgICAgIHNldFRpbWVvdXQoKCkgPT4gdGhpcy5jaGVja1Byb3h5SGVhbHRoKG5ld1Byb3h5LmlkKSwgMTAwMCk7CiAgICAgIAogICAgfSBjYXRjaCAoZXJyb3IpIHsKICAgICAgY29uc29sZS5lcnJvcignRmFpbGVkIHRvIGNyZWF0ZSBwcm94eTonLCBlcnJvcik7CiAgICB9CiAgfQoKICBhc3luYyBjcmVhdGVNYXBwaW5nKCkgewogICAgY29uc3QgZm9ybSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdmb3JtLW1hcHBpbmcnKTsKICAgIGNvbnN0IGZvcm1EYXRhID0gbmV3IEZvcm1EYXRhKGZvcm0pOwoKICAgIGNvbnN0IGNsaWVudElQID0gKGZvcm1EYXRhLmdldCgnY2xpZW50X2lwJykgfHwgJycpLnRyaW0oKTsKICAgIGNvbnN0IHByb3h5SWQgPSBmb3JtRGF0YS5nZXQoJ3Byb3h5X2lkJyk7CgogICAgLy8gRnJvbnRlbmQgdmFsaWRhdGlvbjogSVB2NCBvbmx5LCBmb3JiaWQgQ0lEUgogICAgY29uc3QgaXB2NFJlID0gL14oMjVbMC01XXwyWzAtNF1cZHxbMDFdP1xkXGQ/KVwuKDI1WzAtNV18MlswLTRdXGR8WzAxXT9cZFxkPylcLigyNVswLTVdfDJbMC00XVxkfFswMV0/XGRcZD8pXC4oMjVbMC01XXwyWzAtNF1cZHxbMDFdP1xkXGQ/KSQvOwogICAgaWYgKGNsaWVudElQLmluY2x1ZGVzKCcvJykpIHsKICAgICAgdGhpcy5zaG93QWxlcnQoJ0NJRFIgaXMgbm90IGFsbG93ZWQuIFBsZWFzZSBlbnRlciBhIHNpbmdsZSBJUHY0IGFkZHJlc3MgKGUuZy4sIDE5Mi4xNjguMi4zKS4nLCAnd2FybmluZycpOwogICAgICByZXR1cm47CiAgICB9CiAgICBpZiAoY2xpZW50SVAgJiYgIWlwdjRSZS50ZXN0KGNsaWVudElQKSkgewogICAgICB0aGlzLnNob3dBbGVydCgnSW52YWxpZCBJUHY0IGFkZHJlc3MgZm9ybWF0LicsICd3YXJuaW5nJyk7CiAgICAgIHJldHVybjsKICAgIH0KCiAgICBpZiAoIWNsaWVudElQIHx8ICFwcm94eUlkKSB7CiAgICAgIHRoaXMuc2hvd0FsZXJ0KCdQbGVhc2UgZmlsbCBhbGwgcmVxdWlyZWQgZmllbGRzJywgJ3dhcm5pbmcnKTsKICAgICAgcmV0dXJuOwogICAgfQoKICAgIHRyeSB7CiAgICAgIC8vIEZpcnN0IGNyZWF0ZSBjbGllbnQgaWYgbm90IGV4aXN0cwogICAgICBsZXQgY2xpZW50SWQ7CiAgICAgIGNvbnN0IGV4aXN0aW5nQ2xpZW50ID0gdGhpcy5jbGllbnRzLmZpbmQoYyA9PiBjLmlwX2NpZHIgPT09IGAke2NsaWVudElQfS8zMmApOwogICAgICAKICAgICAgaWYgKGV4aXN0aW5nQ2xpZW50KSB7CiAgICAgICAgY2xpZW50SWQgPSBleGlzdGluZ0NsaWVudC5pZDsKICAgICAgfSBlbHNlIHsKICAgICAgICBjb25zdCBjbGllbnQgPSBhd2FpdCB0aGlzLmFwaUNhbGwoYCR7dGhpcy5hcGlCYXNlfS92MS9jbGllbnRzYCwgewogICAgICAgICAgbWV0aG9kOiAnUE9TVCcsCiAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7CiAgICAgICAgICAgIGlwX2NpZHI6IGNsaWVudElQLCAvLyBBUEkgd2lsbCBhdXRvLWFkZCAvMzIKICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZQogICAgICAgICAgfSkKICAgICAgICB9KTsKICAgICAgICBjbGllbnRJZCA9IGNsaWVudC5pZDsKICAgICAgfQoKICAgICAgLy8gQ3JlYXRlIG1hcHBpbmcKICAgICAgYXdhaXQgdGhpcy5hcGlDYWxsKGAke3RoaXMuYXBpQmFzZX0vdjEvbWFwcGluZ3NgLCB7CiAgICAgICAgbWV0aG9kOiAnUE9TVCcsCiAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoewogICAgICAgICAgY2xpZW50X2lkOiBjbGllbnRJZCwKICAgICAgICAgIHByb3h5X2lkOiBwcm94eUlkCiAgICAgICAgfSkKICAgICAgfSk7CgogICAgICB0aGlzLnNob3dBbGVydCgnTWFwcGluZyBjcmVhdGVkIHN1Y2Nlc3NmdWxseScsICdzdWNjZXNzJyk7CiAgICAgIGZvcm0ucmVzZXQoKTsKICAgICAgdGhpcy5sb2FkRGF0YSgpOwogICAgICAKICAgICAgLy8gQXV0byByZWNvbmNpbGUgYWZ0ZXIgY3JlYXRpbmcgbWFwcGluZwogICAgICBzZXRUaW1lb3V0KCgpID0+IHRoaXMucmVjb25jaWxlUnVsZXMoKSwgMTAwMCk7CgogICAgfSBjYXRjaCAoZXJyb3IpIHsKICAgICAgY29uc29sZS5lcnJvcignRmFpbGVkIHRvIGNyZWF0ZSBtYXBwaW5nOicsIGVycm9yKTsKICAgIH0KICB9CgogIGFzeW5jIGNoZWNrUHJveHlIZWFsdGgocHJveHlJZCkgewogICAgdHJ5IHsKICAgICAgYXdhaXQgdGhpcy5hcGlDYWxsKGAke3RoaXMuYXBpQmFzZX0vdjEvcHJveGllcy8ke3Byb3h5SWR9L2NoZWNrYCwgewogICAgICAgIG1ldGhvZDogJ1BPU1QnCiAgICAgIH0pOwogICAgICAKICAgICAgdGhpcy5zaG93QWxlcnQoJ0hlYWx0aCBjaGVjayBjb21wbGV0ZWQnLCAnc3VjY2VzcycpOwogICAgICB0aGlzLmxvYWREYXRhKCk7CiAgICB9IGNhdGNoIChlcnJvcikgewogICAgICBjb25zb2xlLmVycm9yKCdIZWFsdGggY2hlY2sgZmFpbGVkOicsIGVycm9yKTsKICAgIH0KICB9CgogIGFzeW5jIGhlYWx0aENoZWNrQWxsKCkgewogICAgaWYgKHRoaXMucHJveGllcy5sZW5ndGggPT09IDApIHsKICAgICAgdGhpcy5zaG93QWxlcnQoJ05vIHByb3hpZXMgdG8gY2hlY2snLCAnd2FybmluZycpOwogICAgICByZXR1cm47CiAgICB9CgogICAgdGhpcy5zaG93QWxlcnQoJ1J1bm5pbmcgaGVhbHRoIGNoZWNrcy4uLicsICdpbmZvJyk7CiAgICAKICAgIGNvbnN0IGNoZWNrUHJvbWlzZXMgPSB0aGlzLnByb3hpZXMubWFwKHByb3h5ID0+IAogICAgICB0aGlzLmNoZWNrUHJveHlIZWFsdGgocHJveHkuaWQpLmNhdGNoKGUgPT4gY29uc29sZS5lcnJvcihgSGVhbHRoIGNoZWNrIGZhaWxlZCBmb3IgJHtwcm94eS5pZH06YCwgZSkpCiAgICApOwoKICAgIHRyeSB7CiAgICAgIGF3YWl0IFByb21pc2UuYWxsKGNoZWNrUHJvbWlzZXMpOwogICAgICB0aGlzLnNob3dBbGVydCgnQWxsIGhlYWx0aCBjaGVja3MgY29tcGxldGVkJywgJ3N1Y2Nlc3MnKTsKICAgIH0gY2F0Y2ggKGVycm9yKSB7CiAgICAgIGNvbnNvbGUuZXJyb3IoJ1NvbWUgaGVhbHRoIGNoZWNrcyBmYWlsZWQ6JywgZXJyb3IpOwogICAgfQogIH0KCiAgYXN5bmMgZGVsZXRlUHJveHkocHJveHlJZCkgewogICAgaWYgKCFjb25maXJtKCdBcmUgeW91IHN1cmUgeW91IHdhbnQgdG8gZGVsZXRlIHRoaXMgcHJveHk/IFRoaXMgd2lsbCBhbHNvIHJlbW92ZSBhbnkgYXNzb2NpYXRlZCBtYXBwaW5ncy4nKSkgewogICAgICByZXR1cm47CiAgICB9CgogICAgdHJ5IHsKICAgICAgYXdhaXQgdGhpcy5hcGlDYWxsKGAke3RoaXMuYXBpQmFzZX0vdjEvcHJveGllcy8ke3Byb3h5SWR9YCwgewogICAgICAgIG1ldGhvZDogJ0RFTEVURScKICAgICAgfSk7CgogICAgICB0aGlzLnNob3dBbGVydCgnUHJveHkgZGVsZXRlZCBzdWNjZXNzZnVsbHknLCAnc3VjY2VzcycpOwogICAgICB0aGlzLmxvYWREYXRhKCk7CiAgICB9IGNhdGNoIChlcnJvcikgewogICAgICBjb25zb2xlLmVycm9yKCdGYWlsZWQgdG8gZGVsZXRlIHByb3h5OicsIGVycm9yKTsKICAgIH0KICB9CgogIGFzeW5jIGRlbGV0ZU1hcHBpbmcobWFwcGluZ0lkKSB7CiAgICBpZiAoIWNvbmZpcm0oJ0FyZSB5b3Ugc3VyZSB5b3Ugd2FudCB0byBkZWxldGUgdGhpcyBtYXBwaW5nPycpKSB7CiAgICAgIHJldHVybjsKICAgIH0KCiAgICB0cnkgewogICAgICBhd2FpdCB0aGlzLmFwaUNhbGwoYCR7dGhpcy5hcGlCYXNlfS92MS9tYXBwaW5ncy8ke21hcHBpbmdJZH1gLCB7CiAgICAgICAgbWV0aG9kOiAnREVMRVRFJwogICAgICB9KTsKCiAgICAgIHRoaXMuc2hvd0FsZXJ0KCdNYXBwaW5nIGRlbGV0ZWQgc3VjY2Vzc2Z1bGx5JywgJ3N1Y2Nlc3MnKTsKICAgICAgdGhpcy5sb2FkRGF0YSgpOwogICAgICAKICAgICAgLy8gQXV0byByZWNvbmNpbGUgYWZ0ZXIgZGVsZXRpbmcgbWFwcGluZwogICAgICBzZXRUaW1lb3V0KCgpID0+IHRoaXMucmVjb25jaWxlUnVsZXMoKSwgMTAwMCk7CgogICAgfSBjYXRjaCAoZXJyb3IpIHsKICAgICAgY29uc29sZS5lcnJvcignRmFpbGVkIHRvIGRlbGV0ZSBtYXBwaW5nOicsIGVycm9yKTsKICAgIH0KICB9CgogIGFzeW5jIHJlY29uY2lsZVJ1bGVzKCkgewogICAgdHJ5IHsKICAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBmZXRjaChgJHt0aGlzLmFnZW50QmFzZX0vcmVjb25jaWxlYCk7CiAgICAgIAogICAgICBpZiAocmVzcG9uc2Uub2spIHsKICAgICAgICB0aGlzLnNob3dBbGVydCgnUnVsZXMgcmVjb25jaWxlZCBzdWNjZXNzZnVsbHknLCAnc3VjY2VzcycpOwogICAgICAgIHRoaXMudXBkYXRlRWxlbWVudCgnbGFzdC1yZWNvbmNpbGUnLCBuZXcgRGF0ZSgpLnRvTG9jYWxlVGltZVN0cmluZygpKTsKICAgICAgICB0aGlzLmxvYWREYXRhKCk7CiAgICAgIH0gZWxzZSB7CiAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdSZWNvbmNpbGUgZmFpbGVkJyk7CiAgICAgIH0KICAgIH0gY2F0Y2ggKGVycm9yKSB7CiAgICAgIGNvbnNvbGUuZXJyb3IoJ1JlY29uY2lsZSBmYWlsZWQ6JywgZXJyb3IpOwogICAgICB0aGlzLnNob3dBbGVydCgnRmFpbGVkIHRvIHJlY29uY2lsZSBydWxlcycsICdkYW5nZXInKTsKICAgIH0KICB9CgogIGV4cG9ydFByb3hpZXMoKSB7CiAgICBpZiAodGhpcy5wcm94aWVzLmxlbmd0aCA9PT0gMCkgewogICAgICB0aGlzLnNob3dBbGVydCgnTm8gcHJveGllcyB0byBleHBvcnQnLCAnd2FybmluZycpOwogICAgICByZXR1cm47CiAgICB9CgogICAgY29uc3QgY3N2Q29udGVudCA9IFsKICAgICAgJ0lELFR5cGUsSG9zdCxQb3J0LFN0YXR1cyxMYXRlbmN5LEV4aXQgSVAsTGFzdCBDaGVjaycsCiAgICAgIC4uLnRoaXMucHJveGllcy5tYXAocCA9PiBbCiAgICAgICAgcC5pZCwKICAgICAgICBwLnR5cGUsCiAgICAgICAgcC5ob3N0LAogICAgICAgIHAucG9ydCwKICAgICAgICBwLnN0YXR1cyB8fCAnVW5rbm93bicsCiAgICAgICAgcC5sYXRlbmN5X21zIHx8ICcnLAogICAgICAgIHAuZXhpdF9pcCB8fCAnJywKICAgICAgICBwLmxhc3RfY2hlY2tlZF9hdCB8fCAnJwogICAgICBdLmpvaW4oJywnKSkKICAgIF0uam9pbignXG4nKTsKCiAgICB0aGlzLmRvd25sb2FkRmlsZShjc3ZDb250ZW50LCAncGd3LXByb3hpZXMuY3N2JywgJ3RleHQvY3N2Jyk7CiAgfQoKICBleHBvcnRNYXBwaW5ncygpIHsKICAgIGlmICh0aGlzLm1hcHBpbmdzLmxlbmd0aCA9PT0gMCkgewogICAgICB0aGlzLnNob3dBbGVydCgnTm8gbWFwcGluZ3MgdG8gZXhwb3J0JywgJ3dhcm5pbmcnKTsKICAgICAgcmV0dXJuOwogICAgfQoKICAgIGNvbnN0IGNzdkNvbnRlbnQgPSBbCiAgICAgICdJRCxDbGllbnQgSVAsUHJveHkgSG9zdCxQcm94eSBQb3J0LFN0YXRlLExvY2FsIFBvcnQnLAogICAgICAuLi50aGlzLm1hcHBpbmdzLm1hcChtID0+IFsKICAgICAgICBtLmlkLAogICAgICAgIG0uY2xpZW50Py5pcF9jaWRyIHx8ICcnLAogICAgICAgIG0ucHJveHk/Lmhvc3QgfHwgJycsCiAgICAgICAgbS5wcm94eT8ucG9ydCB8fCAnJywKICAgICAgICBtLnN0YXRlIHx8ICdQRU5ESU5HJywKICAgICAgICBtLmxvY2FsX3JlZGlyZWN0X3BvcnQgfHwgJycKICAgICAgXS5qb2luKCcsJykpCiAgICBdLmpvaW4oJ1xuJyk7CgogICAgdGhpcy5kb3dubG9hZEZpbGUoY3N2Q29udGVudCwgJ3Bndy1tYXBwaW5ncy5jc3YnLCAndGV4dC9jc3YnKTsKICB9CgogIGRvd25sb2FkRmlsZShjb250ZW50LCBmaWxlbmFtZSwgbWltZVR5cGUpIHsKICAgIGNvbnN0IGJsb2IgPSBuZXcgQmxvYihbY29udGVudF0sIHsgdHlwZTogbWltZVR5cGUgfSk7CiAgICBjb25zdCB1cmwgPSB3aW5kb3cuVVJMLmNyZWF0ZU9iamVjdFVSTChibG9iKTsKICAgIGNvbnN0IGEgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdhJyk7CiAgICBhLmhyZWYgPSB1cmw7CiAgICBhLmRvd25sb2FkID0gZmlsZW5hbWU7CiAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGEpOwogICAgYS5jbGljaygpOwogICAgZG9jdW1lbnQuYm9keS5yZW1vdmVDaGlsZChhKTsKICAgIHdpbmRvdy5VUkwucmV2b2tlT2JqZWN0VVJMKHVybCk7CiAgICAKICAgIHRoaXMuc2hvd0FsZXJ0KGAke2ZpbGVuYW1lfSBkb3dubG9hZGVkYCwgJ3N1Y2Nlc3MnKTsKICB9CgogIHNob3dBbGVydChtZXNzYWdlLCB0eXBlID0gJ2luZm8nKSB7CiAgICBjb25zdCBhbGVydENvbnRhaW5lciA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdhbGVydHMnKTsKICAgIGlmICghYWxlcnRDb250YWluZXIpIHJldHVybjsKCiAgICBjb25zdCBhbGVydCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwogICAgYWxlcnQuY2xhc3NOYW1lID0gYGFsZXJ0IGFsZXJ0LSR7dHlwZX1gOwogICAgYWxlcnQudGV4dENvbnRlbnQgPSBtZXNzYWdlOwoKICAgIGFsZXJ0Q29udGFpbmVyLmFwcGVuZENoaWxkKGFsZXJ0KTsKCiAgICAvLyBBdXRvIHJlbW92ZSBhZnRlciA1IHNlY29uZHMKICAgIHNldFRpbWVvdXQoKCkgPT4gewogICAgICBhbGVydC5yZW1vdmUoKTsKICAgIH0sIDUwMDApOwogIH0KCiAgc2hvd0xvYWRpbmcoc2hvdykgewogICAgY29uc3QgbG9hZGluZ0VsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2xvYWRpbmctaW5kaWNhdG9yJyk7CiAgICBpZiAobG9hZGluZ0VsKSB7CiAgICAgIGxvYWRpbmdFbC5zdHlsZS5kaXNwbGF5ID0gc2hvdyA/ICdmbGV4JyA6ICdub25lJzsKICAgIH0KICB9CgogIHVwZGF0ZUVsZW1lbnQoaWQsIHZhbHVlKSB7CiAgICBjb25zdCBlbGVtZW50ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoaWQpOwogICAgaWYgKGVsZW1lbnQpIHsKICAgICAgZWxlbWVudC50ZXh0Q29udGVudCA9IHZhbHVlOwogICAgfQogIH0KCiAgdXBkYXRlTGFzdFJlZnJlc2goKSB7CiAgICB0aGlzLnVwZGF0ZUVsZW1lbnQoJ2xhc3QtcmVmcmVzaCcsIG5ldyBEYXRlKCkudG9Mb2NhbGVUaW1lU3RyaW5nKCkpOwogIH0KfQoKLy8gSW5pdGlhbGl6ZSB3aGVuIERPTSBpcyBsb2FkZWQKZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcignRE9NQ29udGVudExvYWRlZCcsICgpID0+IHsKICB3aW5kb3cucGd3ID0gbmV3IFBHV01hbmFnZXIoKTsKfSk7CgovLyBTZXQgYWN0aXZlIG5hdmlnYXRpb24KZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcignRE9NQ29udGVudExvYWRlZCcsICgpID0+IHsKICBjb25zdCBjdXJyZW50UGF0aCA9IHdpbmRvdy5sb2NhdGlvbi5wYXRobmFtZTsKICBjb25zdCBuYXZMaW5rcyA9IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJy5uYXYtbGluaycpOwogIAogIG5hdkxpbmtzLmZvckVhY2gobGluayA9PiB7CiAgICBsaW5rLmNsYXNzTGlzdC5yZW1vdmUoJ2FjdGl2ZScpOwogICAgaWYgKGxpbmsuZ2V0QXR0cmlidXRlKCdocmVmJykgPT09IGN1cnJlbnRQYXRoKSB7CiAgICAgIGxpbmsuY2xhc3NMaXN0LmFkZCgnYWN0aXZlJyk7CiAgICB9CiAgfSk7Cn0pOwo=`
