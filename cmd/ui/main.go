package main

import (
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
		io.WriteString(w, embeddedJS)
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
const embeddedDashboard = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PGW Dashboard</title>
  <link rel="stylesheet" href="/static/styles.css">
</head>
<body>
  <header class="header">
    <div class="header-content">
      <div class="logo">🔒 Proxy Gateway</div>
      <nav class="nav">
        <a href="/" class="nav-link">Dashboard</a>
        <a href="/manage" class="nav-link">Manage</a>
      </nav>
    </div>
  </header>

  <div class="container">
    <div id="alerts"></div>
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-value" id="stat-proxies">—</div>
        <div class="stat-label">Total Proxies</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" id="stat-mappings">—</div>
        <div class="stat-label">Active Mappings</div>
      </div>
    </div>

    <div class="card">
      <div class="card-header"><h3 class="card-title">Quick Actions</h3></div>
      <div class="card-content">
        <div class="flex gap-2">
          <button id="btn-health-all" class="btn btn-primary">Health Check All</button>
          <button id="btn-reconcile" class="btn btn-success">Apply Rules</button>
          <button id="btn-refresh" class="btn btn-secondary">Refresh</button>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-header"><h3 class="card-title">Proxies</h3></div>
      <div class="table-container">
        <table class="table">
          <thead><tr><th>ID</th><th>Address</th><th>Status</th><th>Actions</th></tr></thead>
          <tbody id="tbody-proxies"><tr><td colspan="4" class="text-center">Loading...</td></tr></tbody>
        </table>
      </div>
    </div>
  </div>

  <script src="/static/app.js"></script>
</body>
</html>`

// Embedded templates (fallback when web directory doesn't exist)
const embeddedManage = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PGW Management</title>
  <link rel="stylesheet" href="/static/styles.css">
</head>
<body>
  <header class="header">
    <div class="header-content">
      <div class="logo">🔒 Proxy Gateway</div>
      <nav class="nav">
        <a href="/" class="nav-link">Dashboard</a>
        <a href="/manage" class="nav-link">Manage</a>
      </nav>
    </div>
  </header>

  <div class="container">
    <div id="alerts"></div>

    <div class="card">
      <div class="card-header">
        <h3 class="card-title">Add New Mapping</h3>
      </div>
      <div class="card-content">
        <form id="form-mapping" class="form-row">
          <div class="form-group">
            <label class="form-label">Client IP</label>
            <input type="text" name="client_ip" class="form-input" placeholder="192.168.1.100" required>
          </div>
          <div class="form-group">
            <label class="form-label">Proxy</label>
            <select name="proxy_id" id="select-proxy" class="form-select" required>
              <option value="">Select proxy...</option>
            </select>
          </div>
          <div class="form-group">
            <button type="submit" class="btn btn-primary">Add Mapping</button>
          </div>
        </form>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <h3 class="card-title">Current Mappings</h3>
        <div class="card-actions">
          <button id="btn-reconcile" class="btn btn-success">🔧 Apply Rules</button>
        </div>
      </div>
      <div class="table-container">
        <table class="table">
          <thead>
            <tr><th>ID</th><th>Client IP</th><th>Proxy</th><th>State</th><th>Actions</th></tr>
          </thead>
          <tbody id="tbody-mappings">
            <tr><td colspan="5" class="text-center">Loading...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <script src="/static/app.js"></script>
</body>
</html>`

// Embedded assets - minimal versions
const embeddedCSS = `
:root{--primary:#2563eb;--success:#059669;--warning:#d97706;--danger:#dc2626;--bg:#0f172a;--surface:#1e293b;--text:#f1f5f9;--text-muted:#94a3b8;--border:#334155}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.6}
.header{background:var(--surface);border-bottom:1px solid var(--border);padding:1rem 0;position:sticky;top:0;z-index:100}
.header-content{max-width:1200px;margin:0 auto;padding:0 1rem;display:flex;justify-content:space-between;align-items:center}
.logo{font-size:1.5rem;font-weight:700;color:var(--primary)}
.nav{display:flex;gap:1rem}
.nav-link{color:var(--text-muted);text-decoration:none;padding:0.5rem 1rem;border-radius:0.5rem;transition:all 0.2s}
.nav-link:hover,.nav-link.active{color:var(--text);background:rgba(255,255,255,0.1)}
.container{max-width:1200px;margin:0 auto;padding:2rem 1rem}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1.5rem;margin-bottom:2rem}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:0.75rem;padding:1.5rem;text-align:center}
.stat-value{font-size:2rem;font-weight:700;color:var(--primary);margin-bottom:0.5rem}
.stat-label{color:var(--text-muted);font-size:0.875rem}
.card{background:var(--surface);border:1px solid var(--border);border-radius:0.75rem;overflow:hidden;margin-bottom:2rem}
.card-header{padding:1.5rem;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}
.card-title{font-size:1.25rem;font-weight:600}
.card-content{padding:1.5rem}
.btn{display:inline-flex;align-items:center;gap:0.5rem;padding:0.5rem 1rem;border:none;border-radius:0.5rem;font-size:0.875rem;font-weight:500;cursor:pointer;transition:all 0.2s;text-decoration:none}
.btn-primary{background:var(--primary);color:white}
.btn-secondary{background:#64748b;color:white}
.btn-success{background:var(--success);color:white}
.btn-danger{background:var(--danger);color:white}
.btn-sm{padding:0.25rem 0.75rem;font-size:0.75rem}
.table-container{overflow-x:auto}
.table{width:100%;border-collapse:collapse}
.table th,.table td{text-align:left;padding:0.75rem;border-bottom:1px solid var(--border)}
.table th{background:rgba(255,255,255,0.05);color:var(--text-muted);font-weight:600;font-size:0.875rem}
.badge{display:inline-block;padding:0.25rem 0.75rem;font-size:0.75rem;font-weight:500;border-radius:9999px}
.badge-success{background:var(--success);color:white}
.badge-warning{background:var(--warning);color:white}
.badge-danger{background:var(--danger);color:white}
.badge-secondary{background:#64748b;color:white}
.form-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;align-items:end}
.form-group{display:flex;flex-direction:column;gap:0.5rem}
.form-label{font-size:0.875rem;font-weight:500;color:var(--text-muted)}
.form-input,.form-select{padding:0.75rem;border:1px solid var(--border);border-radius:0.5rem;background:var(--bg);color:var(--text);font-size:0.875rem}
.alert{padding:1rem;border-radius:0.5rem;margin-bottom:1rem;font-size:0.875rem}
.alert-success{background:rgba(5,150,105,0.1);border:1px solid var(--success);color:var(--success)}
.alert-warning{background:rgba(217,119,6,0.1);border:1px solid var(--warning);color:var(--warning)}
.alert-danger{background:rgba(220,38,38,0.1);border:1px solid var(--danger);color:var(--danger)}
.loading{display:flex;align-items:center;justify-content:center;padding:2rem;color:var(--text-muted)}
.spinner{width:1.5rem;height:1.5rem;border:2px solid var(--border);border-top:2px solid var(--primary);border-radius:50%;animation:spin 1s linear infinite;margin-right:0.5rem}
@keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}
.text-center{text-align:center}
.hidden{display:none}
.flex{display:flex}
.gap-2{gap:1rem}
`


const embeddedJS = `
class PGWManager {
  constructor() {
    this.apiBase = '/api';
    this.agentBase = '/agent';
    this.pSort = 'address'; this.pAsc = true;
    this.mSort = 'client'; this.mAsc = true;
    try {
      const sp = JSON.parse(localStorage.getItem('pgw_sort_p2')||'{}');
      if (sp && sp.k) { this.pSort = sp.k; this.pAsc = !!sp.a; }
      const sm = JSON.parse(localStorage.getItem('pgw_sort_m2')||'{}');
      if (sm && sm.k) { this.mSort = sm.k; this.mAsc = !!sm.a; }
    } catch (_) {}
    this.init();
  }
  init() {
    document.getElementById('btn-refresh')?.addEventListener('click', () => this.loadData());
    document.getElementById('btn-health-all')?.addEventListener('click', () => this.healthCheckAll());
    document.getElementById('btn-reconcile')?.addEventListener('click', () => this.reconcileRules());
    document.getElementById('form-mapping')?.addEventListener('submit', (e) => { e.preventDefault(); this.createMapping(); });
    this.loadData();
    setInterval(() => this.loadData(), 30000);
  }
  async apiCall(url, options={}) {
    const resp = await fetch(url, { headers: { 'Content-Type': 'application/json', ...(options.headers||{}) }, ...options });
    if (!resp.ok) throw new Error('HTTP '+resp.status);
    if (resp.status === 204) return null;
    return await resp.json();
  }
  async loadData() {
    try {
      const [proxies, mappings] = await Promise.all([
        this.apiCall(this.apiBase + '/v1/proxies'),
        this.apiCall(this.apiBase + '/v1/mappings')
      ]);
      this.renderStats(proxies||[], mappings||[]);
      this.renderProxies(proxies||[]);
      this.renderMappings(mappings||[]);
      this.renderProxySelect(proxies||[]);
    } catch (e) { console.error(e); }
  }
  renderStats(proxies, mappings) {
    const s = (id,v) => { const el=document.getElementById(id); if (el) el.textContent = String(v); };
    s('stat-proxies', proxies.length);
    s('stat-mappings', mappings.length);
    s('last-refresh', new Date().toLocaleTimeString());
  }
  sortProxies(arr) {
    const key = this.pSort, asc = this.pAsc;
    const val = (p) => {
      if (key==='id') return (p.id||'');
      if (key==='address') return ((p.host||'')+':'+p.port).toLowerCase();
      if (key==='status') return (p.status||'');
      if (key==='latency') return (p.latency_ms==null?Infinity:p.latency_ms);
      if (key==='exit') return (p.exit_ip||'');
      return ((p.host||'')+':'+p.port).toLowerCase();
    };
    return arr.slice().sort((a,b)=>{ const va=val(a), vb=val(b); if (va<vb) return asc?-1:1; if (va>vb) return asc?1:-1; return 0; });
  }
  renderProxies(proxies) {
    const tbody = document.getElementById('tbody-proxies');
    if (!tbody) return;
    const sorted = this.sortProxies(proxies||[]);
    // update header with icons and click
    const thead = tbody.parentElement?.querySelector('thead');
    if (thead) {
      const arrow = this.pAsc ? ' \u25B2' : ' \u25BC';
      thead.innerHTML = '<tr>'
        + '<th data-k="id" class="sortable">ID' + (this.pSort==='id'?arrow:'') + '</th>'
        + '<th>Type</th>'
        + '<th data-k="address" class="sortable">Address' + (this.pSort==='address'?arrow:'') + '</th>'
        + '<th data-k="status" class="sortable">Status' + (this.pSort==='status'?arrow:'') + '</th>'
        + '<th data-k="latency" class="sortable">Latency' + (this.pSort==='latency'?arrow:'') + '</th>'
        + '<th data-k="exit" class="sortable">Exit IP' + (this.pSort==='exit'?arrow:'') + '</th>'
        + '<th>Actions</th>'
        + '</tr>';
      thead.querySelectorAll('th.sortable').forEach((th)=>{
        th.style.cursor='pointer'; th.onclick=()=>{
          const k = th.getAttribute('data-k');
          if (this.pSort===k) this.pAsc=!this.pAsc; else { this.pSort=k; this.pAsc=true; }
          localStorage.setItem('pgw_sort_p2', JSON.stringify({k:this.pSort,a:this.pAsc}));
          this.renderProxies(proxies);
        };
      });
    }
    tbody.innerHTML = sorted.length ? sorted.map(p=>
      '<tr>'
      + '<td>'+(p.id||'').slice(0,8)+'</td>'
      + '<td>'+(p.type||'')+'</td>'
      + '<td>'+(p.host||'')+':'+p.port+'</td>'
      + '<td><span class="badge badge-'+((p.status==='OK')?'success':(p.status==='DEGRADED')?'warning':'danger')+'">'+(p.status||'')+'</span></td>'
      + '<td>'+(p.latency_ms!=null?p.latency_ms:'—')+'</td>'
      + '<td>'+(p.exit_ip||'—')+'</td>'
      + '<td><button class="btn btn-sm btn-secondary" onclick="pgw.checkProxyHealth(\''+(p.id||'')+'\')">Check</button></td>'
      + '</tr>'
    ).join('') : '<tr><td colspan="7" class="text-center">No proxies</td></tr>';
  }
  sortMappings(arr) {
    const key=this.mSort, asc=this.mAsc;
    const val=(m)=>{
      if (key==='id') return (m.id||'');
      if (key==='client') return (((m.client||{}).ip_cidr)||'');
      if (key==='proxy'){ const p=m.proxy||{}; return ((p.host||'')+':'+(p.port!=null?p.port:'')); }
      if (key==='state') return (m.state||'');
      return (((m.client||{}).ip_cidr)||'');
    };
    return arr.slice().sort((a,b)=>{ const va=val(a), vb=val(b); if (va<vb) return asc?-1:1; if (va>vb) return asc?1:-1; return 0; });
  }
  renderMappings(mappings) {
    const tbody = document.getElementById('tbody-mappings');
    if (!tbody) return;
    const sorted = this.sortMappings(mappings||[]);
    const thead = tbody.parentElement?.querySelector('thead');
    if (thead) {
      const arrow = this.mAsc ? ' \u25B2' : ' \u25BC';
      thead.innerHTML = '<tr>'
        + '<th data-k="id" class="sortable">ID' + (this.mSort==='id'?arrow:'') + '</th>'
        + '<th data-k="client" class="sortable">Client IP' + (this.mSort==='client'?arrow:'') + '</th>'
        + '<th data-k="proxy" class="sortable">Proxy' + (this.mSort==='proxy'?arrow:'') + '</th>'
        + '<th data-k="state" class="sortable">State' + (this.mSort==='state'?arrow:'') + '</th>'
        + '<th>Actions</th>'
        + '</tr>';
      thead.querySelectorAll('th.sortable').forEach((th)=>{
        th.style.cursor='pointer'; th.onclick=()=>{
          const k = th.getAttribute('data-k');
          if (this.mSort===k) this.mAsc=!this.mAsc; else { this.mSort=k; this.mAsc=true; }
          localStorage.setItem('pgw_sort_m2', JSON.stringify({k:this.mSort,a:this.mAsc}));
          this.renderMappings(mappings);
        };
      });
    }
    tbody.innerHTML = sorted.length ? sorted.map(m=>{
      const c = (m.client&&m.client.ip_cidr)?m.client.ip_cidr:'—';
      const p = (m.proxy&&m.proxy.host)?(m.proxy.host+':'+m.proxy.port):'—';
      const st = m.state||'PENDING';
      const badge = '<span class="badge '+(st==='APPLIED'?'badge-success':'badge-warning')+'">'+st+'</span>';
      return '<tr>'
        + '<td>'+(m.id||'').slice(0,8)+'</td>'
        + '<td>'+c+'</td>'
        + '<td>'+p+'</td>'
        + '<td>'+badge+'</td>'
        + '<td><button class="btn btn-sm btn-danger" onclick="pgw.deleteMapping(\''+(m.id||'')+'\')">Delete</button></td>'
        + '</tr>';
    }).join('') : '<tr><td colspan="5" class="text-center">No mappings</td></tr>';
  }
  async createMapping(){
    const form=document.getElementById('form-mapping');
    const fd=new FormData(form);
    const clientIP=(fd.get('client_ip')||'').trim();
    const proxyId=fd.get('proxy_id');
    if(!clientIP||!proxyId){this.showAlert('Please fill all fields','warning');return}
    try{
      const client=await this.apiCall(this.apiBase+'/v1/clients',{method:'POST',body:JSON.stringify({ip_cidr:clientIP,enabled:true})});
      await this.apiCall(this.apiBase+'/v1/mappings',{method:'POST',body:JSON.stringify({client_id:client.id,proxy_id:proxyId})});
      this.showAlert('Mapping created','success'); form.reset(); this.loadData(); setTimeout(()=>this.reconcileRules(),1000);
    }catch(e){console.error(e)}
  }
  async checkProxyHealth(id){ try{ await this.apiCall(this.apiBase+'/v1/proxies/'+id+'/check',{method:'POST'}); this.showAlert('Health check completed','success'); this.loadData(); } catch(e){ console.error(e); } }
  async healthCheckAll(){ try{ const proxies=await this.apiCall(this.apiBase+'/v1/proxies'); await Promise.all((proxies||[]).map(p=>this.checkProxyHealth(p.id))); this.showAlert('All health checks completed','success'); } catch(e){ console.error(e); } }
  async deleteMapping(id){ if(!confirm('Delete this mapping?')) return; try{ await this.apiCall(this.apiBase+'/v1/mappings/'+id,{method:'DELETE'}); this.showAlert('Mapping deleted','success'); this.loadData(); setTimeout(()=>this.reconcileRules(),1000);}catch(e){console.error(e)} }
  async reconcileRules(){ try{ const r=await fetch(this.agentBase+'/reconcile'); if(r.ok){ this.showAlert('Rules applied','success'); this.loadData(); } else throw new Error('Reconcile failed'); } catch(e){ this.showAlert('Failed to apply rules','danger'); } }
  showAlert(message,type='info'){ const c=document.getElementById('alerts'); if(!c) return; const a=document.createElement('div'); a.className='alert alert-'+type; a.textContent=message; c.appendChild(a); setTimeout(()=>a.remove(),5000); }
}
document.addEventListener('DOMContentLoaded',()=>{ window.pgw=new PGWManager(); });
`
