class PGWManager {
  constructor() {
    this.apiBase = '/api';
    this.agentBase = '/agent';
    this.proxies = [];
    this.clients = [];
    this.mappings = [];
    this.loading = false;
    // sorting state (persisted)
    this.pSort = 'address'; this.pAsc = true;
    this.mSort = 'client';  this.mAsc = true;
    try {
      const sp = JSON.parse(localStorage.getItem('pgw_sort_p2')||'{}');
      if (sp && sp.k) { this.pSort = sp.k; this.pAsc = !!sp.a; }
      const sm = JSON.parse(localStorage.getItem('pgw_sort_m2')||'{}');
      if (sm && sm.k) { this.mSort = sm.k; this.mAsc = !!sm.a; }
    } catch (_) {}
    
    this.init();
  }

  init() {
    this.bindEvents();
    this.loadData();
    
    // Auto refresh every 30 seconds
    setInterval(() => this.loadData(), 30000);
  }

  bindEvents() {
    // Refresh button
    document.getElementById('btn-refresh')?.addEventListener('click', () => {
      this.loadData();
    });

    // Health check all proxies
    document.getElementById('btn-health-all')?.addEventListener('click', () => {
      this.healthCheckAll();
    });

    // Reconcile rules
    document.getElementById('btn-reconcile')?.addEventListener('click', () => {
      this.reconcileRules();
    });

    // Create proxy form
    document.getElementById('form-proxy')?.addEventListener('submit', (e) => {
      e.preventDefault();
      this.createProxy();
    });


    // Import proxies (bulk)
    document.getElementById("btn-import-proxies")?.addEventListener("click", (e) => {
      e.preventDefault();
      this.importProxies();
    });
    // Create mapping form
    document.getElementById('form-mapping')?.addEventListener('submit', (e) => {
      e.preventDefault();
      this.createMapping();
    });
  }

  async apiCall(url, options = {}) {
    try {
      const response = await fetch(url, {
        headers: {
          'Content-Type': 'application/json',
          ...options.headers
        },
        ...options
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      if (response.status === 204) {
        return null;
      }

      return await response.json();
    } catch (error) {
      console.error('API call failed:', error);
      this.showAlert('API call failed: ' + error.message, 'danger');
      throw error;
    }
  }

  async loadData() {
    if (this.loading) return;
    
    this.loading = true;
    this.showLoading(true);

    try {
      const [proxies, clients, mappings] = await Promise.all([
        this.apiCall(`${this.apiBase}/v1/proxies`),
        this.apiCall(`${this.apiBase}/v1/clients`),
        this.apiCall(`${this.apiBase}/v1/mappings/active`)
      ]);

      this.proxies = proxies || [];
      this.clients = clients || [];
      this.mappings = mappings || [];

      this.renderStats();
      this.renderProxies();
      this.renderProxySummary();
      this.renderMappings();
      this.renderClients();
      this.updateCounts();
      this.updateLastRefresh();

    } catch (error) {
      console.error('Failed to load data:', error);
    } finally {
      this.loading = false;
      this.showLoading(false);
    }
  }

  renderStats() {
    const okProxies = this.proxies.filter(p => p.status === 'OK').length;
    const activeMappings = this.mappings.filter(m => m.client?.enabled && m.proxy?.enabled).length;
    
    this.updateElement('stat-proxies', this.proxies.length);
    this.updateElement('stat-proxies-ok', okProxies);
    this.updateElement('stat-clients', this.clients.length);
    this.updateElement('stat-mappings', activeMappings);
  }

  renderProxies() {
    const tbody = document.getElementById('tbody-proxies');
    if (!tbody) return;
    // sort
    const key = this.pSort, asc = this.pAsc;
    const val = (p) => {
      if (key==='id') return (p.id||'');
      if (key==='type') return (p.type||'');
      if (key==='address') return ((p.host||'')+':'+p.port).toLowerCase();
      if (key==='status') return (p.status||'');
      if (key==='latency') return (p.latency_ms==null?Infinity:p.latency_ms);
      if (key==='exit') return (p.exit_ip||'');
      if (key==='last') return (p.last_checked_at||'');
      return ((p.host||'')+':'+p.port).toLowerCase();
    };
    const sorted = (this.proxies||[]).slice().sort((a,b)=>{ const va=val(a), vb=val(b); if (va<vb) return asc?-1:1; if (va>vb) return asc?1:-1; return 0; });
    // header icons + click
    const thead = tbody.parentElement?.querySelector('thead');
    if (thead) {
      const arrow = asc ? ' \\u25B2' : ' \\u25BC';
      thead.innerHTML = '<tr>'
        + '<th data-k="id" class="sortable">ID'+(key==='id'?arrow:'')+'</th>'
        + '<th data-k="type" class="sortable">Type'+(key==='type'?arrow:'')+'</th>'
        + '<th data-k="address" class="sortable">Address'+(key==='address'?arrow:'')+'</th>'
        + '<th data-k="status" class="sortable">Status'+(key==='status'?arrow:'')+'</th>'
        + '<th data-k="latency" class="sortable">Latency'+(key==='latency'?arrow:'')+'</th>'
        + '<th data-k="exit" class="sortable">Exit IP'+(key==='exit'?arrow:'')+'</th>'
        + '<th data-k="last" class="sortable">Last Check'+(key==='last'?arrow:'')+'</th>'
        + '<th>Actions</th>'
        + '</tr>';
      thead.querySelectorAll('th.sortable').forEach((th)=>{
        th.style.cursor='pointer'; th.onclick=()=>{
          const k=th.getAttribute('data-k');
          if (this.pSort===k) this.pAsc=!this.pAsc; else { this.pSort=k; this.pAsc=true; }
          localStorage.setItem('pgw_sort_p2', JSON.stringify({k:this.pSort,a:this.pAsc}));
          this.renderProxies();
        };
      });
    }

    tbody.innerHTML = '';

    if (sorted.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-center">No proxies configured</td></tr>';
      return;
    }

    sorted.forEach(proxy => {
      const row = this.createProxyRow(proxy);
      tbody.appendChild(row);
    });
  }

  renderProxySummary() {
    const tbody = document.getElementById('tbody-proxy-summary');
    if (!tbody) return;

    tbody.innerHTML = '';

    if (this.proxies.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="text-center">No proxies configured</td></tr>';
      return;
    }

    this.proxies.forEach(proxy => {
      const tr = document.createElement('tr');
      const statusBadge = this.createStatusBadge(proxy.status);
      const latencyText = proxy.latency_ms !== null ? `${proxy.latency_ms}ms` : '—';
      const lastChecked = proxy.last_checked_at 
        ? new Date(proxy.last_checked_at).toLocaleTimeString()
        : '—';

      tr.innerHTML = `
        <td>${proxy.host}:${proxy.port}</td>
        <td>${statusBadge}</td>
        <td>${latencyText}</td>
        <td>${proxy.exit_ip || '—'}</td>
        <td>${lastChecked}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  createProxyRow(proxy) {
    const tr = document.createElement('tr');
    
    const statusBadge = this.createStatusBadge(proxy.status);
    const latencyText = proxy.latency_ms !== null ? `${proxy.latency_ms}ms` : '—';
    const lastChecked = proxy.last_checked_at 
      ? new Date(proxy.last_checked_at).toLocaleTimeString()
      : '—';

    tr.innerHTML = `
      <td><code>${proxy.id.slice(0, 8)}</code></td>
      <td>${proxy.type}</td>
      <td>${proxy.host}:${proxy.port}</td>
      <td>${statusBadge}</td>
      <td>${latencyText}</td>
      <td>${proxy.exit_ip || '—'}</td>
      <td>${lastChecked}</td>
      <td>
        <button class="btn btn-sm btn-secondary" onclick="pgw.checkProxyHealth('${proxy.id}')" data-tooltip="Health check">
          Check
        </button>
        <button class="btn btn-sm btn-danger" onclick="pgw.deleteProxy('${proxy.id}')" data-tooltip="Delete proxy">
          ×
        </button>
      </td>
    `;

    return tr;
  }

  createStatusBadge(status) {
    const statusClass = {
      'OK': 'text-bg-success',
      'DEGRADED': 'text-bg-warning',
      'DOWN': 'text-bg-danger'
    }[status] || 'text-bg-secondary';

    return `<span class="badge ${statusClass}">${status || 'Unknown'}</span>`;
  }

  renderMappings() {
    const tbody = document.getElementById('tbody-mappings');
    if (!tbody) return;
    // sort
    const key = this.mSort, asc = this.mAsc;
    const val = (m) => {
      if (key==='id') return (m.id||'');
      if (key==='client') return ((m.client?.ip_cidr)||'');
      if (key==='proxy') { const p=m.proxy||{}; return ((p.host||'')+':'+(p.port??'')); }
      if (key==='state') return (m.state||'');
      if (key==='port') return (m.local_redirect_port??0);
      return ((m.client?.ip_cidr)||'');
    };
    const sorted = (this.mappings||[]).slice().sort((a,b)=>{ const va=val(a), vb=val(b); if (va<vb) return asc?-1:1; if (va>vb) return asc?1:-1; return 0; });
    // header icons + click
    const thead = tbody.parentElement?.querySelector('thead');
    if (thead) {
      const arrow = asc ? ' \\u25B2' : ' \\u25BC';
      thead.innerHTML = '<tr>'
        + '<th data-k="id" class="sortable">ID'+(key==='id'?arrow:'')+'</th>'
        + '<th data-k="client" class="sortable">Client IP/CIDR'+(key==='client'?arrow:'')+'</th>'
        + '<th data-k="proxy" class="sortable">Proxy Server'+(key==='proxy'?arrow:'')+'</th>'
        + '<th data-k="state" class="sortable">State'+(key==='state'?arrow:'')+'</th>'
        + '<th data-k="port" class="sortable">Local Port'+(key==='port'?arrow:'')+'</th>'
        + '<th>Actions</th>'
        + '</tr>';
      thead.querySelectorAll('th.sortable').forEach((th)=>{
        th.style.cursor='pointer'; th.onclick=()=>{
          const k=th.getAttribute('data-k');
          if (this.mSort===k) this.mAsc=!this.mAsc; else { this.mSort=k; this.mAsc=true; }
          localStorage.setItem('pgw_sort_m2', JSON.stringify({k:this.mSort,a:this.mAsc}));
          this.renderMappings();
        };
      });
    }

    tbody.innerHTML = '';

    if (sorted.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="text-center">No mappings configured</td></tr>';
      return;
    }

    sorted.forEach(mapping => {
      const row = this.createMappingRow(mapping);
      tbody.appendChild(row);
    });
  }

  createMappingRow(mapping) {
    const tr = document.createElement('tr');
    
    const proxyAddress = mapping.proxy 
      ? `${mapping.proxy.host}:${mapping.proxy.port}`
      : '—';
    
    const stateBadge = this.createStatusBadge(mapping.state || 'PENDING');

    tr.innerHTML = `
      <td><code>${mapping.id.slice(0, 8)}</code></td>
      <td>${mapping.client?.ip_cidr || '—'}</td>
      <td>${proxyAddress}</td>
      <td>${stateBadge}</td>
      <td>${mapping.local_redirect_port || '—'}</td>
      <td>
        <button class="btn btn-sm btn-danger" onclick="pgw.deleteMapping('${mapping.id}')">
          Delete
        </button>
      </td>
    `;

    return tr;
  }

  renderClients() {
    const select = document.getElementById('select-proxy');
    if (!select) return;

    select.innerHTML = '<option value="">Select proxy server...</option>';

    const used = new Set((this.mappings || []).map(m => m && m.proxy ? m.proxy.id : null).filter(Boolean));
    const available = (this.proxies || []).filter(p => !used.has(p.id));

    if (!available || available.length === 0) {
      const opt = document.createElement('option');
      opt.disabled = true;
      opt.textContent = 'No available proxies (all mapped)';
      select.appendChild(opt);
      return;
    }

    available.forEach(proxy => {
      const option = document.createElement('option');
      option.value = proxy.id;
      const statusIndicator = proxy.status === 'OK' ? '✓' : proxy.status === 'DEGRADED' ? '⚠' : '✗';
      option.textContent = `${statusIndicator} ${proxy.host}:${proxy.port} (${proxy.type})`;
      select.appendChild(option);
    });
  }
  parseProxyLine(line) {
    const m = line.trim().match(/^([^:\s]+):(\d{1,5}):([^:]*):([^:]*)$/);
    if (!m) return null;
    const host = m[1];
    const port = parseInt(m[2], 10);
    const username = m[3] || "";
    const password = m[4] || "";
    if (!host || !port || port <= 0 || port > 65535) return null;
    return { type: "http", host, port, username, password, enabled: true };
  }

  async importProxies() {
    const textarea = document.getElementById("import-proxies");
    if (!textarea) return;
    const raw = textarea.value || "";
    const lines = raw.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    if (lines.length === 0) {
      this.showAlert("No proxies to import", "warning");
      return;
    }

    let ok = 0, skipped = 0;
    for (const [idx, line] of lines.entries()) {
      if (line.startsWith("#")) { skipped++; continue; }
      const data = this.parseProxyLine(line);
      if (!data) { skipped++; continue; }
      try {
        const created = await this.apiCall(`${this.apiBase}/v1/proxies`, { method: "POST", body: JSON.stringify(data) });
        ok++;
        setTimeout(() => this.checkProxyHealth(created.id), 500);
      } catch (e) {
        console.error("Import failed for line", idx+1, line, e);
        skipped++;
      }
    }

    this.showAlert(`Imported ${ok} proxies${skipped?`, skipped ${skipped}`:""}`, ok>0 ? "success" : "warning");
    if (ok>0) this.loadData();
  }


  updateCounts() {
    this.updateElement('proxy-count', `${this.proxies.length} proxies`);
    this.updateElement('mapping-count', `${this.mappings.length} mappings`);
  }

  async createProxy() {
    const form = document.getElementById('form-proxy');
    const formData = new FormData(form);

    const proxyData = {
      type: formData.get('type'),
      host: formData.get('host'),
      port: parseInt(formData.get('port')),
      username: formData.get('username') || '',
      password: formData.get('password') || '',
      enabled: true
    };

    try {
      const newProxy = await this.apiCall(`${this.apiBase}/v1/proxies`, {
        method: 'POST',
        body: JSON.stringify(proxyData)
      });

      this.showAlert('Proxy created successfully', 'success');
      form.reset();
      this.loadData();
      
      // Auto health check the new proxy
      setTimeout(() => this.checkProxyHealth(newProxy.id), 1000);
      
    } catch (error) {
      console.error('Failed to create proxy:', error);
    }
  }

  async createMapping() {
    const form = document.getElementById('form-mapping');
    const formData = new FormData(form);

    const clientIP = (formData.get('client_ip') || '').trim();
    const proxyId = formData.get('proxy_id');

    // Frontend validation: IPv4 only, forbid CIDR
    const ipv4Re = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
    if (clientIP.includes('/')) {
      this.showAlert('CIDR is not allowed. Please enter a single IPv4 address (e.g., 192.168.2.3).', 'warning');
      return;
    }
    if (clientIP && !ipv4Re.test(clientIP)) {
      this.showAlert('Invalid IPv4 address format.', 'warning');
      return;
    }

    if (!clientIP || !proxyId) {
      this.showAlert('Please fill all required fields', 'warning');
      return;
    }

    try {
      // First create client if not exists
      let clientId;
      const existingClient = this.clients.find(c => c.ip_cidr === `${clientIP}/32`);
      
      if (existingClient) {
        clientId = existingClient.id;
      } else {
        const client = await this.apiCall(`${this.apiBase}/v1/clients`, {
          method: 'POST',
          body: JSON.stringify({
            ip_cidr: clientIP, // API will auto-add /32
            enabled: true
          })
        });
        clientId = client.id;
      }

      // Create mapping
      await this.apiCall(`${this.apiBase}/v1/mappings`, {
        method: 'POST',
        body: JSON.stringify({
          client_id: clientId,
          proxy_id: proxyId
        })
      });

      this.showAlert('Mapping created successfully', 'success');
      form.reset();
      this.loadData();
      
      // Auto reconcile after creating mapping
      setTimeout(() => this.reconcileRules(), 1000);

    } catch (error) {
      console.error('Failed to create mapping:', error);
    }
  }

  async checkProxyHealth(proxyId) {
    try {
      await this.apiCall(`${this.apiBase}/v1/proxies/${proxyId}/check`, {
        method: 'POST'
      });
      
      this.showAlert('Health check completed', 'success');
      this.loadData();
    } catch (error) {
      console.error('Health check failed:', error);
    }
  }

  async healthCheckAll() {
    if (this.proxies.length === 0) {
      this.showAlert('No proxies to check', 'warning');
      return;
    }

    this.showAlert('Running health checks...', 'info');
    
    const checkPromises = this.proxies.map(proxy => 
      this.checkProxyHealth(proxy.id).catch(e => console.error(`Health check failed for ${proxy.id}:`, e))
    );

    try {
      await Promise.all(checkPromises);
      this.showAlert('All health checks completed', 'success');
    } catch (error) {
      console.error('Some health checks failed:', error);
    }
  }

  async deleteProxy(proxyId) {
    if (!confirm('Are you sure you want to delete this proxy? This will also remove any associated mappings.')) {
      return;
    }

    try {
      await this.apiCall(`${this.apiBase}/v1/proxies/${proxyId}`, {
        method: 'DELETE'
      });

      this.showAlert('Proxy deleted successfully', 'success');
      this.loadData();
    } catch (error) {
      console.error('Failed to delete proxy:', error);
    }
  }

  async deleteMapping(mappingId) {
    if (!confirm('Are you sure you want to delete this mapping?')) {
      return;
    }

    try {
      await this.apiCall(`${this.apiBase}/v1/mappings/${mappingId}`, {
        method: 'DELETE'
      });

      this.showAlert('Mapping deleted successfully', 'success');
      this.loadData();
      
      // Auto reconcile after deleting mapping
      setTimeout(() => this.reconcileRules(), 1000);

    } catch (error) {
      console.error('Failed to delete mapping:', error);
    }
  }

  async reconcileRules() {
    try {
      const response = await fetch(`${this.agentBase}/reconcile`);
      
      if (response.ok) {
        this.showAlert('Rules reconciled successfully', 'success');
        this.updateElement('last-reconcile', new Date().toLocaleTimeString());
        this.loadData();
      } else {
        throw new Error('Reconcile failed');
      }
    } catch (error) {
      console.error('Reconcile failed:', error);
      this.showAlert('Failed to reconcile rules', 'danger');
    }
  }

  exportProxies() {
    if (this.proxies.length === 0) {
      this.showAlert('No proxies to export', 'warning');
      return;
    }

    const csvContent = [
      'ID,Type,Host,Port,Status,Latency,Exit IP,Last Check',
      ...this.proxies.map(p => [
        p.id,
        p.type,
        p.host,
        p.port,
        p.status || 'Unknown',
        p.latency_ms || '',
        p.exit_ip || '',
        p.last_checked_at || ''
      ].join(','))
    ].join('\n');

    this.downloadFile(csvContent, 'pgw-proxies.csv', 'text/csv');
  }

  exportMappings() {
    if (this.mappings.length === 0) {
      this.showAlert('No mappings to export', 'warning');
      return;
    }

    const csvContent = [
      'ID,Client IP,Proxy Host,Proxy Port,State,Local Port',
      ...this.mappings.map(m => [
        m.id,
        m.client?.ip_cidr || '',
        m.proxy?.host || '',
        m.proxy?.port || '',
        m.state || 'PENDING',
        m.local_redirect_port || ''
      ].join(','))
    ].join('\n');

    this.downloadFile(csvContent, 'pgw-mappings.csv', 'text/csv');
  }

  downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
    
    this.showAlert(`${filename} downloaded`, 'success');
  }

  showAlert(message, type = 'info') {
    const container = document.getElementById('alerts');
    if (!container) return;

    // Ensure container is overlay and toast-ready (CSS handles positioning)
    container.classList.add('toast-stack');

    const bsType = ['success','danger','warning','info','primary','secondary'].includes(type) ? type : 'info';
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-bg-${bsType} border-0`;
    toast.setAttribute('role','alert');
    toast.setAttribute('aria-live','assertive');
    toast.setAttribute('aria-atomic','true');

    const inner = document.createElement('div');
    inner.className = 'd-flex';
    const body = document.createElement('div');
    body.className = 'toast-body';
    body.textContent = message;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn-close btn-close-white me-2 m-auto';
    btn.setAttribute('data-bs-dismiss','toast');
    btn.setAttribute('aria-label','Close');

    inner.appendChild(body);
    inner.appendChild(btn);
    toast.appendChild(inner);

    container.appendChild(toast);

    const inst = bootstrap.Toast.getOrCreateInstance(toast, { delay: 3500 });
    inst.show();
    toast.addEventListener('hidden.bs.toast', () => toast.remove());
  }

  showLoading(show) {
    const loadingEl = document.getElementById('loading-indicator');
    if (loadingEl) {
      loadingEl.style.display = show ? 'flex' : 'none';
    }
  }

  updateElement(id, value) {
    const element = document.getElementById(id);
    if (element) {
      element.textContent = value;
    }
  }

  updateLastRefresh() {
    this.updateElement('last-refresh', new Date().toLocaleTimeString());
  }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  window.pgw = new PGWManager();
});

// Set active navigation
document.addEventListener('DOMContentLoaded', () => {
  const currentPath = window.location.pathname;
  const navLinks = document.querySelectorAll('.nav-link');
  
  navLinks.forEach(link => {
    link.classList.remove('active');
    if (link.getAttribute('href') === currentPath) {
      link.classList.add('active');
    }
  });
});
