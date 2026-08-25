(() => {
  'use strict';

  const API = '/api/v2';
  const CONTROL_PLANE_CHECK = '/api/v1/proxies/';
  const PAGE_LIMIT = 200;
  const MAX_PAGE_ITEMS = 5000;
  const state = { proxies: [], clients: [], policies: [], mappings: [], agent: null, audits: [], nextAuditCursor: '', loadEpoch: 0, loadController: null };
  const byID = (id) => document.getElementById(id);
  const text = (value) => value === undefined || value === null || value === '' ? '—' : String(value);
  const iso = (value) => value ? new Date(value).toLocaleString() : '—';
  const itemList = (page) => Array.isArray(page) ? page : (page?.items || []);
  const idKey = (prefix) => `${prefix}-${globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(16).slice(2)}`}`;

  function announce(message, urgent = false) {
    const live = byID(urgent ? 'ui-errors' : 'ui-status');
    if (live) live.textContent = message;
  }
  function clearNode(node) { while (node?.firstChild) node.removeChild(node.firstChild); }
  function cell(row, value, className = '') { const td = document.createElement('td'); td.textContent = text(value); if (className) td.className = className; row.append(td); return td; }
  function button(label, className, click) { const result = document.createElement('button'); result.type = 'button'; result.className = className; result.textContent = label; result.addEventListener('click', click); return result; }
  function statusMark(value) { const mark = document.createElement('span'); const normalized = value || 'UNKNOWN'; mark.className = `status-mark state-${normalized.toLowerCase()}`; mark.textContent = normalized; mark.setAttribute('aria-label', `Status: ${normalized}`); return mark; }
  function mappingVersion(mapping) { return `"${Number(mapping.version || 0)}"`; }

  async function request(path, options = {}) {
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 12000);
    const parentSignal = options.signal;
    const abortFromParent = () => controller.abort();
    parentSignal?.addEventListener('abort', abortFromParent, { once: true });
    const headers = new Headers(options.headers || {});
    if (options.body !== undefined && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
    try {
      const response = await fetch(path, { ...options, headers, signal: controller.signal, credentials: 'same-origin' });
      if (response.status === 401) { window.location.assign('/login'); throw new Error('Your session has expired.'); }
      if (!response.ok) {
        let detail = {};
        try { detail = await response.json(); } catch (_) { /* never render raw upstream responses */ }
        const error = new Error(detail?.error?.message || `Request failed (${response.status}).`);
        error.status = response.status; error.code = detail?.error?.code; error.details = detail?.error?.details;
        throw error;
      }
      return response.status === 204 ? null : response.json();
    } finally { clearTimeout(timer); parentSignal?.removeEventListener('abort', abortFromParent); }
  }
  function mutation(method, path, version, body) {
    const headers = { 'Idempotency-Key': idKey('ui') };
    if (version !== undefined && version !== null) headers['If-Match'] = version;
    return request(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  }

  async function loadPaged(resource, signal) {
    const items = []; const cursors = new Set(); let cursor = '';
    while (true) {
      const params = new URLSearchParams({ limit: String(PAGE_LIMIT) }); if (cursor) params.set('cursor', cursor);
      const page = await request(`${API}/${resource}?${params}`, { signal }); const pageItems = itemList(page);
      if (items.length + pageItems.length > MAX_PAGE_ITEMS) throw new Error(`${resource} exceeded the safe UI pagination limit.`);
      items.push(...pageItems);
      const next = page?.next_cursor;
      if (!next) return items;
      if (typeof next !== 'string' || cursors.has(next)) throw new Error(`${resource} pagination cursor is invalid or repeated.`);
      cursors.add(next); cursor = next;
    }
  }

  function normalizeIPv4(value) {
    const raw = String(value || '').trim(); const cidr = raw.split('/');
    if (cidr.length > 2 || (cidr.length === 2 && cidr[1] !== '32')) return null;
    const address = cidr[0]; const parts = address.split('.');
    if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) return null;
    return `${parts.map((part) => String(Number(part))).join('.')}/32`;
  }
  function validatePreview() {
    const clientInput = byID('mapping-client-ip'); const proxyID = byID('mapping-proxy')?.value; const policyID = byID('mapping-policy')?.value; const port = Number(byID('mapping-port')?.value); const errors = [];
    const normalized = normalizeIPv4(clientInput?.value);
    if (!normalized) errors.push('Enter one IPv4 client address; it will be normalized to /32.');
    if (!proxyID) errors.push('Choose an enabled proxy.');
    const policy = state.policies.find((candidate) => candidate.id === policyID);
    if (!policy || policy.kind !== 'web_only' || !policy.enabled) errors.push('Choose an enabled web_only policy.');
    if (!Number.isInteger(port) || port < 15001 || port > 15999) errors.push('Redirect port must be between 15001 and 15999.');
    if (state.mappings.some((mapping) => mapping.local_redirect_port === port && mapping.desired_state !== 'DELETED')) errors.push('That redirect port is already reserved by a non-deleted mapping.');
    const proxy = state.proxies.find((candidate) => candidate.id === proxyID);
    if (proxy && (!proxy.enabled || proxy.status === 'DOWN')) errors.push('Selected proxy is unavailable; choose an enabled compatible proxy.');
    const output = byID('mapping-preview'); const inputError = byID('mapping-client-error');
    clientInput?.setAttribute('aria-invalid', String(!normalized)); if (inputError) inputError.textContent = normalized ? '' : 'A valid IPv4 address is required.';
    if (output) {
      clearNode(output); const title = document.createElement('strong'); title.textContent = errors.length ? 'Validation needs attention' : 'Client-side validation preview'; output.append(title);
      const list = document.createElement('ul');
      (errors.length ? errors : [`Client: ${normalized}`, `Proxy: ${proxy?.label || proxy?.host || proxyID}`, 'Policy: web_only (TCP 80/443 only)', `Redirect port: ${port}`, 'No direct fallback: traffic is never sent directly to WAN.', 'Capability matrix is not exposed by this API; server-side validation remains authoritative.']).forEach((message) => { const item = document.createElement('li'); item.textContent = message; list.append(item); });
      output.append(list); output.classList.toggle('validation-failed', errors.length > 0);
    }
    return { valid: errors.length === 0, normalized, proxyID, policyID, port };
  }
  function fillMappingForm() {
    const proxy = byID('mapping-proxy'); const policy = byID('mapping-policy');
    if (proxy) { clearNode(proxy); proxy.append(new Option('Choose an enabled proxy', '')); state.proxies.filter((item) => item.enabled).forEach((item) => proxy.append(new Option(`${item.label || item.host}:${item.port} (${item.status || 'UNKNOWN'})`, item.id))); }
    if (policy) { clearNode(policy); policy.append(new Option('Choose web_only policy', '')); state.policies.filter((item) => item.enabled && item.kind === 'web_only').forEach((item) => policy.append(new Option(`${item.name} — TCP 80/443`, item.id))); }
  }
  function renderAgent() {
    const agent = state.agent || {}; const pending = Number(agent.pending_generation || 0); const applied = Number(agent.applied_generation || 0); const mismatch = pending !== applied;
    byID('agent-state-value').textContent = text(agent.state); byID('agent-generation-value').textContent = `pending ${pending} / applied ${applied}${mismatch ? ' (mismatch)' : ''}`; byID('agent-ruleset-value').textContent = text(agent.ruleset_hash); byID('agent-reconcile-value').textContent = iso(agent.updated_at);
    const ipv6 = agent.ipv6_policy === 'deny' ? 'deny-only' : 'unverified/invalid';
    byID('agent-ipv6-policy-value').textContent = agent.ipv6_policy_verified === true && agent.ipv6_policy === 'deny' ? `${ipv6} (VERIFIED)` : `${ipv6} (not verified)`;
    const rollback = agent.state === 'ROLLED_BACK' || /rollback|lkg/i.test(agent.last_error || '');
    byID('agent-lkg-value').textContent = rollback ? `Rollback/LKG signalled: ${text(agent.last_error)}` : 'LKG/rollback fields are not exposed by this API.'; byID('agent-error-value').textContent = text(agent.last_error); byID('agent-state-panel')?.classList.toggle('has-mismatch', mismatch);
  }
  function latestReason(mappingID) { const related = state.audits.find((event) => event.entity_id === mappingID); if (!related) return 'No mapping-specific reason reported.'; let payload = related.payload; if (typeof payload === 'string') { try { payload = JSON.parse(payload); } catch (_) { payload = {}; } } return payload?.reason_code || payload?.reason || related.action || 'No mapping-specific reason reported.'; }
  function renderMappings() {
    const body = byID('mappings-body'); if (!body) return; clearNode(body);
    if (!state.mappings.length) { const row = document.createElement('tr'); const td = cell(row, 'No mappings configured. Create a draft after validating it.', 'empty'); td.colSpan = 7; body.append(row); return; }
    state.mappings.forEach((mapping) => {
      const row = document.createElement('tr'); cell(row, mapping.id, 'monospace'); cell(row, `${mapping.client_id} → ${mapping.proxy_id}`);
      const desired = document.createElement('td'); desired.append(statusMark(mapping.desired_state)); row.append(desired);
      cell(row, `desired ${text(mapping.desired_generation)}\napplied ${text(mapping.applied_generation)}`, 'multiline'); cell(row, `desired ${text(mapping.desired_hash)}\napplied ${text(mapping.applied_hash)}`, 'multiline monospace');
      const plane = document.createElement('td'); plane.append(statusMark(mapping.data_plane_state)); const reason = document.createElement('small'); reason.textContent = latestReason(mapping.id); plane.append(document.createElement('br'), reason); row.append(plane);
      const actions = document.createElement('td'); actions.className = 'row-actions';
      if (mapping.desired_state === 'DRAFT' || mapping.desired_state === 'SUSPENDED') actions.append(button('Activate', 'btn btn-primary btn-sm', () => mappingAction(mapping, 'activate')));
      if (mapping.desired_state === 'ACTIVE') actions.append(button('Suspend', 'btn btn-warning btn-sm', () => mappingAction(mapping, 'suspend')));
      if (mapping.desired_state !== 'DELETED') actions.append(button('Delete', 'btn btn-outline-danger btn-sm', () => deleteMapping(mapping))); row.append(actions); body.append(row);
    });
  }
  function renderProofs() {
    const body = byID('proxies-body'); if (!body) return; clearNode(body);
    if (!state.proxies.length) { const row = document.createElement('tr'); const td = cell(row, 'No proxies are available for a control-plane check.', 'empty'); td.colSpan = 6; body.append(row); return; }
    state.proxies.forEach((proxy) => { const row = document.createElement('tr'); cell(row, proxy.label || proxy.id); cell(row, proxy.status); cell(row, proxy.exit_ip); cell(row, proxy.latency_ms === undefined ? '—' : `${proxy.latency_ms} ms`); cell(row, iso(proxy.last_checked_at)); const actions = document.createElement('td'); actions.append(button('Check egress (control-plane)', 'btn btn-outline-light btn-sm', () => checkProxy(proxy))); row.append(actions); body.append(row); });
  }
  function auditSummary(payload) { if (!payload) return 'not reported'; let object = payload; if (typeof payload === 'string') { try { object = JSON.parse(payload); } catch (_) { return 'not reported'; } } return [object.generation && `generation ${object.generation}`, object.reason_code || object.reason].filter(Boolean).join(', ') || 'not reported'; }
  function renderAudit() {
    const timeline = byID('audit-timeline'); if (!timeline) return; clearNode(timeline); if (!state.audits.length) { const item = document.createElement('li'); item.textContent = 'No audit events returned.'; timeline.append(item); }
    state.audits.forEach((event) => { const item = document.createElement('li'); const heading = document.createElement('strong'); heading.textContent = `${text(event.action)} by ${text(event.actor)}`; item.append(heading, document.createTextNode(` — ${iso(event.created_at)}; entity ${text(event.entity)} ${text(event.entity_id)}; generation/reason: ${auditSummary(event.payload)}`)); timeline.append(item); }); byID('audit-more').hidden = !state.nextAuditCursor;
  }
  function renderSummary() { byID('summary-proxies').textContent = String(state.proxies.length); byID('summary-mappings').textContent = String(state.mappings.length); byID('summary-verified').textContent = String(state.mappings.filter((item) => item.data_plane_state === 'VERIFIED').length); byID('summary-refreshed').textContent = new Date().toLocaleTimeString(); }
  function render() { fillMappingForm(); renderSummary(); renderAgent(); renderMappings(); renderProofs(); renderAudit(); }
  async function loadAll() {
    state.loadController?.abort();
    const controller = new AbortController(); state.loadController = controller; const epoch = ++state.loadEpoch;
    announce('Refreshing control-plane data…');
    try {
      const [proxies, clients, policies, mappings, agent, audits] = await Promise.all([loadPaged('proxies', controller.signal), loadPaged('clients', controller.signal), loadPaged('egress-policies', controller.signal), loadPaged('mappings', controller.signal), request(`${API}/agent/state`, { signal: controller.signal }), request(`${API}/audit-events?limit=50`, { signal: controller.signal })]);
      if (controller.signal.aborted || epoch !== state.loadEpoch) return;
      state.proxies = itemList(proxies); state.clients = itemList(clients); state.policies = itemList(policies); state.mappings = itemList(mappings); state.agent = agent; state.audits = itemList(audits); state.nextAuditCursor = audits?.next_cursor || ''; render(); announce('Control-plane data refreshed.');
    } catch (error) { if (!controller.signal.aborted && epoch === state.loadEpoch) announce(error.message || 'Unable to load control-plane data.', true); }
    finally { if (epoch === state.loadEpoch) state.loadController = null; }
  }
  async function loadMoreAudit() { if (!state.nextAuditCursor) return; try { const page = await request(`${API}/audit-events?limit=50&cursor=${encodeURIComponent(state.nextAuditCursor)}`); state.audits.push(...itemList(page)); state.nextAuditCursor = page?.next_cursor || ''; renderAudit(); announce('More audit events loaded.'); } catch (error) { announce(error.message || 'Unable to load audit events.', true); } }
  async function createMapping(event) {
    event.preventDefault(); const preview = validatePreview(); if (!preview.valid) { announce('Correct the validation issues before creating a draft.', true); return; }
    try { let client = state.clients.find((item) => item.ip_cidr === preview.normalized); if (!client) client = await mutation('POST', `${API}/clients`, undefined, { id: idKey('client'), ip_cidr: preview.normalized, enabled: true }); await mutation('POST', `${API}/mappings`, undefined, { id: idKey('mapping'), client_id: client.id, proxy_id: preview.proxyID, policy_id: preview.policyID, local_redirect_port: preview.port }); byID('mapping-form')?.reset(); await loadAll(); announce('Draft mapping created. Activate it explicitly after review.'); } catch (error) { announce(error.message || 'Unable to create draft mapping.', true); }
  }
  async function mappingAction(mapping, action) { try { await mutation('POST', `${API}/mappings/${encodeURIComponent(mapping.id)}/${action}`, mappingVersion(mapping), {}); await loadAll(); announce(`Mapping ${action} requested.`); } catch (error) { if (error.status === 409 || error.status === 412) { await loadAll(); announce('This mapping changed elsewhere; data was reloaded before retrying.', true); } else announce(error.message || `Unable to ${action} mapping.`, true); } }
  async function deleteMapping(mapping) { if (!window.confirm(`Delete mapping ${mapping.id}? This removes its redirect after drain.`)) return; try { await mutation('DELETE', `${API}/mappings/${encodeURIComponent(mapping.id)}`, mappingVersion(mapping)); await loadAll(); announce('Mapping delete requested.'); } catch (error) { if (error.status === 409 || error.status === 412) { await loadAll(); announce('This mapping changed elsewhere; data was reloaded before retrying.', true); } else announce(error.message || 'Unable to delete mapping.', true); } }
  async function checkProxy(proxy) { try { await request(`${CONTROL_PLANE_CHECK}${encodeURIComponent(proxy.id)}/check`, { method: 'POST' }); await loadAll(); announce('Proxy control-plane check completed. This is not proof that a mapping is applied or verified.'); } catch (error) { announce(error.message || 'Proxy control-plane check failed.', true); } }
  async function logout() { try { await request('/logout', { method: 'POST' }); } catch (_) { /* cookie clearance is authoritative */ } window.location.assign('/login'); }
  function bind() { byID('refresh')?.addEventListener('click', loadAll); byID('mapping-preview-button')?.addEventListener('click', validatePreview); byID('mapping-form')?.addEventListener('submit', createMapping); byID('audit-more')?.addEventListener('click', loadMoreAudit); byID('logout')?.addEventListener('click', logout); ['mapping-client-ip', 'mapping-proxy', 'mapping-policy', 'mapping-port'].forEach((id) => byID(id)?.addEventListener('input', () => { byID('mapping-preview').textContent = 'Preview updates when requested.'; })); }
  document.addEventListener('DOMContentLoaded', () => { bind(); loadAll(); });
})();
