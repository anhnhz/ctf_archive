const LOGO_SVG = `<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path d="M12 2L2 7v10l10 5 10-5V7L12 2zm0 2.18l6.83 3.41L12 10.91 5.17 7.59 12 4.18zM4 8.73l7 3.5v7.54l-7-3.5V8.73zm9 11.04v-7.54l7-3.5v7.54l-7 3.5z"/></svg>`;

const STATES = ['DRAFT','BUILD','SIGNED','REVIEW','DEPLOYED'];
const STATE_CLASS = {DRAFT:'badge-draft',BUILD:'badge-build',SIGNED:'badge-signed',REVIEW:'badge-review',DEPLOYED:'badge-deployed'};

let currentToken = localStorage.getItem('dh_token');
let currentWorkspace = JSON.parse(localStorage.getItem('dh_workspace') || 'null');
let currentView = 'dashboard';
let workspaceCache = [];
let pendingCredentials = null;

const $ = s => document.querySelector(s);
const $$ = s => document.querySelectorAll(s);

function parseJwtPayload(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    return JSON.parse(atob(parts[1].replace(/-/g,'+').replace(/_/g,'/')));
  } catch { return null; }
}

const WS_PREFIX_RE = /^[a-zA-Z0-9][a-zA-Z0-9_-]*$/;
function validateWsName(name) {
  if (!name) return null;
  if (name.length > 24) return 'Maximum 24 characters';
  if (!WS_PREFIX_RE.test(name)) return 'Only letters, numbers, hyphens, and underscores allowed';
  return null;
}

function checkWsName(el) {
  const err = validateWsName(el.value.trim());
  const errEl = $('#wsNameError');
  const btn = $('#registerBtn');
  if (err) {
    errEl.textContent = err; errEl.style.display = 'block'; el.style.borderColor = 'var(--red)';
    if (btn) btn.disabled = true;
  } else {
    errEl.style.display = 'none'; el.style.borderColor = '';
    if (btn) btn.disabled = false;
  }
}

async function api(path, opts = {}) {
  const headers = {'Content-Type':'application/json',...(opts.headers||{})};
  if (currentToken) headers['Authorization'] = `Bearer ${currentToken}`;
  const res = await fetch(path, {...opts, headers});
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw {status: res.status, ...data};
  return data;
}

async function apiRaw(path, body, contentType) {
  const headers = {'Content-Type': contentType};
  if (currentToken) headers['Authorization'] = `Bearer ${currentToken}`;
  const res = await fetch(path, {method:'POST', headers, body});
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw {status: res.status, ...data};
  return data;
}

function toast(msg, type = 'info') {
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.textContent = msg;
  $('#toasts').appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

function timeAgo(d) {
  if (!d) return '';
  const s = Math.floor((Date.now() - new Date(d)) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  return `${Math.floor(s/86400)}d ago`;
}

function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

function copyText(text) {
  navigator.clipboard.writeText(text).then(() => toast('Copied', 'success')).catch(() => {});
}

function toggleProfileMenu(e) {
  e.stopPropagation();
  const menu = $('#profileMenu');
  if (menu) menu.classList.toggle('open');
}
document.addEventListener('click', () => {
  const menu = $('#profileMenu');
  if (menu) menu.classList.remove('open');
});

/* ======================== TOPBAR ======================== */

function renderTopbar() {
  return `<div class="topbar">
    <div class="topbar-brand">${LOGO_SVG}<span>Dark Harbor</span></div>
    <nav class="topbar-nav">
      <a href="#" onclick="navigate('dashboard');return false" class="${currentView==='dashboard'?'active':''}">Workspaces</a>
      <a href="#" onclick="navigate('health');return false" class="${currentView==='health'?'active':''}">Health</a>
    </nav>
    <div class="topbar-right">
      <span class="topbar-env">pipeline v2</span>
      ${currentWorkspace ? `<div class="topbar-user" onclick="toggleProfileMenu(event)">
        <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0a8 8 0 110 16A8 8 0 018 0zM1.5 8a6.5 6.5 0 1013 0 6.5 6.5 0 00-13 0z"/></svg>
        ${esc(currentWorkspace.name)}
        <div class="profile-menu" id="profileMenu">
          <div class="profile-menu-header">Workspace #${currentWorkspace.id}</div>
          <div class="profile-menu-item" onclick="event.stopPropagation();copyText(currentToken||'')">Copy API Token</div>
          <div class="profile-menu-item" onclick="event.stopPropagation();navigate('workspace',${currentWorkspace.id})">Workspace Settings</div>
          <div class="profile-menu-divider"></div>
          <div class="profile-menu-item profile-menu-danger" onclick="event.stopPropagation();logout()">Sign Out</div>
        </div>
      </div>` : ''}
    </div>
  </div>`;
}

/* ======================== LOGIN ======================== */

function renderLogin() {
  const credCard = pendingCredentials ? `
    <div class="credential-card">
      <h3>Workspace Created — Save Your API Token</h3>
      <div class="credential-row"><label>Workspace</label><code>${esc(pendingCredentials.name)}</code></div>
      <div class="credential-row" style="margin-top:8px"><label>API Token</label></div>
      <div style="margin-top:4px"><textarea class="form-textarea" rows="3" readonly onclick="this.select()" style="font-size:.7rem">${esc(pendingCredentials.token)}</textarea></div>
      <button class="btn btn-sm" style="margin-top:8px" onclick="copyText('${esc(pendingCredentials.token)}')">Copy Token</button>
      <div style="margin-top:12px;font-size:.75rem;color:var(--text-muted)">Save this token to rejoin your workspace later.</div>
      <button class="btn btn-primary" style="width:100%;margin-top:12px;justify-content:center" onclick="enterDashboard()">Continue to Dashboard</button>
    </div>` : '';

  return `<div class="login-page">
    <div class="login-card">
      <div class="login-logo">${LOGO_SVG}<h1>Dark Harbor</h1><p>Pipeline Security Platform</p></div>
      <div class="login-tabs">
        <div class="login-tab active" onclick="switchLoginTab('register',this)">New Workspace</div>
        <div class="login-tab" onclick="switchLoginTab('rejoin',this)">Rejoin Workspace</div>
      </div>
      <div class="login-panel active" id="panel-register">
        <form id="registerForm">
          <div class="form-group">
            <label class="form-label">Workspace Prefix <span style="color:var(--text-muted)">(optional)</span></label>
            <input class="form-input" id="wsName" placeholder="my-project" autocomplete="off" maxlength="24" oninput="checkWsName(this)">
            <div id="wsNameError" style="color:var(--red);font-size:.75rem;margin-top:4px;display:none"></div>
            <div style="color:var(--text-muted);font-size:.75rem;margin-top:4px">A unique ID will be appended automatically</div>
          </div>
          <button type="submit" class="btn btn-primary" id="registerBtn" style="width:100%;justify-content:center;padding:10px">Initialize Workspace</button>
        </form>
      </div>
      <div class="login-panel" id="panel-rejoin">
        <form id="rejoinForm">
          <div class="form-group">
            <label class="form-label">API Token</label>
            <textarea class="form-textarea" id="rejoinToken" rows="3" placeholder="eyJhbGciOiJIUzI1NiIs..." required></textarea>
            <div style="color:var(--text-muted);font-size:.75rem;margin-top:4px">Paste the API token from your workspace registration</div>
          </div>
          <button type="submit" class="btn btn-primary" style="width:100%;justify-content:center;padding:10px">Rejoin Workspace</button>
        </form>
      </div>
      ${credCard}
    </div>
  </div>`;
}

function switchLoginTab(name, el) {
  $$('.login-tab').forEach(t => t.classList.remove('active'));
  $$('.login-panel').forEach(p => p.classList.remove('active'));
  el.classList.add('active');
  $(`#panel-${name}`).classList.add('active');
}

function enterDashboard() {
  if (pendingCredentials) {
    currentToken = pendingCredentials.token;
    currentWorkspace = pendingCredentials.workspace;
    localStorage.setItem('dh_token', pendingCredentials.token);
    localStorage.setItem('dh_workspace', JSON.stringify(pendingCredentials.workspace));
    pendingCredentials = null;
  }
  navigate('dashboard');
}

/* ======================== PIPELINE BAR ======================== */

function renderPipelineBar(state) {
  const idx = STATES.indexOf(state);
  let html = '<div class="pipeline-bar">';
  STATES.forEach((s, i) => {
    if (i > 0) html += `<div class="pipeline-connector${i <= idx ? ' done' : ''}"></div>`;
    const cls = i < idx ? 'done' : i === idx ? 'active' : '';
    html += `<div class="pipeline-step ${cls}">
      <div class="pipeline-step-dot">${i < idx ? '&#10003;' : i + 1}</div>
      <div class="pipeline-step-label">${s}</div>
    </div>`;
  });
  html += '</div>';
  return html;
}

/* ======================== DASHBOARD ======================== */

function renderDashboard() {
  return `${renderTopbar()}
  <div class="container">
    <div class="page-header">
      <div><h1 class="page-title">Workspaces</h1><p class="page-subtitle">Manage your pipeline workspaces</p></div>
      <button class="btn btn-primary" onclick="showCreateModal()">
        <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M7.75 2a.75.75 0 01.75.75V7h4.25a.75.75 0 010 1.5H8.5v4.25a.75.75 0 01-1.5 0V8.5H2.75a.75.75 0 010-1.5H7V2.75A.75.75 0 017.75 2z"/></svg>
        New Workspace
      </button>
    </div>
    <div class="stats-grid" id="statsGrid">
      <div class="stat-card"><div class="stat-value" id="statTotal">-</div><div class="stat-label">Total Workspaces</div></div>
      <div class="stat-card"><div class="stat-value" id="statDraft">-</div><div class="stat-label">In Draft</div></div>
      <div class="stat-card"><div class="stat-value" id="statActive">-</div><div class="stat-label">Active Pipelines</div></div>
      <div class="stat-card"><div class="stat-value" id="statReview">-</div><div class="stat-label">Pending Review</div></div>
    </div>
    <div class="card">
      <div class="card-header"><h3>All Workspaces</h3></div>
      <div id="wsList"><div class="loading-overlay"><div class="spinner"></div>Loading workspaces...</div></div>
    </div>
  </div>`;
}

function renderWorkspaceList(workspaces) {
  if (!workspaces.length) return `<div class="empty-state">
    <svg viewBox="0 0 24 24" fill="currentColor"><path d="M3 3h18v18H3V3zm2 2v14h14V5H5zm4 3h6v2H9V8zm0 4h6v2H9v-2z"/></svg>
    <h3>No workspaces yet</h3><p>Create your first workspace to start a pipeline</p></div>`;
  return workspaces.map(ws => `<div class="ws-row" onclick="navigate('workspace',${ws.id})">
    <div class="dot ${ws.pipeline_state==='DRAFT'?'dot-gray':ws.pipeline_state==='REVIEW'?'dot-yellow dot-pulse':'dot-blue dot-pulse'}"></div>
    <div class="ws-info">
      <div class="ws-name">${esc(ws.name)}</div>
      <div class="ws-meta">ID: ${ws.id} &middot; ${timeAgo(ws.created_at)}</div>
    </div>
    <span class="badge ${STATE_CLASS[ws.pipeline_state]||'badge-draft'}">${ws.pipeline_state}</span>
  </div>`).join('');
}

/* ======================== WORKSPACE DETAIL ======================== */

function renderWorkspaceDetail(ws, pipelineData) {
  const transitions = (pipelineData && pipelineData.transitions) || [];
  return `${renderTopbar()}
  <div class="container">
    <div class="page-header">
      <div>
        <div style="display:flex;align-items:center;gap:12px">
          <a href="#" onclick="navigate('dashboard');return false" style="color:var(--text-secondary);font-size:1.5rem;line-height:1;padding:4px 8px">&larr;</a>
          <h1 class="page-title">${esc(ws.name)}</h1>
          <span class="badge ${STATE_CLASS[ws.pipeline_state]||'badge-draft'}">${ws.pipeline_state}</span>
        </div>
        <p class="page-subtitle">Workspace #${ws.id}</p>
      </div>
      <button class="btn btn-danger btn-sm" onclick="resetPipeline(${ws.id})">Reset Pipeline</button>
    </div>
    ${renderPipelineBar(ws.pipeline_state)}
    <div class="tabs">
      <div class="tab active" onclick="switchTab('overview',this)">Overview</div>
      <div class="tab" onclick="switchTab('transitions',this)">Transitions</div>
      <div class="tab" onclick="switchTab('builds',this)">Build Reports</div>
      <div class="tab" onclick="switchTab('webhooks',this)">Webhooks</div>
      <div class="tab" onclick="switchTab('deploy',this)">Deploy</div>
      <div class="tab" onclick="switchTab('config',this)">Configuration</div>
    </div>

    <!-- Overview -->
    <div class="tab-content active" id="tab-overview">
      <div class="detail-grid">
        <div class="card"><div class="card-header"><h3>Pipeline Info</h3></div><div class="card-body">
          <div class="kv-row"><span class="kv-key">State</span><span class="kv-val">${ws.pipeline_state}</span></div>
          <div class="kv-row"><span class="kv-key">Manifest Hash</span><span class="kv-val">${ws.manifest_hash || 'Not set'}</span></div>
          <div class="kv-row"><span class="kv-key">Webhook URL</span><span class="kv-val">${ws.webhook_url || 'Not configured'}</span></div>
          <div class="kv-row"><span class="kv-key">Created</span><span class="kv-val">${ws.created_at ? new Date(ws.created_at).toLocaleString() : '-'}</span></div>
        </div></div>
        <div class="card"><div class="card-header"><h3>Pipeline Actions</h3></div><div class="card-body">
          <div style="margin-bottom:12px">
            <div class="form-group" style="margin-bottom:8px">
              <label class="form-label">Manifest Reference</label>
              <input class="form-input" id="manifestRef" placeholder="sha256:abc123..." value="${ws.manifest_hash||''}">
            </div>
            <button class="btn" onclick="advancePipeline(${ws.id},'build')" ${ws.pipeline_state!=='DRAFT'?'disabled':''}>Start Build</button>
          </div>
          <div style="margin-bottom:12px">
            <div class="form-group" style="margin-bottom:4px">
              <label class="form-label">Digest Algorithm</label>
              <select class="form-select" id="digestAlgo"><option value="sha256">sha256</option><option value="blake3">blake3</option></select>
            </div>
            <div class="form-group" style="margin-bottom:8px">
              <label class="form-label">Signing Nonce</label>
              <input class="form-input" id="signingNonce" placeholder="manifest hash from build step">
            </div>
            <button class="btn" onclick="advancePipeline(${ws.id},'sign')" ${ws.pipeline_state!=='BUILD'?'disabled':''}>Sign Artifacts</button>
          </div>
          <div>
            <button class="btn" onclick="advancePipeline(${ws.id},'review')" ${ws.pipeline_state!=='SIGNED'?'disabled':''}>Submit for Review</button>
            ${ws.pipeline_state==='SIGNED' && !ws.webhook_url ? '<div style="color:var(--yellow);font-size:.75rem;margin-top:4px">Webhook URL must be configured first</div>' : ''}
          </div>
        </div></div>
      </div>
    </div>

    <!-- Transitions -->
    <div class="tab-content" id="tab-transitions">
      <div class="card"><div class="card-body">
        ${transitions.length ? `<div class="timeline">${transitions.map(t => {
          const cls = t.to_state === 'DRAFT' ? 'warning' : t.to_state === 'REVIEW' ? 'info' : 'success';
          return `<div class="timeline-item ${cls}"><div class="timeline-dot"></div>
            <div class="timeline-title">${t.from_state} &rarr; ${t.to_state}</div>
            <div class="timeline-meta">${timeAgo(t.created_at)}</div></div>`;
        }).join('')}</div>` : '<div class="empty-state"><h3>No transitions yet</h3><p>Start the pipeline to see transition history</p></div>'}
      </div></div>
    </div>

    <!-- Build Reports -->
    <div class="tab-content" id="tab-builds">
      <div class="card" style="margin-bottom:16px"><div class="card-header"><h3>Upload Test Report</h3></div><div class="card-body">
        <div class="form-group">
          <label class="form-label">JUnit XML</label>
          <textarea class="form-textarea" id="xmlInput" rows="6" placeholder='<?xml version="1.0"?>
<testsuites>
  <testsuite name="integration" tests="2">
    <testcase name="auth-flow"/>
    <testcase name="deploy-check">
      <failure message="timeout"/>
    </testcase>
  </testsuite>
</testsuites>'></textarea>
        </div>
        <button class="btn btn-primary" onclick="uploadTestReport(${ws.id})">Upload Report</button>
      </div></div>
      <div class="card"><div class="card-header"><h3>Reports</h3></div>
        <div id="buildReports"><div class="loading-overlay"><div class="spinner"></div>Loading...</div></div>
      </div>
    </div>

    <!-- Webhooks -->
    <div class="tab-content" id="tab-webhooks">
      <div class="card" style="margin-bottom:16px"><div class="card-header"><h3>Webhook Configuration</h3></div><div class="card-body">
        <div class="kv-row"><span class="kv-key">Current URL</span><span class="kv-val" id="webhookUrl">${ws.webhook_url || 'Not configured'}</span></div>
        <div class="form-group" style="margin-top:16px">
          <label class="form-label">Webhook Endpoint URL</label>
          <input class="form-input" id="webhookInput" placeholder="https://your-server.com/webhook">
        </div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-primary" onclick="saveWebhook(${ws.id})">Save</button>
          <button class="btn" onclick="testWebhook(${ws.id})">Test Webhook</button>
        </div>
      </div></div>
      <div class="card"><div class="card-header"><h3>Test Result</h3></div><div class="card-body">
        <div id="webhookResult" class="result-panel" style="min-height:40px">No test performed yet</div>
      </div></div>
    </div>

    <!-- Deploy -->
    <div class="tab-content" id="tab-deploy">
      <div class="card" style="margin-bottom:16px"><div class="card-header"><h3>Deploy Token</h3></div><div class="card-body">
        <p style="font-size:.8125rem;color:var(--text-secondary);margin-bottom:12px">Generate a short-lived deploy token. Workspace must be in REVIEW state.</p>
        <button class="btn btn-primary" onclick="generateDeployToken(${ws.id})">Generate Token</button>
        <div id="tokenDisplay" style="margin-top:12px"></div>
      </div></div>
      <div class="card" style="margin-bottom:16px"><div class="card-header"><h3>Use Deploy Token</h3></div><div class="card-body">
        <div class="form-group">
          <label class="form-label">Token</label>
          <input class="form-input" id="deployTokenInput" placeholder="paste deploy token here">
        </div>
        <div class="form-group">
          <label class="form-label">Action</label>
          <select class="form-select" id="deployAction">
            <option value="seal">Seal</option>
            <option value="sign">Sign</option>
          </select>
        </div>
        <button class="btn btn-primary" onclick="useDeployToken(${ws.id})">Execute</button>
        <div id="deployResult" style="margin-top:12px"></div>
      </div></div>
      <div class="card"><div class="card-header"><h3>Override Result</h3></div><div class="card-body">
        <button class="btn" onclick="checkOverride(${ws.id})">Check Override Result</button>
        <div id="overrideResult" style="margin-top:12px"></div>
      </div></div>
    </div>

    <!-- Configuration -->
    <div class="tab-content" id="tab-config">
      <div class="card"><div class="card-header"><h3>Edge Proxy Routing</h3></div><div class="card-body">
        <div class="code-block">routes:
  /api/*             → api-server:3000
  /build/*           → build-runner:9000
  /health/*          → policy-engine:5000

tls_termination: edge
forwarded_proto: https
server: dark-harbor-edge</div>
      </div></div>
      <div class="card" style="margin-top:16px"><div class="card-header"><h3>Network Topology</h3></div><div class="card-body">
        <div class="code-block">Services:
  haproxy        Load balancer (entry point)
  edge-proxy     Request filtering and routing
  api-server     Core API
  build-runner   Build artifact processing
  policy-engine  Policy enforcement and signing

Storage:
  PostgreSQL     Workspace and pipeline state
  Redis          Session cache and tokens</div>
      </div></div>
    </div>
  </div>`;
}

/* ======================== HEALTH ======================== */

function renderHealthPage() {
  return `${renderTopbar()}
  <div class="container">
    <div class="page-header"><div><h1 class="page-title">System Health</h1><p class="page-subtitle">Service status and connectivity</p></div></div>
    <div class="card"><div class="card-body" id="healthContent"><div class="loading-overlay"><div class="spinner"></div>Checking services...</div></div></div>
  </div>`;
}

/* ======================== TAB / NAVIGATION ======================== */

function switchTab(name, el) {
  $$('.tab').forEach(t => t.classList.remove('active'));
  $$('.tab-content').forEach(t => t.classList.remove('active'));
  el.classList.add('active');
  const panel = $(`#tab-${name}`);
  if (panel) panel.classList.add('active');
  if (name === 'builds') loadBuildReports();
  if (name === 'webhooks') loadWebhookConfig();
}

function navigate(view, param) {
  currentView = view;
  if (view === 'dashboard') {
    if (!currentToken && !currentWorkspace) { render(); return; }
    render(); loadWorkspaces();
  } else if (view === 'workspace') {
    window._currentWsId = param;
    loadWorkspaceDetail(param);
  } else if (view === 'health') {
    render(); checkHealth();
  }
}

/* ======================== DATA LOADING ======================== */

let currentPage = 1;

async function loadWorkspaces(page) {
  currentPage = page || 1;
  try {
    const data = await api(`/api/workspaces?page=${currentPage}&limit=20`);
    workspaceCache = data.workspaces || [];
    let html = renderWorkspaceList(workspaceCache);
    if (data.total_pages > 1) {
      html += `<div style="display:flex;justify-content:center;align-items:center;gap:12px;padding:16px">
        <button class="btn btn-sm" onclick="loadWorkspaces(${currentPage - 1})" ${currentPage <= 1 ? 'disabled' : ''}>&larr; Prev</button>
        <span style="font-size:.8125rem;color:var(--text-secondary)">Page ${data.page} of ${data.total_pages}</span>
        <button class="btn btn-sm" onclick="loadWorkspaces(${currentPage + 1})" ${currentPage >= data.total_pages ? 'disabled' : ''}>Next &rarr;</button>
      </div>`;
    }
    $('#wsList').innerHTML = html;
    $('#statTotal').textContent = data.total || 0;
    $('#statDraft').textContent = workspaceCache.filter(w => w.pipeline_state === 'DRAFT').length;
    $('#statActive').textContent = workspaceCache.filter(w => ['BUILD','SIGNED'].includes(w.pipeline_state)).length;
    $('#statReview').textContent = workspaceCache.filter(w => w.pipeline_state === 'REVIEW').length;
  } catch (e) {
    $('#wsList').innerHTML = renderWorkspaceList([]);
    ['statTotal','statDraft','statActive','statReview'].forEach(id => $(`#${id}`).textContent = '0');
  }
}

async function loadWorkspaceDetail(wsId) {
  try {
    const [wsData, pipeData] = await Promise.allSettled([
      api(`/api/workspaces/${wsId}`), api(`/api/pipeline/${wsId}/status`)
    ]);
    const ws = wsData.status === 'fulfilled' ? wsData.value.workspace : (workspaceCache.find(w => w.id == wsId) || {id:wsId,name:'Workspace',pipeline_state:'DRAFT'});
    const pipeline = pipeData.status === 'fulfilled' ? pipeData.value : {};
    if (pipeline.pipeline_state) ws.pipeline_state = pipeline.pipeline_state;
    if (pipeline.manifest_hash) ws.manifest_hash = pipeline.manifest_hash;
    if (pipeline.webhook_url) ws.webhook_url = pipeline.webhook_url;
    $('#app').innerHTML = renderWorkspaceDetail(ws, pipeline);
  } catch {
    const ws = workspaceCache.find(w => w.id == wsId) || {id:wsId,name:'Workspace',pipeline_state:'DRAFT'};
    $('#app').innerHTML = renderWorkspaceDetail(ws, {});
  }
}

async function loadBuildReports() {
  const wsId = window._currentWsId;
  if (!wsId) return;
  try {
    const data = await api(`/api/builds/${wsId}/reports`);
    const reports = data.reports || [];
    if (!reports.length) {
      $('#buildReports').innerHTML = '<div class="card-body"><div class="empty-state"><h3>No reports yet</h3><p>Upload a JUnit XML test report above</p></div></div>';
      return;
    }
    $('#buildReports').innerHTML = `<div class="card-body"><table><thead><tr><th>Report ID</th><th>Total</th><th>Passed</th><th>Failed</th><th>Time</th><th></th></tr></thead><tbody>${reports.map(r =>
      `<tr id="row-${esc(r.id)}"><td><code style="font-size:.75rem">${esc(r.id).substring(0,8)}...</code></td>
       <td>${r.total||'-'}</td><td style="color:var(--green)">${r.passed||'-'}</td><td style="color:var(--red)">${r.failed||'-'}</td>
       <td>${timeAgo(r.parsed_at)}</td>
       <td><button class="btn btn-sm" onclick="viewReport('${wsId}','${esc(r.id)}',this)">View</button></td></tr>`
    ).join('')}</tbody></table></div>`;
  } catch {
    $('#buildReports').innerHTML = '<div class="card-body"><div class="empty-state"><h3>Unable to load reports</h3><p>Authentication may be required</p></div></div>';
  }
}

async function loadWebhookConfig() {
  const wsId = window._currentWsId;
  if (!wsId) return;
  try {
    const data = await api(`/api/webhooks/${wsId}`);
    const el = $('#webhookUrl');
    if (el) el.textContent = data.webhook_url || 'Not configured';
  } catch { /* 401 expected with local token */ }
}

async function checkHealth() {
  const services = [
    {name:'API Server', path:'/api/health'},
    {name:'Build Runner', path:'/build/health'},
    {name:'Policy Engine', path:'/health/policy-engine'}
  ];
  let html = '<table><thead><tr><th>Service</th><th>Status</th><th>Details</th></tr></thead><tbody>';
  for (const svc of services) {
    try {
      const data = await api(svc.path);
      html += `<tr><td><span class="dot dot-green"></span> ${svc.name}</td><td><span class="badge badge-deployed">Healthy</span></td><td><code>${JSON.stringify(data).substring(0,80)}</code></td></tr>`;
    } catch (e) {
      html += `<tr><td><span class="dot dot-red"></span> ${svc.name}</td><td><span class="badge badge-failed">Error</span></td><td>${esc(e.error || 'unreachable')}</td></tr>`;
    }
  }
  html += '</tbody></table>';
  $('#healthContent').innerHTML = html;
}

/* ======================== ACTIONS ======================== */

async function advancePipeline(wsId, action) {
  try {
    let body = {};
    if (action === 'build') {
      const ref = ($('#manifestRef') || {}).value || '';
      body = {manifest_ref: ref || undefined, build_config: {}};
    } else if (action === 'sign') {
      const algo = ($('#digestAlgo') || {}).value || 'sha256';
      const nonce = ($('#signingNonce') || {}).value || '';
      body = {digest_algorithm: algo, signing_nonce: nonce || undefined};
    }
    const res = await api(`/api/pipeline/${wsId}/${action}`, {method:'POST', body: JSON.stringify(body)});
    if (res.pipeline_state === 'QUARANTINED') {
      toast('Transition rejected — state set to QUARANTINED', 'error');
    } else {
      toast(`Pipeline transitioned to ${res.pipeline_state}`, 'success');
    }
    navigate('workspace', wsId);
  } catch (e) { toast(e.error || `Failed: ${action}`, 'error'); }
}

async function resetPipeline(wsId) {
  try {
    await api(`/api/pipeline/${wsId}/reset`, {method:'POST', body:'{}'});
    toast('Pipeline reset to DRAFT', 'success');
    navigate('workspace', wsId);
  } catch (e) { toast(e.error || 'Reset failed', 'error'); }
}

function showCreateModal() {
  const prefix = prompt('Workspace name prefix (optional):');
  if (prefix === null) return;
  createWorkspace(prefix.trim());
}

async function createWorkspace(prefix) {
  try {
    await api('/api/workspaces', {method:'POST', body: JSON.stringify({name: prefix || undefined})});
    toast('Workspace created', 'success');
    loadWorkspaces();
  } catch (e) { toast(e.error || 'Failed to create workspace', 'error'); }
}

/* Build Reports */
async function uploadTestReport(wsId) {
  const xml = $('#xmlInput').value.trim();
  if (!xml) { toast('Paste JUnit XML first', 'error'); return; }
  try {
    const data = await apiRaw(`/api/builds/${wsId}/test-report`, xml, 'application/xml');
    toast(`Report uploaded: ${data.summary.passed} passed, ${data.summary.failed} failed`, 'success');
    $('#xmlInput').value = '';
    loadBuildReports();
  } catch (e) { toast(e.error || 'Upload failed', 'error'); }
}

async function viewReport(wsId, reportId, btn) {
  const row = $(`#row-${reportId}`);
  if (!row) return;
  const existing = row.nextElementSibling;
  if (existing && existing.classList.contains('report-detail-row')) { existing.remove(); return; }
  try {
    const data = await api(`/api/builds/${wsId}/reports/${reportId}`);
    const cases = (data.results && data.results.cases) || [];
    const tr = document.createElement('tr');
    tr.className = 'report-detail-row';
    tr.innerHTML = `<td colspan="6"><div class="report-detail">${cases.map(c =>
      `<div class="report-case">
        <span class="dot ${c.status==='passed'?'dot-green':c.status==='failed'?'dot-red':'dot-yellow'}"></span>
        <span style="flex:1">${esc(c.suite)} / ${esc(c.name)}</span>
        <span class="badge ${c.status==='passed'?'badge-deployed':'badge-failed'}">${c.status}</span>
      </div>${c.output ? `<div class="code-block" style="margin:4px 0 8px 20px;font-size:.75rem">${esc(c.output)}</div>` : ''}`
    ).join('') || '<div style="color:var(--text-muted)">No test cases</div>'}</div></td>`;
    row.after(tr);
  } catch (e) { toast(e.error || 'Failed to load report', 'error'); }
}

/* Webhooks */
async function saveWebhook(wsId) {
  const url = $('#webhookInput').value.trim();
  if (!url) { toast('Enter a webhook URL', 'error'); return; }
  try {
    await api(`/api/webhooks/${wsId}`, {method:'POST', body: JSON.stringify({url})});
    toast('Webhook saved', 'success');
    const el = $('#webhookUrl');
    if (el) el.textContent = url;
  } catch (e) { toast(e.error || 'Failed to save webhook', 'error'); }
}

async function testWebhook(wsId) {
  const el = $('#webhookResult');
  if (el) el.textContent = 'Sending test event...';
  try {
    const data = await api(`/api/webhooks/${wsId}/test`, {method:'POST', body:'{}'});
    if (el) { el.textContent = JSON.stringify(data, null, 2); el.className = 'result-panel success'; }
    toast('Webhook test sent', 'success');
  } catch (e) {
    if (el) { el.textContent = JSON.stringify(e, null, 2); el.className = 'result-panel error'; }
    toast(e.error || 'Webhook test failed', 'error');
  }
}

/* Deploy */
async function generateDeployToken(wsId) {
  try {
    const data = await api(`/api/deploy/${wsId}/token`, {method:'POST', body:'{}'});
    const el = $('#tokenDisplay');
    if (el) {
      el.innerHTML = `<div class="result-panel success"><strong>Token:</strong> ${esc(data.token)}<br><strong>TTL:</strong> ${data.ttl_ms}ms<br><span style="color:var(--yellow)">Token expires in 3 seconds</span></div>`;
      const inp = $('#deployTokenInput');
      if (inp) inp.value = data.token;
    }
    toast('Deploy token generated', 'success');
  } catch (e) { toast(e.error || 'Failed to generate token', 'error'); }
}

async function useDeployToken(wsId) {
  const token = $('#deployTokenInput').value.trim();
  const action = $('#deployAction').value;
  if (!token) { toast('Enter a deploy token', 'error'); return; }
  try {
    const data = await api(`/api/deploy/${wsId}/use-token`, {method:'POST', body: JSON.stringify({token, action})});
    const el = $('#deployResult');
    if (el) { el.innerHTML = `<div class="result-panel success">${esc(JSON.stringify(data, null, 2))}</div>`; }
    toast(`Token used: ${action}`, 'success');
  } catch (e) { toast(e.error || 'Token use failed', 'error'); }
}

async function checkOverride(wsId) {
  try {
    const data = await api(`/api/deploy/${wsId}/override-result`);
    const el = $('#overrideResult');
    if (el) { el.innerHTML = `<div class="result-panel success">${esc(JSON.stringify(data, null, 2))}</div>`; }
  } catch (e) {
    const el = $('#overrideResult');
    if (el) { el.innerHTML = `<div class="result-panel error">${esc(e.error || 'No override result')}</div>`; }
  }
}

/* ======================== AUTH ======================== */

function logout() {
  currentToken = null;
  currentWorkspace = null;
  pendingCredentials = null;
  localStorage.removeItem('dh_token');
  localStorage.removeItem('dh_workspace');
  navigate('dashboard');
}

/* ======================== RENDER ======================== */

function render() {
  if (!currentToken && !currentWorkspace) {
    $('#app').innerHTML = renderLogin();
    const regForm = $('#registerForm');
    if (regForm) regForm.addEventListener('submit', async e => {
      e.preventDefault();
      const name = $('#wsName').value.trim();
      const vErr = validateWsName(name);
      if (vErr) { toast(vErr, 'error'); return; }
      try {
        const data = await api('/api/auth/register', {method:'POST', body: JSON.stringify({workspace_name: name || undefined})});
        pendingCredentials = { name: data.workspace.name, token: data.token, workspace: data.workspace };
        render();
      } catch (e) { toast(e.error || 'Registration failed', 'error'); }
    });
    const rejoinForm = $('#rejoinForm');
    if (rejoinForm) rejoinForm.addEventListener('submit', e => {
      e.preventDefault();
      const token = $('#rejoinToken').value.trim();
      if (!token) { toast('Paste your API token', 'error'); return; }
      const payload = parseJwtPayload(token);
      if (!payload || !payload.workspace) { toast('Invalid token format', 'error'); return; }
      currentToken = token;
      currentWorkspace = { name: payload.workspace, pipeline_state: 'DRAFT' };
      localStorage.setItem('dh_token', token);
      localStorage.setItem('dh_workspace', JSON.stringify(currentWorkspace));
      toast(`Rejoined workspace "${payload.workspace}"`, 'success');
      navigate('dashboard');
    });
  } else if (currentView === 'health') {
    $('#app').innerHTML = renderHealthPage();
  } else {
    $('#app').innerHTML = renderDashboard();
  }
}

render();
if (currentToken || currentWorkspace) navigate('dashboard');
