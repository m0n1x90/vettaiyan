/* ─── Vettaiyan EDR Dashboard SPA ──────────────────── */

const API = '';
let currentPage = 'dashboard';

// ─── Navigation ──────────────────────────────────────

document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
        document.querySelector('.nav-item.active')?.classList.remove('active');
        item.classList.add('active');
        navigateTo(item.dataset.page);
    });
});

function navigateTo(page) {
    currentPage = page;
    const content = document.getElementById('content');
    content.innerHTML = '<div class="loading"><div class="spinner"></div><p>Loading...</p></div>';

    const routes = {
        dashboard: renderDashboard,
        threats: renderThreats,
        timeline: renderTimeline,
        detections: renderDetections,
        response: renderResponse,
        scan: renderScan,
        settings: renderSettings
    };

    (routes[page] || renderDashboard)();
}

// ─── Fetch helper ────────────────────────────────────

async function api(path) {
    const res = await fetch(API + path);
    return res.json();
}

async function apiPost(path, body) {
    const res = await fetch(API + path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body
    });
    return res.json();
}

// ─── Dashboard ───────────────────────────────────────

async function renderDashboard() {
    const data = await api('/api/dashboard');
    const stats = await api('/api/scan/stats');

    document.getElementById('content').innerHTML = `
        <div class="page-header">
            <h1>⌂ Dashboard</h1>
            <p>Overview of endpoint status and real-time metrics</p>
        </div>
        <div class="stats-grid">
            <div class="stat-card danger">
                <div class="stat-value">${data.threatCount}</div>
                <div class="stat-label">Threats Detected</div>
            </div>
            <div class="stat-card warning">
                <div class="stat-value">${data.detectionCount}</div>
                <div class="stat-label">Behavior Detections</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${data.eventCount}</div>
                <div class="stat-label">Telemetry Events</div>
            </div>
            <div class="stat-card success">
                <div class="stat-value">${stats.filesScanned || '0'}</div>
                <div class="stat-label">Files Scanned</div>
            </div>
        </div>
        <div class="card">
            <h2>Endpoint Metadata</h2>
            <div class="meta-grid">
                <div class="meta-item"><span class="meta-label">Hostname</span><span class="meta-value">${esc(data.hostname)}</span></div>
                <div class="meta-item"><span class="meta-label">User</span><span class="meta-value">${esc(data.user)}</span></div>
                <div class="meta-item"><span class="meta-label">Agent Status</span><span class="meta-value success">Running</span></div>
                <div class="meta-item"><span class="meta-label">Last Scan</span><span class="meta-value">${esc(data.lastScanTime)}</span></div>
                <div class="meta-item"><span class="meta-label">Scan Type</span><span class="meta-value">${esc(data.lastScanType)}</span></div>
            </div>
        </div>
        <div class="card" id="recent-threats-card">
            <h2>Recent Threats</h2>
            <div id="recent-threats"></div>
        </div>`;

    const threats = await api('/api/threats?page=1&size=5');
    const el = document.getElementById('recent-threats');
    if (threats.items.length === 0) {
        el.innerHTML = '<div class="empty-state"><div class="icon">🛡️</div><p>No threats detected</p></div>';
    } else {
        el.innerHTML = `<table class="data-table"><thead><tr>
            <th>Rule</th><th>File</th><th>Time</th><th>Action</th>
        </tr></thead><tbody>${threats.items.map(t => `<tr>
            <td>${esc(t.ruleName)}</td><td title="${esc(t.filePath)}">${esc(t.fileName)}</td>
            <td>${esc(t.timestamp)}</td><td>${esc(t.actionTaken)}</td>
        </tr>`).join('')}</tbody></table>`;
    }
}

// ─── Threats ─────────────────────────────────────────

let threatPage = 1;
async function renderThreats(page = 1) {
    threatPage = page;
    const data = await api(`/api/threats?page=${page}&size=10`);
    const totalPages = Math.max(1, Math.ceil(data.total / 10));

    document.getElementById('content').innerHTML = `
        <div class="page-header">
            <h1>⚠ Threats</h1>
            <p>YARA scan results — ${data.total} total threats detected</p>
        </div>
        <div class="card">
            ${data.items.length === 0 ? '<div class="empty-state"><div class="icon">✓</div><p>No threats found</p></div>' : `
            <table class="data-table"><thead><tr>
                <th>ID</th><th>Rule</th><th>File</th><th>Hash</th><th>Type</th><th>Time</th><th>Action</th>
            </tr></thead><tbody>${data.items.map(t => `<tr>
                <td>${t.id}</td>
                <td><strong>${esc(t.ruleName)}</strong></td>
                <td title="${esc(t.filePath)}">${esc(t.fileName)}</td>
                <td title="${esc(t.fileHash)}">${esc(t.fileHash.substring(0, 12))}...</td>
                <td>${esc(t.fileType)}</td>
                <td>${esc(t.timestamp)}</td>
                <td>${esc(t.actionTaken)}</td>
            </tr>`).join('')}</tbody></table>`}
            <div class="pagination">
                <span>Page ${page} of ${totalPages}</span>
                <div>
                    <button class="btn" ${page <= 1 ? 'disabled' : ''} onclick="renderThreats(${page - 1})">← Prev</button>
                    <button class="btn" ${page >= totalPages ? 'disabled' : ''} onclick="renderThreats(${page + 1})">Next →</button>
                </div>
            </div>
        </div>`;
}

// ─── Timeline ────────────────────────────────────────

let timelinePage = 1;
let timelineType = 'all';
async function renderTimeline(page = 1) {
    timelinePage = page;
    const data = await api(`/api/events?page=${page}&size=50&type=${timelineType}`);
    const totalPages = Math.max(1, Math.ceil(data.total / 50));

    document.getElementById('content').innerHTML = `
        <div class="page-header">
            <h1>☰ Timeline</h1>
            <p>Real-time telemetry events — ${data.total} total</p>
        </div>
        <div class="card">
            <div class="toolbar">
                <select onchange="timelineType=this.value; renderTimeline(1)">
                    <option value="all" ${timelineType === 'all' ? 'selected' : ''}>All Events</option>
                    <option value="ProcessCreate" ${timelineType === 'ProcessCreate' ? 'selected' : ''}>Process Create</option>
                    <option value="ProcessTerminate" ${timelineType === 'ProcessTerminate' ? 'selected' : ''}>Process Terminate</option>
                    <option value="ImageLoad" ${timelineType === 'ImageLoad' ? 'selected' : ''}>Image Load</option>
                    <option value="ThreadCreate" ${timelineType === 'ThreadCreate' ? 'selected' : ''}>Thread Create</option>
                    <option value="Registry" ${timelineType === 'Registry' ? 'selected' : ''}>Registry</option>
                    <option value="File" ${timelineType === 'File' ? 'selected' : ''}>File I/O</option>
                    <option value="Handle" ${timelineType === 'Handle' ? 'selected' : ''}>Handle</option>
                </select>
                <button class="btn" onclick="renderTimeline(timelinePage)">↻ Refresh</button>
                <span style="color:var(--text-dim);font-size:12px">${data.total.toLocaleString()} events</span>
            </div>
            ${data.items.length === 0 ? '<div class="empty-state"><p>No events found</p></div>' : `
            <div style="max-height:60vh;overflow-y:auto">
            <table class="data-table"><thead><tr>
                <th>ID</th><th>Type</th><th>PID</th><th>TID</th><th>Timestamp</th><th>Detail</th>
            </tr></thead><tbody>${data.items.map(e => `<tr>
                <td>${e.id}</td>
                <td><span class="badge badge-info">${esc(e.eventType)}</span></td>
                <td>${e.processId}</td>
                <td>${e.threadId}</td>
                <td>${esc(e.timestamp)}</td>
                <td title="${esc(e.detail)}">${esc(truncate(e.detail, 80))}</td>
            </tr>`).join('')}</tbody></table>
            </div>`}
            <div class="pagination">
                <span>Page ${page} of ${totalPages}</span>
                <div>
                    <button class="btn" ${page <= 1 ? 'disabled' : ''} onclick="renderTimeline(${page - 1})">← Prev</button>
                    <button class="btn" ${page >= totalPages ? 'disabled' : ''} onclick="renderTimeline(${page + 1})">Next →</button>
                </div>
            </div>
        </div>`;
}

// ─── Detections ──────────────────────────────────────

let detectionPage = 1;
async function renderDetections(page = 1) {
    detectionPage = page;
    const data = await api(`/api/detections?page=${page}&size=20`);
    const totalPages = Math.max(1, Math.ceil(data.total / 20));

    const sevBadge = s => {
        const m = { 4: 'critical', 3: 'high', 2: 'medium', 1: 'low', 0: 'info' };
        const n = { 4: 'Critical', 3: 'High', 2: 'Medium', 1: 'Low', 0: 'Info' };
        return `<span class="badge badge-${m[s] || 'info'}">${n[s] || 'Unknown'}</span>`;
    };

    document.getElementById('content').innerHTML = `
        <div class="page-header">
            <h1>◉ Behavior Detections</h1>
            <p>MITRE ATT&CK mapped behavioral alerts — ${data.total} total</p>
        </div>
        <div class="card">
            <div class="toolbar">
                <button class="btn" onclick="renderDetections(detectionPage)">↻ Refresh</button>
            </div>
            ${data.items.length === 0 ? '<div class="empty-state"><div class="icon">✓</div><p>No behavioral detections</p></div>' : `
            <div style="max-height:60vh;overflow-y:auto">
            <table class="data-table"><thead><tr>
                <th>Severity</th><th>Rule</th><th>Description</th><th>Tactic</th><th>Technique</th><th>PID</th><th>Image</th><th>Time</th>
            </tr></thead><tbody>${data.items.map(d => `<tr>
                <td>${sevBadge(d.severity)}</td>
                <td><strong>${esc(d.ruleName)}</strong></td>
                <td title="${esc(d.description)}">${esc(truncate(d.description, 50))}</td>
                <td>${esc(d.mitreTactic)}</td>
                <td>${esc(d.mitreTechnique)}</td>
                <td>${d.processId}</td>
                <td title="${esc(d.processImage)}">${esc(truncate(d.processImage, 30))}</td>
                <td>${esc(d.timestamp)}</td>
            </tr>`).join('')}</tbody></table>
            </div>`}
            <div class="pagination">
                <span>Page ${page} of ${totalPages}</span>
                <div>
                    <button class="btn" ${page <= 1 ? 'disabled' : ''} onclick="renderDetections(${page - 1})">← Prev</button>
                    <button class="btn" ${page >= totalPages ? 'disabled' : ''} onclick="renderDetections(${page + 1})">Next →</button>
                </div>
            </div>
        </div>`;
}

// ─── Response Actions ────────────────────────────────

async function renderResponse() {
    let statusResult = '';
    try {
        const s = await apiPost('/api/response/status');
        statusResult = s.result || 'Unknown';
    } catch { statusResult = 'Cannot reach agent'; }

    const connected = !statusResult.startsWith('ERROR');

    document.getElementById('content').innerHTML = `
        <div class="page-header">
            <h1>⚡ Response Actions</h1>
            <p>Execute response actions on the endpoint</p>
        </div>
        <div class="card">
            <h2>Agent Status</h2>
            <div class="meta-item">
                <span class="meta-label">Connection</span>
                <span class="meta-value ${connected ? 'success' : 'error'}">${connected ? '● Connected' : '● Disconnected'}</span>
            </div>
            <div style="margin-top:8px;font-size:12px;font-family:monospace;color:var(--text-dim)">${esc(statusResult)}</div>
            <button class="btn" style="margin-top:12px" onclick="renderResponse()">↻ Refresh Status</button>
        </div>
        <div class="action-grid">
            <div class="action-card">
                <h3>Kill Process</h3>
                <div class="input-row">
                    <input class="input" id="kill-pid" type="number" placeholder="Process ID (PID)">
                    <button class="btn btn-danger" onclick="doKill()">Kill</button>
                </div>
                <div class="action-result" id="kill-result"></div>
            </div>
            <div class="action-card">
                <h3>Quarantine File</h3>
                <div class="input-row">
                    <input class="input" id="quar-path" placeholder="File path">
                    <button class="btn btn-danger" onclick="doQuarantine()">Quarantine</button>
                </div>
                <div class="action-result" id="quar-result"></div>
            </div>
            <div class="action-card">
                <h3>Network Isolation</h3>
                <div class="input-row">
                    <button class="btn btn-danger" onclick="doIsolate()">Isolate Endpoint</button>
                    <button class="btn" onclick="doUnisolate()">Remove Isolation</button>
                </div>
                <div class="action-result" id="iso-result"></div>
            </div>
        </div>`;
}

async function doKill() {
    const pid = document.getElementById('kill-pid').value;
    if (!pid) return;
    const r = await apiPost('/api/response/kill', `pid=${pid}`);
    document.getElementById('kill-result').textContent = r.result || r.error;
}
async function doQuarantine() {
    const path = document.getElementById('quar-path').value;
    if (!path) return;
    const r = await apiPost('/api/response/quarantine', `path=${path}`);
    document.getElementById('quar-result').textContent = r.result || r.error;
}
async function doIsolate() {
    const r = await apiPost('/api/response/isolate');
    document.getElementById('iso-result').textContent = r.result || r.error;
}
async function doUnisolate() {
    const r = await apiPost('/api/response/unisolate');
    document.getElementById('iso-result').textContent = r.result || r.error;
}

// ─── Scan ────────────────────────────────────────────

async function renderScan() {
    const stats = await api('/api/scan/stats');

    document.getElementById('content').innerHTML = `
        <div class="page-header">
            <h1>⊙ Scan</h1>
            <p>Trigger YARA scans on the endpoint</p>
        </div>
        <div class="card">
            <h2>Last Scan</h2>
            <div class="meta-grid">
                <div class="meta-item"><span class="meta-label">Time</span><span class="meta-value">${esc(stats.timestamp)}</span></div>
                <div class="meta-item"><span class="meta-label">Type</span><span class="meta-value">${esc(stats.scanType)}</span></div>
                <div class="meta-item"><span class="meta-label">Duration</span><span class="meta-value">${esc(stats.duration)}</span></div>
                <div class="meta-item"><span class="meta-label">Threats Found</span><span class="meta-value">${esc(stats.threatsFound)}</span></div>
                <div class="meta-item"><span class="meta-label">Files Scanned</span><span class="meta-value">${esc(stats.filesScanned)}</span></div>
            </div>
        </div>
        <div class="card">
            <h2>Start New Scan</h2>
            <div class="radio-group">
                <label><input type="radio" name="scantype" value="quick" checked> Quick Scan (User Profile)</label>
                <label><input type="radio" name="scantype" value="full"> Full Scan (All Drives)</label>
                <label><input type="radio" name="scantype" value="custom"> Custom Path</label>
            </div>
            <div id="custom-path-row" style="display:none;margin-bottom:12px">
                <input class="input" id="scan-path" placeholder="Enter directory path" style="width:400px">
            </div>
            <button class="btn btn-primary" id="scan-btn" onclick="startScan()">Start Scan</button>
            <div id="scan-status" style="margin-top:12px;color:var(--text-dim);font-size:13px"></div>
        </div>`;

    document.querySelectorAll('input[name="scantype"]').forEach(r => {
        r.addEventListener('change', () => {
            document.getElementById('custom-path-row').style.display = r.value === 'custom' ? 'block' : 'none';
        });
    });
}

async function startScan() {
    const type = document.querySelector('input[name="scantype"]:checked').value;
    const statusEl = document.getElementById('scan-status');
    const btn = document.getElementById('scan-btn');
    btn.disabled = true;
    statusEl.textContent = 'Scanning...';

    let scanPath;
    if (type === 'quick') {
        scanPath = 'C:\\Users\\' + (await api('/api/dashboard')).user;
    } else if (type === 'full') {
        scanPath = 'C:\\';
    } else {
        scanPath = document.getElementById('scan-path').value;
        if (!scanPath) { statusEl.textContent = 'Enter a path'; btn.disabled = false; return; }
    }

    try {
        const r = await apiPost('/api/scan', `path=${encodeURIComponent(scanPath)}`);
        statusEl.textContent = `Scan queued: ${r.path || scanPath}. Files will be scanned by the agent in the background.`;
    } catch (e) {
        statusEl.textContent = 'Failed to start scan: ' + e.message;
    }
    btn.disabled = false;
}

// ─── Settings ────────────────────────────────────────

function renderSettings() {
    document.getElementById('content').innerHTML = `
        <div class="page-header">
            <h1>⚙ Settings</h1>
            <p>Configuration and information</p>
        </div>
        <div class="card">
            <h2>About</h2>
            <div class="meta-grid">
                <div class="meta-item"><span class="meta-label">Product</span><span class="meta-value">Vettaiyan EDR</span></div>
                <div class="meta-item"><span class="meta-label">Version</span><span class="meta-value">1.0.0</span></div>
                <div class="meta-item"><span class="meta-label">Dashboard</span><span class="meta-value">Web UI (localhost:9630)</span></div>
                <div class="meta-item"><span class="meta-label">Components</span><span class="meta-value">Kernel Driver + Minifilter + Agent Service</span></div>
            </div>
        </div>
        <div class="card">
            <h2>Architecture</h2>
            <div class="meta-grid">
                <div class="meta-item"><span class="meta-label">VettaiyanDriver</span><span class="meta-value">KMDF kernel driver — process, thread, image, registry, object monitoring</span></div>
                <div class="meta-item"><span class="meta-label">VettaiyanFilter</span><span class="meta-value">Filesystem minifilter — file I/O monitoring</span></div>
                <div class="meta-item"><span class="meta-label">VettaiyanAgent</span><span class="meta-value">C++ service — YARA scanner, behavioral detection, response engine, web server</span></div>
            </div>
        </div>`;
}

// ─── SSE Notifications ───────────────────────────────

function connectSSE() {
    const es = new EventSource('/api/notifications');
    es.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            showToast(data.type, data.title, data.message);
        } catch {}
    };
    es.onerror = () => {
        es.close();
        setTimeout(connectSSE, 5000);
    };
}

function showToast(type, title, message) {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    const cls = (type === 'threat' || type === 'critical') ? 'threat' : type === 'warning' ? 'warning' : 'info';
    const icon = cls === 'threat' ? '🔴' : cls === 'warning' ? '🟡' : '🔵';
    toast.className = `toast ${cls}`;
    toast.innerHTML = `<span class="toast-icon">${icon}</span><div class="toast-body"><div class="toast-title">${esc(title)}</div><div class="toast-msg">${esc(message)}</div></div>`;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 8000);
}

// ─── Utilities ───────────────────────────────────────

function esc(s) {
    if (!s) return '';
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}

function truncate(s, n) {
    if (!s) return '';
    return s.length > n ? s.substring(0, n) + '...' : s;
}

// ─── Init ────────────────────────────────────────────

navigateTo('dashboard');
connectSSE();
