// --- DOM Selectors & Utility Helpers ---
const $ = selector => document.querySelector(selector);
const esc = value => String(value ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const fmt = value => value ? new Date(value).toLocaleString() : '-';

// --- Supabase Client & Runtime State ---
const authClient = window.supabase.createClient('https://gdmumyordhlcbdptpqec.supabase.co', 'sb_publishable_9Xm7bMNWpcPcOW2_CjOo6A_V84e5Wa9');

let authMode = 'signin';
let monitorTimer = null;
let monitorSequence = 0;
let monitorHistory = [];
let emailTimer = null;
let audioContext = null;
let lastTamperSignal = false;

// --- Forensic Sound Alerts (Web Audio API) ---
function unlockAlertSound() {
  if (!audioContext) {
    const AudioCtor = window.AudioContext || window.webkitAudioContext;
    if (AudioCtor) audioContext = new AudioCtor();
  }
  if (audioContext?.state === 'suspended') {
    audioContext.resume().catch(() => { });
  }
}

function playTamperSound() {
  unlockAlertSound();
  if (!audioContext) return;
  const now = audioContext.currentTime;
  [0, 0.18, 0.36].forEach((delay, index) => {
    const oscillator = audioContext.createOscillator();
    const gain = audioContext.createGain();
    oscillator.type = 'sawtooth';
    oscillator.frequency.value = index === 1 ? 660 : 520;
    gain.gain.setValueAtTime(0.0001, now + delay);
    gain.gain.exponentialRampToValueAtTime(0.16, now + delay + 0.02);
    gain.gain.exponentialRampToValueAtTime(0.0001, now + delay + 0.14);
    oscillator.connect(gain).connect(audioContext.destination);
    oscillator.start(now + delay);
    oscillator.stop(now + delay + 0.16);
  });
}

window.addEventListener('pointerdown', unlockAlertSound, { once: true });

// --- Persistent Examination Identifier ---
const examinationId = (() => {
  const key = 'tamperguard-examination-v2';
  let value = sessionStorage.getItem(key);
  if (!value) {
    value = `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
    sessionStorage.setItem(key, value);
  }
  return value;
})();

// --- API Service Layer ---
async function api(path, options = {}) {
  const { data } = await authClient.auth.getSession();
  const headers = { ...(options.headers || {}), 'X-TamperGuard-Examination': examinationId };
  if (data.session?.access_token) {
    headers.Authorization = `Bearer ${data.session.access_token}`;
  }
  const response = await fetch('/api/' + path, { ...options, headers });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || response.statusText);
  return payload;
}

// --- UI Messaging & State Toggles ---
function showError(message) {
  const bar = $('#errorBar');
  bar.hidden = !message;
  bar.textContent = message ? `⚠ ${message}` : '';
}

function authMessage(message, bad = false) {
  const box = $('#authMessage');
  box.hidden = !message;
  box.textContent = message || '';
  box.className = `auth-message${bad ? ' bad' : ''}`;
}

function setAuthMode(mode) {
  authMode = mode;
  $('#authTitle').textContent = mode === 'signin' ? 'Sign in' : 'Create account';
  $('#authHint').textContent = mode === 'signin'
    ? 'Sign in to open your isolated evidence workspace.'
    : 'Create an account for a separate TamperGuard evidence source.';
  $('#authSubmit').textContent = mode === 'signin' ? 'Sign in' : 'Sign up';
  $('#authToggle').textContent = mode === 'signin'
    ? 'Need an account? Sign up'
    : 'Already have an account? Sign in';
  authMessage('');
}

function showApp(session) {
  $('#authView').hidden = !!session;
  $('#appShell').hidden = !session;
  if (session) {
    $('#accountEmail').textContent = session.user.email || '';
    if (typeof loadStatus === 'function') loadStatus();
  }
}

// --- Auth Event Handlers ---
$('#authToggle').onclick = () => setAuthMode(authMode === 'signin' ? 'signup' : 'signin');

$('#authForm').onsubmit = async event => {
  event.preventDefault();
  $('#authSubmit').disabled = true;
  authMessage('');
  try {
    const credentials = { email: $('#authEmail').value.trim(), password: $('#authPassword').value };
    const result = authMode === 'signin'
      ? await authClient.auth.signInWithPassword(credentials)
      : await authClient.auth.signUp(credentials);

    if (result.error) throw result.error;
    if (authMode === 'signup' && !result.data.session) {
      authMessage('Account created. Check your email to confirm it, then sign in.');
      $('#authPassword').value = '';
    } else {
      showApp(result.data.session);
    }
  } catch (error) {
    authMessage(error.message, true);
  } finally {
    $('#authSubmit').disabled = false;
  }
};

$('#signOutBtn').onclick = () => authClient.auth.signOut();
authClient.auth.onAuthStateChange((_event, session) => showApp(session));

// --- Preset Scenarios ---
const scenarios = {
  clean: `2025-01-10 08:01:23 INFO User admin logged in from 192.168.1.1
2025-01-10 08:02:11 INFO File /etc/config.yaml read by admin
2025-01-10 08:05:44 INFO Database backup completed successfully
2025-01-10 08:10:09 INFO Service nginx restarted by admin
2025-01-10 08:15:31 INFO User guest logged out
2025-01-10 08:20:00 INFO Scheduled scan completed - 0 threats`,
  deletion: `2025-01-10 08:01:23 INFO User admin logged in from 192.168.1.1
2025-01-10 08:05:44 INFO Database backup completed successfully
2025-01-10 08:15:31 INFO User guest logged out
2025-01-10 08:20:00 INFO Scheduled scan completed - 0 threats
[ENTRIES 08:02:11-08:05:44 MISSING - POSSIBLE DELETION]`,
  modified: `2025-01-10 08:01:23 INFO User admin logged in from 192.168.1.1
2025-01-10 08:02:11 INFO File /etc/passwd read by guest
2025-01-10 08:05:44 INFO Database backup completed successfully
2025-01-10 08:10:09 INFO Service nginx restarted by admin
2025-01-10 08:15:31 INFO User attacker logged out
2025-01-10 08:20:00 INFO Scheduled scan completed - 0 threats`,
  injected: `2025-01-10 08:01:23 INFO User admin logged in from 192.168.1.1
2025-01-10 08:02:11 INFO File /etc/config.yaml read by admin
2025-01-10 08:04:57 WARN Failed login from 10.0.0.99
2025-01-10 08:04:58 INFO User root logged in from 10.0.0.99
2025-01-10 08:05:00 INFO sudo su executed by unknown
2025-01-10 08:05:44 INFO Database backup completed`,
  timestamp: `2025-01-10 08:01:23 INFO User admin logged in from 192.168.1.1
2025-01-10 08:02:11 INFO File /etc/config.yaml read by admin
2025-01-10 07:58:44 INFO Database backup completed successfully
2025-01-10 08:10:09 INFO Service nginx restarted by admin
2025-01-10 08:09:15 INFO User guest logged out
2025-01-10 08:20:00 INFO Scheduled scan completed - 0 threats`
};

function activity(text, className = '') {
  const row = document.createElement('div');
  row.className = className;
  row.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
  $('#ltLog2').appendChild(row);
  $('#ltLog2').scrollTop = $('#ltLog2').scrollHeight;
}

// --- Manual Verification Module ---
function renderManual(result) {
  const bad = result.verdict === 'TAMPERED';
  const score = bad ? Math.max(15, 70 - result.issues.length * 11) : 98;
  if (bad) playTamperSound();

  $('#ltResult').className = `lt-result ${bad ? 'threat' : 'safe'}`;
  $('#ltResult').innerHTML = `
    <div class="lt-verdict">
      <b>${bad ? '⚠ LOG TAMPERING DETECTED' : '✓ LOGS INTACT'}</b>
      <span>${result.entries} entries · Integrity score ${score}%</span>
    </div>
    <div class="lt-metrics">
      <span><b>${result.entries}</b>Entries checked</span>
      <span><b>${result.issues.length}</b>Anomalies found</span>
      <span><b>${score}%</b>Integrity score</span>
    </div>`;

  $('#ltIssues').innerHTML = result.issues.length
    ? result.issues.map(issue => `<div class="lt-issue ${issue.type}">${issue.type === 'error' ? '●' : '▲'} ${esc(issue.msg)}</div>`).join('')
    : '<div class="lt-issue ok">✓ No anomalies found. Logs appear genuine.</div>';
}

async function verifyManual() {
  const log = $('#ltLog').value.trim();
  if (!log) return showError('Choose a scenario or paste log entries first.');
  showError('');
  $('#ltResult').className = 'lt-empty';
  $('#ltResult').textContent = 'Verifying…';
  $('#ltIssues').innerHTML = '';
  activity(`Method: ${$('#ltMethod').value}`);
  activity('Building timestamp and integrity checks…');
  try {
    const result = await api('logtamper', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ log })
    });
    renderManual(result);
    activity(`Verdict: ${result.verdict} — ${result.issues.length} issue(s)`, result.issues.length ? 'log-bad' : 'log-good');
  } catch (error) {
    showError(error.message);
  }
}

// --- Live Monitor & Traffic Summary ---
function renderSummary(summary) {
  const chips = (values, empty) => {
    const items = Object.entries(values || {}).sort((a, b) => b[1] - a[1]).slice(0, 8);
    return items.length
      ? items.map(([name, count]) => `<span class="packet-chip">${esc(name)} <b>${count}</b></span>`).join('')
      : `<span class="muted">${empty}</span>`;
  };

  const recent = (summary.recent || []).slice().reverse().slice(0, 12);

  $('#ltPacketSummary').innerHTML = `
    <div class="summary-title">Traffic summary</div>
    <div class="packet-grid">
      <div>
        <small>Event types</small>
        <div class="packet-chips">${chips(summary.event_types, 'No event types yet')}</div>
      </div>
      <div>
        <small>Protocols</small>
        <div class="packet-chips">${chips(summary.protocols, 'No protocol data yet')}</div>
      </div>
      <div>
        <small>Websites / domains</small>
        <div class="packet-chips">${(summary.websites || []).slice(0, 12).map(site => `<span class="packet-chip website">${esc(site.name)} <b>${site.count}</b></span>`).join('') || '<span class="muted">No DNS, HTTP, or TLS hostnames yet</span>'}</div>
      </div>
      <div class="packet-wide">
        <small>Recent records</small>
        ${recent.map(item => `
          <div class="packet-row">
  <b>${esc(item.event_type || 'unknown')}</b>
  <span>${esc(item.protocol || 'n/a')}</span>
  <span>${esc(item.source || '?')} → ${esc(item.destination || '?')}${item.website ? ` · ${esc(item.website)}` : ''}</span>
</div>`).join('') || '<span class="muted">Waiting for records…</span>'}
</div>
      <div class="packet-wide">
        <small>Website visit timeline</small>
        ${(summary.visits || []).slice().reverse().slice(0, 30).map(item => `
          <div class="packet-row">
            <b>${fmt(item.timestamp)}</b>
            <span>${esc(item.protocol || 'web')}</span>
            <span>${esc(item.website)}${item.status ? ` · HTTP ${esc(item.status)}` : ''}</span>
          </div>`).join('') || '<span class="muted">Waiting for website activity…</span>'}
      </div>
    </div>`;
}

function renderMonitor(data) {
  const bad = data.verdict === 'TAMPERED';
  if (bad && !lastTamperSignal) playTamperSound();
  lastTamperSignal = bad;

  $('#ltMonitorResult').className = `lt-result ${bad ? 'threat' : 'safe'}`;
  $('#ltMonitorResult').innerHTML = `
    <div class="lt-verdict">
      <b>${bad ? '⚠ TAMPERING INDICATORS DETECTED' : '✓ LOG STREAM INTACT'}</b>
      <span>${data.matched_entries || 0} records analysed · ${(data.issues || []).length} issue(s)</span>
    </div>`;

  $('#ltMonitorEntries').textContent = `${data.matched_entries || 0} records`;
  renderSummary(data.packet_summary || {});

  (data.events || []).forEach(event => {
    monitorSequence = Math.max(monitorSequence, Number(event.sequence || 0));
    monitorHistory.push(event);
  });
  monitorHistory = monitorHistory.slice(-80);
  $('#ltMonitorEvents').innerHTML = monitorHistory.map(event => `<div class="${event.type || ''}">[${new Date(event.timestamp).toLocaleTimeString()}] ${esc(event.message)}</div>`).join('');
}

function setMonitorStatus(text, className = '') {
  $('#ltMonitorStatus').textContent = text;
  $('#ltMonitorStatus').className = `monitor-badge ${className}`;
}

async function pollMonitor() {
  try {
    const data = await api(`logtamper/monitor/status?after=${monitorSequence}`);
    renderMonitor(data);
    if (data.status === 'error') {
      setMonitorStatus(data.error || 'Monitor error', 'error');
    } else if (data.status === 'running') {
      setMonitorStatus('Monitoring Suricata log', 'connected');
    } else {
      setMonitorStatus('Monitor stopped');
    }
  } catch (error) {
    setMonitorStatus('Backend unavailable', 'error');
  }
}

async function startMonitor() {
  const path = $('#ltSuricataPath').value.trim();
  if (!path) return showError('Enter the full path to Suricata eve.json or fast.log.');
  try {
    await api('logtamper/monitor/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path, format: $('#ltSuricataFormat').value })
    });
    showError('');
    monitorSequence = 0;
    monitorHistory = [];
    $('#ltMonitorEvents').innerHTML = '';
    $('#ltMonitorStart').disabled = true;
    $('#ltMonitorStop').disabled = false;
    setMonitorStatus('Monitoring Suricata log', 'connected');
    activity(`Monitor started at current file end: ${path}`);
    if (!monitorTimer) monitorTimer = setInterval(pollMonitor, 1000);
    await pollMonitor();
  } catch (error) {
    setMonitorStatus(error.message, 'error');
  }
}

async function stopMonitor() {
  await api('logtamper/monitor/stop', { method: 'POST' }).catch(() => { });
  $('#ltMonitorStart').disabled = false;
  $('#ltMonitorStop').disabled = true;
  setMonitorStatus('Monitor stopped');
  if (monitorTimer) {
    clearInterval(monitorTimer);
    monitorTimer = null;
  }
}

// --- Main Suricata Status Checker ---
async function loadStatus() {
  try {
    const status = await api('status');
    const live = status.connection === 'LIVE';
    const bad = status.last_verification?.status === 'TAMPERED';
    if (bad && !lastTamperSignal) playTamperSound();
    lastTamperSignal = bad;

    $('#connectionPill').textContent = status.connection;
    $('#connectionPill').className = `pill ${live ? 'ok' : ['STALE', 'ERROR'].includes(status.connection) ? 'bad' : ''}`;
    $('#statusTitle').textContent = bad
      ? 'Log tampering detected'
      : live
        ? 'Suricata is live'
        : status.connection === 'STALE'
          ? 'Suricata is not active'
          : `Suricata log ${status.connection.toLowerCase()}`;
    $('#statusDetail').textContent = status.file.error || `${status.state.last_line} lines chained · ${((status.file.fileSize || 0) / 1024).toFixed(1)} KB`;
    $('#statusSource').textContent = status.eve_path;
  } catch (error) {
    showError(error.message);
  }
}

// --- Email Forensics Module ---
function showEmailModule(show) {
  $('#emailModule').hidden = !show;
  document.querySelectorAll('.workspace > :not(#emailModule):not(#errorBar)').forEach(node => {
    node.hidden = show;
  });
  if (show) {
    loadEmailModule();
    if (!emailTimer) emailTimer = setInterval(loadEmailModule, 3000);
  } else if (emailTimer) {
    clearInterval(emailTimer);
    emailTimer = null;
  }
}

function renderEmailRows(rows) {
  $('#emailRows').innerHTML = rows.length ? rows.map(row => {
    const risk = row.risk
      ? `<span class="email-risk ${row.risk.severity}">${esc(row.risk.severity)}</span>`
      : '<span class="email-safe">Normal</span>';
    return `
      <tr>
        <td>${fmt(row.ts)}</td>
        <td class="mono">${esc(row.sender || '-')}</td>
        <td>${esc(row.recipients.join(', ') || '-')}</td>
        <td>${esc(row.helo || row.host || '-')}</td>
        <td class="mono">${esc(row.src_ip || '?')} → ${esc(row.dest_ip || '?')}</td>
        <td>${risk}</td>
        <td>${esc(row.summary || '')}</td>
      </tr>`;
  }).join('') : '<tr><td colspan="7" class="muted">No SMTP email records received yet. Suricata must observe SMTP traffic and have smtp enabled in eve.json.</td></tr>';
}

async function loadEmailModule() {
  try {
    const data = await api('email/events?limit=100');
    const threats = data.rows.filter(row => row.risk);
    $('#emailCount').textContent = data.rows.length;
    $('#emailThreatCount').textContent = threats.length;
    $('#emailLastSeen').textContent = data.rows[0]?.ts ? fmt(data.rows[0].ts) : '-';
    $('#emailLiveBadge').textContent = data.rows.length ? 'Receiving metadata' : 'Waiting';
    $('#emailLiveBadge').className = `monitor-badge ${data.rows.length ? 'connected' : ''}`;
    renderEmailRows(data.rows);
    $('#emailAlerts').innerHTML = threats.length ? threats.map(row => `
      <div class="email-alert">
        <b>${esc(row.risk.severity.toUpperCase())}</b>
        <span>${fmt(row.risk.detected_at)} · line ${row.line_no}</span>
        <p>${esc(row.risk.detail)}</p>
      </div>`).join('') : '<p class="email-safe">✓ No suspicious email metadata detected.</p>';
  } catch (error) {
    $('#emailLiveBadge').textContent = 'Backend unavailable';
    $('#emailLiveBadge').className = 'monitor-badge error';
  }
}

// --- Global Action Listeners ---
$('#verifyChainBtn').onclick = async () => {
  const button = $('#verifyChainBtn');
  button.disabled = true;
  button.textContent = 'Verifying…';
  try {
    const result = await api('verify', { method: 'POST' });
    activity(`Evidence chain: ${result.status}`);
    await loadStatus();
  } catch (error) {
    showError(error.message);
  } finally {
    button.disabled = false;
    button.textContent = 'Verify evidence chain';
  }
};

$('#reportBtn').onclick = async () => {
  try {
    const { data } = await authClient.auth.getSession();
    const response = await fetch(`/api/report?exam=${encodeURIComponent(examinationId)}`, {
      headers: { Authorization: `Bearer ${data.session?.access_token || ''}` }
    });
    if (!response.ok) throw new Error('Could not generate the report.');
    const url = URL.createObjectURL(await response.blob());
    const tab = window.open(url, '_blank');
    if (tab) tab.onload = () => URL.revokeObjectURL(url);
  } catch (error) {
    showError(error.message);
  }
};

document.querySelectorAll('.lt-scenario').forEach(button => {
  button.onclick = () => {
    $('#ltLog').value = scenarios[button.dataset.scenario] || '';
    showError('');
  };
});

$('#ltVerify').onclick = verifyManual;
$('#ltMonitorStart').onclick = startMonitor;
$('#ltMonitorStop').onclick = stopMonitor;
$('#emailModuleBtn').onclick = () => showEmailModule(true);
$('#closeEmailModule').onclick = () => showEmailModule(false);

// --- Initialization ---
authClient.auth.getSession().then(({ data, error }) => {
  if (error) authMessage(error.message, true);
  showApp(data.session);
  if (data.session) {
    loadStatus();
    setInterval(loadStatus, 5000);
  }
});