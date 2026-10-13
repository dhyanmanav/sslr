require('dotenv').config();
const express = require('express'), cors = require('cors'), fs = require('fs'), crypto = require('crypto'),
  readline = require('readline'), path = require('path');
const { SUPABASE_URL, SUPABASE_ANON_KEY, EVE_PATH, SOURCE_ID = 'suricata-main', PORT = 3000 } = process.env;
const POLL_MS = +process.env.POLL_MS || 2000, VERIFY_MS = (+process.env.AUTO_VERIFY_SECONDS || 30) * 1000;
const ACTIVE_WINDOW_MS = +process.env.ACTIVE_WINDOW_SECONDS * 1000 || 15000;
const MAX_STORED_EVENTS = Math.max(100, +process.env.MAX_STORED_EVENTS || 2000);
const IGNORED_SURICATA_ALERTS = /ipv4 truncated packet|packet too short|checksum invalid/i;
if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !EVE_PATH) { console.error('Set SUPABASE_URL, SUPABASE_ANON_KEY and EVE_PATH in .env'); process.exit(1); }

const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const GENESIS = sha('GENESIS');
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

async function sb(p, { method = 'GET', body, prefer, count } = {}) {
  const h = { apikey: SUPABASE_ANON_KEY, Authorization: 'Bearer ' + SUPABASE_ANON_KEY, 'Content-Type': 'application/json' };
  const pf = [prefer, count && 'count=exact'].filter(Boolean).join(','); if (pf) h.Prefer = pf;
  const r = await fetch(SUPABASE_URL.replace(/\/$/, '') + '/rest/v1/' + p, { method, headers: h, body: body && JSON.stringify(body) });
  if (!r.ok) throw new Error(`Supabase ${r.status} on ${method} ${p}: ${await r.text()}`);
  const t = await r.text(), total = (r.headers.get('content-range') || '').split('/')[1];
  return { data: t ? JSON.parse(t) : null, total: total && total !== '*' ? +total : null };
}
const custody = async (actor, action, detail) => { try { await sb('custody_log', { method: 'POST', body: { actor, action, detail: `${sourceId()}: ${detail}` }, prefer: 'return=minimal' }); } catch (e) { console.error('custody:', e.message); } };

/* ---------- classification: only EMAIL or WEB events ---------- */
const MAIL = /smtp|imap|pop3|mail|outlook|office365/i;
function classify(e) {
  const t = e.event_type; if (!['http', 'tls', 'dns', 'smtp', 'alert'].includes(t)) return null;
  const host = e.http?.hostname || e.tls?.sni || e.dns?.rrname || '', ap = e.app_proto || '';
  let category = null, summary = '';
  if (t === 'smtp' || /smtp|imap|pop3/.test(ap) || (host && MAIL.test(host))) category = 'email';
  else if (t === 'alert') category = 'security';
  else if (['http', 'tls', 'dns'].includes(t) || ['http', 'tls', 'dns'].includes(ap)) category = 'web';
  if (!category) return null;
  if (t === 'http') summary = `${e.http.http_method || ''} ${host}${e.http.url || ''} → ${e.http.status || '-'}`;
  else if (t === 'tls') summary = `TLS ${host || e.dest_ip} ${e.tls?.version || ''}`;
  else if (t === 'dns') summary = `DNS ${e.dns?.type || ''} ${host} ${e.dns?.rdata || ''}`.trim();
  else if (t === 'smtp') summary = `SMTP ${e.smtp?.mail_from || ''} → ${(e.smtp?.rcpt_to || []).join(', ')} (helo ${e.smtp?.helo || '-'})`;
  else summary = `ALERT ${e.alert?.signature || ''}`;
  return { category, host, summary: summary.trim() };
}
function emailThreat(e) {
  if (e.event_type !== 'smtp' && !/smtp|imap|pop3/i.test(e.app_proto || '')) return null;
  const smtp = e.smtp && typeof e.smtp === 'object' ? e.smtp : {};
  const from = String(smtp.mail_from || smtp.from || '').toLowerCase();
  const helo = String(smtp.helo || '').toLowerCase();
  const text = JSON.stringify(smtp).toLowerCase();
  const reasons = [];
  if (/free-money|lottery|urgent|verify-account|password-reset|crypto|bitcoin|gift-card|wire-transfer/i.test(text)) reasons.push('Suspicious social-engineering language');
  if (/\.(zip|rar|7z|scr|exe|js|vbs|iso|lnk)(["'\s;]|$)/i.test(text)) reasons.push('Potentially dangerous attachment or filename');
  if (from && /@(mailinator|tempmail|10minutemail|guerrillamail)\./i.test(from)) reasons.push('Disposable sender domain');
  if (helo && /^[\d.]+$/.test(helo)) reasons.push('SMTP HELO is a raw IP address');
  return reasons.length ? { severity: reasons.length > 1 ? 'high' : 'medium', reasons } : null;
}

/* ---------- ingestion: tail eve.json, build SHA-256 hash chain over EVERY line ---------- */
let st = { last_line: 0, last_offset: 0, last_chain: GENESIS }, busy = false;
const stat = { fileSize: 0, fileMtimeMs: null, exists: false, connected: false, active: false, lastPoll: null, lastChanged: null, lastEvent: null, error: null }, seen = new Set();
let activeSourceId = SOURCE_ID, activeUser = null, activeToken = null;
const sourceId = () => activeSourceId;

async function getAuthUser(token) {
  const r = await fetch(SUPABASE_URL.replace(/\/$/, '') + '/auth/v1/user', {
    headers: { apikey: SUPABASE_ANON_KEY, Authorization: 'Bearer ' + token }
  });
  if (!r.ok) throw new Error('Your session has expired. Please sign in again.');
  return r.json();
}
async function activateAccount(req) {
  const auth = req.get('authorization') || '', token = auth.replace(/^Bearer\s+/i, '');
  if (!token || token === SUPABASE_ANON_KEY) return;
  if (token === activeToken && activeUser) return;
  const user = await getAuthUser(token);
  activeUser = user;
  activeToken = token;
  const examination = String(req.get('x-tamperguard-examination') || req.query.exam || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 48);
  activeSourceId = `account-${user.id}${examination ? `-exam-${examination}` : ''}`;
  st = { last_line: 0, last_offset: 0, last_chain: GENESIS };
  seen.clear();
  await loadState();
  await ingestOnce();
}

async function alertOnce(kind, severity, line_no, detail, verification_id) {
  const k = kind + line_no + detail; if (seen.has(k)) return; seen.add(k);
  try {
    await sb('tamper_alerts', { method: 'POST', body: [{ source_id: sourceId(), kind, severity, line_no, detail, verification_id: verification_id || null }], prefer: 'return=minimal' });
  } catch (e) {
    console.error('alert write:', e.message);
    throw e;
  }
  await custody(activeUser?.email || 'SYSTEM', 'ALERT_' + kind, detail);
}
async function loadState() {
  const { data } = await sb(`log_sources?id=eq.${sourceId()}`);
  if (data[0]) st = data[0];
  else if (sourceId().includes('-exam-')) {
    st = await baselineAtCurrentEnd();
    await saveState();
  } else await saveState();
}
async function baselineAtCurrentEnd() {
  if (!fs.existsSync(EVE_PATH)) return { last_line: 0, last_offset: 0, last_chain: GENESIS };
  const file = fs.statSync(EVE_PATH);
  let last_line = 0, last_chain = GENESIS;
  const rl = readline.createInterface({ input: fs.createReadStream(EVE_PATH), crlfDelay: Infinity });
  for await (const raw of rl) { last_line++; last_chain = sha(last_chain + sha(raw)); }
  rl.close();
  return { last_line, last_offset: file.size, last_chain };
}
const saveState = () => sb('log_sources', { method: 'POST', prefer: 'resolution=merge-duplicates,return=minimal',
  body: { id: sourceId(), path: EVE_PATH, last_line: st.last_line, last_offset: st.last_offset, last_chain: st.last_chain, updated_at: new Date().toISOString() } });
async function pruneEvents() {
  const { data } = await sb(`log_events?source_id=eq.${sourceId()}&select=line_no&order=line_no.desc&limit=1&offset=${MAX_STORED_EVENTS}`);
  if (data?.[0]?.line_no) await sb(`log_events?source_id=eq.${sourceId()}&line_no=lte.${data[0].line_no}`, { method: 'DELETE', prefer: 'return=minimal' });
}
async function clearNoisyAlerts() {
  // Alerts are append-only; noisy historical rows are filtered from views instead of deleted.
}
const visibleAlert = a => !(a.kind === 'SURICATA_ALERT' && /ipv4 truncated packet|packet too short|checksum invalid/i.test(a.detail || ''));

/* ---------- standalone Log Tampering workspace monitor ---------- */
const tamperMonitor = {
  status: 'stopped', path: null, format: 'auto', offset: 0, buffer: '',
  entries: 0, matched_entries: 0, issues: [], events: [], sequence: 0,
  packet_types: {}, protocols: {}, websites: {}, recent: [], visits: [],
  last_timestamp: null, last_visit_times: {}, timer: null, error: null
};
const monitorPush = (message, type = 'info', verdict) => {
  tamperMonitor.sequence++;
  tamperMonitor.events.push({
    sequence: tamperMonitor.sequence,
    timestamp: new Date().toISOString(),
    type, verdict: verdict || (tamperMonitor.issues.length ? 'TAMPERED' : 'CLEAN'),
    message
  });
  tamperMonitor.events = tamperMonitor.events.slice(-200);
};
const countMonitor = (bucket, value) => { if (value) bucket[value] = (bucket[value] || 0) + 1; };
const monitorTimestamp = (value, line) => {
  if (value) return value;
  const m = line.match(/(20\d{2}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?|\d{2}:\d{2}:\d{2})/);
  return m ? m[1].replace(/\//g, '-') : null;
};
const parseMonitorTime = value => {
  if (!value) return null;
  const d = new Date(value.length === 8 ? `1970-01-01T${value}Z` : value);
  return Number.isNaN(d.getTime()) ? null : d;
};
function monitorDetails(line, parsed) {
  if (!parsed || typeof parsed !== 'object') return { event_type: 'fast.log', protocol: null, website: null, source: null, destination: null };
  const flow = parsed.flow && typeof parsed.flow === 'object' ? parsed.flow : {};
  const dns = parsed.dns && typeof parsed.dns === 'object' ? parsed.dns : {};
  const http = parsed.http && typeof parsed.http === 'object' ? parsed.http : {};
  const tls = parsed.tls && typeof parsed.tls === 'object' ? parsed.tls : {};
  let website = dns.rrname || http.hostname || tls.sni;
  if (!website && http.url) { try { website = new URL(http.url).hostname; } catch (_) {} }
  return {
    event_type: String(parsed.event_type || 'unknown'),
    protocol: parsed.proto ? String(parsed.proto).toUpperCase() : null,
    website: website ? String(website) : null,
    source: parsed.src_ip || flow.src_ip || null,
    destination: parsed.dest_ip || flow.dest_ip || null,
    timestamp: parsed.timestamp || null,
    status: http.status || null,
    referer: http.http_referer || null
  };
}
function processMonitorLines(lines) {
  const newIssues = [];
  for (const raw of lines) {
    const line = raw.trim(); if (!line) continue;
    tamperMonitor.entries++;
    let parsed = null;
    const isJson = tamperMonitor.format === 'eve.json' || (tamperMonitor.format === 'auto' && line.startsWith('{'));
    if (isJson) {
      try { parsed = JSON.parse(line); } catch (_) {
        newIssues.push({ type: 'error', msg: `Invalid Suricata JSON at entry ${tamperMonitor.entries}; possible partial or modified record.` });
      }
    }
    if (parsed?.cyberforensics_test_tampered === true) {
      newIssues.push({ type: 'error', msg: `Explicit test tampering marker found at entry ${tamperMonitor.entries}.` });
    }
    const details = monitorDetails(line, parsed);
    tamperMonitor.matched_entries++;
    countMonitor(tamperMonitor.packet_types, details.event_type);
    countMonitor(tamperMonitor.protocols, details.protocol);
    countMonitor(tamperMonitor.websites, details.website);
    if (details.event_type !== 'unknown' || details.protocol || details.website) {
      tamperMonitor.recent.push(details);
      tamperMonitor.recent = tamperMonitor.recent.slice(-40);
    }
    if (details.website) {
      const host = details.website.toLowerCase().replace(/\.$/, '');
      const current = parseMonitorTime(details.timestamp) || new Date();
      const previous = tamperMonitor.last_visit_times[host];
      if (!previous || current.getTime() - previous.getTime() >= 2000) {
        tamperMonitor.last_visit_times[host] = current;
        tamperMonitor.visits.push({ ...details, website: host, timestamp: details.timestamp || current.toISOString() });
        tamperMonitor.visits = tamperMonitor.visits.slice(-200);
      }
    }
    const current = parseMonitorTime(monitorTimestamp(details.timestamp, line));
    const previous = parseMonitorTime(tamperMonitor.last_timestamp);
    if (current && previous && previous.getTime() - current.getTime() > 1000) {
      newIssues.push({ type: 'warn', msg: `Timestamp reversal at entry ${tamperMonitor.entries}: ${monitorTimestamp(details.timestamp, line)} < ${tamperMonitor.last_timestamp}` });
    }
    if (current && (!previous || current > previous)) tamperMonitor.last_timestamp = monitorTimestamp(details.timestamp, line);
    if (!isJson && /\b(?:MISSING|DELETED|TRUNCATED|TAMPERED|MODIFIED)\b/i.test(line)) {
      newIssues.push({ type: 'error', msg: `Suspicious tampering marker found at entry ${tamperMonitor.entries}.` });
    }
  }
  if (newIssues.length) {
    tamperMonitor.issues.push(...newIssues); tamperMonitor.issues = tamperMonitor.issues.slice(-50);
    newIssues.forEach(i => monitorPush(i.msg, i.type, 'TAMPERED'));
  } else if (lines.length) monitorPush(`Analysed ${lines.length} new Suricata record(s); no tampering indicators found.`, 'ok', 'CLEAN');
}
function pollTamperMonitor() {
  if (tamperMonitor.status !== 'running') return;
  try {
    const file = fs.statSync(tamperMonitor.path);
    if (file.size < tamperMonitor.offset) {
      tamperMonitor.issues.push({ type: 'error', msg: 'Suricata log size decreased; possible truncation or rewrite detected.' });
      monitorPush('Suricata log size decreased; possible truncation or rewrite detected.', 'error', 'TAMPERED');
      tamperMonitor.offset = 0; tamperMonitor.buffer = '';
    }
    if (file.size === tamperMonitor.offset) return;
    const fd = fs.openSync(tamperMonitor.path, 'r');
    const buf = Buffer.alloc(file.size - tamperMonitor.offset);
    fs.readSync(fd, buf, 0, buf.length, tamperMonitor.offset); fs.closeSync(fd);
    tamperMonitor.offset = file.size; tamperMonitor.buffer += buf.toString('utf8');
    const parts = tamperMonitor.buffer.split(/\r?\n/);
    tamperMonitor.buffer = parts.pop() || ''; processMonitorLines(parts);
  } catch (e) {
    tamperMonitor.status = 'error'; tamperMonitor.error = e.message;
    monitorPush(`Monitor error: ${e.message}`, 'error', 'TAMPERED');
  }
}
function resetTamperMonitor() {
  if (tamperMonitor.timer) clearInterval(tamperMonitor.timer);
  tamperMonitor.timer = null; tamperMonitor.status = 'stopped';
}

async function ingestOnce() {
  if (busy) return; busy = true;
  try {
    let file;
    try {
      file = fs.statSync(EVE_PATH);
    } catch (e) {
      if (e.code === 'ENOENT') {
        stat.fileSize = 0; stat.fileMtimeMs = null; stat.exists = false; stat.connected = false; stat.active = false; stat.lastPoll = new Date().toISOString();
        stat.lastEvent = null; stat.error = `Waiting for Suricata log: ${EVE_PATH}`;
        return;
      }
      throw e;
    }
    const size = file.size, mtimeMs = file.mtimeMs;
    const changed = stat.fileSize !== size || stat.fileMtimeMs !== mtimeMs;
    stat.fileSize = size; stat.fileMtimeMs = mtimeMs; stat.exists = true; stat.connected = true;
    stat.active = Date.now() - mtimeMs <= ACTIVE_WINDOW_MS; stat.lastPoll = new Date().toISOString();
    if (changed) stat.lastChanged = new Date(mtimeMs).toISOString();
    stat.error = null;
    if (size < st.last_offset) { await alertOnce('FILE_TRUNCATED', 'critical', st.last_line, `eve.json shrank from ${st.last_offset} to ${size} bytes (truncated, rotated or replaced)`); return; }
    if (size === st.last_offset) return;
    const len = Math.min(size - st.last_offset, 8 * 1024 * 1024), buf = Buffer.alloc(len);
    const fd = fs.openSync(EVE_PATH, 'r'); fs.readSync(fd, buf, 0, len, st.last_offset); fs.closeSync(fd);
    const nl = buf.lastIndexOf(10); if (nl < 0) return;
    const lines = buf.subarray(0, nl + 1).toString('utf8').split('\n'); lines.pop();
    let off = st.last_offset, ln = st.last_line, chain = st.last_chain; const rows = [];
    for (const raw of lines) {
      ln++; const line = raw.replace(/\r$/, ''), start = off; off += Buffer.byteLength(raw) + 1;
      const ls = sha(line); chain = sha(chain + ls);
      let e; try { e = JSON.parse(line); } catch { continue; }
      stat.lastEvent = e.timestamp || stat.lastEvent;
      const mailRisk = emailThreat(e);
      if (mailRisk) await alertOnce('EMAIL_THREAT', mailRisk.severity, ln, mailRisk.reasons.join('; '));
      if (e.event_type === 'alert') {
        const severity = e.alert?.severity === 1 ? 'critical' : e.alert?.severity === 2 ? 'high' : 'medium';
        const signature = e.alert?.signature || 'Suricata security alert';
        const demo = e.cyberforensics_test_tampered === true || /tamperguard demo|synthetic attack/i.test(signature);
        if (demo) await alertOnce('SYNTHETIC_TAMPER_TEST', 'critical', ln, 'TamperGuard live demonstration attack detected by Suricata.');
        else if (severity === 'critical' && !IGNORED_SURICATA_ALERTS.test(signature)) await alertOnce('SURICATA_ALERT', severity, ln, signature);
      }
      const c = classify(e); if (!c) continue;
      rows.push({ source_id: sourceId(), line_no: ln, byte_offset: start, ts: e.timestamp || null, category: c.category, event_type: e.event_type, host: c.host || null,
        src_ip: e.src_ip || null, src_port: e.src_port || null, dest_ip: e.dest_ip || null, dest_port: e.dest_port || null, proto: e.proto || null, summary: c.summary || null,
        line_sha256: ls, chain_hash: chain, raw: e });
    }
    for (let i = 0; i < rows.length; i += 500)
      await sb('log_events?on_conflict=source_id,line_no', { method: 'POST', body: rows.slice(i, i + 500), prefer: 'resolution=ignore-duplicates,return=minimal' });
    st = { ...st, last_line: ln, last_offset: off, last_chain: chain }; await saveState();
    await pruneEvents();
    if (rows.length) await custody('SYSTEM', 'INGEST', `${rows.length} events stored, chain head at line ${ln}`);
  } catch (e) {
    stat.connected = false; stat.error = e.message; console.error('ingest:', e.message);
  } finally { busy = false; }
}

/* ---------- verification: re-walk the file and compare with stored baseline ---------- */
let verifying = false;
async function verify(actor = 'SYSTEM') {
  if (verifying) return { status: 'BUSY' }; verifying = true;
  try {
    const { data: v } = await sb('verifications', { method: 'POST', body: { source_id: sourceId(), status: 'RUNNING', actor: activeUser?.email || actor }, prefer: 'return=representation' });
    const vid = v[0].id, evs = [];
    for (let o = 0; ; o += 1000) {
      const { data } = await sb(`log_events?source_id=eq.${sourceId()}&select=line_no,line_sha256,chain_hash,summary&order=line_no.asc&limit=1000&offset=${o}`);
      evs.push(...data); if (data.length < 1000) break;
    }
    const byLine = new Map(evs.map(e => [e.line_no, e])), byHash = new Map(evs.map(e => [e.line_sha256, e]));
    const found = new Map(), bad = [], issues = [], flag = new Map(); let chain = GENESIS, walked = 0, lastGood = 0;
    const firstRetainedLine = evs.length ? Math.min(...evs.map(e => e.line_no)) : st.last_line + 1;
    if (fs.existsSync(EVE_PATH) && st.last_line > 0) {
      const rl = readline.createInterface({ input: fs.createReadStream(EVE_PATH), crlfDelay: Infinity });
      for await (const raw of rl) {
        const ln = walked + 1; if (ln > st.last_line) break; walked = ln;
        const ls = sha(raw); chain = sha(chain + ls);
        const m = byHash.get(ls); if (m && m.line_no !== ln && !found.has(m.line_no)) found.set(m.line_no, ln);
        const ev = byLine.get(ln);
        if (ev) {
          if (ls === ev.line_sha256) {
            if (ln === firstRetainedLine) { chain = ev.chain_hash; lastGood = ln; }
            else if (chain !== ev.chain_hash) { flag.set(ln, 'chain_break'); issues.push(['CHAIN_BREAK', 'high', ln, `Hash chain broken in the retained verification window near line ${ln}.`]); }
            else lastGood = ln;
          } else bad.push(ev);
          chain = ev.chain_hash;
        }
        if (ln === st.last_line && chain !== st.last_chain) issues.push(['TAIL_MISMATCH', 'high', ln, `Chain head at line ${ln} differs from the recorded head (changes after line ${lastGood}).`]);
      }
      rl.close();
    }
    const missing = [], shifts = new Map();
    for (const e of bad) {
      if (e.line_no > walked) { flag.set(e.line_no, 'missing'); missing.push(e); }
      else if (found.has(e.line_no)) { flag.set(e.line_no, 'shifted'); const d = found.get(e.line_no) - e.line_no, s = shifts.get(d) || { n: 0, first: e.line_no }; s.n++; shifts.set(d, s); }
      else { flag.set(e.line_no, 'modified'); issues.push(['LINE_MODIFIED', 'critical', e.line_no, `Line ${e.line_no} no longer matches its recorded SHA-256. Original event: "${e.summary}"`]); }
    }
    if (walked < st.last_line) issues.push(['LOGS_DELETED', 'critical', walked + 1, `File has ${walked} lines but ${st.last_line} were recorded: ${st.last_line - walked} line(s) deleted or truncated.`]);
    for (const [d, s] of shifts) issues.push([d < 0 ? 'LINES_REMOVED' : 'LINES_INSERTED', 'critical', s.first, `${Math.abs(d)} line(s) ${d < 0 ? 'removed' : 'inserted'} at or before line ${s.first}; ${s.n} later recorded events shifted position.`]);
    for (const i of issues) await alertOnce(i[0], i[1], i[2], i[3], vid);
    // flag rows in DB
    await sb(`log_events?source_id=eq.${sourceId()}&status=neq.ok`, { method: 'PATCH', body: { status: 'ok' } });
    const groups = {}; for (const [l, s] of flag) (groups[s] ||= []).push(l);
    for (const [s, ls] of Object.entries(groups)) for (let i = 0; i < ls.length; i += 150)
      await sb(`log_events?source_id=eq.${sourceId()}&line_no=in.(${ls.slice(i, i + 150).join(',')})`, { method: 'PATCH', body: { status: s } });
    const status = issues.length ? 'TAMPERED' : 'INTACT';
    await sb(`verifications?id=eq.${vid}`, { method: 'PATCH', body: { status, finished_at: new Date().toISOString(), lines_checked: walked, events_checked: evs.length, issues: issues.length, head_chain: chain } });
    if (actor !== 'SYSTEM' || issues.length) await custody(actor, 'VERIFY', `${status}: ${walked} lines, ${evs.length} events, ${issues.length} issue(s)`);
    return { id: vid, status, lines_checked: walked, events_checked: evs.length, issues: issues.map(i => ({ kind: i[0], severity: i[1], line_no: i[2], detail: i[3] })) };
  } finally { verifying = false; }
}

/* ---------- API ---------- */
const app = express(); app.use(cors(), express.json()); app.use(express.static(path.join(__dirname, 'public')));
const w = fn => async (req, res) => { try { await activateAccount(req); await fn(req, res); } catch (e) { res.status(500).json({ error: e.message }); } };
const who = req => activeUser?.email || 'authenticated examiner';

app.get('/api/status', w(async (req, res) => {
  const { data } = await sb(`verifications?source_id=eq.${sourceId()}&order=id.desc&limit=1`);
  res.json({
    source: sourceId(),
    eve_path: EVE_PATH,
    state: st,
    file: stat,
    connection: !stat.connected ? (stat.error?.startsWith('Waiting for Suricata') ? 'WAITING' : 'ERROR') : (stat.active ? 'LIVE' : 'STALE'),
    demo_data: false,
    last_verification: data[0] || null
  });
}));
app.get('/api/stats', w(async (req, res) => {
  const q = (f = '') => sb(`log_events?source_id=eq.${sourceId()}${f}&select=id&limit=1`, { count: true });
  const [total, email, web, security, flagged, alertRows, sample] = await Promise.all([q(), q('&category=eq.email'), q('&category=eq.web'), q('&category=eq.security'), q('&status=neq.ok'),
    sb(`tamper_alerts?source_id=eq.${sourceId()}&select=id,kind,detail&limit=200`), sb(`log_events?source_id=eq.${sourceId()}&select=ts,host,category,event_type&order=line_no.desc&limit=${MAX_STORED_EVENTS}`)]);
  const rows = sample.data, hosts = {}, types = {};
  rows.forEach(r => { if (r.host) hosts[r.host] = (hosts[r.host] || 0) + 1; types[r.event_type] = (types[r.event_type] || 0) + 1; });
  const ts = rows.map(r => +new Date(r.ts)).filter(Boolean), min = Math.min(...ts), max = Math.max(...ts), N = 24, bins = Array(N).fill(0).map(() => ({ email: 0, web: 0, security: 0 }));
  rows.forEach(r => { const t = +new Date(r.ts); if (!t) return; bins[Math.min(N - 1, Math.floor((t - min) / ((max - min) || 1) * N))][r.category]++; });
  res.json({ total: total.total, email: email.total, web: web.total, security: security.total, flagged: flagged.total, alerts: alertRows.data.filter(visibleAlert).length, lines: st.last_line,
    topHosts: Object.entries(hosts).sort((a, b) => b[1] - a[1]).slice(0, 8), types,
    timeline: bins.map((b, i) => ({ t: new Date(min + (i + 0.5) * ((max - min) || 1) / N).toISOString(), ...b })) });
}));
app.get('/api/events', w(async (req, res) => {
  const { category, type, q, flagged, limit = 25, offset = 0 } = req.query;
  let f = `source_id=eq.${sourceId()}`;
  if (category) f += `&category=eq.${encodeURIComponent(category)}`; if (type) f += `&event_type=eq.${encodeURIComponent(type)}`;
  if (flagged === '1') f += '&status=neq.ok'; if (q) f += `&summary=ilike.*${encodeURIComponent(q.replace(/[*,()]/g, ''))}*`;
  const r = await sb(`log_events?${f}&select=id,line_no,ts,category,event_type,host,src_ip,src_port,dest_ip,dest_port,summary,status,line_sha256,chain_hash,raw&order=line_no.desc&limit=${+limit}&offset=${+offset}`, { count: true });
  res.json({ total: r.total, rows: r.data });
}));
app.get('/api/alerts', w(async (req, res) => {
  const active = req.query.active === '1';
  const since = active ? new Date(Date.now() - 60 * 1000).toISOString() : null;
  const filter = since ? `&detected_at=gte.${encodeURIComponent(since)}` : '';
  res.json((await sb(`tamper_alerts?source_id=eq.${sourceId()}${filter}&order=id.desc&limit=200`)).data.filter(visibleAlert));
}));
app.get('/api/verifications', w(async (req, res) => res.json((await sb(`verifications?source_id=eq.${sourceId()}&order=id.desc&limit=100`)).data)));
app.get('/api/custody', w(async (req, res) => {
  const rows = (await sb('custody_log?order=id.desc&limit=200')).data;
  res.json(rows.filter(c => String(c.detail || '').startsWith(sourceId() + ':') || String(c.detail || '').includes(`case ${sourceId()}`)));
}));
app.post('/api/verify', w(async (req, res) => res.json(await verify(who(req)))));

app.post('/api/logtamper', w(async (req, res) => {
  const text = String(req.body?.log || '');
  const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const issues = [], times = [];
  lines.forEach(line => { const m = line.match(/(\d{2}:\d{2}:\d{2})/); if (m) times.push(m[1]); });
  for (let i = 1; i < times.length; i++)
    if (times[i] < times[i - 1]) issues.push({ type: 'warn', msg: `Timestamp reversal at entry ${i + 1}: ${times[i]} < ${times[i - 1]}` });
  if (/MISSING/i.test(text)) issues.push({ type: 'error', msg: 'Log entries reported missing — possible deletion' });
  if (/sudo su|unknown/i.test(text)) issues.push({ type: 'error', msg: 'Privilege escalation pattern detected' });
  if (/attacker|etc\/passwd/i.test(text)) issues.push({ type: 'error', msg: 'Suspicious user / sensitive file access' });
  res.json({ verdict: issues.length ? 'TAMPERED' : 'INTACT', issues, entries: lines.length });
}));
app.post('/api/logtamper/monitor/start', w(async (req, res) => {
  const monitorPath = path.resolve(String(req.body?.path || '').trim());
  const format = String(req.body?.format || 'auto').toLowerCase();
  if (!['auto', 'eve.json', 'fast.log'].includes(format)) return res.status(400).json({ error: 'Format must be auto, eve.json, or fast.log' });
  if (!monitorPath || !fs.existsSync(monitorPath) || !fs.statSync(monitorPath).isFile()) return res.status(400).json({ error: `Log file does not exist: ${monitorPath}` });
  resetTamperMonitor();
  Object.assign(tamperMonitor, { status: 'running', path: monitorPath, format, offset: fs.statSync(monitorPath).size, buffer: '', entries: 0, matched_entries: 0, issues: [], events: [], sequence: 0, packet_types: {}, protocols: {}, websites: {}, recent: [], visits: [], last_timestamp: null, last_visit_times: {}, error: null });
  tamperMonitor.timer = setInterval(pollTamperMonitor, 500);
  monitorPush(`Monitoring started: ${monitorPath}`, 'system', 'CLEAN');
  res.json({ status: tamperMonitor.status, path: monitorPath, format });
}));
app.post('/api/logtamper/monitor/stop', w(async (req, res) => { resetTamperMonitor(); res.json({ status: tamperMonitor.status }); }));
app.get('/api/logtamper/monitor/status', w(async (req, res) => {
  const after = Number(req.query.after || 0);
  const events = tamperMonitor.events.filter(e => e.sequence > after);
  const websites = Object.entries(tamperMonitor.websites).map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count);
  res.json({
    status: tamperMonitor.status, path: tamperMonitor.path, format: tamperMonitor.format,
    entries: tamperMonitor.entries, matched_entries: tamperMonitor.matched_entries,
    verdict: tamperMonitor.issues.length ? 'TAMPERED' : 'CLEAN', issues: tamperMonitor.issues.slice(-50),
    error: tamperMonitor.error, sequence: tamperMonitor.sequence, events,
    packet_summary: { event_types: tamperMonitor.packet_types, protocols: tamperMonitor.protocols, websites, recent: tamperMonitor.recent, visits: tamperMonitor.visits }
  });
}));

app.get('/api/email/events', w(async (req, res) => {
  const limit = Math.min(100, Math.max(1, Number(req.query.limit || 50)));
  const since = req.query.since ? `&ts=gte.${encodeURIComponent(req.query.since)}` : '';
  const result = await sb(`log_events?source_id=eq.${sourceId()}&category=eq.email${since}&select=line_no,ts,event_type,host,src_ip,src_port,dest_ip,dest_port,proto,summary,status,raw&order=line_no.desc&limit=${limit}`);
  const alerts = (await sb(`tamper_alerts?source_id=eq.${sourceId()}&kind=eq.EMAIL_THREAT&order=id.desc&limit=100`)).data;
  const rows = (result.data || []).map(row => {
    const smtp = row.raw?.smtp || {};
    const from = smtp.mail_from || smtp.from || null;
    const to = smtp.rcpt_to || smtp.to || [];
    const risk = alerts.find(alert => alert.line_no === row.line_no);
    return { ...row, sender: from, recipients: Array.isArray(to) ? to : [to], helo: smtp.helo || null, risk: risk ? { severity: risk.severity, detail: risk.detail, detected_at: risk.detected_at } : null };
  });
  res.json({ rows, alerts });
}));

app.get('/api/report', w(async (req, res) => {
  const [vs, al, cu, ev, src] = await Promise.all([
    sb(`verifications?source_id=eq.${sourceId()}&order=id.desc&limit=20`),
    sb(`tamper_alerts?source_id=eq.${sourceId()}&order=id.desc&limit=200`),
    sb('custody_log?order=id.desc&limit=300'),
    sb(`log_events?source_id=eq.${sourceId()}&select=line_no,ts,category,event_type,host,src_ip,dest_ip,summary,status&order=line_no.desc&limit=${MAX_STORED_EVENTS}`),
    sb(`log_sources?id=eq.${sourceId()}&limit=1`)
  ]);
  al.data = al.data.filter(visibleAlert);
  cu.data = cu.data.filter(c => String(c.detail || '').startsWith(sourceId() + ':') || String(c.detail || '').includes(`case ${sourceId()}`)).slice(0, 60);
  const last = vs.data[0], events = ev.data || [], source = src.data[0] || st;
  const counts = events.reduce((out, row) => { out[row.category] = (out[row.category] || 0) + 1; out.types[row.event_type] = (out.types[row.event_type] || 0) + 1; return out; }, { types: {} });
  const emailThreats = al.data.filter(a => a.kind === 'EMAIL_THREAT');
  const attacks = al.data.filter(a => /TAMPER|INSERT|REMOVE|DELETE|MODIF|TRUNCAT|SYNTHETIC/i.test(`${a.kind} ${a.detail}`));
  const tr = (a) => `<tr>${a.map(x => `<td>${esc(x)}</td>`).join('')}</tr>`;
  const rows = (items, empty, columns) => items.length ? items.map(tr).join('') : tr([empty, ...Array(Math.max(0, columns - 1)).fill('')]);
  const generated = new Date().toISOString(), connection = stat.active ? 'LIVE' : stat.exists ? 'STALE' : 'WAITING';
  const statusDescription = last?.status === 'TAMPERED'
    ? 'Evidence integrity exceptions were recorded. Preserve the source file and review the findings below.'
    : last?.status === 'INTACT' ? 'The latest verification matched the stored baseline for the examined window.'
    : 'No completed verification exists for this account yet.';
  await custody(who(req), 'REPORT_GENERATED', `case ${sourceId()}`);
  const reportStatus = last?.status || 'NOT VERIFIED';
  const statusColor = reportStatus === 'INTACT' ? '#087443' : reportStatus === 'TAMPERED' ? '#b42318' : '#946200';
  res.type('html').send(`<!doctype html><html><head><meta charset=utf-8><title>TamperGuard | Forensic Report</title><style>
  :root{--ink:#172033;--muted:#667085;--line:#d0d5dd;--soft:#f2f4f7;--blue:#175cd3;--red:#b42318;--green:#087443}
  *{box-sizing:border-box}body{font:13px/1.55 Arial,Helvetica,sans-serif;max-width:1080px;margin:0 auto;padding:30px 38px;color:var(--ink);background:#fff}
  header{display:flex;justify-content:space-between;gap:24px;align-items:flex-start;border-bottom:4px solid var(--blue);padding-bottom:20px}.brand{font-size:25px;font-weight:800;letter-spacing:-.03em}.subtitle{color:var(--muted);margin-top:4px}.meta{text-align:right;color:var(--muted);font-size:11px}
  h1{font-size:28px;margin:25px 0 7px}h2{font-size:17px;margin:27px 0 9px;border-bottom:1px solid var(--line);padding-bottom:7px}h3{font-size:14px;margin:0 0 5px}.actions{display:flex;gap:8px;margin:16px 0}.btn{background:var(--blue);border:0;border-radius:6px;color:#fff;padding:9px 14px;font-weight:700;cursor:pointer}
  .status{padding:17px 20px;border:2px solid ${statusColor};border-radius:10px;color:${statusColor};background:${reportStatus === 'INTACT' ? '#ecfdf3' : reportStatus === 'TAMPERED' ? '#fef3f2' : '#fffaeb'};font-size:18px;font-weight:800}.status small{display:block;font-size:13px;font-weight:400;color:var(--ink);margin-top:5px}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:16px 0}.stat{background:var(--soft);border:1px solid var(--line);border-radius:8px;padding:12px}.stat b{display:block;font-size:20px}.stat span{font-size:10px;color:var(--muted);text-transform:uppercase}.box{background:var(--soft);border:1px solid var(--line);border-radius:8px;padding:14px;margin:12px 0}.callout{border-left:4px solid var(--blue);background:#eff6ff;padding:12px 15px;margin:12px 0}.danger{border-left-color:var(--red);background:#fff1f0}.success{border-left-color:var(--green);background:#ecfdf3}
  table{border-collapse:collapse;width:100%;font-size:11px;margin:8px 0 18px;page-break-inside:auto}thead{display:table-header-group}tr{page-break-inside:avoid;page-break-after:auto}td,th{border:1px solid var(--line);padding:6px 7px;text-align:left;vertical-align:top}th{background:#eaecf0;font-size:10px;text-transform:uppercase}code{font:10px Consolas,monospace;word-break:break-all}.hash{background:#f8f9fc;padding:8px;border:1px solid var(--line);border-radius:5px}.footer{margin-top:35px;border-top:1px solid var(--line);padding-top:14px;color:var(--muted);font-size:10px}.signature{margin-top:42px;display:flex;justify-content:space-between}
  @page{size:A4;margin:13mm}@media print{body{padding:0;max-width:none}.actions{display:none}.box,.callout,.stat{break-inside:avoid}.signature{page-break-inside:avoid}h2{page-break-after:avoid}}@media(max-width:700px){body{padding:18px}.grid{grid-template-columns:repeat(2,1fr)}header{display:block}.meta{text-align:left;margin-top:12px}.signature{display:block}.signature span{display:block;margin-top:16px}}
  </style></head><body>
  <header><div><div class=brand>TamperGuard</div><div class=subtitle>Standalone Log Tampering Forensics Workspace</div></div><div class=meta>CASE ${esc(sourceId())}<br>Generated ${esc(generated)}<br>Examiner ${esc(who(req))}</div></header>
  <div class=actions><button class=btn onclick="window.print()">Print / Save as PDF</button><button class=btn onclick="window.close()">Close</button></div>
  <h1>Forensic Log Integrity & Attack Report</h1>
  <p>This report records the evidence examination performed by TamperGuard for the authenticated account. It combines the Suricata log hash chain, verification results, live-source state, tamper alerts, classified traffic, and chain-of-custody activity.</p>
  <div class=status>${esc(reportStatus)}<small>${esc(statusDescription)} ${last ? `${last.lines_checked || 0} lines and ${last.events_checked || 0} classified events were checked; ${last.issues || 0} issue(s) were recorded.` : 'Run Verify evidence chain to create the first formal examination.'}</small></div>
  <div class=grid><div class=stat><span>Evidence source</span><b>${esc(sourceId())}</b></div><div class=stat><span>Total lines chained</span><b>${source.last_line || st.last_line || 0}</b></div><div class=stat><span>Attack findings</span><b>${attacks.length}</b></div><div class=stat><span>Live state</span><b>${connection}</b></div><div class=stat><span>Retained events</span><b>${events.length}</b></div><div class=stat><span>Web events</span><b>${counts.web || 0}</b></div><div class=stat><span>Email events</span><b>${counts.email || 0}</b></div><div class=stat><span>Security events</span><b>${counts.security || 0}</b></div></div>
  <h2>1. Case and evidence details</h2><div class=box><b>Evidence path:</b> ${esc(EVE_PATH)}<br><b>Authenticated examiner:</b> ${esc(who(req))}<br><b>Account evidence namespace:</b> ${esc(sourceId())}<br><b>Report generated:</b> ${esc(generated)}<br><b>Suricata connection:</b> ${esc(connection)}<br><b>Last file change:</b> ${esc(stat.lastChanged || '-')}<br><b>Last observed event:</b> ${esc(stat.lastEvent || '-')}<br><b>Current file size:</b> ${stat.fileSize || 0} bytes</div>
  <h2>2. Attack and tampering assessment</h2>${attacks.length ? `<div class="callout danger"><b>${attacks.length} attack-related finding(s) recorded.</b><br>The findings below indicate log modification, insertion, deletion, truncation, a synthetic tampering marker, or another integrity exception. Preserve the original evidence file, do not overwrite it, and export this report with the relevant alert timestamps.</div><table><tr><th>Detected</th><th>Severity</th><th>Finding</th><th>Line</th><th>Technical detail</th></tr>${attacks.map(a => tr([a.detected_at, a.severity, a.kind, a.line_no, a.detail])).join('')}</table>` : `<div class="callout success"><b>No attack-related tamper finding is recorded in this account.</b><br>Normal security traffic may still be present, but no stored integrity alert matched the tampering categories used by this report.</div>`}
  <h2>3. Email security findings</h2><div class=box><b>Email metadata findings:</b> ${emailThreats.length}<br><b>Scope:</b> SMTP metadata only; message bodies and attachments are not stored by TamperGuard.</div><table><tr><th>Detected</th><th>Severity</th><th>Line</th><th>Finding</th><th>Details</th></tr>${rows(emailThreats.map(a => [a.detected_at, a.severity, a.line_no, a.kind, a.detail]), 'No suspicious email metadata detected', 5)}</table>
  <h2>4. Traffic and event profile</h2><div class=box><b>Retained classified events:</b> ${events.length}<br><b>Categories:</b> web ${counts.web || 0}, email ${counts.email || 0}, security ${counts.security || 0}<br><b>Event types:</b> ${esc(Object.entries(counts.types).map(([k, v]) => `${k} (${v})`).join(', ') || 'None')}</div><table><tr><th>Line</th><th>Time</th><th>Category</th><th>Type</th><th>Host</th><th>Source</th><th>Destination</th><th>Integrity</th></tr>${rows(events.slice(0, 100).reverse().map(e => [e.line_no, e.ts || '-', e.category, e.event_type, e.host || '-', e.src_ip || '-', e.dest_ip || '-', e.status || 'ok']), 'No retained classified events', 8)}</table>
  <h2>5. Examination methodology</h2><p>Every evidence line is hashed with SHA-256 and linked into a sequential chain using <code>chain_n = SHA256(chain_(n-1) + SHA256(line_n))</code>. Verification re-reads the configured file and compares line hashes, positions, chain continuity, line counts, and the recorded chain head. This identifies modified content, inserted lines, removed lines, reordering, truncation, and chain-head mismatch. The live monitor separately watches only newly appended records and flags malformed JSON, timestamp reversal, file shrinkage, and the explicit demonstration marker. Email security uses explainable SMTP metadata rules and never stores message bodies in this module.</p>
  <h2>6. Cryptographic evidence</h2><div class=box><b>Hash algorithm:</b> SHA-256<br><b>Event-detail retention:</b> newest ${MAX_STORED_EVENTS} classified events<br><b>Genesis hash:</b> <code>${GENESIS}</code><br><b>Recorded chain head at line ${source.last_line || st.last_line || 0}:</b><div class=hash><code>${esc(source.last_chain || st.last_chain || GENESIS)}</code></div></div>
  <h2>7. Verification history</h2><table><tr><th>ID</th><th>Started</th><th>Finished</th><th>Status</th><th>Lines</th><th>Events</th><th>Issues</th><th>Actor</th></tr>${rows(vs.data.map(a => [a.id, a.started_at, a.finished_at || '-', a.status, a.lines_checked || 0, a.events_checked || 0, a.issues || 0, a.actor]), 'No verification runs', 8)}</table>
  <h2>8. Complete integrity alert register</h2><table><tr><th>Detected</th><th>Severity</th><th>Finding</th><th>Line</th><th>Details</th></tr>${rows(al.data.map(a => [a.detected_at, a.severity, a.kind, a.line_no, a.detail]), 'No integrity alerts recorded', 5)}</table>
  <h2>9. Chain of custody</h2><table><tr><th>Time</th><th>Actor</th><th>Action</th><th>Detail</th></tr>${rows(cu.data.map(a => [a.at, a.actor, a.action, a.detail]), 'No custody records', 4)}</table>
  <h2>10. Examiner response guidance</h2><div class=callout><b>If an attack finding is present:</b> keep the original Suricata file unchanged, record the host and time, stop any process that may overwrite the evidence, preserve a backup copy, run Verify evidence chain again after preservation, and attach this PDF with the alert register and chain head.</div>
  <div class=signature><span>Examiner signature: __________________________</span><span>Date: ______________</span></div><div class=footer>TamperGuard standalone forensic report · Account-isolated case ${esc(sourceId())} · Evidence details are retained according to the configured retention policy.</div></body></html>`);
}));

(async () => {
  try { await loadState(); await pruneEvents(); await clearNoisyAlerts(); await custody('SYSTEM', 'SERVICE_START', `watching ${EVE_PATH}; retaining newest ${MAX_STORED_EVENTS} classified events`); } catch (e) { console.error('Startup failed - check Supabase URL/key and that supabase_schema.sql was run:\n', e.message); process.exit(1); }
  app.listen(PORT, () => console.log(`TamperGuard running at http://localhost:${PORT}`));
  setInterval(ingestOnce, POLL_MS); ingestOnce();
  setInterval(() => verify('SYSTEM').catch(e => console.error('verify:', e.message)), VERIFY_MS);
})();
