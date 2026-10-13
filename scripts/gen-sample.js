// Generates a realistic sample eve.json for demo only. Use --live to keep appending.
require('dotenv').config(); const fs = require('fs');
const P = process.env.DEMO_EVE_PATH || './demo-eve.json', live = process.argv.includes('--live'), n = +process.argv[2] || 300;
const web = ['www.google.com', 'github.com', 'news.ycombinator.com', 'cdn.jsdelivr.net', 'stackoverflow.com'], mail = ['smtp.gmail.com', 'imap.gmail.com', 'outlook.office365.com', 'smtp.mail.yahoo.com'];
const pick = a => a[Math.floor(Math.random() * a.length)], base = { src_ip: '192.168.1.23', src_port: 50000, dest_ip: '142.250.77.4', dest_port: 443, proto: 'TCP' };
function ev() {
  const r = Math.random(), t = new Date().toISOString().replace('Z', '+0000'), f = { timestamp: t, flow_id: Math.floor(Math.random() * 1e15), ...base, src_port: 49000 + Math.floor(Math.random() * 9000) };
  if (r < 0.15) return { ...f, event_type: 'stats', stats: { uptime: 100 } };
  if (r < 0.30) return { ...f, event_type: 'flow', flow: { pkts_toserver: 5 } };
  if (r < 0.50) return { ...f, event_type: 'dns', dns: { type: 'query', rrname: pick([...web, ...mail]), rrtype: 'A' } };
  if (r < 0.70) return { ...f, event_type: 'tls', app_proto: 'tls', tls: { sni: pick([...web, ...mail]), version: 'TLS 1.3' } };
  if (r < 0.85) return { ...f, dest_port: 80, event_type: 'http', app_proto: 'http', http: { hostname: pick(web), url: '/index.html', http_method: 'GET', status: 200 } };
  if (r < 0.93) return { ...f, dest_port: 587, event_type: 'smtp', app_proto: 'smtp', smtp: { helo: 'laptop', mail_from: '<me@example.com>', rcpt_to: ['<friend@example.com>'] } };
  return { ...f, event_type: 'alert', app_proto: 'http', alert: { signature: 'ET POLICY Suspicious User-Agent', severity: 2 } };
}
if (!live) { fs.writeFileSync(P, Array.from({ length: n }, () => JSON.stringify(ev())).join('\n') + '\n'); console.log(`Wrote ${n} lines to ${P}`); }
else { console.log('Appending to', P); setInterval(() => fs.appendFileSync(P, JSON.stringify(ev()) + '\n'), 1000); }
