// DEMO ONLY: simulate an attacker editing the log.  node scripts/tamper.js modify|delete|insert|truncate [line]
require('dotenv').config(); const fs = require('fs');
const P = process.env.DEMO_EVE_PATH || './demo-eve.json', [mode = 'modify', ln = 20] = process.argv.slice(2), L = fs.readFileSync(P, 'utf8').split('\n'), i = +ln - 1;
if (mode === 'modify') L[i] = L[i].replace(/"(src_ip|dest_ip)":"[^"]+"/, '"$1":"10.0.0.1"').replace(/"hostname":"[^"]+"/, '"hostname":"example.org"').replace(/"sni":"[^"]+"/, '"sni":"example.org"').replace(/"rrname":"[^"]+"/, '"rrname":"example.org"');
else if (mode === 'delete') L.splice(i, 1);
else if (mode === 'insert') L.splice(i, 0, JSON.stringify({ timestamp: new Date().toISOString(), event_type: 'http', app_proto: 'http', http: { hostname: 'forged.example', url: '/', http_method: 'GET', status: 200 } }));
else if (mode === 'truncate') L.splice(-21, 20);
fs.writeFileSync(P, L.join('\n')); console.log(`Tamper simulated: ${mode} at line ${ln}`);
