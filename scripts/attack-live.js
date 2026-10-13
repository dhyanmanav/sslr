// Demo only: modify one existing eve.json line in place while Suricata keeps running.
// This preserves the line length and avoids replacing/truncating the live evidence file.
require('dotenv').config();
const fs = require('fs'), crypto = require('crypto');

const P = process.env.EVE_PATH, lineNo = +(process.argv[2] || 20);
if (!P) throw new Error('EVE_PATH is not configured');
if (!Number.isInteger(lineNo) || lineNo < 1) throw new Error('Usage: node scripts/attack-live.js <line-number>');

const data = fs.readFileSync(P);
const lines = [], newline = 10;
for (let start = 0, i = 1; start < data.length; i++) {
  const end = data.indexOf(newline, start);
  const stop = end === -1 ? data.length : end;
  lines.push({ number: i, start, end: stop });
  if (end === -1) break;
  start = end + 1;
}
const target = lines[lineNo - 1];
if (!target) throw new Error(`Line ${lineNo} does not exist in ${P}`);

const original = data.subarray(target.start, target.end).toString('utf8');
let forged = original;
const replacements = [
  [/"src_ip":"([^"]+)"/, (m, v) => `"src_ip":"${'10.0.0.1'.padEnd(v.length, '0').slice(0, v.length)}"`],
  [/"dest_ip":"([^"]+)"/, (m, v) => `"dest_ip":"${'10.0.0.2'.padEnd(v.length, '0').slice(0, v.length)}"`],
  [/"hostname":"([^"]+)"/, (m, v) => `"hostname":"${'tampered.local'.padEnd(v.length, 'x').slice(0, v.length)}"`],
  [/"sni":"([^"]+)"/, (m, v) => `"sni":"${'tampered.local'.padEnd(v.length, 'x').slice(0, v.length)}"`],
  [/"rrname":"([^"]+)"/, (m, v) => `"rrname":"${'tampered.local'.padEnd(v.length, 'x').slice(0, v.length)}"`]
];
for (const [pattern, replacement] of replacements) {
  if (pattern.test(forged)) {
    forged = forged.replace(pattern, replacement);
    break;
  }
}
if (forged === original) {
  const digest = crypto.createHash('sha256').update(original).digest('hex');
  forged = original.slice(0, -1) + (original.endsWith('0') ? '1' : '0');
  if (Buffer.byteLength(forged) !== Buffer.byteLength(original)) throw new Error(`Could not create a same-length change for line ${lineNo}`);
  console.log(`No target field found; changed final byte of line hash ${digest.slice(0, 12)}…`);
}

const replacement = Buffer.from(forged);
const originalBytes = data.subarray(target.start, target.end);
if (replacement.length !== originalBytes.length) throw new Error('Refusing to change line length in a live log');

let fd;
try {
  fd = fs.openSync(P, 'r+');
} catch (e) {
  if (e.code === 'EPERM' || e.code === 'EACCES') {
    throw new Error(
      `Windows denied write access to ${P}. ` +
      'Run this command from an Administrator PowerShell. ' +
      'If it still fails, Suricata has opened the file without write sharing; ' +
      'configure EVE_PATH outside Program Files (for example C:\\Suricata\\log\\eve.json) ' +
      'or use the non-live demo after stopping Suricata.'
    );
  }
  throw e;
}
try { fs.writeSync(fd, replacement, 0, replacement.length, target.start); fs.fsyncSync(fd); }
finally { fs.closeSync(fd); }
console.log(`Live tamper simulated at line ${lineNo}: modified in place while Suricata can continue running.`);
