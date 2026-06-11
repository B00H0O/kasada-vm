
import fs from 'node:fs';
import path from 'node:path';

const K = 41;
const decodeChar = (code) => (code & ~63) | ((K * (code & 63)) & 63);
function decode(s) {
  let out = '';
  for (const ch of s) {
    const c = ch.charCodeAt(0);
    const p = decodeChar(c);
    out += (p >= 32 && p <= 126) ? String.fromCharCode(p) : ch;
  }
  return out;
}

const MAP = {};
for (let c = 32; c <= 126; c++) { const p = decodeChar(c); if (p >= 32 && p <= 126) MAP[String.fromCharCode(c)] = String.fromCharCode(p); }

const OUT = path.resolve('dump');
const lines = fs.readFileSync(path.join(OUT, 'embedded-strings.txt'), 'utf8').split('\n').filter(Boolean);
const cracked = lines.map((l) => `${decode(l)}   <-   ${l}`);
fs.writeFileSync(path.join(OUT, 'cracked-strings.txt'), cracked.join('\n'), 'utf8');

const allChars = new Set();
for (const l of lines) for (const c of l) if (/[A-Za-z]/.test(c) || '_~]{}|^<>'.includes(c)) allChars.add(c);
const known = [...allChars].filter((c) => c in MAP).length;
console.log(`[crack] alphabet chars seen: ${allChars.size}, mapped: ${known} (${Math.round(100*known/allChars.size)}%)`);
console.log(`[crack] unmapped chars: ${[...allChars].filter((c)=>!(c in MAP)).join(' ')}`);
console.log('[crack] -> dump/cracked-strings.txt\n');

const idx = lines.map((l, i) => [l.length, i]).sort((a, b) => b[0] - a[0]).slice(0, 30);
for (const [, i] of idx) console.log('  ', decode(lines[i]).slice(0, 150));
