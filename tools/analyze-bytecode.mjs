
import fs from 'node:fs';
import path from 'node:path';

const OUT = path.resolve('dump');
const bc = JSON.parse(fs.readFileSync(path.join(OUT, 'bytecode.json'), 'utf8'));
const prog = bc[0]?.ints || [];
console.log(`[an] program: ${prog.length} ints (base f=${bc[0]?.f}, alphabet len=${bc[0]?.vLen})`);

let min = Infinity, max = -Infinity, neg = 0;
const small = new Map();
for (const n of prog) {
  if (n < min) min = n; if (n > max) max = n; if (n < 0) neg++;
  if (n >= 0 && n <= 255) small.set(n, (small.get(n) || 0) + 1);
}
console.log(`[an] range: min=${min} max=${max} negatives=${neg}`);
const topSmall = [...small.entries()].sort((a, b) => b[1] - a[1]).slice(0, 25);
console.log('[an] most frequent 0..255 values (opcode candidates):');
console.log('   ', topSmall.map(([v, c]) => `${v}x${c}`).join('  '));

const runs = [];
let cur = '';
for (const n of prog) {
  if (n >= 32 && n <= 126) cur += String.fromCharCode(n);
  else { if (cur.length >= 3) runs.push(cur); cur = ''; }
}
if (cur.length >= 3) runs.push(cur);
const uniq = [...new Set(runs)];
fs.writeFileSync(path.join(OUT, 'embedded-strings.txt'), uniq.join('\n'), 'utf8');
console.log(`\n[an] embedded ASCII runs (len>=3): ${runs.length} total, ${uniq.length} unique -> dump/embedded-strings.txt`);

const RE = /tl|mfc|\bfp\b|kpsdk|webdriver|canvas|navigator|chrome|automation|headless|phantom|configure|integrity|toString|debugger|cookie|userAgent|plugin|stack|eval|webgl|notification|x-kpsdk|149e|2d206a|secureserver|\/v1\/|login|Function|prototype|performance|hardware|languages|screen|timezone|appVersion|vendor|product|spoof|emit|ready/i;
const hits = uniq.filter((s) => RE.test(s));
console.log(`\n[an] INTERESTING embedded strings (${hits.length}):`);
for (const s of hits.slice(0, 120)) console.log('   ·', JSON.stringify(s.slice(0, 140)));

const longest = [...uniq].sort((a, b) => b.length - a.length).slice(0, 25);
console.log('\n[an] LONGEST embedded strings:');
for (const s of longest) console.log('   ·', JSON.stringify(s.slice(0, 160)));
