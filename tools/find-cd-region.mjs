
import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';

const HERE = path.dirname(url.fileURLToPath(import.meta.url));
const OUT = path.join(HERE, '..', 'dump');
const bc = JSON.parse(fs.readFileSync(path.join(OUT, 'bytecode.json'), 'utf8'));
const P = bc[0]?.ints || [];
const K = bc[0]?.f ?? 41;
const N = P.length;
console.log(`[cd] program: ${N} ints  (base K=${K}, alphabet len=${bc[0]?.vLen})`);

const decChar = (s) => (((s & 0xffffffc0) >>> 0) | ((K * s) & 63)) >>> 0;
const isPrintable = (c) => c >= 9 && c <= 126;

function tryString(i, maxLen = 256) {
  const a = P[i];
  if (!Number.isInteger(a) || a < 1 || a > maxLen) return null;
  if (i + a >= N) return null;
  let s = '';
  for (let k = 0; k < a; k++) {
    const code = decChar(P[i + 1 + k]);
    if (!isPrintable(code)) return null;
    s += String.fromCharCode(code);
  }
  return { str: s, end: i + a };
}

const POW_TERMS = [
  'tp-v2-input', 'tp-v2', 'answers', 'workTime', 'duration', 'digest',
  'dynamicConfig', 'validUntil', 'difficulty', 'nonce', 'seqNum', 'marker',
  'featureFlags', 'JS_SHA25', 'sha25', 'sha22', 'createHash', 'finalize',
  'hashedstack', 'hash', 'interrogation', 'x-kpsdk-cd', 'kpsdkCd',
  'getRandomValues', 'crypto', 'setUint32', 'DataView', 'workAround',
  'serverTime', 'clientTime', 'timings', 'attempts', 'Challenge',
];
const strHits = [];
for (let i = 0; i < N; i++) {
  const r = tryString(i, 200);
  if (!r) continue;
  if (r.str.length < 3) continue;

  const wordish = (r.str.match(/[A-Za-z0-9_\-:.\/]/g) || []).length;
  if (wordish / r.str.length < 0.7) continue;
  strHits.push({ at: i, end: r.end, len: r.str.length, str: r.str });
}
console.log(`[cd] decodable string-operands found (len>=3, wordish): ${strHits.length}`);

const decoded = new Array(N).fill(null);
for (let i = 0; i < N; i++) {
  const c = decChar(P[i]);
  if (c >= 32 && c <= 126) decoded[i] = String.fromCharCode(c);
}

const runs = [];
{
  let s = -1;
  for (let i = 0; i <= N; i++) {
    if (i < N && decoded[i] !== null) { if (s < 0) s = i; }
    else { if (s >= 0 && i - s >= 8) runs.push({ start: s, end: i - 1, text: decoded.slice(s, i).join('') }); s = -1; }
  }
}
console.log(`[cd] contiguous printable runs (>=8): ${runs.length}`);
const biggest = [...runs].sort((a, b) => (b.end - b.start) - (a.end - a.start)).slice(0, 6);
console.log('[cd] largest string-pool segments:');
for (const r of biggest) console.log(`   ints[${r.start}..${r.end}] (${r.end - r.start + 1} chars)`);

console.log('\n[cd] ==== (a) PoW / crypto STRING locations (exact int offset of first byte) ====');
const powLocs = [];
for (const term of POW_TERMS) {
  let found = false;
  for (const r of runs) {
    let idx = r.text.indexOf(term);
    while (idx >= 0) {
      const at = r.start + idx;
      powLocs.push({ term, at, str: r.text.slice(idx, idx + Math.min(term.length + 24, 60)) });
      found = true;
      idx = r.text.indexOf(term, idx + 1);
    }
  }
  if (found) {
    const locs = powLocs.filter((p) => p.term === term);
    console.log(`   ${term.padEnd(16)} ${locs.length}x @ ${locs.map((l) => l.at).join(', ')}`);
    console.log(`        ctx: "${locs[0].str.replace(/\n/g, ' ')}"`);
  } else {
    console.log(`   ${term.padEnd(16)} NOT FOUND as a contiguous decoded run`);
  }
}

function decodeDoubleAt(i) {

  const iHi = P[i] | 0, lo = P[i + 1] | 0;
  const e = (0x80000000 & iHi) ? -1 : 1;
  const u = (0x7ff00000 & iHi) >> 20;
  let f = (0xfffff & iHi) * 2 ** 32 + (lo < 0 ? lo + 2 ** 32 : lo);
  if (u === 2047) return f ? NaN : e * Infinity;
  if (u !== 0) { f += 2 ** 52; return e * f * 2 ** (u - 1075); }
  return e * f * 2 ** (1 - 1075);
}
const MAGIC = new Set([
  4503599627370496,
  9007199254740992,
  281474976710656,
  13, 5, 6, 7, 8,
  64, 32,
]);
console.log('\n[cd] ==== (b) BIG / MAGIC numeric constants ====');
const constHits = [];

for (let i = 0; i + 2 < N; i++) {
  if (P[i] === 4) {
    const v = decodeDoubleAt(i + 1);
    if (Number.isFinite(v) && MAGIC.has(v)) {
      constHits.push({ kind: 'double', at: i, val: v });
    }
  }
}

for (let i = 0; i < N; i++) {
  const r = P[i];
  if ((r & 1) === 1) {
    const v = r >> 1;
    if (MAGIC.has(v) && v >= 13) constHits.push({ kind: 'int', at: i, val: v });
  }

  if (P[i] === 4503599627370496) constHits.push({ kind: 'raw', at: i, val: P[i] });
}
const byVal = new Map();
for (const c of constHits) {
  const k = `${c.kind}:${c.val}`;
  if (!byVal.has(k)) byVal.set(k, []);
  byVal.get(k).push(c.at);
}
for (const [k, ats] of [...byVal.entries()].sort()) {
  console.log(`   ${k.padEnd(22)} ${ats.length}x @ ${ats.slice(0, 12).join(',')}${ats.length > 12 ? '...' : ''}`);
}
if (!constHits.length) console.log('   (none of the exact magic doubles found as aligned operands - see notes)');

const SHA_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
const SHA_H = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const valIndex = new Map();
function note(v, at) {
  if (!valIndex.has(v)) valIndex.set(v, []);
  valIndex.get(v).push(at);
}
for (let i = 0; i < N; i++) {
  const r = P[i];
  note(r >>> 0, i);
  if ((r & 1) === 1) note((r >> 1) >>> 0, i);
}
console.log('\n[cd] ==== (c) SHA-256 round-constant K[] presence ====');
let kFound = 0;
const kPositions = [];
for (const k of SHA_K) {
  const ats = valIndex.get(k >>> 0);
  if (ats && ats.length) { kFound++; kPositions.push(...ats); }
}
let hFound = 0;
const hPositions = [];
for (const h of SHA_H) {
  const ats = valIndex.get(h >>> 0);
  if (ats && ats.length) { hFound++; hPositions.push(...ats); }
}
console.log(`   sha256 K[] constants present as ints: ${kFound}/64`);
console.log(`   sha256 H[] init constants present:    ${hFound}/8`);
if (kFound) {
  const sorted = [...new Set(kPositions)].sort((a, b) => a - b);
  console.log(`   K[] hit positions (min..max): ${sorted[0]} .. ${sorted[sorted.length - 1]} (${sorted.length} hits)`);
  console.log(`   first 16: ${sorted.slice(0, 16).join(',')}`);
}
if (hFound) {
  const sorted = [...new Set(hPositions)].sort((a, b) => a - b);
  console.log(`   H[] hit positions: ${sorted.join(',')}`);
}

let bestRun = { len: 0, at: -1, stride: 0 };
for (let stride = 1; stride <= 2; stride++) {
  for (let i = 0; i + 2 < N; i++) {

    const v0 = (P[i] & 1) ? (P[i] >> 1) >>> 0 : P[i] >>> 0;
    if (v0 !== (SHA_K[0] >>> 0) && v0 !== (SHA_K[0] >> 1 >>> 0)) continue;
    let j = 0, k = i;
    while (j < 64 && k < N) {
      const v = (P[k] & 1) ? (P[k] >> 1) >>> 0 : P[k] >>> 0;
      if (v === (SHA_K[j] >>> 0)) { j++; k += stride; }
      else break;
    }
    if (j > bestRun.len) bestRun = { len: j, at: i, stride };
  }
}
console.log(`   longest in-order K[] run: ${bestRun.len}/64 ${bestRun.len ? `starting @${bestRun.at} (stride ${bestRun.stride})` : ''}`);

console.log('\n[cd] ==== REGION ESTIMATE (clustering PoW string indices) ====');
const anchors = powLocs
  .filter((p) => ['tp-v2-input', 'workTime', 'answers', 'duration', 'digest', 'JS_SHA25', 'sha25', 'validUntil', 'dynamicConfig', 'kpsdkCd', 'x-kpsdk-cd'].includes(p.term))
  .map((p) => p.at)
  .sort((a, b) => a - b);
if (anchors.length) {

  const GAP = 4000;
  const clusters = [];
  let cur = [anchors[0]];
  for (let i = 1; i < anchors.length; i++) {
    if (anchors[i] - anchors[i - 1] <= GAP) cur.push(anchors[i]);
    else { clusters.push(cur); cur = [anchors[i]]; }
  }
  clusters.push(cur);
  for (const c of clusters) {
    console.log(`   region ints[${c[0]} .. ${c[c.length - 1]}]  (${c.length} PoW anchors, span ${c[c.length - 1] - c[0]})`);
  }
  console.log(`   tp-v2-input anchor(s): ${powLocs.filter(p => p.term === 'tp-v2-input').map(p => p.at).join(', ') || '(none - see notes)'}`);
} else {
  console.log('   (no PoW string anchors decoded as length-prefixed operands - they may be split across helpers; see notes)');
}

const artifact = {
  programLen: N,
  base: K,
  powStringLocations: powLocs,
  bigConstHits: constHits,
  sha256: {
    kFound, hFound,
    kPositions: [...new Set(kPositions)].sort((a, b) => a - b).slice(0, 200),
    hPositions: [...new Set(hPositions)].sort((a, b) => a - b),
  },
};
fs.writeFileSync(path.join(OUT, 'cd-region.json'), JSON.stringify(artifact, null, 2), 'utf8');
console.log('\n[cd] wrote dump/cd-region.json');
