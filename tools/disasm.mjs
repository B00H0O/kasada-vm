

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DUMP = join(__dirname, '..', 'dump');

const raw = JSON.parse(readFileSync(join(DUMP, 'bytecode.json'), 'utf8'));
const wrap = Array.isArray(raw) ? raw[0] : raw;
const INTS = wrap.ints || (Array.isArray(raw) ? raw : null);
if (!INTS || !Array.isArray(INTS)) throw new Error('could not find ints[] in bytecode.json');
const N = INTS.length;
console.error(`[disasm] loaded ${N} ints (vLen=${wrap.vLen}, f=${wrap.f})`);

const cipherMap = JSON.parse(readFileSync(join(DUMP, 'cipher-map.json'), 'utf8'));
const K = cipherMap.K ?? 41;
function decodeChar(s) {
  return String.fromCharCode((0xFFFFFFC0 & s) | ((K * (s & 63)) & 63));
}
function printableChar(s) {
  const ch = decodeChar(s);
  const cc = ch.charCodeAt(0);
  return cc >= 32 && cc < 127 ? ch : '.';
}

const TAG = { dbl: 4, str: 6, tru: 8, fal: 10, nul: 12, vod: 14 };

const OPCODE_MAX = 84;
function isOpcode(v) {
  return Number.isInteger(v) && v >= 0 && v <= OPCODE_MAX;
}

const OPHINT = {
  60: 'push_const',
  59: 'store_reg',
  76: 'store/mov',
  75: 'load/get',
  83: 'binop',
  3:  'binop',
  49: 'load_const',
  14: 'return/mark',
  70: 'return/mark',
  81: 'return/mark',
  48: 'new_frame',
  25: 'call',
};

function readDouble(hi, lo) {
  const e = (0x80000000 & hi) ? -1 : 1;
  const u = (0x7FF00000 & hi) >> 20;
  let f = (0xFFFFF & hi) * (2 ** 32) + (lo < 0 ? lo + 2 ** 32 : lo);
  if (u === 2047) return f ? NaN : e * Infinity;
  if (u !== 0) { f += 2 ** 52; return e * f * (2 ** (u - 1075)); }
  return e * f * (2 ** (1 - 1075));
}

function decodeOperand(cur) {
  const r = INTS[cur.ip++];
  if (r === undefined) return { kind: 'eof', repr: '<eof>' };
  if (r & 1) return { kind: 'int', val: r >> 1, repr: '#' + (r >> 1) };
  if (r === TAG.dbl) {
    const hi = INTS[cur.ip++], lo = INTS[cur.ip++];
    const v = readDouble(hi, lo);
    return { kind: 'double', val: v, repr: v + 'd' };
  }
  if (r === TAG.str) {
    const len = INTS[cur.ip++];
    let s = '';
    for (let i = 0; i < len; i++) s += decodeChar(INTS[cur.ip++]);
    const safe = s.replace(/\\/g, '\\\\').replace(/\n/g, '\\n').replace(/"/g, '\\"');
    return { kind: 'string', val: s, repr: `"${safe}"` };
  }
  if (r === TAG.tru) return { kind: 'bool', repr: 'true' };
  if (r === TAG.fal) return { kind: 'bool', repr: 'false' };
  if (r === TAG.nul) return { kind: 'null', repr: 'null' };
  if (r === TAG.vod) return { kind: 'void', repr: 'void0' };
  return { kind: 'reg', val: r >> 5, repr: 'R' + (r >> 5) };
}

function consumeOperand(ip, limit) {
  const r = INTS[ip];
  if (r === undefined) return -1;
  if (r & 1) return ip + 1;
  if (r === TAG.dbl) return ip + 3;
  if (r === TAG.str) {
    const len = INTS[ip + 1];
    if (len < 0 || len > 5000) return -1;
    return ip + 2 + len;
  }
  if (r === TAG.tru || r === TAG.fal || r === TAG.nul || r === TAG.vod) return ip + 1;
  return ip + 1;
}
function stepN(ip, n, limit) {
  let c = ip + 1;
  for (let k = 0; k < n; k++) { c = consumeOperand(c, limit); if (c < 0) return -1; }
  return c;
}

function validateStringPool() {
  let s = '';
  for (let i = 27659; i <= 33015 && i < N; i++) s += decodeChar(INTS[i]);
  const markers = ['tp-v2-input', 'workTime', 'answers', 'duration', 'digest',
    'validUntil', 'x-kpsdk-cd', 'JS_SHA256', 'createHash', 'dynamicConfig', 'seqNum'];
  const found = markers.filter(m => s.includes(m));
  const at = 30115 - 27659;
  return { found, sample: s.slice(at, at + 48) };
}

const CODE_END = 27659;
const ARITY = {};

function deriveArities() {
  for (let op = 0; op <= OPCODE_MAX; op++) ARITY[op] = 2;
  for (let pass = 0; pass < 80; pass++) {
    const occ = {}; for (let op = 0; op <= OPCODE_MAX; op++) occ[op] = [];
    let ip = 1, guard = 0;
    while (ip < CODE_END && guard++ < N * 3) {
      const op = INTS[ip];
      if (!isOpcode(op)) { ip++; continue; }
      occ[op].push(ip);
      const nx = stepN(ip, ARITY[op], CODE_END);
      if (nx < 0 || nx <= ip) { ip++; continue; }
      ip = nx;
    }
    let changed = 0;
    for (let op = 0; op <= OPCODE_MAX; op++) {
      const ips = occ[op]; if (ips.length < 2) continue;
      let best = ARITY[op], bestScore = -Infinity;
      for (let n = 0; n <= 6; n++) {
        let ok = 0, tot = 0;
        for (const s of ips) {
          const e = stepN(s, n, CODE_END);
          if (e < 0) continue; tot++;
          if (e >= CODE_END || isOpcode(INTS[e])) ok++;
        }
        if (!tot) continue;
        const sc = ok / tot - n * 1e-4;
        if (sc > bestScore) { bestScore = sc; best = n; }
      }
      if (best !== ARITY[op]) { ARITY[op] = best; changed++; }
    }
    if (!changed) { console.error(`[disasm] arity fixpoint converged at pass ${pass}`); break; }
  }
}

const POOL_START = 27659, POOL_END = 33015;
function pad(n) { return String(n).padStart(6, ' '); }

const POOL_CHUNK = 96;
function sweep(fromIp, toIp) {
  const lines = [];
  let ip = fromIp, guard = 0, misaligns = 0, instrs = 0;

  let poolRunStart = -1, poolRunText = '';
  const flushPool = () => {
    if (poolRunStart < 0) return;
    for (let off = 0; off < poolRunText.length; off += POOL_CHUNK) {
      const chunk = poolRunText.slice(off, off + POOL_CHUNK);
      const at = poolRunStart + off;
      lines.push(`${pad(at)} .pool    "${chunk.replace(/\\/g, '\\\\').replace(/\n/g, '\\n').replace(/"/g, '\\"')}"`);
    }
    poolRunStart = -1; poolRunText = '';
  };

  while (ip < toIp && guard++ < N * 3) {
    const inPool = ip >= POOL_START && ip < POOL_END;

    if (inPool) {
      if (poolRunStart < 0) poolRunStart = ip;
      poolRunText += printableChar(INTS[ip]);
      ip++;
      continue;
    }
    const op = INTS[ip];
    if (!isOpcode(op)) {
      flushPool();
      lines.push(`${pad(ip)} .data    ${op}\t; '${printableChar(op)}'`);
      misaligns++;
      ip++;
      continue;
    }
    flushPool();
    const n = ARITY[op] ?? 1;
    const cur = { ip: ip + 1 };
    const ops = [];
    let bad = false;
    for (let k = 0; k < n; k++) {
      if (cur.ip >= toIp) { bad = true; break; }
      const o = decodeOperand(cur);
      if (o.kind === 'eof') { bad = true; break; }
      ops.push(o.repr);
    }
    const name = (OPHINT[op] || 'op').padEnd(13);
    lines.push(`${pad(ip)} OP(${String(op).padStart(2)}) ${name} ${ops.join(', ')}`);
    instrs++;
    ip = bad ? ip + 1 : cur.ip;
    if (bad) misaligns++;
  }
  flushPool();
  return { lines, misaligns, instrs };
}

const pool = validateStringPool();
console.error(`[disasm] string-pool markers found: ${pool.found.join(', ')}`);
console.error(`[disasm] tp-v2-input window: ${JSON.stringify(pool.sample)}`);

deriveArities();
const arityStr = Object.keys(ARITY).map(Number).sort((a, b) => a - b)
  .map(o => `${o}:${ARITY[o]}`).join(' ');
console.error(`[disasm] derived arities -> ${arityStr}`);

let _ip = 1, _instr = 0, _mis = 0, _cov = 0;
while (_ip < CODE_END) {
  const op = INTS[_ip];
  if (!isOpcode(op)) { _mis++; _ip++; continue; }
  const nx = stepN(_ip, ARITY[op], CODE_END);
  if (nx < 0 || nx <= _ip) { _mis++; _ip++; continue; }
  _cov += nx - _ip; _instr++; _ip = nx;
}
console.error(`[disasm] code-region coverage: ${_cov}/${CODE_END - 1} ints (${(100 * _cov / (CODE_END - 1)).toFixed(1)}%), ${_instr} instrs, ${_mis} misaligns`);

const header =
  `; Kasada VM linear-sweep disassembly  (p.js j-1.2.430)\n` +
  `; program ints=${N}, decoder base f=${wrap.f}, cipher K=${K}\n` +
  `; operand TAGs: dbl=${TAG.dbl} str=${TAG.str} true=${TAG.tru} false=${TAG.fal} null=${TAG.nul} void=${TAG.vod}\n` +
  `; opcodes: raw int in [0..${OPCODE_MAX}] (odd+even), used as handler-table index\n` +
  `; arities: ${arityStr}\n` +
  `; pool[${POOL_START}..${POOL_END}] rendered as decoded text via cipher K=${K}\n` +
  `; format: <ip> OP(<num>) <name> <operands>   ('#'=int  R#=register  "..."=string  ...d=double)\n` +
  `; ---------------------------------------------------------------------------------------\n`;

const full = sweep(1, N);
writeFileSync(join(DUMP, 'disasm.txt'), header + full.lines.join('\n') + '\n');
console.error(`[disasm] wrote dump/disasm.txt (${full.lines.length} lines, ${full.instrs} instrs, ${full.misaligns} misaligns)`);

const cd = sweep(27000, Math.min(33500, N));
writeFileSync(join(DUMP, 'disasm-cd-region.txt'),
  header.replace('disassembly  (', 'disassembly - cd/PoW region 27000..33500  (') +
  cd.lines.join('\n') + '\n');
console.error(`[disasm] wrote dump/disasm-cd-region.txt (${cd.lines.length} lines, ${cd.instrs} instrs)`);
