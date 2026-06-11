
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const sha256 = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const sha256buf = (b) => crypto.createHash('sha256').update(b).digest('hex');
const hmac = (key, msg) => crypto.createHmac('sha256', key).update(msg, 'utf8').digest('hex');
const difficulty = (h) => 0x10000000000000 / (parseInt(h.slice(0, 13), 16) + 1);

const TR = path.resolve('_vm-traces');
const S = [];
for (const d of fs.readdirSync(TR)) {
  const tf = path.join(TR, d, 'trace.json'), lf = path.join(TR, d, 'tl.json');
  if (!fs.existsSync(tf)) continue;
  try {
    const t = JSON.parse(fs.readFileSync(tf, 'utf8'));
    const cd = JSON.parse(t.kpsdkHeaders.cd);
    const tl = fs.existsSync(lf) ? JSON.parse(fs.readFileSync(lf, 'utf8')) : {};
    const rh = tl.resHeaders || {};
    const qh = tl.reqHeaders || {};
    S.push({
      id: cd.id, st: cd.st, rst: cd.rst, workTime: cd.workTime, d: cd.d, answers: cd.answers,
      duration: cd.duration,
      ct: t.kpsdkHeaders.ct,
      reqct: qh['x-kpsdk-ct'] || null,
      im: qh['x-kpsdk-im'] || null,
      dt: qh['x-kpsdk-dt'] || null,
      r: rh['x-kpsdk-r'] || null,
      serverSt: rh['x-kpsdk-st'] || null,
      h: t.kpsdkHeaders.h,
      fc: t.kpsdkHeaders.fc,
      v: t.kpsdkHeaders.v,
    });
  } catch (e) { console.error('load err', e.message); }
}
console.log(`${S.length} samples loaded:`);
for (const s of S) console.log(`  id=${s.id.slice(0, 10)}... ans=[${s.answers}] st=${s.st} workTime=${s.workTime} r=${s.r}`);
if (S.length !== 4) console.warn('WARNING: expected 4 samples');

function b64decode(str) {
  try { return Buffer.from(str, 'base64'); } catch { return null; }
}
function b64urlDecode(str) {
  try { return Buffer.from(str, 'base64url'); } catch { return null; }
}

function componentsFor(s) {
  const c = {};

  c.st = String(s.st);
  c.rst = String(s.rst);
  c.workTime = String(s.workTime);
  c.d = String(s.d);
  c.duration = String(s.duration);
  c.id = s.id;
  c.serverSt = String(s.serverSt);
  c.v = s.v;
  c.h = s.h;
  c.fc = s.fc;
  c.empty = '';

  c.r = s.r || '';
  c.r0 = (s.r || '').split('-')[0] || '';
  c.r1 = (s.r || '').split('-')[1] || '';

  const ct = s.ct || '';
  c.ct = ct;
  c.ct1 = ct.slice(1);
  c.ct2 = ct.slice(2);
  c.ct16 = ct.slice(0, 16);
  c.ct32 = ct.slice(0, 32);
  c.ct43 = ct.slice(0, 43);
  c.ctTail = ct.slice(-32);
  c.shaCt = sha256(ct);
  c.shaCt1 = sha256(ct.slice(1));

  for (const [tag, str] of [['ct', ct], ['ct1', ct.slice(1)], ['ct2', ct.slice(2)]]) {
    const b = b64decode(str);
    if (b) {
      c['ctB_hex_' + tag] = b.toString('hex');
      c['ctB_sha_' + tag] = sha256buf(b);
      c['ctB_16hex_' + tag] = b.slice(0, 16).toString('hex');
      c['ctB_32hex_' + tag] = b.slice(0, 32).toString('hex');
    }
    const bu = b64urlDecode(str);
    if (bu) c['ctBu_sha_' + tag] = sha256buf(bu);
  }

  const rct = s.reqct || '';
  c.reqct = rct;
  c.reqct1 = rct.slice(1);
  c.reqct32 = rct.slice(0, 32);
  c.shaReqct = sha256(rct);
  { const b = b64decode(rct.slice(1)); if (b) c.reqctB_sha = sha256buf(b); }

  const im = s.im || '';
  c.im = im;
  c.shaIm = sha256(im);
  { const b = b64urlDecode(im); if (b) { c.imB_hex = b.toString('hex'); c.imB_sha = sha256buf(b); c.imB_16hex = b.slice(0, 16).toString('hex'); } }

  c.dt = s.dt || '';
  c.shaDt = sha256(s.dt || '');

  c.shaId = sha256(s.id);
  c.shaSt = sha256(String(s.st));
  c.shaWt = sha256(String(s.workTime));
  c.shaRst = sha256(String(s.rst));
  c.shaR = sha256(s.r || '');

  c.sha2Id = sha256(sha256(s.id));
  c.sha2Ct = sha256(sha256(ct));

  c.st_id = `${s.st}, ${s.id}`;
  c.id_st = `${s.id}, ${s.st}`;
  c.st_id_ct = `${s.st}${s.id}${ct}`;
  c.sha_st_id_ct = sha256(`${s.st}${s.id}${ct}`);
  c.sha_st_id = sha256(`${s.st}${s.id}`);
  c.sha_id_st = sha256(`${s.id}${s.st}`);
  c.sha_ct_id = sha256(`${ct}${s.id}`);
  c.sha_ct_st = sha256(`${ct}${s.st}`);

  const keys = { ct, ct1: ct.slice(1), st: String(s.st), id: s.id, r: s.r || '', im, reqct: rct, serverSt: String(s.serverSt) };
  const msgs = { st: String(s.st), id: s.id, workTime: String(s.workTime), rst: String(s.rst), empty: '', stid: `${s.st}${s.id}`, tp: `tp-v2-input, ${s.st}, ${s.id}` };
  for (const [kn, kv] of Object.entries(keys)) for (const [mn, mv] of Object.entries(msgs)) {
    c[`hmac_${kn}_${mn}`] = hmac(kv, mv);
  }
  return c;
}

const COMP = S.map(componentsFor);
const ALLNAMES = Object.keys(COMP[0]);

const NAMES = ALLNAMES.filter((n) => COMP.every((c) => c[n] !== undefined));
console.log(`\ncomponent pool: ${NAMES.length} candidate values per sample`);

const NONCE_FMTS = {
  'n, base':  (n, base) => `${n}, ${base}`,
  'n,base':   (n, base) => `${n},${base}`,
  'base, n':  (n, base) => `${base}, ${n}`,
  'base,n':   (n, base) => `${base},${n}`,
  'n base':   (n, base) => `${n} ${base}`,
  'basen':    (n, base) => `${base}${n}`,
  'nbase':    (n, base) => `${n}${base}`,
  'shaN, base': (n, base) => `${sha256(String(n))}, ${base}`,
  'base, shaN': (n, base) => `${base}, ${sha256(String(n))}`,
};
const NONCE_FMT_KEYS = Object.keys(NONCE_FMTS);

const MAX_NONCE = 20000;

function ansFor(seedStr, { th, rounds, chain, nonceFmt }) {
  let base = sha256(seedStr);
  const seed0 = base;
  const out = [];
  const fmt = NONCE_FMTS[nonceFmt];
  for (let i = 0; i < rounds; i++) {
    let n = 1;
    for (; n <= MAX_NONCE; n++) {
      const h = sha256(fmt(n, base));
      if (Math.floor(difficulty(h)) >= th) { out.push(n); base = chain ? h : seed0; break; }
    }
    if (n > MAX_NONCE) return null;
  }
  return out;
}

const eq = (a, b) => a && b && a.length === b.length && a.every((x, i) => x === b[i]);

const PATH = '149e9513-01fa-4fb0-aad4-566afd725d1b/2d206a39-8ed7-437e-a3be-862e0f06eea3';
const UUID1 = '149e9513-01fa-4fb0-aad4-566afd725d1b';
const UUID2 = '2d206a39-8ed7-437e-a3be-862e0f06eea3';
const PFX = ['tp-v2-input', 'tp-v2', 'tp', '', PATH, UUID1, UUID2, 'kpsdk'];
const SEPS = [', ', ',', ' ', '', '-', ':', '|'];
const THS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
const NONCE_FMT_TRY = ['n, base', 'n,base', 'base, n', 'base,n', 'shaN, base'];

console.log('\n=== PHASE A: single-component seeds (prefix+sep+comp), all params ===');
let triesA = 0;
const hitsA = [];
for (const name of NAMES) {
  for (const pfx of PFX) {
    for (const sep of SEPS) {
      const mid = pfx ? pfx + sep : '';
      for (const nf of NONCE_FMT_TRY) {
        for (const chain of [true, false]) {
          for (const th of THS) {
            triesA++;
            let ok = true;
            for (let i = 0; i < S.length; i++) {
              const s = S[i];
              const seed = `${mid}${COMP[i][name]}`;
              const a = ansFor(seed, { th, rounds: s.answers.length, chain, nonceFmt: nf });
              if (!eq(a, s.answers)) { ok = false; break; }
            }
            if (ok) hitsA.push({ comp: name, pfx, sep: JSON.stringify(sep), nf, chain, th });
          }
        }
      }
    }
  }
}
console.log(`  PHASE A tries: ${triesA}  hits: ${hitsA.length}`);
for (const h of hitsA.slice(0, 20)) console.log('   [ok]', JSON.stringify(h));

console.log('\n=== PHASE B: two-component seeds (prefix + A + B), focused params ===');
const SCALARS = ['st', 'id', 'workTime', 'rst', 'serverSt', 'r', 'r1', 'd', 'duration', 'empty'];
const SECRETS = NAMES.filter((n) =>
  n.startsWith('sha') || n.startsWith('ctB') || n.startsWith('ctBu') || n.startsWith('imB') ||
  n.startsWith('hmac_') || n.startsWith('reqctB') || ['ct', 'ct1', 'ct32', 'reqct', 'im', 'r1', 'r'].includes(n)
);
const PFX_B = ['tp-v2-input', 'tp-v2', ''];
const SEPS_B = [', ', ',', ''];
const PARAMSETS_B = [
  { th: 5, chain: true, nonceFmt: 'n, base' },
  { th: 5, chain: false, nonceFmt: 'n, base' },
  { th: 5, chain: true, nonceFmt: 'n,base' },
  { th: 4, chain: true, nonceFmt: 'n, base' },
  { th: 6, chain: true, nonceFmt: 'n, base' },
  { th: 3, chain: true, nonceFmt: 'n, base' },
];
let triesB = 0;
const hitsB = [];
for (const a of SCALARS) {
  for (const b of SECRETS) {
    for (const pfx of PFX_B) {
      for (const sep of SEPS_B) {
        for (const ps of PARAMSETS_B) {
          triesB++;
          const mid = pfx ? pfx + sep : '';
          let ok = true;
          for (let i = 0; i < S.length; i++) {
            const s = S[i];
            const seed = `${mid}${COMP[i][a]}${sep}${COMP[i][b]}`;
            const ans = ansFor(seed, { ...ps, rounds: s.answers.length });
            if (!eq(ans, s.answers)) { ok = false; break; }
          }
          if (ok) hitsB.push({ a, b, pfx, sep: JSON.stringify(sep), ...ps });
        }
      }
    }
  }
}
console.log(`  PHASE B tries: ${triesB}  hits: ${hitsB.length}`);
for (const h of hitsB.slice(0, 20)) console.log('   [ok]', JSON.stringify(h));

console.log('\n=== PHASE C: tp-v2-input, st, id (+SECRET inserted) ===');
let triesC = 0;
const hitsC = [];
const POSNS = ['append', 'prepend', 'replace-id', 'replace-st'];
for (const b of SECRETS) {
  for (const pos of POSNS) {
    for (const ps of PARAMSETS_B) {
      triesC++;
      let ok = true;
      for (let i = 0; i < S.length; i++) {
        const s = S[i], c = COMP[i];
        let seed;
        if (pos === 'append') seed = `tp-v2-input, ${s.st}, ${s.id}, ${c[b]}`;
        else if (pos === 'prepend') seed = `tp-v2-input, ${c[b]}, ${s.st}, ${s.id}`;
        else if (pos === 'replace-id') seed = `tp-v2-input, ${s.st}, ${c[b]}`;
        else seed = `tp-v2-input, ${c[b]}, ${s.id}`;
        const ans = ansFor(seed, { ...ps, rounds: s.answers.length });
        if (!eq(ans, s.answers)) { ok = false; break; }
      }
      if (ok) hitsC.push({ secret: b, pos, ...ps });
    }
  }
}
console.log(`  PHASE C tries: ${triesC}  hits: ${hitsC.length}`);
for (const h of hitsC.slice(0, 20)) console.log('   [ok]', JSON.stringify(h));

console.log('\n=== PHASE D: base = component directly (skip seed-sha256) ===');
let triesD = 0;
const hitsD = [];
function ansFromBase(base0, { th, rounds, chain, nonceFmt }) {
  let base = base0; const out = []; const fmt = NONCE_FMTS[nonceFmt];
  for (let i = 0; i < rounds; i++) {
    let n = 1;
    for (; n <= MAX_NONCE; n++) { const h = sha256(fmt(n, base)); if (Math.floor(difficulty(h)) >= th) { out.push(n); base = chain ? h : base0; break; } }
    if (n > MAX_NONCE) return null;
  }
  return out;
}
const HEXISH = NAMES.filter((n) => COMP[0][n] && /^[0-9a-f]+$/i.test(COMP[0][n]) && COMP[0][n].length >= 13);
for (const name of HEXISH) {
  for (const nf of NONCE_FMT_TRY) {
    for (const chain of [true, false]) {
      for (const th of THS) {
        triesD++;
        let ok = true;
        for (let i = 0; i < S.length; i++) {
          const s = S[i];
          const a = ansFromBase(COMP[i][name], { th, rounds: s.answers.length, chain, nonceFmt: nf });
          if (!eq(a, s.answers)) { ok = false; break; }
        }
        if (ok) hitsD.push({ baseComp: name, nf, chain, th });
      }
    }
  }
}
console.log(`  PHASE D tries: ${triesD}  hits: ${hitsD.length}`);
for (const h of hitsD.slice(0, 20)) console.log('   [ok]', JSON.stringify(h));

const total = triesA + triesB + triesC + triesD;
const allHits = [...hitsA.map(h => ({ phase: 'A', ...h })), ...hitsB.map(h => ({ phase: 'B', ...h })),
  ...hitsC.map(h => ({ phase: 'C', ...h })), ...hitsD.map(h => ({ phase: 'D', ...h }))];
console.log(`\n================ SUMMARY ================`);
console.log(`total combos tried: ${total}  (A=${triesA} B=${triesB} C=${triesC} D=${triesD})  x ${S.length} samples`);
if (allHits.length) {
  console.log(`[ok][ok] CRACKED - ${allHits.length} format(s) reproduce ALL ${S.length} samples:`);
  for (const h of allHits) console.log('   ', JSON.stringify(h));
} else {
  console.log('[fail] NO format reproduced all 4 samples. The cd seed mixes an UNCAPTURED VM-internal value.');
}
