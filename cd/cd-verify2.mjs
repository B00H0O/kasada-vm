
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';

const __dir = path.dirname(url.fileURLToPath(import.meta.url));
const TRACE_DIR = path.join(__dir, '..', '_vm-traces');
const sha256 = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const difficulty = (h) => 0x10000000000000 / (parseInt(h.slice(0, 13), 16) + 1);

const samples = [];
for (const d of fs.readdirSync(TRACE_DIR)) {
  const dir = path.join(TRACE_DIR, d);
  if (!fs.statSync(dir).isDirectory()) continue;
  const t = JSON.parse(fs.readFileSync(path.join(dir, 'trace.json'), 'utf8'));
  const tl = JSON.parse(fs.readFileSync(path.join(dir, 'tl.json'), 'utf8'));
  const cd = JSON.parse(t.kpsdkHeaders.cd);
  samples.push({
    name: d, cd, st: cd.st, rst: cd.rst, workTime: cd.workTime, d: cd.d, id: cd.id, answers: cd.answers,
    ct: t.kpsdkHeaders.ct, ctReq: tl.reqHeaders['x-kpsdk-ct'], fc: t.kpsdkHeaders.fc, h: t.kpsdkHeaders.h,
    r: tl.resHeaders['x-kpsdk-r'], domain: 'sso.secureserver.net',
  });
}

console.log('--- x-kpsdk-r decode ---');
for (const s of samples) {
  const tail = s.r.split('-')[1];
  let b64 = '';
  try { b64 = Buffer.from(tail.replace(/_/g, '/').replace(/-/g, '+'), 'base64').toString('hex'); } catch {}
  console.log(`  r=${s.r}  tail="${tail}" b64->hex=${b64}  ct[0..4]=${s.ct.slice(0,5)}`);
}
console.log('');

const fieldVal = (s, f) => ({
  st: String(s.st), rst: String(s.rst), workTime: String(s.workTime), id: s.id,
  ct: s.ct, ctReq: s.ctReq, fc: s.fc, r: s.r, domain: s.domain, d: String(s.d),
  rtail: s.r.split('-')[1] || '',
}[f] ?? '');

function findAnswers(preimage, { rounds = 2, threshold = 5, chain = 'h', t2 = null } = {}) {
  let base = sha256(preimage);
  const answers = [];
  for (let i = 0; i < rounds; i++) {
    const T = (i === 1 && t2 != null) ? t2 : threshold;
    let nonce = 1, won = null;
    for (;;) {
      const h = sha256(`${nonce}, ${base}`);
      if (Math.floor(difficulty(h)) >= T) { won = h; break; }
      nonce++;
      if (nonce > 8000) { won = null; break; }
    }
    if (won == null) { answers.push(-1); break; }
    answers.push(nonce);
    if (chain === 'h') base = won;
    else if (chain === 'answer') base = sha256(`${nonce}, ${base}`);
    else if (chain === 'idx') base = sha256(`${preimage}, ${i + 1}`);
    else if (chain === 'append') base = sha256(`${base}${nonce}`);
  }
  return answers;
}

const SEPS = [', ', ',', ' ', '|', ''];
const ORDERINGS = [
  ['st', 'id'], ['workTime', 'id'], ['st', 'ct', 'id'], ['st', 'ct'], ['ct', 'st'],
  ['st', 'ct', 'fc', 'domain', 'id'], ['st', 'ct', 'fc', 'domain'], ['ct', 'domain'],
  ['st', 'r', 'id'], ['st', 'r'], ['r', 'id'], ['ct', 'rtail'], ['st', 'rtail', 'id'],
  ['st'], ['ct'], ['workTime'], ['st', 'workTime', 'id'], ['workTime', 'st', 'id'],
  ['st', 'd', 'id'], ['st', 'id', 'd'],
];
const THRESHOLDS = [5, 4, 6];
const CHAINS = ['h', 'idx', 'append'];
const T2S = [null, 5, 6, 7, 8];

let best = { count: -1 }, matches = [], combos = 0;
for (const sep of SEPS)
  for (const ordering of ORDERINGS)
    for (const threshold of THRESHOLDS)
      for (const chain of CHAINS)
        for (const t2 of T2S) {
          combos++;
          let cnt = 0; const per = [];
          for (const s of samples) {
            const preimage = ['tp-v2-input', ...ordering.map(f => fieldVal(s, f))].join(sep);
            const ans = findAnswers(preimage, { threshold, chain, t2 });
            const ok = JSON.stringify(ans) === JSON.stringify(s.answers);
            if (ok) cnt++; per.push({ ok, ans });
          }
          if (cnt > best.count) best = { count: cnt, cfg: { sep, ordering, threshold, chain, t2 }, per };
          if (cnt === samples.length) matches.push({ sep, ordering, threshold, chain, t2 });
        }

console.log(`Tried ${combos} configs.`);
if (matches.length) {
  console.log(`[ok][ok][ok] 4/4 MATCH: ${matches.length} config(s)`);
  for (const m of matches) console.log(`  sep="${m.sep}" order=[${m.ordering}] T=${m.threshold} chain=${m.chain} t2=${m.t2}`);
} else {
  console.log(`[fail] NO 4/4. Best=${best.count}/4: sep="${best.cfg.sep}" order=[${best.cfg.ordering}] T=${best.cfg.threshold} chain=${best.cfg.chain} t2=${best.cfg.t2}`);
  best.per.forEach((p, i) => console.log(`   s${i}: want [${samples[i].answers}] got [${p.ans}] ${p.ok ? '[ok]' : ''}`));
}
