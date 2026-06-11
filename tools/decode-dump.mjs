
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { Window } from 'happy-dom';

const PJS = process.argv[2] || path.resolve('../_vm-traces/2026-05-29T11-03-38-285Z/p.js');
const OUT = path.resolve('dump');
fs.mkdirSync(OUT, { recursive: true });
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36';
const ORIGIN = 'https://sso.secureserver.net';
const PJS_URL = `${ORIGIN}/149e9513-01fa-4fb0-aad4-566afd725d1b/2d206a39-8ed7-437e-a3be-862e0f06eea3/p.js`;

let src = fs.readFileSync(PJS, 'utf8');
console.log(`[dump] p.js: ${PJS} (${src.length} bytes)`);

const ANCHOR = 't*=a}return p}';
if (!src.includes(ANCHOR)) {
  console.error('[dump] FATAL: decoder anchor not found - p.js structure changed. Re-inspect the head of p.js.');
  process.exit(1);
}
src = src.replace(ANCHOR, 't*=a}try{__teeA&&__teeA(v,f,p)}catch(e){}return p}');
console.log('[dump] decoder patched (tee installed).');

const calls = [];
const teeFn = (v, f, p) => {

  let ascii = '';
  let printable = p.length > 0;
  for (const n of p) {
    if (n >= 9 && n <= 126) ascii += String.fromCharCode(n);
    else { printable = false; break; }
  }
  calls.push({ vLen: v?.length, f, outLen: p.length, ascii: printable ? ascii : null, ints: Array.from(p) });
};

const hd = new Window({ url: PJS_URL, settings: { disableJavaScriptEvaluation: true } });
try { Object.defineProperty(hd.navigator, 'userAgent', { value: UA, configurable: true }); } catch {}

const ctxTarget = hd.window;
ctxTarget.fetch = () => Promise.resolve(new hd.Response('{}', { status: 200 }));
class FakeXHR { open(){} setRequestHeader(){} send(){ this.status=200; this.responseText='{}'; this.readyState=4; try{this.onreadystatechange&&this.onreadystatechange()}catch{} } addEventListener(){} getAllResponseHeaders(){return ''} }
ctxTarget.XMLHttpRequest = FakeXHR;
for (const name of ['Proxy','Reflect','WeakMap','WeakSet','WeakRef','Symbol','BigInt','Promise','Map','Set','ArrayBuffer','SharedArrayBuffer','DataView','Atomics','Int8Array','Uint8Array','Uint8ClampedArray','Int16Array','Uint16Array','Int32Array','Uint32Array','Float32Array','Float64Array','BigInt64Array','BigUint64Array','Intl','RegExp','Date','Error','Function','globalThis']) {
  if (ctxTarget[name] === undefined && globalThis[name] !== undefined) { try { ctxTarget[name] = globalThis[name]; } catch {} }
}
try {
  const s = hd.document.createElement('script'); s.src = PJS_URL; hd.document.head.appendChild(s);
  Object.defineProperty(hd.document, 'currentScript', { get: () => s, configurable: true });
} catch {}

const BIND = new Set(['setTimeout','clearTimeout','setInterval','clearInterval','addEventListener','removeEventListener','dispatchEvent','queueMicrotask','atob','btoa','postMessage','requestAnimationFrame']);
const overrides = { __teeA: teeFn, fetch: ctxTarget.fetch, XMLHttpRequest: FakeXHR, console: { log(){}, warn(){}, error(){}, info(){}, debug(){} } };
let proxyObj;
const handler = {
  get(t, p) {
    if (p in overrides) return overrides[p];
    if (p === 'window' || p === 'self' || p === 'globalThis' || p === 'top' || p === 'parent') return proxyObj;
    if (p in t) { const v = t[p]; return (typeof v === 'function' && BIND.has(p)) ? v.bind(t) : v; }
    return undefined;
  },
  set(t, p, v) { t[p] = v; return true; },
  has() { return true; },
};
proxyObj = new Proxy(ctxTarget, handler);
const context = vm.createContext(proxyObj);

console.log('[dump] running patched p.js ...');
try { vm.runInContext(src, context, { filename: 'p.js', timeout: 10000 }); }
catch (e) { console.log('[dump] run error (often fine - data already decoded):', e?.name, String(e?.message).slice(0, 120)); }
await new Promise((r) => setTimeout(r, 1500));

const strings = calls.filter((c) => c.ascii && c.ascii.length >= 2).map((c) => c.ascii);
const uniqStrings = [...new Set(strings)];
const bytecode = calls.filter((c) => !c.ascii && c.outLen > 4).map((c) => ({ vLen: c.vLen, f: c.f, outLen: c.outLen, ints: c.ints }));

fs.writeFileSync(path.join(OUT, 'A-calls.json'), JSON.stringify(calls.map((c) => ({ ...c, ints: c.ints.length > 200 ? c.ints.slice(0, 200) : c.ints })), null, 1));
fs.writeFileSync(path.join(OUT, 'strings.txt'), uniqStrings.join('\n'), 'utf8');
fs.writeFileSync(path.join(OUT, 'bytecode.json'), JSON.stringify(bytecode, null, 1));

console.log('\n========== DECODE DUMP ==========');
console.log('decoder calls:', calls.length);
console.log('ASCII strings:', strings.length, `(${uniqStrings.length} unique) -> dump/strings.txt`);
console.log('bytecode-ish arrays:', bytecode.length, `(largest ${Math.max(0, ...bytecode.map((b) => b.outLen))} ints) -> dump/bytecode.json`);
const hits = uniqStrings.filter((s) => /tl|mfc|\bfp\b|kpsdk|webdriver|canvas|navigator|chrome|automation|headless|phantom|configure|integrity|toString|debugger|cookie|userAgent|plugin|stack|Function|eval|callPhantom|webgl|notification/i.test(s));
console.log('\nINTERESTING strings (' + hits.length + '):');
for (const s of hits.slice(0, 100)) console.log('   ·', JSON.stringify(s.slice(0, 120)));
console.log('=================================');
