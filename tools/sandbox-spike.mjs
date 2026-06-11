
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { Window } from 'happy-dom';

const PJS = process.argv[2] || path.resolve('../_vm-traces/2026-05-29T11-03-38-285Z/p.js');
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36';
const ORIGIN = 'https://sso.secureserver.net';
const PAGE_URL = `${ORIGIN}/149e9513-01fa-4fb0-aad4-566afd725d1b/2d206a39-8ed7-437e-a3be-862e0f06eea3/fp?x-kpsdk-v=j-1.2.430`;

const pjsSrc = fs.readFileSync(PJS, 'utf8');
console.log(`[spike] p.js: ${PJS} (${pjsSrc.length} bytes)`);

const access = new Map();
const sets = new Map();
const missing = new Map();
const net = [];
const errors = [];
let kpsdkSeen = false;

const bump = (m, k) => m.set(k, (m.get(k) || 0) + 1);

const BIND_THESE = new Set([
  'setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'requestAnimationFrame',
  'cancelAnimationFrame', 'addEventListener', 'removeEventListener', 'dispatchEvent',
  'queueMicrotask', 'atob', 'btoa', 'getComputedStyle', 'matchMedia', 'postMessage', 'setImmediate',
]);

const hd = new Window({ url: PAGE_URL, settings: { disableJavaScriptEvaluation: true } });

try {
  Object.defineProperty(hd.navigator, 'userAgent', { value: UA, configurable: true });
  Object.defineProperty(hd.navigator, 'platform', { value: 'Win32', configurable: true });
  Object.defineProperty(hd.navigator, 'hardwareConcurrency', { value: 8, configurable: true });
  Object.defineProperty(hd.navigator, 'language', { value: 'en-US', configurable: true });
} catch (e) {  }

function recordFetch(input, init = {}) {
  const url = typeof input === 'string' ? input : input?.url || String(input);
  const method = (init.method || (typeof input === 'object' && input?.method) || 'GET').toUpperCase();
  const body = init.body;
  net.push({ via: 'fetch', method, url, bodyLen: body ? (body.length ?? body.byteLength ?? null) : null,
             bodyPreview: typeof body === 'string' ? body.slice(0, 120) : (body ? `<${body.constructor?.name}>` : null) });

  return Promise.resolve(new hd.Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
}

class FakeXHR {
  constructor() { this._h = {}; this.readyState = 0; this.status = 0; this.responseText = ''; }
  open(method, url) { this._m = method; this._u = url; this.readyState = 1; }
  setRequestHeader(k, v) { this._h[k] = v; }
  send(body) {
    net.push({ via: 'xhr', method: this._m, url: this._u,
               bodyLen: body ? (body.length ?? body.byteLength ?? null) : null,
               bodyPreview: typeof body === 'string' ? body.slice(0, 120) : (body ? `<${body.constructor?.name}>` : null),
               headers: this._h });

    this.status = 200; this.responseText = '{}'; this.readyState = 4;
    try { this.onreadystatechange && this.onreadystatechange(); } catch (e) { errors.push('xhr.cb: ' + e.message); }
    try { this.onload && this.onload(); } catch {}
  }
  getResponseHeader() { return null; }
  getAllResponseHeaders() { return ''; }
  addEventListener(ev, fn) { if (ev === 'load') this.onload = fn; if (ev === 'readystatechange') this.onreadystatechange = fn; }
}

const PJS_URL = `${ORIGIN}/149e9513-01fa-4fb0-aad4-566afd725d1b/2d206a39-8ed7-437e-a3be-862e0f06eea3/p.js`;
let scriptEl = null;
try {
  scriptEl = hd.document.createElement('script');
  scriptEl.src = PJS_URL;
  scriptEl.setAttribute('src', PJS_URL);
  hd.document.head.appendChild(scriptEl);
  Object.defineProperty(hd.document, 'currentScript', { get: () => scriptEl, configurable: true });
} catch (e) { console.log('[spike] currentScript setup failed:', e.message); }

const hostAccess = new Map();
function wrapHost(name, obj) {
  if (!obj || typeof obj !== 'object') return obj;
  return new Proxy(obj, {
    get(t, p) {
      if (typeof p === 'string') bump(hostAccess, `${name}.${p}`);
      const v = t[p];
      return typeof v === 'function' ? v.bind(t) : v;
    },
    has(t, p) { return p in t; },
  });
}
const wrapped = {
  navigator: wrapHost('navigator', hd.navigator),
  document: wrapHost('document', hd.document),
  screen: wrapHost('screen', hd.screen),
  location: wrapHost('location', hd.location),
  history: wrapHost('history', hd.history),
};

const decoded = [];
const TappedString = new Proxy(String, {
  get(t, p) {
    if (p === 'fromCharCode') {
      return function (...codes) {
        const s = String.fromCharCode(...codes);
        if (s.length > 1) decoded.push(s);
        return s;
      };
    }
    const v = t[p];
    return typeof v === 'function' ? v.bind(t) : v;
  },
});

const nativeStr = (name) => `function ${name}() { [native code] }`;
const makeNative = (fn, name) => { try { Object.defineProperty(fn, 'toString', { value: () => nativeStr(name), configurable: true }); fn.toString.toString = () => nativeStr('toString'); } catch {} return fn; };
makeNative(recordFetch, 'fetch');
makeNative(FakeXHR, 'XMLHttpRequest');

const overrides = {
  fetch: recordFetch,
  XMLHttpRequest: FakeXHR,
  String: TappedString,
  console: { log: () => {}, warn: () => {}, error: () => {}, debug: () => {}, info: () => {} },

};

let proxyObj;
const handler = {
  get(target, prop) {
    if (typeof prop === 'string') bump(access, prop);
    if (prop === 'KPSDK' && target.KPSDK) kpsdkSeen = true;
    if (prop in overrides) return overrides[prop];
    if (typeof prop === 'string' && prop in wrapped) return wrapped[prop];
    if (prop === 'window' || prop === 'self' || prop === 'globalThis' || prop === 'top' || prop === 'parent') return proxyObj;
    if (prop === Symbol.unscopables) return undefined;
    if (prop in target) {
      const v = target[prop];

      if (typeof v === 'function' && BIND_THESE.has(prop)) return v.bind(target);
      return v;
    }
    if (typeof prop === 'string' && !(prop in target)) bump(missing, prop);
    return undefined;
  },
  set(target, prop, value) {
    if (typeof prop === 'string') bump(sets, prop);
    if (prop === 'KPSDK') { kpsdkSeen = true; console.log('[spike] >>> window.KPSDK was SET (type ' + typeof value + ')'); }
    target[prop] = value;
    return true;
  },
  has() { return true; },
  defineProperty(t, p, desc) {
    if (typeof p === 'string') { bump(sets, `def:${p}`); if (p === 'KPSDK') { kpsdkSeen = true; console.log('[spike] >>> KPSDK via defineProperty'); } }
    return Reflect.defineProperty(t, p, desc);
  },
};

const ctxTarget = hd.window;

ctxTarget.fetch = recordFetch;
ctxTarget.XMLHttpRequest = FakeXHR;

for (const name of [
  'Proxy', 'Reflect', 'WeakMap', 'WeakSet', 'WeakRef', 'Symbol', 'BigInt', 'Promise',
  'Map', 'Set', 'ArrayBuffer', 'SharedArrayBuffer', 'DataView', 'Atomics', 'JSON', 'Math',
  'Int8Array', 'Uint8Array', 'Uint8ClampedArray', 'Int16Array', 'Uint16Array',
  'Int32Array', 'Uint32Array', 'Float32Array', 'Float64Array', 'BigInt64Array', 'BigUint64Array',
  'Intl', 'RegExp', 'Date', 'Error', 'TypeError', 'RangeError', 'Function', 'globalThis',
]) {
  if (ctxTarget[name] === undefined && globalThis[name] !== undefined) {
    try { ctxTarget[name] = globalThis[name]; } catch {}
  }
}

const beforeProps = new Set(Object.getOwnPropertyNames(ctxTarget));
proxyObj = new Proxy(ctxTarget, handler);
const context = vm.createContext(proxyObj);

console.log('[spike] running p.js in sandbox (3s budget for timers/promises)...');
let ranOk = true;
try {
  vm.runInContext(pjsSrc, context, { filename: 'p.js', timeout: 8000 });
} catch (e) {
  ranOk = false;
  const loc = String(e?.stack || '').match(/p\.js:\d+:\d+/)?.[0] || '?';
  errors.push(`top-level: ${e?.name || 'Error'}: ${String(e?.message || e).slice(0, 240)} @ ${loc}`);
}

await new Promise((r) => setTimeout(r, 500));
const fireEvt = (target, type, Ctor = 'Event') => {
  try {
    const ev = new hd[Ctor](type, { bubbles: false });
    target.dispatchEvent?.(ev);
  } catch (e) { errors.push(`evt ${type}: ${e.message}`); }
};
console.log('[spike] firing DOMContentLoaded + load ...');
try { Object.defineProperty(hd.document, 'readyState', { value: 'complete', configurable: true }); } catch {}
fireEvt(hd.document, 'readyState');
fireEvt(hd.document, 'DOMContentLoaded');
fireEvt(ctxTarget, 'DOMContentLoaded');
fireEvt(ctxTarget, 'load');
fireEvt(ctxTarget, 'pageshow');

await new Promise((r) => setTimeout(r, 3000));

const top = (m, n = 30) => [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n).map(([k, v]) => `${k}(${v})`).join(', ');

const after = new Set(Object.getOwnPropertyNames(ctxTarget));
const newProps = [...after].filter((p) => !beforeProps.has(p));
console.log('\n========== SPIKE REPORT ==========');
console.log('NEW window own-props p.js added:', newProps.length ? newProps.join(', ') : '(none)');
console.log('top-level executed without throw:', ranOk);
console.log('window.KPSDK appeared:', kpsdkSeen, ' KPSDK value:', typeof ctxTarget.KPSDK);
console.log('\nNETWORK ATTEMPTS:', net.length);
for (const n of net) console.log('  ', n.via, n.method, (n.url || '').slice(0, 95), 'bodyLen=' + n.bodyLen, n.bodyPreview ? 'preview=' + n.bodyPreview : '');
console.log('\nWINDOW WRITES (what p.js defined):\n  ', top(sets, 40));
console.log('\nTOP GLOBAL ACCESSES:\n  ', top(access));
console.log('\nHOST PROBES (navigator/document/screen/... .prop):\n  ', top(hostAccess, 60));
console.log('\nMISSING (read -> undefined):\n  ', top(missing, 40));
console.log('\nERRORS:', errors.length);
for (const e of errors.slice(0, 12)) console.log('  -', e);

const uniq = [...new Set(decoded)];
fs.writeFileSync('decoded-strings.txt', uniq.join('\n'), 'utf8');
console.log(`\nDECODED STRINGS: ${decoded.length} total, ${uniq.length} unique -> decoded-strings.txt`);
const interesting = uniq.filter((s) => /tl|mfc|fp|kpsdk|webdriver|canvas|navigator|chrome|automation|headless|callPhantom|emit|configure|ready|integrity|toString|debugger|x-kpsdk|\/149e|cookie|userAgent|plugins|notification|permission/i.test(s));
console.log('INTERESTING decoded strings (' + interesting.length + '):');
for (const s of interesting.slice(0, 80)) console.log('   ·', JSON.stringify(s.slice(0, 100)));
console.log('==================================');
process.exit(0);
