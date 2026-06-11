
import fs from 'node:fs';
import vm from 'node:vm';
import { Window } from 'happy-dom';
import { Impit } from 'impit';

function parseProxy(raw) {
  raw = String(raw).trim().replace(/^https?:\/\//, '');
  if (raw.includes('@')) {
    const [cred, hp] = raw.split('@');
    const [user, pass] = cred.split(':');
    const [host, port] = hp.split(':');
    return { host, port, user, pass };
  }
  const p = raw.split(':');
  if (p.length === 4) return { host: p[0], port: p[1], user: p[2], pass: p[3] };
  if (p.length === 2) return { host: p[0], port: p[1], user: '', pass: '' };
  throw new Error('bad PROXY format (use host:port:user:pass)');
}

const REAL = !!process.env.REAL;
let impit = null, proxyUrl = null;
if (REAL) {
  if (!process.env.PROXY) { console.error('REAL=1 needs a PROXY env var (host:port:user:pass)'); process.exit(1); }
  const p = parseProxy(process.env.PROXY);
  proxyUrl = p.user
    ? `http://${encodeURIComponent(p.user)}:${encodeURIComponent(p.pass)}@${p.host}:${p.port}`
    : `http://${p.host}:${p.port}`;
  impit = new Impit({ browser: 'chrome', proxyUrl, ignoreTlsErrors: true });
}
const jar = new Map();
const updateJar = (setCookie) => { for (const sc of [].concat(setCookie || [])) { const m = /^([^=;]+)=([^;]*)/.exec(sc); if (m) jar.set(m[1].trim(), m[2]); } };
const cookieHeader = () => [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
const realReq = [];
async function forwardReal(method, absUrl, headers, body) {
  const h = { ...headers };

  if (/\/149e9513/.test(absUrl)) { h['x-kpsdk-v'] = h['x-kpsdk-v'] || 'j-1.2.430'; h['user-agent'] = UA; }
  if (jar.size) h['cookie'] = cookieHeader();
  let payload = body;
  if (body && typeof body !== 'string') { try { payload = Buffer.from(body.buffer || body); } catch { payload = Buffer.from(String(body), 'latin1'); } }
  else if (typeof body === 'string') payload = Buffer.from(body, 'latin1');
  const res = await impit.fetch(absUrl, { method, headers: h, body: method === 'GET' ? undefined : payload });
  const respHeaders = {}; try { res.headers.forEach((v, k) => { respHeaders[k.toLowerCase()] = v; }); } catch {}
  updateJar(respHeaders['set-cookie']);
  const text = await res.text();
  realReq.push({ method, url: absUrl, status: res.status, ct: respHeaders['x-kpsdk-ct'] || null, st: respHeaders['x-kpsdk-st'] || null, len: text.length, bodyHead: text.slice(0, 80) });
  console.log(`[REAL] ${method} ${absUrl.slice(-40)} -> ${res.status} ${respHeaders['x-kpsdk-ct'] ? 'ct!' : ''} ${text.slice(0, 40).replace(/\s+/g, ' ')}`);
  return { status: res.status, headers: respHeaders, text };
}
const absUrl = (u) => (String(u).startsWith('http') ? String(u) : ORIGIN + String(u));

const DECOMP = 'Emrovsky/decomp.js';
const REGEN = fs.readFileSync('node_modules/regenerator-runtime/runtime.js', 'utf8');
const src = fs.readFileSync(DECOMP, 'utf8');
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36';
const ORIGIN = 'https://sso.secureserver.net';
const PAGE = `${ORIGIN}/149e9513-01fa-4fb0-aad4-566afd725d1b/2d206a39-8ed7-437e-a3be-862e0f06eea3/fp?x-kpsdk-v=j-1.2.430`;

const net = [];
const errors = [];
const access = new Map();
const missing = new Map();
const bump = (m, k) => m.set(k, (m.get(k) || 0) + 1);
const nowMs = Date.now();

const hd = new Window({ url: PAGE, settings: { disableJavaScriptEvaluation: true } });
try {
  Object.defineProperty(hd.navigator, 'userAgent', { value: UA, configurable: true });
  Object.defineProperty(hd.navigator, 'platform', { value: 'Win32', configurable: true });
  Object.defineProperty(hd.navigator, 'hardwareConcurrency', { value: 8, configurable: true });
  Object.defineProperty(hd.navigator, 'languages', { value: ['en-US', 'en'], configurable: true });
  Object.defineProperty(hd.navigator, 'deviceMemory', { value: 8, configurable: true });
} catch {}

const ctx2d = new Proxy({}, { get: (t, p) => (typeof p === 'string' && /fillText|fillRect|arc|beginPath|stroke|fill|moveTo|lineTo|rect|save|restore|translate|rotate|scale|setTransform|clearRect|putImageData|drawImage|getImageData|measureText|createLinearGradient|addColorStop|closePath|bezierCurveTo|quadraticCurveTo|isPointInPath/.test(p)) ? () => ({ width: 0, data: new Uint8Array(0), addColorStop() {} }) : (p === 'canvas' ? canvasEl : 0) });
const glStub = new Proxy({}, { get: (t, p) => {
  if (p === 'getParameter') return (x) => ({ 37445: 'Google Inc. (NVIDIA)', 37446: 'ANGLE (NVIDIA GeForce RTX 3060)', 7936: 'WebKit', 7937: 'WebKit WebGL', 7938: 'WebGL 1.0' }[x] ?? 0);
  if (p === 'getExtension') return () => ({ UNMASKED_VENDOR_WEBGL: 37445, UNMASKED_RENDERER_WEBGL: 37446 });
  if (p === 'getSupportedExtensions') return () => ['WEBGL_debug_renderer_info', 'OES_texture_float'];
  if (p === 'getShaderPrecisionFormat') return () => ({ rangeMin: 127, rangeMax: 127, precision: 23 });
  return typeof p === 'string' ? () => 0 : 0;
}});
let canvasEl;
function makeCanvas() {
  return { width: 300, height: 150, getContext: (k) => (/webgl/i.test(k) ? glStub : ctx2d), toDataURL: () => 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAASwAAAABCAYAAAB' + 'A'.repeat(40), getBoundingClientRect: () => ({ x: 0, y: 0, width: 300, height: 150 }), style: {} };
}
canvasEl = makeCanvas();

function recordNet(via, method, url, headers, body) {
  let bodyStr = null;
  try { bodyStr = typeof body === 'string' ? body : (body && body.byteLength != null ? Buffer.from(body).toString('latin1') : (body == null ? null : String(body))); } catch {}
  const entry = { t: Date.now() - nowMs, via, method, url: String(url), headers, bodyLen: bodyStr?.length ?? null, body: bodyStr };
  net.push(entry);

  try { fs.appendFileSync('dump/decomp-net.jsonl', JSON.stringify(entry) + '\n'); } catch {}
  console.log(`[decomp] >>> ${via} ${method} ${String(url).slice(0, 80)} bodyLen=${entry.bodyLen}`);
}
const TL_RESP_HEADERS = { 'x-kpsdk-ct': 'SANDBOXCT' + 'x'.repeat(160), 'x-kpsdk-cr': 'true', 'x-kpsdk-st': String(nowMs), 'x-kpsdk-r': '1-AAAA', 'access-control-expose-headers': 'x-kpsdk-ct,x-kpsdk-r,x-kpsdk-c,x-kpsdk-h,x-kpsdk-fc', 'content-type': 'application/json' };
const MFC_RESP_HEADERS = { 'x-kpsdk-fc': 'eyJmZWF0dXJlRmxhZ3MiOnt9fQ==', 'x-kpsdk-h': '01AAAA', 'content-type': 'application/json' };
const KASADA_PATH = '149e9513-01fa-4fb0-aad4-566afd725d1b';
function respHeadersFor(url) {
  const u = String(url);
  if (/\/mfc/.test(u)) return { ...TL_RESP_HEADERS, ...MFC_RESP_HEADERS };

  if (u.includes(KASADA_PATH) || /\/tl(\?|$)|\/r(\?|$)/.test(u)) return TL_RESP_HEADERS;
  return { 'content-type': 'application/json' };
}

const recordFetch = (input, init = {}) => {
  const url = typeof input === 'string' ? input : input?.url || String(input);
  const method = (init.method || 'GET').toUpperCase();
  recordNet('fetch', method, url, init.headers, init.body);
  if (REAL && /^https?:|^\/149e9513|\/v1\/api/.test(String(url))) {
    return forwardReal(method, absUrl(url), init.headers || {}, init.body)
      .then((r) => new hd.Response(r.text, { status: r.status, headers: r.headers }))
      .catch((e) => { errors.push('fwd fetch: ' + e.message); return new hd.Response('', { status: 0 }); });
  }
  const rh = respHeadersFor(url);
  return Promise.resolve(new hd.Response('{"reload":false}', { status: 200, headers: rh }));
};
class FakeXHR {
  constructor() { this._h = {}; this.readyState = 0; this.status = 0; this.responseText = '{"reload":false}'; this.response = this.responseText; }
  open(m, u) { this._m = m; this._u = u; this.readyState = 1; }
  setRequestHeader(k, v) { this._h[k] = v; }
  getResponseHeader(name) { const rh = this._realH || respHeadersFor(this._u || ''); return rh[String(name).toLowerCase()] ?? null; }
  getAllResponseHeaders() { const rh = this._realH || respHeadersFor(this._u || ''); return Object.entries(rh).map(([k, v]) => `${k}: ${v}`).join('\r\n'); }
  _finish() { this.readyState = 4; for (const cb of ['onreadystatechange', 'onload', 'onloadend']) { try { this[cb] && this[cb](); } catch (e) { errors.push(`xhr.${cb}: ${e.message}`); } } }
  send(body) {
    recordNet('xhr', this._m, this._u, this._h, body);
    if (REAL && /^https?:|^\/149e9513|\/v1\/api/.test(String(this._u))) {
      forwardReal(this._m, absUrl(this._u), this._h, body).then((r) => {
        this.status = r.status; this._realH = r.headers; this.responseText = r.text; this.response = r.text; this._finish();
      }).catch((e) => { errors.push('fwd xhr: ' + e.message); this.status = 0; this._finish(); });
      return;
    }
    this.status = 200; this._finish();
  }
  addEventListener(ev, fn) { if (ev === 'load') this.onload = fn; if (ev === 'readystatechange') this.onreadystatechange = fn; if (ev === 'loadend') this.onloadend = fn; }
  removeEventListener() {} abort() {} overrideMimeType() {}
}
const sendBeacon = (url, data) => { recordNet('beacon', 'POST', url, {}, data); return true; };

const ctxTarget = hd.window;
ctxTarget.fetch = recordFetch; ctxTarget.XMLHttpRequest = FakeXHR;
if (ctxTarget.navigator) { try { ctxTarget.navigator.sendBeacon = sendBeacon; } catch {} }
for (const name of ['Proxy','Reflect','WeakMap','WeakSet','WeakRef','Symbol','BigInt','Promise','Map','Set','ArrayBuffer','SharedArrayBuffer','DataView','Atomics','Int8Array','Uint8Array','Uint8ClampedArray','Int16Array','Uint16Array','Int32Array','Uint32Array','Float32Array','Float64Array','BigInt64Array','BigUint64Array','Intl','RegExp','Date','Error','Function','globalThis','TextEncoder','TextDecoder','crypto'])
  if (ctxTarget[name] === undefined && globalThis[name] !== undefined) { try { ctxTarget[name] = globalThis[name]; } catch {} }
const nativeStr = (n) => `function ${n}() { [native code] }`;
const mk = (fn, n) => { try { fn.toString = () => nativeStr(n); } catch {} return fn; };
mk(recordFetch, 'fetch'); mk(FakeXHR, 'XMLHttpRequest'); mk(sendBeacon, 'sendBeacon');

const origCreate = hd.document.createElement.bind(hd.document);
hd.document.createElement = (tag, ...r) => (String(tag).toLowerCase() === 'canvas' ? makeCanvas() : origCreate(tag, ...r));
try { const s = origCreate('script'); s.src = PAGE; hd.document.head.appendChild(s); Object.defineProperty(hd.document, 'currentScript', { get: () => s, configurable: true }); } catch {}

const BIND = new Set(['setTimeout','clearTimeout','setInterval','clearInterval','addEventListener','removeEventListener','dispatchEvent','queueMicrotask','atob','btoa','postMessage','requestAnimationFrame','cancelAnimationFrame','getComputedStyle','matchMedia']);

let intervalCount = 0;

const fakeSetInterval = (fn, delay) => {
  intervalCount++;
  let n = 0;
  const tick = () => { if (n++ >= 40) return; try { typeof fn === 'function' && fn(); } catch (e) { errors.push('interval: ' + e.message); } setTimeout(tick, Math.max(25, delay || 25)); };
  setTimeout(tick, Math.max(25, delay || 25));
  return intervalCount;
};

const messageListeners = [];
function addEventListenerShim(type, fn) {
  if (type === 'message') { messageListeners.push(fn); console.log('[decomp] (message listener registered)'); return; }
  try { hd.window.addEventListener(type, fn); } catch {}
}
let msgCount = 0;
function postMessageShim(data, origin) {
  setTimeout(() => {
    msgCount++;
    const ev = { data, origin: origin || '*', source: proxyObj, ports: [], type: 'message' };
    try { if (typeof ctxTarget.onmessage === 'function') ctxTarget.onmessage(ev); } catch (e) { errors.push('onmessage: ' + e.message); }
    for (const l of messageListeners) { try { l(ev); } catch (e) { errors.push('msgListener: ' + e.message); } }
  }, 0);
}
const overrides = { fetch: recordFetch, XMLHttpRequest: FakeXHR, setInterval: fakeSetInterval, clearInterval: () => {}, addEventListener: addEventListenerShim, postMessage: postMessageShim, console: { log() {}, warn() {}, error() {}, info() {}, debug() {} } };
let proxyObj;
const handler = {
  get(t, p) {
    if (typeof p === 'string') bump(access, p);
    if (p in overrides) return overrides[p];
    if (p === 'window' || p === 'self' || p === 'globalThis' || p === 'top' || p === 'parent' || p === 'frames') return proxyObj;
    if (p in t) { const v = t[p]; return (typeof v === 'function' && BIND.has(p)) ? v.bind(t) : v; }
    if (typeof p === 'string') bump(missing, p);
    return undefined;
  },
  set(t, p, v) { t[p] = v; return true; },
  has() { return true; },
  defineProperty(t, p, d) { return Reflect.defineProperty(t, p, d); },
};
proxyObj = new Proxy(ctxTarget, handler);
const context = vm.createContext(proxyObj);

console.log('[decomp] loading regenerator-runtime + decomp.js (' + src.length + ' bytes)...');
let ranOk = true;
try {
  vm.runInContext(REGEN, context, { filename: 'regenerator.js' });
  vm.runInContext(src, context, { filename: 'decomp.js', timeout: 20000 });
} catch (e) {
  ranOk = false;
  const loc = String(e?.stack || '').match(/decomp\.js:\d+:\d+/)?.[0] || '?';
  errors.push(`${e?.name}: ${String(e?.message).slice(0, 200)} @ ${loc}`);
}
await new Promise((r) => setTimeout(r, REAL ? 25000 : 4000));

const top = (m, n = 30) => [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n).map(([k, v]) => `${k}(${v})`).join(', ');
console.log('\n========== DECOMP RUN ==========');
console.log('ran without top-level throw:', ranOk);
console.log('setInterval (heartbeat) suppressed calls:', intervalCount);
try {
  const K = ctxTarget.KPSDK || {};
  console.log('window.KPSDK keys:', Object.keys(K).join(',') || '(empty)');
  console.log('  KPSDK.configure:', typeof K.configure, ' isReady:', typeof K.isReady, ' ct:', (K.ct ? String(K.ct).slice(0,30)+'...' : K.ct));
  console.log('  message listeners:', messageListeners.length, ' messages dispatched:', msgCount);
} catch (e) { console.log('KPSDK read error', e.message); }
console.log('\nNETWORK ATTEMPTS:', net.length);
for (const n of net) { console.log('  ', n.via, n.method, n.url.slice(0, 100), 'bodyLen=' + n.bodyLen); if (n.bodyPreview) console.log('      body:', n.bodyPreview); if (n.headers) console.log('      hdrs:', JSON.stringify(n.headers).slice(0, 200)); }

fs.writeFileSync('dump/decomp-net.json', JSON.stringify(net, null, 2));
if (REAL) {
  console.log('\n=== REAL handshake (proxied to live secureserver) ===');
  for (const r of realReq) console.log(`  ${r.method} ...${r.url.slice(-36)} -> ${r.status}${r.ct ? '  CT=' + r.ct.slice(0, 28) + '...' : ''}  ${r.bodyHead.replace(/\s+/g, ' ')}`);
  const minted = realReq.find((r) => r.ct);
  console.log(minted ? `\n[ok] SERVER RETURNED A REAL ct (${minted.url.slice(-6)} -> ${minted.status}) - browserless fingerprint ACCEPTED!`
    : `\n[fail] no real ct returned - server blocked/!=200 (anti-VM or flow mismatch). Statuses: ${realReq.map((r) => r.status).join(',')}`);
  fs.writeFileSync('dump/decomp-real-handshake.json', JSON.stringify(realReq, null, 2));
}
console.log('\nERRORS:', errors.length); for (const e of errors.slice(0, 10)) console.log('  -', e);
console.log('\nMISSING (top):', top(missing, 25));
console.log('================================');
