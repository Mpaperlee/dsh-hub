// dsh-hub — a JupyterHub-style front for DeepSeek Harness (dsh).
//
// Architecture (mirrors JupyterHub):
//   Authenticator  — PAM (system accounts), login page, HMAC-signed session cookie
//   Spawner        — on first authenticated request, spawn `dsh web --port <N>`
//                    as that OS user (uid/gid), with DSH_HOME isolated per user,
//                    plus an iptables loopback owner-guard so OTHER local users
//                    cannot reach the unauthenticated dsh port.
//   Proxy          — routes HTTP + WebSocket by session cookie to the user's backend
//                    (single shared hostname; no path rewriting needed).
//   Culler         — stops idle backends after IDLE_CULL_MS and removes guards.
//
// dsh itself is NOT modified — it stays on 127.0.0.1, single-user, untouched,
// so upstream upgrades and plugin installs keep working.
//
// Run as root (systemd) for PAM + setuid + iptables. Non-root runs in degraded
// dev mode (no setuid spawn, no iptables guard, PAM may fail without shadow access).

import http from 'node:http';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import crypto from 'node:crypto';
import { networkInterfaces } from 'node:os';
import { spawn, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import httpProxy from 'http-proxy';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------- config ----

function int(v, dflt) { const n = Number(v); return Number.isInteger(n) && n > 0 ? n : dflt; }
function intOrZero(v, dflt) { const n = Number(v); return Number.isInteger(n) && n >= 0 ? n : dflt; }

// Trust modes:
//  - 'origin-rewrite' (default): proxy rewrites Host (changeOrigin) and Origin
//    to loopback; CSRF protection is carried by the hub's SameSite=Lax cookie.
//    This is the ONLY mode that works behind a loopback-binding proxy: dsh's
//    RPC host empties trustedHosts for loopback-authority /api channels
//    (rpc-host.ts: `authority === 'loopback' ? [] : trustedHosts`), so
//    --trusted-host cannot grant non-loopback Hosts there.
//  - 'trusted-host': spawn dsh with its official `--trusted-host` flag and
//    forward Host/Origin untouched. Only works when the fence actually feeds
//    the flag to the channel (direct LAN binds), kept for future dsh support
//    of proxied deployments.
const TRUST_MODE = process.env.TRUST_MODE === 'trusted-host' ? 'trusted-host' : 'origin-rewrite';

function lanIpv4s() {
  return Object.values(networkInterfaces()).flat()
    .filter((i) => i && i.family === 'IPv4' && !i.internal)
    .map((i) => i.address);
}

const TRUSTED_HOSTS = [
  ...lanIpv4s(),
  ...(process.env.TRUSTED_HOSTS ?? '')
    .split(',').map((s) => s.trim()).filter(Boolean),
];

function detectDshBin() {
  if (process.env.DSH_BIN) return process.env.DSH_BIN;
  const candidates = [
    path.join(process.cwd(), 'deepseek-harness/apps/cli/lib/bin.js'),
    path.resolve(__dirname, '../../deepseek-harness/apps/cli/lib/bin.js'),
    '/usr/local/lib/dsh/apps/cli/lib/bin.js',
  ];
  for (const c of candidates) {
    try { fs.accessSync(c, fs.constants.X_OK); return c; } catch { /* next */ }
  }
  console.error(
    '[hub] FATAL: dsh binary not found. Set DSH_BIN to the dsh CLI entry\n' +
    '[hub] (a built checkout: <repo>/apps/cli/lib/bin.js). Detected candidates:\n' +
    candidates.map((c) => `        ${c}`).join('\n'));
  process.exit(1);
}

const CFG = {
  hubHost: process.env.HUB_HOST ?? '0.0.0.0',
  hubPort: int(process.env.HUB_PORT, 3080),
  dshBin: detectDshBin(),
  sessionTtlMs: int(process.env.SESSION_TTL_MS, 7 * 24 * 3600 * 1000),
  // 0 disables culling entirely — backends keep running with the browser
  // closed, JupyterHub/tmux-style. Pick a positive value to reap idle ones.
  idleCullMs: intOrZero(process.env.IDLE_CULL_MS, 4 * 3600 * 1000),
  spawnTimeoutMs: int(process.env.SPAWN_TIMEOUT_MS, 60_000),
  cookieName: 'dshhub_session',
  // Optional comma-separated allow-list of usernames. Empty = all system users.
  allowUsers: (process.env.ALLOW_USERS ?? '')
    .split(',').map((s) => s.trim()).filter(Boolean),
  logDir: process.env.HUB_LOG_DIR ?? '/var/log/dsh-hub',
};

const IS_ROOT = process.getuid?.() === 0;
const IPTABLES = IS_ROOT && hasBin('iptables');

function hasBin(name) {
  const { statSync } = fs;
  for (const dir of ['/usr/sbin', '/usr/bin', '/sbin', '/bin']) {
    try { statSync(`${dir}/${name}`); return true; } catch { /* keep looking */ }
  }
  return false;
}

// ----------------------------------------------------------- cookie secret --

const SECRET_PATH = process.env.COOKIE_SECRET_FILE ?? path.join(__dirname, '..', '.cookie-secret');
let SECRET;
{
  try {
    SECRET = fs.readFileSync(SECRET_PATH);
  } catch {
    SECRET = crypto.randomBytes(32);
    fs.writeFileSync(SECRET_PATH, SECRET, { mode: 0o600 });
  }
}

function sign(user, exp) {
  return crypto.createHmac('sha256', SECRET).update(`${user}.${exp}`).digest('base64url');
}

function makeCookie(user) {
  const exp = Date.now() + CFG.sessionTtlMs;
  return `${user}.${exp}.${sign(user, exp)}`;
}

function parseCookie(req) {
  const raw = req.headers.cookie ?? '';
  for (const part of raw.split(';')) {
    const [k, ...rest] = part.trim().split('=');
    if (k === CFG.cookieName) return rest.join('=');
  }
  return null;
}

function sessionUser(req) {
  const val = parseCookie(req);
  if (!val) return null;
  const m = /^(.+)\.(\d+)\.(.+)$/.exec(val);
  if (!m) return null;
  const [, user, expStr, sig] = m;
  const exp = Number(expStr);
  if (!Number.isFinite(exp) || exp < Date.now()) return null;
  const expect = sign(user, exp);
  const a = Buffer.from(sig), b = Buffer.from(expect);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  return user;
}

// ------------------------------------------------------------- user lookup --

const passwdCache = new Map(); // user -> {uid, gid, home, shell} | null

function lookupUser(user) {
  if (!/^[a-z_][a-z0-9_-]{0,31}$/i.test(user)) return null;
  if (passwdCache.has(user)) return passwdCache.get(user);
  let info = null;
  try {
    const out = execFileSync('getent', ['passwd', user], { timeout: 3000 }).toString();
    const [name, , uid, gid, , home, shell] = out.trim().split(':');
    if (name === user) info = { uid: +uid, gid: +gid, home, shell };
  } catch { /* unknown user */ }
  passwdCache.set(user, info);
  return info;
}

// ----------------------------------------------------------------- PAM ------

const LOGIN_ATTEMPTS = new Map(); // ip -> {count, until}
function rateLimited(ip) {
  const now = Date.now();
  const rec = LOGIN_ATTEMPTS.get(ip);
  if (!rec) return false;
  if (rec.until > now) return true;
  if (rec.until !== 0 && rec.until <= now) LOGIN_ATTEMPTS.delete(ip);
  return false;
}
function recordFailure(ip) {
  const rec = LOGIN_ATTEMPTS.get(ip) ?? { count: 0, until: 0 };
  rec.count += 1;
  if (rec.count >= 5) { rec.until = Date.now() + 60_000; rec.count = 0; }
  LOGIN_ATTEMPTS.set(ip, rec);
}

// Two PAM paths:
//  1. native `authenticate-pam` (optionalDependency; needs libpam0g-dev to build)
//  2. `su` fallback: spawn `su <user> -c 'exit 0'` as an unprivileged uid —
//     su then verifies the TARGET user's password through PAM. Zero native
//     deps; failed attempts land in the normal auth log.
let pamNative = null;
try { pamNative = (await import('authenticate-pam')).default; } catch { /* optional */ }

function pamAuthenticate(user, password) {
  if (pamNative) {
    return new Promise((resolve) => {
      pamNative.authenticate(user, password, (err) => resolve(!err));
    });
  }
  return new Promise((resolve) => {
    const opts = { stdio: ['pipe', 'ignore', 'ignore'] };
    if (IS_ROOT) opts.uid = 65534; // nobody: non-root su prompts via PAM
    const child = spawn('su', [user, '-c', 'exit 0'], opts);
    let done = false;
    const finish = (ok) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve(ok);
    };
    const timer = setTimeout(() => { child.kill('SIGKILL'); finish(false); }, 10_000);
    child.on('error', () => finish(false));
    child.on('exit', (code) => finish(code === 0));
    child.stdin.write(`${password}\n`);
    child.stdin.end();
  });
}

// -------------------------------------------------------------- backends ----

/** @type {Map<string, Backend>} */
const backends = new Map();

class Backend {
  constructor(user, info, port) {
    this.user = user;
    this.info = info;
    this.port = port;
    this.child = null;
    this.ready = null;      // promise resolved when TCP accepts
    this.lastActivity = Date.now();
    this.starting = false;
  }
}

function randomFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
    srv.on('error', reject);
  });
}

function waitTcp(port, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    (function tryOnce() {
      const sock = net.connect(port, '127.0.0.1');
      sock.once('connect', () => { sock.destroy(); resolve(); });
      sock.once('error', () => {
        sock.destroy();
        if (Date.now() > deadline) reject(new Error(`backend did not come up within ${timeoutMs}ms`));
        else setTimeout(tryOnce, 300);
      });
    })();
  });
}

// iptables loopback owner-guard: only the backend's own uid (and root) may
// connect to the backend port on lo. Other local users get DROPped. This closes
// the "dsh has no auth and loopback is shared" hole on multi-user machines.
function addGuard(port, uid) {
  if (!IPTABLES) return;
  // Insert in reverse so final order is: ACCEPT(root), ACCEPT(uid), DROP.
  runIptables(['-I', 'OUTPUT', '1', '-o', 'lo', '-p', 'tcp', '--dport', String(port),
    '-j', 'DROP']);
  runIptables(['-I', 'OUTPUT', '1', '-o', 'lo', '-p', 'tcp', '--dport', String(port),
    '-m', 'owner', '--uid-owner', String(uid), '-j', 'ACCEPT']);
  runIptables(['-I', 'OUTPUT', '1', '-o', 'lo', '-p', 'tcp', '--dport', String(port),
    '-m', 'owner', '--uid-owner', '0', '-j', 'ACCEPT']);
}
function removeGuard(port, uid) {
  if (!IPTABLES) return;
  for (const args of [
    ['-o', 'lo', '-p', 'tcp', '--dport', String(port), '-m', 'owner', '--uid-owner', '0', '-j', 'ACCEPT'],
    ['-o', 'lo', '-p', 'tcp', '--dport', String(port), '-m', 'owner', '--uid-owner', String(uid), '-j', 'ACCEPT'],
    ['-o', 'lo', '-p', 'tcp', '--dport', String(port), '-j', 'DROP'],
  ]) {
    try {
      const bin = fs.existsSync('/usr/sbin/iptables') ? '/usr/sbin/iptables' : '/usr/bin/iptables';
      execFileSync(bin, ['-D', 'OUTPUT', ...args], { stdio: 'ignore', timeout: 5000 });
    } catch { /* already gone */ }
  }
}
function runIptables(args, tolerate = false) {
  const bin = '/usr/sbin/iptables';
  try {
    execFileSync(fs.existsSync(bin) ? bin : '/usr/bin/iptables', args, { stdio: 'ignore', timeout: 5000 });
  } catch (err) {
    if (!tolerate) console.error('[hub] iptables failed:', args.join(' '), err.message);
  }
}

function logStreamFor(user) {
  try {
    fs.mkdirSync(CFG.logDir, { recursive: true });
    fs.accessSync(CFG.logDir, fs.constants.W_OK);
    const stream = fs.createWriteStream(path.join(CFG.logDir, `${user}.log`), { flags: 'a' });
    stream.on('error', (e) => console.error(`[hub] backend log for ${user} unavailable:`, e.message));
    return stream;
  } catch {
    return 'ignore';
  }
}

async function getOrCreateBackend(user) {
  let be = backends.get(user);
  if (be && be.child && be.child.exitCode === null) return be;
  if (be?.starting) return be;

  const info = lookupUser(user);
  if (!info) throw new Error(`unknown system user: ${user}`);
  if (CFG.allowUsers.length && !CFG.allowUsers.includes(user)) {
    throw new Error(`user ${user} is not on the allow-list`);
  }

  const port = await randomFreePort();
  be = new Backend(user, info, port);
  be.starting = true;
  backends.set(user, be);

  const home = info.home;
  const env = {
    HOME: home,
    DSH_HOME: path.join(home, '.dsh'),   // per-user data root: sessions, keys, settings
    PATH: '/usr/local/bin:/usr/bin:/bin',
    LANG: process.env.LANG ?? 'en_US.UTF-8',
    TERM: 'xterm-256color',
  };

  const opts = {
    cwd: home,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  };
  if (IS_ROOT) { opts.uid = info.uid; opts.gid = info.gid; }
  else console.warn('[hub] non-root: spawning dsh as hub user (dev mode, no isolation)');

  console.log(`[hub] spawning dsh for ${user} (uid ${info.uid}) on 127.0.0.1:${port}, DSH_HOME=${env.DSH_HOME}`);
  const args = [CFG.dshBin, 'web', '--port', String(port)];
  if (TRUST_MODE === 'trusted-host') {
    for (const authority of TRUSTED_HOSTS) args.push('--trusted-host', authority);
  }
  const child = spawn(process.execPath, args, opts);
  be.child = child;
  const log = logStreamFor(user);
  if (log !== 'ignore') {
    child.stdout.pipe(log, { end: false });
    child.stderr.pipe(log, { end: false });
  } else {
    child.stdout.resume(); child.stderr.resume();
  }

  addGuard(port, info.uid);

  child.once('exit', (code, signal) => {
    console.log(`[hub] dsh for ${user} exited (code=${code} signal=${signal})`);
    removeGuard(port, info.uid);
    if (backends.get(user) === be) backends.delete(user);
  });

  be.ready = waitTcp(port, CFG.spawnTimeoutMs).finally(() => { be.starting = false; });
  await be.ready;
  return be;
}

async function stopBackend(user) {
  const be = backends.get(user);
  if (!be) return;
  console.log(`[hub] culling dsh for ${user} (port ${be.port})`);
  be.child?.kill('SIGTERM');
  setTimeout(() => be.child?.kill('SIGKILL'), 5000).unref();
}

// Idle culler. 0 = never cull (JupyterHub-style always-on backends; the
// browser-closed conversation keeps running indefinitely, tmux-style).
if (CFG.idleCullMs > 0) {
  setInterval(() => {
    const now = Date.now();
    for (const [user, be] of backends) {
      if (now - be.lastActivity > CFG.idleCullMs) stopBackend(user);
    }
  }, 60_000).unref();
}

// ---------------------------------------------------------------- proxy -----

// dsh's web UI calls the browser-global `crypto.randomUUID()` (e.g. provider
// catalog / draft attachments). Browsers only expose that API in SECURE
// contexts (https or localhost), so bare `http://<server-ip>:3080` breaks with
// "crypto.randomUUID is not a function". `crypto.getRandomValues` IS available
// in insecure contexts, so we inject a complete v4-UUID polyfill into every
// proxied HTML page — no dsh modification needed, upgrades keep working.
const RANDOM_UUID_POLYFILL = `<script>(function(){
if (typeof crypto!=='undefined'&&typeof crypto.randomUUID==='function')return;
function uuid4(){
  var b=crypto.getRandomValues(new Uint8Array(16));
  b[6]=(b[6]&15)|64;b[8]=(b[8]&63)|128;
  var s='';for(var i=0;i<16;i++)s+=b[i].toString(16).padStart(2,'0');
  return s.slice(0,8)+'-'+s.slice(8,12)+'-'+s.slice(12,16)+'-'+s.slice(16,20)+'-'+s.slice(20);
}
try{Object.defineProperty(crypto,'randomUUID',{value:uuid4,writable:true,configurable:true});}
catch(e){try{crypto.randomUUID=uuid4;}catch(e2){}}
})();</script>`;

// dsh's settings/credentials plane is browser-gated: connection.isLoopback is
// computed from location.hostname (packages/client/connection), so a page
// served from a LAN hostname reports "settings are unavailable in this
// browser" even though the hub's origin-rewrite already passes the server-side
// loopback fence. Location members are [LegacyUnforgeable] (own non-
// configurable accessors on the location instance), so no polyfill can spoof
// them — instead we patch the served connection plugin bundle in flight:
//
//   isLoopback: pageLocation === void 0 || isLoopbackHostname(pageLocation.hostname),
//   → isLoopback: true,
//
// The trust boundary moves to the hub exactly like origin-rewrite: the PAM
// session cookie decides who reaches the backend at all. The patch is
// pattern-based against the unminified bundle and FAILS LOUD (startup log) if
// upstream renames the expression, so upgrades surface immediately instead of
// silently regressing settings.
const CONNECTION_LOOPBACK_PATCH = /isLoopback:[^,\n]*isLoopbackHostname\([^)]*\)/;
const patchedJsCache = new Map(); // url+etag -> patched body
let loopbackPatchMissing = false;

const proxy = httpProxy.createProxyServer({
  ws: true,
  // trusted-host mode keeps the browser's real Host so dsh's own fence (fed by
  // --trusted-host at spawn) makes the decision. origin-rewrite mode masquerades
  // as a loopback same-origin client instead.
  changeOrigin: TRUST_MODE === 'origin-rewrite',
  proxyTimeout: 120_000,
  selfHandleResponse: true, // we own the response so we can rewrite HTML
});

proxy.on('proxyRes', (proxyRes, req, res) => {
  const ct = String(proxyRes.headers['content-type'] ?? '');
  const url = String(req.url ?? '');
  // Plugin bundles: patch the connection client's isLoopback gate in flight.
  const isPluginJs = /^\/plugins\/.+\.js(\?|$)/.test(url);
  if (isPluginJs) {
    const chunks = [];
    proxyRes.on('data', (c) => chunks.push(c));
    proxyRes.on('error', () => res.destroy());
    proxyRes.on('end', () => {
      const headers = { ...proxyRes.headers };
      const cacheKey = `${url}|${String(headers.etag ?? '')}`;
      const cached = patchedJsCache.get(cacheKey);
      let body = cached;
      if (body === undefined) {
        let js = Buffer.concat(chunks).toString('utf-8');
        if (CONNECTION_LOOPBACK_PATCH.test(js)) {
          js = js.replace(CONNECTION_LOOPBACK_PATCH, 'isLoopback: true');
          console.log(`[hub] patched connection isLoopback gate in ${url.split('?')[0]}`);
        } else if (/isLoopback/.test(js) && !loopbackPatchMissing) {
          loopbackPatchMissing = true;
          console.warn(`[hub] WARNING: ${url.split('?')[0]} mentions isLoopback but the patch pattern did not match — settings will report "unavailable in this browser". Update CONNECTION_LOOPBACK_PATCH for this dsh version.`);
        }
        body = Buffer.from(js, 'utf-8');
        if (patchedJsCache.size > 64) patchedJsCache.clear();
        patchedJsCache.set(cacheKey, body);
      }
      delete headers['content-length'];
      delete headers['content-encoding'];
      res.writeHead(proxyRes.statusCode, headers);
      res.end(body);
    });
    return;
  }
  if (!/text\/html/i.test(ct)) {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
    return;
  }
  const chunks = [];
  proxyRes.on('data', (c) => chunks.push(c));
  proxyRes.on('error', () => res.destroy());
  proxyRes.on('end', () => {
    const headers = { ...proxyRes.headers };
    delete headers['content-length'];
    delete headers['content-encoding'];
    res.writeHead(proxyRes.statusCode, headers);
    const html = Buffer.concat(chunks).toString('utf-8');
    const injected = /<head[^>]*>/i.test(html)
      ? html.replace(/<head[^>]*>/i, (m) => m + RANDOM_UUID_POLYFILL)
      : RANDOM_UUID_POLYFILL + html;
    res.end(Buffer.from(injected, 'utf-8'));
  });
});

proxy.on('error', (err, req, res) => {
  console.error('[hub] proxy error:', err.message);
  if (res instanceof http.ServerResponse) {
    if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain' });
    res.end('dsh-hub: backend unavailable\n');
  } else if (res?.destroy) {
    res.destroy();
  }
});

// ---------------------------------------------------------------- pages -----

function sendHtml(res, status, body, headers = {}) {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', ...headers });
  res.end(body);
}

const LOGIN_PAGE = `<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>dsh-hub login</title>
<style>
  :root { color-scheme: dark; }
  body { font-family: system-ui, sans-serif; background: #101418; color: #e6e6e6;
         display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
  .card { background: #1a2027; padding: 2.2rem 2.6rem; border-radius: 12px; width: 22rem;
          box-shadow: 0 8px 40px rgba(0,0,0,.45); }
  h1 { font-size: 1.25rem; margin: 0 0 .3rem; }
  p.sub { color: #8b97a3; font-size: .85rem; margin: 0 0 1.6rem; }
  label { display: block; font-size: .8rem; color: #8b97a3; margin: .9rem 0 .25rem; }
  input { width: 100%; box-sizing: border-box; padding: .55rem .7rem; border-radius: 8px;
          border: 1px solid #2c3641; background: #101418; color: inherit; font-size: .95rem; }
  button { margin-top: 1.5rem; width: 100%; padding: .6rem; border: 0; border-radius: 8px;
           background: #3b82f6; color: #fff; font-size: .95rem; cursor: pointer; }
  button:hover { background: #2f6fe0; }
  .err { color: #f87171; font-size: .85rem; min-height: 1.2em; margin-top: 1rem; }
</style>
</head>
<body>
  <form class="card" method="post" action="/hub/login">
    <h1>DeepSeek Harness</h1>
    <p class="sub">使用服务器系统账号登录(每用户独立隔离实例)</p>
    <label for="u">用户名</label>
    <input id="u" name="username" autocomplete="username" autofocus required>
    <label for="p">密码</label>
    <input id="p" name="password" type="password" autocomplete="current-password" required>
    <div class="err">__MSG__</div>
    <button type="submit">登录</button>
  </form>
</body>
</html>`;

// -------------------------------------------------------------- handlers ----

function clientIp(req) {
  return req.socket.remoteAddress ?? '?';
}

function readBody(req, limit = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString()));
    req.on('error', reject);
  });
}

function urlencoded(body) {
  const params = new URLSearchParams(body);
  return { username: params.get('username') ?? '', password: params.get('password') ?? '' };
}

async function handleLogin(req, res) {
  const ip = clientIp(req);
  if (rateLimited(ip)) {
    sendHtml(res, 429, LOGIN_PAGE.replace('__MSG__', '尝试过多,请 1 分钟后再试'));
    return;
  }
  const { username, password } = urlencoded(await readBody(req));
  if (!username || !password) {
    sendHtml(res, 401, LOGIN_PAGE.replace('__MSG__', '请输入用户名和密码'));
    return;
  }
  const info = lookupUser(username);
  const ok = info && await pamAuthenticate(username, password)
    && !(CFG.allowUsers.length && !CFG.allowUsers.includes(username));
  if (!ok) {
    recordFailure(ip);
    sendHtml(res, 401, LOGIN_PAGE.replace('__MSG__', '用户名或密码错误'));
    return;
  }
  const token = makeCookie(username);
  res.writeHead(303, {
    'set-cookie': `${CFG.cookieName}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(CFG.sessionTtlMs / 1000)}`,
    location: '/',
  });
  res.end();
}

function handleLogout(req, res) {
  res.writeHead(303, {
    'set-cookie': `${CFG.cookieName}=; Path=/; HttpOnly; Max-Age=0`,
    location: '/hub/login',
  });
  res.end();
}

const STARTING_PAGE = `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta http-equiv="refresh" content="3"><title>starting…</title>
<style>body{font-family:system-ui;background:#101418;color:#e6e6e6;display:flex;
justify-content:center;padding-top:12rem}p{color:#8b97a3}</style></head>
<body><p>正在为你的账号启动 dsh 实例,首次约需 10 秒,即将自动刷新…</p></body></html>`;

// ------------------------------------------- /api/session.list response cache --
// dsh's session.list recomputes projections for every session (zstd-decode of
// large logs + projection apply); on this deployment it routinely takes
// 40-66s — far past the web client's 30s unary timeout, so the sidebar renders
// no history whenever the cache is cold. This cache makes the sidebar always
// instant: once a 200 response exists for a key it is served forever
// (serve-stale), with one throttled background revalidation refreshing it.
// A cached hit never spawns the backend, so idle culling keeps working.
// Revalidation failures keep the stale entry and back off, so a dead backend
// never empties the sidebar. Only 200 responses are cached; keys are per
// user + request-body hash so different payloads never mix.
const SESSION_LIST_PATH = '/api/session.list';
const RPC_CACHE_REVALIDATE_MS = 10_000;   // min gap between background refreshes
const RPC_CACHE_FAIL_BACKOFF_MS = 30_000; // pause after a failed refresh
const rpcCache = new Map(); // key -> { status, headers, body, nextRevalidateAt, inflight }
const RPC_CACHE_MAX = 500;

function sessionListCacheKey(user, body) {
  const hash = crypto.createHash('sha256').update(body).digest('hex').slice(0, 16);
  return `${user}:session.list:${hash}`;
}

function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function sanitizeForwardHeaders(headers, bePort) {
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    const key = k.toLowerCase();
    if (['connection', 'transfer-encoding', 'upgrade', 'keep-alive', 'proxy-connection', 'te', 'content-length', 'host'].includes(key)) continue;
    out[k] = v;
  }
  out.host = `127.0.0.1:${bePort}`;
  return out;
}

function forwardSessionList(be, headers, body) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port: be.port,
      method: 'POST',
      path: SESSION_LIST_PATH,
      headers: { ...sanitizeForwardHeaders(headers, be.port), 'content-length': body.length, connection: 'close' },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

function serveCachedSessionList(res, entry) {
  if (res.destroyed || res.writableEnded) return;
  try {
    res.writeHead(entry.status, {
      'content-type': entry.headers['content-type'] ?? 'application/json',
      'content-length': entry.body.length,
    });
    res.end(entry.body);
  } catch {
    /* client already gone — nothing to serve */
  }
}

async function revalidateSessionList(user, be, body, key) {
  const now = Date.now();
  try {
    const captured = await forwardSessionList(be, { accept: 'application/json', 'content-type': 'application/json' }, body);
    if (captured.status === 200) {
      rpcCache.set(key, { ...captured, nextRevalidateAt: now + RPC_CACHE_REVALIDATE_MS, inflight: false });
    } else {
      const entry = rpcCache.get(key);
      if (entry) entry.nextRevalidateAt = now + RPC_CACHE_FAIL_BACKOFF_MS;
    }
  } catch (err) {
    console.error(`[hub] session.list revalidate failed for ${user}:`, err.message);
    // Keep serving the stale snapshot; back off so a dead backend is not hammered.
    const entry = rpcCache.get(key);
    if (entry) entry.nextRevalidateAt = now + RPC_CACHE_FAIL_BACKOFF_MS;
  } finally {
    const entry = rpcCache.get(key);
    if (entry) entry.inflight = false;
  }
}

async function route(req, res) {
  const url = new URL(req.url, 'http://x');

  if (url.pathname === '/hub/login' && req.method === 'GET') {
    sendHtml(res, 200, LOGIN_PAGE.replace('__MSG__', ''));
    return;
  }
  if (url.pathname === '/hub/login' && req.method === 'POST') {
    await handleLogin(req, res);
    return;
  }
  if (url.pathname === '/hub/logout') {
    handleLogout(req, res);
    return;
  }

  const user = sessionUser(req);
  if (!user) {
    res.writeHead(303, { location: '/hub/login' });
    res.end();
    return;
  }
  if (!lookupUser(user)) {  // account deleted since login
    handleLogout(req, res);
    return;
  }

  // Session-list RPC cache: serve the last known snapshot forever (serve-stale),
  // refresh it in the background on a throttle (see block above).
  if (req.method === 'POST' && url.pathname === SESSION_LIST_PATH) {
    const body = await readRequestBody(req);
    const key = sessionListCacheKey(user, body);
    const entry = rpcCache.get(key);
    const now = Date.now();
    if (entry) {
      serveCachedSessionList(res, entry);
      if (now >= entry.nextRevalidateAt && !entry.inflight) {
        entry.inflight = true;
        const be = backends.get(user);
        if (be?.port) {
          revalidateSessionList(user, be, body, key).catch((err) =>
            console.error(`[hub] session.list revalidate failed for ${user}:`, err.message));
        } else {
          entry.inflight = false;
          entry.nextRevalidateAt = now + RPC_CACHE_FAIL_BACKOFF_MS;
        }
      }
      return;
    }
    // No snapshot yet: forward (capturing), cache 200s, respond.
    let be;
    try {
      be = await getOrCreateBackend(user);
    } catch (err) {
      console.error(`[hub] spawn failed for ${user}:`, err.message);
      sendHtml(res, 503, `<pre>dsh-hub: 无法启动你的实例\n${err.message}</pre>`);
      return;
    }
    be.lastActivity = Date.now();
    req.headers.origin = `http://127.0.0.1:${be.port}`;
    req.headers['accept-encoding'] = 'identity';
    let captured;
    try {
      captured = await forwardSessionList(be, req.headers, body);
    } catch (err) {
      // Backend died between spawn and forward (cull/restart race): fall back
      // to the streaming proxy, which re-triggers the spawn-on-demand path.
      console.error(`[hub] session.list forward failed for ${user}:`, err.message);
      proxy.web(req, res, { target: `http://127.0.0.1:${be.port}` });
      return;
    }
    if (captured.status === 200) {
      if (rpcCache.size >= RPC_CACHE_MAX) {
        const oldest = rpcCache.keys().next().value;
        if (oldest !== undefined) rpcCache.delete(oldest);
      }
      rpcCache.set(key, {
        ...captured,
        nextRevalidateAt: now + RPC_CACHE_REVALIDATE_MS,
        inflight: false,
      });
    }
    if (res.destroyed || res.writableEnded) return;
    res.writeHead(captured.status, {
      'content-type': captured.headers['content-type'] ?? 'application/json',
      'content-length': captured.body.length,
    });
    res.end(captured.body);
    return;
  }

  // Fast path: spawn already in progress — show the "starting" page instead
  // of blocking the request for the full spawn duration.
  const existing = backends.get(user);
  if (existing?.starting) {
    sendHtml(res, 200, STARTING_PAGE);
    return;
  }

  let be;
  try {
    be = await getOrCreateBackend(user);
  } catch (err) {
    console.error(`[hub] spawn failed for ${user}:`, err.message);
    sendHtml(res, 503, `<pre>dsh-hub: 无法启动你的实例\n${err.message}</pre>`);
    return;
  }
  be.lastActivity = Date.now();
  if (TRUST_MODE === 'origin-rewrite') {
    // Legacy fallback: align Origin with the loopback Host changeOrigin sends;
    // cross-site protection is carried by the hub's SameSite cookie instead.
    // Also inject Origin when the browser omitted it entirely (service-worker
    // or extension re-fetches drop Origin/Sec-Fetch-* headers): plugin guards
    // like task-board's browser-marker check need one of the two, and this
    // request already passed the hub's PAM cookie authentication.
    req.headers.origin = `http://127.0.0.1:${be.port}`;
  }
  // Force identity encoding so the HTML rewrite below sees plain text.
  req.headers['accept-encoding'] = 'identity';
  proxy.web(req, res, { target: `http://127.0.0.1:${be.port}` });
}

const server = http.createServer((req, res) => {
  route(req, res).catch((err) => {
    console.error('[hub] handler error:', err);
    if (!res.headersSent) res.writeHead(500);
    res.end('dsh-hub: internal error');
  });
});

// WebSocket upgrade (dsh event streams) — routed by the same session cookie.
server.on('upgrade', (req, socket, head) => {
  const user = sessionUser(req);
  if (!user) {
    socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
    socket.destroy();
    return;
  }
  const be = backends.get(user);
  if (!be || !be.child || be.child.exitCode !== null) {
    socket.write('HTTP/1.1 503 Service Unavailable\r\n\r\n');
    socket.destroy();
    return;
  }
  be.lastActivity = Date.now();
  if (TRUST_MODE === 'origin-rewrite') {
    req.headers.origin = `http://127.0.0.1:${be.port}`;
  }
  proxy.ws(req, socket, head, { target: `http://127.0.0.1:${be.port}` });
});

// ------------------------------------------------------------------ boot ----

try { fs.mkdirSync(CFG.logDir, { recursive: true }); } catch { /* non-root dev run */ }
server.listen(CFG.hubPort, CFG.hubHost, () => {
  console.log(`[hub] dsh-hub listening on ${CFG.hubHost}:${CFG.hubPort}`);
  console.log(`[hub] dsh binary: ${CFG.dshBin}`);
  console.log(`[hub] trust mode: ${TRUST_MODE}` +
    (TRUST_MODE === 'trusted-host' ? ` (authorities: ${TRUSTED_HOSTS.join(', ') || 'none detected — set TRUSTED_HOSTS'})` : ''));
  console.log(`[hub] running as ${IS_ROOT ? 'root (full isolation mode)' : `uid ${process.getuid?.()} (dev mode — no setuid/iptables)`}`);
  if (!IPTABLES) console.warn('[hub] WARNING: iptables unavailable — loopback ports of user instances are NOT guarded against other local users');
  if (CFG.allowUsers.length) console.log(`[hub] allow-list: ${CFG.allowUsers.join(', ')}`);
  console.log(CFG.idleCullMs === 0
    ? '[hub] idle culling DISABLED — backends run until stopped'
    : `[hub] idle cull after ${Math.round(CFG.idleCullMs / 60000)} min`);
});
