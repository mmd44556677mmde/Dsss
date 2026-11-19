'use strict';

const express = require('express');
const http = require('http');
const net = require('net');
const proxy = require('http-proxy').createProxyServer({ target: 'http://127.0.0.1:10000', ws: true });
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawn, execFileSync } = require('child_process');

const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.resolve(process.env.DATA_DIR || './data');
const XRAY = process.env.XRAY_PATH || 'xray';
const PASSWORD = process.env.ADMIN_PASSWORD || '';
if (PASSWORD.length < 16) throw new Error('ADMIN_PASSWORD must be at least 16 characters');
const configuredUrl = process.env.PUBLIC_URL || (process.env.RAILWAY_PUBLIC_DOMAIN ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : `http://localhost:${PORT}`);
const publicUrl = new URL(configuredUrl);
if (!['http:', 'https:'].includes(publicUrl.protocol) || publicUrl.username || publicUrl.password || publicUrl.pathname !== '/' || publicUrl.search || publicUrl.hash) throw new Error('PUBLIC_URL must be an http(s) origin without a path');
if (process.env.NODE_ENV === 'production' && publicUrl.protocol !== 'https:') throw new Error('Production PUBLIC_URL must use HTTPS');
fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
const statePath = path.join(DATA_DIR, 'clients.json');
const configPath = path.join(DATA_DIR, 'xray.json');
let clients = fs.existsSync(statePath) ? JSON.parse(fs.readFileSync(statePath, 'utf8')) : [];
if (!Array.isArray(clients) || clients.some(c => !c || !crypto.randomUUID || typeof c.name !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(c.id))) throw new Error('Invalid saved clients.json');
function atomicWrite(file, data) {
  const temp = `${file}.${crypto.randomBytes(8).toString('hex')}.tmp`;
  try { fs.writeFileSync(temp, data, { mode: 0o600, flag: 'wx' }); fs.renameSync(temp, file); }
  finally { try { fs.unlinkSync(temp); } catch (e) { if (e.code !== 'ENOENT') console.error('Temporary file cleanup failed', e.message); } }
}
function xrayConfig(entries) {
  return {
    log: { loglevel: 'warning', access: 'none' },
    inbounds: [{ listen: '127.0.0.1', port: 10000, protocol: 'vless', settings: { clients: entries.map(c => ({ id: c.id })), decryption: 'none' }, streamSettings: { network: 'ws', wsSettings: { path: '/vpn' } } }],
    outbounds: [{ protocol: 'freedom', tag: 'direct' }, { protocol: 'blackhole', tag: 'blocked' }],
    routing: { domainStrategy: 'IPIfNonMatch', rules: [
      { type: 'field', domain: ['regexp:(^|\\.)railway\\.internal$', 'full:localhost'], outboundTag: 'blocked' },
      { type: 'field', ip: ['geoip:private', '0.0.0.0/8', '100.64.0.0/10', '169.254.0.0/16', '224.0.0.0/4', '::1/128', 'fc00::/7', 'fe80::/10'], outboundTag: 'blocked' }
    ] }
  };
}
let child = null, stopping = false, shuttingDown = false;
async function startCore(entries) {
  atomicWrite(configPath, JSON.stringify(xrayConfig(entries), null, 2));
  execFileSync(XRAY, ['run', '-test', '-config', configPath], { stdio: 'pipe', timeout: 10000 });
  const instance = spawn(XRAY, ['run', '-config', configPath], { stdio: ['ignore', 'ignore', 'pipe'] });
  child = instance;
  instance.stderr.on('data', data => console.error('Xray:', data.toString().trim()));
  instance.on('error', err => console.error('Xray process error:', err.message));
  instance.on('exit', (code) => {
    if (child === instance) child = null;
    if (!stopping && !shuttingDown) { console.error(`Xray stopped (${code}); restarting app`); process.exit(1); }
  });
  for (let i = 0; i < 50; i++) {
    if (instance.exitCode !== null || instance.signalCode !== null) throw new Error('Xray failed to start');
    const available = await new Promise(resolve => { const s = net.connect(10000, '127.0.0.1'); s.once('connect', () => { s.destroy(); resolve(true); }); s.once('error', () => resolve(false)); s.setTimeout(200, () => { s.destroy(); resolve(false); }); });
    if (available) return;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error('Xray did not become ready');
}
async function stopCore() {
  if (!child) return;
  const instance = child;
  stopping = true;
  await new Promise(resolve => {
    const timer = setTimeout(() => instance.kill('SIGKILL'), 3000);
    instance.once('exit', () => { clearTimeout(timer); resolve(); });
    instance.kill('SIGTERM');
  });
  stopping = false;
}
let queue = Promise.resolve();
function changeClients(update) {
  const work = queue.then(async () => {
    const next = update(clients);
    const old = clients;
    // Validate before disrupting connections; the state is authoritative after restart.
    const candidate = path.join(DATA_DIR, 'candidate.json');
    atomicWrite(candidate, JSON.stringify(xrayConfig(next)));
    try { execFileSync(XRAY, ['run', '-test', '-config', candidate], { stdio: 'pipe', timeout: 10000 }); }
    finally { try { fs.unlinkSync(candidate); } catch {} }
    atomicWrite(statePath, JSON.stringify(next));
    try { await stopCore(); await startCore(next); clients = next; }
    catch (error) {
      try { await stopCore(); atomicWrite(statePath, JSON.stringify(old)); await startCore(old); }
      catch (rollbackError) { console.error('Core rollback failed:', rollbackError.message); process.exit(1); }
      throw error;
    }
  });
  queue = work.catch(() => {});
  return work;
}
const sessions = new Map();
const failures = [];
function getSession(req) {
  const token = /(?:^|;\s*)session=([a-f0-9]{64})(?:;|$)/.exec(req.headers.cookie || '')?.[1];
  const session = token && sessions.get(token);
  if (session && session.expires > Date.now()) return session;
  if (token) sessions.delete(token);
  return null;
}
function requireAuth(req, res, next) {
  const session = getSession(req);
  if (!session) return res.status(401).json({ error: 'ابتدا وارد شوید.' });
  if (!['GET', 'HEAD'].includes(req.method) && req.get('X-CSRF-Token') !== session.csrf) return res.status(403).json({ error: 'درخواست نامعتبر است.' });
  req.session = session; next();
}
function clientLink(c) {
  const query = new URLSearchParams({ encryption: 'none', security: publicUrl.protocol === 'https:' ? 'tls' : 'none', type: 'ws', host: publicUrl.hostname, path: '/vpn' });
  if (publicUrl.protocol === 'https:') query.set('sni', publicUrl.hostname);
  return `vless://${c.id}@${publicUrl.hostname}:${publicUrl.port || (publicUrl.protocol === 'https:' ? '443' : '80')}?${query}#${encodeURIComponent(c.name)}`;
}
const app = express();
app.disable('x-powered-by');
app.use((req, res, next) => { res.set('X-Content-Type-Options', 'nosniff'); res.set('X-Frame-Options', 'DENY'); res.set('Referrer-Policy', 'no-referrer'); res.set('Content-Security-Policy', "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"); res.set('Cache-Control', 'no-store'); next(); });
app.use(express.json({ limit: '4kb', inflate: false }));
app.get('/health', (req, res) => res.status(child ? 200 : 503).send(child ? 'ok' : 'core unavailable'));
app.post('/api/login', (req, res) => {
  const now = Date.now(); while (failures.length && failures[0] < now - 15 * 60 * 1000) failures.shift();
  if (failures.length >= 15) return res.status(429).json({ error: 'تلاش بیش از حد؛ ۱۵ دقیقه بعد دوباره امتحان کنید.' });
  const supplied = typeof req.body?.password === 'string' ? req.body.password : '';
  const a = crypto.createHash('sha256').update(supplied).digest();
  const b = crypto.createHash('sha256').update(PASSWORD).digest();
  if (!crypto.timingSafeEqual(a, b)) { failures.push(now); return res.status(401).json({ error: 'رمز عبور نادرست است.' }); }
  failures.length = 0;
  for (const [key, value] of sessions) if (value.expires <= now) sessions.delete(key);
  if (sessions.size >= 100) return res.status(429).json({ error: 'تعداد نشست‌ها بیش از حد است.' });
  const token = crypto.randomBytes(32).toString('hex');
  const csrf = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { csrf, expires: now + 8 * 60 * 60 * 1000 });
  res.set('Set-Cookie', `session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800${publicUrl.protocol === 'https:' ? '; Secure' : ''}`);
  res.json({ csrf });
});
app.get('/api/session', requireAuth, (req, res) => res.json({ csrf: req.session.csrf }));
app.post('/api/logout', requireAuth, (req, res) => { for (const [key, value] of sessions) if (value === req.session) sessions.delete(key); res.set('Set-Cookie', 'session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0'); res.json({ ok: true }); });
app.get('/api/clients', requireAuth, (req, res) => res.json({ clients: clients.map(c => ({ ...c, link: clientLink(c) })), core: Boolean(child), publicOrigin: publicUrl.origin }));
app.post('/api/clients', requireAuth, async (req, res) => {
  const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
  if (!name || name.length > 60 || /[\u0000-\u001f\u007f]/.test(name)) return res.status(400).json({ error: 'نام باید بین ۱ تا ۶۰ کاراکتر باشد.' });
  const entry = { id: crypto.randomUUID(), name, createdAt: new Date().toISOString() };
  try { await changeClients(old => [...old, entry]); res.status(201).json({ ...entry, link: clientLink(entry) }); }
  catch (e) { console.error('Create failed:', e.message); res.status(500).json({ error: 'اعمال تغییر ناموفق بود؛ وضعیت هسته و فضای ذخیره را بررسی کنید.' }); }
});
app.delete('/api/clients/:id', requireAuth, async (req, res) => {
  try {
    await changeClients(old => { if (!old.some(c => c.id === req.params.id)) { const e = new Error('not found'); e.notFound = true; throw e; } return old.filter(c => c.id !== req.params.id); });
    res.json({ ok: true });
  } catch (e) { if (e.notFound) return res.status(404).json({ error: 'کانفیگ پیدا نشد.' }); console.error('Delete failed:', e.message); res.status(500).json({ error: 'حذف ناموفق بود؛ وضعیت هسته را بررسی کنید.' }); }
});
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html' }));
app.use((err, req, res, next) => { console.error('Request error:', err.message); res.status(err.status || 500).json({ error: 'درخواست نامعتبر است.' }); });
const server = http.createServer(app);
proxy.on('error', (err, req, res) => { console.error('Proxy error:', err.message); if (res && typeof res.writeHead === 'function' && !res.headersSent) { res.writeHead(502); res.end('Core unavailable'); } else if (res && typeof res.destroy === 'function') res.destroy(); });
server.on('upgrade', (req, socket, head) => {
  if (req.url !== '/vpn' || !child) return socket.destroy();
  proxy.ws(req, socket, head);
});
async function main() {
  await startCore(clients);
  server.listen(PORT, '0.0.0.0', () => console.log(`Panel listening on port ${PORT}`));
}
main().catch(e => { console.error('Startup failed:', e.message); process.exit(1); });
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, async () => { if (shuttingDown) return; shuttingDown = true; server.close(); await stopCore(); process.exit(0); });
