'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { spawn } = require('node:child_process');

async function freePort() { return new Promise(resolve => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); }); }); }
async function ready(url, process) { for (let i = 0; i < 100; i++) { if (process.exitCode !== null) throw new Error('panel exited'); try { if ((await fetch(url + '/health')).ok) return; } catch {} await new Promise(r => setTimeout(r, 50)); } throw new Error('not ready'); }
test('login, CSRF, create, persistence across restart, delete', async t => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'panel-test-'));
  const mock = path.join(tmp, 'xray');
  fs.writeFileSync(mock, `#!/usr/bin/env node
const http = require('http'), crypto = require('crypto'); if (process.argv.includes('-test')) process.exit(0); const server = http.createServer((req, res) => res.end()); server.on('upgrade', (req, socket) => { const accept = crypto.createHash('sha1').update(req.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64'); socket.write('HTTP/1.1 101 Switching Protocols\\r\\nUpgrade: websocket\\r\\nConnection: Upgrade\\r\\nSec-WebSocket-Accept: ' + accept + '\\r\\n\\r\\n'); }); server.listen(10000, '127.0.0.1');
`, { mode: 0o755 });
  const port = await freePort(), url = `http://127.0.0.1:${port}`;
  const env = { ...process.env, ADMIN_PASSWORD: 'a-very-long-test-password', DATA_DIR: path.join(tmp, 'data'), XRAY_PATH: mock, PORT: String(port), PUBLIC_URL: url, NODE_ENV: 'test' };
  let child;
  async function start() { child = spawn(process.execPath, ['server.js'], { cwd: path.join(__dirname, '..'), env, stdio: 'ignore' }); await ready(url, child); }
  async function stop() { if (child && child.exitCode === null) { child.kill('SIGTERM'); await new Promise(resolve => child.once('exit', resolve)); } }
  t.after(async () => { await stop(); fs.rmSync(tmp, { recursive: true, force: true }); });
  await start();
  assert.equal((await fetch(url + '/api/clients')).status, 401);
  const login = await fetch(url + '/api/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ password: env.ADMIN_PASSWORD }) });
  assert.equal(login.status, 200);
  const cookie = login.headers.get('set-cookie').split(';')[0], csrf = (await login.json()).csrf;
  assert.equal((await fetch(url + '/api/clients', { method: 'POST', headers: { cookie, 'content-type': 'application/json' }, body: JSON.stringify({ name: 'test' }) })).status, 403);
  const created = await fetch(url + '/api/clients', { method: 'POST', headers: { cookie, 'x-csrf-token': csrf, 'content-type': 'application/json' }, body: JSON.stringify({ name: 'گوشی' }) });
  assert.equal(created.status, 201); const entry = await created.json(); assert.match(entry.link, /^vless:\/\//); assert.match(entry.link, /security=none/);
  const websocket = new WebSocket(`ws://127.0.0.1:${port}/vpn`);
  await new Promise((resolve, reject) => { websocket.addEventListener('open', resolve, { once: true }); websocket.addEventListener('error', reject, { once: true }); });
  websocket.close();
  await stop(); await start();
  const login2 = await fetch(url + '/api/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ password: env.ADMIN_PASSWORD }) });
  const cookie2 = login2.headers.get('set-cookie').split(';')[0], csrf2 = (await login2.json()).csrf;
  const list = await (await fetch(url + '/api/clients', { headers: { cookie: cookie2 } })).json();
  assert.equal(list.clients.length, 1); assert.equal(list.clients[0].id, entry.id);
  const del = await fetch(url + '/api/clients/' + entry.id, { method: 'DELETE', headers: { cookie: cookie2, 'x-csrf-token': csrf2 } }); assert.equal(del.status, 200);
  assert.equal((await (await fetch(url + '/api/clients', { headers: { cookie: cookie2 } })).json()).clients.length, 0);
});
