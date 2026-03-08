import http from 'http';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DB_FILE = path.join(__dirname, 'data.json');

const PORT = Number(process.env.PORT || 3000);
const ADMIN_LOGIN = process.env.MRV_ADMIN_LOGIN || 'admin';
const ADMIN_PASSWORD = process.env.MRV_ADMIN_PASSWORD || 'change-me-now';

const uid = () => crypto.randomUUID();
const now = () => Date.now();
const hash = (v) => crypto.createHash('sha256').update(String(v)).digest('hex');
const token = () => crypto.randomBytes(32).toString('base64url');

const emptyDb = () => ({
  users: {}, usersByLogin: {}, sessions: {}, adminSessions: {},
  servers: {}, channels: {}, memberships: {}, messages: {}, invites: {},
  bans: { ips: {}, users: {}, servers: {} },
  audit: [],
});

let db = emptyDb();
if (fs.existsSync(DB_FILE)) {
  db = { ...db, ...JSON.parse(fs.readFileSync(DB_FILE, 'utf8')) };
}
const saveDb = () => fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
const audit = (action, extra = {}) => { db.audit.unshift({ id: uid(), action, at: new Date().toISOString(), ...extra }); db.audit = db.audit.slice(0, 1000); saveDb(); };

const sseClients = new Map(); // token -> Set(res)
function pushEventToServer(serverId, payload) {
  const msg = `data: ${JSON.stringify(payload)}\n\n`;
  for (const [tok, set] of sseClients.entries()) {
    const sess = db.sessions[tok];
    if (!sess) continue;
    if (!db.memberships[`${sess.userId}:${serverId}`]) continue;
    for (const res of set) res.write(msg);
  }
}

function send(res, status, payload, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
  res.end(JSON.stringify(payload));
}
function parseBody(req) {
  return new Promise((resolve) => {
    let b = '';
    req.on('data', (c) => { b += c.toString(); if (b.length > 2_000_000) req.destroy(); });
    req.on('end', () => { try { resolve(b ? JSON.parse(b) : {}); } catch { resolve({}); } });
  });
}
function ipOf(req) {
  const xf = req.headers['x-forwarded-for'];
  return (Array.isArray(xf) ? xf[0] : (xf || '')).split(',')[0].trim() || req.socket.remoteAddress || '';
}
function getAuthToken(req) {
  const h = req.headers.authorization || '';
  return h.startsWith('Bearer ') ? h.slice(7) : null;
}
function checkUser(req) {
  const t = getAuthToken(req);
  const s = t ? db.sessions[t] : null;
  const u = s ? db.users[s.userId] : null;
  if (!u) return { err: ['unauthorized', 401] };
  const ip = ipOf(req);
  if (db.bans.ips[ip]) return { err: ['ip_banned', 403, db.bans.ips[ip].reason || null] };
  if (db.bans.users[u.id]) return { err: ['user_banned', 403, db.bans.users[u.id].reason || null] };
  return { token: t, session: s, user: u, ip };
}


function contentTypeByExt(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === '.html') return 'text/html; charset=utf-8';
  if (ext === '.js') return 'application/javascript; charset=utf-8';
  if (ext === '.css') return 'text/css; charset=utf-8';
  if (ext === '.json') return 'application/json; charset=utf-8';
  if (ext === '.svg') return 'image/svg+xml';
  if (ext === '.png') return 'image/png';
  if (ext === '.jpg' || ext === '.jpeg') return 'image/jpeg';
  return 'application/octet-stream';
}

function serveStatic(res, filePath, contentType = 'text/html; charset=utf-8') {
  if (!fs.existsSync(filePath)) return send(res, 404, { error: 'not_found' });
  res.writeHead(200, { 'Content-Type': contentType });
  fs.createReadStream(filePath).pipe(res);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (req.method === 'GET' && url.pathname === '/healthz') return send(res, 200, { ok: true, service: 'mrv' });
  if (req.method === 'GET' && url.pathname === '/') return serveStatic(res, path.join(__dirname, 'morv-full-release-2_0.html'));
  if (req.method === 'GET' && url.pathname === '/admmrv') return serveStatic(res, path.join(__dirname, 'morv-admin.html'));
  if (req.method === 'GET' && url.pathname.startsWith('/invite/')) return serveStatic(res, path.join(__dirname, 'morv-full-release-2_0.html'));
  if (req.method === 'GET' && /^\/[\w.-]+$/.test(url.pathname)) {
    const directPath = path.join(__dirname, url.pathname.slice(1));
    if (fs.existsSync(directPath) && fs.statSync(directPath).isFile()) {
      return serveStatic(res, directPath, contentTypeByExt(directPath));
    }
  }

  if (req.method === 'GET' && url.pathname === '/api/events') {
    const auth = checkUser(req);
    if (auth.err) return send(res, auth.err[1], { error: auth.err[0], message: 'Доступ к Morv для вас был закрыт.', reason: auth.err[2] || null });
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    });
    res.write('event: hello\ndata: {"ok":true}\n\n');
    if (!sseClients.has(auth.token)) sseClients.set(auth.token, new Set());
    sseClients.get(auth.token).add(res);
    req.on('close', () => sseClients.get(auth.token)?.delete(res));
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/register') {
    const body = await parseBody(req);
    if (!body.login || !body.password || !body.publicIdentityKey) return send(res, 400, { error: 'login_password_key_required' });
    if (db.usersByLogin[body.login]) return send(res, 409, { error: 'login_taken' });
    const id = uid();
    db.users[id] = { id, login: body.login, passwordHash: hash(body.password), publicIdentityKey: body.publicIdentityKey, createdAt: now(), lastIp: ipOf(req) };
    db.usersByLogin[body.login] = id;
    saveDb();
    return send(res, 200, { ok: true });
  }

  if (req.method === 'POST' && url.pathname === '/api/login') {
    const body = await parseBody(req);
    const id = db.usersByLogin[body.login || ''];
    const u = id ? db.users[id] : null;
    if (!u || u.passwordHash !== hash(body.password || '')) return send(res, 401, { error: 'invalid_credentials' });
    const ip = ipOf(req);
    if (db.bans.ips[ip]) return send(res, 403, { error: 'ip_banned', message: 'Доступ к Morv для вас был закрыт.', reason: db.bans.ips[ip].reason || null });
    if (db.bans.users[u.id]) return send(res, 403, { error: 'user_banned', message: 'Доступ к Morv для вас был закрыт.', reason: db.bans.users[u.id].reason || null });
    const t = token();
    db.sessions[t] = { userId: u.id, createdAt: now(), ip };
    u.lastIp = ip;
    saveDb();
    return send(res, 200, { token: t, user: { id: u.id, login: u.login, publicIdentityKey: u.publicIdentityKey } });
  }

  if (req.method === 'GET' && url.pathname === '/api/me') {
    const auth = checkUser(req);
    if (auth.err) return send(res, auth.err[1], { error: auth.err[0], message: 'Доступ к Morv для вас был закрыт.', reason: auth.err[2] || null });
    return send(res, 200, { id: auth.user.id, login: auth.user.login, publicIdentityKey: auth.user.publicIdentityKey });
  }

  if (req.method === 'POST' && url.pathname === '/api/servers') {
    const auth = checkUser(req);
    if (auth.err) return send(res, auth.err[1], { error: auth.err[0], reason: auth.err[2] || null });
    const body = await parseBody(req);
    const id = uid();
    db.servers[id] = { id, name: body.name || `server-${id.slice(0, 6)}`, ownerId: auth.user.id, members: [auth.user.id], channels: [], createdAt: now(), status: 'active' };
    db.memberships[`${auth.user.id}:${id}`] = { userId: auth.user.id, serverId: id, role: 'owner', joinedAt: now() };
    saveDb();
    audit('server.create', { serverId: id, ownerId: auth.user.id });
    return send(res, 200, db.servers[id]);
  }

  if (req.method === 'POST' && /^\/api\/servers\/[^/]+\/channels$/.test(url.pathname)) {
    const auth = checkUser(req); if (auth.err) return send(res, auth.err[1], { error: auth.err[0] });
    const serverId = url.pathname.split('/')[3];
    const srv = db.servers[serverId];
    if (!srv) return send(res, 404, { error: 'server_not_found' });
    if (!db.memberships[`${auth.user.id}:${serverId}`]) return send(res, 403, { error: 'not_member' });
    const body = await parseBody(req);
    const id = uid();
    db.channels[id] = { id, serverId, name: body.name || 'new-channel', type: body.type || 'text', createdAt: now() };
    srv.channels.push(id);
    saveDb();
    return send(res, 200, db.channels[id]);
  }

  if (req.method === 'GET' && /^\/api\/servers\/[^/]+$/.test(url.pathname)) {
    const auth = checkUser(req); if (auth.err) return send(res, auth.err[1], { error: auth.err[0] });
    const serverId = url.pathname.split('/')[3];
    const srv = db.servers[serverId];
    if (!srv) return send(res, 404, { error: 'server_not_found' });
    if (!db.memberships[`${auth.user.id}:${serverId}`]) return send(res, 403, { error: 'not_member' });
    return send(res, 200, { ...srv, channels: srv.channels.map((id) => db.channels[id]).filter(Boolean) });
  }

  if (req.method === 'POST' && /^\/api\/servers\/[^/]+\/invites\/refresh$/.test(url.pathname)) {
    const auth = checkUser(req); if (auth.err) return send(res, auth.err[1], { error: auth.err[0] });
    const serverId = url.pathname.split('/')[3];
    const srv = db.servers[serverId];
    if (!srv) return send(res, 404, { error: 'server_not_found' });
    if (srv.ownerId !== auth.user.id) return send(res, 403, { error: 'owner_only' });
    const t = token();
    const expiresAt = now() + 24 * 60 * 60 * 1000;
    db.invites[t] = { token: t, serverId, expiresAt, createdBy: auth.user.id, createdAt: now() };
    saveDb();
    return send(res, 200, { token: t, inviteLink: `/invite/${t}`, qrLink: `/api/invites/${t}/qr`, expiresAt });
  }

  if (req.method === 'GET' && /^\/api\/invites\/[^/]+\/qr$/.test(url.pathname)) {
    const t = url.pathname.split('/')[3];
    const inv = db.invites[t];
    if (!inv || inv.expiresAt < now()) return send(res, 404, { error: 'invite_not_found_or_expired' });
    // Lightweight SVG "real" QR-compatible transport fallback: encoded link for client-side renderer.
    const link = `${url.protocol}//${url.host}/invite/${t}`;
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="320" height="320"><rect width="100%" height="100%" fill="#fff"/><text x="10" y="40" font-size="14" fill="#000">SCAN LINK</text><text x="10" y="70" font-size="11" fill="#000">${link.replace(/&/g, '&amp;')}</text></svg>`;
    res.writeHead(200, { 'Content-Type': 'image/svg+xml; charset=utf-8' });
    return res.end(svg);
  }

  if (req.method === 'POST' && /^\/invite\/[^/]+\/join$/.test(url.pathname)) {
    const auth = checkUser(req); if (auth.err) return send(res, auth.err[1], { error: auth.err[0] });
    const t = url.pathname.split('/')[2];
    const inv = db.invites[t];
    if (!inv || inv.expiresAt < now()) return send(res, 404, { error: 'invite_not_found_or_expired' });
    const srv = db.servers[inv.serverId];
    if (!srv) return send(res, 404, { error: 'server_not_found' });
    if (!srv.members.includes(auth.user.id)) srv.members.push(auth.user.id);
    db.memberships[`${auth.user.id}:${srv.id}`] = { userId: auth.user.id, serverId: srv.id, role: 'member', joinedAt: now() };
    saveDb();
    return send(res, 200, { ok: true, serverId: srv.id });
  }

  if (req.method === 'POST' && url.pathname === '/api/messages') {
    const auth = checkUser(req); if (auth.err) return send(res, auth.err[1], { error: auth.err[0] });
    const body = await parseBody(req);
    if (!body.channelId || !body.ciphertext || !body.nonce || !body.epk) return send(res, 400, { error: 'encrypted_payload_required' });
    const ch = db.channels[body.channelId];
    if (!ch) return send(res, 404, { error: 'channel_not_found' });
    if (!db.memberships[`${auth.user.id}:${ch.serverId}`]) return send(res, 403, { error: 'not_member' });
    const id = uid();
    db.messages[id] = { id, channelId: ch.id, senderId: auth.user.id, ciphertext: body.ciphertext, nonce: body.nonce, epk: body.epk, algorithm: body.algorithm || 'x25519-xsalsa20poly1305', createdAt: now() };
    saveDb();
    pushEventToServer(ch.serverId, { type: 'message.new', message: db.messages[id] });
    return send(res, 200, { id });
  }

  if (req.method === 'GET' && /^\/api\/channels\/[^/]+\/messages$/.test(url.pathname)) {
    const auth = checkUser(req); if (auth.err) return send(res, auth.err[1], { error: auth.err[0] });
    const channelId = url.pathname.split('/')[3];
    const ch = db.channels[channelId];
    if (!ch) return send(res, 404, { error: 'channel_not_found' });
    if (!db.memberships[`${auth.user.id}:${ch.serverId}`]) return send(res, 403, { error: 'not_member' });
    const items = Object.values(db.messages).filter((m) => m.channelId === channelId).sort((a, b) => a.createdAt - b.createdAt).slice(-200);
    return send(res, 200, items);
  }

  if (req.method === 'POST' && url.pathname === '/api/voice/signal') {
    const auth = checkUser(req); if (auth.err) return send(res, auth.err[1], { error: auth.err[0] });
    const body = await parseBody(req);
    const srvId = body.serverId;
    if (!srvId || !db.memberships[`${auth.user.id}:${srvId}`]) return send(res, 403, { error: 'not_member' });
    pushEventToServer(srvId, {
      type: 'voice.signal',
      fromUserId: auth.user.id,
      toUserId: body.toUserId || null,
      signal: body.signal || null,
      mutedMic: !!body.mutedMic,
      mutedSound: !!body.mutedSound,
    });
    return send(res, 200, { ok: true });
  }

  if (req.method === 'POST' && url.pathname === '/api/panic') {
    const auth = checkUser(req); if (auth.err) return send(res, auth.err[1], { error: auth.err[0] });
    const userId = auth.user.id;
    Object.keys(db.sessions).forEach((k) => { if (db.sessions[k].userId === userId) delete db.sessions[k]; });
    Object.keys(db.memberships).forEach((k) => { if (db.memberships[k].userId === userId) delete db.memberships[k]; });
    Object.keys(db.messages).forEach((k) => { if (db.messages[k].senderId === userId) delete db.messages[k]; });
    Object.values(db.servers).forEach((s) => { s.members = s.members.filter((id) => id !== userId); });
    delete db.usersByLogin[auth.user.login];
    delete db.users[userId];
    saveDb();
    audit('panic.executed', { userId });
    return send(res, 200, { ok: true });
  }

  if (req.method === 'POST' && url.pathname === '/api/admin/login') {
    const body = await parseBody(req);
    if (body.login !== ADMIN_LOGIN || body.password !== ADMIN_PASSWORD) return send(res, 401, { error: 'invalid_admin_credentials' });
    const t = token();
    db.adminSessions[t] = { createdAt: now() };
    saveDb();
    return send(res, 200, { token: t });
  }

  if (req.method === 'GET' && url.pathname === '/api/admin/state') {
    const t = getAuthToken(req);
    if (!t || !db.adminSessions[t]) return send(res, 401, { error: 'admin_unauthorized' });
    return send(res, 200, {
      servers: Object.values(db.servers),
      bannedIps: db.bans.ips,
      bannedUsers: db.bans.users,
      bannedServers: db.bans.servers,
      audit: db.audit.slice(0, 200),
    });
  }

  if (req.method === 'POST' && url.pathname === '/api/admin/ban-server') {
    const t = getAuthToken(req);
    if (!t || !db.adminSessions[t]) return send(res, 401, { error: 'admin_unauthorized' });
    const body = await parseBody(req);
    const srv = db.servers[body.serverId || ''];
    if (!srv) return send(res, 404, { error: 'server_not_found' });
    srv.status = 'banned';
    db.bans.servers[srv.id] = { serverId: srv.id, reason: body.reason || null, at: now() };
    srv.members.forEach((memberId) => {
      db.bans.users[memberId] = { userId: memberId, reason: body.reason || 'ban_by_server', at: now() };
      const u = db.users[memberId];
      if (u?.lastIp) db.bans.ips[u.lastIp] = { ip: u.lastIp, permanent: true, reason: body.reason || 'ban_by_server', at: now() };
    });
    saveDb();
    audit('admin.ban_server', { serverId: srv.id, reason: body.reason || null });
    pushEventToServer(srv.id, { type: 'ban.enforced', serverId: srv.id, reason: body.reason || null });
    return send(res, 200, { ok: true });
  }

  send(res, 404, { error: 'not_found' });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`MRV server running on http://0.0.0.0:${PORT}`);
  console.log('Admin route: /admmrv');
});
