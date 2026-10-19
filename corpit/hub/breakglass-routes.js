// =====================================================================
// breakglass-routes.js  (v1.0.0)
//
// Login endpoint for the 'itam' break-glass account.
//
//   POST /api/breakglass/login   { password, totp }
//     -> 200 { token, expiresInMinutes }   on success
//     -> 401 { error, code }               on any failure (deliberately vague)
//     -> 429 { error, code }               when locked out
//     -> 503 { error, code }               when not enrolled
//
// Controls:
//   * Rate limit: 5 failures per source IP -> 15 minute lockout (in-memory;
//     a process restart clears it, which is acceptable for a single-node
//     deployment and avoids a DB dependency during an outage).
//   * Every attempt (success and failure) -> rbac_audit_log.
//   * Every SUCCESS -> alert email via Microsoft Graph (app 04ecee8f
//     credentials, AZURE_* env vars, same pattern as the digest job).
//     Email failure never blocks the login - during a real outage Graph
//     may be down too; the audit row is the record that cannot fail open.
//
// Mount (server.js):
//   const breakglassRoutes = require('./breakglass-routes');
//   app.use('/api/breakglass', breakglassRoutes);
//
// NOTE: intentionally does NOT use rbac-middleware - this is the path that
// must work when Azure, the DC, and everything else is down.
// =====================================================================

'use strict';

const express = require('express');
const mysql   = require('mysql2/promise');
const bg      = require('./breakglass-auth');
const mailGraph = require('./mail-graph');

const router = express.Router();
router.use(express.json({ limit: '4kb' }));

const ALERT_TO = (process.env.BREAKGLASS_ALERT_TO || 'jriggs@auction.com')
  .split(',').map(s => s.trim()).filter(Boolean);
// [CORPIT-QA 2026-09-07] ALERT_FROM removed. It was used as the /users/{id}
// path segment, and the mail attribute is not an identifier Graph accepts in /users/{...},
// so NO break-glass alert has ever been delivered from this host -- the
// send 404'd and the catch below logged it where nobody reads. The From:
// address is unchanged (itcommand@auction.com); mail-graph.js owns it,
// and CORPIT_MAIL_FROM overrides it platform-wide if it ever must change.

// Small dedicated pool for audit writes only.
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 2,
});

// ---------- rate limiting (per source IP, in-memory) --------------------

const MAX_FAILURES  = 5;
const LOCKOUT_MS    = 15 * 60 * 1000;
// Global backstop: a per-IP counter alone can be rotated around, so '*' counts
// every failure from every source and locks the door for everyone at 20.
const GLOBAL_KEY    = '*';
const GLOBAL_MAX_FAILURES = 20;
const failures = new Map();   // ip -> { count, lockedUntil, last }

function clientIp(req) {
  // nginx sets X-Real-IP from $remote_addr; X-Forwarded-For is client-supplied and forgeable.
  return (req.headers['x-real-ip'] || (req.socket && req.socket.remoteAddress) || '')
    .split(',')[0].trim() || 'unknown';
}

function checkLock(ip) {
  if (ip !== GLOBAL_KEY) { const g = checkLock(GLOBAL_KEY); if (g.locked) return g; }
  const rec = failures.get(ip);
  if (!rec) return { locked: false };
  if (rec.lockedUntil && Date.now() < rec.lockedUntil) {
    return { locked: true, retryAfterS: Math.ceil((rec.lockedUntil - Date.now()) / 1000) };
  }
  if (rec.lockedUntil && Date.now() >= rec.lockedUntil) failures.delete(ip);
  return { locked: false };
}

function recordFailure(ip) {
  if (ip !== GLOBAL_KEY) recordFailure(GLOBAL_KEY);
  const rec = failures.get(ip) || { count: 0, lockedUntil: 0, last: 0 };
  if (rec.last && Date.now() - rec.last > LOCKOUT_MS * 4) rec.count = 0;   // an hour of quiet forgets old failures
  rec.last = Date.now();
  rec.count += 1;
  const max = ip === GLOBAL_KEY ? GLOBAL_MAX_FAILURES : MAX_FAILURES;
  if (rec.count >= max) rec.lockedUntil = Date.now() + LOCKOUT_MS;
  failures.set(ip, rec);
  return rec;
}

function clearFailures(ip) { failures.delete(ip); }

// ---------- audit --------------------------------------------------------

async function audit(req, action, details) {
  try {
    await pool.execute(
      `INSERT INTO rbac_audit_log
         (actor_email, action, target_email, target_page_key, details, ip_address, user_agent)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        bg.ACCOUNT_EMAIL,
        action,
        null,
        'breakglass',
        details ? JSON.stringify(details) : null,
        clientIp(req),
        ((req.headers['user-agent'] || '') + '').slice(0, 500) || null,
      ]
    );
  } catch (e) {
    console.error('[breakglass] audit insert failed:', e.message);
  }
}

// ---------- Graph alert email (best-effort, never blocks) ----------------

async function sendAlert(req) {
  try {
    if (!mailGraph.configured()) {
      console.warn('[breakglass] AZURE_* env not set - alert email skipped');
      return;
    }

    const when = new Date().toISOString();
    const ip = clientIp(req);
    const body = {
      message: {
        subject: '[IT Command] BREAK-GLASS LOGIN — itam account used',
        body: {
          contentType: 'Text',
          content:
            'The itam break-glass account successfully signed in.\n\n' +
            'Time (UTC): ' + when + '\n' +
            'Source IP:  ' + ip + '\n' +
            'User agent: ' + (req.headers['user-agent'] || 'unknown') + '\n\n' +
            'If this was not an authorized emergency use, rotate the itam ' +
            'credentials immediately (re-run breakglass-enroll.js) and review ' +
            'rbac_audit_log for target_page_key = breakglass.',
        },
        toRecipients: ALERT_TO.map(a => ({ emailAddress: { address: a } })),
      },
      saveToSentItems: false,
    };
    const sendRes = await mailGraph.sendMail({
      to: ALERT_TO,
      subject: body.message.subject,
      text: body.message.body.content,
      saveToSentItems: false,
    });
    if (!sendRes.ok) throw new Error('sendMail ' + sendRes.reason +
      (sendRes.status ? ' HTTP ' + sendRes.status : ''));
    console.log('[breakglass] alert email sent to', ALERT_TO.join(', '));
  } catch (e) {
    console.error('[breakglass] alert email failed (login still granted):', e.message);
  }
}

// ---------- routes -------------------------------------------------------

router.post('/login', async (req, res) => {
  const ip = clientIp(req);

  if (!bg.isConfigured()) {
    return res.status(503).json({ error: 'Break-glass not enrolled', code: 'NOT_ENROLLED' });
  }

  const lock = checkLock(ip);
  if (lock.locked) {
    await audit(req, 'breakglass_locked_out', { retryAfterS: lock.retryAfterS });
    return res.status(429).json({
      error: 'Too many failed attempts. Try again later.',
      code:  'LOCKED_OUT',
    });
  }

  const { password, totp } = req.body || {};
  if (typeof password !== 'string' || typeof totp !== 'string') {
    recordFailure(ip);
    await audit(req, 'breakglass_login_failed', { reason: 'malformed_request' });
    return res.status(401).json({ error: 'Authentication failed', code: 'AUTH_FAILED' });
  }

  // Verify BOTH factors before responding, so the response time does not
  // reveal which factor failed.
  const passOk = await bg.verifyPassword(password);
  const totpResult = bg.verifyTotp(totp);

  if (!passOk || !totpResult.ok) {
    const rec = recordFailure(ip);
    await audit(req, 'breakglass_login_failed', {
      reason: !passOk ? 'password' : totpResult.reason,
      failureCount: rec.count,
      lockedOut: !!(rec.lockedUntil && Date.now() < rec.lockedUntil),
    });
    return res.status(401).json({ error: 'Authentication failed', code: 'AUTH_FAILED' });
  }

  clearFailures(ip);
  const token = bg.mintSessionToken();
  await audit(req, 'breakglass_login_success', {});
  sendAlert(req);   // fire-and-forget by design

  // ITAM-01: break-glass is refused a /api/rbac/session token by design, so it must
  // get the gate cookie here or the emergency path would be locked out of every page.
  require('./session-cookie').setSessionCookie(res, token, 60 * 60 * 1000, req);
  res.json({ token, expiresInMinutes: 60 });
});

// Lightweight status probe (no auth): tells the login page whether the
// break-glass path is available at all. Reveals nothing else.
router.get('/status', (req, res) => {
  res.json({ enrolled: bg.isConfigured() });
});

module.exports = router;
