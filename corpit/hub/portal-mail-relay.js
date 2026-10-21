// portal-mail-relay.js — loopback-only Graph sendMail relay for the Access Portal
// (accessportal app.py on :8001). Holds NO secret of its own: reuses the AZURE_*
// Graph app creds already in this .env. The portal box never sees them.
//
// Policy enforced HERE, where the portal cannot override it:
//   - caller must be loopback AND present X-Portal-Mail-Key (PORTAL_MAIL_KEY)
//   - sender is pinned server-side (PORTAL_MAIL_FROM / PORTAL_MAIL_FROM_NAME)
//   - recipients must be @auction.com, max 25 per send
//   - 120 sends per rolling hour
//   - every send (and every refusal) appended to logs/portal-mail-audit.log
//
// NOT mounted under /api/ on purpose: no nginx location proxies /internal/*, so
// this is unreachable through either vhost even before the key check.

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const router = express.Router();

const RELAY_KEY = process.env.PORTAL_MAIL_KEY || '';
// sendMail is addressed by UPN — the mailbox's SMTP alias set decides nothing here.
const SENDER_UPN = process.env.PORTAL_MAIL_SENDER_UPN || 'itcommand@auctiondotcom.onmicrosoft.com';
const FROM_ADDR = process.env.PORTAL_MAIL_FROM || 'itcommand@auction.com';
const FROM_NAME = process.env.PORTAL_MAIL_FROM_NAME || 'Enterprise Approval Portal';
const ALLOWED_RCPT = /^[^@\s]+@auction\.com$/i;
const MAX_RCPT = 25;
const MAX_SUBJECT = 300;
const MAX_HTML = 512 * 1024;
const RATE_MAX = 120;               // per rolling hour
const RATE_WINDOW_MS = 60 * 60 * 1000;

const AUDIT_DIR = path.join(__dirname, 'logs');
const AUDIT_FILE = path.join(AUDIT_DIR, 'portal-mail-audit.log');
try { fs.mkdirSync(AUDIT_DIR, { recursive: true }); } catch (e) { /* audit falls back to console */ }

function audit(entry) {
  const line = JSON.stringify({ ts: new Date().toISOString(), ...entry });
  fs.appendFile(AUDIT_FILE, line + '\n', () => {});
  console.log('[portal-mail] ' + line);
}

// ── Graph token (client credentials, cached) ────────────────────────────────
let _tok = { value: null, exp: 0 };
async function graphToken() {
  const now = Date.now() / 1000;
  if (_tok.value && now < _tok.exp - 120) return _tok.value;
  const T = process.env.AZURE_TENANT_ID, C = process.env.AZURE_CLIENT_ID, S = process.env.AZURE_CLIENT_SECRET;
  if (!T || !C || !S) throw new Error('AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET missing');
  const body = new URLSearchParams({
    client_id: C, client_secret: S,
    scope: 'https://graph.microsoft.com/.default', grant_type: 'client_credentials',
  });
  const r = await fetch(`https://login.microsoftonline.com/${T}/oauth2/v2.0/token`, {
    method: 'POST', body,
  });
  if (!r.ok) throw new Error('token HTTP ' + r.status);
  const j = await r.json();
  _tok = { value: j.access_token, exp: now + (j.expires_in || 3600) };
  return _tok.value;
}

// ── Guards ──────────────────────────────────────────────────────────────────
const LOOPBACK = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);
function isLoopback(req) {
  // Two addresses, and both must be loopback. The socket peer is the one value
  // a caller cannot forge -- but behind nginx it is ALWAYS loopback, so on its
  // own it proved nothing about a proxied request (CHG-ARCH-05). req.ip follows
  // X-Forwarded-For (trust proxy is on app-wide), which nginx sets on every
  // request it proxies and app.py never sends: a request that came in through
  // a vhost shows the browser's address here and is refused, while a direct
  // loopback caller that forges X-Forwarded-For can only deny itself.
  return LOOPBACK.has(req.socket.remoteAddress) && LOOPBACK.has(req.ip);
}

function keyOk(req) {
  // Compare digests: a non-ASCII header has a different byte length than its
  // .length, and timingSafeEqual throws on unequal lengths inside an async route.
  try {
    if (!RELAY_KEY) return false;
    const got = String(req.get('X-Portal-Mail-Key') || '');
    const h = (v) => crypto.createHash('sha256').update(v, 'utf8').digest();
    return crypto.timingSafeEqual(h(got), h(RELAY_KEY));
  } catch (e) {
    return false;
  }
}

const _sends = [];
function rateOk() {
  const cut = Date.now() - RATE_WINDOW_MS;
  while (_sends.length && _sends[0] < cut) _sends.shift();
  return _sends.length < RATE_MAX;
}

// ── POST /internal/portal-mail/send  {to, subject, html} ────────────────────
router.post('/send', async (req, res) => {
  const deny = (code, error) => {
    audit({ ok: false, deny: error, src: req.socket.remoteAddress, to: req.body && req.body.to });
    return res.status(code).json({ ok: false, error });
  };

  if (!isLoopback(req)) return deny(403, 'loopback only');
  if (!keyOk(req)) return deny(401, 'bad or missing relay key');
  if (!rateOk()) return deny(429, 'rate limit: ' + RATE_MAX + '/hour');

  let { to, subject, html } = req.body || {};
  if (typeof to === 'string') to = [to];
  if (!Array.isArray(to)) return deny(400, 'to must be a string or array');
  to = [...new Set(to.map(a => String(a || '').trim()).filter(Boolean))];
  if (!to.length || to.length > MAX_RCPT) return deny(400, `1-${MAX_RCPT} recipients required`);
  const bad = to.filter(a => !ALLOWED_RCPT.test(a));
  if (bad.length) return deny(403, 'recipient not allowed: ' + bad.join(', '));
  subject = String(subject || '').trim();
  if (!subject || subject.length > MAX_SUBJECT) return deny(400, 'subject required, max ' + MAX_SUBJECT + ' chars');
  html = String(html || '');
  if (!html || html.length > MAX_HTML) return deny(400, 'html body required, max ' + MAX_HTML + ' bytes');

  let token;
  try { token = await graphToken(); }
  catch (e) { audit({ ok: false, error: 'token: ' + e.message }); return res.status(502).json({ ok: false, error: 'graph token failed' }); }

  const payload = {
    message: {
      subject,
      body: { contentType: 'HTML', content: html },
      from: { emailAddress: { address: FROM_ADDR, name: FROM_NAME } },
      toRecipients: to.map(a => ({ emailAddress: { address: a } })),
    },
    saveToSentItems: 'true',
  };
  try {
    const r = await fetch('https://graph.microsoft.com/v1.0/users/' + encodeURIComponent(SENDER_UPN) + '/sendMail', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (r.status !== 202 && !r.ok) {
      const detail = (await r.text()).slice(0, 300);
      audit({ ok: false, error: 'sendMail HTTP ' + r.status, detail, to, subject });
      return res.status(502).json({ ok: false, error: 'sendMail HTTP ' + r.status, detail });
    }
    _sends.push(Date.now());
    audit({ ok: true, from: FROM_ADDR, to, subject });
    return res.status(202).json({ ok: true });
  } catch (e) {
    audit({ ok: false, error: e.message, to, subject });
    return res.status(502).json({ ok: false, error: e.message });
  }
});

module.exports = router;
