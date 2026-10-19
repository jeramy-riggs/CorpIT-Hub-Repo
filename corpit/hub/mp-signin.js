// mp-signin.js — My Profile's own sign-in.  (MP-SIGNIN, 2026-10-07)
//
// WHY THIS EXISTS
// ---------------
// My Profile is for every employee and contractor whose AD account is active. The
// platform front door (oidc-auth.js) cannot serve that: its Entra app (CorpIT Hub) is
// assignment-required, so anyone outside the Hub groups is refused by Microsoft before
// this platform ever sees them, and its callback lives on corpit.nrpi.local.
//
// This module runs the same authorization-code + PKCE flow against the Access Portal
// identity app (assignment NOT required, tenant-wide consent), entirely on the My
// Profile host: its callback is https://<that host>/api/mpauth/callback.
//
// WHAT IT ISSUES
// --------------
// A HOST-SCOPED it_session (session-auth.js MP-SIGNIN-SCOPE): scp=<host>, signed with
// a key derived for that host. It opens My Profile and is rejected everywhere else,
// so opening this door to everyone widens nothing on the rest of the platform.
//
// WHO GETS IN
// -----------
// Microsoft proves who you are; AD decides whether you are still active
// (ad-groups.accountForSignIn). Disabled, expired, missing, ambiguous or "directory
// unreachable" all refuse -- fail closed. Which hosts may use this, and the app
// credentials, come from CONFIG_FILE; no file means the door is shut.

'use strict';

const crypto  = require('crypto');
const fs      = require('fs');
const express = require('express');
const jwt     = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const sessionAuth   = require('./session-auth');
const adGroups      = require('./ad-groups');
const sessionCookie = require('./session-cookie');

const router = express.Router();

const CONFIG_FILE = process.env.MP_SIGNIN_CONFIG || '/etc/corpit/myprofile-signin.json';
const TX_COOKIE   = '__Host-mp_sso_tx';
const TX_TTL_MS   = 10 * 60 * 1000;
const TX_COOKIE_OPTS = { httpOnly: true, secure: true, sameSite: 'lax', path: '/' };
const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ── configuration: { tenant_id, client_id, client_secret, hosts: [..] } ──────
// Re-read when the file changes, so rotating the secret or adding a host needs no
// restart. Anything malformed = not configured.
let _cfg = { key: null, val: null };
function config() {
  let st;
  try { st = fs.statSync(CONFIG_FILE); } catch (e) { _cfg = { key: null, val: null }; return null; }
  const key = st.mtimeMs + ':' + st.size;
  if (key === _cfg.key) return _cfg.val;
  let val = null;
  try {
    const raw = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    const hosts = Array.isArray(raw.hosts) ? raw.hosts.map(normHost).filter(Boolean) : [];
    if (GUID_RE.test(raw.tenant_id || '') && GUID_RE.test(raw.client_id || '') &&
        typeof raw.client_secret === 'string' && raw.client_secret && hosts.length) {
      val = { tenant: raw.tenant_id.toLowerCase(), clientId: raw.client_id.toLowerCase(),
              secret: raw.client_secret, hosts: hosts };
    } else {
      console.error('[mp-signin] %s is incomplete - sign-in disabled', CONFIG_FILE);
    }
  } catch (e) {
    console.error('[mp-signin] cannot read %s: %s - sign-in disabled', CONFIG_FILE, e.message);
  }
  _cfg = { key: key, val: val };
  return val;
}

function normHost(h) {
  return String(h || '').trim().toLowerCase().replace(/:\d+$/, '').replace(/\.$/, '');
}

// The Host header, never X-Forwarded-Host: nginx picks the server block by Host, so
// Host is the vhost actually serving this request, while X-Forwarded-Host is whatever
// the client chose to send unless a location overrides it.
function hostOf(req) { return normHost(req.headers.host); }

// ── JWKS, one client per tenant ──────────────────────────────────────────────
const _jwks = new Map();
function getKeyFor(tenant) {
  if (!_jwks.has(tenant)) {
    _jwks.set(tenant, jwksClient({
      jwksUri: 'https://login.microsoftonline.com/' + tenant + '/discovery/v2.0/keys',
      cache: true, cacheMaxAge: 60 * 60 * 1000, rateLimit: true, jwksRequestsPerMinute: 10,
    }));
  }
  const client = _jwks.get(tenant);
  return function (header, cb) {
    client.getSigningKey(header.kid, function (err, key) {
      if (err) return cb(err);
      cb(null, key.getPublicKey());
    });
  };
}

// ── helpers (same shapes as oidc-auth.js) ────────────────────────────────────
const b64url = buf => Buffer.from(buf).toString('base64')
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
function fromB64url(s) {
  s = String(s).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}
function readCookieAll(req, name) {
  const raw = req.headers.cookie || '';
  const out = [];
  const re = new RegExp('(?:^|;\\s*)' + name + '=([^;]*)', 'g');
  let m;
  while ((m = re.exec(raw)) !== null) {
    try { out.push(decodeURIComponent(m[1])); } catch (e) { out.push(m[1]); }
  }
  return out;
}
function safeEqual(a, b) {
  const A = Buffer.from(String(a || ''), 'utf8');
  const B = Buffer.from(String(b || ''), 'utf8');
  if (A.length !== B.length || A.length === 0) return false;
  return crypto.timingSafeEqual(A, B);
}
// Own key for the transaction cookie, derived from the platform secret, so a sealed
// oidc-auth transaction can never be replayed here or the other way round.
function txMac(data) {
  const k = crypto.createHmac('sha256', process.env.RBAC_SESSION_SECRET).update('mp-signin-tx:v1').digest();
  return crypto.createHmac('sha256', k).update(data).digest();
}
function sealTx(obj) {
  const body = b64url(JSON.stringify(obj));
  return body + '.' + b64url(txMac(body));
}
function openTx(raw) {
  try {
    const str = String(raw || '');
    const dot = str.indexOf('.');
    if (dot === -1) return null;
    const body = str.slice(0, dot);
    const sig  = fromB64url(str.slice(dot + 1));
    const want = txMac(body);
    if (sig.length !== want.length || !crypto.timingSafeEqual(sig, want)) return null;
    const tx = JSON.parse(fromB64url(body).toString('utf8'));
    if (!tx || typeof tx.ts !== 'number' || Date.now() - tx.ts > TX_TTL_MS) return null;
    return tx;
  } catch (e) { return null; }
}

// Return target: a path on THIS host only. A relative path, or an absolute https URL
// whose origin is exactly this host; everything else is '/'. Same hardening as
// oidc-auth.js parseReturn (control characters, '//' prefixes, normalisation).
function returnPath(rd, origin) {
  const raw = String(rd || '').trim();
  if (!raw || /[\u0000- \\]/.test(raw)) return '/';
  try {
    const u = new URL(raw, origin);
    if (u.origin !== origin) return '/';
    const p = (u.pathname || '/') + (u.search || '');
    return p.indexOf('//') === 0 ? '/' : p;
  } catch (e) { return '/'; }
}

function refuse(res, reason, detail) {
  console.warn('[mp-signin] sign-in refused: %s %s', reason, detail || '');
  res.clearCookie(TX_COOKIE, TX_COOKIE_OPTS);
  return res.redirect(302, '/login.html?sso=' + encodeURIComponent(reason));
}

// ── GET /api/mpauth/login ────────────────────────────────────────────────────
router.get('/login', function (req, res) {
  res.set('Cache-Control', 'no-store, private');
  const cfg = config();
  if (!cfg) return refuse(res, 'not_configured');
  const host = hostOf(req);
  if (cfg.hosts.indexOf(host) === -1) return res.status(404).end();
  const origin = 'https://' + host;

  const verifier  = b64url(crypto.randomBytes(64));
  const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
  const state = b64url(crypto.randomBytes(32));
  const nonce = b64url(crypto.randomBytes(32));

  res.cookie(TX_COOKIE, sealTx({
    state: state, nonce: nonce, verifier: verifier, host: host,
    path: returnPath(req.query.rd, origin), ts: Date.now(),
  }), Object.assign({}, TX_COOKIE_OPTS, { maxAge: TX_TTL_MS }));

  const q = new URLSearchParams({
    client_id: cfg.clientId,
    response_type: 'code',
    redirect_uri: origin + '/api/mpauth/callback',
    response_mode: 'query',
    scope: 'openid profile email',
    state: state, nonce: nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });
  return res.redirect(302, 'https://login.microsoftonline.com/' + cfg.tenant +
                           '/oauth2/v2.0/authorize?' + q.toString());
});

// ── GET /api/mpauth/callback ─────────────────────────────────────────────────
router.get('/callback', async function (req, res) {
  res.set('Cache-Control', 'no-store, private');
  const cfg = config();
  if (!cfg) return refuse(res, 'not_configured');
  const host = hostOf(req);
  if (cfg.hosts.indexOf(host) === -1) return res.status(404).end();

  let tx = null;
  for (const raw of readCookieAll(req, TX_COOKIE)) {
    tx = openTx(raw);
    if (tx) break;
  }
  if (!tx) return refuse(res, 'expired');
  res.clearCookie(TX_COOKIE, TX_COOKIE_OPTS);       // one callback per attempt
  if (tx.host !== host) return refuse(res, 'host_mismatch', tx.host + ' -> ' + host);

  if (req.query.error) {
    return refuse(res, String(req.query.error).slice(0, 64), String(req.query.error_description || '').slice(0, 200));
  }
  if (!safeEqual(req.query.state, tx.state)) return refuse(res, 'state_mismatch');
  const code = req.query.code;
  if (!code) return refuse(res, 'no_code');

  const redirectUri = 'https://' + host + '/api/mpauth/callback';
  let tokenSet;
  try {
    const r = await fetch('https://login.microsoftonline.com/' + cfg.tenant + '/oauth2/v2.0/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: cfg.clientId,
        client_secret: cfg.secret,
        grant_type: 'authorization_code',
        code: String(code),
        redirect_uri: redirectUri,
        code_verifier: tx.verifier,
        scope: 'openid profile email',
      }),
    });
    tokenSet = await r.json();
    if (!r.ok) return refuse(res, 'token_endpoint', tokenSet.error_description || tokenSet.error);
  } catch (e) {
    return refuse(res, 'token_unreachable', e.message);
  }
  if (!tokenSet.id_token) return refuse(res, 'no_id_token');

  let claims;
  try {
    claims = await new Promise(function (resolve, reject) {
      jwt.verify(tokenSet.id_token, getKeyFor(cfg.tenant), {
        algorithms: ['RS256'],
        audience: cfg.clientId,
        issuer: ['https://login.microsoftonline.com/' + cfg.tenant + '/v2.0',
                 'https://sts.windows.net/' + cfg.tenant + '/'],
        clockTolerance: 120,
      }, function (err, decoded) { return err ? reject(err) : resolve(decoded); });
    });
  } catch (e) {
    return refuse(res, 'id_token_rejected', e.message);
  }
  if (String(claims.tid || '').toLowerCase() !== cfg.tenant) return refuse(res, 'wrong_tenant');
  if (!safeEqual(claims.nonce, tx.nonce)) return refuse(res, 'nonce_mismatch');

  const email = String(claims.preferred_username || claims.upn || claims.email || '')
    .trim().toLowerCase();
  if (!email) return refuse(res, 'no_username');
  const name = claims.name || email;

  // AD is the authority on "active". Anything but a clean 'active' is a refusal.
  const acct = await adGroups.accountForSignIn(email);
  if (!acct || acct.status !== 'active') {
    const st = acct ? acct.status : 'unknown';
    return refuse(res, st === 'unknown' ? 'directory_unavailable' : 'account_not_active', email + ' ' + st);
  }

  const token = sessionAuth.mintSessionToken(email, name, acct.groups, { scope: host });
  const v = token ? sessionAuth.verifySessionToken(token, { host: host }) : null;
  if (!v || !v.ok) return refuse(res, 'session_mint_failed', email);
  sessionCookie.setSessionCookie(res, token, v.exp - Date.now(), req);
  console.log('[mp-signin] sign-in ok %s on %s -> %s', email, host, tx.path);
  return res.redirect(302, '/auth-complete.html?rd=' + encodeURIComponent(tx.path));
});

module.exports = router;
module.exports.isConfigured = function () { return !!config(); };
if (process.env.MP_SIGNIN_TEST_EXPORTS === '1') {
  module.exports._t = { returnPath, sealTx, openTx, config, hostOf };
}
