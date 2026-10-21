// oidc-auth.js — the platform's single sign-in front door.  (CorpIT Hub SSO)
//
// WHY THIS EXISTS
// ---------------
// login.html used to run the OAuth *implicit* flow: response_type='id_token token',
// response_mode=fragment. That put a raw id_token in the browser's URL fragment, and
// nothing ever validated the nonce — it was Math.random() in the page with no
// server-side copy to compare against. Implicit is retired in OAuth 2.1 for exactly
// these reasons.
//
// This module replaces it with authorization-code + PKCE:
//   - the code→token exchange happens here, server-side, with the client secret
//   - no token of any kind reaches the browser
//   - state and nonce are 32 crypto-random bytes, compared with timingSafeEqual
//   - the id_token is fully validated: RS256 via tenant JWKS, plus iss, aud, tid,
//     nonce and expiry
//
// WHAT IT DOES *NOT* DO
// ---------------------
// It does not decide what you may see. It proves who you are and mints the same
// it_session token every existing login path already mints, so gate-routes.js and
// rbac-middleware.js are untouched and keep making every authorization decision.
// Entra's "assignment required" (the SaaS-ITH-* role and approver groups) is the outer gate;
// RBAC remains the inner one.
//
// ONE FRONT DOOR, MANY HOSTS
// --------------------------
// Only this origin is registered in Entra as a redirect URI. Other vhosts — on this
// box or on itam — never talk to Entra. They bounce an unauthenticated visitor here,
// and after a successful sign-in they receive a short-lived, audience-bound handoff
// token and mint their OWN host-only cookie from it (see /accept).
//
// The alternative — widening it_session to Domain=.nrpi.local — was rejected: that
// broadcasts the session token to every HTTPS host under nrpi.local, including domain
// controllers and appliances this platform does not own.

'use strict';

const crypto  = require('crypto');
const fs      = require('fs');
const express = require('express');
const jwt     = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const sessionAuth   = require('./session-auth');
const adGroups      = require('./ad-groups');   // CORPIT-SITE-AUTHZ
const sessionCookie = require('./session-cookie');

const router = express.Router();

// ── configuration ────────────────────────────────────────────────────────────
// Deliberately reads the CorpIT Hub registration's own vars. The older
// RBAC_AZURE_* pair stays in place so the legacy implicit path keeps verifying
// tokens it already issued; nothing here touches it.
const TENANT_ID     = process.env.SSO_TENANT_ID     || process.env.RBAC_AZURE_TENANT_ID;
const CLIENT_ID     = process.env.SSO_CLIENT_ID;
const CLIENT_SECRET = process.env.SSO_CLIENT_SECRET;
const AUTH_ORIGIN   = (process.env.SSO_AUTH_ORIGIN || '').replace(/\/+$/, '');
const REDIRECT_URI  = AUTH_ORIGIN + '/api/auth/callback';

// Hosts this platform is willing to send a signed-in user back to. Anything not
// listed here is refused outright — an open redirector on the sign-in path would
// hand an attacker a credible phishing landing spot on our own domain.
const ALLOWED_HOSTS = String(process.env.SSO_ALLOWED_HOSTS || '')
  .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

// CORPIT-AUDIT-MEDIUM  __Host- forbids Domain= and requires Path=/, so no sibling host under
// nrpi.local can plant or shadow this cookie and fixate a sign-in transaction.
const TX_COOKIE   = '__Host-it_sso_tx';  // in-flight sign-in state
const HANDOFF_BIND_COOKIE = '__Host-it_handoff_bind'; // target-browser sign-in state
const HANDOFF_BIND_PARAM = '_it_handoff_bind';
const TX_TTL_MS   = 10 * 60 * 1000;    // an unfinished sign-in dies after 10 min
const HANDOFF_TTL_MS = 60 * 1000;      // cross-host handoff token lifetime

// CORPIT-BACKUP-HANDOFF-KEY (2026-09-26): the ITAM backup console gets handoffs signed
// with a key of its own, so the copy that lives on ITAM can open that console and
// nothing else. Every other audience keeps RBAC_SESSION_SECRET.
const BACKUP_HANDOFF_ORIGIN   = 'https://backup.nrpi.local';
const BACKUP_HANDOFF_KEY_FILE = '/etc/corpit/backup-handoff.key';

// CORPIT-DEV-HANDOFF-KEY (2026-09-30): the ITAM dev server (dev-<site>.nrpi.local) gets
// handoffs signed with a dev-only key, never the master RBAC_SESSION_SECRET. Hosts must be
// exactly dev-<label>.nrpi.local over https with no port.
const DEV_HOST_RE          = /^dev-[a-z0-9](?:[a-z0-9-]{0,40}[a-z0-9])?\.nrpi\.local$/;
const DEV_ORIGIN_RE        = /^https:\/\/dev-[a-z0-9](?:[a-z0-9-]{0,40}[a-z0-9])?\.nrpi\.local$/;
const DEV_HANDOFF_KEY_FILE = '/etc/corpit/dev-handoff.key';
function devHandoffKey() {
  try {
    const key = fs.readFileSync(DEV_HANDOFF_KEY_FILE);
    return key.length >= 32 ? key : null;
  } catch (e) { return null; }
}

function isConfigured() {
  return !!(TENANT_ID && CLIENT_ID && CLIENT_SECRET && AUTH_ORIGIN);
}

const authority = () => 'https://login.microsoftonline.com/' + TENANT_ID;

// ── JWKS (same shape rbac-middleware.js already uses) ─────────────────────────
const jwks = jwksClient({
  jwksUri: authority() + '/discovery/v2.0/keys',
  cache: true,
  cacheMaxAge: 60 * 60 * 1000,
  rateLimit: true,
  jwksRequestsPerMinute: 10,
});

function getKey(header, cb) {
  jwks.getSigningKey(header.kid, (err, key) => {
    if (err) return cb(err);
    cb(null, key.getPublicKey());
  });
}

// Entra flips between v1 and v2 issuer strings depending on the account; accept both.
const VALID_ISSUERS = [
  'https://login.microsoftonline.com/' + TENANT_ID + '/v2.0',
  'https://sts.windows.net/' + TENANT_ID + '/',
];

// ── small helpers ─────────────────────────────────────────────────────────────
const b64url = buf => Buffer.from(buf).toString('base64')
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function fromB64url(s) {
  s = String(s).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}

// This app does not load cookie-parser, so read the header directly — the same
// approach gate-routes.js already takes. res.cookie()/res.clearCookie() are Express
// built-ins and need no parser.
function readCookieAll(req, name) {
  // Returns EVERY value sent under this name, not just the first. A browser can
  // legitimately hold two same-named cookies at different scopes, and taking the
  // first one lets a shadowing duplicate silently displace the real value.
  const raw = req.headers.cookie || '';
  const out = [];
  const re = new RegExp('(?:^|;\\s*)' + name + '=([^;]*)', 'g');
  let m;
  while ((m = re.exec(raw)) !== null) {
    try { out.push(decodeURIComponent(m[1])); } catch (e) { out.push(m[1]); }
  }
  return out;
}

function hmac(data) {
  return crypto.createHmac('sha256', process.env.RBAC_SESSION_SECRET).update(data).digest();
}

// Constant-time compare that never throws on a length mismatch.
function safeEqual(a, b) {
  const A = Buffer.from(String(a || ''), 'utf8');
  const B = Buffer.from(String(b || ''), 'utf8');
  if (A.length !== B.length || A.length === 0) return false;
  return crypto.timingSafeEqual(A, B);
}

// ── return-target validation ─────────────────────────────────────────────────
// Accepts a site-relative path, or an absolute https URL on an allow-listed host.
// Everything else collapses to '/'. Protocol-relative '//evil.com' is rejected
// explicitly: it looks relative but the browser treats it as absolute.
function parseReturn(rd, fallbackOrigin) {
  const raw = String(rd || '').trim();
  if (!raw) return { origin: fallbackOrigin, path: '/' };

  // CORPIT-REDIRECT-HARDEN
  // The URL parser STRIPS tab/LF/CR before parsing, so '/<TAB>/evil.com' is not
  // the relative path it looks like - it resolves to '//evil.com' and leaves the
  // platform. Testing only for the literal '//' and '/\\' prefixes let it through.
  // Reject the whole control class, the way login.html's sanitizeReturn already does.
  if (/[\u0000-\u0020\\]/.test(raw)) return { origin: fallbackOrigin, path: '/' };

  if (raw.startsWith('/') && !raw.startsWith('//')) {
    // Canonicalise through the same parser the browser will use, then confirm the
    // origin really did not move, rather than trusting a prefix test to predict it.
    try {
      const rel = new URL(raw, fallbackOrigin);
      if (rel.origin !== fallbackOrigin) return { origin: fallbackOrigin, path: '/' };
      const p = (rel.pathname || '/') + (rel.search || '');
      // Normalisation can produce a protocol-relative PATH: '/..//evil.com'
      // collapses to '//evil.com', which any downstream location.replace(path)
      // would then read as an absolute URL off this origin.
      if (p.indexOf('//') === 0) return { origin: fallbackOrigin, path: '/' };
      return { origin: fallbackOrigin, path: p };
    } catch (e) {
      return { origin: fallbackOrigin, path: '/' };
    }
  }
  try {
    const u = new URL(raw);
    if (u.protocol !== 'https:') return { origin: fallbackOrigin, path: '/' };
    const _h = u.hostname.toLowerCase();
    if (!ALLOWED_HOSTS.includes(_h) && !(DEV_HOST_RE.test(_h) && !u.port)) {   // CORPIT-DEV-HANDOFF-KEY
      return { origin: fallbackOrigin, path: '/' };
    }
    return { origin: 'https://' + u.host, path: (u.pathname || '/') + (u.search || '') };
  } catch (e) {
    return { origin: fallbackOrigin, path: '/' };
  }
}

// ── in-flight transaction, carried in a signed cookie ─────────────────────────
// A cookie rather than server memory: it survives an api restart mid-sign-in and
// needs no shared store if this ever runs more than one worker.
function sealTx(obj) {
  const body = b64url(JSON.stringify(obj));
  return body + '.' + b64url(hmac(body));
}

function openTx(raw) {
  try {
    const str = String(raw || '');
    const dot = str.indexOf('.');
    if (dot === -1) return null;
    const body = str.slice(0, dot);
    const sig  = fromB64url(str.slice(dot + 1));
    const want = hmac(body);
    if (sig.length !== want.length || !crypto.timingSafeEqual(sig, want)) return null;
    const tx = JSON.parse(fromB64url(body).toString('utf8'));
    if (!tx || typeof tx.ts !== 'number' || Date.now() - tx.ts > TX_TTL_MS) return null;
    return tx;
  } catch (e) { return null; }
}

// Path must be '/' for the __Host- prefix to be accepted by the browser.
const TX_COOKIE_OPTS = { httpOnly: true, secure: true, sameSite: 'lax', path: '/' };

// ── cross-host handoff token ──────────────────────────────────────────────────
// Audience-bound and 60s-lived. Both boxes already share RBAC_SESSION_SECRET, so
// the target host verifies this with no shared storage and no call back to us.
// The one exception is BACKUP_HANDOFF_ORIGIN, which holds only its own key.

// CORPIT-BACKUP-HANDOFF-KEY: raw bytes, no trim -- ITAM reads its copy the same way,
// so a stray newline must break both ends alike rather than only one. Read at each
// sign-in, not at start: removing the file takes effect without a restart.
// null when missing, unreadable or short; the caller then refuses the sign-in.
function backupHandoffKey() {
  try {
    const key = fs.readFileSync(BACKUP_HANDOFF_KEY_FILE);
    return key.length >= 32 ? key : null;
  } catch (e) { return null; }
}

function mintHandoff(email, name, targetOrigin, path, groups, ait) {
  const payload = JSON.stringify({
    sub: String(email || '').trim().toLowerCase(),
    name: name || email || '',
    typ: 'handoff',
    // CORPIT-SESSION-CAP-HANDOFF (2026-09-04): carry the ORIGINAL sign-in time
    // across the host hop. Without it the target host mints ait=now and the 12h
    // absolute cap is reset for free, simply by opening a second vhost.
    // Omitted (not null) when absent, so a caller that has no anchor produces a
    // token byte-identical to the pre-cap one.
    ait: (typeof ait === 'number' && isFinite(ait) && ait > 0) ? ait : undefined,
    // CORPIT-SITE-AUTHZ carry the resolved groups across the handoff, so a cross-host
    // sign-in does not land with an unresolved group list on the target.
    grp: Array.isArray(groups) ? groups.map(String) : undefined,
    aud: targetOrigin,
    rd:  path,
    exp: Date.now() + HANDOFF_TTL_MS,
    jti: crypto.randomBytes(12).toString('hex'),
  });
  if (targetOrigin === BACKUP_HANDOFF_ORIGIN) {
    // CORPIT-BACKUP-HANDOFF-KEY: never the master key for this audience, not even as
    // a fallback. No key file means no handoff.
    const key = backupHandoffKey();
    if (!key) return null;
    return b64url(payload) + '.' + b64url(crypto.createHmac('sha256', key).update(payload).digest());
  }
  if (DEV_ORIGIN_RE.test(String(targetOrigin || ''))) {
    // CORPIT-DEV-HANDOFF-KEY: dev audience -> dev key only, no master-key fallback.
    const dkey = devHandoffKey();
    if (!dkey) return null;
    return b64url(payload) + '.' + b64url(crypto.createHmac('sha256', dkey).update(payload).digest());
  }
  return b64url(payload) + '.' + b64url(hmac(payload));
}

function verifyHandoff(token, selfOrigin) {
  try {
    const str = String(token || '');
    const dot = str.indexOf('.');
    if (dot === -1 || str.indexOf('.', dot + 1) !== -1) return null;
    const raw = fromB64url(str.slice(0, dot));
    const sig = fromB64url(str.slice(dot + 1));
    let want;
    if (DEV_ORIGIN_RE.test(String(selfOrigin || ''))) {     // CORPIT-DEV-HANDOFF-KEY
      const dkey = devHandoffKey();
      if (!dkey) return null;
      want = crypto.createHmac('sha256', dkey).update(raw).digest();
    } else {
      want = hmac(raw);
    }
    if (sig.length !== want.length || !crypto.timingSafeEqual(sig, want)) return null;
    const p = JSON.parse(raw.toString('utf8'));
    if (p.typ !== 'handoff') return null;
    if (typeof p.exp !== 'number' || Date.now() > p.exp) return null;
    if (p.aud !== selfOrigin) return null;           // minted for a different host
    if (/@local$/.test(String(p.sub || ''))) return null;  // FP-04, mirrors session-auth
    return p;
  } catch (e) { return null; }
}

// Replay defence for the handoff token. Per-host, in-memory, and only needs to
// outlive the token itself (60s) — a restart losing this set costs nothing,
// because an expired token is refused anyway.
const usedJti = new Map();
function jtiSeen(jti) {
  const now = Date.now();
  for (const [k, exp] of usedJti) if (exp < now) usedJti.delete(k);
  if (usedJti.has(jti)) return true;
  usedJti.set(jti, now + HANDOFF_TTL_MS * 5);
  return false;
}

// CORPIT-SELF-ORIGIN-HOST (F18): Host only, never X-Forwarded-Host. Every nginx
// /api/auth/ location sets Host $host, but corpit's /hub-api/ proxy passes the
// client's own X-Forwarded-Host through, so trusting it let a caller pick which
// audience (and which handoff key) /accept verified against. Normalised the way
// mp-signin.js does it: lower case, no port, no trailing dot.
function selfOrigin(req) {
  const host = String(req.headers.host || '').trim().toLowerCase().replace(/:\d+$/, '').replace(/\.$/, '');
  return 'https://' + host;
}

// CORPIT-HANDOFF-BIND-ALL (F47): every handoff is bound to the browser that asked
// for it, not just dev ones. The target host sets a nonce cookie and puts the same
// nonce in the return path; the auth origin signs that path into the handoff but
// never sees the HttpOnly cookie, so a leaked /accept URL cannot sign in a
// different browser as its subject. A few recent nonces are kept so two tabs
// signing in at once do not knock each other out.
// The backup console is the one audience this hub never accepts for: its own app
// on ITAM runs /accept and its own bind check, so it is left out of all this.
const HANDOFF_BIND_KEEP = 4;
function needsBind(origin) { return origin !== BACKUP_HANDOFF_ORIGIN; }
function bindNonces(req) {
  const out = [];
  for (const raw of readCookieAll(req, HANDOFF_BIND_COOKIE)) {
    for (const n of String(raw || '').split('.')) if (/^[A-Za-z0-9_-]{43}$/.test(n)) out.push(n);
  }
  return out;
}
function boundReturn(req, res, here, path) {
  const nonce = b64url(crypto.randomBytes(32));
  const rd = new URL(path, here);
  rd.searchParams.set(HANDOFF_BIND_PARAM, nonce);
  const keep = bindNonces(req).filter(n => n !== nonce).slice(-(HANDOFF_BIND_KEEP - 1));
  res.cookie(HANDOFF_BIND_COOKIE, keep.concat(nonce).join('.'), { ...TX_COOKIE_OPTS, maxAge: TX_TTL_MS });
  return here + rd.pathname + rd.search;
}
function hasBindParam(origin, path) {
  try { return !!new URL(path, origin).searchParams.get(HANDOFF_BIND_PARAM); } catch (e) { return false; }
}

// ── GET /api/auth/login ───────────────────────────────────────────────────────
router.get('/login', (req, res) => {
  if (!isConfigured()) {
    return res.status(503).type('text/plain')
      .send('Single sign-on is not configured on this host.');
  }
  const here = selfOrigin(req);
  const target = parseReturn(req.query.rd, here);

  // [CORPIT-HUB-SSO-DELEGATE]
  // Only the auth host may run the transaction. It owns the single redirect URI
  // registered in Entra, and the state/nonce cookie has to live on the origin that
  // will read it back in /callback. Any other vhost hands the whole sign-in over
  // and gets its session on the return trip via the handoff token.
  if (here !== AUTH_ORIGIN) {
    // CORPIT-HANDOFF-BIND-ALL: a sign-in for another host starts on THAT host, so
    // the bind cookie lands in the browser that will receive the handoff.
    if (target.origin !== here && needsBind(target.origin)) {
      return res.redirect(302, target.origin + '/api/auth/login?rd=' + encodeURIComponent(target.path));
    }
    const back = target.origin === here ? boundReturn(req, res, here, target.path) : target.origin + target.path;
    return res.redirect(302, AUTH_ORIGIN + '/api/auth/login?rd=' + encodeURIComponent(back));
  }
  // CORPIT-HANDOFF-BIND-ALL: on the auth host, a return to another host that does
  // not yet carry a bind nonce goes to that host first to pick one up. It comes
  // back with the nonce in the path, so this does not loop.
  if (target.origin !== here && needsBind(target.origin) && !hasBindParam(target.origin, target.path)) {
    return res.redirect(302, target.origin + '/api/auth/login?rd=' + encodeURIComponent(target.path));
  }

  const verifier  = b64url(crypto.randomBytes(64));
  const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
  const state = b64url(crypto.randomBytes(32));
  const nonce = b64url(crypto.randomBytes(32));

  res.cookie(TX_COOKIE, sealTx({
    state, nonce, verifier,
    origin: target.origin, path: target.path,
    ts: Date.now(),
  }), { ...TX_COOKIE_OPTS, maxAge: TX_TTL_MS });

  const q = new URLSearchParams({
    client_id: CLIENT_ID,
    response_type: 'code',
    redirect_uri: REDIRECT_URI,
    response_mode: 'query',
    scope: 'openid profile email',
    state, nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });
  res.redirect(302, authority() + '/oauth2/v2.0/authorize?' + q.toString());
});

// ── GET /api/auth/callback ────────────────────────────────────────────────────
router.get('/callback', async (req, res) => {
  const fail = (reason, detail) => {
    console.warn('[oidc-auth] sign-in refused: %s %s', reason, detail || '');
    res.clearCookie(TX_COOKIE, TX_COOKIE_OPTS);
    return res.redirect(302, '/login.html?sso=' + encodeURIComponent(reason));
  };

  if (!isConfigured()) return fail('not_configured');

  // Try every value sent under this cookie name and take the first that verifies,
  // so a planted duplicate cannot displace the genuine transaction.
  let tx = null;
  for (const raw of readCookieAll(req, TX_COOKIE)) {
    tx = openTx(raw);
    if (tx) break;
  }
  if (!tx) return fail('expired');           // no transaction, or older than 10 min

  // Burn the transaction cookie immediately: one callback per sign-in attempt.
  res.clearCookie(TX_COOKIE, TX_COOKIE_OPTS);

  if (req.query.error) {
    return fail(String(req.query.error).slice(0, 64), String(req.query.error_description || '').slice(0, 200));
  }
  if (!safeEqual(req.query.state, tx.state)) return fail('state_mismatch');

  const code = req.query.code;
  if (!code) return fail('no_code');

  // ── exchange, server-side, with the client secret ──
  let tokenSet;
  try {
    const r = await fetch(authority() + '/oauth2/v2.0/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        grant_type: 'authorization_code',
        code: String(code),
        redirect_uri: REDIRECT_URI,
        code_verifier: tx.verifier,
        scope: 'openid profile email',
      }),
    });
    tokenSet = await r.json();
    if (!r.ok) return fail('token_endpoint', tokenSet.error_description || tokenSet.error);
  } catch (e) {
    return fail('token_unreachable', e.message);
  }
  if (!tokenSet.id_token) return fail('no_id_token');

  // ── validate the id_token completely ──
  let claims;
  try {
    claims = await new Promise((resolve, reject) => {
      jwt.verify(tokenSet.id_token, getKey, {
        algorithms: ['RS256'],
        audience: CLIENT_ID,
        issuer: VALID_ISSUERS,
        clockTolerance: 120,
      }, (err, decoded) => err ? reject(err) : resolve(decoded));
    });
  } catch (e) {
    return fail('id_token_rejected', e.message);
  }
  // Pin the tenant explicitly on top of the issuer check.
  if (claims.tid !== TENANT_ID) return fail('wrong_tenant');
  // The nonce is the whole point of the rewrite — the old implicit path never did this.
  if (!safeEqual(claims.nonce, tx.nonce)) return fail('nonce_mismatch');

  const email = String(claims.preferred_username || claims.upn || claims.email || '')
    .trim().toLowerCase();
  if (!email) return fail('no_username');
  const name = claims.name || email;

  const here = selfOrigin(req);

  // Same host: set the session cookie directly, exactly as the old path did.
  // CORPIT-SITE-AUTHZ one directory lookup, here, where a user is already waiting on a
  // redirect. Never fatal: on failure groups come back null and the user still
  // signs in, they simply have no group-gated sites until the next sign-in.
  const groups = await adGroups.groupsForSignIn(email);

  if (tx.origin === here) {
    const token = sessionAuth.mintSessionToken(email, name, groups);
    sessionCookie.setSessionCookie(res, token, sessionAuth.SESSION_TTL_MS, req);
    console.log('[oidc-auth] sign-in ok %s -> %s', email, tx.path);
    // Via the bootstrap page: the cookie alone satisfies nginx's gate, but the
    // frontend sends Authorization: Bearer out of sessionStorage, which a 302
    // cannot populate. auth-complete.html fills it in and forwards.
    return res.redirect(302, '/auth-complete.html?rd=' + encodeURIComponent(tx.path));
  }

  // Different host: hand off. That host mints its own cookie; ours is never widened.
  // Date.now() is this sign-in's anchor, and it TRAVELS with the handoff rather than
  // restarting on the target -- that is what mintHandoff's cap marker above is for.
  //
  // CORPIT-CAP-ANCHOR-HONESTY (2026-09-04): say what this actually guarantees. An
  // earlier draft of this comment claimed the anchor is safe to reset because "the
  // user has just completed a real Entra credential prompt". THIS CODE CANNOT KNOW
  // THAT. /api/auth/callback completes identically whether Entra prompted for
  // credentials or silently re-issued from a surviving Entra SSO session -- which is
  // precisely why /api/gate/federated-logout exists. So the 12h cap binds the
  // SLIDING-RENEWAL CHAIN, not the identity: a user at the cap who goes back through
  // /login.html?switch=1, or who simply visits a vhost that holds no cookie yet, can
  // be signed in again silently and start a fresh window with no credential entry.
  // The two paths this change controls (the watcher's "Sign in again" and login.js's
  // SESSION_ABSOLUTE_CAP branch) both route through federated-logout, so THEY end the
  // Entra session first and the next sign-in really is a prompt. Nothing else does.
  // If the cap must bind the identity, the lever is an authorize-time prompt=login /
  // max_age when the caller arrives holding a past-cap session -- a deliberate change
  // to this route, not something to assume is already true.
  const h = mintHandoff(email, name, tx.origin, tx.path, groups, Date.now());
  // CORPIT-BACKUP-HANDOFF-KEY: null only for BACKUP_HANDOFF_ORIGIN with no usable key.
  if (!h) return fail('handoff_key_unavailable', tx.origin);
  console.log('[oidc-auth] sign-in ok %s -> handoff to %s', email, tx.origin);
  return res.redirect(302, tx.origin + '/api/auth/accept?t=' + encodeURIComponent(h));
});

// ── GET /api/auth/accept ──────────────────────────────────────────────────────
// The other end of the handoff. Runs on the TARGET host and mints that host's own
// cookie. Never contacts Entra.
router.get('/accept', (req, res) => {
  const here = selfOrigin(req);
  const p = verifyHandoff(req.query.t, here);
  if (!p) return res.redirect(302, '/login.html?sso=handoff_invalid');
  // CORPIT-HANDOFF-BIND-ALL (F47): required on every host, not only dev ones.
  let rd;
  try { rd = new URL(String(p.rd || ''), here); } catch (e) { rd = null; }
  const nonce = rd && rd.origin === here ? rd.searchParams.get(HANDOFF_BIND_PARAM) : null;
  const held = bindNonces(req);
  if (!nonce || !held.some(n => safeEqual(n, nonce))) {
    return res.redirect(302, '/login.html?sso=handoff_unbound');
  }
  const rest = held.filter(n => n !== nonce);
  if (rest.length) res.cookie(HANDOFF_BIND_COOKIE, rest.join('.'), { ...TX_COOKIE_OPTS, maxAge: TX_TTL_MS });
  else res.clearCookie(HANDOFF_BIND_COOKIE, TX_COOKIE_OPTS);
  rd.searchParams.delete(HANDOFF_BIND_PARAM);
  const boundPath = rd.pathname + rd.search;
  if (jtiSeen(p.jti)) return res.redirect(302, '/login.html?sso=handoff_replayed');

  const token = sessionAuth.mintSessionToken(p.sub, p.name,
                  Array.isArray(p.grp) ? p.grp : null,
                  (typeof p.ait === 'number' ? { ait: p.ait } : undefined));
  // CORPIT-SESSION-CAP-ACCEPT: a handoff is 60s-lived, so a null here means the
  // user's 12h window closed between the callback and this hop. Send them back
  // through a real sign-in rather than silently issuing nothing (setSessionCookie
  // short-circuits on a falsy token, so the alternative is a redirect into a
  // host with no cookie and no explanation).
  if (!token) return res.redirect(302, '/login.html?sso=handoff_invalid');
  // maxAge from the token's REAL exp, which the cap may have CLAMPED below the
  // full TTL. A hardcoded SESSION_TTL_MS here would leave a dead cookie in the
  // browser for hours after the token inside it stopped verifying.
  const _v = sessionAuth.verifySessionToken(token);
  sessionCookie.setSessionCookie(res, token,
    (_v && _v.ok) ? (_v.exp - Date.now()) : sessionAuth.SESSION_TTL_MS, req);
  console.log('[oidc-auth] handoff accepted %s on %s', p.sub, here);
  // Redirect to the clean path so the one-time token leaves the address bar.
  const path = (typeof boundPath === 'string' && boundPath.startsWith('/') && !boundPath.startsWith('//')) ? boundPath : '/';
  return res.redirect(302, '/auth-complete.html?rd=' + encodeURIComponent(path));
});

// ── GET /api/auth/identity ────────────────────────────────────────────────────
// The completion page runs on every SSO host, including hosts without an
// /api/rbac/me proxy. Verify the host's HttpOnly session here and return only
// display identity; never hand a bearer credential to page JavaScript.
router.get('/identity', (req, res) => {
  res.set('Cache-Control', 'no-store, private');
  res.set('Vary', 'Cookie');
  for (const token of readCookieAll(req, sessionCookie.NAME)) {
    const identity = sessionAuth.verifySessionToken(token, { host: req.get('host') });
    if (identity && identity.ok) {
      return res.json({ email: identity.email, displayName: identity.name });
    }
  }
  return res.status(401).json({ ok: false, error: 'NO_SESSION' });
});

// ── GET /api/auth/status ──────────────────────────────────────────────────────
// Read-only self-check, for verification and for the console's settings page.
// Reports configuration shape only — never a secret.
// [CORPIT-HUB-SSO-TOKEN]
// The former token handoff exposed the HttpOnly session as a portable bearer
// to every same-origin script. Browser callers now use the cookie directly.
router.get('/token', (req, res) => {
  res.set('Cache-Control', 'no-store, private');
  return res.status(410).json({ ok: false, error: 'TOKEN_HANDOFF_RETIRED' });
});

router.get('/status', (req, res) => {
  // Anonymous probe: says whether SSO is configured and nothing about how.
  // Tenant/client ids, redirect URI, allowed hosts and secret presence are
  // for the console (signed-in, superadmin), not for whoever hits this URL.
  res.json({
    configured: isConfigured(),
    is_auth_host: isConfigured() && selfOrigin(req) === AUTH_ORIGIN,
    flow: 'authorization_code+PKCE(S256)',
  });
});

module.exports = router;
module.exports.isConfigured = isConfigured;
if (process.env.OIDC_TEST_EXPORTS === '1') { module.exports._t = { parseReturn, mintHandoff, verifyHandoff, selfOrigin }; }
