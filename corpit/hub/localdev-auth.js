// =====================================================================
// localdev-auth.js  (v1.0.0)
//
// Local DEV/test accounts that bypass Entra SSO, so an admin can sign in
// as a tier1 / infosec / no-role user and see what that user really sees —
// exercising the real server-side guard, not a client-side simulation.
//
// Deliberately NOT break-glass. Break-glass is one always-super-admin
// account for emergencies (breakglass-auth.js, typ 'breakglass'). These are
// many low-privilege accounts for testing. Separate token type, separate
// table, separate kill switch.
//
// Hard guarantees, enforced here and again in rbac-middleware:
//   * a local account can NEVER be super-admin, whatever the DB says
//   * sign-in names must end in @local, so they can never collide with a
//     real mailbox or match an Entra identity
//   * the whole feature is off unless LOCALDEV_ENABLED=1 is in the env
//
// Env:
//   LOCALDEV_ENABLED     '1' to permit local sign-in at all
//   RBAC_SESSION_SECRET  HMAC key (shared with session-auth.js)
// =====================================================================

'use strict';

const crypto = require('crypto');

const TOKEN_TYP = 'localdev';
const TTL_MS    = 8 * 60 * 60 * 1000;   // 8 hours, no sliding refresh
// An elevated account can do anything, so its window is deliberately short —
// the same 60 minutes break-glass gets, and with no refresh either.
const ELEVATED_TTL_MS = 60 * 60 * 1000;
const SUFFIX    = '@local';
// Minimum password length. Elevated accounts get a much longer floor because
// the password is the ONLY factor standing in front of full platform access.
const MIN_PASSWORD          = 10;
const MIN_PASSWORD_ELEVATED = 20;

// Read-only QA tokens (2026-08-26). Minted on-box only, by bin/qa-token, for an
// account that is already active — so they are strictly WEAKER than the password
// login the same account already has, never a new privilege. The `ro` claim is
// enforced at the api-beta deny-by-default blanket (server.js), which 403s every
// non-GET/HEAD/OPTIONS. Short window because the whole point is a QA sweep, not a
// standing credential.
const QA_TTL_MS     = 45 * 60 * 1000;
const QA_TTL_MAX_MS =  4 * 60 * 60 * 1000;

const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 };

function env(name) {
  const v = process.env[name];
  if (!v) throw new Error('Missing required env var: ' + name);
  return v;
}

function isEnabled() {
  return process.env.LOCALDEV_ENABLED === '1' && !!process.env.RBAC_SESSION_SECRET;
}

// Switch ONE of two. Elevation additionally requires a row in
// rbac_local_elevation (checked live, per request, in rbac-middleware) — so
// turning this off disables every elevated account instantly without touching
// the database, and deleting the rows does the same without touching the env.
function isElevationAllowed() {
  return isEnabled() && process.env.LOCALDEV_ALLOW_SUPERADMIN === '1';
}

function isLocalName(email) {
  const e = String(email || '').trim().toLowerCase();
  return e.length > SUFFIX.length && e.endsWith(SUFFIX) && /^[a-z0-9._-]+@local$/.test(e);
}

// ---------- password hashing (scrypt, same shape as breakglass) --------

function hashPassword(plain) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16);
    crypto.scrypt(String(plain), salt, SCRYPT.keylen,
      { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, maxmem: 256 * 1024 * 1024 },
      (err, derived) => {
        if (err) return reject(err);
        resolve(['scrypt', SCRYPT.N, SCRYPT.r, SCRYPT.p,
                 salt.toString('hex'), derived.toString('hex')].join('$'));
      });
  });
}

function verifyPassword(plain, stored) {
  return new Promise((resolve) => {
    try {
      const parts = String(stored || '').split('$');
      if (parts.length !== 6 || parts[0] !== 'scrypt') return resolve(false);
      const N = parseInt(parts[1], 10), r = parseInt(parts[2], 10), p = parseInt(parts[3], 10);
      const salt = Buffer.from(parts[4], 'hex');
      const expected = Buffer.from(parts[5], 'hex');
      crypto.scrypt(String(plain), salt, expected.length,
        { N, r, p, maxmem: 256 * 1024 * 1024 }, (err, derived) => {
          if (err) return resolve(false);
          resolve(derived.length === expected.length && crypto.timingSafeEqual(derived, expected));
        });
    } catch (e) { resolve(false); }
  });
}

// ---------- token ------------------------------------------------------

function b64url(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function fromB64url(s) {
  s = String(s).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}

// `elevated` only shortens the token's life and labels it for display. It is
// NOT the source of authority — rbac-middleware re-reads rbac_local_elevation
// on every request, so revoking elevation takes effect on the next call rather
// than whenever the token happens to expire.
function mintToken(email, name, elevated, opts) {
  opts = opts || {};
  // Read-only and elevated are mutually exclusive by construction: a token that
  // cannot write has no business also carrying the elevated label, and allowing
  // both would create a combination nobody has reasoned about.
  const readOnly = !!opts.readOnly;
  if (readOnly && elevated) throw new Error('a read-only token cannot be elevated');
  const ttl = readOnly
    ? Math.min(Math.max(Number(opts.ttlMs) || QA_TTL_MS, 60 * 1000), QA_TTL_MAX_MS)
    : (elevated ? ELEVATED_TTL_MS : TTL_MS);
  const payload = JSON.stringify({
    sub: String(email || '').trim().toLowerCase(),
    name: name || email || '',
    typ: TOKEN_TYP,
    elv: !!elevated,
    // Omitted entirely when false, so ordinary tokens keep their exact prior shape.
    ro: readOnly || undefined,
    iat: Date.now(),
    exp: Date.now() + ttl,
    jti: crypto.randomBytes(8).toString('hex'),
  });
  const sig = crypto.createHmac('sha256', env('RBAC_SESSION_SECRET')).update(payload).digest();
  return b64url(payload) + '.' + b64url(sig);
}

// { ok:true, email, name, exp } | { ok:false, expired:true } | { ok:false }
function verifyToken(token) {
  try {
    if (!isEnabled()) return { ok: false };
    const str = String(token || '');
    const first = str.indexOf('.');
    if (first === -1 || str.indexOf('.', first + 1) !== -1) return { ok: false };
    const payloadRaw = fromB64url(str.slice(0, first));
    const sig = fromB64url(str.slice(first + 1));
    const expected = crypto.createHmac('sha256', env('RBAC_SESSION_SECRET')).update(payloadRaw).digest();
    if (sig.length !== expected.length || !crypto.timingSafeEqual(sig, expected)) return { ok: false };
    const payload = JSON.parse(payloadRaw.toString('utf8'));
    if (payload.typ !== TOKEN_TYP) return { ok: false };
    // Belt and braces: even a validly-signed token for a non-@local name is refused.
    if (!isLocalName(payload.sub)) return { ok: false };
    if (typeof payload.exp !== 'number' || Date.now() > payload.exp) return { ok: false, expired: true };
    return { ok: true, email: payload.sub, name: payload.name || payload.sub,
             exp: payload.exp, elevatedToken: !!payload.elv,
             readOnly: !!payload.ro };
  } catch (e) { return { ok: false }; }
}

module.exports = {
  TOKEN_TYP, TTL_MS, ELEVATED_TTL_MS, QA_TTL_MS, QA_TTL_MAX_MS, SUFFIX,
  MIN_PASSWORD, MIN_PASSWORD_ELEVATED,
  isEnabled, isElevationAllowed, isLocalName,
  hashPassword, verifyPassword,
  mintToken, verifyToken,
};
