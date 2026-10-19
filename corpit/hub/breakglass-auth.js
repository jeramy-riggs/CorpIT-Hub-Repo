// =====================================================================
// breakglass-auth.js  (v1.0.0)
//
// Local break-glass authentication for the 'itam' account. Node core
// crypto only - no npm dependencies, so it works even when the world is
// on fire (which is the only time it should be used).
//
// Env (in /var/www/corpit-hub-api/.env, written by breakglass-enroll.js):
//   ITAM_PASSWORD_HASH  — scrypt hash, format: scrypt$N$r$p$salthex$keyhex
//   ITAM_TOTP_SECRET    — base32 shared secret (RFC 4648, no padding)
//   RBAC_SESSION_SECRET — HMAC key for minting local session tokens
//
// Exports:
//   verifyPassword(plain)          -> Promise<boolean>
//   verifyTotp(code)               -> { ok, reason? }   (replay-guarded)
//   mintSessionToken()             -> signed token, 60 min TTL
//   verifySessionToken(token)      -> { ok, email? }
//   isConfigured()                 -> boolean
// =====================================================================

'use strict';

const crypto = require('crypto');

const ACCOUNT_EMAIL   = 'itam@local';       // never a real mailbox
const SESSION_TTL_MS  = 60 * 60 * 1000;     // 60 minutes, no refresh
const TOTP_STEP_S     = 30;
const TOTP_DIGITS     = 6;
const TOTP_WINDOW     = 1;                  // accept current step +/- 1 (~90s)

function env(name) { return process.env[name] || ''; }

function isConfigured() {
  return !!(env('ITAM_PASSWORD_HASH') && env('ITAM_TOTP_SECRET') && env('RBAC_SESSION_SECRET'));
}

// ---------- password (scrypt) ------------------------------------------

function verifyPassword(plain) {
  return new Promise((resolve) => {
    try {
      const stored = env('ITAM_PASSWORD_HASH');
      const parts = stored.split('$');
      // scrypt$N$r$p$salthex$keyhex
      if (parts.length !== 6 || parts[0] !== 'scrypt') return resolve(false);
      const N = parseInt(parts[1], 10);
      const r = parseInt(parts[2], 10);
      const p = parseInt(parts[3], 10);
      const salt = Buffer.from(parts[4], 'hex');
      const expected = Buffer.from(parts[5], 'hex');
      crypto.scrypt(String(plain), salt, expected.length, { N, r, p, maxmem: 256 * 1024 * 1024 }, (err, derived) => {
        if (err) return resolve(false);
        resolve(derived.length === expected.length && crypto.timingSafeEqual(derived, expected));
      });
    } catch (e) {
      resolve(false);
    }
  });
}

// ---------- TOTP (RFC 6238, HMAC-SHA1) ---------------------------------

function base32Decode(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = String(input).toUpperCase().replace(/=+$/g, '').replace(/[\s-]/g, '');
  let bits = 0, value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx === -1) throw new Error('invalid base32 character');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function hotp(keyBuf, counter) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const digest = crypto.createHmac('sha1', keyBuf).update(msg).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const bin =
    ((digest[offset]     & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8)  |
    ( digest[offset + 3] & 0xff);
  return String(bin % (10 ** TOTP_DIGITS)).padStart(TOTP_DIGITS, '0');
}

// Replay guard: remember the highest accepted time-step for this process.
// A restart clears it, but a restart also takes longer than the 30s window,
// so a replayed code has expired by then anyway.
let lastAcceptedStep = 0;

function verifyTotp(code) {
  const clean = String(code || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(clean)) return { ok: false, reason: 'MALFORMED_CODE' };

  let key;
  try {
    key = base32Decode(env('ITAM_TOTP_SECRET'));
  } catch (e) {
    return { ok: false, reason: 'SECRET_INVALID' };
  }

  const nowStep = Math.floor(Date.now() / 1000 / TOTP_STEP_S);
  for (let offset = -TOTP_WINDOW; offset <= TOTP_WINDOW; offset++) {
    const step = nowStep + offset;
    if (step <= lastAcceptedStep) continue;         // replay guard
    const expected = hotp(key, step);
    const a = Buffer.from(expected);
    const b = Buffer.from(clean);
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
      lastAcceptedStep = step;
      return { ok: true };
    }
  }
  return { ok: false, reason: 'CODE_INCORRECT_OR_REPLAYED' };
}

// ---------- local session tokens ---------------------------------------
// Format: base64url(payloadJson) + '.' + base64url(hmacSha256(payload))

function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function fromB64url(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}

function mintSessionToken() {
  const payload = JSON.stringify({
    sub: ACCOUNT_EMAIL,
    typ: 'breakglass',
    iat: Date.now(),
    exp: Date.now() + SESSION_TTL_MS,
    jti: crypto.randomBytes(8).toString('hex'),
  });
  const sig = crypto.createHmac('sha256', env('RBAC_SESSION_SECRET')).update(payload).digest();
  return b64url(payload) + '.' + b64url(sig);
}

function verifySessionToken(token) {
  try {
    const dot = String(token || '').indexOf('.');
    if (dot === -1) return { ok: false };
    const payloadRaw = fromB64url(token.slice(0, dot));
    const sig = fromB64url(token.slice(dot + 1));
    const expected = crypto.createHmac('sha256', env('RBAC_SESSION_SECRET')).update(payloadRaw).digest();
    if (sig.length !== expected.length || !crypto.timingSafeEqual(sig, expected)) return { ok: false };
    const payload = JSON.parse(payloadRaw.toString('utf8'));
    if (payload.typ !== 'breakglass') return { ok: false };
    if (typeof payload.exp !== 'number' || Date.now() > payload.exp) return { ok: false, expired: true };
    // CORPIT-SESSION-CAP-BREAKGLASS (2026-09-04): exp/iat are surfaced so
    // /api/gate/session-info can show a break-glass user an HONEST countdown
    // instead of a bar with nothing in it. Both values are already in the signed
    // payload; exposing them here keeps ONE verified decode path, rather than
    // letting session-info parse the token itself.
    //
    // Deliberately NOT returned: `ait` / `absAit`. A break-glass session has a
    // FIXED 60-minute TTL (mintSessionToken above takes no options and always
    // sets exp = now + SESSION_TTL_MS) and must never become a sliding one:
    //   * there is no re-mint path -- rbac-routes.js POST /api/rbac/session
    //     rejects req.user.isBreakglass with a 403 before it reaches the mint;
    //   * rbac-middleware.js returns from the break-glass branch before the
    //     typ:'session' branch, so req.sessionClaims is never set for one, and
    //     the renewal route's carry-forward has nothing to read;
    //   * session-auth.js's verify rejects typ !== 'session', so a break-glass
    //     token cannot be presented as a capped session either.
    // Adding an anchor here would hand the renewal path something to extend.
    // It is intentionally absent -- do not "complete" this object.
    return { ok: true, email: payload.sub, exp: payload.exp, iat: payload.iat };
  } catch (e) {
    return { ok: false };
  }
}

module.exports = {
  ACCOUNT_EMAIL,
  isConfigured,
  verifyPassword,
  verifyTotp,
  mintSessionToken,
  verifySessionToken,
};
