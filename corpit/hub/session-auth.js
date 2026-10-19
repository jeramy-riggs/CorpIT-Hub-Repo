// session-auth.js - long-lived user session tokens for IT Command
//
// Mirrors the break-glass token format (breakglass-auth.js) exactly:
//   b64url(JSON payload) + '.' + b64url(HMAC-SHA256(payload, RBAC_SESSION_SECRET))
// but with typ: 'session' so the two token families can never be confused.
// breakglass-auth.verifySessionToken() rejects these on its typ check, and
// this module rejects break-glass tokens on ours. A real Azure JWT (3 parts)
// fails the typ check here and falls through to the JWKS path in
// rbac-middleware.js.
//
// TTL: 10 hours. Sliding: POST /api/rbac/session with a still-valid session
// token re-mints a fresh one (see rbac-routes.js). Sliding is bounded by an
// ABSOLUTE 12h cap measured from the first sign-in (SESSION_ABS_CAP_MS, carried
// in the 'ait' claim), so re-minting can never make a session immortal.
//
// Local DEV/test identities (…@local) are only ever carried by typ 'localdev'
// tokens (localdev-auth.js), which die with LOCALDEV_ENABLED. A typ 'session'
// token naming one is refused here (FP-04, 2026-09-02) so that family can
// never outlive the kill switch or escape the local-account clamps.

'use strict';

const crypto = require('crypto');
const fs     = require('fs');

// ---------- CORPIT-REVOKE (2026-09-02) --------------------------------------
// Session tokens are stateless HMACs, so until now nothing could end one early:
// "Sign Out" cleared the cookie in YOUR browser while the token itself stayed
// valid for its full 10h anywhere it had been copied. This is the missing half.
//
// Why a FILE and not the database: verifySessionToken() is on the nginx
// auth_request path, so it runs on every navigation, and it is deliberately
// pure-crypto with no network dependency -- a database hiccup must never lock
// every user out. A local file read, guarded by an mtime check, keeps that
// property AND is visible to the second node process (:3000) which imports this
// same module in its own memory. An in-memory Set alone would be invisible to it
// and would forget everything on restart.
//
// CORPIT-REVOKE-FILE-SHARED (2026-09-04): "visible to the second node process" is
// TRUE ONLY IF SESSION_REVOKE_FILE is set, to the SAME absolute path, in BOTH pm2
// environments. The default below is __dirname-relative and the two apps live in
// different directories (/var/www/corpit-hub-api and /var/www/api), so unset means
// TWO SEPARATE DENYLISTS. That was survivable while revocation was per-jti and
// mostly cosmetic; CORPIT-REVOKE-CHAIN makes the epoch the ONLY thing that kills a
// renewed chain, so an unshared file means: sign out on corpit (handled by :3001,
// which stamps the epoch in its own copy) and :3000 -- the inventory API behind
// corpit's `location /api/` catch-all -- keeps accepting the revoked token until its
// exp. Page navigation is correctly blocked (the gate is :3001), so it presents as
// "signed out, but the API still answers": exactly the half-state CORPIT-REVOKE
// exists to remove. DEPLOY: confirm SESSION_REVOKE_FILE is one shared absolute path
// (/var/lib/corpit-session/revoked-sessions.json since PATH-RELEASE-20260929, 0600, corpit)
// in both processes, and set it with `env VAR=v pm2 restart --update-env` -- editing
// .env does NOT change a running process's env (DEPLOY-FACTS, pm2 section).
// PATH-RELEASE-20260929: the default is no longer __dirname-relative. corpit-paths.js
// resolves SESSION_REVOKE_FILE (absolute override) or /var/lib/corpit-session/revoked-sessions.json,
// refuses the legacy /var/lib/corpit and code-dir locations, and throws if the directory is
// missing, so this module fails to load (cookie auth fails closed) instead of reading an empty list.
const REVOKE_FILE = require('./corpit-paths').sessionRevokeFile();
let _revCache = { key: null, set: new Set(), epochs: {}, loaded: false };

function _revKey() {
  try {
    const st = fs.statSync(REVOKE_FILE);
    return st.mtimeMs + ':' + st.size;
  } catch (e) {
    // ENOENT is the normal steady state: nothing has ever been revoked.
    if (e && e.code === 'ENOENT') return 'absent';
    return null;   // unreadable for some OTHER reason - see below
  }
}

function _revoked() {
  const key = _revKey();
  // Unreadable for a reason other than "missing": keep the last known list
  // rather than silently deciding nothing is revoked. Fail closed on the data
  // we have; never fail open to an empty set.
  if (key === null) {
    if (!_revCache.loaded) console.error('[session-auth] CORPIT-REVOKE: cannot read', REVOKE_FILE, '- treating as empty until it can be read');
    return _revCache;
  }
  if (key === _revCache.key) return _revCache;
  let set = new Set();
  let epochs = {};
  if (key !== 'absent') {
    try {
      const raw = JSON.parse(fs.readFileSync(REVOKE_FILE, 'utf8'));
      const list = Array.isArray(raw) ? raw : (raw && Array.isArray(raw.revoked) ? raw.revoked : []);
      const now = Date.now();
      for (const e of list) {
        if (!e || !e.jti) continue;
        // An entry past its own exp can never match a live token again.
        if (typeof e.exp === 'number' && e.exp < now) continue;
        set.add(String(e.jti));
      }
      // CORPIT-REVOKE-EPOCH: { "<email>": <ms epoch> } - every session for that
      // identity minted before this instant is dead. An entry older than one full
      // TTL can be dropped: no live token could still predate it.
      const ep = (raw && raw.epochs && typeof raw.epochs === 'object') ? raw.epochs : {};
      for (const k of Object.keys(ep)) {
        const t = Number(ep[k]);
        if (!isFinite(t) || (t + SESSION_TTL_MS) < now) continue;
        epochs[String(k).trim().toLowerCase()] = t;
      }
    } catch (err) {
      console.error('[session-auth] CORPIT-REVOKE: malformed', REVOKE_FILE, '-', err.message, '- keeping previous list');
      return _revCache;
    }
  }
  _revCache = { key: key, set: set, epochs: epochs, loaded: true };
  return _revCache;
}

function isRevoked(jti) {
  if (!jti) return false;
  return _revoked().set.has(String(jti));
}

// True when this identity's sessions were revoked wholesale after `iat`.
// Tokens with no iat (none are minted without one) are never matched, so a
// missing claim can never be silently treated as revoked.
function isEpochRevoked(email, iat) {
  if (!email || typeof iat !== 'number') return false;
  const t = _revoked().epochs[String(email).trim().toLowerCase()];
  return typeof t === 'number' && iat < t;
}

// Append a jti to the denylist. exp is the token's own expiry, so the entry can
// be pruned once it could no longer match anything. Written atomically (tmp +
// rename) so a concurrent reader never sees a half-written file.
function _load() {
  try {
    const raw = JSON.parse(fs.readFileSync(REVOKE_FILE, 'utf8'));
    return {
      list: Array.isArray(raw) ? raw : (raw && Array.isArray(raw.revoked) ? raw.revoked : []),
      epochs: (raw && raw.epochs && typeof raw.epochs === 'object') ? raw.epochs : {},
    };
  } catch (e) {
    if (e.code === 'ENOENT') return { list: [], epochs: {} };
    throw e; // Never overwrite unreadable or malformed revocations with an empty list.
  }
}

const { atomicWriteDurableSync } = require('./durable-file');

function _save(list, epochs) {
  try {
    atomicWriteDurableSync(REVOKE_FILE, JSON.stringify({ revoked: list, epochs: epochs }), 0o600);
  } catch (e) {
    // A directory-sync failure can happen after rename: report failure, never undo
    // a revocation that might already be durable, and invalidate cached state.
    _revCache = { key: null, set: new Set(), epochs: {}, loaded: false };
    console.error('[session-auth] CORPIT-REVOKE: write or sync failed:', e.message);
    return false;
  }
  _revCache = { key: null, set: new Set(), epochs: {}, loaded: false };   // force re-read
  return true;
}

// CHG-ARCH-21 B2 (2026-09-25): two processes now write this file (corpit-hub-api and
// corpit-gate-api), so each read-modify-write below runs under an exclusive flock(2) on
// REVOKE_FILE + '.lock'. /usr/bin/flock takes the lock on the open file description handed to it
// as fd 3; the lock outlives that child and is released when the fd is closed here (or when this
// process dies). It waits at most 1 s. If the lock cannot be taken, fail the
// operation; an unlocked read-modify-write could erase another process's revocation.
const { spawnSync } = require('child_process');
const REVOKE_LOCK = REVOKE_FILE + '.lock';
function _withRevokeLock(fn) {
  let fd = null;
  try {
    fd = fs.openSync(REVOKE_LOCK, 'a', 0o600);
    const r = spawnSync('/usr/bin/flock', ['-x', '-w', '1', '3'], { stdio: ['ignore', 'ignore', 'pipe', fd] });
    if (r.error || r.status !== 0) throw new Error(r.error ? r.error.message : 'flock exit ' + r.status);
  } catch (e) {
    console.error('[session-auth] CORPIT-REVOKE: lock failed:', e.message, '- write refused');
    if (fd !== null) { try { fs.closeSync(fd); } catch (e2) {} }
    return false;
  }
  try { return fn(); } catch (e) {
    console.error('[session-auth] CORPIT-REVOKE: update failed:', e.message);
    return false;
  } finally { try { fs.closeSync(fd); } catch (e) {} }
}

// Revoke EVERY session for one identity that was minted before `ts` (default now).
// This is the 'sign out everywhere' lever. It is not a ban: a token minted after
// `ts` -- i.e. the user signing in again -- is unaffected.
function revokeUser(email, ts) {
  const who = String(email || '').trim().toLowerCase();
  if (!who) return false;
  return _withRevokeLock(function () {
    const cur = _load();
    const now = Date.now();
    const epochs = {};
    for (const k of Object.keys(cur.epochs)) {
      const t = Number(cur.epochs[k]);
      if (isFinite(t) && (t + SESSION_TTL_MS) >= now) epochs[k] = t;   // prune the dead
    }
    epochs[who] = Math.max(typeof ts === 'number' ? ts : now + 1, Number(cur.epochs[who]) || 0);
    const list = cur.list.filter(function (e) {
      return e && e.jti && !(typeof e.exp === 'number' && e.exp < now);
    });
    return _save(list, epochs);
  });
}

function revokeSession(jti, exp) {
  if (!jti) return false;
  return _withRevokeLock(function () {
    const cur = _load();
    let list = cur.list;
    const now = Date.now();
    list = list.filter(function (e) {
      return e && e.jti && String(e.jti) !== String(jti) &&
             !(typeof e.exp === 'number' && e.exp < now);
    });
    list.push({ jti: String(jti), exp: (typeof exp === 'number' ? exp : now + SESSION_TTL_MS), at: now });
    return _save(list, cur.epochs);
  });
}


const SESSION_TTL_MS = 10 * 60 * 60 * 1000; // 10 hours
// CORPIT-SESSION-CAP-CONST (2026-09-04): 12h from the FIRST sign-in ('ait').
// Enforced by CLAMPING at mint (exp = min(now+TTL, ait+CAP)), NEVER by extending.
// The revocation pruning at :79 and :143 assumes exp <= iat + SESSION_TTL_MS; an
// 'exp = ait + CAP' implementation would drop epoch entries while the tokens they
// kill are still valid, silently resurrecting revoked sessions.
const SESSION_ABS_CAP_MS = 12 * 60 * 60 * 1000;

function env(name) {
  const v = process.env[name];
  if (!v) throw new Error('Missing required env var: ' + name);
  return v;
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromB64url(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}

function isConfigured() {
  return !!process.env.RBAC_SESSION_SECRET;
}

// CORPIT-SITE-AUTHZ  `groups` is the user's AD security groups, resolved once at sign-in
// (ad-groups.js) and filtered to those some site policy references. Pass null -
// not [] - when the directory could not be consulted: null means "unknown", [] is
// a real, empty entitlement, and site-access.js treats the two differently.
// MP-SIGNIN-SCOPE (2026-10-07) -- HOST-SCOPED sessions.
// My Profile signs people in through its own Entra app (mp-signin.js), which is NOT
// assignment-required: any active AD account may use it. A token from that path must
// open My Profile and nothing else, so it carries scp:<host> and is signed with a key
// DERIVED for that host. Two locks, on purpose:
//   - the derived key means every verifier that does not know about scopes -- an older
//     copy of this file, breakglass, localdev, any other service holding the master
//     secret -- fails the signature and rejects it outright;
//   - this file only accepts it when the caller passes the host the request arrived on
//     and that host equals scp. No host passed = rejected (fail closed).
// Unscoped tokens are unchanged: same key, same payload, host ignored.
const SCOPE_KEY_LABEL = 'corpit-scoped-session:v1:';
function normScope(h) {
  return String(h || '').trim().toLowerCase().replace(/:\d+$/, '').replace(/\.$/, '');
}
function _signingKey(scp) {
  const master = env('RBAC_SESSION_SECRET');
  if (!scp) return master;
  return crypto.createHmac('sha256', master).update(SCOPE_KEY_LABEL + scp).digest();
}

function mintSessionToken(email, name, groups, opts) {
  const now = Date.now();
  // MP-SIGNIN-SCOPE: a scope that was asked for but normalises to nothing must never
  // quietly become an UNSCOPED (platform-wide) token.
  let scp;
  if (opts && opts.scope != null) {
    scp = normScope(opts.scope);
    if (!scp) return null;
  }
  // CORPIT-SESSION-CAP-MINT: 'ait' is the ORIGINAL sign-in time, carried forward
  // across every re-mint. A fresh sign-in passes no opts, so ait === now and this
  // token is behaviourally identical to what this function produced before the cap
  // existed. Date.now() is read ONCE: it used to be called twice, so iat and exp
  // could land a millisecond apart.
  let ait = (opts && typeof opts.ait === 'number' && isFinite(opts.ait) && opts.ait > 0)
    ? opts.ait : now;
  if (ait > now) ait = now;                          // a caller may only ever SHORTEN
  if (ait + SESSION_ABS_CAP_MS <= now) return null;  // cap reached: caller must re-authenticate
  const payload = JSON.stringify({
    sub:  String(email || '').trim().toLowerCase(),
    name: name || email || '',
    typ:  'session',
    grp:  Array.isArray(groups) ? groups.map(String) : undefined,
    iat:  now,
    // CLAMP, never extend. See SESSION_ABS_CAP_MS's comment for why this must not
    // be ait+CAP: the epoch prune depends on exp <= iat + SESSION_TTL_MS holding.
    exp:  Math.min(now + SESSION_TTL_MS, ait + SESSION_ABS_CAP_MS),
    ait:  ait,
    jti:  crypto.randomBytes(8).toString('hex'),
    scp:  scp,                                       // MP-SIGNIN-SCOPE; omitted when unscoped
  });
  const sig = crypto.createHmac('sha256', _signingKey(scp))
    .update(payload).digest();
  return b64url(payload) + '.' + b64url(sig);
}

// Returns:
//   { ok: true, email, name, exp, jti, iat, ait, absAit, groups, scope }  valid session
//   (scope is null for a platform token, the host for a MP-SIGNIN-SCOPE token)
//   { ok: false, expired: true }    session token, but past exp OR past its cap
//   { ok: false }                   not a session token / bad signature
// `ait` is the raw claim and is null on anything minted before 2026-09-04;
// `absAit` is the EFFECTIVE cap anchor and is always a number. Read absAit.
function _verifySessionToken(token, allowRevoked, host) {
  try {
    const str = String(token || '');
    // A session token has exactly one dot; Azure JWTs have two.
    const first = str.indexOf('.');
    if (first === -1 || str.indexOf('.', first + 1) !== -1) return { ok: false };
    const payloadRaw = fromB64url(str.slice(0, first));
    const sig = fromB64url(str.slice(first + 1));
    // MP-SIGNIN-SCOPE: the key depends on the (still unverified) scp claim, so read it
    // first. Safe: a forged scp only selects which key the signature must match.
    const peek = JSON.parse(payloadRaw.toString('utf8'));
    if (peek.scp !== undefined && (typeof peek.scp !== 'string' || !peek.scp)) return { ok: false };
    const scp = (typeof peek.scp === 'string') ? peek.scp : null;
    const expected = crypto.createHmac('sha256', _signingKey(scp))
      .update(payloadRaw).digest();
    if (sig.length !== expected.length || !crypto.timingSafeEqual(sig, expected)) {
      return { ok: false };
    }
    const payload = peek;
    if (payload.typ !== 'session') return { ok: false };
    // MP-SIGNIN-SCOPE: a scoped token is not a credential anywhere but its own host --
    // not even an "expired" one, so another host never reports TOKEN_EXPIRED for it.
    if (scp && normScope(host) !== scp) return { ok: false };
    // FP-04: never a session for a local DEV/test identity (see header).
    if (/@local$/.test(String(payload.sub || '').trim().toLowerCase())) return { ok: false };
    if (typeof payload.exp !== 'number' || Date.now() > payload.exp) {
      return { ok: false, expired: true };
    }
    // CORPIT-SESSION-CAP-VERIFY: absolute ceiling measured from the FIRST sign-in.
    // Pure arithmetic - no file, no DB, no network - so /check stays pure-crypto.
    // The typeof guard is load-bearing: every token live at the 2026-09-04 deploy
    // lacks 'ait' and can never enter this branch, so the deploy logs nobody out.
    // expired:true (not a new code) is deliberate - rbac-middleware.js:435 already
    // surfaces that as TOKEN_EXPIRED, which is the 're-authenticate' outcome the
    // cap wants.
    if (typeof payload.ait === 'number' && Date.now() > payload.ait + SESSION_ABS_CAP_MS) {
      return { ok: false, expired: true };
    }
    // CORPIT-REVOKE: checked AFTER signature and expiry, so a forged or stale
    // token is rejected on its own merits and never consults the denylist.
    if (!allowRevoked && isRevoked(payload.jti)) return { ok: false, revoked: true };
    // CORPIT-REVOKE-EPOCH: catches sessions the per-jti list cannot see, because
    // /api/auth/accept and the sliding renewal both mint a brand-new jti.
    if (!allowRevoked && isEpochRevoked(payload.sub, payload.iat)) return { ok: false, revoked: true };
    return { ok: true, email: payload.sub, name: payload.name || payload.sub, exp: payload.exp,
             jti: payload.jti,
             iat: (typeof payload.iat === 'number' ? payload.iat : null),
             // CORPIT-SESSION-CAP-CLAIMS  Raw claim: null on every token minted before 2026-09-04.
             ait: (typeof payload.ait === 'number' ? payload.ait : null),
             // EFFECTIVE anchor. The missing-ait fallback is materialised HERE, once,
             // so the re-mint path and /api/gate/session-info can never disagree. A
             // legacy token anchors to its own signed iat: conservative, and its own
             // exp (iat+10h) always fires before iat+12h, so nothing is shortened.
             absAit: (typeof payload.ait === 'number' ? payload.ait
                      : (typeof payload.iat === 'number' ? payload.iat : Date.now())),
             // Absent on tokens minted before per-site authorization existed.
             groups: Array.isArray(payload.grp) ? payload.grp : null,
             scope: scp };
  } catch (e) {
    return { ok: false };
  }
}

// opts.host: the host the request arrived on (MP-SIGNIN-SCOPE). Only needed for a
// scoped token to verify; platform tokens ignore it.
function verifySessionToken(token, opts) {
  return _verifySessionToken(token, false, opts && opts.host);
}

// Logout only: authenticate signature/expiry, then revoke jti + identity in ONE
// locked durable replacement. Already-revoked cookies can retry a failed fsync,
// but must never advance an epoch or invalidate a session minted after logout.
// This exports no revocation-bypassing authentication result to other callers.
function revokeTokenForLogout(token, opts) {
  if (!isConfigured()) return false;
  const identity = _verifySessionToken(token, true, opts && opts.host);   // MP-SIGNIN-SCOPE
  if (!identity.ok) return true; // Invalid/expired cookies can simply be cleared.
  if (!identity.jti || !identity.email) return false;
  return _withRevokeLock(function () {
    const cur = _load();
    const who = String(identity.email).trim().toLowerCase();
    const now = Date.now();
    const previousEpoch = Number(cur.epochs[who]);
    const alreadyRevoked = cur.list.some(function (entry) {
      return entry && String(entry.jti) === String(identity.jti);
    }) || (typeof identity.iat === 'number' && Number.isFinite(previousEpoch) &&
           identity.iat < previousEpoch);
    if (alreadyRevoked) {
      // Rename may have succeeded before directory fsync failed on the earlier
      // attempt. Persist the CURRENT state without extending its revocation.
      return _save(cur.list, cur.epochs);
    }
    const list = cur.list.filter(function (entry) {
      return entry && entry.jti && !(typeof entry.exp === 'number' && entry.exp < now);
    });
    list.push({ jti: String(identity.jti), exp: identity.exp, at: now });
    const epochs = {};
    for (const key of Object.keys(cur.epochs)) {
      const time = Number(cur.epochs[key]);
      if (Number.isFinite(time) && time + SESSION_TTL_MS >= now) epochs[key] = time;
    }
    epochs[who] = Math.max(now, typeof identity.iat === 'number' ? identity.iat + 1 : now,
                           Number.isFinite(previousEpoch) ? previousEpoch : 0);
    return _save(list, epochs);
  });
}

module.exports = {
  SESSION_TTL_MS,
  SESSION_ABS_CAP_MS,   // CORPIT-SESSION-CAP-EXPORT
  isConfigured,
  mintSessionToken,
  verifySessionToken,
  revokeTokenForLogout,
  // CORPIT-REVOKE
  isRevoked,
  isEpochRevoked,
  revokeSession,
  revokeUser,
  REVOKE_FILE,
};
