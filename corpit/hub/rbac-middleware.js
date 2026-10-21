// =====================================================================
// rbac-middleware.js  —  v3.0.0
//
// RBAC v3 middleware for api-beta. Same exports as v1 plus helpers:
//   loadCurrentUser        — verifies the Azure id_token, resolves roles from
//                            AD when stale, attaches req.user
//   requireSuperAdmin      — gates routes to super-admins
//   requirePage(k, l)      — gates routes via the v3 role model
//   audit                  — audit-log helper (unchanged contract)
//   computeEffectivePages  — full page->level map for a user (used by /me)
//
// v3 model (schema: rbac-v3 migration, 2026-08-03):
//   * A user holds ZERO OR MORE roles, written to rbac_user_roles at login
//     from AD security group membership (rbac_roles.ad_group_dn).
//   * Each role has a default_access (none|read|admin) applying to every
//     ACTIVE page. rbac_role_pages holds only per-page EXCEPTIONS.
//   * rbac_user_page_access is a per-user OVERRIDE layer: read/admin widen
//     or hold, 'none' explicitly denies. An override always wins.
//   * Merge: for each role, level(page) = exception ?? default. User level =
//     most permissive across roles. Override (if present) replaces that.
//   * Super-admin = RBAC_SUPERADMINS env var  UNION  membership of the
//     'superadmin' role (AD group SaaS-ITH-SA). Env-var entries are the
//     break-glass floor and are never removable from a browser.
//   * HARD EXCLUSION: page 'rbac-admin' (and requireSuperAdmin routes) can
//     never be granted by any role default or exception — super-admin only.
//     A per-user override cannot grant it either.
//   * Staleness: roles resolved more than ROLE_STALENESS_MS ago (24h), or
//     invalidated via rbac_users.roles_invalidated_at, are re-resolved from
//     AD on the next request. Resolution failure FAILS CLOSED with a
//     distinct code so "directory down" never reads as "access denied".
//   * Pages with status='retired'/'draft'/'beta' still enforce normally —
//     status only affects nav/tile rendering, never the guard.
//
// Required env vars (in /var/www/corpit-hub-api/.env):
//   RBAC_AZURE_TENANT_ID   — Azure tenant id
//   RBAC_AZURE_CLIENT_ID   — Azure app registration client id (audience pin)
//   RBAC_SUPERADMINS       — comma-separated emails (break-glass floor)
//   LDAP_URL / LDAP_BASE_DN / LDAP_BIND_USER / LDAP_BIND_PASS (resolver)
//
// Usage in server.js / route files: unchanged from v1.
// =====================================================================

'use strict';

const jwt        = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const sessionAuth = require('./session-auth');
const { resolveRoles } = require('./rbac-ad-resolver');
let breakglass = null;
try { breakglass = require('./breakglass-auth'); }
catch (e) { console.warn('[rbac-middleware] breakglass-auth not present - local break-glass disabled'); }
let localdev = null;
try { localdev = require('./localdev-auth'); }
catch (e) { console.warn('[rbac-middleware] localdev-auth not present - DEV sign-in disabled'); }

// ---------- constants ---------------------------------------------------
const ROLE_STALENESS_MS = 24 * 60 * 60 * 1000;   // 24 hours
const HARD_EXCLUDED_PAGES = new Set(['rbac-admin']); // super-admin only, always
const LEVEL_RANK = { none: 0, read: 1, admin: 2 };

// ---------- env validation (logged once at module load) ----------------
const TENANT_ID  = process.env.RBAC_AZURE_TENANT_ID;
const CLIENT_ID  = process.env.RBAC_AZURE_CLIENT_ID;
const SUPERADMINS = (process.env.RBAC_SUPERADMINS || '')
  .split(',')
  .map(s => s.trim().toLowerCase())
  .filter(Boolean);

if (!TENANT_ID || !CLIENT_ID) {
  console.error('[rbac-middleware] FATAL: RBAC_AZURE_TENANT_ID or RBAC_AZURE_CLIENT_ID missing in env');
}
if (SUPERADMINS.length === 0) {
  console.warn('[rbac-middleware] WARN: RBAC_SUPERADMINS is empty — break-glass floor is unset');
}

// ---------- super-admin provenance (CORPIT-SA-AUDIT) -------------------------
// Super-admin can be granted three different ways, and until now the audit log
// could not tell them apart after the fact. Carrying the source on req.user
// means every recorded super-admin action says where the privilege came from.
//   'env'      - RBAC_SUPERADMINS break-glass floor, no database row behind it
//   'role'     - the AD-resolved 'superadmin' role, revocable in the directory
//   'env+role' - both
function superAdminSourceFor(isEnv, roles) {
  const byRole = Array.isArray(roles) && roles.includes('superadmin');
  if (isEnv && byRole) return 'env+role';
  if (isEnv)  return 'env';
  if (byRole) return 'role';
  return null;
}

// Reads are de-duplicated per actor+method+path so a polling admin dashboard
// cannot drown the log; writes are ALWAYS recorded, never de-duplicated.
const SA_PASS_DEDUPE_MS = 5 * 60 * 1000;
const saPassSeen = new Map();

// ---------- JWKS client (caches Azure public keys, 10 minutes) ---------
const jwks = jwksClient({
  jwksUri: `https://login.microsoftonline.com/${TENANT_ID}/discovery/v2.0/keys`,
  cache: true,
  cacheMaxAge: 10 * 60 * 1000,        // 10 minutes
  rateLimit: true,
  jwksRequestsPerMinute: 10,
});

function getSigningKey(header, callback) {
  jwks.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err);
    callback(null, key.getPublicKey());
  });
}

// Accept both v1 and v2 issuer formats — Azure sometimes flips between them
const VALID_ISSUERS = [
  `https://login.microsoftonline.com/${TENANT_ID}/v2.0`,
  `https://sts.windows.net/${TENANT_ID}/`,
];

function verifyToken(token) {
  return new Promise((resolve, reject) => {
    jwt.verify(
      token,
      getSigningKey,
      {
        algorithms:    ['RS256'],
        audience:      CLIENT_ID,
        issuer:        VALID_ISSUERS,
        clockTolerance: 30,           // 30s of clock-skew tolerance
        ignoreExpiration: false,       // H-1 (2026-09-02): enforce exp. Sessions persist via the
                                       // typ:'session' token from POST /api/rbac/session, not here
      },
      (err, decoded) => err ? reject(err) : resolve(decoded)
    );
  });
}

// True only for POST /api/rbac/session - the one route allowed to consume a
// raw Azure id_token (it mints the typ:'session' token everything else uses).
// Uses originalUrl so it holds under both app-level and router-level mounts.
function isSessionMintRequest(req) {
  if (!req || req.method !== 'POST') return false;
  // F37: linear trailing-'/' strip (the /\/+$/ regex backtracked quadratically).
  let p = String(req.originalUrl || req.url || '').split('?')[0];
  let e = p.length; while (e > 0 && p.charCodeAt(e - 1) === 47) e--;
  p = p.slice(0, e);
  return p === '/api/rbac/session';
}

function extractEmail(claims) {
  const raw = claims.preferred_username || claims.email || claims.upn || null;
  return raw ? String(raw).trim().toLowerCase() : null;
}

function maxLevel(a, b) {
  return (LEVEL_RANK[a] >= LEVEL_RANK[b]) ? a : b;
}

// ---------- G19: one identity load per request ---------------------------
// server.js's /api blanket runs loadCurrentUser, and then most routers run it
// again for the SAME request through their own createRbac(pool). That second
// run reads the same rows from the same database and builds the same req.user.
// It is skipped only when nothing that decides the answer has changed:
//   * the earlier load ended on a clean success path (markLoaded). A failed,
//     partial (break-glass floor, last-known-good), inactive-user or strict
//     load leaves no mark and is never reused;
//   * req.user is still the object that load built, with the same content;
//   * the credential headers, req.authVia, req.sessionClaims, method and URL
//     are the ones that load read;
//   * this instance reads the same database the same way (sameTarget);
//   * this call did not ask for the stricter directory check
//     (req.portalStrictDirectory), and the instance did not opt out.
// Anything else runs the full load exactly as before, clearing the mark first.
// The mark is a non-enumerable Symbol property on req: nothing on the wire can
// set it, it does not show in JSON, Object.keys or inspect, and it ends with the
// request, so the next request always loads from the database.
const LOADED = Symbol('rbac-middleware.loadedIdentity');

// ConnectionConfig fields with no bearing on which rows come back or how they
// decode: the pool back-reference and the handshake client attributes.
// charsetNumber is compared by family instead.
const TARGET_SKIP = new Set(['pool', 'connectAttributes', 'charsetNumber']);
// 45 = utf8mb4_general_ci (charset: 'utf8mb4'), 224 = utf8mb4_unicode_ci (the
// mysql2 default). Same encoding both ways, and every lookup in loadCurrentUser
// compares a column to a parameter, where the column's own collation decides.
function charsetFamily(n) { return (n === 45 || n === 224) ? 'utf8mb4' : n; }
function isComplex(v) { return v !== null && (typeof v === 'object' || typeof v === 'function'); }
// True only when two mysql2 connection configs reach the same server, account
// and database and decode results the same way: every plain field equal, and no
// object or function field (typeCast function, queryFormat, ssl, stream, auth
// plugins) on either side, since those cannot be proven equal.
function sameTarget(a, b) {
  if (!a || !b) return false;
  if (charsetFamily(a.charsetNumber) !== charsetFamily(b.charsetNumber)) return false;
  const keys = new Set(Object.keys(a).concat(Object.keys(b)));
  for (const k of keys) {
    if (TARGET_SKIP.has(k)) continue;
    if (isComplex(a[k]) || isComplex(b[k]) || a[k] !== b[k]) return false;
  }
  return true;
}
// Each createRbac instance gets a target id once, at creation, so the mark on
// req carries a small integer and never a reference to anything holding a
// database password. A config that matches nothing (or cannot be compared)
// gets an id of its own.
const TARGETS = [];
function targetIdOf(pool) {
  const c = pool && pool.pool && pool.pool.config && pool.pool.config.connectionConfig;
  if (!c || typeof c !== 'object') return null;
  for (let i = 0; i < TARGETS.length; i++) if (sameTarget(TARGETS[i], c)) return i;
  TARGETS.push(sameTarget(c, c) ? c : null);
  return TARGETS.length - 1;
}

// ---------- factory ----------------------------------------------------
// opts.reuseIdentity === false makes this instance always run the full load and
// never reuse one made earlier in the request (bug-reports-routes.js keeps its
// deliberate re-check this way). Without opts, behaviour is the G19 default.
module.exports = function createRbac(pool, opts) {
  if (!pool) {
    throw new Error('[rbac-middleware] pool argument is required (mysql2/promise pool)');
  }
  const reuseIdentity = !(opts && opts.reuseIdentity === false);
  const myTarget = targetIdOf(pool);

  // Per-process guard so several concurrent requests from the same user do
  // not each fire an LDAP resolution. Maps email -> in-flight promise.
  const inflightResolutions = new Map();

  /**
   * Insert one row into rbac_audit_log. Errors are logged, never thrown,
   * so an audit gap never breaks the request flow.
   */
  // CORPIT-AUDIT-MEDIUM  X-Forwarded-For is set by nginx on only 5 of 38 proxy blocks, so a client
  // could previously put anything in it and have it stored verbatim as the audit
  // row's IP. Mirror the rate limiter in server.js: believe X-Real-IP only when the
  // request genuinely arrived from nginx on loopback, otherwise use the real peer.
  function auditClientIp(req) {
    const peer = (req.socket && req.socket.remoteAddress) || '';
    const fromProxy = peer === '127.0.0.1' || peer === '::1' || peer === '::ffff:127.0.0.1';
    const chosen = (fromProxy && req.headers['x-real-ip']) || peer;
    return String(chosen || '').split(',')[0].trim().slice(0, 45) || null;
  }

  async function audit(req, action, target_email, target_page_key, details) {
    try {
      await pool.execute(
        `INSERT INTO rbac_audit_log
           (actor_email, action, target_email, target_page_key, details, ip_address, user_agent)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          (req.user && req.user.email) || 'anonymous',
          action,
          target_email   || null,
          target_page_key || null,
          details ? JSON.stringify(details) : null,
          auditClientIp(req),
          ((req.headers['user-agent'] || '') + '').slice(0, 500) || null,
        ]
      );
    } catch (e) {
      console.error('[rbac-middleware] audit insert failed:', e.message);
    }
  }

  /**
   * Run AD resolution for one email, de-duplicated across concurrent
   * requests. Returns the resolver result object.
   */
  function resolveOnce(email) {
    if (inflightResolutions.has(email)) return inflightResolutions.get(email);
    const p = resolveRoles(pool, email)
      .finally(() => inflightResolutions.delete(email));
    inflightResolutions.set(email, p);
    return p;
  }

  /**
   * Load the user's persisted role rows.
   */
  async function loadRoles(email) {
    const [rows] = await pool.query(
      'SELECT role_key FROM rbac_user_roles WHERE email = ?',
      [email]
    );
    return rows.map(r => r.role_key);
  }

  /**
   * Reads Authorization: Bearer <token>, validates the JWT, ensures the
   * user's AD roles are fresh (resolving when stale), and attaches req.user:
   *   { email, displayName, isSuperAdmin, isActive, roles: [...] }
   * Does NOT reject the request — sets req.user = null (with req.tokenError)
   * on failure so downstream guards decide whether to enforce.
   */
  // ---------- CORPIT-COOKIE-AUTH (2026-09-02) --------------------------
  // This used to read ONLY 'Authorization: Bearer'. That is why sign-in copies
  // the HttpOnly it_session token into sessionStorage (auth-complete.js) so page
  // JS can replay it as a bearer -- which hands any XSS a portable, long-lived
  // credential and defeats the entire point of HttpOnly.
  //
  // The browser already sends the cookie on every same-origin request, so that
  // copy is unnecessary. Accept the cookie as an EQUAL credential when no bearer
  // is present. Purely additive: anything that authenticates today authenticates
  // identically after this.
  //
  // :3000 (/var/www/api/server.js) has done exactly this since 2026-08-24, for
  // the same observed bug. This brings :3001 into line -- but populates req.user
  // through the normal path rather than short-circuiting the guard, so roles and
  // super-admin status resolve exactly as they do for a bearer.
  //
  // A browser can hold TWO it_session cookies during a Domain= rollout and send
  // both, so every value is tried (same as /api/auth/token and gate-routes).
  function sessionCookieValues(req) {
    const out = [];
    const raw = req.headers.cookie || '';
    const re = /(?:^|;\s*)it_session=([^;]*)/g;
    let mm;
    while ((mm = re.exec(raw)) !== null) {
      let v = mm[1];
      try { v = decodeURIComponent(v); } catch (e) { /* malformed %-escape: use raw */ }
      if (v) out.push(v);
    }
    return out;
  }

  // Pre-select the cookie value the main path will accept. Verification below is
  // pure HMAC (no DB, no LDAP), so running it twice costs nothing measurable and
  // this stays a SELECTION step -- not a second, divergent authentication path.
  // An expired session token is returned too, so the main path can report
  // TOKEN_EXPIRED rather than a misleading NO_TOKEN.
  function pickCookieCredential(req) {
    let expiredCandidate = null;
    const vals = sessionCookieValues(req);
    for (let i = 0; i < vals.length; i++) {
      const v = vals[i];
      try {
        if (breakglass && breakglass.isConfigured()) {
          const r = breakglass.verifySessionToken(v);
          if (r && r.ok) return { token: v };
        }
      } catch (e) {}
      try {
        if (localdev && localdev.isEnabled()) {
          const r = localdev.verifyToken(v);
          if (r && r.ok) return { token: v };
        }
      } catch (e) {}
      try {
        if (sessionAuth.isConfigured()) {
          const r = sessionAuth.verifySessionToken(v, { host: req.headers.host });   // MP-SIGNIN-SCOPE
          if (r && r.ok) return { token: v };
          if (r && (r.expired || r.revoked) && !expiredCandidate) expiredCandidate = v;
        }
      } catch (e) {}
    }
    return expiredCandidate ? { token: expiredCandidate } : null;
  }

  // G19: may this call reuse the identity this request already loaded?
  function canReuse(req) {
    const mk = req[LOADED];
    return !!mk && myTarget !== null && mk.target === myTarget &&
      req.user != null && req.user === mk.user && JSON.stringify(req.user) === mk.snap &&
      req.headers.authorization === mk.authz && req.headers.cookie === mk.cookie &&
      req.authVia === mk.authVia && req.sessionClaims === mk.claims &&
      req.method === mk.method && req.originalUrl === mk.url;
  }

  // G19: record a clean, non-strict load so a later call in the same request
  // can reuse it. Called only on the three full-success paths below.
  function markLoaded(req, strict) {
    if (!reuseIdentity || strict || myTarget === null || !req.user) return;
    Object.defineProperty(req, LOADED, {
      configurable: true, enumerable: false, writable: false,
      value: Object.freeze({
        target: myTarget, user: req.user, snap: JSON.stringify(req.user),
        authz: req.headers.authorization, cookie: req.headers.cookie,
        authVia: req.authVia, claims: req.sessionClaims,
        method: req.method, url: req.originalUrl,
      }),
    });
  }

  async function loadCurrentUser(req, res, next) {
    const strict = !!req.portalStrictDirectory;
    if (reuseIdentity && !strict && canReuse(req)) return next();
    if (req[LOADED]) delete req[LOADED];

    const auth = req.headers.authorization || '';
    let m = auth.match(/^Bearer\s+(.+)$/i);
    // req.authVia tells the CSRF guard in server.js which credential was used.
    // A bearer cannot be forged cross-origin (the attacker's page cannot read the
    // token to set the header); a cookie can, because the browser attaches it.
    req.authVia = m ? 'bearer' : null;
    if (!m) {
      const ck = pickCookieCredential(req);
      if (ck) { m = [null, ck.token]; req.authVia = 'cookie'; }
    }
    if (!m) {
      req.user = null;
      return next();
    }

    // Break-glass first: a cheap local HMAC check with no network
    // dependency, so the itam account works when Azure and the DC are down.
    if (breakglass && breakglass.isConfigured()) {
      const bgResult = breakglass.verifySessionToken(m[1]);
      if (bgResult.ok) {
        req.user = {
          email:        breakglass.ACCOUNT_EMAIL,
          displayName:  'Break-glass (itam)',
          isSuperAdmin: true,
          isActive:     true,
          roles:        ['superadmin'],
          isBreakglass: true,
          superAdminSource: 'breakglass',
        };
        markLoaded(req, strict);
        return next();
      }
      if (bgResult.expired) {
        req.user = null;
        req.tokenError = 'BREAKGLASS_EXPIRED';
        return next();
      }
      // not a break-glass token at all - fall through to Azure JWT path
    }

    // ── Local DEV/test accounts ─────────────────────────────────────────
    // Checked before the Azure path, after break-glass. These exist so an
    // admin can sign in AS a tier1 / no-role user and exercise the real
    // server-side guard. Three things are enforced here and cannot be
    // overridden from the database:
    //   * isSuperAdmin is hard-false, always
    //   * the account must still be active in rbac_local_users
    //   * the whole path is inert unless LOCALDEV_ENABLED=1
    if (localdev && localdev.isEnabled()) {
      const ldRes = localdev.verifyToken(m[1]);
      if (ldRes.expired) {
        req.user = null;
        req.tokenError = 'TOKEN_EXPIRED';
        return next();
      }
      if (ldRes.ok) {
        const [acct] = await pool.query(
          'SELECT email, display_name, is_active FROM rbac_local_users WHERE email = ? LIMIT 1',
          [ldRes.email]
        );
        if (acct.length === 0 || !acct[0].is_active) {
          req.user = null;
          req.tokenError = 'LOCALDEV_DISABLED';
          return next();
        }
        const roles = await loadRoles(ldRes.email);
        req.user = {
          email:        ldRes.email,
          displayName:  acct[0].display_name || ldRes.email,
          // Hard false. A local account is never super-admin, even if its
          // email were added to RBAC_SUPERADMINS or given the superadmin role.
          isSuperAdmin: false,
          isActive:     true,
          roles:        roles.filter(function (r) { return r !== 'superadmin'; }),
          isLocalTest:  true,
          // Read-only QA token: server.js's blanket 403s every mutating method
          // for this user. Carried on req.user so route handlers can also read it.
          readOnly:     !!ldRes.readOnly,
        };
        markLoaded(req, strict);
        return next();
      }
      // not a localdev token - fall through
    }

    let claims = null;
    // User session tokens (typ 'session') minted by POST /api/rbac/session.
    // Checked before the Azure JWT path; wrong-typ tokens fall through.
    if (sessionAuth.isConfigured()) {
      const sres = sessionAuth.verifySessionToken(m[1], { host: req.headers.host });   // MP-SIGNIN-SCOPE
      if (sres.expired) {
        req.user = null;
        req.tokenError = 'TOKEN_EXPIRED';
        return next();
      }
      // CORPIT-REVOKE: a signed, unexpired token whose session was ended.
      // Distinct code so "you signed out" never reads as "your token is invalid".
      if (sres.revoked) {
        req.user = null;
        req.tokenError = 'SESSION_REVOKED';
        return next();
      }
      if (sres.ok) {
        claims = { preferred_username: sres.email, name: sres.name };
        // CORPIT-SESSION-CLAIMS (2026-09-04): the FULL verified session claims,
        // for the re-mint path in rbac-routes.js POST /api/rbac/session ONLY.
        // `claims` above deliberately collapses to email+name for the shared
        // downstream path, which discards grp/ait/iat/jti -- and a re-mint that
        // read only req.user would therefore strip the user's AD groups (locking
        // them out of every group-mode vhost with 'session-predates-policy') and
        // reset the 12h absolute cap on every renewal.
        //
        // Nothing else in this file assigns it, and every earlier credential
        // branch (break-glass, localdev) has already returned by here, so its
        // mere PRESENCE is the predicate for "this request arrived on a
        // renewable typ:'session' credential" -- one fact rather than three
        // guards that can drift apart. It is derived from the SAME token that
        // produced req.user (bearer if one was sent, otherwise the cookie
        // pickCookieCredential selected), so the two can never name different
        // identities. Read-only downstream: do not mutate it.
        req.sessionClaims = sres;
      }
    }
    if (!claims) {
      // H-1 (2026-09-02): a raw Azure id_token is accepted ONLY to mint a
      // session at POST /api/rbac/session. Everything else must carry the
      // typ:'session' token that route returns (login.html stores it as
      // sso_user.idToken; rbac-client.js attaches it). Distinct code so a
      // client can tell "wrong credential" from "expired".
      if (!isSessionMintRequest(req)) {
        req.user = null;
        req.tokenError = 'ID_TOKEN_NOT_ACCEPTED';
        return next();
      }
      try {
        claims = await verifyToken(m[1]);
      } catch (err) {
        req.user = null;
        req.tokenError = (err && err.name === 'TokenExpiredError')
          ? 'TOKEN_EXPIRED'
          : 'TOKEN_INVALID';
        return next();
      }
    }

    const email = extractEmail(claims);
    if (!email) {
      req.user = null;
      req.tokenError = 'NO_EMAIL_CLAIM';
      return next();
    }

    const isEnvSuperAdmin = SUPERADMINS.includes(email);
    let displayName = claims.name || email;
    let isActive    = true;
    let resolvedAt  = null;
    let invalidatedAt = null;
    let rowExists   = false;
    // G19: set when a lookup failed and the load carried on anyway (env
    // super-admin floor, last-known-good roles). Such a load is never reused.
    let degraded    = false;

    try {
      const [rows] = await pool.query(
        `SELECT display_name, is_active, roles_resolved_at, roles_invalidated_at
           FROM rbac_users WHERE email = ? LIMIT 1`,
        [email]
      );
      if (rows.length > 0) {
        rowExists     = true;
        displayName   = rows[0].display_name || displayName;
        isActive      = !!rows[0].is_active;
        resolvedAt    = rows[0].roles_resolved_at ? new Date(rows[0].roles_resolved_at).getTime() : null;
        invalidatedAt = rows[0].roles_invalidated_at ? new Date(rows[0].roles_invalidated_at).getTime() : null;
      }
    } catch (err) {
      console.error('[rbac-middleware] rbac_users lookup failed:', err.message);
      // On a DB error we cannot trust any state: treat as unauthenticated-ish
      // but leave env super-admins standing (break-glass floor).
      if (!isEnvSuperAdmin) {
        req.user = null;
        req.tokenError = 'USER_LOOKUP_ERROR';
        return next();
      }
      degraded = true;
    }

    // Manual disable switch always wins (env super-admins excepted).
    if (rowExists && !isActive && !isEnvSuperAdmin) {
      req.user = { email, displayName, isSuperAdmin: false, isActive: false, roles: [] };
      return next();
    }

    // Decide whether AD resolution is needed.
    const now = Date.now();
    const stale =
      !resolvedAt ||
      (now - resolvedAt) > (req.portalStrictDirectory ? 5 * 60 * 1000 : ROLE_STALENESS_MS) ||
      (invalidatedAt && invalidatedAt > resolvedAt);

    if (stale) {
      const result = await resolveOnce(email);
      if (!result.ok) {
        // FAIL CLOSED — but with a truthful, distinct error code, and the
        // env-var break-glass floor stays standing.
        if (isEnvSuperAdmin) {
          console.warn('[rbac-middleware] resolution failed for env super-admin', email, '-', result.code, '(continuing on break-glass floor)');
          req.user = { email, displayName, isSuperAdmin: true, isActive: true, roles: [], superAdminSource: 'env-unresolved' };
          return next();
        }
        // ITAM-01b (staged 2026-08-14, deploy 2026-08-17): a TRANSIENT directory
        // outage must not lock out a user we have already resolved before. For
        // DIRECTORY_UNAVAILABLE WITH an existing rbac_users row, fall through and
        // serve last-known-good roles from rbac_user_roles below. USER_NOT_FOUND /
        // AMBIGUOUS_USER remain hard denials (genuine identity problems, not infra).
        if (req.portalStrictDirectory || !(result.code === 'DIRECTORY_UNAVAILABLE' && rowExists)) {
          req.user = null;
          req.tokenError = result.code;    // USER_NOT_FOUND | AMBIGUOUS_USER | DIRECTORY_UNAVAILABLE
          return next();
        }
        console.warn('[rbac-middleware] directory unavailable for', email, '- serving last-known-good cached roles (known user, row exists)');
        degraded = true;
      }
      if (result.displayName) displayName = result.displayName;
    }

    let roles = [];
    try {
      roles = await loadRoles(email);
    } catch (err) {
      console.error('[rbac-middleware] rbac_user_roles lookup failed:', err.message);
      if (!isEnvSuperAdmin) {
        req.user = null;
        req.tokenError = 'USER_LOOKUP_ERROR';
        return next();
      }
      degraded = true;
    }

    const isSuperAdmin = isEnvSuperAdmin || roles.includes('superadmin');

    req.user = {
      email, displayName, isSuperAdmin, isActive: true, roles,
      superAdminSource: superAdminSourceFor(isEnvSuperAdmin, roles),
    };
    if (!degraded) markLoaded(req, strict);
    next();
  }

  /**
   * Compute the effective access level for ONE page under the v3 model.
   * Returns 'none' | 'read' | 'admin'. Assumes req.user checks already done.
   */
  async function portalLevel(email, roles, level, explicitDeny) {
    if (explicitDeny) return 'none';
    try {
      const scope = await require('./portal-access').portalScope(email, roles);
      return scope.blocked ? 'none' : (scope.admitted ? maxLevel(level, 'read') : level);
    } catch (e) {
      console.error('[rbac] approval policy unavailable:', e.message);
      return 'none'; // Other pages remain independent of the portal service.
    }
  }

  async function effectiveLevelForPage(email, roles, pageKey, accessPolicy, includeApprovalScope=true) {
    // Hard exclusion: no role or override can grant these.
    if (HARD_EXCLUDED_PAGES.has(pageKey)) return 'none';

    // Per-user override wins outright when present (including 'none' deny).
    const [ovr] = await pool.query(
      'SELECT access_level FROM rbac_user_page_access WHERE email = ? AND page_key = ? LIMIT 1',
      [email, pageKey]
    );
    if (ovr.length > 0) return pageKey === 'approver-portal' && includeApprovalScope
      ? portalLevel(email, roles, ovr[0].access_level, ovr[0].access_level === 'none') : ovr[0].access_level;

    let level = 'none';

    if (roles.length > 0) {
      const [defs] = await pool.query(
        'SELECT role_key, default_access FROM rbac_roles WHERE role_key IN (?)',
        [roles]
      );
      const [excs] = await pool.query(
        'SELECT role_key, access_level FROM rbac_role_pages WHERE page_key = ? AND role_key IN (?)',
        [pageKey, roles]
      );
      const excMap = Object.fromEntries(excs.map(e => [e.role_key, e.access_level]));
      for (const d of defs) {
        const roleLevel = excMap[d.role_key] !== undefined ? excMap[d.role_key] : d.default_access;
        level = maxLevel(level, roleLevel);
      }
    }

    // 'authenticated' pages give any signed-in user at least read.
    if (accessPolicy === 'authenticated') level = maxLevel(level, 'read');
    if (pageKey === 'approver-portal' && includeApprovalScope) return portalLevel(email, roles, level, false);
    return level;
  }

  /**
   * Full page->level map for a user. Exported for GET /me and the admin UI.
   * Super-admins get admin on every page ('read' on authenticated-policy
   * pages, matching prior behaviour).
   */
  async function computeEffectivePages(email, roles, isSuperAdmin) {
    // [CORPIT-QA 2026-09-07] SEC-2. This comment block has always said
    // "every ACTIVE page", but the query had no status filter, so the 4
    // retired and 2 draft rows resolved exactly like live ones -- which is
    // how ad-provisioning (retired) and exec-command (draft) sat inside
    // tier2's admin default. Verified before applying: all six non-active
    // pages have no file on this host, so nothing reachable loses access.
    const [allPages] = await pool.query(
      "SELECT page_key, access_policy FROM rbac_pages WHERE status = 'active'"
    );

    const pages = {};

    if (isSuperAdmin) {
      for (const p of allPages) {
        pages[p.page_key] = p.access_policy === 'authenticated' ? 'read' : 'admin';
      }
      return pages;
    }

    // Batch the three layers once, then merge in memory.
    const [ovrRows] = await pool.query(
      'SELECT page_key, access_level FROM rbac_user_page_access WHERE email = ?',
      [email]
    );
    const ovrMap = Object.fromEntries(ovrRows.map(r => [r.page_key, r.access_level]));

    let defRows = [], excRows = [];
    if (roles.length > 0) {
      [defRows] = await pool.query(
        'SELECT role_key, default_access FROM rbac_roles WHERE role_key IN (?)',
        [roles]
      );
      [excRows] = await pool.query(
        'SELECT role_key, page_key, access_level FROM rbac_role_pages WHERE role_key IN (?)',
        [roles]
      );
    }
    const excByPage = {};
    for (const e of excRows) {
      (excByPage[e.page_key] = excByPage[e.page_key] || {})[e.role_key] = e.access_level;
    }

    for (const p of allPages) {
      let level;

      if (HARD_EXCLUDED_PAGES.has(p.page_key)) {
        level = 'none';
      } else if (ovrMap[p.page_key] !== undefined) {
        level = ovrMap[p.page_key];
      } else {
        level = 'none';
        const pageExc = excByPage[p.page_key] || {};
        for (const d of defRows) {
          const roleLevel = pageExc[d.role_key] !== undefined ? pageExc[d.role_key] : d.default_access;
          level = maxLevel(level, roleLevel);
        }
        if (p.access_policy === 'authenticated') level = maxLevel(level, 'read');
      }

      if (p.page_key === 'approver-portal') level = await portalLevel(email, roles, level, ovrMap[p.page_key] === 'none');
      if (level !== 'none') pages[p.page_key] = level;
    }

    return pages;
  }

  /**
   * Landing-page section visibility.
   *
   * Sections are VISIBLE by default -- rbac_section_visibility only records
   * deviations, so an empty table means every user sees the page exactly as
   * it shipped. Precedence:
   *   1. a per-user row wins outright
   *   2. otherwise role rows merge most-permissively (any role that says
   *      visible=1 beats a role that says visible=0), matching how page
   *      levels merge in computeEffectivePages
   *   3. otherwise the section is visible
   *
   * Returns the array of section_keys to HIDE. This is a layout concern, not
   * a security boundary, so super-admins are NOT exempt -- hiding a section
   * for a super-admin hides it for them too, which is what makes "view as"
   * faithful.
   *
   * @param {string} email
   * @param {string[]} roles
   * @returns {Promise<string[]>} section_keys to hide
   */
  async function computeHiddenSections(email, roles) {
    const list = Array.isArray(roles) ? roles : [];
    let rows;
    try {
      if (list.length > 0) {
        [rows] = await pool.query(
          `SELECT scope_type, section_key, visible
             FROM rbac_section_visibility
            WHERE (scope_type = 'user' AND scope_id = ?)
               OR (scope_type = 'role' AND scope_id IN (?))`,
          [email, list]
        );
      } else {
        [rows] = await pool.query(
          `SELECT scope_type, section_key, visible
             FROM rbac_section_visibility
            WHERE scope_type = 'user' AND scope_id = ?`,
          [email]
        );
      }
    } catch (err) {
      // Fail OPEN: a section is chrome, not a permission. If this lookup
      // breaks we show the full page rather than blanking it for everyone.
      console.error('[rbac-middleware] computeHiddenSections failed:', err.message);
      return [];
    }

    const userRule = Object.create(null);
    const roleRule = Object.create(null);
    for (const r of rows) {
      if (r.scope_type === 'user') {
        userRule[r.section_key] = !!r.visible;
      } else {
        roleRule[r.section_key] = roleRule[r.section_key] === true || !!r.visible;
      }
    }

    const hidden = [];
    const keys = new Set(Object.keys(userRule).concat(Object.keys(roleRule)));
    for (const k of keys) {
      const vis = userRule[k] !== undefined ? userRule[k] : roleRule[k];
      if (vis === false) hidden.push(k);
    }
    return hidden.sort();
  }

  /**
   * Express middleware. Requires req.user to be a super-admin
   * (RBAC_SUPERADMINS env var OR the 'superadmin' AD-resolved role).
   * Use after loadCurrentUser.
   */
  async function requireSuperAdmin(req, res, next) {
    if (!req.user) {
      return res.status(401).json({
        error: 'Authentication required',
        code:  req.tokenError || 'UNAUTHENTICATED',
      });
    }
    if (!req.user.isSuperAdmin) {
      await audit(req, 'authorization_denied', null, 'rbac-admin', {
        reason: 'not_super_admin',
        path:   req.originalUrl || req.url,
      });
      return res.status(403).json({
        error: 'Super-admin access required',
        code:  'NOT_SUPER_ADMIN',
      });
    }

    // CORPIT-SA-AUDIT - the pass is recorded, not just the denial. requireSuperAdmin
    // guards genuinely destructive routes (GPO apply/execute, upload deletes),
    // so "who used super-admin, when, and what granted it" has to be
    // answerable from the log alone.
    try {
      const method  = (req.method || 'GET').toUpperCase();
      const isWrite = method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS';
      const upath   = req.originalUrl || req.url;
      let record    = true;

      if (!isWrite) {
        const key  = (req.user.email || '') + ' ' + method + ' ' + upath;
        const now  = Date.now();
        const last = saPassSeen.get(key);
        if (last && (now - last) < SA_PASS_DEDUPE_MS) {
          record = false;
        } else {
          saPassSeen.set(key, now);
          if (saPassSeen.size > 2000) {
            for (const [k, t] of saPassSeen) {
              if ((now - t) >= SA_PASS_DEDUPE_MS) saPassSeen.delete(k);
            }
          }
        }
      }

      if (record) {
        // Deliberately not awaited: audit() swallows its own errors, and a
        // super-admin request should not block on an audit insert.
        audit(req, 'superadmin_access', null, null, {
          path:       upath,
          method:     method,
          write:      isWrite,
          granted_by: req.user.superAdminSource || 'unknown',
        });
      }
    } catch (e) {
      // Auditing must never be the reason a legitimate request fails.
      console.error('[rbac-middleware] superadmin_access audit failed:', e.message);
    }

    next();
  }

  /**
   * Factory returning Express middleware that gates the route to a specific
   * page at a specific level, under the v3 role model.
   *
   * Logic:
   *   - 401 if no req.user; the code carries WHY (TOKEN_*, DIRECTORY_UNAVAILABLE,
   *     USER_NOT_FOUND, AMBIGUOUS_USER) so the frontend can say the truth
   *   - super-admins bypass to admin level on every page
   *   - inactive users are denied
   *   - unknown page_key fails closed (403)
   *   - hard-excluded pages (rbac-admin) are super-admin only, always
   *   - otherwise: effective level = per-user override, else most-permissive
   *     of (role exception ?? role default) across the user's roles, floored
   *     at 'read' for 'authenticated'-policy pages
   *
   * @param {string} pageKey   page_key from rbac_pages
   * @param {'read'|'admin'} level required access level (default: 'read')
   */
  function requirePage(pageKey, level = 'read') {
    if (!['read', 'admin'].includes(level)) {
      throw new Error(`[rbac-middleware] requirePage: invalid level '${level}' (use 'read' or 'admin')`);
    }
    return async (req, res, next) => {
      if (!req.user) {
        return res.status(401).json({
          error: 'Authentication required',
          code:  req.tokenError || 'UNAUTHENTICATED',
        });
      }

      // super-admins always pass
      if (req.user.isSuperAdmin) return next();

      if (!req.user.isActive) {
        await audit(req, 'authorization_denied', null, pageKey, {
          reason: 'user_inactive',
          path:   req.originalUrl || req.url,
        });
        return res.status(403).json({
          error: 'User is not active',
          code:  'INACTIVE_USER',
        });
      }

      // Look up the page's access_policy
      let policyRow;
      try {
        const [rows] = await pool.query(
          'SELECT access_policy FROM rbac_pages WHERE page_key = ? LIMIT 1',
          [pageKey]
        );
        policyRow = rows[0];
      } catch (err) {
        console.error('[rbac-middleware] rbac_pages lookup failed:', err.message);
        return res.status(500).json({
          error: 'Permission check failed',
          code:  'PAGE_LOOKUP_ERROR',
        });
      }

      if (!policyRow) {
        await audit(req, 'authorization_denied', null, pageKey, {
          reason: 'unknown_page_key',
          path:   req.originalUrl || req.url,
        });
        return res.status(403).json({
          error: 'Unknown page',
          code:  'UNKNOWN_PAGE',
        });
      }

      let granted;
      try {
        granted = await effectiveLevelForPage(
          req.user.email, req.user.roles || [], pageKey, policyRow.access_policy
        );
      } catch (err) {
        console.error('[rbac-middleware] effective level computation failed:', err.message);
        return res.status(500).json({
          ok: false,
          error: 'Permission check failed',
          code:  'GRANT_LOOKUP_ERROR',
        });
      }

      if (LEVEL_RANK[granted] < LEVEL_RANK[level]) {
        await audit(req, 'authorization_denied', null, pageKey, {
          reason:   granted === 'none' ? 'no_grant' : 'insufficient_level',
          granted,
          required: level,
          roles:    req.user.roles || [],
          path:     req.originalUrl || req.url,
        });
        return res.status(403).json({
          ok: false,
          error: granted === 'none' ? 'Access not granted' : 'Admin access required for this action',
          code:  granted === 'none' ? 'NO_ACCESS' : 'INSUFFICIENT_LEVEL',
        });
      }

      next();
    };
  }

  return {
    loadCurrentUser,
    requireSuperAdmin,
    requirePage,
    audit,                   // exposed so route handlers can write their own audit entries
    effectiveLevelForPage,  // shared portal entry evaluator
    computeEffectivePages,   // v3: used by GET /me and the admin console
    computeHiddenSections,   // landing-page section visibility (default: visible)
    // Exported so an admin UI can label these pages as unreachable instead of
    // rendering whatever the grant tables would otherwise compute for them —
    // the code overrules the tables here, and the screen must say so.
    HARD_EXCLUDED_PAGES,
  };
};
