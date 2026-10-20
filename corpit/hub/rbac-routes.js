'use strict';

// =====================================================================
// rbac-routes.js — RBAC Phase 1 + 1.5 API endpoints.
// Mounted in server.js as: app.use('/api/rbac', require('./rbac-routes'));
// =====================================================================

const express = require('express');
const portalOwner = require('./portal-access-owner');
const router  = express.Router();
const mysql   = require('mysql2/promise');
const createRbac = require('./rbac-middleware');
const { resolveScope, SCOPE_KINDS, resolveViewAs, canViewAs } = require('./scope-lib');
const ldap = require('ldapjs');
const { resolveRoles } = require('./rbac-ad-resolver');

/* Live membership of the reporting AD group.
 * Read from the directory, NOT from rbac_user_roles: that table is written at
 * sign-in, so somebody added to the group this morning is absent from it until
 * they next log in. For a screen whose job is "who has this", absent-until-login
 * is the wrong answer - it looks like they were never added. */
const REPORTING_GROUP_DN = 'CN=SaaS-ITH-RPT,OU=SaaS Okta,OU=Groups,DC=NRPI,DC=LOCAL';

function ldapGroupMembers(groupDn) {
  return new Promise((resolve, reject) => {
    const c = ldap.createClient({ url: process.env.LDAP_URL, connectTimeout: 5000, timeout: 8000 });
    const done = (err, val) => { try { c.unbind(() => {}); } catch (e) {} err ? reject(err) : resolve(val); };
    c.on('error', (e) => done(e));
    c.bind(process.env.LDAP_BIND_USER, process.env.LDAP_BIND_PASS, (be) => {
      if (be) return done(be);
      const dns = [];
      c.search(groupDn, { scope: 'base', attributes: ['member'] }, (se, res) => {
        if (se) return done(se);
        res.on('searchEntry', (x) => {
          for (const a of (x.pojo ? x.pojo.attributes : x.attributes)) {
            if (a.type === 'member') dns.push(...(a.values || a.vals));
          }
        });
        res.on('error', (e) => done(e));
        res.on('end', () => {
          if (!dns.length) return done(null, []);
          // One search for every member's mail, rather than a lookup per DN.
          const filter = '(|' + dns.map((d) => '(distinguishedName=' +
            String(d).replace(/[\\()*\0]/g, (ch) => '\\' + ch.charCodeAt(0).toString(16)) + ')').join('') + ')';
          const out = [];
          c.search(process.env.LDAP_BASE_DN, { scope: 'sub', filter, attributes: ['mail', 'displayName', 'userAccountControl'] },
            (se2, r2) => {
              if (se2) return done(se2);
              r2.on('searchEntry', (x) => {
                const o = {};
                for (const a of (x.pojo ? x.pojo.attributes : x.attributes)) o[a.type] = (a.values || a.vals)[0];
                if (o.mail) out.push({ email: String(o.mail).toLowerCase(), name: o.displayName || null,
                                       disabled: !!(parseInt(o.userAccountControl, 10) & 2) });
              });
              r2.on('error', (e) => done(e));
              r2.on('end', () => done(null, out));
            });
        });
      });
    });
  });
}

const pool = mysql.createPool({
  host:     process.env.DB_HOST || 'localhost',
  port:     parseInt(process.env.DB_PORT || '3306', 10),
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit:    5,
  queueLimit:         0,
});

const rbac = createRbac(pool);

// helpers --------------------------------------------------------------
const ROLE_KEY_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
function validateRoleKey(rk) {
  return typeof rk === 'string' && ROLE_KEY_RE.test(rk);
}

// Accept grants in array form [{page_key, access_level}, ...]
// or object form {page_key: access_level, ...}.
// Returns array form, or null if input shape is invalid.
// Levels accepted on the wire. 'none' is a real, storable value in both
// rbac_user_page_access and rbac_role_pages: it is the deny hatch that lets a
// person or a role be held BELOW the role's default_access. Without it a role
// whose default is 'admin' (tier2) could never have a single page carved out.
const ACCESS_LEVELS = ['none', 'read', 'admin'];

function normaliseGrants(grants) {
  if (grants === undefined || grants === null) return [];
  if (Array.isArray(grants)) return grants;
  if (typeof grants === 'object') {
    return Object.entries(grants).map(([page_key, access_level]) => ({ page_key, access_level }));
  }
  return null;
}

// every endpoint here populates req.user first
router.use(rbac.loadCurrentUser);

// ── GET /me — current user + permission map ───────────────────────────
router.get('/me', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({
      error: 'Authentication required',
      code:  req.tokenError || 'UNAUTHENTICATED',
    });
  }
  try {
    // RBAC v3: role defaults + exceptions + per-user overrides, merged in
    // one place (rbac-middleware.computeEffectivePages). Inactive users get
    // no pages.
    let pages = {};
    if (req.user.isSuperAdmin || req.user.isActive) {
      pages = await rbac.computeEffectivePages(
        req.user.email,
        req.user.roles || [],
        req.user.isSuperAdmin
      );
    }

    // Landing-page section visibility. Sections default to VISIBLE, so this
    // is a hide-list; it is chrome rather than a permission and never gates
    // an API, which is why a failure here degrades to "show everything".
    let hiddenSections = [];
    try {
      hiddenSections = await rbac.computeHiddenSections(req.user.email, req.user.roles || []);
    } catch (secErr) {
      console.warn('[rbac-routes] /me computeHiddenSections failed:', secErr.message);
    }

    res.json({
      email:        req.user.email,
      displayName:  req.user.displayName,
      isSuperAdmin: req.user.isSuperAdmin,
      isActive:     req.user.isActive,
      roles:        req.user.roles || [],
      pages,
      hiddenSections,
    });
  } catch (err) {
    console.error('[rbac-routes] GET /me failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

// -- POST /me/refresh -- self-service AD re-resolve ---------------------
// Stamps the CALLER'S OWN roles_invalidated_at, so their next request (the
// account component immediately re-fetches /me) resolves fresh from the
// directory. Strictly self-scoped. A missing rbac_users row is a harmless
// no-op: a user with no row is already resolved on every request.
router.post('/me/refresh', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({
      error: 'Authentication required',
      code:  req.tokenError || 'UNAUTHENTICATED',
    });
  }
  try {
    await pool.execute(
      'UPDATE rbac_users SET roles_invalidated_at = NOW() WHERE email = ?',
      [req.user.email]
    );
    await rbac.audit(req, 'self_refresh_requested', req.user.email, null, {});
    res.json({ ok: true });
  } catch (err) {
    console.error('[rbac-routes] POST /me/refresh failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});
// -- GET /me/activity -- the caller's own audit trail --------------------
router.get('/me/activity', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required', code: req.tokenError || 'UNAUTHENTICATED' });
  }
  try {
    const [rows] = await pool.query(
      `SELECT action, target_page_key, details, created_at
         FROM rbac_audit_log
        WHERE actor_email = ?
        ORDER BY created_at DESC
        LIMIT 25`,
      [req.user.email]
    );
    res.json({ activity: rows });
  } catch (err) {
    console.error('[rbac-routes] GET /me/activity failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

// -- GET/PUT /me/prefs -- self-scoped preferences ------------------------
const PREF_KEYS = { default_landing: 256, density: 32, theme: 32, reduce_motion: 8, color_mode: 8, pins: 2048, quick_actions: 1024 };  // key -> max length

router.get('/me/prefs', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required', code: req.tokenError || 'UNAUTHENTICATED' });
  }
  try {
    const [rows] = await pool.query(
      'SELECT pref_key, pref_value FROM rbac_user_prefs WHERE email = ?', [req.user.email]
    );
    const prefs = {};
    for (const r of rows) prefs[r.pref_key] = r.pref_value;
    res.json({ prefs });
  } catch (err) {
    console.error('[rbac-routes] GET /me/prefs failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

router.put('/me/prefs', express.json({ limit: '8kb' }), async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required', code: req.tokenError || 'UNAUTHENTICATED' });
  }
  const body = (req.body && req.body.prefs) || null;
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return res.status(400).json({ error: 'prefs object required', code: 'BAD_REQUEST' });
  }
  const entries = Object.entries(body);
  for (const [k, v] of entries) {
    if (!(k in PREF_KEYS)) {
      return res.status(400).json({ error: 'Unknown preference: ' + k, code: 'BAD_REQUEST' });
    }
    if (typeof v !== 'string' || v.length > PREF_KEYS[k]) {
      return res.status(400).json({ error: 'Invalid value for ' + k, code: 'BAD_REQUEST' });
    }
  }
  if (entries.length === 0) return res.json({ ok: true, saved: 0 });
  try {
    await pool.query(
      'INSERT INTO rbac_user_prefs (email, pref_key, pref_value) VALUES ? ' +
      'ON DUPLICATE KEY UPDATE pref_value = VALUES(pref_value)',
      [entries.map(([k, v]) => [req.user.email, k, v])]
    );
    res.json({ ok: true, saved: entries.length });
  } catch (err) {
    console.error('[rbac-routes] PUT /me/prefs failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});
// ── GET /me/scope — the caller's own DATA scope ───────────────────────
// Deliberately above router.use(requireSuperAdmin): every authenticated user
// needs this to render "you are seeing Department X" on a reporting page.
// Scope is not access - holding a scope grants no page.
router.get('/me/scope', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required', code: 'NO_SESSION' });
  }
  try {
    res.json({ scope: await resolveScope(pool, req.user.email) });
  } catch (err) {
    console.error('[rbac-routes] GET /me/scope failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

// ── GET /me/view-as — do I hold view-as, and at what level ────────────
router.get('/me/view-as', async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Authentication required', code: 'NO_SESSION' });
  try {
    res.json({ grant: await resolveViewAs(pool, req.user.email) });
  } catch (err) {
    console.error('[rbac-routes] GET /me/view-as failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

// ── POST /me/view-as/check — may I borrow this person's view? ─────────
// Answering this needs the caller's OWN authority only, so it stays above the
// super-admin gate: a department-level delegate must be able to test a target.
router.post('/me/view-as/check', express.json({ limit: '4kb' }), async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Authentication required', code: 'NO_SESSION' });
  const target = String((req.body && req.body.email) || '').trim().toLowerCase();
  if (!target) return res.status(400).json({ error: 'email required', code: 'BAD_INPUT' });
  try {
    const v = await canViewAs(pool, req.user.email, target);
    if (v.ok) {
      await rbac.audit(req, 'view_as_used', target, null, { via: v.level, scope: v.scope && v.scope.kind });
    }
    res.json({ ok: v.ok, reason: v.reason, scope: v.ok ? v.scope : null, via: v.level || null });
  } catch (err) {
    console.error('[rbac-routes] POST /me/view-as/check failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

// ── GET /me/view-as/candidates — grant-scoped directory search ────────
// Above the super-admin gate on purpose: a non-SA delegate must be able to find
// a target. The candidate set is the caller's OWN authority, never wider:
//   any        → the people directory (hr_roster), min 2-char query
//   reports    → the caller's direct reports (manager_email/leader_email = me)
//   department → the caller's department
// Bounded grants are re-run through canViewAs so the subset rule still applies
// (e.g. a department-mate who is your own leader is refused). 'any' skips that
// per-row check because canViewAs short-circuits to ok for every target.
router.get('/me/view-as/candidates', async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Authentication required', code: 'NO_SESSION' });
  const me = String(req.user.email || '').trim().toLowerCase();
  const q  = String(req.query.q || '').trim().toLowerCase();
  try {
    const grant = await resolveViewAs(pool, me);
    if (!grant) return res.json({ grant: null, candidates: [] });
    const like = '%' + q.replace(/[\\%_]/g, function (ch) { return '\\' + ch; }) + '%';
    let rows;
    if (grant.level === 'any') {
      if (q.length < 2) return res.json({ grant: grant, candidates: [] });
      [rows] = await pool.query(
        `SELECT LOWER(email) AS email, COALESCE(employee_name, common_name) AS display_name,
                title, department
           FROM hr_roster
          WHERE email IS NOT NULL AND email <> '' AND LOWER(email) <> ?
            AND (LOWER(email) LIKE ? OR LOWER(common_name) LIKE ? OR LOWER(employee_name) LIKE ?)
          ORDER BY display_name LIMIT 25`,
        [me, like, like, like]);
      return res.json({ grant: grant, candidates: rows });
    }
    if (grant.level === 'reports') {
      [rows] = await pool.query(
        `SELECT LOWER(email) AS email, COALESCE(employee_name, common_name) AS display_name,
                title, department
           FROM hr_roster
          WHERE email IS NOT NULL AND email <> ''
            AND (LOWER(manager_email) = ? OR LOWER(leader_email) = ?)
            ${q ? "AND (LOWER(email) LIKE ? OR LOWER(common_name) LIKE ? OR LOWER(employee_name) LIKE ?)" : ''}
          ORDER BY display_name LIMIT 50`,
        q ? [me, me, like, like, like] : [me, me]);
    } else { // department
      [rows] = await pool.query(
        `SELECT LOWER(t.email) AS email, COALESCE(t.employee_name, t.common_name) AS display_name,
                t.title, t.department
           FROM hr_roster m JOIN hr_roster t ON t.dept_code = m.dept_code
          WHERE LOWER(m.email) = ? AND t.email IS NOT NULL AND t.email <> '' AND LOWER(t.email) <> ?
            ${q ? "AND (LOWER(t.email) LIKE ? OR LOWER(t.common_name) LIKE ? OR LOWER(t.employee_name) LIKE ?)" : ''}
          ORDER BY display_name LIMIT 50`,
        q ? [me, me, like, like, like] : [me, me]);
    }
    const out = [];
    for (const r of rows) {
      const v = await canViewAs(pool, me, r.email);
      if (v.ok) out.push(r);
    }
    res.json({ grant: grant, candidates: out });
  } catch (err) {
    console.error('[rbac-routes] GET /me/view-as/candidates failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

// ── GET /pages — page registry, anyone authenticated ──────────────────
router.get('/pages', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({
      error: 'Authentication required',
      code:  req.tokenError || 'UNAUTHENTICATED',
    });
  }
  try {
    const [rows] = await pool.query(
      `SELECT page_key, display_name, url_path, category, has_admin_actions,
              access_policy, status, nav_visible, display_order
         FROM rbac_pages
         ORDER BY display_order, page_key`
    );
    // hard_excluded means computeEffectiveLevel returns 'none' for this page no
    // matter what any role grant or per-user override says (super admins bypass
    // it earlier and still get in). An admin screen that rendered the grant
    // tables for these would be showing access that does not exist.
    const hard = rbac.HARD_EXCLUDED_PAGES || new Set();
    res.json({
      pages: rows.map(p => Object.assign({}, p, { hard_excluded: hard.has(p.page_key) })),
    });
  } catch (err) {
    console.error('[rbac-routes] GET /pages failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

// == Session mint / sliding extend =====================================
// POST /api/rbac/session  — MUST stay ABOVE requireSuperAdmin; any
// authenticated, active, non-breakglass, non-local-test user may extend
// their session. (Route does its own auth checks internally.)
const sessionAuth = require('./session-auth');
router.post('/session', async (req, res) => {
  if (!req.user || !req.user.email) {
    return res.status(401).json({ error: 'Not authenticated', code: req.tokenError || 'NO_TOKEN' });
  }
  // CORPIT-RENEW-REFUSAL-CODES (2026-09-04): every refusal on this route carries a
  // machine-readable `code`. The session watcher latches a non-cap 403 as a durable
  // server refusal and stops offering "Stay signed in" -- but it can only do that if
  // it can TELL the refusals apart, and /api/gate/session-info cannot help: that
  // route is pure-crypto by design (CORRECTIONS.md C6) and knows nothing about
  // rbac_users.is_active, so it keeps answering renewable:true for a deactivated
  // account. Without a code the bar re-renders the same dead button on every click.
  if (req.user.isBreakglass) {
    return res.status(403).json({ error: 'Break-glass sessions cannot be extended',
      code: 'BREAKGLASS_SESSION' });
  }
  // FP-04 (2026-09-02): a local DEV/test account (typ 'localdev', see
  // localdev-auth.js) must never be upgraded to a typ 'session' token. That
  // token would outlive the LOCALDEV_ENABLED kill switch, skip the
  // isSuperAdmin/is_active clamps in rbac-middleware.js, and turn a fixed 8h
  // credential into a 10h sliding one. session-auth.js refuses such subjects
  // on verify as well.
  if (req.user.isLocalTest) {
    return res.status(403).json({ error: 'Local test sessions cannot be extended', code: 'LOCAL_TEST_ACCOUNT' });
  }
  if (!req.user.isActive) {
    return res.status(403).json({ error: 'Account is inactive', code: 'ACCOUNT_INACTIVE' });
  }
  if (!sessionAuth.isConfigured()) {
    return res.status(503).json({ error: 'RBAC_SESSION_SECRET not configured' });
  }
  // CORPIT-SESSION-CAP-RENEW (2026-09-04): THE renewal endpoint. This route --
  // not /api/gate/refresh -- mints, because /api/gate/refresh is in server.js's
  // API_PUBLIC and so skips BOTH loadCurrentUser and the CORPIT-CSRF origin
  // check. `.local` is not a public suffix, so every *.nrpi.local origin is
  // same-SITE with us and SameSite=Lax blocks nothing: a public, CSRF-exempt
  // mint endpoint would let any page (or any XSS) on any sibling vhost silently
  // extend a victim's session. Here, a cookie-authenticated POST must carry a
  // positively same-origin verdict, and the guards above (isBreakglass,
  // isLocalTest, isActive) have already run.
  //
  // This block also absorbs the two live bugs the 2026-09-04 cookie hotfix
  // fixed. Both fired on every "Stay signed in" click and must not come back:
  //
  // 1. setSessionCookie was called WITHOUT `req`, so cookieDomainFor() took its
  //    `if (!req) return DOMAIN` branch (session-cookie.js:34) and set
  //    Domain=.corpit.nrpi.local unconditionally -- while :44 first CLEARS the
  //    working host-only cookie. On any host not under that domain
  //    (reporting.nrpi.local, subadmin, accessportal, directory) the browser
  //    DISCARDS the replacement, so extending the session DELETED it. The page
  //    kept working on the sessionStorage bearer copy until the next
  //    navigation, at which point the nginx gate 401'd the user to sign-in --
  //    i.e. the button whose whole job is to keep you signed in signed you out.
  //
  // 2. mintSessionToken was called with no `groups`, so every extend minted a
  //    token with grp omitted. site-access.js:97 reads that as null and :127
  //    returns {allow:false, reason:'session-predates-policy'} on every
  //    group-mode vhost. The PRIOR claim is carried forward: it is already
  //    signed, verifySessionToken() hands it back, and round-tripping it needs
  //    no directory call, so it cannot strip an entitlement during an LDAP blip.
  //    null (unknown) round-trips as null, [] (a real empty entitlement) as [];
  //    site-access.js distinguishes the two, so the copy must not collapse them.
  //
  // The prior claims now come from req.sessionClaims (set once in
  // rbac-middleware.js) rather than from a second cookie scan here. That is
  // strictly better than the hotfix's own loop, in three ways:
  //   * the middleware's pickCookieCredential already tries EVERY it_session
  //     value, so the Domain-rollout case the loop existed for is still covered;
  //   * it also covers a request authenticated by a bearer session token with no
  //     usable cookie, which the loop silently minted groups:null for;
  //   * it can only ever be the credential that produced req.user, so it cannot
  //     splice a DIFFERENT identity's groups into this token -- which the loop
  //     could, when a raw Azure id_token bearer arrived alongside somebody
  //     else's session cookie.
  // prior is null only on that raw-id_token path (rbac-middleware.js:139-145
  // allows it on THIS route alone); it then mints ait=now with groups=null,
  // exactly as it does today. login.html no longer stores raw id_tokens, so it
  // is a legacy path.
  //
  // BE EXPLICIT ABOUT WHAT THAT PATH COSTS, so it is a decision and not an
  // omission (2026-09-04 repair pass). A caller holding an unexpired Azure
  // id_token audienced to CLIENT_ID gets: (a) ait = now, i.e. a fresh 12h window,
  // which is a second and quieter way to restart the cap on top of the one in
  // oidc-auth.js (see CORPIT-CAP-ANCHOR-HONESTY there - the cap binds the renewal
  // chain, not the identity); and (b) grp omitted, which site-access.js:127 reads
  // as 'session-predates-policy' and which will lock that user out of every
  // group-mode vhost until their next real sign-in. NOT changed here, and both
  // rejected fixes are recorded so the next reader does not re-derive them:
  // resolving groups on this path would put a live directory call on the renewal
  // path, which must survive a directory outage (CORRECTIONS.md C6, and the owner
  // decision "No directory call on renewal"); and retiring isSessionMintRequest()
  // is a rbac-middleware.js change that belongs to whoever owns that file, in its
  // own deploy, with its own rollback. Retire it there, not by widening this one.
  // CORPIT-RENEW-CAP-GUARD (2026-09-04): resolve the cap constant ONCE, through the
  // same typeof/isFinite/>0 guard /api/gate/session-info uses. This file and that one
  // are the two endpoints the SAME watcher reads, and DEPLOY-FACTS records that
  // corpitpen has no apply/rollback harness -- so a hand rollback of session-auth.js
  // that leaves this file live is a real state. Reading the constant unguarded there
  // produces `undefined + number` = NaN, which serialises to null and would have the
  // two endpoints silently disagree about the same session. An UNMEASURED cap is not
  // a REACHED cap: emit null deliberately, and say so, rather than by accident.
  const CAP_MS = (typeof sessionAuth.SESSION_ABS_CAP_MS === 'number' &&
                  isFinite(sessionAuth.SESSION_ABS_CAP_MS) &&
                  sessionAuth.SESSION_ABS_CAP_MS > 0)
    ? sessionAuth.SESSION_ABS_CAP_MS : null;
  const prior = (req.sessionClaims && req.sessionClaims.ok &&
                 // Belt and braces on the invariant above: same credential, so
                 // same subject. If that ever stops holding, degrade to "no
                 // prior" rather than carrying a stranger's entitlements.
                 String(req.sessionClaims.email || '').toLowerCase() ===
                 String(req.user.email || '').toLowerCase())
    ? req.sessionClaims : null;
  const token = sessionAuth.mintSessionToken(
    req.user.email,
    req.user.displayName || req.user.email,
    prior ? prior.groups : null,
    // absAit, not ait: session-auth.js materialises the legacy-token fallback
    // once, so this path can never disagree with /api/gate/session-info about
    // where the 12h window started.
    // MP-SIGNIN-SCOPE: a host-scoped session renews as host-scoped. Dropping the scope
    // here would turn My Profile's open sign-in into a platform-wide token.
    prior ? { ait: prior.absAit, scope: prior.scope || undefined } : undefined);
  if (!token) {
    // The absolute cap is reached: mintSessionToken refuses rather than issuing
    // a token that verify would immediately reject. 403, NOT 401 -- a 401 on a
    // non-/api/gate/ path makes rbac-client.js's fetch intercept fire
    // goLoginExpired() and redirect on the spot, and the session watcher must be
    // the one that decides how the cap is presented (it offers "Sign in again"
    // -> /api/gate/federated-logout, which ends the Entra session too so the
    // next sign-in is a real credential prompt).
    // capMs travels WITH the refusal so the sign-in page can render the real number
    // instead of a hardcoded '12-hour' that goes stale the day the cap is retuned
    // (the watcher already derives its copy from the server's capMs). null when the
    // constant could not be resolved -- the caller then says it number-free rather
    // than inventing one.
    return res.status(403).json({ ok: false, code: 'SESSION_ABSOLUTE_CAP',
      capMs: CAP_MS,
      error: 'Session has reached its absolute limit; sign in again' });
  }
  const _v = sessionAuth.verifySessionToken(token, { host: req.headers.host });   // MP-SIGNIN-SCOPE
  if (!_v || !_v.ok) {
    // Unreachable in practice: we just minted and signed this. The one way in is
    // a sign-out landing in the same millisecond (revokeUser stamps an epoch and
    // isEpochRevoked is `iat < t`). Fail loudly rather than sending a NaN maxAge
    // and a body full of undefined.
    return res.status(503).json({ ok: false, code: 'SESSION_MINT_UNVERIFIABLE',
      error: 'Session could not be renewed; sign in again' });
  }
  // ITAM-01: also place the signed token in an HttpOnly cookie so nginx's
  // auth_request page gate can verify it (JS keeps using the JSON copy).
  // `req` is MANDATORY -- see (1) above. Do not drop it again.
  // maxAge comes from the token's REAL exp, which the cap may have CLAMPED to
  // less than the full 10h TTL; the old hardcoded 10h would have outlived the
  // token near the cap and turned a clean expiry into a 401.
  require('./session-cookie').setSessionCookie(res, token, _v.exp - Date.now(), req);
  // A minted credential must never sit in a shared cache.
  res.set('Cache-Control', 'no-store, private');
  // The browser uses the refreshed HttpOnly cookie; do not return its portable
  // bearer value to page JavaScript.
  res.json({ ok: true, exp: _v.exp,
             email: _v.email, name: _v.name,
             // Same guard as above: null, explicitly, when the cap could not be
             // measured -- never a NaN that JSON quietly turns into the same null.
             absExp: (CAP_MS === null) ? null : (_v.absAit + CAP_MS),
             capMs: CAP_MS });
});

// ── everything below requires super-admin ─────────────────────────────
router.use(rbac.requireSuperAdmin);

// ── GET /users — list users (now includes role_key) ───────────────────
router.get('/users', async (req, res) => {
  try {
    const includeInactive = req.query.include_inactive === '1';
    const sql = `
      SELECT u.email, u.display_name, u.role_key, u.is_active, u.notes,
             u.created_at, u.created_by, u.updated_at, u.updated_by,
             COALESCE(g.grant_count, 0) AS grant_count,
             COALESCE(r.role_list, '') AS role_list
        FROM rbac_users u
        LEFT JOIN (
          SELECT email, COUNT(*) AS grant_count
            FROM rbac_user_page_access GROUP BY email
        ) g ON g.email = u.email
        LEFT JOIN (
          SELECT email, GROUP_CONCAT(role_key ORDER BY role_key SEPARATOR ',') AS role_list
            FROM rbac_user_roles GROUP BY email
        ) r ON r.email = u.email
        ${includeInactive ? '' : 'WHERE u.is_active = 1'}
        ORDER BY u.email`;
    const [rows] = await pool.query(sql);
    // roles[] comes from rbac_user_roles, which is what actually resolves access.
    // u.role_key is only a display hint and is known to disagree with it (it
    // undercounted tier2 by 3), so never present role_key as the membership answer.
    res.json({
      users: rows.map(u => Object.assign({}, u, {
        roles: u.role_list ? u.role_list.split(',') : [],
      })),
    });
  } catch (err) {
    console.error('[rbac-routes] GET /users failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

// ── POST /users — add user ────────────────────────────────────────────
router.post('/users', async (req, res) => {
  const email       = ((req.body && req.body.email) || '').trim().toLowerCase();
  const displayName = ((req.body && req.body.display_name) || '').trim() || null;
  const notes       = ((req.body && req.body.notes) || '').trim() || null;

  if (!email) {
    return res.status(400).json({ error: 'email is required', code: 'BAD_INPUT' });
  }
  if (!/^[a-z0-9._%+-]+@auction\.com$/.test(email)) {
    return res.status(400).json({
      error: 'email must be a valid @auction.com address',
      code:  'BAD_DOMAIN',
    });
  }

  try {
    await pool.execute(
      `INSERT INTO rbac_users (email, display_name, is_active, notes, created_by, updated_by)
       VALUES (?, ?, 1, ?, ?, ?)`,
      [email, displayName, notes, req.user.email, req.user.email]
    );
    await rbac.audit(req, 'user_added', email, null, { display_name: displayName, notes });
    res.status(201).json({ email, display_name: displayName, is_active: 1, notes });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'user already exists', code: 'DUPLICATE' });
    }
    console.error('[rbac-routes] POST /users failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

// ── PATCH /users/:email — update user ─────────────────────────────────
router.patch('/users/:email', async (req, res) => {
  const email   = (req.params.email || '').trim().toLowerCase();
  const updates = {};
  const body    = req.body || {};

  if (Object.prototype.hasOwnProperty.call(body, 'display_name')) {
    updates.display_name = (body.display_name || '').trim() || null;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'notes')) {
    updates.notes = (body.notes || '').trim() || null;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'is_active')) {
    updates.is_active = body.is_active ? 1 : 0;
  }

  if (Object.keys(updates).length === 0) {
    return res.status(400).json({ error: 'no updatable fields provided', code: 'BAD_INPUT' });
  }

  try {
    const [existing] = await pool.query(
      'SELECT email, display_name, notes, is_active FROM rbac_users WHERE email = ? LIMIT 1',
      [email]
    );
    if (existing.length === 0) {
      return res.status(404).json({ error: 'user not found', code: 'NOT_FOUND' });
    }

    const setClauses = Object.keys(updates).map(k => `${k} = ?`);
    const values     = Object.values(updates);
    setClauses.push('updated_by = ?');
    values.push(req.user.email, email);

    await pool.execute(
      `UPDATE rbac_users SET ${setClauses.join(', ')} WHERE email = ?`,
      values
    );

    let action = 'user_updated';
    if ('is_active' in updates) {
      action = updates.is_active ? 'user_reactivated' : 'user_soft_deleted';
    }
    await rbac.audit(req, action, email, null, { before: existing[0], after: updates });

    res.json({ email, ...updates });
  } catch (err) {
    console.error('[rbac-routes] PATCH /users/:email failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

// ── DELETE /users/:email — soft-delete ────────────────────────────────
router.delete('/users/:email', async (req, res) => {
  const email = (req.params.email || '').trim().toLowerCase();
  try {
    const [existing] = await pool.query(
      'SELECT is_active FROM rbac_users WHERE email = ? LIMIT 1',
      [email]
    );
    if (existing.length === 0) {
      return res.status(404).json({ error: 'user not found', code: 'NOT_FOUND' });
    }

    await pool.execute(
      `UPDATE rbac_users SET is_active = 0, updated_by = ? WHERE email = ?`,
      [req.user.email, email]
    );

    await rbac.audit(req, 'user_soft_deleted', email, null, {
      was_active: !!existing[0].is_active,
    });

    res.json({ email, is_active: 0 });
  } catch (err) {
    console.error('[rbac-routes] DELETE /users/:email failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

// ── GET /users/:email/access — grants for one user (now includes role_key)
// ── role_key compatibility shim ────────────────────────────────────────
// rbac_users.role_key is a leftover from the single-role model. The guard
// (computeEffectivePages) never reads it, and it had drifted out of sync for
// 4 of 11 users — showing sescobedo as tier2 when the guard treats them as
// infosec. Roles now come only from rbac_user_roles, written from AD at login.
// This derives the single "primary" role for the old console's display, and
// the full list for anything that wants it.
async function rolesOf(runner, email) {
  const [rows] = await runner.query(
    'SELECT role_key FROM rbac_user_roles WHERE email = ? ORDER BY role_key',
    [email]
  );
  return rows.map(r => r.role_key);
}
// Display-only: the most privileged role a user holds, so the old console's
// single-select Role card has something truthful to show.
async function primaryRoleOf(runner, email) {
  const roles = await rolesOf(runner, email);
  if (roles.length === 0) return null;
  if (roles.includes('superadmin')) return 'superadmin';
  const [rank] = await runner.query(
    "SELECT role_key FROM rbac_roles WHERE role_key IN (?) ORDER BY FIELD(default_access,'admin','read','none'), role_key LIMIT 1",
    [roles]
  );
  return rank.length ? rank[0].role_key : roles[0];
}

router.get('/users/:email/access', async (req, res) => {
  const email = (req.params.email || '').trim().toLowerCase();
  try {
    const [userRows] = await pool.query(
      'SELECT email FROM rbac_users WHERE email = ? LIMIT 1',
      [email]
    );
    if (userRows.length === 0) {
      return res.status(404).json({ error: 'user not found', code: 'NOT_FOUND' });
    }
    const liveRoles      = await rolesOf(pool, email);
    const livePrimaryRole = await primaryRoleOf(pool, email);
    const [rows] = await pool.query(
      `SELECT page_key, access_level, granted_at, granted_by
         FROM rbac_user_page_access
         WHERE email = ? ORDER BY page_key`,
      [email]
    );
    res.json({ email, role_key: livePrimaryRole, roles: liveRoles, access: rows });
  } catch (err) {
    console.error('[rbac-routes] GET /users/:email/access failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

// ── PUT /users/:email/access — replace all grants atomically ──────────
// Body: {
//   access:   { "page-key-1": "read", "page-key-2": "admin", ... },
//   role_key: "tier1" | null   (optional; tracks tier assignment for display)
// }
router.put('/users/:email/access', async (req, res) => {
  const email  = (req.params.email || '').trim().toLowerCase();
  const access = (req.body && req.body.access) || {};
  const roleKeyProvided = req.body && Object.prototype.hasOwnProperty.call(req.body, 'role_key');
  const roleKey = roleKeyProvided ? (req.body.role_key || null) : undefined;

  if (typeof access !== 'object' || access === null || Array.isArray(access)) {
    return res.status(400).json({ error: 'access must be an object', code: 'BAD_INPUT' });
  }
  for (const [pk, lvl] of Object.entries(access)) {
    if (!ACCESS_LEVELS.includes(lvl)) {
      return res.status(400).json({
        error: `invalid level "${lvl}" for "${pk}" (must be none, read or admin)`,
        code:  'BAD_LEVEL',
      });
    }
  }
  if (roleKey !== undefined && roleKey !== null && !validateRoleKey(roleKey)) {
    return res.status(400).json({ error: 'invalid role_key format', code: 'BAD_ROLE_KEY' });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [userRows] = await conn.query(
      'SELECT email FROM rbac_users WHERE email = ? LIMIT 1',
      [email]
    );
    if (userRows.length === 0) {
      await conn.rollback();
      return res.status(404).json({ error: 'user not found', code: 'NOT_FOUND' });
    }
    const beforeRoleKey = await primaryRoleOf(conn, email);

    // verify role exists if a non-null role_key was provided
    if (roleKey !== undefined && roleKey !== null) {
      const [roleRows] = await conn.query(
        'SELECT role_key FROM rbac_roles WHERE role_key = ? LIMIT 1',
        [roleKey]
      );
      if (roleRows.length === 0) {
        await conn.rollback();
        return res.status(400).json({ error: `unknown role_key "${roleKey}"`, code: 'UNKNOWN_ROLE' });
      }
    }

    const [beforeRows] = await conn.query(
      'SELECT page_key, access_level FROM rbac_user_page_access WHERE email = ?',
      [email]
    );
    const beforeMap = Object.fromEntries(beforeRows.map(r => [r.page_key, r.access_level]));
    if (!portalOwner.preserve(res, access, beforeMap)) { await conn.rollback(); return; }

    // validate every page_key in the new access map exists
    const keys = Object.keys(access);
    if (keys.length > 0) {
      const placeholders = keys.map(() => '?').join(',');
      const [pageRows] = await conn.query(
        `SELECT page_key FROM rbac_pages WHERE page_key IN (${placeholders})`,
        keys
      );
      const valid = new Set(pageRows.map(r => r.page_key));
      const invalid = keys.filter(k => !valid.has(k));
      if (invalid.length > 0) {
        await conn.rollback();
        return res.status(400).json({
          error: `unknown page_key(s): ${invalid.join(', ')}`,
          code:  'UNKNOWN_PAGE',
        });
      }
    }

    await conn.execute('DELETE FROM rbac_user_page_access WHERE email = ? AND page_key NOT IN (\'accessportal\',\'approver-portal\')', [email]);

    if (Object.keys(access).some(pk => !portalOwner.owns(pk))) {
      const rows = Object.entries(access).filter(([pk]) => !portalOwner.owns(pk)).map(([pk, lvl]) => [email, pk, lvl, req.user.email]);
      const placeholders = rows.map(() => '(?, ?, ?, ?)').join(', ');
      const flat = [].concat(...rows);
      await conn.execute(
        `INSERT INTO rbac_user_page_access (email, page_key, access_level, granted_by)
         VALUES ${placeholders}`,
        flat
      );
    }

    // Roles are resolved from AD group membership, not set here. The old
    // console posted role_key to "apply a role"; that only ever wrote a display
    // column the guard ignored. Accept the field so old clients do not break,
    // but never store it — changing someone's role means changing their AD group.

    await conn.commit();

    // audit role change first (if any)
    if (roleKeyProvided && beforeRoleKey !== roleKey) {
      await rbac.audit(req, 'role_change_ignored', email, roleKey || beforeRoleKey || null, {
        requested: roleKey,
        actual:    beforeRoleKey,
        reason:    'roles come from AD group membership; role_key is not stored',
      });
    }

    // audit grant diffs (one entry per changed page_key)
    const allKeys = new Set([...Object.keys(beforeMap), ...keys]);
    for (const pk of allKeys) {
      const before = beforeMap[pk];
      const after  = access[pk];
      if (before === after) continue;
      let action = 'access_changed';
      if (!before && after)  action = 'access_granted';
      if (before  && !after) action = 'access_revoked';
      await rbac.audit(req, action, email, pk, { before: before || null, after: after || null });
    }

    res.json({ email, role_key: beforeRoleKey, roles: await rolesOf(pool, email), access });
  } catch (err) {
    try { await conn.rollback(); } catch (_) {}
    console.error('[rbac-routes] PUT /users/:email/access failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  } finally {
    conn.release();
  }
});

// =====================================================================
// Phase 1.5: Editable role / tier definitions
// =====================================================================

// ── GET /roles — list all roles with grants and usage counts ──────────
router.get('/roles', async (req, res) => {
  try {
    const [roles] = await pool.query(
      `SELECT role_key, display_name, description, is_system,
              default_access, ad_group_dn, created_at, updated_at
         FROM rbac_roles
         ORDER BY is_system DESC, role_key`
    );
    const [pages] = await pool.query(
      `SELECT role_key, page_key, access_level
         FROM rbac_role_pages
         ORDER BY role_key, page_key`
    );
    // rbac_user_roles is the membership authority, but it also holds @local
    // localdev test accounts and rows whose rbac_users record was never created.
    // Reporting the raw row count as "people" overstates who a role really
    // reaches, so split it: real active humans, and everything else, named.
    const [usage] = await pool.query(
      `SELECT ur.role_key,
              COUNT(*) AS member_rows,
              SUM(CASE WHEN u.email IS NOT NULL AND u.is_active = 1
                        AND ur.email NOT LIKE '%@local' THEN 1 ELSE 0 END) AS user_count,
              SUM(CASE WHEN ur.email LIKE '%@local' THEN 1 ELSE 0 END)      AS test_accounts,
              SUM(CASE WHEN u.email IS NULL THEN 1 ELSE 0 END)              AS orphan_rows,
              SUM(CASE WHEN u.email IS NOT NULL AND u.is_active = 0
                        AND ur.email NOT LIKE '%@local' THEN 1 ELSE 0 END)  AS inactive_users
         FROM rbac_user_roles ur
         LEFT JOIN rbac_users u ON u.email = ur.email
         GROUP BY ur.role_key`
    );

    const grantMap = {};
    for (const r of roles) grantMap[r.role_key] = [];
    for (const p of pages) {
      if (grantMap[p.role_key]) {
        grantMap[p.role_key].push({ page_key: p.page_key, access_level: p.access_level });
      }
    }
    const usageMap = Object.fromEntries(usage.map(u => [u.role_key, u]));

    const out = roles.map(r => ({
      role_key:     r.role_key,
      display_name: r.display_name,
      description:  r.description,
      is_system:      !!r.is_system,
      default_access: r.default_access,
      ad_group_dn:    r.ad_group_dn,
      created_at:     r.created_at,
      updated_at:     r.updated_at,
      // user_count is PEOPLE. The rest of the rows are broken out beside it so a
      // screen can say "7 people (+3 not real accounts)" rather than just "10".
      user_count:     Number((usageMap[r.role_key] || {}).user_count || 0),
      member_rows:    Number((usageMap[r.role_key] || {}).member_rows || 0),
      test_accounts:  Number((usageMap[r.role_key] || {}).test_accounts || 0),
      orphan_rows:    Number((usageMap[r.role_key] || {}).orphan_rows || 0),
      inactive_users: Number((usageMap[r.role_key] || {}).inactive_users || 0),
      // Super admins are resolved before the grant tables are read, so nothing
      // in this role's rows describes what its members can actually reach.
      bypasses_matrix: r.role_key === 'superadmin',
      grants:         grantMap[r.role_key] || [],
    }));
    res.json({ roles: out });
  } catch (err) {
    console.error('[rbac-routes] GET /roles failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

// ── POST /roles — create new role ─────────────────────────────────────
// Body: { role_key, display_name, description?, grants?: array | object }
router.post('/roles', async (req, res) => {
  const body        = req.body || {};
  const roleKey     = (body.role_key || '').trim().toLowerCase();
  const displayName = (body.display_name || '').trim();
  const description = (body.description || '').trim() || null;
  const grantsRaw   = normaliseGrants(body.grants);
  if (grantsRaw && grantsRaw.some(g => portalOwner.owns(g.page_key))) return portalOwner.reject(res);
  const defaultAccess = body.default_access === undefined
    ? 'none'
    : String(body.default_access).trim().toLowerCase();

  if (!ACCESS_LEVELS.includes(defaultAccess)) {
    return res.status(400).json({
      error: 'default_access must be none, read or admin',
      code:  'BAD_DEFAULT_ACCESS',
    });
  }
  if (!roleKey) {
    return res.status(400).json({ error: 'role_key is required', code: 'BAD_INPUT' });
  }
  if (!validateRoleKey(roleKey)) {
    return res.status(400).json({
      error: 'role_key must be 1-64 chars, lowercase alphanumeric with optional dashes/underscores, starting with letter or digit',
      code:  'BAD_ROLE_KEY',
    });
  }
  if (!displayName) {
    return res.status(400).json({ error: 'display_name is required', code: 'BAD_INPUT' });
  }
  if (displayName.length > 128) {
    return res.status(400).json({ error: 'display_name too long (max 128)', code: 'BAD_INPUT' });
  }
  if (grantsRaw === null) {
    return res.status(400).json({ error: 'grants must be array or object', code: 'BAD_INPUT' });
  }
  for (const g of grantsRaw) {
    if (!g || typeof g.page_key !== 'string' || !ACCESS_LEVELS.includes(g.access_level)) {
      return res.status(400).json({
        error: 'each grant must have {page_key: string, access_level: none|read|admin}',
        code:  'BAD_GRANT',
      });
    }
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    if (grantsRaw.length > 0) {
      const keys = grantsRaw.map(g => g.page_key);
      const placeholders = keys.map(() => '?').join(',');
      const [pageRows] = await conn.query(
        `SELECT page_key FROM rbac_pages WHERE page_key IN (${placeholders})`,
        keys
      );
      const valid = new Set(pageRows.map(r => r.page_key));
      const invalid = keys.filter(k => !valid.has(k));
      if (invalid.length > 0) {
        await conn.rollback();
        return res.status(400).json({
          error: `unknown page_key(s): ${invalid.join(', ')}`,
          code:  'UNKNOWN_PAGE',
        });
      }
    }

    await conn.execute(
      `INSERT INTO rbac_roles (role_key, display_name, description, is_system, default_access)
       VALUES (?, ?, ?, 0, ?)`,
      [roleKey, displayName, description, defaultAccess]
    );

    if (grantsRaw.length > 0) {
      const rows = grantsRaw.map(g => [roleKey, g.page_key, g.access_level]);
      const placeholders = rows.map(() => '(?, ?, ?)').join(', ');
      const flat = [].concat(...rows);
      await conn.execute(
        `INSERT INTO rbac_role_pages (role_key, page_key, access_level)
         VALUES ${placeholders}`,
        flat
      );
    }

    await conn.commit();

    await rbac.audit(req, 'role_created', null, roleKey, {
      display_name:   displayName,
      description,
      default_access: defaultAccess,
      grant_count:    grantsRaw.length,
      grants:         grantsRaw,
    });

    res.status(201).json({
      role_key:       roleKey,
      display_name:   displayName,
      description,
      is_system:      false,
      default_access: defaultAccess,
      grants:         grantsRaw,
      user_count:     0,
    });
  } catch (err) {
    try { await conn.rollback(); } catch (_) {}
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'role already exists', code: 'DUPLICATE' });
    }
    console.error('[rbac-routes] POST /roles failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  } finally {
    conn.release();
  }
});

// ── PUT /roles/:role_key — update name/description/grants ─────────────
// Body: { display_name?, description?, grants?: array | object }
// Note: editing a role does NOT retroactively change existing users assigned to it.
router.put('/roles/:role_key', async (req, res) => {
  const roleKey   = (req.params.role_key || '').trim().toLowerCase();
  const body      = req.body || {};
  const hasName   = Object.prototype.hasOwnProperty.call(body, 'display_name');
  const hasDesc   = Object.prototype.hasOwnProperty.call(body, 'description');
  const hasGrants = Object.prototype.hasOwnProperty.call(body, 'grants');
  const hasDefault = Object.prototype.hasOwnProperty.call(body, 'default_access');

  const displayName = hasName ? (body.display_name || '').trim() : undefined;
  const description = hasDesc ? ((body.description || '').trim() || null) : undefined;
  const grantsRaw   = hasGrants ? normaliseGrants(body.grants) : undefined;
  const defaultAccess = hasDefault
    ? String(body.default_access == null ? '' : body.default_access).trim().toLowerCase()
    : undefined;

  if (!hasName && !hasDesc && !hasGrants && !hasDefault) {
    return res.status(400).json({ error: 'no updatable fields provided', code: 'BAD_INPUT' });
  }
  if (hasDefault && !ACCESS_LEVELS.includes(defaultAccess)) {
    return res.status(400).json({
      error: 'default_access must be none, read or admin',
      code:  'BAD_DEFAULT_ACCESS',
    });
  }
  if (hasName && !displayName) {
    return res.status(400).json({ error: 'display_name cannot be empty', code: 'BAD_INPUT' });
  }
  if (hasName && displayName.length > 128) {
    return res.status(400).json({ error: 'display_name too long (max 128)', code: 'BAD_INPUT' });
  }
  if (hasGrants) {
    if (grantsRaw === null) {
      return res.status(400).json({ error: 'grants must be array or object', code: 'BAD_INPUT' });
    }
    for (const g of grantsRaw) {
      if (!g || typeof g.page_key !== 'string' || !ACCESS_LEVELS.includes(g.access_level)) {
        return res.status(400).json({
          error: 'each grant must have {page_key: string, access_level: none|read|admin}',
          code:  'BAD_GRANT',
        });
      }
    }
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [existing] = await conn.query(
      `SELECT role_key, display_name, description, is_system, default_access
         FROM rbac_roles WHERE role_key = ? LIMIT 1`,
      [roleKey]
    );
    if (existing.length === 0) {
      await conn.rollback();
      return res.status(404).json({ error: 'role not found', code: 'NOT_FOUND' });
    }
    const before = existing[0];

    let beforeGrants = null;
    if (hasGrants) {
      const [beforeRows] = await conn.query(
        'SELECT page_key, access_level FROM rbac_role_pages WHERE role_key = ? ORDER BY page_key',
        [roleKey]
      );
      beforeGrants = beforeRows.map(r => ({ page_key: r.page_key, access_level: r.access_level }));
      if (!portalOwner.preserveRows(res, grantsRaw, beforeGrants)) { await conn.rollback(); return; }

      if (grantsRaw.length > 0) {
        const keys = grantsRaw.map(g => g.page_key);
        const placeholders = keys.map(() => '?').join(',');
        const [pageRows] = await conn.query(
          `SELECT page_key FROM rbac_pages WHERE page_key IN (${placeholders})`,
          keys
        );
        const valid = new Set(pageRows.map(r => r.page_key));
        const invalid = keys.filter(k => !valid.has(k));
        if (invalid.length > 0) {
          await conn.rollback();
          return res.status(400).json({
            error: `unknown page_key(s): ${invalid.join(', ')}`,
            code:  'UNKNOWN_PAGE',
          });
        }
      }
    }

    if (hasName || hasDesc || hasDefault) {
      const sets = [];
      const vals = [];
      if (hasName) { sets.push('display_name = ?'); vals.push(displayName); }
      if (hasDesc) { sets.push('description = ?');  vals.push(description); }
      if (hasDefault) { sets.push('default_access = ?'); vals.push(defaultAccess); }
      vals.push(roleKey);
      await conn.execute(
        `UPDATE rbac_roles SET ${sets.join(', ')} WHERE role_key = ?`,
        vals
      );
    }

    if (hasGrants) {
      await conn.execute('DELETE FROM rbac_role_pages WHERE role_key = ? AND page_key NOT IN (\'accessportal\',\'approver-portal\')', [roleKey]);
      if (grantsRaw.some(g => !portalOwner.owns(g.page_key))) {
        const rows = grantsRaw.filter(g => !portalOwner.owns(g.page_key)).map(g => [roleKey, g.page_key, g.access_level]);
        const placeholders = rows.map(() => '(?, ?, ?)').join(', ');
        const flat = [].concat(...rows);
        await conn.execute(
          `INSERT INTO rbac_role_pages (role_key, page_key, access_level)
           VALUES ${placeholders}`,
          flat
        );
      }
    }

    await conn.commit();

    const auditDetails = {};
    if (hasName)   auditDetails.display_name = { before: before.display_name, after: displayName };
    if (hasDesc)   auditDetails.description  = { before: before.description,  after: description };
    if (hasGrants) auditDetails.grants       = { before: beforeGrants,        after: grantsRaw };
    if (hasDefault) auditDetails.default_access = { before: before.default_access, after: defaultAccess };
    await rbac.audit(req, 'role_updated', null, roleKey, auditDetails);

    const [refreshedRole] = await pool.query(
      `SELECT role_key, display_name, description, is_system, default_access, created_at, updated_at
         FROM rbac_roles WHERE role_key = ?`,
      [roleKey]
    );
    const [refreshedGrants] = await pool.query(
      'SELECT page_key, access_level FROM rbac_role_pages WHERE role_key = ? ORDER BY page_key',
      [roleKey]
    );
    res.json({
      role_key:       refreshedRole[0].role_key,
      display_name:   refreshedRole[0].display_name,
      description:    refreshedRole[0].description,
      is_system:      !!refreshedRole[0].is_system,
      default_access: refreshedRole[0].default_access,
      created_at:     refreshedRole[0].created_at,
      updated_at:     refreshedRole[0].updated_at,
      grants:         refreshedGrants,
    });
  } catch (err) {
    try { await conn.rollback(); } catch (_) {}
    console.error('[rbac-routes] PUT /roles/:role_key failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  } finally {
    conn.release();
  }
});

// ── DELETE /roles/:role_key — delete a role ───────────────────────────
// CASCADE removes role_pages; rbac_users.role_key gets SET NULL via FK.
// is_system roles cannot be deleted.
router.delete('/roles/:role_key', async (req, res) => {
  const roleKey = (req.params.role_key || '').trim().toLowerCase();
  try {
    const [existing] = await pool.query(
      'SELECT role_key, display_name, is_system FROM rbac_roles WHERE role_key = ? LIMIT 1',
      [roleKey]
    );
    if (existing.length === 0) {
      return res.status(404).json({ error: 'role not found', code: 'NOT_FOUND' });
    }
    if (existing[0].is_system) {
      return res.status(400).json({
        error:    'cannot delete a system role',
        code:     'SYSTEM_ROLE',
        role_key: roleKey,
      });
    }

    const [usage] = await pool.query(
      'SELECT COUNT(*) AS n FROM rbac_user_roles WHERE role_key = ?',
      [roleKey]
    );
    const userCount = usage[0].n;

    await pool.execute('DELETE FROM rbac_roles WHERE role_key = ?', [roleKey]);

    await rbac.audit(req, 'role_deleted', null, roleKey, {
      display_name:        existing[0].display_name,
      orphaned_user_count: userCount,
    });

    res.json({
      role_key:            roleKey,
      deleted:             true,
      orphaned_user_count: userCount,
    });
  } catch (err) {
    console.error('[rbac-routes] DELETE /roles/:role_key failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

// ── GET /audit — audit log feed (paginated by id cursor) ──────────────
router.get('/audit', async (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit  || '50', 10), 200);
  const before = parseInt(req.query.before || '0', 10);
  try {
    let sql = `SELECT id, actor_email, action, target_email, target_page_key,
                      details, ip_address, user_agent, created_at
                 FROM rbac_audit_log`;
    const params = [];
    if (before > 0) {
      sql += ' WHERE id < ?';
      params.push(before);
    }
    sql += ' ORDER BY id DESC LIMIT ?';
    params.push(limit);

    const [rows] = await pool.query(sql, params);
    res.json({
      entries:     rows,
      next_before: rows.length === limit ? rows[rows.length - 1].id : null,
    });
  } catch (err) {
    console.error('[rbac-routes] GET /audit failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});


// ── GET /admin/view-as/:email — SA impersonation lookup ─────────────
// VIEW-AS-ENDPOINT-v1
// Returns the effective pages/roles for any user, same shape as /me.
// Client-side only: the caller's real token is never swapped.
router.get('/admin/view-as/:email', async (req, res) => {
  const targetEmail = (req.params.email || '').trim().toLowerCase();
  if (!targetEmail) {
    return res.status(400).json({ error: 'email is required', code: 'BAD_INPUT' });
  }

  try {
    // 1. Look up user record
    const [userRows] = await pool.query(
      'SELECT display_name, is_active, roles_resolved_at FROM rbac_users WHERE email = ? LIMIT 1',
      [targetEmail]
    );
    const exists = userRows.length > 0;
    const displayName = exists ? userRows[0].display_name : null;
    const isActive = exists ? !!userRows[0].is_active : false;
    const resolvedAt = exists ? userRows[0].roles_resolved_at : null;

    // 2. Get AD-resolved roles from rbac_user_roles
    const [roleRows] = await pool.query(
      'SELECT role_key FROM rbac_user_roles WHERE email = ?',
      [targetEmail]
    );
    const roles = roleRows.map(r => r.role_key);

    // 3. Super-admin check: env var (username) OR 'superadmin' role
    const saList = (process.env.RBAC_SUPERADMINS || '')
      .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
    // Match rbac-middleware.js:295 exactly — RBAC_SUPERADMINS holds full email
    // addresses, so comparing only the username part silently under-reported
    // super-admin for anyone listed there without the superadmin AD role.
    const isSuperAdmin = saList.includes(targetEmail) || roles.includes('superadmin');

    // 4. Compute effective pages (what they'd see if active)
    let pages = {};
    try {
      pages = await rbac.computeEffectivePages(targetEmail, roles, isSuperAdmin);
    } catch (cpErr) {
      console.warn('[rbac-routes] view-as computeEffectivePages failed:', cpErr.message);
    }

    // 5. Audit the lookup
    await rbac.audit(req, 'view_as_lookup', targetEmail, null, {
      roles,
      isSuperAdmin,
      isActive,
    });

    // Same hide-list the target would get from /me, so View-As reproduces
    // their landing page faithfully rather than just their page grants.
    let hiddenSections = [];
    try {
      hiddenSections = await rbac.computeHiddenSections(targetEmail, roles);
    } catch (secErr) {
      console.warn('[rbac-routes] view-as computeHiddenSections failed:', secErr.message);
    }

    res.json({
      email:        targetEmail,
      displayName:  displayName,
      isSuperAdmin: isSuperAdmin,
      isActive:     isActive,
      roles:        roles,
      pages:        pages,
      hiddenSections,
      _viewAs:            true,
      _userExists:        exists,
      _rolesResolvedAt:   resolvedAt,
    });
  } catch (err) {
    console.error('[rbac-routes] GET /admin/view-as/:email failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});




// =====================================================================
// Landing-page section visibility (super-admin only -- everything below
// router.use(requireSuperAdmin) at the top of this file).
//
// Model: sections are VISIBLE by default. rbac_section_visibility stores
// only deviations, so an empty table == stock page for everyone. A
// per-user row beats role rows; role rows merge most-permissively.
// =====================================================================

const SECTION_KEY_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;

async function knownSectionKeys() {
  const [rows] = await pool.query('SELECT section_key FROM rbac_sections');
  return new Set(rows.map(r => r.section_key));
}

// Body shape: { sections: { "<section_key>": true|false, ... } }
// A key present with true/false writes an explicit rule; any key NOT present
// is cleared, so the scope falls back to inheritance. Returns null if bad.
function normaliseSectionRules(body) {
  const raw = body && body.sections;
  if (raw === undefined || raw === null) return {};
  if (typeof raw !== 'object' || Array.isArray(raw)) return null;
  const out = {};
  for (const [k, v] of Object.entries(raw)) {
    if (typeof v !== 'boolean') return null;
    out[k] = v;
  }
  return out;
}

async function writeSectionRules(scopeType, scopeId, rules, actor) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    await conn.execute(
      'DELETE FROM rbac_section_visibility WHERE scope_type = ? AND scope_id = ?',
      [scopeType, scopeId]
    );
    const entries = Object.entries(rules);
    if (entries.length > 0) {
      await conn.query(
        `INSERT INTO rbac_section_visibility
           (scope_type, scope_id, section_key, visible, updated_by)
         VALUES ?`,
        [entries.map(([k, v]) => [scopeType, scopeId, k, v ? 1 : 0, actor])]
      );
    }
    await conn.commit();
  } catch (err) {
    try { await conn.rollback(); } catch (e) {}
    throw err;
  } finally {
    conn.release();
  }
}

// ── GET /sections — the registry of hideable sections ────────────────
router.get('/sections', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT section_key, page_key, display_name, description, dom_id, display_order
         FROM rbac_sections
        ORDER BY display_order, section_key`
    );
    res.json({ sections: rows });
  } catch (err) {
    console.error('[rbac-routes] GET /sections failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

// ── GET /users/:email/sections ───────────────────────────────────────
router.get('/users/:email/sections', async (req, res) => {
  const email = (req.params.email || '').trim().toLowerCase();
  if (!email) return res.status(400).json({ error: 'email is required', code: 'BAD_INPUT' });
  try {
    const [rows] = await pool.query(
      `SELECT section_key, visible FROM rbac_section_visibility
        WHERE scope_type = 'user' AND scope_id = ?`,
      [email]
    );
    const [roleRows] = await pool.query(
      'SELECT role_key FROM rbac_user_roles WHERE email = ?',
      [email]
    );
    const roles = roleRows.map(r => r.role_key);
    res.json({
      email,
      roles,
      rules: Object.fromEntries(rows.map(r => [r.section_key, !!r.visible])),
      effectiveHidden: await rbac.computeHiddenSections(email, roles),
    });
  } catch (err) {
    console.error('[rbac-routes] GET /users/:email/sections failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

// ── PUT /users/:email/sections ───────────────────────────────────────
router.put('/users/:email/sections', express.json({ limit: '16kb' }), async (req, res) => {
  const email = (req.params.email || '').trim().toLowerCase();
  if (!email) return res.status(400).json({ error: 'email is required', code: 'BAD_INPUT' });

  const rules = normaliseSectionRules(req.body);
  if (rules === null) {
    return res.status(400).json({
      error: 'sections must be an object of {section_key: boolean}',
      code:  'BAD_INPUT',
    });
  }
  const known = await knownSectionKeys();
  const bad = Object.keys(rules).filter(k => !SECTION_KEY_RE.test(k) || !known.has(k));
  if (bad.length) {
    return res.status(400).json({ error: `unknown section_key(s): ${bad.join(', ')}`, code: 'UNKNOWN_SECTION' });
  }

  try {
    const [beforeRows] = await pool.query(
      `SELECT section_key, visible FROM rbac_section_visibility
        WHERE scope_type = 'user' AND scope_id = ?`,
      [email]
    );
    const before = Object.fromEntries(beforeRows.map(r => [r.section_key, !!r.visible]));

    await writeSectionRules('user', email, rules, req.user.email);
    await rbac.audit(req, 'section_visibility_changed', email, null, {
      scope: 'user', before, after: rules,
    });

    const [roleRows] = await pool.query(
      'SELECT role_key FROM rbac_user_roles WHERE email = ?', [email]
    );
    const roles = roleRows.map(r => r.role_key);
    res.json({ ok: true, email, rules, effectiveHidden: await rbac.computeHiddenSections(email, roles) });
  } catch (err) {
    console.error('[rbac-routes] PUT /users/:email/sections failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

// ── GET /roles/:role_key/sections ────────────────────────────────────
router.get('/roles/:role_key/sections', async (req, res) => {
  const roleKey = (req.params.role_key || '').trim().toLowerCase();
  if (!validateRoleKey(roleKey)) {
    return res.status(400).json({ error: 'invalid role_key format', code: 'BAD_ROLE_KEY' });
  }
  try {
    const [rows] = await pool.query(
      `SELECT section_key, visible FROM rbac_section_visibility
        WHERE scope_type = 'role' AND scope_id = ?`,
      [roleKey]
    );
    res.json({ role_key: roleKey, rules: Object.fromEntries(rows.map(r => [r.section_key, !!r.visible])) });
  } catch (err) {
    console.error('[rbac-routes] GET /roles/:role_key/sections failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

// ── PUT /roles/:role_key/sections ────────────────────────────────────
router.put('/roles/:role_key/sections', express.json({ limit: '16kb' }), async (req, res) => {
  const roleKey = (req.params.role_key || '').trim().toLowerCase();
  if (!validateRoleKey(roleKey)) {
    return res.status(400).json({ error: 'invalid role_key format', code: 'BAD_ROLE_KEY' });
  }
  const rules = normaliseSectionRules(req.body);
  if (rules === null) {
    return res.status(400).json({
      error: 'sections must be an object of {section_key: boolean}',
      code:  'BAD_INPUT',
    });
  }
  const known = await knownSectionKeys();
  const bad = Object.keys(rules).filter(k => !SECTION_KEY_RE.test(k) || !known.has(k));
  if (bad.length) {
    return res.status(400).json({ error: `unknown section_key(s): ${bad.join(', ')}`, code: 'UNKNOWN_SECTION' });
  }

  try {
    const [roleRows] = await pool.query('SELECT role_key FROM rbac_roles WHERE role_key = ? LIMIT 1', [roleKey]);
    if (!roleRows.length) {
      return res.status(404).json({ error: 'role not found', code: 'ROLE_NOT_FOUND' });
    }
    const [beforeRows] = await pool.query(
      `SELECT section_key, visible FROM rbac_section_visibility
        WHERE scope_type = 'role' AND scope_id = ?`,
      [roleKey]
    );
    const before = Object.fromEntries(beforeRows.map(r => [r.section_key, !!r.visible]));

    await writeSectionRules('role', roleKey, rules, req.user.email);
    await rbac.audit(req, 'section_visibility_changed', null, null, {
      scope: 'role', role_key: roleKey, before, after: rules,
    });
    res.json({ ok: true, role_key: roleKey, rules });
  } catch (err) {
    console.error('[rbac-routes] PUT /roles/:role_key/sections failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

// =====================================================================
// DATA SCOPE administration.  (2026-09-03)
// Everything below sits under router.use(rbac.requireSuperAdmin) at line ~245,
// so these are limited to RBAC_SUPERADMINS + the superadmin AD group.
//
// Scope answers "how much of the data may this person see", which is a separate
// question from page access. See scope-lib.js for the resolution ladder.
// =====================================================================

// GET /api/rbac/users/:email/scope — the assigned row (if any) and what actually resolves.
router.get('/users/:email/scope', async (req, res) => {
  const email = (req.params.email || '').trim().toLowerCase();
  try {
    const [rows] = await pool.query(
      'SELECT scope_kind, scope_value, note, granted_by, granted_at FROM rbac_user_scope WHERE email = ?',
      [email]
    );
    res.json({
      email,
      assigned:  rows.length ? rows[0] : null,
      effective: await resolveScope(pool, email),
    });
  } catch (err) {
    console.error('[rbac-routes] GET /users/:email/scope failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

// PUT /api/rbac/users/:email/scope — body { scope_kind, scope_value, note }
router.put('/users/:email/scope', express.json({ limit: '8kb' }), async (req, res) => {
  const email = (req.params.email || '').trim().toLowerCase();
  const kind  = ((req.body && req.body.scope_kind) || '').trim();
  let   value = req.body && req.body.scope_value != null ? String(req.body.scope_value).trim() : null;
  const note  = req.body && req.body.note ? String(req.body.note).slice(0, 500) : null;

  if (!SCOPE_KINDS.includes(kind)) {
    return res.status(400).json({ error: `scope_kind must be one of ${SCOPE_KINDS.join(', ')}`, code: 'BAD_KIND' });
  }
  // 'org' used to be refused here on the grounds that it belongs in AD. That was
  // wrong in practice: the roster in Manage access IS the AD group, so refusing
  // org left every row in it unadjustable and the override reachable by nobody.
  // An assignment now outranks the group (scope-lib ladder step 1), which makes
  // both directions expressible - narrow a group member, or widen someone who is
  // not in the group - and both are audited with the assigning owner's name.
  // The AD group remains the default and is what DELETE falls back to.

  try {
    // Validate the target so a typo cannot silently produce an empty dashboard.
    if (kind === 'department') {
      if (!value) return res.status(400).json({ error: 'scope_value (dept_code) required', code: 'VALUE_REQUIRED' });
      const [d] = await pool.query('SELECT 1 FROM hr_roster WHERE dept_code = ? LIMIT 1', [value]);
      if (!d.length) return res.status(400).json({ error: `unknown dept_code "${value}"`, code: 'UNKNOWN_DEPT' });
    } else if (kind === 'leader') {
      value = (value || email).toLowerCase();
      const [l] = await pool.query('SELECT 1 FROM hr_roster WHERE leader_email = ? LIMIT 1', [value]);
      if (!l.length) return res.status(400).json({ error: `"${value}" is not a leader for anyone in the roster`, code: 'NOT_A_LEADER' });
    } else if (kind === 'team') {
      value = (value || email).toLowerCase();
      const [m] = await pool.query('SELECT 1 FROM hr_roster WHERE manager_email = ? LIMIT 1', [value]);
      if (!m.length) return res.status(400).json({ error: `"${value}" manages nobody in the roster`, code: 'NOT_A_MANAGER' });
    } else if (kind === 'self') {
      value = email;
    } else if (kind === 'org') {
      value = null;
    }

    const [beforeRows] = await pool.query(
      'SELECT scope_kind, scope_value FROM rbac_user_scope WHERE email = ?', [email]
    );
    await pool.query(
      `INSERT INTO rbac_user_scope (email, scope_kind, scope_value, note, granted_by)
       VALUES (?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE scope_kind = VALUES(scope_kind), scope_value = VALUES(scope_value),
                               note = VALUES(note), granted_by = VALUES(granted_by)`,
      [email, kind, value, note, req.user.email]
    );
    await rbac.audit(req, 'scope_assigned', email, null, {
      before: beforeRows.length ? beforeRows[0] : null,
      after:  { scope_kind: kind, scope_value: value },
      note,
    });
    res.json({ ok: true, email, effective: await resolveScope(pool, email) });
  } catch (err) {
    console.error('[rbac-routes] PUT /users/:email/scope failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

// DELETE /api/rbac/users/:email/scope — drop the override, fall back to derived.
router.delete('/users/:email/scope', async (req, res) => {
  const email = (req.params.email || '').trim().toLowerCase();
  try {
    const [beforeRows] = await pool.query(
      'SELECT scope_kind, scope_value FROM rbac_user_scope WHERE email = ?', [email]
    );
    if (!beforeRows.length) {
      return res.status(404).json({ error: 'no assigned scope for that user', code: 'NOT_FOUND' });
    }
    await pool.query('DELETE FROM rbac_user_scope WHERE email = ?', [email]);
    await rbac.audit(req, 'scope_cleared', email, null, { before: beforeRows[0], after: null });
    res.json({ ok: true, email, effective: await resolveScope(pool, email) });
  } catch (err) {
    console.error('[rbac-routes] DELETE /users/:email/scope failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

// GET /api/rbac/scope/assignments — every override, for the console list view.
router.get('/scope/assignments', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT s.email, s.scope_kind, s.scope_value, s.note, s.granted_by, s.granted_at,
              r.employee_name, r.department
         FROM rbac_user_scope s
         LEFT JOIN hr_roster r ON r.email = s.email
        ORDER BY s.granted_at DESC`
    );
    const [orgMembers] = await pool.query(
      `SELECT ur.email, r.employee_name FROM rbac_user_roles ur
         LEFT JOIN hr_roster r ON r.email = ur.email
        WHERE ur.role_key = 'reporting' ORDER BY ur.email`
    );
    res.json({ assignments: rows, orgWide: orgMembers, orgWideSource: 'AD group SaaS-ITH-RPT' });
  } catch (err) {
    console.error('[rbac-routes] GET /scope/assignments failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

// ---- View-As delegation (super-admin only, per the gate above) --------------
router.get('/view-as/grants', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT v.email, v.level, v.note, v.granted_by, v.granted_at, r.employee_name, r.department
         FROM rbac_view_as v LEFT JOIN hr_roster r ON r.email = v.email
        ORDER BY FIELD(v.level,'any','department','reports'), v.email`);
    res.json({ grants: rows });
  } catch (err) {
    console.error('[rbac-routes] GET /view-as/grants failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

router.put('/users/:email/view-as', express.json({ limit: '4kb' }), async (req, res) => {
  const email = (req.params.email || '').trim().toLowerCase();
  const level = String((req.body && req.body.level) || '').trim();
  const note  = req.body && req.body.note ? String(req.body.note).slice(0, 500) : null;
  if (!['department', 'reports', 'any'].includes(level)) {
    return res.status(400).json({ error: "level must be department, reports or any", code: 'BAD_LEVEL' });
  }
  try {
    const [before] = await pool.query('SELECT level FROM rbac_view_as WHERE email = ?', [email]);
    await pool.query(
      `INSERT INTO rbac_view_as (email, level, note, granted_by) VALUES (?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE level=VALUES(level), note=VALUES(note), granted_by=VALUES(granted_by)`,
      [email, level, note, req.user.email]);
    await rbac.audit(req, 'view_as_granted', email, null,
      { before: before.length ? before[0].level : null, after: level, note });
    res.json({ ok: true, email, level });
  } catch (err) {
    console.error('[rbac-routes] PUT /users/:email/view-as failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

router.delete('/users/:email/view-as', async (req, res) => {
  const email = (req.params.email || '').trim().toLowerCase();
  try {
    const [before] = await pool.query('SELECT level FROM rbac_view_as WHERE email = ?', [email]);
    if (!before.length) return res.status(404).json({ error: 'no view-as grant', code: 'NOT_FOUND' });
    await pool.query('DELETE FROM rbac_view_as WHERE email = ?', [email]);
    await rbac.audit(req, 'view_as_revoked', email, null, { before: before[0].level, after: null });
    res.json({ ok: true, email });
  } catch (err) {
    console.error('[rbac-routes] DELETE /users/:email/view-as failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

// GET /api/rbac/scope/roster — everyone who should appear in Manage access:
// live AD group members UNION explicit page grants, each with the dashboard they
// currently resolve to. ?refresh=1 also re-resolves roles from AD for each member,
// so a person added to the group minutes ago does not have to sign in first.
router.get('/scope/roster', async (req, res) => {
  const wantRefresh = String(req.query.refresh || '') === '1';
  let members = [], adError = null;
  try {
    members = await ldapGroupMembers(REPORTING_GROUP_DN);
  } catch (e) {
    // The directory being unreachable must not blank the screen - fall back to
    // what the database knows and say so, rather than implying the group is empty.
    adError = e.message || 'directory unreachable';
    const [rows] = await pool.query(
      "SELECT ur.email, r.employee_name AS name FROM rbac_user_roles ur " +
      "LEFT JOIN hr_roster r ON r.email = ur.email WHERE ur.role_key = 'reporting'");
    members = rows.map((r) => ({ email: r.email, name: r.name, disabled: false, stale: true }));
  }

  if (wantRefresh && !adError) {
    for (const m of members) { try { await resolveRoles(pool, m.email); } catch (e) { /* per-user, non-fatal */ } }
  }

  try {
    const [grants] = await pool.query(
      "SELECT email, access_level, granted_by FROM rbac_user_page_access WHERE page_key = 'ai-usage-credits'");
    const [scopes] = await pool.query('SELECT email, scope_kind, scope_value FROM rbac_user_scope');
    const [vas]    = await pool.query('SELECT email, level FROM rbac_view_as');
    const gMap = {}; grants.forEach((g) => { gMap[g.email.toLowerCase()] = g; });
    const sMap = {}; scopes.forEach((x) => { sMap[x.email.toLowerCase()] = x; });
    const vMap = {}; vas.forEach((x) => { vMap[x.email.toLowerCase()] = x.level; });

    const emails = new Set([...members.map((m) => m.email), ...Object.keys(gMap)]);
    const [names] = await pool.query(
      'SELECT email, employee_name, title, department FROM hr_roster WHERE email IN (?)',
      [[...emails].length ? [...emails] : ['']]);
    const nMap = {}; names.forEach((n) => { nMap[n.email.toLowerCase()] = n; });
    const inGroup = new Set(members.map((m) => m.email));

    const people = [];
    for (const email of emails) {
      const scope = await resolveScope(pool, email);
      const hr = nMap[email] || {};
      const m = members.find((x) => x.email === email);
      people.push({
        email,
        name: hr.employee_name || (m && m.name) || null,
        title: hr.title || null,
        department: hr.department || null,
        inGroup: inGroup.has(email),
        disabled: !!(m && m.disabled),
        access: gMap[email] ? gMap[email].access_level : null,
        grantedBy: gMap[email] ? gMap[email].granted_by : null,
        scope: { kind: scope.kind, value: scope.value || null, label: scope.label,
                 source: scope.source, deny: !!scope.deny },
        assigned: !!sMap[email],
        viewAs: vMap[email] || '',
      });
    }
    people.sort((a, b) => (b.inGroup - a.inGroup) || String(a.name || a.email).localeCompare(String(b.name || b.email)));
    res.json({ people, groupDn: REPORTING_GROUP_DN, adError, refreshed: wantRefresh && !adError, at: new Date().toISOString() });
  } catch (err) {
    console.error('[rbac-routes] GET /scope/roster failed:', err.message);
    res.status(500).json({ error: 'Internal error', code: 'INTERNAL' });
  }
});

module.exports = router;
