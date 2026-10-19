// gate-routes.js — nginx auth_request endpoint for the HTML page gate.  (ITAM-01)
//
// PURE CRYPTO ONLY. This verifies the it_session cookie's HMAC signature + expiry
// using the three existing token verifiers and nothing else.
//
// It deliberately does NOT call rbac-middleware.loadCurrentUser(). That path does a
// live AD/directory resolution and, on USER_NOT_FOUND / AMBIGUOUS_USER /
// DIRECTORY_UNAVAILABLE, fails closed for EVERY user except those listed in
// RBAC_SUPERADMINS (rbac-middleware.js:342-352, the "break-glass floor").
// Gating pages on that is what locked out all regular users while only the
// hardcoded super-admins could still sign in, the last time this gate was changed.
// Directory state must never be able to lock a user out of a page.
//
// Returns 204 (allow) or 401 (deny). nginx maps 401 -> redirect to /login.html.
//
// 2026-08-24 (Approver Portal gate): during the Domain=.itam.nrpi.local cookie
// rollout a browser can hold TWO it_session cookies (old host-only + new domain)
// and sends both, so /check now tries every it_session value, not just the first.
// On allow it also returns X-Gate-Email (from the HMAC-verified claims — still no
// directory call) so the accessportal vhost can forward the identity to backends
// via auth_request_set.

const express = require('express');
const sessionAuth = require('./session-auth');
const breakglass  = require('./breakglass-auth');
const localdev    = require('./localdev-auth');
const sessionCookie = require('./session-cookie');
const siteAccess    = require('./site-access');   // CORPIT-SITE-AUTHZ

const LEGACY_VALUE = 'granted_2024';
// Stage 3 (dual-accept): the legacy static cookie is still honoured so nobody is
// locked out during rollout. Stage 4 flips this to false, then the value is retired.
const ACCEPT_LEGACY = false; // Stage 4 2026-08-24 (ITAM-RT-02): primary gate no longer accepts the public legacy cookie

function readCookies(req, name) {
  const raw = req.headers.cookie || '';
  const re = new RegExp('(?:^|;\\s*)' + name + '=([^;]*)', 'g');
  const out = [];
  let m;
  while ((m = re.exec(raw)) !== null) {
    try { out.push(decodeURIComponent(m[1])); }
    catch (e) { out.push(m[1]); } // malformed %-escape: try the raw value
  }
  return out;
}

// Try each verifier. All three are HMAC-over-RBAC_SESSION_SECRET, distinguished by
// their `typ` claim, and all are synchronous pure crypto (no DB, no LDAP, no await).
// MP-SIGNIN-SCOPE: `host` is the host the request is FOR. A host-scoped session token
// (My Profile's own sign-in) verifies only when it matches; platform tokens ignore it.
function verifyAny(token, host) {
  if (!token) return null;
  // CORPIT-SITE-AUTHZ-FIX carry the group list through. Rebuilding the identity without
  // it made every session look unresolved, so group mode denied everyone.
  // SESSION-WATCH-VERIFYANY 2026-09-04: exp/iat/ait/absAit added for GET /session-info.
  // Additive only - /check reads kind/email/groups/readOnly and ignores the rest.
  try { const r = sessionAuth.verifySessionToken(token, { host: host }); if (r && r.ok) return { kind: 'session', email: r.email, name: r.name, groups: r.groups, exp: r.exp, iat: r.iat, ait: r.ait, absAit: r.absAit }; } catch (e) {}
  try { const r = breakglass.verifySessionToken(token);  if (r && r.ok) return { kind: 'breakglass', email: r.email, exp: r.exp, iat: r.iat }; } catch (e) {}
  try { const r = localdev.verifyToken(token);           if (r && r.ok) return { kind: 'localdev', email: r.email || r.sub, readOnly: !!r.readOnly, exp: r.exp }; } catch (e) {}
  return null;
}

// Methods a read-only QA token may use anywhere behind the gate.
const GATE_READ_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

// Protected approval routes use active-account checks, fresh directory roles,
// shared page rules, and the portal's own team/resource policies. General /check
// retains the platform's existing authentication and site-policy behavior.
const mysql = require('mysql2/promise');
let _pool = null;
function pool() {
  if (!_pool) {
    _pool = mysql.createPool({
      host: process.env.DB_HOST || 'localhost', port: +(process.env.DB_PORT || 3306),
      user: process.env.DB_USER, password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME, connectionLimit: 3, connectTimeout: 3000,
    });
  }
  return _pool;
}
const portalRbac = require('./rbac-middleware')(pool());
const router = express.Router();

router.get('/check', function (req, res) {
  for (const candidate of readCookies(req, 'it_session')) {
    const who = verifyAny(candidate, req.get('X-Original-Host'));
    if (who) {
      // Read-only QA tokens (2026-08-26). Enforced HERE because this is the only
      // point EVERY gated path shares — including /helpdesk/, which has no
      // in-process auth of its own and would otherwise accept a POST (e.g.
      // /api/health/sync, a full Okta sync) from a token we called read-only.
      // nginx sends the original method as X-Original-Method; if that header is
      // absent we do NOT guess — an unknown method with a read-only token is
      // refused, so a missed proxy_set_header fails closed rather than silently
      // re-opening writes.
      // No effect on any other session: tokens without the `ro` claim never
      // enter this branch, so real users are untouched.
      if (who.readOnly) {
        const method = String(req.get('X-Original-Method') || '').toUpperCase();
        if (!GATE_READ_METHODS.has(method)) {
          res.set('X-Gate-Auth', 'readonly-denied');
          return res.status(403).end();
        }
        res.set('X-Gate-ReadOnly', '1');
      }
      res.set('X-Gate-Auth', who.kind);
      // Header-safe: strip anything outside printable ASCII before res.set().
      const gateEmail = String(who.email || '').replace(/[^\x20-\x7e]/g, '').toLowerCase();
      res.set('X-Gate-Email', gateEmail);

      // CORPIT-SITE-AUTHZ  Authenticated is not the same as entitled. Which AD groups may open
      // which host is set in the admin console; break-glass and super-admin
      // identities are allowed everywhere, including a site created minutes ago.
      // nginx passes the target host as X-Original-Host; its absence means the
      // vhost was wired without that header, so treat it as an unknown site and
      // let the default policy (deny, bar super-admins) apply rather than guess.
      const verdict = siteAccess.decide(req.get('X-Original-Host'), gateEmail,
                                        who.groups === undefined ? null : who.groups);
      if (!verdict.allow) {
        res.set('X-Gate-Auth', 'not-entitled');
        res.set('X-Gate-Reason', verdict.reason);
        // 403, not 401: this person IS signed in. A 401 would bounce them back
        // to the sign-in page, which would send them straight back here.
        return res.status(403).end();
      }
      res.set('X-Gate-Site', verdict.reason);
      return res.status(204).end();
    }
  }
  if (ACCEPT_LEGACY && readCookies(req, 'it_auth')[0] === LEGACY_VALUE) {
    // Counted so adoption of the signed cookie can be measured before Stage 4.
    res.set('X-Gate-Auth', 'legacy');
    return res.status(204).end();
  }
  res.set('X-Gate-Auth', 'none');
  return res.status(401).end();
});

// POST /api/gate/refresh — re-issues the it_session cookie for an already-valid
// session, migrating pre-rollout HOST-ONLY cookies to the Domain=.itam.nrpi.local
// form without a fresh login. login.html calls this on its already-signed-in
// short-circuit (every valid session is <10h old, so it always carries a
// verifiable it_session). Same pure-crypto posture as /check; it re-sets the SAME
// token, so no privilege or lifetime change — the token's own expiry still
// governs, the cookie is only transport. Safe cross-site: re-setting the caller's
// own cookie achieves nothing for an attacker.
//
// CORPIT-NO-MINT-HERE (2026-09-04): this route must NEVER be changed to MINT a
// fresh token, however convenient that looks when adding sliding renewal.
// It is listed in server.js API_PUBLIC, so it skips loadCurrentUser (no isActive
// check) AND the CORPIT-CSRF origin guard. '.local' is not a public suffix, so
// every *.nrpi.local origin is same-SITE with corpit and SameSite=Lax blocks
// nothing: a public, CSRF-exempt mint endpoint would let any page on any sibling
// vhost -- or any XSS anywhere on the platform -- silently extend a victim's
// session up to the absolute cap. The renewal endpoint is POST /api/rbac/session,
// which is deliberately NOT in API_PUBLIC (CORRECTIONS.md C4). Re-setting the
// SAME token, as below, is what keeps this route safe to leave public.
//
// CORPIT-REFRESH-COOKIE-DOMAIN (2026-09-04): this route STILL mints nothing --
// the constraint above is untouched -- but its cookie TRANSPORT was carrying the
// same two bugs the 2026-09-04 cookie hotfix fixed in rbac-routes.js, and it is
// the sibling call site that hotfix did not reach:
//
//  1. setSessionCookie was called WITHOUT `req`, so cookieDomainFor() took its
//     `if (!req) return DOMAIN` branch (session-cookie.js:34) and set
//     Domain=.corpit.nrpi.local unconditionally -- while :44 first CLEARS the
//     working host-only cookie. On any host not under that domain
//     (reporting.nrpi.local, subadmin, accessportal, directory) the browser
//     DISCARDS the replacement and only the clear lands, so PROBING the session
//     DELETED it. Near-unreachable until now, because login.js only reached this
//     route on the break-glass it_auth path; WEB-2 makes it Step 1 for every
//     signed-in visitor to login.html, and login.html is aliased onto four
//     vhosts. Passing `req` is transport-only and changes nothing about C4.
//  2. The maxAge was hardcoded at 10h. The 12h cap CLAMPS exp, so near the cap a
//     10h cookie outlives the token inside it by hours and 401s every navigation
//     instead of simply being absent. Take the ttl from the token's own exp --
//     verifyAny already computed it, so keep its result instead of discarding it.
router.post('/refresh', function (req, res) {
  for (const candidate of readCookies(req, 'it_session')) {
    const v = verifyAny(candidate, req.get('host'));
    if (v) {
      const ttl = (typeof v.exp === 'number' && v.exp > Date.now())
        ? (v.exp - Date.now()) : 10 * 60 * 60 * 1000;
      sessionCookie.setSessionCookie(res, candidate, ttl, req);
      return res.status(204).end();
    }
  }
  return res.status(401).end();
});

/* GET /api/gate/session-info — the CALLER'S OWN session lifetime, read from its
 * it_session cookie. (SESSION-WATCH-SESSION-INFO 2026-09-04)
 *
 * The countdown must come from the HttpOnly cookie the tab is actually riding,
 * not from a sessionStorage mirror -- that mirror is idToken:'' on
 * reporting/ai-usage-credits.html, so a client-side decode returns null there and
 * the old watcher bounced a perfectly live session to the sign-in page.
 *
 * Returns `now` so the countdown runs on SERVER time: a skewed client clock can
 * then neither warn early nor bounce a live session.
 *
 * Never returns jti (the revocation handle), the token itself, or grp (AD group
 * names are directory topology; /check deliberately emits only X-Gate-Email).
 *
 * Public in server.js API_PUBLIC for the same reason /check is (CORRECTIONS.md
 * C6): pure-HMAC verify inside, JSON 401 otherwise, and routing it through
 * loadCurrentUser would 401 the countdown on a directory hiccup - whereupon the
 * watcher would have to guess, which is the exact failure this route exists to
 * eliminate. Read-only GET, so the CSRF guard is not in play either way.
 *
 * Same pure-crypto posture as /check: no DB, no network, no file read beyond the
 * revocation check verifySessionToken already does.
 */
router.get('/session-info', function (req, res) {
  res.set('Cache-Control', 'no-store, private');
  res.set('Vary', 'Cookie');
  // The 12h ceiling lives in session-auth.js (CORPIT-SESSION-CAP). Read it
  // defensively: were that constant ever absent, `anchor + undefined` is NaN,
  // which serialises as absExp:null while `now < NaN` is false -- so the bar would
  // print the at-the-cap copy and REMOVE a 'Stay signed in' button that still
  // works. Report an unmeasured cap instead: invent no numbers, keep offering
  // renewal, because without the constant the mint side is not clamping either.
  const CAP_MS = (typeof sessionAuth.SESSION_ABS_CAP_MS === 'number' &&
                  isFinite(sessionAuth.SESSION_ABS_CAP_MS) &&
                  sessionAuth.SESSION_ABS_CAP_MS > 0)
    ? sessionAuth.SESSION_ABS_CAP_MS : null;
  // Iterate EVERY it_session value and stop at the first that VERIFIES, never [0]:
  // during a cookie-Domain rollout the browser sends the stale host-only cookie
  // first, and taking [0] would report the wrong session or 401 a signed-in user.
  for (const candidate of readCookies(req, 'it_session')) {
    const w = verifyAny(candidate, req.get('host'));
    if (!w) continue;
    const now = Date.now();
    const body = {
      ok: true, kind: w.kind, email: w.email, now: now,
      iat: (typeof w.iat === 'number' ? w.iat : null),
      exp: (typeof w.exp === 'number' ? w.exp : null),
      absExp: null, capMs: null, capSource: null,
      renewable: false, reason: null,
    };
    if (w.kind === 'session') {
      if (CAP_MS === null) {
        // Could not MEASURE the cap. That is not the same fact as 'you are at the
        // cap', and it must never be presented as one.
        body.capSource = 'unmeasured';
        body.renewable = true;
      } else {
        const anchor = (typeof w.absAit === 'number') ? w.absAit : now;
        body.capMs     = CAP_MS;
        body.absExp    = anchor + CAP_MS;
        // 'iat-fallback' = minted before the cap existed. It still gets a CONCRETE
        // absExp so the client never has to infer one.
        body.capSource = (typeof w.ait === 'number') ? 'ait' : 'iat-fallback';
        // CORPIT-CAP-RENEWABLE-MEANS-GAIN (2026-09-04): renewable must mean "a
        // renewal would actually EXTEND this session", not "the cap instant has
        // not passed yet". Those are the same fact only if the two expiries can
        // differ, and they cannot: mintSessionToken CLAMPS every token to
        // exp = min(now+TTL, ait+CAP), so from ~2h after sign-in exp === absExp.
        // `now < absExp` is then true for exactly as long as the token verifies
        // at all -- verifySessionToken rejects at exp AND at ait+CAP -- so
        // renewable:false could only be reached at an instant where this route
        // has already 401'd, and the whole at-the-cap UX (the bar's 'cap' mode,
        // login.js's SESSION_ABSOLUTE_CAP branch, rbac-routes' 403) was dead
        // code. Compare the two expiries instead: while exp < absExp a renewal
        // buys real time; once exp has been clamped to absExp it buys zero ms,
        // and offering "Stay signed in" there is a control that completes and
        // does nothing -- the fake control this change exists to remove.
        body.renewable = (typeof w.exp === 'number') ? (w.exp < body.absExp)
                                                     : (now < body.absExp);
        if (!body.renewable) body.reason = 'absolute-cap-reached';
      }
    } else {
      // Report the lifetime, never imply it can be extended: break-glass is fixed
      // at 60 minutes and localdev has no sliding refresh. The bar must not draw a
      // Stay-signed-in button the server is guaranteed to refuse.
      body.reason = (w.kind === 'breakglass') ? 'breakglass-not-renewable'
                                              : 'localdev-not-renewable';
    }
    return res.status(200).json(body);
  }
  res.set('X-Gate-Auth', 'none');
  return res.status(401).json({ ok: false, error: 'NO_SESSION' });
});

/* GET /landing — where can this person actually go?
 *
 * Answers the dead end in "you are signed in, but not permitted on this site":
 * rather than stopping there, offer a site their groups DO open.
 *
 * Public for the same reason /api/gate/logout is: it must work from a host the
 * caller is NOT entitled to, it requires a valid session, and it reports only
 * the caller's OWN access. It returns a hostname, never a redirect -- the
 * caller decides what to do with it, which keeps this a lookup rather than an
 * open-redirect primitive driven by a query parameter.
 *
 * `exclude` is the host that just refused them, so the answer is never the page
 * they are already stuck on.
 */
// The hub is the natural landing when several sites qualify: it is the platform
// front door rather than one department's report.
const LANDING_PREFERENCE = ['corpit.nrpi.local'];

router.get('/landing', function (req, res) {
  let who = null;
  for (const candidate of readCookies(req, 'it_session')) {
    const w = verifyAny(candidate, req.get('host'));
    if (w) { who = w; break; }
  }
  res.set('Cache-Control', 'no-store, private');
  if (!who) { res.set('X-Gate-Auth', 'none'); return res.status(401).json({ host: null }); }

  const email  = String(who.email || '').replace(/[^\x20-\x7e]/g, '').toLowerCase();
  const groups = who.groups === undefined ? null : who.groups;
  const exclude = siteAccess.normHost(req.query.exclude || req.get('X-Original-Host') || '');

  const sites = siteAccess.allowedSitesFor(email, groups)
    .filter(function (s) { return siteAccess.normHost(s.host) !== exclude; });

  sites.sort(function (a, b) {
    const ia = LANDING_PREFERENCE.indexOf(a.host), ib = LANDING_PREFERENCE.indexOf(b.host);
    return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
  });

  return res.status(200).json({
    host:  sites.length ? sites[0].host : null,
    count: sites.length,
    sites: sites,
  });
});

// GET /check-approver — shared page, site, account and approval-scope checks for the
// accessportal approver routes. 204 + identity/tier on success, 401 (no session),
// 403 (valid session but not authorised).
router.get('/check-approver', async function (req, res) {
  try {
    // The general site gate stays unchanged. Protected approval routes use the
    // same active-account and role resolver as the Hub, with bounded freshness.
    req.portalStrictDirectory = true;
    const rbac = portalRbac;
    await new Promise((resolve,reject) => Promise.resolve(rbac.loadCurrentUser(req,res,resolve)).catch(reject));
    const u = req.user;
    if (!u) return res.status(req.tokenError === 'DIRECTORY_UNAVAILABLE' || req.tokenError === 'USER_LOOKUP_ERROR' ? 503 : 401).end();
    if (!u.isActive) return res.status(403).end();
    if (u.readOnly && !GATE_READ_METHODS.has(String(req.get('X-Original-Method') || '').toUpperCase())) return res.status(403).end();
    const acc = await require('./portal-access').evaluate(pool(),rbac,u,req.sessionClaims && req.sessionClaims.groups);
    if (!acc.allowed) {res.set('X-Gate-Auth',acc.reason);return res.status(403).end();}
    res.set('X-Gate-Auth','approver');
    res.set('X-Gate-Email',String(u.email).replace(/[^\x20-\x7e]/g,'').toLowerCase());
    res.set('X-Gate-Tier',acc.tier);
    res.set('X-Gate-Level',acc.level);
    res.set('X-Gate-Roles',u.roles.filter(k=>/^[a-z0-9][a-z0-9-]{0,63}$/.test(k)).join(','));
    if(u.readOnly)res.set('X-Gate-ReadOnly','1');
    return res.status(204).end();
  } catch(e) {console.error('[portal-gate]',e.message);return res.status(503).end();}
});

// POST /logout — the ONLY way to actually end an ITAM session. it_session is
// HttpOnly, so page JS cannot clear it; before this existed "Sign Out" cleared
// sessionStorage and the legacy it_auth cookie while the real gate cookie stayed
// valid for its full TTL. Clears both the host-only and Domain=.itam.nrpi.local
// variants (a browser can hold both during the cookie rollout) plus the legacy
// value. POST-only so a stray <img>/link cannot log people out. Unauthenticated
// by design: unverifiable cookies are cleared; a durable revocation failure
// returns 503 with a retry path instead of reporting successful sign-out.
function logoutDurabilityFailure(res, retryPath) {
  // Keep the cookie so a signed, already-revoked token can confirm durability.
  res.set('Cache-Control', 'no-store, private');
  return res.status(503).json({ code: 'REVOCATION_NOT_DURABLE',
    error: 'Sign-out could not be confirmed. Please retry.', retry: retryPath });
}

router.post('/logout', function (req, res) {
  // CORPIT-REVOKE (2026-09-02): clearing the cookie only ends the session in THIS
  // browser -- the token itself stayed valid for its full TTL anywhere it had been
  // copied. Revoke every session cookie presented, so signing out actually ends
  // the session. An unverifiable cookie is simply cleared, exactly as before;
  // verified cookies require a durable result before success.
  //
  // Same-origin required BEFORE revoking. This route is public, POST-only and
  // credential-free by design, so any page can fire it with the cookie attached --
  // and '.local' is not a public suffix, so every *.nrpi.local host counts as
  // same-SITE and SameSite=Lax does not stop them. While logout merely cleared a
  // cookie that was a nuisance; now that it durably revokes, a forged one is a
  // session kill. A cross-origin caller still gets its cookie cleared and still
  // gets 204 -- it just does not get to revoke.
  var revokeAllowed = true;
  try {
    var _sfs = req.get('sec-fetch-site');
    var _org = req.get('origin');
    if (_sfs) revokeAllowed = (_sfs === 'same-origin');
    else if (_org) revokeAllowed = (_org === ((req.get('x-forwarded-proto') || req.protocol) + '://' + req.get('host')));
    // Neither header: a non-browser client calling its own logout. Allowed --
    // it can only ever revoke a session whose cookie it already holds.
  } catch (e) {}
  if (!revokeAllowed) {
    console.warn('[gate/logout] cross-origin logout - cookie cleared, jti NOT revoked');
  }
  if (revokeAllowed) {
    try {
      var raw = req.headers.cookie || '';
      var re = /(?:^|;\s*)it_session=([^;]*)/g, mm;
      while ((mm = re.exec(raw)) !== null) {
        var value = mm[1];
        try { value = decodeURIComponent(value); } catch (e) {}
        if (!sessionAuth.revokeTokenForLogout(value, { host: req.get('host') })) {
          return logoutDurabilityFailure(res, '/api/gate/logout');
        }
      }
    } catch (e) {
      console.error('[gate/logout] durable revocation failed:', e.message);
      return logoutDurabilityFailure(res, '/api/gate/logout');
    }
  }
  try { sessionCookie.clearSessionCookie(res); } catch (e) {}
  try {
    res.clearCookie('it_auth', { path: '/' });
  } catch (e) {}
  return res.status(204).end();
});

/* ── GET /api/gate/federated-logout ───────────────────────────────────────
 * FEDERATED sign-out (2026-09-03).
 *
 * POST /logout above ends OUR session: it revokes the jti and clears the
 * cookie. It does NOT touch the Entra session, and Entra is what actually
 * decides whether the next sign-in prompts. So "Sign out" followed by opening
 * any gated page silently re-authenticated through login.js's auto-start and
 * the user was never really signed out - which is what Jeramy reported twice.
 *
 * This route does the local teardown and then hands the browser to Microsoft's
 * logout endpoint, so the Entra session ends too and the next visit is a real
 * sign-in.
 *
 * It is a GET because it is a top-level NAVIGATION, not an XHR - the browser
 * has to leave this origin. It repeats the local teardown rather than assuming
 * the POST ran, so hitting this URL directly is a complete sign-out and never
 * leaves the half-state "signed out of Entra, still holding a local cookie".
 *
 * Cross-origin callers get the cookie cleared and the redirect, but do NOT get
 * to revoke - same rule as POST /logout. A forged logout is an annoyance, not
 * a compromise, but there is no reason to hand it the durable half.
 *
 * post_logout_redirect_uri is sent ONLY when SSO_POST_LOGOUT_REDIRECT is set,
 * because Entra rejects an unregistered one. Unset (the default today) means
 * Microsoft shows its own "You signed out" page, which needs no app-registration
 * change and is an unambiguous end state. To land back on our own sign-in page
 * instead, register that URL under the app registration's post-logout redirect
 * URIs and set the env var.
 *
 * If the tenant is not configured we fall back to the local sign-out landing
 * rather than emitting a broken Microsoft URL.
 */
router.get('/federated-logout', function (req, res) {
  var revokeAllowed = true;
  try {
    var sfs = req.get('sec-fetch-site');
    var org = req.get('origin');
    if (sfs) revokeAllowed = (sfs === 'same-origin');
    else if (org) revokeAllowed = (org === ((req.get('x-forwarded-proto') || req.protocol) + '://' + req.get('host')));
  } catch (e) {}
  if (!revokeAllowed) {
    console.warn('[gate/federated-logout] cross-origin - cookie cleared, jti NOT revoked');
  }
  if (revokeAllowed) {
    try {
      var raw = req.headers.cookie || '';
      var re = /(?:^|;\s*)it_session=([^;]*)/g, mm;
      while ((mm = re.exec(raw)) !== null) {
        var value = mm[1];
        try { value = decodeURIComponent(value); } catch (e) {}
        if (!sessionAuth.revokeTokenForLogout(value, { host: req.get('host') })) {
          return logoutDurabilityFailure(res, '/api/gate/federated-logout');
        }
      }
    } catch (e) {
      console.error('[gate/logout] durable revocation failed:', e.message);
      return logoutDurabilityFailure(res, '/api/gate/federated-logout');
    }
  }
  try { sessionCookie.clearSessionCookie(res); } catch (e) {}
  try {
    res.clearCookie('it_auth', { path: '/' });
  } catch (e) {}

  res.set('Cache-Control', 'no-store, private');

  var tenant = process.env.SSO_TENANT_ID || process.env.RBAC_AZURE_TENANT_ID;
  if (!tenant) {
    console.warn('[gate/federated-logout] no tenant configured - local sign-out only');
    return res.redirect(302, '/login.html?signedout=1&federated=unavailable');
  }
  var url = 'https://login.microsoftonline.com/' + encodeURIComponent(tenant) +
            '/oauth2/v2.0/logout';
  var rd = (process.env.SSO_POST_LOGOUT_REDIRECT || '').trim();
  if (rd) url += '?post_logout_redirect_uri=' + encodeURIComponent(rd);
  return res.redirect(302, url);
});

module.exports = router;
