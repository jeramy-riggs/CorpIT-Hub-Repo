// == CorpIT session watcher v2.0 (2026-09-04) ==============================
// [IT-SESS-WATCH]  THE single implementation. The v1.4 IIFE at the bottom of
// rbac-client.js was deleted in the same change (WEB-1); do not reintroduce a
// second one. Deploys to /var/www/html/it-session-watch.js and is served on
// reporting AND subadmin through an nginx `alias` at the same inode (NGX-6/NGX-7)
// -- one file, one posture, no drift. reporting also keeps the sibling symlink
// pattern of rbac-client.js/it-topbar.js, but the alias is what GUARANTEES the file
// answers there: an exact-match location beats `location /`, so a missed symlink
// step can no longer leave that vhost with a 404 and no watcher.
//
// Server-driven: the countdown comes from GET /api/gate/session-info, which reads
// the HttpOnly it_session cookie the tab is actually riding. It NEVER parses the
// sessionStorage mirror to decide whether the session is alive - that mirror is
// idToken:'' on reporting/ai-usage-credits.html:656, and the old watcher read that
// as 'no readable expiry' and redirected a perfectly valid tab to sign-in.
//
// THE THREE RULES THIS FILE EXISTS TO ENFORCE:
//  1. Never render a control that cannot complete.
//  2. Never present a transport failure as a statement about the session.
//  3. Never navigate away on a measurement this file made alone.
//
// PURE ASCII, deliberately. This file is loaded cross-vhost, including under
// subadmin's strict CSP, and an external script inherits its encoding from the
// response header rather than from any meta tag on the host page. A stray
// non-ASCII byte would be decoded differently on the three vhosts. Escape, never
// paste. Likewise: no inline <script> anywhere, no eval, no new Function.
// An injected <style> element IS allowed (style-src carries 'unsafe-inline').
(function () {
  'use strict';
  if (window.__itSessionWatchLoaded) return;   // load-once, matching it-topbar.js
  window.__itSessionWatchLoaded = true;

  // Sign-in / auth pages: never run here. EXACT-match on '/login.html' (the v1.4
  // guard) misses /login_sso.html and subadmin's extension-less Flask route
  // '/login' - the same shape as nginx's 'location = /x' defeated by '/x/'.
  if (/^\/login(_sso)?(\.html)?$/.test(window.location.pathname)) return;
  if (/^\/auth-complete\.html$/.test(window.location.pathname)) return;

  // Defensive: if a heuristically-cached rbac-client.js still carries the v1.4
  // watcher (nginx/sub-reporting sets no Cache-Control on 'location /'), remove
  // its bar so two implementations cannot fight over one element id. The ?v=
  // cache-busters in WEB-3/WEB-4 are the primary fix; this is the backstop.
  try {
    var _old = document.getElementById('itcmd-sess-bar');
    if (_old && _old.parentNode) _old.parentNode.removeChild(_old);
  } catch (e) {}

  var STATUS_URL = '/api/gate/session-info'; // MUST stay under /api/gate/ - rbac-client.js
                                             // exempts only that prefix from its global
                                             // 401-means-redirect fetch intercept.
                                             // Written as an exact literal, never built by
                                             // concatenation: corpit routes this path with
                                             // an EXACT-match location, and a trailing
                                             // slash falls through to the :3000 app.
  var RENEW_URL  = '/api/rbac/session';      // POST. NOT /api/gate/refresh: that route is
                                             // API_PUBLIC and CSRF-exempt and deliberately
                                             // mints nothing (CORRECTIONS.md C4). This one
                                             // runs loadCurrentUser (is_active) and the
                                             // CORPIT-CSRF origin check.
                                             // rbac-client.js exempts this EXACT pathname
                                             // from its 401-means-redirect intercept, so a
                                             // 401 here stays OUR failure to handle (renew()
                                             // repairs the bearer) instead of navigating a
                                             // page away behind a background renewal.
  var TOKEN_URL  = '/api/auth/token';        // GET. Hands back the caller's OWN cookie
                                             // token. Used to repair a stale per-tab bearer.
                                             // Reachable on all three vhosts (corpit's own
                                             // block; snippets/corpit-hub-sso.conf:109 for
                                             // subadmin and reporting).
                                             // rbac-client.js exempts this EXACT pathname
                                             // from its 401-means-redirect intercept
                                             // (isTokenUrl), same as STATUS_URL/RENEW_URL, so
                                             // a NO_SESSION 401 during a bearer repair stays
                                             // OURS to handle (resyncBearer returns false)
                                             // instead of hard-redirecting a bearer-without-
                                             // cookie session to /login.html at boot.
  var LOGOUT_URL = '/api/gate/federated-logout'; // Revokes, clears the cookie AND ends the
                                             // Entra session. Reachable on all three vhosts
                                             // (corpit.nrpi.local.conf:588; the shared
                                             // snippet at :193 for subadmin and reporting).

  var WARN_MS      = 15 * 60 * 1000;  // show the bar / start renewing inside this window
  var IDLE_MS      = WARN_MS;         // 'active' = interacted within this window
  var CHECK_MS     = 20 * 1000;       // local tick (cheap: no network)
  var REFETCH_MS   = 60 * 1000;       // re-read the server ONLY inside the warn window
  var RENEW_MIN_MS = 60 * 1000;       // at most one SILENT renew attempt per minute
  var UNREACH_AT   = 3;               // consecutive renew transport failures -> 'unreachable'
  var BAR_ID = 'itcmd-sess-bar', CSS_ID = 'itcmd-sess-css';
  var RENEW_STAMP = 'itcmd_sess_renewed';   // cross-tab signal (localStorage)

  // ---- diagnostics log: PRESERVED VERBATIM from v1.4 ---------------------
  // The expiry bar looks alarming when it appears and there is no record of
  // WHY: how long the token was minted for, how old it already was, and what
  // the client did next. This keeps a small rolling log so the answer is one
  // command away instead of a live debugging session.
  //
  //   itSessionLog()        pretty-print the log for this browser
  //   itSessionLog(true)    also return the raw array
  //
  // Never records the token itself - only its iat/exp/jti claims and timings.
  // Same key, same cap, same rolling slice, same window.itSessionLog(raw)
  // contract, same event names. New events only ADD: 'renew-silent',
  // 'renew-refused', 'renew-401', 'cap-reached', 'status-401',
  // 'status-unavailable', 'bearer-resync', 'peer-renewed'.
  // 'extend-failed' now carries WHICH kind of failure it was: {transport:true} for a
  // genuine network error, or {status:<code>} when the server answered. Without that
  // the log points support at the network for a 503 from corpit-hub-api.
  var LOG_KEY = 'itcmd_sess_log';
  var LOG_MAX = 60;

  function sessLog(event, detail) {
    var row = { t: new Date().toISOString(), page: location.pathname, event: event };
    if (detail) for (var k in detail) if (detail.hasOwnProperty(k)) row[k] = detail[k];
    try {
      var arr = JSON.parse(localStorage.getItem(LOG_KEY) || '[]');
      arr.push(row);
      if (arr.length > LOG_MAX) arr = arr.slice(-LOG_MAX);
      localStorage.setItem(LOG_KEY, JSON.stringify(arr));
    } catch (e) { /* storage full or blocked: the console line below still lands */ }
    // debug level (2026-09-06): silent at Chrome's default console verbosity, shown
    // under 'Verbose'; itSessionLog() prints the stored table on demand. Was console.info.
    try { console.debug('[itcmd-session]', event, row); } catch (e) {}
    return row;
  }

  window.itSessionLog = function (raw) {
    var arr = [];
    try { arr = JSON.parse(localStorage.getItem(LOG_KEY) || '[]'); } catch (e) {}
    try { console.table ? console.table(arr) : console.log(arr); } catch (e) {}
    return raw ? arr : arr.length + ' entries (pass true to get the array)';
  };

  function b64pad(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    return s;
  }

  // Decode the CLIENT mirror's token payload. DIAGNOSTICS ONLY - nothing here
  // decides anything. The corpit token is TWO segments (payload.sig) so the
  // payload is parts[0], not parts[1]; iat/exp are MILLISECONDS (Date.now()), so
  // the '> 1e12 ? v : v * 1000' normaliser stays. Do NOT 'fix' it to seconds.
  function payloadOf(tok) {
    var parts = String(tok).split('.');
    var seg = (parts.length === 3) ? parts[1] : parts[0];
    return { parts: parts.length, p: JSON.parse(atob(b64pad(seg))) };
  }

  // Snapshot of the token's shape and timing, for the log only. The whole value
  // of this row is 'what did the CLIENT think' set against what the SERVER said,
  // so the server's answer (st) is folded in beside it.
  function tokenFacts() {
    var out;
    try {
      var raw = sessionStorage.getItem('sso_user');
      if (!raw) { out = { token: 'absent' }; }
      else {
        var tok = JSON.parse(raw).idToken;
        if (!tok) { out = { token: 'no idToken field' }; }
        else {
          var d = payloadOf(tok), p = d.p;
          var norm = function (v) { return typeof v === 'number' ? (v > 1e12 ? v : v * 1000) : null; };
          var exp = norm(p.exp), iat = norm(p.iat), now = Date.now();
          out = {
            parts: d.parts,                       // 2 here, not a standard JWT
            jti: p.jti || null,
            iat: iat ? new Date(iat).toISOString() : null,
            exp: exp ? new Date(exp).toISOString() : null,
            lifetimeMin: (exp && iat) ? +((exp - iat) / 60000).toFixed(1) : null,
            ageMin: iat ? +((now - iat) / 60000).toFixed(1) : null,
            remainingMin: exp ? +((exp - now) / 60000).toFixed(1) : null
          };
        }
      }
    } catch (e) { out = { token: 'unreadable', err: String(e).slice(0, 60) }; }
    // What the SERVER last said. Never the token, never jti-from-server, never grp.
    try {
      if (st) {
        out.srvKind = st.kind || null;
        out.srvExp = (typeof st.exp === 'number') ? new Date(st.exp).toISOString() : null;
        out.srvAbsExp = (typeof st.absExp === 'number') ? new Date(st.absExp).toISOString() : null;
        out.srvCapSource = st.capSource || null;
        out.srvRenewable = (st.renewable === true);
      } else {
        out.srvKind = 'unmeasured';
      }
    } catch (e) {}
    return out;
  }

  // The per-tab Bearer's own expiry, for the boot-time repair decision only.
  // null means absent / empty / unparseable - all of which mean 'repair it', and
  // NONE of which mean 'the session ended'. That conflation was the v1.4 bug.
  function localBearerExpMs() {
    try {
      var raw = sessionStorage.getItem('sso_user');
      if (!raw) return null;
      var tok = JSON.parse(raw).idToken;
      if (!tok) return null;
      var p = payloadOf(tok).p;
      if (typeof p.exp !== 'number') return null;
      return p.exp > 1e12 ? p.exp : p.exp * 1000;
    } catch (e) { return null; }
  }

  // ---- state -------------------------------------------------------------
  var st = null;         // last good server answer
  var skewMs = 0;        // serverNow - clientNow, so a skewed clock cannot bounce us
  var lastFetchAt = 0, lastRenewAt = 0, renewFails = 0;
  // [SESSION-WATCH-REFUSAL 2026-09-04] Three counters, three different facts, and
  // they must never be conflated - that conflation IS rule 2 in the header:
  //   renewFails  the renew endpoint could not be REACHED (network/DNS/TLS). Only
  //               the .catch arm increments it.
  //   srvErrFails the server ANSWERED and could not renew right now (5xx, 404).
  //               Transient; the control stays live and the retry is genuine.
  //   refusedCode the server ANSWERED and refused durably for this session (a
  //               non-cap 403: inactive account, break-glass, local-test, a
  //               read-only QA token). /api/gate/session-info is pure-crypto by
  //               design (CORRECTIONS.md C6) and CANNOT know about any of those,
  //               so it keeps saying renewable:true - without latching it here the
  //               bar would re-render an identical dead 'Stay signed in' button on
  //               every click, forever. Latched, never cleared: none of these
  //               becomes untrue while this token lives.
  var srvErrFails = 0;
  var refusedCode = null, refusedText = null;
  var lastActivityAt = Date.now();   // opening the page IS activity
  var terminal = false;              // at-cap or redirecting: stop the poll
  var redirected = false;            // redirect latch (v1.4 semantics: one per page)
  var dismissed = false;             // per-tab dismissal of a non-renewable bar
  var capLogged = false;             // 'cap-reached' is logged once, not per tick
  var pollId = null, countId = null;
  var curMode = null;                // what the bar is currently rendering
  var curDeadline = null;            // SERVER-time instant the countdown counts to
  function srvNow() { return Date.now() + skewMs; }

  // ---- activity ----------------------------------------------------------
  // EXACTLY these four, passive+capture. Deliberately NOT mousemove (a cursor
  // resting on a trackpad renews forever), NOT focus/visibilitychange, and NOT
  // scroll - these dashboards auto-scroll sections into view as their 30+ XHRs
  // land, so scroll here is XHR-derived, not user-derived. None of the four can
  // be synthesised by a fetch completing, which is the required property: a page
  // that polls itself must never be able to hold a session open unattended.
  ['pointerdown', 'keydown', 'wheel', 'touchstart'].forEach(function (ev) {
    document.addEventListener(ev, function () {
      var n = Date.now();
      if (n - lastActivityAt > 30000) lastActivityAt = n;   // throttled write
    }, { passive: true, capture: true });
  });
  // lastActivityAt lives in a module var, NEVER in storage: a background tab in
  // another window must not keep this one alive.
  function isActive() {
    return (Date.now() - lastActivityAt) < IDLE_MS &&
           document.visibilityState !== 'hidden';
  }

  // ---- server ------------------------------------------------------------
  function fetchStatus() {
    lastFetchAt = Date.now();
    return fetch(STATUS_URL, {
      credentials: 'same-origin',
      headers: { 'Accept': 'application/json' }
    })
      .then(function (r) {
        if (r.status === 401) {
          // 'This request carried no valid it_session cookie' is NOT the same as
          // 'this user's session ended'. A localdev/QA bearer session has no cookie
          // at all (nothing in the codebase ever puts a localdev token in one), and
          // a bfcache restore after sign-out lands here too. Render the unknown
          // state and STOP. Never navigate on this. The old watcher's equivalent
          // branch is the bug this whole change exists to remove.
          sessLog('status-401', tokenFacts());
          st = null; terminal = true; stopPoll(); hideBar();
          return null;
        }
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(function (j) {
        if (!j || !j.ok) return null;
        skewMs = (typeof j.now === 'number') ? (j.now - Date.now()) : 0;
        st = j;
        return j;
      })
      .catch(function () {
        // NEVER redirect and NEVER claim expiry on 'could not measure'. Keep the
        // last known state and keep counting; if there is none, render NOTHING at
        // all. A blank page area is honest; a false "your session ended" is not.
        sessLog('status-unavailable', { url: STATUS_URL });
        return null;
      });
  }

  // Repair a stale per-tab Bearer. rbac-client.js attaches sso_user.idToken on every
  // /api/ call and rbac-middleware PREFERS a bad bearer over a good cookie (it only
  // reads the cookie when there is no Authorization header at all), so a tab whose
  // sibling renewed would 401 against a live session. Called on boot, on the peer
  // renewal signal, and after our own renewal.
  // [SESSION-WATCH-COOKIE-ONLY 2026-09-04] Some pages deliberately hold NO portable
  // copy of the credential: reporting/ai-usage-credits.html rebuilds its mirror as
  // { idToken: '', cookieSession: true } precisely so the tab rides the HttpOnly
  // cookie, and its own hasToken()/authHeaders() are written for that. Writing a
  // 10h cross-vhost session token into sessionStorage there would hand any XSS on
  // that page a long-lived portable credential the page had deliberately given up -
  // a silent posture REVERSAL, not a repair. The watcher itself never needs a
  // bearer: every fetch it makes is credentials:'same-origin'.
  function isCookieOnlyMirror() {
    try {
      var m = JSON.parse(sessionStorage.getItem('sso_user') || '{}') || {};
      return !!(m.cookieSession && !m.idToken);
    } catch (e) { return false; }
  }

  function adoptToken(j) {
    if (!j || !j.token) return false;
    if (isCookieOnlyMirror()) return false;   // see above: do not plant a bearer here
    try {
      var raw = JSON.parse(sessionStorage.getItem('sso_user') || '{}');
      if (raw.idToken === j.token) return false;
      raw.idToken = j.token;
      // email/name are repopulated because the cookieSession rebuild path writes a
      // mirror with neither, and the topbar renders from them.
      if (j.email) raw.email = j.email;
      if (j.name)  raw.name  = j.name;
      sessionStorage.setItem('sso_user', JSON.stringify(raw));
    } catch (e) { return false; }
    return true;
  }

  function resyncBearer() {
    // Cookie-only SSO tabs have no browser-readable bearer to repair.
    if (isCookieOnlyMirror()) return Promise.resolve(false);
    return fetch(TOKEN_URL, { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (j) {
        if (!adoptToken(j)) return false;
        sessLog('bearer-resync', tokenFacts());
        return true;
      })
      .catch(function () { return false; });
  }

  function renew(explicit) {
    var now = Date.now();
    // The throttle governs the SILENT path only. Suppressing an explicit click
    // would leave a button that looks live and does nothing, which is exactly the
    // fake control this file exists to avoid.
    if (!explicit && (now - lastRenewAt) < RENEW_MIN_MS) return Promise.resolve(false);
    lastRenewAt = now;
    return fetch(RENEW_URL, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Accept': 'application/json' }
    })
      .then(function (r) {
        if (r.status === 403) {
          // The SERVER refused: the 12h cap (code SESSION_ABSOLUTE_CAP), an inactive
          // account, break-glass, a local-test account, or a read-only QA token.
          // All of these are real, permanent-for-this-session answers - unlike a
          // network failure - so renewFails is NOT incremented: a refusal is not a
          // transport failure and must never produce the 'unreachable' copy.
          //
          // READ THE BODY. Only SESSION_ABSOLUTE_CAP is visible to
          // /api/gate/session-info (it is arithmetic on the token's own claims);
          // every other refusal lives in the database and that route is pure-crypto,
          // so deferring to its renewable flag for those would leave the bar
          // re-rendering the same dead button on every click. Latch instead.
          return r.json().catch(function () { return null; }).then(function (e) {
            var code = (e && e.code) ? String(e.code) : null;
            if (code !== 'SESSION_ABSOLUTE_CAP') {
              refusedCode = code || 'REFUSED';
              // The server's own sentence, when it sent one. Never invented here:
              // an unnamed reason renders as the number-free copy in renderBar.
              refusedText = (e && typeof e.error === 'string') ? e.error : null;
            }
            sessLog('renew-refused', Object.assign({ code: code || null }, tokenFacts()));
            return fetchStatus().then(function () { return false; });
          });
        }
        if (r.status === 401) {
          // An ANSWER, not a transport failure. Two live causes: this tab's bearer
          // went stale while the cookie moved on (rbac-middleware PREFERS a bad
          // bearer over a good cookie), or the request genuinely carried nothing.
          // Repair the bearer once and re-read; never increment renewFails, and
          // never render the 'unreachable' copy about a server that answered
          // immediately. rbac-client.js exempts this exact path from its
          // 401-means-redirect intercept so this stays OUR failure to handle.
          sessLog('renew-401', tokenFacts());
          return resyncBearer().then(fetchStatus).then(function () { return false; });
        }
        if (!r.ok) {
          // 5xx (including the SESSION_MINT_UNVERIFIABLE mint-race guard) or a 404
          // where this route is not proxied. The server ANSWERED, so this is not a
          // network fact and must not borrow the 'unreachable' copy - but it is
          // transient, so the control stays live and the retry is real. Record the
          // status: without it the log points support at the network instead of at
          // corpit-hub-api.
          srvErrFails++;
          sessLog('extend-failed', { status: r.status, srvErrs: srvErrFails });
          return false;
        }
        return r.json().then(function (j) {
          adoptToken(j);
          renewFails = 0; srvErrFails = 0;
          // Tell sibling tabs. They cannot see our sessionStorage (it is per tab) and
          // their own cookie now looks healthy, so without this they would keep an
          // expired bearer and 401 against a live session.
          try { localStorage.setItem(RENEW_STAMP, String(Date.now())); } catch (e) {}
          sessLog(explicit ? 'extend-ok' : 'renew-silent', tokenFacts());
          return fetchStatus().then(function () { return true; });
        });
      })
      .catch(function () {
        // ONLY a genuine transport failure reaches here now (network, DNS, TLS, an
        // aborted request). This is the one arm entitled to the 'unreachable' copy.
        renewFails++;
        sessLog('extend-failed', { transport: true, fails: renewFails });
        return false;
      });
  }

  // Sibling tab renewed: adopt the new token, refresh our view. Nothing here decides
  // expiry, so a forged storage event can only cause a harmless extra fetch.
  window.addEventListener('storage', function (e) {
    if (!e || e.key !== RENEW_STAMP || terminal) return;
    sessLog('peer-renewed', {});
    resyncBearer().then(fetchStatus).then(function () { tick(); });
  });

  // ---- css ---------------------------------------------------------------
  // createElement('style') + textContent. Allowed on subadmin (style-src 'self'
  // 'unsafe-inline'; with no style-src-elem declared it falls back to style-src).
  // Palette, tabular-nums, :focus-visible outline and @media print{display:none}
  // are preserved verbatim from v1.4.
  function ensureCss() {
    if (document.getElementById(CSS_ID)) return;
    var sc = document.createElement('style');
    sc.id = CSS_ID;
    sc.textContent =
      '#itcmd-sess-bar{position:fixed;left:0;right:0;bottom:0;z-index:99999;' +
        'font:13px/1.4 "IBM Plex Sans",system-ui,sans-serif;padding:10px 16px;' +
        'display:flex;align-items:center;gap:14px;justify-content:center;' +
        'flex-wrap:wrap;}' +
      '#itcmd-sess-bar b{font-variant-numeric:tabular-nums;}' +
      '#itcmd-sess-bar button{font:inherit;font-weight:600;border-radius:6px;' +
        'padding:6px 14px;cursor:pointer;}' +
      '#itcmd-sess-bar button:focus-visible{outline:2px solid currentColor;outline-offset:2px;}' +
      '#itcmd-sess-bar .itcmd-sess-x{background:transparent;border:0;font-weight:400;' +
        'opacity:.75;padding:6px 8px;}' +
      '#itcmd-sess-bar.on-dark{background:#3A2F14;color:#FFD27A;' +
        'border-top:1px solid #8A6D1F;' +
        'box-shadow:0 -1px 0 rgba(0,0,0,.4),0 -10px 28px -14px rgba(0,0,0,.7);}' +
      '#itcmd-sess-bar.on-dark .itcmd-sess-primary{background:#FFD27A;color:#241C07;border:0;}' +
      '#itcmd-sess-bar.on-dark .itcmd-sess-ghost{background:transparent;color:#FFD27A;' +
        'border:1px solid #8A6D1F;}' +
      '#itcmd-sess-bar.on-dark .itcmd-sess-x{color:#FFD27A;}' +
      '#itcmd-sess-bar.on-light{background:#FDF3D6;color:#6B4E07;' +
        'border-top:1px solid #E3C77A;' +
        'box-shadow:0 -1px 0 rgba(24,44,82,.10),0 -10px 26px -16px rgba(24,44,82,.34);}' +
      '#itcmd-sess-bar.on-light .itcmd-sess-primary{background:#6B4E07;color:#FFF8E6;border:0;}' +
      '#itcmd-sess-bar.on-light .itcmd-sess-ghost{background:transparent;color:#6B4E07;' +
        'border:1px solid #D9BE72;}' +
      '#itcmd-sess-bar.on-light .itcmd-sess-x{color:#6B4E07;}' +
      '@media print{#itcmd-sess-bar{display:none;}}';
    (document.head || document.documentElement).appendChild(sc);
  }

  // THEME by MEASUREMENT, not by selector. The v1.4 hooks
  // ('[data-theme="light"] X, body.light X') are both unreliable here: grep -c
  // data-theme is 0 in web/admin.html, web/console.html, reporting/index.html and
  // reporting/ai-usage-credits.html; reporting/index.html carries a body.light RULE
  // but its markup is a bare <body> and it renders DARK; and a prefers-color-scheme
  // arm would paint a pale slab across that dark page whenever the OS is light.
  // So read the ground the bar actually sits on and pick from that.
  function lumOf(rgb) {
    var m = String(rgb || '').match(/rgba?\(([^)]+)\)/);
    if (!m) return null;
    var p = m[1].split(',');
    if (p.length > 3 && parseFloat(p[3]) === 0) return null;   // fully transparent
    var r = parseFloat(p[0]) / 255, g = parseFloat(p[1]) / 255, b = parseFloat(p[2]) / 255;
    if (isNaN(r) || isNaN(g) || isNaN(b)) return null;
    var f = function (c) { return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4); };
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
  }

  function pickPalette(el) {
    if (!el) return;
    var L = null;
    try {
      if (document.body) L = lumOf(window.getComputedStyle(document.body).backgroundColor);
      if (L === null && document.documentElement) {
        L = lumOf(window.getComputedStyle(document.documentElement).backgroundColor);
      }
    } catch (e) {}
    // An unpainted ground is the browser default, which is white. Guessing dark
    // there would put a dark slab on a light page - the exact v1.4 complaint.
    if (L === null) L = 1;
    var want = (L >= 0.35) ? 'on-light' : 'on-dark';
    if (el.className !== want) el.className = want;
  }

  // ---- bar ---------------------------------------------------------------
  function fmt(ms) {
    var s = Math.max(0, Math.round(ms / 1000));
    return Math.floor(s / 60) + ':' + ('0' + (s % 60)).slice(-2);
  }

  function fmtClock(ts) {
    var d = new Date(ts);
    try {
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch (e) {
      return ('0' + d.getHours()).slice(-2) + ':' + ('0' + d.getMinutes()).slice(-2);
    }
  }

  // N comes from the SERVER's capMs, never a hardcoded 12: if the cap is ever
  // retuned in session-auth.js the bar must not keep quoting the old number.
  function capHours(capMs) {
    var h = (typeof capMs === 'number' && capMs > 0) ? capMs / 3600000 : null;
    if (h === null) return null;
    return (Math.abs(h - Math.round(h)) < 0.05) ? String(Math.round(h))
                                                : String(Math.round(h * 10) / 10);
  }

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  function button(id, cls, label, onClick) {
    var b = el('button', cls, label);
    b.id = id;
    b.type = 'button';
    b.addEventListener('click', onClick);
    return b;
  }

  function doSignOut() {
    sessLog('signout-from-bar', tokenFacts());
    redirected = true; terminal = true; stopPoll(); stopCount();
    // ONE sign-out for the whole site. it-topbar.js owns it wherever it is loaded;
    // the v1.4 local-teardown + POST /api/gate/logout fallback is DELETED - it was
    // an eighth sign-out implementation, and federated-logout repeats the whole
    // teardown server-side anyway. federated-logout is reachable on all three
    // vhosts, so this control always completes; hiding it would be as much a fake
    // control as showing a broken one.
    if (typeof window.itSignOut === 'function') { window.itSignOut(); return; }
    window.location.replace(LOGOUT_URL);
  }

  function doReauth() {
    // At the cap the ONLY honest exit is a real credential prompt.
    // /api/gate/federated-logout, NOT /login.html: it revokes, clears the cookie
    // AND ends the Entra session, so the next sign-in cannot be a silent re-issue.
    redirected = true; terminal = true; stopPoll(); stopCount();
    sessLog('redirect-to-login', tokenFacts());
    window.location.replace(LOGOUT_URL);
  }

  function doExtend(ev) {
    var b = ev && ev.currentTarget;
    var was = b ? b.textContent : null;
    if (b) { b.disabled = true; b.textContent = 'Extending...'; }
    renew(true).then(function (ok) {
      if (b) { b.disabled = false; if (was !== null) b.textContent = was; }
      if (ok) { hideBar(); return; }
      // Failure is NOT a verdict on the session. Re-run the state machine and let
      // it choose between 'unreachable' (transport) and whatever the server said.
      curMode = null;
      tick();
    });
  }

  function stopCount() { if (countId) { clearInterval(countId); countId = null; } }
  function stopPoll()  { if (pollId)  { clearInterval(pollId);  pollId  = null; } }

  function hideBar() {
    var b = document.getElementById(BAR_ID);
    if (b && b.parentNode) b.parentNode.removeChild(b);
    curMode = null; curDeadline = null;
    stopCount();
  }

  function paintCount() {
    var c = document.getElementById('itcmd-sess-count');
    if (!c || curDeadline === null) return;
    c.textContent = fmt(curDeadline - srvNow());
  }

  // renderBar(mode, msLeft, opts) builds/updates #itcmd-sess-bar. FOUR modes; see
  // the per-mode comments below. The bar is rebuilt ONLY when the mode changes, so
  // the 1s countdown never tears down a button the user is about to press.
  function renderBar(mode, msLeft, opts) {
    opts = opts || {};
    ensureCss();
    if (!document.body) return;
    var bar = document.getElementById(BAR_ID);
    if (bar && curMode === mode) {
      curDeadline = (mode === 'cap') ? null : (srvNow() + msLeft);
      pickPalette(bar);
      paintCount();
      return;
    }
    if (bar && bar.parentNode) bar.parentNode.removeChild(bar);
    stopCount();
    bar = el('div', null, null);
    bar.id = BAR_ID;
    bar.setAttribute('role', 'status');
    bar.setAttribute('aria-live', 'polite');

    var msg = el('span', null, null);
    bar.appendChild(msg);

    function withCount(prefix, suffix) {
      msg.textContent = '';
      msg.appendChild(document.createTextNode(prefix));
      var b = el('b', null, '--:--');
      b.id = 'itcmd-sess-count';
      msg.appendChild(b);
      if (suffix) msg.appendChild(document.createTextNode(suffix));
    }

    if (mode === 'warn') {
      // 'warn' - idle, renewable, room under the cap. The case the bar exists for.
      withCount('Your session expires in ', '');
      bar.appendChild(button('itcmd-sess-extend', 'itcmd-sess-primary',
        'Stay signed in', doExtend));
      sessLog('warn-bar-shown', Object.assign(
        { warnThresholdMin: WARN_MS / 60000 }, tokenFacts()));

    } else if (mode === 'cap') {
      // 'cap' - ONLY when the SERVER said renewable:false, or the cap instant has
      // actually passed. NEVER on capLeft <= WARN_MS and NEVER on renewFails:
      // entering this 15 minutes early would print a false statement AND remove a
      // button that still works. Copy stays future-tense until the cap passes.
      var n = capHours(opts.capMs);
      var limit = n ? (' past the ' + n + '-hour limit.') : ' any further.';
      if (typeof opts.endsAt === 'number' && (opts.endsAt - srvNow()) > 0) {
        msg.textContent = 'Your session ends at ' + fmtClock(opts.endsAt) +
                          ' and cannot be extended' + limit;
      } else {
        msg.textContent = n ? ('Your session has reached its ' + n + '-hour limit.')
                            : 'Your session has reached its limit.';
      }
      // The 'Stay signed in' button is REMOVED FROM THE DOM here - not disabled,
      // not dimmed, not pointer-events:none, all of which stay Tab-focusable and
      // Enter-activatable and are therefore fake controls. It simply is not built.
      bar.appendChild(button('itcmd-sess-again', 'itcmd-sess-primary',
        'Sign in again', doReauth));

    } else if (mode === 'refused') {
      // The server ANSWERED and refused durably for this session (see the refusal
      // latch in the state block) - an inactive account, break-glass, a local-test account, a
      // read-only QA token. Not the cap, so it must NOT borrow the cap's copy or
      // quote a limit the server never named. Like 'cap', the 'Stay signed in'
      // button is not built at all: it is a control that cannot complete.
      withCount('Your session can\'t be extended. It ends in ', '');
      if (opts.detail) {
        msg.appendChild(document.createTextNode(' (' + opts.detail + ')'));
      }
      bar.appendChild(button('itcmd-sess-again', 'itcmd-sess-primary',
        'Sign in again', doReauth));

    } else if (mode === 'declined') {
      // The server answered but could not renew right now (5xx / 404). Transient,
      // so the control stays - it can still succeed - but the copy must not claim
      // the server is unreachable when it replied, and must not claim the session
      // ended when nothing said that.
      withCount('The server couldn\'t extend your session just now. Retrying... ', '');
      bar.appendChild(button('itcmd-sess-extend', 'itcmd-sess-primary',
        'Try again', doExtend));

    } else if (mode === 'unreachable') {
      // 'unreachable' - we could not REACH the renew endpoint. A transport fact,
      // not a session fact, and it must never borrow the cap copy and must never
      // redirect. The extend control STAYS, because it can still succeed.
      withCount('We can\'t reach the server to extend your session. Retrying... ', '');
      bar.appendChild(button('itcmd-sess-extend', 'itcmd-sess-primary',
        'Try again', doExtend));

    } else {
      // 'readonly' - break-glass (or localdev, unreachable through the cookie
      // today). Countdown only: the server refuses these families by design, so an
      // extend button here would be a control that cannot complete. Carries a
      // dismiss so a 60-minute break-glass session during an incident is not pinned
      // under a bar for its last quarter.
      withCount('Your session expires in ', '');
      var x = button('itcmd-sess-x', 'itcmd-sess-x', 'x', function () {
        dismissed = true; hideBar();
      });
      x.setAttribute('aria-label', 'Dismiss');
      x.setAttribute('title', 'Dismiss');
      bar.appendChild(x);
    }

    // SIGN OUT is rendered in EVERY mode and always completes.
    bar.appendChild(button('itcmd-sess-out', 'itcmd-sess-ghost', 'Sign out', doSignOut));

    document.body.appendChild(bar);
    curMode = mode;
    curDeadline = (mode === 'cap') ? null : (srvNow() + msLeft);
    pickPalette(bar);
    paintCount();
    if (curDeadline !== null && !countId) countId = setInterval(paintCount, 1000);
  }

  function goLogin(expired) {
    if (redirected) return;
    redirected = true; terminal = true; stopPoll(); stopCount();
    sessLog('redirect-to-login', tokenFacts());
    var ret = encodeURIComponent(window.location.pathname + window.location.search);
    // [CORPIT-RETURN-HASH] keep the #view on the sign-in URL; login.js carries it through.
    var h = /^#[A-Za-z0-9_\-\/.:]{1,100}$/.test(window.location.hash) ? window.location.hash : '';
    window.location.replace('/login.html?return=' + ret + (expired ? '&expired=1' : '') + h);
  }

  // ---- state machine -----------------------------------------------------
  function tick() {
    if (terminal) return;
    if (!st) { hideBar(); return; }              // could not measure: render NOTHING
    var now = srvNow();
    var left    = (typeof st.exp === 'number') ? (st.exp - now) : null;
    var capLeft = (typeof st.absExp === 'number') ? (st.absExp - now) : Infinity;
    if (left === null) { hideBar(); return; }

    // (7) EXPIRED - but only the SERVER may conclude that. st can be up to REFETCH_MS
    // stale, and a background tab's setInterval is throttled to ~1/min regardless of
    // CHECK_MS, so a sibling tab's silent renewal is invisible here. Re-confirm before
    // navigating: if the server says we are still alive, keep the page; if the fetch
    // fails, keep the page. Only a fresh answer with a past exp, or a 401 that has
    // already latched terminal, may move the user.
    if (left <= 0) {
      return fetchStatus().then(function (j) {
        if (terminal) return;                                   // 401 handled it
        if (!j) { hideBar(); return; }                           // unreachable: stay put
        if (typeof j.exp === 'number' && (j.exp - srvNow()) > 0) { tick(); return; }
        goLogin(true);
      });
    }

    var shown = Math.min(left, capLeft);
    if (shown > WARN_MS) { hideBar(); return; }                 // (1) nothing to say
    if (Date.now() - lastFetchAt > REFETCH_MS) fetchStatus();   // freshness in the window

    // [SESSION-WATCH-CAP-DERIVED 2026-09-04] A renewal can only help while exp is
    // still BELOW absExp: mintSessionToken clamps every token to
    // exp = min(now+TTL, ait+CAP), so once the two coincide a renewal returns 200
    // and buys ZERO milliseconds. The server says so itself now (session-info's
    // renewable compares exp with absExp), but derive it here too - an older
    // corpit-hub-api, or a hand rollback of that one file, still answers
    // renewable:true right up to the cut, and the difference between the two
    // beliefs is whether the user gets a warning at all or is cut off mid-work
    // with none. Both must agree before a 'Stay signed in' button is drawn.
    var atCap = (typeof st.exp === 'number' && typeof st.absExp === 'number' &&
                 st.exp >= st.absExp);
    // (2) AT CAP - server verdict, or the same arithmetic the server does.
    if (st.kind === 'session' && (st.renewable === false || capLeft <= 0 || atCap)) {
      if (!capLogged) { capLogged = true; sessLog('cap-reached', tokenFacts()); }
      renderBar('cap', shown, { capMs: st.capMs, endsAt: st.absExp });
      if (capLeft <= 0) { terminal = true; stopPoll(); stopCount(); }
      return;
    }
    // (2b) DURABLE SERVER REFUSAL - the server answered 403 with something other
    // than the cap. session-info cannot see any of those reasons, so this latch is
    // the ONLY thing standing between a deactivated account and a bar that offers
    // the same dead button on every click until the token dies under them.
    if (refusedCode) {
      renderBar('refused', shown, { detail: refusedText });
      return;
    }
    // (3) NON-RENEWABLE FAMILY (break-glass).
    if (st.kind !== 'session') {
      if (!dismissed) renderBar('readonly', shown, { reason: st.reason });
      return;
    }
    // (4) RENEW ENDPOINT UNREACHABLE - a transport fact, never the cap copy.
    // Keep genuinely retrying (RENEW_MIN_MS-throttled, so at most one attempt a
    // minute): the copy says "Retrying..." and it must be TRUE. Without this the
    // bar would sit there claiming to retry while doing nothing, which is the same
    // fake-control failure as a dead button. A success resets renewFails to 0 and
    // the next tick leaves this state on its own.
    if (renewFails >= UNREACH_AT) {
      renew(false);
      renderBar('unreachable', shown, {});
      return;
    }
    // (4b) THE SERVER ANSWERED AND COULD NOT RENEW (5xx / 404). Same shape as (4) -
    // keep genuinely retrying so "Retrying..." is true - but say the true thing:
    // the server replied, so this is not a network failure and must not be dressed
    // as one.
    if (srvErrFails >= UNREACH_AT) {
      renew(false);
      renderBar('declined', shown, {});
      return;
    }
    // (5) SILENT RENEW: active, visible, renewable, room under the cap. Reaching
    // here means atCap is false, so this renewal really does move exp.
    if (isActive()) { renew(false); hideBar(); return; }
    // (6) idle or hidden: this is the case the bar exists for.
    renderBar('warn', shown, {});
  }

  // ---- boot --------------------------------------------------------------
  function boot() {
    ensureCss();
    sessLog('page-load', tokenFacts());

    // Re-pick the palette whenever the page's theme can have changed. A class or
    // data-theme flip on <html>/<body> is how every theme control on this platform
    // works, and the bar must follow it without a reload.
    try {
      var mo = new MutationObserver(function () {
        pickPalette(document.getElementById(BAR_ID));
      });
      var opt = { attributes: true, attributeFilter: ['class', 'data-theme', 'style'] };
      if (document.documentElement) mo.observe(document.documentElement, opt);
      if (document.body) mo.observe(document.body, opt);
    } catch (e) {}

    // Repair a per-tab bearer that is already stale or empty (a sibling tab renewed
    // while this one was closed). Cheap, once, at load -- but NOT on a page that
    // deliberately holds no bearer at all (see isCookieOnlyMirror above, and note
    // that the earlier draft of this comment named ai-usage-credits.html's
    // cookieSession mirror as a REASON to repair, which had it exactly backwards).
    // localBearerExpMs() returns null for 'absent', 'empty' AND
    // 'unparseable', and on ai-usage-credits.html empty is the DESIGNED steady
    // state ({ idToken: '', cookieSession: true }). Repairing a bearer nothing on
    // that page wants would fetch the 10h session token and park it in
    // sessionStorage - reachable by any XSS - to fix a problem that does not exist.
    var be = localBearerExpMs();
    var needBearer = !isCookieOnlyMirror() &&
                     ((be === null) || (be - Date.now() < WARN_MS));
    (needBearer ? resyncBearer() : Promise.resolve(false))
      .then(fetchStatus)
      .then(function () { tick(); });

    // Local tick only. The network is touched once at load, once per REFETCH_MS inside
    // the warn window, after every renew, on a peer renewal, and on becoming visible.
    // A naive 20s poll of the endpoint would be ~1,800 requests per tab per session on
    // every page on every vhost, sharing one rate-limit bucket with the page's own API
    // traffic. Cleared on every terminal state so an at-cap page (where the user stays
    // put) does not tick forever - the v1.4 interval was never cleared.
    pollId = setInterval(tick, CHECK_MS);

    document.addEventListener('visibilitychange', function () {
      pickPalette(document.getElementById(BAR_ID));
      if (document.visibilityState === 'visible' && !terminal) {
        fetchStatus().then(function () { tick(); });
      }
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
