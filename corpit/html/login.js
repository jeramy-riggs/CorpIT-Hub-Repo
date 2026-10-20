/* CorpIT shared sign-in behaviour.
 *
 * Externalised from the page on 2026-09-02 when the sign-in page was replaced
 * with the CorpIT "Command center" design, which is authored with ZERO inline
 * script and ZERO on* handlers. That is not decoration: the security-headers
 * snippet ships CSP as Report-Only with a note to promote it after violation
 * review, and script-src 'self' would kill an inline <script>. Promoting the
 * CSP must not be able to break sign-in on every host at once.
 *
 * Logic is carried over from the previous page unchanged except where noted.
 */
(function () {
  'use strict';

  var COOKIE = 'it_auth';
  var COOKIE_VAL = 'granted_2024';
  // Was '/admin.html'. This page is now served on every vhost (accessportal,
  // subadmin, directory, corpit) from one copy, and /admin.html exists only on
  // corpit -- as a cross-host fallback it is a dead end. '/' is host-portable
  // and matches what the Entra button already fell back to.
  var POST_LOGIN_URL = '/';

  function $(id) { return document.getElementById(id); }

  /* -- Deep-link return support --------------------------------------------
   * Pages bounce here with ?return=<path>. Only ever honour same-origin
   * absolute paths (single leading slash), never login.html itself, so the
   * parameter cannot be abused as an open redirect. */
  function sanitizeReturn(r) {
    if (!r) return null;
    r = String(r);
    if (r.length > 2000) return null;
    if (/[\u0000-\u001f\\]/.test(r)) return null;
    // Cross-host allowlist: exactly the approver console on the accessportal vhost.
    if (r === 'https://accessportal.nrpi.local/approver.html') return r;
    if (!/^\/[A-Za-z0-9_\-.]/.test(r)) return null;
    if (r.toLowerCase().indexOf('/login.html') === 0) return null;
    return r;
  }

  var _qs = new URLSearchParams(location.search);
  var _returnTarget = sanitizeReturn(_qs.get('return'));

  /* [CORPIT-RETURN-HASH] 2026-10-14. A deep link such as /identity-diag.html#projects
   * lost its #view at sign-in: the fragment never reaches the server, so ?return=
   * and every hop after it carry path + query only, and the visitor landed on the
   * page's default view. The browser does keep the fragment across nginx's 302, so
   * it is on THIS page's URL. Hold it in this tab's sessionStorage keyed to the
   * return path; auth-complete.js (and showRedirectAndGo below) put it back.
   * Only a plain view name is kept -- no '=' or '&' -- so a token-shaped fragment
   * is never carried, and the clear-the-hash block further down still runs. */
  var RETURN_HASH_KEY = 'it_return_hash';
  var RETURN_HASH_RE = /^#[A-Za-z0-9_\-\/.:]{1,100}$/;
  var _returnHash = (_returnTarget && _returnTarget.charAt(0) === '/' &&
    RETURN_HASH_RE.test(window.location.hash)) ? window.location.hash : '';
  try {
    if (_returnHash) {
      sessionStorage.setItem(RETURN_HASH_KEY,
        JSON.stringify({ path: _returnTarget, hash: _returnHash, at: Date.now() }));
    } else if (_returnTarget) {
      sessionStorage.removeItem(RETURN_HASH_KEY);
    }
  } catch (e) { /* storage blocked: the page still opens, on its default view */ }

  /* -- status line ---------------------------------------------------------- */
  function showStatus(msg, type) {
    var el = $('status-msg');
    if (!el) return;
    el.textContent = msg;
    el.className = 'flash ' + (type === 'err' ? 'error' : (type === 'ok' ? 'ok' : 'info'));
    el.style.display = 'block';
  }
  function fieldError(id, msg) {
    var el = $(id);
    if (!el) return;
    el.textContent = msg;
    el.style.display = msg ? 'block' : 'none';
  }

  /* -- cookies -------------------------------------------------------------- */
  function setCookie(n, v, h) {
    document.cookie = n + '=' + v + ';expires=' +
      new Date(Date.now() + h * 3600000).toUTCString() + ';path=/;SameSite=Lax;Secure';
  }
  function getCookieVal(n) {
    var c = document.cookie.split(';').map(function (x) { return x.trim(); })
      .find(function (x) { return x.indexOf(n + '=') === 0; });
    return c ? c.split('=')[1] : null;
  }
  // Cookie is the same value nginx enforces; its own expires= governs lifetime.
  //
  // DEAD SINCE 2026-09-04 (the re-mint short-circuit further down this file),
  // DELIBERATELY LEFT IN PLACE FOR THIS DEPLOY ONLY. isSessionValid() and hasLiveToken() below (and getCookieVal
  // above, reachable only through isSessionValid) have no caller any more: the
  // already-signed-in short-circuit stopped gating on the legacy it_auth cookie -
  // which is set only by the break-glass branch, carries a 1h TTL and has not been
  // extended by anything since the v1.4 watcher's refreshCookie() was deleted - and
  // probes the server instead. Removing them here would widen a diff that deploy
  // STEP 5 has to be revertable on its own, so they go in a follow-up.
  // DO NOT reinstate either of them as a guard on the short-circuit: gating a live
  // SSO session on a cookie nothing extends is exactly the bug that made FIX 2
  // unreachable for every ordinary user.
  function isSessionValid() { return getCookieVal(COOKIE) === COOKIE_VAL; }

  // Drop a leftover legacy cookie + stale tab state so the form is usable again.
  function clearStaleSession() {
    try {
      sessionStorage.removeItem('sso_user');
      sessionStorage.removeItem('auth_expiry');
    } catch (e) {}
    document.cookie = COOKIE + '=; Max-Age=0; path=/';
    showStatus('Your session has ended. Please sign in again.', 'err');
  }

  // A tab-local, unexpired token is what protected pages actually require
  // (sessionStorage is per-tab; the cookie alone is not enough to enter).
  function hasLiveToken() {
    try {
      var raw = sessionStorage.getItem('sso_user'); if (!raw) return false;
      var tok = JSON.parse(raw).idToken; if (!tok) return false;
      var parts = String(tok).split('.');
      var seg = (parts.length === 3) ? parts[1] : parts[0];
      seg = seg.replace(/-/g, '+').replace(/_/g, '/');
      while (seg.length % 4) seg += '=';
      var p = JSON.parse(atob(seg));
      if (typeof p.exp !== 'number') return false;
      var ms = p.exp > 1e12 ? p.exp : p.exp * 1000;
      return ms > Date.now() + 30000;
    } catch (e) { return false; }
  }

  function showRedirectAndGo() {
    var f = $('login-form'), r = $('redirect-msg');
    if (f) f.style.display = 'none';
    if (r) r.style.display = 'block';
    try { sessionStorage.removeItem(RETURN_HASH_KEY); } catch (e) {}
    setTimeout(function () {
      window.location.replace(_returnTarget ? _returnTarget + _returnHash : POST_LOGIN_URL);
    }, 600);
  }

  /* -- Entra --------------------------------------------------------------- */
  /* The OAuth implicit flow is retired. This hands off to the platform front
   * door, which runs authorization-code + PKCE and exchanges the code
   * server-side. No token of any kind reaches this page.
   * The href is set here rather than in the markup so the return target rides
   * along; the markup ships a bare /api/auth/login so the button still works
   * if script is blocked entirely. */
  /* [CORPIT-SSO-AUTOHANDOFF] 2026-09-22. Arriving with ?return= means a GATE
   * BOUNCE, not a deliberate visit to the sign-in page: the visitor clicked a link
   * and nginx sent them to a vhost they hold no session for. corpit is
   * SSO_AUTH_ORIGIN and already holds the SSO session, so /api/auth/login
   * round-trips through it and mints this host's session with no credential
   * prompt. Waiting for a click here bought nothing but the sign-in screen.
   *
   * Only fires where a loop cannot form:
   *  - ?return= present. A bare /login.html still shows the form.
   *  - no ?sso=. That is how a FAILED sign-in comes back, and oidc-auth.js sends
   *    those to /login.html?sso=<reason> with NO return=, so this is belt and
   *    braces rather than the only guard.
   *  - one attempt per 20s per origin, recorded BEFORE navigating away. If the
   *    handoff completes but the gate still refuses, the second bounce lands
   *    inside that window and stops, showing the button and saying why.
   *  - if sessionStorage throws (private mode, blocked storage) the guard cannot
   *    be trusted, so the hop is SKIPPED and the page behaves exactly as it does
   *    today. Failing closed costs one click; failing open costs a redirect loop.
   * Sign-out is already protected: the ?signedout/?signout early return above
   * runs before any of this. */
  function autoHandoff() {
    /* [MYPROFILE-SIGNIN] 2026-09-23. A host whose sign-in page is meant to be SEEN
     * opts out with <html data-sso-auto="off"> (myprofile.nrpi.local): the page says
     * what the app is, then one click. Every other host is unchanged. */
    if (document.documentElement.getAttribute('data-sso-auto') === 'off') return false;
    if (!_returnTarget || _qs.has('sso')) return false;
    var now = Date.now(), last = 0;
    try {
      last = parseInt(sessionStorage.getItem('sso_auto_at') || '0', 10) || 0;
      if (now - last < 20000) {
        /* Refused: the previous hop landed straight back here. Say so and stop --
         * and return TRUE, because this is the page's final state. Every caller
         * follows a false with its own status line, which used to overwrite this
         * message with 'Sign in to continue' or 'Your session has ended' before
         * anyone could read it (CHG-ARCH-04). The stale tab identity goes too, so
         * the next visit starts clean instead of re-trusting it. */
        sessionStorage.removeItem('sso_user');
        sessionStorage.removeItem('auth_expiry');
        showStatus('Automatic sign-in did not complete. Please use the button below.', 'err');
        return true;
      }
      sessionStorage.setItem('sso_auto_at', String(now));
      /* Drop the stale tab-local identity without clearStaleSession()'s "your
       * session has ended" copy -- nothing has ended from the user's point of
       * view, they are mid-hop between two vhosts. */
      sessionStorage.removeItem('sso_user');
      sessionStorage.removeItem('auth_expiry');
    } catch (e) { return false; }
    showStatus('Signing you in\u2026', 'info');
    window.location.replace('/api/auth/login?rd=' + encodeURIComponent(_returnTarget));
    return true;
  }

  var sso = $('btn-sso');
  if (sso) {
    sso.setAttribute('href',
      '/api/auth/login?rd=' + encodeURIComponent(_returnTarget || '/'));
  }

  /* -- live service status -------------------------------------------------
   * The header status line opens making NO claim and only turns green once
   * /api/health has actually answered. The previous page hardcoded "Identity
   * services operational", which kept saying so straight through an outage --
   * the same failure mode as an nginx error_page that rewrites a 5xx to 200.
   * /api/health is anonymous by design and returns {status, timestamp} only,
   * so this leaks nothing to someone who has not signed in. */
  /* FU-20 (2026-09-08): /api/health proves the hub API is up and its DB answers
   * SELECT 1 -- which is exactly what sign-in needs, and nothing more. 'CorpIT
   * platform online' claimed the whole platform off that one probe. Name what
   * was measured. */
  (function serviceStatus() {
    var box = $('svc-status'), txt = $('svc-status-text');
    if (!box || !txt) return;
    function set(state, msg) { box.setAttribute('data-state', state); txt.textContent = msg; }
    fetch('/api/health', { cache: 'no-store', credentials: 'omit' })
      .then(function (r) {
        if (!r.ok) throw new Error('http ' + r.status);
        return r.json();
      })
      .then(function (j) {
        if (j && j.status === 'ok') set('ok', 'Sign-in service online');
        else set('degraded', 'Sign-in service degraded');
        // Platform version rides along on the health response -- no extra
        // request, and it cannot disagree with what is actually deployed.
        // textContent, never innerHTML; the API also semver-validates it.
        var v = $('app-version');
        if (v && j && j.version) v.textContent = ' \u00B7 v' + j.version;
      })
      // A probe that FAILED means we could not measure -- not that sign-in is
      // broken. Saying "Sign-in service unavailable" while someone is signing in
      // perfectly well is as wrong as a hardcoded green. Report the honest thing.
      .catch(function () { set('unknown', 'Sign-in status unavailable'); });
  })();

  /* Nothing legitimate puts a token in the fragment any more, so refuse to act
   * on one at all rather than leave a second, weaker way in. Clear it so a
   * stale bookmark or Back-button entry cannot keep re-presenting it. */
  if (window.location.hash) {
    window.history.replaceState(null, '',
      window.location.pathname + window.location.search);
  }

  /* -- break-glass local sign-in -------------------------------------------
   * The 'itam' account only, verified server-side (password + TOTP). No
   * credentials live in this page. On success the API sets the real it_session
   * cookie itself (breakglass-routes.js), which is what the gate accepts. */
  var localForm = $('local-section');
  if (localForm) {
    localForm.addEventListener('submit', function (ev) {
      ev.preventDefault();
      var btn = $('btn-local');
      var p = $('login-pass').value || '';
      var otp = ($('login-otp').value || '').replace(/\s/g, '');
      if (!p || !/^\d{6}$/.test(otp)) {
        fieldError('local-error', 'Enter the password and the current 6-digit code');
        return;
      }
      fieldError('local-error', '');
      btn.disabled = true;
      fetch('/api/breakglass/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ password: p, totp: otp })
      })
        .then(function (r) { return r.json().then(function (j) { return { status: r.status, body: j }; }); })
        .then(function (res) {
          btn.disabled = false;
          if (res.status === 200 && res.body.token) {
            try {
              sessionStorage.setItem('sso_user', JSON.stringify({
                name: 'Break-glass (itam)', email: 'itam@local', idToken: res.body.token
              }));
            } catch (e) {}
            setCookie(COOKIE, COOKIE_VAL, 1);
            showRedirectAndGo();
          } else if (res.status === 429) {
            fieldError('local-error', 'Locked out after repeated failures. Wait 15 minutes.');
          } else if (res.status === 503) {
            fieldError('local-error', 'Break-glass is not enrolled on this server.');
          } else {
            fieldError('local-error', 'Authentication failed');
            $('login-pass').value = ''; $('login-pass').focus();
          }
        })
        .catch(function () {
          btn.disabled = false;
          fieldError('local-error', 'Could not reach the API');
        });
    });
  }

  /* Break-glass is only OFFERED where it can actually complete. The page is one
   * shared file across four vhosts, but /api/breakglass/* is reachable on corpit
   * only -- on the others it is gated, so the form would render a password+TOTP
   * box whose submit could never succeed. Rather than widen an authentication
   * endpoint onto three more hostnames, the control stays hidden unless the
   * server confirms break-glass is enrolled AND reachable from this host. */
  var localDetails = $('local-details');
  if (localDetails) {
    fetch('/api/breakglass/status', { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(); })
      .then(function (st) { if (st && st.enrolled === true) localDetails.hidden = false; })
      .catch(function () { /* not available here - leave it hidden */ });
  }

  /* -- arrival state -------------------------------------------------------- */
  if (_qs.has('expired')) showStatus('Your session expired. Please sign in again.', 'err');

  /* /api/auth/callback redirects back here with ?sso=<reason> when a sign-in is
   * refused. Reasons are a fixed server-side vocabulary, but they arrive via the
   * URL, so map them to fixed strings and never render the raw value. */
  var _ssoMsg = {
    expired: 'That sign-in took too long. Please try again.',
    state_mismatch: 'Sign-in could not be verified. Please start again from this page.',
    nonce_mismatch: 'Sign-in could not be verified. Please start again from this page.',
    wrong_tenant: 'That account is not in this directory.',
    id_token_rejected: 'Microsoft returned a token we could not verify. Please try again.',
    token_endpoint: 'Microsoft refused the sign-in. Please try again.',
    token_unreachable: 'We could not reach Microsoft. Please try again in a moment.',
    no_username: 'Microsoft did not return a username for that account.',
    not_configured: 'Single sign-on is not configured on this host.',
    handoff_invalid: 'That sign-in link is no longer valid. Please sign in again.',
    handoff_replayed: 'That sign-in link was already used. Please sign in again.',
    access_denied: 'Sign-in was cancelled, or your account is not assigned to this application.'
  };
  if (_qs.has('sso')) {
    showStatus(_ssoMsg[_qs.get('sso')] || 'Sign-in could not be completed. Please try again.', 'err');
  }

  /* Sign-out lands here. signedout=1 means /api/gate/logout returned 204 and the
   * HttpOnly it_session cookie is gone. signout=failed means the call did not get
   * through, so this browser may still hold a valid session - say so plainly
   * instead of implying a clean sign-out. */
  if (_qs.get('signedout') === '1') {
    showStatus('You\u2019re signed out.', 'ok');
  } else if (_qs.get('signout') === 'failed') {
    showStatus('We couldn\u2019t reach the server to end your session. Sign in again, ' +
      'or close the browser to be sure.', 'err');
  }

  // Never short-circuit straight back into the app on the sign-out landing.
  if (_qs.has('signedout') || _qs.has('signout')) return;

  /* CORPIT-SESSION-REMINT (FIX 2, 2026-09-04). The old guard tested
   * isSessionValid(), i.e. the legacy it_auth cookie - set only by the break-glass
   * branch below, with a 1h TTL, and no longer extended by anything since the v1.4
   * watcher's refreshCookie() was deleted. Gating on it meant ordinary SSO users
   * never reached this branch at all. Probe the server instead.
   * ?switch=1 is the deliberate escape hatch: it reaches the form (and therefore
   * the break-glass control) even while holding a valid session, which matters in
   * an Entra outage - the one time you need break-glass is the one time you cannot
   * federate out to get to the form.
   * The ?signedout/?signout early return above still protects the sign-out
   * landing; without it, sign-out would resurrect the session. */
  if (!_qs.has('switch')) {
    /* Step 1: does a real session exist here? /api/gate/refresh is UNCHANGED - it
     * verifies the HttpOnly it_session cookie and re-sets the SAME token (cookie
     * transport only, no mint), which is also what migrates a host-only cookie to
     * the Domain form. That migration is the other half of why it has to run
     * FIRST. It stays API_PUBLIC and CSRF-exempt precisely because it cannot
     * issue anything; the leftover it_auth cookie it replaced could not be
     * cleared by a sign-out on another *.nrpi.local host, and trusting it alone
     * sent users into a login.html -> gated page -> login.html loop. */
    fetch('/api/gate/refresh', { method: 'POST', credentials: 'same-origin' })
      .then(function (r) {
        if (r.status === 401) {
          // No session HERE. If this was a gate bounce, hop through the auth
          // origin instead of asking for a click; see [CORPIT-SSO-AUTOHANDOFF].
          if (autoHandoff()) return;
          // No session. Only say 'your session has ended' if this browser actually
          // thought it had one; otherwise leave the form clean for a first visit.
          var had = false;
          try { had = !!sessionStorage.getItem('sso_user'); } catch (e) {}
          if (had) clearStaleSession();
          else if (_returnTarget) showStatus('Sign in to continue to your page', 'info');
          return;
        }
        if (!(r.status === 204 || r.ok)) {
          /* The route is not reachable on this vhost (accessportal and directory
           * have no /api/gate/refresh block). That is a ROUTING gap, not a dead
           * session: never claim the session ended, and never dead-end the page.
           *
           * [CORPIT-SIGNIN-NOLOOP] 2026-09-23. This host cannot verify the session,
           * so the tab-local identity (sessionStorage 'sso_user') is the only hint,
           * and it used to be trusted unconditionally: showRedirectAndGo() sent the
           * visitor straight back to the page they came from. Anyone who arrived by
           * GATE BOUNCE (?return=) had just been refused by that page, so it bounced
           * them here again, about once a second, for as long as the tab stayed open
           * (2026-09-22: one client, 4,113 laps in 68 minutes). Every lap also
           * probed /api/breakglass/status, which shared its rate-limit bucket with
           * /api/auth/, so the same address was then refused sign-in on every host.
           *
           * Rules now:
           *  - ?return= present: the gate has ALREADY refused this session, so the
           *    tab-local identity proves nothing here. Never redirect on it; hop
           *    through the auth origin instead (autoHandoff, which has its own 20s
           *    guard and shows the button when the hop does not complete).
           *  - no ?return= (a deliberate visit): the redirect to '/' still happens,
           *    but at most once per 20s per tab. A repeat inside that window is a
           *    loop, not a visitor, so the form is shown instead. If sessionStorage
           *    throws, the guard cannot be trusted and nothing redirects. */
          if (!_returnTarget) {
            var live = false;
            try {
              var goAt = parseInt(sessionStorage.getItem('sso_go_at') || '0', 10) || 0;
              live = !!sessionStorage.getItem('sso_user') && (Date.now() - goAt) >= 20000;
              if (live) sessionStorage.setItem('sso_go_at', String(Date.now()));
            } catch (e) { live = false; }
            if (live) { showRedirectAndGo(); return; }
          }
          /* No /api/gate/refresh on this vhost (directory 405, accessportal 404),
           * so the 401 branch above can never run here -- but /api/auth/login is
           * routed on all five, so the gate bounce can still be made silent.
           * Same guard, same loop protection. [CORPIT-SSO-AUTOHANDOFF] */
          if (autoHandoff()) return;
          if (_returnTarget) showStatus('Sign in to continue to your page', 'info');
          return;
        }
        /* Step 2: the session is real - now genuinely re-mint it, so passing back
         * through sign-in grants a fresh window (subject to the 12h cap). This is
         * the whole point of FIX 2: /api/gate/refresh re-sets the SAME token, so
         * on its own this page granted no new lifetime at all.
         * POST /api/rbac/session, NOT /api/gate/refresh: the refresh route is in
         * server.js API_PUBLIC and therefore bypasses the CORPIT-CSRF origin check,
         * and '.local' is not a public suffix, so a CSRF-exempt mint endpoint would
         * be reachable from every *.nrpi.local origin. /api/rbac/session is behind
         * loadCurrentUser (is_active, break-glass and local-test refusals) and the
         * CSRF guard, which for a cookie-authenticated POST requires a positively
         * same-origin verdict. See CORRECTIONS.md C4.
         * A FAILED re-mint must never sign anyone out: they still hold a valid
         * session, so enter on it. Re-mint is a bonus, not a precondition - and it
         * is not proxied on every vhost that serves this shared page, so a 404 or
         * an unreachable host has to degrade silently. */
        var capped = false;
        return fetch('/api/rbac/session', { method: 'POST', credentials: 'same-origin',
                                            headers: { 'Accept': 'application/json' } })
          .then(function (m) {
            if (m.status === 403) {
              /* The 12h absolute cap is the ONE refusal this page must act on. The
               * session genuinely cannot be extended again, so redirecting into the
               * app would hand the user a countdown with only one ending, and
               * leaving them here would loop them through a sign-in page that
               * cannot sign them in. Send them to a REAL sign-in:
               * /api/gate/federated-logout revokes locally AND ends the Entra
               * session, so the next sign-in is a genuine credential prompt that
               * starts a fresh 12h window. It clears it_session on the way out, so
               * coming back here cannot re-enter this branch - no loop. It is
               * reachable on every vhost that serves this page (corpit has its own
               * block at corpit.nrpi.local.conf:588; the snippet vhosts get it from
               * snippets/corpit-hub-sso.conf:193), so this is not a dead control.
               * EVERY OTHER 403 - inactive account, break-glass, local-test, a
               * read-only QA token - must NOT sign anyone out from here. Those fall
               * through and the user enters on the session they already hold; the
               * watcher and the token's own exp are what enforce those. */
              return m.json().catch(function () { return null; }).then(function (e) {
                if (e && e.code === 'SESSION_ABSOLUTE_CAP') {
                  capped = true;
                  /* CORPIT-CAP-COPY-FROM-SERVER (2026-09-04): the number comes from
                   * the server's capMs, exactly as it-session-watch.js derives its
                   * own copy. A hardcoded '12-hour' here would contradict the bar on
                   * the very next screen the day SESSION_ABS_CAP_MS is retuned, and
                   * neither screen would look like the stale one. No capMs (an older
                   * API, or a cap that could not be measured) -> say it number-free
                   * rather than invent one. */
                  var _h = null;
                  if (e && typeof e.capMs === 'number' && e.capMs > 0) {
                    var _n = e.capMs / 3600000;
                    _h = (Math.abs(_n - Math.round(_n)) < 0.05) ? String(Math.round(_n))
                                                                : String(Math.round(_n * 10) / 10);
                  }
                  showStatus((_h ? ('You\u2019ve reached the ' + _h + '-hour limit for a single sign-in. ')
                                 : 'You\u2019ve reached the limit for a single sign-in. ') +
                    'Taking you to sign in again\u2026', 'info');
                  window.location.replace('/api/gate/federated-logout');
                }
                return null;
              });
            }
            return m.ok ? m.json() : null;
          })
          .then(function (j) {
            if (j && j.ok) {
              /* Renewal refreshes the HttpOnly cookie. Clear any old SSO bearer
               * mirror so later API calls keep using that cookie. */
              try {
                var raw = JSON.parse(sessionStorage.getItem('sso_user') || '{}');
                raw.idToken = '';
                raw.cookieSession = true;
                if (j.email) raw.email = j.email;
                if (j.name)  raw.name  = j.name;
                sessionStorage.setItem('sso_user', JSON.stringify(raw));
              } catch (e) {}
              /* Notify sibling tabs that their cookie was renewed. */
              try { localStorage.setItem('itcmd_sess_renewed', String(Date.now())); } catch (e) {}
            }
          })
          .catch(function () { /* re-mint unavailable: enter on the existing session */ })
          .then(function () { if (!capped) showRedirectAndGo(); });
      })
      .catch(function () {
        /* Network error. Leave the sign-in form usable and say nothing false. */
        if (_returnTarget) showStatus('Sign in to continue to your page', 'info');
      });
    return;
  }

  /* -- NO-AUTO-SIGNIN (2026-09-03) ----------------------------------------
   * This page never starts an identity-provider round trip on its own. The
   * visitor clicks the Microsoft button, always.
   *
   * What used to be here: when ?return= was present - i.e. on EVERY bounce
   * from a protected page - the script called
   *     location.replace(<entra authorize url>)
   * immediately, so a visitor was handed to login.microsoftonline.com before
   * they had touched anything. It was introduced to hide the extra hop caused
   * by host-only sessions (each vhost holds its own cookie, so crossing hosts
   * lands here even when you signed in a minute ago next door).
   *
   * Removed on Jeramy's instruction. Two reasons it was worth the extra click:
   * an automatic redirect to an external identity provider is not something
   * the user asked for, and it actively fought sign-out - the Entra session
   * outlives the local one, so the auto-redirect signed people straight back
   * in after they had deliberately signed out.
   *
   * The retry-budget helpers (AUTO_KEY / autoState / noteAuto) went with it;
   * they existed only to keep the auto-redirect from looping.
   *
   * If the cross-vhost hop ever needs smoothing again, do it with a visible
   * affordance - a button that says where it is sending you - not a redirect
   * that fires before the page is read. */

  if (_returnTarget) showStatus('Sign in to continue to your page', 'info');
})();
