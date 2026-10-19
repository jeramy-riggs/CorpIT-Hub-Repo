// rbac-client.js — IT Command RBAC foundation v1.3
// v1.3 adds View-As impersonation for super-admins (client-side only).
//   - me() returns simulated profile when view-as is active
//   - realMe() always returns the true logged-in identity
//   - viewAs(data) / exitViewAs() / isViewingAs() / viewAsTarget()
//   - Persists across pages via sessionStorage('itcmd_viewas')
//   - Amber banner with Exit button injected at top of page
// v1.2 features (MutationObserver, token attach, /me cache, canAccess/canAdmin,
// applyDomGuards) preserved.
(function(){
  'use strict';

  var STORAGE_KEY = 'sso_user';
  var ME_ENDPOINT = '/api/rbac/me';
  var LOGIN_PATH  = '/login.html';
  var API_PREFIX  = '/api/';
  // The vendor-integration surface. It was '/beta-api/' on ITAM and that prefix
  // does not exist on this host at all, so the two isApiUrl() lines that tested
  // for it matched nothing: every warranty / Kandji / Intune-Graph / ABM /
  // endpoints-sync call went out with no bearer and no 401 inspection.
  var HUB_PREFIX  = '/hub-api/';
  var VIEWAS_KEY  = 'itcmd_viewas';
  var NOTICE_ID    = 'itcmd-rbac-notice';
  var GUARD_CSS_ID = 'itcmd-rbac-guard-css';
  var BANNER_ID   = 'itcmd-viewas-bar';

  function getIdToken() {
    try {
      var raw = sessionStorage.getItem(STORAGE_KEY);
      if (!raw) return null;
      var parsed = JSON.parse(raw);
      return parsed && parsed.idToken ? parsed.idToken : null;
    } catch(e) { return null; }
  }

  // Parsed rather than prefix-matched: a string test only recognises the exact
  // forms it was written for, while a URL parser normalises several it does not
  // (a tab or newline inside the path, '/x/..//api/y'). One same-origin test and
  // one pathname test then cover relative, absolute and query-bearing URLs
  // alike -- and hub calls are absolute (WARRANTY_BASE is origin + '/hub-api'),
  // which is exactly the shape the four old branches all missed.
  function isApiUrl(u) {
    if (!u) return false;
    try {
      var url = new URL(u, window.location.href);
      if (url.origin !== window.location.origin) return false;
      return url.pathname.indexOf(API_PREFIX) === 0 ||
             url.pathname.indexOf(HUB_PREFIX) === 0;
    } catch (e) { return false; }
  }

  // The session RENEWAL endpoint, matched on the parsed PATHNAME and exactly - not
  // as a substring, which '/api/rbac/session-anything' would also satisfy - so the
  // 401 exemption below can never widen to the rest of the RBAC admin API.
  function isRenewUrl(u) {
    if (!u) return false;
    try { return new URL(u, window.location.href).pathname === '/api/rbac/session'; }
    catch (e) { return false; }
  }

  // The per-tab bearer REPAIR endpoint, matched on the exact PATHNAME. The session
  // watcher's resyncBearer() (it-session-watch.js) GETs /api/auth/token to re-mint a
  // stale per-tab bearer, and it owns that request's failure: a NO_SESSION 401 there
  // means "could not repair the bearer", not "your session ended". Without this
  // exemption the wrapped fetch below would hard-redirect a bearer-session-without-
  // cookie (localdev/QA, bfcache restore) to /login.html BEFORE the watcher's own
  // 401-tolerant handling runs - the exact lockout the STATUS_URL/RENEW_URL
  // exemptions exist to prevent. A real expired user is still redirected: their
  // actual /api/ or /hub-api/ data loads 401 through this same wrapper.
  function isTokenUrl(u) {
    if (!u) return false;
    try { return new URL(u, window.location.href).pathname === '/api/auth/token'; }
    catch (e) { return false; }
  }

  // One redirect per page. A session that expires with the tab open 401s every
  // table load at the same instant; without the latch each of them assigns
  // location.href, and the login page must never be bounced at itself.
  var _authRedirected = false;
  function goLoginExpired() {
    if (_authRedirected) return;
    if (window.location.pathname === LOGIN_PATH) return;
    _authRedirected = true;
    window.location.href = LOGIN_PATH + '?expired=1&return=' +
      encodeURIComponent(window.location.pathname + window.location.search);
  }

  // The observability INGEST endpoint, matched on the exact PATHNAME. it-observe.js
  // loads after this file on purpose (it needs the bearer-attaching wrapper), which
  // means its background flush - a 10-second interval the user never asked for -
  // runs through the 401 branch below. A 401 there means "the report could not be
  // filed"; it is not a verdict on the session, and it must not be able to pull a
  // user off a page they are working on. The reporter is also the one caller that
  // CANNOT be trusted to be a session probe: it fires on a timer whether or not the
  // page is doing anything, so it would be the first request to 401 after a session
  // ends and would hard-navigate mid-edit, ahead of the session watcher that owns
  // that decision. Ingest only - the dashboard's own /api/observe/ GETs are ordinary
  // page reads and keep the default redirect.
  function isObserveUrl(u) {
    if (!u) return false;
    try { return new URL(u, window.location.href).pathname === '/api/observe/client'; }
    catch (e) { return false; }
  }

  // ── fetch intercept — always sends the REAL user's token ──────────────
  var _origFetch = window.fetch.bind(window);
  window.fetch = function(input, init) {
    try {
      var url = (typeof input === 'string') ? input : (input && input.url) || '';
      if (isApiUrl(url)) {
        var t = getIdToken();
        if (t) {
          init = init || {};
          init.headers = Object.assign({}, init.headers || {}, { 'Authorization': 'Bearer ' + t });
        }
      }
    } catch(e) {}
    return _origFetch(input, init).then(function(res) {
      try {
        var url = (typeof input === 'string') ? input : (input && input.url) || '';
        if (isApiUrl(url) && res.status === 401) {
          // The 401 IS the signal. This used to reopen the body and test
          // data.code === 'TOKEN_EXPIRED' -- a key the core API has never sent;
          // it answers {ok:false, error:'AUTH_REQUIRED', detail:...} -- so the
          // branch never ran and an expired session rendered as a fully-chromed
          // console reporting zero employees, zero MacBooks, zero endpoints.
          // Do not depend on the body at all: a 401 carrying proxy HTML, or
          // nothing, or a shape no one has written down yet, is still a 401.
          // /hub-api/ especially: its nginx block carries no `error_page 401` on
          // purpose, so a gate denial there arrives as HTML no JSON test reads.
          //
          // THREE exceptions, and all are LOAD-BEARING - do not "tidy" any away.
          //
          // 1. /api/gate/ is the sign-out and session surface and is ungated at the
          //    proxy, so a 401 there is that endpoint's own answer, not a verdict on
          //    this page. Redirecting would race the federated-logout navigation the
          //    sign-out path is already performing (/it-session-watch.js, and
          //    it-topbar.js itSignOut - the v1.4 bar that used to live at the bottom
          //    of THIS file was deleted on 2026-09-04), and sign-out on this console
          //    has been broken by exactly that kind of race before. It also covers
          //    GET /api/gate/session-info, whose whole contract is that a 401 means
          //    "could not measure", never "your session ended": hard-redirecting a
          //    localdev/QA bearer session or a bfcache restore on it would
          //    reintroduce the bug the session watcher exists to kill.
          // 2. The EXACT path /api/rbac/session is the renewal endpoint, and
          //    it-session-watch.js owns that request's failure handling: it repairs
          //    the bearer and re-reads status on a 401. A redirect here would be a
          //    navigation triggered by a background renewal the user never asked
          //    for. Exact match only - the rest of /api/rbac/ keeps the default.
          // 3. The EXACT path /api/observe/client is the observability BEACON, which
          //    posts on a background timer. See isObserveUrl() above.
          if (url.indexOf('/api/gate/') === -1 && !isRenewUrl(url) && !isTokenUrl(url) &&
              !isObserveUrl(url)) goLoginExpired();
        }
      } catch(e) {}
      return res;
    });
  };

  // ── state ─────────────────────────────────────────────────────────────
  var ME_PROMISE = null;
  var ME_DATA = null;       // the real logged-in user (always truth)
  var VIEWAS_DATA = null;   // override when viewing as another user
  // 'pending' until /me answers, then 'ok' on a real profile, 'unauthenticated'
  // on a 401, 'unavailable' when we never got an answer at all. That last one is
  // NOT a denial -- it is "could not ask" -- and the UI has to say so rather
  // than quietly serving a read-tier console to an admin.
  var ME_STATE = 'pending';
  // nginx allows :3001 sixty seconds upstream, and a socket held open without
  // answering never settles at all -- in which case applyDomGuards() would never
  // run and every guarded control would sit in its pre-verdict state for the
  // life of the tab. Bound the wait so "no answer" resolves the way "no" does.
  var ME_TIMEOUT_MS = 8000;

  // The shape we fall back to whenever the answer is not an affirmative grant.
  // It was written out twice inline; one helper keeps deny in a single place, so
  // a field added to the real profile cannot go missing from the closed one.
  function denyProfile() {
    return { email: null, isSuperAdmin: false, isActive: false, pages: {}, roles: [] };
  }

  function loadMe() {
    if (ME_PROMISE) return ME_PROMISE;
    var t = getIdToken();
    var headers = t ? { 'Authorization': 'Bearer ' + t } : {};
    var ctl = ('AbortController' in window) ? new AbortController() : null;
    var opts = { headers: headers };
    if (ctl) opts.signal = ctl.signal;

    ME_PROMISE = new Promise(function (resolve) {
      var settled = false;
      function settle(data, state) {
        // A late answer arriving after the timeout is ignored on purpose: the
        // page has already been rendered against the closed verdict, and
        // flipping controls back in silently is a second surprise. The notice
        // offers Retry, which re-asks explicitly.
        if (settled) return;
        settled = true;
        ME_STATE = state;
        ME_DATA = data;
        resolve(data);
      }
      var timer = setTimeout(function () {
        if (ctl) { try { ctl.abort(); } catch (e) {} }
        console.warn('[rbac-client] /me did not answer in ' + ME_TIMEOUT_MS + 'ms - failing closed');
        settle(denyProfile(), 'unavailable');
      }, ME_TIMEOUT_MS);

      _origFetch(ME_ENDPOINT, opts).then(function (r) {
        clearTimeout(timer);
        if (r.status === 401) { settle(denyProfile(), 'unauthenticated'); return null; }
        return r.json().then(function (data) {
          // A 200 whose body is not a profile object is not a grant. Without
          // this ME_DATA stays null, applyDomGuards() hits its !effectiveMe()
          // early return, and the fail-closed rule installed below then hides
          // every guarded control for the life of the tab with nothing said --
          // the same silent failure one layer down. Treat it as "could not ask".
          if (!data || typeof data !== 'object') { settle(denyProfile(), 'unavailable'); return; }
          settle(data, 'ok');
        });
      }).catch(function (e) {
        clearTimeout(timer);
        console.error('[rbac-client] /me load failed:', e && e.message);
        settle(denyProfile(), 'unavailable');
      });
    });
    return ME_PROMISE;
  }

  // ── effective identity ────────────────────────────────────────────────
  function effectiveMe() {
    return VIEWAS_DATA || ME_DATA;
  }

  function canAccess(pageKey) {
    var d = effectiveMe();
    if (!d) return false;
    if (d.isSuperAdmin) return true;
    return !!(d.pages && d.pages[pageKey]);
  }
  function canAdmin(pageKey) {
    var d = effectiveMe();
    if (!d) return false;
    if (d.isSuperAdmin) return true;
    return !!(d.pages && d.pages[pageKey] === 'admin');
  }

  // ── DOM guards ────────────────────────────────────────────────────────
  // Fail closed by default. Before this, a guarded control painted enabled and
  // stayed that way until /me answered -- so a slow or restarting :3001 showed
  // every admin affordance to every user for the length of the request, and a
  // hung socket showed them for the life of the tab. Denial is now the
  // pre-verdict state; only an affirmative grant reveals.
  //
  // display:none, not [hidden] and not pointer-events:none. [hidden] loses to
  // any class that sets display, and this file is shared across vhosts so it
  // cannot assume the page carries [hidden]{display:none!important}. An element
  // merely faded with pointer-events:none is still Tab-focusable and
  // Enter-activatable -- that is a fake control, not a hidden one.
  function installGuardCss() {
    if (document.getElementById(GUARD_CSS_ID)) return;
    var head = document.head || document.documentElement;
    if (!head) return;
    var st = document.createElement('style');
    st.id = GUARD_CSS_ID;
    st.textContent =
      '[data-rbac-page]:not([data-rbac-applied]){display:none!important;}' +
      // Theme-aware for the same reason the session bar is: hardcoded amber put
      // a dark slab across a light page, and not every console uses
      // [data-theme] (ai-usage-credits switches on body.light).
      '#' + NOTICE_ID + '{position:fixed;left:16px;bottom:16px;z-index:99998;max-width:380px;' +
        'background:#3A2F14;color:#FFD27A;border:1px solid #8A6D1F;border-radius:8px;' +
        'font:13px/1.45 "IBM Plex Sans",system-ui,sans-serif;padding:10px 14px;' +
        'display:flex;align-items:center;gap:12px;' +
        'box-shadow:0 10px 28px -14px rgba(0,0,0,.7);}' +
      '#' + NOTICE_ID + ' button{flex:0 0 auto;font:inherit;font-weight:600;' +
        'border:1px solid #8A6D1F;border-radius:6px;padding:5px 12px;' +
        'background:transparent;color:#FFD27A;cursor:pointer;}' +
      '#' + NOTICE_ID + ' button:focus-visible{outline:2px solid currentColor;outline-offset:2px;}' +
      '[data-theme="light"] #' + NOTICE_ID + ',body.light #' + NOTICE_ID + '{' +
        'background:#FDF3D6;color:#6B4E07;border-color:#E3C77A;' +
        'box-shadow:0 10px 26px -16px rgba(24,44,82,.34);}' +
      '[data-theme="light"] #' + NOTICE_ID + ' button,body.light #' + NOTICE_ID + ' button{' +
        'color:#6B4E07;border-color:#D9BE72;}' +
      '@media print{#' + NOTICE_ID + '{display:none;}}';
    head.appendChild(st);
  }
  installGuardCss();

  // Belt for the stylesheet: an inline display:none needs no CSS to have been
  // allowed or applied. Marked, so applyDomGuards knows this hide is OURS and
  // lifts only it -- never a display the page set for its own reasons.
  function preHideGuards(root) {
    root = root || document;
    var els = root.querySelectorAll('[data-rbac-page]:not([data-rbac-applied])');
    for (var i = 0; i < els.length; i++) {
      els[i].style.display = 'none';
      els[i].dataset.rbacPending = '1';
    }
    return els.length;
  }

  // Shown only when the verdict never arrived AND that silence actually cost the
  // user a control. A clean denial is not news; an unknown is -- and "the
  // buttons are missing, with no explanation" is the same silent failure the
  // rest of this port is closing.
  function showRbacNotice() {
    if (document.getElementById(NOTICE_ID) || !document.body) return;
    var box = document.createElement('div');
    box.id = NOTICE_ID;
    box.setAttribute('role', 'status');
    var msg = document.createElement('span');
    msg.textContent = 'Access could not be verified, so admin controls are hidden.';
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.textContent = 'Retry';
    btn.addEventListener('click', function () {
      btn.disabled = true;
      btn.textContent = 'Checking...';
      window.itRbac.refresh().then(function () {
        if (ME_STATE === 'ok') { hideRbacNotice(); return; }
        btn.disabled = false;
        btn.textContent = 'Retry';
      });
    });
    box.appendChild(msg);
    box.appendChild(btn);
    document.body.appendChild(box);
  }

  function hideRbacNotice() {
    var el = document.getElementById(NOTICE_ID);
    if (el && el.parentNode) el.parentNode.removeChild(el);
  }

  function applyDomGuards(root) {
    root = root || document;
    if (!effectiveMe()) return 0;
    var els = root.querySelectorAll('[data-rbac-page]');
    var n = 0;
    for (var i = 0; i < els.length; i++) {
      var el = els[i];
      if (el.dataset.rbacApplied === '1') continue;
      var page  = el.getAttribute('data-rbac-page');
      var level = el.getAttribute('data-rbac-level') || 'read';
      var ok = level === 'admin' ? canAdmin(page) : canAccess(page);
      // Lift the fail-closed pre-hide only now that a verdict exists. Done
      // before the branches below so hide, dim and reveal all start from the
      // same known state; this is one synchronous pass, nothing repaints in
      // between. Setting data-rbac-applied at the end of the loop is what
      // releases the stylesheet rule, so reveal is always verdict-driven.
      if (el.dataset.rbacPending === '1') {
        el.style.display = '';
        delete el.dataset.rbacPending;
      }
      if (!ok) {
        var action = el.getAttribute('data-rbac-action') || 'hide';
        if (action === 'dim') {
          el.style.opacity = '0.4';
          el.style.pointerEvents = 'none';
          el.style.cursor = 'not-allowed';
          // pointer-events:none is NOT disabled -- the control stays
          // Tab-focusable and Enter-activatable, which is exactly how a denied
          // user reaches something we have already told them is unavailable.
          // inert makes the refusal real. Set behind our own marker so
          // resetDomGuards undoes only what we put here, never an element the
          // page disabled for its own reasons.
          el.setAttribute('inert', '');
          el.setAttribute('aria-disabled', 'true');
          el.dataset.rbacInert = '1';
          if (!el.title) el.title = 'Access not granted — contact IT';
        } else {
          el.style.display = 'none';
        }
        n++;
      }
      el.dataset.rbacApplied = '1';
    }
    return n;
  }

  function resetDomGuards() {
    var els = document.querySelectorAll('[data-rbac-applied]');
    for (var i = 0; i < els.length; i++) {
      var el = els[i];
      // Removing data-rbac-applied also re-arms the fail-closed stylesheet rule,
      // so the gap between this reset and the re-apply that always follows it is
      // hidden rather than exposed.
      delete el.dataset.rbacApplied;
      // restore original state (undo both hide and dim)
      el.style.display = '';
      el.style.opacity = '';
      el.style.pointerEvents = '';
      el.style.cursor = '';
      delete el.dataset.rbacPending;
      if (el.dataset.rbacInert === '1') {
        el.removeAttribute('inert');
        el.removeAttribute('aria-disabled');
        delete el.dataset.rbacInert;
      }
    }
  }

  // v1.2: MutationObserver — auto-apply on dynamically-injected elements
  var _observer = null;
  function startObserver() {
    if (_observer || !('MutationObserver' in window)) return;
    _observer = new MutationObserver(function(mutations) {
      var needs = false;
      for (var i = 0; i < mutations.length && !needs; i++) {
        var m = mutations[i];
        if (m.type !== 'childList' || !m.addedNodes.length) continue;
        for (var j = 0; j < m.addedNodes.length; j++) {
          var node = m.addedNodes[j];
          if (node.nodeType !== 1) continue;
          if (node.hasAttribute && node.hasAttribute('data-rbac-page')) { needs = true; break; }
          if (node.querySelector && node.querySelector('[data-rbac-page]:not([data-rbac-applied])')) { needs = true; break; }
        }
      }
      if (needs) applyDomGuards();
    });
    _observer.observe(document.body, { childList: true, subtree: true });
  }

  // ── View-As banner ────────────────────────────────────────────────────
  function escText(s) {
    var d = document.createElement('div');
    d.textContent = s == null ? '' : String(s);
    return d.innerHTML;
  }

  function injectBanner() {
    removeBanner();
    var d = VIEWAS_DATA;
    if (!d) return;
    var bar = document.createElement('div');
    bar.id = BANNER_ID;
    bar.style.cssText =
      'position:fixed;top:0;left:0;right:0;z-index:99999;' +
      'background:linear-gradient(135deg,#92400E 0%,#78350F 100%);' +
      'color:#FDE68A;padding:9px 20px;font-size:13px;font-family:inherit;' +
      'display:flex;align-items:center;justify-content:center;gap:10px;' +
      'box-shadow:0 2px 12px rgba(0,0,0,.5);letter-spacing:.2px;';
    var roles = (d.roles || []).join(', ') || 'no roles';
    var name = d.displayName || d.email || 'unknown';
    var inactive = d.isActive === false ? ' <span style="color:#FCA5A5;font-weight:600;">(inactive)</span>' : '';
    bar.innerHTML =
      '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" style="flex-shrink:0;"><path d="M8 1a4 4 0 00-4 4c0 2.5 2 4.5 4 6 2-1.5 4-3.5 4-6a4 4 0 00-4-4zm0 5.5A1.5 1.5 0 118 2a1.5 1.5 0 010 4.5zM2 13.5c0-2 2.7-3 6-3s6 1 6 3V15H2v-1.5z" fill="currentColor"/></svg>' +
      '<span>Viewing as <strong>' + escText(name) + '</strong>' + inactive + '</span>' +
      '<span style="opacity:.65;font-size:12px;">' + escText(roles) + '</span>' +
      '<button id="itcmd-viewas-exit" style="margin-left:6px;padding:4px 14px;border-radius:4px;' +
      'border:1px solid #FDE68A;background:transparent;color:#FDE68A;cursor:pointer;font-size:12px;' +
      'font-family:inherit;font-weight:600;transition:background .15s,color .15s;">Exit</button>';
    document.body.insertBefore(bar, document.body.firstChild);
    // push page content down
    document.body.style.paddingTop = bar.offsetHeight + 'px';
    document.getElementById('itcmd-viewas-exit').addEventListener('click', deactivateViewAs);
    // hover effect
    var btn = document.getElementById('itcmd-viewas-exit');
    btn.addEventListener('mouseenter', function(){ this.style.background = '#FDE68A'; this.style.color = '#78350F'; });
    btn.addEventListener('mouseleave', function(){ this.style.background = 'transparent'; this.style.color = '#FDE68A'; });
  }

  function removeBanner() {
    var bar = document.getElementById(BANNER_ID);
    if (bar) bar.remove();
    document.body.style.paddingTop = '';
  }

  // ── View-As activation / deactivation ─────────────────────────────────
  function activateViewAs(data) {
    VIEWAS_DATA = data;
    try { sessionStorage.setItem(VIEWAS_KEY, JSON.stringify(data)); } catch(e) {}
    resetDomGuards();
    applyDomGuards();
    injectBanner();
  }

  function deactivateViewAs() {
    VIEWAS_DATA = null;
    try { sessionStorage.removeItem(VIEWAS_KEY); } catch(e) {}
    removeBanner();
    resetDomGuards();
    applyDomGuards();
  }

  function restoreViewAs() {
    try {
      var raw = sessionStorage.getItem(VIEWAS_KEY);
      if (raw) {
        VIEWAS_DATA = JSON.parse(raw);
        // re-inject banner (runs before applyDomGuards in autoApply)
        injectBanner();
      }
    } catch(e) {
      VIEWAS_DATA = null;
      try { sessionStorage.removeItem(VIEWAS_KEY); } catch(e2) {}
    }
  }

  // ── public API ────────────────────────────────────────────────────────
  window.itRbac = {
    ready: loadMe,
    me: function(){ return effectiveMe(); },
    realMe: function(){ return ME_DATA; },
    canAccess: canAccess,
    canAdmin: canAdmin,
    applyDomGuards: applyDomGuards,
    refresh: function() {
      ME_PROMISE = null; ME_DATA = null; ME_STATE = 'pending';
      return loadMe().then(function(){ resetDomGuards(); applyDomGuards(); });
    },
    // 'pending' | 'ok' | 'unauthenticated' | 'unavailable'. Anything that renders
    // its own admin affordance must gate on isVerified(), not on canAdmin()
    // alone: canAdmin() answers false while the verdict is still unknown, which
    // is the right answer for hiding and the wrong one for explaining.
    state: function() { return ME_STATE; },
    isVerified: function() { return ME_STATE === 'ok'; },
    // View-As API (super-admin only, client-side simulation)
    viewAs: activateViewAs,
    exitViewAs: deactivateViewAs,
    isViewingAs: function() { return !!VIEWAS_DATA; },
    viewAsTarget: function() { return VIEWAS_DATA; }
  };

  // ── boot ──────────────────────────────────────────────────────────────
  function autoApply() {
    // Hide first, ask second. Everything guarded is closed before a verdict
    // exists and is opened only by an affirmative grant.
    preHideGuards();
    loadMe().then(function() {
      restoreViewAs();
      var denied = applyDomGuards();
      startObserver();
      // Only speak up when we could not decide AND that cost the user something.
      // A determined denial needs no announcement; an unknown does.
      if (ME_STATE === 'unavailable' && denied > 0) showRbacNotice();
    });
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', autoApply);
  } else {
    autoApply();
  }
})();
