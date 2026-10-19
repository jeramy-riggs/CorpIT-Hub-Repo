// =====================================================================
// it-topbar.js  (v1.0.0)
//
// The one right-hand cluster for every IT Command page:
//
//     [ theme ]  [ <- Operations Hub ]  [ avatar v ]
//
// Replaces four divergent implementations that had drifted apart in
// colour, size, identity source, menu contents and — worst — in what
// "Sign Out" actually did:
//
//   it-hub-link.js   pill + avatar, identity from the id_token
//   it-account.js    avatar only, identity from /api/rbac/me
//   per-page markup  IT_Inventory_App, identity-diag, zscaler-command-
//                    center, ai-usage-credits, signin-watch each hand-
//                    rolled their own menu
//   rbac-client.js   the session-expiry bar had a seventh variant
//
// THE SIGN-OUT BUG THIS FIXES
// ---------------------------
// Every one of those cleared sessionStorage and the legacy it_auth
// cookie, then redirected to /login.html. None of them touched
// it_session — the HttpOnly cookie the nginx auth_request gate actually
// enforces. Page JS cannot clear an HttpOnly cookie, so the session
// stayed valid for its full TTL: after "Sign Out" anyone could type the
// URL of a gated page and walk straight back in. POST /api/gate/logout
// (api-beta, gate-routes.js) is the only thing that ends a session, and
// nothing on the site called it. window.itSignOut() below does.
//
// MOUNTING
//   1. #it-topbar or #it-account, if the page provides one
//   2. otherwise the page's own bar: .topbar / .appbar / header.topbar
//   3. otherwise a fixed dock in the top-right corner
//
// The theme control is not reimplemented here — it-theme-toggle.js
// renders its button into #ittb-theme-slot when this cluster is present,
// so accent handoff and server-side persistence keep working unchanged.
//
// Include once, anywhere:  <script src="/it-topbar.js" defer></script>
// =====================================================================

(function () {
  'use strict';
  if (window.__itTopbarLoaded) return;
  window.__itTopbarLoaded = true;

  // The login page has no session to show and must never redirect itself.
  if (/\/login(_sso)?\.html$/.test(window.location.pathname)) return;

  var ME_URL      = '/api/rbac/me';
  var USERS_URL   = '/api/rbac/users?include_inactive=1';
  var VIEWAS_URL  = '/api/rbac/admin/view-as/';
  var REFRESH_URL = '/api/rbac/me/refresh';
  var LOGOUT_URL  = '/api/gate/logout';
  var HUB_HOST    = 'corpit.nrpi.local';
  /* The Hub is served at / on corpit and NOWHERE else on this box. Written as a
   * bare '/', this pill was a dead control on every other vhost: on reporting,
   * '/' 302s to ai-usage-credits.html, so "<- CorpIT Hub" returned you to the
   * page you clicked it from. it-hub-link.js does the host math and the
   * per-vhost access check; the fallback keeps the link correct on pages that
   * do not load it (where the only consequence is no pre-click check). */
  function hubUrl() {
    if (window.ITHubLink) return window.ITHubLink.url('/');
    return String(window.location.hostname || '').toLowerCase() === HUB_HOST ? '/' : 'https://' + HUB_HOST + '/';
  }
  var PROFILE_URL = '/my-profile.html';
  var ADMIN_URL   = 'https://subadmin.nrpi.local/';   // corpit: the admin console is the subadmin vhost (was /saas-admin.html, which 404s here)
  /* Health & settings has one home in the Subadmin control plane. */
  function healthUrl() {
    var h = String(window.location.hostname || '').toLowerCase();
    if (h === 'subadmin.nrpi.local' || h === 'dev-subadmin.nrpi.local') return '/health';
    return 'https://' + (/^dev-/.test(h) ? 'dev-subadmin.nrpi.local' : 'subadmin.nrpi.local') + '/health';
  }
  var LOGOUT_TIMEOUT_MS = 6000;

  var me = null;
  var usersCache = null;
  var signingOut = false;

  /* ------------------------------------------------------------------ *
   * icons — one family, 24px grid, 1.8 stroke, currentColor
   * ------------------------------------------------------------------ */
  function icon(path, extra) {
    return '<svg class="ittb-i" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
           'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"' +
           (extra || '') + '>' + path + '</svg>';
  }
  var IC = {
    back:    '<path d="M19 12H5"/><path d="M11 18l-6-6 6-6"/>',
    user:    '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
    refresh: '<path d="M21 12a9 9 0 1 1-2.64-6.36"/><path d="M21 3v6h-6"/>',
    eye:     '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>',
    shield:  '<path d="M12 3l7 3v5.5c0 4.5-3 8.2-7 9.5-4-1.3-7-5-7-9.5V6l7-3Z"/><path d="M9.2 12l2 2 3.6-3.8"/>',
    signout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5"/><path d="M21 12H9"/>',
    pulse:   '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
    chev:    '<path d="M6 9l6 6 6-6"/>'
  };

  /* ------------------------------------------------------------------ *
   * styles
   *
   * The cluster carries its own token set rather than inheriting page
   * variables: twenty hand-built palettes do not agree on what --bg or
   * --line mean, and a cluster that changes shape per page is the thing
   * we are removing. --accent / --blue are the one exception — both
   * it-theme.js and it-theme-toggle.js normalise them per colour mode,
   * so the user's accent family still reaches the cluster.
   * ------------------------------------------------------------------ */
  var CSS = [
    '.ittb{',
      '--ittb-fg:#e6edf7;',
      '--ittb-muted:#9fb2cb;',            /* 7.0:1 on --ittb-surface */
      '--ittb-surface:rgba(10,22,40,.85);',
      '--ittb-panel:#0d1626;',
      '--ittb-panel-2:#182437;',
      '--ittb-line:#243349;',
      '--ittb-av-bg:#152238;',
      '--ittb-shadow:0 14px 34px -10px rgba(0,0,0,.65);',
      '--ittb-accent:var(--accent,var(--blue,#38bdf8));',
      'display:inline-flex;align-items:center;gap:8px;margin-left:auto;order:99;',
      'font-family:"IBM Plex Sans",system-ui,-apple-system,"Segoe UI",sans-serif;',
      'line-height:1;flex:0 0 auto;',
    '}',
    '[data-theme="light"] .ittb,body.light .ittb{',
      '--ittb-fg:#101c2e;',
      '--ittb-muted:#5a6e8a;',            /* 4.9:1 on white */
      '--ittb-surface:rgba(255,255,255,.92);',
      '--ittb-panel:#ffffff;',
      '--ittb-panel-2:#eef2f7;',
      '--ittb-line:#d6dde8;',
      '--ittb-av-bg:#e7edf5;',
      '--ittb-shadow:0 14px 34px -10px rgba(20,40,80,.24);',
    '}',
    '.ittb.ittb-fixed{position:fixed;top:10px;right:14px;z-index:10001;margin:0;}',
    '.ittb *,.ittb *::before,.ittb *::after{box-sizing:border-box;}',
    '.ittb .ittb-i{width:15px;height:15px;flex:0 0 auto;}',

    /* --- shared control shape: theme button, hub pill, avatar --- */
    '.ittb .ittb-ctl{',
      'display:inline-flex;align-items:center;gap:6px;height:32px;padding:0 11px;',
      'border-radius:8px;border:1px solid var(--ittb-line);background:var(--ittb-surface);',
      'color:var(--ittb-muted);font:500 12px/1 inherit;text-decoration:none;white-space:nowrap;',
      'cursor:pointer;-webkit-backdrop-filter:blur(6px);backdrop-filter:blur(6px);',
      'transition:color .15s ease,border-color .15s ease,background-color .15s ease;',
    '}',
    '.ittb .ittb-ctl:hover{color:var(--ittb-accent);border-color:color-mix(in srgb,var(--ittb-accent) 45%,transparent);' +
      'background:color-mix(in srgb,var(--ittb-accent) 9%,var(--ittb-surface));}',
    '.ittb .ittb-ctl:focus-visible{outline:2px solid var(--ittb-accent);outline-offset:2px;}',
    '.ittb .ittb-ctl:active{transform:translateY(.5px);}',

    /* --- avatar --- */
    /* the theme button is it-theme-toggle.js's; adopted into the cluster it
       drops its label and squares up to the avatar's 32px rhythm */
    /* When the page gives us its own mount div, order:99 on .ittb only sorts
       INSIDE that div — the div itself is the bar's flex child. Push that
       instead, so the avatar anchors the far right rather than sitting to
       the left of whatever the page appended after the mount point (the
       Operations Hub version chip, server-health's version badge). */
    '.ittb-anchor{order:99;margin-left:auto;}',
    '.ittb #itThemeBtn{padding:0;width:32px;justify-content:center;}',
    '.ittb #itThemeBtn .itt-txt{display:none;}',

    '.ittb-avwrap{position:relative;display:inline-flex;}',
    '.ittb .ittb-av{',
      'position:relative;overflow:hidden;width:32px;height:32px;padding:0;border-radius:50%;',
      'display:inline-flex;align-items:center;justify-content:center;',
      'border:1px solid var(--ittb-line);background:var(--ittb-av-bg);color:var(--ittb-fg);',
      'font:600 11.5px/1 inherit;letter-spacing:.4px;cursor:pointer;',
      'transition:border-color .15s ease,box-shadow .15s ease;',
    '}',
    '.ittb .ittb-av:hover,.ittb .ittb-av[aria-expanded="true"]{border-color:var(--ittb-accent);' +
      'box-shadow:0 0 0 3px color-mix(in srgb,var(--ittb-accent) 18%,transparent);}',
    '.ittb .ittb-av:focus-visible{outline:2px solid var(--ittb-accent);outline-offset:2px;}',
    '.ittb .ittb-av .ittb-photo{position:absolute;inset:0;width:100%;height:100%;object-fit:cover;' +
      'border-radius:inherit;opacity:0;transition:opacity .2s ease;}',
    '.ittb .ittb-av .ittb-photo.on{opacity:1;}',
    /* identity is still loading: hold the box, do not flash a "?" */
    '.ittb .ittb-av.ittb-wait{color:transparent;}',
    '.ittb .ittb-av.ittb-wait::after{content:"";position:absolute;inset:0;border-radius:inherit;' +
      'background:linear-gradient(100deg,transparent 20%,color-mix(in srgb,var(--ittb-fg) 12%,transparent) 50%,transparent 80%);' +
      'background-size:220% 100%;animation:ittb-shimmer 1.1s linear infinite;}',
    '@keyframes ittb-shimmer{from{background-position:120% 0}to{background-position:-120% 0}}',

    /* --- menu --- */
    '.ittb-menu{',
      'position:absolute;right:0;top:calc(100% + 8px);min-width:246px;z-index:10002;',
      'background:var(--ittb-panel);border:1px solid var(--ittb-line);border-radius:11px;',
      'box-shadow:var(--ittb-shadow);padding:6px;',
      'opacity:0;transform:translateY(-4px) scale(.985);transform-origin:top right;',
      'pointer-events:none;visibility:hidden;',
      'transition:opacity .16s cubic-bezier(.2,.8,.3,1),transform .16s cubic-bezier(.2,.8,.3,1),visibility 0s linear .16s;',
    '}',
    '.ittb-menu.on{opacity:1;transform:none;pointer-events:auto;visibility:visible;transition-delay:0s;}',
    '.ittb-menu .ittb-id{padding:9px 10px 11px;border-bottom:1px solid var(--ittb-line);margin-bottom:6px;}',
    '.ittb-menu .ittb-nm{font:600 13px/1.3 inherit;color:var(--ittb-fg);' +
      'overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}',
    '.ittb-menu .ittb-em{font:400 11px/1.4 inherit;color:var(--ittb-muted);margin-top:3px;word-break:break-all;}',
    '.ittb-menu .ittb-sa{display:inline-block;margin-top:6px;padding:1px 7px;border-radius:999px;',
      'font:600 9.5px/1.6 inherit;letter-spacing:.6px;text-transform:uppercase;',
      'color:var(--ittb-accent);background:color-mix(in srgb,var(--ittb-accent) 15%,transparent);}',
    '.ittb-menu .ittb-item{',
      'display:flex;align-items:center;gap:9px;width:100%;padding:8px 10px;border:0;border-radius:7px;',
      'background:none;color:var(--ittb-fg);font:500 13px/1.2 inherit;text-align:left;text-decoration:none;',
      'cursor:pointer;transition:background-color .12s ease,color .12s ease;',
    '}',
    '.ittb-menu .ittb-item .ittb-i{color:var(--ittb-muted);transition:color .12s ease;}',
    '.ittb-menu .ittb-item:hover,.ittb-menu .ittb-item:focus-visible{background:var(--ittb-panel-2);outline:none;}',
    '.ittb-menu .ittb-item:hover .ittb-i,.ittb-menu .ittb-item:focus-visible .ittb-i{color:var(--ittb-accent);}',
    '.ittb-menu .ittb-item:focus-visible{box-shadow:inset 0 0 0 1.5px var(--ittb-accent);}',
    '.ittb-menu .ittb-item[aria-disabled="true"]{opacity:.5;pointer-events:none;}',
    '.ittb-menu .ittb-div{height:1px;background:var(--ittb-line);margin:6px 4px;}',
    '.ittb-menu .ittb-note{padding:2px 10px 6px;font:400 11px/1.45 inherit;color:var(--ittb-muted);}',
    '.ittb-menu .ittb-note.err{color:#F0A0A0;}',
    '[data-theme="light"] .ittb-menu .ittb-note.err,body.light .ittb-menu .ittb-note.err{color:#B0303C;}',
    /* spinner used by Refresh + Sign out */
    '.ittb-spin{width:14px;height:14px;flex:0 0 auto;border-radius:50%;border:1.8px solid currentColor;' +
      'border-top-color:transparent;animation:ittb-rot .6s linear infinite;}',
    '@keyframes ittb-rot{to{transform:rotate(360deg)}}',

    /* --- view-as picker --- */
    '.ittb-scrim{position:fixed;inset:0;z-index:10050;display:none;align-items:center;justify-content:center;',
      'background:rgba(4,12,24,.62);padding:20px;}',
    '[data-theme="light"] .ittb-scrim,body.light .ittb-scrim{background:rgba(24,40,66,.34);}',
    '.ittb-scrim.on{display:flex;}',
    '.ittb-va{width:440px;max-width:100%;max-height:min(560px,86vh);display:flex;flex-direction:column;',
      'background:var(--ittb-panel);border:1px solid var(--ittb-line);border-radius:13px;box-shadow:var(--ittb-shadow);',
      'font-family:"IBM Plex Sans",system-ui,-apple-system,sans-serif;}',
    '.ittb-va h2{margin:0;font:600 15px/1.3 inherit;color:var(--ittb-fg);}',
    '.ittb-vah{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;',
      'padding:16px 18px 12px;border-bottom:1px solid var(--ittb-line);}',
    '.ittb-vax{display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;',
      'border:1px solid transparent;border-radius:7px;background:none;color:var(--ittb-muted);cursor:pointer;}',
    '.ittb-vax:hover{color:var(--ittb-fg);background:var(--ittb-panel-2);}',
    '.ittb-vax:focus-visible{outline:2px solid var(--ittb-accent);outline-offset:2px;}',
    '.ittb-vas{margin:12px 18px 4px;padding:9px 12px;width:calc(100% - 36px);border-radius:8px;',
      'border:1px solid var(--ittb-line);background:var(--ittb-panel-2);color:var(--ittb-fg);',
      'font:400 13px/1.3 inherit;outline:none;}',
    '.ittb-vas:focus{border-color:var(--ittb-accent);box-shadow:0 0 0 3px color-mix(in srgb,var(--ittb-accent) 16%,transparent);}',
    '.ittb-vas::placeholder{color:var(--ittb-muted);}',
    '.ittb-vai{padding:6px 18px 8px;font:400 11.5px/1.5 inherit;color:var(--ittb-muted);}',
    '.ittb-val{flex:1;overflow-y:auto;padding:4px 10px 12px;scrollbar-width:thin;',
      'scrollbar-color:var(--ittb-line) transparent;}',
    '.ittb-val::-webkit-scrollbar{width:10px}',
    '.ittb-val::-webkit-scrollbar-thumb{background:var(--ittb-line);border-radius:6px;border:3px solid transparent;background-clip:content-box}',
    '.ittb-row{display:flex;align-items:center;gap:10px;width:100%;padding:8px 10px;border:0;border-radius:8px;',
      'background:none;text-align:left;cursor:pointer;transition:background-color .12s ease;}',
    '.ittb-row:hover,.ittb-row:focus-visible{background:var(--ittb-panel-2);outline:none;}',
    '.ittb-row:focus-visible{box-shadow:inset 0 0 0 1.5px var(--ittb-accent);}',
    '.ittb-row .nm{font:500 13px/1.3 inherit;color:var(--ittb-fg);}',
    '.ittb-row .em{font:400 11px/1.4 inherit;color:var(--ittb-muted);margin-top:2px;word-break:break-all;}',
    '.ittb-row .tag{font:600 9.5px/1.6 inherit;letter-spacing:.4px;text-transform:uppercase;',
      'padding:1px 6px;border-radius:4px;color:#F0A0A0;background:rgba(190,60,72,.18);}',
    '[data-theme="light"] .ittb-row .tag,body.light .ittb-row .tag{color:#9C2A34;background:#FBE4E6;}',
    '.ittb-row .cur{font:600 10.5px/1 inherit;color:var(--ittb-accent);white-space:nowrap;}',
    '.ittb-va-msg{padding:26px 18px;text-align:center;font:400 12.5px/1.5 inherit;color:var(--ittb-muted);}',

    /* --- environment --- */
    '@media (pointer:coarse){',
      '.ittb .ittb-ctl{height:38px;padding:0 13px;}',
      '.ittb .ittb-av{width:38px;height:38px;}',
      '.ittb #itThemeBtn{width:38px;}',
      '.ittb-menu .ittb-item{padding:11px 10px;}',
    '}',
    '@media (max-width:560px){.ittb .ittb-hub-txt{display:none;}.ittb .ittb-hub{padding:0 9px;}}',
    '@media (prefers-reduced-motion:reduce){',
      '.ittb *,.ittb-menu,.ittb-scrim *{transition-duration:.01ms!important;animation-duration:.01ms!important;}',
    '}',
    '@media print{.ittb,.ittb-scrim{display:none!important;}}',
    /* older engines without color-mix still get a visible hover */
    '@supports not (color:color-mix(in srgb,red 50%,blue)){',
      '.ittb .ittb-ctl:hover{border-color:var(--ittb-accent);background:var(--ittb-surface);}',
      '.ittb .ittb-av:hover,.ittb .ittb-av[aria-expanded="true"]{box-shadow:none;}',
    '}'
  ].join('');

  /* ------------------------------------------------------------------ *
   * the canonical sign-out — the only one on the site
   * ------------------------------------------------------------------ */
  function clearLocalSession() {
    try {
      sessionStorage.removeItem('sso_user');
      sessionStorage.removeItem('auth_expiry');
      sessionStorage.removeItem('itcmd_viewas');
    } catch (e) {}
    // Belt and braces for the legacy value; /api/gate/logout clears the
    // authoritative cookies (both it_session variants and both it_auth
    // variants) server-side, which is the part page JS cannot do.
    try {
      document.cookie = 'it_auth=; Max-Age=0; path=/';
    } catch (e) {}
  }

  // Ends the session for real, then leaves. Resolves nothing — it navigates.
  function itSignOut(onState) {
    if (signingOut) return;
    signingOut = true;
    var report = typeof onState === 'function' ? onState : function () {};
    report('busy');

    var done = false;
    function finish(ok) {
      if (done) return;
      done = true;
      clearLocalSession();
      /* FEDERATED sign-out (2026-09-03). Landing on /login.html only ended OUR
         session; the Entra session survived, so the next gated page silently
         re-authenticated through login.js's auto-start and the user was never
         actually signed out.
         Going to /api/gate/federated-logout instead repeats the local teardown
         server-side and then hands the browser to Microsoft's logout endpoint.
         Used on BOTH outcomes on purpose: if the POST above timed out, this GET
         is the teardown that actually lands, so the old 'signout=failed' path is
         strictly worse than retrying here.
         replace(), not href: Back must not restore a gated page rendered with the
         session we just ended. */
      window.location.replace('/api/gate/federated-logout');
    }

    var timer = setTimeout(function () { finish(false); }, LOGOUT_TIMEOUT_MS);

    fetch(LOGOUT_URL, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'X-Requested-With': 'it-topbar' }
    })
      .then(function (r) { clearTimeout(timer); finish(r.status === 204 || r.ok); })
      .catch(function () { clearTimeout(timer); finish(false); });
  }
  window.itSignOut = itSignOut;

  /* ------------------------------------------------------------------ *
   * identity
   * ------------------------------------------------------------------ */
  function tokenClaims() {
    try {
      var sso = JSON.parse(sessionStorage.getItem('sso_user') || '{}');
      var tok = sso.idToken || sso.id_token || '';
      var p = {};
      if (tok && String(tok).split('.').length === 3) {
        var seg = String(tok).split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
        while (seg.length % 4) seg += '=';
        p = JSON.parse(atob(seg));
      }
      return {
        name: sso.displayName || sso.name || p.name || '',
        email: sso.email || p.email || p.preferred_username || p.upn || ''
      };
    } catch (e) { return { name: '', email: '' }; }
  }

  function initialsOf(name, email) {
    var src = String(name || email || '').trim();
    if (!src) return '';
    var parts = src.split(/[\s@._-]+/).filter(Boolean);
    var s = parts.length >= 2 ? (parts[0][0] + parts[1][0]) : parts[0].slice(0, 2);
    return s.toUpperCase();
  }

  function esc(s) {
    var d = document.createElement('div');
    d.textContent = s == null ? '' : String(s);
    return d.innerHTML;
  }

  /* ------------------------------------------------------------------ *
   * build
   * ------------------------------------------------------------------ */
  var els = {};

  /* Twenty hand-built pages, twenty names for the same bar. Ordered by
     confidence and probed ONE AT A TIME: a comma-joined selector list
     returns the first match in DOCUMENT order, not the first selector
     that matches, so a `.topbar` reused deeper down would beat the real
     `header.top` above it. */
  var BAR_SELECTORS = [
    'header.topbar', 'header.appbar', 'header.page-header', 'header.page-head',
    'header.masthead', 'header.ribbon', 'header.top', 'header.ntop',
    'header[role="banner"]', '#topbar',
    '.topbar', '.appbar', '.page-header', '.page-head', '.suitebar'
  ];

  /* A bare `.topbar` class is not proof: pages reuse it for card headers,
     sub-toolbars and footers. An element scoped to <header> is trusted;
     anything matched by a bare class has to look like a bar — full width,
     short, and at the top of the page. */
  function plausibleBar(el, selector) {
    if (selector.charAt(0) === 'h') return true;          // header.* / header[role]
    try {
      var r = el.getBoundingClientRect();
      return r.width >= window.innerWidth * 0.55 && r.height <= 140 && r.top <= 160;
    } catch (e) { return true; }
  }

  function findBar() {
    for (var i = 0; i < BAR_SELECTORS.length; i++) {
      var el = document.querySelector(BAR_SELECTORS[i]);
      if (el && plausibleBar(el, BAR_SELECTORS[i])) return el;
    }
    return null;
  }

  function findMount() {
    var explicit = document.getElementById('it-topbar') || document.getElementById('it-account');
    if (explicit) {
      explicit.classList.add('ittb-anchor');
      // data-ittb-fixed: the page has no bar that survives its own view
      // switching. ad-management's only header lives inside #modeHousekeeping,
      // so mounting there put the cluster — and that page's ONLY sign-out —
      // inside a container that disappears in GPO Audit mode.
      return { node: explicit, fixed: explicit.hasAttribute('data-ittb-fixed'), locked: true };
    }
    var bar = findBar();
    if (bar) return { node: bar, fixed: false };
    return { node: document.body, fixed: true };
  }

  /* Some consoles (the NOC pages) build their whole shell at runtime from
     it-noc.js, so at DOMContentLoaded there is no bar to mount into yet —
     and whatever we appended to <body> can be wiped when that shell lands.
     Watch briefly: move into the real bar the moment it appears, and
     re-attach if the page detached us. */
  function watchForBar(wrap) {
    if (!window.MutationObserver || !document.body) return;
    var obs = new MutationObserver(function () {
      var bar = findBar();
      if (bar && wrap.parentNode !== bar) {
        wrap.classList.remove('ittb-fixed');
        bar.appendChild(wrap);
      } else if (!bar && !wrap.isConnected) {
        wrap.classList.add('ittb-fixed');
        document.body.appendChild(wrap);
      }
    });
    obs.observe(document.body, { childList: true, subtree: true });
    setTimeout(function () { obs.disconnect(); }, 5000);
  }

  function build() {
    var style = document.createElement('style');
    style.id = 'it-topbar-css';
    style.textContent = CSS;
    document.head.appendChild(style);

    var mount = findMount();
    var seed = tokenClaims();
    var seedInitials = initialsOf(seed.name, seed.email);

    // "<- Operations Hub" pointing at the page you are already on is a dead
    // control. The hub answers to two paths (/helpdesk/ is an nginx alias for
    // helpdesk-landing.html), so check both.
    var onHub = String(window.location.hostname || '').toLowerCase() === HUB_HOST &&
                (/^\/helpdesk\/?$/.test(window.location.pathname) ||
                 /^\/(helpdesk-landing\.html|landing\.html)?$/.test(window.location.pathname));

    var wrap = document.createElement('div');
    wrap.className = 'ittb' + (mount.fixed ? ' ittb-fixed' : '');
    wrap.innerHTML =
      '<span id="ittb-theme-slot"></span>' +
      (onHub ? '' :
        '<a class="ittb-ctl ittb-hub" href="' + hubUrl() + '" aria-label="CorpIT Hub">' +
          icon(IC.back) + '<span class="ittb-hub-txt">CorpIT Hub</span>' +
        '</a>') +
      '<span class="ittb-avwrap">' +
        '<button type="button" class="ittb-av' + (seedInitials ? '' : ' ittb-wait') + '" id="ittb-av" ' +
          'aria-haspopup="menu" aria-expanded="false" aria-controls="ittb-menu" ' +
          'aria-label="Account menu">' + esc(seedInitials || ' ') + '</button>' +
        '<div class="ittb-menu" id="ittb-menu" role="menu" aria-labelledby="ittb-av">' +
          '<div class="ittb-id">' +
            '<div class="ittb-nm" id="ittb-nm">' + esc(seed.name || seed.email || '—') + '</div>' +
            '<div class="ittb-em" id="ittb-em">' + esc(seed.email || '') + '</div>' +
            '<span class="ittb-sa" id="ittb-sa" hidden>super-admin</span>' +
          '</div>' +
          '<a class="ittb-item" role="menuitem" tabindex="-1" href="' + PROFILE_URL + '">' +
            icon(IC.user) + 'My profile</a>' +
          '<button type="button" class="ittb-item" role="menuitem" tabindex="-1" id="ittb-refresh">' +
            icon(IC.refresh) + '<span>Refresh my access</span></button>' +
          '<button type="button" class="ittb-item" role="menuitem" tabindex="-1" id="ittb-viewas" hidden>' +
            icon(IC.eye) + 'View as user</button>' +
          '<a class="ittb-item" role="menuitem" tabindex="-1" id="ittb-admin" href="' + ADMIN_URL + '" hidden>' +
            icon(IC.shield) + 'Admin center</a>' +
          '<a class="ittb-item" role="menuitem" tabindex="-1" id="ittb-health" href="' + healthUrl() + '" hidden>' +
            icon(IC.pulse) + 'Health &amp; settings</a>' +
          '<div class="ittb-note" id="ittb-note" hidden></div>' +
          '<div class="ittb-div"></div>' +
          '<button type="button" class="ittb-item" role="menuitem" tabindex="-1" id="ittb-signout">' +
            icon(IC.signout) + '<span>Sign out</span></button>' +
        '</div>' +
      '</span>';

    mount.node.appendChild(wrap);

    /* Site access is per-vhost by AD group, so someone who belongs on reporting
     * may have no business on the Hub. Ask before sending them: a click we know
     * would be refused is cancelled here and they stay on the page they clicked
     * from, instead of a sign-in round trip that ends on a 403. If the check
     * cannot be made the click still goes through -- the gate on corpit is the
     * authority, this is only a courtesy. */
    if (window.ITHubLink) {
      var hubPill = wrap.querySelector('.ittb-hub');
      if (hubPill) window.ITHubLink.guard(hubPill, 'You do not have access to the CorpIT Hub');
    }

    /* A bar can match every structural test and still be too narrow to hold
       us — report-bug's header is a 712px centred block that wrapped onto a
       third row the moment a 220px cluster landed in it. Measure instead of
       guessing: if we ended up on a line of our own, we do not belong inline,
       so fall back to the corner dock the page used before.

       This must run AFTER layout settles. Measured inline at DOMContentLoaded
       it reads the pre-wrap geometry and never fires, which is exactly what
       happened the first time. */
    function demoteIfWrapped() {
      if (mount.fixed || !wrap.parentNode || wrap.classList.contains('ittb-fixed')) return;
      var host = wrap.parentNode;
      var br = host.getBoundingClientRect();
      var wr = wrap.getBoundingClientRect();
      if (wr.height && (wr.top - br.top) > wr.height + 6) {
        wrap.classList.add('ittb-fixed');
        document.body.appendChild(wrap);
        mount.fixed = true;
      }
    }
    if (!mount.fixed) {
      requestAnimationFrame(function () { requestAnimationFrame(demoteIfWrapped); });
      window.addEventListener('load', demoteIfWrapped);
      var rt = null;
      window.addEventListener('resize', function () {
        clearTimeout(rt); rt = setTimeout(demoteIfWrapped, 150);
      });
    }
    // A page that explicitly asked for the corner dock must not be dragged
    // back into a bar by the observer.
    if (mount.fixed && !mount.locked) watchForBar(wrap);

    els.wrap    = wrap;
    els.av      = wrap.querySelector('#ittb-av');
    els.menu    = wrap.querySelector('#ittb-menu');
    els.nm      = wrap.querySelector('#ittb-nm');
    els.em      = wrap.querySelector('#ittb-em');
    els.sa      = wrap.querySelector('#ittb-sa');
    els.refresh = wrap.querySelector('#ittb-refresh');
    els.viewas  = wrap.querySelector('#ittb-viewas');
    els.admin   = wrap.querySelector('#ittb-admin');
    els.health  = wrap.querySelector('#ittb-health');
    els.signout = wrap.querySelector('#ittb-signout');
    els.note    = wrap.querySelector('#ittb-note');

    if (seed.email) attachPhoto(seed.email);
    wireMenu();

    els.refresh.addEventListener('click', function () { refreshAccess(); });
    els.viewas.addEventListener('click', function () { closeMenu(false); openViewAs(); });
    els.signout.addEventListener('click', function () {
      var label = els.signout.querySelector('span');
      itSignOut(function (state) {
        if (state !== 'busy') return;
        els.signout.setAttribute('aria-disabled', 'true');
        els.signout.querySelector('.ittb-i').outerHTML = '<span class="ittb-spin"></span>';
        label.textContent = 'Signing out…';
        els.menu.querySelectorAll('.ittb-item').forEach(function (n) {
          if (n !== els.signout) n.setAttribute('aria-disabled', 'true');
        });
      });
    });

    // it-theme-toggle.js may have already docked itself before we mounted.
    // Pull its button into our slot so there is one cluster, not two.
    adoptThemeButton();
    window.addEventListener('it-theme-toggle-ready', adoptThemeButton);
  }

  function attachPhoto(email) {
    var img = document.createElement('img');
    img.className = 'ittb-photo';
    img.alt = '';
    img.decoding = 'async';
    img.addEventListener('load', function () { img.classList.add('on'); });
    img.addEventListener('error', function () { img.remove(); });
    img.src = '/api/photo?upn=' + encodeURIComponent(email);
    els.av.appendChild(img);
  }

  function adoptThemeButton() {
    var slot = document.getElementById('ittb-theme-slot');
    var btn  = document.getElementById('itThemeBtn');
    if (!slot || !btn || btn.parentNode === slot) return;
    var dock = document.getElementById('itThemeDock');
    slot.appendChild(btn);
    btn.classList.add('ittb-ctl');
    if (dock && !dock.childElementCount) dock.remove();
  }

  /* ------------------------------------------------------------------ *
   * menu behaviour — mouse, touch and keyboard
   * ------------------------------------------------------------------ */
  function menuItems() {
    return Array.prototype.filter.call(
      els.menu.querySelectorAll('.ittb-item'),
      function (n) { return !n.hidden && n.getAttribute('aria-disabled') !== 'true'; }
    );
  }

  function openMenu(focusFirst) {
    els.menu.classList.add('on');
    els.av.setAttribute('aria-expanded', 'true');
    if (focusFirst) { var i = menuItems(); if (i.length) i[0].focus(); }
  }

  function closeMenu(returnFocus) {
    if (!els.menu.classList.contains('on')) return;
    els.menu.classList.remove('on');
    els.av.setAttribute('aria-expanded', 'false');
    clearNote();
    if (returnFocus) els.av.focus();
  }

  function wireMenu() {
    els.av.addEventListener('click', function (ev) {
      ev.stopPropagation();
      if (els.menu.classList.contains('on')) closeMenu(false); else openMenu(false);
    });

    els.av.addEventListener('keydown', function (ev) {
      if (ev.key === 'Escape' && els.menu.classList.contains('on')) {
        ev.preventDefault(); closeMenu(true); return;
      }
      if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp') {
        ev.preventDefault();
        openMenu(false);
        var i = menuItems();
        if (i.length) i[ev.key === 'ArrowUp' ? i.length - 1 : 0].focus();
      }
    });

    els.menu.addEventListener('keydown', function (ev) {
      var items = menuItems();
      // Signing out disables every item, so menuItems() is legitimately empty
      // mid-flight. items[(at + 1) % 0] is items[NaN] -> undefined.focus().
      // Escape must still work in that state, so handle it before bailing.
      if (!items.length) {
        if (ev.key === 'Escape') { ev.preventDefault(); closeMenu(true); }
        return;
      }
      var at = items.indexOf(document.activeElement);
      switch (ev.key) {
        case 'ArrowDown':
          ev.preventDefault(); items[(at + 1 + items.length) % items.length].focus(); break;
        case 'ArrowUp':
          ev.preventDefault(); items[(at - 1 + items.length) % items.length].focus(); break;
        case 'Home':
          ev.preventDefault(); items[0].focus(); break;
        case 'End':
          ev.preventDefault(); items[items.length - 1].focus(); break;
        case 'Escape':
          ev.preventDefault(); closeMenu(true); break;
        case 'Tab':
          closeMenu(false); break;
      }
    });

    // A click inside the menu must not bubble to the document closer, or
    // the menu would shut before "Refresh my access" could report back.
    els.menu.addEventListener('click', function (ev) { ev.stopPropagation(); });
    document.addEventListener('click', function () { closeMenu(false); });
  }

  function setNote(text, isErr) {
    els.note.textContent = text;
    els.note.className = 'ittb-note' + (isErr ? ' err' : '');
    els.note.hidden = false;
  }
  function clearNote() { els.note.hidden = true; els.note.textContent = ''; }

  /* ------------------------------------------------------------------ *
   * data
   * ------------------------------------------------------------------ */
  function fetchMe() {
    return fetch(ME_URL, { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : null; });
  }

  /* G19: rbac-client.js already asks /api/rbac/me once per page. Share that
     request instead of sending an identical second one. Only a verified
     profile is taken from it; every other outcome (rbac-client absent, 401,
     timeout, a body that is not a profile) and the re-read after "Refresh my
     access" (fresh) go through fetchMe(), exactly as before. */
  function loadMe(fresh) {
    var rb = window.itRbac, shared = null;
    if (!fresh && rb && typeof rb.ready === 'function') {
      try { shared = rb.ready(); } catch (e) { shared = null; }
    }
    var src = shared
      ? Promise.resolve(shared).then(function (d) {
          var verified = typeof rb.isVerified === 'function' && rb.isVerified();
          return (verified && d && typeof d === 'object' && typeof d.email === 'string' && d.email)
            ? d : fetchMe();
        }, fetchMe)
      : fetchMe();
    return src
      .then(function (u) {
        me = u;
        els.av.classList.remove('ittb-wait');
        if (!u) {
          // The gate let this page load, so the person is signed in; only
          // the RBAC lookup failed. Fall back to the token claims rather
          // than showing a "?" that implies a broken session.
          var seed = tokenClaims();
          var ini = initialsOf(seed.name, seed.email);
          els.av.firstChild.nodeValue = ini || '—';
          return;
        }
        var nm = u.displayName || u.email || '';
        var ini = initialsOf(nm, u.email);
        els.av.firstChild.nodeValue = ini || '—';
        els.av.setAttribute('aria-label', 'Account menu for ' + (nm || u.email || 'this session'));
        els.nm.textContent = nm || '—';
        els.em.textContent = u.email || '';
        if (u.email && !els.av.querySelector('.ittb-photo')) attachPhoto(u.email);

        var real = (window.itRbac && window.itRbac.realMe) ? window.itRbac.realMe() : u;
        var isSA = real ? real.isSuperAdmin : u.isSuperAdmin;
        els.sa.hidden = !isSA;
        els.viewas.hidden = !isSA;
        els.admin.hidden = !isSA;
        els.health.hidden = !isSA;
      })
      .catch(function () {
        els.av.classList.remove('ittb-wait');
        var seed = tokenClaims();
        els.av.firstChild.nodeValue = initialsOf(seed.name, seed.email) || '—';
      });
  }

  function refreshAccess() {
    var label = els.refresh.querySelector('span');
    var ico = els.refresh.querySelector('.ittb-i');
    var orig = label.textContent;
    els.refresh.setAttribute('aria-disabled', 'true');
    if (ico) ico.style.animation = 'ittb-rot .8s linear infinite';
    label.textContent = 'Refreshing…';
    clearNote();

    fetch(REFRESH_URL, { method: 'POST', credentials: 'same-origin' })
      .then(function (r) {
        return r.json().catch(function () { return {}; })
          .then(function (j) { return { ok: r.ok, body: j }; });
      })
      .then(function (res) {
        if (!res.ok) throw new Error(res.body.error || 'Could not reach the directory');
        return loadMe(true);
      })
      .then(function () {
        label.textContent = orig;
        setNote('Access refreshed from Active Directory.', false);
      })
      .catch(function (e) {
        label.textContent = orig;
        setNote(e.message || 'Refresh failed. Try again in a moment.', true);
      })
      .then(function () {
        els.refresh.removeAttribute('aria-disabled');
        if (ico) ico.style.animation = '';
      });
  }

  /* ------------------------------------------------------------------ *
   * view-as picker (super-admins)
   * ------------------------------------------------------------------ */
  var va = {};

  function ensureViewAs() {
    if (va.scrim) return;
    var scrim = document.createElement('div');
    scrim.className = 'ittb-scrim ittb';
    scrim.innerHTML =
      '<div class="ittb-va" role="dialog" aria-modal="true" aria-labelledby="ittb-va-h">' +
        '<div class="ittb-vah">' +
          '<div><h2 id="ittb-va-h">View as another user</h2></div>' +
          '<button type="button" class="ittb-vax" id="ittb-va-x" aria-label="Close">' +
            icon('<path d="M6 6l12 12M18 6L6 18"/>') + '</button>' +
        '</div>' +
        '<input class="ittb-vas" id="ittb-va-q" type="search" autocomplete="off" spellcheck="false" ' +
          'placeholder="Search by name or email…" aria-label="Search users">' +
        '<p class="ittb-vai">Nav items, buttons and page access reflect their role. API calls still run as you.</p>' +
        '<div class="ittb-val" id="ittb-va-list"></div>' +
      '</div>';
    document.body.appendChild(scrim);

    va.scrim = scrim;
    va.q = scrim.querySelector('#ittb-va-q');
    va.list = scrim.querySelector('#ittb-va-list');

    scrim.querySelector('#ittb-va-x').addEventListener('click', closeViewAs);
    scrim.addEventListener('mousedown', function (ev) { if (ev.target === scrim) closeViewAs(); });
    va.q.addEventListener('input', function () { renderUsers(va.q.value.trim().toLowerCase()); });
    scrim.addEventListener('keydown', function (ev) {
      if (ev.key === 'Escape') { ev.preventDefault(); closeViewAs(); return; }
      if (ev.key !== 'Tab') return;
      // keep focus inside the dialog
      var f = scrim.querySelectorAll('button,input,[tabindex]:not([tabindex="-1"])');
      if (!f.length) return;
      var first = f[0], last = f[f.length - 1];
      if (ev.shiftKey && document.activeElement === first) { ev.preventDefault(); last.focus(); }
      else if (!ev.shiftKey && document.activeElement === last) { ev.preventDefault(); first.focus(); }
    });
  }

  function openViewAs() {
    ensureViewAs();
    va.returnTo = document.activeElement;
    va.scrim.classList.add('on');
    va.q.value = '';
    setTimeout(function () { va.q.focus(); }, 60);

    if (usersCache) { renderUsers(''); return; }
    va.list.innerHTML = '<div class="ittb-va-msg">Loading users…</div>';
    fetch(USERS_URL, { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (!d || !d.users) { va.list.innerHTML = '<div class="ittb-va-msg">Could not load the user list.</div>'; return; }
        usersCache = d.users;
        renderUsers('');
      })
      .catch(function () {
        va.list.innerHTML = '<div class="ittb-va-msg">Could not load the user list.</div>';
      });
  }

  function closeViewAs() {
    if (!va.scrim) return;
    va.scrim.classList.remove('on');
    if (va.returnTo && va.returnTo.focus) va.returnTo.focus();
  }

  function renderUsers(q) {
    var cur = (window.itRbac && window.itRbac.isViewingAs && window.itRbac.isViewingAs())
      ? window.itRbac.viewAsTarget() : null;
    var realEmail = (window.itRbac && window.itRbac.realMe && window.itRbac.realMe())
      ? window.itRbac.realMe().email : (me && me.email);

    var rows = (usersCache || []).filter(function (u) {
      if (realEmail && u.email === realEmail) return false;
      if (!q) return true;
      return ((u.display_name || '') + ' ' + u.email).toLowerCase().indexOf(q) !== -1;
    });

    if (!rows.length) {
      va.list.innerHTML = '<div class="ittb-va-msg">No users match “' + esc(q) + '”.</div>';
      return;
    }

    va.list.innerHTML = rows.map(function (u) {
      var isCur = cur && cur.email === u.email;
      return '<button type="button" class="ittb-row" data-email="' + esc(u.email) + '">' +
        '<span style="flex:1;min-width:0">' +
          '<span class="nm" style="display:block">' + esc(u.display_name || u.email) + '</span>' +
          '<span class="em" style="display:block">' + esc(u.email) +
            (u.is_active === false ? ' <span class="tag">inactive</span>' : '') +
          '</span>' +
        '</span>' +
        (isCur ? '<span class="cur">Active</span>' : '') +
      '</button>';
    }).join('');

    Array.prototype.forEach.call(va.list.querySelectorAll('.ittb-row'), function (r) {
      r.addEventListener('click', pickViewAs);
    });
  }

  function pickViewAs(ev) {
    var row = ev.currentTarget;
    var email = row.getAttribute('data-email');
    if (!email) return;
    row.setAttribute('aria-disabled', 'true');
    row.style.opacity = '.5';

    fetch(VIEWAS_URL + encodeURIComponent(email), { credentials: 'same-origin' })
      .then(function (r) { if (!r.ok) throw new Error('Could not load that user’s access'); return r.json(); })
      .then(function (d) {
        closeViewAs();
        if (window.itRbac && window.itRbac.viewAs) window.itRbac.viewAs(d);
      })
      .catch(function (e) {
        row.removeAttribute('aria-disabled');
        row.style.opacity = '';
        var msg = document.createElement('div');
        msg.className = 'ittb-va-msg';
        msg.style.cssText = 'padding:6px 10px;text-align:left';
        msg.textContent = e.message || 'Could not load that user.';
        row.parentNode.insertBefore(msg, row.nextSibling);
        setTimeout(function () { if (msg.parentNode) msg.remove(); }, 3200);
      });
  }

  /* ------------------------------------------------------------------ *
   * Review aid: ?depth=off strips the scope hook so the page renders
   * exactly as it did before the elevation layer. Nothing is persisted and
   * nothing else changes, so it is a like-for-like A/B on the real page
   * rather than on a mockup. ?depth=on is the default and needs no flag.
   * ------------------------------------------------------------------ */
  function depthToggle() {
    try {
      if (/[?&]depth=off(&|$)/.test(window.location.search) && document.body) {
        document.body.removeAttribute('data-dp');
      }
    } catch (e) {}
  }

  function boot() {
    depthToggle();
    build();
    loadMe();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
