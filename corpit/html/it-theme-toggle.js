// =====================================================================
// it-theme-toggle.js  (v1.0.0)
//
// Light/dark mode for IT Command consoles. Mirrors the M365 Control
// Centre pattern: :root holds the dark palette, [data-theme="light"]
// overrides it, and a "◐ Theme" pill flips the attribute.
//
// What this adds over that page's inline version:
//   * persistence      - the choice survives reload (localStorage)
//   * no flash         - the stored theme is applied at parse time,
//                        before first paint, so a light user never sees
//                        a dark frame
//   * system default   - first visit follows prefers-color-scheme
//   * one location     - the pill is docked at a fixed top-right slot on
//                        every page, and any pre-existing fixed top-right
//                        cluster (it-hub-link / it-version-badge) is
//                        shifted left to make room, so the control lands
//                        at identical viewport coordinates everywhere
//   * accent handoff   - it-theme.js writes --accent/--blue as INLINE
//                        styles on :root, which outrank a stylesheet
//                        [data-theme="light"] rule. Those tokens are
//                        re-asserted per mode here (see applyAccents).
//
// Load in <head>, BEFORE the page's own <style>, ideally right after
// it-theme.js:  <script src="/it-theme-toggle.js"></script>
// =====================================================================

(function () {
  'use strict';
  if (window.__itThemeToggleLoaded) return;
  window.__itThemeToggleLoaded = true;

  var KEY = 'it_color_mode';           // 'light' | 'dark'
  var DOCK_TOP = 10, DOCK_RIGHT = 14;  // canonical slot, all pages
  var GAP = 10;

  // ---- resolve + apply (runs before paint) --------------------------
  // Stored value may be 'light' | 'dark' | 'system'. 'system' (and absent)
  // means follow prefers-color-scheme.
  function stored() {
    try {
      var v = localStorage.getItem(KEY);
      return (v === 'light' || v === 'dark' || v === 'system') ? v : null;
    } catch (e) { return null; }
  }
  function explicit() { var v = stored(); return (v === 'light' || v === 'dark') ? v : null; }
  function resolve(v) { return (v === 'light' || v === 'dark') ? v : systemPref(); }
  function systemPref() {
    try {
      return (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches)
        ? 'light' : 'dark';
    } catch (e) { return 'dark'; }
  }

  // it-theme.js pushes accent tokens as inline styles on :root, which beat
  // any [data-theme="light"] rule in the sheet. Bright cyan on a white panel
  // is unreadable, so each mode re-asserts its own accent at the same
  // (inline) precedence. Dark values mirror it-theme.js's 'ocean' default;
  // if the user picked another accent family, its cached prefs win on dark.
  // Light counterparts of it-theme.js's four accent families. The bright
  // dark-mode accents fail contrast on a white panel, so each family gets a
  // darkened twin that keeps its hue.
  var LIGHT_ACCENT = {
    ocean: { accent: '#0E7C86', hover: '#0B6570', tint: '#D6F1F5' },
    reef:  { accent: '#0F7A54', hover: '#0B5E41', tint: '#D6F4E7' },
    abyss: { accent: '#6D4AC7', hover: '#57399F', tint: '#E9E2FB' },
    ember: { accent: '#A16207', hover: '#7C4A05', tint: '#FBEFD3' }
  };
  function accentFamily() {
    try {
      var c = JSON.parse(localStorage.getItem('it_theme_cache') || '{}');
      return LIGHT_ACCENT[c.theme] ? c.theme : 'ocean';
    } catch (e) { return 'ocean'; }
  }
  function applyAccents(mode) {
    var r = document.documentElement;
    if (mode === 'dark') {
      // hand control back to it-theme.js so the user's accent family returns
      var cached = null;
      try { cached = JSON.parse(localStorage.getItem('it_theme_cache') || 'null'); } catch (e) {}
      if (cached && window.itThemeApply) { window.itThemeApply(cached); return; }
      // it-theme.js absent or signed out: clear our overrides so the page's
      // own :root values apply again
      ['--accent','--blue','--accent-hover','--blue-h','--accent-tint','--blue-t']
        .forEach(function (t) { r.style.removeProperty(t); });
      return;
    }
    var a = LIGHT_ACCENT[accentFamily()];
    ['--accent', '--blue'].forEach(function (t) { r.style.setProperty(t, a.accent); });
    ['--accent-hover', '--blue-h'].forEach(function (t) { r.style.setProperty(t, a.hover); });
    ['--accent-tint', '--blue-t'].forEach(function (t) { r.style.setProperty(t, a.tint); });
  }

  function apply(mode, persist) {
    document.documentElement.setAttribute('data-theme', mode);
    applyAccents(mode);
    if (persist) { try { localStorage.setItem(KEY, mode); } catch (e) {} }
    var btn = document.getElementById('itThemeBtn');
    if (btn) {
      btn.setAttribute('aria-pressed', mode === 'light' ? 'true' : 'false');
      btn.title = mode === 'light' ? 'Switch to dark mode' : 'Switch to light mode';
    }
    try {
      window.dispatchEvent(new CustomEvent('itcolormodechange', { detail: { mode: mode } }));
    } catch (e) {}
  }

  var current = resolve(stored());
  apply(current, false);   // synchronous: no flash of the wrong palette

  // follow the OS only while the user has not made an explicit choice
  try {
    var mq = window.matchMedia('(prefers-color-scheme: light)');
    var onSys = function (e) { if (!explicit()) apply(e.matches ? 'light' : 'dark', false); };
    if (mq.addEventListener) mq.addEventListener('change', onSys);
    else if (mq.addListener) mq.addListener(onSys);
  } catch (e) {}

  // ---- server-side persistence --------------------------------------
  // localStorage alone dies when the tech clears site data, and does not
  // follow them to another machine. The authoritative copy is the
  // color_mode key in rbac_user_prefs, reached through /api/rbac/me/prefs.
  var userActed = false;   // a click always beats an in-flight GET

  function token() {
    try { var s = JSON.parse(sessionStorage.getItem('sso_user') || '{}'); return s.idToken || null; }
    catch (e) { return null; }
  }

  // ONE prefs GET per page (2026-09-06). it-theme.js and it-theme-toggle.js both read
  // the same record in the same tick, so the in-flight request is shared through
  // window.__itPrefsGet and dropped once it settles (a later call fetches fresh).
  // Both scripts carry an identical copy of this helper because either may load first.
  function prefsGet(t) {
    var w = window, cur = w.__itPrefsGet;
    if (cur && cur.token === t) return cur.promise;
    var p = fetch('/api/rbac/me/prefs', { headers: { Authorization: 'Bearer ' + t } })
      .then(function (r) { return r.ok ? r.json() : null; });
    function drop() { if (w.__itPrefsGet && w.__itPrefsGet.promise === p) w.__itPrefsGet = null; }
    p.then(drop, drop);
    w.__itPrefsGet = { token: t, promise: p };
    return p;
  }

  function pullFromServer() {
    var t = token();
    if (!t) return;                       // signed out: local value stands
    prefsGet(t)
      .then(function (d) {
        if (!d || !d.prefs || userActed) return;
        var srv = d.prefs.color_mode;
        if (srv !== 'light' && srv !== 'dark' && srv !== 'system') return;
        try { localStorage.setItem(KEY, srv); } catch (e) {}
        var want = resolve(srv);
        if (want !== document.documentElement.getAttribute('data-theme')) apply(want, false);
      })
      .catch(function () { /* offline: local value stands */ });
  }

  var pushTimer = null;
  function pushToServer(value) {
    var t = token();
    if (!t) return;
    clearTimeout(pushTimer);
    pushTimer = setTimeout(function () {
      fetch('/api/rbac/me/prefs', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + t },
        body: JSON.stringify({ prefs: { color_mode: value } })
      }).catch(function () { /* offline: localStorage still has it */ });
    }, 250);
  }

  pullFromServer();

  // ---- the control --------------------------------------------------
  function glyph(cls, path) {
    return '<svg class="itt-gl ' + cls + '" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
      'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + path + '</svg>';
  }
  var ICON_SUN  = glyph('itt-sun', '<circle cx="12" cy="12" r="4.2"/><path d="M12 2.6v2.2M12 19.2v2.2' +
    'M4.2 4.2l1.6 1.6M18.2 18.2l1.6 1.6M2.6 12h2.2M19.2 12h2.2M4.2 19.8l1.6-1.6M18.2 5.8l1.6-1.6"/>');
  var ICON_MOON = glyph('itt-moon', '<path d="M20 14.2A8.2 8.2 0 0 1 9.8 4 8.6 8.6 0 1 0 20 14.2Z"/>');

  function boot() {
    if (document.getElementById('itThemeBtn')) return;

    var css = document.createElement('style');
    css.textContent =
      '#itThemeDock{position:fixed;z-index:10001;top:' + DOCK_TOP + 'px;right:' + DOCK_RIGHT + 'px;' +
        'display:inline-flex;align-items:center}' +
      '#itThemeDock #itThemeBtn{display:inline-flex;align-items:center;gap:6px;cursor:pointer;white-space:nowrap;' +
        'font:500 12px "IBM Plex Sans",system-ui,-apple-system,sans-serif;padding:5px 11px;border-radius:7px;' +
        'color:#94a3b8;background:rgba(10,22,40,.85);border:1px solid #1e293b;' +
        '-webkit-backdrop-filter:blur(6px);backdrop-filter:blur(6px);transition:.15s}' +
      '#itThemeDock #itThemeBtn:hover{color:#38bdf8;border-color:rgba(56,189,248,.4);background:rgba(56,189,248,.08)}' +
      '#itThemeDock #itThemeBtn:focus-visible{outline:2px solid #38bdf8;outline-offset:2px}' +
      '#itThemeDock #itThemeBtn .itt-ico{font-size:13px;line-height:1}' +
      // light-mode skin for the pill itself (it sits above page chrome)
      '[data-theme="light"] #itThemeDock #itThemeBtn{color:#41526b;background:rgba(255,255,255,.9);border-color:#cbd5e3}' +
      '[data-theme="light"] #itThemeDock #itThemeBtn:hover{color:#0e7c86;border-color:rgba(14,124,134,.45);background:rgba(14,124,134,.08)}' +

      // ---- shared injected chrome -------------------------------------
      // it-hub-link.js / it-version-chip.js / it-version-badge.js / it-nav.js
      // hardcode a dark palette and append their <style> AFTER this one, so
      // these rules carry an attribute selector to outrank them.
      '[data-theme="light"] .ithub-pill{color:#41526b;background:rgba(255,255,255,.9);border-color:#cbd5e3}' +
      '[data-theme="light"] .ithub-pill:hover{color:#0e7c86;border-color:rgba(14,124,134,.4);background:rgba(14,124,134,.08)}' +
      '[data-theme="light"] .ithub-menu{background:#ffffff;border-color:#dde3ec;box-shadow:0 12px 32px rgba(20,40,80,.18)}' +
      '[data-theme="light"] .ithub-menu .um-id{border-bottom-color:#dde3ec}' +
      '[data-theme="light"] .ithub-menu .um-name{color:#0f1b2d}' +
      '[data-theme="light"] .ithub-menu .um-email{color:#7387a1}' +
      '[data-theme="light"] .ithub-menu .um-item{color:#0f1b2d}' +
      '[data-theme="light"] .ithub-menu .um-item:hover{background:#eef1f6}' +
      '[data-theme="light"] .it-version-chip,[data-theme="light"] .it-version-chip a{color:#7387a1}' +
      '[data-theme="light"] .it-version-badge{color:#41526b;background:rgba(255,255,255,.9);border-color:#cbd5e3}' +
      '[data-theme="light"] .itnav{background:#f4f7fb;border-color:#dde3ec}' +
      '[data-theme="light"] .itnav-link,[data-theme="light"] .itnav-trigger,[data-theme="light"] .itnav-homebase{color:#41526b}' +
      '[data-theme="light"] .itnav-link:hover,[data-theme="light"] .itnav-trigger:hover{background:rgba(15,27,45,.06);color:#0f1b2d}' +
      '[data-theme="light"] .itnav-menu{background:#ffffff;border-color:#dde3ec;box-shadow:0 12px 32px rgba(20,40,80,.18)}' +
      '[data-theme="light"] .itnav-menu a{color:#0f1b2d}' +
      '[data-theme="light"] .itnav-menu a:hover{background:#eef1f6}' +

      // the control shows its DESTINATION: a sun while dark, a moon while light
      '#itThemeBtn .itt-gl{width:15px;height:15px;flex:0 0 auto;display:none}' +
      '#itThemeBtn .itt-sun{display:block}' +
      '[data-theme="light"] #itThemeBtn .itt-sun{display:none}' +
      '[data-theme="light"] #itThemeBtn .itt-moon{display:block}' +
      '@media print{#itThemeDock{display:none}}';
    document.head.appendChild(css);

    var dock = document.createElement('div');
    dock.id = 'itThemeDock';
    var btn = document.createElement('button');
    btn.id = 'itThemeBtn';
    btn.type = 'button';
    btn.setAttribute('aria-label', 'Toggle light and dark mode');
    btn.innerHTML = ICON_SUN + ICON_MOON + '<span class="itt-txt">Theme</span>';
    btn.addEventListener('click', function () {
      var next = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
      userActed = true;
      apply(next, true);
      pushToServer(next);      // survives logout and a cleared browser
    });
    // it-topbar.js owns the top-right cluster where it is present; render
    // into its slot so there is one group of controls instead of a pill
    // floating over the page's own bar.
    var slot = document.getElementById('ittb-theme-slot');
    if (slot) {
      btn.classList.add('ittb-ctl');
      slot.appendChild(btn);
    } else {
      dock.appendChild(btn);
      document.body.appendChild(dock);
    }

    apply(document.documentElement.getAttribute('data-theme') || current, false);
    if (!slot) reflow();
    // the cluster may mount after us; tell it there is a button to adopt
    try { window.dispatchEvent(new CustomEvent('it-theme-toggle-ready')); } catch (e) {}
  }

  // The pill owns the canonical top-right slot on every page, so whatever
  // already lives there has to move. Two cases:
  //   1. a known fixed cluster (it-hub-link / it-version-badge) -> re-anchor it
  //   2. the page's own top bar in normal flow -> reserve space with padding
  // Case 2 is found by asking the document what is actually underneath the
  // pill, which is the only reliable test across this many hand-built layouts.
  function reflow() {
    var btn = document.getElementById('itThemeBtn');
    if (btn && btn.closest('.ittb')) return;   // adopted into the shared cluster
    var dock = document.getElementById('itThemeDock');
    if (!dock) return;
    var w = dock.offsetWidth;
    if (!w) return;
    var need = w + GAP;
    var shift = DOCK_RIGHT + need;

    ['.ithub-cluster.ithub-fixed', '.it-version-badge-fixed'].forEach(function (sel) {
      var el = document.querySelector(sel);
      if (el && el.dataset.ittShifted !== '1') {
        el.style.right = shift + 'px';
        el.dataset.ittShifted = '1';
      }
    });

    // what sits under the pill?
    var prev = dock.style.pointerEvents;
    dock.style.pointerEvents = 'none';
    var hits = [];
    try {
      hits = document.elementsFromPoint(
        Math.max(0, window.innerWidth - DOCK_RIGHT - Math.round(w / 2)),
        DOCK_TOP + Math.round((dock.offsetHeight || 26) / 2)) || [];
    } catch (e) {}
    dock.style.pointerEvents = prev;

    for (var i = 0; i < hits.length; i++) {
      var el = hits[i];
      if (!el || el === document.body || el === document.documentElement) continue;
      if (dock.contains(el)) continue;
      // climb to the bar-like container: spans most of the width, short, at top
      var bar = el;
      while (bar && bar !== document.body) {
        var r = bar.getBoundingClientRect();
        if (r.width >= window.innerWidth * 0.55 && r.height <= 110 && r.top <= 24) break;
        bar = bar.parentElement;
      }
      if (!bar || bar === document.body) continue;
      if (bar.dataset.ittPadded === '1') return;
      var cs = getComputedStyle(bar);
      if (cs.position === 'fixed' || cs.position === 'absolute') {
        // right-anchored chrome: push it in from the edge
        var right = parseFloat(cs.right);
        bar.style.right = ((isNaN(right) ? 0 : right) + need) + 'px';
      } else {
        // normal-flow bar: reserve the slot so its right-aligned children move
        var pr = parseFloat(cs.paddingRight) || 0;
        bar.style.paddingRight = (pr + need) + 'px';
      }
      bar.dataset.ittPadded = '1';
      return;
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else { boot(); }
  // those clusters inject asynchronously; re-check a few times
  window.addEventListener('load', reflow);
  setTimeout(reflow, 300);
  setTimeout(reflow, 1200);
  window.addEventListener('resize', reflow);

  // Public API. Pages listen for 'itcolormodechange' to repaint canvases
  // (Chart.js etc.); my-profile.html uses setPreference to expose the
  // Light / Dark / System control alongside the other appearance prefs.
  window.itColorMode = {
    // the mode actually rendering right now
    get: function () { return document.documentElement.getAttribute('data-theme'); },
    // what the user chose: 'light' | 'dark' | 'system'
    getPreference: function () { return stored() || 'system'; },
    set: function (m) {
      userActed = true;
      var v = (m === 'light' || m === 'dark') ? m : 'dark';
      apply(v, true); pushToServer(v);
    },
    setPreference: function (v) {
      userActed = true;
      v = (v === 'light' || v === 'dark' || v === 'system') ? v : 'system';
      try { localStorage.setItem(KEY, v); } catch (e) {}
      apply(resolve(v), false);
      pushToServer(v);
    }
  };
})();
