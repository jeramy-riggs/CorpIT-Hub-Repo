// =====================================================================
// it-theme.js  (v1.0.0)
//
// Platform theme engine for IT Command. Reads the signed-in user's
// appearance preferences and applies them as CSS variable overrides on
// :root - so every Deep Ocean page that includes this script honors the
// user's choices with zero page-side changes.
//
// Preferences consumed (from /api/rbac/me/prefs):
//   theme          ocean | reef | abyss | ember          (accent family)
//   density        comfortable | compact                 (spacing var)
//   reduce_motion  on | off                              (kills transitions)
//
// Include on any page, ideally in <head> so paint is right first time:
//   <script src="/it-theme.js"></script>
//
// Fast path: last-applied prefs are cached in localStorage and applied
// synchronously at parse time (no flash of default accent); the network
// fetch then reconciles and updates the cache. Signed-out pages simply
// keep defaults.
// =====================================================================

(function () {
  'use strict';
  if (window.__itThemeLoaded) return;
  window.__itThemeLoaded = true;

  var ACCENTS = {
    ocean: { accent: '#22D3EE', hover: '#67E8F9', tint: '#0E3A4A' },
    reef:  { accent: '#34D399', hover: '#6EE7B7', tint: '#0B2E24' },
    abyss: { accent: '#A78BFA', hover: '#C4B5FD', tint: '#231A3E' },
    ember: { accent: '#FBBF24', hover: '#FCD34D', tint: '#2E2508' },
  };
  // Light twins of the four accent families. The dark-mode accents are bright
  // enough to fail contrast on a white panel, so each family needs a darkened
  // counterpart that keeps its hue. These mirror LIGHT_ACCENT in
  // it-theme-toggle.js — keep the two in step.
  var LIGHT_ACCENTS = {
    ocean: { accent: '#0E7C86', hover: '#0B6570', tint: '#D6F1F5' },
    reef:  { accent: '#0F7A54', hover: '#0B5E41', tint: '#D6F4E7' },
    abyss: { accent: '#6D4AC7', hover: '#57399F', tint: '#E9E2FB' },
    ember: { accent: '#A16207', hover: '#7C4A05', tint: '#FBEFD3' }
  };

  function isLight() {
    try { return document.documentElement.getAttribute('data-theme') === 'light'; }
    catch (e) { return false; }
  }

  var CACHE_KEY = 'it_theme_cache';

  function apply(prefs) {
    prefs = prefs || {};
    var r = document.documentElement;
    // These are written as INLINE styles on :root, so they outrank any
    // [data-theme="light"] rule in a stylesheet. Writing the bright dark-mode
    // accent while the page is in light mode therefore sticks — it is not a
    // flash — and any control filled with var(--blue) that carries white text
    // drops to ~1.8:1. Pick the twin that matches the mode actually in force.
    var fam = LIGHT_ACCENTS[prefs.theme] ? prefs.theme : 'ocean';
    var a = isLight() ? LIGHT_ACCENTS[fam] : (ACCENTS[prefs.theme] || ACCENTS.ocean);
    r.style.setProperty('--accent', a.accent);
    r.style.setProperty('--accent-hover', a.hover);
    r.style.setProperty('--accent-tint', a.tint);
    // Console pages use --blue as their accent token; keep them in step.
    r.style.setProperty('--blue', a.accent);
    r.style.setProperty('--blue-h', a.hover);
    r.style.setProperty('--blue-t', a.tint);

    r.style.setProperty('--row-pad', prefs.density === 'compact' ? '4px' : '8px');
    r.setAttribute('data-density', prefs.density === 'compact' ? 'compact' : 'comfortable');

    var m = document.getElementById('it-theme-motion');
    if (prefs.reduce_motion === 'on') {
      if (!m) {
        m = document.createElement('style');
        m.id = 'it-theme-motion';
        m.textContent = '*,*::before,*::after{transition:none!important;animation:none!important;}';
        document.head.appendChild(m);
      }
    } else if (m) {
      m.remove();
    }
  }

  // Synchronous fast path from cache - no accent flash.
  try { apply(JSON.parse(localStorage.getItem(CACHE_KEY) || '{}')); } catch (e) { /* defaults */ }

  // Reconcile from the server.
  // ONE prefs GET per page (2026-09-06). it-theme.js and it-theme-toggle.js both read
  // the same record in the same tick, so the in-flight request is shared through
  // window.__itPrefsGet and dropped once it settles (a later call fetches fresh).
  // Both scripts carry an identical copy of this helper because either may load first.
  function prefsGet() {
    var w = window, cur = w.__itPrefsGet;
    if (cur) return cur.promise;
    var p = fetch('/api/rbac/me/prefs', { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : null; });
    function drop() { if (w.__itPrefsGet && w.__itPrefsGet.promise === p) w.__itPrefsGet = null; }
    p.then(drop, drop);
    w.__itPrefsGet = { promise: p };
    return p;
  }

  prefsGet()
    .then(function (d) {
      if (!d || !d.prefs) return;
      apply(d.prefs);
      try { localStorage.setItem(CACHE_KEY, JSON.stringify(d.prefs)); } catch (e) { /* full */ }
    })
    .catch(function () { /* offline: cache stands */ });

  // Pages (the profile) can push changes live:
  // it-theme-toggle.js fires this when the mode changes; re-running apply()
  // keeps the accent correct no matter which script settled last.
  try {
    window.addEventListener('itcolormodechange', function () {
      try { apply(JSON.parse(localStorage.getItem(CACHE_KEY) || '{}')); } catch (e) {}
    });
  } catch (e) {}

  window.itThemeApply = function (prefs) {
    apply(prefs);
    try { localStorage.setItem(CACHE_KEY, JSON.stringify(prefs)); } catch (e) { /* full */ }
  };
})();
