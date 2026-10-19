// =====================================================================
// it-version.js  (v1.0.0)  —  version branding as a watermark
//
// Replaces three separate treatments of the same information:
//   it-version-chip.js    a fixed bottom-right mono chip
//   it-version-badge.js   a bordered pill with a glowing cyan dot, docked
//                         into the nav, plus a page footer
//   inline .verchip       a hand-written bordered span in the top bar
//                         (helpdesk-landing, hardcoded "v2.0.0")
//
// A version number is not a control and does not deserve a box. It is a
// mark on the surface: set quietly in the corner, in the page's own voice,
// under the content rather than competing with it. No border, no fill, no
// dot, no shadow — and pointer-events:none, so it can never intercept a
// click meant for the page.
//
//   <script src="/it-version.js" data-app-key="my-app" defer></script>
//
// Optional attributes:
//   data-footer="1"   also render the changelog / report-a-bug footer that
//                     it-version-badge.js used to own. Only the pages that
//                     already had that footer should pass it — dropping the
//                     pill must not drop the only route to the changelog.
//   data-label="..."  override the display name (default: the app_name the
//                     changelog API returns, else the key).
// =====================================================================

(function () {
  'use strict';
  if (window.__itVersionLoaded) return;
  window.__itVersionLoaded = true;

  var script = document.currentScript;
  var appKey = script && script.getAttribute('data-app-key');
  if (!appKey) return;
  // corpit: the footer links to /it-command-changelog.html and /report-bug.html.
  // Both were withheld here until 2026-09-07 because neither page existed on
  // this host and a footer of dead links is worse than none. Both are now
  // deployed and both link forms were exercised in QA (the changelog deep-link
  // hash, and the bug form's app/version/page query), so the attribute is read
  // again. Carried by observability.html and server-health.html only.
  var wantFooter = script.getAttribute('data-footer') === '1';
  var labelOverride = script.getAttribute('data-label') || '';
  // data-version pins the number statically. The changelog API is behind the
  // RBAC gate and 401s on any page that does not load rbac-client.js, and a
  // watermark that silently fails to appear is worse than one that never
  // needed the network. Pages whose version was already hardcoded pass this.
  var staticVersion = script.getAttribute('data-version') || '';

  var CHANGELOG_URL = '/it-command-changelog.html';
  var BUG_FORM_URL  = '/report-bug.html';

  function css() {
    if (document.getElementById('it-version-css')) return;
    var s = document.createElement('style');
    s.id = 'it-version-css';
    s.textContent = [
      '.it-watermark{',
        'position:fixed;right:15px;bottom:11px;z-index:2;',
        'font:600 9.5px/1 "IBM Plex Sans",system-ui,-apple-system,"Segoe UI",sans-serif;',
        'letter-spacing:.17em;text-transform:uppercase;white-space:nowrap;',
        'color:#E6EDF7;opacity:.17;',
        'pointer-events:none;user-select:none;-webkit-user-select:none;',
      '}',
      // The mark belongs to the surface, so it inverts with it.
      '[data-theme="light"] .it-watermark,body.light .it-watermark{color:#101C2E;opacity:.28;}',
      // Its own version numerals sit on the baseline with the letters.
      '.it-watermark b{font-weight:600;font-variant-numeric:tabular-nums;letter-spacing:.10em;}',
      '.it-watermark i{font-style:normal;opacity:.55;margin:0 .5em;}',
      '@media (max-width:640px){.it-watermark{display:none;}}',
      '@media print{.it-watermark,.it-version-footer{display:none;}}',

      // Footer (unchanged in purpose, restyled to match the rest of the work)
      '.it-version-footer{',
        'margin-top:40px;padding:18px 20px;text-align:center;',
        'border-top:1px solid rgba(255,255,255,.06);',
        'font:400 12px/1.6 "IBM Plex Sans",system-ui,-apple-system,sans-serif;color:#7E93AE;',
      '}',
      '[data-theme="light"] .it-version-footer{border-top-color:rgba(16,28,46,.10);color:#5A6E8A;}',
      '.it-version-footer a{color:inherit;text-decoration:none;border-bottom:1px solid currentColor;',
        'padding-bottom:1px;margin:0 8px;opacity:.85;transition:opacity .15s ease;}',
      '.it-version-footer a:hover{opacity:1;}',
      '.it-version-footer a:focus-visible{outline:2px solid var(--accent,#38bdf8);outline-offset:3px;}'
    ].join('');
    document.head.appendChild(s);
  }

  function esc(v) {
    var d = document.createElement('div');
    d.textContent = v == null ? '' : String(v);
    return d.innerHTML;
  }

  function renderMark(label, version) {
    var el = document.getElementById('it-watermark');
    if (!el) {
      el = document.createElement('div');
      el.id = 'it-watermark';
      el.className = 'it-watermark';
      el.setAttribute('aria-hidden', 'true');   // decorative; not read aloud
      document.body.appendChild(el);
    }
    // [CORPIT-QA 2026-09-08] A falsy version renders the label alone. Every
    // caller below can now pass null for "we could not determine it", which
    // is the same stance renderFooterLinksOnly() already took for the footer.
    el.innerHTML = esc(label) + (version
      ? '<i>·</i><b>v' + esc(version) + '</b>'
      : '');
  }

  function renderFooter(label, version) {
    if (!wantFooter || document.querySelector('.it-version-footer')) return;
    var f = document.createElement('div');
    f.className = 'it-version-footer';
    f.innerHTML =
      esc(label) + ' &middot; v' + esc(version) + ' &middot; ' +
      '<a href="' + CHANGELOG_URL + '#' + encodeURIComponent(appKey) + '">Changelog</a>' +
      '<a href="#" data-bug-report>Report a bug</a>';
    document.body.appendChild(f);
    var bug = f.querySelector('[data-bug-report]');
    if (bug) bug.addEventListener('click', function (e) {
      e.preventDefault();
      window.open(BUG_FORM_URL +
        '?app=' + encodeURIComponent(label) +
        '&version=' + encodeURIComponent(version) +
        '&page=' + encodeURIComponent(location.pathname + location.search), '_blank');
    });
  }

  // Footer without a version we could not confirm — links only, no invented number.
  function renderFooterLinksOnly(label) {
    if (document.querySelector('.it-version-footer')) return;
    var f = document.createElement('div');
    f.className = 'it-version-footer';
    f.innerHTML = esc(label) + ' &middot; ' +
      '<a href="' + CHANGELOG_URL + '#' + encodeURIComponent(appKey) + '">Changelog</a>' +
      '<a href="#" data-bug-report>Report a bug</a>';
    document.body.appendChild(f);
    var bug = f.querySelector('[data-bug-report]');
    if (bug) bug.addEventListener('click', function (e) {
      e.preventDefault();
      window.open(BUG_FORM_URL + '?app=' + encodeURIComponent(label) +
        '&page=' + encodeURIComponent(location.pathname + location.search), '_blank');
    });
  }

  function boot() {
    css();
    if (staticVersion) {
      renderMark(labelOverride || appKey, staticVersion);
      renderFooter(labelOverride || appKey, staticVersion);
      return;
    }
    fetch('/api/bugs/changelog/' + encodeURIComponent(appKey))
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (d) {
        var app = d && d.app || {};
        var label = labelOverride || app.app_name || appKey;
        // [CORPIT-QA 2026-09-08] Was: app.current_version || '1.0.0'. A row
        // with no version would then display 1.0.0 as though it had been
        // read from the registry. current_version is NOT NULL today, so this
        // never fired -- it is closed here so that adding a row without a
        // version cannot silently publish an invented one later.
        var version = app.current_version || null;
        renderMark(label, version);
        if (version) renderFooter(label, version);
        else if (wantFooter) renderFooterLinksOnly(label);
      })
      .catch(function () {
        // No changelog record is not an error worth showing anyone: a mark with
        // no version to state simply does not appear. The FOOTER is different —
        // on the pages that carry it, it is the only route to the changelog and
        // the bug form, so it must render regardless of the fetch. (The badge
        // this replaced did the same in its own catch branch; dropping it would
        // have quietly removed those links.)
        var label = labelOverride || appKey;
        // [CORPIT-QA 2026-09-08] Was: renderMark(label, '1.0.0'). Reaching
        // this branch means the changelog lookup failed outright, so the
        // version is precisely what we do not know. The label still renders.
        if (labelOverride) renderMark(label, null);
        if (wantFooter) renderFooterLinksOnly(label);
      });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
