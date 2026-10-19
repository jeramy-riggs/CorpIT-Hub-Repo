// =====================================================================
// it-hub-link.js — "where is the CorpIT Hub from here, and may I go there?"
//
// The platform is several vhosts on one box (corpit, reporting, subadmin,
// accessportal, directory) and every page carries the same topbar. Until this
// file existed, the topbar's "<- CorpIT Hub" pill and My Profile's Hub links
// were written as bare "/" and "/identity-diag.html": correct on corpit, and
// on every OTHER host either a dead control (reporting's "/" 302s straight
// back to the page you clicked from) or a 404.
//
// Two jobs, both host-aware:
//
//   url(path)   The Hub lives on corpit.nrpi.local. On corpit that is a plain
//               relative path; anywhere else it has to be absolute, and it
//               carries ?from=<this page> so a refusal can send the visitor
//               back where they started instead of stranding them.
//
//   entitled()  Site access is per-vhost by AD group. /api/gate/landing is the
//               same policy the nginx gate applies (site-access.js), and it is
//               readable from a host you are NOT entitled to, so a page can ask
//               "could I open the Hub?" before sending anyone there.
//
// FAIL-OPEN IS DELIBERATE. This is a courtesy check, not a control: the gate on
// corpit is what actually decides. If /api/gate/landing is unreachable we let
// the click through rather than inventing a refusal the platform did not make —
// and the ?from= bounce on no-site-access.html catches the visitor at the far
// end. Never move an authorization decision into this file.
// =====================================================================

(function () {
  'use strict';
  if (window.ITHubLink) return;

  var HOST = 'corpit.nrpi.local';
  var here = String(window.location.hostname || '').toLowerCase();
  var isHome = here === HOST;

  // One request per page, shared by every caller. null means "could not tell".
  var pending = null, known = null;

  function entitled() {
    if (isHome) return Promise.resolve(true);
    if (known !== null) return Promise.resolve(known);
    if (pending) return pending;
    if (!window.fetch) return Promise.resolve(null);
    pending = fetch('/api/gate/landing', { credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (!d || !Array.isArray(d.sites)) return null;      // unreadable -> unknown
        known = d.sites.some(function (s) {
          return String(s && s.host || '').toLowerCase() === HOST;
        });
        return known;
      })
      .catch(function () { return null; });
    return pending;
  }

  /* An absolute URL back to the page doing the asking, so a refusal on the Hub
   * can return the visitor here. Only the origin + path + hash: a query string
   * could carry anything and this value ends up in someone else's URL bar. */
  function fromHere() {
    return window.location.origin + window.location.pathname + (window.location.hash || '');
  }

  function url(path) {
    var p = String(path == null ? '/' : path);
    if (p.charAt(0) !== '/') return p;                       // already absolute: leave it alone
    if (isHome) return p;
    var sep = p.indexOf('?') < 0 ? '?' : '&';
    return 'https://' + HOST + p + sep + 'from=' + encodeURIComponent(fromHere());
  }

  /* Cancel the navigation when we KNOW the visitor cannot open the Hub, so the
   * click leaves them on the page they clicked from instead of walking them
   * through a sign-in round trip to a 403. Unknown (check failed) still goes. */
  function guard(el, label) {
    if (!el || isHome || el.__hubGuarded) return;
    el.__hubGuarded = true;
    entitled();                                              // warm the answer before the click
    el.addEventListener('click', function (ev) {
      if (known !== false) return;                           // true or unknown: let it go
      ev.preventDefault();
      hint(el, label || 'You do not have access to the CorpIT Hub');
    });
  }

  /* A refused click has to say something or it reads as a broken link. Plain
   * text into a node we own -- no innerHTML anywhere in this file. */
  var hintT = null;
  function hint(el, msg) {
    var box = document.getElementById('ithub-hint');
    if (!box) {
      box = document.createElement('div');
      box.id = 'ithub-hint';
      box.setAttribute('role', 'status');
      box.style.cssText = 'position:fixed;z-index:2147483000;max-width:min(320px,80vw);' +
        'padding:8px 12px;border-radius:10px;font:500 12.5px/1.45 system-ui,sans-serif;' +
        'background:#1f2937;color:#f9fafb;box-shadow:0 6px 24px rgba(0,0,0,.28);' +
        'opacity:0;transition:opacity .15s ease;pointer-events:none';
      document.body.appendChild(box);
    }
    box.textContent = msg;
    var r = el.getBoundingClientRect();
    box.style.top = Math.round(r.bottom + 8) + 'px';
    box.style.left = Math.round(Math.max(8, Math.min(r.left, window.innerWidth - 340))) + 'px';
    box.style.opacity = '1';
    clearTimeout(hintT);
    hintT = setTimeout(function () { box.style.opacity = '0'; }, 2600);
  }

  /* One delegated handler for EVERY link on the page that points at the Hub,
   * however it got there. My Profile paints its favourites, activity and change
   * rows from the API, so per-element guards would have to be re-applied after
   * each repaint and would eventually be missed on one of them. Capture phase so
   * a page's own click handler cannot navigate first. */
  function guardDocument() {
    if (isHome || document.__hubGuardedDoc) return;
    document.__hubGuardedDoc = true;
    entitled();
    document.addEventListener('click', function (ev) {
      if (known !== false) return;                           // true or unknown: let it go
      var a = ev.target;
      while (a && a.nodeType === 1 && a.tagName !== 'A') a = a.parentNode;
      if (!a || a.nodeType !== 1 || !a.getAttribute('href')) return;
      var h;
      try { h = new URL(a.href, window.location.href).hostname.toLowerCase(); } catch (e) { return; }
      if (h !== HOST) return;
      ev.preventDefault();
      ev.stopPropagation();
      hint(a, 'You do not have access to the CorpIT Hub');
    }, true);
  }

  window.ITHubLink = {
    HOST: HOST,
    isHome: isHome,
    url: url,
    entitled: entitled,
    guard: guard,
    guardDocument: guardDocument,
    /* Rewrite an existing element's href in place and guard it. Used for the
     * links that are written as "/..." in static markup. */
    wire: function (el, label) {
      if (!el) return;
      var href = el.getAttribute('href');
      if (href && href.charAt(0) === '/') el.setAttribute('href', url(href));
      guard(el, label);
    },
  };
})();
