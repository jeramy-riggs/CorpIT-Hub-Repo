// page-guard.js — sends a signed-in person who lacks access to THIS page to the Access Pass screen, instead of leaving them on a blank page.
//
// Opt-in, one tag per page, loaded AFTER /rbac-client.js:
//   <script src="/rbac-client.js"></script>
//   <script src="/access-pass/page-guard.js" data-page="identity-diag" data-level="read"></script>
//
//   data-page   the page's rbac key (same one as data-rbac-page elsewhere on the page)
//   data-level  "read" (default) or "admin"
//
// It only ever acts on a verified "no". rbac-client already hides the guarded parts of a page while the answer is unknown and keeps
// them hidden if it never arrives; this script adds the way forward, nothing more. So it does NOT redirect when:
//   - the access check is unavailable or the person is not signed in (a wrong "request access" screen is worse than a blank one),
//   - a super admin is previewing another person with View As (they would be bounced out of the preview),
//   - the page or level in the tag is not something the access-request service accepts.
// The destination is /access-needed.html?page=<key>&level=<level>, which asks the hub what is missing and files the ticket on one press.
// location.replace, not assign: Back goes to wherever they came from instead of bouncing them straight into this page again.
(function () {
  'use strict';

  var tag = document.currentScript;
  if (!tag) return;
  var page = (tag.getAttribute('data-page') || '').trim();
  var level = (tag.getAttribute('data-level') || 'read').trim().toLowerCase();
  // same shape the hub accepts (access-request-routes.js PAGE_RE); anything else would only earn a 400 on the other side
  if (!/^[a-z0-9][a-z0-9_.-]{0,63}$/i.test(page)) return;
  if (level !== 'read' && level !== 'admin') return;

  var settled = false;
  function go() {
    if (settled) return;
    settled = true;
    window.location.replace('/access-needed.html?page=' + encodeURIComponent(page) + '&level=' + level);
  }

  function judge() {
    var rb = window.itRbac;
    if (!rb || typeof rb.canAccess !== 'function') return;
    if (typeof rb.isVerified === 'function' && !rb.isVerified()) return;     // pending / unauthenticated / unavailable: say nothing
    if (typeof rb.isViewingAs === 'function' && rb.isViewingAs()) return;    // View As is a preview, not the person's own access
    var ok = level === 'admin' ? rb.canAdmin(page) : rb.canAccess(page);
    if (ok === false) go();                                                  // only a definite "no"
  }

  // rbac-client may still be loading, or may have loaded before us; wait for it briefly, never forever
  var tries = 0;
  (function wait() {
    var rb = window.itRbac;
    if (rb && typeof rb.ready === 'function') {
      var p;
      try { p = rb.ready(); } catch (e) { return; }
      if (p && typeof p.then === 'function') p.then(judge, function () {});
      else judge();
      return;
    }
    if (++tries < 100) window.setTimeout(wait, 100);                         // ~10s, then give up quietly
  })();
})();
