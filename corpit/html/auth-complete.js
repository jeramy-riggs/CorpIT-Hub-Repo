/* auth-complete.js — the last step of a CorpIT Hub sign-in.
 *
 * By the time this runs, /api/auth/callback has already validated the Entra
 * id_token server-side and set the HttpOnly it_session cookie. nginx's gate is
 * satisfied. What is still missing is the frontend's copy: rbac-middleware.js
 * authenticates API calls from `Authorization: Bearer`, which every page reads
 * out of sessionStorage.sso_user — and a 302 cannot write sessionStorage.
 *
 * So this page asks for the token that is already in its own cookie, stores it in
 * the exact shape the retired implicit flow used, and forwards. It is deliberately
 * the only new thing the browser has to do.
 */
(function () {
  'use strict';

  var work = document.getElementById('work');
  var err  = document.getElementById('err');

  function fail(msg) {
    document.getElementById('errmsg').textContent = msg;
    work.style.display = 'none';
    err.style.display = 'block';
  }

  // Only ever forward to a path on this origin. '//evil.com' looks relative but
  // browsers read it as absolute, so it is rejected explicitly — the server makes
  // the same check, and this keeps the two ends honest.
  function safePath(raw) {
    // CORPIT-REDIRECT-HARDEN
    // The URL parser strips tab/LF/CR before parsing, so '/<TAB>/evil.com' reads
    // as '//evil.com' - an absolute URL off this origin - and the old prefix
    // tests passed it through to location.replace().
    if (!raw) return '/';
    if (/[\u0000-\u0020\\]/.test(raw)) return '/';
    if (raw.charAt(0) !== '/') return '/';
    if (raw.indexOf('//') === 0) return '/';
    try {
      var u = new URL(raw, window.location.origin);
      if (u.origin !== window.location.origin) return '/';
      var p = u.pathname + u.search;
      // '/..//evil.com' normalises to the protocol-relative '//evil.com', which
      // location.replace() would read as an absolute URL off this origin.
      if (p.indexOf('//') === 0) return '/';
      return p;
    } catch (e) {
      return '/';
    }
  }

  var rd = '/';
  try {
    rd = safePath(new URLSearchParams(window.location.search).get('rd'));
  } catch (e) { rd = '/'; }

  fetch('/api/auth/token', { credentials: 'same-origin', cache: 'no-store' })
    .then(function (r) {
      if (!r.ok) throw new Error('no_session_' + r.status);
      return r.json();
    })
    .then(function (j) {
      if (!j || !j.ok || !j.token) throw new Error('no_token');
      // Same shape login.html has always written: name, email, idToken.
      sessionStorage.setItem('sso_user', JSON.stringify({
        name: j.name || j.email || '',
        email: j.email || '',
        idToken: j.token
      }));
      // replace() so Back does not land the user on this throwaway page.
      window.location.replace(rd);
    })
    .catch(function (e) {
      fail('We signed you in with Microsoft, but this browser could not pick up the '
         + 'session. Please try signing in again.');
      if (window.console) console.warn('[auth-complete]', e && e.message);
    });
})();
