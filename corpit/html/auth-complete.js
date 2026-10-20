/* auth-complete.js — the last step of a CorpIT Hub sign-in.
 *
 * /api/auth/callback validates the Entra id_token server-side and sets the
 * HttpOnly it_session cookie. Read /api/auth/identity to populate a display-only tab
 * mirror; API calls authenticate with the cookie, never a JavaScript token.
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

  // [CORPIT-RETURN-HASH] login.js holds a deep link's #view (it never reaches the
  // server). Put it back only when it was saved for this same path in the last
  // 15 minutes, and drop it after one use either way.
  var hash = '';
  try {
    var saved = JSON.parse(sessionStorage.getItem('it_return_hash') || 'null');
    sessionStorage.removeItem('it_return_hash');
    if (saved && typeof saved.hash === 'string' && /^#[A-Za-z0-9_\-\/.:]{1,100}$/.test(saved.hash) &&
        typeof saved.at === 'number' && Date.now() - saved.at < 15 * 60 * 1000 &&
        typeof saved.path === 'string' && safePath(saved.path) === rd) {
      hash = saved.hash;
    }
  } catch (e) { hash = ''; }

  fetch('/api/auth/identity', { credentials: 'same-origin', cache: 'no-store' })
    .then(function (r) {
      if (!r.ok) throw new Error('no_session_' + r.status);
      return r.json();
    })
    .then(function (j) {
      if (!j || !j.email) throw new Error('no_session');
      // Keep only display identity in tab storage. API calls use the HttpOnly
      // session cookie; no portable bearer credential reaches page JavaScript.
      sessionStorage.setItem('sso_user', JSON.stringify({
        name: j.displayName || j.email || '',
        email: j.email || '',
        idToken: '',
        cookieSession: true
      }));
      // replace() so Back does not land the user on this throwaway page.
      window.location.replace(rd + hash);
    })
    .catch(function (e) {
      fail('We signed you in with Microsoft, but this browser could not pick up the '
         + 'session. Please try signing in again.');
      if (window.console) console.warn('[auth-complete]', e && e.message);
    });
})();
