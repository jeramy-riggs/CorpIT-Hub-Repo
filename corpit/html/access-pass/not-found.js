// not-found.js — fills in /not-found.html, the page nginx serves for its own "no such file" (404) on a gated site.
// The page is complete without it. This adds the two things only the browser knows: the address that was asked for, and a Back button.
// Text goes in with textContent only; the path comes from the URL bar and is never parsed as markup.
(function () {
  'use strict';
  var path = window.location.pathname + window.location.search;
  if (path.length > 140) path = path.slice(0, 137) + '…';

  var d = document.getElementById('d-path');
  if (d) d.textContent = path + '  ·  not found (HTTP 404)';
  var s = document.getElementById('d-site');
  if (s) s.textContent = window.location.host + ' is answering';

  // Back only when there is a page on this site to go back to; otherwise the home button is the only action.
  // Built here, not shipped hidden in the HTML: the button's own display rule would override a hidden attribute.
  var row = document.getElementById('row');
  var ref = '';
  try { ref = document.referrer ? new URL(document.referrer).origin : ''; } catch (e) { ref = ''; }
  if (row && window.history.length > 1 && ref === window.location.origin) {
    var back = document.createElement('a');
    back.className = 'btn btn--ghost';
    back.href = document.referrer;
    back.textContent = 'Go back';
    back.addEventListener('click', function (ev) { ev.preventDefault(); window.history.back(); });
    row.appendChild(back);
  }
})();
