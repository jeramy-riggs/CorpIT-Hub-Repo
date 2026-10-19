// Fills in which site was refused, then offers a way onward.
// Kept in its own file because the platform CSP forbids inline script;
// textContent (never innerHTML) so a hostname can never be treated as markup.
(function () {
  var el = document.getElementById('host');
  if (el) el.textContent = window.location.host;

  /* A refusal should not be a dead end. Ask the gate which sites this person CAN
   * open and move them to one.
   *
   * Two candidates, in order:
   *
   *   1. ?from=<absolute url>  — the page that sent them here. Cross-vhost links
   *      (the topbar's "CorpIT Hub" pill, My Profile's Hub links) carry it, so a
   *      visitor who follows one to a site their groups do not open is returned
   *      to exactly where they were rather than dropped on some other host.
   *   2. the gate's own pick — the preferred site their groups DO open.
   *
   * The hostname is used to build the URL but is NEVER trusted as free text: it
   * has to look like a hostname and must not be the host that just refused us,
   * or this becomes an open redirect driven by an API response. `from` is held
   * to a stricter bar again — https, and its host must appear in THIS caller's
   * own allowed-site list — so a crafted link can only ever return someone to a
   * site they could already have opened themselves. The gate already excludes
   * the current host; these are the second checks, on the client side, because
   * a redirect target is worth validating twice. */
  var slot = document.getElementById('onward');
  if (!slot || !window.fetch) return;

  function hostOk(h) {
    return /^[a-z0-9.-]{1,253}$/i.test(h) &&
           h.toLowerCase() !== String(window.location.host).toLowerCase();
  }

  /* The page we were sent from, if it is one this person may actually open. */
  function backLink(sites) {
    var raw = /[?&]from=([^&]+)/.exec(window.location.search || '');
    if (!raw) return null;
    var u;
    try { u = new URL(decodeURIComponent(raw[1])); } catch (e) { return null; }
    if (u.protocol !== 'https:') return null;
    if (!hostOk(u.host)) return null;
    var allowed = (sites || []).some(function (s) {
      return String(s && s.host || '').toLowerCase() === u.host.toLowerCase();
    });
    if (!allowed) return null;
    return { url: u.origin + u.pathname + (u.hash || ''), host: u.host, back: true };
  }

  fetch('/api/gate/landing?exclude=' + encodeURIComponent(window.location.host),
        { credentials: 'same-origin' })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (d) {
      if (!d) return;
      var go = backLink(d.sites);
      if (!go) {
        if (!d.host || !hostOk(String(d.host))) return;
        go = { url: 'https://' + String(d.host) + '/', host: String(d.host), back: false };
      }

      var secs = 5, timer = null;

      slot.hidden = false;
      var txt = document.createElement('span');
      var link = document.createElement('a');
      link.href = go.url; link.textContent = go.host;
      var stay = document.createElement('button');
      stay.type = 'button'; stay.className = 'stay'; stay.textContent = 'Stay here';
      stay.addEventListener('click', function () {
        if (timer) clearInterval(timer);
        slot.textContent = '';
        var a2 = document.createElement('a');
        a2.href = go.url; a2.textContent = (go.back ? 'Back to ' : 'Go to ') + go.host;
        slot.appendChild(a2);
      });

      function paint() {
        txt.textContent = go.back ? 'Taking you back to ' : 'You do have access to ';
        slot.textContent = '';
        slot.appendChild(txt);
        slot.appendChild(link);
        slot.appendChild(document.createTextNode(' — in ' + secs + 's. '));
        slot.appendChild(stay);
      }
      paint();
      timer = setInterval(function () {
        secs -= 1;
        if (secs <= 0) { clearInterval(timer); window.location.replace(go.url); return; }
        paint();
      }, 1000);
    })
    .catch(function () { /* no onward offer; the page still explains the refusal */ });
})();
