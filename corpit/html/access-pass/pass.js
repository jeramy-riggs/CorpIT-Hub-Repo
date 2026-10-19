// pass.js — drives /no-site-access.html (kind=site) and /access-needed.html (kind=app).
//
// What it does: asks /api/access-request/context what was refused and what access would fix it, shows that on
// the badge, and on ONE press files ONE Help Desk ticket through /api/access-request/file. The person types
// nothing; the server rebuilds every fact from the verified session, so the browser is only ever asked "which
// button was pressed". Kept in its own file because the platform CSP forbids inline script. All text goes in
// through textContent, never innerHTML, so a host, group or page name can never be treated as markup.
(function () {
  'use strict';

  var body = document.body;
  var KIND = body.getAttribute('data-kind') === 'app' ? 'app' : 'site';
  var qs = new URLSearchParams(window.location.search);
  var PAGE = String(qs.get('page') || '').slice(0, 64);
  var LEVEL = qs.get('level') === 'admin' ? 'admin' : 'read';
  var HOST = window.location.host;

  function $(id) { return document.getElementById(id); }
  var E = {
    stage: $('stage'), h: $('h'), lead: $('lead'), actions: $('actions'), live: $('live'), badge: $('badge'),
    avatar: $('p-avatar'), name: $('p-name'), mail: $('p-mail'),
    open: $('p-open'), openSub: $('p-open-sub'), need: $('p-need'), status: $('p-status'),
    stampWord: $('stamp-word'), stampSmall: $('stamp-small'), hint: $('stamp-hint'), bars: $('p-bars'),
  };
  if (!E.stage || !E.h || !E.actions) return;

  // ── tiny DOM helpers ───────────────────────────────────────────────────────────────────────────────────────────
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }
  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }
  var NS = 'http://www.w3.org/2000/svg';
  // one stroke weight, one grid, drawn here rather than borrowed
  var ICONS = {
    key: ['<circle cx="8" cy="15" r="4"/>', '<path d="M10.9 12.1 20 3m-3.2 3.2 3 3m-5.6-.4 2.2 2.2"/>'],
    check: ['<circle cx="12" cy="12" r="9"/>', '<path d="m8 12.5 2.8 2.8L16 9.5"/>'],
    users: ['<circle cx="9" cy="8" r="3.5"/>', '<path d="M2.5 20c.6-3.6 3.2-5.5 6.5-5.5s5.9 1.9 6.5 5.5"/>', '<circle cx="17" cy="9" r="2.5"/>', '<path d="M17.5 14.6c2.3.3 3.8 1.9 4.3 4.4"/>'],
    arrow: ['<path d="M5 12h14m-5-6 6 6-6 6"/>'],
    swap: ['<path d="M9 4H5.5A1.5 1.5 0 0 0 4 5.5v13A1.5 1.5 0 0 0 5.5 20H9"/>', '<path d="m16 8 4 4-4 4M20 12H9"/>'],
    refresh: ['<path d="M20 11a8 8 0 0 0-14.5-4.5L4 8"/>', '<path d="M4 4v4h4"/>', '<path d="M4 13a8 8 0 0 0 14.5 4.5L20 16"/>', '<path d="M20 20v-4h-4"/>'],
    alert: ['<path d="M12 3.5 2.5 20h19z"/>', '<path d="M12 10v4.5M12 17.4v.1"/>'],
    dashed: ['<circle cx="12" cy="12" r="9" stroke-dasharray="3 3.3"/>'],
    back: ['<path d="M19 12H5m5-6-6 6 6 6"/>'],
  };
  function icon(name) {
    var s = document.createElementNS(NS, 'svg');
    s.setAttribute('viewBox', '0 0 24 24');
    s.setAttribute('fill', 'none');
    s.setAttribute('stroke', 'currentColor');
    s.setAttribute('stroke-width', '1.75');
    s.setAttribute('stroke-linecap', 'round');
    s.setAttribute('stroke-linejoin', 'round');
    s.setAttribute('aria-hidden', 'true');
    s.setAttribute('focusable', 'false');
    // static strings authored above — never fed from the network
    s.innerHTML = (ICONS[name] || []).join('');
    return s;
  }
  function announce(msg) { if (E.live) { E.live.textContent = ''; window.setTimeout(function () { E.live.textContent = msg; }, 30); } }
  function fmtWhen(iso) {
    var d = new Date(iso);
    if (isNaN(d.getTime())) return '';
    try { return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }).format(d); }
    catch (e) { return d.toLocaleString(); }
  }
  function initials(name, email) {
    var src = String(name || '').trim();
    if (!src) src = String(email || '').split('@')[0].replace(/[._-]+/g, ' ');
    var parts = src.split(/\s+/).filter(Boolean);
    if (!parts.length) return '?';
    var a = parts[0].charAt(0), b = parts.length > 1 ? parts[parts.length - 1].charAt(0) : '';
    return (a + b).toUpperCase();
  }

  // ── network ────────────────────────────────────────────────────────────────────────────────────────────────────
  function api(url, opts) {
    var ctl = ('AbortController' in window) ? new AbortController() : null;
    var timer = window.setTimeout(function () { if (ctl) ctl.abort(); }, 12000);
    opts = opts || {};
    opts.credentials = 'same-origin';
    opts.cache = 'no-store';
    if (ctl) opts.signal = ctl.signal;
    return fetch(url, opts).then(function (r) {
      window.clearTimeout(timer);
      return r.json().then(function (j) { return { status: r.status, json: j }; }, function () { return { status: r.status, json: null }; });
    }, function (e) { window.clearTimeout(timer); throw e; });
  }
  function contextUrl() {
    var p = new URLSearchParams({ kind: KIND });
    if (KIND === 'app') { p.set('page', PAGE); p.set('level', LEVEL); }
    return '/api/access-request/context?' + p.toString();
  }
  function signInUrl() {
    return '/login.html?return=' + encodeURIComponent(window.location.pathname + window.location.search);
  }

  // ── the badge ──────────────────────────────────────────────────────────────────────────────────────────────────
  function hash(str) {
    var h = 2166136261;
    for (var i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; }
    return h >>> 0;
  }
  // Decorative only (aria-hidden): a stable strip derived from who + what, so the same request always prints the same.
  function paintBars(seedText) {
    if (!E.bars) return;
    clear(E.bars);
    var h = hash(seedText || 'corpit'), x = h || 1;
    for (var i = 0; i < 46; i++) {
      x ^= x << 13; x ^= x >>> 17; x ^= x << 5; x >>>= 0;
      var b = el('b', (x & 7) === 0 ? 'gap' : '');
      b.style.width = (1 + (x % 3)) + 'px';
      E.bars.appendChild(b);
    }
  }
  function chip(text) {
    var c = el('span', 'chip');
    c.appendChild(icon('users'));
    c.appendChild(el('span', null, text));
    return c;
  }
  function paintNeed(need, level) {
    clear(E.need);
    if (!need || !need.groups || !need.groups.length) { E.need.textContent = '—'; return; }
    var ul = el('ul', 'chips');
    var shown = need.groups.slice(0, 4), more = need.groups.length - shown.length;
    shown.forEach(function (g, i) {
      var li = el('li');
      if (i > 0) li.appendChild(el('span', 'or', 'or'));
      li.appendChild(chip(g));
      ul.appendChild(li);
    });
    if (more > 0) { var lm = el('li'); lm.appendChild(el('span', 'or', 'or ' + more + ' more')); ul.appendChild(lm); }
    E.need.appendChild(ul);
    if (KIND === 'app' && level) E.need.appendChild(el('span', 'sub', level + ' access'));
  }
  // kinds: none | filed | practice | note   (note = a plain sentence, no stamp)
  function paintStatus(kind, text, ticketId) {
    clear(E.status);
    var wrap = el('span', 'state state--' + (kind === 'filed' ? 'filed' : kind === 'practice' ? 'practice' : 'none'));
    wrap.appendChild(icon(kind === 'filed' ? 'check' : kind === 'practice' ? 'alert' : 'dashed'));
    wrap.appendChild(el('span', null, text));
    E.status.appendChild(wrap);
    if (ticketId) E.status.appendChild(el('span', 'ticket-no num', ticketId));
  }
  function stamp(on, word, small, cls) {
    E.badge.classList.remove('is-stamped', 'is-practice', 'is-onfile');
    if (E.hint) E.hint.hidden = true;
    if (!on) return;
    E.stampWord.textContent = word;
    E.stampSmall.textContent = small;
    if (cls) E.badge.classList.add(cls);
    // restart the animation when the stamp is applied a second time
    void E.badge.offsetWidth;
    E.badge.classList.add('is-stamped');
  }
  function paintPass(v) {
    var u = v.user, t = v.target || {};
    E.badge.classList.toggle('is-loading', !!v.loading);
    E.avatar.textContent = u ? initials(u.name, u.email) : (v.loading ? '' : '?');
    E.name.textContent = u ? (u.name || u.email) : '';
    E.mail.textContent = u && u.name ? u.email : '';
    E.open.textContent = t.label || (v.loading ? '' : HOST);
    E.openSub.textContent = KIND === 'site' ? (t.host || HOST) : ((t.key ? t.key + ' · ' : '') + (t.host || HOST));
    paintNeed(v.need, v.level);
    paintBars(((u && u.email) || '') + '|' + (t.key || HOST));
  }

  // ── states ─────────────────────────────────────────────────────────────────────────────────────────────────────
  var S = { v: null, filing: false, pressed: false, err: null };

  function groupsText(need) {
    if (!need || !need.groups) return '';
    var g = need.groups;
    return g.length === 1 ? g[0] : g.slice(0, 3).join(', ') + (g.length > 3 ? ', …' : '');
  }
  function onePlural(need, one, many) { return need && need.any_of ? many : one; }

  function btn(label, iconName, cls, onClick) {
    var b = el('button', 'btn ' + cls);
    b.type = 'button';
    if (iconName) b.appendChild(icon(iconName));
    b.appendChild(el('span', null, label));
    if (onClick) b.addEventListener('click', onClick);
    return b;
  }
  function anchor(label, iconName, href, cls) {
    var a = el('a', cls);
    a.href = href;
    if (iconName) a.appendChild(icon(iconName));
    a.appendChild(el('span', null, label));
    return a;
  }
  // federated-logout ends the Entra session too; a local sign-out alone signs the same identity straight back in
  function signOutLink(label) { return anchor(label || 'Sign out and back in', 'swap', '/api/gate/federated-logout', 'link'); }

  function setText(h, leads) {
    E.h.textContent = h;
    clear(E.lead);
    // the lead slot holds one or two paragraphs
    var first = true;
    leads.forEach(function (t) {
      if (!t) return;
      if (first) { E.lead.textContent = t; first = false; }
      else { var p = el('p', 'lead', t); E.lead.parentNode.insertBefore(p, E.lead.nextSibling); E.extra = (E.extra || []).concat(p); }
    });
    document.title = h + ' · CorpIT';
  }
  function clearExtra() { (E.extra || []).forEach(function (p) { if (p.parentNode) p.parentNode.removeChild(p); }); E.extra = []; }

  function actionsReset() { clear(E.actions); }
  function addNotice(kind, text) {
    var n = el('p', 'notice notice--' + kind);
    n.appendChild(icon(kind === 'ok' ? 'check' : 'alert'));
    n.appendChild(el('span', null, text));
    E.actions.appendChild(n);
    return n;
  }

  function render(v) {
    S.v = v;
    var t = v.target || {};
    var label = t.label || HOST;
    var need = v.need;
    E.stage.setAttribute('aria-busy', v.state === 'loading' || S.filing ? 'true' : 'false');
    clearExtra();
    actionsReset();
    var links = el('div', 'links');
    var showLinks = true;
    var focusTarget = null;

    switch (v.state) {
      case 'loading':
        // first paint keeps the page's own static copy (hidden until the first real answer); a retry says so
        if (E.booted) setText('Checking your access…', ['One moment.']);
        paintPass({ loading: true, target: { label: '', host: HOST }, user: null });
        paintStatus('none', 'Checking…');
        stamp(false);
        showLinks = false;
        break;

      case 'ready': {
        var insufficient = v.reason === 'INSUFFICIENT_LEVEL';
        var h = KIND === 'app' && insufficient ? label + ' needs ' + v.level + ' access' : 'You don’t have access to ' + label + ' yet';
        var lead1 = KIND === 'site'
          ? label + ' is limited to members of ' + onePlural(need, 'the group', 'one of the groups') + ' on your access pass. Your account isn’t in ' + onePlural(need, 'it', 'any of them') + '.'
          : 'Your account doesn’t have ' + (v.level === 'admin' ? 'admin ' : '') + 'access to ' + label + '. It’s granted through ' + onePlural(need, 'the group', 'one of the groups') + ' on your access pass.';
        setText(h, [lead1, 'Press the button and the Help Desk gets a ticket that already names ' + onePlural(need, 'it', 'them') + '. There is nothing to fill in.']);
        paintPass(v);
        paintStatus('none', 'Not requested yet');
        stamp(false);
        if (E.hint) E.hint.hidden = false;
        if (v.dry_run) addNotice('warn', 'Practice run: pressing the button sends nothing to the Help Desk.');
        if (S.err) addNotice('warn', S.err);
        var row = el('div', 'row');
        var ask = btn(S.err ? 'Try again' : 'Request access', S.err ? 'refresh' : 'key', 'btn--primary', file);
        ask.id = 'ask';
        row.appendChild(ask);
        E.actions.appendChild(row);
        E.actions.appendChild(el('p', 'fine', 'Nothing is sent until you press. The ticket is filed under your name.'));
        if (S.err) focusTarget = ask;
        break;
      }

      case 'filed':
      case 'already': {
        var prac = !!v.dry_run && v.state === 'filed';
        var tk = v.ticket || {};
        var idText = prac ? 'Practice' : '#' + tk.display_id;
        var when = tk.created_at ? fmtWhen(tk.created_at) : '';
        var line;
        if (prac) {
          setText('Practice run complete', ['Nothing was sent: this is the development server, so no ticket exists. On the live platform this files a Help Desk ticket for ' + onePlural(need, 'the group', 'one of the groups') + ' on your access pass.']);
        } else if (v.state === 'filed') {
          setText('Your request is with the Help Desk', ['Ticket ' + idText + ' asks them to add you to ' + onePlural(need, 'the group', 'one of the groups') + ' on your access pass. There is nothing more for you to add.', 'Once they’ve done it, sign out and back in. Group membership is read when you sign in.']);
        } else {
          setText('You’ve already asked for this', ['Ticket ' + idText + (when ? ' was filed ' + when : ' is on file') + '. The Help Desk already has the group and the details' + (S.pressed ? ', so no second ticket was created.' : '.'), 'Once they’ve added you, sign out and back in. Group membership is read when you sign in.']);
        }
        paintPass(v);
        paintStatus(prac ? 'practice' : 'filed', prac ? 'Practice run' : 'Requested', prac ? '' : idText);
        stamp(true, prac ? 'Practice' : v.state === 'already' ? 'On file' : 'Requested', prac ? 'Not sent' : 'Help Desk', prac ? 'is-practice' : v.state === 'already' ? 'is-onfile' : '');
        var res = el('div', 'result' + (prac ? ' is-practice' : ''));
        res.tabIndex = -1;
        var rl = el('div', 'result-line');
        rl.appendChild(icon(prac ? 'alert' : 'check'));
        rl.appendChild(el('span', 'result-id num', idText));
        res.appendChild(rl);
        line = prac ? 'No ticket was created' : v.state === 'filed' ? 'Filed just now' : (tk.status ? 'Status: ' + tk.status : (when ? 'Filed ' + when : ''));
        if (line) res.appendChild(el('p', 'result-sub', line));
        E.actions.appendChild(res);
        if (!prac) links.appendChild(signOutLink());   // a practice run changed nothing, so there is nothing to sign back in for
        focusTarget = res;
        break;
      }

      case 'allowed':
        setText('You can open ' + label + ' now', ['Your access is in place.']);
        paintPass(v);
        paintStatus('filed', 'Access in place');
        stamp(false);
        var go = btn(KIND === 'site' ? 'Open ' + label : 'Go back', KIND === 'site' ? 'arrow' : 'back', 'btn--primary', function () {
          if (KIND === 'site') { window.location.replace(window.location.href); }
          else if (window.history.length > 1) { window.history.back(); } else { window.location.assign('/'); }
        });
        var r1 = el('div', 'row'); r1.appendChild(go); E.actions.appendChild(r1);
        showLinks = false;
        break;

      case 'stale-session':
        setText('Sign in again to refresh your access', ['Your sign-in is older than the current access rules for ' + label + ', so we can’t tell what you’re allowed to open. Signing in again usually clears it up.']);
        paintPass(v);
        paintStatus('none', 'Sign-in needs refreshing');
        stamp(false);
        var r2 = el('div', 'row');
        r2.appendChild(anchor('Sign out and back in', 'swap', '/api/gate/federated-logout', 'btn btn--primary'));
        E.actions.appendChild(r2);
        showLinks = false;
        break;

      case 'unavailable':
        setText('We can’t file this one for you', [label + ' doesn’t have an access group we can request automatically. Tell the Help Desk you need access to ' + label + ' (' + (t.host || HOST) + ').']);
        paintPass(v);
        paintStatus('none', 'Can’t be filed here');
        stamp(false);
        links.appendChild(signOutLink('Use a different account'));
        break;

      case 'signin':
        setText('Sign in to continue', ['We need to know who you are before we can file anything.']);
        paintPass({ target: { label: label, host: HOST }, user: null });
        paintStatus('none', 'Not signed in');
        stamp(false);
        var r3 = el('div', 'row');
        r3.appendChild(anchor('Sign in', 'arrow', signInUrl(), 'btn btn--primary'));
        E.actions.appendChild(r3);
        showLinks = false;
        break;

      case 'error':
      default:
        // the request service answered but the address carried no usable target: retrying cannot help, and "can't reach" would be untrue
        if (v.why === 'target') {
          setText(KIND === 'app' ? 'We couldn’t tell which page you were opening' : 'We couldn’t tell which site you were opening', ['Nothing was filed. Go back and open this screen again from the page that sent you here, so we know what access to ask for.']);
        } else if (v.why === 'busy') {
          setText('Too many tries just now', [(v.message || '') + ' Nothing was filed. Wait a minute, then try again.']);
        } else {
          setText('We can’t reach the access request service', [(v.message || 'Nothing was filed.') + ' Try again in a moment, or tell the Help Desk you need access to ' + HOST + '.']);
        }
        paintPass({ target: { label: label, host: HOST }, user: v.user || null });
        paintStatus('none', 'Unknown');
        stamp(false);
        var r4 = el('div', 'row');
        if (v.why !== 'target') {
          var again = btn('Try again', 'refresh', 'btn--primary', load);
          r4.appendChild(again);
        }
        E.actions.appendChild(r4);
        showLinks = false;
        break;
    }

    if (showLinks) {
      if (KIND === 'site' || v.state !== 'unavailable') {
        // "Use a different account" is useful on every refusal; the filed/already states carry their own sign-out link
        if (v.state === 'ready') links.appendChild(signOutLink('Use a different account'));
      }
      E.actions.appendChild(links);
      E.onwardSlot = links;
      paintOnward();
    }

    // the first real answer lifts the copy into view; later state changes re-run the same rise on the headline only
    if (v.state !== 'loading') {
      var first = !E.booted;
      E.booted = true;
      E.stage.removeAttribute('data-boot');
      if (first || E.lastState !== v.state) {
        var rise = first ? [E.h, E.lead, E.actions] : [E.h];
        rise.forEach(function (n) { n.classList.remove('swap'); });
        void E.h.offsetWidth;
        rise.forEach(function (n) { n.classList.add('swap'); });
      }
      E.lastState = v.state;
    }

    if (focusTarget) { try { focusTarget.focus({ preventScroll: false }); } catch (e) { /* older engines */ } }
    announce(E.h.textContent + (E.lead.textContent ? '. ' + E.lead.textContent : ''));
  }

  // ── onward offer: a refusal is never a dead end ────────────────────────────────────────────────────────────────
  // Same two candidates the old page used — the page that sent them here (?from=), else the gate's own pick — held to
  // the same checks: https, hostname-shaped, never the host that just refused us, and `from` must be a site this
  // person can already open. No countdown any more: an auto-redirect would pull the page away mid-request.
  var onward = undefined;   // undefined = not asked yet, null = nothing to offer
  function hostOk(h) {
    return /^[a-z0-9.-]{1,253}$/i.test(h) && h.toLowerCase() !== String(HOST).toLowerCase();
  }
  function backLink(sites) {
    var raw = /[?&]from=([^&]+)/.exec(window.location.search || '');
    if (!raw) return null;
    var u;
    try { u = new URL(decodeURIComponent(raw[1])); } catch (e) { return null; }
    if (u.protocol !== 'https:' || !hostOk(u.host)) return null;
    var ok = (sites || []).some(function (s) { return String(s && s.host || '').toLowerCase() === u.host.toLowerCase(); });
    return ok ? { url: u.origin + u.pathname + (u.hash || ''), host: u.host, back: true } : null;
  }
  function fetchOnward() {
    if (onward !== undefined || !window.fetch) return;
    onward = null;
    api('/api/gate/landing?exclude=' + encodeURIComponent(HOST)).then(function (r) {
      var d = r.status === 200 ? r.json : null;
      if (!d) return;
      var go = backLink(d.sites);
      if (!go) {
        if (!d.host || !hostOk(String(d.host))) return;
        go = { url: 'https://' + String(d.host) + '/', host: String(d.host), back: false };
      }
      onward = go;
      paintOnward();
    }).catch(function () { /* no offer; the page still explains the refusal */ });
  }
  function paintOnward() {
    var slot = E.onwardSlot;
    if (!slot) return;
    var old = slot.querySelector('[data-onward]');
    if (old) old.parentNode.removeChild(old);
    if (KIND === 'app') {
      if (window.history.length > 1) {
        var b = el('button', 'link'); b.type = 'button'; b.setAttribute('data-onward', '1');
        b.appendChild(icon('back')); b.appendChild(el('span', null, 'Go back'));
        b.addEventListener('click', function () { window.history.back(); });
        slot.appendChild(b);
      }
      return;
    }
    if (!onward) return;
    var a = anchor((onward.back ? 'Back to ' : 'Open ') + onward.host + (onward.back ? '' : ' (you have access)'), 'arrow', onward.url, 'link');
    a.setAttribute('data-onward', '1');
    slot.appendChild(a);
  }

  // ── loading and filing ─────────────────────────────────────────────────────────────────────────────────────────
  function stateFromContext(res) {
    var j = res.json;
    if (res.status === 401) return { state: 'signin' };
    if (res.status === 400 || res.status === 404) return { state: 'error', why: 'target', message: KIND === 'app' ? 'We couldn’t tell which page you were opening.' : 'We couldn’t tell which site you were opening.' };
    if (res.status === 429) return { state: 'error', why: 'busy', message: 'There have been a lot of requests from this connection.' };
    if (res.status !== 200 || !j || !j.ok) return { state: 'error' };
    return j;
  }
  function load() {
    S.err = null; S.pressed = false;
    render({ state: 'loading' });
    api(contextUrl()).then(function (res) {
      var v = stateFromContext(res);
      if (v.state === 'ready' || v.state === 'already') fetchOnward(); else if (v.state === 'unavailable') fetchOnward();
      render(v);
    }).catch(function () { render({ state: 'error' }); });
  }

  function file() {
    if (S.filing) return;
    S.filing = true; S.err = null; S.pressed = true;
    var ask = $('ask');
    if (ask) {
      ask.classList.add('is-busy');
      ask.setAttribute('aria-disabled', 'true');
      clear(ask);
      ask.appendChild(el('span', null, 'Sending…'));
    }
    E.stage.setAttribute('aria-busy', 'true');
    announce('Sending your request');
    var payload = { kind: KIND, path: window.location.pathname };
    if (KIND === 'app') { payload.page = PAGE; payload.level = LEVEL; }
    api('/api/access-request/file', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }).then(function (res) {
      S.filing = false;
      var j = res.json;
      if (res.status === 401) { render({ state: 'signin', target: S.v && S.v.target }); return; }
      if (res.status === 200 && j && j.ok) { render(j); return; }
      var code = j && j.error;
      S.err = code === 'TOO_MANY_REQUESTS' || code === 'RATE_LIMITED' ? 'You’ve sent several requests in a row. Wait a few minutes and try again.'
        : code === 'BUSY' ? 'Another request from you is still being processed. Try again in a moment.'
        : 'That didn’t send, so nothing was filed. Try again.';
      render(S.v);
    }).catch(function () {
      S.filing = false;
      S.err = 'That didn’t send, so nothing was filed. Check your connection and try again.';
      render(S.v);
    });
  }

  load();
})();
