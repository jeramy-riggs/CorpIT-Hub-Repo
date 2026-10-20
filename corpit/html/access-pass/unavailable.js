// unavailable.js — drives /gate-unavailable.html, the page nginx serves when the gate or the app behind it can't answer.
//
// It does not guess. Three independent facts are measured and shown, and the headline is derived only from them:
//   1. this page loaded           -> the person's connection to the edge works (known, not probed)
//   2. GET  /api/health           -> the CorpIT sign-in service (:3001)
//   3. GET  /api/gate/landing     -> the access check that nginx asks before every gated page (:3002, a separate process;
//                                    401 without a session still proves it answered, only a 5xx/no answer counts as down)
//   4. HEAD /                     -> the site the person was opening (idempotent, so it never repeats a click-through
//                                    URL; the page they asked for is only requested once, at the end, by the reload)
// Nothing is "all clear" until a probe actually answered; before the first answer every row says "Checking…".
// A 429 is its own answer (gate429kit 2026-10-20): the service is up but is turning this network away for a moment,
// so it reads "busy", never "Responding", the headline says so, and the next check waits for the limit to reset
// (checking every 5 s would only spend more of the same allowance).
// No ticket button on purpose: an outage affects everyone, and a flood of tickets would bury the real work.
(function () {
  'use strict';

  var HOST = window.location.host;
  function $(id) { return document.getElementById(id); }
  var E = { stage: $('stage'), h: $('h'), lead: $('lead'), actions: $('actions'), live: $('live'),
            radar: $('radar'), checks: $('checks'), next: $('next'), last: $('last') };
  if (!E.stage || !E.h || !E.checks) return;

  function el(tag, cls, text) { var n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; }
  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }
  var NS = 'http://www.w3.org/2000/svg';
  var ICONS = {
    check: '<circle cx="12" cy="12" r="9"/><path d="m8 12.5 2.8 2.8L16 9.5"/>',
    down: '<circle cx="12" cy="12" r="9"/><path d="m9 9 6 6m0-6-6 6"/>',
    wait: '<path d="M20 11a8 8 0 0 0-14.5-4.5L4 8"/><path d="M4 4v4h4"/><path d="M4 13a8 8 0 0 0 14.5 4.5L20 16"/><path d="M20 20v-4h-4"/>',
    unsure: '<path d="M12 3.5 2.5 20h19z"/><path d="M12 10v4.5M12 17.4v.1"/>',
    refresh: '<path d="M20 11a8 8 0 0 0-14.5-4.5L4 8"/><path d="M4 4v4h4"/><path d="M4 13a8 8 0 0 0 14.5 4.5L20 16"/><path d="M20 20v-4h-4"/>',
    busy: '<circle cx="12" cy="12" r="9"/><path d="M12 7.5V12l3 2"/>',
  };
  function icon(name, spin) {
    var s = document.createElementNS(NS, 'svg');
    s.setAttribute('viewBox', '0 0 24 24'); s.setAttribute('fill', 'none'); s.setAttribute('stroke', 'currentColor');
    s.setAttribute('stroke-width', '1.75'); s.setAttribute('stroke-linecap', 'round'); s.setAttribute('stroke-linejoin', 'round');
    s.setAttribute('aria-hidden', 'true'); s.setAttribute('focusable', 'false');
    if (spin) s.setAttribute('class', 'pending-spin');
    s.innerHTML = ICONS[name] || '';   // static strings authored above
    return s;
  }
  function announce(msg) { if (E.live) { E.live.textContent = ''; window.setTimeout(function () { E.live.textContent = msg; }, 30); } }

  // ── probes ─────────────────────────────────────────────────────────────────────────────────────────────────────
  // Each resolves (never rejects) to { v: 'ok' | 'down' | 'unsure' | 'busy', note, wait? }.
  function probe(url, method, judge) {
    return new Promise(function (resolve) {
      var ctl = ('AbortController' in window) ? new AbortController() : null;
      var timer = window.setTimeout(function () { if (ctl) ctl.abort(); }, 4000);
      var opts = { method: method, cache: 'no-store', credentials: 'same-origin', redirect: 'manual' };
      if (ctl) opts.signal = ctl.signal;
      fetch(url, opts).then(function (r) {
        window.clearTimeout(timer);
        resolve(judge(r));
      }, function (e) {
        window.clearTimeout(timer);
        resolve({ v: 'down', note: e && e.name === 'AbortError' ? 'No answer within 4 seconds' : 'Could not connect' });
      });
    });
  }
  // 429: up, but limiting this network. wait = seconds until it lets requests through again (Retry-After, else the
  // RateLimit-Reset that express-rate-limit sends), kept between 5 and 65 so a bad header can't stall or spin the page.
  function judgeBusy(r) {
    if (r.status !== 429) return null;
    var s = parseInt(r.headers.get('Retry-After') || r.headers.get('RateLimit-Reset') || '', 10);
    if (!(s >= 0)) s = 30;
    return { v: 'busy', note: 'Busy: too many requests from your network (HTTP 429)', wait: Math.min(Math.max(s + 1, 5), 65) };
  }
  function judgeHealth(r) {
    var b = judgeBusy(r); if (b) return b;
    // an opaque redirect or status 0 means a redirect we chose not to follow: something answered
    if (r.type === 'opaqueredirect' || r.status === 0) return { v: 'ok', note: 'Responding' };
    if (r.status >= 500) return { v: 'down', note: 'Not responding (HTTP ' + r.status + ')' };
    if (r.status >= 200 && r.status < 400) return { v: 'ok', note: 'Responding (HTTP ' + r.status + ')' };
    return { v: 'unsure', note: 'Unclear answer (HTTP ' + r.status + ')' };
  }
  function judgeGate(r) {
    var b = judgeBusy(r); if (b) return b;
    if (r.type === 'opaqueredirect' || r.status === 0) return { v: 'ok', note: 'Responding' };
    if (r.status >= 500) return { v: 'down', note: 'Not responding (HTTP ' + r.status + ')' };
    return { v: 'ok', note: 'Responding (HTTP ' + r.status + ')' };
  }
  function judgeSite(r) {
    var b = judgeBusy(r); if (b) return b;
    // the site's front door answering with a sign-in redirect or a refusal still proves it is up
    if (r.type === 'opaqueredirect' || r.status === 0) return { v: 'ok', note: 'Responding (sign-in redirect)' };
    if (r.status >= 500) return { v: 'down', note: 'Not responding (HTTP ' + r.status + ')' };
    return { v: 'ok', note: 'Responding (HTTP ' + r.status + ')' };
  }

  // ── painting ───────────────────────────────────────────────────────────────────────────────────────────────────
  var R = { edge: { v: 'ok', note: 'This page loaded from ' + HOST }, auth: null, gate: null, site: null };

  function row(kind, what, detail, state) {
    var li = el('li', state);
    li.appendChild(icon(kind, state === 'wait'));
    li.appendChild(el('span', 'what', what));
    li.appendChild(el('span', 'detail', detail));
    return li;
  }
  function stateOf(r) { return !r ? 'wait' : r.v === 'ok' ? 'ok' : r.v === 'down' ? 'down' : 'wait'; }
  function iconOf(r) { return !r ? 'wait' : r.v === 'ok' ? 'check' : r.v === 'down' ? 'down' : r.v === 'busy' ? 'busy' : 'unsure'; }
  function paintChecks() {
    clear(E.checks);
    E.checks.appendChild(row('check', 'Your connection to CorpIT', R.edge.note, 'ok'));
    E.checks.appendChild(row(iconOf(R.auth), 'Sign-in service', R.auth ? R.auth.note : 'Checking…', stateOf(R.auth)));
    E.checks.appendChild(row(iconOf(R.gate), 'Access check', R.gate ? R.gate.note : 'Checking…', stateOf(R.gate)));
    E.checks.appendChild(row(iconOf(R.site), HOST, R.site ? R.site.note : 'Checking…', stateOf(R.site)));
  }

  var lastHead = '';
  function headline(h, lead) {
    if (h === lastHead) return;
    lastHead = h;
    E.h.textContent = h;
    E.lead.textContent = lead;
    document.title = h + ' · CorpIT';
    E.h.classList.remove('swap'); void E.h.offsetWidth; E.h.classList.add('swap');
    announce(h + '. ' + lead);
  }

  // derived from the measured facts only
  function conclude() {
    var a = R.auth, g = R.gate, s = R.site;
    E.radar.classList.remove('is-down', 'is-up');
    if (!a || !g || !s) return 'checking';
    var authDown = a.v === 'down', gateDown = g.v === 'down', siteDown = s.v === 'down';
    var limited = [a, g, s].filter(function (x) { return x.v === 'busy'; });
    if (!authDown && !gateDown && !limited.length && !siteDown) {
      E.radar.classList.add('is-up');
      headline('Back online', 'Taking you back to what you were opening…');
      return 'up';
    }
    E.radar.classList.add('is-down');
    if (authDown) {
      headline('Sign-in isn’t answering right now',
        'CorpIT can’t check who you are at the moment, so nobody is being let through, including you. Nothing is wrong with your account. This page keeps checking and takes you back in as soon as it can.');
    } else if (gateDown) {
      headline('Access checks aren’t answering right now',
        'CorpIT can’t check which sites you’re allowed into at the moment, so nobody is being let through, including you. Nothing is wrong with your account. This page keeps checking and takes you back in as soon as it can.');
    } else if (limited.length) {
      R.wait = Math.max.apply(null, limited.map(function (x) { return x.wait; }));
      headline('Too many requests from your network',
        'CorpIT is up. It is slowing down requests from your network for a moment, usually because many pages were opened quickly. Nothing is wrong with your account. This page waits for the limit to reset, then takes you back.');
      return 'busy';
    } else {
      headline(HOST + ' isn’t answering right now',
        'CorpIT sign-in is working, but ' + HOST + ' itself isn’t responding. This page keeps checking and takes you back in when it answers.');
    }
    return 'down';
  }

  // ── the loop: check now, then again after a backoff of 5s growing to 30s ───────────────────────────────────────
  var delay = 5000, timer = null, tick = null, due = 0, busy = false, fails = 0, nowBtn = null, helpNote = null;

  function setNext(text) { E.next.textContent = text; }
  function countdown() {
    var s = Math.max(0, Math.ceil((due - Date.now()) / 1000));
    setNext('Next check in ' + s + 's');
  }
  function clock() {
    var d = new Date();
    try { return new Intl.DateTimeFormat(undefined, { hour: 'numeric', minute: '2-digit', second: '2-digit' }).format(d); }
    catch (e) { return d.toLocaleTimeString(); }
  }
  function setBusy(on) {
    busy = on;
    if (nowBtn) nowBtn.setAttribute('aria-disabled', on ? 'true' : 'false');   // stays focusable; check() ignores presses while busy
    if (on) { window.clearInterval(tick); setNext('Checking…'); }
  }

  function check() {
    if (busy) return;
    window.clearTimeout(timer); window.clearInterval(tick);
    setBusy(true);
    Promise.all([
      probe('/api/health', 'GET', judgeHealth),
      probe('/api/gate/landing', 'GET', judgeGate),
      probe('/', 'HEAD', judgeSite),
    ]).then(function (res) {
      R.auth = res[0]; R.gate = res[1]; R.site = res[2];
      E.last.textContent = clock();
      paintChecks();
      var verdict = conclude();
      setBusy(false);
      if (verdict === 'up') {
        setNext('Reloading…');
        // one request for the page they originally asked for, nothing else
        window.setTimeout(function () { window.location.replace(window.location.href); }, 900);
        return;
      }
      if (verdict === 'busy') {
        delay = 5000;   // back to the normal cadence once the limit has reset
        due = Date.now() + R.wait * 1000;
        countdown();
        tick = window.setInterval(countdown, 1000);
        timer = window.setTimeout(check, R.wait * 1000);
        return;
      }
      fails += 1;
      if (fails >= 6 && !helpNote) {
        helpNote = el('p', 'fine', 'Still not back after a few minutes? Tell the Help Desk you were opening ' + HOST + window.location.pathname.slice(0, 120) + ' and that it isn’t answering. Others will be seeing the same thing, so one message is enough.');
        E.actions.appendChild(helpNote);
      }
      delay = Math.min(delay + 5000, 30000);
      due = Date.now() + delay;
      countdown();
      tick = window.setInterval(countdown, 1000);
      timer = window.setTimeout(check, delay);
    });
  }

  // controls
  var row1 = el('div', 'row');
  nowBtn = el('button', 'btn btn--ghost');
  nowBtn.type = 'button';
  nowBtn.appendChild(icon('refresh'));
  nowBtn.appendChild(el('span', null, 'Check now'));
  nowBtn.addEventListener('click', function () { delay = 5000; fails = Math.min(fails, 5); check(); });
  row1.appendChild(nowBtn);
  E.actions.appendChild(row1);

  document.addEventListener('visibilitychange', function () { if (!document.hidden && !busy) check(); });
  window.addEventListener('online', function () { if (!busy) check(); });

  paintChecks();
  E.stage.removeAttribute('data-boot');
  check();
})();
