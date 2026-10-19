// =====================================================================
// it-observe.js (v1.0.0) - the browser end of CorpIT observability.
//
//   <script src="/it-observe.js" data-app-key="identity-diag" defer></script>
//
// Loaded in the same shared-script slot as it-topbar.js and feed-freshness.js,
// on every page. It reports four things and invents nothing:
//
//   1. Uncaught errors and unhandled promise rejections.
//   2. Failed same-origin API calls - network failure or a >=400 status.
//   3. Assets that failed to load (a script or stylesheet that 404s changes
//      what the page can do, and today does so silently).
//   4. DEGRADED RENDERS - a page saying, in its own words, "I showed the user
//      an unknown/partial state here."
//
// (4) is the reason this exists. Every other signal describes something that
// threw. The expensive failures on this platform did not throw: Cert Watchtower
// rendered ok/142d for four months on a dead cron, the SharePoint tile rendered
// "No DLP hits" over 25,115 real hits, and the Zscaler tables rendered empty
// because a stale secret made every upstream call fail. In each case the page
// worked perfectly and told the user something false. A page calling
//
//     ITObserve.degraded('dlp-tile', 'DLP status unavailable')
//
// at the moment it paints that state is the only way that becomes countable.
//
// Design constraints:
//   * Never break the page. Every entry point is wrapped; a throw inside this
//     file must not surface anywhere.
//   * Never loop. A failed report must not itself be reported, or one dead
//     endpoint becomes an unbounded write storm.
//   * Never send an identifier. The page sends no name, no UPN, no cookie. The
//     server derives who this is from the session it already has.
//   * Never block unload. Flushing on the way out uses sendBeacon.
// =====================================================================

(function () {
  'use strict';
  if (window.__itObserveLoaded) return;
  window.__itObserveLoaded = true;

  var ENDPOINT = '/api/observe/client';
  var FLUSH_MS = 10000;
  var MAX_QUEUE = 100;        // hard cap; oldest dropped
  var MAX_PER_FP = 5;         // per fingerprint, per page-load
  var script = document.currentScript;
  var APP_KEY = (script && script.getAttribute('data-app-key')) || null;
  var APP_VERSION = (script && script.getAttribute('data-version')) || null;

  // Endpoints whose 404 is a documented "no record" answer, not a fault.
  // Only 404 is downgraded; every other status from them reports normally.
  var DOCUMENTED_404 = [
    /^\/api\/bugs\/changelog\//,   // it-version.js: no changelog for this app key
    /^\/api\/photo(\?|$)/           // it-topbar.js: no profile photo, falls back to initials
  ];
  function expected404(url, status) {
    if (status !== 404 || !url) return false;
    var path = String(url).replace(/^https?:\/\/[^/]+/i, '');
    for (var i = 0; i < DOCUMENTED_404.length; i++) {
      if (DOCUMENTED_404[i].test(path)) return true;
    }
    return false;
  }

  // The same idea on the RESOURCE path, which needs its own list because an
  // error event on an element carries no status -- the browser tells us the
  // load failed and nothing more. So this cannot mean "404 is fine, 500 is
  // not"; it can only mean "a failed load of THIS url is a documented outcome
  // rather than a fault". Only /api/photo qualifies: it-topbar.js sets the
  // avatar <img src> unconditionally and falls back to initials when it does
  // not load, so every user without a profile photo would otherwise stamp a
  // severity:'error' row on every page load and bury the real signal.
  // The message says the status was not observable, so nobody later reads
  // this row as proof the endpoint returned 404.
  var DOCUMENTED_RESOURCE_FAIL = [
    /^\/api\/photo(\?|$)/          // it-topbar.js: no profile photo, falls back to initials
  ];
  function expectedResourceFail(url) {
    if (!url) return false;
    var path = String(url).replace(/^https?:\/\/[^/]+/i, '');
    for (var i = 0; i < DOCUMENTED_RESOURCE_FAIL.length; i++) {
      if (DOCUMENTED_RESOURCE_FAIL[i].test(path)) return true;
    }
    return false;
  }

  var queue = [];
  var seen = {};              // fingerprint -> count, so a render loop cannot flood
  var sending = false;
  var sessionKey = makeSessionKey();

  // A per-tab id so one tab's events group together. Random, not derived from
  // anything about the user, and never persisted beyond the tab.
  function makeSessionKey() {
    try {
      var k = sessionStorage.getItem('itobs');
      if (k) return k;
      var a = new Uint8Array(8);
      (window.crypto || {}).getRandomValues ? crypto.getRandomValues(a)
        : a.forEach(function (_, i) { a[i] = (Math.random() * 256) | 0; });
      k = Array.prototype.map.call(a, function (b) {
        return ('0' + b.toString(16)).slice(-2);
      }).join('');
      sessionStorage.setItem('itobs', k);
      return k;
    } catch (e) { return null; }   // private mode, blocked storage - not fatal
  }

  // The url has to be part of the key, with ids collapsed the same way the
  // server collapses them. Without it, every endpoint returning the same status
  // shares ONE key: the key for a failing GET that 500s was literally
  // "fetch_fail||GET 500 Internal Server Error|||500" for the whole site, so
  // eleven endpoints failing together reported five and silently discarded the
  // rest -- and the fifth was annotated "further identical events from this
  // page-load are suppressed", which was false. They were different endpoints.
  // The server side already fingerprints WITH the target (obs-routes.js), so
  // this only brings the client's key, the one that decides what is ever sent,
  // into line with the grouping that was always intended.
  function fpUrl(u) {
    if (!u) return '';
    var p = String(u).replace(/^https?:\/\/[^/]+/i, '').split('#')[0].split('?')[0];
    return p.split('/').map(function (seg) {
      if (!seg) return seg;
      if (seg.indexOf('@') !== -1 || /%40/i.test(seg)) return ':id';
      if (/^[0-9]+$/.test(seg) && seg.length > 2) return ':id';
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(seg)) return ':id';
      if (/^[0-9a-f]{16,}$/i.test(seg)) return ':id';
      return seg;
    }).join('/');
  }

  function fp(e) {
    return [e.kind, e.widget || '', e.message || '', e.source || '', e.line || '',
            e.status || '', fpUrl(e.url)].join('|');
  }

  function record(e) {
    try {
      if (!e || !e.kind) return;
      var k = fp(e);
      seen[k] = (seen[k] || 0) + 1;
      // Report the first few, then stop. The COUNT is preserved on the last one
      // that gets through, so the dashboard is not misled into thinking a
      // runaway loop happened five times.
      if (seen[k] > MAX_PER_FP) return;
      if (seen[k] === MAX_PER_FP) e.detail = (e.detail ? e.detail + ' | ' : '') +
        'further identical events from this page-load are suppressed';
      e.at = new Date().toISOString();
      queue.push(e);
      while (queue.length > MAX_QUEUE) queue.shift();
    } catch (err) { /* never break the page */ }
  }

  // Payload ceiling. Two separate limits sit above this and both used to be
  // discovered the hard way:
  //   * navigator.sendBeacon refuses a body over the user agent's beacon quota
  //     (~64 KB) and merely returns false;
  //   * the server enforces the console's "Largest browser report accepted"
  //     (obs-ingest-cap.js) and answers 413.
  // 60 KB keeps an ordinary report under both. Anything larger is halved rather
  // than dropped, because half a report reaching the collector beats none.
  var MAX_BODY = 60000;

  // Builds a payload from a SLICE. Deliberately does not touch the queue:
  // draining as a side effect of building is what made a refused sendBeacon
  // silently destroy every queued event, and the pages producing the largest
  // payloads -- the ones in an error cascade -- were exactly the ones refused.
  function envelopeOf(events) {
    return {
      page: location.pathname,
      appKey: APP_KEY,
      appVersion: APP_VERSION,
      sessionKey: sessionKey,
      viewport: (window.innerWidth || 0) + 'x' + (window.innerHeight || 0),
      events: events,
    };
  }

  // Largest prefix of the queue whose serialised body fits MAX_BODY, plus that
  // body. Always sends at least one event: a single event over the ceiling is
  // unsendable either way, and reporting it truncated is better than silence.
  function fittingPayload() {
    var take = queue.length;
    var body = JSON.stringify(envelopeOf(queue.slice(0, take)));
    while (take > 1 && body.length > MAX_BODY) {
      take = Math.floor(take / 2);
      body = JSON.stringify(envelopeOf(queue.slice(0, take)));
    }
    return { take: take, body: body };
  }

  // Ordinary flush. Uses the real fetch captured before the wrapper below, so a
  // failure here can never be caught by our own instrumentation and re-queued.
  var rawFetch = window.fetch && window.fetch.bind(window);

  function flush() {
    if (sending || !queue.length || !rawFetch) return;
    sending = true;
    var p = fittingPayload();
    var body = p.body;
    queue.splice(0, p.take);
    rawFetch(ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: body,
    }).catch(function () {
      // Deliberately silent, and deliberately not retried. If the collector is
      // down, the events are gone. That is the correct trade: an observability
      // client that retries is an observability client that can amplify an
      // outage it was supposed to describe.
    }).then(function () { sending = false; });
  }

  // Unload flush. sendBeacon survives the page going away; fetch does not.
  //
  // sendBeacon returns false when the user agent refuses to queue the request --
  // most often an oversized body, but also a beacon quota already spent by
  // another beacon in the same navigation. That return value used to be
  // discarded, and the queue had already been emptied by envelope(), so a
  // refusal destroyed the whole report with nothing left to retry. Now the
  // queue is only drained once the user agent has actually accepted it, and a
  // refusal halves the payload and tries again on the way down.
  function flushBeacon() {
    try {
      if (!queue.length || !navigator.sendBeacon) return;
      var take = queue.length;
      while (take >= 1) {
        var body = JSON.stringify(envelopeOf(queue.slice(0, take)));
        if (body.length <= MAX_BODY &&
            navigator.sendBeacon(ENDPOINT, new Blob([body], { type: 'application/json' }))) {
          queue.splice(0, take);
          return;
        }
        if (take === 1) return;   // one event and still refused: nothing to salvage
        take = Math.floor(take / 2);
      }
    } catch (e) { /* nothing to do on the way out */ }
  }

  // -- 1. uncaught errors and rejections ------------------------------------
  window.addEventListener('error', function (ev) {
    // A resource that failed to load arrives on the same event, distinguished
    // by having a target element rather than a message.
    var t = ev.target;
    if (t && t !== window && (t.tagName === 'SCRIPT' || t.tagName === 'LINK' || t.tagName === 'IMG')) {
      var rurl = t.src || t.href || null;
      var rbenign = expectedResourceFail(rurl);
      record({
        kind: 'resource_fail', severity: rbenign ? 'info' : 'error',
        message: t.tagName.toLowerCase() + ' failed to load' +
                 (rbenign ? ' (documented optional resource; status not observable here)' : ''),
        url: rurl,
      });
      return;
    }
    record({
      kind: 'error', severity: 'error',
      message: ev.message || 'uncaught error',
      source: ev.filename || null,
      line: ev.lineno || null,
      col: ev.colno || null,
      detail: (ev.error && ev.error.stack) ? String(ev.error.stack).slice(0, 2000) : null,
    });
  }, true);   // capture phase: resource errors do not bubble

  window.addEventListener('unhandledrejection', function (ev) {
    var r = ev.reason;
    record({
      kind: 'rejection', severity: 'error',
      message: (r && (r.message || r.toString && r.toString())) || 'unhandled rejection',
      detail: (r && r.stack) ? String(r.stack).slice(0, 2000) : null,
    });
  });

  // -- 2. failed API calls ---------------------------------------------------
  // Wraps fetch to observe outcomes only. It does not read, clone or buffer any
  // response body: doing so would let the logger change what the page receives.
  if (rawFetch) {
    window.fetch = function (input, init) {
      var url;
      try { url = (typeof input === 'string') ? input : (input && input.url) || String(input); }
      catch (e) { url = ''; }

      // Never instrument our own reporting call: that is the loop.
      if (url && url.indexOf(ENDPOINT) !== -1) return rawFetch.apply(this, arguments);
      // Only same-origin calls. A cross-origin failure is usually the other
      // site's problem and the URL is not ours to ship anywhere.
      var sameOrigin = !/^[a-z]+:\/\//i.test(url) || url.indexOf(location.origin) === 0;
      if (!sameOrigin) return rawFetch.apply(this, arguments);

      var t0 = (window.performance && performance.now) ? performance.now() : Date.now();
      var method = (init && init.method) || (input && input.method) || 'GET';

      return rawFetch.apply(this, arguments).then(function (res) {
        if (!res.ok) {
          var benign = expected404(url, res.status);
          record({
            kind: 'fetch_fail',
            severity: benign ? 'info' : (res.status >= 500 ? 'error' : 'warn'),
            message: method + ' ' + res.status + (res.statusText ? ' ' + res.statusText : '') +
                     (benign ? ' (documented "no record" answer)' : ''),
            url: url, status: res.status, requestId: res.headers.get('X-Request-ID'),
            durationMs: Math.round(((window.performance && performance.now) ? performance.now() : Date.now()) - t0),
          });
        }
        return res;
      }, function (err) {
        record({
          kind: 'fetch_fail', severity: 'error',
          message: method + ' network failure',
          detail: (err && err.message) ? String(err.message).slice(0, 500) : null,
          url: url, status: null,
          durationMs: Math.round(((window.performance && performance.now) ? performance.now() : Date.now()) - t0),
        });
        throw err;   // the page's own error handling is unchanged
      });
    };
  }

  // -- 3. the public API -----------------------------------------------------
  window.ITObserve = {
    // The signal this whole file exists for. Call it at the moment the page
    // paints an unknown / partial / could-not-measure state.
    //
    //   ITObserve.degraded('kpi-invest', 'Active incidents unavailable',
    //                      'Rapid7 HTTP 502; spray HTTP 502');
    //
    // `widget` should be stable - an element id or a short slug - because it is
    // the grouping key. `message` should be the text the USER was actually
    // shown, so the dashboard row and the screenshot in a ticket match.
    degraded: function (widget, message, detail) {
      record({
        kind: 'degraded', severity: 'warn',
        widget: widget || null,
        message: message || 'degraded render',
        detail: detail || null,
      });
    },
    // For a page that wants to time something itself.
    slow: function (widget, ms, message) {
      record({ kind: 'slow', severity: 'info', widget: widget || null,
               message: message || 'slow render', durationMs: ms });
    },
    flush: flush,
    // Exposed for the observability page's own self-test.
    _pending: function () { return queue.length; },
  };

  // -- 4. lifecycle ----------------------------------------------------------
  var timer = setInterval(flush, FLUSH_MS);
  window.addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'hidden') flushBeacon();
  });
  window.addEventListener('pagehide', function () {
    clearInterval(timer); timer = null; flushBeacon();
  });
  // FC-07. pagehide fires on EVERY navigation away, including the bfcache-eligible
  // ones, and nothing re-armed the interval. A user who navigated away and pressed
  // Back got the same live document restored with a dead flusher: it kept recording
  // and never sent anything again for the life of that tab. Re-arm on restore, and
  // send what the hidden period accumulated.
  window.addEventListener('pageshow', function (ev) {
    if (!timer) timer = setInterval(flush, FLUSH_MS);
    if (ev && ev.persisted) flush();
  });
})();
