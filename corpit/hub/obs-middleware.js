// ---------------------------------------------------------------------------
// obs-middleware.js - layer 4: what the API actually served.        2026-09-06
//
// api-metrics.js already counts requests and errors per /api/<module> in a
// rolling in-process window, and the Server Health dashboard reads it. That is
// the right tool for "is the error rate up". It cannot answer the question that
// keeps costing time: "the SharePoint tile is empty for this one person - what
// did the API return to THEM, and how long did it take?" Counters have no
// individual requests in them, and they reset on restart.
//
// So this is deliberately NOT a replacement for api-metrics. It is the durable,
// per-request layer underneath it:
//
//   * every 5xx is kept
//   * every 4xx is kept (an unexpected 401/403 is how a broken gate presents)
//   * every request slower than OBS_SLOW_MS is kept
//   * ordinary fast 2xx are sampled at OBS_SAMPLE_RATE
//
// Sampling is what keeps this from becoming a second nginx access log. The
// sampled flag records WHY a row is present, so the dashboard never reports a
// sampled count as if it were a total - the same "a count is not a list length"
// trap that made the ZCC drift table disagree with its own header.
// ---------------------------------------------------------------------------
'use strict';

const obs = require('./obs-lib');

const context = require('./activity-context');

const TABLE = 'obs_request';
const COLS = ['at', 'app', 'method', 'route', 'status', 'duration_ms', 'bytes',
              'actor_key', 'err', 'sampled', 'request_id'];

// The caller's identity, if some earlier middleware established one. Read from
// several places because the two apps set it differently, and hashed on the way
// out - the raw value never reaches the buffer.
function actorOf(req) {
  const u = req.user || req.currentUser || req.rbacUser || null;
  const id = (u && (u.upn || u.userPrincipalName || u.mail || u.email || u.username)) ||
             req.sessionUpn || null;
  return obs.actorKey(id);
}

// P-6: obs_request.client_ip is gone, and the function that produced it with it.
//
// Three things were wrong with it at once and each alone was enough:
//
//   1. It was forgeable. `fromProxy` tested whether the peer was 127.0.0.1 --
//      which is EVERY request, because every request arrives from nginx on
//      loopback. So the guard tested nothing, and the header was trusted
//      whenever nginx had not already set it. nginx sets X-Real-IP on only some
//      of its proxy blocks here (rbac-middleware.js:168 carries the same
//      finding for X-Forwarded-For: 5 of 38), so on the rest any caller could
//      write whatever address it liked into this column.
//   2. Nothing read it. No route, no panel, no query. It answered no question
//      anyone was asking, so its only effect was the storage.
//   3. It was the one raw identifier in a table designed to hold none. This
//      module's header says it plainly -- no bodies, no headers, no employee
//      identifiers -- and identity here is deliberately an HMAC handle so that
//      the log cannot become a searchable index of who looked up whom. On a
//      /8 of issued desktops an IP IS a person: the live table had 112 of 194
//      rows on a single address. Sitting beside actor_key in the same row, it
//      undid the pseudonymisation it was stored next to.
//
// The stored values were deleted, not just orphaned. If source IPs are ever
// genuinely needed for diagnostics, that is a deliberate decision that starts
// with nginx setting the header on every block -- not a forgeable field
// arriving by default.

// nginx's own code for "client closed the request before a response was sent".
// Borrowed deliberately: it is the convention an operator reading these rows
// already knows, and it is outside the range any handler here can return, so an
// abort can never be confused with a status a client actually received.
const CLIENT_CLOSED = 499;

function middleware(req, res, next) {
  if (!obs.CFG.enabled) return context.run(req, res, next);
  const started = process.hrtime.bigint();
  let recorded = false;

  // 'finish' fires when the response was fully written. It does NOT fire when
  // the socket dies first -- a client that navigates away mid-request, a fetch
  // that is aborted, a proxy timeout, a handler that never answers. Those were
  // the requests this table could not see, and they are the ones worth seeing:
  // a page rendering an unknown state because its call never returned had no
  // server-side row at all, so the layer built to explain that silence was
  // itself silent about it.
  //
  // Both events therefore land here, and the flag makes the pair idempotent --
  // on a normal response Node emits 'finish' and then 'close'.
  function finalize(completed) {
    if (recorded) return;
    recorded = true;
    const ms = Number(process.hrtime.bigint() - started) / 1e6;
    const raw = req.originalUrl || req.url || '';
    const rawPath = raw.split('?')[0];

    // A sensitive route keeps its method, path and status - never its query.
    // Knowing that /api/sdops/unlock was called and returned 500 is the whole
    // diagnostic value; knowing whose account it was is not ours to store.
    const route = obs.isSensitiveRoute(rawPath)
      ? obs.normalizePath(rawPath)
      : obs.redactUrl(raw);

    // res.statusCode on an aborted request is whatever the handler last set, and
    // for one that never answered that is Express's default 200. Recording that
    // would be the green em-dash again: a request nobody received, stored as a
    // success. CLIENT_CLOSED says what was actually observed.
    const status = completed ? res.statusCode : CLIENT_CLOSED;
    const slow = ms >= obs.CFG.slowMs;
    const failed = status >= 400;
    // An abort is never sampled away. It is rare, it is always interesting, and
    // it is the single case this middleware previously could not report at all.
    // Math.random is the right tool for the rest: load shedding, not security.
    const keep = !completed || failed || slow || req.activityDependencyFailed || (Math.random() < obs.CFG.sampleRate);
    if (!keep) return;

    const len = Number(res.getHeader('content-length'));

    obs.push(TABLE, COLS, [
      obs.nowSql(),
      obs.CFG.app,
      obs.clip(req.method, 8),
      obs.clip(route, 191),
      status,
      Math.round(ms),
      Number.isFinite(len) ? len : null,
      actorOf(req),
      // res.locals.obsError lets a route explain its own failure in one line
      // instead of leaving the dashboard to infer it from a status code.
      completed
        ? obs.clip(obs.scrub(res.locals && res.locals.obsError), 255)
        : 'connection closed before the response completed',
      (failed || slow || req.activityDependencyFailed) ? 0 : 1,
      req.activityRequestId || null,
    ]);
  }

  res.on('finish', obs.safe(function () { finalize(true); }));
  // writableFinished distinguishes "closed after a complete response" (the
  // ordinary case, already recorded above) from "closed instead of one".
  res.on('close', obs.safe(function () { finalize(res.writableFinished === true); }));

  context.run(req, res, next);
}

module.exports = { middleware, TABLE, COLS, CLIENT_CLOSED };
