'use strict';
// /var/www/corpit-hub-api/gate-server.js -- CHG-ARCH-21 (2026-09-25)
// The auth gate (/api/gate/*) in its own process on 127.0.0.1:3002 (pm2 app corpit-gate-api).
// Until this change it was served only inside corpit-hub-api (server.js:523) and shared the hub's
// event loop, so anything that stalled the hub stalled every page's auth_request (nginx gives
// /_gate 2 s). This file mounts the SAME ./gate-routes behind the pipeline server.js puts in
// front of it, so the answers do not change:
//   obs-middleware (server.js:107), drain (110), JSON 1 MB (138-145), cors (146), trust proxy (147),
//   rate limit (152-165), api-metrics (168), obs-lib pool + heartbeat (195), x-powered-by off (234),
//   the /api deny-by-default blanket (315-404) for the /api/gate paths, the body-error handler
//   (717-726), drain.attach (729-731).
// The hub keeps mounting gate-routes too (decision B3), so a rollback is one nginx reload.
// Proof: gate-contract.js `compare golden-3001-v2.json http://127.0.0.1:3002` -> 0 differ.
// cwd is the hub tree and .env is the hub's .env (secrets stay there). The port is NOT read from
// PORT: that .env sets PORT=3001 for the hub, and dotenv would hand it to this process. GATE_PORT
// exists only so the rehearsal can run this file on a scratch port; production sets none.
// Decisions (DECISIONS-2026-09-25 section B): B1 telemetry (OBS_APP=corpit-gate-api comes from the
// pm2 entry), B6 pool 5, B7 liveness /api/health.
// B1 names obs-middleware, api-metrics and the heartbeat. server.js's other telemetry starters are
// NOT started here: obs-dependency.install() (fetch wrapper), obs-prune (hub only, by design) and
// obs-seed-jobs (the hub applies obs-jobs.json). obs-ingest-cap serves /api/observe/client only.
require('dotenv').config();

(function installCrashLogging() {
  // Same recorder as server.js:10-89, writing to this app's own CRASH_LOG (ecosystem entry).
  const fs = require('fs');
  const os = require('os');
  const LOG = process.env.CRASH_LOG || '/var/log/corpit/gate-api-lifecycle.log';
  let sinkDead = false;
  function record(kind, err, extra) {
    let line;
    try {
      line = [
        '[' + new Date().toISOString() + ']',
        kind,
        'pid=' + process.pid,
        'uptime=' + Math.round(process.uptime()) + 's',
        'rss=' + Math.round(process.memoryUsage().rss / 1048576) + 'MB',
        'host=' + os.hostname(),
        extra ? ('ctx=' + extra) : '',
        '\n  ' + ((err && (err.stack || err.message)) || String(err)),
        '\n'
      ].join(' ');
    } catch (e) { line = '[' + new Date().toISOString() + '] ' + kind + ' (unformattable)\n'; }
    try { fs.appendFileSync(LOG, line); } catch (e) {
      if (!sinkDead) {
        sinkDead = true;
        try {
          process.stderr.write('[' + new Date().toISOString() +
            '] LIFECYCLE LOG SINK UNWRITABLE ' + LOG + ' (' +
            ((e && e.code) || e) + ') -- records continue on stderr only\n');
        } catch (e2) {}
      }
    }
    try { process.stderr.write(line); } catch (e) {}
  }
  process.on('uncaughtException', function (err) {
    record('FATAL uncaughtException', err);
    process.exit(1);
  });
  process.on('unhandledRejection', function (reason) {
    record('FATAL unhandledRejection', reason);
    process.exit(1);
  });
  // pm2 stops with SIGINT; drain.js stops accepting, drains up to 8 s, closes the pool, exits.
  ['SIGINT', 'SIGTERM'].forEach(function (sig) {
    process.on(sig, function () {
      record(sig + ' (orderly stop/restart)', 'n/a');
      require('./drain').begin(sig, record);
    });
  });
  record('STARTUP', 'process started', 'node=' + process.version);
})();

const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = parseInt(process.env.GATE_PORT, 10) || 3002;

// B1, server.js:107 unchanged: registered FIRST so a 429 or a body error is recorded too.
try { app.use(require('./obs-middleware').middleware); }
catch (e) { console.error('[startup] obs-middleware not loaded:', e.message); }
app.use(require('./drain').middleware);
// server.js:138-145: /api/gate is on neither of its skip lists, so the 1 MB parser always applies there.
app.use(express.json({ limit: '1mb' }));
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || '*' }));
app.set('trust proxy', 1);
// server.js:152-165, except that /api/gate/check is not counted (gate429kit 2026-10-20). The buckets are
// this process's own (in-memory store; B11).
// Why /check is skipped: nginx asks it once for EVERY gated request (page, script, style, API call -- an AI
// Governance load is ~58), so a quick walk through a few pages, or everyone behind one office NAT or ZPA
// connector, spent the 500/min bucket on page assets. nginx's auth_request turns the 429 into a 500 and
// error_page into the 503 "isn't answering" page (UAT 1.5: 59 gate 429s, 2026-10-20 04:42Z). Only the internal
// /_gate location proxies to it (no public location maps to /api/gate/check), and it is a pure HMAC check of
// the cookie with no DB or LDAP, so there is nothing behind it for the limiter to protect. Every other gate
// route (landing, logout, refresh, ...) stays limited, and the APIs behind the pages keep their own limiters.
app.use(rateLimit({
  windowMs: 60_000,
  max: 500,
  standardHeaders: true,
  skip: (req) => req.path === '/api/gate/check',
  keyGenerator: (req) => {
    const peer = req.socket && req.socket.remoteAddress;
    const fromProxy = peer === '127.0.0.1' || peer === '::1' || peer === '::ffff:127.0.0.1';
    return (fromProxy && req.headers['x-real-ip']) || req.ip;
  },
}));
// B1, server.js:168 unchanged: per-module request / error counters, in-process.
try { app.use(require('./api-metrics').middleware); }
catch (e) { console.error('[startup] api-metrics not loaded:', e.message); }

// server.js:176-185 with connectionLimit 5 (B6). Used only by the blanket's loadCurrentUser below;
// gate-routes.js keeps its own 3-connection pool, as it does inside the hub.
const pool = mysql.createPool({
  host:               process.env.DB_HOST,
  port:               parseInt(process.env.DB_PORT) || 3306,
  database:           process.env.DB_NAME,
  user:               process.env.DB_USER,
  password:           process.env.DB_PASSWORD,
  waitForConnections: true,
  connectionLimit:    5,
  charset:            'utf8mb4',
});

// B1, server.js:195 unchanged: the telemetry flusher's own 2-connection pool, which also arms the
// 10-minute heartbeat (srv_job_run 'obs-heartbeat-' + OBS_APP).
try { require('./obs-lib').initPool(); }
catch (e) { console.error('[startup] obs-lib pool not set:', e.message); }

// server.js:233-404, the ITAM-001 deny-by-default blanket, for /api/gate. API_PUBLIC is server.js's
// entries under /api/gate, character for character. The API_CRON and API_SYNC_ADMIN branches are
// left out because none of their paths is under /api/gate. The rest -- loadCurrentUser, the 401
// body, the CSRF origin check, the read-only clamp -- is server.js's code unchanged.
// /api/gate/landing is not public in server.js either (golden landing|none = AUTH_REQUIRED).
app.disable('x-powered-by');
const rbacGate = require('./rbac-middleware')(pool);

// B7: liveness only. No database query: the gate's job is to answer, and a MySQL blip must not make
// a probe restart or page it. drain.middleware (above) already answers 503 here while draining.
app.get('/api/health', function (req, res) {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

const API_PUBLIC = new Set([
  '/api/gate/check',
  '/api/gate/refresh',
  '/api/gate/session-info',
  '/api/gate/check-approver',
  '/api/gate/logout',
  '/api/gate/federated-logout',
]);
const READ_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
app.use('/api/gate', function (req, res, next) {
  var p = req.originalUrl.split('?')[0].replace(/\/+$/, '') || '/';
  if (API_PUBLIC.has(p)) return next();
  return rbacGate.loadCurrentUser(req, res, function () {
    if (!req.user) {
      return res.status(401).json({ ok: false, error: 'AUTH_REQUIRED', detail: req.tokenError || 'NO_TOKEN' });
    }
    if (!READ_METHODS.has(req.method)) {
      var sfs = req.get('sec-fetch-site');
      var org = req.get('origin');
      var verdict;
      if (sfs) {
        verdict = (sfs === 'same-origin') ? 'ok' : 'cross';
      } else if (org) {
        var _oh = null;
        try { var _u = new URL(org); _oh = (_u.protocol === 'https:') ? _u.host.toLowerCase().replace(/:443$/, '') : null; } catch (e) { _oh = null; }
        var _hh = String(req.get('host') || '').toLowerCase().replace(/:443$/, '');
        verdict = (_oh && _oh === _hh) ? 'ok' : 'cross';
      } else {
        verdict = 'absent';
      }
      var csrfOk = (req.authVia === 'cookie') ? (verdict === 'ok') : (verdict !== 'cross');
      if (!csrfOk) {
        console.warn('[csrf-deny] ' + req.method + ' ' + p + ' via=' + req.authVia +
                     ' sec-fetch-site=' + (sfs || '-') + ' origin=' + (org || '-') +
                     ' user=' + (req.user && req.user.email));
        return res.status(403).json({ ok: false, error: 'CSRF_ORIGIN_REQUIRED',
          detail: 'A cookie-authenticated ' + req.method + ' must come from this origin. ' +
                  'Non-browser clients should send Authorization: Bearer instead.' });
      }
    }
    if (req.user.readOnly && !READ_METHODS.has(req.method)) {
      return res.status(403).json({ ok: false, error: 'READ_ONLY_TOKEN',
        detail: req.method + ' is not permitted with a read-only QA token.' });
    }
    return next();
  });
});

app.use('/api/gate', require('./gate-routes'));

// server.js:717-726 unchanged.
app.use(function (err, req, res, next) {
  if (err && err.type && err.status >= 400 && err.status < 500 && !res.headersSent) {
    return res.status(err.status).json({
      ok: false,
      error: err.type === 'entity.too.large' ? 'BODY_TOO_LARGE' : 'BAD_BODY',
      detail: err.message,
    });
  }
  return next(err);
});

// server.js:729-731, with this process's port and name.
require('./drain').attach(app.listen(PORT, '127.0.0.1', () => {
  console.log(`corpit-gate-api listening on 127.0.0.1:${PORT}`);
}), [pool]);
