// ---------------------------------------------------------------------------
// obs-dependency.js - layer 3: what we asked of everyone else.      2026-09-06
//
// The gap this closes, stated as the incident it would have caught:
//
//   corpit's ZSCALER_CLIENT_SECRET was stale, so every /api/zscaler call 500'd
//   upstream. The Command Center rendered empty tables. Nothing anywhere
//   recorded that Zscaler had refused us - the page simply showed no devices,
//   which is indistinguishable from a fleet with no devices. It was found by
//   hand, by curling the vendor.
//
// Same shape as the Cert Watchtower cron dying in May and the page happily
// reporting ok/142d for four months: an upstream stopped answering and the only
// artefact was an absence.
//
// Coverage without edits: 56 modules in this tree call the global fetch() that
// Node 20 provides, so wrapping it once at startup instruments all of them.
// The 20 modules on raw https.request and the 7 on axios are not covered by the
// wrapper and must call record() explicitly - stats().uninstrumented says so
// rather than letting the dashboard imply full coverage it does not have.
//
// The wrapper measures time-to-response-headers, not time-to-body-consumed.
// It deliberately does not touch, clone or buffer the body: doing so would make
// observability capable of changing the behaviour it observes, and a large
// response would be held in memory twice.
// ---------------------------------------------------------------------------
'use strict';

const obs = require('./obs-lib');

const context = require('./activity-context');

const TABLE = 'obs_dependency';
const COLS = ['at', 'app', 'vendor', 'operation', 'method', 'host', 'path',
              'status', 'ok', 'duration_ms', 'err', 'request_id', 'actor_key'];

// Hostname -> the name a human would use in a sentence. Anything unmatched is
// reported under its own hostname rather than silently bucketed as 'other',
// because an unrecognised upstream is exactly the thing worth noticing.
const VENDORS = [
  [/(^|\.)graph\.microsoft\.com$/,            'graph'],
  [/(^|\.)login\.microsoftonline\.com$/,      'entra-auth'],
  [/(^|\.)sts\.windows\.net$/,                'entra-auth'],
  [/(^|\.)manage\.office\.com$/,              'm365-mgmt'],
  [/(^|\.)bap\.microsoft\.com$/,              'powerplatform'],
  [/(^|\.)sharepoint\.com$/,                  'sharepoint'],
  [/(^|\.)okta\.com$/,                        'okta'],
  [/(^|\.)oktapreview\.com$/,                 'okta'],
  [/(^|\.)zsapi\.net$/,                       'zscaler'],
  // ZIdentity OneAPI issues the OAuth2 token that gates every ZIA and ZPA call
  // below, and it lives on the tenant's vanity domain (auction.zslogin.net),
  // which matches none of the patterns above. Without this line the token call
  // files under its own hostname while the calls it authorises file under
  // 'zscaler' -- so a dashboard filtered to 'zscaler' shows every data call and
  // hides the auth failure that caused them. That is the exact incident this
  // layer was built for: a stale ZSCALER_CLIENT_SECRET, empty tables, and no
  // artefact anywhere saying the vendor had refused us.
  [/(^|\.)zslogin\.net$/,                     'zscaler'],
  // Zscaler Workflow Automation (ZWA), the DLP-incident source, on its own
  // host and its own API key. Layer 3 surfaced it under the raw hostname
  // api.us2.zsworkflow.net the first hour it was watching, which is the
  // unmapped-upstream path working as intended -- and the reason to map it now
  // is that a reader filtering the dashboard to 'zscaler' would otherwise see
  // every other Zscaler plane and silently miss this one. host and path keep
  // the per-plane detail.
  [/(^|\.)zsworkflow\.net$/,                  'zscaler'],
  [/(^|\.)zscaler\.com$/,                     'zscaler'],
  [/(^|\.)zscalertwo\.net$/,                  'zscaler'],
  [/(^|\.)zdxcloud\.net$/,                    'zscaler'],
  [/(^|\.)manageengine\.com$/,                'sdp'],
  [/(^|\.)zoho\.com$/,                        'sdp'],
  [/(^|\.)rapid7\.com$/,                      'rapid7'],
  [/(^|\.)insight\.rapid7\.com$/,             'rapid7'],
  [/(^|\.)meraki\.com$/,                      'meraki'],
  [/(^|\.)kandji\.io$/,                       'kandji'],
  [/(^|\.)apple\.com$/,                       'apple-bm'],
  [/(^|\.)anthropic\.com$/,                   'anthropic'],
  [/(^|\.)itam\.nrpi\.local$/,                'itam'],
  [/(^|\.)corpit\.nrpi\.local$/,              'corpit-self'],
];

function vendorOf(host) {
  const h = String(host || '').toLowerCase();
  for (const v of VENDORS) if (v[0].test(h)) return v[1];
  return obs.clip(h, 40) || 'unknown';
}

// Explicit recorder. Anything not on global fetch calls this.
const record = obs.safe(function (d) {
  const ctx=context.current(), req=ctx.req||{}, u=req.user||req.currentUser||req.rbacUser||{};
  if (!d.ok && ctx.req) ctx.req.activityDependencyFailed = true;
  obs.push(TABLE, COLS, [
    obs.nowSql(),
    obs.CFG.app,
    obs.clip(d.vendor || vendorOf(d.host), 40),
    obs.clip(d.operation || '', 120),
    obs.clip(d.method || 'GET', 8),
    obs.clip(d.host, 120),
    obs.clip(obs.redactUrl(d.path), 191),
    Number.isFinite(d.status) ? d.status : null,
    d.ok ? 1 : 0,
    Number.isFinite(d.durationMs) ? Math.round(d.durationMs) : null,
    obs.clip(obs.scrub(d.err), 255),
    ctx.requestId || null,
    obs.actorKey(u.upn || u.userPrincipalName || u.mail || u.email || u.username || req.sessionUpn || null),
  ]);
});

// -- the fetch wrapper ------------------------------------------------------
let installed = false;
let retryTimer = null;

// install() is called once, at startup. It used to return false forever if
// recording happened to be off at that moment -- and recording is a console
// setting that an operator can switch back on at any time, read by obs-lib on a
// 30s poll. So a process that booted with obs disabled had its outbound calls
// permanently uninstrumented, silently, no matter what the console said
// afterwards. Layer 3 would report nothing and there was no state that said why.
//
// The retry is unref'd and stops itself the moment the wrap succeeds.
function armRetry() {
  if (retryTimer || installed) return;
  retryTimer = setInterval(function () {
    if (installed) { clearInterval(retryTimer); retryTimer = null; return; }
    if (obs.CFG.enabled) install();
  }, 60000);
  if (retryTimer.unref) retryTimer.unref();
}

function install() {
  if (installed) return false;
  if (!obs.CFG.enabled) { armRetry(); return false; }
  // No global fetch at all (an older runtime) is not transient, so there is
  // nothing to retry towards -- but it IS a state, and arming the retry keeps
  // the reason visible instead of returning a bare false that reads as "off".
  if (typeof globalThis.fetch !== 'function') { armRetry(); return false; }
  const original = globalThis.fetch;
  installed = true;
  // Stop retrying in the same statement that makes it installed. Leaving the
  // timer to notice on its own tick left installRetrying reporting a retry that
  // was no longer happening: a status field describing the past, which is the
  // whole defect class this build exists to catch.
  if (retryTimer) { clearInterval(retryTimer); retryTimer = null; }

  globalThis.fetch = function (input, init) {
    let host = null, path = null, method = 'GET';
    // Parsing the request must never be able to break the request. If we cannot
    // work out what is being called, we still make the call - untracked.
    try {
      const url = (typeof input === 'string') ? input
                : (input && input.url) ? input.url
                : String(input);
      const u = new URL(url);
      host = u.hostname;
      path = u.pathname + (u.search || '');
      method = (init && init.method) || (input && input.method) || 'GET';
    } catch (e) { /* not a URL we can parse; fall through untracked */ }

    if (!host) return original.apply(this, arguments);

    const started = process.hrtime.bigint();
    const ms = function () { return Number(process.hrtime.bigint() - started) / 1e6; };

    return original.apply(this, arguments).then(function (res) {
      record({ vendor: vendorOf(host), host: host, path: path, method: method,
               status: res.status, ok: res.ok, durationMs: ms() });
      return res;
    }, function (err) {
      // status stays NULL: we never got a response at all. That is a different
      // fact from "responded 500", and the dashboard shows it as such.
      record({ vendor: vendorOf(host), host: host, path: path, method: method,
               status: null, ok: false, durationMs: ms(),
               err: (err && (err.code || err.message)) || 'fetch failed' });
      throw err;
    });
  };
  return true;
}

function stats() {
  return {
    fetchWrapped: installed,
    // Distinguishes "not wrapped, and nothing is trying" from "not wrapped yet,
    // waiting for recording to be switched on". Only the first is a fault.
    installRetrying: !!retryTimer,
    // Stated plainly so the dashboard cannot imply coverage it does not have.
    uninstrumented: 'modules using axios or raw https.request are not captured ' +
                    'automatically; they must call obs-dependency.record()',
  };
}

module.exports = { install, record, vendorOf, stats, TABLE, COLS };
