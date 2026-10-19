// ──────────────────────────────────────────────────────────────
// ha-cluster.test.js — summarize() in ha-cluster-routes.js.
//
//   cd /var/www/corpit-hub-api && node --test ha-cluster.test.js
//
// The two fixtures are the real /run/corpit-ha-status/status.json files from
// node A (Primary) and node B (Secondary), captured 2026-10-01 with the bulky
// stonith history and journal tails trimmed (summarize() does not read them).
// ──────────────────────────────────────────────────────────────
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { summarize, STALE_SECONDS } = require('./ha-cluster-routes');

const A = {"bootId":"a681c20f-9d7d-41cc-941a-597cb14fe5f4","drbd":{"cs":"Connected","csSince":"2026-09-30T02:20:49Z","disk":"UpToDate","flags":"r-----","line":"0: cs:Connected ro:Primary/Secondary ds:UpToDate/UpToDate C r-----","minor":0,"moduleLoaded":true,"oosKiB":0,"peerDisk":"UpToDate","peerRole":"Secondary","present":true,"protocol":"C","role":"Primary","sinceResolutionSeconds":15,"suspended":false,"suspendedSince":null,"version":"version: 8.4.11 (api:1/proto:86-101)"},"durationMs":145,"errors":[],"exporterVersion":"1.2.0","handler":{"journal":[],"processes":[],"records":{"count":40,"dirPresent":true,"latestDecision":{"elapsedSeconds":5.679,"exitCode":7,"file":"20260929T210714.978904Z-19528-decision.json","kind":"decision","mode":"promotion","outcome":"fenced","pid":19528,"readable":true,"reason":"Constraint owned and peer stopped twice","recordedAt":"2026-09-29T21:07:14.978927+00:00"},"latestStarted":{"file":"20260929T210709.331354Z-19528-started.json","kind":"started","mode":"promotion","pid":19528,"readable":true,"recordedAt":"2026-09-29T21:07:09.331383+00:00"},"recentDecisions":[{"elapsedSeconds":5.551,"exitCode":7,"file":"20260929T045510.871387Z-1697168-decision.json","kind":"decision","mode":"primary","outcome":"fenced","pid":1697168,"readable":true,"reason":"Constraint owned and peer stopped twice","recordedAt":"2026-09-29T04:55:10.871412+00:00"},{"elapsedSeconds":481.396,"exitCode":1,"file":"20260929T053054.450149Z-1718336-decision.json","kind":"decision","mode":"primary","outcome":"not_confirmed","pid":1718336,"readable":true,"reason":"Deadline reached without a confirmed fence","recordedAt":"2026-09-29T05:30:54.450173+00:00"},{"elapsedSeconds":479.721,"exitCode":1,"file":"20260929T053216.303775Z-1718931-decision.json","kind":"decision","mode":"primary","outcome":"not_confirmed","pid":1718931,"readable":true,"reason":"Deadline reached without a confirmed fence","recordedAt":"2026-09-29T05:32:16.303803+00:00"},{"elapsedSeconds":23.033,"exitCode":7,"file":"20260929T161532.868190Z-1863241-decision.json","kind":"decision","mode":"primary","outcome":"fenced","pid":1863241,"readable":true,"reason":"Constraint owned and peer stopped twice","recordedAt":"2026-09-29T16:15:32.868223+00:00"},{"elapsedSeconds":5.679,"exitCode":7,"file":"20260929T210714.978904Z-19528-decision.json","kind":"decision","mode":"promotion","outcome":"fenced","pid":19528,"readable":true,"reason":"Constraint owned and peer stopped twice","recordedAt":"2026-09-29T21:07:14.978927+00:00"}]}},"kernelFencePeer":[],"node":"ip-10-9-58-207","observedAt":"2026-10-01T01:36:17Z","pacemaker":{"cloneFound":true,"controldGiveUps":[],"dc":"ip-10-9-59-25","dcPresent":true,"drbdInstances":[{"active":true,"failed":false,"managed":true,"nodes":["ip-10-9-59-25"],"role":"Unpromoted"},{"active":true,"failed":false,"managed":true,"nodes":["ip-10-9-58-207"],"role":"Promoted"}],"failCounts":[],"fenceConstraint":{"constraints":[],"owners":[],"present":false},"maintenanceMode":false,"nodes":[{"isDc":false,"maintenance":false,"name":"ip-10-9-58-207","online":true,"pending":false,"shutdown":false,"standby":false,"unclean":false},{"isDc":true,"maintenance":false,"name":"ip-10-9-59-25","online":true,"pending":false,"shutdown":false,"standby":false,"unclean":false}],"promotedNodes":["ip-10-9-58-207"],"reachable":true,"resources":{"fence-A":{"failed":false,"managed":true,"nodes":["ip-10-9-59-25"],"role":"Started"},"fence-B":{"failed":false,"managed":true,"nodes":["ip-10-9-58-207"],"role":"Started"},"fs-corpit":{"failed":false,"managed":true,"nodes":["ip-10-9-58-207"],"role":"Started"}},"stonithEnabled":true,"stonithHistory":[{"action":"off","client":"pacemaker-controld.1366","completed":"2026-09-30 02:18:59.878514Z","delegate":"ip-10-9-59-25","exit-reason":null,"extended-status":null,"origin":"ip-10-9-59-25","status":"success","target":"ip-10-9-58-207"},{"action":"off","client":"stonith_admin.195468","completed":"2026-09-30 02:18:59.878514Z","delegate":"ip-10-9-59-25","exit-reason":null,"extended-status":null,"origin":"ip-10-9-59-25","status":"success","target":"ip-10-9-58-207"}],"stopAllResources":false,"withQuorum":true},"restart":{"commissioned":true,"join":{"error":null,"present":true,"status":{"at":"2026-09-30T02:20:04Z","failedGuards":[],"outcome":"started","severity":null}},"joinHold":false,"markerError":null,"peer":{"error":null,"present":true,"status":{"at":"2026-09-29T21:21:37.242291Z","capStarts":2,"capWindowSeconds":3600,"history":[{"at":"2026-09-29T21:07:09.567470Z","outcome":"accepted","severity":null},{"at":"2026-09-29T21:07:45.421991Z","outcome":"started","severity":null},{"at":"2026-09-29T21:21:37.054351Z","outcome":"rejoined","severity":null},{"at":"2026-09-29T21:21:37.057763Z","outcome":"accepted","severity":null},{"at":"2026-09-29T21:21:37.134481Z","outcome":"peer_already_running","severity":null},{"at":"2026-09-29T21:21:37.242291Z","outcome":"rejoined","severity":null}],"outcome":"rejoined","severity":null,"startsInWindow":1}},"peerHold":false,"schemaVersion":1,"units":{"corpit-cluster-autojoin.service":{"ActiveState":"active","LoadState":"loaded","Result":"success","SubState":"exited","UnitFileState":"enabled"},"corpit-peer-autostart.path":{"ActiveState":"active","LoadState":"loaded","Result":"success","SubState":"waiting","UnitFileState":"enabled"},"corpit-peer-autostart.service":{"ActiveState":"inactive","LoadState":"loaded","Result":"success","SubState":"dead","UnitFileState":"static"}}},"schemaVersion":1};
const B = {"bootId":"c5a8720e-8d78-460c-871a-ce23a65b0af8","drbd":{"cs":"Connected","csSince":"2026-09-30T02:20:46Z","disk":"UpToDate","flags":"r-----","line":"0: cs:Connected ro:Secondary/Primary ds:UpToDate/UpToDate C r-----","minor":0,"moduleLoaded":true,"oosKiB":0,"peerDisk":"UpToDate","peerRole":"Primary","present":true,"protocol":"C","role":"Secondary","sinceResolutionSeconds":15,"suspended":false,"suspendedSince":null,"version":"version: 8.4.11 (api:1/proto:86-101)"},"durationMs":128,"errors":[],"exporterVersion":"1.2.0","handler":{"journal":[{"at":"2026-09-30T02:00:13Z","message":"start mode=promotion peer=ip-10-9-58-207 i-08572626d70e9dbc3","pid":127277,"priority":5},{"at":"2026-09-30T02:00:13Z","message":"crm-fence-peer.sh rc=7","pid":127277,"priority":6},{"at":"2026-09-30T02:00:19Z","decision":"fenced","exitCode":7,"message":"decision=fenced exit=7: Constraint owned and peer stopped twice","pid":127277,"priority":5},{"at":"2026-09-30T02:19:00Z","message":"start mode=promotion peer=ip-10-9-58-207 i-08572626d70e9dbc3","pid":196772,"priority":5},{"at":"2026-09-30T02:19:00Z","message":"crm-fence-peer.sh rc=7","pid":196772,"priority":6},{"at":"2026-09-30T02:19:05Z","decision":"fenced","exitCode":7,"message":"decision=fenced exit=7: Constraint owned and peer stopped twice","pid":196772,"priority":5}],"processes":[],"records":{"count":7,"dirPresent":true,"latestDecision":{"elapsedSeconds":5.766,"exitCode":7,"file":"20260930T021905.897221Z-196772-decision.json","kind":"decision","mode":"promotion","outcome":"fenced","pid":196772,"readable":true,"reason":"Constraint owned and peer stopped twice","recordedAt":"2026-09-30T02:19:05.897256+00:00"},"latestStarted":{"file":"20260930T021900.162965Z-196772-started.json","kind":"started","mode":"promotion","pid":196772,"readable":true,"recordedAt":"2026-09-30T02:19:00.162996+00:00"},"recentDecisions":[{"elapsedSeconds":0.0,"exitCode":1,"file":"20260926T163735.022186Z-75240-decision.json","kind":"decision","mode":null,"outcome":"reconnected","pid":75240,"readable":true,"reason":"Replication link reconnected; result is moot","recordedAt":"2026-09-26T16:37:35.022212+00:00"},{"elapsedSeconds":5.702,"exitCode":7,"file":"20260929T203927.920606Z-161958-decision.json","kind":"decision","mode":"promotion","outcome":"fenced","pid":161958,"readable":true,"reason":"Constraint owned and peer stopped twice","recordedAt":"2026-09-29T20:39:27.920633+00:00"},{"elapsedSeconds":5.781,"exitCode":7,"file":"20260930T020019.520847Z-127277-decision.json","kind":"decision","mode":"promotion","outcome":"fenced","pid":127277,"readable":true,"reason":"Constraint owned and peer stopped twice","recordedAt":"2026-09-30T02:00:19.520883+00:00"},{"elapsedSeconds":5.766,"exitCode":7,"file":"20260930T021905.897221Z-196772-decision.json","kind":"decision","mode":"promotion","outcome":"fenced","pid":196772,"readable":true,"reason":"Constraint owned and peer stopped twice","recordedAt":"2026-09-30T02:19:05.897256+00:00"}]}},"kernelFencePeer":[{"at":"2026-09-30T02:20:44Z","message":"drbd corpit-data: helper command: /sbin/drbdadm unfence-peer corpit-data exit code 0 (0x0)","pid":null,"priority":6},{"at":"2026-09-30T02:20:44Z","message":"drbd corpit-data: helper command: /sbin/drbdadm unfence-peer corpit-data","pid":null,"priority":6}],"node":"ip-10-9-59-25","observedAt":"2026-10-01T01:36:16Z","pacemaker":{"cloneFound":true,"controldGiveUps":[],"dc":"ip-10-9-59-25","dcPresent":true,"drbdInstances":[{"active":true,"failed":false,"managed":true,"nodes":["ip-10-9-59-25"],"role":"Unpromoted"},{"active":true,"failed":false,"managed":true,"nodes":["ip-10-9-58-207"],"role":"Promoted"}],"failCounts":[],"fenceConstraint":{"constraints":[],"owners":[],"present":false},"maintenanceMode":false,"nodes":[{"isDc":false,"maintenance":false,"name":"ip-10-9-58-207","online":true,"pending":false,"shutdown":false,"standby":false,"unclean":false},{"isDc":true,"maintenance":false,"name":"ip-10-9-59-25","online":true,"pending":false,"shutdown":false,"standby":false,"unclean":false}],"promotedNodes":["ip-10-9-58-207"],"reachable":true,"resources":{"fence-A":{"failed":false,"managed":true,"nodes":["ip-10-9-59-25"],"role":"Started"},"fence-B":{"failed":false,"managed":true,"nodes":["ip-10-9-58-207"],"role":"Started"},"fs-corpit":{"failed":false,"managed":true,"nodes":["ip-10-9-58-207"],"role":"Started"}},"stonithEnabled":true,"stonithHistory":[{"action":"off","client":"pacemaker-controld.1366","completed":"2026-09-30 02:18:59.878514Z","delegate":"ip-10-9-59-25","exit-reason":null,"extended-status":null,"origin":"ip-10-9-59-25","status":"success","target":"ip-10-9-58-207"},{"action":"off","client":"stonith_admin.195468","completed":"2026-09-30 02:18:59.878514Z","delegate":"ip-10-9-59-25","exit-reason":null,"extended-status":null,"origin":"ip-10-9-59-25","status":"success","target":"ip-10-9-58-207"}],"stopAllResources":false,"withQuorum":true},"restart":{"commissioned":true,"join":{"error":null,"present":true,"status":{"at":"2026-09-29T21:08:10Z","failedGuards":[],"outcome":"started","severity":null}},"joinHold":false,"markerError":null,"peer":{"error":null,"present":true,"status":{"at":"2026-09-30T02:23:29.610667Z","capStarts":2,"capWindowSeconds":3600,"history":[{"at":"2026-09-30T02:00:13.966557Z","outcome":"accepted","severity":null},{"at":"2026-09-30T02:00:49.644863Z","outcome":"started","severity":null},{"at":"2026-09-30T02:14:56.936543Z","outcome":"rejoined","severity":null},{"at":"2026-09-30T02:14:56.940430Z","outcome":"accepted","severity":null},{"at":"2026-09-30T02:14:57.017341Z","outcome":"peer_already_running","severity":null},{"at":"2026-09-30T02:14:57.129985Z","outcome":"rejoined","severity":null},{"at":"2026-09-30T02:19:00.495327Z","outcome":"accepted","severity":null},{"at":"2026-09-30T02:19:36.148805Z","outcome":"started","severity":null},{"at":"2026-09-30T02:20:51.796798Z","outcome":"rejoined","severity":null},{"at":"2026-09-30T02:20:51.800107Z","outcome":"capped","severity":"critical"},{"at":"2026-09-30T02:23:29.610667Z","outcome":"acknowledged","severity":null}],"outcome":"acknowledged","severity":null,"startsInWindow":2}},"peerHold":false,"schemaVersion":1,"units":{"corpit-cluster-autojoin.service":{"ActiveState":"active","LoadState":"loaded","Result":"success","SubState":"exited","UnitFileState":"enabled"},"corpit-peer-autostart.path":{"ActiveState":"active","LoadState":"loaded","Result":"success","SubState":"waiting","UnitFileState":"enabled"},"corpit-peer-autostart.service":{"ActiveState":"inactive","LoadState":"loaded","Result":"success","SubState":"dead","UnitFileState":"static"}}},"schemaVersion":1};

function clone(o) { return JSON.parse(JSON.stringify(o)); }
function at(raw, plusSeconds) { return Date.parse(raw.observedAt) + (plusSeconds || 0) * 1000; }
function texts(s) { return s.reasons.map(function (r) { return r.text; }).join(' | '); }

test('real node A (Primary) summarises healthy, with its own identity', function () {
  const s = summarize(A, at(A, 5));
  assert.strictEqual(s.state, 'healthy', texts(s));
  assert.strictEqual(s.node, 'ip-10-9-58-207');
  assert.strictEqual(s.drbd.role, 'Primary');
  assert.strictEqual(s.drbd.connection, 'Connected');
  assert.strictEqual(s.ageSeconds, 5);
  assert.deepStrictEqual(s.pacemaker.promoted, ['ip-10-9-58-207']);
  assert.strictEqual(s.pacemaker.nodes.length, 2);
  assert.ok(s.pacemaker.nodes.every(function (n) { return n.online; }));
  assert.ok(s.pacemaker.resources.length >= 3);
  assert.strictEqual(s.lastDecision.outcome, 'fenced');
});

test('real node B (Secondary) summarises healthy and reports B as the observer', function () {
  const s = summarize(B, at(B, 5));
  assert.strictEqual(s.state, 'healthy', texts(s));
  assert.strictEqual(s.node, 'ip-10-9-59-25');
  assert.strictEqual(s.drbd.role, 'Secondary');
});

test('a feed older than the stale limit is unknown, never healthy', function () {
  const s = summarize(A, at(A, STALE_SECONDS + 30));
  assert.strictEqual(s.state, 'unknown');
  assert.match(texts(s), /s old/);
});

test('a feed exactly at the stale limit is still current', function () {
  assert.strictEqual(summarize(A, at(A, STALE_SECONDS)).state, 'healthy');
});

test('a stale feed that last said critical stays critical', function () {
  const r = clone(A); r.pacemaker.nodes[1].online = false;
  assert.strictEqual(summarize(r, at(r, 600)).state, 'critical');
});

test('missing, unreadable or non-object feeds are unknown and carry the reason', function () {
  const now = Date.now();
  assert.strictEqual(summarize(null, now, 'cluster status feed not found on this node').state, 'unknown');
  assert.match(texts(summarize(null, now, 'cluster status feed not found on this node')), /not found/);
  assert.strictEqual(summarize('nope', now).state, 'unknown');
  assert.strictEqual(summarize(undefined, now).state, 'unknown');
});

test('a feed with no usable timestamp is unknown', function () {
  const r = clone(A); delete r.observedAt;
  assert.strictEqual(summarize(r, Date.now()).state, 'unknown');
});

const CASES = [
  ['peer node offline',           function (r) { r.pacemaker.nodes[1].online = false; },                'critical'],
  ['node unclean',                function (r) { r.pacemaker.nodes[1].unclean = true; },               'critical'],
  ['node standby',                function (r) { r.pacemaker.nodes[1].standby = true; },               'warning'],
  ['node pending',                function (r) { r.pacemaker.nodes[1].pending = true; },               'warning'],
  ['node in maintenance',         function (r) { r.pacemaker.nodes[1].maintenance = true; },           'maintenance'],
  ['cluster maintenance mode',    function (r) { r.pacemaker.maintenanceMode = true; },                'maintenance'],
  ['no promoted node',            function (r) { r.pacemaker.promotedNodes = []; },                    'critical'],
  ['two promoted nodes',          function (r) { r.pacemaker.promotedNodes = ['a', 'b']; },            'critical'],
  ['fail count recorded',         function (r) { r.pacemaker.failCounts = [{ rsc: 'x' }]; },           'critical'],
  ['controller gave up',          function (r) { r.pacemaker.controldGiveUps = [{}]; },                'critical'],
  ['resource failed',             function (r) { r.pacemaker.resources['fs-corpit'].failed = true; },  'critical'],
  ['STONITH disabled',            function (r) { r.pacemaker.stonithEnabled = false; },                'critical'],
  ['fence constraint present',    function (r) { r.pacemaker.fenceConstraint.present = true; },        'warning'],
  ['Pacemaker unreachable',       function (r) { r.pacemaker.reachable = false; },                     'unknown'],
  ['Pacemaker block missing',     function (r) { delete r.pacemaker; },                                'unknown'],
  ['DRBD StandAlone',             function (r) { r.drbd.cs = 'StandAlone'; },                          'critical'],
  ['DRBD Disconnected',           function (r) { r.drbd.cs = 'Disconnected'; },                        'critical'],
  ['DRBD resyncing',              function (r) { r.drbd.cs = 'SyncSource'; },                          'warning'],
  ['local disk not UpToDate',     function (r) { r.drbd.disk = 'Inconsistent'; },                      'critical'],
  ['peer disk not UpToDate',      function (r) { r.drbd.peerDisk = 'Outdated'; },                      'warning'],
  ['out-of-sync blocks',          function (r) { r.drbd.oosKiB = 128; },                               'warning'],
  ['DRBD I/O suspended',          function (r) { r.drbd.suspended = true; },                           'warning'],
  ['DRBD module not loaded',      function (r) { r.drbd.moduleLoaded = false; },                       'critical'],
  ['DRBD block missing',          function (r) { delete r.drbd; },                                     'unknown'],
  ['exporter errors',             function (r) { r.errors = ['pcs timed out']; },                      'warning'],
];
CASES.forEach(function (c) {
  test('verdict: ' + c[0] + ' -> ' + c[2], function () {
    const r = clone(A); c[1](r);
    const s = summarize(r, at(r, 5));
    assert.strictEqual(s.state, c[2], texts(s));
    assert.ok(s.reasons.length >= 1);
  });
});

test('worst condition wins, never an average', function () {
  const r = clone(A);
  r.drbd.oosKiB = 8;                       // warning
  r.pacemaker.nodes[1].online = false;     // critical
  r.errors = ['x'];                        // warning
  const s = summarize(r, at(r, 5));
  assert.strictEqual(s.state, 'critical');
  assert.ok(s.reasons.length >= 3);
});

test('a healthy cluster carries no reasons', function () {
  assert.deepStrictEqual(summarize(A, at(A, 5)).reasons, []);
});

test('summarize does not mutate its input and bounds hostile strings', function () {
  const r = clone(A); r.node = 'x'.repeat(5000); r.errors = ['y'.repeat(5000)];
  const before = JSON.stringify(r);
  const s = summarize(r, at(r, 5));
  assert.strictEqual(JSON.stringify(r), before);
  assert.ok(s.node.length <= 80);
  assert.ok(s.exporterErrors[0].length <= 200);
});

test('nothing outside the summary shape leaks (no raw stonith history, journal or boot id)', function () {
  const s = JSON.stringify(summarize(A, at(A, 5)));
  assert.ok(!/stonithHistory|bootId|kernelFencePeer|journal/.test(s));
});

// ── the route gate ────────────────────────────────────────────────────────
// ha-cluster-routes.js builds its rbac from ./rbac-middleware at require time, so
// this loads a private copy with a stand-in for that module. The stand-in's
// requireSuperAdmin follows the real contract (401 with no user, 403
// NOT_SUPER_ADMIN for a non-super-admin, otherwise next); what is under test is
// WHICH guard /cluster is wired to. The real middleware is exercised on the dev hub.
test('GET /cluster is super-admin only: guarded by requireSuperAdmin, never by requirePage', async function () {
  const http = require('node:http');
  const express = require('express');
  const rbacPath = require.resolve('./rbac-middleware');
  const routesPath = require.resolve('./ha-cluster-routes');
  const saved = { rbac: require.cache[rbacPath], routes: require.cache[routesPath], file: process.env.HA_STATUS_FILE };
  const guards = [];
  process.env.HA_STATUS_FILE = '/nonexistent/corpit-ha-status.json';
  require.cache[rbacPath] = { id: rbacPath, filename: rbacPath, loaded: true, exports: function () {
    return {
      loadCurrentUser: function (req, res, next) {
        const raw = req.headers['x-test-user'];
        req.user = raw ? JSON.parse(raw) : null;
        next();
      },
      requireSuperAdmin: function (req, res, next) {
        guards.push('requireSuperAdmin');
        if (!req.user) return res.status(401).json({ error: 'Authentication required', code: 'UNAUTHENTICATED' });
        if (!req.user.isSuperAdmin) return res.status(403).json({ error: 'Super-admin access required', code: 'NOT_SUPER_ADMIN' });
        next();
      },
      requirePage: function () { guards.push('requirePage'); return function (req, res, next) { next(); }; }
    };
  } };
  delete require.cache[routesPath];
  let server;
  try {
    const app = express();
    app.use('/api/system', require('./ha-cluster-routes').router);
    server = await new Promise(function (ok) { const s = app.listen(0, '127.0.0.1', function () { ok(s); }); });
    function get(user) {
      return new Promise(function (ok, bad) {
        const headers = user ? { 'x-test-user': JSON.stringify(user) } : {};
        http.get({ host: '127.0.0.1', port: server.address().port, path: '/api/system/cluster', headers: headers }, function (res) {
          let b = ''; res.on('data', function (c) { b += c; });
          res.on('end', function () { ok({ status: res.statusCode, body: JSON.parse(b) }); });
        }).on('error', bad);
      });
    }
    const anon = await get(null);
    assert.strictEqual(anon.status, 401);
    const tier2 = await get({ email: 't2@example.test', isSuperAdmin: false, roles: ['tier2'], pages: { 'server-health': 'admin' } });
    assert.strictEqual(tier2.status, 403);
    assert.strictEqual(tier2.body.code, 'NOT_SUPER_ADMIN');
    assert.ok(!('state' in tier2.body), 'a refused caller gets no cluster data');
    const sa = await get({ email: 'sa@example.test', isSuperAdmin: true, roles: ['superadmin'] });
    assert.strictEqual(sa.status, 200);
    assert.strictEqual(sa.body.state, 'unknown');           // no feed file in the test: unknown, never healthy
    assert.ok(guards.length === 3 && guards.every(function (g) { return g === 'requireSuperAdmin'; }), 'only requireSuperAdmin guards /cluster: ' + guards.join(','));
  } finally {
    if (server) await new Promise(function (ok) { server.close(ok); });
    if (saved.rbac) require.cache[rbacPath] = saved.rbac; else delete require.cache[rbacPath];
    if (saved.routes) require.cache[routesPath] = saved.routes; else delete require.cache[routesPath];
    if (saved.file === undefined) delete process.env.HA_STATUS_FILE; else process.env.HA_STATUS_FILE = saved.file;
  }
});
