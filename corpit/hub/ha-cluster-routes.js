// ──────────────────────────────────────────────────────────────
// ha-cluster-routes.js — A/B cluster health for the Health Center page.
//
// Mount: app.use('/api/system', require('./ha-cluster-routes').router);
//
// Read-only. Summarises the status file the node-local exporter
// (corpit-ha-status.timer, every 15 s) writes to /run/corpit-ha-status/status.json.
// The file is that node's own view of DRBD and Pacemaker; the request lands on
// the owner node (NLB owner-aware routing), so `node` in the reply says whose
// view it is. Super-admins only (requireSuperAdmin, the same gate Sign-In Watch
// uses): the Health Center page is super-admin only, and this is its one new
// endpoint, so the rule is enforced here and not only in the page. Per-route on
// purpose: this router is mounted on /api/system beside the Server Health
// routes, so a router-wide gate would lock them out too. No new page key.
//
// A feed that is missing, unreadable or older than STALE_SECONDS is reported
// `unknown`, never healthy: the page must not claim the cluster is fine from
// a file nobody is refreshing.
// ──────────────────────────────────────────────────────────────
'use strict';

const express = require('express');
const fs = require('fs');
const mysql = require('mysql2/promise');
const createRbac = require('./rbac-middleware');

const STATUS_FILE = process.env.HA_STATUS_FILE || '/run/corpit-ha-status/status.json';
const STALE_SECONDS = 90;            // the exporter runs every 15 s: six missed beats
const MAX_BYTES = 1024 * 1024;

// Same vocabulary and ordering as srv-dashboard-routes.js.
const STATES = ['critical', 'offline', 'warning', 'maintenance', 'unknown', 'healthy'];
function worst(a, b) {
  const ia = STATES.indexOf(a) === -1 ? STATES.length : STATES.indexOf(a);
  const ib = STATES.indexOf(b) === -1 ? STATES.length : STATES.indexOf(b);
  return ia <= ib ? a : b;
}

const RESYNC = ['SyncSource', 'SyncTarget', 'PausedSyncS', 'PausedSyncT', 'VerifyS', 'VerifyT', 'StartingSyncS', 'StartingSyncT'];

function str(v, n) { return v == null ? null : String(v).slice(0, n || 200); }
function arr(v) { return Array.isArray(v) ? v : []; }

// raw: parsed status.json (or null). now: epoch ms. Pure — no I/O, so it is
// tested against the real files from both nodes.
function summarize(raw, now, readError) {
  const out = {
    timestamp: new Date(now).toISOString(), state: 'healthy', reasons: [],
    node: null, observedAt: null, ageSeconds: null, source: 'node-local status file',
    drbd: null, pacemaker: null, holds: null, lastDecision: null, exporterErrors: [],
  };
  function add(st, text) { out.reasons.push({ state: st, text: text }); out.state = worst(out.state, st); }

  if (!raw || typeof raw !== 'object') {
    add('unknown', readError || 'cluster status feed is not available on this node');
    return out;
  }

  out.node = str(raw.node, 80);
  const seen = Date.parse(raw.observedAt);
  if (!isFinite(seen)) {
    add('unknown', 'cluster status feed has no valid timestamp');
  } else {
    out.observedAt = new Date(seen).toISOString();
    out.ageSeconds = Math.max(0, Math.round((now - seen) / 1000));
    if (out.ageSeconds > STALE_SECONDS) add('unknown', 'cluster status feed is ' + out.ageSeconds + ' s old (refreshed every 15 s)');
  }

  const d = raw.drbd && typeof raw.drbd === 'object' ? raw.drbd : null;
  if (d) {
    out.drbd = {
      role: str(d.role, 40), peerRole: str(d.peerRole, 40), connection: str(d.cs, 40),
      disk: str(d.disk, 40), peerDisk: str(d.peerDisk, 40),
      oosKiB: Number.isFinite(Number(d.oosKiB)) ? Number(d.oosKiB) : null, suspended: !!d.suspended,
    };
    if (d.present === false || d.moduleLoaded === false) add('critical', 'DRBD is not present on this node');
    else {
      if (d.cs !== 'Connected') {
        if (RESYNC.indexOf(d.cs) !== -1) add('warning', 'DRBD is resyncing (' + d.cs + ')');
        else add('critical', 'DRBD connection is ' + str(d.cs, 40));
      }
      if (d.disk !== 'UpToDate') add('critical', 'DRBD local disk is ' + str(d.disk, 40) + ', not UpToDate');
      if (d.peerDisk !== 'UpToDate' && d.cs === 'Connected') add('warning', 'DRBD peer disk is ' + str(d.peerDisk, 40) + ', not UpToDate');
      if (out.drbd.oosKiB > 0) add('warning', out.drbd.oosKiB + ' KiB out of sync');
      if (d.suspended) add('warning', 'DRBD I/O is suspended');
    }
  } else add('unknown', 'DRBD state missing from the feed');

  const p = raw.pacemaker && typeof raw.pacemaker === 'object' ? raw.pacemaker : null;
  if (p) {
    const nodes = arr(p.nodes).map(function (n) {
      return { name: str(n.name, 80), online: !!n.online, standby: !!n.standby, maintenance: !!n.maintenance,
               unclean: !!n.unclean, pending: !!n.pending, isDc: !!n.isDc };
    });
    const resources = Object.keys(p.resources && typeof p.resources === 'object' ? p.resources : {}).map(function (k) {
      const r = p.resources[k] || {};
      return { name: str(k, 80), role: str(r.role, 40), failed: !!r.failed, managed: r.managed !== false, nodes: arr(r.nodes).map(function (x) { return str(x, 80); }) };
    });
    out.pacemaker = {
      reachable: p.reachable !== false, dc: str(p.dc, 80), maintenanceMode: !!p.maintenanceMode,
      stonithEnabled: p.stonithEnabled !== false, promoted: arr(p.promotedNodes).map(function (x) { return str(x, 80); }),
      nodes: nodes, resources: resources, failCounts: arr(p.failCounts).length,
      fenceConstraint: !!(p.fenceConstraint && p.fenceConstraint.present),
    };
    if (!out.pacemaker.reachable) add('unknown', 'cluster manager is not reachable from this node');
    else {
      if (out.pacemaker.maintenanceMode) add('maintenance', 'cluster is in maintenance mode');
      if (!nodes.length) add('unknown', 'cluster node list is empty');
      nodes.forEach(function (n) {
        if (!n.online) add('critical', 'node ' + n.name + ' is offline');
        else if (n.unclean) add('critical', 'node ' + n.name + ' is unclean');
        else if (n.standby) add('warning', 'node ' + n.name + ' is in standby');
        else if (n.pending) add('warning', 'node ' + n.name + ' is pending');
        if (n.maintenance) add('maintenance', 'node ' + n.name + ' is in maintenance');
      });
      if (out.pacemaker.promoted.length !== 1) add('critical', out.pacemaker.promoted.length + ' nodes hold the DRBD primary role (expected 1)');
      resources.forEach(function (r) { if (r.failed) add('critical', 'resource ' + r.name + ' has failed'); });
      if (out.pacemaker.failCounts) add('critical', out.pacemaker.failCounts + ' resource fail count(s) recorded');
      if (arr(p.controldGiveUps).length) add('critical', 'cluster controller gave up on ' + arr(p.controldGiveUps).length + ' action(s)');
      if (!out.pacemaker.stonithEnabled) add('critical', 'fencing (STONITH) is disabled');
      if (out.pacemaker.fenceConstraint) add('warning', 'a DRBD fence constraint is in place');
    }
  } else add('unknown', 'Pacemaker state missing from the feed');

  const hr = raw.restart && typeof raw.restart === 'object' ? raw.restart : null;
  if (hr) out.holds = { join: !!hr.joinHold, peer: !!hr.peerHold };

  const ld = raw.handler && raw.handler.records && raw.handler.records.latestDecision;
  if (ld && typeof ld === 'object') {
    out.lastDecision = { mode: str(ld.mode, 40), outcome: str(ld.outcome, 40), reason: str(ld.reason, 200), recordedAt: str(ld.recordedAt, 40) };
  }

  out.exporterErrors = arr(raw.errors).slice(0, 5).map(function (e) { return str(typeof e === 'string' ? e : JSON.stringify(e), 200); });
  if (out.exporterErrors.length) add('warning', 'the status exporter reported ' + arr(raw.errors).length + ' error(s)');

  return out;
}

function readStatus(file) {
  return new Promise(function (resolve) {
    fs.stat(file, function (e, st) {
      if (e) return resolve({ raw: null, error: e.code === 'ENOENT' ? 'cluster status feed not found on this node' : 'cluster status feed is not readable (' + e.code + ')' });
      if (st.size > MAX_BYTES) return resolve({ raw: null, error: 'cluster status feed is unexpectedly large' });
      fs.readFile(file, 'utf8', function (e2, txt) {
        if (e2) return resolve({ raw: null, error: 'cluster status feed is not readable (' + e2.code + ')' });
        try { resolve({ raw: JSON.parse(txt), error: null }); }
        catch (e3) { resolve({ raw: null, error: 'cluster status feed is not valid JSON' }); }
      });
    });
  });
}

const router = express.Router();
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT) || 3306,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  waitForConnections: true,
  connectionLimit: 2,
  charset: 'utf8mb4',
});
const rbac = createRbac(pool);
router.use(rbac.loadCurrentUser);

router.get('/cluster', rbac.requireSuperAdmin, async function (req, res) {
  try {
    const r = await readStatus(STATUS_FILE);
    res.json(summarize(r.raw, Date.now(), r.error));
  } catch (e) {
    res.status(500).json({ error: 'cluster summary failed' });
  }
});

module.exports = { router: router, summarize: summarize, STALE_SECONDS: STALE_SECONDS };
