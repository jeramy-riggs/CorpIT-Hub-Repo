// ─────────────────────────────────────────────────────────────────────────────
// srv-dashboard-routes.js — Server Health & Maintenance dashboard.
//
// Mount: app.use('/api/system', require('./srv-dashboard-routes'));
//        (after system-health-routes.js and system-actions-routes.js)
//
// Every route here is gated server-side on the 'server-health' page: read for
// the dashboard, admin for anything that registers, edits, acknowledges, or
// probes. Hiding the nav link is not the control.
//
// SCOPE: the servers, virtual hosts, jobs and APIs surfaced here come from the
// CorpIT registry tables (srv_server / srv_vhost), the local box's own crontab
// and Express router stack, and the vendor probes CorpIT already runs. There is
// no discovery path and no free-form target parameter anywhere in this file.
// ─────────────────────────────────────────────────────────────────────────────
'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');
const createRbac = require('./rbac-middleware');
const probe = require('./srv-probe-lib');

let apiMetrics = null;
try { apiMetrics = require('./api-metrics'); } catch (e) { /* optional */ }

const router = express.Router();

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT) || 3306,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  waitForConnections: true,
  connectionLimit: 4,
  charset: 'utf8mb4',
});

const rbac = createRbac(pool);
router.use(rbac.loadCurrentUser);

const PAGE = 'server-health';
// settingsfold W6 2026-10-12: PUT /thresholds writes an rbac_audit_log row.
const SA = require('./settings-audit');
const needRead = rbac.requirePage(PAGE, 'read');
const needAdmin = rbac.requirePage(PAGE, 'admin');

// ── shared vocabulary ───────────────────────────────────────────────────────
// One status vocabulary for the whole dashboard, so a card, a row and a
// finding never disagree about what "warning" means.
const STATES = ['critical', 'offline', 'warning', 'maintenance', 'unknown', 'healthy'];
function worst(a, b) {
  const ia = STATES.indexOf(a) === -1 ? STATES.length : STATES.indexOf(a);
  const ib = STATES.indexOf(b) === -1 ? STATES.length : STATES.indexOf(b);
  return ia <= ib ? a : b;
}
// system-health-routes speaks ok/warn/down; translate at the boundary.
function fromLegacy(s) {
  return s === 'ok' ? 'healthy' : s === 'warn' ? 'warning' : s === 'down' ? 'critical' : 'unknown';
}

function clean(s, max) {
  if (s == null) return null;
  return String(s).replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max || 512);
}
function actor(req) { return (req.user && req.user.email) || 'unknown'; }

// Every aggregate below is wrapped: one failing source degrades to a labelled
// 'unavailable' block and the rest of the dashboard still renders.
async function isolate(name, fn) {
  try {
    const value = await fn();
    return { source: name, ok: true, value: value };
  } catch (e) {
    console.error('[srv-dashboard] source "' + name + '" failed:', e.message);
    return { source: name, ok: false, error: clean(e.message, 200) || 'Source unavailable', value: null };
  }
}

async function thresholds() {
  const [rows] = await pool.query(
    'SELECT threshold_key, warn_value, crit_value, unit, description, updated_by, updated_at FROM srv_threshold');
  const t = {};
  rows.forEach(function (r) {
    t[r.threshold_key] = {
      warn: r.warn_value == null ? null : Number(r.warn_value),
      crit: r.crit_value == null ? null : Number(r.crit_value),
      unit: r.unit, description: r.description,
      updatedBy: r.updated_by, updatedAt: r.updated_at,
    };
  });
  return t;
}
function th(t, key, fb) { return t[key] || fb; }

// ── local host telemetry (the one server CorpIT collects deeply) ─────────────
// Reuses the live /api/system/health handler rather than re-implementing the
// collectors, by calling it in-process through a fake res.
function callLocal(req, subPath) {
  return new Promise(function (resolve, reject) {
    const app = req.app;
    if (!app) return reject(new Error('no app handle'));
    const stack = (app._router && app._router.stack) || [];
    let handler = null;
    stack.forEach(function (layer) {
      if (handler || !layer.handle || !layer.handle.stack) return;
      if (!layer.regexp || !layer.regexp.test('/api/system')) return;
      layer.handle.stack.forEach(function (rl) {
        if (handler || !rl.route || rl.route.path !== subPath) return;
        if (!rl.route.methods || !rl.route.methods.get) return;
        handler = rl.route.stack[rl.route.stack.length - 1].handle;
      });
    });
    if (!handler) return reject(new Error('handler ' + subPath + ' not mounted'));

    const timer = setTimeout(function () { reject(new Error('local collector timed out')); }, 20000);
    const fakeRes = {
      statusCode: 200,
      status: function (c) { this.statusCode = c; return this; },
      json: function (body) { clearTimeout(timer); resolve({ status: this.statusCode, body: body }); },
      set: function () { return this; }, setHeader: function () {},
    };
    try {
      handler(Object.assign(Object.create(req), { query: {}, params: {} }), fakeRes,
        function (e) { clearTimeout(timer); reject(e || new Error('next() called')); });
    } catch (e) { clearTimeout(timer); reject(e); }
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// SERVERS
// ═══════════════════════════════════════════════════════════════════════════
async function serverRows(req) {
  const t = await thresholds();
  const [rows] = await pool.query(
    'SELECT s.*, ' +
    ' (SELECT COUNT(*) FROM srv_vhost v WHERE v.server_id = s.id AND v.status <> "retired") AS vhost_count ' +
    'FROM srv_server s WHERE s.status <> "retired" ORDER BY s.is_local DESC, s.hostname');

  // Local telemetry, fetched once and attached to the is_local row.
  let local = null, localErr = null;
  if (rows.some(function (r) { return r.is_local; })) {
    try { local = (await callLocal(req, '/health')).body; }
    catch (e) { localErr = clean(e.message, 160); }
  }
  let backups = null;
  try { backups = (await callLocal(req, '/backups')).body; } catch (e) { /* Unknown */ }

  const [vh] = await pool.query(
    'SELECT v.server_id, v.id, v.fqdn, v.friendly_name, COALESCE(c.state, "unknown") AS state, ' +
    'c.tls_days_left, c.cert_state FROM srv_vhost v ' +
    'LEFT JOIN srv_vhost_current c ON c.vhost_id = v.id WHERE v.status <> "retired"');

  const [maint] = await pool.query(
    'SELECT * FROM srv_maintenance WHERE status IN ("scheduled","in_progress") ' +
    'AND item_type = "server" ORDER BY starts_at');

  const [findings] = await pool.query(
    'SELECT item_ref, severity, COUNT(*) n FROM srv_finding ' +
    'WHERE status <> "resolved" AND item_type IN ("server","host") GROUP BY item_ref, severity');

  return rows.map(function (s) {
    const out = {
      id: s.id, hostname: s.hostname, friendlyName: s.friendly_name,
      kind: s.kind, environment: s.environment, location: s.location, role: s.server_role,
      osName: s.os_name, osVersion: s.os_version, ownerEmail: s.owner_email,
      monitorMode: s.monitor_mode, isLocal: !!s.is_local,
      monitoringEnabled: !!s.monitoring_enabled, registryStatus: s.status, notes: s.notes,
      vhostCount: s.vhost_count,
      vhosts: vh.filter(function (v) { return v.server_id === s.id; }).map(function (v) {
        return { id: v.id, fqdn: v.fqdn, friendlyName: v.friendly_name, state: v.state, certState: v.cert_state, tlsDaysLeft: v.tls_days_left };
      }),
      maintenance: maint.filter(function (m) { return String(m.item_ref) === String(s.id); }),
      // Everything below is Unknown until a collector fills it in. CorpIT does
      // not agent remote hosts, and inventing numbers would be worse than a
      // blank.
      health: 'unknown', lastCheckIn: null, uptimeSec: null, lastReboot: null,
      cpu: null, memory: null, disk: null, io: null,
      diskWarning: null, patches: null, pendingReboot: null,
      backup: null, endpointSecurity: null, services: null,
      certWarnings: [], dataAvailability: {},
    };

    if (s.is_local && local) {
      out.health = worst(worst(fromLegacy(local.cpu && local.cpu.state), fromLegacy(local.memory && local.memory.state)),
        fromLegacy(local.disk && local.disk.state));
      out.lastCheckIn = local.timestamp;
      out.uptimeSec = local.uptimeSec;
      out.lastReboot = local.uptimeSec ? new Date(Date.now() - local.uptimeSec * 1000).toISOString() : null;
      out.cpu = local.cpu; out.memory = local.memory; out.disk = local.disk; out.io = local.io;
      out.patches = local.patches;
      out.pendingReboot = local.patches ? !!local.patches.rebootRequired : null;
      if (local.patches && (local.patches.rebootRequired || local.patches.security > 0)) out.health = worst(out.health, 'warning');
      const dt = th(t, 'disk_used_pct', { warn: 75, crit: 90 });
      if (local.disk && local.disk.usedPct >= dt.crit) out.diskWarning = { level: 'critical', message: 'Root filesystem at ' + local.disk.usedPct + '%' };
      else if (local.disk && local.disk.usedPct >= dt.warn) out.diskWarning = { level: 'warning', message: 'Root filesystem at ' + local.disk.usedPct + '%' };
      if (backups && backups.nightly) {
        const bt = th(t, 'backup_age_hours', { warn: 30, crit: 50 });
        const age = backups.nightly.latestAgeHours;
        out.backup = {
          latestAgeHours: age, count: backups.nightly.count,
          latest: backups.nightly.latest ? backups.nightly.latest.name : null,
          state: age == null ? 'unknown' : (age >= bt.crit ? 'critical' : age >= bt.warn ? 'warning' : 'healthy'),
        };
      }
      // Patch counts come from the background apt collection in system-health-routes.js,
      // so they are labelled 'cached' with their age (decision G6, 2026-09-25).
      out.dataAvailability = {
        metrics: 'live', patches: 'cached',
        backup: backups ? 'live' : 'unavailable',
        endpointSecurity: 'not-collected', services: 'live',
        patchesAgeSec: local.patches && typeof local.patches.ageSec === 'number' ? local.patches.ageSec : null,
      };
    } else if (s.is_local && localErr) {
      out.health = 'unknown';
      out.dataAvailability = { metrics: 'unavailable', error: localErr };
    } else {
      // Registered but not locally collected: reachability is inferred from
      // this server's own registered vhosts, and nothing else is claimed.
      const states = out.vhosts.map(function (v) { return v.state; });
      if (s.monitor_mode === 'probe' && states.length) {
        out.health = states.reduce(function (acc, x) { return worst(acc, x); }, 'healthy');
        out.dataAvailability = { metrics: 'not-collected', reachability: 'via-registered-vhosts' };
      } else {
        out.dataAvailability = { metrics: 'not-collected', reachability: s.monitor_mode === 'none' ? 'not-collected' : 'no-vhosts-registered' };
      }
    }

    if (s.status === 'maintenance' || out.maintenance.some(function (m) { return m.status === 'in_progress'; })) out.health = 'maintenance';
    if (!s.monitoring_enabled) out.health = 'unknown';

    out.vhosts.forEach(function (v) {
      if (v.tlsDaysLeft != null && v.tlsDaysLeft <= th(t, 'cert_days_left', { warn: 30 }).warn) {
        out.certWarnings.push({ fqdn: v.fqdn, daysLeft: v.tlsDaysLeft, state: v.certState });
      }
    });

    const mine = findings.filter(function (f) { return String(f.item_ref) === String(s.id) || f.item_ref === s.hostname; });
    out.openFindings = { critical: 0, warning: 0, info: 0 };
    mine.forEach(function (f) { out.openFindings[f.severity] = f.n; });
    return out;
  });
}

router.get('/servers', needRead, async function (req, res) {
  try { res.json({ timestamp: new Date().toISOString(), servers: await serverRows(req) }); }
  catch (e) { res.status(500).json({ error: clean(e.message, 200) }); }
});

router.get('/servers/:id(\\d+)', needRead, async function (req, res) {
  try {
    const all = await serverRows(req);
    const one = all.find(function (s) { return s.id === Number(req.params.id); });
    if (!one) return res.status(404).json({ error: 'Not found' });
    let trend = [];
    if (one.isLocal) {
      const [hist] = await pool.query(
        'SELECT snapshot_date, cpu_load_pct, mem_used_pct, disk_used_pct FROM server_health_snapshots ' +
        'ORDER BY snapshot_date DESC LIMIT 30');
      trend = hist.reverse();
    }
    res.json({ server: one, trend: trend });
  } catch (e) { res.status(500).json({ error: clean(e.message, 200) }); }
});

const SERVER_FIELDS = ['hostname', 'friendly_name', 'kind', 'environment', 'location', 'server_role',
  'os_name', 'os_version', 'owner_email', 'monitor_mode', 'monitoring_enabled', 'status', 'notes'];
const ENUMS = {
  kind: ['physical', 'virtual', 'container', 'unknown'],
  monitor_mode: ['local', 'probe', 'none'],
  status: ['active', 'maintenance', 'retired'],
  exposure: ['internal', 'external', 'unknown'],
};
function pick(body, fields) {
  const out = {};
  fields.forEach(function (f) {
    if (!Object.prototype.hasOwnProperty.call(body, f)) return;
    let v = body[f];
    if (ENUMS[f] && ENUMS[f].indexOf(v) === -1) throw new Error('Invalid value for ' + f);
    if (typeof v === 'string') v = clean(v, (f === 'notes' || f === 'purpose') ? 2000 : 255);
    if (f === 'monitoring_enabled' || f === 'expect_https') v = v ? 1 : 0;
    out[f] = v;
  });
  return out;
}
const FQDN_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i;

// A registry entry becomes a request this server makes. These ranges are not
// CorpIT inventory and exist only to be reached from inside a host, so they are
// refused at registration rather than relied on never being entered.
const BLOCKED_TARGETS = [
  { re: /^169\.254\./, why: 'link-local addresses, including cloud instance metadata' },
  { re: /^fe80:/i, why: 'IPv6 link-local addresses' },
  { re: /^metadata\.google\.internal$/i, why: 'the cloud metadata service' },
  { re: /^instance-data(\.|$)/i, why: 'the cloud metadata service' },
];
function assertRegistrable(host) {
  const h = String(host || '').toLowerCase();
  for (const b of BLOCKED_TARGETS) {
    if (b.re.test(h)) {
      throw new Error('That target cannot be registered: ' + b.why +
        ' are outside the CorpIT inventory and this dashboard will not probe them.');
    }
  }
}

router.post('/servers', needAdmin, async function (req, res) {
  try {
    const d = pick(req.body || {}, SERVER_FIELDS);
    if (!d.hostname || !FQDN_RE.test(d.hostname)) return res.status(400).json({ error: 'A valid hostname is required.' });
    assertRegistrable(d.hostname);
    d.created_by = actor(req);
    const cols = Object.keys(d);
    const [r] = await pool.query('INSERT INTO srv_server (' + cols.join(',') + ') VALUES (' +
      cols.map(function () { return '?'; }).join(',') + ')', cols.map(function (c) { return d[c]; }));
    res.json({ ok: true, id: r.insertId });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'That hostname is already registered.' });
    res.status(400).json({ error: clean(e.message, 200) });
  }
});

router.put('/servers/:id(\\d+)', needAdmin, async function (req, res) {
  try {
    const d = pick(req.body || {}, SERVER_FIELDS);
    if (d.hostname && !FQDN_RE.test(d.hostname)) return res.status(400).json({ error: 'Invalid hostname.' });
    const cols = Object.keys(d);
    if (!cols.length) return res.status(400).json({ error: 'Nothing to update.' });
    const [r] = await pool.query('UPDATE srv_server SET ' + cols.map(function (c) { return c + '=?'; }).join(',') +
      ' WHERE id=?', cols.map(function (c) { return d[c]; }).concat([req.params.id]));
    res.json({ ok: true, changed: r.affectedRows });
  } catch (e) { res.status(400).json({ error: clean(e.message, 200) }); }
});

router.delete('/servers/:id(\\d+)', needAdmin, async function (req, res) {
  try {
    // Retire rather than delete: history and findings stay attributable.
    const [r] = await pool.query('UPDATE srv_server SET status="retired" WHERE id=? AND is_local=0', [req.params.id]);
    if (!r.affectedRows) return res.status(400).json({ error: 'Not found, or this is the local host and cannot be retired.' });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: clean(e.message, 200) }); }
});

// ═══════════════════════════════════════════════════════════════════════════
// VIRTUAL HOSTS / SUBDOMAINS
// ═══════════════════════════════════════════════════════════════════════════
async function vhostRows(includeRetired) {
  const t = await thresholds();
  const staleT = th(t, 'vhost_check_stale_min', { warn: 45, crit: 180 });
  const [rows] = await pool.query(
    'SELECT v.*, s.hostname AS server_hostname, s.friendly_name AS server_friendly, ' +
    'a.app_name, a.app_url, c.state AS h_state, c.dns_state, c.resolved_ip, c.last_status, ' +
    'c.response_ms, c.redirect_to, c.redirect_loop, c.tls_issuer, c.tls_not_after, ' +
    'c.tls_days_left, c.tls_name_match, c.cert_state, c.https_available, c.http_available, ' +
    'c.error_message, c.checked_at, c.ok_since, c.failing_since ' +
    'FROM srv_vhost v ' +
    'LEFT JOIN srv_server s ON s.id = v.server_id ' +
    // app_registry.app_key is utf8mb4_0900_ai_ci but srv_vhost's table default is
    // utf8mb4_unicode_ci; an ALTER that recreates srv_vhost.app_key at the table
    // default makes this join throw 'Illegal mix of collations'. Force the join
    // collation so it survives that drift. (Fixed 2026-08-21.)
    'LEFT JOIN app_registry a ON a.app_key = v.app_key COLLATE utf8mb4_0900_ai_ci ' +
    'LEFT JOIN srv_vhost_current c ON c.vhost_id = v.id ' +
    'WHERE ' + (includeRetired ? '1=1' : 'v.status <> "retired"') + ' ORDER BY v.fqdn');

  // 24h availability from the retained probe history.
  const [avail] = await pool.query(
    'SELECT vhost_id, COUNT(*) total, SUM(state="healthy") ok, AVG(response_ms) avg_ms, ' +
    'MAX(response_ms) max_ms FROM srv_vhost_check ' +
    'WHERE checked_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) GROUP BY vhost_id');
  const availBy = {};
  avail.forEach(function (a) {
    availBy[a.vhost_id] = {
      checks: a.total,
      uptimePct: a.total ? Math.round((a.ok / a.total) * 1000) / 10 : null,
      avgMs: a.avg_ms == null ? null : Math.round(a.avg_ms),
      maxMs: a.max_ms,
    };
  });

  const now = Date.now();
  return rows.map(function (v) {
    const ageMin = v.checked_at ? Math.round((now - new Date(v.checked_at).getTime()) / 60000) : null;
    let state = v.h_state || 'unknown';
    const flags = [];
    if (!v.monitoring_enabled) { state = 'unknown'; flags.push('monitoring-disabled'); }
    else if (ageMin == null) { state = 'unknown'; flags.push('never-checked'); }
    else if (ageMin > staleT.crit) { state = 'unknown'; flags.push('check-stale'); }
    else if (ageMin > staleT.warn) { flags.push('check-aging'); }
    if (v.status === 'maintenance') state = 'maintenance';
    if (v.app_key && !v.app_name) flags.push('app-link-missing');

    return {
      id: v.id, fqdn: v.fqdn, friendlyName: v.friendly_name, purpose: v.purpose,
      exposure: v.exposure, environment: v.environment, location: v.location,
      serverId: v.server_id, serverHostname: v.server_hostname, serverFriendly: v.server_friendly,
      appKey: v.app_key, appName: v.app_name, appUrl: v.app_url,
      binding: v.binding, port: v.port, expectHttps: !!v.expect_https,
      expectedIp: v.expected_ip, expectedStatus: v.expected_status, probePath: v.probe_path,
      monitoringEnabled: !!v.monitoring_enabled, ownerEmail: v.owner_email,
      dependsOn: v.depends_on, registryStatus: v.status, notes: v.notes,
      state: state, dnsState: v.dns_state || 'unknown', resolvedIp: v.resolved_ip,
      lastStatus: v.last_status, responseMs: v.response_ms,
      redirectTo: v.redirect_to, redirectLoop: !!v.redirect_loop,
      tlsIssuer: v.tls_issuer, tlsNotAfter: v.tls_not_after, tlsDaysLeft: v.tls_days_left,
      tlsNameMatch: v.tls_name_match == null ? null : !!v.tls_name_match,
      certState: v.cert_state || 'unknown',
      httpsAvailable: v.https_available == null ? null : !!v.https_available,
      httpAvailable: v.http_available == null ? null : !!v.http_available,
      errorMessage: v.error_message, lastCheckedAt: v.checked_at, checkAgeMin: ageMin,
      okSince: v.ok_since, failingSince: v.failing_since,
      availability24h: availBy[v.id] || null,
      flags: flags,
    };
  });
}

router.get('/vhosts', needRead, async function (req, res) {
  try {
    const includeRetired = req.query.include === 'retired';
    res.json({ timestamp: new Date().toISOString(), includeRetired: includeRetired,
      vhosts: await vhostRows(includeRetired) });
  }
  catch (e) { res.status(500).json({ error: clean(e.message, 200) }); }
});

router.get('/vhosts/:id(\\d+)', needRead, async function (req, res) {
  try {
    const all = await vhostRows(true);
    const one = all.find(function (v) { return v.id === Number(req.params.id); });
    if (!one) return res.status(404).json({ error: 'Not found' });
    const [hist] = await pool.query(
      'SELECT checked_at, state, last_status, response_ms, cert_state, tls_days_left, error_message ' +
      'FROM srv_vhost_check WHERE vhost_id=? ORDER BY checked_at DESC LIMIT 200', [req.params.id]);
    res.json({ vhost: one, history: hist.reverse() });
  } catch (e) { res.status(500).json({ error: clean(e.message, 200) }); }
});

const VHOST_FIELDS = ['fqdn', 'friendly_name', 'purpose', 'exposure', 'environment', 'location',
  'server_id', 'app_key', 'binding', 'port', 'expect_https', 'expected_ip', 'expected_status',
  'probe_path', 'monitoring_enabled', 'owner_email', 'depends_on', 'status', 'notes'];

function validateVhost(d) {
  if (d.fqdn != null) {
    d.fqdn = String(d.fqdn).toLowerCase().trim();
    if (!FQDN_RE.test(d.fqdn)) throw new Error('Enter a valid fully qualified domain name.');
    assertRegistrable(d.fqdn);
  }
  if (d.port != null) {
    d.port = parseInt(d.port, 10);
    if (!(d.port > 0 && d.port < 65536)) throw new Error('Port must be between 1 and 65535.');
  }
  if (d.expected_status != null) {
    d.expected_status = parseInt(d.expected_status, 10);
    if (!(d.expected_status >= 100 && d.expected_status <= 599)) throw new Error('Expected status must be a valid HTTP status code.');
  }
  if (d.probe_path != null) {
    d.probe_path = String(d.probe_path).trim() || '/';
    if (d.probe_path.charAt(0) !== '/' || /[\s"'<>\\]/.test(d.probe_path)) throw new Error('The probe path must start with "/" and contain no spaces.');
    d.probe_path = d.probe_path.slice(0, 255);
  }
  if (d.server_id === '' || d.server_id === null) d.server_id = null;
  else if (d.server_id != null) d.server_id = parseInt(d.server_id, 10) || null;
  if (d.expected_ip) {
    d.expected_ip = String(d.expected_ip).trim();
    if (!/^[0-9a-f.:]{2,45}$/i.test(d.expected_ip)) throw new Error('Expected address must be an IP address.');
    assertRegistrable(d.expected_ip);
  }
  return d;
}

router.post('/vhosts', needAdmin, async function (req, res) {
  try {
    const d = validateVhost(pick(req.body || {}, VHOST_FIELDS));
    if (!d.fqdn) return res.status(400).json({ error: 'A fully qualified domain name is required.' });
    d.created_by = actor(req);
    const cols = Object.keys(d);
    const [r] = await pool.query('INSERT INTO srv_vhost (' + cols.join(',') + ') VALUES (' +
      cols.map(function () { return '?'; }).join(',') + ')', cols.map(function (c) { return d[c]; }));
    res.json({ ok: true, id: r.insertId });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'That host name, port and path are already registered.' });
    if (e.code === 'ER_NO_REFERENCED_ROW_2') return res.status(400).json({ error: 'That hosting server does not exist.' });
    res.status(400).json({ error: clean(e.message, 200) });
  }
});

router.put('/vhosts/:id(\\d+)', needAdmin, async function (req, res) {
  try {
    const d = validateVhost(pick(req.body || {}, VHOST_FIELDS));
    const cols = Object.keys(d);
    if (!cols.length) return res.status(400).json({ error: 'Nothing to update.' });
    const [r] = await pool.query('UPDATE srv_vhost SET ' + cols.map(function (c) { return c + '=?'; }).join(',') +
      ' WHERE id=?', cols.map(function (c) { return d[c]; }).concat([req.params.id]));
    res.json({ ok: true, changed: r.affectedRows });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'That host name, port and path are already registered.' });
    res.status(400).json({ error: clean(e.message, 200) });
  }
});

router.delete('/vhosts/:id(\\d+)', needAdmin, async function (req, res) {
  try {
    const [r] = await pool.query('UPDATE srv_vhost SET status="retired", monitoring_enabled=0 WHERE id=?', [req.params.id]);
    if (!r.affectedRows) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: clean(e.message, 200) }); }
});

// Persist one probe result. Shared by the on-demand recheck below and kept
// identical in shape to what vhost-health-job.js writes.
async function writeCheck(vhostId, r) {
  const [ins] = await pool.query(
    'INSERT INTO srv_vhost_check (vhost_id, state, dns_state, resolved_ip, http_status, https_status, ' +
    'last_status, response_ms, redirect_to, redirect_hops, redirect_loop, tls_issuer, tls_subject, ' +
    'tls_not_after, tls_days_left, tls_name_match, tls_self_signed, cert_state, https_available, ' +
    'http_available, error_code, error_message) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
    [vhostId, r.state, r.dns_state, r.resolved_ip, r.http_status, r.https_status, r.last_status,
      r.response_ms, r.redirect_to, r.redirect_hops, r.redirect_loop, r.tls_issuer, r.tls_subject,
      r.tls_not_after, r.tls_days_left, r.tls_name_match, r.tls_self_signed, r.cert_state,
      r.https_available, r.http_available, r.error_code, r.error_message]);

  const healthy = r.state === 'healthy';
  await pool.query(
    'INSERT INTO srv_vhost_current (vhost_id, last_check_id, state, dns_state, resolved_ip, last_status, ' +
    'response_ms, redirect_to, redirect_loop, tls_issuer, tls_not_after, tls_days_left, tls_name_match, ' +
    'cert_state, https_available, http_available, error_message, checked_at, ok_since, failing_since) ' +
    'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP,' +
    (healthy ? 'CURRENT_TIMESTAMP' : 'NULL') + ',' + (healthy ? 'NULL' : 'CURRENT_TIMESTAMP') + ') ' +
    'ON DUPLICATE KEY UPDATE last_check_id=VALUES(last_check_id), state=VALUES(state), ' +
    'dns_state=VALUES(dns_state), resolved_ip=VALUES(resolved_ip), last_status=VALUES(last_status), ' +
    'response_ms=VALUES(response_ms), redirect_to=VALUES(redirect_to), redirect_loop=VALUES(redirect_loop), ' +
    'tls_issuer=VALUES(tls_issuer), tls_not_after=VALUES(tls_not_after), tls_days_left=VALUES(tls_days_left), ' +
    'tls_name_match=VALUES(tls_name_match), cert_state=VALUES(cert_state), ' +
    'https_available=VALUES(https_available), http_available=VALUES(http_available), ' +
    'error_message=VALUES(error_message), checked_at=CURRENT_TIMESTAMP, ' +
    'ok_since=' + (healthy ? 'COALESCE(ok_since, CURRENT_TIMESTAMP)' : 'NULL') + ', ' +
    'failing_since=' + (healthy ? 'NULL' : 'COALESCE(failing_since, CURRENT_TIMESTAMP)'),
    [vhostId, ins.insertId, r.state, r.dns_state, r.resolved_ip, r.last_status, r.response_ms,
      r.redirect_to, r.redirect_loop, r.tls_issuer, r.tls_not_after, r.tls_days_left,
      r.tls_name_match, r.cert_state, r.https_available, r.http_available, r.error_message]);
  return ins.insertId;
}

// On-demand recheck. The target is looked up BY ID from the registry — the
// caller never supplies a host name — so this cannot be turned into a scanner.
router.post('/vhosts/:id(\\d+)/check', needAdmin, async function (req, res) {
  try {
    const [rows] = await pool.query(
      'SELECT v.*, s.hostname AS server_hostname FROM srv_vhost v LEFT JOIN srv_server s ON s.id=v.server_id ' +
      'WHERE v.id=? AND v.status <> "retired"', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    const vh = rows[0];
    const [allFqdn] = await pool.query('SELECT fqdn FROM srv_vhost');
    const allowed = new Set(allFqdn.map(function (r) { return String(r.fqdn).toLowerCase(); }));
    const t = await thresholds();
    const r = await probe.probeVhost(vh, allowed, {
      vhost_response_ms: th(t, 'vhost_response_ms', { warn: 1500, crit: 5000 }),
      cert_days_left: th(t, 'cert_days_left', { warn: 30, crit: 7 }),
    });
    await writeCheck(vh.id, r);
    try {
      await pool.query('INSERT INTO server_action_audit (action, actor, detail, result) VALUES (?,?,?,?)',
        ['vhost.check', actor(req), vh.fqdn, r.state]);
    } catch (e) { /* audit is best-effort; never fail the check on it */ }
    res.json({ ok: true, result: r });
  } catch (e) { res.status(500).json({ error: clean(e.message, 200) }); }
});

// ── nginx binding audit (local box only) ───────────────────────────────────
// Reads the local nginx configuration CorpIT already owns and compares it with
// the registry. This is a config read, not a scan: no name found here is ever
// probed unless an admin registers it.
const NGINX_DIR = '/etc/nginx/sites-enabled';
// NGINX-TLS-NS-20260929: sites the root helper manages are enabled in their own
// namespace (included by nginx.conf right after sites-enabled/*). Missing on a node
// that holds no namespace (HA passive); that is not an error.
const NGINX_MANAGED_DIR = '/etc/nginx/corpit-ha/enabled';
function nginxServerNames() {
  const found = [];
  let entries = [];
  try { entries = fs.readdirSync(NGINX_DIR).map(function (f) { return [NGINX_DIR, f]; }); }
  catch (e) { return { error: 'nginx configuration is not readable by the API process', sites: [] }; }
  try { entries = entries.concat(fs.readdirSync(NGINX_MANAGED_DIR).map(function (f) { return [NGINX_MANAGED_DIR, f]; })); }
  catch (e) { /* no managed namespace on this node */ }
  entries.forEach(function (ent) {
    const f = ent[1];
    if (/\.(bak|sed-bak|save|orig)|~$/.test(f)) return;
    let txt = '';
    try { txt = fs.readFileSync(path.join(ent[0], f), 'utf8'); } catch (e) { return; }
    const names = [];
    (txt.match(/^[\t ]*server_name[\t ]+([^;]+);/gm) || []).forEach(function (m) {
      m.replace(/^[\t ]*server_name[\t ]+/, '').replace(/;$/, '').trim().split(/\s+/).forEach(function (n) {
        if (n && n !== '_' && names.indexOf(n) === -1) names.push(n.toLowerCase());
      });
    });
    const hasTls = /ssl_certificate[\t ]+/.test(txt);
    names.forEach(function (n) { found.push({ name: n, file: f, hasTls: hasTls }); });
  });
  return { sites: found };
}

router.get('/vhost-config-audit', needRead, async function (req, res) {
  try {
    const ng = nginxServerNames();
    const [rows] = await pool.query('SELECT id, fqdn, status, monitoring_enabled, binding, server_id FROM srv_vhost');
    const registered = new Map(rows.map(function (r) { return [String(r.fqdn).toLowerCase(), r]; }));

    const issues = [];
    const seen = {};
    ng.sites.forEach(function (s) {
      seen[s.name] = (seen[s.name] || 0) + 1;
      if (!registered.has(s.name)) {
        issues.push({
          kind: 'unregistered-binding', severity: 'warning', fqdn: s.name, file: s.file,
          message: 'nginx on this host serves ' + s.name + ', but it is not registered in CorpIT.',
          action: 'Register it so it is monitored, or remove the server block if it is obsolete.',
        });
      }
    });
    Object.keys(seen).forEach(function (n) {
      if (seen[n] > 1) issues.push({
        kind: 'duplicate-binding', severity: 'warning', fqdn: n,
        message: n + ' is declared in ' + seen[n] + ' server blocks on this host.',
        action: 'Consolidate the duplicate server_name declarations; nginx serves the first match.',
      });
    });
    rows.forEach(function (r) {
      if (r.status === 'retired') return;
      const local = ng.sites.some(function (s) { return s.name === String(r.fqdn).toLowerCase(); });
      if (!local && r.server_id) {
        issues.push({
          kind: 'binding-not-found', severity: 'info', fqdn: r.fqdn, vhostId: r.id,
          message: r.fqdn + ' is registered against a server, but no matching server_name was found in this host\'s nginx configuration.',
          action: 'Expected when the vhost is hosted elsewhere. Otherwise check the binding recorded on the CorpIT record.',
        });
      }
      if (!r.monitoring_enabled && r.status === 'active') issues.push({
        kind: 'monitoring-off', severity: 'warning', fqdn: r.fqdn, vhostId: r.id,
        message: r.fqdn + ' is an active CorpIT record with monitoring switched off.',
        action: 'Turn monitoring on, or retire the record if the host name is gone.',
      });
    });

    res.json({
      timestamp: new Date().toISOString(),
      configReadable: !ng.error, configError: ng.error || null,
      nginxNames: ng.sites, issues: issues,
    });
  } catch (e) { res.status(500).json({ error: clean(e.message, 200) }); }
});

// ═══════════════════════════════════════════════════════════════════════════
// JOBS
// ═══════════════════════════════════════════════════════════════════════════
router.get('/jobs', needRead, async function (req, res) {
  try {
    const t = await thresholds();
    const stuck = th(t, 'job_stuck_min', { warn: 120, crit: 360 });
    let cron = null, cronErr = null;
    try { cron = (await callLocal(req, '/cron')).body; } catch (e) { cronErr = clean(e.message, 160); }

    let history = [];
    try {
      const [h] = await pool.query(
        'SELECT job_name, COUNT(*) runs, SUM(state="failed") failures, ' +
        'MAX(observed_at) last_seen, AVG(duration_sec) avg_sec FROM srv_job_run ' +
        // Only this host's rows. srv_job_run was seeded from ITAM and 956 of its
        // rows describe jobs that ran there; they fall outside this 7-day window
        // today, but a re-seed would put another machine's run history behind
        // this host's job names with nothing to distinguish them.
        'WHERE observed_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) AND host = ? ' +
        'GROUP BY job_name', [require('os').hostname()]);
      history = h;
    } catch (e) { /* history is optional enrichment */ }
    const histBy = {};
    history.forEach(function (h) {
      histBy[h.job_name] = { runs7d: h.runs, failures7d: h.failures, avgSec: h.avg_sec == null ? null : Math.round(h.avg_sec) };
    });

    const jobs = (cron && cron.jobs ? cron.jobs : []).map(function (j) {
      let state = fromLegacy(j.state);
      const flags = [];
      if (j.running) {
        const mins = (j.elapsedSec || 0) / 60;
        if (mins >= stuck.crit) { state = 'critical'; flags.push('stuck'); }
        else if (mins >= stuck.warn) { state = 'warning'; flags.push('long-running'); }
        else { state = 'healthy'; flags.push('running'); }
      }
      if (j.lastExit != null && j.lastExit !== 0) { state = 'critical'; flags.push('last-run-failed'); }
      if (j.state === 'warn') flags.push('delayed');
      if (j.state === 'down' && !j.running) flags.push('overdue');
      if (j.state === 'unknown') flags.push(j.note ? 'no-log' : 'unknown');
      return {
        name: j.name, purpose: j.command ? clean(j.command, 300) : null,
        schedule: j.schedule, scheduleText: j.scheduleText,
        state: state, flags: flags,
        running: !!j.running, elapsedSec: j.elapsedSec || null,
        lastRun: j.mtime || j.lastStart || null, nextRun: j.nextRun,
        lastExit: j.lastExit, lastResult: j.lastExit == null ? null : (j.lastExit === 0 ? 'success' : 'failed'),
        lastLine: j.lastLine ? clean(j.lastLine, 300) : null,
        durationSec: j.durationSec, durationSource: j.durationSource,
        server: 'corpit', owner: j.user || null,
        source: j.source, log: j.log, note: clean(j.note || j.error, 200),
        history: histBy[j.name] || null,
      };
    });

    const counts = { running: 0, healthy: 0, delayed: 0, failed: 0, stuck: 0, unknown: 0, total: jobs.length };
    jobs.forEach(function (j) {
      if (j.flags.indexOf('stuck') !== -1) counts.stuck++;
      else if (j.running) counts.running++;
      if (j.state === 'critical') counts.failed++;
      else if (j.state === 'warning') counts.delayed++;
      else if (j.state === 'unknown') counts.unknown++;
      else counts.healthy++;
    });

    res.json({
      timestamp: new Date().toISOString(),
      available: !cronErr, error: cronErr,
      serverTz: cron && cron.serverTz, counts: counts, jobs: jobs,
      historyWindowDays: 7, historyRows: history.length,
    });
  } catch (e) { res.status(500).json({ error: clean(e.message, 200) }); }
});

// ═══════════════════════════════════════════════════════════════════════════
// APIs — internal (this app's mounted modules) + external (vendor probes)
// ═══════════════════════════════════════════════════════════════════════════
const EXTERNAL_APIS = [
  {
    key: 'okta', name: 'Okta', path: '/okta', category: 'Identity',
    purpose: 'Directory, SSO and MFA source for identity pages.',
    endpointCategory: 'Okta org API — read-only org and user reads',
    checkMethod: 'CorpIT makes an authenticated call against our own Okta org and reports what it answered. It is not the vendor status page: this catches an expired token or a revoked grant that the public page would never show.',
    credentialSource: 'Okta API token held in the API service environment. Never rendered on this page.',
    dependents: ['identity-diag', 'user-360', 'okta-mfa'],
    itamItem: 'CorpIT vendor integration — Okta',
  },
  {
    key: 'entra', name: 'Microsoft Entra ID', path: '/entra', category: 'Identity',
    purpose: 'Graph directory, sign-in and audit data.',
    endpointCategory: 'Microsoft Graph — directory read (client credentials)',
    checkMethod: 'CorpIT requests a Graph token for our tenant and performs a directory read. Microsoft Service Health is not used because the ServiceHealth.Read.All app role is not granted, so this is a live reachability check rather than a vendor advisory feed.',
    credentialSource: 'Azure app registration (client credentials) in the API service environment. Never rendered on this page.',
    dependents: ['identity-diag', 'signin-watch', 'tenant-sentinel'],
    itamItem: 'CorpIT vendor integration — Microsoft Graph',
  },
  {
    key: 'intune', name: 'Microsoft Intune', path: '/intune', category: 'Endpoint',
    purpose: 'Managed-device inventory and compliance.',
    endpointCategory: 'Microsoft Graph — deviceManagement read (overview + managedDevices)',
    checkMethod: 'CorpIT reads the Intune device-management overview and then counts devices whose compliance state is non-compliant. The probe reports Needs review when the API answers correctly but the estate it describes has a condition worth acting on.',
    credentialSource: 'The same Azure app registration used for Entra. Never rendered on this page.',
    dependents: ['inventory', 'identity-diag'],
    itamItem: 'CorpIT vendor integration — Microsoft Intune',
  },
  {
    key: 'zia', name: 'Zscaler Internet Access', path: '/zia', category: 'Network',
    purpose: 'Web policy and user data for Zscaler pages.',
    endpointCategory: 'Zscaler ZIdentity OneAPI — authenticated tenant read',
    checkMethod: 'CorpIT authenticates against our ZIA tenant through ZIdentity OneAPI and times the response.',
    credentialSource: 'ZIdentity OAuth client in the API service environment. Never rendered on this page.',
    dependents: ['zscaler-command-center'],
    itamItem: 'CorpIT vendor integration — Zscaler',
  },
  {
    key: 'iru', name: 'Kandji', path: '/iru', category: 'Endpoint',
    purpose: 'Apple device management records.',
    endpointCategory: 'Kandji API — devices list, single-page read',
    checkMethod: 'CorpIT requests one page of the Kandji device list with our API token and times the response. A 401 or 403 here means the token expired, was revoked, or lost its scope.',
    credentialSource: 'Kandji API token in the API service environment. Never rendered on this page.',
    dependents: ['inventory'],
    itamItem: 'CorpIT vendor integration — Kandji',
  },
];

// Fields a vendor probe may attach that are safe to surface: counts and status
// codes only. Anything not on this list is dropped rather than forwarded, so a
// probe cannot leak a token or a connection string into the page by accident.
var SAFE_METRIC_KEYS = ['enrolled', 'nonCompliant', 'nonCompliantCapped', 'httpStatus',
  'responseMs', 'devices', 'users', 'count', 'total'];
var METRIC_LABEL = {
  enrolled: 'Devices enrolled', nonCompliant: 'Devices non-compliant',
  nonCompliantCapped: 'Non-compliant count was capped by the page size',
  httpStatus: 'HTTP status returned', responseMs: 'Vendor round-trip',
  devices: 'Devices reported', users: 'Users reported', count: 'Records reported',
  total: 'Records reported',
};
function safeMetrics(body) {
  var out = [];
  if (!body) return out;
  SAFE_METRIC_KEYS.forEach(function (k) {
    if (body[k] == null) return;
    out.push({ key: k, label: METRIC_LABEL[k] || k, value: body[k] });
  });
  return out;
}

// Why the dashboard is showing this state, in the operator's language. The
// vendor probe supplies the evidence; this turns it into a reason.
function explainVendor(meta, body, state) {
  var d = clean(body && body.detail, 400);
  if (state === 'healthy') {
    return { reason: 'The authenticated call against our tenant succeeded.', action: 'No action needed.' };
  }
  if (state === 'unknown') {
    return {
      reason: 'CorpIT could not complete its check, so the health of this integration is unknown — not healthy.',
      action: 'Confirm the probe is configured on this server, then re-check.',
    };
  }
  var text = String(d || '');
  if (meta.key === 'intune' && body && body.nonCompliant) {
    return {
      reason: 'The Intune API answered normally, so the integration itself is working. The warning is about what it reported: ' +
        body.nonCompliant + (body.nonCompliantCapped ? ' or more' : '') + ' of ' + (body.enrolled || 'the') +
        ' enrolled devices are non-compliant.' +
        (body.nonCompliantCapped ? ' The count was capped by the API page size, so the real figure is higher.' : ''),
      action: 'Open Inventory or Identity Diagnostics to see which devices are non-compliant and why. ' +
        'This state clears on its own once the device count returns to zero — no change to CorpIT is required.',
    };
  }
  if (/rate limit|429/i.test(text)) {
    return {
      reason: 'The vendor is throttling our calls (HTTP 429).',
      action: 'Reduce the polling frequency of the jobs that use this integration, or wait for the vendor window to reset.',
    };
  }
  if (/auth|401|403|token/i.test(text)) {
    return {
      reason: 'The vendor rejected our credentials. The integration is down for every CorpIT page that depends on it.',
      action: 'Reissue the API credential for this integration and update the API service environment. Do not paste credentials into this dashboard.',
    };
  }
  if (/zero|no devices/i.test(text)) {
    return {
      reason: 'The API answered but returned an empty estate, which normally means a scope or tenant problem rather than a real empty tenant.',
      action: 'Check that the app registration still has its device-management scope against the correct tenant.',
    };
  }
  return {
    reason: 'The vendor probe reported a condition that is not a clean success. The probe\'s own words are shown above.',
    action: 'Re-check to confirm it is not transient, then follow the vendor detail.',
  };
}

function vendorState(s) {
  return s === 'ok' ? 'healthy' : s === 'warn' ? 'warning' : s === 'bad' ? 'critical' : 'unknown';
}

// One vendor timing out must not delay the others or the page.
function callTenantHealth(req, p, timeoutMs) {
  return new Promise(function (resolve) {
    const t = setTimeout(function () { resolve({ ok: false, error: 'Probe timed out' }); }, timeoutMs);
    const stack = (req.app && req.app._router && req.app._router.stack) || [];
    let handler = null;
    stack.forEach(function (layer) {
      if (handler || !layer.handle || !layer.handle.stack) return;
      if (!layer.regexp || !layer.regexp.test('/api/tenant-health')) return;
      layer.handle.stack.forEach(function (rl) {
        if (handler || !rl.route) return;
        const paths = Array.isArray(rl.route.path) ? rl.route.path : [rl.route.path];
        if (paths.indexOf(p) === -1 || !rl.route.methods.get) return;
        handler = rl.route.stack[rl.route.stack.length - 1].handle;
      });
    });
    if (!handler) { clearTimeout(t); return resolve({ ok: false, error: 'Vendor probe is not mounted on this server' }); }
    const fakeRes = {
      statusCode: 200,
      status: function (c) { this.statusCode = c; return this; },
      json: function (body) { clearTimeout(t); resolve({ ok: true, status: this.statusCode, body: body }); },
      set: function () { return this; }, setHeader: function () {},
    };
    try {
      Promise.resolve(handler(Object.assign(Object.create(req), { query: {}, params: {} }), fakeRes,
        function () { clearTimeout(t); resolve({ ok: false, error: 'Probe did not respond' }); }))
        .catch(function (e) { clearTimeout(t); resolve({ ok: false, error: clean(e.message, 120) }); });
    } catch (e) { clearTimeout(t); resolve({ ok: false, error: clean(e.message, 120) }); }
  });
}

// The overview waits at most OVERVIEW_VENDOR_WAIT_MS per vendor. A slower probe keeps running and
// its answer is remembered, so the next overview shows it; until then that vendor reads as its last
// known state (if recent) or unknown. A slow vendor (Graph timing out on Intune) no longer holds up
// the whole page.
const OVERVIEW_VENDOR_WAIT_MS = 2500;
const LAST_VENDOR_MAX_AGE_MS = 15 * 60 * 1000;
const _lastVendor = {};
function overviewVendorState(req, a) {
  const full = callTenantHealth(req, a.path, 9000).then(function (r) {
    const s = r.ok ? vendorState((r.body || {}).state) : 'unknown';
    _lastVendor[a.key] = { state: s, at: Date.now() };
    return s;
  });
  const wait = new Promise(function (resolve) { setTimeout(resolve, OVERVIEW_VENDOR_WAIT_MS, null); });
  return Promise.race([full, wait]).then(function (s) {
    if (s != null) return s;
    const last = _lastVendor[a.key];
    return last && Date.now() - last.at < LAST_VENDOR_MAX_AGE_MS ? last.state : 'unknown';
  });
}

router.get('/apis', needRead, async function (req, res) {
  try {
    const metrics = apiMetrics ? apiMetrics.snapshot() : { windowMin: null, prefixes: {} };
    const [vhrows] = await pool.query(
      'SELECT fqdn, id FROM srv_vhost WHERE status <> "retired" ORDER BY id LIMIT 1');
    const originFqdn = vhrows.length ? vhrows[0].fqdn : null;
    const originId = vhrows.length ? vhrows[0].id : null;

    // Internal: the modules this Express app actually mounted. A module that
    // failed to mount simply is not in the stack — which is the signal.
    const stack = (req.app && req.app._router && req.app._router.stack) || [];
    const modules = {};
    stack.forEach(function (layer) {
      if (!layer.handle || !layer.handle.stack || !layer.regexp) return;
      const m = layer.regexp.source.match(/^\^\\\/api\\\/([a-z0-9_-]+)/i);
      if (!m) return;
      const prefix = '/api/' + m[1];
      if (!modules[prefix]) modules[prefix] = { prefix: prefix, routes: 0, methods: {} };
      layer.handle.stack.forEach(function (rl) {
        if (!rl.route) return;
        Object.keys(rl.route.methods).forEach(function (mm) {
          if (!rl.route.methods[mm]) return;
          modules[prefix].routes++;
          const M = mm.toUpperCase();
          modules[prefix].methods[M] = (modules[prefix].methods[M] || 0) + 1;
        });
      });
    });

    const t = await thresholds();
    const errT = th(t, 'api_error_rate_pct', { warn: 10, crit: 35 });
    const internal = Object.keys(modules).sort().map(function (p) {
      const mm = metrics.prefixes[p] || null;
      let state = 'healthy';
      const notes = [];
      if (mm && mm.requests > 0) {
        if (mm.errorRatePct >= errT.crit) { state = 'critical'; notes.push('Server errors on ' + mm.errorRatePct + '% of requests.'); }
        else if (mm.errorRatePct >= errT.warn) { state = 'warning'; notes.push('Server errors on ' + mm.errorRatePct + '% of requests.'); }
      } else {
        notes.push('No traffic in the last ' + (metrics.windowMin || 60) + ' minutes.');
      }
      return {
        scope: 'internal', key: p, name: p,
        purpose: modules[p].routes + ' routes mounted on this server.',
        category: 'CorpIT internal API', state: state,
        itamItem: 'corpit (corpit-hub-api)', domain: originFqdn, vhostId: originId,
        routes: modules[p].routes, methods: modules[p].methods,
        requests: mm ? mm.requests : null, errors: mm ? mm.errors : null,
        errorRatePct: mm ? mm.errorRatePct : null, lastRequestAt: mm ? mm.lastRequestAt : null,
        windowMin: metrics.windowMin, note: notes.join(' '), mounted: true,
      };
    });

    // External: the vendor probes CorpIT already runs, in parallel, each isolated.
    // "Answered" and "clean" are different questions. An integration that
    // responds every time but reports a concern is available, not down —
    // conflating the two made a working integration read as 0% available.
    const [histRows] = await pool.query(
      'SELECT api_key, COUNT(*) checks, ' +
      'SUM(state IN ("healthy","warning")) answered, SUM(state="healthy") clean, ' +
      'SUM(state IN ("critical","unknown")) failed, ' +
      'AVG(NULLIF(response_ms,0)) avg_ms, MIN(checked_at) since FROM srv_api_check ' +
      'WHERE checked_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) GROUP BY api_key');
    const histBy = {};
    histRows.forEach(function (h) {
      histBy[h.api_key] = {
        checks: h.checks,
        answered: h.answered, clean: h.clean, failed: h.failed,
        answeredPct: h.checks ? Math.round((h.answered / h.checks) * 1000) / 10 : null,
        cleanPct: h.checks ? Math.round((h.clean / h.checks) * 1000) / 10 : null,
        errorRatePct: h.checks ? Math.round((h.failed / h.checks) * 1000) / 10 : null,
        avgMs: h.avg_ms == null ? null : Math.round(h.avg_ms),
        since: h.since, windowDays: 7,
      };
    });

    const external = await Promise.all(EXTERNAL_APIS.map(async function (a) {
      const started = Date.now();
      const r = await callTenantHealth(req, a.path, 9000);
      const ms = Date.now() - started;
      const hist = histBy[a.key] || null;
      const base = {
        scope: 'external', key: a.key, name: a.name, purpose: a.purpose, category: a.category,
        itamItem: a.itamItem, endpointCategory: a.endpointCategory, checkMethod: a.checkMethod,
        credentialSource: a.credentialSource, dependents: a.dependents,
        domain: null, vhostId: null,
        certificate: { collected: false, note: 'Vendor-managed endpoint. CorpIT does not hold a certificate monitor for this host, so certificate expiry is not collected here.' },
        history: hist,
        availabilityPct: hist ? hist.answeredPct : null,
        errorRatePct: hist ? hist.errorRatePct : null,
      };
      if (!r.ok) {
        return Object.assign(base, {
          state: 'unknown', responseMs: ms, lastCheckAt: new Date().toISOString(),
          httpResult: null, note: r.error, cached: false,
          why: explainVendor(a, null, 'unknown'), metrics: [],
        });
      }
      const b = r.body || {};
      const state = vendorState(b.state);
      const fromCache = !!b.cached;
      return Object.assign(base, {
        state: state, responseMs: fromCache ? null : ms, measuredMs: ms,
        lastCheckAt: b.checkedAt || new Date().toISOString(),
        httpResult: clean(b.text, 200), note: clean(b.detail, 400), cached: !!b.cached,
        metrics: safeMetrics(b), why: explainVendor(a, b, state),
      });
    }));

    // Record the observation so availability and error rate come from real
    // history. Throttled to one row per integration per five minutes so an
    // open dashboard with auto-refresh does not flood the table.
    try {
      for (const a of external) {
        await pool.query(
          'INSERT INTO srv_api_check (api_key, scope, state, http_result, response_ms, detail) ' +
          'SELECT ?,?,?,?,?,? FROM DUAL WHERE NOT EXISTS (' +
          '  SELECT 1 FROM srv_api_check WHERE api_key=? AND checked_at > DATE_SUB(NOW(), INTERVAL 5 MINUTE))',
          [a.key, 'external', a.state, a.httpResult, a.responseMs, a.note, a.key]);  // null when cached
      }
      await pool.query('DELETE FROM srv_api_check WHERE checked_at < DATE_SUB(NOW(), INTERVAL 30 DAY)');
    } catch (e) { /* history is enrichment; never fail the page on it */ }

    // A degraded integration belongs in the triage list too, with the same
    // fingerprint discipline as every other finding.
    try {
      for (const a of external) {
        const fpk = 'api|vendor|' + a.key;
        if (a.state === 'critical' || a.state === 'warning') {
          await pool.query(
            'INSERT INTO srv_finding (fingerprint, severity, confidence, item_type, item_ref, item_label, ' +
            'title, detail, probable_cause, impact, recommendation, evidence, status) ' +
            'VALUES (?,?,?,?,?,?,?,?,?,?,?,?, "open") ' +
            'ON DUPLICATE KEY UPDATE severity=VALUES(severity), detail=VALUES(detail), ' +
            'probable_cause=VALUES(probable_cause), impact=VALUES(impact), ' +
            'recommendation=VALUES(recommendation), evidence=VALUES(evidence), ' +
            'last_seen_at=CURRENT_TIMESTAMP, resolved_at=NULL, status=IF(status="resolved","open",status)',
            [fpk, a.state === 'critical' ? 'critical' : 'warning', 'confirmed', 'api', a.key, a.name,
              a.name + ' — ' + (a.httpResult || 'not healthy'), a.note,
              a.why && a.why.reason, 'Depends on this integration: ' + (a.dependents || []).join(', ') + '.',
              a.why && a.why.action, JSON.stringify({ state: a.state, result: a.httpResult, metrics: a.metrics })]);
        } else if (a.state === 'healthy') {
          // Only a MEASURED healthy result clears the alarm. 'unknown' means the
          // probe could not run (vendor unreachable, credential expired, timed
          // out) -- resolving on that let a dead probe close its own finding,
          // which is the exact opposite of what an unrunnable check means.
          await pool.query(
            'UPDATE srv_finding SET status="resolved", resolved_at=CURRENT_TIMESTAMP ' +
            'WHERE fingerprint=? AND status<>"resolved"', [fpk]);
        }
      }
    } catch (e) { /* finding sync must not break the API view */ }

    res.json({ timestamp: new Date().toISOString(), metricsWindowMin: metrics.windowMin, internal: internal, external: external });
  } catch (e) { res.status(500).json({ error: clean(e.message, 200) }); }
});

// ── Identity behind each integration ────────────────────────────────────────
// Which credential CorpIT presents, and what that credential is actually allowed
// to do. For the Microsoft integrations the granted application permissions are
// read from the `roles` claim of a token CorpIT mints for itself — that is the
// authoritative list the resource server will honour, and it needs no extra
// directory permission to obtain. The token itself is never returned, logged,
// or rendered; only the app's display name, its non-secret identifiers, and the
// permission names.
const INTEGRATION_IDENTITY = {
  intune: {
    credentialType: 'azure-app-registration',
    resource: 'https://graph.microsoft.com',
    envVars: ['AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET'],
    required: [
      { permission: 'DeviceManagementManagedDevices.Read.All', purpose: 'Read the Intune device-management overview and the non-compliant device list.' },
    ],
    wanted: [
      { permission: 'DeviceManagementConfiguration.Read.All', purpose: 'Read compliance and configuration policy names alongside the device counts.' },
    ],
  },
  entra: {
    credentialType: 'azure-app-registration',
    resource: 'https://graph.microsoft.com',
    envVars: ['AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET'],
    required: [
      { permission: 'User.Read.All', purpose: 'Directory read used as the live reachability check.' },
      { permission: 'AuditLog.Read.All', purpose: 'Sign-in and audit data for the identity pages that depend on this integration.' },
    ],
    wanted: [
      { permission: 'ServiceHealth.Read.All', purpose: "Read Microsoft's own service-health advisories. Without it this probe can only report whether Graph answers us, not whether Microsoft has declared an incident." },
    ],
  },
  okta: {
    credentialType: 'api-token',
    resource: 'Okta org API',
    envVars: ['OKTA_BASE_URL', 'OKTA_API_TOKEN'],
    note: 'Okta SSWS tokens carry the permissions of the admin who created them and the API does not expose that scope, so CorpIT cannot enumerate them. Check the token in the Okta admin console under Security → API → Tokens.',
  },
  zia: {
    credentialType: 'oauth-client',
    resource: 'Zscaler ZIdentity OneAPI',
    envVars: ['ZSCALER_VANITY_DOMAIN', 'ZSCALER_CLIENT_ID', 'ZSCALER_CLIENT_SECRET'],
    note: 'Scopes are assigned to the OneAPI client in the ZIdentity admin console and are not readable from the API, so CorpIT cannot enumerate them here.',
  },
  iru: {
    credentialType: 'api-token',
    resource: 'Kandji API',
    envVars: ['KANDJI_BASE_URL', 'KANDJI_TOKEN'],
    note: 'Kandji API tokens carry a fixed permission set chosen at creation time; the API does not report it, so CorpIT cannot enumerate it here.',
  },
};

var _azClaims = { at: 0, value: null, error: null };
async function azureAppIdentity() {
  // The claim set changes only when an admin re-consents, so a long cache is
  // correct and keeps this page off the token endpoint.
  if (_azClaims.value && (Date.now() - _azClaims.at) < 30 * 60 * 1000) return _azClaims.value;
  if (_azClaims.error && (Date.now() - _azClaims.at) < 60 * 1000) throw new Error(_azClaims.error);

  const tenant = process.env.AZURE_TENANT_ID, client = process.env.AZURE_CLIENT_ID,
    secret = process.env.AZURE_CLIENT_SECRET;
  if (!tenant || !client || !secret) throw new Error('The Azure app registration is not configured on this server.');

  const body = new URLSearchParams({
    client_id: client, client_secret: secret,
    scope: 'https://graph.microsoft.com/.default', grant_type: 'client_credentials',
  });
  const ctl = new AbortController();
  const timer = setTimeout(function () { ctl.abort(); }, 9000);
  let token;
  try {
    const r = await fetch('https://login.microsoftonline.com/' + tenant + '/oauth2/v2.0/token',
      { method: 'POST', body: body, signal: ctl.signal });
    const j = await r.json();
    if (!j.access_token) throw new Error('The token endpoint returned no token for this app registration.');
    token = j.access_token;
  } catch (e) {
    _azClaims = { at: Date.now(), value: null, error: clean(e.message, 160) };
    throw new Error(_azClaims.error);
  } finally { clearTimeout(timer); }

  // Decode only — this token was minted by us for us, and it is discarded here.
  let claims = {};
  try {
    const seg = token.split('.')[1];
    claims = JSON.parse(Buffer.from(seg.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
  } catch (e) { throw new Error('The token could not be decoded on this server.'); }
  token = null;

  const value = {
    displayName: clean(claims.app_displayname, 200),
    appId: clean(claims.appid, 64),
    tenantId: clean(claims.tid, 64),
    audience: clean(claims.aud, 120),
    issuedAt: claims.iat ? new Date(claims.iat * 1000).toISOString() : null,
    expiresAt: claims.exp ? new Date(claims.exp * 1000).toISOString() : null,
    roles: Array.isArray(claims.roles) ? claims.roles.slice().sort() : [],
  };
  _azClaims = { at: Date.now(), value: value, error: null };
  return value;
}

router.get('/apis/:key/identity', needRead, async function (req, res) {
  const key = String(req.params.key || '').slice(0, 32);
  const meta = EXTERNAL_APIS.filter(function (a) { return a.key === key; })[0];
  const ident = INTEGRATION_IDENTITY[key];
  if (!meta || !ident) return res.status(404).json({ error: 'That integration is not registered in CorpIT.' });

  const out = {
    key: key, name: meta.name,
    credentialType: ident.credentialType,
    resource: ident.resource,
    // Names only. The values live in the API service environment and are never
    // read into a response.
    configuredBy: ident.envVars.map(function (v) {
      return { name: v, set: !!process.env[v], secret: /SECRET|TOKEN|PASSWORD|KEY/.test(v) };
    }),
    note: ident.note || null,
    app: null, permissions: null, required: [], wanted: [], available: false,
    unavailableReason: null,
  };

  if (ident.credentialType !== 'azure-app-registration') {
    out.unavailableReason = ident.note;
    return res.json(out);
  }

  try {
    const az = await azureAppIdentity();
    out.available = true;
    out.app = {
      displayName: az.displayName, applicationId: az.appId, tenantId: az.tenantId,
      audience: az.audience, tokenExpiresAt: az.expiresAt,
      portalUrl: az.appId
        ? 'https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Overview/appId/' + encodeURIComponent(az.appId)
        : null,
    };
    const granted = az.roles;
    // Graph permissions nest: DeviceManagementConfiguration.ReadWrite.All
    // already carries .Read.All, so a required Read is satisfied by a granted
    // ReadWrite of the same resource. Reporting it as missing would send an
    // admin to grant a permission they already have.
    function satisfies(want) {
      if (granted.indexOf(want) !== -1) return true;
      const m = want.match(/^(.*)\.Read(\.All)?$/);
      if (!m) return false;
      const rw = m[1] + '.ReadWrite' + (m[2] || '');
      return granted.indexOf(rw) !== -1;
    }
    out.permissions = granted.map(function (r) {
      return {
        permission: r, type: 'Application',
        writeCapable: /\.(ReadWrite|Write|Send|Manage)/.test(r),
        usedByThisIntegration: (ident.required || []).concat(ident.wanted || [])
          .some(function (x) { return x.permission === r; }),
      };
    });
    out.required = (ident.required || []).map(function (x) {
      return { permission: x.permission, purpose: x.purpose, granted: satisfies(x.permission) };
    });
    out.wanted = (ident.wanted || []).map(function (x) {
      return { permission: x.permission, purpose: x.purpose, granted: satisfies(x.permission) };
    });
    out.summary = {
      total: granted.length,
      writeCapable: out.permissions.filter(function (p) { return p.writeCapable; }).length,
      requiredMissing: out.required.filter(function (r) { return !r.granted; }).length,
      wantedMissing: out.wanted.filter(function (r) { return !r.granted; }).length,
    };
  } catch (e) {
    out.unavailableReason = clean(e.message, 200);
  }
  res.json(out);
});

// ═══════════════════════════════════════════════════════════════════════════
// FINDINGS
// ═══════════════════════════════════════════════════════════════════════════
router.get('/findings', needRead, async function (req, res) {
  try {
    const includeResolved = req.query.include === 'resolved';
    const [rows] = await pool.query(
      'SELECT * FROM srv_finding ' + (includeResolved ? '' : 'WHERE status <> "resolved" ') +
      'ORDER BY FIELD(severity,"critical","warning","info"), last_seen_at DESC LIMIT 500');
    // Same reason as gpo-audit /findings: the 500 above is a transport cap, and
    // a page that renders rows.length as the total would under-report the
    // moment a real incident pushes the table past it.
    const [[cnt]] = await pool.query(
      'SELECT COUNT(*) AS total FROM srv_finding ' +
      (includeResolved ? '' : 'WHERE status <> "resolved"'));
    res.json({
      timestamp: new Date().toISOString(),
      total: cnt.total,
      truncated: rows.length < cnt.total,
      findings: rows.map(function (f) {
        let ev = null;
        try { ev = typeof f.evidence === 'string' ? JSON.parse(f.evidence) : f.evidence; } catch (e) { ev = null; }
        return {
          id: f.id, severity: f.severity, confidence: f.confidence,
          itemType: f.item_type, itemRef: f.item_ref, itemLabel: f.item_label,
          title: f.title, detail: f.detail, probableCause: f.probable_cause,
          impact: f.impact, recommendation: f.recommendation, evidence: ev,
          firstSeenAt: f.first_seen_at, lastSeenAt: f.last_seen_at, resolvedAt: f.resolved_at,
          status: f.status, ackBy: f.ack_by, ackAt: f.ack_at, ackNote: f.ack_note, ownerEmail: f.owner_email,
        };
      }),
    });
  } catch (e) { res.status(500).json({ error: clean(e.message, 200) }); }
});

router.post('/findings/:id(\\d+)/ack', needAdmin, async function (req, res) {
  try {
    const note = clean((req.body || {}).note, 500);
    const owner = clean((req.body || {}).owner, 255);
    const [r] = await pool.query(
      'UPDATE srv_finding SET status="acknowledged", ack_by=?, ack_at=CURRENT_TIMESTAMP, ack_note=?, ' +
      'owner_email=COALESCE(?, owner_email) WHERE id=? AND status<>"resolved"',
      [actor(req), note, owner || null, req.params.id]);
    if (!r.affectedRows) return res.status(404).json({ error: 'Not found, or already resolved.' });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: clean(e.message, 200) }); }
});

router.post('/findings/:id(\\d+)/unack', needAdmin, async function (req, res) {
  try {
    const [r] = await pool.query(
      'UPDATE srv_finding SET status="open", ack_by=NULL, ack_at=NULL, ack_note=NULL ' +
      'WHERE id=? AND status="acknowledged"', [req.params.id]);
    if (!r.affectedRows) return res.status(404).json({ error: 'Not found, or not acknowledged.' });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: clean(e.message, 200) }); }
});

// ═══════════════════════════════════════════════════════════════════════════
// THRESHOLDS
// ═══════════════════════════════════════════════════════════════════════════
router.get('/thresholds', needRead, async function (req, res) {
  try { res.json({ thresholds: await thresholds() }); }
  catch (e) { res.status(500).json({ error: clean(e.message, 200) }); }
});

router.put('/thresholds', needAdmin, async function (req, res) {
  // settingsfold W6: audited whenever the UPDATEs committed.
  // W6 follow-up e (2026-10-12): every key is validated first, then all keys are
  // written in ONE transaction. Any invalid key is a 400 with nothing written; a DB
  // error rolls the whole save back. The partial flag below is kept but can no longer
  // be true (saWritten is only set after the commit, when the status is 200).
  let saBefore, saWritten = [];
  try {
    const updates = (req.body && req.body.thresholds) || {};
    const keys = Object.keys(updates);
    if (!keys.length) return res.status(400).json({ error: 'Nothing to update.' });
    const [known] = await pool.query('SELECT threshold_key FROM srv_threshold');
    const allowed = new Set(known.map(function (k) { return k.threshold_key; }));
    saBefore = await SA.byKey(pool, 'SELECT threshold_key, warn_value, crit_value FROM srv_threshold', [], 'threshold_key');
    const vals = [];
    for (const k of keys) {
      if (!allowed.has(k)) return res.status(400).json({ error: 'Unknown threshold: ' + clean(k, 64) });
      const w = Number(updates[k].warn), c = Number(updates[k].crit);
      if (!isFinite(w) || !isFinite(c)) return res.status(400).json({ error: 'Both values must be numbers for ' + k + '.' });
      if (w < 0 || c < 0 || w > 1e9 || c > 1e9) return res.status(400).json({ error: 'Values for ' + k + ' are out of range.' });
      vals.push([k, w, c]);
    }
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      for (const v of vals) {
        await conn.query('UPDATE srv_threshold SET warn_value=?, crit_value=?, updated_by=? WHERE threshold_key=?',
          [v[1], v[2], actor(req), v[0]]);
      }
      await conn.commit();
    } catch (e) {
      try { await conn.rollback(); } catch (_) { /* the connection is released below either way */ }
      throw e;
    } finally { conn.release(); }
    saWritten = vals.map(function (v) { return v[0]; });
    res.json({ ok: true, updated: keys.length });
  } catch (e) { res.status(400).json({ error: clean(e.message, 200) }); }
  finally {
    if (saWritten.length) {
      const saAfter = await SA.byKey(pool, 'SELECT threshold_key, warn_value, crit_value FROM srv_threshold', [], 'threshold_key');
      const flat = function (m) {
        if (m === undefined) return undefined;
        const o = {};
        saWritten.forEach(function (k) { const r = m[k] || {}; o[k + '.warn'] = r.warn_value; o[k + '.crit'] = r.crit_value; });
        return o;
      };
      const keysFlat = [];
      saWritten.forEach(function (k) { keysFlat.push(k + '.warn', k + '.crit'); });
      await SA.record(rbac, req, PAGE, 'settings_saved', SA.entry({ what: 'thresholds', op: 'update',
        before: flat(saBefore), after: flat(saAfter), keys: keysFlat,
        extra: { rows: saWritten.length, partial: res.statusCode >= 400 ? true : undefined } }));
    }
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// MAINTENANCE
// ═══════════════════════════════════════════════════════════════════════════
router.get('/maintenance', needRead, async function (req, res) {
  try {
    const [rows] = await pool.query(
      'SELECT m.*, ' +
      ' CASE WHEN m.item_type="server" THEN (SELECT hostname FROM srv_server WHERE id=m.item_ref) ' +
      '      WHEN m.item_type="vhost"  THEN (SELECT fqdn FROM srv_vhost WHERE id=m.item_ref) ' +
      '      ELSE m.item_ref END AS resolved_label ' +
      'FROM srv_maintenance m WHERE m.status <> "cancelled" ORDER BY COALESCE(m.starts_at, m.due_at)');
    const now = Date.now();
    res.json({
      timestamp: new Date().toISOString(),
      items: rows.map(function (m) {
        const due = m.due_at ? new Date(m.due_at).getTime() : null;
        const start = m.starts_at ? new Date(m.starts_at).getTime() : null;
        const end = m.ends_at ? new Date(m.ends_at).getTime() : null;
        return {
          id: m.id, kind: m.kind, itemType: m.item_type, itemRef: m.item_ref, itemLabel: m.resolved_label,
          title: m.title, detail: m.detail, startsAt: m.starts_at, endsAt: m.ends_at, dueAt: m.due_at,
          status: m.status, ownerEmail: m.owner_email,
          overdue: !!(due && due < now && m.status !== 'done'),
          active: !!(start && start <= now && (!end || end >= now) && m.status !== 'done'),
          upcoming: !!(start && start > now),
        };
      }),
    });
  } catch (e) { res.status(500).json({ error: clean(e.message, 200) }); }
});

const MAINT_FIELDS = ['kind', 'item_type', 'item_ref', 'title', 'detail', 'starts_at', 'ends_at', 'due_at', 'status', 'owner_email'];
const MAINT_ENUMS = {
  kind: ['window', 'task'],
  item_type: ['server', 'vhost', 'job', 'api', 'service', 'global'],
  status: ['scheduled', 'in_progress', 'done', 'cancelled'],
};
function pickMaint(body) {
  const out = {};
  MAINT_FIELDS.forEach(function (f) {
    if (!Object.prototype.hasOwnProperty.call(body, f)) return;
    const v = body[f];
    if (MAINT_ENUMS[f] && MAINT_ENUMS[f].indexOf(v) === -1) throw new Error('Invalid value for ' + f);
    if (/_at$/.test(f)) {
      if (!v) { out[f] = null; return; }
      const d = new Date(v);
      if (isNaN(d.getTime())) throw new Error('Invalid date for ' + f);
      out[f] = d;
      return;
    }
    out[f] = typeof v === 'string' ? clean(v, f === 'detail' ? 2000 : 255) : v;
  });
  return out;
}

router.post('/maintenance', needAdmin, async function (req, res) {
  try {
    const d = pickMaint(req.body || {});
    if (!d.title) return res.status(400).json({ error: 'A title is required.' });
    d.created_by = actor(req);
    const cols = Object.keys(d);
    const [r] = await pool.query('INSERT INTO srv_maintenance (' + cols.join(',') + ') VALUES (' +
      cols.map(function () { return '?'; }).join(',') + ')', cols.map(function (c) { return d[c]; }));
    res.json({ ok: true, id: r.insertId });
  } catch (e) { res.status(400).json({ error: clean(e.message, 200) }); }
});

router.put('/maintenance/:id(\\d+)', needAdmin, async function (req, res) {
  try {
    const d = pickMaint(req.body || {});
    const cols = Object.keys(d);
    if (!cols.length) return res.status(400).json({ error: 'Nothing to update.' });
    const [r] = await pool.query('UPDATE srv_maintenance SET ' + cols.map(function (c) { return c + '=?'; }).join(',') +
      ' WHERE id=?', cols.map(function (c) { return d[c]; }).concat([req.params.id]));
    res.json({ ok: true, changed: r.affectedRows });
  } catch (e) { res.status(400).json({ error: clean(e.message, 200) }); }
});

router.delete('/maintenance/:id(\\d+)', needAdmin, async function (req, res) {
  try {
    await pool.query('UPDATE srv_maintenance SET status="cancelled" WHERE id=?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: clean(e.message, 200) }); }
});

// ═══════════════════════════════════════════════════════════════════════════
// OVERVIEW — one call, every source isolated
// ═══════════════════════════════════════════════════════════════════════════
router.get('/overview', needRead, async function (req, res) {
  try {
    const t = await thresholds();
    const parts = await Promise.all([
      isolate('servers', function () { return serverRows(req); }),
      isolate('vhosts', function () { return vhostRows(); }),
      isolate('jobs', async function () {
        let cron = null;
        try { cron = (await callLocal(req, '/cron')).body; }
        catch (e) { throw new Error('scheduled-job data is unavailable'); }
        const stuck = th(t, 'job_stuck_min', { warn: 120, crit: 360 });
        const c = { total: 0, running: 0, failed: 0, delayed: 0, stuck: 0, unknown: 0, healthy: 0 };
        (cron.jobs || []).forEach(function (j) {
          c.total++;
          const mins = j.running ? (j.elapsedSec || 0) / 60 : 0;
          if (j.running && mins >= stuck.warn) c.stuck++;
          else if (j.running) c.running++;
          if (j.lastExit != null && j.lastExit !== 0) c.failed++;
          else if (j.state === 'down') c.failed++;
          else if (j.state === 'warn') c.delayed++;
          else if (j.state === 'unknown') c.unknown++;
          else c.healthy++;
        });
        return c;
      }),
      isolate('apis', async function () {
        const metrics = apiMetrics ? apiMetrics.snapshot() : { prefixes: {} };
        const errT = th(t, 'api_error_rate_pct', { warn: 10, crit: 35 });
        let degradedInternal = 0, internalTotal = 0;
        Object.keys(metrics.prefixes).forEach(function (p) {
          internalTotal++;
          if (metrics.prefixes[p].requests > 0 && metrics.prefixes[p].errorRatePct >= errT.warn) degradedInternal++;
        });
        const ext = await Promise.all(EXTERNAL_APIS.map(function (a) { return overviewVendorState(req, a); }));
        return {
          internalActive: internalTotal, internalDegraded: degradedInternal,
          externalTotal: ext.length,
          externalDegraded: ext.filter(function (s) { return s === 'warning'; }).length,
          externalDown: ext.filter(function (s) { return s === 'critical'; }).length,
          externalUnknown: ext.filter(function (s) { return s === 'unknown'; }).length,
        };
      }),
      isolate('findings', async function () {
        const [rows] = await pool.query(
          'SELECT severity, status, COUNT(*) n FROM srv_finding WHERE status <> "resolved" GROUP BY severity, status');
        const c = { critical: 0, warning: 0, info: 0, acknowledged: 0, open: 0 };
        rows.forEach(function (r) {
          c[r.severity] += r.n;
          if (r.status === 'acknowledged') c.acknowledged += r.n; else c.open += r.n;
        });
        return c;
      }),
      isolate('maintenance', async function () {
        const [rows] = await pool.query(
          'SELECT status, due_at, starts_at, ends_at FROM srv_maintenance WHERE status IN ("scheduled","in_progress")');
        const now = Date.now();
        return {
          total: rows.length,
          overdue: rows.filter(function (m) { return m.due_at && new Date(m.due_at).getTime() < now; }).length,
          active: rows.filter(function (m) { return m.starts_at && new Date(m.starts_at).getTime() <= now && (!m.ends_at || new Date(m.ends_at).getTime() >= now); }).length,
          upcoming: rows.filter(function (m) { return m.starts_at && new Date(m.starts_at).getTime() > now; }).length,
        };
      }),
      isolate('backups', async function () {
        const b = (await callLocal(req, '/backups')).body;
        const bt = th(t, 'backup_age_hours', { warn: 30, crit: 50 });
        const age = b && b.nightly ? b.nightly.latestAgeHours : null;
        return {
          latestAgeHours: age, count: b && b.nightly ? b.nightly.count : null,
          totalBytes: b ? b.grandTotalBytes : null,
          state: age == null ? 'unknown' : (age >= bt.crit ? 'critical' : age >= bt.warn ? 'warning' : 'healthy'),
          failures: age == null ? null : (age >= bt.crit ? 1 : 0),
        };
      }),
      isolate('certificates', async function () {
        const ct = th(t, 'cert_days_left', { warn: 30, crit: 7 });
        const [rows] = await pool.query(
          'SELECT v.fqdn, c.tls_days_left, c.cert_state, c.tls_not_after FROM srv_vhost v ' +
          'JOIN srv_vhost_current c ON c.vhost_id=v.id WHERE v.status <> "retired"');
        return {
          expiringSoon: rows.filter(function (r) { return r.tls_days_left != null && r.tls_days_left <= ct.warn && r.tls_days_left >= 0; }).length,
          expired: rows.filter(function (r) { return r.tls_days_left != null && r.tls_days_left < 0; }).length,
          mismatched: rows.filter(function (r) { return r.cert_state === 'mismatch'; }).length,
          soonest: rows.filter(function (r) { return r.tls_days_left != null; })
            .sort(function (a, b) { return a.tls_days_left - b.tls_days_left; })[0] || null,
        };
      }),
    ]);
    const servers = parts[0], vhosts = parts[1], jobs = parts[2], apis = parts[3],
      findings = parts[4], maint = parts[5], backups = parts[6], certs = parts[7];

    function tally(list, key) {
      const c = { healthy: 0, warning: 0, critical: 0, offline: 0, maintenance: 0, unknown: 0, total: 0 };
      (list || []).forEach(function (x) { c.total++; c[x[key]] = (c[x[key]] || 0) + 1; });
      return c;
    }
    const serverCounts = servers.ok ? tally(servers.value, 'health') : null;
    const vhostCounts = vhosts.ok ? tally(vhosts.value, 'state') : null;

    // Overall status: the worst confirmed condition anywhere, never averaged.
    // There is deliberately no health percentage — a single number would hide
    // which item is broken and could not be explained on the page.
    // Operators read these as sentences. "1 server(s)" is the sound of a
    // template, not a report.
    function plural(n, one, many) { return n + ' ' + (n === 1 ? one : (many || one + 's')); }
    let overall = 'healthy';
    const reasons = [];
    if (serverCounts) {
      if (serverCounts.critical || serverCounts.offline) { overall = 'critical'; reasons.push(plural(serverCounts.critical + serverCounts.offline, 'server') + ' critical or offline'); }
      else if (serverCounts.warning) { overall = worst(overall, 'warning'); reasons.push(plural(serverCounts.warning, 'server') + ' in warning'); }
    }
    if (vhostCounts) {
      if (vhostCounts.critical || vhostCounts.offline) { overall = 'critical'; reasons.push(plural(vhostCounts.critical + vhostCounts.offline, 'virtual host') + ' unavailable'); }
      else if (vhostCounts.warning) { overall = worst(overall, 'warning'); reasons.push(plural(vhostCounts.warning, 'virtual host') + ' degraded'); }
    }
    if (findings.ok && findings.value.critical) { overall = 'critical'; reasons.push(plural(findings.value.critical, 'critical finding')); }
    if (jobs.ok && (jobs.value.failed || jobs.value.stuck)) { overall = 'critical'; reasons.push(plural(jobs.value.failed + jobs.value.stuck, 'job') + ' failed or stuck'); }
    else if (jobs.ok && jobs.value.delayed) { overall = worst(overall, 'warning'); reasons.push(plural(jobs.value.delayed, 'job') + ' delayed'); }
    if (jobs.ok && jobs.value.unknown && overall === 'healthy') { overall = 'unknown'; reasons.push(plural(jobs.value.unknown, 'job') + ' not confirmed running'); }
    if (apis.ok && apis.value.externalDown) { overall = 'critical'; reasons.push(plural(apis.value.externalDown, 'integration') + ' down'); }
    else if (apis.ok && apis.value.externalDegraded) { overall = worst(overall, 'warning'); reasons.push(plural(apis.value.externalDegraded, 'integration') + ' degraded'); }
    if (apis.ok && apis.value.internalDegraded) { overall = worst(overall, 'warning'); reasons.push(plural(apis.value.internalDegraded, 'internal API') + ' erroring'); }
    // An integration whose probe could not run is not a pass. It cannot raise
    // the verdict above warning on its own, but it must never read as healthy.
    if (apis.ok && apis.value.externalUnknown && overall === 'healthy') { overall = 'unknown'; reasons.push(plural(apis.value.externalUnknown, 'integration') + ' not measured'); }
    if (backups.ok && backups.value.state === 'critical') { overall = 'critical'; reasons.push('nightly backup is overdue'); }
    else if (backups.ok && backups.value.state === 'warning') { overall = worst(overall, 'warning'); reasons.push('nightly backup is ageing'); }
    if (certs.ok && certs.value.expired) { overall = 'critical'; reasons.push(plural(certs.value.expired, 'expired certificate')); }
    else if (certs.ok && certs.value.expiringSoon) { overall = worst(overall, 'warning'); reasons.push(plural(certs.value.expiringSoon, 'certificate') + ' expiring soon'); }
    if (maint.ok && maint.value.overdue) { overall = worst(overall, 'warning'); reasons.push(plural(maint.value.overdue, 'overdue maintenance task')); }
    if (maint.ok && maint.value.active) reasons.push(plural(maint.value.active, 'maintenance window') + ' active');

    const unavailable = parts.filter(function (s) { return !s.ok; })
      .map(function (s) { return { source: s.source, error: s.error }; });
    if (unavailable.length && overall === 'healthy') overall = 'unknown';

    // Patch / reboot readiness comes from the one host CorpIT collects.
    let patches = null;
    if (servers.ok) {
      const local = servers.value.find(function (s) { return s.isLocal; });
      if (local && local.patches) {
        patches = {
          upgradable: local.patches.upgradable, security: local.patches.security,
          actionable: local.patches.actionable, phased: local.patches.phased,
          rebootRequired: !!local.patches.rebootRequired,
          rebootPackages: local.patches.rebootPackages || [],
        };
      }
    }

    res.json({
      timestamp: new Date().toISOString(),
      overall: overall, reasons: reasons,
      counts: {
        servers: serverCounts, vhosts: vhostCounts,
        jobs: jobs.ok ? jobs.value : null,
        apis: apis.ok ? apis.value : null,
        findings: findings.ok ? findings.value : null,
        maintenance: maint.ok ? maint.value : null,
        backups: backups.ok ? backups.value : null,
        certificates: certs.ok ? certs.value : null,
      },
      patches: patches,
      unavailable: unavailable,
      thresholds: t,
    });
  } catch (e) {
    res.status(500).json({ error: clean(e.message, 200) });
  }
});

module.exports = router;
