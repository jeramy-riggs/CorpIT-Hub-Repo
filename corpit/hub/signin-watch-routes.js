'use strict';
// SIGNIN-WATCH-ROUTES v2.6.1 (KPI risk detections) — console API for the Sign-In Watch feature
// Marker: SIGNIN-WATCH-ROUTES
// Mounted at /api/signin-watch (server.js). The ITAM-001 deny-by-default
// blanket has already run loadCurrentUser, so req.user is present for any
// request that reaches this router. All routes below are super-admin only.

const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');
const { validCidr, ipInCidr, fmtDateTimeSql } = require('./signin-watch-lib');
const { dispatch, testChannel } = require('./alert-dispatch');
const { requestRapid7Xref } = require('./rapid7-session-proxy');

// Links that leave this process and reach a person (SDP ticket bodies here,
// alert cards in alert-dispatch.js) must name THIS host. ALLOWED_ORIGIN is the
// canonical origin the platform already configures.
const HUB_ORIGIN = (process.env.ALLOWED_ORIGIN || 'https://corpit.nrpi.local').replace(/\/+$/, '');

// v2.0.0 additions
let sdpLookup;
try { sdpLookup = require('./sdp-lookup'); } catch (e) { console.warn('[signin-watch-routes] sdp-lookup not loadable:', e.message); }

const offload = require('./sqlite-offload');   // read-only SQLite off the event loop (CHG-ARCH-03b)

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 5,
});

// ---- authorization ----------------------------------------------------
// Was a local `saOnly` that checked req.user.isSuperAdmin and returned 403.
// Effective access is UNCHANGED -- still super-admin only, nothing widened.
// What changes is that it now runs through the platform's audited gate.
//
// The local guard skipped the audit trail entirely. rbac-middleware's
// requireSuperAdmin deliberately records the PASS as well as the denial
// (action `superadmin_access`, with `granted_by`), because -- in that file's
// own words -- "who used super-admin, when, and what granted it has to be
// answerable from the log alone". This router carries 35 routes, 17 of which
// write: acknowledge every open violation at once, pause a watchlist entry,
// create an alert channel, push an SDP ticket. Sign-In Watch is the console
// somebody opens to investigate a suspected account compromise, so unaudited
// privileged writes are least acceptable exactly here.
//
// loadCurrentUser is not re-run: the deny-by-default blanket on /api in
// server.js has already populated req.user for anything reaching this router
// (see the header comment above). The module pool is reused rather than opening
// a second one, matching bug-reports-routes.js.
const createRbac = require('./rbac-middleware');
const rbac = createRbac(pool);
router.use(rbac.requireSuperAdmin);

// settingsfold W6 2026-10-12: every settings write below also writes its own
// rbac_audit_log row (page signin-watch, action settings_saved / settings_deleted /
// settings_test_sent|failed) naming WHAT changed, old -> new. requireSuperAdmin's
// superadmin_access row only says a write was attempted. Recorded on success only;
// channel config_json / mention_config (webhook URLs) are recorded as "(changed)".
const SA = require('./settings-audit');
const SW_PAGE = 'signin-watch';
const SW_WL_COLS = 'id, upn, active, watch_okta, watch_entra, note, tier, pause_ticket_display';
const SW_WL_KEYS = ['active', 'watch_okta', 'watch_entra', 'note', 'tier'];
const SW_NET_COLS = 'id, label, cidr, type, note, enabled';
const SW_NET_KEYS = ['label', 'cidr', 'type', 'note', 'enabled'];
const SW_CH_COLS = 'id, name, type, fire_on, tier_filter, auto_investigate, enabled, config_json, mention_config';
const SW_CH_KEYS = ['name', 'type', 'fire_on', 'tier_filter', 'auto_investigate', 'enabled', 'config_json', 'mention_config'];
const SW_CH_SECRET = ['config_json', 'mention_config'];

function bad(res, msg) { return res.status(400).json({ ok: false, error: msg }); }
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ── Status ────────────────────────────────────────────────────────────
router.get('/status', async (req, res) => {
  try {
    const [state] = await pool.query('SELECT key_name, key_value, updated_at FROM signin_watch_state');
    const [[wl]] = await pool.query('SELECT COUNT(*) AS n FROM signin_watchlist WHERE active = 1');
    const [[tn]] = await pool.query('SELECT COUNT(*) AS n FROM trusted_networks WHERE enabled = 1');
    const [[ch]] = await pool.query('SELECT COUNT(*) AS n FROM alert_channels WHERE enabled = 1');
    const [[v24]] = await pool.query('SELECT COUNT(*) AS n FROM signin_violations WHERE created_at > NOW() - INTERVAL 1 DAY');
    const [[vun]] = await pool.query('SELECT COUNT(*) AS n FROM signin_violations WHERE acked = 0');
    const stateMap = {};
    for (const r of state) stateMap[r.key_name] = { value: r.key_value, updated_at: r.updated_at };
    res.json({ ok: true, state: stateMap, counts: { watched: wl.n, networks: tn.n, channels: ch.n, violations_24h: v24.n, unacked: vun.n } });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── Watchlist CRUD ────────────────────────────────────────────────────
router.get('/watchlist', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM signin_watchlist ORDER BY active DESC, upn');
    res.json({ ok: true, rows });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

router.post('/watchlist', async (req, res) => {
  const b = req.body || {};
  const upn = String(b.upn || '').trim().toLowerCase();
  if (!EMAIL_RE.test(upn)) return bad(res, 'invalid upn');
  try {
    const tier = (b.tier === 'vip') ? 'vip' : 'standard';
    const before = await SA.snap(pool, 'SELECT ' + SW_WL_COLS + ' FROM signin_watchlist WHERE upn = ?', [upn]);
    await pool.query(
      `INSERT INTO signin_watchlist (upn, watch_okta, watch_entra, note, added_by, active, tier)
       VALUES (?, ?, ?, ?, ?, 1, ?)
       ON DUPLICATE KEY UPDATE watch_okta = VALUES(watch_okta), watch_entra = VALUES(watch_entra),
         note = VALUES(note), active = 1, tier = VALUES(tier)`,
      [upn, b.watch_okta === false ? 0 : 1, b.watch_entra === false ? 0 : 1,
       (b.note || '').slice(0, 500) || null, req.user.email, tier]);
    const after = await SA.snap(pool, 'SELECT ' + SW_WL_COLS + ' FROM signin_watchlist WHERE upn = ?', [upn]);
    await SA.record(rbac, req, SW_PAGE, 'settings_saved', SA.entry({ what: 'watchlist',
      id: after ? after.id : undefined, subject: upn, before, after, keys: SW_WL_KEYS }));
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

router.patch('/watchlist/:id', async (req, res) => {
  const b = req.body || {};
  const sets = [], vals = [];
  if ('active' in b) { sets.push('active = ?'); vals.push(b.active ? 1 : 0); }
  if ('watch_okta' in b) { sets.push('watch_okta = ?'); vals.push(b.watch_okta ? 1 : 0); }
  if ('watch_entra' in b) { sets.push('watch_entra = ?'); vals.push(b.watch_entra ? 1 : 0); }
  if ('note' in b) { sets.push('note = ?'); vals.push(String(b.note || '').slice(0, 500) || null); }
  if ('tier' in b) { sets.push('tier = ?'); vals.push(b.tier === 'vip' ? 'vip' : 'standard'); }
  if (!sets.length) return bad(res, 'nothing to update');
  vals.push(parseInt(req.params.id, 10));
  try {
    const id = vals[vals.length - 1];
    const before = await SA.snap(pool, 'SELECT ' + SW_WL_COLS + ' FROM signin_watchlist WHERE id = ?', [id]);
    const [r] = await pool.query(`UPDATE signin_watchlist SET ${sets.join(', ')} WHERE id = ?`, vals);
    if (r.affectedRows > 0) {
      const after = await SA.snap(pool, 'SELECT ' + SW_WL_COLS + ' FROM signin_watchlist WHERE id = ?', [id]);
      await SA.record(rbac, req, SW_PAGE, 'settings_saved', SA.entry({ what: 'watchlist', op: 'update', id,
        subject: (after || before || {}).upn, before, after, keys: SW_WL_KEYS.filter(k => k in b) }));
    }
    res.json({ ok: true, changed: r.affectedRows });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

router.delete('/watchlist/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const before = await SA.snap(pool, 'SELECT ' + SW_WL_COLS + ' FROM signin_watchlist WHERE id = ?', [id]);
    const [r] = await pool.query('DELETE FROM signin_watchlist WHERE id = ?', [parseInt(req.params.id, 10)]);
    if (r.affectedRows > 0)
      await SA.record(rbac, req, SW_PAGE, 'settings_deleted', SA.entry({ what: 'watchlist', op: 'delete', id,
        subject: before ? before.upn : undefined, before, after: null, keys: SW_WL_KEYS }));
    res.json({ ok: true, deleted: r.affectedRows });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── v2.3.0: alert pause — link an open SDP ticket, suppress alerts while it stays open ──
const PAUSE_CLOSED_STATUSES = new Set(['resolved', 'closed', 'cancelled', 'canceled']);

// Resolve a ticket reference: internal ID first, display ID as fallback.
async function resolvePauseTicket(ticketRef) {
  if (!sdpLookup) throw new Error('sdp-lookup module unavailable');
  const ref = String(ticketRef).trim().replace(/^#/, '');
  if (!/^\d+$/.test(ref)) throw new Error('ticket id must be numeric');
  try {
    const t = await sdpLookup.getRequestById(ref);
    if (t) return t;
  } catch (e) { /* not an internal id — try display id */ }
  if (sdpLookup.getRequestByDisplayId) {
    const d = await sdpLookup.getRequestByDisplayId(ref);
    if (!d.absent && d.request) {
      const r = d.request;
      return {
        id: r.id,
        display_id: r.display_id || r.id,
        subject: r.subject || null,
        status: (r.status && r.status.name) || 'Unknown',
        url: `https://sdpondemand.manageengine.com/app/${process.env.SDP_PORTAL}/WorkOrder.do?woMode=viewWO&woID=${r.id}`,
      };
    }
  }
  return null;
}

// v2.7.0: shared pause application — used by manual pause AND auto-pause-on-ticket.
// ticketObj must have { id, display_id, url, status }. Idempotent: if the entry is
// already paused, it is left as-is and { skipped:true } is returned.
async function applyPause(pool, watchId, upn, ticketObj, actorEmail, opts) {
  opts = opts || {};
  const [[cur]] = await pool.query('SELECT pause_ticket_id FROM signin_watchlist WHERE id = ?', [watchId]);
  if (cur && cur.pause_ticket_id) return { skipped: true, reason: 'already_paused' };
  const display = String(ticketObj.display_id || ticketObj.id).slice(0, 40);
  await pool.query(
    `UPDATE signin_watchlist SET pause_ticket_id = ?, pause_ticket_display = ?, pause_ticket_url = ?,
       paused_by = ?, paused_at = NOW() WHERE id = ?`,
    [ticketObj.id, display, ticketObj.url, actorEmail || null, watchId]);
  let associated = 0;
  if (opts.associate !== false) {
    const days = Math.min(Math.max(parseInt(opts.associate_days, 10) || 30, 1), 90);
    try {
      const [ar] = await pool.query(
        `UPDATE signin_violations SET sdp_ticket_id = ?, sdp_ticket_url = ?, sdp_ticket_display = ?
         WHERE upn = ? AND sdp_ticket_id IS NULL AND event_time > NOW() - INTERVAL ? DAY`,
        [ticketObj.id, ticketObj.url, display, upn, days]);
      associated = ar.affectedRows;
    } catch (e) { /* non-fatal — pause itself succeeded */ }
  }
  return { skipped: false, associated, display };
}

router.post('/watchlist/:id/pause', async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const ticketRef = (req.body && req.body.ticket_id) || '';
  if (!ticketRef) return bad(res, 'ticket_id required');
  try {
    const [rows] = await pool.query('SELECT id, upn FROM signin_watchlist WHERE id = ?', [id]);
    if (!rows.length) return res.status(404).json({ ok: false, error: 'watchlist entry not found' });
    let t;
    try { t = await resolvePauseTicket(ticketRef); }
    catch (e) { return bad(res, e.message); }
    if (!t) return bad(res, 'ticket not found in SDP');
    if (PAUSE_CLOSED_STATUSES.has(String(t.status).toLowerCase()))
      return bad(res, 'ticket #' + (t.display_id || t.id) + ' is already ' + t.status);
    const pr = await applyPause(pool, id, rows[0].upn, t, req.user.email, {
      associate: req.body.associate_existing !== false,
      associate_days: req.body.associate_days,
    });
    if (!pr.skipped)
      await SA.record(rbac, req, SW_PAGE, 'settings_saved', SA.entry({ what: 'watchlist', op: 'pause', id,
        subject: rows[0].upn, extra: { ticket: pr.display || String(t.display_id || t.id), associated: pr.associated || 0 } }));
    res.json({ ok: true, ticket: t, associated: pr.associated || 0 });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

router.post('/watchlist/:id/resume', async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const before = await SA.snap(pool, 'SELECT ' + SW_WL_COLS + ' FROM signin_watchlist WHERE id = ?', [id]);
    const [r] = await pool.query(
      `UPDATE signin_watchlist SET pause_ticket_id = NULL, pause_ticket_display = NULL,
         pause_ticket_url = NULL, paused_by = NULL, paused_at = NULL WHERE id = ?`,
      [parseInt(req.params.id, 10)]);
    if (r.affectedRows > 0)
      await SA.record(rbac, req, SW_PAGE, 'settings_saved', SA.entry({ what: 'watchlist', op: 'resume', id,
        subject: before ? before.upn : undefined,
        extra: { was_paused_on: before === undefined ? '(unknown)' : (before && before.pause_ticket_display) || null } }));
    res.json({ ok: true, changed: r.affectedRows });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── Trusted networks CRUD ─────────────────────────────────────────────
const NET_TYPES = new Set(['zscaler', 'office-plano', 'office-irvine', 'other']);

router.get('/networks', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM trusted_networks ORDER BY type, cidr');
    res.json({ ok: true, rows });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

router.post('/networks', async (req, res) => {
  const b = req.body || {};
  const cidr = String(b.cidr || '').trim();
  if (!validCidr(cidr)) return bad(res, 'invalid cidr');
  if (!NET_TYPES.has(b.type)) return bad(res, 'invalid type');
  if (!b.label || !String(b.label).trim()) return bad(res, 'label required');
  try {
    const before = await SA.snap(pool, 'SELECT ' + SW_NET_COLS + ' FROM trusted_networks WHERE cidr = ?', [cidr]);
    await pool.query(
      `INSERT INTO trusted_networks (label, cidr, type, note, created_by, enabled)
       VALUES (?, ?, ?, ?, ?, 1)
       ON DUPLICATE KEY UPDATE label = VALUES(label), type = VALUES(type), note = VALUES(note), enabled = 1`,
      [String(b.label).slice(0, 120), cidr, b.type, (b.note || '').slice(0, 500) || null, req.user.email]);
    const after = await SA.snap(pool, 'SELECT ' + SW_NET_COLS + ' FROM trusted_networks WHERE cidr = ?', [cidr]);
    await SA.record(rbac, req, SW_PAGE, 'settings_saved', SA.entry({ what: 'trusted_network',
      id: after ? after.id : undefined, subject: cidr, before, after, keys: SW_NET_KEYS }));
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

router.patch('/networks/:id', async (req, res) => {
  const b = req.body || {};
  const sets = [], vals = [];
  if ('enabled' in b) { sets.push('enabled = ?'); vals.push(b.enabled ? 1 : 0); }
  if ('label' in b) { sets.push('label = ?'); vals.push(String(b.label || '').slice(0, 120)); }
  if ('type' in b) { if (!NET_TYPES.has(b.type)) return bad(res, 'invalid type'); sets.push('type = ?'); vals.push(b.type); }
  if ('note' in b) { sets.push('note = ?'); vals.push(String(b.note || '').slice(0, 500) || null); }
  if ('cidr' in b) { const c = String(b.cidr || '').trim(); if (!validCidr(c)) return bad(res, 'invalid cidr'); sets.push('cidr = ?'); vals.push(c); }
  if (!sets.length) return bad(res, 'nothing to update');
  vals.push(parseInt(req.params.id, 10));
  try {
    const id = vals[vals.length - 1];
    const before = await SA.snap(pool, 'SELECT ' + SW_NET_COLS + ' FROM trusted_networks WHERE id = ?', [id]);
    const [r] = await pool.query(`UPDATE trusted_networks SET ${sets.join(', ')} WHERE id = ?`, vals);
    if (r.affectedRows > 0) {
      const after = await SA.snap(pool, 'SELECT ' + SW_NET_COLS + ' FROM trusted_networks WHERE id = ?', [id]);
      await SA.record(rbac, req, SW_PAGE, 'settings_saved', SA.entry({ what: 'trusted_network', op: 'update', id,
        subject: (after || before || {}).cidr, before, after, keys: SW_NET_KEYS.filter(k => k in b) }));
    }
    res.json({ ok: true, changed: r.affectedRows });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

router.delete('/networks/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const before = await SA.snap(pool, 'SELECT ' + SW_NET_COLS + ' FROM trusted_networks WHERE id = ?', [id]);
    const [r] = await pool.query('DELETE FROM trusted_networks WHERE id = ?', [parseInt(req.params.id, 10)]);
    if (r.affectedRows > 0)
      await SA.record(rbac, req, SW_PAGE, 'settings_deleted', SA.entry({ what: 'trusted_network', op: 'delete', id,
        subject: before ? before.cidr : undefined, before, after: null, keys: SW_NET_KEYS }));
    res.json({ ok: true, deleted: r.affectedRows });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// Quick "is this IP trusted?" tester for the console
router.get('/networks/check/:ip', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT label, cidr, type FROM trusted_networks WHERE enabled = 1');
    const hits = rows.filter(r => ipInCidr(req.params.ip, r.cidr));
    res.json({ ok: true, ip: req.params.ip, trusted: hits.length > 0, matches: hits });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── Violations feed ───────────────────────────────────────────────────
router.get('/violations', async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
  const where = [], vals = [];
  if (req.query.upn) { where.push('upn = ?'); vals.push(String(req.query.upn).toLowerCase()); }
  if (req.query.unacked === '1') where.push('acked = 0');
  if (req.query.source && ['okta', 'entra'].includes(req.query.source)) { where.push('source = ?'); vals.push(req.query.source); }
  if (req.query.hours) { where.push('event_time > NOW() - INTERVAL ? HOUR'); vals.push(Math.min(parseInt(req.query.hours, 10) || 24, 8760)); }
  const sql = `SELECT id, upn, source, source_event_id, event_time, ip, geo_country, geo_city,
                      geo_asn, geo_isp, result,
                      failure_reason, app_name, client_app, user_agent, acked, ack_by, ack_at, ack_note,
                      alert_sent, alert_channels_hit, sdp_ticket_id, sdp_ticket_url, created_at,
                      CASE source
                        WHEN 'entra' THEN JSON_OBJECT(
                          'browser', JSON_UNQUOTE(JSON_EXTRACT(raw_json,'$.deviceDetail.browser')),
                          'os',      JSON_UNQUOTE(JSON_EXTRACT(raw_json,'$.deviceDetail.operatingSystem')),
                          'device',  JSON_UNQUOTE(JSON_EXTRACT(raw_json,'$.deviceDetail.displayName')),
                          'managed', JSON_EXTRACT(raw_json,'$.deviceDetail.isManaged'),
                          'compliant', JSON_EXTRACT(raw_json,'$.deviceDetail.isCompliant'),
                          'deviceId', JSON_UNQUOTE(JSON_EXTRACT(raw_json,'$.deviceDetail.deviceId'))
                        )
                        WHEN 'okta' THEN JSON_OBJECT(
                          'device',  JSON_UNQUOTE(JSON_EXTRACT(raw_json,'$.client.device')),
                          'os',      JSON_UNQUOTE(JSON_EXTRACT(raw_json,'$.client.userAgent.os')),
                          'browser', JSON_UNQUOTE(JSON_EXTRACT(raw_json,'$.client.userAgent.browser')),
                          'ua',      JSON_UNQUOTE(JSON_EXTRACT(raw_json,'$.client.userAgent.rawUserAgent')),
                          'zone',    JSON_UNQUOTE(JSON_EXTRACT(raw_json,'$.client.zone'))
                        )
                      END AS device_info,
                      CASE source
                        WHEN 'entra' THEN JSON_OBJECT(
                          'ca_status',        JSON_UNQUOTE(JSON_EXTRACT(raw_json,'$.conditionalAccessStatus')),
                          'resource',         JSON_UNQUOTE(JSON_EXTRACT(raw_json,'$.resourceDisplayName')),
                          'is_interactive',   JSON_EXTRACT(raw_json,'$.isInteractive'),
                          'risk_during',      JSON_UNQUOTE(JSON_EXTRACT(raw_json,'$.riskLevelDuringSignIn')),
                          'risk_aggregate',   JSON_UNQUOTE(JSON_EXTRACT(raw_json,'$.riskLevelAggregated')),
                          'ca_policies',      JSON_EXTRACT(raw_json,'$.appliedConditionalAccessPolicies')
                        )
                        WHEN 'okta' THEN JSON_OBJECT(
                          'is_proxy',         JSON_EXTRACT(raw_json,'$.securityContext.isProxy'),
                          'as_number',        JSON_EXTRACT(raw_json,'$.securityContext.asNumber'),
                          'as_org',           JSON_UNQUOTE(JSON_EXTRACT(raw_json,'$.securityContext.asOrg')),
                          'isp',              JSON_UNQUOTE(JSON_EXTRACT(raw_json,'$.securityContext.isp')),
                          'domain',           JSON_UNQUOTE(JSON_EXTRACT(raw_json,'$.securityContext.domain')),
                          'behaviors',        JSON_UNQUOTE(JSON_EXTRACT(raw_json,'$.debugContext.debugData.behaviors'))
                        )
                      END AS threat_context
               FROM signin_violations ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
               ORDER BY event_time DESC LIMIT ?`;
  vals.push(limit);
  try {
    const [rows] = await pool.query(sql, vals);
    // The 500-row cap above is a server decision the page cannot see. Return the
    // real number of matching rows so the UI can say "500 of 2,160" rather than
    // presenting a truncated page as the entire result set.
    const [[{ matched }]] = await pool.query(
      `SELECT COUNT(*) matched FROM signin_violations ${where.length ? 'WHERE ' + where.join(' AND ') : ''}`,
      vals.slice(0, -1));
    res.json({ ok: true, rows, matched, capped: matched > rows.length });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

router.get('/violations/:id/raw', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT raw_json FROM signin_violations WHERE id = ?', [parseInt(req.params.id, 10)]);
    if (!rows.length) return res.status(404).json({ ok: false, error: 'not found' });
    res.json({ ok: true, raw: rows[0].raw_json });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

router.post('/violations/:id/ack', async (req, res) => {
  const note = String((req.body && req.body.note) || '').slice(0, 500) || null;
  try {
    const [r] = await pool.query(
      'UPDATE signin_violations SET acked = 1, ack_by = ?, ack_at = NOW(), ack_note = ? WHERE id = ?',
      [req.user.email, note, parseInt(req.params.id, 10)]);
    res.json({ ok: true, changed: r.affectedRows });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

router.post('/violations/ack-all', async (req, res) => {
  // v2: supports optional filters — source, result, before, after
  const b = req.body || {};
  const where = ['acked = 0'], vals = [];
  if (b.source && ['okta', 'entra'].includes(b.source)) { where.push('source = ?'); vals.push(b.source); }
  if (b.result && ['success', 'failure', 'unknown'].includes(b.result)) { where.push('result = ?'); vals.push(b.result); }
  if (b.before) { where.push('event_time < ?'); vals.push(b.before); }
  if (b.after) { where.push('event_time > ?'); vals.push(b.after); }
  const note = String(b.note || 'bulk ack').slice(0, 500);
  try {
    // Bind order must match the statement: the two SET placeholders first, then
    // the WHERE values. The previous array put the WHERE values first, so any
    // filter shifted every bind (ack_by <- source, WHERE source <- the note).
    const [r] = await pool.query(
      `UPDATE signin_violations SET acked = 1, ack_by = ?, ack_at = NOW(), ack_note = ? WHERE ${where.join(' AND ')}`,
      [req.user.email, note, ...vals]);
    res.json({ ok: true, changed: r.affectedRows });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── Alert channels CRUD + test ────────────────────────────────────────
const CH_TYPES = new Set(['teams', 'slack', 'email', 'sdp', 'webhook']);
const FIRE_ON = new Set(['all', 'success', 'failure']);

router.get('/channels', async (req, res) => {
  try {
    // [CORPIT-QA 2026-09-07] Explicit projection, not SELECT *. config_json
    // holds the channel's webhook URL -- a bearer credential: anyone with it can
    // post into the Teams channel -- and mention_config its routing. loadChannels()
    // renders name/type/fire_on/tier_filter/auto_investigate/enabled/
    // last_test_result/id only, so shipping the secret bought nothing and put it
    // in page memory, devtools and any HAR captured for a support ticket.
    const [rows] = await pool.query(
      `SELECT id, name, type, fire_on, tier_filter, auto_investigate, enabled,
              last_test_at, last_test_result, created_by, created_at, updated_at
         FROM alert_channels ORDER BY enabled DESC, name`);
    res.json({ ok: true, rows });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

router.post('/channels', async (req, res) => {
  const b = req.body || {};
  if (!b.name || !String(b.name).trim()) return bad(res, 'name required');
  if (!CH_TYPES.has(b.type)) return bad(res, 'invalid type');
  if (b.fire_on && !FIRE_ON.has(b.fire_on)) return bad(res, 'invalid fire_on');
  let cfg = b.config_json;
  if (typeof cfg === 'string') { try { cfg = JSON.parse(cfg); } catch (e) { return bad(res, 'config_json is not valid JSON'); } }
  if (!cfg || typeof cfg !== 'object') return bad(res, 'config_json required');
  try {
    const tierFilter = ['all','vip','standard'].includes(b.tier_filter) ? b.tier_filter : 'all';
    const autoInv = b.auto_investigate ? 1 : 0;
    let mention = null;
    if (b.mention_config) {
      let mc = b.mention_config;
      if (typeof mc === 'string') { try { mc = JSON.parse(mc); } catch (e) { return bad(res, 'mention_config is not valid JSON'); } }
      if (mc && typeof mc === 'object') mention = JSON.stringify(mc);
    }
    const [ins] = await pool.query(
      'INSERT INTO alert_channels (name, type, config_json, fire_on, tier_filter, mention_config, auto_investigate, created_by, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)',
      [String(b.name).slice(0, 120), b.type, JSON.stringify(cfg), b.fire_on || 'all', tierFilter, mention, autoInv, req.user.email]);
    const after = await SA.snap(pool, 'SELECT ' + SW_CH_COLS + ' FROM alert_channels WHERE id = ?', [ins.insertId]);
    await SA.record(rbac, req, SW_PAGE, 'settings_saved', SA.entry({ what: 'alert_channel', op: 'create',
      id: ins.insertId, subject: after ? after.name : String(b.name).slice(0, 120), before: null, after,
      keys: SW_CH_KEYS, secretKeys: SW_CH_SECRET }));
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

router.patch('/channels/:id', async (req, res) => {
  const b = req.body || {};
  const sets = [], vals = [];
  if ('enabled' in b) { sets.push('enabled = ?'); vals.push(b.enabled ? 1 : 0); }
  if ('name' in b) { sets.push('name = ?'); vals.push(String(b.name || '').slice(0, 120)); }
  if ('fire_on' in b) { if (!FIRE_ON.has(b.fire_on)) return bad(res, 'invalid fire_on'); sets.push('fire_on = ?'); vals.push(b.fire_on); }
  if ('config_json' in b) {
    let cfg = b.config_json;
    if (typeof cfg === 'string') { try { cfg = JSON.parse(cfg); } catch (e) { return bad(res, 'config_json is not valid JSON'); } }
    if (!cfg || typeof cfg !== 'object') return bad(res, 'config_json invalid');
    sets.push('config_json = ?'); vals.push(JSON.stringify(cfg));
  }
  if ('tier_filter' in b) { if (!['all','vip','standard'].includes(b.tier_filter)) return bad(res, 'invalid tier_filter'); sets.push('tier_filter = ?'); vals.push(b.tier_filter); }
  if ('auto_investigate' in b) { sets.push('auto_investigate = ?'); vals.push(b.auto_investigate ? 1 : 0); }
  if ('mention_config' in b) {
    let mc = b.mention_config;
    if (typeof mc === 'string') { try { mc = JSON.parse(mc); } catch (e) { return bad(res, 'mention_config is not valid JSON'); } }
    sets.push('mention_config = ?'); vals.push(mc && typeof mc === 'object' ? JSON.stringify(mc) : null);
  }
  if (!sets.length) return bad(res, 'nothing to update');
  vals.push(parseInt(req.params.id, 10));
  try {
    const id = vals[vals.length - 1];
    const before = await SA.snap(pool, 'SELECT ' + SW_CH_COLS + ' FROM alert_channels WHERE id = ?', [id]);
    const [r] = await pool.query(`UPDATE alert_channels SET ${sets.join(', ')} WHERE id = ?`, vals);
    if (r.affectedRows > 0) {
      const after = await SA.snap(pool, 'SELECT ' + SW_CH_COLS + ' FROM alert_channels WHERE id = ?', [id]);
      await SA.record(rbac, req, SW_PAGE, 'settings_saved', SA.entry({ what: 'alert_channel', op: 'update', id,
        subject: (after || before || {}).name, before, after, keys: SW_CH_KEYS.filter(k => k in b), secretKeys: SW_CH_SECRET }));
    }
    res.json({ ok: true, changed: r.affectedRows });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

router.delete('/channels/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const before = await SA.snap(pool, 'SELECT ' + SW_CH_COLS + ' FROM alert_channels WHERE id = ?', [id]);
    const [r] = await pool.query('DELETE FROM alert_channels WHERE id = ?', [parseInt(req.params.id, 10)]);
    if (r.affectedRows > 0)
      await SA.record(rbac, req, SW_PAGE, 'settings_deleted', SA.entry({ what: 'alert_channel', op: 'delete', id,
        subject: before ? before.name : undefined, before, after: null, keys: SW_CH_KEYS, secretKeys: SW_CH_SECRET }));
    res.json({ ok: true, deleted: r.affectedRows });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

router.post('/channels/:id/test', async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const result = await testChannel(pool, parseInt(req.params.id, 10), req.user.email);
    const ch = await SA.snap(pool, 'SELECT name FROM alert_channels WHERE id = ?', [id]);
    await SA.record(rbac, req, SW_PAGE, result && result.ok ? 'settings_test_sent' : 'settings_test_failed',
      SA.entry({ what: 'alert_channel', op: 'test', id, subject: ch ? ch.name : undefined, extra: { ok: !!(result && result.ok) } }));
    res.json({ ok: result.ok, detail: result.detail });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});



// ── v2.0.0: Enhanced KPIs ─────────────────────────────────────────────
router.get('/kpi', async (req, res) => {
  try {
    const [[{total}]] = await pool.query('SELECT COUNT(*) total FROM signin_violations');
    const [[{open}]] = await pool.query('SELECT COUNT(*) open FROM signin_violations WHERE acked = 0');
    const [[{watched}]] = await pool.query('SELECT COUNT(*) watched FROM signin_watchlist WHERE active = 1');
    const [[{risk_7d}]] = await pool.query(
      `SELECT COUNT(*) risk_7d FROM entra_risk_detections r
       -- COLLATE, not an ALTER: entra_* is utf8mb4_0900_ai_ci and signin_* is
       -- utf8mb4_unicode_ci in this schema, so this comparison is the only
       -- thing that is wrong. Without it the whole KPI strip 500s.
       JOIN signin_watchlist w
         ON LOWER(r.user_principal_name) COLLATE utf8mb4_unicode_ci = w.upn
        AND w.active = 1
       WHERE r.detected_date_time > NOW() - INTERVAL 7 DAY`);
    // failure streak: consecutive failures (newest first) until a success
    const [streakRows] = await pool.query(
      'SELECT result FROM signin_violations ORDER BY event_time DESC LIMIT 200');
    let streak = 0;
    for (const r of streakRows) { if (r.result === 'failure') streak++; else break; }
    // last 72h counts by result
    const [recent] = await pool.query(
      'SELECT result, COUNT(*) n FROM signin_violations WHERE event_time > NOW() - INTERVAL 72 HOUR GROUP BY result');
    const recentMap = {};
    for (const r of recent) recentMap[r.result] = r.n;
    res.json({ ok: true, total, open, watched, failure_streak: streak, recent_72h: recentMap , risk_7d });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── v2.0.0: Entra Risk Detections (local DB) ─────────────────────────
router.get('/risk-detections', async (req, res) => {
  const upn = (req.query.upn || '').toLowerCase().trim();
  if (!upn) return bad(res, 'upn required');
  const days = Math.min(parseInt(req.query.days, 10) || 90, 365);
  try {
    const [rows] = await pool.query(
      `SELECT entra_id, risk_event_type, risk_level, risk_state, risk_detail,
              source, detection_timing_type, ip_address, location_city, location_country,
              activity_date_time, detected_date_time
       FROM entra_risk_detections
       WHERE LOWER(user_principal_name) = ? AND detected_date_time > NOW() - INTERVAL ? DAY
       ORDER BY detected_date_time DESC LIMIT 50`,
      [upn, days]);
    res.json({ ok: true, rows });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── v2.0.0: Employee Status (cross-ref via entra_users) ──────────────
router.get('/employee-status', async (req, res) => {
  const upn = (req.query.upn || '').toLowerCase().trim();
  if (!upn) return bad(res, 'upn required');
  try {
    // Step 1: resolve UPN → mail via entra_users
    const [eu] = await pool.query(
      'SELECT mail, display_name FROM entra_users WHERE LOWER(user_principal_name) = ? LIMIT 1', [upn]);
    if (!eu.length) return res.json({ ok: true, found: false, reason: 'no entra_users match' });
    const mail = (eu[0].mail || '').toLowerCase();
    const displayName = eu[0].display_name || '';

    // Step 2: check active_employees
    const [active] = await pool.query(
      `SELECT status, employee_name, first_last, business_email, job_name, department,
              location_name, manager_name, hire_date, updated_at
       FROM active_employees WHERE LOWER(business_email) = ? OR first_last = ? LIMIT 1`,
      [mail, displayName]);

    // Step 3: check terminated_employees
    const [termed] = await pool.query(
      `SELECT status, employee_name, first_last, business_email, job_name, department,
              location_name, termination_date, is_termination_reason, functional_leader, updated_at
       FROM terminated_employees WHERE LOWER(business_email) = ? OR first_last = ? LIMIT 1`,
      [mail, displayName]);

    const stale_threshold = 90 * 24 * 60 * 60 * 1000; // 90 days
    const result = { ok: true, found: true, upn, resolved_mail: mail, display_name: displayName };

    if (termed.length) {
      result.employee_status = 'terminated';
      result.record = termed[0];
      result.data_stale = (Date.now() - new Date(termed[0].updated_at).getTime()) > stale_threshold;
    } else if (active.length) {
      result.employee_status = 'active';
      result.record = active[0];
      result.data_stale = (Date.now() - new Date(active[0].updated_at).getTime()) > stale_threshold;
    } else {
      result.found = false;
      result.reason = 'no employee record for ' + mail;
    }
    res.json(result);
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── v2.0.0: SDP Ticket Creation ──────────────────────────────────────
router.post('/violations/:id/sdp-ticket', async (req, res) => {
  if (!sdpLookup || !sdpLookup.createTicket) {
    return res.status(501).json({ ok: false, error: 'SDP integration not available' });
  }
  const violId = parseInt(req.params.id, 10);
  try {
    const [rows] = await pool.query('SELECT * FROM signin_violations WHERE id = ?', [violId]);
    if (!rows.length) return res.status(404).json({ ok: false, error: 'violation not found' });
    const v = rows[0];
    if (v.sdp_ticket_id) {
      return res.json({ ok: true, already_exists: true, ticket_id: v.sdp_ticket_id, ticket_url: v.sdp_ticket_url });
    }
    const geo = [v.geo_city, v.geo_country].filter(Boolean).join(', ') || 'Unknown';
    const ticket = await sdpLookup.createTicket({
      subject: `[Sign-In Watch] ${v.result === 'success' ? 'SUCCESSFUL' : 'Attempted'} sign-in — ${v.upn} from ${geo}`,
      description: [
        `Sign-In Watch violation #${v.id}`,
        `User: ${v.upn}`,
        `Source: ${(v.source || '').toUpperCase()}`,
        `Result: ${(v.result || 'unknown').toUpperCase()}`,
        `Time: ${v.event_time}`,
        `IP: ${v.ip || '—'}`,
        `Location: ${geo}`,
        v.geo_asn ? `ASN: ${v.geo_asn}` : null,
        v.geo_isp ? `ISP: ${v.geo_isp}` : null,
        `App: ${v.app_name || '—'}`,
        v.failure_reason ? `Reason: ${v.failure_reason}` : null,
        '',
        `Investigate: ${HUB_ORIGIN}/signin-watch.html?violation=${v.id}`,
      ].filter(Boolean).join('\n'),
      requesterEmail: req.user.email,
      requesterName: req.user.name || req.user.email,
    });
    const tDisplay = String(ticket.display_id || ticket.id).slice(0, 40);
    await pool.query(
      'UPDATE signin_violations SET sdp_ticket_id = ?, sdp_ticket_url = ?, sdp_ticket_display = ? WHERE id = ?',
      [ticket.id, ticket.url, tDisplay, violId]);
    // v2.7.0: auto-pause this user's watchlist entry so alerts are suppressed while
    // the ticket is open (auto-resumes when the ticket is closed — poller checks every 5 min).
    let auto_pause = null;
    try {
      const [wl] = await pool.query('SELECT id, upn FROM signin_watchlist WHERE upn = ? LIMIT 1', [v.upn]);
      if (wl.length) {
        const pr = await applyPause(pool, wl[0].id, wl[0].upn,
          { id: ticket.id, display_id: ticket.display_id || ticket.id, url: ticket.url },
          req.user.email, { associate: true });
        auto_pause = { watchlist_id: wl[0].id, paused: !pr.skipped, associated: pr.associated || 0, reason: pr.reason || null };
      }
    } catch (e) { auto_pause = { error: e.message }; }
    res.json({ ok: true, ticket_id: ticket.id, ticket_display: tDisplay, ticket_url: ticket.url, auto_pause });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── v2.0.0: Subnet Clustering ────────────────────────────────────────
router.get('/subnet-cluster', async (req, res) => {
  const ip = (req.query.ip || '').trim();
  if (!ip) return bad(res, 'ip required');
  try {
    let rows;
    if (ip.includes(':')) {
      // IPv6: match on first 4 hextets (/48-ish)
      const prefix = ip.split(':').slice(0, 4).join(':');
      [rows] = await pool.query(
        `SELECT ip, geo_country, geo_city, geo_asn, geo_isp, result, event_time, upn,
                COUNT(*) OVER (PARTITION BY ip) AS ip_count
         FROM signin_violations WHERE ip LIKE CONCAT(?, '%')
         ORDER BY event_time DESC LIMIT 100`,
        [prefix]);
    } else {
      // IPv4: match on /24
      const prefix = ip.split('.').slice(0, 3).join('.') + '.';
      [rows] = await pool.query(
        `SELECT ip, geo_country, geo_city, geo_asn, geo_isp, result, event_time, upn,
                COUNT(*) OVER (PARTITION BY ip) AS ip_count
         FROM signin_violations WHERE ip LIKE CONCAT(?, '%')
         ORDER BY event_time DESC LIMIT 100`,
        [prefix]);
    }
    // summarize
    const ips = new Map();
    for (const r of rows) {
      if (!ips.has(r.ip)) ips.set(r.ip, { ip: r.ip, geo: [r.geo_city, r.geo_country].filter(Boolean).join(', '), asn: r.geo_asn, isp: r.geo_isp, count: 0, results: {} });
      const e = ips.get(r.ip);
      e.count++;
      e.results[r.result] = (e.results[r.result] || 0) + 1;
    }
    res.json({ ok: true, query_ip: ip, cluster_size: ips.size, total_events: rows.length, ips: [...ips.values()] });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── v2.0.0: LSS/NSS Local Cross-Reference ───────────────────────────
// Both telemetry files hold millisecond timestamps; the first version
// compared them against seconds and never matched a row. The reads run in a
// worker thread (sqlite-offload), each bounded to its window through the ts
// index, and a missing file answers null for that side as before.
const XREF_DATA_DIR = require('path').join(__dirname, 'data');
const XREF_LSS_DB = process.env.LSS_DB || require('path').join(XREF_DATA_DIR, 'lss.db');
const XREF_NSS_DB = process.env.NSS_DB || require('path').join(XREF_DATA_DIR, 'nss.db');
function xrefLikeEscape(s) { return String(s).replace(/[\\%_]/g, '\\$&'); }
async function xrefSide(dbPath, sql, params, label) {
  if (!require('fs').existsSync(dbPath)) return null;
  const r = await offload.query(dbPath, [{ sql, params }], { timeoutMs: 20000, label });
  if (!r.ok) return { error: r.error };
  return { row_count: r.results[0].length, rows: r.results[0].slice(0, 20) };
}
router.get('/lss-nss-xref', async (req, res) => {
  const upn = String(req.query.upn || '').toLowerCase().trim();
  const time = String(req.query.time || ''); // ISO string — event time
  if (!upn || !time) return bad(res, 'upn and time required');
  const eventMs = new Date(time).getTime();
  if (!Number.isFinite(eventMs)) return bad(res, 'time must be an ISO-8601 timestamp');
  const windowMin = Math.min(Math.max(parseInt(req.query.window, 10) || 30, 1), 1440); // minutes, 1..24h
  const from = eventMs - windowMin * 60000, to = eventMs + windowMin * 60000;
  const like = '%' + xrefLikeEscape(upn) + '%';
  try {
    const [lss, nss] = await Promise.all([
      xrefSide(XREF_LSS_DB,
        'SELECT ts, user, app, host, client_ip, server_ip, status FROM conns INDEXED BY ix_conns_ts ' +
        "WHERE ts BETWEEN ? AND ? AND LOWER(user) LIKE ? ESCAPE '\\' ORDER BY ts DESC LIMIT 50", [from, to, like], 'LSS cross-reference'),
      xrefSide(XREF_NSS_DB,
        'SELECT ts, user, host, url, action, reason, client_ip, url_category FROM ssl_events INDEXED BY ix_ssl_ts ' +
        "WHERE ts BETWEEN ? AND ? AND LOWER(user) LIKE ? ESCAPE '\\' ORDER BY ts DESC LIMIT 50", [from, to, like], 'NSS cross-reference')
    ]);
    res.json({ ok: true, lss, nss, window_min: windowMin });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── v2.0.0: Assigned devices for a user (local Intune DB) ────────────
router.get('/assigned-devices', async (req, res) => {
  const upn = (req.query.upn || '').toLowerCase().trim();
  if (!upn) return bad(res, 'upn required');
  try {
    const [rows] = await pool.query(
      `SELECT device_name, os, os_version, ownership, compliance, model,
              serial_number, last_checkin, primary_user_name
       FROM it_inventory.intune_devices WHERE LOWER(primary_user_upn) = ?
       ORDER BY last_checkin DESC`,
      [upn]);
    res.json({ ok: true, rows });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});



// ── v2.6.0: Graph-direct risk + MFA posture (app 3836db07, ENTRA_* creds) ──
let _graphTok = null, _graphTokExp = 0;
async function graphToken() {
  if (_graphTok && Date.now() < _graphTokExp - 60000) return _graphTok;
  const body = new URLSearchParams({
    client_id: process.env.ENTRA_CLIENT_ID,
    client_secret: process.env.ENTRA_CLIENT_SECRET,
    scope: 'https://graph.microsoft.com/.default',
    grant_type: 'client_credentials',
  });
  const r = await fetch(`https://login.microsoftonline.com/${process.env.ENTRA_TENANT_ID}/oauth2/v2.0/token`,
    { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
  const j = await r.json();
  if (!j.access_token) throw new Error('graph token: ' + (j.error_description || j.error || r.status));
  _graphTok = j.access_token;
  _graphTokExp = Date.now() + (j.expires_in || 3600) * 1000;
  return _graphTok;
}

router.get('/risky-user', async (req, res) => {
  const upn = String(req.query.upn || '').trim().toLowerCase();
  if (!EMAIL_RE.test(upn)) return bad(res, 'invalid upn');
  try {
    const tok = await graphToken();
    const r = await fetch("https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?$filter=userPrincipalName eq '" + upn.replace(/'/g, "''") + "'",
      { headers: { Authorization: 'Bearer ' + tok } });
    if (!r.ok) return res.status(502).json({ ok: false, error: 'graph ' + r.status });
    const j = await r.json();
    const u = (j.value || [])[0] || null;
    res.json({ ok: true, found: !!u, risk: u ? {
      riskLevel: u.riskLevel, riskState: u.riskState, riskDetail: u.riskDetail,
      updated: u.riskLastUpdatedDateTime } : null });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

const MFA_TYPES = {
  '#microsoft.graph.passwordAuthenticationMethod':            { name: 'Password',              mfa: false, phishRes: false },
  '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod': { name: 'Microsoft Authenticator', mfa: true,  phishRes: false },
  '#microsoft.graph.phoneAuthenticationMethod':               { name: 'Phone (SMS/voice)',     mfa: true,  phishRes: false },
  '#microsoft.graph.fido2AuthenticationMethod':               { name: 'FIDO2 security key',    mfa: true,  phishRes: true },
  '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod': { name: 'Windows Hello',     mfa: true,  phishRes: true },
  '#microsoft.graph.softwareOathAuthenticationMethod':        { name: 'Software TOTP',         mfa: true,  phishRes: false },
  '#microsoft.graph.temporaryAccessPassAuthenticationMethod': { name: 'Temporary Access Pass', mfa: true,  phishRes: false },
  '#microsoft.graph.emailAuthenticationMethod':               { name: 'Email (SSPR only)',     mfa: false, phishRes: false },
  '#microsoft.graph.x509CertificateAuthenticationMethod':     { name: 'Certificate',           mfa: true,  phishRes: true },
};

router.get('/mfa-posture', async (req, res) => {
  const upn = String(req.query.upn || '').trim().toLowerCase();
  if (!EMAIL_RE.test(upn)) return bad(res, 'invalid upn');
  try {
    const tok = await graphToken();
    const r = await fetch('https://graph.microsoft.com/v1.0/users/' + encodeURIComponent(upn) + '/authentication/methods',
      { headers: { Authorization: 'Bearer ' + tok } });
    if (!r.ok) return res.status(502).json({ ok: false, error: 'graph ' + r.status });
    const j = await r.json();
    const methods = (j.value || []).map(m => {
      const t = MFA_TYPES[m['@odata.type']] || { name: String(m['@odata.type'] || '').replace('#microsoft.graph.', ''), mfa: true, phishRes: false };
      return { type: t.name, mfa: t.mfa, phishing_resistant: t.phishRes,
        detail: m.displayName || m.phoneNumber || m.emailAddress || null,
        created: m.createdDateTime || null };
    });
    res.json({ ok: true, methods,
      has_mfa: methods.some(m => m.mfa),
      phishing_resistant: methods.some(m => m.phishing_resistant) });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── v2.5.0: target history — the siege context for one account ──
router.get('/user-history', async (req, res) => {
  const upn = String(req.query.upn || '').trim().toLowerCase();
  if (!EMAIL_RE.test(upn)) return bad(res, 'invalid upn');
  try {
    const [[agg]] = await pool.query(
      `SELECT COUNT(*) AS attempts,
              MIN(event_time) AS first_seen, MAX(event_time) AS last_seen,
              COUNT(DISTINCT ip) AS unique_ips,
              COUNT(DISTINCT geo_country) AS countries,
              COUNT(DISTINCT geo_asn) AS asns,
              SUM(result = 'success') AS successes,
              SUM(result = 'failure') AS failures,
              SUM(event_time > NOW() - INTERVAL 24 HOUR) AS last_24h,
              SUM(event_time > NOW() - INTERVAL 7 DAY) AS last_7d,
              COUNT(DISTINCT sdp_ticket_id) AS tickets
       FROM signin_violations WHERE upn = ?`, [upn]);
    const [top_countries] = await pool.query(
      `SELECT geo_country AS country, COUNT(*) AS n FROM signin_violations
       WHERE upn = ? AND geo_country IS NOT NULL
       GROUP BY geo_country ORDER BY n DESC LIMIT 6`, [upn]);
    res.json({ ok: true, upn, history: agg, top_countries });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── v2.1.0: VIP status board ──────────────────────────────────────────
router.get('/vip-board', async (req, res) => {
  try {
    const [vips] = await pool.query(
      "SELECT id, upn, note, watch_okta, watch_entra, pause_ticket_id, pause_ticket_display, pause_ticket_url FROM signin_watchlist WHERE active = 1 AND tier = 'vip' ORDER BY upn");
    const board = [];
    for (const vip of vips) {
      // last sign-in event of ANY kind (from violations table — only untrusted show here)
      const [[last]] = await pool.query(
        'SELECT event_time, ip, geo_country, geo_city, result, source FROM signin_violations WHERE upn = ? ORDER BY event_time DESC LIMIT 1',
        [vip.upn]);
      const [[open]] = await pool.query(
        'SELECT COUNT(*) AS n FROM signin_violations WHERE upn = ? AND acked = 0', [vip.upn]);
      const [[recent]] = await pool.query(
        'SELECT COUNT(*) AS n FROM signin_violations WHERE upn = ? AND event_time > NOW() - INTERVAL 24 HOUR', [vip.upn]);
      // resolve display name via entra_users
      const [[eu]] = await pool.query(
        'SELECT display_name FROM entra_users WHERE LOWER(user_principal_name) = ? LIMIT 1', [vip.upn]);
      board.push({
        upn: vip.upn,
        display_name: eu ? eu.display_name : vip.upn,
        note: vip.note,
        open_violations: open.n,
        violations_24h: recent.n,
        last_violation: last || null,
        paused: !!vip.pause_ticket_id,
        pause_ticket_display: vip.pause_ticket_display || null,
        pause_ticket_url: vip.pause_ticket_url || null,
        status: open.n > 0 ? 'alert' : (recent.n > 0 ? 'watch' : 'clear'),
      });
    }
    res.json({ ok: true, vips: board });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── v2.1.0: server-side investigation snapshot ────────────────────────
// Runs local-DB enrichment (safe, no heavy external calls) and stores JSON on the row.
// Used by auto-investigate (job) and the manual "snapshot" button.
async function buildInvestigationSnapshot(pool, violId) {
  const [rows] = await pool.query('SELECT * FROM signin_violations WHERE id = ?', [violId]);
  if (!rows.length) return null;
  const v = rows[0];
  const upn = (v.upn || '').toLowerCase();
  const snap = { built_at: new Date().toISOString(), upn, findings: [] };

  // employee status via entra_users cross-ref
  try {
    const [[eu]] = await pool.query('SELECT mail, display_name FROM entra_users WHERE LOWER(user_principal_name) = ? LIMIT 1', [upn]);
    if (eu) {
      const mail = (eu.mail || '').toLowerCase();
      const [[termed]] = await pool.query('SELECT status, termination_date, is_termination_reason, updated_at FROM terminated_employees WHERE LOWER(business_email) = ? OR first_last = ? LIMIT 1', [mail, eu.display_name || '']);
      const [[active]] = await pool.query('SELECT status, job_name, department, updated_at FROM active_employees WHERE LOWER(business_email) = ? OR first_last = ? LIMIT 1', [mail, eu.display_name || '']);
      if (termed) { snap.employee = { status: 'terminated', ...termed }; snap.findings.push('Terminated employee'); }
      else if (active) { snap.employee = { status: 'active', ...active }; }
    }
  } catch (e) { snap.employee_error = e.message; }

  // entra risk detections (90d)
  try {
    const [rd] = await pool.query('SELECT risk_event_type, risk_level, detected_date_time FROM entra_risk_detections WHERE LOWER(user_principal_name) = ? AND detected_date_time > NOW() - INTERVAL 90 DAY ORDER BY detected_date_time DESC LIMIT 10', [upn]);
    snap.risk_detections = rd;
    if (rd.length) snap.findings.push(rd.length + ' Entra risk detections');
  } catch (e) { snap.risk_error = e.message; }

  // subnet cluster
  try {
    if (v.ip) {
      const prefix = v.ip.includes(':') ? v.ip.split(':').slice(0, 4).join(':') : v.ip.split('.').slice(0, 3).join('.') + '.';
      const [cluster] = await pool.query("SELECT DISTINCT ip FROM signin_violations WHERE ip LIKE CONCAT(?, '%')", [prefix]);
      snap.subnet_cluster_size = cluster.length;
      if (cluster.length > 1) snap.findings.push(cluster.length + ' IPs in attacker subnet');
    }
  } catch (e) { snap.subnet_error = e.message; }

  // assigned devices
  try {
    const [devs] = await pool.query('SELECT device_name, os, compliance FROM it_inventory.intune_devices WHERE LOWER(primary_user_upn) = ?', [upn]);
    snap.assigned_devices = devs.length;
  } catch (e) { /* ignore */ }

  // device posture from raw_json (attacker device)
  try {
    const raw = typeof v.raw_json === 'object' ? v.raw_json : JSON.parse(v.raw_json || '{}');
    const dd = raw.deviceDetail || {};
    if (dd.isManaged === false) snap.findings.push('Unmanaged device');
    if (raw.conditionalAccessStatus === 'notApplied') snap.findings.push('CA not enforced');
    snap.ca_status = raw.conditionalAccessStatus || null;
  } catch (e) { /* ignore */ }

  return snap;
}

router.post('/violations/:id/snapshot', async (req, res) => {
  const violId = parseInt(req.params.id, 10);
  try {
    const snap = await buildInvestigationSnapshot(pool, violId);
    if (!snap) return res.status(404).json({ ok: false, error: 'violation not found' });
    await pool.query('UPDATE signin_violations SET auto_investigation = ?, investigated_at = NOW() WHERE id = ?', [JSON.stringify(snap), violId]);
    res.json({ ok: true, snapshot: snap });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// export the snapshot builder for the job to reuse
router.buildInvestigationSnapshot = buildInvestigationSnapshot;

// ── v2.2.0: Rapid7 cross-user IP correlation ─────────────────────────
// Proxies to /api/rapid7/ip-xref and annotates results with watchlist membership
router.get('/rapid7-ip-xref', async (req, res) => {
  const ip = typeof req.query.ip === 'string' ? req.query.ip.trim() : '';
  const hours = req.query.hours === undefined ? '720' : req.query.hours;
  const subnet = req.query.subnet === undefined ? '1' : req.query.subnet;
  if (!require('net').isIP(ip)) return bad(res, 'A valid IPv4 or IPv6 address is required');
  if (typeof hours !== 'string' || !/^[1-9]\d{0,3}$/.test(hours) || Number(hours) > 2160) {
    return bad(res, 'hours must be between 1 and 2160');
  }
  if (subnet !== '0' && subnet !== '1') return bad(res, 'subnet must be 0 or 1');

  try {
    // This is a second authenticated request to the SAME API. Desktop clients
    // authenticate with it_session; forwarding only Authorization lost their
    // session. Host must also survive for host-scoped session verification.
    const params = new URLSearchParams({ ip, hours, subnet });
    const r7Resp = await requestRapid7Xref(params, req.headers);
    const r7Data = r7Resp.data;

    if (!r7Resp.ok || !r7Data || r7Data.ok !== true || !Array.isArray(r7Data.users)) {
      // The OUTER request already passed the session and super-admin gates.
      // A downstream failure is an enrichment error, not an expired browser
      // session. In particular, do not trigger global logout with its 401.
      return res.status(502).json({ ok: false, error: 'Rapid7 enrichment unavailable',
        upstream_status: r7Resp.status });
    }

    // Cross-reference found usernames against our watchlist
    const [watchlist] = await pool.query('SELECT upn, tier, active FROM signin_watchlist');
    const watchMap = new Map(watchlist.map(w => [w.upn.toLowerCase(), w]));

    const annotated = (r7Data.users || []).map(u => {
      const watched = watchMap.get(u.username.toLowerCase());
      return {
        ...u,
        on_watchlist: !!watched,
        watchlist_tier: watched ? watched.tier : null,
        watchlist_active: watched ? !!watched.active : null,
      };
    });

    // Separate watched vs other users
    const watchedHits = annotated.filter(u => u.on_watchlist);
    const otherHits = annotated.filter(u => !u.on_watchlist);

    res.json({
      ok: true,
      query_ip: ip,
      search_term: r7Data.search_term,
      subnet_mode: r7Data.subnet_mode,
      hours_back: r7Data.hours_back,
      total_events: r7Data.total_events,
      unique_users: annotated.length,
      watched_hits: watchedHits.length,
      other_hits: otherHits.length,
      watched_users: watchedHits,
      other_users: otherHits.slice(0, 20), // cap non-watched at 20
      logsets: r7Data.logsets,
    });
  } catch (e) {
    const timedOut = e.name === 'TimeoutError' || e.name === 'AbortError';
    res.status(timedOut ? 504 : 502).json({ ok: false,
      error: timedOut ? 'Rapid7 enrichment timed out' : 'Rapid7 enrichment unavailable' });
  }
});

// ── v2.1.1: Re-push alert to channels ────────────────────────────────
router.post('/violations/:id/repush', async (req, res) => {
  const violId = parseInt(req.params.id, 10);
  try {
    const [rows] = await pool.query('SELECT * FROM signin_violations WHERE id = ?', [violId]);
    if (!rows.length) return res.status(404).json({ ok: false, error: 'violation not found' });
    const v = rows[0];

    // look up tier + pause ticket from watchlist
    const [wl] = await pool.query(
      "SELECT tier, pause_ticket_display, pause_ticket_url FROM signin_watchlist WHERE upn = ? LIMIT 1", [v.upn]);
    const tier = wl.length ? (wl[0].tier || 'standard') : 'standard';
    // ticket shown on the card: the violation's own SDP ticket wins, else the account pause ticket
    let ticket_display = null, ticket_url = null;
    if (v.sdp_ticket_id) { ticket_display = String(v.sdp_ticket_display || v.sdp_ticket_id); ticket_url = v.sdp_ticket_url || null; }
    else if (wl.length && wl[0].pause_ticket_display) { ticket_display = wl[0].pause_ticket_display; ticket_url = wl[0].pause_ticket_url || null; }

    // build dispatch payload from stored violation
    let snapshot = null;
    if (v.auto_investigation) {
      try { snapshot = typeof v.auto_investigation === 'object' ? v.auto_investigation : JSON.parse(v.auto_investigation); } catch (e) {}
    }

    // extract fields from raw_json
    let ca_status = null, resource = null, device_managed = null, device_id = null;
    try {
      const raw = typeof v.raw_json === 'object' ? v.raw_json : JSON.parse(v.raw_json || '{}');
      ca_status = raw.conditionalAccessStatus || null;
      resource = raw.resourceDisplayName || null;
      device_managed = raw.deviceDetail ? raw.deviceDetail.isManaged : null;
      device_id = raw.deviceDetail ? (raw.deviceDetail.deviceId || null) : null;
    } catch (e) {}

    const payload = {
      upn: v.upn,
      source: v.source,
      result: v.result,
      event_time: v.event_time,
      ip: v.ip,
      geo_country: v.geo_country,
      geo_city: v.geo_city,
      geo_asn: v.geo_asn,
      geo_isp: v.geo_isp,
      failure_reason: v.failure_reason,
      app_name: v.app_name,
      client_app: v.client_app,
      tier,
      ca_status,
      resource,
      device_managed,
      device_id,
      snapshot,
      violation_id: v.id,
      ticket_display,
      ticket_url,
      repush: true,
    };

    const { dispatch } = require('./alert-dispatch');
    const out = await dispatch(pool, payload);

    // update alert tracking
    await pool.query(
      'UPDATE signin_violations SET alert_sent = 1, alert_channels_hit = ? WHERE id = ?',
      [JSON.stringify({ sent: out.sent, failed: out.failed, repushed_at: new Date().toISOString() }).slice(0, 500), violId]);

    res.json({ ok: true, sent: out.sent, failed: out.failed });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

module.exports = router;
