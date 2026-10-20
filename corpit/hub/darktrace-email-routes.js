'use strict';
// DARKTRACE-EMAIL 2026-10-14 — console API for Darktrace /EMAIL data.
// Mounted at /api/sentinel/darktrace-email (server.js, before /api/sentinel), so it rides
// the existing /api/sentinel/ proxy on the corpit vhost. The /api blanket in server.js
// has already run loadCurrentUser.
//
// Access (Jeramy 2026-10-14):
//   data routes  — SaaS-ITH-HD only: an active user holding the tier2 role. No super-admin bypass.
//   /config      — Hub super admin (requireSuperAdmin, audited), the same gate as the other
//                  Hub editors folded into subadmin Settings. Tokens are write-only: no route
//                  returns them and the audit row records only (set)/(changed)/(cleared).
// Reads come from the hub tables darktrace-email-sync.js fills; only /config/test calls
// Darktrace from a request, and only with read-only calls.

const express = require('express');
const router = express.Router();
const lib = require('./darktrace-email-lib');
const SA = require('./settings-audit');
const createRbac = require('./rbac-middleware');

const pool = lib.pool();
const rbac = createRbac(pool);
const PAGE_KEY = 'darktrace-email';
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const DAY = 86400000;

router.use(require('./schema/readiness').requireSchema('darktrace-email'));

function fail(res, e) { res.status(500).json({ ok: false, error: (e && e.message) || String(e) }); }

async function latestRun(okOnly) {
  const [rows] = await pool.query(
    'SELECT id, started_at, finished_at, state, held_7d, junk_7d, critical_7d, threats_7d, inbound_7d, messages, rcpts, ' +
    'dlp_rows, anomaly_rows, audit_new, pages, note FROM dt_email_run ' +
    (okOnly ? "WHERE state IN ('ok','partial') " : '') + 'ORDER BY id DESC LIMIT 1');
  return rows[0] || null;
}

// ── settings (super admin) ─────────────────────────────────────────────────
const cfgRouter = express.Router();
cfgRouter.use(rbac.requireSuperAdmin);
const CFG_KEYS = ['enabled', 'host', 'cadence_min', 'public_token', 'private_token'];
const CFG_SECRET = ['public_token', 'private_token'];

cfgRouter.get('/', async (req, res) => {
  try {
    const cfg = await lib.loadConfig(pool);
    res.json({ ok: true, config: lib.publicConfig(cfg), configured: lib.configured(cfg),
               console_url: lib.consoleUrl(cfg), last_run: await latestRun(false) });
  } catch (e) { fail(res, e); }
});

cfgRouter.put('/', async (req, res) => {
  const b = req.body || {}, set = {};
  if ('enabled' in b) set.enabled = (b.enabled === true || b.enabled === 1 || b.enabled === '1' || b.enabled === 'true') ? 1 : 0;
  if ('host' in b) {
    const h = String(b.host == null ? '' : b.host).trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (h && !lib.HOST_RE.test(h)) return res.status(400).json({ ok: false, error: 'Host must be a host name such as azeus1-30575-01.cloud.darktrace.com' });
    set.host = h || null;
  }
  if ('cadence_min' in b) {
    const n = Number(b.cadence_min);
    if (!Number.isInteger(n) || n < 15 || n > 1440) return res.status(400).json({ ok: false, error: 'Pull interval must be a whole number of minutes from 15 to 1440' });
    set.cadence_min = n;
  }
  for (const k of CFG_SECRET) {
    if (!(k in b)) continue;
    const v = b[k] == null ? '' : String(b[k]).trim();
    if (v.length > 200 || /\s/.test(v)) return res.status(400).json({ ok: false, error: k.replace('_', ' ') + ' is not a token' });
    set[k] = v || null;                       // '' clears
  }
  const keys = Object.keys(set);
  if (!keys.length) return res.status(400).json({ ok: false, error: 'nothing to save' });
  try {
    const before = await SA.snap(pool, 'SELECT ' + CFG_KEYS.join(', ') + ' FROM dt_email_config WHERE id = 1');
    const cols = keys.concat('updated_by');
    const vals = keys.map(k => set[k]).concat(req.user.email || null);
    await pool.query(
      'INSERT INTO dt_email_config (id, ' + cols.join(', ') + ') VALUES (1, ' + cols.map(() => '?').join(', ') + ') ' +
      'ON DUPLICATE KEY UPDATE ' + cols.map(c => c + '=VALUES(' + c + ')').join(', '), vals);
    const after = await SA.snap(pool, 'SELECT ' + CFG_KEYS.join(', ') + ' FROM dt_email_config WHERE id = 1');
    await SA.record(rbac, req, PAGE_KEY, 'settings_saved', SA.entry({ what: 'darktrace-email config', id: 1,
      before, after, keys: CFG_KEYS, secretKeys: CFG_SECRET }));
    const cfg = await lib.loadConfig(pool);
    res.json({ ok: true, config: lib.publicConfig(cfg), configured: lib.configured(cfg) });
  } catch (e) { fail(res, e); }
});

// Uses the SAVED settings: one GET (dash/threat_data, last hour) and one search page.
cfgRouter.post('/test', async (req, res) => {
  const cfg = await lib.loadConfig(pool).catch(() => null);
  if (!lib.configured(cfg)) return res.status(400).json({ ok: false, error: 'Save the host and both tokens first.' });
  const now = Date.now();
  async function step(fn) {
    const t = Date.now();
    try { await fn(); return { ok: true, ms: Date.now() - t }; }
    catch (e) { return { ok: false, ms: Date.now() - t, status: e.status || null, error: e.message }; }
  }
  const getR = await step(() => lib.get(cfg, 'dash/threat_data', { start: now - 3600000, end: now, domains: '' }));
  const searchR = await step(() => lib.post(cfg, 'emails/search', { itemsPerPage: 1, page: 0, timeFrom: now - 3600000, timeTo: now,
    query: { mode: 'and', criteriaList: [{ apiFilter: 'rcpt_rcpt_status', operator: '=', value: 'held' }] } }));
  const ok = getR.ok && searchR.ok;
  await SA.record(rbac, req, PAGE_KEY, ok ? 'settings_test_sent' : 'settings_test_failed',
    SA.entry({ what: 'darktrace-email connection test', op: 'test', extra: { get_ok: getR.ok, search_ok: searchR.ok } }));
  res.json({ ok: true, passed: ok, get: getR, search: searchR });
});

router.use('/config', cfgRouter);

// ── data (SaaS-ITH-HD only) ──────────────────────────────────────────────────
router.use(function (req, res, next) {
  const u = req.user;
  if (!u) return res.status(401).json({ ok: false, error: 'AUTH_REQUIRED' });
  if (u.isActive === true && Array.isArray(u.roles) && u.roles.indexOf('tier2') !== -1) return next();
  return res.status(403).json({ ok: false, error: 'FORBIDDEN', detail: 'Darktrace email data is limited to SaaS-ITH-HD.' });
});

router.get('/status', async (req, res) => {
  try {
    const cfg = await lib.loadConfig(pool);
    const pc = lib.publicConfig(cfg);
    res.json({ ok: true, enabled: pc.enabled, configured: lib.configured(cfg), cadence_min: pc.cadence_min, last_run: await latestRun(false) });
  } catch (e) { fail(res, e); }
});

router.get('/kpis', async (req, res) => {
  try {
    const r = await latestRun(true);
    const cfg = await lib.loadConfig(pool);
    res.json({ ok: true, as_of: r ? r.finished_at : null, state: r ? r.state : null, window_days: 7,
      held: r ? r.held_7d : null, critical: r ? r.critical_7d : null, threats: r ? r.threats_7d : null,
      inbound: r ? r.inbound_7d : null, console_url: lib.consoleUrl(cfg) });
  } catch (e) { fail(res, e); }
});

// One person: held / junk mail addressed to them in the last 7 days (as of the last
// run), and their row on the anomaly list, if any.
router.get('/user', async (req, res) => {
  const email = String(req.query.email || '').trim().toLowerCase();
  if (!EMAIL_RE.test(email) || email.length > 320) return res.status(400).json({ ok: false, error: 'email required' });
  try {
    const r = await latestRun(true);
    if (!r) return res.json({ ok: true, email, as_of: null, held: null, junk: null, recent: [], anomaly: null });
    const since = new Date(new Date(r.started_at).getTime() - 7 * DAY);
    const [cnt] = await pool.query(
      `SELECT x.rcpt_status s, COUNT(DISTINCT x.uuid) n FROM dt_email_rcpt x JOIN dt_email_message m ON m.uuid = x.uuid
        WHERE x.rcpt_to = ? AND x.seen_run_id = ? AND m.dtime >= ? AND x.rcpt_status IN ('held','junk') GROUP BY x.rcpt_status`,
      [email, r.id, since]);
    const [recent] = await pool.query(
      `SELECT m.dtime, m.from_email, m.from_name, m.subject, m.model_score, m.is_critical, x.rcpt_status
         FROM dt_email_rcpt x JOIN dt_email_message m ON m.uuid = x.uuid
        WHERE x.rcpt_to = ? AND x.seen_run_id = ? AND m.dtime >= ? AND x.rcpt_status IN ('held','junk')
        ORDER BY m.dtime DESC LIMIT 10`, [email, r.id, since]);
    const [an] = await pool.query(
      'SELECT mailbox, n_emails, n_attachments, n_links, n_last_period, n_last_week, percentage, total_emails FROM dt_email_anomaly WHERE mailbox = ?', [email]);
    const by = {}; for (const c of cnt) by[c.s] = Number(c.n);
    res.json({ ok: true, email, as_of: r.finished_at, held: by.held || 0, junk: by.junk || 0, recent, anomaly: an[0] || null });
  } catch (e) { fail(res, e); }
});

router.get('/dlp', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT sender, n_emails, n_attachments, n_rcpts, total_emails, run_id FROM dt_email_dlp ORDER BY n_emails DESC, sender');
    res.json({ ok: true, rows });
  } catch (e) { fail(res, e); }
});

router.get('/anomaly', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT mailbox, n_emails, n_attachments, n_links, n_last_period, n_last_week, percentage, total_emails, run_id FROM dt_email_anomaly ORDER BY percentage DESC, mailbox');
    res.json({ ok: true, rows });
  } catch (e) { fail(res, e); }
});

router.get('/audit', async (req, res) => {
  const days = Math.min(90, Math.max(1, parseInt(req.query.days, 10) || 7));
  try {
    const [rows] = await pool.query(
      'SELECT uuid, event_at, event, account_id, tid, provider FROM dt_email_audit WHERE event_at >= NOW() - INTERVAL ? DAY ORDER BY event_at DESC LIMIT 1000', [days]);
    res.json({ ok: true, days, rows });
  } catch (e) { fail(res, e); }
});

module.exports = router;
