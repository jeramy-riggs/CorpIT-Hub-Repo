// Feed freshness — is the data behind a page actually being collected on this host?
//
// Why this exists: 42 collector scripts are deployed to corpit and only a handful
// are scheduled. Tables seeded from the ITAM dump therefore stop advancing, and
// every endpoint that windows "the last N hours" over one of them returns zero
// rows. A zero row count is then rendered as an all-clear -- "No failed sign-ins",
// "No active incidents", "No DLP hits" -- when the truth is that nothing has been
// collected since the seed. That is the same false-green defect class that let
// Cert Watchtower report ok/142d for four months after its cron died.
//
// This route reports, per feed, the age of the newest row against the cadence the
// feed is supposed to keep, and it distinguishes four states rather than two:
//
//   ok      measured, and within cadence
//   stale   measured, and older than cadence
//   empty   measured, and the table has no rows at all on this host
//   unknown NOT measured -- the query failed, or a sparse feed has no recorded
//           collector run. Never reported as ok or stale.
//
// A feed may additionally carry quiet:true, meaning it is a sparse feed whose
// collector is current and simply had nothing to record. state is 'ok' and
// lastEventAgeHours says how long it has been quiet.
//
// Mount: app.use('/api/feeds', require('./feed-freshness-routes'));
// Deliberately NOT mounted under /api/system: that router gates every path on a
// 'server-health' read grant, which would 403 a user of Identity Diagnostics or
// SharePoint Governance who legitimately needs to know their own page is stale.

const express = require('express');
const mysql = require('mysql2/promise');
const HOST = require('os').hostname();   // srv_job_run carries rows imported from ITAM (host NULL); only this host's runs count

const router = express.Router();

const pool = mysql.createPool({
  host:               process.env.DB_HOST,
  port:               parseInt(process.env.DB_PORT) || 3306,
  database:           process.env.DB_NAME,
  user:               process.env.DB_USER,
  password:           process.env.DB_PASSWORD,
  waitForConnections: true,
  connectionLimit:    3,
  charset:            'utf8mb4',
});

// ── Registry ────────────────────────────────────────────────────────────────
// maxAgeH is the cadence the feed is meant to keep, not a guess at how fresh it
// happens to be. `collector` names the script that populates it so the banner can
// say what is not running rather than only that something is wrong.
const FEEDS = [
  // Identity Diagnostics
  { key:'entra_signin_logs',      page:['identity-diag','signin-watch'], label:'Entra sign-in logs',
    table:'corpit_hub.entra_signin_logs',      ts:'created_at',      maxAgeH:6,   collector:'entra-sync.js' },
  { key:'signin_violations',      page:['identity-diag','signin-watch'], label:'Sign-in violations',
    table:'corpit_hub.signin_violations',      ts:'event_time',      maxAgeH:6,   collector:'signin-watch-job.js' },
  { key:'sdops_spray',            page:'identity-diag',        label:'Password-spray detections',
    table:'corpit_hub.sdops_spray',            ts:'last_seen',       maxAgeH:2,   collector:'collect-spray.js' },
  { key:'sdops_lockout',          page:['identity-diag','tenant-sentinel'], label:'Account lockouts',
    table:'corpit_hub.sdops_lockout',          ts:'created_at',      maxAgeH:6,   collector:'collect-lockouts.js' },
  { key:'sdops_ad_auth_event',    page:'identity-diag',        label:'AD authentication events',
    table:'corpit_hub.sdops_ad_auth_event',    ts:'collected_at',    maxAgeH:6,   collector:'collect-ad-auth-events.js' },

  // SharePoint Governance
  { key:'dlp_alerts',             page:'sharepoint-governance', label:'DLP alerts',
    table:'corpit_hub.dlp_alerts',             ts:'last_seen',       maxAgeH:24,  collector:'dlp-search-sync.js' },
  { key:'site_storage_snapshots', page:'sharepoint-governance', label:'Site storage snapshots',
    table:'corpit_hub.site_storage_snapshots', ts:'created_at',      maxAgeH:24,  collector:'site-storage-collect-job.js' },
  { key:'department_site_folders',page:'sharepoint-governance', label:'Department folder walk',
    table:'corpit_hub.department_site_folders',ts:'created_at',      maxAgeH:24,  collector:'dept-folder-walk-job.js' },
  { key:'sentinel_sp_site',       page:['sharepoint-governance','tenant-sentinel'], label:'M365 SharePoint site reports',
    table:'corpit_hub.sentinel_sp_site',       ts:'collected_at',    maxAgeH:24,  collector:'collect-m365-reports.js' },
  { key:'file_inventory_runs',    page:'sharepoint-governance', label:'File inventory crawl',
    table:'corpit_hub.file_inventory_runs',    ts:'finished_at',     maxAgeH:26,  collector:'stale-crawl-job.js' },
  { key:'storage_snapshots',       page:'sharepoint-governance', label:'Storage growth snapshots',
    table:'corpit_hub.storage_snapshots',      ts:'snap_date',       maxAgeH:48,  collector:'storage-collect-job.js' },
  { key:'sp_label_scan_runs',     page:'sharepoint-governance', label:'Retention label scan',
    table:'corpit_hub.sp_label_scan_runs',     ts:'finished_at',     maxAgeH:26,  collector:'sp-label-scan-job.js' },

  // Zscaler Command Center
  { key:'zcc_devices',            page:'zscaler-command-center', label:'ZCC enrolled devices',
    table:'corpit_hub.zcc_devices',            ts:'updated_at',      maxAgeH:24,  collector:'zcc-devices-sync.js' },
  { key:'zdx_presence_geo',       page:'zscaler-command-center', label:'ZDX presence / geo',
    table:'corpit_hub.zdx_presence_geo',       ts:'updated_at',      maxAgeH:24,  collector:'zdx-presence-sync.js' },
  { key:'zdx_user_isp',           page:'zscaler-command-center', label:'ZDX user ISP',
    table:'corpit_hub.zdx_user_isp',           ts:'updated_at',      maxAgeH:24,  collector:'zdx-isp-crawl.js' },

  // Cert Watchtower  (it_inventory DB; cron runs from /var/www/api)
  { key:'cert_current',           page:'cert-watchtower',      label:'Certificate inventory',
    table:'it_inventory.cert_current',         ts:'last_checked_at', maxAgeH:26,  collector:'cert-watchtower-cron.js' },
  { key:'cert_checks',            page:'cert-watchtower',      label:'Certificate check history',
    table:'it_inventory.cert_checks',          ts:'checked_at',      maxAgeH:26,  collector:'cert-watchtower-cron.js' },

  // M365 Control Center (tenant-sentinel)
  // The page's score, grade and four headline tiles are all computed over these
  // tables. With none of the collectors scheduled here they stop advancing, the
  // windowed queries return zero, and the page renders "0 lockouts", "no
  // critical findings" and a green "live" pill over feeds that are two weeks
  // old. The page's own /api/sentinel/freshness view carries the full 21-source
  // detail; these are the ones that decide the headline.
  { key:'sentinel_legacy_signin', page:'tenant-sentinel',      label:'Legacy auth sign-ins',
    table:'corpit_hub.sentinel_legacy_signin', ts:'created_at',      maxAgeH:6,   collector:'collect-legacy-auth.js' },
  { key:'entra_users',            page:'tenant-sentinel',      label:'Entra ID users',
    table:'corpit_hub.entra_users',            ts:'last_synced_at',  maxAgeH:24,  collector:'entra-sync.js' },
  { key:'okta_users',             page:['tenant-sentinel','okta-dashboard'], label:'Okta users',
    table:'corpit_hub.okta_users',             ts:'last_synced_at',  maxAgeH:24,  collector:'collect-okta-users.js' },
  { key:'okta_user_factors',      page:['tenant-sentinel','okta-dashboard'], label:'Okta MFA factor enrolment',
    table:'corpit_hub.okta_user_factors',      ts:'last_synced_at',  maxAgeH:24,  collector:'collect-okta-factors.js' },
  // [CORPIT 2026-09-10] Okta -> Entra CA migration snapshot, ported from ITAM.
  // Root crontab 05:36; ITAM runs its own copy at 04:15 against the same tenants.
  { key:'oem_okta_policy',        page:['okta-entra-migration'], label:'Okta -> Entra CA snapshot',
    table:'corpit_hub.oem_okta_policy',        ts:'collected_at',    maxAgeH:24,  collector:'collect-okta-entra.js' },
  // [CORPIT 2026-09-07] okta_apps was in no registry. okta-sync.js only ran from
  // an in-process scheduler that fires inside one wall-clock minute (04:00) and
  // never survived a syncs-worker restart on this host, so the table held ITAM's
  // 2026-08-27 seed for eleven days while the page would have shown it as fact.
  // It now runs from cron (okta-apps-sync-job.js, 04:40) and is measured here.
  { key:'okta_apps',              page:['okta-dashboard'],     label:'Okta applications',
    table:'corpit_hub.okta_apps',              ts:'last_synced_at',  maxAgeH:24,  collector:'okta-apps-sync-job.js' },
  { key:'priv_role_assignment',   page:'tenant-sentinel',      label:'Entra directory role assignments',
    table:'corpit_hub.priv_role_assignment',   ts:'collected_at',    maxAgeH:24,  collector:'collect-priv-roles.js' },
  { key:'sentinel_secure_score',  page:'tenant-sentinel',      label:'Microsoft Secure Score',
    table:'corpit_hub.sentinel_secure_score',  ts:'collected_at',    maxAgeH:24,  collector:'collect-defender.js' },
  { key:'sentinel_risky_user',    page:'tenant-sentinel',      label:'Defender risky users',
    table:'corpit_hub.sentinel_risky_user',    ts:'collected_at',    maxAgeH:24,  collector:'collect-defender.js' },
  { key:'sentinel_incident',      page:'tenant-sentinel',      label:'Defender incidents',
    table:'corpit_hub.sentinel_incident',      ts:'collected_at',    maxAgeH:24,  collector:'collect-incidents.js' },
  { key:'sentinel_intune_device', page:'tenant-sentinel',      label:'Intune devices',
    table:'corpit_hub.sentinel_intune_device', ts:'collected_at',    maxAgeH:24,  collector:'collect-intune.js' },
  { key:'sentinel_mailbox_usage', page:'tenant-sentinel',      label:'Mailbox usage reports',
    table:'corpit_hub.sentinel_mailbox_usage', ts:'collected_at',    maxAgeH:24,  collector:'collect-m365-reports.js' },
  { key:'sentinel_score_history', page:'tenant-sentinel',      label:'Nightly score snapshot',
    table:'corpit_hub.sentinel_score_history', ts:'snapshot_date',   maxAgeH:48,  collector:'snapshot-history-job.js' },

  // Server Health
  { key:'srv_vhost_current',      page:'server-health',        label:'Virtual-host probes',
    table:'corpit_hub.srv_vhost_current',      ts:'checked_at',      maxAgeH:1,   collector:'vhost-health-job.js' },
  { key:'server_health_snapshots',page:'server-health',        label:'Host health snapshots',
    table:'corpit_hub.server_health_snapshots',ts:'created_at',      maxAgeH:26,  collector:'health-snapshot-job.js' },
  // [CORPIT-QA 2026-09-07] Backs tenant-sentinel's "Tenant changes" view. It was
  // consumed but unregistered, so the page's own freshness banner could not see
  // it and the view labelled a 10-day-stale window "the last 30 days".
  { key:'entra_audit_logs',       page:'tenant-sentinel',      label:'Entra audit logs',
    table:'corpit_hub.entra_audit_logs',       ts:'activity_date_time', maxAgeH:6, collector:'entra-sync.js' },
  // Tenant insights (licences, per-user activity, service principals) are read
  // by tenant-sentinel but were never registered here, so a frozen collector
  // looked like fresh data.
  { key:'insight_sku',            page:'tenant-sentinel',      label:'M365 licence SKUs',
    table:'corpit_hub.insight_sku',            ts:'collected_at',       maxAgeH:48, collector:'collect-tenant-insights.js' },
  { key:'insight_user_activity',  page:'tenant-sentinel',      label:'M365 per-user activity',
    table:'corpit_hub.insight_user_activity',  ts:'collected_at',       maxAgeH:48, collector:'collect-tenant-insights.js' },
  { key:'insight_service_principal', page:'tenant-sentinel',   label:'Service principals',
    table:'corpit_hub.insight_service_principal', ts:'collected_at',    maxAgeH:48, collector:'collect-tenant-insights.js' },
];

// MAX() over a non-indexed column on a multi-hundred-thousand-row table is a full
// scan, so the whole set is cached rather than recomputed per page load.
const TTL_MS = 5 * 60 * 1000;
let cache = null;
let snapshotInFlight = null;

// Identifiers come only from the FEEDS table above, never from the request, so
// they are safe to interpolate. Values are still parameterised everywhere else.
const IDENT = /^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)?$/;

// ── Sparse feeds ────────────────────────────────────────────────────────────
// Feeds whose tables hold discrete events that may legitimately not occur. For
// these, an old newest-row measures the world rather than the pipeline, so
// health is taken from the last successful collector run instead.
//
// runMaxAgeH is the collector's schedule plus slack, NOT the data cadence:
//   collect-spray.js        3 * * * *     hourly        -> 2
//   collect-lockouts.js     21 */2 * * *  every 2 hours -> 3
//   collect-legacy-auth.js  13 */2 * * *  every 2 hours -> 3
//   collect-defender.js     20 4 * * *    daily         -> 26
//   collect-incidents.js    38 4 * * *    daily         -> 26
//
// Deliberately NOT applied to high-volume feeds (entra_signin_logs,
// sdops_ad_auth_event, entra_audit_logs). There a gap in rows really does mean
// something broke, and moving them to run-based health would hide a collector
// that runs, succeeds, and returns nothing because its query is wrong.
const SPARSE = {
  sdops_spray:            { runMaxAgeH: 2  },
  sdops_lockout:          { runMaxAgeH: 3  },
  sentinel_legacy_signin: { runMaxAgeH: 3  },
  sentinel_risky_user:    { runMaxAgeH: 26 },
  sentinel_incident:      { runMaxAgeH: 26 },
};

async function measure(f) {
  const base = {
    key: f.key, page: f.page, label: f.label, table: f.table,
    maxAgeHours: f.maxAgeH, collector: f.collector,
  };
  if (!IDENT.test(f.table) || !IDENT.test(f.ts)) {
    return Object.assign({}, base, { state: 'unknown', error: 'registry entry is not a valid identifier' });
  }
  try {
    const [rows] = await pool.query(
      'SELECT COUNT(*) AS n, MAX(`' + f.ts + '`) AS newest, ' +
      'TIMESTAMPDIFF(MINUTE, MAX(`' + f.ts + '`), NOW()) AS age_min FROM ' + f.table
    );
    const r = rows[0] || {};
    const n = Number(r.n || 0);
    if (n === 0) {
      return Object.assign({}, base, { state: 'empty', rows: 0, newest: null, ageHours: null });
    }
    if (r.newest == null || r.age_min == null) {
      // Rows exist but every timestamp is NULL: measured, but says nothing about age.
      return Object.assign({}, base, {
        state: 'unknown', rows: n, newest: null, ageHours: null,
        error: 'rows present but ' + f.ts + ' is NULL on every row',
      });
    }
    const ageH = Number(r.age_min) / 60;
    return Object.assign({}, base, {
      rows: n,
      newest: r.newest,
      ageHours: Math.round(ageH * 10) / 10,
      state: ageH > f.maxAgeH ? 'stale' : 'ok',
    });
  } catch (e) {
    // Could not measure. This is NOT 'ok' and NOT 'stale'.
    return Object.assign({}, base, { state: 'unknown', error: e.code || e.message });
  }
}

// The last recorded run of every job, keyed by the name cronwrap writes (which
// is the same string the registry above stores in `collector`).
//
// This exists because measure() above answers only "how old is the newest row",
// and that question cannot distinguish a collector that finished from one that
// died a third of the way in: MAX(ts) goes current the moment the FIRST row
// lands. A dlp-search-sync killed at 3,151 of 25,000 rows left the feed
// reporting 0.1h old and state 'ok' over a table that was 12% rebuilt.
//
// Deliberately NOT folded into `state`. `state` means one thing -- how old the
// data is -- and every consumer reads `state !== 'ok'` as "stale", then renders
// an age from it. A fresh-but-failing feed has an age of nearly zero, so
// overloading the enum would print "0h behind" for a problem that is not about
// age at all. It is a separate signal because it is a separate fact.
// Longest a job may legitimately sit in 'running'. The slowest job here is
// stale-crawl-job.js at ~7.6h, so 12 leaves headroom without letting a run that
// died at midnight still claim to be running the next evening.
const STUCK_AFTER_H = 12;

async function lastRuns() {
  try {
    const [rows] = await pool.query(
      'SELECT j.job_name, j.state, j.finished_at, j.started_at, j.exit_code, ' +
      '       TIMESTAMPDIFF(MINUTE, j.finished_at, NOW()) AS age_min, ' +
      '       TIMESTAMPDIFF(MINUTE, j.started_at,  NOW()) AS start_age_min ' +
      'FROM srv_job_run j ' +
      'JOIN (SELECT job_name, MAX(id) AS id FROM srv_job_run WHERE host = ? GROUP BY job_name) m ' +
      '  ON m.id = j.id', [HOST]);
    const by = {};
    for (const r of rows) {
      // A 'running' row older than STUCK_AFTER_H is not a run in progress. It is
      // a run that was killed before it could record an outcome, and saying
      // 'running' about it is a false status -- the reader takes it as healthy.
      const startAgeH = r.start_age_min == null ? null : Number(r.start_age_min) / 60;
      const stuck = r.state === 'running' && r.finished_at == null &&
                    startAgeH != null && startAgeH > STUCK_AFTER_H;
      by[r.job_name] = {
        state: stuck ? 'abandoned' : r.state,
        finishedAt: r.finished_at,
        startedAt: r.started_at,
        exitCode: r.exit_code,
        ageHours: r.age_min == null ? null : Math.round(Number(r.age_min) / 6) / 10,
        // For a run with no finish, age is measured from its start -- otherwise
        // an abandoned run reports a null age and reads as "no information".
        startAgeHours: startAgeH == null ? null : Math.round(startAgeH * 10) / 10,
      };
      if (stuck) by[r.job_name].abandoned = true;
    }
    return by;
  } catch (e) {
    // Could not read the run log. That is not evidence of success OR failure,
    // so every feed gets lastRun:null and nobody is accused of failing.
    return null;
  }
}

async function snapshot() {
  if (cache && (Date.now() - cache.at) < TTL_MS) return cache.data;
  // Many dashboards ask for the same snapshot at once. Share the cold refresh
  // so they do not each scan every feed table. A rejected refresh can retry.
  if (snapshotInFlight) return snapshotInFlight;
  snapshotInFlight = buildSnapshot().finally(function () { snapshotInFlight = null; });
  return snapshotInFlight;
}

async function buildSnapshot() {
  // These measurements are independent. The pool's three-connection limit
  // bounds database concurrency while allowing the independent scans to run
  // together instead of making every page wait for their summed latency.
  const [feeds, runs] = await Promise.all([
    Promise.all(FEEDS.map(measure)),
    lastRuns(),
  ]);
  for (const f of feeds) {
    const r = runs && f.collector ? runs[f.collector] : null;
    f.lastRun = r || null;
    // Only an explicitly recorded failure counts. No record at all means the
    // job has not run since the run log started -- unknown, not failing.
    f.producerFailing = !!(r && r.state === 'failed');
    // Counted apart from producerFailing: a job that died without recording an
    // outcome never reports 'failed', so it would otherwise be invisible.
    f.producerAbandoned = !!(r && r.abandoned);

    // The third producer fault, and the quietest one. The last run SUCCEEDED,
    // so neither flag above is set, and the rows it wrote may still be young
    // enough for state 'ok' -- while the collector has missed its window and
    // nothing new is arriving. Judged only where runMaxAgeH is declared; a
    // threshold invented for an uncharacterised schedule manufactures alarms.
    const runSpec = SPARSE[f.key];
    f.producerOverdue = !!(runSpec && r && r.finishedAt != null &&
                           r.ageHours != null && r.ageHours > runSpec.runMaxAgeH);
    if (f.producerOverdue) {
      f.producerOverdueBy = {
        lastSuccessAgeHours: r.ageHours,
        expectedWithinHours: runSpec.runMaxAgeH,
      };
    }

    // A sparse feed with no recent rows is either quiet or dead, and row age
    // cannot tell them apart. Ask the run log instead.
    const spec = SPARSE[f.key];
    if (spec && (f.state === 'stale' || f.state === 'empty')) {
      f.sparse = true;
      f.lastEventAgeHours = f.ageHours;          // kept: "quiet for N hours"
      if (!r || r.finishedAt == null) {
        // Never run here. That is not evidence the feed is fine.
        f.state = 'unknown';
        f.error = 'no recorded run of ' + f.collector;
      } else if (r.state === 'success' && r.ageHours != null && r.ageHours <= spec.runMaxAgeH) {
        f.state = 'ok';
        f.quiet = true;
        f.quietReason = 'collector ran ' + r.ageHours + 'h ago and found nothing to record';
      }
      // else: the collector itself is overdue or failed. state stays stale/empty
      // because the rows really are old -- but producerOverdue/producerFailing
      // above now name WHY, so the banner stops implying a data-pipeline fault
      // for a collector that did not run.
    }
  }
  const count = feeds.reduce(function (a, f) { a[f.state] = (a[f.state] || 0) + 1; return a; }, {});
  const data = {
    measuredAt: new Date().toISOString(),
    feeds: feeds,
    count: count,
    // 'degraded' covers anything that is not a measured-and-current feed.
    degraded: feeds.filter(function (f) { return f.state !== 'ok'; }).length,
    // Counted separately: these feeds may look current and still be partial.
    producerFailing: feeds.filter(function (f) { return f.producerFailing; }).length,
    producerAbandoned: feeds.filter(function (f) { return f.producerAbandoned; }).length,
    producerOverdue: feeds.filter(function (f) { return f.producerOverdue; }).length,
  };
  cache = { at: Date.now(), data: data };
  return data;
}

// ── Access control ──────────────────────────────────────────────────────────
// Any signed-in user may read this: it reports only table names, row counts and
// timestamps for feeds they already see rendered, and every page needs it to be
// able to tell the truth about its own data. loadCurrentUser does not reject on
// its own -- it sets req.user = null -- so the check is explicit.
const createRbac = require('./rbac-middleware');
const rbac = createRbac(pool);
router.use(rbac.loadCurrentUser);
router.use(function (req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'authentication required' });
  next();
});

// GET /api/feeds/freshness[?page=identity-diag]
router.get('/freshness', async function (req, res) {
  try {
    const data = await snapshot();
    const page = (req.query.page || '').trim();
    if (!page) return res.json(data);
    // `page` may be a string or a list: a feed can back more than one console
    // (entra_signin_logs and signin_violations feed both identity-diag and
    // signin-watch). An equality test silently returned zero feeds for the
    // page that was not named, and zero feeds renders no banner -- which a
    // reader cannot tell apart from "all feeds fresh".
    const feeds = data.feeds.filter(function (f) {
      return Array.isArray(f.page) ? f.page.indexOf(page) !== -1 : f.page === page;
    });
    return res.json({
      measuredAt: data.measuredAt,
      page: page,
      feeds: feeds,
      count: feeds.reduce(function (a, f) { a[f.state] = (a[f.state] || 0) + 1; return a; }, {}),
      degraded: feeds.filter(function (f) { return f.state !== 'ok'; }).length,
      producerFailing: feeds.filter(function (f) { return f.producerFailing; }).length,
      producerAbandoned: feeds.filter(function (f) { return f.producerAbandoned; }).length,
      producerOverdue: feeds.filter(function (f) { return f.producerOverdue; }).length,
    });
  } catch (e) {
    return res.status(500).json({ error: 'freshness query failed', message: e.message });
  }
});

module.exports = router;
