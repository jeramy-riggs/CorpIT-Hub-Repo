// =============================================================================
// okta-sync.js — Okta Apps → MySQL sync for matching against Entra
//
// Mirrors /api/v1/apps into corpit_hub.okta_apps.
// Runs via scheduler (daily at 4 AM) or manual trigger.
// Reuses entra_sync_status table for bookkeeping (job='okta_apps').
// =============================================================================

const mysql = require('mysql2/promise');

// Config
const OKTA_BASE_URL  = process.env.OKTA_BASE_URL;
const OKTA_API_TOKEN = process.env.OKTA_API_TOKEN;

// Reuse same DB pool pattern as entra-sync; share it via require
const entraSync = require('./entra-sync');
const db = entraSync.db;
// Rescan R4: a job's AbortSignal aborts when its sync lock is lost; stopIfLost(signal) throws the
// lock-lost error at each safe point, before the next write.
const stopIfLost = require('./sync-lock').throwIfLost;

const nil = v => (v === undefined ? null : v);
const sleep = ms => new Promise(r => setTimeout(r, ms));

let graphCallCount = 0;  // reused name for consistency with entra-sync bookkeeping

// -----------------------------------------------------------------------------
// Okta HTTP helper with rate-limit handling
// -----------------------------------------------------------------------------
async function oktaFetch(url, _attempts = 0) {
  if (!OKTA_BASE_URL || !OKTA_API_TOKEN) {
    throw new Error('Okta credentials not configured (OKTA_BASE_URL / OKTA_API_TOKEN)');
  }
  const res = await fetch(url, {
    headers: {
      Authorization: 'SSWS ' + OKTA_API_TOKEN,
      Accept: 'application/json'
    }
  });
  graphCallCount++;

  if (res.status === 429) {
    if (_attempts >= 4) throw new Error(`Okta 429 exhausted after ${_attempts + 1} attempts: ${url}`);
    const retryAfter = parseInt(res.headers.get('retry-after') || '10', 10);
    console.warn(`[okta-sync] 429 rate limit, waiting ${retryAfter}s (attempt ${_attempts + 1}/5)`);
    await sleep(retryAfter * 1000);
    return oktaFetch(url, _attempts + 1);
  }

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Okta ${res.status}: ${url} — ${text.slice(0, 300)}`);
  }

  // Extract pagination link
  const linkHeader = res.headers.get('link') || '';
  const nextMatch = linkHeader.match(/<([^>]+)>;\s*rel="next"/);
  const nextUrl = nextMatch ? nextMatch[1] : null;

  const body = await res.json();
  return { body, nextUrl };
}

async function oktaFetchAllPages(startUrl, signal) {
  const all = [];
  let url = startUrl;
  let safetyCap = 50;  // 50 × 200 = 10,000 apps max
  while (url && safetyCap-- > 0) {
    stopIfLost(signal);
    const { body, nextUrl } = await oktaFetch(url);
    if (Array.isArray(body)) all.push(...body);
    url = nextUrl;
  }
  return all;
}

// -----------------------------------------------------------------------------
// Count direct user + group assignments for a single app.
// Uses paginated list endpoints (users limit=500, groups limit=200).
// -----------------------------------------------------------------------------
async function countAppAssignments(appId) {
  const countPages = async (startUrl) => {
    let total = 0, url = startUrl, safety = 50;
    while (url && safety-- > 0) {
      const { body, nextUrl } = await oktaFetch(url);
      if (Array.isArray(body)) total += body.length;
      url = nextUrl;
      await sleep(300);  // per-call pacing (tuned for 4 AM quiet window)
    }
    return total;
  };
  const users  = await countPages(`${OKTA_BASE_URL}/api/v1/apps/${appId}/users?limit=500`);
  const groups = await countPages(`${OKTA_BASE_URL}/api/v1/apps/${appId}/groups?limit=200`);
  return { users, groups };
}

// -----------------------------------------------------------------------------
// Populate assigned_user_count + assigned_group_count for all seen apps.
// Per-app errors are logged and skipped; the loop continues.
// -----------------------------------------------------------------------------
async function updateAssignmentCounts(signal) {
  const [rows] = await db.execute(
    `SELECT okta_id, label FROM okta_apps WHERE seen_in_last_sync = 1`
  );
  let updated = 0, failed = 0;
  for (const r of rows) {
    stopIfLost(signal);
    try {
      const { users, groups } = await countAppAssignments(r.okta_id);
      stopIfLost(signal);
      await db.execute(
        `UPDATE okta_apps SET assigned_user_count = ?, assigned_group_count = ? WHERE okta_id = ?`,
        [users, groups, r.okta_id]
      );
      updated++;
      await sleep(50);
    } catch (e) {
      stopIfLost(signal);   // a lost lock ends the job; it is not a per-app error
      console.warn(`[okta-sync] count failed for ${r.label} (${r.okta_id}): ${e.message}`);
      failed++;
    }
  }
  console.log(`[okta-sync] assignment counts: ${updated} updated, ${failed} failed`);
  return { counts_updated: updated, counts_failed: failed };
}

// -----------------------------------------------------------------------------
// Sync status bookkeeping (reuses entra_sync_status)
// -----------------------------------------------------------------------------
async function recordJobStart(job) {
  graphCallCount = 0;
  const [result] = await db.execute(
    `INSERT INTO entra_sync_status (job, started_at, status) VALUES (?, NOW(), 'running')`,
    [job]
  );
  return result.insertId;
}

async function recordJobEnd(id, status, stats = {}) {
  await db.execute(
    `UPDATE entra_sync_status
       SET completed_at = NOW(),
           status = ?,
           records_fetched = ?,
           records_upserted = ?,
           records_deleted = ?,
           error_message = ?,
           graph_api_calls = ?
     WHERE id = ?`,
    [
      status,
      stats.fetched ?? null,
      stats.upserted ?? null,
      stats.deleted ?? null,
      stats.error ?? null,
      graphCallCount,
      id
    ]
  );
}

// -----------------------------------------------------------------------------
// Main sync — Apps
// -----------------------------------------------------------------------------
async function syncOktaApps(signal) {
  const jobId = await recordJobStart('okta_apps');
  try {
    stopIfLost(signal);
    await db.execute(`UPDATE okta_apps SET seen_in_last_sync = 0`);

    const url = `${OKTA_BASE_URL}/api/v1/apps?limit=200`;
    const apps = await oktaFetchAllPages(url, signal);

    let upserted = 0;
    for (const a of apps) {
      stopIfLost(signal);
      await db.execute(
        `INSERT INTO okta_apps
           (okta_id, name, label, status, sign_on_mode, base_url, app_link_href,
            features_json, accessibility_json, visibility_json,
            created_at_okta, last_updated_at_okta,
            last_synced_at, seen_in_last_sync, raw_json)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,NOW(),1,?)
         ON DUPLICATE KEY UPDATE
           name                 = VALUES(name),
           label                = VALUES(label),
           status               = VALUES(status),
           sign_on_mode         = VALUES(sign_on_mode),
           base_url             = VALUES(base_url),
           app_link_href        = VALUES(app_link_href),
           features_json        = VALUES(features_json),
           accessibility_json   = VALUES(accessibility_json),
           visibility_json      = VALUES(visibility_json),
           last_updated_at_okta = VALUES(last_updated_at_okta),
           last_synced_at       = NOW(),
           seen_in_last_sync    = 1,
           raw_json             = VALUES(raw_json)`,
        [
          nil(a.id),
          nil(a.name),
          nil(a.label),
          nil(a.status),
          nil(a.signOnMode),
          nil(a.settings?.app?.baseUrl),
          nil(a._links?.appLinks?.[0]?.href),
          JSON.stringify(a.features || []),
          JSON.stringify(a.accessibility || {}),
          JSON.stringify(a.visibility || {}),
          a.created ? new Date(a.created) : null,
          a.lastUpdated ? new Date(a.lastUpdated) : null,
          JSON.stringify((function scrub(v) {
            // raw_json never carries a secret (v2 secrets-1): oem-lib.scrubAppRecord when it is there, the same key list inline when it is not
            try { const s = require('./oem-lib').scrubAppRecord; if (typeof s === 'function') return s(v); } catch (e) { /* oem-lib absent or older: inline scrub below */ }
            const KEYS = /^(client_secret|clientsecret|secret|sharedsecret|shared_secret|password|passwd|private_key|privatekey|api_key|apikey|access_token|refresh_token|id_token|session_token|cookie|mfa_code|otp)$/i;
            const walk = (x, d) => (d > 12 ? '[depth]' : Array.isArray(x) ? x.map((y) => walk(y, d + 1)) : (x && typeof x === 'object') ? Object.fromEntries(Object.entries(x).map(([k, y]) => [k, KEYS.test(k) ? '[redacted]' : walk(y, d + 1)])) : x);
            return walk(v, 0);
          })(a))
        ]
      );
      upserted++;
    }

    // Populate assignment counts (best-effort; errors logged per-app)
    const countStats = await updateAssignmentCounts(signal);

    stopIfLost(signal);
    await recordJobEnd(jobId, 'success', { fetched: apps.length, upserted, ...countStats });
    return { fetched: apps.length, upserted, ...countStats };
  } catch (err) {
    await recordJobEnd(jobId, 'failure', { error: err.message });
    throw err;
  }
}

// =============================================================================
// MATCHER — Okta app ↔ Entra app
// =============================================================================

// The name-only tokenizer that lived here (STOP_TOKENS stripped environment words such as
// 'sandbox', which is how a production Okta app matched a sandbox Entra app) is retired.
// Matching now lives in oem-discovery.js.

// Run the matcher. Writes to app_matches.
// Since 2026-09-10 the name-only matcher is replaced by the identifier-first matcher in
// oem-discovery.js (launcher app id, ACS/audience, reply-URL hosts, environment words as
// separators). It never deletes manual_* rows, keeps a single auto row per Okta app, and
// rebuilds the migration work queue afterwards. The job bookkeeping stays the same so
// entra_sync_status keeps showing app_matcher runs.
async function runMatcher(signal) {
  const jobId = await recordJobStart('app_matcher');
  try {
    const D = require('./oem-discovery');
    const log = (m, level) => console.log(`[okta-sync] matcher: ${m}`);
    log.cancelled = () => !!(signal && signal.aborted);   // oem-discovery checks this per Okta app
    const stats = await D.runMatcher(log);
    stopIfLost(signal);
    const work = await D.buildWorkItems(log);
    console.log('[okta-sync] matcher results:', JSON.stringify(stats), 'work items:', JSON.stringify(work));
    stopIfLost(signal);
    await recordJobEnd(jobId, 'success', { fetched: stats.scope, upserted: stats.updated + stats.inserted });
    return Object.assign({}, stats, { work });
  } catch (e) {
    // oem-discovery's cancel check throws a bare 'cancelled'; name the lost lock instead
    const err = (signal && signal.aborted && e && e.message === 'cancelled') ? signal.reason : e;
    await recordJobEnd(jobId, 'failure', { error: err.message });
    throw err;
  }
}

const JOBS = {
  okta_apps:   syncOktaApps,
  app_matcher: runMatcher
};

// Same cross-process lock as entra-sync: the syncs-worker scheduler, the manual
// trigger and okta-apps-sync-job.js can all start these; a second run queues.
async function runSyncJob(name) {
  if (!JOBS[name]) throw new Error(`Unknown Okta job: ${name}`);
  return require('./sync-lock').withLock(`corpit:okta-sync:${name}`, 900, async (lease) => {
    console.log(`[okta-sync] starting job=${name}`);
    const t0 = Date.now();
    const result = await JOBS[name](lease.signal);
    console.log(`[okta-sync] done job=${name} duration_ms=${Date.now() - t0}`);
    return result;
  });
}

// -----------------------------------------------------------------------------
// Scheduler (daily at 4 AM — offset from other nightly syncs)
// -----------------------------------------------------------------------------
function startScheduler() {
  if ((process.env.OKTA_SYNC_ENABLED || 'true').toLowerCase() !== 'true') {
    console.log('[okta-sync] scheduler disabled');
    return;
  }
  setInterval(() => {
    const now = new Date();
    if (now.getHours() === 4 && now.getMinutes() === 0) {
      runSyncJob('okta_apps').catch(e => console.error('[okta-sync]', e.message));
    }
    if (now.getHours() === 4 && now.getMinutes() === 5) {
      runSyncJob('app_matcher').catch(e => console.error('[okta-sync]', e.message));
    }
  }, 60000);
  console.log('[okta-sync] scheduler started (okta apps 4:00, matcher 4:05)');
}

module.exports = {
  runSyncJob,
  startScheduler,
  syncOktaApps,
  runMatcher,
  updateAssignmentCounts,
  JOBS: Object.keys(JOBS)
};
