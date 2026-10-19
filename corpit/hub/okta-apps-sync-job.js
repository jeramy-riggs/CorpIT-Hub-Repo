// =============================================================================
// okta-apps-sync-job.js — cron entry point for the Okta application inventory
//                                                            CorpIT 2026-09-07
//
// WHY THIS FILE EXISTS
// --------------------
// okta-sync.js mirrors /api/v1/apps into corpit_hub.okta_apps and then matches
// those apps against Entra (JOBS: okta_apps, app_matcher). It has no CLI entry
// point of its own -- it is a library plus an in-process scheduler that
// syncs-worker.js starts:
//
//     setInterval(() => { if (h === 4 && m === 0) runSyncJob('okta_apps') }, 60000)
//
// That scheduler fires only if a tick lands inside one specific wall-clock
// minute. On ITAM the worker is long-lived and hits it every night. On CorpIT
// the worker is restarted whenever the platform is deployed, and a 60s
// setInterval also drifts, so 04:00 is missed. The evidence, read from
// entra_sync_status on both hosts:
//
//     ITAM    okta_apps  success every day, most recently 2026-09-07 04:00
//     CorpIT  okta_apps  last row 2026-08-27 04:00 -- the date corpit_hub was
//                        seeded from ITAM. It has never run on this host.
//
// So okta_apps was not "a bit stale": the collector was deployed and
// effectively unscheduled, and okta_apps held a frozen copy of ITAM's
// 2026-08-27 snapshot (239 rows) while Okta had moved on to 240.
//
// The fix follows the convention every other CorpIT collector uses -- cron +
// flock + corpit-cronwrap -- which is immune to process restarts and records
// the run in srv_job_run. OKTA_SYNC_ENABLED=false in .env switches off the
// in-process scheduler so the two can never both run; that switch is
// okta-sync.js's own documented control, so no library code changed.
//
// Offset from ITAM's 04:00 on purpose: both hosts read the SAME Okta tenant,
// and a full pass makes ~270 API calls, so they are kept apart rather than
// stacked on one rate-limit window.
//
// Reads Okta, writes only corpit_hub. Nothing here touches ITAM.
//
// Cron:
//   40 4 * * * cd /var/www/corpit-hub-api && /usr/bin/flock -n /run/okta-apps-sync.lock \
//     /usr/local/bin/corpit-cronwrap okta-apps-sync-job.js /usr/bin/node \
//     -r dotenv/config okta-apps-sync-job.js >> /var/log/corpit/okta-apps-sync.log 2>&1
// =============================================================================

const oktaSync = require('./okta-sync');
const entraSync = require('./entra-sync');

const stamp = () => new Date().toISOString();

(async () => {
  let failed = 0;

  // okta_apps first. The matcher compares okta_apps against the Entra app list,
  // so running it after a failed mirror would only re-match yesterday's rows and
  // report success over data that never refreshed.
  try {
    console.log(`[okta-apps-sync] ${stamp()} starting okta_apps`);
    await oktaSync.runSyncJob('okta_apps');
    console.log(`[okta-apps-sync] ${stamp()} okta_apps OK`);

    try {
      console.log(`[okta-apps-sync] ${stamp()} starting app_matcher`);
      await oktaSync.runSyncJob('app_matcher');
      console.log(`[okta-apps-sync] ${stamp()} app_matcher OK`);
    } catch (e) {
      failed++;
      console.error(`[okta-apps-sync] ${stamp()} app_matcher FAILED: ${e.message}`);
    }
  } catch (e) {
    failed++;
    console.error(`[okta-apps-sync] ${stamp()} okta_apps FAILED: ${e.message}`);
    console.error(`[okta-apps-sync] ${stamp()} app_matcher SKIPPED — it would have`
      + ' re-matched the previous snapshot and reported success over stale rows');
  }

  // okta-sync borrows entra-sync's pool, so this is the one to close.
  try { await entraSync.db.end(); } catch (_) { /* closing must not mask the result */ }
  // okta-sync also pulls in oem-lib (raw_json scrub, and oem-discovery for the matcher), and oem-lib opens its own
  // pool at require time. Left open, the process never exits: 2026-09-15's run logged DONE at 04:50:36Z and sat
  // for 29,435 s until MySQL's wait_timeout dropped the idle connections, so cron's flock and the v2 refresh
  // (which runs this file as a child with a 15-minute timeout) both saw a hung job. Close it when it was loaded.
  try {
    const lib = require.cache[require.resolve('./oem-lib')];
    if (lib && lib.exports && lib.exports.pool && typeof lib.exports.pool.end === 'function') await lib.exports.pool.end();
  } catch (_) { /* closing must not mask the result */ }

  if (failed) {
    console.error(`[okta-apps-sync] ${stamp()} DONE with ${failed} failure(s)`);
    process.exit(1);
  }
  console.log(`[okta-apps-sync] ${stamp()} DONE`);
  // Backstop: if some other handle is still open, say so and exit anyway rather than hang until wait_timeout.
  setTimeout(() => {
    console.error(`[okta-apps-sync] ${stamp()} event loop still alive 10 s after DONE (an open pool or timer); exiting 0`);
    process.exit(0);
  }, 10000).unref();
})().catch(e => {
  console.error('[okta-apps-sync] FATAL', e && e.stack || e);
  process.exit(1);
});
