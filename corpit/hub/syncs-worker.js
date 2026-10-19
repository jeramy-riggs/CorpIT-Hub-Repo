// syncs-worker.js — dedicated pm2 process for scheduled sync jobs
// Split out of api-beta (2026-08-14) so heavy Entra/Okta syncs no longer
// block user-facing /api/rbac endpoints on the api-beta event loop.
//
// This process runs ONLY the scheduler ticks. The same modules are still
// loaded in api-beta because other files (entra-routes, photo-route,
// okta-sync) require them as libraries (getAccessToken, manual-trigger
// endpoints, etc.). Only .startScheduler() has been moved.
//
// Env: reads /var/www/corpit-hub-api/.env via dotenv (pm2 cwd = /var/www/corpit-hub-api).
// No HTTP port bound.

require('dotenv').config();

process.on('uncaughtException', (err) => {
  console.error('[syncs-worker] uncaughtException:', err && err.stack || err);
});
process.on('unhandledRejection', (err) => {
  console.error('[syncs-worker] unhandledRejection:', err && err.stack || err);
});

try {
  require('./entra-sync').startScheduler();
} catch (e) {
  console.error('[syncs-worker] FAILED to start entra-sync scheduler:', e && e.stack || e);
}

try {
  require('./okta-sync').startScheduler();
} catch (e) {
  console.error('[syncs-worker] FAILED to start okta-sync scheduler:', e && e.stack || e);
}

// Heartbeat every 15 min so pm2 log tail shows this process is alive
// between the actual scheduled runs.
setInterval(() => {
  const rss = Math.round(process.memoryUsage().rss / 1024 / 1024);
  console.log('[syncs-worker] alive rss=' + rss + 'MB uptime=' + Math.round(process.uptime()) + 's');
}, 15 * 60 * 1000);

console.log('[syncs-worker] started, PID=' + process.pid);
