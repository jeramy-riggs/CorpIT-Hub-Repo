// collect-ad-auth-events.js
// Pulls Okta System Log events for eventType 'user.authentication.auth_via_AD_agent'
// (Okta-delegated authentication to on-prem Active Directory via the AD Agent).
// Paginates via the Link 'next' header until caught up to now. Upserts into
// sdops_ad_auth_event, keyed on event uuid. Duplicate-safe.
// Manual run: cd /var/www/corpit-hub-api && env $(cat .env | grep -v '^#' | grep -v '^$' | xargs) node collect-ad-auth-events.js

const mysql = require('mysql2/promise');
const axios = require('axios');

const LOOKBACK_HOURS = parseInt(process.env.AD_AUTH_LOOKBACK_HOURS || '24', 10);
const MAX_PAGES = parseInt(process.env.AD_AUTH_MAX_PAGES || '300', 10);

async function getPool() {
  return mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '3306', 10),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 5,
  });
}

function parseNextLink(linkHeader) {
  if (!linkHeader) return null;
  const parts = linkHeader.split(',');
  for (const part of parts) {
    const m = part.match(/<([^>]+)>;\s*rel="next"/);
    if (m) return m[1];
  }
  return null;
}

async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function fetchEvents() {
  const since = new Date(Date.now() - LOOKBACK_HOURS * 3600 * 1000).toISOString();
  const filter = encodeURIComponent('eventType eq "user.authentication.auth_via_AD_agent"');
  let url = `${process.env.OKTA_BASE_URL}/api/v1/logs?since=${since}&filter=${filter}&limit=1000`;

  const allEvents = [];
  let page = 0;

  while (url && page < MAX_PAGES) {
    page += 1;
    const resp = await axios.get(url, {
      headers: { Authorization: `SSWS ${process.env.OKTA_API_TOKEN}` }
    });

    const filtered = resp.data.filter(e => e.target && e.target[0] && e.target[0].type === 'AppUser');
    allEvents.push(...filtered);

    const remaining = parseInt(resp.headers['x-rate-limit-remaining'] || '10', 10);
    const lastPublished = resp.data[resp.data.length - 1]?.published;
    console.log(`[collect-ad-auth-events] page ${page}: raw=${resp.data.length} appUser=${filtered.length} rateRemaining=${remaining} through=${lastPublished || 'n/a'}`);

    if (resp.data.length === 0) break;

    url = parseNextLink(resp.headers['link']);

    if (remaining <= 3) {
      const resetAt = parseInt(resp.headers['x-rate-limit-reset'] || '0', 10) * 1000;
      const waitMs = Math.max(1000, resetAt - Date.now() + 1000);
      console.log(`[collect-ad-auth-events] rate limit low, sleeping ${Math.round(waitMs/1000)}s`);
      await sleep(waitMs);
    } else {
      await sleep(300);
    }
  }

  return allEvents;
}

async function upsertEvents(pool, events) {
  if (!events.length) return 0;

  const sql = `
    INSERT INTO sdops_ad_auth_event
      (event_uuid, upn, display_name, outcome, reason, ip_address, country, city, published_at, collected_at)
    VALUES ?
    ON DUPLICATE KEY UPDATE
      outcome = VALUES(outcome),
      reason = VALUES(reason),
      collected_at = NOW()
  `;

  const now = new Date();
  const values = events.map(e => [
    e.uuid,
    e.target[0].alternateId || null,
    e.target[0].displayName || null,
    e.outcome?.result || null,
    e.outcome?.reason || null,
    e.client?.ipAddress || null,
    e.client?.geographicalContext?.country || null,
    e.client?.geographicalContext?.city || null,
    e.published ? new Date(e.published) : null,
    now
  ]);

  // Upsert in batches to avoid one giant query
  let affected = 0;
  const BATCH = 500;
  for (let i = 0; i < values.length; i += BATCH) {
    const [result] = await pool.query(sql, [values.slice(i, i + BATCH)]);
    affected += result.affectedRows;
  }
  return affected;
}

async function logRun(pool, status, error, startedAt) {
  await pool.query(
    `INSERT INTO sdops_collector_run (module, started_at, finished_at, status, error) VALUES (?, ?, NOW(), ?, ?)`,
    ['ad_auth_events', startedAt, status, error || null]
  );
}

async function main() {
  const startedAt = new Date();
  const pool = await getPool();

  try {
    const events = await fetchEvents();
    const affected = await upsertEvents(pool, events);
    console.log(`[collect-ad-auth-events] done. total AppUser events: ${events.length}, upserted: ${affected}`);
    await logRun(pool, 'ok', null, startedAt);
    process.exit(0);
  } catch (err) {
    console.error('[collect-ad-auth-events] error:', err.response?.data || err.message);
    await logRun(pool, 'error', err.message, startedAt).catch(() => {});
    process.exit(1);
  } finally {
    await pool.end().catch(() => {});
  }
}

main();
