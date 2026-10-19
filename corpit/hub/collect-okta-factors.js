// collect-okta-factors.js
// Real MFA data: one call per Okta user to /api/v1/users/{id}/factors, since
// Okta's user-list endpoint (used by collect-okta-users.js) never includes
// factor enrollment. This is the fix for PRIV-MFA-091 / IAM-MFA-097, which
// were previously (and wrongly) built against Entra's own auth-methods table
// even though this tenant's real MFA challenge happens in Okta.
//
// Runtime note: ~1,562 users x one call each. Sequential with a small delay
// and 429 backoff to stay well under Okta's rate limits — expect several
// minutes to run. Schedule daily, not every 30 minutes like collect-okta-users.js.
require('dotenv').config({ path: __dirname + '/.env' });
const mysql = require('mysql2/promise');

const DELAY_MS = 60; // gentle pacing between calls

function sleep(ms) { return new Promise((res) => setTimeout(res, ms)); }

async function fetchFactors(base, headers, oktaId, retried = false) {
  const res = await fetch(`${base}/api/v1/users/${oktaId}/factors`, { headers });
  if (res.status === 429) {
    if (retried) throw new Error(`persistent 429 for user ${oktaId}`);
    const retryAfter = parseInt(res.headers.get('retry-after') || '5', 10);
    console.log(`rate limited, waiting ${retryAfter}s...`);
    await sleep(retryAfter * 1000);
    return fetchFactors(base, headers, oktaId, true);
  }
  if (res.status === 404) return []; // deprovisioned/removed users can 404
  if (!res.ok) throw new Error(`Okta ${res.status} for user ${oktaId}: ${await res.text()}`);
  return res.json();
}

async function main() {
  const base = process.env.OKTA_BASE_URL.replace(/\/+$/, '');
  const headers = { Authorization: 'SSWS ' + process.env.OKTA_API_TOKEN, Accept: 'application/json' };
  const pool = mysql.createPool({
    host: process.env.DB_HOST, user: process.env.DB_USER,
    password: process.env.DB_PASSWORD, database: process.env.DB_NAME,
    waitForConnections: true, connectionLimit: 3,
  });

  const [users] = await pool.query(`SELECT okta_id FROM okta_users WHERE status != 'DEPROVISIONED'`);
  console.log(`fetching factors for ${users.length} users...`);

  let processed = 0, totalFactors = 0, errors = 0;
  const now = new Date();
  for (const u of users) {
    try {
      const factors = await fetchFactors(base, headers, u.okta_id);
      const seenIds = [];
      for (const f of factors) {
        seenIds.push(f.id);
        await pool.query(
          `INSERT INTO okta_user_factors (okta_id, factor_id, factor_type, provider, status, last_synced_at)
           VALUES (?,?,?,?,?,?)
           ON DUPLICATE KEY UPDATE factor_type=VALUES(factor_type), provider=VALUES(provider),
             status=VALUES(status), last_synced_at=VALUES(last_synced_at)`,
          [u.okta_id, f.id, f.factorType, f.provider, f.status, now]
        );
        totalFactors++;
      }
      // clean up factors that no longer exist for this user (removed/deleted)
      if (seenIds.length) {
        await pool.query(
          `DELETE FROM okta_user_factors WHERE okta_id = ? AND factor_id NOT IN (${seenIds.map(() => '?').join(',')})`,
          [u.okta_id, ...seenIds]
        );
      } else {
        await pool.query(`DELETE FROM okta_user_factors WHERE okta_id = ?`, [u.okta_id]);
      }
      processed++;
    } catch (e) {
      errors++;
      console.log(`error for ${u.okta_id}: ${e.message}`);
    }
    await sleep(DELAY_MS);
    if (processed % 200 === 0) console.log(`... ${processed}/${users.length} processed`);
  }

  console.log(`okta-factors: ${processed} users processed, ${totalFactors} factors recorded, ${errors} errors`);
  await pool.end();
  // A run in which every call failed (expired SSWS token, Okta outage) still
  // printed "OK" and exited 0, so a wholesale collection failure was
  // indistinguishable from a tenant with no MFA enrolled -- and every
  // privileged account then rendered as "no strong MFA". Fail loudly instead.
  if (users.length && errors / users.length > 0.5) {
    throw new Error(
      `${errors}/${users.length} users failed (${Math.round((errors / users.length) * 100)}%) - treating run as failed`);
  }
}

main().then(() => { console.log('collect-okta-factors OK', new Date().toISOString()); process.exit(0); })
  .catch((e) => { console.error('collect-okta-factors FAILED:', e.message); process.exit(1); });
