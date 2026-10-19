// =============================================================================
// entra-sync.js — Microsoft Graph → MySQL sync for IT Command Entra dashboard
//
// Syncs from Entra tenant to corpit_hub:
//   users, apps, app_assignments, groups, group_memberships,
//   signin_logs, audit_logs, risky_users, risk_detections, auth_methods
//
// Scheduled by server.js to run at ~:05 and ~:35 past each hour.
// Also exposes routes via entra-routes.js for manual triggers and data reads.
//
// Auth: client_credentials against IT-Command-IdentityDiag app (3836db07...)
// Deps: mysql2/promise (existing), native fetch (Node 18+)
// =============================================================================

const mysql = require('mysql2/promise');
const syncLock = require('./sync-lock');
// Rescan R4: each job receives an AbortSignal that aborts when its sync lock is lost;
// stopIfLost(signal) throws the lock-lost error at the job's safe points, before its next write.
const stopIfLost = syncLock.throwIfLost;

// -----------------------------------------------------------------------------
// Config (from .env, with safe defaults)
// -----------------------------------------------------------------------------
const TENANT_ID     = process.env.ENTRA_TENANT_ID;
const CLIENT_ID     = process.env.ENTRA_CLIENT_ID;
const CLIENT_SECRET = process.env.ENTRA_CLIENT_SECRET;

const ENABLED       = (process.env.ENTRA_SYNC_ENABLED || 'true').toLowerCase() === 'true';
const CONCURRENCY   = parseInt(process.env.ENTRA_SYNC_CONCURRENCY || '5', 10);
const RETENTION_DAYS = parseInt(process.env.ENTRA_LOG_RETENTION_DAYS || '90', 10);
const SLACK_WEBHOOK = process.env.ENTRA_SLACK_WEBHOOK || process.env.SLACK_WEBHOOK_URL || '';

const GRAPH_BASE  = 'https://graph.microsoft.com/v1.0';
const TOKEN_URL   = `https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token`;

// MySQL — reuse existing corpit_hub via same creds as rest of api-beta
const db = mysql.createPool({
  host:     process.env.DB_HOST || 'localhost',
  port:     parseInt(process.env.DB_PORT || '3306', 10),
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// -----------------------------------------------------------------------------
// Token cache (client_credentials flow)
// -----------------------------------------------------------------------------
let cachedToken = null;
let cachedTokenExpiresAt = 0;
let graphCallCount = 0;  // Reset per sync job

async function getAccessToken() {
  const now = Date.now();
  if (cachedToken && now < cachedTokenExpiresAt - 300_000) {
    return cachedToken;  // 5 min safety buffer
  }
  const body = new URLSearchParams({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    scope: 'https://graph.microsoft.com/.default',
    grant_type: 'client_credentials'
  });
  const res = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body
  });
  const data = await res.json();
  if (!data.access_token) {
    throw new Error('Token acquire failed: ' + JSON.stringify(data));
  }
  cachedToken = data.access_token;
  cachedTokenExpiresAt = now + (data.expires_in * 1000);
  return cachedToken;
}

// -----------------------------------------------------------------------------
// Graph HTTP helper with retry/throttle handling
// -----------------------------------------------------------------------------
class Graph404Error extends Error {
  constructor(url) { super(`Graph 404: ${url}`); this.name = 'Graph404Error'; this.url = url; }
}

async function graphFetch(url, options = {}, retries = 5) {
  const token = await getAccessToken();
  const res = await fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      Authorization: 'Bearer ' + token,
      Accept: 'application/json'
    }
  });
  graphCallCount++;

  if (res.status === 429 || res.status === 503) {
    if (retries <= 0) throw new Error(`Graph ${res.status} after retries: ${url}`);
    const retryAfter = parseInt(res.headers.get('retry-after') || '10', 10);
    await sleep(retryAfter * 1000);
    return graphFetch(url, options, retries - 1);
  }

  if (res.status === 401) {
    // Token expired unexpectedly — clear cache and retry once
    cachedToken = null;
    if (retries > 0) return graphFetch(url, options, retries - 1);
  }

  if (res.status === 404) {
    throw new Graph404Error(url);
  }
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Graph ${res.status}: ${url} — ${text.slice(0, 300)}`);
  }

  return res.json();
}

async function graphFetchAllPages(url, signal) {
  const all = [];
  let nextUrl = url;
  let safetyCap = 200;  // Never loop forever — 200 pages × 999 = 199,800 records max
  while (nextUrl && safetyCap-- > 0) {
    stopIfLost(signal);
    const page = await graphFetch(nextUrl);
    if (Array.isArray(page.value)) all.push(...page.value);
    nextUrl = page['@odata.nextLink'] || null;
  }
  return all;
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// mysql2 rejects undefined bind params — coerce to null
const nil = v => (v === undefined ? null : v);

// Concurrency-limited parallel processor
async function parallelLimit(items, limit, worker) {
  const results = [];
  let i = 0;
  const running = [];
  const runNext = async () => {
    if (i >= items.length) return;
    const idx = i++;
    const p = worker(items[idx], idx).then(r => { results[idx] = r; });
    running.push(p);
    await p;
    running.splice(running.indexOf(p), 1);
  };
  const starters = Array(Math.min(limit, items.length)).fill(0).map(async () => {
    while (i < items.length) await runNext();
  });
  await Promise.all(starters);
  return results;
}

// -----------------------------------------------------------------------------
// Sync status bookkeeping
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

async function postSlack(text) {
  if (!SLACK_WEBHOOK) return;
  try {
    await fetch(SLACK_WEBHOOK, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text })
    });
  } catch (e) {
    console.error('[entra-sync] Slack post failed:', e.message);
  }
}

// Helper: get last successful completed_at for a job (used by incremental syncs)
async function getLastSuccessTime(job) {
  const [rows] = await db.execute(
    `SELECT completed_at FROM entra_sync_status
     WHERE job = ? AND status = 'success'
     ORDER BY completed_at DESC LIMIT 1`,
    [job]
  );
  if (rows.length === 0) {
    // First run — go back 7 days for append-only logs, or 1 hour for state syncs
    const d = new Date(Date.now() - 7 * 86400000);
    return d;
  }
  return new Date(rows[0].completed_at);
}

// Format Date → Graph ISO 8601 string
function graphIso(d) { return d.toISOString().replace(/\.\d{3}Z$/, 'Z'); }

// -----------------------------------------------------------------------------
// SYNC JOBS
// -----------------------------------------------------------------------------

// --- Users -------------------------------------------------------------------
async function syncUsers(signal) {
  const jobId = await recordJobStart('users');
  try {
    // Mark all as not-seen; upsert will flip to seen=1 for returned rows
    stopIfLost(signal);
    await db.execute(`UPDATE entra_users SET seen_in_last_sync = 0`);

    const select = [
      'id','userPrincipalName','displayName','givenName','surname','mail',
      'jobTitle','department','officeLocation','accountEnabled',
      'createdDateTime','userType','lastPasswordChangeDateTime'
    ].join(',');
    const url = `${GRAPH_BASE}/users?$filter=userType eq 'Member'&$select=${select}&$top=999`;
    const users = await graphFetchAllPages(url, signal);

    let upserted = 0;
    for (const u of users) {
      stopIfLost(signal);
      await db.execute(
        `INSERT INTO entra_users
           (entra_id, user_principal_name, display_name, given_name, surname, mail,
            job_title, department, office_location, account_enabled,
            created_at_entra, last_password_change, user_type,
            status, last_synced_at, seen_in_last_sync, raw_json)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,NOW(),1,?)
         ON DUPLICATE KEY UPDATE
           user_principal_name = VALUES(user_principal_name),
           display_name        = VALUES(display_name),
           given_name          = VALUES(given_name),
           surname             = VALUES(surname),
           mail                = VALUES(mail),
           job_title           = VALUES(job_title),
           department          = VALUES(department),
           office_location     = VALUES(office_location),
           account_enabled     = VALUES(account_enabled),
           last_password_change = VALUES(last_password_change),
           status              = VALUES(status),
           last_synced_at      = NOW(),
           seen_in_last_sync   = 1,
           raw_json            = VALUES(raw_json)`,
        [
          nil(u.id),
          nil(u.userPrincipalName),
          nil(u.displayName),
          nil(u.givenName),
          nil(u.surname),
          nil(u.mail),
          nil(u.jobTitle),
          nil(u.department),
          nil(u.officeLocation),
          u.accountEnabled ? 1 : 0,
          u.createdDateTime ? new Date(u.createdDateTime) : null,
          u.lastPasswordChangeDateTime ? new Date(u.lastPasswordChangeDateTime) : null,
          nil(u.userType),
          u.accountEnabled ? 'ACTIVE' : 'DISABLED',
          JSON.stringify(u)
        ]
      );
      upserted++;
    }

    // Mark stale users as STALE (last seen > 7 days ago)
    stopIfLost(signal);
    await db.execute(
      `UPDATE entra_users
         SET status = 'STALE'
       WHERE seen_in_last_sync = 0
         AND last_synced_at < DATE_SUB(NOW(), INTERVAL 7 DAY)`
    );

    stopIfLost(signal);
    await recordJobEnd(jobId, 'success', { fetched: users.length, upserted });
    return { fetched: users.length, upserted };
  } catch (err) {
    await recordJobEnd(jobId, 'failure', { error: err.message });
    await postSlack(`❌ Entra sync failed (users): ${err.message}`);
    throw err;
  }
}

// --- Apps (Service Principals) -----------------------------------------------
async function syncApps(signal) {
  const jobId = await recordJobStart('apps');
  try {
    stopIfLost(signal);
    await db.execute(`UPDATE entra_apps SET seen_in_last_sync = 0`);

    // replyUrls / servicePrincipalNames / loginUrl are what identifier-based Okta matching
    // keys on (oem-discovery.js). They ride along in raw_json; the columns are unchanged.
    const select = [
      'id','appId','displayName','appRoleAssignmentRequired','accountEnabled',
      'signInAudience','preferredSingleSignOnMode','homepage','tags',
      'publisherName','servicePrincipalType','info','createdDateTime',
      'replyUrls','servicePrincipalNames','loginUrl','logoutUrl',
      'notificationEmailAddresses','preferredTokenSigningKeyThumbprint'
    ].join(',');
    const url = `${GRAPH_BASE}/servicePrincipals?$select=${select}&$top=999`;
    const apps = await graphFetchAllPages(url, signal);

    let upserted = 0;
    for (const a of apps) {
      stopIfLost(signal);
      await db.execute(
        `INSERT INTO entra_apps
           (entra_id, app_id, display_name, app_role_assignment_required,
            account_enabled, sign_in_audience, preferred_single_sign_on_mode,
            homepage_url, logo_url, publisher_name, service_principal_type,
            tags_json, created_at_entra, last_synced_at, seen_in_last_sync, raw_json)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,NOW(),1,?)
         ON DUPLICATE KEY UPDATE
           app_id                         = VALUES(app_id),
           display_name                   = VALUES(display_name),
           app_role_assignment_required   = VALUES(app_role_assignment_required),
           account_enabled                = VALUES(account_enabled),
           sign_in_audience               = VALUES(sign_in_audience),
           preferred_single_sign_on_mode  = VALUES(preferred_single_sign_on_mode),
           homepage_url                   = VALUES(homepage_url),
           logo_url                       = VALUES(logo_url),
           publisher_name                 = VALUES(publisher_name),
           service_principal_type         = VALUES(service_principal_type),
           tags_json                      = VALUES(tags_json),
           last_synced_at                 = NOW(),
           seen_in_last_sync              = 1,
           raw_json                       = VALUES(raw_json)`,
        [
          nil(a.id),
          nil(a.appId),
          nil(a.displayName),
          a.appRoleAssignmentRequired ? 1 : 0,
          a.accountEnabled ? 1 : 0,
          nil(a.signInAudience),
          nil(a.preferredSingleSignOnMode),
          nil(a.homepage),
          nil(a.info?.logoUrl),
          nil(a.publisherName),
          nil(a.servicePrincipalType),
          JSON.stringify(a.tags || []),
          a.createdDateTime ? new Date(a.createdDateTime) : null,
          JSON.stringify(a)
        ]
      );
      upserted++;
    }

    stopIfLost(signal);
    await recordJobEnd(jobId, 'success', { fetched: apps.length, upserted });
    return { fetched: apps.length, upserted };
  } catch (err) {
    await recordJobEnd(jobId, 'failure', { error: err.message });
    await postSlack(`❌ Entra sync failed (apps): ${err.message}`);
    throw err;
  }
}

// --- App Assignments — Group-scoped (fully replaced per sync) ----------------
// Only handles Group-type assignments (from /servicePrincipals/{id}/appRoleAssignedTo).
// User-type assignments are owned by syncUserAppAssignments.
async function syncAppAssignments(signal) {
  const jobId = await recordJobStart('app_assignments');
  try {
    // Get all apps that have assignment_required = true (the ones that track assignments)
    const [apps] = await db.execute(
      `SELECT entra_id FROM entra_apps WHERE app_role_assignment_required = 1`
    );

    const allAssignments = [];
    // Concurrency-limit per-app calls
    await parallelLimit(apps, CONCURRENCY, async (app) => {
      stopIfLost(signal);
      try {
        const url = `${GRAPH_BASE}/servicePrincipals/${app.entra_id}/appRoleAssignedTo?$top=999`;
        const assigns = await graphFetchAllPages(url, signal);
        // Keep only Group-type rows — Users come from syncUserAppAssignments
        allAssignments.push(...assigns.filter(a => a.principalType === 'Group'));
      } catch (e) {
        stopIfLost(signal);   // a lost lock ends the job; it is not a per-app error
        if (e instanceof Graph404Error) {
          console.warn(`[entra-sync] SP ${app.entra_id} returned 404 — pruning from entra_apps`);
          await db.execute(`DELETE FROM entra_apps WHERE entra_id = ?`, [app.entra_id]);
        } else {
          console.error(`[entra-sync] app assignments for ${app.entra_id}:`, e.message);
        }
      }
    });

    // Wipe only Group rows; refill. Leave User rows intact.
    stopIfLost(signal);
    const conn = await db.getConnection();
    try {
      await conn.beginTransaction();
      await conn.execute(`DELETE FROM entra_app_assignments WHERE principal_type = 'Group'`);

      for (const a of allAssignments) {
        await conn.execute(
          `INSERT INTO entra_app_assignments
             (assignment_id, principal_id, principal_type, principal_display_name,
              principal_upn, resource_id, resource_display_name, app_role_id,
              created_at_entra, last_synced_at)
           VALUES (?,?,?,?,?,?,?,?,?,NOW())
           ON DUPLICATE KEY UPDATE
             resource_display_name = VALUES(resource_display_name),
             app_role_id           = VALUES(app_role_id),
             last_synced_at        = NOW()`,
          [
            nil(a.id),
            nil(a.principalId),
            'Group',
            nil(a.principalDisplayName),
            null,  // groups have no UPN
            nil(a.resourceId),
            nil(a.resourceDisplayName),
            nil(a.appRoleId),
            a.createdDateTime ? new Date(a.createdDateTime) : null
          ]
        );
      }

      // Update denormalized counts on entra_apps
      await conn.execute(
        `UPDATE entra_apps a
           LEFT JOIN (
             SELECT resource_id,
                    SUM(principal_type = 'User') AS u,
                    SUM(principal_type = 'Group') AS g
             FROM entra_app_assignments GROUP BY resource_id
           ) c ON c.resource_id = a.entra_id
         SET a.assigned_user_count = COALESCE(c.u, 0),
             a.assigned_group_count = COALESCE(c.g, 0)`
      );

      stopIfLost(signal);   // lost during the rewrite: roll it back
      await conn.commit();
    } catch (e) {
      await conn.rollback();
      throw e;
    } finally {
      conn.release();
    }

    stopIfLost(signal);
    await recordJobEnd(jobId, 'success',
      { fetched: allAssignments.length, upserted: allAssignments.length });
    return { fetched: allAssignments.length };
  } catch (err) {
    await recordJobEnd(jobId, 'failure', { error: err.message });
    await postSlack(`❌ Entra sync failed (app_assignments): ${err.message}`);
    throw err;
  }
}

// --- Groups ------------------------------------------------------------------
async function syncGroups(signal) {
  const jobId = await recordJobStart('groups');
  try {
    stopIfLost(signal);
    await db.execute(`UPDATE entra_groups SET seen_in_last_sync = 0`);

    const select = [
      'id','displayName','description','mail','mailEnabled','securityEnabled',
      'groupTypes','visibility','createdDateTime'
    ].join(',');
    const url = `${GRAPH_BASE}/groups?$select=${select}&$top=999`;
    const groups = await graphFetchAllPages(url, signal);

    for (const g of groups) {
      stopIfLost(signal);
      await db.execute(
        `INSERT INTO entra_groups
           (entra_id, display_name, description, mail, mail_enabled, security_enabled,
            group_types_json, visibility, created_at_entra, last_synced_at, seen_in_last_sync)
         VALUES (?,?,?,?,?,?,?,?,?,NOW(),1)
         ON DUPLICATE KEY UPDATE
           display_name      = VALUES(display_name),
           description       = VALUES(description),
           mail              = VALUES(mail),
           mail_enabled      = VALUES(mail_enabled),
           security_enabled  = VALUES(security_enabled),
           group_types_json  = VALUES(group_types_json),
           visibility        = VALUES(visibility),
           last_synced_at    = NOW(),
           seen_in_last_sync = 1`,
        [
          nil(g.id), nil(g.displayName), nil(g.description), nil(g.mail),
          g.mailEnabled ? 1 : 0, g.securityEnabled ? 1 : 0,
          JSON.stringify(g.groupTypes || []),
          nil(g.visibility),
          g.createdDateTime ? new Date(g.createdDateTime) : null
        ]
      );
    }

    stopIfLost(signal);
    await recordJobEnd(jobId, 'success',
      { fetched: groups.length, upserted: groups.length });
    return { fetched: groups.length };
  } catch (err) {
    await recordJobEnd(jobId, 'failure', { error: err.message });
    await postSlack(`❌ Entra sync failed (groups): ${err.message}`);
    throw err;
  }
}

// --- Group Memberships (table mirrors Graph; only changed rows are written) ---
// CHG-ARCH-25 (2026-09-24): every :05/:35 run used to DELETE all ~42k rows and re-insert them one
// at a time: ~84k binlog row events per run for a table that barely changes, the largest write
// source on the box. writeMemberships() diffs instead. The end state is what the old DELETE +
// INSERT IGNORE left (same rows, same member_type, first occurrence wins on a duplicate key, same
// char(36)/varchar(32) truncation); one difference: last_synced_at now moves only on rows that are
// inserted or updated (nothing reads it, checked 2026-09-24), and the job's records_upserted /
// records_deleted now count real writes. Undo: rollback.sh in
// /var/backups/corpit-arch-fix-20260924/chg25-entra-memberships
const MEMBERSHIP_CHUNK = 500;

// Runs inside the caller's transaction on `conn`. Returns { inserted, updated, deleted, unchanged }.
async function writeMemberships(conn, allMembers) {
  // The primary key compares case-insensitively (utf8mb4_0900_ai_ci), so key on lower case.
  const key = (g, m) => (g + '|' + m).toLowerCase();
  const want = new Map();
  for (const m of allMembers) {
    const row = [String(m.groupId).slice(0, 36), String(m.memberId).slice(0, 36), String(m.memberType).slice(0, 32)];
    const k = key(row[0], row[1]);
    if (!want.has(k)) want.set(k, row);
  }
  // FOR UPDATE locks every row and gap, as the old DELETE did: nothing else writes in between.
  const [cur] = await conn.query('SELECT group_id, member_id, member_type FROM entra_group_memberships FOR UPDATE');
  const del = [], upd = [], seen = new Set();
  for (const r of cur) {
    const k = key(r.group_id, r.member_id), w = want.get(k);
    seen.add(k);
    if (!w) del.push([r.group_id, r.member_id]);
    else if (w[0] !== r.group_id || w[1] !== r.member_id || w[2] !== r.member_type) upd.push([w, r]);
  }
  const ins = [];
  for (const [k, row] of want) if (!seen.has(k)) ins.push(row);

  for (let i = 0; i < del.length; i += MEMBERSHIP_CHUNK) {
    await conn.query('DELETE FROM entra_group_memberships WHERE (group_id, member_id) IN (?)',
      [del.slice(i, i + MEMBERSHIP_CHUNK)]);
  }
  for (const [w, r] of upd) {
    await conn.query(
      `UPDATE entra_group_memberships SET group_id = ?, member_id = ?, member_type = ?, last_synced_at = NOW()
        WHERE group_id = ? AND member_id = ?`,
      [w[0], w[1], w[2], r.group_id, r.member_id]
    );
  }
  for (let i = 0; i < ins.length; i += MEMBERSHIP_CHUNK) {
    const chunk = ins.slice(i, i + MEMBERSHIP_CHUNK);
    await conn.query(
      `INSERT IGNORE INTO entra_group_memberships (group_id, member_id, member_type, last_synced_at)
       VALUES ${chunk.map(() => '(?,?,?,NOW())').join(',')}`,
      chunk.flat()
    );
  }
  return { inserted: ins.length, updated: upd.length, deleted: del.length, unchanged: want.size - ins.length - upd.length };
}

async function syncGroupMemberships(signal) {
  const jobId = await recordJobStart('group_memberships');
  try {
    // Only groups the last group pass still saw: a group deleted in Entra keeps its row
    // (seen_in_last_sync = 0) for history, and Graph answers 404 for its members forever.
    const [groups] = await db.execute(`SELECT entra_id FROM entra_groups WHERE seen_in_last_sync = 1`);

    const allMembers = [];
    await parallelLimit(groups, CONCURRENCY, async (group) => {
      stopIfLost(signal);
      try {
        const url = `${GRAPH_BASE}/groups/${group.entra_id}/members/$ref?$top=999`;
        const members = await graphFetchAllPages(url, signal);
        for (const m of members) {
          // @odata.id format:
          // https://graph.microsoft.com/v2/{tenant}/directoryObjects/{GUID}/Microsoft.DirectoryServices.{Type}
          const odataId = m['@odata.id'] || '';
          const parts = odataId.split('/');
          // Expected: [..., 'directoryObjects', GUID, 'Microsoft.DirectoryServices.User']
          const doIdx = parts.indexOf('directoryObjects');
          if (doIdx < 0 || doIdx + 1 >= parts.length) continue;
          const memberId = parts[doIdx + 1];
          const typeSeg = parts[doIdx + 2] || '';
          // "Microsoft.DirectoryServices.User" → "User"
          const memberType = typeSeg.split('.').pop() || 'Unknown';
          if (!memberId || memberId.length > 128) continue;
          allMembers.push({ groupId: group.entra_id, memberId, memberType });
        }
      } catch (e) {
        stopIfLost(signal);   // a lost lock ends the job; it is not a per-group error
        console.error(`[entra-sync] memberships for ${group.entra_id}:`, e.message);
      }
    });

    stopIfLost(signal);
    const conn = await db.getConnection();
    let written;
    try {
      await conn.beginTransaction();
      written = await writeMemberships(conn, allMembers);
      stopIfLost(signal);   // lost while diffing/writing: roll the whole write back
      await conn.commit();
    } catch (e) {
      await conn.rollback();
      throw e;
    } finally {
      conn.release();
    }

    stopIfLost(signal);
    await recordJobEnd(jobId, 'success',
      { fetched: allMembers.length, upserted: written.inserted + written.updated, deleted: written.deleted });
    return { fetched: allMembers.length };
  } catch (err) {
    await recordJobEnd(jobId, 'failure', { error: err.message });
    await postSlack(`❌ Entra sync failed (group_memberships): ${err.message}`);
    throw err;
  }
}

// --- Sign-in Logs (append-only, incremental) ---------------------------------
async function syncSignIns(signal) {
  const jobId = await recordJobStart('signins');
  try {
    const lastSync = await getLastSuccessTime('signins');
    // Back off 5 min to catch late-arriving events
    const since = new Date(lastSync.getTime() - 5 * 60000);
    const url = `${GRAPH_BASE}/auditLogs/signIns?$filter=createdDateTime ge ${graphIso(since)}&$top=1000`;
    const signins = await graphFetchAllPages(url, signal);

    let upserted = 0;
    for (const s of signins) {
      stopIfLost(signal);
      const outcome = s.status?.errorCode === 0 ? 'SUCCESS' : 'FAILURE';
      const severity = s.riskLevelDuringSignIn === 'high' ? 'ERROR'
                     : s.riskLevelDuringSignIn === 'medium' ? 'WARN'
                     : outcome === 'FAILURE' ? 'WARN' : 'INFO';
      const displayMessage = `${s.userPrincipalName || '?'} → ${s.appDisplayName || '?'} (${outcome})`;

      await db.execute(
        `INSERT IGNORE INTO entra_signin_logs
           (entra_id, created_at, user_id, user_principal_name, user_display_name,
            app_id, app_display_name, client_app_used, ip_address,
            location_city, location_state, location_country,
            device_id, device_display_name, device_os, device_browser,
            is_interactive, risk_level_during_signin, risk_state,
            conditional_access_status, status_error_code, status_failure_reason,
            outcome, severity, display_message, raw_json)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [
          nil(s.id),
          new Date(s.createdDateTime),
          nil(s.userId),
          nil(s.userPrincipalName),
          nil(s.userDisplayName),
          nil(s.appId),
          nil(s.appDisplayName),
          nil(s.clientAppUsed),
          nil(s.ipAddress),
          nil(s.location?.city),
          nil(s.location?.state),
          nil(s.location?.countryOrRegion),
          nil(s.deviceDetail?.deviceId),
          nil(s.deviceDetail?.displayName),
          nil(s.deviceDetail?.operatingSystem),
          nil(s.deviceDetail?.browser),
          s.isInteractive ? 1 : 0,
          nil(s.riskLevelDuringSignIn),
          nil(s.riskState),
          nil(s.conditionalAccessStatus),
          nil(s.status?.errorCode),
          nil(s.status?.failureReason),
          outcome,
          severity,
          displayMessage.slice(0, 512),
          JSON.stringify(s)
        ]
      );
      upserted++;
    }

    // Recompute is_likely_locked: ≥3 failures in last hour, no success since
    stopIfLost(signal);
    await db.execute(`
      UPDATE entra_users u
      SET is_likely_locked = (
        (SELECT COUNT(*) FROM entra_signin_logs s1
          WHERE s1.user_id = u.entra_id
            AND s1.outcome = 'FAILURE'
            AND s1.created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)) >= 3
        AND
        NOT EXISTS (SELECT 1 FROM entra_signin_logs s2
          WHERE s2.user_id = u.entra_id
            AND s2.outcome = 'SUCCESS'
            AND s2.created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR))
      )
    `);

    // Update last_login for each user
    stopIfLost(signal);
    await db.execute(`
      UPDATE entra_users u
      SET last_login = (
        SELECT MAX(created_at) FROM entra_signin_logs s
         WHERE s.user_id = u.entra_id AND s.outcome = 'SUCCESS'
      )
    `);

    stopIfLost(signal);
    await recordJobEnd(jobId, 'success', { fetched: signins.length, upserted });
    return { fetched: signins.length, upserted };
  } catch (err) {
    await recordJobEnd(jobId, 'failure', { error: err.message });
    await postSlack(`❌ Entra sync failed (signins): ${err.message}`);
    throw err;
  }
}

// --- Audit Logs (append-only, incremental) -----------------------------------
async function syncAuditLogs(signal) {
  const jobId = await recordJobStart('audit_logs');
  try {
    const lastSync = await getLastSuccessTime('audit_logs');
    const since = new Date(lastSync.getTime() - 5 * 60000);
    const url = `${GRAPH_BASE}/auditLogs/directoryAudits?$filter=activityDateTime ge ${graphIso(since)}&$top=1000`;
    const events = await graphFetchAllPages(url, signal);

    let upserted = 0;
    for (const e of events) {
      stopIfLost(signal);
      await db.execute(
        `INSERT IGNORE INTO entra_audit_logs
           (entra_id, activity_date_time, activity_display_name, category,
            result, result_reason, initiated_by_user_id, initiated_by_user_upn,
            initiated_by_app_id, initiated_by_app_name, target_resources_json, raw_json)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
        [
          nil(e.id),
          new Date(e.activityDateTime),
          nil(e.activityDisplayName),
          nil(e.category),
          nil(e.result),
          nil(e.resultReason),
          nil(e.initiatedBy?.user?.id),
          nil(e.initiatedBy?.user?.userPrincipalName),
          nil(e.initiatedBy?.app?.appId),
          nil(e.initiatedBy?.app?.displayName),
          JSON.stringify(e.targetResources || []),
          JSON.stringify(e)
        ]
      );
      upserted++;
    }

    stopIfLost(signal);
    await recordJobEnd(jobId, 'success', { fetched: events.length, upserted });
    return { fetched: events.length, upserted };
  } catch (err) {
    await recordJobEnd(jobId, 'failure', { error: err.message });
    await postSlack(`❌ Entra sync failed (audit_logs): ${err.message}`);
    throw err;
  }
}

// --- Risky Users (snapshot) --------------------------------------------------
async function syncRiskyUsers(signal) {
  const jobId = await recordJobStart('risky_users');
  try {
    const url = `${GRAPH_BASE}/identityProtection/riskyUsers?$filter=riskLevel ne 'none'&$top=500`;
    const users = await graphFetchAllPages(url, signal);

    // Wipe and refill (atomic snapshot)
    stopIfLost(signal);
    const conn = await db.getConnection();
    try {
      await conn.beginTransaction();
      await conn.execute(`DELETE FROM entra_risky_users`);
      for (const u of users) {
        await conn.execute(
          `INSERT INTO entra_risky_users
             (entra_id, user_id, user_principal_name, user_display_name,
              risk_level, risk_state, risk_detail,
              risk_last_updated_date_time, is_deleted, last_synced_at)
           VALUES (?,?,?,?,?,?,?,?,?,NOW())`,
          [
            nil(u.id),
            nil(u.id),
            nil(u.userPrincipalName),
            nil(u.userDisplayName),
            nil(u.riskLevel),
            nil(u.riskState),
            nil(u.riskDetail),
            u.riskLastUpdatedDateTime ? new Date(u.riskLastUpdatedDateTime) : null,
            u.isDeleted ? 1 : 0
          ]
        );
      }
      stopIfLost(signal);   // lost during the refill: roll it back
      await conn.commit();
    } catch (e) {
      await conn.rollback();
      throw e;
    } finally {
      conn.release();
    }

    stopIfLost(signal);
    await recordJobEnd(jobId, 'success',
      { fetched: users.length, upserted: users.length });
    return { fetched: users.length };
  } catch (err) {
    await recordJobEnd(jobId, 'failure', { error: err.message });
    await postSlack(`❌ Entra sync failed (risky_users): ${err.message}`);
    throw err;
  }
}

// --- Risk Detections (append-only, incremental) ------------------------------
async function syncRiskDetections(signal) {
  const jobId = await recordJobStart('risk_detections');
  try {
    const lastSync = await getLastSuccessTime('risk_detections');
    const since = new Date(lastSync.getTime() - 5 * 60000);
    const url = `${GRAPH_BASE}/identityProtection/riskDetections?$filter=detectedDateTime ge ${graphIso(since)}&$top=500`;
    const detections = await graphFetchAllPages(url, signal);

    for (const d of detections) {
      stopIfLost(signal);
      await db.execute(
        `INSERT IGNORE INTO entra_risk_detections
           (entra_id, user_id, user_principal_name, ip_address,
            location_city, location_country, risk_event_type,
            risk_level, risk_state, risk_detail, source,
            detection_timing_type, activity_date_time, detected_date_time,
            last_synced_at, raw_json)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,NOW(),?)`,
        [
          nil(d.id),
          nil(d.userId),
          nil(d.userPrincipalName),
          nil(d.ipAddress),
          nil(d.location?.city),
          nil(d.location?.countryOrRegion),
          nil(d.riskEventType),
          nil(d.riskLevel),
          nil(d.riskState),
          nil(d.riskDetail),
          nil(d.source),
          nil(d.detectionTimingType),
          d.activityDateTime ? new Date(d.activityDateTime) : null,
          d.detectedDateTime ? new Date(d.detectedDateTime) : null,
          JSON.stringify(d)
        ]
      );
    }

    stopIfLost(signal);
    await recordJobEnd(jobId, 'success',
      { fetched: detections.length, upserted: detections.length });
    return { fetched: detections.length };
  } catch (err) {
    await recordJobEnd(jobId, 'failure', { error: err.message });
    await postSlack(`❌ Entra sync failed (risk_detections): ${err.message}`);
    throw err;
  }
}

// --- Auth Methods (per user, serial — avoid deadlocks) ----------------------
async function syncAuthMethods(signal) {
  const jobId = await recordJobStart('auth_methods');
  try {
    const [users] = await db.execute(
      `SELECT entra_id FROM entra_users WHERE account_enabled = 1 AND seen_in_last_sync = 1`
    );

    let totalFetched = 0;
    let userErrors = 0;

    // Serial loop — no transactions, no parallelism.
    // Autocommit avoids deadlocks; per-user latency ~100-300ms.
    for (const user of users) {
      stopIfLost(signal);
      try {
        const url = `${GRAPH_BASE}/users/${user.entra_id}/authentication/methods`;
        const page = await graphFetch(url);
        const methods = page.value || [];

        // Delete existing rows for this user, then insert fresh
        stopIfLost(signal);
        await db.execute(
          `DELETE FROM entra_auth_methods WHERE user_id = ?`,
          [user.entra_id]
        );

        for (const m of methods) {
          const odataType = m['@odata.type'] || '';
          const methodType = odataType
            .replace(/^#microsoft\.graph\./, '')
            .replace(/AuthenticationMethod$/, 'Method')
            .slice(0, 64);
          const methodId = String(m.id || '').slice(0, 128);
          if (!methodId) continue;  // skip methods with no ID

          await db.execute(
            `INSERT INTO entra_auth_methods
               (user_id, method_id, method_type, display_name,
                details_json, created_date_time, last_synced_at)
             VALUES (?,?,?,?,?,?,NOW())
             ON DUPLICATE KEY UPDATE
               method_type       = VALUES(method_type),
               display_name      = VALUES(display_name),
               details_json      = VALUES(details_json),
               created_date_time = VALUES(created_date_time),
               last_synced_at    = NOW()`,
            [
              user.entra_id,
              methodId,
              methodType,
              nil(m.displayName || m.deviceTag || m.phoneNumber),
              JSON.stringify(m),
              m.createdDateTime ? new Date(m.createdDateTime) : null
            ]
          );
        }
        totalFetched += methods.length;
      } catch (e) {
        stopIfLost(signal);   // a lost lock ends the job; it is not a per-user error
        userErrors++;
        // Only log the first 5 so we don't flood
        if (userErrors <= 5) {
          console.error(`[entra-sync] auth methods for ${user.entra_id}:`, e.message);
        }
      }
    }

    if (userErrors > 5) {
      console.error(`[entra-sync] auth_methods: ${userErrors} total user errors (only first 5 shown)`);
    }

    stopIfLost(signal);
    await recordJobEnd(jobId, userErrors > 0 ? 'partial' : 'success',
      { fetched: totalFetched, upserted: totalFetched });
    return { fetched: totalFetched, errors: userErrors };
  } catch (err) {
    await recordJobEnd(jobId, 'failure', { error: err.message });
    await postSlack(`❌ Entra sync failed (auth_methods): ${err.message}`);
    throw err;
  }
}

// --- Per-user App Assignments (enabled users, hourly) ------------------------
// Fills the gap where apps are "open to all" (assignmentRequired=false) —
// those apps don't show in /servicePrincipals/{id}/appRoleAssignedTo.
// Per-user enumeration catches them via /users/{id}/appRoleAssignments.
//
// OWNS: User-type rows in entra_app_assignments
// syncAppAssignments owns Group-type rows and won't touch User-type.
async function syncUserAppAssignments(signal) {
  const jobId = await recordJobStart('user_app_assignments');
  try {
    const [users] = await db.execute(
      `SELECT entra_id FROM entra_users WHERE account_enabled = 1 AND seen_in_last_sync = 1`
    );

    // Wipe existing User rows first — we'll re-populate authoritatively
    stopIfLost(signal);
    await db.execute(`DELETE FROM entra_app_assignments WHERE principal_type = 'User'`);

    let totalFetched = 0;
    let userErrors = 0;

    // Serial — same pattern as syncAuthMethods, avoid deadlocks
    for (const user of users) {
      stopIfLost(signal);
      try {
        const url = `${GRAPH_BASE}/users/${user.entra_id}/appRoleAssignments?$top=999`;
        const assigns = await graphFetchAllPages(url, signal);

        stopIfLost(signal);
        for (const a of assigns) {
          await db.execute(
            `INSERT INTO entra_app_assignments
               (assignment_id, principal_id, principal_type, principal_display_name,
                principal_upn, resource_id, resource_display_name, app_role_id,
                created_at_entra, last_synced_at)
             VALUES (?,?,'User',?,NULL,?,?,?,?,NOW())
             ON DUPLICATE KEY UPDATE
               resource_display_name = VALUES(resource_display_name),
               app_role_id           = VALUES(app_role_id),
               last_synced_at        = NOW()`,
            [
              nil(a.id),
              nil(a.principalId || user.entra_id),
              nil(a.principalDisplayName),
              nil(a.resourceId),
              nil(a.resourceDisplayName),
              nil(a.appRoleId),
              a.createdDateTime ? new Date(a.createdDateTime) : null
            ]
          );
          totalFetched++;
        }
      } catch (e) {
        stopIfLost(signal);   // a lost lock ends the job; it is not a per-user error
        userErrors++;
        if (userErrors <= 5) {
          console.error(`[entra-sync] user app assignments for ${user.entra_id}:`, e.message);
        }
      }
    }

    if (userErrors > 5) {
      console.error(`[entra-sync] user_app_assignments: ${userErrors} total user errors`);
    }

    // Recompute denormalized counts on entra_apps
    stopIfLost(signal);
    await db.execute(`
      UPDATE entra_apps a
        LEFT JOIN (
          SELECT resource_id,
                 SUM(principal_type = 'User')  AS u,
                 SUM(principal_type = 'Group') AS g
          FROM entra_app_assignments GROUP BY resource_id
        ) c ON c.resource_id = a.entra_id
      SET a.assigned_user_count  = COALESCE(c.u, 0),
          a.assigned_group_count = COALESCE(c.g, 0)
    `);

    stopIfLost(signal);
    await recordJobEnd(jobId, userErrors > 0 ? 'partial' : 'success',
      { fetched: totalFetched, upserted: totalFetched });
    return { fetched: totalFetched, errors: userErrors };
  } catch (err) {
    await recordJobEnd(jobId, 'failure', { error: err.message });
    await postSlack(`❌ Entra sync failed (user_app_assignments): ${err.message}`);
    throw err;
  }
}

// -----------------------------------------------------------------------------
// RETENTION / PRUNING
// -----------------------------------------------------------------------------
async function pruneOldLogs(signal) {
  const jobId = await recordJobStart('prune');
  try {
    stopIfLost(signal);
    const [a] = await db.execute(
      `DELETE FROM entra_signin_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)`,
      [RETENTION_DAYS]
    );
    stopIfLost(signal);
    const [b] = await db.execute(
      `DELETE FROM entra_audit_logs WHERE activity_date_time < DATE_SUB(NOW(), INTERVAL ? DAY)`,
      [RETENTION_DAYS]
    );
    stopIfLost(signal);
    const [c] = await db.execute(
      `DELETE FROM entra_risk_detections WHERE detected_date_time < DATE_SUB(NOW(), INTERVAL ? DAY)`,
      [RETENTION_DAYS]
    );
    // Keep last 1000 rows per sync job
    stopIfLost(signal);
    await db.execute(`
      DELETE s1 FROM entra_sync_status s1
      INNER JOIN (
        SELECT job, MIN(id) AS keep_above FROM (
          SELECT id, job,
                 ROW_NUMBER() OVER (PARTITION BY job ORDER BY id DESC) AS rn
          FROM entra_sync_status
        ) t WHERE rn = 1000 GROUP BY job
      ) k ON s1.job = k.job AND s1.id < k.keep_above
    `);

    const deleted = a.affectedRows + b.affectedRows + c.affectedRows;
    stopIfLost(signal);
    await recordJobEnd(jobId, 'success', { deleted });
    return { deleted };
  } catch (err) {
    await recordJobEnd(jobId, 'failure', { error: err.message });
    throw err;
  }
}

// -----------------------------------------------------------------------------
// ORCHESTRATION
// -----------------------------------------------------------------------------
const JOBS = {
  users:                 syncUsers,
  apps:                  syncApps,
  app_assignments:       syncAppAssignments,
  user_app_assignments:  syncUserAppAssignments,
  groups:                syncGroups,
  group_memberships:     syncGroupMemberships,
  signins:               syncSignIns,
  audit_logs:            syncAuditLogs,
  risky_users:           syncRiskyUsers,
  risk_detections:       syncRiskDetections,
  auth_methods:          syncAuthMethods,
  prune:                 pruneOldLogs
};

// Scheduler, manual triggers and OEM tooling run in different processes, so jobs and
// the full sync take MySQL named locks (sync-lock.js). A second run of the same job
// queues behind the first (callers keep their result); a second full sync is skipped.
// Rescan R4: a job gets its lock's lease signal (a full run adds the full-run lock's), so losing
// either lock stops the job at its next safe point; its catch records 'failure' with the reason.
const FULL_LOCK = 'corpit:entra-sync:full';
const JOB_LOCK_WAIT_SEC = 900;   // longest job (auth_methods) ran ~630 s over 14 days

async function runSyncJob(name, outerSignal) {
  if (!JOBS[name]) throw new Error(`Unknown job: ${name}`);
  return syncLock.withLock(`corpit:entra-sync:${name}`, JOB_LOCK_WAIT_SEC, async (lease) => {
    const signal = outerSignal ? AbortSignal.any([outerSignal, lease.signal]) : lease.signal;
    stopIfLost(signal);   // the full-run lock can be lost while this job waits for its own
    console.log(`[entra-sync] starting job=${name}`);
    const t0 = Date.now();
    const result = await JOBS[name](signal);
    console.log(`[entra-sync] done job=${name} duration_ms=${Date.now() - t0}`);
    return result;
  });
}

let isRunning = false;

async function runFullSync() {
  if (isRunning) {
    console.log('[entra-sync] skipping: previous sync still running');
    return;
  }
  if (!ENABLED) {
    console.log('[entra-sync] skipping: ENTRA_SYNC_ENABLED=false');
    return;
  }
  isRunning = true;
  try {
    const r = await syncLock.withLock(FULL_LOCK, 0, runFullSyncLocked);
    if (r && r.skipped) console.log('[entra-sync] skipping: full sync already running in another process');
  } finally {
    isRunning = false;
  }
}

async function runFullSyncLocked(lease) {
  const t0 = Date.now();
  let failed = 0;
  console.log('[entra-sync] ===== full sync start =====');

  // Dependencies: users, apps, groups first (parallel-safe),
  // then assignments, memberships, auth_methods (depend on prior data)
  // Logs can run anywhere
  const order = [
    'users', 'apps', 'groups',
    'app_assignments', 'group_memberships', 'auth_methods',
    'signins', 'audit_logs', 'risky_users', 'risk_detections'
  ];

  for (const job of order) {
    if (lease.signal.aborted) {   // Rescan R4: the full-run lock is gone, start nothing else
      failed++;
      console.error(`[entra-sync] full sync stopped before job=${job}: ${lease.signal.reason.message}`);
      break;
    }
    try {
      await runSyncJob(job, lease.signal);
    } catch (e) {
      failed++;
      console.error(`[entra-sync] job=${job} failed — continuing:`, e.message);
    }
  }

  console.log(`[entra-sync] ===== full sync end duration_ms=${Date.now() - t0} =====`);
  // Observability: this runs inside the syncs-worker pm2 process, so nothing
  // else writes a srv_job_run row for it. A failed sub-job marks the run failed.
  try { await require('./obs-job').record(db, 'entra-sync.js', { startedAt: new Date(t0), finishedAt: new Date(), exitCode: (failed || lease.signal.aborted) ? 1 : 0 }); } catch (e) {}
}

// -----------------------------------------------------------------------------
// SCHEDULER — setInterval-based (ticks every minute, runs when :05 or :35)
// -----------------------------------------------------------------------------
function startScheduler() {
  if (!ENABLED) {
    console.log('[entra-sync] scheduler disabled (ENTRA_SYNC_ENABLED=false)');
    return;
  }
  // Full sync tick — check every minute, run when minute == 5 or 35
  setInterval(() => {
    const m = new Date().getMinutes();
    if (m === 5 || m === 35) runFullSync().catch(e => console.error(e));
  }, 60000);

  // Per-user app assignments — hourly at :10 (separate cron, ~5 min runtime)
  setInterval(() => {
    const now = new Date();
    if (now.getMinutes() === 10) {
      runSyncJob('user_app_assignments').catch(e => console.error(e));
    }
  }, 60000);

  // Prune tick — check every minute, run when 3:15 AM (approx)
  setInterval(() => {
    const now = new Date();
    if (now.getHours() === 3 && now.getMinutes() === 15) {
      runSyncJob('prune').catch(e => console.error(e));
    }
  }, 60000);

  console.log('[entra-sync] scheduler started (full sync :05/:35, user assignments :10, prune 3:15 AM)');
}

// -----------------------------------------------------------------------------
// EXPORTS
// -----------------------------------------------------------------------------
module.exports = {
  db,
  runFullSync,
  runSyncJob,
  FULL_LOCK,
  startScheduler,
  getAccessToken,
  graphFetch,
  JOBS: Object.keys(JOBS),
  _writeMemberships: writeMemberships   // CHG-ARCH-25 rehearsal harness only
};
