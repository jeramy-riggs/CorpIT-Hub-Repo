// collect-lockout-resolutions.js
// v7: same resolution logic as v6, plus stores the SDP ticket's display ID and
// internal ID (for clickable WorkOrder.do links) when a ticket match is found.
// Manual run: cd /var/www/corpit-hub-api && env $(cat .env | grep -v '^#' | grep -v '^$' | xargs) node collect-lockout-resolutions.js

const mysql = require('mysql2/promise');
const { oktaRequest, oktaFilterValue } = require('./okta-lookup');

const LOOKBACK_DAYS = parseInt(process.env.LOCKOUT_RESOLUTION_LOOKBACK_DAYS || '14', 10);
const RETRY_HOURS = parseInt(process.env.LOCKOUT_RESOLUTION_RETRY_HOURS || '6', 10);
const BATCH_SIZE = parseInt(process.env.LOCKOUT_RESOLUTION_BATCH_SIZE || '40', 10);
const OKTA_CALL_DELAY_MS = parseInt(process.env.LOCKOUT_RESOLUTION_OKTA_DELAY_MS || '300', 10);
const AUTO_CLEAR_MAX_MINUTES = parseInt(process.env.LOCKOUT_AUTO_CLEAR_MAX_MINUTES || '75', 10);

const SDP_KEYWORDS = ['lockout', 'locked out', 'unlock', 'password', "can't log in", 'cannot log in', 'cant login'];
const SDP_CATEGORY_KEYWORDS = ['lockout', 'unlock', 'password'];

function isAttackTool(appDisplayName) {
  const a = (appDisplayName || '').toLowerCase();
  return a.indexOf('powershell') >= 0
    || a.indexOf('azure cli') >= 0
    || a.indexOf('graph command') >= 0
    || a.indexOf('azure active directory powershell') >= 0;
}

function toMysqlDate(isoStringOrDate) {
  if (!isoStringOrDate) return null;
  const d = isoStringOrDate instanceof Date ? isoStringOrDate : new Date(isoStringOrDate);
  return isNaN(d.getTime()) ? null : d;
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

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

async function fetchUnresolvedLockouts(pool) {
  const [rows] = await pool.query(
    `SELECT id, upn, display_name, created_at, app_display_name
       FROM sdops_lockout
      WHERE created_at >= (NOW() - INTERVAL ? DAY)
        AND (
          resolution_status IS NULL
          OR (resolution_status = 'unresolved' AND (resolution_checked_at IS NULL OR resolution_checked_at < (NOW() - INTERVAL ? HOUR)))
        )
      ORDER BY created_at ASC
      LIMIT ?`,
    [LOOKBACK_DAYS, RETRY_HOURS, BATCH_SIZE]
  );
  return rows;
}

async function findSdpTicket(pool, upn, displayName, lockoutTime) {
  const categoryClauses = SDP_CATEGORY_KEYWORDS.map(() =>
    "(LOWER(COALESCE(category,'')) LIKE ? OR LOWER(COALESCE(subcategory,'')) LIKE ?)"
  ).join(' OR ');
  const categoryParams = SDP_CATEGORY_KEYWORDS.flatMap(k => [`%${k}%`, `%${k}%`]);

  const subjectClauses = SDP_KEYWORDS.map(() => '(LOWER(subject) LIKE ?)').join(' OR ');
  const subjectParams = SDP_KEYWORDS.map(k => `%${k}%`);

  const nameClause = displayName ? "OR LOWER(subject) LIKE ?" : '';
  const nameParam = displayName ? [`%${displayName.toLowerCase()}%`] : [];

  const [rows] = await pool.query(
    `SELECT id, sdp_internal_id, subject, category, subcategory, requester_email, created_at
       FROM sdops_request
      WHERE created_at BETWEEN (? - INTERVAL 1 DAY) AND (? + INTERVAL 5 DAY)
        AND (
          LOWER(requester_email) = LOWER(?)
          ${nameClause}
        )
        AND (
          ${categoryClauses}
          OR ${subjectClauses}
        )
      ORDER BY created_at ASC
      LIMIT 1`,
    [lockoutTime, lockoutTime, upn, ...nameParam, ...categoryParams, ...subjectParams]
  );
  return rows[0] || null;
}

async function findOktaResolution(upn, lockoutTime) {
  const since = new Date(lockoutTime).toISOString();
  // The UPN is spliced into a double-quoted filter; refuse anything that could
  // end the string (see oktaFilterValue in okta-lookup.js).
  const safeUpn = oktaFilterValue(upn);
  if (!safeUpn) return null;
  const filter = 'target.alternateId eq "' + safeUpn + '"';
  const path = '/api/v1/logs?since=' + encodeURIComponent(since) +
    '&filter=' + encodeURIComponent(filter) + '&sortOrder=ASCENDING&limit=25';
  const res = await oktaRequest(path);
  if (res.status !== 200 || !Array.isArray(res.body)) return null;

  let firstSuccessWithinWindow = null;
  const lockoutMs = new Date(lockoutTime).getTime();

  for (const ev of res.body) {
    const type = (ev.eventType || '').toLowerCase();
    const isUnlock = type.indexOf('account.unlock') >= 0 || type.indexOf('unlock') >= 0;
    if (isUnlock) {
      const actorId = (ev.actor && ev.actor.alternateId || '').toLowerCase();
      const actorName = (ev.actor && ev.actor.displayName) || '';
      const isSelf = actorId && actorId === upn.toLowerCase();
      return { kind: 'unlock', published: ev.published, actorId, actorName, isSelf };
    }
    if (!firstSuccessWithinWindow && ev.outcome && ev.outcome.result === 'SUCCESS') {
      const gapMinutes = (new Date(ev.published).getTime() - lockoutMs) / 60000;
      if (gapMinutes >= 0 && gapMinutes <= AUTO_CLEAR_MAX_MINUTES) {
        firstSuccessWithinWindow = { published: ev.published, eventType: ev.eventType };
      }
    }
  }

  if (firstSuccessWithinWindow) {
    return { kind: 'auto_cleared', published: firstSuccessWithinWindow.published, eventType: firstSuccessWithinWindow.eventType };
  }
  return null;
}

async function resolveRow(pool, row) {
  if (isAttackTool(row.app_display_name)) {
    return {
      resolution_status: 'not_applicable',
      resolution_detail: 'Attack-tool sign-in (automated password-spray) -- not a user-caused lockout',
      resolution_source: null,
      resolved_at: null,
      resolution_ticket_id: null,
      resolution_ticket_internal_id: null,
    };
  }

  const ticket = await findSdpTicket(pool, row.upn, row.display_name, row.created_at);
  if (ticket) {
    const viaName = ticket.requester_email && ticket.requester_email.toLowerCase() !== row.upn.toLowerCase();
    return {
      resolution_status: 'sdp_ticket',
      resolution_detail: 'Ticket ' + ticket.id + (viaName ? ' (filed by ' + ticket.requester_email + ')' : '') + ': ' + (ticket.subject || '').slice(0, 200),
      resolution_source: 'sdp',
      resolved_at: toMysqlDate(ticket.created_at),
      resolution_ticket_id: ticket.id,
      resolution_ticket_internal_id: ticket.sdp_internal_id || null,
    };
  }

  try {
    const res = await findOktaResolution(row.upn, row.created_at);
    if (res && res.kind === 'unlock') {
      return {
        resolution_status: res.isSelf ? 'self_service' : 'admin_unlock',
        resolution_detail: res.isSelf ? 'Self-service unlock via Okta' : ('Unlocked by ' + (res.actorName || res.actorId || 'admin')),
        resolution_source: 'okta',
        resolved_at: toMysqlDate(res.published),
        resolution_ticket_id: null,
        resolution_ticket_internal_id: null,
      };
    }
    if (res && res.kind === 'auto_cleared') {
      return {
        resolution_status: 'auto_cleared',
        resolution_detail: 'No explicit unlock action -- successful sign-in within ' + AUTO_CLEAR_MAX_MINUTES + ' min of lockout (' + res.eventType + ')',
        resolution_source: 'okta',
        resolved_at: toMysqlDate(res.published),
        resolution_ticket_id: null,
        resolution_ticket_internal_id: null,
      };
    }
  } catch (e) {
    console.error(`[collect-lockout-resolutions] Okta lookup failed for ${row.upn}: ${e.message}`);
    return null;
  }

  return {
    resolution_status: 'unresolved',
    resolution_detail: null,
    resolution_source: null,
    resolved_at: null,
    resolution_ticket_id: null,
    resolution_ticket_internal_id: null,
  };
}

(async () => {
  const started = new Date();
  let pool;
  let checked = 0, resolved = 0, notApplicable = 0, errors = 0;
  const breakdown = {};
  try {
    pool = await getPool();
    const rows = await fetchUnresolvedLockouts(pool);

    for (const row of rows) {
      checked++;
      let result;
      try {
        result = await resolveRow(pool, row);
      } catch (e) {
        errors++;
        console.error(`[collect-lockout-resolutions] error resolving ${row.upn}: ${e.message}`);
        continue;
      }
      if (result === null) continue;

      try {
        await pool.query(
          `UPDATE sdops_lockout
              SET resolution_status = ?, resolution_detail = ?, resolution_source = ?,
                  resolved_at = ?, resolution_checked_at = NOW(),
                  resolution_ticket_id = ?, resolution_ticket_internal_id = ?
            WHERE id = ?`,
          [result.resolution_status, result.resolution_detail, result.resolution_source, result.resolved_at,
           result.resolution_ticket_id, result.resolution_ticket_internal_id, row.id]
        );
      } catch (e) {
        errors++;
        console.error(`[collect-lockout-resolutions] UPDATE failed for ${row.upn} (${row.id}): ${e.message}`);
        continue;
      }

      breakdown[result.resolution_status] = (breakdown[result.resolution_status] || 0) + 1;
      if (result.resolution_status === 'not_applicable') {
        notApplicable++;
      } else if (result.resolution_status !== 'unresolved') {
        resolved++;
        await sleep(OKTA_CALL_DELAY_MS);
      }
    }

    console.log(`[${started.toISOString()}] lockout-resolutions checked=${checked} resolved=${resolved} not_applicable=${notApplicable} errors=${errors} breakdown=${JSON.stringify(breakdown)} lookback=${LOOKBACK_DAYS}d autoClearMax=${AUTO_CLEAR_MAX_MINUTES}min`);
  } catch (err) {
    console.error(`[${started.toISOString()}] ERROR: ${err.message}`);
    process.exitCode = 1;
  } finally {
    if (pool) await pool.end();
  }
})();
