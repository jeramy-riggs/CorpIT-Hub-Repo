// collect-email-activity.js (v4)
// Pulls messages from helpdesk@auction.com via Graph and matches each one
// against sdops_request to determine: converted (new ticket), reply_logged
// (merged into an existing ticket's conversation), or no_ticket (no match).
//
// v3: scopes collection to the Inbox folder subtree only (Inbox + all its
// nested subfolders, however deep — e.g. monthly archive folders the team
// moves processed emails into), excluding Sent/Deleted/Drafts/Junk/etc.
//
// v4: adds conversationId-based fallback matching. The primary match is
// (requester_email, normalized subject) as before — but a reply from anyone
// OTHER than the original requester (e.g. a technician replying on the
// thread) won't match on requester_email. Fallback: if a message doesn't
// match by requester_email/subject, check whether any other message in this
// batch (or already stored from a prior run) shares its conversationId and
// DID resolve to a ticket — if so, inherit that ticket as 'reply_logged'
// regardless of who sent this particular message.
//
// Manual run: cd /var/www/corpit-hub-api && env $(cat .env | grep -v '^#' | grep -v '^$' | xargs) node collect-email-activity.js

const mysql = require('mysql2/promise');

const LOOKBACK_HOURS = parseInt(process.env.EMAIL_LOOKBACK_HOURS || '24', 10);
const MATCH_TOLERANCE_SEC = parseInt(process.env.EMAIL_MATCH_TOLERANCE_SEC || '180', 10);
const MAILBOX = process.env.HELPDESK_MAILBOX || 'helpdesk@auction.com';

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

async function getToken() {
  const res = await fetch(
    `https://login.microsoftonline.com/${process.env.ENTRA_TENANT_ID}/oauth2/v2.0/token`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.ENTRA_CLIENT_ID,
        client_secret: process.env.ENTRA_CLIENT_SECRET,
        scope: 'https://graph.microsoft.com/.default',
        grant_type: 'client_credentials',
      }),
    }
  );
  const data = await res.json();
  if (!data.access_token) throw new Error('Token failure: ' + JSON.stringify(data));
  return data.access_token;
}

async function buildInboxFolderSet(token) {
  const headers = { Authorization: `Bearer ${token}` };
  const base = `https://graph.microsoft.com/v1.0/users/${encodeURIComponent(MAILBOX)}/mailFolders`;

  const inboxRes = await fetch(`${base}/inbox`, { headers });
  if (!inboxRes.ok) throw new Error(`Graph ${inboxRes.status} (inbox lookup): ${await inboxRes.text()}`);
  const inbox = await inboxRes.json();

  const included = new Set([inbox.id]);
  let queue = [inbox.id];

  while (queue.length) {
    const next = [];
    for (const folderId of queue) {
      let url = `${base}/${encodeURIComponent(folderId)}/childFolders?$top=100&$select=id,childFolderCount`;
      while (url) {
        const res = await fetch(url, { headers });
        if (!res.ok) throw new Error(`Graph ${res.status} (childFolders): ${await res.text()}`);
        const data = await res.json();
        for (const f of data.value || []) {
          included.add(f.id);
          if (f.childFolderCount > 0) next.push(f.id);
        }
        url = data['@odata.nextLink'] || null;
      }
    }
    queue = next;
  }
  return included;
}

async function fetchMessages(token) {
  const since = new Date(Date.now() - LOOKBACK_HOURS * 3600 * 1000)
    .toISOString().replace(/\.\d{3}Z$/, 'Z');
  const filter = encodeURIComponent(`receivedDateTime ge ${since}`);
  const select = 'id,subject,from,receivedDateTime,parentFolderId,conversationId';
  let url = `https://graph.microsoft.com/v1.0/users/${encodeURIComponent(MAILBOX)}/messages` +
    `?$filter=${filter}&$select=${select}&$top=100&$orderby=receivedDateTime desc`;
  const rows = [];

  while (url) {
    const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    if (!res.ok) throw new Error(`Graph ${res.status}: ${await res.text()}`);
    const data = await res.json();
    for (const m of data.value || []) {
      rows.push({
        id: m.id,
        receivedAt: m.receivedDateTime ? new Date(m.receivedDateTime) : null,
        subject: m.subject || '',
        fromName: (m.from && m.from.emailAddress && m.from.emailAddress.name) || '',
        fromEmail: ((m.from && m.from.emailAddress && m.from.emailAddress.address) || '').toLowerCase(),
        parentFolderId: m.parentFolderId || '',
        conversationId: m.conversationId || '',
      });
    }
    url = data['@odata.nextLink'] || null;
  }
  return rows;
}

function normalizeSubject(s) {
  let out = (s || '').trim();
  const prefixRe = /^(re|fw|fwd|aw)\s*:\s*/i;
  while (prefixRe.test(out)) out = out.replace(prefixRe, '').trim();
  return out.toLowerCase();
}

async function loadCandidateTickets(pool, fromEmails) {
  if (!fromEmails.length) return [];
  const placeholders = fromEmails.map(() => '?').join(',');
  const [rows] = await pool.query(
    `SELECT id, subject, requester_email AS requesterEmail, technician,
            created_at AS createdAt, last_updated_at AS lastUpdatedAt
     FROM sdops_request
     WHERE LOWER(requester_email) IN (${placeholders})
       AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)`,
    fromEmails
  );
  return rows;
}

async function loadResolvedConversations(pool, conversationIds) {
  const ids = [...new Set(conversationIds.filter(Boolean))];
  if (!ids.length) return new Map();
  const placeholders = ids.map(() => '?').join(',');
  const [rows] = await pool.query(
    `SELECT conversation_id AS conversationId, matched_ticket_id AS ticketId, technician
     FROM sdops_email_activity
     WHERE conversation_id IN (${placeholders}) AND match_type != 'no_ticket'
       AND matched_ticket_id IS NOT NULL`,
    ids
  );
  const map = new Map();
  for (const r of rows) if (!map.has(r.conversationId)) map.set(r.conversationId, r);
  return map;
}

function primaryMatch(email, candidates) {
  const normEmailSubj = normalizeSubject(email.subject);
  const pool = candidates.filter(t => (t.requesterEmail || '').toLowerCase() === email.fromEmail
    && normalizeSubject(t.subject) === normEmailSubj);
  if (!pool.length) return null;

  const emailMs = email.receivedAt ? email.receivedAt.getTime() : 0;
  const toleranceMs = MATCH_TOLERANCE_SEC * 1000;

  let hit = pool.find(t => t.createdAt && Math.abs(new Date(t.createdAt).getTime() - emailMs) <= toleranceMs);
  if (hit) return { matchType: 'converted', ticketId: hit.id, technician: hit.technician || null };

  hit = pool.find(t => t.lastUpdatedAt && Math.abs(new Date(t.lastUpdatedAt).getTime() - emailMs) <= toleranceMs);
  if (hit) return { matchType: 'reply_logged', ticketId: hit.id, technician: hit.technician || null };

  const newest = pool.slice().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))[0];
  return { matchType: 'reply_logged', ticketId: newest.id, technician: newest.technician || null };
}

async function upsert(pool, rows) {
  if (!rows.length) return 0;
  const sql = `
    INSERT INTO sdops_email_activity
      (message_id, received_at, subject, from_name, from_email,
       matched_ticket_id, conversation_id, match_type, technician, collected_at)
    VALUES ?
    ON DUPLICATE KEY UPDATE
      matched_ticket_id = VALUES(matched_ticket_id),
      conversation_id = VALUES(conversation_id),
      match_type = VALUES(match_type),
      technician = VALUES(technician),
      collected_at = VALUES(collected_at)
  `;
  const [result] = await pool.query(sql, [rows]);
  return result.affectedRows;
}

(async () => {
  const started = new Date();
  let pool;
  try {
    const token = await getToken();
    const includedFolders = await buildInboxFolderSet(token);
    const allMessages = await fetchMessages(token);
    const messages = allMessages.filter(m => includedFolders.has(m.parentFolderId));
    const excludedCount = allMessages.length - messages.length;

    pool = await getPool();

    const uniqueFromEmails = [...new Set(messages.map(m => m.fromEmail).filter(Boolean))];
    const candidates = await loadCandidateTickets(pool, uniqueFromEmails);

    // Pass 1: primary (requester_email, subject) match.
    const results = messages.map(m => ({ email: m, match: primaryMatch(m, candidates) }));

    // Build conversationId -> resolved-ticket map from this batch's own hits.
    const convMap = new Map();
    for (const r of results) {
      if (r.match && r.email.conversationId && !convMap.has(r.email.conversationId)) {
        convMap.set(r.email.conversationId, { ticketId: r.match.ticketId, technician: r.match.technician });
      }
    }

    // Pass 2: for anything still unmatched, check prior runs' resolved conversations too.
    const stillUnmatched = results.filter(r => !r.match && r.email.conversationId);
    const priorResolved = await loadResolvedConversations(pool, stillUnmatched.map(r => r.email.conversationId));
    for (const [k, v] of priorResolved) if (!convMap.has(k)) convMap.set(k, v);

    const now = new Date();
    let conversationFallbackCount = 0;
    const rows = results.map(r => {
      let match = r.match;
      if (!match) {
        const inherited = convMap.get(r.email.conversationId);
        if (inherited) {
          match = { matchType: 'reply_logged', ticketId: inherited.ticketId, technician: inherited.technician };
          conversationFallbackCount++;
        } else {
          match = { matchType: 'no_ticket', ticketId: null, technician: null };
        }
      }
      return [
        r.email.id, r.email.receivedAt, r.email.subject, r.email.fromName, r.email.fromEmail,
        match.ticketId, r.email.conversationId || null, match.matchType, match.technician, now,
      ];
    });

    const affected = await upsert(pool, rows);
    const counts = rows.reduce((acc, r) => { acc[r[7]] = (acc[r[7]] || 0) + 1; return acc; }, {});
    console.log(`[${started.toISOString()}] folders=${includedFolders.size} fetched=${allMessages.length} ` +
      `in-scope=${rows.length} excluded=${excludedCount} conv-fallback=${conversationFallbackCount} affected=${affected} ` +
      `converted=${counts.converted || 0} reply_logged=${counts.reply_logged || 0} no_ticket=${counts.no_ticket || 0}`);
  } catch (err) {
    console.error(`[${started.toISOString()}] ERROR: ${err.message}`);
    process.exitCode = 1;
  } finally {
    if (pool) await pool.end();
  }
})();
