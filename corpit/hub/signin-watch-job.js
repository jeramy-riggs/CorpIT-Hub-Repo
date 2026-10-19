'use strict';
// SIGNIN-WATCH-JOB v2.4.0 (Entra risk detection watcher + correlation) — near-real-time sign-in watchlist poller
// Marker: SIGNIN-WATCH-JOB
// PM2 process (name: signin-watch). Cycle: every POLL_MS (default 60s):
//   1. load active watchlist + enabled trusted networks
//   2. poll Okta System Log since cursor (client-side filter to watchlist)
//   3. poll Entra signIns per watched user since cursor
//   4. any watched sign-in from a non-trusted IP -> insert violation (idempotent) -> dispatch alerts
// Cursors + heartbeat live in signin_watch_state.

require('dotenv').config();
const mysql = require('mysql2/promise');
const { ipTrustedType, normalizeOktaEvent, normalizeEntraEvent, fmtDateTimeSql } = require('./signin-watch-lib');
let ziaAuth = null;
try { ({ ziaAuth } = require('./zscaler-lookup')); } catch (e) { console.warn('[signin-watch] zscaler-lookup not found — ZDX cross-ref disabled'); }
const ZDX_XREF = process.env.SIGNIN_WATCH_ZDX_XREF !== '0';   // default ON
const ZDX_WINDOW_MIN = 60;
const { dispatch } = require('./alert-dispatch');
// v2.1.0: reuse the server-side snapshot builder from the routes module
let buildInvestigationSnapshot = null;
try { buildInvestigationSnapshot = require('./signin-watch-routes').buildInvestigationSnapshot; } catch (e) { console.warn('[signin-watch] snapshot builder not available:', e.message); }
// v2.2.0: SDP lookup for pause-ticket status checks
let sdpLookup = null;
try { sdpLookup = require('./sdp-lookup'); } catch (e) { console.warn('[signin-watch] sdp-lookup not available — pause auto-resume disabled'); }
const PAUSE_CHECK_MS = parseInt(process.env.SIGNIN_WATCH_PAUSE_CHECK_MS || '300000', 10);   // 5 min
const PAUSE_CLOSED = new Set(['resolved', 'closed', 'cancelled', 'canceled']);
let lastPauseCheck = 0;
// v2.4.0: Entra risk detection watcher
const RISK_CHECK_MS = parseInt(process.env.SIGNIN_WATCH_RISK_CHECK_MS || '300000', 10);   // 5 min
const RISK_ALERT_TYPES = new Set(['leakedCredentials', 'passwordSpray', 'maliciousIPAddress', 'suspiciousBrowser', 'anomalousToken']);
let lastRiskCheck = 0;
// v2.5.0: device/geo alert suppression
// Home country = US. Providers differ: Entra gives ISO-2 ("US"), Okta gives full name ("United States").
const US_COUNTRY_VALUES = new Set(['us', 'usa', 'united states', 'united states of america']);
function isUsCountry(c) { return !!c && US_COUNTRY_VALUES.has(String(c).trim().toLowerCase()); }
// Impossible-travel window: a different-country sighting for the same user within this many hours.
const IMPOSSIBLE_TRAVEL_HOURS = parseInt(process.env.SIGNIN_WATCH_IMPOSSIBLE_TRAVEL_HOURS || '4', 10);

const POLL_MS = parseInt(process.env.SIGNIN_WATCH_POLL_MS || '60000', 10);
const LOOKBACK_MIN = 15;           // first-run lookback
// [CORPIT-QA 2026-09-08] Events older than this are recorded but never alerted
// on -- see the stale-cursor gate in handleViolation(). 360 min is far wider
// than any normal poll gap (POLL_MS is 60s) and far short of a multi-day
// catch-up, so a brief outage still pages and a ten-day one never does.
const MAX_ALERT_AGE_MIN = parseInt(process.env.SIGNIN_WATCH_MAX_ALERT_AGE_MIN || '360', 10);
const OKTA_PAGE_LIMIT = 500;
const OKTA_MAX_PAGES = 5;
const ENTRA_TOP = 100;

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 3,
});

const log = (...a) => console.log(new Date().toISOString(), '[signin-watch]', ...a);
const warn = (...a) => console.warn(new Date().toISOString(), '[signin-watch] WARN', ...a);

// ── state helpers ─────────────────────────────────────────────────────
async function getState(key) {
  const [rows] = await pool.query('SELECT key_value FROM signin_watch_state WHERE key_name = ?', [key]);
  return rows.length ? rows[0].key_value : null;
}
async function setState(key, value) {
  await pool.query(
    'INSERT INTO signin_watch_state (key_name, key_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE key_value = VALUES(key_value)',
    [key, value]);
}

// ── Entra token (cached) ──────────────────────────────────────────────
let entraTok = { token: null, exp: 0 };
async function entraToken() {
  if (entraTok.token && Date.now() < entraTok.exp - 60000) return entraTok.token;
  const r = await fetch(`https://login.microsoftonline.com/${process.env.ENTRA_TENANT_ID}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: process.env.ENTRA_CLIENT_ID,
      client_secret: process.env.ENTRA_CLIENT_SECRET,
      scope: 'https://graph.microsoft.com/.default',
      grant_type: 'client_credentials',
    }),
    signal: AbortSignal.timeout(15000),
  });
  const j = await r.json();
  if (!j.access_token) throw new Error('entra token: ' + (j.error_description || j.error || r.status));
  entraTok = { token: j.access_token, exp: Date.now() + (j.expires_in || 3600) * 1000 };
  return entraTok.token;
}

// ── Okta poll ─────────────────────────────────────────────────────────
const OKTA_EVENT_RE = /^user\.(session\.start|authentication\.)/;

async function pollOkta(watchSet) {
  let since = await getState('okta_cursor');
  if (!since) since = new Date(Date.now() - LOOKBACK_MIN * 60000).toISOString();
  let url = `${process.env.OKTA_BASE_URL}/api/v1/logs?since=${encodeURIComponent(since)}&sortOrder=ASCENDING&limit=${OKTA_PAGE_LIMIT}`;
  const hits = [];
  let lastPublished = since;
  let pages = 0;
  while (url && pages < OKTA_MAX_PAGES) {
    const r = await fetch(url, {
      headers: { Authorization: 'SSWS ' + process.env.OKTA_API_TOKEN },
      signal: AbortSignal.timeout(20000),
    });
    if (r.status !== 200) throw new Error('okta HTTP ' + r.status + ': ' + (await r.text()).slice(0, 200));
    const events = await r.json();
    if (!events.length) break;
    for (const ev of events) {
      if (ev.published) lastPublished = ev.published;
      if (!OKTA_EVENT_RE.test(ev.eventType || '')) continue;
      const upn = ((ev.actor && ev.actor.alternateId) || '').toLowerCase();
      const w = watchSet.get(upn);
      if (w && w.watch_okta) { const ne = normalizeOktaEvent(ev); ne.tier = w.tier || 'standard'; if (w.pause_ticket_id) ne.__pause = { id: w.pause_ticket_id, display: w.pause_ticket_display || String(w.pause_ticket_id), url: w.pause_ticket_url || null }; hits.push(ne); }
    }
    pages++;
    // pagination: Link header rel="next"
    const link = r.headers.get('link') || '';
    const m = link.match(/<([^>]+)>;\s*rel="next"/);
    url = (events.length === OKTA_PAGE_LIMIT && m) ? m[1] : null;
  }
  // advance cursor 1ms past last seen event to avoid re-reading it
  if (lastPublished !== since) {
    const next = new Date(new Date(lastPublished).getTime() + 1).toISOString();
    await setState('okta_cursor', next);
  } else {
    await setState('okta_cursor', since);
  }
  return hits;
}

// ── Entra poll ────────────────────────────────────────────────────────
async function pollEntra(watchRows) {
  const entraUsers = watchRows.filter(w => w.watch_entra);
  if (!entraUsers.length) return [];
  let since = await getState('entra_cursor');
  if (!since) since = new Date(Date.now() - LOOKBACK_MIN * 60000).toISOString();
  const token = await entraToken();
  const hits = [];
  let maxSeen = since;
  for (const w of entraUsers) {
    const filter = `userPrincipalName eq '${w.upn.replace(/'/g, "''")}' and createdDateTime gt ${since}`;
    let url = `https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=${encodeURIComponent(filter)}&$top=${ENTRA_TOP}`;
    let pages = 0;
    while (url && pages < 3) {
      const r = await fetch(url, { headers: { Authorization: 'Bearer ' + token }, signal: AbortSignal.timeout(25000) });
      if (r.status === 429) { warn('entra 429, backing off this cycle'); return hits; }
      if (r.status !== 200) throw new Error('entra HTTP ' + r.status + ': ' + (await r.text()).slice(0, 200));
      const j = await r.json();
      for (const ev of (j.value || [])) {
        { const ne = normalizeEntraEvent(ev); ne.tier = w.tier || 'standard'; if (w.pause_ticket_id) ne.__pause = { id: w.pause_ticket_id, display: w.pause_ticket_display || String(w.pause_ticket_id), url: w.pause_ticket_url || null }; hits.push(ne); }
        if (ev.createdDateTime && ev.createdDateTime > maxSeen) maxSeen = ev.createdDateTime;
      }
      url = j['@odata.nextLink'] || null;
      pages++;
    }
  }
  if (maxSeen !== since) {
    await setState('entra_cursor', new Date(new Date(maxSeen).getTime() + 1).toISOString());
  } else {
    await setState('entra_cursor', since);
  }
  return hits;
}

// ── ZDX cross-ref: is this user actually present on a Zscaler-managed device? ──
// Fail-open: any ZDX error returns true (treat as trusted) so API blips never
// generate false alarms; the error is recorded in signin_watch_state.
async function zdxUserPresent(upn, cache) {
  if (!ZDX_XREF || !ziaAuth) return true;
  if (cache.has(upn)) return cache.get(upn);
  let present = true;
  try {
    const token = await ziaAuth();
    const now = Math.floor(Date.now() / 1000);
    const from = now - ZDX_WINDOW_MIN * 60;
    const r = await fetch('https://api.zsapi.net/zdx/v1/devices?q=' + encodeURIComponent(upn) + '&from=' + from + '&to=' + now, {
      headers: { Authorization: 'Bearer ' + token },
      signal: AbortSignal.timeout(15000),
    });
    if (r.status === 200) {
      const j = await r.json();
      const list = Array.isArray(j) ? j : (j.devices || j.items || []);
      present = list.length > 0;
      await setState('zdx_xref_last_error', '');
    } else {
      await setState('zdx_xref_last_error', 'HTTP ' + r.status);
    }
  } catch (e) {
    try { await setState('zdx_xref_last_error', e.message.slice(0, 300)); } catch (e2) {}
  }
  cache.set(upn, present);
  return present;
}

// ── ip-api.com ASN/ISP enrichment (v2.0.0) ──────────────────────────
// Free tier: HTTP only, 45 req/min — well within our volume.
// Fail-open: errors return null, violation still recorded without ASN.
const ipApiCache = new Map();
async function ipApiLookup(ip) {
  if (!ip) return { asn: null, isp: null };
  if (ipApiCache.has(ip)) return ipApiCache.get(ip);
  let result = { asn: null, isp: null };
  try {
    const r = await fetch('http://ip-api.com/json/' + encodeURIComponent(ip) + '?fields=as,isp,org,proxy', {
      signal: AbortSignal.timeout(5000),
    });
    if (r.status === 200) {
      const j = await r.json();
      // j.as = "AS12345 Some Org" — extract just the AS number
      const asMatch = (j.as || '').match(/^AS(\d+)/);
      result = {
        asn: asMatch ? 'AS' + asMatch[1] : (j.as || '').slice(0, 20),
        isp: (j.isp || j.org || '').slice(0, 200),
      };
    } else if (r.status === 429) {
      log('ip-api rate-limited, skipping enrichment');
    }
  } catch (e) { /* fail-open — enrichment is best-effort */ }
  ipApiCache.set(ip, result);
  return result;
}

// ── violation insert + alert ──────────────────────────────────────────
async function recordViolation(v) {
  // v2.0.0: enrich with ASN/ISP before insert
  const geo = await ipApiLookup(v.ip);
  const [r] = await pool.query(
    `INSERT IGNORE INTO signin_violations
       (upn, source, source_event_id, event_time, ip, geo_country, geo_city,
        geo_asn, geo_isp, result,
        failure_reason, app_name, client_app, user_agent, raw_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [v.upn, v.source, v.source_event_id, fmtDateTimeSql(v.event_time), v.ip,
     v.geo_country, v.geo_city, geo.asn, geo.isp, v.result, v.failure_reason,
     v.app_name ? String(v.app_name).slice(0, 200) : null,
     v.client_app ? String(v.client_app).slice(0, 200) : null,
     v.user_agent ? String(v.user_agent).slice(0, 500) : null,
     JSON.stringify(v.raw)]);
  if (r.affectedRows === 0) return false;   // duplicate — already seen + alerted
  const insertId = r.insertId;

  // v2.4.0: correlate with Microsoft's own detections — same user ±30 min.
  // Two independent engines agreeing is the strongest signal we can produce.
  let msMatch = null;
  try {
    const [[m]] = await pool.query(
      `SELECT risk_event_type, risk_level, ip_address FROM entra_risk_detections
       WHERE LOWER(user_principal_name) = ?
         AND ABS(TIMESTAMPDIFF(MINUTE, COALESCE(activity_date_time, detected_date_time), ?)) <= 30
       ORDER BY risk_level = 'high' DESC, detected_date_time DESC LIMIT 1`,
      [v.upn.toLowerCase(), fmtDateTimeSql(v.event_time)]);
    if (m) {
      msMatch = { type: m.risk_event_type, level: m.risk_level, ip_match: !!(m.ip_address && m.ip_address === v.ip) };
      await pool.query('UPDATE signin_violations SET ms_risk_match = ? WHERE id = ?', [JSON.stringify(msMatch), insertId]);
      v.ms_risk_match = msMatch;
      log(`VIOLATION ${v.upn} correlated with MS detection: ${m.risk_event_type} (${m.risk_level})${msMatch.ip_match ? ' same IP' : ''}`);
    }
  } catch (e) { warn('ms correlate:', e.message); }

  // v2.1.0: auto-investigate — always for VIP, then attach snapshot to payload
  let snapshot = null;
  const needsAutoInv = (v.tier === 'vip');
  if (needsAutoInv && buildInvestigationSnapshot) {
    try {
      snapshot = await buildInvestigationSnapshot(pool, insertId);
      if (snapshot) {
        await pool.query('UPDATE signin_violations SET auto_investigation = ?, investigated_at = NOW() WHERE id = ?',
          [JSON.stringify(snapshot), insertId]);
      }
    } catch (e) { warn('auto-investigate:', e.message); }
  }

  // v2.5.0: enrich BEFORE any suppression decision (device_managed / geo drive the gate)
  v.snapshot = snapshot;
  try {
    const raw = v.raw || {};
    // Entra fields
    if (v.source === 'entra') {
      v.resource = raw.resourceDisplayName || null;
      v.device_managed = raw.deviceDetail ? raw.deviceDetail.isManaged : null;
      v.device_id = raw.deviceDetail ? (raw.deviceDetail.deviceId || null) : null;
      v.ca_status = raw.conditionalAccessStatus || null;
    }
    // Okta fields
    if (v.source === 'okta') {
      v.resource = raw.target ? (raw.target[0] && raw.target[0].displayName) : null;
      v.device_managed = null; // not available in Okta System Log
      v.device_id = raw.client && raw.client.id ? raw.client.id : null;
    }
  } catch (e) { /* non-fatal — enrichment best-effort */ }

  // [CORPIT-QA 2026-09-08] Stale-cursor backfill gate. LOOKBACK_MIN above only
  // guards a MISSING cursor; a STALE cursor is the dangerous case and was not
  // guarded at all. This process was started under pm2 for the first time on
  // 2026-09-08 with entra_cursor still reading 2026-08-28, so ten days of
  // history replayed through dispatch() and fired 95 Teams cards for events
  // ITAM had already alerted on when they actually happened. "New to this
  // process" is not "new in the world". The violation is still recorded in
  // full, with the same enrichment -- only the page is withheld.
  const ageMin = (Date.now() - new Date(v.event_time).getTime()) / 60000;
  if (Number.isFinite(ageMin) && ageMin > MAX_ALERT_AGE_MIN) {
    await pool.query(
      'UPDATE signin_violations SET alert_sent = 0, alert_channels_hit = ? WHERE id = ?',
      [JSON.stringify({ suppressed: 'stale_backfill', age_min: Math.round(ageMin),
                        max_age_min: MAX_ALERT_AGE_MIN }).slice(0, 500), insertId]);
    log(`VIOLATION ${v.upn} ${v.source} ${v.result} ip=${v.ip} — alert suppressed `
      + `(backfill: event is ${Math.round(ageMin)} min old, limit ${MAX_ALERT_AGE_MIN})`);
    return true;
  }

  // v2.2.0: alert pause — record the violation but suppress dispatch while the
  // linked SDP ticket stays open. Investigation data is still captured above.
  if (v.__pause) {
    // v2.3.0: auto-associate the new violation with the pause ticket
    await pool.query(
      'UPDATE signin_violations SET alert_sent = 0, alert_channels_hit = ?, sdp_ticket_id = ?, sdp_ticket_url = ? WHERE id = ?',
      [JSON.stringify({ suppressed: 'paused', ticket: v.__pause.display }).slice(0, 500),
       v.__pause.id || null, v.__pause.url || null, insertId]);
    log(`VIOLATION ${v.upn} ${v.source} ${v.result} ip=${v.ip} — alert suppressed (paused, SDP #${v.__pause.display})`);
    return true;
  }

  // v2.5.0: device/geo suppression gate.
  // This code only ever runs for UNTRUSTED IPs (Zscaler egress is in trusted_networks,
  // so on-VPN sign-ins never reach here). We suppress the alert — but still record and
  // investigate — only when we can POSITIVELY clear the event:
  //   US geo + managed/company device + no impossible travel + no MS risk correlation.
  // Anything we cannot clear still alerts. Out-of-country always alerts (urgent).
  try {
    const us = isUsCountry(v.geo_country);
    const managed = (v.device_managed === true);
    const hasRisk = !!v.ms_risk_match;

    // Impossible travel (US only): same user seen in a DIFFERENT country within the window.
    let impossibleTravel = false;
    if (us && managed && !hasRisk) {
      try {
        const [[prior]] = await pool.query(
          `SELECT geo_country FROM signin_violations
             WHERE upn = ? AND id <> ?
               AND geo_country IS NOT NULL AND geo_country <> ''
               AND event_time >= (? - INTERVAL ? HOUR)
               AND NOT (LOWER(geo_country) IN ('us','usa','united states','united states of america'))
             ORDER BY event_time DESC LIMIT 1`,
          [v.upn, insertId, fmtDateTimeSql(v.event_time), IMPOSSIBLE_TRAVEL_HOURS]);
        if (prior) impossibleTravel = true;
      } catch (e) { warn('impossible-travel check:', e.message); }
    }

    const suppress = us && managed && !hasRisk && !impossibleTravel;
    if (suppress) {
      await pool.query(
        'UPDATE signin_violations SET alert_sent = 0, alert_channels_hit = ? WHERE id = ?',
        [JSON.stringify({ suppressed: 'managed-us', device_managed: true, geo_country: v.geo_country || null }).slice(0, 500), insertId]);
      log(`VIOLATION ${v.upn} ${v.source} ${v.result} ip=${v.ip} geo=${v.geo_city || '?'},${v.geo_country || '?'} — alert suppressed (managed US device, no impossible travel, no MS risk)`);
      return true;
    }
    // Not suppressed: mark out-of-country as urgent so dispatch/cards can flag it.
    if (!us) { v.urgent = true; v.urgent_reason = 'out_of_country'; }
    else if (impossibleTravel) { v.urgent = true; v.urgent_reason = 'impossible_travel'; }
  } catch (e) { warn('suppression gate:', e.message); }

  const out = await dispatch(pool, v);
  await pool.query(
    'UPDATE signin_violations SET alert_sent = ?, alert_channels_hit = ? WHERE id = ?',
    [out.sent.length ? 1 : 0,
     JSON.stringify({ sent: out.sent, failed: out.failed }).slice(0, 500),
     insertId]);
  log(`VIOLATION ${v.upn} ${v.source} ${v.result} ip=${v.ip} geo=${v.geo_city || '?'},${v.geo_country || '?'} alerts sent=${out.sent.length} failed=${out.failed.length}`);
  return true;
}

// ── main cycle ────────────────────────────────────────────────────────
// ── v2.2.0: pause-ticket status check — auto-resume when the SDP ticket closes ──
// Fail-safe: SDP errors keep the account paused (no alert flapping); the error
// is surfaced in signin_watch_state.pause_check_last_error.
async function checkPausedTickets() {
  if (!sdpLookup || !sdpLookup.getRequestById) return;
  let rows;
  try {
    [rows] = await pool.query(
      'SELECT id, upn, pause_ticket_id, pause_ticket_display FROM signin_watchlist WHERE pause_ticket_id IS NOT NULL');
  } catch (e) { return; }
  if (!rows.length) return;
  for (const w of rows) {
    try {
      const t = await sdpLookup.getRequestById(w.pause_ticket_id);
      const status = t ? String(t.status).toLowerCase() : 'missing';
      if (!t || PAUSE_CLOSED.has(status)) {
        await pool.query(
          `UPDATE signin_watchlist SET pause_ticket_id = NULL, pause_ticket_display = NULL,
             pause_ticket_url = NULL, paused_by = NULL, paused_at = NULL WHERE id = ?`, [w.id]);
        log(`pause auto-resumed ${w.upn} — SDP #${w.pause_ticket_display} is ${t ? t.status : 'not found'}; alerts re-enabled`);
      }
      await setState('pause_check_last_error', '');
    } catch (e) {
      try { await setState('pause_check_last_error', ('#' + w.pause_ticket_display + ': ' + e.message).slice(0, 300)); } catch (e2) {}
    }
  }
}

// ── v2.4.0: risk detection watcher ──
// Pulls new Entra risk detections from Graph (cursor in signin_watch_state.risk_cursor),
// upserts them into entra_risk_detections so every downstream reader gets fresher data,
// and dispatches an alert for watched users on high-risk / credential-level detections.
// leakedCredentials is the headline case: no sign-in ever occurs, so violation
// polling alone would never see it.
async function checkRiskDetections(watchSet) {
  let cursor = null;
  try {
    const [[row]] = await pool.query("SELECT key_value FROM signin_watch_state WHERE key_name = 'risk_cursor'");
    cursor = row ? row.key_value : null;
  } catch (e) {}
  if (!cursor) cursor = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
  const token = await entraToken();
  const filter = `detectedDateTime gt ${cursor}`;
  const url = `https://graph.microsoft.com/v1.0/identityProtection/riskDetections?$filter=${encodeURIComponent(filter)}&$top=50`;
  const r = await fetch(url, { headers: { Authorization: 'Bearer ' + token } });
  if (!r.ok) throw new Error('riskDetections HTTP ' + r.status);
  const j = await r.json();
  const rows = j.value || [];
  let maxSeen = cursor;
  for (const d of rows) {
    if (d.detectedDateTime > maxSeen) maxSeen = d.detectedDateTime;
    const upn = (d.userPrincipalName || '').toLowerCase();
    // upsert into the local table (id-checked; entra-sync remains the bulk owner)
    try {
      const [[ex]] = await pool.query('SELECT 1 AS x FROM entra_risk_detections WHERE entra_id = ? LIMIT 1', [d.id]);
      if (!ex) {
        await pool.query(
          `INSERT INTO entra_risk_detections
             (entra_id, user_principal_name, risk_event_type, risk_level, risk_state, risk_detail,
              source, detection_timing_type, ip_address, location_city, location_country,
              activity_date_time, detected_date_time)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
          [d.id, d.userPrincipalName, d.riskEventType, d.riskLevel, d.riskState, d.riskDetail,
           d.source, d.detectionTimingType, d.ipAddress,
           d.location ? d.location.city : null, d.location ? d.location.countryOrRegion : null,
           fmtDateTimeSql(d.activityDateTime), fmtDateTimeSql(d.detectedDateTime)]);
      } else {
        await pool.query('UPDATE entra_risk_detections SET risk_state = ?, risk_level = ? WHERE entra_id = ?',
          [d.riskState, d.riskLevel, d.id]);
      }
    } catch (e) { warn('risk upsert:', e.message); }
    // alert: watched user + (high risk OR headline detection type)
    const w = watchSet.get(upn);
    if (w && (d.riskLevel === 'high' || RISK_ALERT_TYPES.has(d.riskEventType))) {
      try {
        await dispatch(pool, {
          kind: 'risk_detection',
          upn,
          tier: w.tier || 'standard',
          result: 'failure',
          risk_event_type: d.riskEventType,
          risk_level: d.riskLevel,
          risk_detail: d.riskDetail,
          ip: d.ipAddress,
          geo_city: d.location ? d.location.city : null,
          geo_country: d.location ? d.location.countryOrRegion : null,
          event_time: d.activityDateTime || d.detectedDateTime,
        });
        log(`RISK DETECTION alerted ${upn} — ${d.riskEventType} (${d.riskLevel})`);
      } catch (e) { warn('risk dispatch:', e.message); }
    }
  }
  await setState('risk_cursor', maxSeen);
  if (rows.length) log(`risk detections: ${rows.length} new, cursor → ${maxSeen}`);
}

let running = false;
let _obsLast = 0;
// Observability: record a srv_job_run row every 5 minutes (or on any failed
// cycle) so this pm2 loop is visible as a scheduled job instead of 'never ran'.
async function _obsRecord(startedAt, ok, force) {
  if (!force && Date.now() - _obsLast < 5 * 60 * 1000) return;
  _obsLast = Date.now();
  try { await require('./obs-job').record(pool, 'signin-watch-job.js', { startedAt, finishedAt: new Date(), exitCode: ok ? 0 : 1 }); } catch (e) {}
}
async function cycle() {
  if (running) return;   // skip overlap
  running = true;
  const _cycleStart = new Date();
  let _cycleOk = true;
  try {
    // v2.2.0: periodically confirm pause tickets are still open (runs before
    // the watchlist load so auto-resumes take effect this same cycle)
    if (Date.now() - lastPauseCheck > PAUSE_CHECK_MS) {
      lastPauseCheck = Date.now();
      await checkPausedTickets();
    }
    const [watchRows] = await pool.query('SELECT upn, watch_okta, watch_entra, tier, pause_ticket_id, pause_ticket_display, pause_ticket_url FROM signin_watchlist WHERE active = 1');
    const [nets] = await pool.query('SELECT cidr, type, enabled FROM trusted_networks WHERE enabled = 1');
    await setState('last_cycle_at', new Date().toISOString());
    if (!watchRows.length) { await setState('last_cycle_note', 'watchlist empty'); return; }
    const watchSet = new Map(watchRows.map(w => [w.upn, w]));

    // v2.4.0: risk detection watcher (fail-soft — never blocks sign-in polling)
    if (Date.now() - lastRiskCheck > RISK_CHECK_MS) {
      lastRiskCheck = Date.now();
      try { await checkRiskDetections(watchSet); await setState('risk_check_last_error', ''); }
      catch (e) { warn('risk check:', e.message); try { await setState('risk_check_last_error', e.message.slice(0, 300)); } catch (e2) {} }
    }

    let events = [];
    try { events = events.concat(await pollOkta(watchSet)); await setState('okta_last_error', ''); }
    catch (e) { warn('okta poll:', e.message); await setState('okta_last_error', e.message.slice(0, 500)); }
    try { events = events.concat(await pollEntra(watchRows)); await setState('entra_last_error', ''); }
    catch (e) { warn('entra poll:', e.message); await setState('entra_last_error', e.message.slice(0, 500)); }

    let violations = 0;
    const zdxCache = new Map();
    for (const ev of events) {
      if (!ev.source_event_id) continue;
      const matchType = ipTrustedType(ev.ip, nets);
      if (matchType && matchType !== 'zscaler') continue;      // office/other trusted — not a violation
      if (matchType === 'zscaler') {
        // Zscaler egress: verify the user actually has a live ZDX device presence.
        if (await zdxUserPresent(ev.upn, zdxCache)) continue;   // genuine Zscaler user — trusted
        ev.failure_reason = ('ZSCALER-XREF: egress IP is Zscaler but user has no ZDX device presence (' + (ev.failure_reason || 'sign-in') + ')').slice(0, 500);
      }
      if (await recordViolation(ev)) violations++;
    }
    await setState('last_cycle_note', `events=${events.length} new_violations=${violations}`);
  } catch (e) {
    _cycleOk = false;
    warn('cycle:', e.message);
    try { await setState('last_cycle_note', 'ERROR ' + e.message.slice(0, 400)); } catch (e2) {}
  } finally {
    await _obsRecord(_cycleStart, _cycleOk, !_cycleOk);
    running = false;
  }
}

log(`starting — poll every ${POLL_MS}ms`);
cycle();
setInterval(cycle, POLL_MS);

process.on('SIGINT', () => { log('SIGINT, exiting'); process.exit(0); });
process.on('SIGTERM', () => { log('SIGTERM, exiting'); process.exit(0); });
