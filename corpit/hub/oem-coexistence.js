/**
 * oem-coexistence.js — "does this application accept two identity providers at once?" and, if so,
 * make it a priority: it can be added to Entra next to Okta, tested with real users and only then
 * cut over, with Okta as the live fallback the whole time.
 *
 * Three sources, each labelled where it shows:
 *   tenant   — a confirmed / identifier-matched Entra application (never a name-similarity guess)
 *              that is enabled and has an SSO mode, plus the interactive sign-ins the platform mirrors
 *              from Entra (entra_signin_logs, by appId) and, when checked, the Okta System Log
 *              (user.authentication.sso events for the app, cached in oem_okta_usage).
 *   vendor   — the vendor guide (oem-vendor-guides.js): documented support, with sources.
 *   recorded — a technician's answer on the scan row (oem_app_scan.coexistence).
 *
 * Levels (rank high → low; the queue sorts by rank before readiness):
 *   proven        both IdPs accepted sign-ins in the window (Entra mirror + Okta System Log)
 *   entra_active  Entra sign-ins seen; the Okta app is active but its usage is unchecked or none
 *   configured    Entra app confirmed, enabled, SSO mode set — no Entra sign-in in the window
 *   recorded      technician recorded "accepts two IdPs"
 *   documented    the vendor documents multi-IdP support (not verified in this tenant)
 *   unknown       nothing known
 *   single        vendor documents one IdP, or the technician recorded "no" — hard cutover
 * A missing sign-in mirror or an unchecked Okta usage is "unknown", never zero.
 */
'use strict';
const L = require('./oem-lib');
const G = require('./oem-vendor-guides');
const { pool, j, nowIso } = L;

const DAYS = 30;
const NO_SSO = /^(BOOKMARK|BROWSER_PLUGIN|SECURE_PASSWORD_STORE|AUTO_LOGIN|BASIC_AUTH)$/i;
// only a bookmark is a pure link; the other tile modes fill a vendor password, so a launch can be a password sign-in that never touches Entra
const PASSWORD_TILE = /^(BROWSER_PLUGIN|SECURE_PASSWORD_STORE|AUTO_LOGIN|BASIC_AUTH)$/i;
const STRATEGY = {
  coexist: 'Add Entra next to Okta, test with real users, then retire the Okta app',
  retire: 'Nothing to federate on the Okta side: confirm users reach the vendor through the Entra app, then retire the Okta tile',
  cutover: 'Vendor accepts one IdP: schedule the switch with the owner; Okta sign-in stops when the vendor is repointed',
  unknown: 'Ask the vendor / owner whether a second IdP can be added before planning the cutover',
};
const RANK = { proven: 6, entra_active: 5, configured: 4, recorded: 3, documented: 2, unknown: 1, single: 0 };
const LABEL = {
  proven: 'Accepts two IdPs — proven in this tenant',
  entra_active: 'Entra already in use alongside Okta',
  configured: 'Entra configured alongside Okta (no Entra sign-in yet)',
  recorded: 'Accepts two IdPs — recorded by a technician',
  documented: 'Accepts two IdPs — vendor documentation',
  unknown: 'Unknown',
  single: 'Single IdP — hard cutover',
};
const CONFIRMED = new Set(['manual_confirmed', 'auto_high']);

/** One query each: Entra sign-ins per appId in the window, the mirror's span, the cached Okta usage. */
async function loadEvidence({ days = DAYS } = {}) {
  const out = { days, entra: new Map(), mirror: { ok: false, oldest: null, newest: null, interactiveOnly: true, error: null }, okta: new Map() };
  try {
    const [[span]] = await pool.query(`SELECT MIN(created_at) oldest, MAX(created_at) newest, COUNT(*) total FROM entra_signin_logs`);
    const total = span ? Number(span.total || 0) : 0; // COUNT(*) arrives as a string from mysql2; "0" would be truthy
    out.mirror = { ok: total > 0, oldest: span ? span.oldest : null, newest: span ? span.newest : null, total, interactiveOnly: true, error: total > 0 ? null : 'the Entra sign-in mirror is empty' };
    const [rows] = await pool.query(`SELECT app_id, COUNT(*) c, MAX(created_at) last, SUM(outcome='SUCCESS') ok FROM entra_signin_logs WHERE created_at > NOW() - INTERVAL ? DAY AND app_id IS NOT NULL GROUP BY app_id`, [days]);
    for (const r of rows) out.entra.set(String(r.app_id).toLowerCase(), { count: Number(r.c), success: Number(r.ok || 0), last: r.last });
  } catch (e) { out.mirror = { ok: false, oldest: null, newest: null, interactiveOnly: true, error: 'sign-in mirror not readable: ' + e.message }; }
  try {
    const [u] = await pool.query(`SELECT okta_id, days, since, count, last_at, sample, error, checked_at, checked_by FROM oem_okta_usage`);
    for (const r of u) out.okta.set(r.okta_id, { days: r.days, since: r.since, count: r.count === null || r.count === undefined ? null : Number(r.count), last: r.last_at, sample: j(r.sample, []), error: r.error, checkedAt: r.checked_at, checkedBy: r.checked_by });
  } catch (e) { /* table absent until 004 runs: Okta usage reads as unchecked */ }
  // which confirmed Entra apps serve more than one Okta app: their sign-ins cannot be attributed to one vendor
  out.shared = new Map();
  try {
    const [m] = await pool.query(`SELECT SUBSTRING(w.item_key, 5) okta_id, a.label, a.status, JSON_UNQUOTE(JSON_EXTRACT(w.facts, '$.match.decision')) decision, JSON_UNQUOTE(JSON_EXTRACT(w.facts, '$.entra.appId')) app_id
      FROM oem_work_item w JOIN okta_apps a ON a.okta_id = SUBSTRING(w.item_key, 5) WHERE w.item_key LIKE 'app:%'`);
    for (const r of m) {
      if (!r.app_id || r.app_id === 'null' || !CONFIRMED.has(r.decision) || String(r.status || 'ACTIVE') === 'INACTIVE') continue;
      const k = String(r.app_id).toLowerCase();
      if (!out.shared.has(k)) out.shared.set(k, []);
      out.shared.get(k).push({ oktaId: r.okta_id, label: r.label });
    }
  } catch (e) { /* attribution unknown: treated as not shared, the evidence line still names the Entra app */ }
  return out;
}

/** Live Okta System Log read for one app: SSO events that name the app as target, last `days` days. */
async function checkOktaUsage(oktaId, { days = DAYS, actor = null } = {}) {
  const since = new Date(Date.now() - days * 86400000);
  // time window as `since=` (a `published gt` filter term matches nothing); target.id is canonical, case-safe
  const path = `/api/v1/logs?since=${encodeURIComponent(since.toISOString())}&limit=100&sortOrder=DESCENDING&filter=${encodeURIComponent(`eventType eq "user.authentication.sso" and target.id eq "${oktaId}"`)}`;
  const r = await L.oktaGet(path);
  const row = { oktaId, days, since, count: null, last: null, sample: [], error: null, checkedAt: nowIso(), checkedBy: actor };
  if (r.status === 200 && Array.isArray(r.body)) {
    const ev = r.body;
    row.count = ev.length; // capped at 100 by the read; enough to say "in use"
    row.capped = ev.length >= 100;
    row.last = ev.length ? ev[0].published : null;
    // every fetched event is kept (≤100 × {published, actor, outcome}) so oem-usage.js can count distinct users per window; rows written before this kept 5
    row.sample = ev.map((e) => ({ published: e.published, actor: e.actor && (e.actor.alternateId || e.actor.displayName) || null, outcome: e.outcome && e.outcome.result || null }));
  } else row.error = r.error || ('HTTP ' + r.status);
  await pool.query(`INSERT INTO oem_okta_usage (okta_id, days, since, count, last_at, sample, error, checked_at, checked_by) VALUES (?,?,?,?,?,?,?,NOW(),?)
                    ON DUPLICATE KEY UPDATE days=VALUES(days), since=VALUES(since), count=VALUES(count), last_at=VALUES(last_at), sample=VALUES(sample), error=VALUES(error), checked_at=NOW(), checked_by=VALUES(checked_by)`,
    [oktaId, days, since, row.count, row.last ? new Date(row.last) : null, JSON.stringify(row.sample), row.error, actor]);
  return row;
}

/** Record the technician's answer on the scan row. supported: true | false | null (clear). */
async function record(oktaId, { supported, note, actor }) {
  const [[cur]] = await pool.query(`SELECT coexistence FROM oem_app_scan WHERE okta_id=?`, [oktaId]);
  if (!cur) return { error: 'not scanned', status: 404, note: 'Scan the app first; the answer is recorded on the scan.' };
  const prev = j(cur.coexistence, null);
  const val = supported === null ? null : { supported: !!supported, note: note || null, by: actor, at: nowIso() };
  await pool.query(`UPDATE oem_app_scan SET coexistence=? WHERE okta_id=?`, [val ? JSON.stringify(val) : null, oktaId]);
  return { ok: true, coexistence: val, previous: prev };
}

/**
 * The signal for one app. Inputs: the queue row basics (name, label, oktaStatus, users, groups),
 * the work-item facts (match + entra), the scan's recorded answer, and the evidence maps.
 */
function coexistenceFor({ app, facts, recorded, evidence }) {
  const ev = evidence || { entra: new Map(), okta: new Map(), mirror: { ok: false }, days: DAYS };
  const days = ev.days || DAYS;
  const match = (facts && facts.match) || {};
  const entra = (facts && facts.entra) || null;
  const guide = G.guideFor(app);
  const gs = G.guideSummary(guide);
  const lines = [];
  const src = { tenant: null, vendor: null, recorded: recorded || null };

  /* tenant evidence: only a confirmed / identifier match counts, and only when the Entra app can sign people in */
  let tenantLevel = null;
  const confirmed = CONFIRMED.has(match.decision) && entra && entra.appId;
  const entraSso = confirmed && entra.enabled !== false && !!entra.ssoMode;
  const es = confirmed ? ev.entra.get(String(entra.appId).toLowerCase()) : null;
  const ou = ev.okta.get(app.oktaId) || null;
  const oktaActive = String(app.oktaStatus || 'ACTIVE') !== 'INACTIVE';
  // a bookmark / SWA tile does no federation: "two IdPs" cannot apply to the Okta side, Entra is simply the IdP already
  const tileOnly = NO_SSO.test(String(app.signOnMode || ''));
  if (confirmed) {
    src.tenant = { entraName: entra.name, entraAppId: entra.appId, decision: match.decision, ssoMode: entra.ssoMode || null, enabled: entra.enabled !== false, entraUsers: entra.users, entraGroups: entra.groups,
      entraSignIns: ev.mirror.ok ? { count: es ? es.count : 0, success: es ? es.success : 0, last: es ? es.last : null, days, basis: 'interactive sign-ins mirrored from Entra (entra_signin_logs), by appId' } : { count: null, days, basis: ev.mirror.error || 'mirror unavailable' },
      oktaUsage: ou ? { count: ou.count, last: ou.last, days: ou.days, checkedAt: ou.checkedAt, error: ou.error, capped: !!ou.capped } : { count: null, checkedAt: null, basis: 'not checked — "Check Okta usage" reads the Okta System Log for this app' } };
    if (entraSso) {
      const pwTile = PASSWORD_TILE.test(String(app.signOnMode || ''));
      if (tileOnly) lines.push(pwTile ? `The Okta app is a ${String(app.signOnMode).toLowerCase().replace(/_/g, ' ')} tile, not a federation: it fills a vendor password, so its launches can be password sign-ins that bypass Entra (${entra.name}) if the vendor still accepts them.`
        : `The Okta app is a bookmark tile, not a federation: the vendor already signs users in through Entra (${entra.name}).`);
      const others = (ev.shared && ev.shared.get(String(entra.appId).toLowerCase()) || []).filter((o) => o.oktaId !== app.oktaId);
      if (es && es.count > 0) {
        lines.push(`${es.count} Entra sign-in${es.count === 1 ? '' : 's'} in ${days} days through ${entra.name} (latest ${new Date(es.last).toISOString().slice(0, 10)}).`);
        const d = (x) => new Date(x).toISOString().slice(0, 10);
        if (tileOnly) {
          // a tile launch is not an IdP accepting a second federation; the most this proves is that Entra is live and the tile is (or is not) still used
          tenantLevel = 'entra_active';
          if (ou && ou.count > 0) lines.push(`${ou.count}${ou.capped ? '+' : ''} Okta tile launch${ou.count === 1 ? '' : 'es'} in ${ou.days} days (latest ${d(ou.last)}): ` + (pwTile ? 'the tile still fills a vendor password for those users — the migration is complete only if the vendor no longer accepts password sign-in; ask the application owner.' : 'users still start from the Okta tile, then sign in through Entra.'));
          else if (ou && ou.count === 0) lines.push(`No Okta tile launch in ${ou.days} days (checked ${d(ou.checkedAt)}): the tile is unused — retire it.`);
          else lines.push(ou && ou.error ? `Okta usage read failed: ${ou.error}.` : 'Okta tile launches not checked yet (one Okta System Log read).');
        } else if (ou && ou.count > 0) {
          if (others.length) { tenantLevel = 'entra_active'; lines.push(`${ou.count}${ou.capped ? '+' : ''} Okta SSO sign-in${ou.count === 1 ? '' : 's'} in ${ou.days} days (latest ${d(ou.last)}); ${entra.name} is also the confirmed Entra app for ${others.map((o) => o.label).join(', ')}, so its Entra sign-ins cannot be attributed to this vendor alone — not counted as proof of two IdPs.`); }
          else { tenantLevel = 'proven'; lines.push(`${ou.count}${ou.capped ? '+' : ''} Okta SSO sign-in${ou.count === 1 ? '' : 's'} in ${ou.days} days (latest ${d(ou.last)}): the vendor accepted both identity providers in the same window.`); }
        }
        else if (ou && ou.count === 0) { tenantLevel = 'entra_active'; lines.push(`No Okta SSO sign-in for this app in ${ou.days} days (checked ${d(ou.checkedAt)}): users may already be on Entra — verify, then retire the Okta app.`); }
        else { tenantLevel = 'entra_active'; lines.push(ou && ou.error ? `Okta usage read failed: ${ou.error}.` : 'Okta usage not checked yet (one Okta System Log read).'); }
        if (others.length && !(ou && ou.count > 0 && !tileOnly)) lines.push(`${entra.name} is also the confirmed Entra app for ${others.map((o) => o.label).join(', ')}: the Entra sign-ins are shared between them.`);
      } else if (ev.mirror.ok) { tenantLevel = 'configured'; lines.push(`${entra.name} is enabled with SSO mode ${entra.ssoMode} (${entra.users || 0} users / ${entra.groups || 0} groups assigned) but no Entra sign-in in ${days} days: coexistence is set up, not yet exercised.`); }
      else { tenantLevel = 'configured'; lines.push(`${entra.name} is enabled with SSO mode ${entra.ssoMode}; Entra sign-ins unknown (${ev.mirror.error || 'mirror unavailable'}).`); }
      if (!oktaActive) lines.push('The Okta app is inactive: nothing to coexist with — this is a retirement, not a migration.');
    } else if (confirmed) lines.push(`${entra.name} is the confirmed Entra app but ${entra.enabled === false ? 'it is disabled' : 'has no SSO mode configured'}: it cannot sign anyone in yet.`);
  }

  /* vendor documentation */
  if (gs.available) {
    src.vendor = { key: gs.key, vendor: gs.vendor, multiIdp: gs.multiIdp, checkedAt: gs.checkedAt, summary: gs.summary, recommended: gs.recommended };
    if (gs.multiIdp === 'yes' || gs.multiIdp === 'conditional') lines.push(`Vendor documentation (${gs.checkedAt}): ${gs.multiIdp === 'conditional' ? 'accepts two IdPs with conditions' : 'accepts more than one IdP'} — not verified in this tenant. See the Vendor guide tab.`);
    else if (gs.multiIdp === 'no') lines.push(`Vendor documentation (${gs.checkedAt}): one identity provider at a time — plan a hard cutover with the owner.`);
  }
  /* technician */
  if (recorded) lines.push(`Recorded by ${recorded.by || 'a technician'} ${recorded.at ? String(recorded.at).slice(0, 10) : ''}: ${recorded.supported ? 'accepts two IdPs' : 'single IdP'}${recorded.note ? ' — ' + recorded.note : ''}.`);

  /* level: tenant evidence wins, then the technician, then the vendor */
  let level = 'unknown';
  if (tenantLevel && oktaActive) level = tenantLevel;
  else if (recorded) level = recorded.supported ? 'recorded' : 'single';
  else if (gs.available && (gs.multiIdp === 'yes' || gs.multiIdp === 'conditional')) level = 'documented';
  else if (gs.available && gs.multiIdp === 'no') level = 'single';
  if (!lines.length) lines.push('No confirmed Entra app with SSO configured, no vendor guide and no technician answer for this application.');

  const strategy = level === 'single' ? 'cutover' : level === 'unknown' ? 'unknown' : (tileOnly && tenantLevel && oktaActive) ? 'retire' : 'coexist';
  return { level, label: LABEL[level], rank: RANK[level], priority: RANK[level] >= RANK.documented, strategy,
    strategyLabel: STRATEGY[strategy],
    evidence: lines, sources: src, guide: gs, window: { days, mirror: ev.mirror } };
}

/** Candidates for an Okta-usage sweep: active apps whose confirmed Entra app is enabled with an SSO mode. */
function sweepCandidate(app, facts) {
  const match = (facts && facts.match) || {}, entra = (facts && facts.entra) || null;
  return String(app.oktaStatus || app.status || 'ACTIVE') !== 'INACTIVE' && CONFIRMED.has(match.decision) && !!(entra && entra.appId && entra.enabled !== false && entra.ssoMode);
}

module.exports = { DAYS, RANK, LABEL, STRATEGY, NO_SSO, PASSWORD_TILE, loadEvidence, checkOktaUsage, record, coexistenceFor, sweepCandidate };
