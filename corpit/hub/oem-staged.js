'use strict';
/**
 * oem-staged.js — the Entra gallery mirror and the Entra-export Staged/Complete ledger (drop 8e).
 *
 *   Gallery   refreshGallery(log)          job 'entra-gallery' / source 'entra_gallery': applicationTemplates -> oem_gallery_template
 *             galleryFor(names)            {prefixes, oidc:[{id,name}], saml:[...]} for an application's names (oem-v2-model.galleryPick)
 *   Export    parseCsv(text)               the Entra "export service principals" CSV -> rows
 *             importExport({rows|csv, sourceFile, actor}, log)   upsert oem_entra_export; rows missing from a re-import are marked removed
 *   Sign-ins  checkStagedSignIns(log, ctx) job 'staged-signins' / source 'staged_signins': per export row read the sign-in mirror
 *                                          (entra_signin_logs, last VERIFIED_WINDOW_DAYS days) and, for rows still staged, the live
 *                                          Graph sign-in log; the first successful interactive sign-in flips staged -> complete,
 *                                          records the sign-in in oem_signin_evidence and writes an oem_work_event per linked Okta app.
 *   Reads     stagedMap()                  {byOkta: Map(oktaId -> info), byEntra: Map(entraId -> info)} for the list and the workspace
 *             stagedFor(oktaId)            the info for one Okta application (with its latest evidence rows) or null
 *             stagedList()                 every export row with its Okta links, possible (unconfirmed) matches and evidence, for /evidence
 *
 * Rules: SSO verification is the proof of completion — nothing here marks an application complete by hand, and complete is
 * terminal. Okta links are the confirmed match rows (oem_app_match state 'confirmed') and uncleared oem_app_migrated rows;
 * a suggested match is shown as "possible — not confirmed", never used to link. Evidence keeps who/when/how (UPN, time,
 * client, CA result, country): never an IP address, never a token. Every write is to CorpIT's own tables; Entra and Okta
 * are read only (L.graphGet / L.graphAll), and a missing table (schema not applied yet) reads as "no data", never a 500.
 */
const L = require('./oem-lib');
const M = require('./oem-v2-model');
const { pool } = L;

const VERIFIED_WINDOW_DAYS = 30;   // Entra keeps sign-in logs 30 days: a success older than that cannot be re-read, so it does not count
const GRAPH_TOP = 50;
const GALLERY_PATH = '/v1.0/applicationTemplates?$select=id,displayName,supportedSingleSignOnModes,publisher';
const SSO_MODES = ['saml', 'oidc', 'password'];
const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const rt = (e) => (typeof L.redactText === 'function' ? L.redactText : String)(e && e.message || e || '').slice(0, 300);
const lc = (v) => (v === null || v === undefined || v === '' ? null : String(v).trim().toLowerCase());
const iso = (d) => (d ? new Date(d).toISOString() : null);
/* A table this module needs may not exist on a database the SQL has not reached: read as empty, never throw. */
const MISSING = (e) => e && (e.code === 'ER_NO_SUCH_TABLE' || /doesn't exist/i.test(String(e.message || '')));
async function q(sql, params) { try { const [rows] = await pool.query(sql, params); return rows; } catch (e) { if (MISSING(e)) return []; throw e; } }

/* ---------------------------------------------------------------- gallery */
function modesOf(t) {
  const m = Array.isArray(t && t.supportedSingleSignOnModes) ? t.supportedSingleSignOnModes.map((x) => String(x).toLowerCase()) : [];
  return m.filter((x, i) => m.indexOf(x) === i).sort();
}
/* refreshGallery(log) -> {records, templates, pages, partial}. Pages WITHOUT $top: applicationTemplates?$top=999 answers exactly 999
   rows with no nextLink (the gallery holds ~39,000 templates, ~2,900 a page). Only templates carrying an SSO mode are kept. */
async function refreshGallery(log) {
  const say = typeof log === 'function' ? log : () => {};
  const r = await L.graphAll(GALLERY_PATH, { maxPages: 400 });
  if (!r.ok && !r.items.length) throw new Error('Entra gallery read failed: ' + (r.error || ('HTTP ' + r.status)));
  const keep = r.items.filter((t) => t && t.id && modesOf(t).some((m) => SSO_MODES.includes(m)));
  say(`gallery: ${r.items.length} template(s) in ${r.pages} page(s); ${keep.length} carry an SSO mode` + (r.partial ? ' (PARTIAL read: ' + (r.error || 'page cap') + ')' : ''), r.partial ? 'warn' : 'info');
  const [[{ t0 }]] = await pool.query('SELECT NOW() AS t0');
  let n = 0;
  for (let i = 0; i < keep.length; i += 400) {
    const chunk = keep.slice(i, i + 400);
    const values = chunk.map((t) => [String(t.id).slice(0, 36), String(t.displayName || '').slice(0, 255), t.publisher ? String(t.publisher).slice(0, 255) : null, modesOf(t).join(',').slice(0, 120), M.galleryStem(t.displayName).slice(0, 255)]);
    await pool.query('INSERT INTO oem_gallery_template (id, display_name, publisher, modes, stem, collected_at) VALUES ' + values.map(() => '(?,?,?,?,?,NOW())').join(',') +
      ' ON DUPLICATE KEY UPDATE display_name=VALUES(display_name), publisher=VALUES(publisher), modes=VALUES(modes), stem=VALUES(stem), collected_at=NOW()', values.flat());
    n += chunk.length;
  }
  if (r.ok && !r.partial) { const [d] = await pool.query('DELETE FROM oem_gallery_template WHERE collected_at < ?', [t0]); if (d && d.affectedRows) say(`gallery: ${d.affectedRows} template(s) no longer listed removed`); }
  return { records: n, templates: r.items.length, pages: r.pages, partial: !!r.partial };
}
/* galleryFor(names) -> {prefixes, oidc, saml}: the product's own templates for an application's names (Okta name/label, Entra destination). */
async function galleryFor(names) {
  const prefixes = M.galleryPrefixes(names);
  if (!prefixes.length) return { prefixes: [], oidc: [], saml: [] };
  const where = prefixes.map(() => '(stem = ? OR stem LIKE ?)').join(' OR ');
  const params = []; for (const p of prefixes) params.push(p, p.replace(/[%_\\]/g, '\\$&') + ' %');
  const rows = await q('SELECT id, display_name, modes, stem FROM oem_gallery_template WHERE ' + where + ' ORDER BY display_name LIMIT 200', params);
  return M.galleryPick(names, rows);
}

/* ----------------------------------------------------------------- export */
/* parseCsv(text) -> [{id, appId, name, state, identifierUri, homepage}] from the Entra enterprise-applications export
   (header: id,displayName,appId,homepage,state,appVisibility,identifierUri — matched by name, any order, quotes per RFC 4180). */
function parseCsv(text) {
  const src = String(text || '').replace(/^﻿/, '');
  const rows = []; let row = [], cell = '', inQ = false;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (inQ) { if (c === '"') { if (src[i + 1] === '"') { cell += '"'; i++; } else inQ = false; } else cell += c; continue; }
    if (c === '"') { inQ = true; continue; }
    if (c === ',') { row.push(cell); cell = ''; continue; }
    if (c === '\n' || c === '\r') { if (c === '\r' && src[i + 1] === '\n') i++; row.push(cell); rows.push(row); row = []; cell = ''; continue; }
    cell += c;
  }
  if (cell !== '' || row.length) { row.push(cell); rows.push(row); }
  const head = (rows.shift() || []).map((h) => String(h).trim().toLowerCase());
  const col = (name) => head.indexOf(name.toLowerCase());
  const ix = { id: col('id'), name: col('displayName'), appId: col('appId'), homepage: col('homepage'), state: col('state'), identifierUri: col('identifierUri') };
  if (ix.id < 0 || ix.name < 0) throw new Error('not an Entra application export: the header needs id and displayName columns');
  const pick = (r, i) => (i >= 0 && r[i] !== undefined ? String(r[i]).trim() : '');
  return rows.filter((r) => r.some((c) => String(c).trim() !== '')).map((r) => ({ id: pick(r, ix.id).toLowerCase(), appId: pick(r, ix.appId).toLowerCase() || null, name: pick(r, ix.name), state: pick(r, ix.state) || null, identifierUri: pick(r, ix.identifierUri) || null, homepage: pick(r, ix.homepage) || null }));
}
/* importExport({rows|csv, sourceFile, actor}, log) -> {imported, added, updated, removed, skipped:[{name, why}]}
   Upserts one oem_entra_export row per service principal; a row present before and missing from this import is marked
   removed_at (its evidence stays). Status is never touched by an import: a re-import cannot un-complete an application. */
async function importExport(input, log) {
  const say = typeof log === 'function' ? log : () => {};
  const inp = input || {};
  const rows = Array.isArray(inp.rows) ? inp.rows : parseCsv(inp.csv);
  const valid = [], skipped = [];
  for (const r of rows) {
    if (!r || !GUID_RE.test(String(r.id || ''))) { skipped.push({ name: r && r.name || '?', why: 'no object id' }); continue; }
    if (!String(r.name || '').trim()) { skipped.push({ name: r.id, why: 'no display name' }); continue; }
    valid.push(r);
  }
  if (!valid.length) throw new Error('the export has no usable rows' + (skipped.length ? ' (' + skipped.length + ' skipped)' : ''));
  const before = new Set((await q('SELECT entra_id FROM oem_entra_export')).map((x) => lc(x.entra_id)));
  let added = 0, updated = 0;
  for (const r of valid) {
    const id = lc(r.id);
    await pool.query(`INSERT INTO oem_entra_export (entra_id, app_id, display_name, identifier_uri, homepage, export_state, source_file, imported_by, imported_at, status, staged_at, removed_at)
      VALUES (?,?,?,?,?,?,?,?,NOW(),'staged',NOW(),NULL)
      ON DUPLICATE KEY UPDATE app_id=VALUES(app_id), display_name=VALUES(display_name), identifier_uri=VALUES(identifier_uri), homepage=VALUES(homepage), export_state=VALUES(export_state), source_file=VALUES(source_file), imported_by=VALUES(imported_by), imported_at=NOW(), removed_at=NULL`,
      [id, GUID_RE.test(String(r.appId || '')) ? lc(r.appId) : null, String(r.name).slice(0, 255), r.identifierUri ? String(r.identifierUri).slice(0, 500) : null, r.homepage ? String(r.homepage).slice(0, 500) : null, r.state ? String(r.state).slice(0, 40) : null, inp.sourceFile ? String(inp.sourceFile).slice(0, 255) : null, inp.actor ? String(inp.actor).slice(0, 190) : null]);
    if (before.has(id)) updated++; else added++;
  }
  const ids = valid.map((r) => lc(r.id));
  const [rm] = await pool.query('UPDATE oem_entra_export SET removed_at=NOW() WHERE removed_at IS NULL AND entra_id NOT IN (?)', [ids]);
  const removed = rm && rm.affectedRows ? rm.affectedRows : 0;
  say(`export import: ${valid.length} row(s) — ${added} added, ${updated} updated, ${removed} marked removed` + (skipped.length ? `, ${skipped.length} skipped` : ''));
  return { imported: valid.length, added, updated, removed, skipped };
}

/* ------------------------------------------------------------------ links */
/* linksFor(entraIds) -> Map(entraId -> [oktaId…]) from confirmed match rows and uncleared migrated records. */
async function linksFor(entraIds) {
  const out = new Map();
  const ids = entraIds.map(lc).filter(Boolean);
  if (!ids.length) return out;
  const add = (e, o) => { const k = lc(e), v = String(o || '').trim(); if (!k || !v) return; if (!out.has(k)) out.set(k, []); if (!out.get(k).includes(v)) out.get(k).push(v); };
  for (const r of await q(`SELECT okta_app_id, entra_sp_id FROM oem_app_match WHERE state='confirmed' AND invalidated_at IS NULL AND entra_sp_id IN (?)`, [ids])) add(r.entra_sp_id, r.okta_app_id);
  for (const r of await q(`SELECT okta_id, entra_id FROM oem_app_migrated WHERE cleared_at IS NULL AND entra_id IN (?)`, [ids])) add(r.entra_id, r.okta_id);
  return out;
}
/* possibleFor(entraIds) -> Map(entraId -> [{oktaId, name}]) — suggested/shortlisted matches, shown as "possible — not confirmed". */
async function possibleFor(entraIds) {
  const out = new Map();
  const ids = entraIds.map(lc).filter(Boolean);
  if (!ids.length) return out;
  const rows = await q(`SELECT okta_app_id, entra_sp_id, state FROM oem_app_match WHERE state IN ('suggested','shortlisted') AND invalidated_at IS NULL AND entra_sp_id IN (?)`, [ids]);
  const names = await oktaNames(rows.map((r) => r.okta_app_id));
  for (const r of rows) { const k = lc(r.entra_sp_id); if (!out.has(k)) out.set(k, []); if (!out.get(k).some((x) => x.oktaId === r.okta_app_id)) out.get(k).push({ oktaId: r.okta_app_id, name: names.get(r.okta_app_id) || r.okta_app_id, state: r.state }); }
  return out;
}
async function oktaNames(oktaIds) {
  const out = new Map();
  const ids = oktaIds.map((x) => String(x || '').trim()).filter(Boolean);
  if (!ids.length) return out;
  for (const r of await q(`SELECT source_id, title FROM oem_work_item WHERE category='applications' AND source_kind='okta_app' AND source_id IN (?)`, [ids])) out.set(r.source_id, r.title);
  return out;
}

/* --------------------------------------------------------------- sign-ins */
function rawOf(r) { const v = r && r.raw_json; if (!v) return null; if (typeof v === 'object') return v; try { return JSON.parse(v); } catch (e) { return null; } }
function evidenceOfMirror(r) {
  const raw = rawOf(r) || {};
  return { signinId: String(r.entra_id), at: r.created_at, user: r.user_principal_name || null, client: r.client_app_used || null, ca: r.conditional_access_status || null,
    auth: raw.authenticationRequirement || null, interactive: r.is_interactive === null || r.is_interactive === undefined ? true : !!Number(r.is_interactive), country: r.location_country || null, source: 'mirror' };
}
function evidenceOfGraph(r) {
  return { signinId: String(r.id), at: r.createdDateTime, user: r.userPrincipalName || null, client: r.clientAppUsed || null, ca: r.conditionalAccessStatus || null,
    auth: r.authenticationRequirement || null, interactive: r.isInteractive !== false, country: r.location && r.location.countryOrRegion || null, source: 'graph' };
}
async function recordEvidence(entraId, appId, ev) {
  if (!ev || !ev.signinId || !ev.at) return false;
  const [r] = await pool.query(`INSERT IGNORE INTO oem_signin_evidence (entra_id, app_id, signin_id, signin_at, user_principal_name, client_app, ca_status, auth_requirement, interactive, location_country, source) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
    [lc(entraId), lc(appId), String(ev.signinId).slice(0, 64), new Date(ev.at), ev.user ? String(ev.user).slice(0, 190) : null, ev.client ? String(ev.client).slice(0, 120) : null, ev.ca ? String(ev.ca).slice(0, 40) : null, ev.auth ? String(ev.auth).slice(0, 40) : null, ev.interactive ? 1 : 0, ev.country ? String(ev.country).slice(0, 8) : null, ev.source === 'graph' ? 'graph' : 'mirror']);
  return !!(r && r.affectedRows);
}
/* The live Graph read for one staged application (client appId, then resource object id), newest first. */
async function graphSignIns(appId, entraId, since) {
  const reads = [];
  if (appId) reads.push(L.graphGet(`/v1.0/auditLogs/signIns?$top=${GRAPH_TOP}&$filter=createdDateTime ge ${since} and appId eq '${appId}'`));
  if (entraId) reads.push(L.graphGet(`/v1.0/auditLogs/signIns?$top=${GRAPH_TOP}&$filter=createdDateTime ge ${since} and resourceId eq '${entraId}'`));
  const rs = await Promise.all(reads);
  const okReads = rs.filter((r) => r && r.status === 200);
  if (!okReads.length) return { ok: false, rows: [], error: rs.map((r) => r && (r.error || r.status)).filter(Boolean).join('; ') || 'no read' };
  const seen = new Set();
  const rows = okReads.flatMap((r) => (r.body && r.body.value) || []).filter((r) => { const id = r.id || (r.createdDateTime + '|' + r.userPrincipalName); if (seen.has(id)) return false; seen.add(id); return true; })
    .sort((a, b) => String(b.createdDateTime || '').localeCompare(String(a.createdDateTime || '')));
  return { ok: true, rows, partial: okReads.length < rs.length };
}
/**
 * checkStagedSignIns(log, ctx, opts) -> {records, staged, complete, completedNow:[{entraId, name, user, at}], graphReads, errors}
 * opts.noGraph skips the live Graph read (tests, offline). Each export row: mirror counts over the window; a staged row with
 * no mirror success also gets a live Graph read so "Check Entra sign-ins now" sees a sign-in made minutes ago.
 */
async function checkStagedSignIns(log, ctx, opts) {
  const say = typeof log === 'function' ? log : () => {};
  const o = opts || {};
  const rows = await q(`SELECT * FROM oem_entra_export WHERE removed_at IS NULL ORDER BY display_name`);
  if (!rows.length) { say('no Entra export rows: import the export first'); return { records: 0, staged: 0, complete: 0, completedNow: [], graphReads: 0, errors: [] }; }
  const days = VERIFIED_WINDOW_DAYS;
  /* one pass over the window for every application: counts by outcome, distinct users of the successes, last success */
  const appIds = rows.map((r) => lc(r.app_id)).filter(Boolean);
  const counts = new Map(), latestOf = new Map();
  if (appIds.length) {
    for (const c of await q(`SELECT LOWER(app_id) AS app_id, outcome, COUNT(*) AS c, COUNT(DISTINCT user_principal_name) AS users, MAX(created_at) AS last FROM entra_signin_logs WHERE LOWER(app_id) IN (?) AND created_at >= NOW() - INTERVAL ? DAY GROUP BY LOWER(app_id), outcome`, [appIds, days])) {
      const k = lc(c.app_id); if (!counts.has(k)) counts.set(k, { ok: 0, fail: 0, users: 0, last: null });
      const v = counts.get(k);
      if (String(c.outcome).toUpperCase() === 'SUCCESS') { v.ok += Number(c.c) || 0; v.users = Number(c.users) || 0; v.last = c.last || null; } else v.fail += Number(c.c) || 0;
    }
    /* the newest successful interactive sign-in per application, one pass (window function; MySQL 8) */
    for (const row of await q(`SELECT * FROM (SELECT entra_id, created_at, user_principal_name, client_app_used, conditional_access_status, is_interactive, location_country, raw_json, LOWER(app_id) AS app_id, ROW_NUMBER() OVER (PARTITION BY LOWER(app_id) ORDER BY created_at DESC) AS rn FROM entra_signin_logs WHERE LOWER(app_id) IN (?) AND outcome = 'SUCCESS' AND (is_interactive IS NULL OR is_interactive = 1) AND created_at >= NOW() - INTERVAL ? DAY) t WHERE rn = 1`, [appIds, days])) latestOf.set(lc(row.app_id), evidenceOfMirror(row));
  }
  const since = new Date(Date.now() - days * 86400000).toISOString();
  const links = await linksFor(rows.map((r) => r.entra_id));
  const out = { records: rows.length, staged: 0, complete: 0, completedNow: [], graphReads: 0, errors: [] };
  for (const r of rows) {
    if (typeof log === 'function' && log.cancelled && log.cancelled()) break;
    const entraId = lc(r.entra_id), appId = lc(r.app_id);
    const c = (appId && counts.get(appId)) || { ok: 0, fail: 0, users: 0, last: null };
    let latest = (appId && latestOf.get(appId)) || null;
    let graphOk = 0, graphFail = 0;
    if (!latest && r.status === 'staged' && !o.noGraph && (appId || entraId)) {
      out.graphReads++;
      try {
        const g = await graphSignIns(appId, entraId, since);
        if (!g.ok) { const why = rt(g.error); out.errors.push(r.display_name + ': ' + why); say(`${r.display_name}: Entra sign-in log not readable (${why})`, 'warn'); }
        else {
          const okRows = g.rows.filter((x) => x.status && x.status.errorCode === 0 && x.isInteractive !== false);
          graphOk = okRows.length; graphFail = g.rows.length - g.rows.filter((x) => x.status && x.status.errorCode === 0).length;
          if (okRows[0]) latest = evidenceOfGraph(okRows[0]);
        }
      } catch (e) { out.errors.push(r.display_name + ': ' + rt(e)); say(`${r.display_name}: Graph read failed: ${rt(e)}`, 'warn'); }
    }
    const ok = c.ok + graphOk, fail = c.fail + graphFail, users = Math.max(c.users, graphOk ? 1 : 0), lastOk = latest ? latest.at : c.last;
    if (latest) { try { await recordEvidence(entraId, appId, latest); } catch (e) { say(`${r.display_name}: evidence row not written: ${rt(e)}`, 'warn'); } }
    if (r.status === 'staged' && latest) {
      const [u] = await pool.query(`UPDATE oem_entra_export SET status='complete', completed_at=NOW(), completed_signin_id=?, completed_signin_at=?, completed_user=?, last_checked_at=NOW(), signin_ok=?, signin_fail=?, signin_users=?, signin_last_ok_at=? WHERE entra_id=? AND status='staged'`,
        [String(latest.signinId).slice(0, 64), new Date(latest.at), latest.user ? String(latest.user).slice(0, 190) : null, ok, fail, users, lastOk ? new Date(lastOk) : null, entraId]);
      if (u && u.affectedRows) {
        out.completedNow.push({ entraId, name: r.display_name, user: latest.user, at: iso(latest.at) });
        say(`${r.display_name}: Complete — ${latest.user || 'a user'} signed in through Entra at ${iso(latest.at)} (${latest.source})`);
        const note = M.stagedWhy({ name: r.display_name, completedUser: latest.user, completedSigninAt: iso(latest.at) });
        const evidence = JSON.stringify({ entraId, appId, signinId: latest.signinId, signinAt: iso(latest.at), user: latest.user, client: latest.client, ca: latest.ca, source: latest.source });
        for (const oktaId of links.get(entraId) || []) {
          try { await pool.query(`INSERT INTO oem_work_event (item_key, event, from_state, to_state, note, actor_email, evidence, created_at) VALUES (?,?,?,?,?,?,?,NOW())`, ['app:' + oktaId, 'sso_verified', 'staged', 'complete', note.slice(0, 500), 'signin-evidence', evidence]); }
          catch (e) { say(`${r.display_name}: work event for ${oktaId} not written: ${rt(e)}`, 'warn'); }
        }
        out.complete++;
        continue;
      }
    }
    await pool.query(`UPDATE oem_entra_export SET last_checked_at=NOW(), signin_ok=?, signin_fail=?, signin_users=?, signin_last_ok_at=? WHERE entra_id=?`, [ok, fail, users, lastOk ? new Date(lastOk) : null, entraId]);
    if (r.status === 'complete') out.complete++; else out.staged++;
  }
  say(`sign-in check: ${out.records} application(s) — ${out.complete} complete, ${out.staged} staged` + (out.completedNow.length ? `; completed now: ${out.completedNow.map((x) => x.name).join(', ')}` : '') + (out.graphReads ? `; ${out.graphReads} live Graph read(s)` : ''));
  return out;
}

/* ------------------------------------------------------------------ reads */
function infoOf(r, oktaIds) {
  return { entraId: lc(r.entra_id), appId: lc(r.app_id), name: r.display_name, status: r.status, exportState: r.export_state || null, importedAt: iso(r.imported_at), sourceFile: r.source_file || null,
    stagedAt: iso(r.staged_at), completedAt: iso(r.completed_at), completedUser: r.completed_user || null, completedSigninAt: iso(r.completed_signin_at), completedSigninId: r.completed_signin_id || null,
    lastCheckedAt: iso(r.last_checked_at), signinOk: Number(r.signin_ok) || 0, signinFail: Number(r.signin_fail) || 0, signinUsers: Number(r.signin_users) || 0, lastOkAt: iso(r.signin_last_ok_at),
    window: VERIFIED_WINDOW_DAYS, oktaIds: oktaIds || [], removedAt: iso(r.removed_at) };
}
const rank = (s) => (s === 'complete' ? 2 : s === 'staged' ? 1 : 0);
/* stagedMap() -> {byOkta, byEntra}: one read for every export row; an Okta app linked to two rows keeps the complete one. */
async function stagedMap() {
  const rows = await q(`SELECT * FROM oem_entra_export WHERE removed_at IS NULL`);
  const byOkta = new Map(), byEntra = new Map();
  if (!rows.length) return { byOkta, byEntra };
  const links = await linksFor(rows.map((r) => r.entra_id));
  for (const r of rows) {
    const info = infoOf(r, links.get(lc(r.entra_id)) || []);
    byEntra.set(info.entraId, info);
    for (const o of info.oktaIds) { const cur = byOkta.get(o); if (!cur || rank(info.status) > rank(cur.status)) byOkta.set(o, info); }
  }
  return { byOkta, byEntra };
}
async function evidenceRows(entraId, limit) {
  const rows = await q(`SELECT signin_id, signin_at, user_principal_name, client_app, ca_status, auth_requirement, interactive, location_country, source FROM oem_signin_evidence WHERE entra_id=? ORDER BY signin_at DESC LIMIT ?`, [lc(entraId), Math.max(1, Math.min(50, Number(limit) || 5))]);
  return rows.map((e) => ({ signinId: e.signin_id, at: iso(e.signin_at), user: e.user_principal_name || null, client: e.client_app || null, ca: e.ca_status || null, auth: e.auth_requirement || null, interactive: !!Number(e.interactive), country: e.location_country || null, source: e.source }));
}
/* stagedFor(oktaId) -> the info for one Okta application (+ evidence rows) or null. */
async function stagedFor(oktaId) {
  const { byOkta } = await stagedMap();
  const info = byOkta.get(String(oktaId || '').trim());
  if (!info) return null;
  return Object.assign({}, info, { evidence: await evidenceRows(info.entraId, 5) });
}
/* stagedList() -> {window, checkedAt, counts, rows} for the Evidence section: every export row, its Okta links (names), possible matches, evidence. */
async function stagedList() {
  const rows = await q(`SELECT * FROM oem_entra_export WHERE removed_at IS NULL ORDER BY status, display_name`);
  const ids = rows.map((r) => r.entra_id);
  const links = await linksFor(ids);
  const possible = await possibleFor(ids);
  const names = await oktaNames([].concat(...Array.from(links.values())));
  const out = [];
  let checkedAt = null;
  for (const r of rows) {
    const info = infoOf(r, links.get(lc(r.entra_id)) || []);
    if (info.lastCheckedAt && (!checkedAt || info.lastCheckedAt > checkedAt)) checkedAt = info.lastCheckedAt;
    out.push(Object.assign(info, { okta: info.oktaIds.map((o) => ({ oktaId: o, name: names.get(o) || o })), possible: possible.get(info.entraId) || [], evidence: await evidenceRows(info.entraId, 3) }));
  }
  const counts = { total: out.length, staged: out.filter((x) => x.status === 'staged').length, complete: out.filter((x) => x.status === 'complete').length, linked: out.filter((x) => x.oktaIds.length).length };
  return { window: VERIFIED_WINDOW_DAYS, checkedAt, counts, rows: out };
}

module.exports = { VERIFIED_WINDOW_DAYS, refreshGallery, galleryFor, parseCsv, importExport, checkStagedSignIns, stagedMap, stagedFor, stagedList, linksFor };
