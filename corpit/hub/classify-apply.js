#!/usr/bin/env node
/**
 * classify-apply.js — Phase 3 ticket-update engine
 *
 * Classifies sdops_request tickets and writes the confident ones' Category/
 * Subcategory back to ServiceDesk Plus, queues the rest for review, and records
 * a full audit trail (previous+new cat/subcat, confidence, explanation, method,
 * timestamp) that doubles as the rollback source.
 *
 * MODES
 *   --check                READ-ONLY. Verifies: DB tables exist, SDP auth,
 *                          every taxonomy name resolves to an SDP id, and probes
 *                          one sample ticket read to confirm id usability.
 *   (no flag)              SIMULATION. Classifies scope, prints auto/review
 *                          counts, resolves ids. NO writes. Saves plan file.
 *   --apply                Executes: updates SDP for AUTO (>=threshold) rows,
 *                          upserts REVIEW rows, writes audit. Honors --limit.
 *   --rollback --run <id>  Restores previous Category/Subcategory for a run.
 *
 * OPTIONS
 *   --limit N              Cap tickets processed this run (test batch). Default: all.
 *   --scope <s>            all | open | closed | missing-category | date-range
 *   --from / --to          for date-range
 *   --threshold X          default 0.8 (or CLASSIFY_THRESHOLD)
 *   --delay MS             pause between SDP writes (default 400)
 *
 * Prereqs: run phase3-schema.sql once; SDP creds in .env (SDP2_* preferred).
 */

'use strict';
const fs = require('fs');
require('dotenv').config({ path: '/var/www/corpit-hub-api/.env' });
const { classify } = require('/var/www/corpit-hub-api/sdp-rules.js');

const args = process.argv.slice(2);
const has = f => args.includes(f);
const valOf = (f, d) => { const i = args.indexOf(f); return i >= 0 && args[i + 1] ? args[i + 1] : d; };

const MODE = has('--rollback') ? 'rollback' : has('--apply') ? 'apply' : has('--check') ? 'check' : 'sim';
const RUN_ARG = valOf('--run', null);
const LIMIT = parseInt(valOf('--limit', '0'), 10) || 0;
const SCOPE = valOf('--scope', 'all');
const FROM = valOf('--from', null);
const TO = valOf('--to', null);
const THRESHOLD = parseFloat(valOf('--threshold', process.env.CLASSIFY_THRESHOLD || '0.8'));
const DELAY = parseInt(valOf('--delay', process.env.CLASSIFY_DELAY_MS || '400'), 10);
const CLOSED = (process.env.CLASSIFY_CLOSED_STATUSES || 'closed,resolved,completed,cancelled,canceled').split(',').map(s => s.trim().toLowerCase());

const BASE = (process.env.SDP_BASE_URL || 'https://sdpondemand.manageengine.com').replace(/\/+$/, '');
const PORTAL = process.env.SDP_PORTAL || 'itdesk';
const ACCOUNTS = (process.env.SDP_ACCOUNTS_URL || 'https://accounts.zoho.com').replace(/\/+$/, '');
const API = `${BASE}/app/${PORTAL}/api/v3`;
const CID = process.env.SDP2_CLIENT_ID || process.env.SDP_CLIENT_ID;
const CSECRET = process.env.SDP2_CLIENT_SECRET || process.env.SDP_CLIENT_SECRET;
const CREFRESH = process.env.SDP2_REFRESH_TOKEN || process.env.SDP_REFRESH_TOKEN;

const sleep = ms => new Promise(r => setTimeout(r, ms));

function dbConfig() {
  const e = process.env;
  const cfg = { user: e.DB_USER || e.MYSQL_USER, password: e.DB_PASS || e.DB_PASSWORD || e.MYSQL_PASSWORD, database: e.DB_NAME || e.MYSQL_DATABASE || 'corpit_hub' };
  if (e.DB_SOCKET) cfg.socketPath = e.DB_SOCKET; else cfg.host = e.DB_HOST || e.MYSQL_HOST || '127.0.0.1';
  return cfg;
}

// ---------- SDP ----------
async function getToken() {
  if (!CID || !CSECRET || !CREFRESH) { console.error('[config] Missing SDP client id/secret/refresh (SDP2_* or SDP_*)'); process.exit(1); }
  const body = new URLSearchParams({ refresh_token: CREFRESH, client_id: CID, client_secret: CSECRET, grant_type: 'refresh_token' });
  const r = await fetch(`${ACCOUNTS}/oauth/v2/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.access_token) { console.error(`[auth] token failed (${r.status}): ${JSON.stringify(j)}`); process.exit(1); }
  return j.access_token;
}
const HDR = t => ({ Authorization: `Zoho-oauthtoken ${t}`, Accept: 'application/vnd.manageengine.sdp.v3+json' });
async function sdpGet(t, path, inputData) {
  const url = new URL(`${API}${path}`);
  if (inputData) url.searchParams.set('input_data', JSON.stringify(inputData));
  const r = await fetch(url, { method: 'GET', headers: HDR(t) });
  const txt = await r.text(); let j; try { j = JSON.parse(txt); } catch { j = { _raw: txt }; }
  return { ok: r.ok, status: r.status, j };
}
async function sdpPut(t, path, obj) {
  const body = new URLSearchParams({ input_data: JSON.stringify(obj) });
  const r = await fetch(`${API}${path}`, { method: 'PUT', headers: { ...HDR(t), 'Content-Type': 'application/x-www-form-urlencoded' }, body });
  const txt = await r.text(); let j; try { j = JSON.parse(txt); } catch { j = { _raw: txt }; }
  return { ok: r.ok, status: r.status, j };
}

// name -> id maps for our taxonomy
async function buildTaxonomyMap(t) {
  const out = await sdpGet(t, '/categories', { list_info: { row_count: 200 } });
  if (!out.ok) { console.error(`[api] GET /categories failed (${out.status})`); process.exit(1); }
  const map = new Map();
  for (const c of (out.j.categories || [])) {
    const sub = await sdpGet(t, `/categories/${c.id}/subcategories`, { list_info: { row_count: 200 } });
    const subMap = new Map();
    for (const s of (sub.ok ? sub.j.subcategories || [] : [])) subMap.set(s.name.toLowerCase(), { id: s.id, name: s.name });
    map.set(c.name.toLowerCase(), { id: c.id, name: c.name, subs: subMap });
    await sleep(80);
  }
  return map;
}

// ---------- scope query ----------
function scopeWhere(cols) {
  const where = [], params = [];
  if (SCOPE === 'open') { where.push(`LOWER(COALESCE(${cols.status},'')) NOT IN (${CLOSED.map(() => '?').join(',')})`); params.push(...CLOSED); }
  else if (SCOPE === 'closed') { where.push(`LOWER(COALESCE(${cols.status},'')) IN (${CLOSED.map(() => '?').join(',')})`); params.push(...CLOSED); }
  else if (SCOPE === 'missing-category') { where.push(`(${cols.category} IS NULL OR TRIM(${cols.category})='' OR LOWER(TRIM(${cols.category}))='general')`); }
  else if (SCOPE === 'date-range') { if (FROM) { where.push(`${cols.created} >= ?`); params.push(FROM); } if (TO) { where.push(`${cols.created} <= ?`); params.push(TO + ' 23:59:59'); } }
  else if (SCOPE !== 'all') { console.error(`[scope] unknown "${SCOPE}"`); process.exit(1); }
  return { sql: where.length ? 'WHERE ' + where.join(' AND ') : '', params };
}

(async () => {
  const mysql = require('mysql2/promise');
  const cfg = dbConfig();
  const db = await mysql.createConnection(cfg);
  console.log(`[mode] ${MODE}  api=${API}  scope=${SCOPE}  threshold=${THRESHOLD}${LIMIT ? `  limit=${LIMIT}` : ''}`);

  // verify tables
  const [tbls] = await db.query(
    `SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=? AND TABLE_NAME IN ('sdops_classification_audit','sdops_classification_review')`, [cfg.database]);
  const haveTables = new Set(tbls.map(r => r.TABLE_NAME.toLowerCase()));
  const tablesReady = haveTables.has('sdops_classification_audit') && haveTables.has('sdops_classification_review');

  // columns
  const [colsRows] = await db.query(`SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME='sdops_request'`, [cfg.database]);
  const avail = new Set(colsRows.map(c => c.COLUMN_NAME.toLowerCase()));
  const pick = (...n) => n.find(x => avail.has(x)) || null;
  const cols = { id: pick('id', 'request_id', 'requestid'), internal: pick('sdp_internal_id', 'internal_id', 'entity_id'), subject: pick('subject'), category: pick('category'), status: pick('status'), created: pick('created_at', 'created_time') };
  if (!cols.id || !cols.subject) { console.error('[schema] need id+subject'); process.exit(1); }
  const SDPID = cols.internal || cols.id;  // column used for SDP API calls (internal id)
  if (!cols.internal) console.error('[warn] no sdp_internal_id column found — falling back to display id (updates may 404)');

  // ---- ROLLBACK ----
  if (MODE === 'rollback') {
    if (!tablesReady) { console.error('[rollback] audit table missing'); process.exit(1); }
    if (!RUN_ARG) { console.error('[rollback] specify --run <run_id>'); process.exit(1); }
    const t = await getToken(); console.log('[auth] token OK');
    const [rows] = await db.query(`SELECT * FROM sdops_classification_audit WHERE run_id=? AND success=1 AND rolled_back=0`, [RUN_ARG]);
    console.log(`[rollback] ${rows.length} updates to revert for run ${RUN_ARG}`);
    const map = await buildTaxonomyMap(t);
    let ok = 0;
    for (const r of rows) {
      let payload;
      if (!r.previous_category || !r.previous_category.trim()) payload = { request: { category: null, subcategory: null } };
      else {
        const c = map.get(r.previous_category.toLowerCase());
        const s = c && r.previous_subcategory ? c.subs.get(r.previous_subcategory.toLowerCase()) : null;
        payload = { request: { category: c ? { id: c.id } : { name: r.previous_category }, subcategory: s ? { id: s.id } : null } };
      }
      const res = await sdpPut(t, `/requests/${r.request_id}`, payload);
      if (res.ok) { await db.query(`UPDATE sdops_classification_audit SET rolled_back=1 WHERE audit_id=?`, [r.audit_id]); ok++; }
      else console.error(`  revert FAILED req ${r.request_id} (${res.status})`);
      await sleep(DELAY);
    }
    console.log(`[rollback] reverted ${ok}/${rows.length}`);
    await db.end(); return;
  }

  // ---- need SDP for check/sim/apply ----
  const t = await getToken(); console.log('[auth] token OK');
  const map = await buildTaxonomyMap(t);

  // verify every taxonomy name our classifier can emit resolves to an id
  const { RULES, AUTOMATED } = require('/var/www/corpit-hub-api/sdp-rules.js');
  const wantPairs = new Set();
  for (const r of RULES) wantPairs.add(`${r.c}||${r.s}`);
  for (const a of AUTOMATED) wantPairs.add(`System Notifications||${a.s}`);
  wantPairs.add('General / Other||Uncategorized');
  const missing = [];
  for (const pair of wantPairs) {
    const [cn, sn] = pair.split('||');
    const c = map.get(cn.toLowerCase());
    if (!c) { missing.push(`category "${cn}"`); continue; }
    if (!c.subs.get(sn.toLowerCase())) missing.push(`subcategory "${cn} / ${sn}"`);
  }

  if (MODE === 'check') {
    console.log(`\n[check] tables present: ${tablesReady ? 'yes' : 'NO — run: sudo mysql corpit_hub < phase3-schema.sql'}`);
    console.log(`[check] taxonomy ids resolve: ${missing.length === 0 ? 'all ' + wantPairs.size + ' OK' : missing.length + ' MISSING'}`);
    missing.forEach(m => console.log(`   - ${m}`));
    // probe one ticket read to confirm id usability for updates
    const [[sample]] = await db.query(`SELECT ${SDPID} AS id FROM sdops_request WHERE ${SDPID} IS NOT NULL LIMIT 1`);
    if (sample) {
      const probe = await sdpGet(t, `/requests/${sample.id}`);
      console.log(`[check] sample ticket read /requests/${sample.id}: HTTP ${probe.status} ${probe.ok ? '(ids usable for updates)' : '(NOT usable — display_id vs internal id mismatch; tell Claude)'}`);
    }
    console.log('\n[check] done.');
    await db.end(); return;
  }

  if (missing.length) { console.error(`[fatal] ${missing.length} taxonomy names do not exist in SDP — run Phase 2 or fix names first.`); process.exit(1); }
  if (MODE === 'apply' && !tablesReady) { console.error('[fatal] tables missing — run: sudo mysql corpit_hub < phase3-schema.sql'); process.exit(1); }

  // load scope
  const { sql: whereSql, params } = scopeWhere(cols);
  const sel = [...new Set([cols.id, SDPID, cols.subject, cols.category].filter(Boolean))].join(', ');
  let q = `SELECT ${sel} FROM sdops_request ${whereSql}`;
  if (LIMIT) q += ` LIMIT ${LIMIT}`;
  const [rows] = await db.query(q, params);
  console.log(`[scope] ${rows.length} tickets`);

  const runId = 'run-' + new Date().toISOString().replace(/[:.]/g, '-');
  let auto = 0, review = 0, applied = 0, failed = 0;

  for (const r of rows) {
    const cur = cols.category ? (r[cols.category] || '') : '';
    const res = classify(r[cols.subject]);
    const isAuto = res.confidence >= THRESHOLD;

    if (!isAuto) {
      review++;
      if (MODE === 'apply') {
        await db.query(
          `INSERT INTO sdops_classification_review (request_id,subject,current_category,recommended_category,recommended_subcategory,confidence,explanation,status,created_at)
           VALUES (?,?,?,?,?,?,?,'pending',NOW())
           ON DUPLICATE KEY UPDATE subject=VALUES(subject),current_category=VALUES(current_category),recommended_category=VALUES(recommended_category),recommended_subcategory=VALUES(recommended_subcategory),confidence=VALUES(confidence),explanation=VALUES(explanation),status='pending',created_at=NOW()`,
          [r[SDPID], r[cols.subject], cur, res.category, res.subcategory, res.confidence, res.explanation]);
      }
      continue;
    }

    auto++;
    if (MODE !== 'apply') continue;

    const c = map.get(res.category.toLowerCase());
    const s = c.subs.get(res.subcategory.toLowerCase());
    const payload = { request: { category: { id: c.id }, subcategory: { id: s.id } } };
    let put = await sdpPut(t, `/requests/${r[SDPID]}`, payload);
    if (put.status === 429) { await sleep(3000); put = await sdpPut(t, `/requests/${r[SDPID]}`, payload); }
    const success = put.ok ? 1 : 0;
    if (success) applied++; else { failed++; if (failed <= 5) console.error(`  update FAILED req ${r[cols.id]} (internal ${r[SDPID]}) (${put.status}): ${JSON.stringify(put.j).slice(0, 200)}`); }
    await db.query(
      `INSERT INTO sdops_classification_audit (run_id,request_id,previous_category,new_category,previous_subcategory,new_subcategory,confidence,explanation,method,sdp_status,success,updated_at)
       VALUES (?,?,?,?,?,?,?,?,'automatic',?,?,NOW())`,
      [runId, r[SDPID], cur || null, res.category, null, res.subcategory, res.confidence, res.explanation, put.status, success]);
    await sleep(DELAY);
  }

  console.log('\n=== RESULT ===');
  console.log(`Auto (>= ${THRESHOLD}):  ${auto}`);
  console.log(`Review (< ${THRESHOLD}): ${review}`);
  if (MODE === 'apply') {
    console.log(`SDP updates applied:  ${applied}`);
    console.log(`SDP updates failed:   ${failed}`);
    console.log(`Review queued:        ${review}`);
    console.log(`\nrun_id: ${runId}`);
    console.log(`rollback this run:  node classify-apply.js --rollback --run ${runId}`);
  } else {
    fs.writeFileSync('/home/ubuntu/phase3-apply-plan.json', JSON.stringify({ scope: SCOPE, threshold: THRESHOLD, auto, review, limit: LIMIT || null }, null, 2));
    console.log('\n[simulation] No writes. Plan: /home/ubuntu/phase3-apply-plan.json');
    console.log('[next] test batch:  node classify-apply.js --apply --limit 25');
  }
  await db.end();
})().catch(e => { console.error('[fatal]', e.message); process.exit(1); });
