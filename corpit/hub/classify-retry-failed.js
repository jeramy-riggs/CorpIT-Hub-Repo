#!/usr/bin/env node
/**
 * classify-retry-failed.js — retry the tickets whose category update failed
 * (typically SDP 4012 on field "mode" for Resolved/Closed tickets).
 *
 *   --inspect (default)  READ-ONLY. GET each failed ticket; report its mode,
 *                        status, and current category. No writes.
 *   --apply              Re-send the update INCLUDING the ticket's existing mode
 *                        (or --mode "<name>" as fallback when mode is null).
 *                        Writes a new audit run.
 *   --mode "<name>"      Fallback mode name to set when a ticket has none
 *                        (use a value seen in --inspect, e.g. "Web Form").
 *   --limit N            Cap tickets this run.
 */
'use strict';
require('dotenv').config({ path: '/var/www/corpit-hub-api/.env' });

const args = process.argv.slice(2);
const has = f => args.includes(f);
const valOf = (f, d) => { const i = args.indexOf(f); return i >= 0 && args[i + 1] ? args[i + 1] : d; };
const MODE = has('--apply') ? 'apply' : 'inspect';
const FALLBACK_MODE = valOf('--mode', null);
const LIMIT = parseInt(valOf('--limit', '0'), 10) || 0;
const DELAY = parseInt(valOf('--delay', '400'), 10);

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
  const cfg = { user: e.DB_USER, password: e.DB_PASS || e.DB_PASSWORD, database: e.DB_NAME || 'corpit_hub' };
  if (e.DB_SOCKET) cfg.socketPath = e.DB_SOCKET; else cfg.host = e.DB_HOST || '127.0.0.1';
  return cfg;
}
async function getToken() {
  const body = new URLSearchParams({ refresh_token: CREFRESH, client_id: CID, client_secret: CSECRET, grant_type: 'refresh_token' });
  const r = await fetch(`${ACCOUNTS}/oauth/v2/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
  const j = await r.json(); if (!j.access_token) { console.error('[auth] failed', j); process.exit(1); } return j.access_token;
}
const HDR = t => ({ Authorization: `Zoho-oauthtoken ${t}`, Accept: 'application/vnd.manageengine.sdp.v3+json' });
async function sdpGet(t, path) { const r = await fetch(`${API}${path}`, { headers: HDR(t) }); const x = await r.text(); let j; try { j = JSON.parse(x); } catch { j = {}; } return { ok: r.ok, status: r.status, j }; }
async function sdpPut(t, path, obj) { const body = new URLSearchParams({ input_data: JSON.stringify(obj) }); const r = await fetch(`${API}${path}`, { method: 'PUT', headers: { ...HDR(t), 'Content-Type': 'application/x-www-form-urlencoded' }, body }); const x = await r.text(); let j; try { j = JSON.parse(x); } catch { j = {}; } return { ok: r.ok, status: r.status, j }; }

async function taxMap(t) {
  const out = await sdpGet(t, '/categories?input_data=' + encodeURIComponent(JSON.stringify({ list_info: { row_count: 200 } })));
  const map = new Map();
  for (const c of (out.j.categories || [])) {
    const s = await sdpGet(t, `/categories/${c.id}/subcategories?input_data=` + encodeURIComponent(JSON.stringify({ list_info: { row_count: 200 } })));
    const subs = new Map(); for (const x of (s.j.subcategories || [])) subs.set(x.name.toLowerCase(), x.id);
    map.set(c.name.toLowerCase(), { id: c.id, subs }); await sleep(60);
  }
  return map;
}

(async () => {
  const mysql = require('mysql2/promise');
  const db = await mysql.createConnection(dbConfig());
  let q = `SELECT audit_id, request_id, new_category, new_subcategory, confidence, explanation FROM sdops_classification_audit WHERE success=0 AND rolled_back=0`;
  if (LIMIT) q += ` LIMIT ${LIMIT}`;
  const [rows] = await db.query(q);
  console.log(`[retry] ${rows.length} failed updates to process · mode=${MODE}${FALLBACK_MODE ? ` fallback-mode="${FALLBACK_MODE}"` : ''}`);
  const t = await getToken(); console.log('[auth] token OK');

  if (MODE === 'inspect') {
    let nullMode = 0; const modeCounts = new Map(); let shown = 0;
    for (const r of rows) {
      const g = await sdpGet(t, `/requests/${r.request_id}`);
      const req = g.j.request || {};
      const modeName = req.mode ? req.mode.name : null;
      if (!modeName) nullMode++; else modeCounts.set(modeName, (modeCounts.get(modeName) || 0) + 1);
      if (shown++ < 15) console.log(`  req ${r.request_id}  status=${req.status ? req.status.name : '?'}  mode=${modeName || 'NULL'}  cat=${req.category ? req.category.name : 'none'}`);
      await sleep(150);
    }
    console.log(`\n[inspect] mode NULL on ${nullMode}/${rows.length}`);
    console.log('[inspect] existing mode values seen:', [...modeCounts.entries()].map(([k, v]) => `${k}(${v})`).join(', ') || 'none');
    console.log('\n[next] retry with:  node classify-retry-failed.js --apply' + (nullMode ? '  --mode "<one of the mode names above>"' : ''));
    await db.end(); return;
  }

  // apply
  const map = await taxMap(t);
  const runId = 'retry-' + new Date().toISOString().replace(/[:.]/g, '-');
  let ok = 0, fail = 0;
  for (const r of rows) {
    const g = await sdpGet(t, `/requests/${r.request_id}`);
    const req = g.j.request || {};
    const c = map.get((r.new_category || '').toLowerCase());
    const sid = c ? c.subs.get((r.new_subcategory || '').toLowerCase()) : null;
    if (!c || !sid) { console.error(`  skip ${r.request_id}: taxonomy id not found`); continue; }
    const reqObj = { category: { id: c.id }, subcategory: { id: sid } };
    if (req.mode && req.mode.id) reqObj.mode = { id: req.mode.id };
    else if (FALLBACK_MODE) reqObj.mode = { name: FALLBACK_MODE };
    let put = await sdpPut(t, `/requests/${r.request_id}`, { request: reqObj });
    if (put.status === 429) { await sleep(3000); put = await sdpPut(t, `/requests/${r.request_id}`, { request: reqObj }); }
    const success = put.ok ? 1 : 0;
    if (success) { ok++; await db.query(`UPDATE sdops_classification_audit SET success=1, sdp_status=?, updated_at=NOW() WHERE audit_id=?`, [put.status, r.audit_id]); }
    else { fail++; if (fail <= 5) console.error(`  still FAILED ${r.request_id} (${put.status}): ${JSON.stringify(put.j).slice(0, 200)}`); await db.query(`UPDATE sdops_classification_audit SET sdp_status=? WHERE audit_id=?`, [put.status, r.audit_id]); }
    await sleep(DELAY);
  }
  console.log(`\n[retry] fixed ${ok}, still failing ${fail}`);
  await db.end();
})().catch(e => { console.error('[fatal]', e.message); process.exit(1); });
