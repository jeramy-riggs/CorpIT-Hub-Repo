#!/usr/bin/env node
/**
 * classify-sim.js — Phase 3 Tier 1 SIMULATION (READ-ONLY)
 * Classifies in-scope sdops_request tickets with the rule engine, computes
 * confidence, and splits into AUTO (>= threshold) vs REVIEW (< threshold).
 * Writes a JSON report + a CSV you can open in Excel. NO DB writes, NO SDP calls.
 *
 * Usage (from /var/www/corpit-hub-api):
 *   node classify-sim.js                         # scope=all
 *   node classify-sim.js --scope open
 *   node classify-sim.js --scope closed
 *   node classify-sim.js --scope missing-category
 *   node classify-sim.js --scope date-range --from 2026-01-01 --to 2026-06-30
 *   node classify-sim.js --threshold 0.85
 *
 * Scopes: all | open | closed | missing-category | date-range
 *   (missing-subcategory and specific-template are NOT available: the local
 *    mirror sdops_request has no subcategory/template columns — those apply
 *    only when reading full ticket detail from SDP in the apply/AI phase.)
 */

'use strict';
const fs = require('fs');
require('dotenv').config({ path: '/var/www/corpit-hub-api/.env' });
const { classify } = require('/var/www/corpit-hub-api/sdp-rules.js');

const args = process.argv.slice(2);
const valOf = (f, d) => { const i = args.indexOf(f); return i >= 0 && args[i + 1] ? args[i + 1] : d; };
const SCOPE = valOf('--scope', 'all');
const FROM = valOf('--from', null);
const TO = valOf('--to', null);
const THRESHOLD = parseFloat(valOf('--threshold', process.env.CLASSIFY_THRESHOLD || '0.8'));
const CLOSED_STATUSES = (process.env.CLASSIFY_CLOSED_STATUSES || 'closed,resolved,completed,cancelled').split(',').map(s => s.trim().toLowerCase());

function dbConfig() {
  const e = process.env;
  const cfg = { user: e.DB_USER || e.MYSQL_USER, password: e.DB_PASS || e.DB_PASSWORD || e.MYSQL_PASSWORD, database: e.DB_NAME || e.MYSQL_DATABASE || 'corpit_hub' };
  if (e.DB_SOCKET) cfg.socketPath = e.DB_SOCKET; else cfg.host = e.DB_HOST || e.MYSQL_HOST || '127.0.0.1';
  return cfg;
}

function csvCell(v) {
  const s = String(v == null ? '' : v);
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

(async () => {
  const mysql = require('mysql2/promise');
  const cfg = dbConfig();
  const db = await mysql.createConnection(cfg);

  // introspect columns
  const [cols] = await db.query(
    `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME='sdops_request'`, [cfg.database]);
  const avail = new Set(cols.map(c => c.COLUMN_NAME.toLowerCase()));
  const pick = (...n) => n.find(x => avail.has(x)) || null;
  const colId = pick('id', 'request_id', 'requestid', 'sdp_id', 'workorder_id', 'woid');
  const colSubject = pick('subject');
  const colCategory = pick('category');
  const colStatus = pick('status');
  const colCreated = pick('created_at', 'created_time', 'createddate');
  if (!colId || !colSubject) { console.error(`[schema] need id + subject columns (found id=${colId} subject=${colSubject})`); process.exit(1); }
  console.log(`[schema] id=${colId} subject=${colSubject} category=${colCategory} status=${colStatus} created=${colCreated}`);

  // build scope WHERE
  const where = [];
  const params = [];
  if (SCOPE === 'open') {
    if (!colStatus) { console.error('[scope] no status column; cannot filter open'); process.exit(1); }
    where.push(`LOWER(COALESCE(${colStatus},'')) NOT IN (${CLOSED_STATUSES.map(() => '?').join(',')})`); params.push(...CLOSED_STATUSES);
  } else if (SCOPE === 'closed') {
    if (!colStatus) { console.error('[scope] no status column; cannot filter closed'); process.exit(1); }
    where.push(`LOWER(COALESCE(${colStatus},'')) IN (${CLOSED_STATUSES.map(() => '?').join(',')})`); params.push(...CLOSED_STATUSES);
  } else if (SCOPE === 'missing-category') {
    if (!colCategory) { console.error('[scope] no category column'); process.exit(1); }
    where.push(`(${colCategory} IS NULL OR TRIM(${colCategory})='' OR LOWER(TRIM(${colCategory}))='general')`);
  } else if (SCOPE === 'date-range') {
    if (!colCreated) { console.error('[scope] no created column'); process.exit(1); }
    if (FROM) { where.push(`${colCreated} >= ?`); params.push(FROM); }
    if (TO) { where.push(`${colCreated} <= ?`); params.push(TO + ' 23:59:59'); }
  } else if (SCOPE === 'missing-subcategory' || SCOPE === 'template') {
    console.error(`[scope] "${SCOPE}" unsupported on local mirror (no such column). Use apply/AI phase which reads full ticket detail from SDP.`); process.exit(1);
  } else if (SCOPE !== 'all') {
    console.error(`[scope] unknown scope "${SCOPE}"`); process.exit(1);
  }
  const whereSql = where.length ? 'WHERE ' + where.join(' AND ') : '';

  const selCols = [colId, colSubject, colCategory, colStatus, colCreated].filter(Boolean).join(', ');
  const [rows] = await db.query(`SELECT ${selCols} FROM sdops_request ${whereSql}`, params);
  console.log(`[scope] ${SCOPE} → ${rows.length} tickets · threshold ${THRESHOLD}`);
  await db.end();

  // classify
  const results = [];
  let auto = 0, review = 0, noChange = 0;
  const catCounts = new Map();
  for (const r of rows) {
    const cur = colCategory ? (r[colCategory] || '') : '';
    const res = classify(r[colSubject]);
    const decision = res.confidence >= THRESHOLD ? 'auto' : 'review';
    if (decision === 'auto') auto++; else review++;
    const same = cur && cur.toLowerCase() === res.category.toLowerCase();
    if (same) noChange++;
    catCounts.set(res.category, (catCounts.get(res.category) || 0) + 1);
    results.push({
      request_id: r[colId], subject: r[colSubject], current_category: cur,
      recommended_category: res.category, recommended_subcategory: res.subcategory,
      confidence: res.confidence, decision, method: res.method,
      changes_category: same ? 'no' : 'yes', explanation: res.explanation,
    });
  }

  // summary
  console.log('\n=== CLASSIFICATION SUMMARY ===');
  console.log(`Total in scope:        ${rows.length}`);
  console.log(`Auto (>= ${THRESHOLD}):        ${auto}  (${Math.round(auto / rows.length * 100)}%)`);
  console.log(`Review (< ${THRESHOLD}):       ${review}  (${Math.round(review / rows.length * 100)}%)`);
  console.log(`Already correct category: ${noChange}`);
  console.log('\nRecommended category distribution:');
  [...catCounts.entries()].sort((a, b) => b[1] - a[1]).forEach(([c, n]) => console.log(`  ${String(n).padStart(5)}  ${c}`));

  // write outputs
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const jsonPath = `/home/ubuntu/phase3-sim-${SCOPE}-${ts}.json`;
  const csvPath = `/home/ubuntu/phase3-sim-${SCOPE}-${ts}.csv`;
  fs.writeFileSync(jsonPath, JSON.stringify({
    generated_at: new Date().toISOString(), scope: SCOPE, from: FROM, to: TO, threshold: THRESHOLD,
    totals: { in_scope: rows.length, auto, review, already_correct: noChange }, results,
  }, null, 2));
  const header = ['request_id', 'confidence', 'decision', 'method', 'changes_category', 'current_category', 'recommended_category', 'recommended_subcategory', 'subject', 'explanation'];
  const csv = [header.join(',')].concat(results.map(r => header.map(h => csvCell(r[h])).join(','))).join('\n');
  fs.writeFileSync(csvPath, csv);

  console.log(`\n[done] report: ${jsonPath}`);
  console.log(`[done] CSV:    ${csvPath}`);
  console.log('\n[simulation] No changes written to SDP or the database.');
  console.log('[next] Eyeball the CSV (esp. decision=review and changes_category=yes). Once the wider-scope');
  console.log('       SDP token lands, the apply engine will write AUTO rows to SDP + queue REVIEW rows,');
  console.log('       with full audit + rollback.');
})().catch(e => { console.error('[fatal]', e.message); process.exit(1); });
