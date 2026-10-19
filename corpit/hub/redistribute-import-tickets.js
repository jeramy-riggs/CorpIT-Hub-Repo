#!/usr/bin/env node
'use strict';
require('dotenv').config();
const mysql = require('mysql2/promise');
const https = require('https');

const TECHS = [
  { name: 'Jaime Leon', id: '259065000000380649' },
  { name: 'Nick Blake', id: '259065000000380641' },
  { name: 'Christopher Balluck', id: '259065000000380665' },
  { name: 'Rey Abad', id: '259065000000380493' }
];

const APPLY = process.argv.includes('--apply');
const ROLLBACK_RUN = (() => {
  const i = process.argv.indexOf('--rollback');
  return i >= 0 ? process.argv[i + 1] : null;
})();

async function getToken() {
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    client_id: process.env.SDP2_CLIENT_ID,
    client_secret: process.env.SDP2_CLIENT_SECRET,
    refresh_token: process.env.SDP2_REFRESH_TOKEN
  }).toString();
  return new Promise((resolve, reject) => {
    const r = https.request('https://accounts.zoho.com/oauth/v2/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }, x => {
      let d = ''; x.on('data', c => d += c); x.on('end', () => resolve(JSON.parse(d).access_token));
    });
    r.on('error', reject); r.write(body); r.end();
  });
}

function putRequest(token, internalId, techId) {
  const input = JSON.stringify({ request: { technician: { id: techId } } });
  const putBody = 'input_data=' + encodeURIComponent(input);
  return new Promise((resolve) => {
    const req = https.request('https://sdpondemand.manageengine.com/app/itdesk/api/v3/requests/' + internalId, {
      method: 'PUT',
      headers: { 'Authorization': 'Zoho-oauthtoken ' + token, 'Accept': 'application/vnd.manageengine.sdp.v3+json', 'Content-Type': 'application/x-www-form-urlencoded' }
    }, x => {
      let d = ''; x.on('data', c => d += c);
      x.on('end', () => resolve({ status: x.statusCode, body: d }));
    });
    req.write(putBody); req.end();
  });
}

async function main() {
  const pool = await mysql.createPool({
    host: process.env.DB_HOST, port: process.env.DB_PORT,
    user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.DB_NAME
  });

  await pool.query(`CREATE TABLE IF NOT EXISTS sdops_redistribute_audit (
    id INT AUTO_INCREMENT PRIMARY KEY,
    run_id VARCHAR(64), request_id VARCHAR(32), sdp_internal_id VARCHAR(32),
    old_technician VARCHAR(128), new_technician VARCHAR(128),
    result VARCHAR(16), detail TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  if (ROLLBACK_RUN) {
    const [rows] = await pool.query('SELECT * FROM sdops_redistribute_audit WHERE run_id = ? AND result = ?', [ROLLBACK_RUN, 'ok']);
    console.log('[rollback] found', rows.length, 'to revert');
    const token = await getToken();
    let ok = 0, fail = 0;
    for (const r of rows) {
      const oldTech = TECHS.find(t => t.name === r.old_technician);
      if (!oldTech) { console.log('  SKIP', r.request_id, '(old technician not in map:', r.old_technician, ')'); continue; }
      const res = await putRequest(token, r.sdp_internal_id, oldTech.id);
      if (res.status === 200) { ok++; } else { fail++; console.log('  FAIL', r.request_id, res.status, res.body.slice(0, 100)); }
    }
    console.log('[rollback] done. ok:', ok, 'fail:', fail);
    await pool.end();
    return;
  }

  const [rows] = await pool.query(`
    SELECT id, sdp_internal_id, technician
    FROM sdops_request
    WHERE gone = 0
      AND created_by_name = 'Rey Abad'
      AND technician = 'Unassigned'
      AND DATE(created_at) = '2026-02-26'
    ORDER BY id
  `);

  console.log('[scope]', rows.length, 'tickets to redistribute');
  const runId = 'redist-' + new Date().toISOString().replace(/[:.]/g, '-');
  console.log('[mode]', APPLY ? 'apply' : 'simulate', '| run_id:', runId);

  const perTech = {};
  TECHS.forEach(t => perTech[t.name] = 0);

  if (!APPLY) {
    rows.forEach((r, i) => { perTech[TECHS[i % TECHS.length].name]++; });
    console.log('[plan] distribution:', perTech);
    console.log('[next] apply with: node redistribute-import-tickets.js --apply');
    await pool.end();
    return;
  }

  const token = await getToken();
  let ok = 0, fail = 0;
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    const tech = TECHS[i % TECHS.length];
    const res = await putRequest(token, r.sdp_internal_id, tech.id);
    const success = res.status === 200;
    if (success) { ok++; perTech[tech.name]++; } else { fail++; console.log('  FAIL', r.id, res.status, res.body.slice(0, 120)); }
    await pool.query(
      'INSERT INTO sdops_redistribute_audit (run_id, request_id, sdp_internal_id, old_technician, new_technician, result, detail) VALUES (?,?,?,?,?,?,?)',
      [runId, r.id, r.sdp_internal_id, r.technician, tech.name, success ? 'ok' : 'fail', success ? null : res.body.slice(0, 500)]
    );
  }
  console.log('[apply] done. ok:', ok, 'fail:', fail);
  console.log('[distribution]', perTech);
  console.log('[rollback if needed] node redistribute-import-tickets.js --rollback ' + runId);
  await pool.end();
}

main().catch(e => { console.error('[error]', e.message); process.exit(1); });
