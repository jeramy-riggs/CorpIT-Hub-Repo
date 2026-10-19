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

const runId = process.argv[2];
if (!runId) { console.error('usage: node retry-failed-redistribute.js <run_id>'); process.exit(1); }

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
  const input = JSON.stringify({ request: {
    technician: { id: techId },
    category: { name: 'General / Other' },
    subcategory: { name: 'Uncategorized' }
  }});
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

  const [rows] = await pool.query('SELECT * FROM sdops_redistribute_audit WHERE run_id = ? AND result = ?', [runId, 'fail']);
  console.log('[scope]', rows.length, 'failed tickets to retry with category fix');

  const token = await getToken();
  let ok = 0, fail = 0;
  const perTech = {};
  TECHS.forEach(t => perTech[t.name] = 0);

  for (const r of rows) {
    const tech = TECHS.find(t => t.name === r.new_technician);
    if (!tech) { console.log('  SKIP', r.request_id, '(unknown technician:', r.new_technician, ')'); continue; }
    const res = await putRequest(token, r.sdp_internal_id, tech.id);
    const success = res.status === 200;
    if (success) { ok++; perTech[tech.name]++; await pool.query('UPDATE sdops_redistribute_audit SET result = ?, detail = ? WHERE id = ?', ['ok', 'retried-with-category-fix', r.id]); }
    else { fail++; console.log('  STILL FAIL', r.request_id, res.status, res.body.slice(0, 150)); }
  }
  console.log('[retry] done. ok:', ok, 'fail:', fail);
  console.log('[distribution added]', perTech);
  await pool.end();
}

main().catch(e => { console.error('[error]', e.message); process.exit(1); });
