#!/usr/bin/env node
// homeoffice-apply.js — assign SDP Site from Entra home office (v2: + Remote).
// Default: SIMULATE (no writes). --apply to write. --limit N for test batch.
// Rollback: --rollback --run <run_id>
'use strict';
const https = require('https');
const mysql = require('mysql2/promise');

const BASE = 'https://sdpondemand.manageengine.com/app/itdesk/api/v3';
const IRV = { id: '259065000000222001', name: 'Irvine Location' };
const PLA = { id: '259065000000391179', name: 'Plano Location' };
const REMOTE = { id: '259065000005353177', name: 'Remote' };
const KNOWN_OFFICE_HINTS = ['mineola','atlanta','las vegas','redwood','chicago','phoenix','new york','belmont','newport','san mateo'];
const APPLY = process.argv.includes('--apply');
const ROLLBACK = process.argv.includes('--rollback');
const limIdx = process.argv.indexOf('--limit');
const LIMIT = limIdx > -1 ? parseInt(process.argv[limIdx + 1], 10) : 0;
const runIdx = process.argv.indexOf('--run');
const RUN_ARG = runIdx > -1 ? process.argv[runIdx + 1] : null;

function getToken() {
  return new Promise((resolve, reject) => {
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: process.env.SDP2_CLIENT_ID,
      client_secret: process.env.SDP2_CLIENT_SECRET,
      refresh_token: process.env.SDP2_REFRESH_TOKEN,
    }).toString();
    const req = https.request('https://accounts.zoho.com/oauth/v2/token',
      { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
      (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => { try { resolve(JSON.parse(d).access_token); } catch (e) { reject(new Error(d)); } }); });
    req.on('error', reject); req.write(body); req.end();
  });
}

function sdpPutSite(internalId, siteId, siteName, token) {
  return new Promise((resolve) => {
    const input = JSON.stringify({ request: { site: { id: siteId } } });
    const body = 'input_data=' + encodeURIComponent(input);
    const req = https.request(BASE + '/requests/' + internalId,
      { method: 'PUT', headers: {
        'Authorization': 'Zoho-oauthtoken ' + token,
        'Accept': 'application/vnd.manageengine.sdp.v3+json',
        'Content-Type': 'application/x-www-form-urlencoded'
      } },
      (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => resolve({ status: res.statusCode, body: d })); });
    req.on('error', (e) => resolve({ status: 0, body: e.message }));
    req.write(body); req.end();
  });
}

(async () => {
  const pool = await mysql.createPool({ host: process.env.DB_HOST, port: process.env.DB_PORT, user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.DB_NAME });
  const token = await getToken();
  console.log('[auth] token OK');

  if (ROLLBACK) {
    if (!RUN_ARG) { console.error('need --run <run_id>'); process.exit(1); }
    const [rows] = await pool.query("SELECT * FROM sdops_homeoffice_audit WHERE run_id=? AND result='ok'", [RUN_ARG]);
    console.log('[rollback] restoring', rows.length, 'tickets...');
    let ok = 0, fail = 0;
    for (const r of rows) {
      if (!r.old_site_id) { fail++; continue; }
      const res = await sdpPutSite(r.sdp_internal_id, r.old_site_id, r.old_site, token);
      if (res.status === 200) { ok++; } else { fail++; console.log('  FAIL', r.request_id, res.status, res.body.slice(0, 120)); }
    }
    console.log('[rollback] done. ok:', ok, 'fail:', fail);
    process.exit(0);
  }

  const [rows] = await pool.query(`
    SELECT r.id, r.sdp_internal_id, r.site, r.site_id,
           COALESCE(e1.office_location, e2.office_location) AS office
    FROM sdops_request r
    LEFT JOIN entra_users e1 ON LOWER(e1.mail) = LOWER(r.requester_email)
    LEFT JOIN entra_users e2 ON LOWER(e2.user_principal_name) = LOWER(r.requester_email)
    WHERE r.gone = 0`);

  const work = [];
  for (const r of rows) {
    const off = (r.office || '').toLowerCase().trim();
    let target = null;
    const isNA = !off || off === 'n/a' || off === 'na';
    if (!isNA) {
      if (off.includes('remote')) target = REMOTE;
      else if (off.includes('irvine') || off.includes('mauchly')) target = IRV;
      else if (off.includes('plano')) target = PLA;
      else if (KNOWN_OFFICE_HINTS.some(h => off.includes(h))) target = REMOTE;
    }
    if (!target) continue;
    if (String(r.site_id) === target.id) continue;
    work.push({ id: r.id, internal: r.sdp_internal_id, oldSite: r.site, oldSiteId: r.site_id, target });
  }
  const batch = LIMIT > 0 ? work.slice(0, LIMIT) : work;
  const toIrv = batch.filter(w => w.target === IRV).length;
  const toPla = batch.filter(w => w.target === PLA).length;
  const toRem = batch.filter(w => w.target === REMOTE).length;
  console.log('[scope] needs correction:', work.length, '| this run:', batch.length, '(toIrvine:', toIrv + ', toPlano:', toPla + ', toRemote:', toRem + ')');

  if (!APPLY) {
    console.log('[simulate] no writes. Run with --apply to write. Use --limit 10 for a test batch.');
    process.exit(0);
  }

  const runId = 'ho-' + new Date().toISOString().replace(/[:.]/g, '-');
  console.log('[apply] run_id:', runId);
  let ok = 0, fail = 0;
  for (const w of batch) {
    const res = await sdpPutSite(w.internal, w.target.id, w.target.name, token);
    const good = res.status === 200;
    if (good) ok++; else fail++;
    await pool.query(
      'INSERT INTO sdops_homeoffice_audit (run_id, request_id, sdp_internal_id, old_site, old_site_id, new_site, new_site_id, result, detail) VALUES (?,?,?,?,?,?,?,?,?)',
      [runId, w.id, w.internal, w.oldSite, w.oldSiteId, w.target.name, w.target.id, good ? 'ok' : 'fail', good ? null : (res.status + ' ' + res.body.slice(0, 200))]
    );
    if (!good) console.log('  FAIL', w.id, res.status, res.body.slice(0, 120));
  }
  console.log('[apply] done. ok:', ok, 'fail:', fail);
  console.log('[rollback if needed] node /tmp/homeoffice-apply.js --rollback --run ' + runId);
  await pool.end();
})();
