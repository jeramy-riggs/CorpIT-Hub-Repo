#!/usr/bin/env node
// sdp-diag.js — READ-ONLY. Isolates scope vs mechanics for the categories API.
'use strict';
const axios = require('axios');
const qs = require('querystring');
require('dotenv').config({ path: '/var/www/corpit-hub-api/.env' });

const BASE = `https://sdpondemand.manageengine.com/app/${process.env.SDP_PORTAL}/api/v3`;

async function token() {
  const r = await axios.post('https://accounts.zoho.com/oauth/v2/token', qs.stringify({
    refresh_token: process.env.SDP_REFRESH_TOKEN,
    client_id: process.env.SDP_CLIENT_ID,
    client_secret: process.env.SDP_CLIENT_SECRET,
    grant_type: 'refresh_token',
  }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
  return r.data.access_token;
}

async function tryGet(tok, path, label) {
  try {
    const r = await axios.get(`${BASE}${path}`, {
      headers: { Authorization: `Zoho-oauthtoken ${tok}`, Accept: 'application/vnd.manageengine.sdp.v3+json' },
      params: { input_data: JSON.stringify({ list_info: { row_count: 1 } }) },
      validateStatus: () => true,
    });
    const body = typeof r.data === 'string' ? r.data.slice(0, 200).replace(/\s+/g, ' ') : JSON.stringify(r.data).slice(0, 300);
    console.log(`\n[${label}] GET ${path}\n  HTTP ${r.status}\n  ${body}`);
  } catch (e) { console.log(`\n[${label}] GET ${path} threw: ${e.message}`); }
}

(async () => {
  const tok = await token();
  console.log('[auth] token OK, length', tok.length);
  await tryGet(tok, '/requests', 'baseline');       // module already uses this successfully
  await tryGet(tok, '/categories', 'target');        // the one that 401s
  await tryGet(tok, '/request_category', 'alt-name'); // some tenants expose it here
  console.log('\nIf baseline=200 but target=401 → scope problem: SDP_REFRESH_TOKEN lacks category/admin scope.');
})().catch(e => console.error('[fatal]', e.response ? `${e.response.status} ${JSON.stringify(e.response.data).slice(0,300)}` : e.message));
