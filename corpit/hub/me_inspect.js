// ME diagnostic v3 — probes multiple inventory endpoints to find which one returns device_model
// for devices where compdetailssummary returns '--'.
require('dotenv').config({ path: '/var/www/corpit-hub-api/.env' });
const mysql = require('mysql2/promise');
const fs = require('fs');
const TOKEN_CACHE = '/tmp/zoho_token.json';

async function getMeToken() {
  try {
    const cached = JSON.parse(fs.readFileSync(TOKEN_CACHE, 'utf8'));
    if (cached.expiresAt > Date.now() + 5 * 60 * 1000) return cached.token;
  } catch (e) {}
  const params = new URLSearchParams({
    refresh_token: process.env.ZOHO_REFRESH_TOKEN,
    client_id:     process.env.ZOHO_CLIENT_ID,
    client_secret: process.env.ZOHO_CLIENT_SECRET,
    grant_type:    'refresh_token',
  });
  const res = await fetch('https://accounts.zoho.com/oauth/v2/token', { method: 'POST', body: params });
  const data = await res.json();
  if (!data.access_token) { console.error('Auth failed:', data); process.exit(2); }
  fs.writeFileSync(TOKEN_CACHE, JSON.stringify({
    token: data.access_token,
    expiresAt: Date.now() + (data.expires_in || 3600) * 1000,
  }), { mode: 0o600 });
  return data.access_token;
}

async function meGet(token, path) {
  const url = `${process.env.ME_BASE_URL}/api/1.4${path}`;
  const res = await fetch(url, { headers: { Authorization: `Zoho-oauthtoken ${token}` } });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch (e) {}
  return { status: res.status, json, text: json ? null : text.slice(0, 400) };
}

function scanForModel(obj, path = '', hits = []) {
  if (!obj || typeof obj !== 'object') return hits;
  for (const [k, v] of Object.entries(obj)) {
    const here = path ? `${path}.${k}` : k;
    if (typeof v === 'string' && /latitude|optiplex|elitebook|thinkpad|inspiron|precision|surface|macbook|ideapad|yoga|xps|probook|vostro/i.test(v)) {
      hits.push(`${here} = ${JSON.stringify(v)}`);
    } else if (typeof v === 'object') {
      scanForModel(v, here, hits);
    }
  }
  return hits;
}

(async () => {
  const targets = process.argv.slice(2);
  if (!targets.length) {
    console.error('Usage: node me_inspect.js <computer_name> [computer_name...]');
    process.exit(1);
  }

  const pool = await mysql.createPool({
    host: 'localhost',
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: 'it_inventory',
  });

  const placeholders = targets.map(() => '?').join(',');
  const [rows] = await pool.query(
    `SELECT computer_name, resource_id, service_tag, device_model, computer_type
       FROM endpoints WHERE computer_name IN (${placeholders})`,
    targets
  );
  console.log('--- DB rows ---');
  console.table(rows);

  const token = await getMeToken();

  for (const r of rows) {
    if (!r.resource_id) {
      console.log(`\n${r.computer_name}: no resource_id, skipping`);
      continue;
    }
    console.log(`\n========== ${r.computer_name} (resid=${r.resource_id}) ==========`);

    const endpoints = [
      `/inventory/compdetailssummary?resid=${r.resource_id}`,
      `/inventory/computerdetails?resid=${r.resource_id}`,
      `/inventory/computerhardware?resid=${r.resource_id}`,
      `/inventory/hardware?resid=${r.resource_id}`,
    ];

    for (const ep of endpoints) {
      console.log(`\n--- ${ep} ---`);
      const result = await meGet(token, ep);
      console.log('HTTP', result.status);
      if (result.json) {
        const hits = scanForModel(result.json);
        if (hits.length) {
          console.log('MODEL VALUES FOUND:');
          hits.forEach(h => console.log('  ' + h));
        } else {
          console.log('No model-shaped string found in response.');
        }
        if (typeof result.json === 'object') {
          console.log('top-level keys:', Object.keys(result.json));
          if (result.json.message_response) {
            console.log('message_response keys:', Object.keys(result.json.message_response));
          }
        }
      } else {
        console.log('non-JSON response:', result.text);
      }
      await new Promise(s => setTimeout(s, 500));
    }
  }

  await pool.end();
})();
