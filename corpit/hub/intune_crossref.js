const express = require('express');
const router  = express.Router();
const mysql   = require('mysql2/promise');

const pool = mysql.createPool({
  host:     process.env.DB_HOST,
  port:     parseInt(process.env.DB_PORT) || 3306,
  database: 'it_inventory',
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  connectionLimit: 5,
  charset: 'utf8mb4',
});

let _token = null, _tokenExp = 0;

async function getGraphToken() {
  if (_token && Date.now() < _tokenExp - 60000) return _token;
  const res = await fetch(`https://login.microsoftonline.com/${process.env.AZURE_TENANT_ID}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id:     process.env.AZURE_CLIENT_ID,
      client_secret: process.env.AZURE_CLIENT_SECRET,
      scope:         'https://graph.microsoft.com/.default',
      grant_type:    'client_credentials',
    }),
  });
  const d = await res.json();
  if (!d.access_token) throw new Error('Graph token failed: ' + JSON.stringify(d));
  _token = d.access_token;
  _tokenExp = Date.now() + d.expires_in * 1000;
  return _token;
}

async function graphGetAll(url) {
  const token = await getGraphToken();
  let all = [];
  while (url) {
    const res  = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    const data = await res.json();
    all = all.concat(data.value || []);
    url = data['@odata.nextLink'] || null;
  }
  return all;
}

// GET /api/intune-crossref/status
router.get('/status', async (req, res) => {
  try {
    const [[la]]  = await pool.query("SELECT COUNT(*) as total, SUM(intune_registered='yes') as registered, SUM(intune_registered='no') as not_registered FROM live_auction_devices");
    const [[mob]] = await pool.query("SELECT COUNT(*) as total, SUM(device_source='intune_graph') as from_graph FROM intune_devices");
    res.json({ live_auction: la, mobile: mob });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// POST /api/intune-crossref/sync
router.post('/sync', async (req, res) => {
  try {
    // Fetch all devices from Graph with IMEI
    const devices = await graphGetAll(
      'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id,serialNumber,deviceName,imei,model,complianceState,userPrincipalName,lastSyncDateTime,operatingSystem,osVersion,manufacturer&$top=999'
    );

    // Build IMEI lookup map
    const imeiMap = {};
    devices.forEach(d => {
      if (d.imei) imeiMap[d.imei.trim()] = d;
    });

    // ── Step 1: Cross-reference Live Auction by IMEI ──
    const [laRows] = await pool.query('SELECT id, imei FROM live_auction_devices WHERE imei IS NOT NULL AND imei != ""');
    let laMatched = 0, laUnmatched = 0;

    for (const row of laRows) {
      const intune = imeiMap[row.imei.trim()];
      if (intune) {
        await pool.query(`
          UPDATE live_auction_devices SET
            intune_registered = 'yes',
            intune_compliance = ?,
            intune_device_id  = ?,
            intune_last_sync  = ?
          WHERE id = ?
        `, [intune.complianceState || 'unknown', intune.id, intune.lastSyncDateTime || null, row.id]);
        laMatched++;
      } else {
        await pool.query(`
          UPDATE live_auction_devices SET
            intune_registered = 'no',
            intune_compliance = NULL,
            intune_device_id  = NULL
          WHERE id = ?
        `, [row.id]);
        laUnmatched++;
      }
    }

    // ── Step 2: Add iPhones from Graph not already in intune_devices ──
    const iphones = devices.filter(d =>
      d.operatingSystem === 'iOS' && d.model && d.model.toLowerCase().includes('iphone')
    );

    const [existingDevices] = await pool.query('SELECT device_id FROM intune_devices');
    const existingIds = new Set(existingDevices.map(r => r.device_id));

    let iphoneAdded = 0, iphoneSkipped = 0;

    for (const d of iphones) {
      if (existingIds.has(d.id)) { iphoneSkipped++; continue; }
      try {
        await pool.query(`
          INSERT INTO intune_devices
            (device_id, device_name, ownership, compliance, os, os_version,
             primary_user_upn, last_checkin, model, serial_number,
             primary_user_name, device_source, device_category)
          VALUES (?, ?, 'Corporate', ?, 'iOS/iPadOS', ?, ?, ?, ?, ?, ?, 'intune_graph', 'iphone')
        `, [
          d.id, d.deviceName || '--', d.complianceState || 'unknown',
          d.osVersion || '--', d.userPrincipalName || '--',
          d.lastSyncDateTime || '--', d.model || '--',
          d.serialNumber || '--', d.userPrincipalName || '--',
        ]);
        iphoneAdded++;
      } catch(e) { /* skip duplicates */ }
    }

    // ── Step 2b: Update carrier flags ──
    // ── IMEI-first matching (strongest identifier) ──
    // T-Mobile by IMEI
    await pool.query("UPDATE intune_devices i JOIN tmobile_lines t ON i.imei = t.imei SET i.carrier='T-Mo' WHERE i.imei IS NOT NULL AND i.imei != '' AND t.imei IS NOT NULL AND t.imei != ''");
    // Verizon by IMEI
    await pool.query("UPDATE intune_devices i JOIN verizon_lines v ON i.imei = v.imei SET i.carrier='VZW' WHERE i.imei IS NOT NULL AND i.imei != '' AND v.imei IS NOT NULL AND v.imei != '' AND i.carrier IS NULL");

    // ── Phone number fallback (for devices without IMEI match) ──
    await pool.query("UPDATE intune_devices i JOIN tmobile_lines t ON RIGHT(REPLACE(i.phone_number,'-',''),10)=RIGHT(REPLACE(t.line,'-',''),10) SET i.carrier='T-Mo' WHERE i.phone_number IS NOT NULL AND i.phone_number NOT LIKE '+%' AND i.carrier IS NULL");
    await pool.query("UPDATE intune_devices i JOIN verizon_lines v ON RIGHT(REPLACE(i.phone_number,'-',''),10)=RIGHT(REPLACE(REPLACE(REPLACE(v.phone_number,'-',''),'.',''),' ',''),10) SET i.carrier='VZW' WHERE i.phone_number IS NOT NULL AND i.carrier IS NULL");

    // ── Step 3: Cross-reference T-Mobile by email ──
    const [tmRows] = await pool.query('SELECT id, line FROM tmobile_lines');
    let tmMatched = 0, tmUnmatched = 0;

    // Build email map from Intune
    const [intunePhones] = await pool.query('SELECT primary_user_upn, device_id, compliance, phone_number FROM intune_devices WHERE device_category = "iphone" AND is_historical = 0');
    const emailMap = {};
    intunePhones.forEach(d => { if (d.primary_user_upn) emailMap[d.primary_user_upn.toLowerCase()] = d; });

    // Build phone map from Intune (strip country code)
    const phoneMap = {};
    intunePhones.forEach(d => {
      if (d.phone_number) {
        const stripped = d.phone_number.replace(/\D/g,'').slice(-10);
        if (stripped) phoneMap[stripped] = d;
      }
    });

    // Also build email map from tmobile description1 -> intune upn
    const [tmFull] = await pool.query('SELECT id, line, description1 FROM tmobile_lines');
    const [employees] = await pool.query('SELECT first_last, business_email FROM active_employees');
    const nameToEmail = {};
    employees.forEach(e => {
      if (e.first_last && e.business_email) {
        // Strip suffixes like (SCII), (SCI) etc
        const clean = e.first_last.replace(/\s*\(.*?\)/g,'').trim().toLowerCase();
        nameToEmail[clean] = e.business_email.toLowerCase();
        nameToEmail[e.first_last.toLowerCase()] = e.business_email.toLowerCase();
      }
    });

    for (const row of tmFull) {
      const phone10 = String(row.line || '').replace(/\D/g,'').slice(-10);
      const name = (row.description1 || '').trim().toLowerCase();
      
      let intune = phoneMap[phone10];
      if (!intune && name && nameToEmail[name]) {
        intune = emailMap[nameToEmail[name]];
      }

      if (intune) {
        await pool.query('UPDATE tmobile_lines SET intune_registered=?, intune_compliance=? WHERE id=?',
          ['yes', intune.compliance || 'unknown', row.id]);
        tmMatched++;
      } else {
        await pool.query('UPDATE tmobile_lines SET intune_registered=?, intune_compliance=NULL WHERE id=?',
          ['no', row.id]);
        tmUnmatched++;
      }
    }

    res.json({
      success: true,
      live_auction: { matched: laMatched, not_in_intune: laUnmatched },
      iphones: { added: iphoneAdded, already_existed: iphoneSkipped },
      tmobile: { matched: tmMatched, not_in_intune: tmUnmatched },
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
