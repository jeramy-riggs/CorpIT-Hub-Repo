'use strict';

/**
 * cert-watchtower-intune-sync.js
 * Cert Watchtower v1.2.0 — Intune Cloud Cert Source
 *
 * Pulls the MDM Push (APNs) certificate from Microsoft Graph API and
 * stores it in cert_intune. Classifies days_remaining using the same
 * thresholds as all other cert types. Pushes to PRTG if enabled.
 *
 * Dependencies: none beyond what prod already has (node-fetch / https built-in)
 * Env vars (all in /var/www/api/.env):
 *   INTUNE_TENANT_ID, INTUNE_CLIENT_ID, INTUNE_CLIENT_SECRET
 *
 * Called by:
 *   - cron at 06:15 UTC via cert-watchtower-intune-cron entry
 *   - POST /api/cert/intune/sync (manual trigger from UI)
 *   - CLI: node cert-watchtower-intune-sync.js
 *
 * Returns a structured result object — no direct log writes.
 * Caller is responsible for logging.
 */

const https  = require('https');
const path   = require('path');
const mysql  = require('mysql2/promise');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const VERSION = '1.2.0';

// ─── Classification thresholds (matches cert-watchtower-routes.js) ───────────
const THRESHOLDS = {
  critical : 30,
  warning  : 60,
};

function classifyCert(daysRemaining) {
  if (daysRemaining === null || daysRemaining === undefined) return 'error';
  if (daysRemaining <= 0)                   return 'expired';
  if (daysRemaining <= THRESHOLDS.critical) return 'critical';
  if (daysRemaining <= THRESHOLDS.warning)  return 'warning';
  return 'ok';
}

function daysUntil(dateStr) {
  if (!dateStr) return null;
  const ms = new Date(dateStr) - new Date();
  return Math.floor(ms / 86400000);
}

// ─── Graph API token acquisition ─────────────────────────────────────────────
async function getGraphToken() {
  const { INTUNE_TENANT_ID, INTUNE_CLIENT_ID, INTUNE_CLIENT_SECRET } = process.env;
  if (!INTUNE_TENANT_ID || !INTUNE_CLIENT_ID || !INTUNE_CLIENT_SECRET) {
    throw new Error('Missing INTUNE_TENANT_ID / INTUNE_CLIENT_ID / INTUNE_CLIENT_SECRET in .env');
  }

  const body = new URLSearchParams({
    grant_type    : 'client_credentials',
    client_id     : INTUNE_CLIENT_ID,
    client_secret : INTUNE_CLIENT_SECRET,
    scope         : 'https://graph.microsoft.com/.default',
  }).toString();

  return new Promise((resolve, reject) => {
    const options = {
      hostname : 'login.microsoftonline.com',
      path     : `/${INTUNE_TENANT_ID}/oauth2/v2.0/token`,
      method   : 'POST',
      headers  : {
        'Content-Type'   : 'application/x-www-form-urlencoded',
        'Content-Length' : Buffer.byteLength(body),
      },
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (!json.access_token) {
            reject(new Error(`Token error: ${json.error_description || JSON.stringify(json)}`));
          } else {
            resolve(json.access_token);
          }
        } catch (e) {
          reject(new Error(`Token parse error: ${e.message}`));
        }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ─── Graph API call ───────────────────────────────────────────────────────────
async function fetchApplePushCert(token) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname : 'graph.microsoft.com',
      path     : '/v1.0/deviceManagement/applePushNotificationCertificate',
      method   : 'GET',
      headers  : {
        'Authorization' : `Bearer ${token}`,
        'Content-Type'  : 'application/json',
      },
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (res.statusCode !== 200) {
            reject(new Error(`Graph API ${res.statusCode}: ${json.error?.message || data}`));
          } else {
            resolve(json);
          }
        } catch (e) {
          reject(new Error(`Graph response parse error: ${e.message}`));
        }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

// ─── Graph API call — VPP token ──────────────────────────────────────────────
async function fetchVppTokens(token) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname : 'graph.microsoft.com',
      path     : '/v1.0/deviceAppManagement/vppTokens',
      method   : 'GET',
      headers  : {
        'Authorization' : `Bearer ${token}`,
        'Content-Type'  : 'application/json',
      },
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (res.statusCode !== 200) {
            reject(new Error(`Graph API ${res.statusCode}: ${json.error?.message || data}`));
          } else {
            resolve(json.value || []);
          }
        } catch (e) {
          reject(new Error(`VPP token response parse error: ${e.message}`));
        }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

// ─── PRTG push ────────────────────────────────────────────────────────────────
async function pushToPrtgIfEnabled(db, row, certStatus, daysRemaining) {
  // Load global PRTG switch
  const [[cfg]] = await db.query(
    `SELECT config_value FROM cert_config WHERE config_key = 'prtg_enabled' LIMIT 1`
  );
  if (!cfg || cfg.config_value !== '1') return { skipped: true, reason: 'global_disabled' };
  if (!row.prtg_push_enabled || !row.prtg_token) return { skipped: true, reason: 'not_configured' };

  // Load PRTG connection config
  const [cfgRows] = await db.query(
    `SELECT config_key, config_value FROM cert_config WHERE config_key IN
     ('prtg_core_host','prtg_push_port','prtg_push_protocol','prtg_verify_tls','prtg_timeout_ms')`
  );
  const cfg2 = Object.fromEntries(cfgRows.map(r => [r.config_key, r.config_value]));

  const host     = cfg2.prtg_core_host    || 'prtg01awsw2us.nrpi.local';
  const port     = cfg2.prtg_push_port    || '5050';
  const protocol = cfg2.prtg_push_protocol || 'http';

  // Build XML payload — 2 channels
  const statusNum = { ok: 0, warning: 1, critical: 2, expired: 3, error: 4 }[certStatus] ?? 4;
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<prtg>
  <result>
    <channel>Days Until Expiry</channel>
    <value>${Math.max(daysRemaining, 0)}</value>
    <customunit>days</customunit>
  </result>
  <result>
    <channel>Cert Status</channel>
    <value>${statusNum}</value>
  </result>
  <text>${row.display_name} cert posture ${certStatus}</text>
</prtg>`;

  const url = `${protocol}://${host}:${port}/${row.prtg_token}`;

  return new Promise((resolve) => {
    try {
      const urlObj   = new URL(url);
      const body     = Buffer.from(xml, 'utf8');
      const options  = {
        hostname : urlObj.hostname,
        port     : urlObj.port || (protocol === 'https' ? 443 : 80),
        path     : urlObj.pathname,
        method   : 'POST',
        headers  : {
          'Content-Type'   : 'text/xml',
          'Content-Length' : body.length,
        },
      };

      const lib = protocol === 'https' ? require('https') : require('http');
      const req = lib.request(options, (res) => {
        let data = '';
        res.on('data', (c) => { data += c; });
        res.on('end', () => {
          try {
            const parsed  = JSON.parse(data);
            const matched = parseInt(parsed['Matching Sensors'] ?? parsed.matchingSensors ?? -1, 10);
            const status  = matched === 0 ? 'mismatch' : (parsed.status === 'Ok' ? 'ok' : 'error');
            resolve({ status, raw: data });
          } catch {
            resolve({ status: 'error', raw: data });
          }
        });
      });
      req.on('error', (e) => resolve({ status: 'error', raw: e.message }));
      req.write(body);
      req.end();
    } catch (e) {
      resolve({ status: 'error', raw: e.message });
    }
  });
}

// ─── Main sync function ───────────────────────────────────────────────────────
async function syncIntuneApnsCert(db) {
  const started = new Date();
  const result  = {
    source_key     : 'intune_apns',
    display_name   : 'Intune MDM Push Certificate',
    started_at     : started.toISOString(),
    status         : null,
    days_remaining : null,
    cert_status    : null,
    prtg           : null,
    error          : null,
  };

  try {
    const token   = await getGraphToken();
    const apnsCert = await fetchApplePushCert(token);

    const daysRemaining = daysUntil(apnsCert.expirationDateTime);
    const certStatus    = classifyCert(daysRemaining);

    result.days_remaining = daysRemaining;
    result.cert_status    = certStatus;

    // Upsert into cert_intune
    await db.query(`
      INSERT INTO cert_intune
        (source_key, display_name, subject, serial_number, apple_identifier,
         not_after, last_modified, upload_status, cert_status, days_remaining, raw_response)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        subject        = VALUES(subject),
        serial_number  = VALUES(serial_number),
        apple_identifier = VALUES(apple_identifier),
        not_after      = VALUES(not_after),
        last_modified  = VALUES(last_modified),
        upload_status  = VALUES(upload_status),
        cert_status    = VALUES(cert_status),
        days_remaining = VALUES(days_remaining),
        raw_response   = VALUES(raw_response),
        last_synced_at = CURRENT_TIMESTAMP
    `, [
      'intune_apns',
      'Intune MDM Push Certificate',
      apnsCert.subject               || null,
      apnsCert.certificateSerialNumber || null,
      apnsCert.appleIdentifier       || null,
      apnsCert.expirationDateTime    ? new Date(apnsCert.expirationDateTime) : null,
      apnsCert.lastModifiedDateTime  ? new Date(apnsCert.lastModifiedDateTime) : null,
      apnsCert.certificateUploadStatus || null,
      certStatus,
      daysRemaining,
      JSON.stringify(apnsCert),
    ]);

    // Fetch the upserted row for PRTG push
    const [[row]] = await db.query(
      `SELECT * FROM cert_intune WHERE source_key = 'intune_apns' LIMIT 1`
    );

    // PRTG push
    const prtgResult = await pushToPrtgIfEnabled(db, row, certStatus, daysRemaining);
    result.prtg = prtgResult;

    if (!prtgResult.skipped) {
      await db.query(`
        UPDATE cert_intune SET
          prtg_last_push_at       = CURRENT_TIMESTAMP,
          prtg_last_push_status   = ?,
          prtg_last_push_response = ?
        WHERE source_key = 'intune_apns'
      `, [prtgResult.status, prtgResult.raw]);
    }

    result.status = 'ok';
  } catch (err) {
    result.status = 'error';
    result.error  = err.message;
  }

  result.duration_ms = Date.now() - started.getTime();
  return result;
}

// ─── VPP token sync ──────────────────────────────────────────────────────────
async function syncIntuneVppToken(db) {
  const started = new Date();
  const result  = {
    source_key   : 'intune_vpp',
    display_name : 'Intune Apple VPP Token',
    started_at   : started.toISOString(),
    status       : null,
    days_remaining: null,
    cert_status  : null,
    prtg         : null,
    error        : null,
  };

  try {
    const token    = await getGraphToken();
    const vppList  = await fetchVppTokens(token);

    if (!vppList || vppList.length === 0) {
      result.status = 'error';
      result.error  = 'No VPP tokens returned from Graph API';
      result.duration_ms = Date.now() - started.getTime();
      return result;
    }

    // Use the first active token (most environments have one)
    const vpp = vppList[0];
    const daysRemaining = daysUntil(vpp.expirationDateTime);
    const certStatus    = classifyCert(daysRemaining);

    result.days_remaining = daysRemaining;
    result.cert_status    = certStatus;

    await db.query(`
      INSERT INTO cert_intune
        (source_key, display_name, subject, serial_number, apple_identifier,
         not_after, last_modified, upload_status, cert_status, days_remaining, raw_response)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        subject        = VALUES(subject),
        apple_identifier = VALUES(apple_identifier),
        not_after      = VALUES(not_after),
        last_modified  = VALUES(last_modified),
        upload_status  = VALUES(upload_status),
        cert_status    = VALUES(cert_status),
        days_remaining = VALUES(days_remaining),
        raw_response   = VALUES(raw_response),
        last_synced_at = CURRENT_TIMESTAMP
    `, [
      'intune_vpp',
      'Intune Apple VPP Token',
      vpp.organizationName || null,
      vpp.id               || null,
      vpp.appleId          || null,
      vpp.expirationDateTime  ? new Date(vpp.expirationDateTime)  : null,
      vpp.lastModifiedDateTime ? new Date(vpp.lastModifiedDateTime) : null,
      vpp.state            || null,
      certStatus,
      daysRemaining,
      JSON.stringify(vpp),
    ]);

    const [[row]] = await db.query(
      `SELECT * FROM cert_intune WHERE source_key = 'intune_vpp' LIMIT 1`
    );

    const prtgResult = await pushToPrtgIfEnabled(db, row, certStatus, daysRemaining);
    result.prtg = prtgResult;

    if (!prtgResult.skipped) {
      await db.query(`
        UPDATE cert_intune SET
          prtg_last_push_at       = CURRENT_TIMESTAMP,
          prtg_last_push_status   = ?,
          prtg_last_push_response = ?
        WHERE source_key = 'intune_vpp'
      `, [prtgResult.status, prtgResult.raw]);
    }

    result.status = 'ok';
  } catch (err) {
    result.status = 'error';
    result.error  = err.message;
  }

  result.duration_ms = Date.now() - started.getTime();
  return result;
}

// ─── Exported API ─────────────────────────────────────────────────────────────
module.exports = { syncIntuneApnsCert, syncIntuneVppToken, classifyCert, daysUntil, VERSION };

// ─── CLI entrypoint ───────────────────────────────────────────────────────────
if (require.main === module) {
  (async () => {
    console.log(`[cert-watchtower-intune-sync] v${VERSION} — manual run`);
    let db;
    try {
      db = await mysql.createConnection({
        host     : process.env.DB_HOST     || 'localhost',
        port     : process.env.DB_PORT     || 3306,
        database : process.env.DB_NAME     || 'it_inventory',
        user     : process.env.DB_USER,
        password : process.env.DB_PASSWORD,
      });

      const [apnsResult, vppResult] = await Promise.all([
        syncIntuneApnsCert(db),
        syncIntuneVppToken(db),
      ]);

      for (const result of [apnsResult, vppResult]) {
        console.log(JSON.stringify(result, null, 2));
        if (result.status === 'ok') {
          console.log(`\n✓ ${result.source_key} — ${result.cert_status} — ${result.days_remaining} days remaining`);
          if (result.prtg && !result.prtg.skipped) {
            console.log(`  PRTG push: ${result.prtg.status}`);
          }
        } else {
          console.error(`\n✗ ${result.source_key} sync failed: ${result.error}`);
        }
      }
      if (apnsResult.status !== 'ok' || vppResult.status !== 'ok') process.exit(1);
    } finally {
      if (db) await db.end();
    }
  })();
}
