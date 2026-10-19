// =============================================================================
// apple-business-mgr.js — Apple Business Manager API → MySQL sync for IT Command
//
// Syncs from ABM tenant to corpit_hub:
//   abm_devices (orgDevices), abm_warranty (appleCareCoverage),
//   abm_mdm_servers (mdmServers), abm_devices.assigned_server_id
//
// Phase 2f scope: devices + warranty + MDM servers + assignedServer relationships.
// Module is standalone; not yet wired into server.js or cron.
// CLI runner is in apple-business-mgr-cli.js.
// =============================================================================

const mysql  = require('mysql2/promise');
const fs     = require('fs');
const crypto = require('crypto');
const jwt    = require('jsonwebtoken');

const CLIENT_ID = process.env.ABM_CLIENT_ID;
const KEY_ID    = process.env.ABM_KEY_ID;
const KEY_PATH  = process.env.ABM_PRIVATE_KEY_PATH;
const ENABLED   = (process.env.ABM_SYNC_ENABLED || 'true').toLowerCase() === 'true';
const PAGE_SIZE = parseInt(process.env.ABM_PAGE_SIZE || '100', 10);

const TOKEN_URL = 'https://account.apple.com/auth/oauth2/token';
const AUDIENCE  = 'https://account.apple.com/auth/oauth2/v2/token';
const API_BASE  = 'https://api-business.apple.com';

const db = mysql.createPool({
  host:     process.env.DB_HOST || 'localhost',
  port:     parseInt(process.env.DB_PORT || '3306', 10),
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 5,
  queueLimit: 0
});

let cachedToken = null;
let cachedTokenExpiresAt = 0;

async function getAccessToken() {
  const now = Date.now();
  if (cachedToken && now < cachedTokenExpiresAt - 300_000) return cachedToken;
  const privateKey = fs.readFileSync(KEY_PATH, 'utf8');
  const iat = Math.floor(now / 1000);
  const assertion = jwt.sign({
    sub: CLIENT_ID, iss: CLIENT_ID, aud: AUDIENCE,
    iat, exp: iat + 300, jti: crypto.randomUUID(),
  }, privateKey, { algorithm: 'ES256', header: { kid: KEY_ID, typ: 'JWT' } });
  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: CLIENT_ID,
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: assertion,
    scope: 'business.api',
  });
  const res = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!res.ok) throw new Error(`ABM token exchange failed: HTTP ${res.status} ${await res.text()}`);
  const data = await res.json();
  cachedToken = data.access_token;
  cachedTokenExpiresAt = now + (data.expires_in * 1000);
  return cachedToken;
}

async function abmGet(path, { retries = 6, allow404 = false } = {}) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    const token = await getAccessToken();
    const res = await fetch(`${API_BASE}${path}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.status === 429 || res.status >= 500) {
      if (attempt === retries) {
        throw new Error(`ABM GET ${path} failed after ${retries} retries: HTTP ${res.status}`);
      }
      try { await res.text(); } catch { /* ignore */ }
      let waitMs;
      if (res.status === 429) {
        const ra = res.headers.get('retry-after');
        if (ra) {
          const secs = parseInt(ra, 10);
          waitMs = Number.isFinite(secs) && secs > 0 ? secs * 1000 : 5000;
        } else {
          waitMs = 1000 * Math.pow(2, attempt);
        }
        waitMs = Math.floor(waitMs * (0.8 + Math.random() * 0.4));
      } else {
        waitMs = 1000 * Math.pow(2, attempt);
      }
      await new Promise(r => setTimeout(r, waitMs));
      continue;
    }
    if (res.status === 404 && allow404) return null;
    if (!res.ok) throw new Error(`ABM GET ${path} failed: HTTP ${res.status} ${await res.text()}`);
    return res.json();
  }
}

function apple2mysql(iso) {
  if (!iso) return null;
  return iso.replace('T', ' ').replace(/\.\d+Z?$/, '').replace(/Z$/, '');
}

function asJson(arrOrNull) {
  if (!arrOrNull || !Array.isArray(arrOrNull) || arrOrNull.length === 0) return null;
  return JSON.stringify(arrOrNull);
}

async function concurrentMap(items, concurrency, fn) {
  const results = new Array(items.length);
  let nextIndex = 0;
  async function worker() {
    while (true) {
      const i = nextIndex++;
      if (i >= items.length) return;
      try {
        results[i] = { ok: true, value: await fn(items[i], i) };
      } catch (err) {
        results[i] = { ok: false, error: err };
      }
    }
  }
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, worker);
  await Promise.all(workers);
  return results;
}

async function* iterateDevices() {
  let cursor = null;
  let page = 0;
  let totalSeen = 0;
  while (true) {
    page += 1;
    const params = new URLSearchParams({ limit: String(PAGE_SIZE) });
    if (cursor) params.set('cursor', cursor);
    const data = await abmGet(`/v1/orgDevices?${params.toString()}`);
    const devices = data.data || [];
    totalSeen += devices.length;
    yield { devices, page, totalSeen };
    cursor = data.meta?.paging?.nextCursor || null;
    if (!cursor || devices.length === 0) break;
  }
}

async function upsertDevice(conn, dev) {
  const a = dev.attributes || {};
  const assignedServerId = dev.relationships?.assignedServer?.data?.id || null;
  const sql = `
    INSERT INTO abm_devices (
      serial_number, device_model, product_family, product_type, device_capacity,
      part_number, order_number, color, status,
      order_date_time, added_to_org_date_time, updated_date_time,
      imei_primary, imei_all, meid, eid,
      wifi_mac_address, bluetooth_mac_address,
      purchase_source_uid, purchase_source_type,
      assigned_server_id, is_active
    ) VALUES (?,?,?,?,?, ?,?,?,?, ?,?,?, ?,?,?,?, ?,?, ?,?, ?, 1)
    ON DUPLICATE KEY UPDATE
      device_model           = VALUES(device_model),
      product_family         = VALUES(product_family),
      product_type           = VALUES(product_type),
      device_capacity        = VALUES(device_capacity),
      part_number            = VALUES(part_number),
      order_number           = VALUES(order_number),
      color                  = VALUES(color),
      status                 = VALUES(status),
      order_date_time        = VALUES(order_date_time),
      added_to_org_date_time = VALUES(added_to_org_date_time),
      updated_date_time      = VALUES(updated_date_time),
      imei_primary           = VALUES(imei_primary),
      imei_all               = VALUES(imei_all),
      meid                   = VALUES(meid),
      eid                    = VALUES(eid),
      wifi_mac_address       = VALUES(wifi_mac_address),
      bluetooth_mac_address  = VALUES(bluetooth_mac_address),
      purchase_source_uid    = VALUES(purchase_source_uid),
      purchase_source_type   = VALUES(purchase_source_type),
      assigned_server_id     = COALESCE(VALUES(assigned_server_id), assigned_server_id),
      is_active              = 1
  `;
  const imeiArr = Array.isArray(a.imei) ? a.imei : null;
  await conn.execute(sql, [
    a.serialNumber || dev.id,
    a.deviceModel || null,
    a.productFamily || null,
    a.productType || null,
    a.deviceCapacity || null,
    a.partNumber || null,
    a.orderNumber || null,
    a.color || null,
    a.status || null,
    apple2mysql(a.orderDateTime),
    apple2mysql(a.addedToOrgDateTime),
    apple2mysql(a.updatedDateTime),
    imeiArr && imeiArr.length ? imeiArr[0] : null,
    asJson(imeiArr),
    asJson(a.meid),
    a.eid || null,
    a.wifiMacAddress || null,
    a.bluetoothMacAddress || null,
    a.purchaseSourceUid || null,
    a.purchaseSourceType || null,
    assignedServerId,
  ]);
}

async function upsertCoverage(conn, coverage, serialNumber) {
  const a = coverage.attributes || {};
  const sql = `
    INSERT INTO abm_warranty (
      coverage_id, serial_number, description, status,
      start_date_time, end_date_time, agreement_number, payment_type,
      is_renewable, is_canceled, contract_cancel_date_time, is_active
    ) VALUES (?,?,?,?, ?,?,?,?, ?,?,?, 1)
    ON DUPLICATE KEY UPDATE
      serial_number             = VALUES(serial_number),
      description               = VALUES(description),
      status                    = VALUES(status),
      start_date_time           = VALUES(start_date_time),
      end_date_time             = VALUES(end_date_time),
      agreement_number          = VALUES(agreement_number),
      payment_type              = VALUES(payment_type),
      is_renewable              = VALUES(is_renewable),
      is_canceled               = VALUES(is_canceled),
      contract_cancel_date_time = VALUES(contract_cancel_date_time),
      is_active                 = 1
  `;
  await conn.execute(sql, [
    coverage.id,
    serialNumber,
    a.description || null,
    a.status || null,
    apple2mysql(a.startDateTime),
    apple2mysql(a.endDateTime),
    a.agreementNumber || null,
    a.paymentType || null,
    a.isRenewable === true ? 1 : (a.isRenewable === false ? 0 : null),
    a.isCanceled  === true ? 1 : (a.isCanceled  === false ? 0 : null),
    apple2mysql(a.contractCancelDateTime),
  ]);
}

async function upsertMdmServer(conn, server) {
  const a = server.attributes || {};
  await conn.execute(`
    INSERT INTO abm_mdm_servers (
      server_id, server_name, server_type,
      created_date_time, updated_date_time, is_active
    ) VALUES (?,?,?, ?,?, 1)
    ON DUPLICATE KEY UPDATE
      server_name       = VALUES(server_name),
      server_type       = VALUES(server_type),
      created_date_time = VALUES(created_date_time),
      updated_date_time = VALUES(updated_date_time),
      is_active         = 1
  `, [
    server.id,
    a.serverName || null,
    a.serverType || null,
    apple2mysql(a.createdDateTime),
    apple2mysql(a.updatedDateTime),
  ]);
}

async function syncDevices({ verbose = false } = {}) {
  if (!ENABLED) return { skipped: true, reason: 'ABM_SYNC_ENABLED=false' };
  const startedAt = new Date();
  const conn = await db.getConnection();
  let upserted = 0;
  let pages = 0;
  const seenSerials = new Set();
  try {
    for await (const { devices, page, totalSeen } of iterateDevices()) {
      pages = page;
      for (const dev of devices) {
        await upsertDevice(conn, dev);
        upserted += 1;
        const sn = (dev.attributes && dev.attributes.serialNumber) || dev.id;
        if (sn) seenSerials.add(sn);
      }
      if (verbose) console.log(`  page ${page}: ${devices.length} devices (running total: ${totalSeen})`);
    }
    let deactivated = 0;
    if (seenSerials.size > 0) {
      const seenArr = Array.from(seenSerials);
      const placeholders = seenArr.map(() => '?').join(',');
      const [pruneRes] = await conn.query(
        `UPDATE abm_devices SET is_active = 0
          WHERE is_active = 1 AND serial_number NOT IN (${placeholders})`,
        seenArr,
      );
      deactivated = pruneRes.affectedRows;
    }
    return {
      ok: true,
      startedAt: startedAt.toISOString(),
      finishedAt: new Date().toISOString(),
      pages, upserted, deactivated,
    };
  } finally {
    conn.release();
  }
}

async function syncMdmServers({ verbose = false } = {}) {
  if (!ENABLED) return { skipped: true, reason: 'ABM_SYNC_ENABLED=false' };
  const startedAt = new Date();
  const conn = await db.getConnection();
  let upserted = 0;
  const seenIds = new Set();
  try {
    const data = await abmGet('/v1/mdmServers');
    const servers = data.data || [];
    for (const s of servers) {
      await upsertMdmServer(conn, s);
      upserted += 1;
      seenIds.add(s.id);
    }
    if (verbose) console.log(`  mdm servers: ${upserted} upserted`);

    let deactivated = 0;
    if (seenIds.size > 0) {
      const arr = Array.from(seenIds);
      const ph = arr.map(() => '?').join(',');
      const [pruneRes] = await conn.query(
        `UPDATE abm_mdm_servers SET is_active = 0
          WHERE is_active = 1 AND server_id NOT IN (${ph})`,
        arr,
      );
      deactivated = pruneRes.affectedRows;
    }
    return {
      ok: true,
      startedAt: startedAt.toISOString(),
      finishedAt: new Date().toISOString(),
      upserted, deactivated,
    };
  } finally {
    conn.release();
  }
}

async function syncAssignedServer({ verbose = false } = {}) {
  if (!ENABLED) return { skipped: true, reason: 'ABM_SYNC_ENABLED=false' };
  const startedAt = new Date();
  const conn = await db.getConnection();
  let updated = 0;
  let unchanged = 0;
  let cleared = 0;
  let failed = 0;
  const failureLogPath = '/var/log/abm-assigned-server-failures.log';
  let failureLogStream = null;
  try {
    const [rows] = await conn.query(
      `SELECT serial_number, assigned_server_id FROM abm_devices WHERE is_active = 1`
    );
    if (verbose) console.log(`  assignedServer sync: ${rows.length} devices to fetch`);

    const concurrency = parseInt(process.env.ABM_ASSIGNED_SERVER_CONCURRENCY || '2', 10);
    let progress = 0;
    const total = rows.length;
    const results = await concurrentMap(rows, concurrency, async (row) => {
      const data = await abmGet(
        `/v1/orgDevices/${encodeURIComponent(row.serial_number)}/relationships/assignedServer`,
        { allow404: true }
      );
      const newId = data?.data?.id || null;
      const oldId = row.assigned_server_id || null;
      let action;
      if (newId === oldId) {
        action = 'unchanged';
      } else if (newId === null) {
        await conn.execute(
          `UPDATE abm_devices SET assigned_server_id = NULL WHERE serial_number = ?`,
          [row.serial_number]
        );
        action = 'cleared';
      } else {
        await conn.execute(
          `UPDATE abm_devices SET assigned_server_id = ? WHERE serial_number = ?`,
          [newId, row.serial_number]
        );
        action = 'updated';
      }
      progress += 1;
      if (verbose && (progress % 50 === 0 || progress === total)) {
        console.log(`  assignedServer: ${progress}/${total} devices processed`);
      }
      return action;
    });

    for (let i = 0; i < results.length; i++) {
      const r = results[i];
      if (r.ok) {
        if (r.value === 'updated') updated += 1;
        else if (r.value === 'unchanged') unchanged += 1;
        else if (r.value === 'cleared') cleared += 1;
      } else {
        failed += 1;
        if (!failureLogStream) {
          try {
            failureLogStream = fs.createWriteStream(failureLogPath, { flags: 'a' });
            failureLogStream.write(`\n=== ${new Date().toISOString()} assignedServer sync failures ===\n`);
          } catch { /* ignore */ }
        }
        if (failureLogStream) {
          failureLogStream.write(`${rows[i].serial_number}\t${r.error.message}\n`);
        }
      }
    }
    if (failureLogStream) {
      await new Promise(resolve => failureLogStream.end(resolve));
      if (verbose) console.log(`  assignedServer: ${failed} failure(s) logged to ${failureLogPath}`);
    }

    return {
      ok: true,
      startedAt: startedAt.toISOString(),
      finishedAt: new Date().toISOString(),
      updated, unchanged, cleared, failed,
    };
  } finally {
    conn.release();
  }
}

async function syncWarranty({ verbose = false } = {}) {
  if (!ENABLED) return { skipped: true, reason: 'ABM_SYNC_ENABLED=false' };
  const startedAt = new Date();
  const conn = await db.getConnection();
  let coveragesUpserted = 0;
  let devicesProcessed = 0;
  let devicesFailed = 0;
  const seenCoverageIds = new Set();
  const failureLogPath = '/var/log/abm-warranty-failures.log';
  let failureLogStream = null;
  try {
    const [serials] = await conn.query(
      `SELECT serial_number FROM abm_devices WHERE is_active = 1`
    );
    if (verbose) console.log(`  warranty sync: ${serials.length} devices to fetch`);

    const concurrency = parseInt(process.env.ABM_WARRANTY_CONCURRENCY || '2', 10);
    let progress = 0;
    const total = serials.length;
    const results = await concurrentMap(serials, concurrency, async (row) => {
      const data = await abmGet(`/v1/orgDevices/${encodeURIComponent(row.serial_number)}/appleCareCoverage`);
      const coverages = data.data || [];
      for (const cov of coverages) {
        await upsertCoverage(conn, cov, row.serial_number);
        if (cov.id) seenCoverageIds.add(cov.id);
      }
      progress += 1;
      if (verbose && (progress % 50 === 0 || progress === total)) {
        console.log(`  warranty: ${progress}/${total} devices processed`);
      }
      return coverages.length;
    });

    for (let i = 0; i < results.length; i++) {
      const r = results[i];
      if (r.ok) {
        devicesProcessed += 1;
        coveragesUpserted += r.value;
      } else {
        devicesFailed += 1;
        if (!failureLogStream) {
          try {
            failureLogStream = fs.createWriteStream(failureLogPath, { flags: 'a' });
            failureLogStream.write(`\n=== ${new Date().toISOString()} warranty sync failures ===\n`);
          } catch { /* ignore */ }
        }
        if (failureLogStream) {
          failureLogStream.write(`${serials[i].serial_number}\t${r.error.message}\n`);
        }
      }
    }
    if (failureLogStream) {
      await new Promise(resolve => failureLogStream.end(resolve));
      if (verbose) console.log(`  warranty: ${devicesFailed} failure(s) logged to ${failureLogPath}`);
    }

    let deactivated = 0;
    if (seenCoverageIds.size > 0) {
      const seenArr = Array.from(seenCoverageIds);
      const placeholders = seenArr.map(() => '?').join(',');
      const [pruneRes] = await conn.query(
        `UPDATE abm_warranty SET is_active = 0
          WHERE is_active = 1 AND coverage_id NOT IN (${placeholders})`,
        seenArr,
      );
      deactivated = pruneRes.affectedRows;
    }

    return {
      ok: true,
      startedAt: startedAt.toISOString(),
      finishedAt: new Date().toISOString(),
      devicesProcessed, devicesFailed, coveragesUpserted, deactivated,
    };
  } finally {
    conn.release();
  }
}

async function fullSync({ verbose = false } = {}) {
  const devices = await syncDevices({ verbose });
  if (devices.skipped) return { devices };
  const mdmServers = await syncMdmServers({ verbose });
  const assignedServer = await syncAssignedServer({ verbose });
  const warranty = await syncWarranty({ verbose });
  return { devices, mdmServers, assignedServer, warranty };
}

module.exports = {
  fullSync,
  syncDevices, syncMdmServers, syncAssignedServer, syncWarranty,
  getAccessToken, abmGet,
};
