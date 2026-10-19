'use strict';
// zsnet-sync.js — Zscaler network-map data sync (ZIA + ZPA + SIPA)
// Run: sudo env "PATH=$PATH" node /var/www/corpit-hub-api/zsnet-sync.js
// Cron target: nightly. Reuses auth helpers from zscaler-lookup.js.
require('dotenv').config({ path: __dirname + '/.env' });
const mysql = require('mysql2/promise');
const { zpaAuth, ziaAuth, httpsRequest } = require('./zscaler-lookup');

const CUSTOMER_ID = process.env.ZPA_CUSTOMER_ID;
const ZPA_BASE = 'https://api.zsapi.net/zpa/mgmtconfig/v1/admin/customers/' + CUSTOMER_ID;
const ZIA_BASE = process.env.ZIA_BASE_URL;

const pool = mysql.createPool({
  host:     process.env.DB_HOST || 'localhost',
  port:     parseInt(process.env.DB_PORT || '3306', 10),
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 5,
  // ZPA ids are 18-digit integers; as JS numbers they lose their last digits.
  supportBigNumbers: true,
  bigNumberStrings: true,
});

// Zscaler booleans arrive as the strings "true"/"false" — the string "false" is truthy in JS.
const zbool = (v) => (v === true || String(v).toLowerCase() === 'true') ? 1 : 0;

// ── thin authenticated GETs (auth cached inside zscaler-lookup) ──
async function zpaGet(path) {
  const token = await zpaAuth();
  const url = new URL(ZPA_BASE + path);
  const res = await httpsRequest(url, { method: 'GET', headers: { Authorization: 'Bearer ' + token } });
  if (res.status !== 200) throw new Error('ZPA GET ' + path + ' -> HTTP ' + res.status);
  return res.body;
}
async function ziaGet(path) {
  let token = await ziaAuth();
  const url = new URL(ZIA_BASE + '/' + path);
  let res = await httpsRequest(url, { method: 'GET', headers: { Authorization: 'Bearer ' + token } });
  if (res.status === 401 || res.status === 403) {
    token = await ziaAuth(true);
    res = await httpsRequest(url, { method: 'GET', headers: { Authorization: 'Bearer ' + token } });
  }
  if (res.status !== 200) throw new Error('ZIA GET ' + path + ' -> HTTP ' + res.status);
  return res.body;
}

// ── paginated ZPA fetch (pagesize 500) ──
async function zpaGetAll(resource) {
  let page = 1, out = [];
  while (true) {
    const body = await zpaGet('/' + resource + '?page=' + page + '&pagesize=500');
    const list = (body && body.list) || [];
    out = out.concat(list);
    const total = parseInt((body && body.totalCount) || '0', 10);
    if (out.length >= total || list.length === 0) break;
    page++;
    if (page > 50) break; // safety
  }
  return out;
}

async function logSync(conn, source, status, count, started, err) {
  await conn.query(
    'INSERT INTO zsnet_sync_log (source,status,row_count,started_at,finished_at,error) VALUES (?,?,?,?,NOW(),?)',
    [source, status, count, started, err || null]
  );
}

async function run() {
  const started = new Date();
  const conn = await pool.getConnection();
  try {
    // ---- fetch everything first (fail before we truncate) ----
    console.log('[zsnet] fetching ZPA applications...');
    const apps = await zpaGetAll('application');
    console.log('[zsnet] fetching ZPA server groups...');
    const sgroups = await zpaGetAll('serverGroup');
    console.log('[zsnet] fetching ZPA connector groups...');
    const cgroups = await zpaGetAll('appConnectorGroup');
    console.log('[zsnet] fetching ZPA connectors...');
    // The read-only API client may not hold Connector read (403 access.denied). That must
    // not abort the whole sync: segments, server groups and gateways are what the Okta →
    // Entra work needs. Connector rows are then kept from the last successful read and the
    // per-source log row says so, so nobody reads stale connector IPs as fresh.
    let connectors = null, connectorErr = null;
    try { connectors = await zpaGetAll('connector'); }
    catch (e) { connectorErr = e.message; console.warn('[zsnet] connector fetch failed (rows kept from the last successful read):', e.message); }
    console.log('[zsnet] fetching ZIA locations...');
    const locations = await ziaGet('locations?page=1&pageSize=1000');
    console.log('[zsnet] fetching ZIA ZPA gateways (SIPA)...');
    let gateways = [];
    try { gateways = await ziaGet('zpaGateways'); }
    catch (e) { console.warn('[zsnet] zpaGateways fetch failed (SIPA edge skipped):', e.message); }

    await conn.beginTransaction();

    // ---- ZPA apps ----
    await conn.query('DELETE FROM zsnet_zpa_app');
    await conn.query('DELETE FROM zsnet_zpa_app_sg');
    for (const a of apps) {
      await conn.query(
        'INSERT INTO zsnet_zpa_app (id,name,domain_names,enabled,modified_time) VALUES (?,?,?,?,?)',
        [a.id, a.name || '', JSON.stringify(a.domainNames || []), zbool(a.enabled), a.modifiedTime || null]
      );
    }

    // ---- ZPA server groups + both edges (apps, connector groups) ----
    await conn.query('DELETE FROM zsnet_zpa_server_group');
    await conn.query('DELETE FROM zsnet_zpa_sg_cg');
    for (const sg of sgroups) {
      await conn.query(
        'INSERT INTO zsnet_zpa_server_group (id,name,enabled) VALUES (?,?,?)',
        [sg.id, sg.name || '', zbool(sg.enabled)]
      );
      for (const app of (sg.applications || [])) {
        await conn.query(
          'INSERT IGNORE INTO zsnet_zpa_app_sg (app_id,server_group_id) VALUES (?,?)',
          [app.id, sg.id]
        );
      }
      for (const cg of (sg.appConnectorGroups || [])) {
        await conn.query(
          'INSERT IGNORE INTO zsnet_zpa_sg_cg (server_group_id,connector_group_id) VALUES (?,?)',
          [sg.id, cg.id]
        );
      }
    }

    // ---- ZPA connector groups ----
    await conn.query('DELETE FROM zsnet_zpa_connector_group');
    for (const cg of cgroups) {
      await conn.query(
        'INSERT INTO zsnet_zpa_connector_group (id,name,location,city_country,country_code,latitude,longitude,enabled,group_type) VALUES (?,?,?,?,?,?,?,?,?)',
        [cg.id, cg.name || '', cg.location || null, cg.cityCountry || null, cg.countryCode || null,
         cg.latitude || null, cg.longitude || null, zbool(cg.enabled), cg.connectorGroupType || null]
      );
    }

    // ---- ZPA connectors ----
    if (connectors) await conn.query('DELETE FROM zsnet_zpa_connector');
    for (const c of (connectors || [])) {
      await conn.query(
        'INSERT INTO zsnet_zpa_connector (id,name,connector_group_id,private_ip,public_ip,location,latitude,longitude,current_version,platform,upgrade_status,control_channel_status,enabled) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
        [c.id, c.name || '', c.appConnectorGroupId || null,
         c.privateIp || null, c.publicIp || null, c.location || null,
         c.latitude || null, c.longitude || null,
         c.currentVersion || null, c.platform || null, c.upgradeStatus || null,
         c.controlChannelStatus || null, zbool(c.enabled)]
      );
    }

    // ---- ZIA locations ----
    await conn.query('DELETE FROM zsnet_zia_location');
    for (const l of (locations || [])) {
      await conn.query(
        'INSERT INTO zsnet_zia_location (id,name,country,state,tz,ip_addresses,ofw_enabled,latitude,longitude) VALUES (?,?,?,?,?,?,?,?,?)',
        [l.id, l.name || '', l.country || null, l.state || null, l.tz || null,
         JSON.stringify(l.ipAddresses || []), l.ofwEnabled ? 1 : 0, l.latitude || null, l.longitude || null]
      );
    }

    // ---- ZIA ZPA gateways (SIPA) + app-segment edge ----
    await conn.query('DELETE FROM zsnet_zia_zpa_gateway');
    await conn.query('DELETE FROM zsnet_zia_gateway_app_segment');
    for (const gw of (gateways || [])) {
      const sgExt = (gw.zpaServerGroup && gw.zpaServerGroup.externalId) || null;
      await conn.query(
        'INSERT INTO zsnet_zia_zpa_gateway (id,name,description,zpa_server_group_ext_id) VALUES (?,?,?,?)',
        [gw.id, gw.name || '', gw.description || null, sgExt]
      );
      for (const seg of (gw.zpaAppSegments || [])) {
        if (!seg.externalId) continue;
        await conn.query(
          'INSERT IGNORE INTO zsnet_zia_gateway_app_segment (gateway_id,app_segment_ext_id,app_segment_name) VALUES (?,?,?)',
          [gw.id, seg.externalId, seg.name || null]
        );
      }
    }

    await conn.commit();
    const connN = connectors ? connectors.length : 0;
    await logSync(conn, 'all', connectors ? 'ok' : 'partial',
      apps.length + sgroups.length + cgroups.length + connN + (locations||[]).length + (gateways||[]).length,
      started, connectors ? null : 'connectors not refreshed: ' + connectorErr);
    await logSync(conn, 'zpa_application', 'ok', apps.length, started, null);
    await logSync(conn, 'zpa_server_group', 'ok', sgroups.length, started, null);
    await logSync(conn, 'zpa_connector_group', 'ok', cgroups.length, started, null);
    await logSync(conn, 'zpa_connector', connectors ? 'ok' : 'error', connN, started, connectorErr);
    await logSync(conn, 'zia_location', 'ok', (locations||[]).length, started, null);
    await logSync(conn, 'zia_zpa_gateway', (gateways||[]).length ? 'ok' : 'error', (gateways||[]).length, started, (gateways||[]).length ? null : 'zpaGateways returned nothing');
    console.log('[zsnet] sync %s — apps:%d sg:%d cg:%d conn:%s loc:%d gw:%d',
      connectors ? 'OK' : 'PARTIAL (connectors kept from last read)',
      apps.length, sgroups.length, cgroups.length, connectors ? connN : 'kept', (locations||[]).length, (gateways||[]).length);
  } catch (e) {
    try { await conn.rollback(); } catch (_) {}
    try { await logSync(conn, 'all', 'error', 0, started, e.message); } catch (_) {}
    console.error('[zsnet] sync FAILED:', e.message);
    process.exitCode = 1;
  } finally {
    conn.release();
    await pool.end();
  }
}
run();
