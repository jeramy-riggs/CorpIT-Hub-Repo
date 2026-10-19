'use strict';
// zsnet-routes.js — Zscaler equipment map graph API (v3: per-site egress nodes)
const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');
const createRbac = require('./rbac-middleware');

const pool = mysql.createPool({
  host:     process.env.DB_HOST || 'localhost',
  port:     parseInt(process.env.DB_PORT || '3306', 10),
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 5,
});
const rbac = createRbac(pool);
router.use(rbac.loadCurrentUser);

function jparse(v, fallback) {
  if (v == null) return fallback;
  if (typeof v === 'object') return v;
  try { return JSON.parse(v); } catch (_) { return fallback; }
}

function siteMeta(cgName) {
  var n = (cgName || '').toUpperCase();
  if (n.indexOf('AWS') !== -1) return { site: 'AWS us-west-2', cloud: true, key: 'aws' };
  if (n.indexOf('SNA') !== -1 || n.indexOf('MAUCHLY') !== -1) return { site: 'Irvine HQ', cloud: false, key: 'irvine' };
  return { site: cgName || 'Unknown', cloud: false, key: cgName || 'unknown' };
}

router.get('/graph', rbac.requirePage('zscaler-diag', 'read'), async (req, res) => {
  try {
    const [cgroups]    = await pool.query('SELECT id,name,location,city_country,country_code FROM zsnet_zpa_connector_group WHERE enabled = 1');
    const [connectors] = await pool.query('SELECT id,name,connector_group_id,private_ip,public_ip,location,current_version,platform,upgrade_status,control_channel_status,enabled FROM zsnet_zpa_connector');
    const [locations]  = await pool.query('SELECT id,name,country,state,tz,ip_addresses,ofw_enabled FROM zsnet_zia_location');
    const [gateways]   = await pool.query('SELECT id,name,description,zpa_server_group_ext_id FROM zsnet_zia_zpa_gateway');
    const [sipaCg]     = await pool.query(
      'SELECT DISTINCT m.connector_group_id AS cg_id ' +
      'FROM zsnet_zia_zpa_gateway gw ' +
      'JOIN zsnet_zpa_server_group sg ON sg.id = gw.zpa_server_group_ext_id ' +
      'JOIN zsnet_zpa_sg_cg m ON m.server_group_id = sg.id'
    );
    const [clientCg]   = await pool.query('SELECT DISTINCT connector_group_id AS cg_id FROM zsnet_zpa_sg_cg');

    const nodes = [];
    const edges = [];
    const seen = new Set();
    const addEdge = (id, source, target, kind, elabel) => {
      if (seen.has(id)) return; seen.add(id);
      edges.push({ data: { id, source, target, kind, elabel: elabel || '' } });
    };

    // upstream nodes
    nodes.push({ data: { id: 'zpa-client', label: 'ZPA Client', type: 'client' } });
    for (const l of locations) {
      nodes.push({ data: {
        id: 'loc-' + l.id, label: l.name, type: 'zia_location',
        country: l.country, state: l.state, tz: l.tz,
        ips: jparse(l.ip_addresses, []), ofw: !!l.ofw_enabled
      }});
    }
    const sipaId = 'sipa-combined';
    if (gateways.length > 0) {
      nodes.push({ data: { id: sipaId, label: 'SIPA Gateways (' + gateways.length + ')', type: 'sipa_gateway' } });
      for (const l of locations) addEdge('e-loc' + l.id + '-sipa', 'loc-' + l.id, sipaId, 'sipa');
    }

    // site compound nodes
    const cgById = {};
    const cgMeta = {};
    for (const cg of cgroups) {
      const meta = siteMeta(cg.name);
      const siteNodeId = 'site-' + cg.id;
      cgById[cg.id] = siteNodeId;
      cgMeta[cg.id] = meta;
      nodes.push({ data: {
        id: siteNodeId,
        label: meta.site + '\n(' + cg.name + ')',
        type: meta.cloud ? 'site_cloud' : 'site_onprem',
        connectorGroup: cg.name, site: meta.site, siteKey: meta.key,
        location: cg.location || cg.city_country || null
      }});
    }

    // upstream -> site edges
    const sipaCgSet = new Set(sipaCg.map(r => String(r.cg_id)));
    const clientCgSet = new Set(clientCg.map(r => String(r.cg_id)));
    for (const cg of cgroups) {
      const siteNodeId = cgById[cg.id];
      if (sipaCgSet.has(String(cg.id))) addEdge('e-sipa-' + cg.id, sipaId, siteNodeId, 'sipa', 'SIPA anchor');
      if (clientCgSet.has(String(cg.id))) addEdge('e-client-' + cg.id, 'zpa-client', siteNodeId, 'zpa', 'direct ZPA');
    }

    // per-site egress nodes (one Internet + one Corp Network per site)
    const siteEgressCreated = {};
    for (const cg of cgroups) {
      const meta = cgMeta[cg.id];
      const inetId = 'egress-internet-' + meta.key;
      const netId  = 'egress-network-' + meta.key;
      if (!siteEgressCreated[meta.key]) {
        siteEgressCreated[meta.key] = true;
        nodes.push({ data: { id: inetId, label: 'Internet\n(' + meta.site + ')', type: 'internet', siteKey: meta.key } });
        nodes.push({ data: { id: netId,  label: 'Corp Network\n(' + meta.site + ')', type: 'network',  siteKey: meta.key } });
      }
    }

    // connectors as children of their site box
    for (const c of connectors) {
      const cg = cgroups.find(g => String(g.id) === String(c.connector_group_id));
      if (!cg) continue;
      const meta = cgMeta[cg.id];
      const parent = cgById[cg.id];
      const ipLine = [c.private_ip, c.public_ip].filter(Boolean).join(' / ');
      nodes.push({ data: {
        id: 'conn-' + c.id,
        label: c.name + (ipLine ? '\n' + ipLine : ''),
        type: 'connector', parent,
        privateIp: c.private_ip, publicIp: c.public_ip, location: c.location,
        version: c.current_version, platform: c.platform,
        upgradeStatus: c.upgrade_status, channelStatus: c.control_channel_status,
        healthy: c.control_channel_status === 'ZPN_STATUS_AUTHENTICATED',
        enabled: !!c.enabled, siteKey: meta.key
      }});
      // egress edges with IP labels — to this site's egress nodes
      const inetId = 'egress-internet-' + meta.key;
      const netId  = 'egress-network-' + meta.key;
      if (c.public_ip)  addEdge('eg-pub-' + c.id, 'conn-' + c.id, inetId, 'egress_public', c.public_ip);
      if (c.private_ip) addEdge('eg-prv-' + c.id, 'conn-' + c.id, netId,  'egress_private', c.private_ip);
    }

    res.json({
      generatedAt: new Date().toISOString(),
      counts: { sites: cgroups.length, connectors: connectors.length, locations: locations.length, sipaGateways: gateways.length },
      nodes, edges
    });
  } catch (e) {
    console.error('[zsnet] /graph error:', e.message);
    res.status(500).json({ error: 'graph_build_failed', message: e.message });
  }
});

router.get('/status', rbac.requirePage('zscaler-diag', 'read'), async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT source,status,row_count,started_at,finished_at,error FROM zsnet_sync_log ORDER BY id DESC LIMIT 10');
    res.json({ recent: rows });
  } catch (e) {
    res.status(500).json({ error: 'status_failed', message: e.message });
  }
});

module.exports = router;
