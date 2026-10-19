/**
 * oem-routes.js — Okta -> Entra Conditional Access migration workspace.
 * Register in server.js next to the sentinel mount:
 *   app.use('/api/oem', require('./oem-routes'));
 *
 * Read endpoints serve the snapshot the collector wrote. Nothing here writes to Entra:
 * the credential holds no write scope, and /capability reports that from the live token
 * rather than asserting it, so the page's labels cannot drift from reality.
 */
'use strict';
const express = require('express');
const mysql = require('mysql2/promise');
const createRbac = require('./rbac-middleware');
const { MAPPINGS, PHASES, classifyStep, capabilityFor } = require('./oem-mapping');
const SIPA = require('./oem-sipa');
const L = require('./oem-lib');

const router = express.Router();
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 5,
  // zsnet_* ids are 18-digit ZPA identifiers. As JS numbers they round
  // (288258444836732930 reads back as 288258444836732900), which is what produced the
  // "inconsistent server-group identifiers" observation. Keep them as strings.
  supportBigNumbers: true,
  bigNumberStrings: true,
});
const rbac = createRbac(pool);
router.use(rbac.loadCurrentUser);
const db = pool;
const PAGE_KEY = 'okta-entra-migration';
const read = () => rbac.requirePage(PAGE_KEY, 'read');
const admin = () => rbac.requirePage(PAGE_KEY, 'admin');

/** mysql2 pre-parses JSON columns; JSON.parse on an object throws. */
const j = (v, dflt) => {
  if (v === null || v === undefined) return dflt;
  if (typeof v === 'object') return v;
  try { return JSON.parse(v); } catch (e) { return dflt; }
};
const fail = (res, e, where) => {
  console.error(`[oem] ${where}:`, e.message);
  res.status(500).json({ error: 'query failed', where });
};

/* ------------------------------------------------------------- capability */

let capCache = { at: 0, roles: null, error: null };

/**
 * The live app-only roles. Read from the token's own roles claim, so it reflects what the
 * credential can do right now. Cached 5 minutes; a consent change shows up on the next read.
 */
async function liveRoles() {
  if (capCache.roles && Date.now() - capCache.at < 300000) return capCache;
  try {
    const r = await fetch(`https://login.microsoftonline.com/${process.env.ENTRA_TENANT_ID}/oauth2/v2.0/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.ENTRA_CLIENT_ID,
        client_secret: process.env.ENTRA_CLIENT_SECRET,
        scope: 'https://graph.microsoft.com/.default',
        grant_type: 'client_credentials',
      }),
    });
    const t = await r.json();
    if (!t.access_token) throw new Error(t.error_description || 'no token');
    const claims = JSON.parse(Buffer.from(t.access_token.split('.')[1], 'base64').toString('utf8'));
    capCache = { at: Date.now(), roles: claims.roles || [], error: null };
  } catch (e) {
    // Unknown is its own state. Reporting zero roles would wrongly mark everything blocked.
    capCache = { at: Date.now(), roles: null, error: e.message };
  }
  return capCache;
}

// GET /api/oem/capability
router.get('/capability', read(), async (req, res) => {
  const c = await liveRoles();
  const roles = c.roles || [];
  const probe = (n) => (c.roles === null ? 'unknown' : roles.includes(n) ? 'granted' : 'missing');

  // The caller's own effective level on this page. The UI renders the step-status
  // control only when this is 'admin', so a read-only viewer is never shown a
  // control that would be refused on click. Anything we cannot determine stays
  // null and is treated as read-only.
  let pageLevel = null;
  try {
    if (req.user && req.user.email && rbac.computeEffectivePages) {
      const pages = await rbac.computeEffectivePages(
        req.user.email, req.user.roles || [], !!req.user.isSuperAdmin);
      pageLevel = pages[PAGE_KEY] || 'none';
    }
  } catch (e) {
    console.error('[oem] pageLevel probe failed:', e.message);
  }

  let okta = null, zscaler = null;
  try { okta = await L.oktaIdentity(); } catch (e) { okta = { known: false, error: e.message }; }
  try { zscaler = await L.zscalerProbe(); } catch (e) { zscaler = { error: e.message }; }
  res.json({
    pageLevel,
    okta: { known: !!okta.known, login: okta.login || null, roles: okta.roles || null, canWriteOkta: okta.known ? okta.canWriteOkta : null, error: okta.error || okta.rolesError || null },
    zscaler: { checkedAt: zscaler.checkedAt || null, serverGroups: zscaler.serverGroups || 'unknown', connectors: zscaler.connectors || 'unknown', gateways: zscaler.gateways || 'unknown', error: zscaler.error || null },
    perAction: '/api/oem/access lists every action with its class (analysis, auto, browser, technician, blocked) and the minimum missing permission.',
    canSetStepState: pageLevel === 'admin' && !(req.user && req.user.readOnly),
    // The Refresh button is gated on this. It has to be emitted here or the
    // page reads undefined and refuses every caller, admins included.
    canRefresh: pageLevel === 'admin' && !(req.user && req.user.readOnly),
    source: 'live token roles claim',
    checkedAt: new Date(c.at).toISOString(),
    error: c.error,
    roleCount: c.roles === null ? null : roles.length,
    roles,
    key: {
      'Policy.Read.All': probe('Policy.Read.All'),
      'Directory.Read.All': probe('Directory.Read.All'),
      'AuditLog.Read.All': probe('AuditLog.Read.All'),
      'Reports.Read.All': probe('Reports.Read.All'),
      'UserAuthenticationMethod.Read.All': probe('UserAuthenticationMethod.Read.All'),
      'Policy.ReadWrite.ConditionalAccess': probe('Policy.ReadWrite.ConditionalAccess'),
      'Group.ReadWrite.All': probe('Group.ReadWrite.All'),
      'Domain.Read.All': probe('Domain.Read.All'),
    },
    canWriteEntra: c.roles === null ? null : roles.includes('Policy.ReadWrite.ConditionalAccess'),
    note: c.roles === null
      ? 'Could not read the credential, so automation availability is unknown rather than absent.'
      : roles.includes('Policy.ReadWrite.ConditionalAccess')
        ? 'The credential can write Conditional Access policies.'
        : 'The credential is read-only for Conditional Access. Every Entra change on this page is a manual step, and the payloads are provided to paste.',
  });
});

/* ---------------------------------------------------------------- overview */

// GET /api/oem/overview
router.get('/overview', read(), async (req, res) => {
  try {
    const [[meta]] = await db.query(`SELECT v, updated_at FROM oem_meta WHERE k='last_run'`);
    const [[mfa]] = await db.query(`SELECT v, updated_at FROM oem_meta WHERE k='mfa_claim'`);
    const [[oc]] = await db.query(
      `SELECT COUNT(*) policies, SUM(rule_count) rules, SUM(app_count) apps,
              SUM(JSON_LENGTH(shadowed_rules)>0) with_shadowed FROM oem_okta_policy`);
    const [[ec]] = await db.query(
      `SELECT COUNT(*) total, SUM(state='enabled') enabled,
              SUM(state='enabledForReportingButNotEnforced') report_only,
              SUM(state='disabled') disabled, SUM(is_inert) inert FROM oem_entra_ca`);
    const [inertByState] = await db.query(
      `SELECT state, COUNT(*) n, GROUP_CONCAT(display_name ORDER BY display_name SEPARATOR ' | ') names
         FROM oem_entra_ca WHERE is_inert=1 GROUP BY state`);
    const [[caFresh]] = await db.query(`SELECT MAX(collected_at) at FROM oem_entra_ca`);
    const [par] = await db.query(
      `SELECT direction, COUNT(*) n FROM oem_zone_parity GROUP BY direction`);
    const [[steps]] = await db.query(
      `SELECT COUNT(*) tracked, SUM(state='done') done, SUM(state='blocked') blocked,
              SUM(state='in_progress') in_progress, SUM(state='skipped') skipped
         FROM oem_step_status`);
    const cap = await liveRoles();
    const run = j(meta && meta.v, null);

    const totalSteps = MAPPINGS.length;
    res.json({
      freshness: {
        lastRun: run ? run.finished : null,
        ok: run ? run.ok : null,
        ageHours: run && run.finished ? +((Date.now() - new Date(run.finished)) / 3600000).toFixed(1) : null,
        warnings: run ? (run.warnings || []) : [],
        counts: run ? run.counts : null,
      },
      okta: oc,
      entra: Object.assign({}, ec, {
        inertByState: inertByState.reduce((a, r) => (a[r.state] = { n: r.n, names: r.names }, a), {}),
        inertEnabled: inertByState.filter((r) => r.state === 'enabled').reduce((a, r) => a + r.n, 0),
        snapshotAt: caFresh ? caFresh.at : null,
      }),
      parity: par.reduce((a, r) => (a[r.direction] = r.n, a), {}),
      mfaClaim: j(mfa && mfa.v, null),
      progress: {
        totalSteps,
        tracked: steps.tracked || 0,
        done: steps.done || 0,
        blocked: steps.blocked || 0,
        in_progress: steps.in_progress || 0,
        skipped: steps.skipped || 0,
        // Everything not in one of the four recorded states: rows still sitting at
        // not_started, plus every mapping that has no row at all.
        notStarted: Math.max(0, totalSteps - (steps.done || 0) - (steps.blocked || 0)
                     - (steps.in_progress || 0) - (steps.skipped || 0)),
        pct: totalSteps ? Math.round(100 * (steps.done || 0) / totalSteps) : 0,
      },
      capability: {
        known: cap.roles !== null,
        canWriteEntra: cap.roles === null ? null : cap.roles.includes('Policy.ReadWrite.ConditionalAccess'),
      },
    });
  } catch (e) { fail(res, e, 'overview'); }
});

/* ------------------------------------------------------------------- okta */

// GET /api/oem/okta/policies?type=
router.get('/okta/policies', read(), async (req, res) => {
  try {
    const args = [];
    let where = '1=1';
    if (req.query.type) { where += ' AND policy_type=?'; args.push(req.query.type); }
    const [rows] = await db.query(
      `SELECT policy_id, policy_type, name, description, status, priority, is_system,
              assignments, rule_count, app_count, app_names, shadowed_rules, collected_at
       FROM oem_okta_policy WHERE ${where}
       ORDER BY FIELD(policy_type,'OKTA_SIGN_ON','ACCESS_POLICY','MFA_ENROLL','PASSWORD',
                      'IDP_DISCOVERY','PROFILE_ENROLLMENT','USER_LIFECYCLE'),
                priority IS NULL, priority, name`, args);
    res.json(rows.map((r) => ({
      id: r.policy_id, type: r.policy_type, name: r.name, description: r.description,
      status: r.status, priority: r.priority, isSystem: !!r.is_system,
      assignments: j(r.assignments, {}), ruleCount: r.rule_count,
      appCount: r.app_count, appNames: j(r.app_names, []),
      shadowedRules: j(r.shadowed_rules, []), collectedAt: r.collected_at,
    })));
  } catch (e) { fail(res, e, 'okta/policies'); }
});

// GET /api/oem/okta/policies/:id — full rule detail
router.get('/okta/policies/:id', read(), async (req, res) => {
  try {
    const [[r]] = await db.query(`SELECT * FROM oem_okta_policy WHERE policy_id=?`, [req.params.id]);
    if (!r) return res.status(404).json({ error: 'not found' });
    res.json({
      id: r.policy_id, type: r.policy_type, name: r.name, description: r.description,
      status: r.status, priority: r.priority, isSystem: !!r.is_system,
      assignments: j(r.assignments, {}), rules: j(r.rules, []),
      appCount: r.app_count, appNames: j(r.app_names, []),
      shadowedRules: j(r.shadowed_rules, []), collectedAt: r.collected_at,
    });
  } catch (e) { fail(res, e, 'okta/policy detail'); }
});

// GET /api/oem/okta/zones
router.get('/okta/zones', read(), async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT zone_id, name, zone_type, status, usage_kind, referenced_by, entry_count,
              cidrs, countries, extras, collected_at FROM oem_okta_zone
       ORDER BY usage_kind, referenced_by DESC, name`);
    res.json(rows.map((r) => ({
      id: r.zone_id, name: r.name, type: r.zone_type, status: r.status,
      usage: r.usage_kind, referencedByPolicies: r.referenced_by,
      entryCount: r.entry_count, cidrs: j(r.cidrs, []), countries: j(r.countries, []),
      extras: j(r.extras, []), collectedAt: r.collected_at,
    })));
  } catch (e) { fail(res, e, 'okta/zones'); }
});

/* ------------------------------------------------------------------ entra */

// GET /api/oem/entra/policies
router.get('/entra/policies', read(), async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT * FROM oem_entra_ca ORDER BY FIELD(state,'enabled','enabledForReportingButNotEnforced','disabled'), display_name`);
    res.json(rows.map((r) => ({
      id: r.ca_id, name: r.display_name, state: r.state,
      conditions: j(r.conditions, {}), grantControls: j(r.grant_controls, {}),
      sessionControls: j(r.session_controls, {}),
      isInert: !!r.is_inert, inertReason: r.inert_reason, collectedAt: r.collected_at,
    })));
  } catch (e) { fail(res, e, 'entra/policies'); }
});

// GET /api/oem/entra/locations
router.get('/entra/locations', read(), async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT * FROM oem_entra_named_location ORDER BY loc_type, is_trusted DESC, display_name`);
    res.json(rows.map((r) => ({
      id: r.loc_id, name: r.display_name, type: r.loc_type,
      isTrusted: r.is_trusted === null ? null : !!r.is_trusted,
      cidrs: j(r.cidrs, []), countries: j(r.countries, []), collectedAt: r.collected_at,
    })));
  } catch (e) { fail(res, e, 'entra/locations'); }
});

/* ----------------------------------------------------------------- parity */

// GET /api/oem/parity?direction=
router.get('/parity', read(), async (req, res) => {
  try {
    const args = [];
    let where = '1=1';
    if (req.query.direction) { where += ' AND direction=?'; args.push(req.query.direction); }
    const [rows] = await db.query(
      `SELECT okta_zone, cidr, direction, kind, detail, entra_location, entra_trusted, is_sipa_anchor
       FROM oem_zone_parity WHERE ${where}
       ORDER BY FIELD(direction,'conflict','okta_only','unused','entra_only'),
                FIELD(kind,'block_trusted_in_entra','in_untrusted_location','no_entra_location','block_missing','zone_unused','entra_only'),
                okta_zone, cidr`, args);
    res.json(rows.map((r) => ({
      oktaZone: r.okta_zone, cidr: r.cidr, direction: r.direction, kind: r.kind,
      detail: r.detail, entraLocation: r.entra_location,
      entraTrusted: r.entra_trusted === null ? null : !!r.entra_trusted,
      isSipaAnchor: !!r.is_sipa_anchor,
    })));
  } catch (e) { fail(res, e, 'parity'); }
});

/* ------------------------------------------------------------------- sipa */

// GET /api/oem/sipa — live anchor facts plus the relay explanation and recommendation
/* ------------------------------------------------------------------ sipa */

let sipaLiveCache = { at: 0, v: null };
/** Live ZPA/ZIA read of the SIPA objects (5-minute cache). Ids stay strings end to end. */
async function sipaLive(force) {
  if (!force && sipaLiveCache.v && Date.now() - sipaLiveCache.at < 300000) return sipaLiveCache.v;
  const out = { checkedAt: new Date().toISOString(), ok: false, error: null, segments: null, serverGroups: null, gateways: null, gatewaysError: null };
  try {
    const { zpaAuth, ziaAuth, httpsRequest } = require('./zscaler-lookup');
    const base = 'https://api.zsapi.net/zpa/mgmtconfig/v1/admin/customers/' + process.env.ZPA_CUSTOMER_ID;
    const token = await zpaAuth();
    const getAll = async (resource) => {
      let page = 1, list = [];
      for (;;) {
        const r = await httpsRequest(new URL(`${base}/${resource}?page=${page}&pagesize=500`), { method: 'GET', headers: { Authorization: 'Bearer ' + token } });
        if (r.status !== 200) throw new Error(`ZPA ${resource} HTTP ${r.status}`);
        const l = (r.body && r.body.list) || [];
        list = list.concat(l);
        const total = parseInt((r.body && r.body.totalCount) || '0', 10);
        if (list.length >= total || !l.length || page > 20) break;
        page++;
      }
      return list;
    };
    const apps = await getAll('application');
    const sgs = await getAll('serverGroup');
    out.segments = apps.filter((a) => /sipa/i.test(a.name || '')).map((a) => ({
      id: String(a.id), name: a.name, destinations: a.domainNames || [], enabled: String(a.enabled) === 'true', modifiedTime: a.modifiedTime ? new Date(Number(a.modifiedTime) * 1000).toISOString() : null,
      serverGroups: (a.serverGroups || []).map((g) => ({ id: String(g.id), name: g.name })), segmentGroup: a.segmentGroupName || null }));
    out.serverGroups = sgs.map((g) => ({ id: String(g.id), name: g.name, enabled: String(g.enabled) === 'true', dynamicDiscovery: String(g.dynamicDiscovery) === 'true', connectorGroups: (g.appConnectorGroups || []).map((c) => ({ id: String(c.id), name: c.name })), applications: (g.applications || []).map((x) => ({ id: String(x.id), name: x.name })) }));
    try {
      let zt = await ziaAuth();
      let gw = await httpsRequest(new URL(process.env.ZIA_BASE_URL + '/zpaGateways'), { method: 'GET', headers: { Authorization: 'Bearer ' + zt } });
      if (gw.status === 401 || gw.status === 403) { zt = await ziaAuth(true); gw = await httpsRequest(new URL(process.env.ZIA_BASE_URL + '/zpaGateways'), { method: 'GET', headers: { Authorization: 'Bearer ' + zt } }); }
      if (gw.status !== 200) throw new Error('ZIA zpaGateways HTTP ' + gw.status);
      out.gateways = (gw.body || []).map((g) => ({ id: String(g.id), name: g.name, description: g.description || null, serverGroup: g.zpaServerGroup ? { id: String(g.zpaServerGroup.externalId || g.zpaServerGroup.id || ''), name: g.zpaServerGroup.name || null } : null, segments: (g.zpaAppSegments || []).map((x) => ({ id: String(x.externalId || x.id || ''), name: x.name })) }));
    } catch (e) { out.gatewaysError = e.message; }
    out.ok = true;
  } catch (e) { out.error = e.message; }
  sipaLiveCache = { at: Date.now(), v: out };
  return out;
}

// GET /api/oem/sipa?live=0|1  — live first, mirror as the fallback, every id a string
router.get('/sipa', read(), async (req, res) => {
  try {
    const [anchors] = await db.query(`SELECT * FROM oem_sipa_anchor ORDER BY site, ip`);
    const [mSegs] = await db.query(
      `SELECT a.id, a.name, a.domain_names, a.enabled, a.modified_time,
              GROUP_CONCAT(CONCAT(CAST(sg.id AS CHAR), '|', sg.name) ORDER BY sg.name SEPARATOR ';') sgs
         FROM zsnet_zpa_app a
         LEFT JOIN zsnet_zpa_app_sg x ON x.app_id=a.id
         LEFT JOIN zsnet_zpa_server_group sg ON sg.id=x.server_group_id
        WHERE a.name LIKE '%SIPA%' GROUP BY a.id, a.name, a.domain_names, a.enabled, a.modified_time ORDER BY a.name`).catch(() => [[]]);
    const [mGw] = await db.query(
      `SELECT g.id, g.name, g.description, CAST(g.zpa_server_group_ext_id AS CHAR) AS sg_id, sg.name AS sg_name,
              GROUP_CONCAT(CONCAT(CAST(s.app_segment_ext_id AS CHAR), '|', IFNULL(s.app_segment_name,'')) ORDER BY s.app_segment_name SEPARATOR ';') AS segments
         FROM zsnet_zia_zpa_gateway g
         LEFT JOIN zsnet_zia_gateway_app_segment s ON s.gateway_id=g.id
         LEFT JOIN zsnet_zpa_server_group sg ON sg.id=g.zpa_server_group_ext_id
        GROUP BY g.id, g.name, g.description, sg_id, sg_name ORDER BY g.name`).catch(() => [[]]);
    const [mSg] = await db.query(
      `SELECT CAST(sg.id AS CHAR) id, sg.name, sg.enabled,
              GROUP_CONCAT(cg.name ORDER BY cg.name SEPARATOR ';') cgs
         FROM zsnet_zpa_server_group sg
         LEFT JOIN zsnet_zpa_sg_cg e ON e.server_group_id=sg.id
         LEFT JOIN zsnet_zpa_connector_group cg ON cg.id=e.connector_group_id
        GROUP BY sg.id, sg.name, sg.enabled`).catch(() => [[]]);
    const [[sync]] = await db.query(
      `SELECT status, row_count, finished_at, error FROM zsnet_sync_log WHERE source='all' ORDER BY id DESC LIMIT 1`).catch(() => [[null]]);
    const [[connSync]] = await db.query(
      `SELECT finished_at FROM zsnet_sync_log WHERE (source='zpa_connector' OR source='all') AND status='ok' ORDER BY id DESC LIMIT 1`).catch(() => [[null]]);
    const live = req.query.live === '0' ? { ok: false, error: 'live read skipped (live=0)', checkedAt: null } : await sipaLive(req.query.live === '1');

    const mirrorSegments = mSegs.map((s) => ({ id: String(s.id), name: s.name, destinations: j(s.domain_names, []), enabled: !!s.enabled, modifiedTime: s.modified_time ? new Date(Number(s.modified_time) * 1000).toISOString() : null, serverGroups: String(s.sgs || '').split(';').filter(Boolean).map((x) => { const [id, name] = x.split('|'); return { id, name }; }), source: 'mirror' }));
    const mirrorGateways = mGw.map((g) => ({ id: String(g.id), name: g.name, description: g.description, serverGroup: g.sg_id ? { id: g.sg_id, name: g.sg_name } : null, segments: String(g.segments || '').split(';').filter(Boolean).map((x) => { const [id, name] = x.split('|'); return { id, name }; }), source: 'mirror' }));
    const segments = live.ok ? live.segments.map((x) => Object.assign(x, { source: 'live' })) : mirrorSegments;
    const gateways = live.ok && live.gateways ? live.gateways.map((x) => Object.assign(x, { source: 'live' })) : mirrorGateways;
    const sgSource = live.ok ? live.serverGroups : mSg.map((g) => ({ id: g.id, name: g.name, enabled: !!g.enabled, connectorGroups: String(g.cgs || '').split(';').filter(Boolean).map((n) => ({ name: n })) }));
    const referenced = new Set();
    for (const s of segments) for (const g of s.serverGroups || []) referenced.add(g.id);
    for (const g of gateways) if (g.serverGroup && g.serverGroup.id) referenced.add(g.serverGroup.id);
    const pinned = new Set(gateways.map((g) => g.serverGroup && g.serverGroup.id).filter(Boolean));
    const serverGroups = sgSource.filter((g) => referenced.has(g.id)).map((g) => ({
      id: g.id, name: g.name, enabled: g.enabled, dynamicDiscovery: g.dynamicDiscovery, connectorGroups: (g.connectorGroups || []).map((c) => c.name),
      role: pinned.has(g.id) ? 'Pinned by a SIPA gateway: this is the group whose connectors carry anchored traffic.' : 'Attached to a SIPA segment only: reachable for the segment, but not the group a ZIA gateway forwards through.',
      pinnedByGateway: pinned.has(g.id),
      source: live.ok ? 'live' : 'mirror',
    }));
    const reuse = segments.find((s) => /^SIPA - Okta$/i.test(s.name)) || null;
    const wanted = SIPA.RECOMMENDATION.addDestinations;
    const has = new Set((reuse ? reuse.destinations : []).map((d) => d.toLowerCase()));
    const gwFor = reuse ? gateways.find((g) => (g.segments || []).some((x) => x.name === reuse.name || x.id === reuse.id)) : null;
    const mirrorAgeDays = sync && sync.finished_at ? +((Date.now() - new Date(sync.finished_at)) / 86400000).toFixed(1) : null;
    const cautions = SIPA.RECOMMENDATION.cautions.slice();
    if (!live.ok) cautions.push(`Live Zscaler read failed (${live.error}); the segment and gateway facts above come from the mirror last synced ${sync && sync.finished_at ? new Date(sync.finished_at).toISOString().slice(0, 10) + ' (' + mirrorAgeDays + ' days ago)' : 'never'}. Confirm in the ZPA console before acting on them.`);
    else cautions.push('Segment, server-group and gateway facts above were read live from Zscaler at ' + live.checkedAt + '. Connector public addresses are not readable by this API client (Connector read is not granted); the anchor addresses were last confirmed ' + (connSync && connSync.finished_at ? new Date(connSync.finished_at).toISOString().slice(0, 10) : 'never') + ' and by reverse DNS.');

    res.json({
      anchors: anchors.map((a) => ({
        ip: a.ip, label: a.label, site: a.site, ptr: a.ptr, carrier: a.carrier,
        oktaZones: j(a.okta_zones, []), entraLocations: j(a.entra_locations, []),
        entraTrusted: a.entra_trusted === null ? null : !!a.entra_trusted,
        inZpaSegment: a.in_zpa_segment, connectorGroup: a.notes,
        lastConfirmed: connSync && connSync.finished_at ? connSync.finished_at : null,
      })),
      relayPath: SIPA.RELAY_PATH,
      segments, gateways, serverGroups,
      segmentToReuse: reuse ? {
        id: reuse.id, name: reuse.name, destinations: reuse.destinations, enabled: reuse.enabled, modifiedTime: reuse.modifiedTime, source: reuse.source,
        gateway: gwFor ? gwFor.name : null, gatewayId: gwFor ? gwFor.id : null, serverGroup: gwFor && gwFor.serverGroup ? gwFor.serverGroup.id : null,
        serverGroupsAttached: reuse.serverGroups, renameTo: SIPA.SEGMENT_TO_REUSE.renameTo,
        entraDestinationsPresent: wanted.filter((d) => has.has(d.toLowerCase())),
        entraDestinationsMissing: wanted.filter((d) => !has.has(d.toLowerCase())),
        oktaDestinationsStill: reuse.destinations.filter((d) => /okta\.com/i.test(d)),
      } : Object.assign({}, SIPA.SEGMENT_TO_REUSE, { source: 'authored fallback (segment not found in live or mirror)' }),
      namingConvention: SIPA.NAMING_CONVENTION,
      recommendation: Object.assign({}, SIPA.RECOMMENDATION, { cautions }),
      zscalerMirror: {
        lastSync: sync ? sync.finished_at : null,
        status: sync ? sync.status : 'unknown',
        ageDays: mirrorAgeDays,
        error: sync ? sync.error : null,
        note: 'The mirror is refreshed by the "Refresh the Zscaler mirror" job. Connector rows stay from the last read the API client was allowed to make.',
      },
      live: { checkedAt: live.checkedAt, ok: !!live.ok, error: live.error || null, gatewaysError: live.gatewaysError || null },
    });
  } catch (e) { fail(res, e, 'sipa'); }
});

/* --------------------------------------------------------------- mappings */

/** Resolve the Entra group object ids the payloads need, so nothing ships a placeholder. */
async function resolveGroups() {
  const names = ['SaaS-MFA-Exclusion', 'SaaS-OktaInternationalUsers', 'SaaS-OktaSessionTesters',
                 'SaaS-SFTP', 'SaaS-MFA-WarRoom', 'SaaS-MFA-TOTP', 'SaaS-MFA-Bypass', 'SaaS-MFA-Server'];
  const [rows] = await db.query(
    `SELECT g.display_name, g.entra_id, COUNT(m.member_id) AS members
     FROM entra_groups g LEFT JOIN entra_group_memberships m ON m.group_id=g.entra_id
     WHERE g.display_name IN (${names.map(() => '?').join(',')})
     GROUP BY g.display_name, g.entra_id`, names).catch(() => [[]]);
  const out = {};
  for (const r of rows) out[r.display_name] = { id: r.entra_id, members: r.members };
  return out;
}

/** Okta's headcount for the same group, from the policy assignment snapshot. */
async function oktaGroupCounts() {
  const out = {};
  // The collector resolves ?expand=stats for the compared groups and stores the
  // result here, which covers groups no policy references. The assignment
  // snapshot below is the fallback for anything the stats pass missed.
  const [[snap]] = await db.query(`SELECT v FROM oem_meta WHERE k='okta_group_counts'`);
  const s = j(snap && snap.v, null);
  if (s && s.counts) Object.assign(out, s.counts);
  const [rows] = await db.query(`SELECT assignments FROM oem_okta_policy`);
  for (const r of rows) {
    for (const g of (j(r.assignments, {}).groups || [])) {
      if (g.name && g.count != null && out[g.name] == null) out[g.name] = g.count;
    }
  }
  return out;
}

// GET /api/oem/mappings — the catalog, labelled against live capability
router.get('/mappings', read(), async (req, res) => {
  try {
    const cap = await liveRoles();
    const roles = cap.roles || [];
    const unknown = cap.roles === null;
    const [stateRows] = await db.query(`SELECT step_key, state, note, actor_email, updated_at FROM oem_step_status`);
    const stateBy = stateRows.reduce((a, r) => (a[r.step_key] = r, a), {});

    const out = MAPPINGS.map((m) => {
      const cls = classifyStep(m, roles);
      const st = stateBy[m.key];
      return {
        key: m.key, phase: m.phase, order: m.order, title: m.title,
        oktaObject: m.oktaObject, entraObject: m.entraObject,
        plain: m.plain, differences: m.differences || [],
        prerequisites: m.prerequisites || [],
        noEquivalentNote: m.noEquivalentNote || null,
        reviewReason: m.reviewReason || null,
        blockedBy: m.blockedBy || null,
        workClass: cls.cls,
        capabilityKnown: !unknown,
        actions: (m.actions || []).map((a, i) => {
          const c = cls.caps[i];
          return {
            id: a.id, label: a.label, declaredClass: a.cls,
            effectiveClass: unknown ? 'unknown' : c.cls,
            runnable: unknown ? null : c.runnable,
            downgraded: !!c.downgraded,
            missingScopes: c.missing, reason: unknown ? 'Credential could not be read, so availability is unknown.' : c.reason,
            creates: a.creates, why: a.why, verify: a.verify || null,
            manual: a.manual || null,
          };
        }),
        state: st ? st.state : 'not_started',
        note: st ? st.note : null,
        updatedBy: st ? st.actor_email : null,
        updatedAt: st ? st.updated_at : null,
      };
    }).sort((a, b) => a.order - b.order);

    res.json({ phases: PHASES, mappings: out,
      capability: { known: !unknown, canWriteEntra: unknown ? null : roles.includes('Policy.ReadWrite.ConditionalAccess') } });
  } catch (e) { fail(res, e, 'mappings'); }
});

/** Say why a push is not offered, from the live roles claim rather than a fixed sentence. */
function canPushReason(cap, what) {
  if (cap.roles === null) return 'The credential could not be read, so whether ' + what + ' is unknown. Paste the body into Graph Explorer signed in as an administrator, or build it in the portal.';
  if (cap.roles.includes('Policy.ReadWrite.ConditionalAccess')) return 'Policy.ReadWrite.ConditionalAccess is consented, but pushing from this page is not wired: no route applies Conditional Access bodies. Paste the body into Graph Explorer or build it in the portal.';
  return 'Policy.ReadWrite.ConditionalAccess is not consented to this credential (minimum permission; an Entra Global Administrator grants it on the IT-Command-IdentityDiag app registration), so ' + what + '. Paste the body into Graph Explorer signed in as an administrator, or build it in the portal.';
}
const isSharedEgress = require('./oem-discovery').isSharedEgress;

// GET /api/oem/mappings/:key/payload — the exact Graph body, with real object ids
router.get('/mappings/:key/payload', read(), async (req, res) => {
  try {
    const m = MAPPINGS.find((x) => x.key === req.params.key);
    if (!m) return res.status(404).json({ error: 'unknown mapping' });
    // The zone parity step produces a named location, not a Conditional Access
    // policy, and its contents come from the live diff rather than a literal.
    // zone-parity named location.
    if (m.key === 'zone-parity') {
      const [miss] = await db.query(
        `SELECT cidr, okta_zone FROM oem_zone_parity
          WHERE direction='okta_only' AND kind='no_entra_location' ORDER BY okta_zone, cidr`);
      const [untrusted] = await db.query(
        `SELECT cidr, entra_location FROM oem_zone_parity
          WHERE direction='okta_only' AND kind='in_untrusted_location' ORDER BY entra_location, cidr`);
      const CAP = 195; // Microsoft's documented ipRanges limit per named location
      const locs = [...new Set(untrusted.map((r) => r.entra_location))].join(', ');
      // Shared Zscaler cloud egress is reachable by every Zscaler customer. Trusting it in
      // Entra would trust the whole Zscaler cloud, so those ranges never enter the body;
      // they are reported beside it with the reason. Dedicated ranges (offices, the SIPA
      // anchors) are the only ones a trusted location may carry.
      const shared = miss.filter((r) => isSharedEgress(r.cidr));
      const dedicated = miss.filter((r) => !isSharedEgress(r.cidr));
      return res.json({
        key: m.key,
        method: 'POST',
        url: 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations',
        payload: dedicated.length ? {
          '@odata.type': '#microsoft.graph.ipNamedLocation',
          displayName: 'Okta OfficeIpZone parity',
          isTrusted: true,
          ipRanges: dedicated.map((r) => ({ '@odata.type': '#microsoft.graph.iPv4CidrRange', cidrAddress: r.cidr })),
        } : null,
        unresolved: [],
        overCap: dedicated.length > CAP,
        note: dedicated.length
          ? dedicated.length + ' dedicated ranges are trusted in Okta and sit in no Entra named location. This body creates one trusted '
            + 'location holding them. Ranges are kept at Okta\'s own entry boundaries so the two lists stay comparable.'
            + (dedicated.length > CAP ? ' This exceeds the ' + CAP + '-range limit for a single named location, so it has to be split.' : '')
          : (shared.length ? 'Every dedicated Okta range already exists in an Entra named location; only shared Zscaler egress is missing, and that must not be trusted. Nothing to create.'
                           : 'Every trusted Okta range already exists in an Entra named location. Nothing to create.'),
        alsoNeeded: untrusted.length
          ? untrusted.length + ' further ranges already exist in Entra but in a location with Mark as trusted switched off ('
            + locs + '). Those need the checkbox, not a new location.'
          : null,
        excludedSharedEgress: shared.map((r) => ({ cidr: r.cidr, oktaZone: r.okta_zone })),
        sharedEgressWarning: shared.length
          ? shared.length + ' Okta-trusted ranges are shared Zscaler cloud egress (any Zscaler customer can arrive from them) and were left out of this body. '
            + 'Trusting them in Entra would trust the whole Zscaler cloud. If Okta relies on them for a control, replace that control with device or SIPA-anchor conditions instead.'
          : null,
        namedLocationsUsed: [],
        canPush: false,
        canPushReason: canPushReason(await liveRoles(), 'this named location cannot be created from here'),
      });
    }
    if (!m.entraPayload) return res.json({ key: m.key, payload: null,
      note: m.noPayloadReason
        || 'This step has no single Conditional Access body to generate. Follow the manual instructions on the step.' });

    const groups = await resolveGroups();
    const [locs] = await db.query(`SELECT loc_id, display_name, is_trusted FROM oem_entra_named_location`);
    const locByName = locs.reduce((a, r) => (a[r.display_name] = r, a), {});

    const payload = JSON.parse(JSON.stringify(m.entraPayload));
    const unresolved = [];
    // Placeholders are resolved against live objects, and anything that cannot be resolved
    // is reported rather than shipped as a literal <angle-bracket> value.
    const walk = (o) => {
      if (Array.isArray(o)) return o.map(walk);
      if (o && typeof o === 'object') { for (const k of Object.keys(o)) o[k] = walk(o[k]); return o; }
      if (typeof o === 'string' && o.startsWith('<') && o.endsWith('>')) {
        const want = o.slice(1, -1);
        if (/BreakGlass/i.test(want)) { unresolved.push({ placeholder: o, why: 'No break-glass group exists yet. Create it first, then this resolves.' }); return o; }
        const g = Object.entries(groups).find(([n]) => want.includes(n));
        if (g) return g[1].id;
        unresolved.push({ placeholder: o, why: 'No live object matched this placeholder.' });
        return o;
      }
      return o;
    };
    walk(payload);

    res.json({
      key: m.key,
      // A step that edits a policy that already exists is a PATCH to that
      // object, not a create. Saying POST there would be wrong instructions.
      method: m.entraPayloadMethod || 'POST',
      url: m.entraPayloadUrl || 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies',
      payload,
      unresolved,
      resolvedGroups: groups,
      namedLocationsUsed: Object.entries(locByName)
        .filter(([, v]) => JSON.stringify(payload).includes(v.loc_id))
        .map(([n, v]) => ({ name: n, id: v.loc_id, isTrusted: v.is_trusted === null ? null : !!v.is_trusted })),
      canPush: false,
      canPushReason: canPushReason(await liveRoles(), 'this payload cannot be pushed from here'),
    });
  } catch (e) { fail(res, e, 'payload'); }
});

/* ----------------------------------------------------------------- impact */

// GET /api/oem/impact/country?days=30 — who a US-only block would have caught
router.get('/impact/country', read(), async (req, res) => {
  const days = Math.min(parseInt(req.query.days || '30', 10), 90);
  try {
    const [byCountry] = await db.query(
      `SELECT IFNULL(location_country,'(unknown)') AS country, COUNT(*) AS signins,
              COUNT(DISTINCT user_principal_name) AS users
       FROM entra_signin_logs
       WHERE created_at > NOW() - INTERVAL ? DAY AND outcome='SUCCESS'
         AND IFNULL(location_country,'') NOT IN ('US','')
       GROUP BY country ORDER BY signins DESC`, [days]);
    const [byUser] = await db.query(
      `SELECT user_principal_name AS upn, user_display_name AS name,
              GROUP_CONCAT(DISTINCT location_country ORDER BY location_country) AS countries,
              COUNT(*) AS signins
       FROM entra_signin_logs
       WHERE created_at > NOW() - INTERVAL ? DAY AND outcome='SUCCESS'
         AND IFNULL(location_country,'') NOT IN ('US','')
       GROUP BY upn, name ORDER BY signins DESC LIMIT 100`, [days]);

    // These succeed in Okta today because the International policy outranks the US-only one.
    const groups = await resolveGroups();
    const intl = groups['SaaS-OktaInternationalUsers'];
    let exempt = [];
    if (intl) {
      const upns = byUser.map((u) => u.upn).filter(Boolean);
      if (upns.length) {
        const [m] = await db.query(
          `SELECT DISTINCT u.user_principal_name AS upn FROM entra_group_memberships gm
           JOIN entra_users u ON u.entra_id = gm.member_id
           WHERE gm.group_id = ? AND u.user_principal_name IN (${upns.map(() => '?').join(',')})`,
          [intl.id, ...upns]).catch(() => [[]]);
        exempt = m.map((r) => r.upn);
      }
    }
    res.json({
      windowDays: days, byCountry, byUser,
      totals: { signins: byCountry.reduce((n, r) => n + r.signins, 0), users: byUser.length },
      oktaExemption: {
        group: 'SaaS-OktaInternationalUsers',
        entraGroupId: intl ? intl.id : null,
        entraMembers: intl ? intl.members : null,
        matchedInWindow: exempt.length,
        note: intl
          ? 'The Okta International Sign On Policy sits at priority 2, above the US-only DENY at priority 3, which is why these sign-ins succeed today. The Entra twin needs this group on the policy exclusion list, or the same users are blocked.'
          : 'The Okta international exemption group could not be resolved in Entra, so the exclusion list cannot be pre-filled.',
        unmatched: byUser.filter((u) => !exempt.includes(u.upn)).map((u) => u.upn),
      },
      caveat: 'The local sign-in mirror holds interactive sign-ins only, so service accounts and device flows are not counted here. Treat this as a floor, not the full blast radius.',
    });
  } catch (e) { fail(res, e, 'impact/country'); }
});

// GET /api/oem/impact/mfa-claim — the measured single vs multi factor split
router.get('/impact/mfa-claim', read(), async (req, res) => {
  try {
    const [[row]] = await db.query(`SELECT v, updated_at FROM oem_meta WHERE k='mfa_claim'`);
    const m = j(row && row.v, null);
    const [[regRow]] = await db.query(`SELECT v FROM oem_meta WHERE k='mfa_registration'`);
    const reg = j(regRow && regRow.v, null);
    res.json({
      measured: m,
      measuredAt: m ? m.measured_at : null,
      registration: reg,
      registrationNote: reg ? null : 'Registration coverage has not been sampled yet. It is collected from the Graph authentication-methods report on the next refresh.',
      source: 'Graph beta auditLogs/signIns, authenticationRequirement. The local mirror does not carry this field, so it is sampled live at collection time.',
      why: 'Entra only treats a sign-in as multi-factor if the federated token says so. Until that claim arrives, an MFA policy sees almost every sign-in as unmet and challenges the user a second time.',
    });
  } catch (e) { fail(res, e, 'impact/mfa-claim'); }
});

// GET /api/oem/impact/group-drift — Okta assignment vs the synced Entra group
router.get('/impact/group-drift', read(), async (req, res) => {
  try {
    const entra = await resolveGroups();
    const okta = await oktaGroupCounts();
    const rows = Object.keys(entra).map((name) => ({
      group: name,
      entraGroupId: entra[name].id,
      entraMembers: entra[name].members,
      oktaMembers: okta[name] != null ? okta[name] : null,
      drift: okta[name] != null ? entra[name].members - okta[name] : null,
    })).sort((a, b) => Math.abs(b.drift || 0) - Math.abs(a.drift || 0));
    const unmeasured = rows.filter((r) => r.oktaMembers === null).map((r) => r.group);
    res.json({
      rows,
      unmeasured,
      note: 'These groups already exist in Entra with object ids, so exclusion groups do not need creating. Where the counts differ, the exclusion carried into Entra would cover a different population than Okta exempts today.',
      oktaCountCaveat: unmeasured.length
        ? 'No Okta headcount was resolved for ' + unmeasured.join(', ') + '. Those rows are unmeasured, not in agreement.'
        : 'Okta headcounts come from a live ?expand=stats read at collection time.',
    });
  } catch (e) { fail(res, e, 'impact/group-drift'); }
});

/* -------------------------------------------------------- admin exposure */

/**
 * Break-glass accounts: looked for, not assumed absent. A break-glass account is a cloud-only
 * user whose name says so, or one excluded from every enabled Conditional Access policy.
 * The recorded designation (oem_meta break_glass) wins when a person has set it.
 */
async function breakGlassStatus() {
  const rec = await L.metaGet('break_glass', null);
  const [named] = await db.query(
    `SELECT entra_id, user_principal_name, display_name, account_enabled
       FROM entra_users WHERE user_type='Member' AND (display_name REGEXP 'break.?glass|emergency' OR user_principal_name REGEXP 'break.?glass|emergency')`).catch(() => [[]]);
  const [cas] = await db.query(`SELECT ca_id, display_name, conditions FROM oem_entra_ca WHERE state='enabled'`);
  const excludedEverywhere = [];
  if (cas.length) {
    const sets = cas.map((c) => new Set(((j(c.conditions, {}) || {}).users || {}).excludeUsers || []));
    const first = [...sets[0]];
    for (const id of first) if (sets.every((st) => st.has(id))) excludedEverywhere.push(id);
  }
  let excludedUsers = [];
  if (excludedEverywhere.length) {
    const [u] = await db.query(`SELECT entra_id, user_principal_name, display_name FROM entra_users WHERE entra_id IN (?)`, [excludedEverywhere]).catch(() => [[]]);
    excludedUsers = u;
  }
  const found = (rec.v && Array.isArray(rec.v.accounts) ? rec.v.accounts.length : 0) || named.length || excludedUsers.length;
  return {
    found,
    designated: rec.v ? rec.v.accounts : null,
    designatedBy: rec.v ? rec.v.by : null,
    namedCandidates: named.map((u) => ({ upn: u.user_principal_name, name: u.display_name, enabled: !!u.account_enabled })),
    excludedFromEveryEnabledPolicy: excludedUsers.map((u) => ({ upn: u.user_principal_name, name: u.display_name })),
    enabledPolicies: cas.length,
    note: found
      ? 'Candidates were found by name or by exclusion from every enabled policy. Confirm they are cloud-only, have a strong stored credential, and are excluded from every policy before enforcing anything.'
      : 'No account on this tenant is designated break-glass, none is named like one, and none is excluded from every enabled Conditional Access policy. Entra guidance is two cloud-only accounts excluded from every policy so a policy mistake cannot lock every administrator out. Creating them is a manual step (user creation is not granted to this credential).',
    checkedAt: new Date().toISOString(),
  };
}

// GET /api/oem/admin-exposure — who holds a privileged role, and how they authenticate
router.get('/admin-exposure', read(), async (req, res) => {
  try {
    const [byRole] = await db.query(
      `SELECT a.role_name,
              IFNULL(t.privilege_tier, 99) AS tier,
              COUNT(*) AS members,
              SUM(a.member_type='user') AS users,
              SUM(a.member_type='group') AS groups_assigned,
              SUM(a.eligibility='permanent') AS permanent,
              SUM(a.eligibility<>'permanent') AS eligible,
              SUM(a.assignment_type='direct') AS direct
       FROM priv_role_assignment a
       LEFT JOIN priv_role_tier t ON t.role_name = a.role_name
       GROUP BY a.role_name, tier
       ORDER BY tier, members DESC`);

    // Method strength for the distinct humans holding any privileged role. The
    // phishing-resistant set is what an admin-tier Conditional Access policy
    // would demand, so the gap between the two counts is the migration blocker.
    const STRONG = ['windowsHelloForBusiness', 'fido2', 'x509Certificate',
                    'microsoftAuthenticatorPasswordless', 'passKeyDeviceBound',
                    'passKeyDeviceBoundAuthenticator', 'passKeyDeviceBoundWindowsHello'];
    const [[tot]] = await db.query(
      `SELECT COUNT(DISTINCT member_entra_id) n FROM priv_role_assignment WHERE member_type='user'`);
    const [[withAny]] = await db.query(
      `SELECT COUNT(DISTINCT a.member_entra_id) n
       FROM priv_role_assignment a JOIN entra_auth_methods m ON m.user_id = a.member_entra_id
       WHERE a.member_type='user' AND m.method_type <> 'password'`);
    const [[withStrong]] = await db.query(
      `SELECT COUNT(DISTINCT a.member_entra_id) n
       FROM priv_role_assignment a JOIN entra_auth_methods m ON m.user_id = a.member_entra_id
       WHERE a.member_type='user' AND m.method_type IN (${STRONG.map(() => '?').join(',')})`, STRONG);
    const [methods] = await db.query(
      `SELECT m.method_type, COUNT(DISTINCT a.member_entra_id) n
       FROM priv_role_assignment a JOIN entra_auth_methods m ON m.user_id = a.member_entra_id
       WHERE a.member_type='user' GROUP BY m.method_type ORDER BY n DESC`);
    const [[fresh]] = await db.query(`SELECT MAX(collected_at) c FROM priv_role_assignment`);
    const [named] = await db.query(
      `SELECT a.role_name, IFNULL(t.privilege_tier,99) tier, u.user_principal_name upn, u.display_name name,
              a.eligibility, a.assignment_type,
              EXISTS(SELECT 1 FROM entra_auth_methods m WHERE m.user_id=a.member_entra_id
                     AND m.method_type IN (${STRONG.map(() => '?').join(',')})) AS phishing_resistant
       FROM priv_role_assignment a
       LEFT JOIN priv_role_tier t ON t.role_name=a.role_name
       LEFT JOIN entra_users u ON u.entra_id = a.member_entra_id
       WHERE a.member_type='user' AND IFNULL(t.privilege_tier,99) <= 1
       ORDER BY tier, a.role_name, upn`, STRONG);

    res.json({
      byRole,
      admins: {
        distinctUsers: tot.n,
        withAnySecondFactor: withAny.n,
        withPhishingResistant: withStrong.n,
        passwordOnly: tot.n - withAny.n,
      },
      methods,
      tier01: named.map((r) => Object.assign({}, r, { phishing_resistant: !!r.phishing_resistant })),
      breakGlass: await breakGlassStatus(),
      collectedAt: fresh ? fresh.c : null,
      source: 'priv_role_assignment and priv_role_tier, populated by the privileged-role collector, joined to entra_auth_methods.',
      caveat: 'Role assignments carried through a group are counted as one assignment, not as the group\'s member count. Tier 99 means the role is not in the privileged-role reference list.',
    });
  } catch (e) { fail(res, e, 'admin-exposure'); }
});

/* ------------------------------------------------------- device coverage */

// GET /api/oem/device-coverage — can a device-trust policy actually be enforced
router.get('/device-coverage', read(), async (req, res) => {
  try {
    const [byState] = await db.query(
      `SELECT IFNULL(compliance_state,'(unknown)') AS state, COUNT(*) n
       FROM sentinel_intune_device GROUP BY state ORDER BY n DESC`);
    const [byOs] = await db.query(
      `SELECT IFNULL(os,'(unknown)') AS os, COUNT(*) n,
              SUM(compliance_state='compliant') compliant,
              SUM(is_encrypted=1) encrypted
       FROM sentinel_intune_device GROUP BY os ORDER BY n DESC`);
    const [[tot]] = await db.query(`SELECT COUNT(*) devices, COUNT(DISTINCT upn) users FROM sentinel_intune_device`);
    const [[fresh]] = await db.query(`SELECT MAX(collected_at) c, MAX(last_sync_dt) s FROM sentinel_intune_device`);
    // The number that decides enforceability: enabled people with no enrolled device.
    const [[noDev]] = await db.query(
      `SELECT COUNT(*) n FROM entra_users u
       WHERE u.account_enabled=1 AND u.user_principal_name IS NOT NULL
         AND NOT EXISTS (SELECT 1 FROM sentinel_intune_device d WHERE d.upn = u.user_principal_name)`)
      .catch(() => [[{ n: null }]]);
    res.json({
      totals: tot,
      byState, byOs,
      usersWithoutDevice: noDev.n,
      collectedAt: fresh ? fresh.c : null,
      lastDeviceSync: fresh ? fresh.s : null,
      source: 'sentinel_intune_device, populated by the Intune collector.',
      caveat: 'A device with no matching enabled Entra user, and a user with two devices, both distort a simple headcount. Devices are matched to people by user principal name.',
    });
  } catch (e) { fail(res, e, 'device-coverage'); }
});

/* ------------------------------------------------------------------ steps */

// GET /api/oem/steps
router.get('/steps', read(), async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT step_key, state, note, actor_email, updated_at FROM oem_step_status ORDER BY step_key`);
    res.json(rows);
  } catch (e) { fail(res, e, 'steps'); }
});

// POST /api/oem/steps — retired 2026-09-10. The old page wrote its own completion
// state here; progress now lives on the work items (POST /api/oem/work/:key/state),
// which require evidence before an item can be called verified. The rows already in
// oem_step_status stay readable above as recorded history.
router.post('/steps', express.json(), admin(), (req, res) => {
  const key = req.body && req.body.stepKey ? String(req.body.stepKey) : '';
  res.status(410).json({
    error: 'Step states are no longer written here. Record progress on the work item instead.',
    useInstead: key ? `/api/oem/work/${encodeURIComponent('mapping:' + key)}/state` : '/api/oem/work/:key/state',
    history: '/api/oem/steps',
  });
});

/* ---------------------------------------------------------------- refresh */

// POST /api/oem/refresh — retired 2026-09-10 in favour of the persisted job runner,
// which records steps, prevents duplicate runs and survives a page refresh.
router.post('/refresh', express.json(), admin(), (req, res) => {
  res.status(410).json({ error: 'Use the job runner instead.', useInstead: '/api/oem/jobs/policy-snapshot', jobs: '/api/oem/jobs' });
});

/* ----------------------------------------------------------------- export */

// GET /api/oem/export — the dated policy snapshot (Okta policies/zones, Entra CA/named locations,
// parity, SIPA anchors, old-page step history). The page embeds it in the migration record
// it downloads from GET /api/oem/export/record.
router.get('/export', read(), async (req, res) => {
  try {
    const [okta] = await db.query(
      `SELECT policy_type, name, status, priority, rule_count, app_count, shadowed_rules FROM oem_okta_policy
       ORDER BY policy_type, priority IS NULL, priority`);
    const [zones] = await db.query(`SELECT name, zone_type, status, usage_kind, referenced_by, entry_count, cidrs FROM oem_okta_zone ORDER BY name`);
    const [ca] = await db.query(`SELECT display_name, state, is_inert, inert_reason FROM oem_entra_ca ORDER BY display_name`);
    const [locs] = await db.query(`SELECT display_name, loc_type, is_trusted, cidrs, countries FROM oem_entra_named_location ORDER BY display_name`);
    const [par] = await db.query(`SELECT okta_zone, cidr, direction, kind, entra_location, entra_trusted, is_sipa_anchor FROM oem_zone_parity ORDER BY direction, okta_zone, cidr`);
    const [anchors] = await db.query(`SELECT * FROM oem_sipa_anchor ORDER BY ip`);
    const [steps] = await db.query(`SELECT step_key, state, note, actor_email, updated_at FROM oem_step_status ORDER BY step_key`);
    const [[meta]] = await db.query(`SELECT v FROM oem_meta WHERE k='last_run'`);
    const [[mfa]] = await db.query(`SELECT v FROM oem_meta WHERE k='mfa_claim'`);
    const cap = await liveRoles();
    res.setHeader('Content-Disposition', `attachment; filename="okta-entra-migration-${new Date().toISOString().slice(0, 10)}.json"`);
    res.json({
      generatedAt: new Date().toISOString(),
      snapshot: j(meta && meta.v, null),
      capability: { roles: cap.roles, canWriteEntra: cap.roles ? cap.roles.includes('Policy.ReadWrite.ConditionalAccess') : null },
      mfaClaim: j(mfa && mfa.v, null),
      okta: { policies: okta.map((r) => Object.assign({}, r, { shadowed_rules: j(r.shadowed_rules, []) })), zones: zones.map((z) => Object.assign({}, z, { cidrs: j(z.cidrs, []) })) },
      entra: { policies: ca, namedLocations: locs.map((l) => Object.assign({}, l, { cidrs: j(l.cidrs, []), countries: j(l.countries, []) })) },
      parity: par,
      sipa: { anchors: anchors.map((a) => Object.assign({}, a, { okta_zones: j(a.okta_zones, []), entra_locations: j(a.entra_locations, []) })), recommendation: SIPA.RECOMMENDATION },
      mappings: MAPPINGS.map((m) => ({ key: m.key, phase: m.phase, title: m.title,
        okta: m.oktaObject, entra: m.entraObject, noEquivalent: m.noEquivalentNote || null })),
      steps,
    });
  } catch (e) { fail(res, e, 'export'); }
});

module.exports = router;
