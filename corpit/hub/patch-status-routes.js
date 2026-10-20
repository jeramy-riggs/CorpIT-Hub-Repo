// ─────────────────────────────────────────────────────────────────────────────
// patch-status-routes.js — Intune health (read only, except the update-ring editor). Started as Windows patch
// status; now the whole Intune estate plus the Entra device records beside it.
//
// Mount: app.use('/api/patch-status', require('./patch-status-routes'));
//
// ACCESS: super-admins, or an ACTIVE holder of the tier2 role (AD group
// SaaS-ITH-HD). Checked here on every request; hiding the page is not the
// control. Jeramy's call, 2026-10-13: "Super admins + SaaS-ITH-HD".
//
// SOURCE: Microsoft Graph, app-only, as the hub's ENTRA_* app
// (IT-Command-IdentityDiag). Build 5 (2026-10-14) reads, besides devices, Defender,
// malware, remote-action audits, Autopilot/enrollment events, endpoint analytics,
// the clean-up rule and Entra devices/users: update rings and their per-device
// results, compliance policies and which devices fail them, the Autopilot device
// list, deployment profiles, enrollment settings and app install status. Those need
// DeviceManagementConfiguration.Read.All, DeviceManagementServiceConfig.Read.All and
// DeviceManagementApps.Read.All, granted 2026-10-14. The roles in the app's token are
// reported to the page, so it says what is held instead of assuming.
//
// The app also holds write permissions. This route writes in one place only: the update
// ring editor (build 8, /rings/:id/save), a PATCH of one Windows Update ring and its /assign,
// super-admins only and audited. The Repair view (build 9, patch-status-repair.js) adds one more write, to
// ManageEngine, not Graph: a run of the pinned repair script on up to five PCs, also super-admins only and audited.
// Every other call is a GET, a Graph $batch whose sub-requests are all GETs, or a POST to a
// Graph *report* or getByIds (both read-only). On the dev server the outbound guard
// refuses the Intune report POSTs, so compliance (build 6) is read with GETs only;
// app install counts have no GET and still come from the report.
// No caller-chosen Graph paths. The parameters (/device/:id, /app/:id) must be GUIDs
// that are in the current snapshot.
//
// Autopilot device identities carry deviceAccountPassword and productKey; Graph
// will not $select on that collection, so they arrive and are dropped by an
// explicit field map. Never map them.
// ─────────────────────────────────────────────────────────────────────────────
'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');
const createRbac = require('./rbac-middleware');

const router = express.Router();

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT) || 3306,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  waitForConnections: true,
  connectionLimit: 2,
  charset: 'utf8mb4',
});
const rbac = createRbac(pool);
router.use(rbac.loadCurrentUser);

function allowed(u) {
  if (!u) return false;
  if (u.isSuperAdmin === true) return true;
  return u.isActive === true && Array.isArray(u.roles) && u.roles.indexOf('tier2') !== -1;
}
router.use(function (req, res, next) {
  if (!req.user) return res.status(401).json({ ok: false, error: 'AUTH_REQUIRED' });
  if (!allowed(req.user)) {
    return res.status(403).json({ ok: false, error: 'FORBIDDEN', detail: 'Intune health is limited to super-admins and SaaS-ITH-HD.' });
  }
  next();
});

// ── configuration ───────────────────────────────────────────────────────────
// BASELINE is the cumulative update every Windows device should be on. Update it
// when a new monthly update is approved. Only builds whose revision is known go
// here; the page never guesses which month an older revision belongs to.
const BASELINE = {
  revision: 9711,
  label: 'October 2026 cumulative update',
  released: '2026-10-13',
  builds: ['10.0.26300', '10.0.26200', '10.0.26100'],
};
// Update rings are read live from Intune (build 5); nothing about them is stated here.
// The Graph permissions this page uses. A ReadWrite grant also allows the read.
const NEEDED = ['DeviceManagementManagedDevices.Read.All', 'DeviceManagementConfiguration.Read.All', 'DeviceManagementServiceConfig.Read.All',
  'DeviceManagementApps.Read.All', 'Directory.Read.All'];
const CACHE_MS = 5 * 60 * 1000;     // a read is reused for five minutes
const MIN_FORCE_MS = 60 * 1000;     // Refresh cannot re-read more than once a minute
const TIMEOUT_MS = 25 * 1000;
const GRAPH = 'https://graph.microsoft.com';
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const STATE_REUSE_MS = 6 * 60 * 60 * 1000;   // longest a device's policy states are reused without a new check-in
const stateCache = new Map();                 // managed device id -> { sync, at, body }

// ── Graph access ────────────────────────────────────────────────────────────
let tok = null, tokP = null, tokRoles = null;
async function token() {
  if (tok && tok.exp - 60000 > Date.now()) return tok.value;
  if (!tokP) tokP = fetchToken().finally(function () { tokP = null; });
  return tokP;
}
async function fetchToken() {
  const ten = process.env.ENTRA_TENANT_ID, id = process.env.ENTRA_CLIENT_ID, sec = process.env.ENTRA_CLIENT_SECRET;
  if (!ten || !id || !sec) throw Object.assign(new Error('Graph app credentials are not configured on this server.'), { code: 'CONFIG' });
  const r = await fetch('https://login.microsoftonline.com/' + encodeURIComponent(ten) + '/oauth2/v2.0/token', {
    method: 'POST',
    body: new URLSearchParams({ client_id: id, client_secret: sec, scope: GRAPH + '/.default', grant_type: 'client_credentials' }),
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  const j = await r.json().catch(function () { return {}; });
  if (!r.ok || !j.access_token) throw Object.assign(new Error('Sign-in to Microsoft Graph failed (' + (j.error || r.status) + ').'), { code: 'TOKEN', http: r.status });
  tok = { value: j.access_token, exp: Date.now() + (Number(j.expires_in) || 3600) * 1000 };
  // The roles claim is what Graph will honour for this token; grants made after it was issued are not in it.
  try {
    const c = JSON.parse(Buffer.from(String(j.access_token).split('.')[1] || '', 'base64url').toString('utf8'));
    tokRoles = { at: Date.now(), roles: Array.isArray(c.roles) ? c.roles.filter(function (r) { return typeof r === 'string'; }) : [] };
  } catch (e) { tokRoles = null; }
  return tok.value;
}

// What the Sources view says when a read threw. On the dev server an outbound guard refuses
// any POST it does not list before it leaves the process; say so rather than blame Graph.
function whyFailed(e) {
  if (e && (e.code === 'CONFIG' || e.code === 'TOKEN')) return e.message;
  if (e && e.name === 'TimeoutError') return 'No answer within ' + (TIMEOUT_MS / 1000) + ' s';
  if (e && e.code === 'EDEVGUARD') return "Refused by this server's outbound guard; the request never reached Graph";
  return 'Graph read failed';
}
function bodyFail(e) { if (e && (e.name === 'TimeoutError' || e.name === 'AbortError')) throw e; return null; }
// One GET, retried up to three times while Intune throttles it (429) or Graph answers with a
// passing server error (502/503/504), each after its Retry-After (2 s if none; capped at 10 s,
// 20 s of waiting in all). The last answer is returned as it came.
const RETRY_HTTP = [429, 502, 503, 504];
async function getOnce(url, opt) {
  let r, waited = 0;
  for (let n = 0; ; n++) {
    r = await fetch(url, Object.assign({}, opt, { signal: AbortSignal.timeout(TIMEOUT_MS) }));
    if (RETRY_HTTP.indexOf(r.status) === -1 || n === 3) return r;
    const wait = Math.min(10, Number(r.headers.get('retry-after')) || 2);
    if (waited + wait > 20) return r;
    try { await r.arrayBuffer(); } catch (e) { /* the throttled answer is discarded */ }
    await new Promise(function (res) { setTimeout(res, wait * 1000); });
    waited += wait;
  }
}

// Reads every page of a fixed Graph collection. Returns a source record either way; its
// count stays null unless rows came back, so a failed read never shows as zero.
async function readAll(label, path) {
  const t0 = Date.now();
  const rec = { label: label, request: 'GET ' + path.split('?')[0], state: 'pending', http: null, ms: null, count: null, at: null, error: null };
  let items = [];
  try {
    const bearer = await token();
    let url = GRAPH + path, pages = 0;
    while (url && pages < 50) {
      const r = await getOnce(url, { headers: { Authorization: 'Bearer ' + bearer, Accept: 'application/json' } });
      rec.http = r.status;
      const j = await r.json().catch(bodyFail);
      if (!r.ok || !j) {
        rec.state = r.status === 401 || r.status === 403 ? 'denied' : 'error';
        rec.error = (j && j.error && j.error.code) || ('HTTP ' + r.status);
        rec.ms = Date.now() - t0; rec.at = Date.now();
        return { rec: rec, items: null };
      }
      items = items.concat(Array.isArray(j.value) ? j.value : []);
      url = j['@odata.nextLink'] || null;
      pages++;
    }
    rec.state = url ? 'partial' : 'ok';
    if (url) rec.error = 'Stopped after 50 pages';
  } catch (e) {
    rec.state = e && e.name === 'TimeoutError' ? 'timeout' : 'error';
    rec.error = whyFailed(e);
    rec.ms = Date.now() - t0; rec.at = Date.now();
    return { rec: rec, items: null };
  }
  rec.ms = Date.now() - t0; rec.at = Date.now(); rec.count = items.length;
  return { rec: rec, items: items };
}

function parseBuild(v) {
  const m = /^(\d+\.\d+\.\d+)\.(\d+)$/.exec(String(v || ''));
  return m ? { base: m[1], rev: Number(m[2]) } : { base: null, rev: null };
}

// ── snapshot ────────────────────────────────────────────────────────────────
let snap = null, inflight = null, lastTry = 0;

function ms(v) { const t = v ? Date.parse(v) : NaN; return isFinite(t) && t > 0 ? t : null; }
function nonZeroGuid(v) { return v && v !== '00000000-0000-0000-0000-000000000000' ? v : null; }

// Full objects, no $select: selecting windowsActiveMalwareCount silently drops
// devices that have not synced for 30 days (see intune-graph-api-traps).
function mapDevice(d) {
  const win = d.operatingSystem === 'Windows';
  const b = win ? parseBuild(d.osVersion) : { base: null, rev: null };
  const grace = ms(d.complianceGracePeriodExpirationDateTime);
  let lastLogon = null, lastLogonUserId = null, primaryLogon = null;
  const uid = nonZeroGuid(d.userId), who = new Set();
  (Array.isArray(d.usersLoggedOn) ? d.usersLoggedOn : []).forEach(function (u) {
    const t = ms(u.lastLogOnDateTime), id = nonZeroGuid(u.userId);
    if (id) who.add(id);
    if (t && (!lastLogon || t > lastLogon)) { lastLogon = t; lastLogonUserId = id; }
    if (t && id && id === uid && (!primaryLogon || t > primaryLogon)) primaryLogon = t;
  });
  return {
    id: d.id,
    name: d.deviceName || '',
    platform: d.operatingSystem || 'Unknown',
    os: d.osVersion || '',
    base: b.base, rev: b.rev,
    user: d.userPrincipalName || '',
    userName: d.userDisplayName || '',
    userId: uid,
    lastSync: ms(d.lastSyncDateTime),
    enrolled: ms(d.enrolledDateTime),
    lastLogon: lastLogon,
    lastLogonUserId: lastLogonUserId,
    primaryLogon: primaryLogon,         // the primary user's own latest sign-in (shared PCs)
    logonUsers: who.size,
    compliance: d.complianceState || 'unknown',
    graceUntil: grace && new Date(grace).getUTCFullYear() < 9000 ? grace : null,
    encrypted: typeof d.isEncrypted === 'boolean' ? d.isEncrypted : null,
    autopilot: d.autopilotEnrolled === true,
    enrollType: d.deviceEnrollmentType || '',
    join: d.joinType || '',
    owner: d.managedDeviceOwnerType || d.ownerType || '',
    model: [d.manufacturer, d.model].filter(Boolean).join(' '),
    serial: d.serialNumber || '',
    aad: nonZeroGuid(d.azureADDeviceId),
    category: d.deviceCategoryDisplayName && d.deviceCategoryDisplayName !== 'Unknown' ? d.deviceCategoryDisplayName : '',
    sku: d.skuFamily || '',
    totalB: Number(d.totalStorageSpaceInBytes) || null,   // 0 = not reported
    freeB: Number(d.freeStorageSpaceInBytes) || null,
    memB: Number(d.physicalMemoryInBytes) || 0,
    malware: Number(d.windowsActiveMalwareCount) || 0,
    certExp: ms(d.managementCertificateExpirationDate),
    patchLevel: d.androidSecurityPatchLevel || d.securityPatchLevel || '',
    ring: null,                         // set from the live rings in collect()
  };
}

function pickNumbers(o) {
  const out = {};
  Object.keys(o || {}).forEach(function (k) { if (typeof o[k] === 'number') out[k] = o[k]; });
  return out;
}

async function readOne(label, path, postBody) {
  // single-object reads share readAll's record shape. postBody is only for read-only
  // actions (directoryObjects/getByIds).
  const t0 = Date.now();
  const rec = { label: label, request: (postBody ? 'POST ' : 'GET ') + path.split('?')[0], state: 'pending', http: null, ms: null, count: null, at: null, error: null };
  try {
    const bearer = await token();
    const opt = { headers: { Authorization: 'Bearer ' + bearer, Accept: 'application/json' } };
    if (postBody) { opt.method = 'POST'; opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(postBody); }
    const r = postBody ? await fetch(GRAPH + path, Object.assign(opt, { signal: AbortSignal.timeout(TIMEOUT_MS) })) : await getOnce(GRAPH + path, opt);
    rec.http = r.status;
    const j = await r.json().catch(bodyFail);
    rec.ms = Date.now() - t0; rec.at = Date.now();
    if (!r.ok || !j) { rec.state = r.status === 401 || r.status === 403 ? 'denied' : 'error'; rec.error = (j && j.error && j.error.code) || ('HTTP ' + r.status); return { rec: rec, item: null }; }
    rec.state = 'ok'; rec.count = 1;
    return { rec: rec, item: j };
  } catch (e) {
    rec.state = e && e.name === 'TimeoutError' ? 'timeout' : 'error';
    rec.error = whyFailed(e);
    rec.ms = Date.now() - t0; rec.at = Date.now();
    return { rec: rec, item: null };
  }
}

// Intune report reads (POST /deviceManagement/reports/*, read-only). Answer shape:
// { Schema: [{ Column }], Values: [[...]], TotalRowCount }; rows come back keyed by column.
// Intune returns about 51 rows a page whatever top asks for, so after the first page the
// rest are read three at a time. Fewer rows than TotalRowCount is reported as partial.
const REPORT_PAGE = 500, REPORT_MAX = 5000, REPORT_PAR = 3;
async function readReport(label, path, filter) {
  const t0 = Date.now();
  const rec = { label: label, request: 'POST ' + path, state: 'pending', http: null, ms: null, count: null, at: null, error: null };
  function fail(state, error) { rec.state = state; rec.error = error; rec.ms = Date.now() - t0; rec.at = Date.now(); return { rec: rec, rows: null }; }
  try {
    const bearer = await token();
    const page = async function (skip) {
      const r = await fetch(GRAPH + path, { method: 'POST', signal: AbortSignal.timeout(TIMEOUT_MS),
        headers: { Authorization: 'Bearer ' + bearer, Accept: 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify({ select: [], filter: filter || '', top: REPORT_PAGE, skip: skip }) });
      const j = await r.json().catch(bodyFail);
      if (!r.ok || !j || !Array.isArray(j.Schema) || !Array.isArray(j.Values)) {
        throw Object.assign(new Error('report'), { report: true, http: r.status, code: (j && j.error && j.error.code) || ('HTTP ' + r.status) });
      }
      const cols = j.Schema.map(function (c) { return c && c.Column; });
      return { http: r.status, total: Number(j.TotalRowCount), rows: j.Values.map(function (v) { const o = {}; cols.forEach(function (c, i) { if (c) o[c] = v[i]; }); return o; }) };
    };
    const first = await page(0);
    rec.http = first.http;
    let rows = first.rows;
    const total = first.total, size = first.rows.length;
    const skips = [];
    if (size && isFinite(total)) for (let k = size; k < Math.min(total, REPORT_MAX); k += size) skips.push(k);
    const got = new Array(skips.length);
    let next = 0;
    await Promise.all(Array.from({ length: Math.min(REPORT_PAR, skips.length) }, async function () {
      while (next < skips.length) { const i = next++; got[i] = (await page(skips[i])).rows; }
    }));
    got.forEach(function (g) { rows = rows.concat(g); });
    rec.state = isFinite(total) && rows.length < total ? 'partial' : 'ok';
    if (rec.state === 'partial') rec.error = 'Read ' + rows.length + ' of ' + total + ' rows';
    rec.ms = Date.now() - t0; rec.at = Date.now(); rec.count = rows.length;
    return { rec: rec, rows: rows };
  } catch (e) {
    if (e && e.report) { rec.http = e.http; return fail(e.http === 401 || e.http === 403 ? 'denied' : 'error', e.code); }
    return fail(e && e.name === 'TimeoutError' ? 'timeout' : 'error',
      whyFailed(e));
  }
}
// Many single-object GETs sent as Graph $batch requests of 20 (every sub-request a GET), one
// batch at a time (Intune throttles per-device reads hard). Sub-requests Graph throttles (429) or
// fails in passing (502/503/504) are retried up to three more rounds, each after the longest Retry-After (capped at 10 s); anything
// still missing makes the source partial. Answer: Map(key -> body).
const BATCH_SIZE = 20, BATCH_PAR = 1, BATCH_RETRIES = 3;
async function readBatch(label, request, items) {
  const t0 = Date.now();
  const rec = { label: label, request: request, state: 'pending', http: null, ms: null, count: null, at: null, error: null };
  const out = new Map();
  let failed = 0, firstErr = null, denied = false;
  try {
    const bearer = await token();
    const send = async function (list) {
      const r = await fetch(GRAPH + '/beta/$batch', { method: 'POST', signal: AbortSignal.timeout(TIMEOUT_MS),
        headers: { Authorization: 'Bearer ' + bearer, Accept: 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify({ requests: list.map(function (x, i) { return { id: String(i), method: 'GET', url: x.url }; }) }) });
      rec.http = r.status;
      const j = await r.json().catch(bodyFail);
      if (!r.ok || !j || !Array.isArray(j.responses)) throw Object.assign(new Error('batch'), { batch: true, http: r.status, code: (j && j.error && j.error.code) || ('HTTP ' + r.status) });
      const retry = [];
      let wait = 0;
      j.responses.forEach(function (x) {
        const it = list[Number(x.id)];
        if (!it) return;
        if (x.status >= 200 && x.status < 300 && x.body) { out.set(it.key, x.body); return; }
        if (RETRY_HTTP.indexOf(x.status) !== -1 && (it.tries || 0) < BATCH_RETRIES) {
          retry.push(Object.assign({}, it, { tries: (it.tries || 0) + 1 }));
          wait = Math.max(wait, Math.min(10, Number(x.headers && (x.headers['Retry-After'] || x.headers['retry-after'])) || 2));
          return;
        }
        failed++;
        if (x.status === 401 || x.status === 403) denied = true;
        if (!firstErr) firstErr = (x.body && x.body.error && x.body.error.code) || ('HTTP ' + x.status);
      });
      if (retry.length) { await new Promise(function (res) { setTimeout(res, wait * 1000); }); await send(retry); }
    };
    const chunks = [];
    for (let i = 0; i < items.length; i += BATCH_SIZE) chunks.push(items.slice(i, i + BATCH_SIZE));
    let next = 0;
    await Promise.all(Array.from({ length: Math.min(BATCH_PAR, chunks.length) }, async function () {
      while (next < chunks.length) await send(chunks[next++]);
    }));
  } catch (e) {
    rec.state = e && e.name === 'TimeoutError' ? 'timeout' : e && e.batch && (e.http === 401 || e.http === 403) ? 'denied' : 'error';
    rec.error = e && e.batch ? e.code : whyFailed(e);
    if (e && e.batch) rec.http = e.http;
    rec.ms = Date.now() - t0; rec.at = Date.now();
    return { rec: rec, items: null };
  }
  rec.ms = Date.now() - t0; rec.at = Date.now(); rec.count = out.size;
  if (!failed) rec.state = 'ok';
  else if (out.size) { rec.state = 'partial'; rec.error = 'Read ' + out.size + ' of ' + items.length + ' (' + firstErr + ')'; }
  else { rec.state = denied ? 'denied' : 'error'; rec.error = firstErr; rec.count = null; }
  return { rec: rec, items: rec.count == null ? null : out };
}
// Several reads of one kind (one per ring, per policy, per group) reported as one source:
// the worst state wins, counts add up. No parts is a complete read of nothing, but only when
// the reads it depends on (parents) came back: a failed parent means the parts were never
// known, so the source is not read (no parts) or incomplete (some parts).
const STATE_RANK = { ok: 0, partial: 1, timeout: 2, error: 3, denied: 4 };
function combine(label, request, recs, parents) {
  recs = recs.filter(Boolean);
  const out = { label: label, request: request, state: 'ok', http: null, ms: 0, count: recs.length ? null : 0, at: Date.now(), error: null, parts: recs.length };
  recs.forEach(function (r) {
    if (r.count != null) out.count = (out.count || 0) + r.count;
    out.ms = Math.max(out.ms, r.ms || 0);
    if ((STATE_RANK[r.state] || 0) >= (STATE_RANK[out.state] || 0) && r.state !== 'ok') { out.state = r.state; out.http = r.http; out.error = r.error; }
    else if (out.http == null) out.http = r.http;
  });
  const lost = (parents || []).filter(function (p) { return !p || (p.state !== 'ok' && p.state !== 'partial'); });
  if (lost.length) {
    const names = lost.map(function (p) { return p ? p.label : 'an earlier read'; }).join(', ');
    if (!recs.length && lost.length === parents.length) { out.state = 'error'; out.error = 'Not read: ' + names + ' failed first'; out.count = null; }
    else if ((STATE_RANK[out.state] || 0) < STATE_RANK.partial) { out.state = 'partial'; out.error = 'Incomplete: ' + names + ' failed'; }
  }
  return out;
}
function tail(t) { return String(t || '').replace('#microsoft.graph.', ''); }
const TARGET_KIND = { groupAssignmentTarget: 'group', exclusionGroupAssignmentTarget: 'exclude', allDevicesAssignmentTarget: 'allDevices',
  allLicensedUsersAssignmentTarget: 'allUsers', configurationManagerCollectionAssignmentTarget: 'configMgr' };
// Assignment targets as stated by Intune. A filter is flagged, never evaluated.
function targetsOf(assignments) {
  return (Array.isArray(assignments) ? assignments : []).map(function (a) {
    const t = (a && a.target) || {}, type = tail(t['@odata.type']);
    return { kind: TARGET_KIND[type] || 'other', type: type, groupId: GUID.test(t.groupId || '') ? t.groupId : null,
      filter: !!(t.deviceAndAppManagementAssignmentFilterType && t.deviceAndAppManagementAssignmentFilterType !== 'none') };
  });
}
function num(v) { const x = Number(v); return isFinite(x) ? x : null; }
// Worst first: a device with two status rows for one ring (two users) shows the worse one.
const RING_STATUS_RANK = { error: 0, conflict: 1, nonCompliant: 2, unknown: 3, notAssigned: 4, notApplicable: 5, remediated: 6, compliant: 7 };

async function collect() {
  const P = [
    readAll('Intune managed devices', '/beta/deviceManagement/managedDevices?$top=999'),
    readAll('Entra devices', '/v1.0/devices?$select=id,deviceId,displayName,operatingSystem,trustType,approximateLastSignInDateTime,accountEnabled,registrationDateTime,isManaged,managementType&$top=999'),
    readOne('Defender overview', '/beta/deviceManagement/deviceProtectionOverview'),
    readOne('Malware overview', '/beta/deviceManagement/windowsMalwareOverview'),
    readAll('Malware detections', '/beta/deviceManagement/windowsMalwareInformation?$top=999'),
    readAll('Autopilot deployments', '/beta/deviceManagement/autopilotEvents?$top=100'),
    readAll('Enrollment failures', '/beta/deviceManagement/troubleshootingEvents?$top=100'),
    readAll('Remote actions', '/beta/deviceManagement/remoteActionAudits?$top=999'),
    readAll('Device clean-up rule', '/beta/deviceManagement/managedDeviceCleanupRules'),
    readAll('Endpoint analytics scores', '/beta/deviceManagement/userExperienceAnalyticsDeviceScores?$top=999'),
    readAll('Entra users', '/v1.0/users?$select=id,userPrincipalName,accountEnabled&$top=999'),
    readAll('Update rings', "/beta/deviceManagement/deviceConfigurations?$filter=isof('microsoft.graph.windowsUpdateForBusinessConfiguration')&$expand=assignments"),
    readAll('Compliance policies', '/beta/deviceManagement/deviceCompliancePolicies?$expand=assignments'),
    readOne('Compliance state summary', '/beta/deviceManagement/deviceCompliancePolicyDeviceStateSummary'),
    readAll('Compliance by setting', '/beta/deviceManagement/deviceCompliancePolicySettingStateSummaries'),
    readAll('Autopilot devices', '/beta/deviceManagement/windowsAutopilotDeviceIdentities?$top=999'),
    readAll('Autopilot profiles', '/beta/deviceManagement/windowsAutopilotDeploymentProfiles?$expand=assignments'),
    readAll('Enrollment settings', '/beta/deviceManagement/deviceEnrollmentConfigurations?$expand=assignments'),
    readReport('App install summary', '/beta/deviceManagement/reports/getAppsInstallSummaryReport', ''),
    readAll('Assigned apps', "/beta/deviceAppManagement/mobileApps?$filter=isAssigned eq true&$expand=assignments&$top=999"),
  ];
  // ── second pass: reads that need a first-pass answer, started as soon as it is back
  // (ring results and members, failing devices per policy, group names).
  let rings = [], ringGroups = [];
  const ringP = P[11].then(function (rg) {
    rings = (rg.items || []).filter(function (r) { return GUID.test(r.id || ''); });
    rings.forEach(function (r) { r._targets = targetsOf(r.assignments); });
    rings.forEach(function (r) { r._targets.forEach(function (t) { if (t.groupId && ringGroups.indexOf(t.groupId) === -1) ringGroups.push(t.groupId); }); });
    return Promise.all([
      Promise.all(rings.map(function (r) { return readAll('Ring results', '/beta/deviceManagement/deviceConfigurations/' + r.id + '/deviceStatuses?$top=999'); })),
      Promise.all(ringGroups.map(function (id) { return readAll('Ring group members', '/v1.0/groups/' + id + '/transitiveMembers?$select=id,deviceId&$top=999'); })),
    ]);
  });
  // Compliance without Intune's report API (the dev server's outbound guard refuses those POSTs):
  // every listed policy's per-device results; the policy states of each device not reporting
  // compliant (the only GET that names the built-in Default Device Compliance Policy); and, for
  // each setting with a failing device, which devices fail it.
  let polList = [], setIds = [];
  const polP = P[12].then(function (cp) {
    polList = (cp.items || []).filter(function (p) { return GUID.test(p.id || ''); }).map(function (p) { return p.id; });
    return Promise.all(polList.map(function (id) { return readAll('Policy device results', '/beta/deviceManagement/deviceCompliancePolicies/' + id + '/deviceStatuses?$top=999'); }));
  });
  // A device's policy states change when it checks in, so an answer is reused while the device's
  // last check-in is unchanged (at most STATE_REUSE_MS); only the rest are read again.
  let stateIds = [], stateReused = 0;
  const dsP = P[0].then(async function (dv) {
    if (!dv.items) return null;
    const want = dv.items.filter(function (d) { return GUID.test(d.id || '') && d.complianceState !== 'compliant'; });
    stateIds = want.map(function (d) { return d.id; });
    const now = Date.now(), have = new Map(), need = [];
    want.forEach(function (d) {
      const c = stateCache.get(d.id), sync = ms(d.lastSyncDateTime);
      if (c && c.sync === sync && now - c.at < STATE_REUSE_MS) have.set(d.id, c.body); else need.push({ id: d.id, sync: sync, grace: d.complianceState === 'inGracePeriod' });
    });
    // When Intune throttles part of the read, the devices left out should be the ones still in grace.
    need.sort(function (a, b) { return a.grace - b.grace; });
    const r = await readBatch('Policy states per device', 'GET /beta/deviceManagement/managedDevices/{device}/deviceCompliancePolicyStates (in $batch)',
      need.map(function (x) { return { key: x.id, url: '/deviceManagement/managedDevices/' + x.id + '/deviceCompliancePolicyStates' }; }));
    need.forEach(function (x) { const b = r.items && r.items.get(x.id); if (b) stateCache.set(x.id, { sync: x.sync, at: now, body: b }); });
    stateCache.forEach(function (v, id) { if (now - v.at >= STATE_REUSE_MS) stateCache.delete(id); });
    stateReused = have.size;
    if (!have.size) return r;
    const all = new Map(have);
    if (r.items) r.items.forEach(function (b, id) { all.set(id, b); });
    r.rec.count = all.size;
    r.rec.reused = have.size;
    if (r.rec.state !== 'ok') {
      const why = r.rec.state === 'partial' ? String(r.rec.error || '').replace(/^Read \d+ of \d+ \((.*)\)$/, '$1') : r.rec.error;
      r.rec.state = 'partial';
      r.rec.error = 'Read ' + all.size + ' of ' + want.length + ' (' + have.size + ' reused from an earlier read, no check-in since; ' + why + ')';
    }
    return { rec: r.rec, items: all.size ? all : null };
  });
  const setP = P[14].then(function (ss) {
    (ss.items || []).forEach(function (x) {
      if (x.id && /^[A-Za-z0-9_.-]+$/.test(x.id) && (num(x.nonCompliantDeviceCount) || 0) + (num(x.errorDeviceCount) || 0) + (num(x.conflictDeviceCount) || 0) > 0 && setIds.indexOf(x.id) === -1) setIds.push(x.id);
    });
    return Promise.all(setIds.map(function (id) { return readAll('Failing devices per setting', '/beta/deviceManagement/deviceCompliancePolicySettingStateSummaries/' + encodeURIComponent(id) + '/deviceComplianceSettingStates?$top=999'); }));
  });
  const gnP = Promise.all([P[11], P[12], P[16], P[17], P[19]]).then(function (L) {
    const ids = [];
    L.forEach(function (x) { (x.items || []).forEach(function (o) { targetsOf(o.assignments).forEach(function (t) { if (t.groupId && ids.indexOf(t.groupId) === -1) ids.push(t.groupId); }); }); });
    return ids.length ? readOne('Group names', '/v1.0/directoryObjects/getByIds', { ids: ids.slice(0, 1000), types: ['group'] }) : null;
  });
  const R = await Promise.all(P);
  const S = await Promise.all([ringP, polP, gnP, dsP, setP]);
  const dev = R[0], entra = R[1], prot = R[2], mwo = R[3], mw = R[4], ap = R[5], te = R[6], ra = R[7], cr = R[8], ux = R[9], us = R[10];
  const rg = R[11], cp = R[12], csum = R[13], ss = R[14], ad = R[15], apf = R[16], ec = R[17], apps = R[18], inv = R[19];

  const ringStatus = S[0][0], ringMembers = S[0][1], polStatus = S[1], gn = S[2], devStates = S[3], setStates = S[4];

  const devices = (dev.items || []).map(mapDevice);
  const byId = new Map(devices.map(function (d) { return [d.id, d]; }));
  // Account state of the primary user and of whoever signed in last. Null means
  // unknown (the user read failed), never "fine". 'missing' = not in the directory,
  // i.e. deleted (or more than 30 days ago, purged).
  // A partial user list would mark real people "not in directory", so only a complete read counts.
  const users = us.items && us.rec.state === 'ok' ? new Map(us.items.map(function (u) { return [u.id, u]; })) : null;
  function acct(id) { if (!id || !users) return null; const u = users.get(id); return !u ? 'missing' : u.accountEnabled === false ? 'disabled' : 'active'; }
  devices.forEach(function (d) {
    d.userState = acct(d.userId);
    const lu = d.lastLogonUserId && users ? users.get(d.lastLogonUserId) : null;
    d.lastLogonUser = lu ? lu.userPrincipalName || '' : null;
    d.lastLogonUserState = acct(d.lastLogonUserId);
  });
  us.rec.count = us.items ? us.items.length : null;

  // ── update rings ──────────────────────────────────────────────────────────
  // Membership: a Windows device is in a ring when its Intune primary user, or the
  // device itself, is in an assigned group and in no excluded group (all devices
  // counts every Windows device). Any target the hub cannot evaluate (all users,
  // an assignment filter, an unreadable group) makes membership unknown for every
  // device, because a device outside one ring could then be in it.
  const members = new Map();
  ringGroups.forEach(function (id, i) {
    const m = ringMembers[i];
    if (!m.items || m.rec.state !== 'ok') { members.set(id, null); return; }
    const u = new Set(), dv = new Set();
    m.items.forEach(function (x) { const t = tail(x['@odata.type']); if (t === 'user') u.add(x.id); else if (t === 'device' && x.deviceId) dv.add(x.deviceId); });
    members.set(id, { users: u, devices: dv });
  });
  function inGroup(g, d) { return !!g && ((!!d.userId && g.users.has(d.userId)) || (!!d.aad && g.devices.has(d.aad))); }
  const wins = devices.filter(function (d) { return d.platform === 'Windows'; });
  const ringOut = rings.map(function (r, i) {
    const T = r._targets, inc = T.filter(function (t) { return t.kind === 'group' || t.kind === 'allDevices'; }), exc = T.filter(function (t) { return t.kind === 'exclude'; });
    let why = null;
    T.forEach(function (t) {
      if (why) return;
      if (t.filter) why = 'An assignment filter applies; the hub does not evaluate filters.';
      else if (t.kind === 'allUsers') why = 'Assigned to all users; the hub cannot tell which devices that reaches.';
      else if (t.kind === 'other' || t.kind === 'configMgr') why = 'Assigned to a target type the hub does not evaluate (' + t.type + ').';
      else if (t.groupId && !members.get(t.groupId)) why = 'An assigned group’s members could not be read.';
    });
    const test = why ? null : function (d) {
      const yes = inc.some(function (t) { return t.kind === 'allDevices' || inGroup(members.get(t.groupId), d); });
      return yes && !exc.some(function (t) { return inGroup(members.get(t.groupId), d); });
    };
    // Per-device results Intune holds for this ring. Row id is <x>_<y>_<managedDeviceId>.
    const st = ringStatus[i], per = new Map();
    (st.items || []).forEach(function (x) {
      const id = String(x.id || '').split('_').pop(), at = ms(x.lastReportedDateTime), s = x.status || 'unknown';
      if (!GUID.test(id)) return;
      const prev = per.get(id);
      if (!prev || (RING_STATUS_RANK[s] != null ? RING_STATUS_RANK[s] : 3) < (RING_STATUS_RANK[prev.status] != null ? RING_STATUS_RANK[prev.status] : 3)) per.set(id, { status: s, at: at });
      else if (at && (!prev.at || at > prev.at) && prev.status === s) prev.at = at;
    });
    const counts = {};
    per.forEach(function (v, id) { counts[v.status] = (counts[v.status] || 0) + 1; const d = byId.get(id); if (d) (d.ringResults = d.ringResults || []).push([r.id, v.status, v.at]); });
    const q = { deferral: num(r.qualityUpdatesDeferralPeriodInDays), deadline: num(r.deadlineForQualityUpdatesInDays), paused: r.qualityUpdatesPaused === true,
      pauseUntil: ms(r.qualityUpdatesPauseExpiryDateTime) };
    const f = { deferral: num(r.featureUpdatesDeferralPeriodInDays), deadline: num(r.deadlineForFeatureUpdatesInDays), paused: r.featureUpdatesPaused === true,
      pauseUntil: ms(r.featureUpdatesPauseExpiryDateTime) };
    return { id: r.id, name: r.displayName || 'Unnamed ring', modified: ms(r.lastModifiedDateTime),
      targets: T.map(function (t) { return { kind: t.kind, groupId: t.groupId, filter: t.filter }; }), assigned: T.some(function (t) { return t.kind !== 'exclude'; }),
      scopeWhy: why, _test: test,
      deferralDays: q.deferral, deadlineDays: q.deadline, graceDays: num(r.deadlineGracePeriodInDays), quality: q, feature: f,
      restartAfterDeadlineOnly: r.postponeRebootUntilAfterDeadline === true, installMode: r.automaticUpdateMode || '',
      results: st.items && st.rec.state === 'ok' ? counts : null, reported: st.items && st.rec.state === 'ok' ? per.size : null };
  }).sort(function (a, b) { return ((a.deferralDays == null ? 99 : a.deferralDays) - (b.deferralDays == null ? 99 : b.deferralDays)) || a.name.localeCompare(b.name); });
  const ringsKnown = !!rg.items && rg.rec.state === 'ok' && ringOut.every(function (r) { return !!r._test; });
  wins.forEach(function (d) {
    if (!ringsKnown) { d.ring = null; return; }
    const hit = ringOut.filter(function (r) { return r._test(d); }).map(function (r) { return r.id; });
    d.rings = hit;
    d.ring = !hit.length ? 'none' : hit.length === 1 ? hit[0] : 'multi';
  });
  ringOut.forEach(function (r) {
    r.members = r._test ? wins.filter(function (d) { return r._test(d); }).length : null;
    delete r._test;
  });

  // ── compliance ────────────────────────────────────────────────────────────
  // Policy states, worst first. A device can hold one row per user for a policy; the worse one counts.
  const POL_RANK = { error: 0, conflict: 1, nonCompliant: 2, inGracePeriod: 3, unknown: 4, notAssigned: 5, notApplicable: 6, remediated: 7, compliant: 8 };
  const POL_LABEL = { error: 'Error', conflict: 'Conflict', nonCompliant: 'Not compliant', inGracePeriod: 'In grace period', unknown: 'Unknown' };
  function polRank(s) { return POL_RANK[s] != null ? POL_RANK[s] : 4; }
  function polFails(s) { return s === 'nonCompliant' || s === 'error' || s === 'conflict'; }
  function addFail(d, pid, st) {
    if (!d || !polFails(st)) return;
    const L = d.failing = d.failing || [];
    if (!L.some(function (x) { return x[0] === pid; })) L.push([pid, POL_LABEL[st] || st]);
  }
  function tally(per) {
    const c = { compliant: 0, nonCompliant: 0, error: 0, conflict: 0, notApplicable: 0 };
    per.forEach(function (st) { if (st === 'remediated') c.compliant++; else if (c[st] != null) c[st]++; });
    return c;
  }
  // Listed policies: per-device results. Row id is <x>_<policyId>_<managedDeviceId>.
  const polCounts = new Map();
  polList.forEach(function (pid, i) {
    const r = polStatus[i];
    if (!r.items || r.rec.state !== 'ok') { polCounts.set(pid, null); return; }
    const per = new Map();
    r.items.forEach(function (x) {
      const id = String(x.id || '').split('_').pop(), st = x.status || 'unknown';
      if (!GUID.test(id) || !byId.has(id)) return;          // devices no longer in Intune keep stale rows
      if (!per.has(id) || polRank(st) < polRank(per.get(id))) per.set(id, st);
    });
    per.forEach(function (st, id) { addFail(byId.get(id), pid, st); });
    polCounts.set(pid, tally(per));
  });
  const policies = (cp.items || []).map(function (p) {
    return { id: p.id, name: p.displayName || 'Unnamed policy', type: tail(p['@odata.type']), modified: ms(p.lastModifiedDateTime),
      targets: targetsOf(p.assignments).map(function (t) { return { kind: t.kind, groupId: t.groupId, filter: t.filter }; }), counts: polCounts.get(p.id) || null };
  });
  // Per-device policy states (devices not reporting compliant only). This is where policies the
  // policy list does not hold appear: Microsoft's built-in Default Device Compliance Policy (its
  // fixed name), and anything else Intune applies (unlisted). Their counts cover only the devices read,
  // so they have no compliant count.
  const extra = new Map();
  if (devStates && devStates.items) devStates.items.forEach(function (body, id) {
    const d = byId.get(id), per = new Map();
    (Array.isArray(body.value) ? body.value : []).forEach(function (x) {
      if (!GUID.test(x.id || '')) return;
      if (!per.has(x.id) || polRank(x.state) < polRank(per.get(x.id).state)) per.set(x.id, { state: x.state || 'unknown', name: x.displayName || '' });
    });
    // Kept for the drawer, so opening a device does not re-read what the snapshot already holds
    // (Intune throttles this call). [policy id, name, state]
    if (d) d.polStates = Array.from(per.entries()).map(function (e) { return [e[0], e[1].name, e[1].state]; });
    per.forEach(function (v, pid) {
      addFail(d, pid, v.state);
      if (polList.indexOf(pid) !== -1) return;
      const e = extra.get(pid) || { name: v.name, per: new Map() };
      e.per.set(id, v.state);
      extra.set(pid, e);
    });
  });
  const statesOk = !!devStates && devStates.rec.state === 'ok';
  extra.forEach(function (e, pid) {
    const c = tally(e.per);
    policies.push({ id: pid, name: e.name || 'Unnamed policy', type: '', builtIn: e.name === 'Default Device Compliance Policy', unlisted: true, modified: null, targets: null,
      counts: { compliant: null, nonCompliant: c.nonCompliant, error: c.error, conflict: c.conflict, notApplicable: null }, partialCounts: !statesOk });
  });
  // Failing settings per device, from the per-setting summaries (not tied to a policy).
  const setOk = setStates.every(function (r) { return r.rec.state === 'ok'; });
  setIds.forEach(function (sid, i) {
    (setStates[i].items || []).forEach(function (x) {
      const d = byId.get(x.deviceId);
      if (!d || !polFails(x.state)) return;
      const L = d.failSettings = d.failSettings || [], nm = x.settingName || x.setting || sid;
      if (!L.some(function (y) { return y[0] === nm; })) L.push([nm, POL_LABEL[x.state] || x.state]);
    });
  });
  const failOk = !!cp.items && cp.rec.state === 'ok' && polStatus.every(function (r) { return r.rec.state === 'ok'; }) && statesOk;
  const stateSum = csum.item ? { compliant: num(csum.item.compliantDeviceCount), nonCompliant: num(csum.item.nonCompliantDeviceCount), grace: num(csum.item.inGracePeriodCount),
    error: num(csum.item.errorDeviceCount), conflict: num(csum.item.conflictDeviceCount), unknown: num(csum.item.unknownDeviceCount), notApplicable: num(csum.item.notApplicableDeviceCount),
    remediated: num(csum.item.remediatedDeviceCount), configManager: num(csum.item.configManagerCount) } : null;
  const settings = (ss.items || []).map(function (x) {
    return { setting: x.settingName || x.setting || '', platform: x.platformType || '', nonCompliant: num(x.nonCompliantDeviceCount) || 0, error: num(x.errorDeviceCount) || 0,
      conflict: num(x.conflictDeviceCount) || 0, compliant: num(x.compliantDeviceCount) || 0, remediated: num(x.remediatedDeviceCount) || 0,
      notApplicable: num(x.notApplicableDeviceCount) || 0, unknown: num(x.unknownDeviceCount) || 0 };
  });

  // ── Autopilot device list: explicit fields only (never deviceAccountPassword or productKey) ──
  const apDevices = ad.items ? ad.items.map(function (a) {
    return { id: a.id, serial: a.serialNumber || '', make: a.manufacturer || '', model: a.model || '', state: a.enrollmentState || '',
      lastContact: ms(a.lastContactedDateTime), intuneId: nonZeroGuid(a.managedDeviceId), aad: nonZeroGuid(a.azureActiveDirectoryDeviceId),
      tag: a.groupTag || '', profile: a.deploymentProfileAssignmentStatus || '', profileAt: ms(a.deploymentProfileAssignedDateTime),
      user: a.userPrincipalName || '', name: a.displayName || '' };
  }) : null;
  ad.items = null;
  const apProfiles = apf.items ? apf.items.map(function (x) {
    return { id: x.id, name: x.displayName || 'Unnamed profile', type: tail(x['@odata.type']), modified: ms(x.lastModifiedDateTime),
      nameTemplate: x.deviceNameTemplate || '', preprovision: x.preprovisioningAllowed === true || x.enableWhiteGlove === true,
      targets: targetsOf(x.assignments).map(function (t) { return { kind: t.kind, groupId: t.groupId, filter: t.filter }; }) };
  }) : null;
  const enrollConfigs = ec.items ? ec.items.map(function (x) {
    return { id: x.id, name: x.displayName || 'Unnamed', type: x.deviceEnrollmentConfigurationType || tail(x['@odata.type']), kind: tail(x['@odata.type']),
      priority: num(x.priority), modified: ms(x.lastModifiedDateTime), limit: num(x.limit),
      targets: targetsOf(x.assignments).map(function (t) { return { kind: t.kind, groupId: t.groupId, filter: t.filter }; }) };
  }).sort(function (a, b) { return (b.priority || 0) - (a.priority || 0) || a.name.localeCompare(b.name); }) : null;

  // ── apps ──────────────────────────────────────────────────────────────────
  // Install counts come only from Intune's report (refused by the dev guard); the assigned-app list
  // and its assignments are plain GETs. With no report the list still shows, with no counts.
  const invBy = new Map((inv.items || []).filter(function (x) { return GUID.test(x.id || ''); }).map(function (x) { return [x.id, x]; }));
  function appTargets(x) {
    return x && Array.isArray(x.assignments) ? targetsOf(x.assignments).map(function (t, i) {
      return { kind: t.kind, groupId: t.groupId, filter: t.filter, intent: String(x.assignments[i].intent || '') };
    }) : null;
  }
  const appList = apps.rows ? apps.rows.filter(function (x) { return GUID.test(x.ApplicationId || ''); }).map(function (x) {
    return { id: x.ApplicationId, name: x.DisplayName || 'Unnamed app', publisher: x.Publisher || '', platform: x.Platform_loc || x.Platform || '', version: x.AppVersion || '',
      type: invBy.has(x.ApplicationId) ? tail(invBy.get(x.ApplicationId)['@odata.type']) : '', targets: appTargets(invBy.get(x.ApplicationId)),
      installed: num(x.InstalledDeviceCount) || 0, failed: num(x.FailedDeviceCount) || 0, pending: num(x.PendingInstallDeviceCount) || 0,
      notInstalled: num(x.NotInstalledDeviceCount) || 0, notApplicable: num(x.NotApplicableDeviceCount) || 0, failedUsers: num(x.FailedUserCount) || 0 };
  }) : inv.items ? Array.from(invBy.values()).map(function (x) {
    return { id: x.id, name: x.displayName || 'Unnamed app', publisher: x.publisher || '', platform: '', version: typeof x.displayVersion === 'string' ? x.displayVersion : '',
      type: tail(x['@odata.type']), targets: appTargets(x), installed: null, failed: null, pending: null, notInstalled: null, notApplicable: null, failedUsers: null };
  }) : null;
  inv.items = null;

  const groups = {};
  if (gn && gn.item && Array.isArray(gn.item.value)) gn.item.value.forEach(function (g) { if (g && g.id) groups[g.id] = g.displayName || ''; });

  const rule = cr.items && cr.items[0] ? cr.items[0] : null;
  const p = prot.item, m = mwo.item;
  const roles = tokRoles ? tokRoles.roles : null;
  return {
    at: Date.now(),
    baseline: BASELINE,
    rings: ringOut,
    ringsKnown: ringsKnown,
    permissions: roles ? { at: tokRoles.at, total: roles.length, needed: NEEDED.map(function (n) {
      const rw = n.replace('.Read.', '.ReadWrite.');
      return { perm: n, held: roles.indexOf(n) !== -1 ? n : roles.indexOf(rw) !== -1 ? rw : null };
    }) } : null,
    sources: { intune: dev.rec, entra: entra.rec, protection: prot.rec, malwareOverview: mwo.rec, malware: mw.rec,
      autopilot: ap.rec, enrollFail: te.rec, actions: ra.rec, cleanup: cr.rec, analytics: ux.rec, users: us.rec,
      rings: rg.rec,
      ringResults: combine('Ring results', 'GET /beta/deviceManagement/deviceConfigurations/{ring}/deviceStatuses', ringStatus.map(function (x) { return x.rec; }), [rg.rec]),
      ringGroups: combine('Ring group members', 'GET /v1.0/groups/{group}/transitiveMembers', ringMembers.map(function (x) { return x.rec; }), [rg.rec]),
      policies: cp.rec, stateSummary: csum.rec,
      compliance: combine('Device results per policy', 'GET /beta/deviceManagement/deviceCompliancePolicies/{policy}/deviceStatuses', polStatus.map(function (x) { return x.rec; }), [cp.rec]),
      complianceDevices: devStates ? devStates.rec : combine('Policy states per device', 'GET /beta/deviceManagement/managedDevices/{device}/deviceCompliancePolicyStates (in $batch)', [], [dev.rec]),
      settingDevices: combine('Failing devices per setting', 'GET /beta/deviceManagement/deviceCompliancePolicySettingStateSummaries/{setting}/deviceComplianceSettingStates', setStates.map(function (x) { return x.rec; }), [ss.rec]),
      settings: ss.rec, apDevices: ad.rec, apProfiles: apf.rec, enrollConfig: ec.rec, apps: apps.rec, appInventory: inv.rec,
      groups: combine('Group names', 'POST /v1.0/directoryObjects/getByIds', [gn && gn.rec], [rg.rec, cp.rec, apf.rec, ec.rec]) },
    devices: devices,
    devicesOk: !!dev.items,
    failOk: failOk,
    // Entra rows as arrays to keep the payload small; ENTRA_COLS names them.
    entraCols: ['objectId', 'deviceId', 'name', 'os', 'trust', 'lastSignIn', 'enabled', 'registered', 'managed', 'mgmtType'],
    entra: entra.items ? entra.items.map(function (e) {
      return [e.id, e.deviceId || null, e.displayName || '', e.operatingSystem || '', e.trustType || '', ms(e.approximateLastSignInDateTime),
        e.accountEnabled === true ? 1 : 0, ms(e.registrationDateTime), e.isManaged === true ? 1 : 0, e.managementType || ''];
    }) : null,
    cleanupRule: rule ? { days: Number(rule.deviceInactivityBeforeRetirementInDays) || null, platform: rule.deviceCleanupRulePlatformType || '', name: rule.displayName || '', modified: ms(rule.lastModifiedDateTime) } : null,
    protection: p ? pickNumbers(p) : null,
    malwareOverview: m ? { devices: Number(m.malwareDetectedDeviceCount) || 0, total: Number(m.totalMalwareCount) || 0, distinct: Number(m.totalDistinctMalwareCount) || 0,
      states: (m.malwareStateSummary || []).map(function (x) { return { state: x.state, devices: x.deviceCount, detections: x.malwareDetectionCount }; }) } : null,
    malware: mw.items ? mw.items.map(function (x) {
      const url = /^https:\/\/([a-z0-9-]+\.)*microsoft\.com\//i.test(x.additionalInformationUrl || '') ? x.additionalInformationUrl : null;
      return { name: x.displayName || '', severity: x.severity || '', category: x.category || '', last: ms(x.lastDetectionDateTime), url: url };
    }) : null,
    autopilot: ap.items ? ap.items.map(function (x) {
      return { at: ms(x.eventDateTime), device: x.managedDeviceName || '', serial: x.deviceSerialNumber || '', user: x.userPrincipalName || '',
        profile: x.windowsAutopilotDeploymentProfileDisplayName || '', esp: x.windows10EnrollmentCompletionPageConfigurationDisplayName || '',
        state: x.deploymentState || '', enrollState: x.enrollmentState || '', type: x.enrollmentType || '', os: x.osVersion || '',
        total: x.deploymentTotalDuration || '', failure: x.enrollmentFailureDetails || '' };
    }) : null,
    enrollFailures: te.items ? te.items.map(function (x) {
      return { at: ms(x.eventDateTime), platform: x.operatingSystem || '', os: x.osVersion || '', type: x.enrollmentType || '',
        category: x.failureCategory || '', reason: x.failureReason || '', userId: x.userId || null, deviceId: x.managedDeviceIdentifier || null };
    }) : null,
    actions: ra.items ? ra.items.map(function (x) {
      return { at: ms(x.requestDateTime), action: x.action || '', state: x.actionState || '', device: x.deviceDisplayName || '', deviceId: x.managedDeviceId || null,
        by: x.initiatedByUserPrincipalName || '', owner: x.deviceOwnerUserPrincipalName || x.userName || '' };
    }) : null,
    analytics: ux.items ? ux.items.map(function (x) {
      return { id: x.id, name: x.deviceName || '', score: x.endpointAnalyticsScore, startup: x.startupPerformanceScore, apps: x.appReliabilityScore,
        wfa: x.workFromAnywhereScore, battery: x.batteryHealthScore, health: x.healthStatus || '' };
    }) : null,
    policies: cp.items || extra.size ? policies : null,
    stateSummary: stateSum,
    stateIds: stateIds.length,
    stateReused: stateReused,
    settings: ss.items ? settings : null,
    apDevices: apDevices,
    apProfiles: apProfiles,
    enrollConfigs: enrollConfigs,
    apps: appList,
    appCounts: !!apps.rows,
    groups: groups,
  };
}

function refresh() {
  if (!inflight) {
    lastTry = Date.now();
    inflight = collect().then(function (s) {
      // A failed device read never replaces a good snapshot; it is reported beside it.
      if (s.devicesOk || !snap) snap = s;
      else snap = Object.assign({}, snap, { refreshError: { at: s.at, source: s.sources.intune } });
      if (s.devicesOk && snap.refreshError) delete snap.refreshError;
      // Only a complete device read is a day's reading.
      if (s.devicesOk && s.sources.intune.state === 'ok') { try { snap.trend = saveTrend(s); } catch (e) { console.error('[patch-status] trend save failed:', e && e.message); } }
      if (!snap.trend) { try { snap.trend = loadTrend().rows; } catch (e) { snap.trend = null; } }
      return snap;
    }).finally(function () { inflight = null; });
  }
  return inflight;
}

// ── daily trend ──────────────────────────────────────────────────────────────
// One row per UTC day (the last good read of the day wins), kept for 400 days.
// These counts use the same definitions as the page (patch-status.js issuesOf /
// intuneQuiet / entraOrphans / enrollGap); change both together.
const TREND_FILE = path.join(__dirname, 'data', 'intune-health-trend.json');
const DAY = 864e5;
function loadTrend() {
  let raw, j = null;
  try { raw = fs.readFileSync(TREND_FILE, 'utf8'); }
  catch (e) { if (e && e.code === 'ENOENT') return { v: 1, rows: [] }; throw e; }   // unreadable is not empty: never overwrite it
  try { j = JSON.parse(raw); } catch (e) { j = null; }
  if (!j || !Array.isArray(j.rows)) {
    const bad = TREND_FILE + '.bad-' + new Date().toISOString().replace(/[-:.]/g, '');
    fs.renameSync(TREND_FILE, bad);
    console.error('[patch-status] trend file was not valid JSON; kept as ' + path.basename(bad) + ', starting a new one');
    return { v: 1, rows: [] };
  }
  j.rows = j.rows.filter(function (r) { return r && typeof r === 'object' && typeof r.day === 'string' && typeof r.at === 'number'; });
  return j;
}
function trendRow(s) {
  const now = s.at, D = s.devices, W = D.filter(function (d) { return d.platform === 'Windows'; });
  const inIntune = new Set(D.map(function (d) { return d.aad; }).filter(Boolean)), ids = new Set(D.map(function (d) { return d.id; }));
  const cross = s.sources.intune.state === 'ok' && s.sources.entra && s.sources.entra.state === 'ok';
  const orph = s.entra && cross ? s.entra.filter(function (e) { return !(e[1] && inIntune.has(e[1])); }) : null;
  const pend = s.actions ? s.actions.filter(function (a) { return a.state === 'pending' && a.deviceId && ids.has(a.deviceId); }).length : null;
  return {
    day: new Date(now).toISOString().slice(0, 10), at: now,
    devices: D.length,
    noncompliant: D.filter(function (d) { return d.compliance === 'noncompliant'; }).length,
    quiet30: D.filter(function (d) { return d.lastSync == null || now - d.lastSync >= 30 * DAY; }).length,
    winTotal: W.length,
    winCurrent: W.filter(function (d) { return d.base && BASELINE.builds.indexOf(d.base) !== -1 && d.rev >= BASELINE.revision; }).length,
    unencrypted: W.filter(function (d) { return d.encrypted === false; }).length,
    departed: s.sources.users && s.sources.users.state === 'ok' ? D.filter(function (d) { return d.userState === 'disabled' || d.userState === 'missing'; }).length : null,
    pendingActions: pend,
    entraNoIntune: orph ? orph.length : null,
    enrollGap: orph ? orph.filter(function (e) { return e[3] === 'Windows' && (e[4] === 'ServerAd' || e[4] === 'AzureAd') && e[6] && e[5] && Math.floor((now - e[5]) / DAY) <= 30; }).length : null,
    appsFailing: s.apps && s.sources.apps && s.sources.apps.state === 'ok' ? s.apps.filter(function (a) { return a.failed > 0; }).length : null,
  };
}
function saveTrend(s) {
  const t = loadTrend(), row = trendRow(s);
  const prev = t.rows.find(function (r) { return r.day === row.day; });
  if (prev) Object.keys(row).forEach(function (k) { if (row[k] == null && prev[k] != null) row[k] = prev[k]; });
  t.rows = t.rows.filter(function (r) { return r.day !== row.day; }).concat([row]).sort(function (a, b) { return a.at - b.at; }).slice(-400);
  const tmp = TREND_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(t), { mode: 0o640 });
  fs.renameSync(tmp, TREND_FILE);
  return t.rows;
}
// So the trend has a point on days nobody opens the page: every 30 minutes, if
// today has no row yet, take one read (the same read the page would take).
setTimeout(function tick() {
  try {
    const today = new Date().toISOString().slice(0, 10), rows = loadTrend().rows;
    if (!inflight && !(rows.length && rows[rows.length - 1].day === today)) refresh().catch(function () {});
  } catch (e) { console.error('[patch-status] trend tick failed:', e && e.message); }
  finally { setTimeout(tick, 30 * 60 * 1000).unref(); }
}, 2 * 60 * 1000).unref();

router.get('/snapshot', async function (req, res) {
  try {
    const force = req.query.refresh === '1';
    const age = snap ? Date.now() - snap.at : Infinity;
    const sinceTry = Date.now() - lastTry;   // while Intune fails, snap.at stays old; lastTry stops a re-read per request
    if (!snap || ringsDirty || (age > CACHE_MS && sinceTry > CACHE_MS) || (force && age > MIN_FORCE_MS && sinceTry > MIN_FORCE_MS)) { ringsDirty = false; await refresh(); }
    res.set('Cache-Control', 'no-store');
    res.json(Object.assign({ ok: true, now: Date.now(), cacheMs: CACHE_MS, minForceMs: MIN_FORCE_MS, canEditRings: canEditRings(req.user) }, snap));
  } catch (e) {
    console.error('[patch-status] snapshot failed:', e && e.message);
    res.status(500).json({ ok: false, error: 'INTERNAL' });
  }
});

// ── one device, on demand (the drawer) ─────────────────────────────────────
const detailCache = new Map();          // id -> { at, body }
const DETAIL_MS = 2 * 60 * 1000;
const HW_KEYS = ['tpmSpecificationVersion', 'operatingSystemEdition', 'operatingSystemLanguage', 'deviceGuardVirtualizationBasedSecurityState',
  'deviceGuardLocalSystemAuthorityCredentialGuardState', 'batteryLevelPercentage', 'batteryHealthPercentage', 'ipAddressV4', 'subnetAddress',
  'deviceFullQualifiedDomainName', 'systemManagementBIOSVersion', 'osBuildNumber', 'isSharedDevice'];

router.get('/device/:id', async function (req, res) {
  try {
    const id = String(req.params.id || '');
    if (!GUID.test(id)) return res.status(400).json({ ok: false, error: 'BAD_ID' });
    if (!snap || !snap.devices.some(function (d) { return d.id === id; })) return res.status(404).json({ ok: false, error: 'NOT_IN_SNAPSHOT' });
    const hit = detailCache.get(id);
    res.set('Cache-Control', 'no-store');
    if (hit && Date.now() - hit.at < DETAIL_MS) return res.json(hit.body);
    const dev = snap.devices.find(function (d) { return d.id === id; });
    const base = '/beta/deviceManagement/managedDevices/' + id;
    const R = await Promise.all([
      readOne('Hardware inventory', base + '?$select=hardwareInformation'),
      dev.platform === 'Windows' ? readOne('Defender state', base + '/windowsProtectionState') : Promise.resolve(null),
      readAll('Discovered apps', base + '/detectedApps?$top=999'),
      dev.polStates ? Promise.resolve(null) : readOne('Compliance policies', base + '/deviceCompliancePolicyStates'),
      // Intent and state are kept per user; the primary user's view is the one Intune shows for the device.
      dev.userId && GUID.test(dev.userId) ? readOne('Assigned apps', '/beta/users/' + dev.userId + '/mobileAppIntentAndStates/' + id) : Promise.resolve(null),
    ]);
    // One row per policy (a policy reported for two users keeps the worse). code 1 = not applicable,
    // 2 = compliant, 0 = anything else. Intune fills settingStates for some policies only; when it is
    // empty the failing setting is not known per policy (the snapshot's per-setting list is shown instead).
    const PST = { compliant: 'Compliant', remediated: 'Compliant', notApplicable: 'Not applicable', notAssigned: 'Not assigned', nonCompliant: 'Not compliant',
      error: 'Error', conflict: 'Conflict', inGracePeriod: 'In grace period', unknown: 'Unknown' };
    const codeOf = function (s) { return s === 'notApplicable' || s === 'notAssigned' ? 1 : s === 'compliant' || s === 'remediated' ? 2 : 0; };
    const pol = new Map();
    if (!R[3]) {
      // From the snapshot's per-device read; Intune names no setting per policy there either.
      const src = snap.sources.complianceDevices || {};
      R[3] = { rec: { label: 'Compliance policies', request: 'Snapshot: ' + (src.request || 'policy states per device'), state: 'ok', http: src.http || null, ms: 0, count: null, at: snap.at, error: null },
        item: { value: dev.polStates.map(function (x) { return { id: x[0], displayName: x[1], state: x[2], settingStates: [] }; }) } };
    }
    const polRows = R[3].item && Array.isArray(R[3].item.value) ? R[3].item.value : null;
    (polRows || []).forEach(function (x) {
      if (!GUID.test(x.id || '')) return;
      const code = codeOf(x.state), prev = pol.get(x.id);
      const bad = function (c) { return c === 1 || c === 2 ? 0 : 1; };
      const settings = (Array.isArray(x.settingStates) ? x.settingStates : []).filter(function (z) { return codeOf(z.state) === 0; }).map(function (z) {
        return { name: z.settingName || z.setting || '', raw: z.setting || '', status: PST[z.state] || String(z.state || ''), detail: z.errorDescription || '', error: num(z.errorCode) || null };
      });
      if (!prev || bad(code) > bad(prev.code)) pol.set(x.id, { id: x.id, name: x.displayName || 'Unnamed policy', code: code, status: PST[x.state] || String(x.state || ''), at: null, settings: settings });
    });
    if (R[3].rec.state === 'ok') R[3].rec.count = polRows ? pol.size : null;
    // The answer names the device it is for; anything else is not this device's list.
    const ai = R[4] && R[4].item;
    if (ai && ai.managedDeviceIdentifier && ai.managedDeviceIdentifier !== id) { R[4].rec.state = 'error'; R[4].rec.error = 'Answer was for another device'; }
    const intent = ai && R[4].rec.state === 'ok' && Array.isArray(ai.mobileAppList) ? ai.mobileAppList : null;
    const hw = R[0].item && R[0].item.hardwareInformation ? R[0].item.hardwareInformation : null, wp = R[1] && R[1].item;
    const body = {
      ok: true, id: id, at: Date.now(),
      sources: { hardware: R[0].rec, defender: R[1] ? R[1].rec : null, apps: R[2].rec, policies: R[3].rec,
        assigned: R[4] ? R[4].rec : null },
      failSettings: dev.failSettings || [],
      policies: polRows ? Array.from(pol.values()).sort(function (a, b) { return ((a.code === 1 || a.code === 2) - (b.code === 1 || b.code === 2)) || a.name.localeCompare(b.name); }) : null,
      assigned: intent ? intent.map(function (a) {
        return { id: GUID.test(a.applicationId || '') ? a.applicationId : null, name: a.displayName || '', intent: a.mobileAppIntent || '', state: a.installState || '',
          version: a.installState === 'installed' ? a.displayVersion || '' : '' };   // Intune sends "0" for an app that is not installed
      }).sort(function (a, b) { return a.name.localeCompare(b.name); }) : null,
      hardware: hw ? HW_KEYS.reduce(function (o, k) { const v = hw[k]; if (v !== null && v !== undefined && v !== '' && !(Array.isArray(v) && !v.length)) o[k] = v; return o; }, {}) : null,
      defender: wp ? {
        protection: wp.malwareProtectionEnabled, realTime: wp.realTimeProtectionEnabled, network: wp.networkInspectionSystemEnabled, tamper: wp.tamperProtectionEnabled,
        state: wp.deviceState || '', product: wp.productStatus || '', signatureOverdue: wp.signatureUpdateOverdue, quickScanOverdue: wp.quickScanOverdue,
        fullScanOverdue: wp.fullScanOverdue, rebootRequired: wp.rebootRequired, fullScanRequired: wp.fullScanRequired,
        signature: wp.signatureVersion || '', engine: wp.engineVersion || '', platform: wp.antiMalwareVersion || '',
        lastQuick: ms(wp.lastQuickScanDateTime), lastFull: ms(wp.lastFullScanDateTime), reported: ms(wp.lastReportedDateTime), vm: wp.isVirtualMachine,
      } : null,
      apps: R[2].items ? R[2].items.map(function (a) { return { name: a.displayName || '', version: a.version || '', publisher: a.publisher || '' }; })
        .sort(function (a, b) { return a.name.localeCompare(b.name); }) : null,
    };
    const failed = [R[0].rec, R[1] && R[1].rec, R[2].rec, R[3].rec, R[4] && R[4].rec].some(function (r) { return r && r.state !== 'ok' && r.state !== 'denied'; });
    if (!failed) {
      detailCache.set(id, { at: Date.now(), body: body });
      if (detailCache.size > 300) detailCache.delete(detailCache.keys().next().value);
    }
    res.json(body);
  } catch (e) {
    console.error('[patch-status] device detail failed:', e && e.message);
    res.status(500).json({ ok: false, error: 'INTERNAL' });
  }
});

// ── one app, on demand: which devices did not install it, and why ─────────
const appCache = new Map();
router.get('/app/:id', async function (req, res) {
  try {
    const id = String(req.params.id || '');
    if (!GUID.test(id)) return res.status(400).json({ ok: false, error: 'BAD_ID' });
    if (!snap || !Array.isArray(snap.apps) || !snap.apps.some(function (a) { return a.id === id; })) return res.status(404).json({ ok: false, error: 'NOT_IN_SNAPSHOT' });
    res.set('Cache-Control', 'no-store');
    const hit = appCache.get(id);
    if (hit && Date.now() - hit.at < DETAIL_MS) return res.json(hit.body);
    const r = await readReport('App install status', '/beta/deviceManagement/reports/retrieveDeviceAppInstallationStatusReport', "(ApplicationId eq '" + id + "')");
    const states = {};
    const rows = r.rows ? r.rows.map(function (x) {
      const st = x.AppInstallState_loc || String(x.InstallState == null ? '' : x.InstallState);
      states[st] = (states[st] || 0) + 1;
      return { deviceId: GUID.test(x.DeviceId || '') ? x.DeviceId : null, device: x.DeviceName || '', user: x.UserPrincipalName || '', platform: x.Platform || '',
        version: x.AppVersion || '', state: st, stateCode: num(x.InstallState), detail: x.AppInstallStateDetails_loc || '', hex: x.HexErrorCode || '', at: ms(x.LastModifiedDateTime) };
    }) : null;
    // Installed rows are only counted; the rest are listed, failures first.
    const body = { ok: true, id: id, at: Date.now(), source: r.rec, states: r.rows ? states : null,
      rows: rows ? rows.filter(function (x) { return x.stateCode !== 1; }).sort(function (a, b) { return ((a.stateCode === 2) ? 0 : 1) - ((b.stateCode === 2) ? 0 : 1) || a.device.localeCompare(b.device); }) : null };
    if (r.rec.state === 'ok') { appCache.set(id, { at: Date.now(), body: body }); if (appCache.size > 200) appCache.delete(appCache.keys().next().value); }
    res.json(body);
  } catch (e) {
    console.error('[patch-status] app detail failed:', e && e.message);
    res.status(500).json({ ok: false, error: 'INTERNAL' });
  }
});

// ── update ring editing (build 8) ───────────────────────────────────────────
// Super-admins only (requireSuperAdmin, which also audits the pass). A read-only token is
// refused by server.js before it gets here. Every save is checked against the ring as Intune
// holds it NOW: if it changed since the editor opened, nothing is sent (409). Only Windows
// Update for Business rings can be changed; any other configuration id is refused.
// Every save writes one audit row (settings-audit: who, when, field old -> new).
const SA = require('./settings-audit');
const RING_TYPE = '#microsoft.graph.windowsUpdateForBusinessConfiguration';
const ACTIVE_HOURS = '#microsoft.graph.windowsUpdateActiveHoursInstall';
// Graph field -> limits Intune applies in its own ring editor.
const RING_FIELDS = {
  qualityUpdatesDeferralPeriodInDays: ['int', 0, 30],
  featureUpdatesDeferralPeriodInDays: ['int', 0, 365],
  deadlineForQualityUpdatesInDays: ['int', 0, 30],
  deadlineForFeatureUpdatesInDays: ['int', 0, 30],
  deadlineGracePeriodInDays: ['int', 0, 7],
  postponeRebootUntilAfterDeadline: ['bool'],
  qualityUpdatesPaused: ['bool'],
  featureUpdatesPaused: ['bool'],
  userPauseAccess: ['enum', ['enabled', 'disabled']],
  userWindowsUpdateScanAccess: ['enum', ['enabled', 'disabled']],
  activeHoursStart: ['hour'],
  activeHoursEnd: ['hour'],
};
const SCOPE_MAX = 25;
let ringsDirty = false;
function canEditRings(u) { return !!(u && u.isSuperAdmin === true && !u.readOnly); }
function hourOf(t) { const m = /^(\d{2}):00:00/.exec(String(t || '')); return m ? Number(m[1]) : null; }
function hourText(h) { return (h < 10 ? '0' : '') + h + ':00:00.0000000'; }
// What the editor shows and what the audit compares: Intune's values, nothing derived.
function ringView(r, assigns, names) {
  const sch = r.installationSchedule || null, active = !!(sch && sch['@odata.type'] === ACTIVE_HOURS);
  const v = { id: r.id, name: r.displayName || 'Unnamed ring', version: r.lastModifiedDateTime || null, isRing: r['@odata.type'] === RING_TYPE,
    installMode: r.automaticUpdateMode || '', activeHoursSchedule: active,
    qualityPauseUntil: r.qualityUpdatesPauseExpiryDateTime || null, featurePauseUntil: r.featureUpdatesPauseExpiryDateTime || null, fields: {} };
  Object.keys(RING_FIELDS).forEach(function (k) {
    if (k === 'activeHoursStart' || k === 'activeHoursEnd') v.fields[k] = active ? hourOf(sch[k]) : null;
    else v.fields[k] = r[k] === undefined ? null : r[k];
  });
  v.targets = targetsOf(assigns).map(function (t) { return Object.assign(t, { name: t.groupId ? names[t.groupId] || null : null }); });
  v.scopeEditable = v.targets.every(function (t) { return !t.filter && ['group', 'exclude', 'allUsers', 'allDevices'].indexOf(t.kind) !== -1; });
  return v;
}
// One write, never retried. A failure is returned, not thrown, so a later step can be
// reported as "not sent" after an earlier one went through.
async function graphWrite(method, path, body) {
  try {
    const bearer = await token();
    const r = await fetch(GRAPH + path, { method: method, headers: { Authorization: 'Bearer ' + bearer, 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(body), signal: AbortSignal.timeout(TIMEOUT_MS) });
    const j = await r.json().catch(function () { return null; });
    return { ok: r.ok, http: r.status, code: (j && j.error && j.error.code) || null, message: (j && j.error && String(j.error.message || '').slice(0, 300)) || null };
  } catch (e) {
    const guard = e && e.code === 'EDEVGUARD', timeout = e && e.name === 'TimeoutError';
    return { ok: false, http: null, code: guard ? 'GUARD' : timeout ? 'TIMEOUT' : 'NETWORK',
      message: guard ? "This server's outbound guard refused the write; nothing reached Intune." : timeout ? 'Intune did not answer in time; the change may or may not have been applied. Reopen the ring to see.' : 'The request could not be sent.' };
  }
}
async function readRing(id) {
  const [rr, ar] = await Promise.all([
    readOne('Update ring', '/beta/deviceManagement/deviceConfigurations/' + id),
    readAll('Ring assignments', '/beta/deviceManagement/deviceConfigurations/' + id + '/assignments'),
  ]);
  if (!rr.item || !ar.items) return { fail: rr.item ? ar.rec : rr.rec };
  const ids = targetsOf(ar.items).map(function (t) { return t.groupId; }).filter(Boolean), names = {};
  if (ids.length) {
    const g = await readOne('Group names', '/v1.0/directoryObjects/getByIds', { ids: ids, types: ['group'] });
    ((g.item && g.item.value) || []).forEach(function (x) { names[x.id] = x.displayName || null; });
  }
  return { ring: ringView(rr.item, ar.items, names) };
}
function failBody(rec) {
  return { ok: false, error: rec && rec.http === 404 ? 'NOT_FOUND' : rec && rec.http === 429 ? 'THROTTLED' : 'READ_FAILED', detail: rec ? rec.error : null };
}
router.get('/rings/:id', async function (req, res) {
  try {
    if (!GUID.test(req.params.id)) return res.status(400).json({ ok: false, error: 'BAD_ID' });
    const x = await readRing(req.params.id);
    res.set('Cache-Control', 'no-store');
    if (x.fail) return res.status(x.fail.http === 404 ? 404 : 502).json(failBody(x.fail));
    if (!x.ring.isRing) return res.status(404).json({ ok: false, error: 'NOT_A_RING' });
    res.json({ ok: true, ring: x.ring, canEdit: canEditRings(req.user), limits: RING_FIELDS, scopeMax: SCOPE_MAX });
  } catch (e) {
    console.error('[patch-status] ring read failed:', e && e.message);
    res.status(500).json({ ok: false, error: 'INTERNAL' });
  }
});
// Search only; no audit row per keystroke. The save that uses a group is audited.
router.get('/groups', async function (req, res) {
  if (!canEditRings(req.user)) return res.status(403).json({ ok: false, error: 'FORBIDDEN' });
  try {
    const q = String(req.query.q || '').replace(/["\\]/g, '').trim().slice(0, 60);
    if (q.length < 2) return res.json({ ok: true, groups: [] });
    const bearer = await token();
    const r = await getOnce(GRAPH + '/v1.0/groups?$search=' + encodeURIComponent('"displayName:' + q + '"') + '&$select=id,displayName,securityEnabled,onPremisesSyncEnabled,groupTypes&$orderby=displayName&$top=15',
      { headers: { Authorization: 'Bearer ' + bearer, Accept: 'application/json', ConsistencyLevel: 'eventual' } });
    const j = await r.json().catch(function () { return null; });
    if (!r.ok || !j) return res.status(502).json({ ok: false, error: 'READ_FAILED', http: r.status });
    res.set('Cache-Control', 'no-store');
    res.json({ ok: true, groups: (j.value || []).filter(function (g) { return GUID.test(g.id || ''); }).map(function (g) {
      return { id: g.id, name: g.displayName || '', security: g.securityEnabled === true, synced: g.onPremisesSyncEnabled === true, dynamic: (g.groupTypes || []).indexOf('DynamicMembership') !== -1 };
    }) });
  } catch (e) {
    console.error('[patch-status] group search failed:', e && e.message);
    res.status(500).json({ ok: false, error: 'INTERNAL' });
  }
});
// Checks one requested change. Returns the value Graph should get, or throws a message.
function checkField(k, v) {
  const L = RING_FIELDS[k];
  if (!L) throw new Error(k + ' cannot be changed here');
  if (L[0] === 'int') { if (!Number.isInteger(v) || v < L[1] || v > L[2]) throw new Error(k + ' must be a whole number from ' + L[1] + ' to ' + L[2]); return v; }
  if (L[0] === 'bool') { if (typeof v !== 'boolean') throw new Error(k + ' must be true or false'); return v; }
  if (L[0] === 'enum') { if (L[1].indexOf(v) === -1) throw new Error(k + ' must be one of ' + L[1].join(', ')); return v; }
  if (L[0] === 'hour') { if (!Number.isInteger(v) || v < 0 || v > 23) throw new Error(k + ' must be an hour from 0 to 23'); return v; }
  throw new Error(k + ' cannot be changed here');
}
function checkScope(sc) {
  if (!sc || typeof sc !== 'object') throw new Error('scope is missing');
  const inc = Array.isArray(sc.include) ? sc.include : [], exc = Array.isArray(sc.exclude) ? sc.exclude : [];
  if (inc.concat(exc).some(function (g) { return !GUID.test(String(g)); })) throw new Error('a group id is not valid');
  if (inc.length + exc.length > SCOPE_MAX) throw new Error('at most ' + SCOPE_MAX + ' groups');
  if (inc.some(function (g) { return exc.indexOf(g) !== -1; })) throw new Error('a group cannot be both included and excluded');
  if (new Set(inc).size !== inc.length || new Set(exc).size !== exc.length) throw new Error('a group is listed twice');
  return { include: inc, exclude: exc, allUsers: sc.allUsers === true, allDevices: sc.allDevices === true };
}
function scopeOf(v) {
  return { include: v.targets.filter(function (t) { return t.kind === 'group'; }).map(function (t) { return t.groupId; }).sort(),
    exclude: v.targets.filter(function (t) { return t.kind === 'exclude'; }).map(function (t) { return t.groupId; }).sort(),
    allUsers: v.targets.some(function (t) { return t.kind === 'allUsers'; }), allDevices: v.targets.some(function (t) { return t.kind === 'allDevices'; }) };
}
function scopeText(sc, names) {
  const nm = function (g) { return names[g] || g; };
  const a = [];
  if (sc.allUsers) a.push('All users'); if (sc.allDevices) a.push('All devices');
  sc.include.forEach(function (g) { a.push(nm(g)); });
  sc.exclude.forEach(function (g) { a.push('not ' + nm(g)); });
  return a.length ? a.join('; ') : 'Not assigned';
}
router.post('/rings/:id/save', rbac.requireSuperAdmin, express.json({ limit: '16kb' }), async function (req, res) {
  const id = req.params.id, b = req.body || {};
  try {
    if (!GUID.test(id)) return res.status(400).json({ ok: false, error: 'BAD_ID' });
    if (!canEditRings(req.user)) return res.status(403).json({ ok: false, error: 'FORBIDDEN' });
    // validate everything before anything is sent
    let set = {}, scope = null;
    try {
      Object.keys(b.set || {}).forEach(function (k) { set[k] = checkField(k, b.set[k]); });
      if (b.scope != null) scope = checkScope(b.scope);
    } catch (e) { return res.status(400).json({ ok: false, error: 'INVALID', detail: e.message }); }
    const cur = await readRing(id);
    if (cur.fail) return res.status(502).json(failBody(cur.fail));
    const before = cur.ring;
    if (!before.isRing) return res.status(404).json({ ok: false, error: 'NOT_A_RING' });
    if (!b.version || b.version !== before.version) return res.status(409).json({ ok: false, error: 'CHANGED', detail: 'The ring was changed in Intune after you opened it.', ring: before });
    Object.keys(set).forEach(function (k) { if (set[k] === before.fields[k]) delete set[k]; });
    if (('activeHoursStart' in set || 'activeHoursEnd' in set) && !before.activeHoursSchedule)
      return res.status(400).json({ ok: false, error: 'INVALID', detail: 'This ring does not install during active hours; change its install schedule in Intune.' });
    if (('activeHoursStart' in set || 'activeHoursEnd' in set) &&
      ('activeHoursStart' in set ? set.activeHoursStart : before.fields.activeHoursStart) === ('activeHoursEnd' in set ? set.activeHoursEnd : before.fields.activeHoursEnd))
      return res.status(400).json({ ok: false, error: 'INVALID', detail: 'Active hours cannot start and end at the same hour.' });
    if (scope) {
      if (!before.scopeEditable) return res.status(400).json({ ok: false, error: 'INVALID', detail: 'This ring has assignment filters or other target types; change its assignments in Intune.' });
      const was = scopeOf(before);
      if (JSON.stringify(was) === JSON.stringify(Object.assign({}, scope, { include: scope.include.slice().sort(), exclude: scope.exclude.slice().sort() }))) scope = null;
    }
    if (!Object.keys(set).length && !scope) return res.json({ ok: true, settings: 'unchanged', scope: 'unchanged', ring: before });
    // every group in the new scope must exist (and gets its name for the audit row)
    const names = {};
    before.targets.forEach(function (t) { if (t.groupId && t.name) names[t.groupId] = t.name; });
    if (scope && scope.include.concat(scope.exclude).length) {
      const g = await readOne('Group names', '/v1.0/directoryObjects/getByIds', { ids: scope.include.concat(scope.exclude), types: ['group'] });
      if (!g.item) return res.status(502).json(failBody(g.rec));
      (g.item.value || []).forEach(function (x) { names[x.id] = x.displayName || x.id; });
      const missing = scope.include.concat(scope.exclude).filter(function (x) { return !names[x]; });
      if (missing.length) return res.status(400).json({ ok: false, error: 'INVALID', detail: 'No such group: ' + missing.join(', ') });
    }
    const out = { settings: Object.keys(set).length ? 'pending' : 'unchanged', scope: scope ? 'pending' : 'unchanged' };
    if (Object.keys(set).length) {
      const body = { '@odata.type': RING_TYPE };
      Object.keys(set).forEach(function (k) { if (k !== 'activeHoursStart' && k !== 'activeHoursEnd') body[k] = set[k]; });
      if ('activeHoursStart' in set || 'activeHoursEnd' in set) body.installationSchedule = { '@odata.type': ACTIVE_HOURS,
        activeHoursStart: hourText('activeHoursStart' in set ? set.activeHoursStart : before.fields.activeHoursStart),
        activeHoursEnd: hourText('activeHoursEnd' in set ? set.activeHoursEnd : before.fields.activeHoursEnd) };
      const w = await graphWrite('PATCH', '/beta/deviceManagement/deviceConfigurations/' + id, body);
      out.settings = w.ok ? 'saved' : 'failed'; out.settingsHttp = w.http; out.settingsError = w.code; out.settingsMessage = w.message;
    }
    if (scope && out.settings !== 'failed') {
      const A = [];
      if (scope.allUsers) A.push({ target: { '@odata.type': '#microsoft.graph.allLicensedUsersAssignmentTarget' } });
      if (scope.allDevices) A.push({ target: { '@odata.type': '#microsoft.graph.allDevicesAssignmentTarget' } });
      scope.include.forEach(function (g) { A.push({ target: { '@odata.type': '#microsoft.graph.groupAssignmentTarget', groupId: g } }); });
      scope.exclude.forEach(function (g) { A.push({ target: { '@odata.type': '#microsoft.graph.exclusionGroupAssignmentTarget', groupId: g } }); });
      const w = await graphWrite('POST', '/beta/deviceManagement/deviceConfigurations/' + id + '/assign', { assignments: A });
      out.scope = w.ok ? 'saved' : 'failed'; out.scopeHttp = w.http; out.scopeError = w.code; out.scopeMessage = w.message;
    } else if (scope) out.scope = 'not sent';
    // what Intune holds now, for the page and the audit row
    const now = await readRing(id), after = now.ring || null;
    if (out.settings === 'saved' || out.scope === 'saved') ringsDirty = true;
    const keys = Object.keys(set);
    const bF = Object.assign({}, before.fields), aF = after ? Object.assign({}, after.fields) : undefined;
    if (scope) { bF.assignments = scopeText(scopeOf(before), names); if (aF) aF.assignments = scopeText(scopeOf(after), names); keys.push('assignments'); }
    await SA.record(rbac, req, 'patch-status', out.settings === 'failed' || out.scope === 'failed' ? 'intune_ring_save_failed' : 'intune_ring_saved',
      SA.entry({ what: 'intune update ring', op: 'update', id: id, subject: before.name, before: bF, after: aF, keys: keys,
        extra: { settings: out.settings, scope: out.scope, settings_http: out.settingsHttp, scope_http: out.scopeHttp, settings_error: out.settingsError, scope_error: out.scopeError } }));
    out.ok = out.settings !== 'failed' && out.scope !== 'failed';
    out.ring = after; out.reread = !!after;
    res.status(out.ok ? 200 : 502).json(out);
  } catch (e) {
    console.error('[patch-status] ring save failed:', e && e.message);
    const guard = e && e.code === 'EDEVGUARD';
    res.status(guard ? 503 : 500).json({ ok: false, error: guard ? 'GUARD' : 'INTERNAL', detail: guard ? "This server's outbound guard refused the write. Nothing was sent to Intune." : null });
  }
});

// ── repair (build 9) ─────────────────────────────────────────────────────────
// Windows PCs that AD, ManageEngine or Entra know and Intune does not, and the
// ManageEngine repair run for super-admins. See patch-status-repair.js.
require('./patch-status-repair')(router, { rbac: rbac, SA: SA,
  snapshot: function () { return snap && Date.now() - snap.at < CACHE_MS ? snap : refresh(); } });

// Shared GPO migration planning. This module receives GET-only Graph readers;
// its only saves are CorpIT register metadata in the existing GPO database.
const migrationPool = mysql.createPool({ host: process.env.DB_HOST || 'localhost', user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '', database: process.env.DB_NAME_BETA || 'corpit_hub', connectionLimit: 2, charset: 'utf8mb4' });
require('./gpo-migration-register').mount(router, { pool: migrationPool, rbac: rbac, json: express.json,
  readAll: readAll, readOne: function (label, path) { return readOne(label, path); },
  snapshot: function () { return snap && Date.now() - snap.at < CACHE_MS ? snap : refresh(); } });

module.exports = router;
