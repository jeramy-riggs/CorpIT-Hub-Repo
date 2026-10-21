// ─────────────────────────────────────────────────────────────────────────────
// patch-status-repair.js — the Repair view of Intune health (build 9, 2026-10-14).
//
// Windows PCs that AD, ManageEngine (Endpoint Central Cloud) or Entra know about but
// Intune does not, why each one is missing, which repair route can reach it, and, for
// super-admins, a run of the ManageEngine repair script on up to five of them at a time.
//
// Mounted by patch-status-routes.js on its own router, so the same gate applies
// (super-admins and SaaS-ITH-HD). Running a repair is super-admins only and audited.
//
// SOURCES
//   Intune + Entra  the patch-status snapshot (not read again here).
//   AD              LDAP, the hub's LDAP_* bind: Windows computers that are not servers.
//   ManageEngine    GET /api/1.4/som/computers (every page) with the hub's ME_* app.
//                   One Zoho access token is reused for its life: Zoho refuses more than
//                   about ten refreshes per refresh token in ten minutes, and the hub's
//                   other ME modules share that refresh token.
// MATCHING (no guessing): AD objectGUID = Entra deviceId (hybrid join writes one into the
//   other), and the computer name (the part before the first dot, upper case) across
//   all four. A PC is in Intune when an Intune device carries one of its Entra device IDs
//   or its name. A source that was not read makes every answer that needs it "unknown".
//
// THE REPAIR (only what was tested by hand on 10-14, nothing new):
//   ME template "CorpIT Intune repair pilot" (id below), which holds the fleet build of
//   intune-repair-fleet.ps1 (stamp 20261014T012307Z). That script acts only on the 33 PCs
//   pinned in it, and only when the PC's Entra device ID matches its pin; on any other PC
//   it stops with exit 10 and changes nothing. So the page offers a run only where
//   the pin matches and ME's agent is installed. A wider script needs a new build, uploaded
//   to ME by a person.
//   Deploy: POST /dcapi/configuration/deploy/template, at most 5 targets a call (ME refuses
//   more with IAM0023). One uninstalled agent fails the whole call (20003), so only
//   installed agents (installation_status 22, managed_status 61) are sent.
//   On the dev server the outbound guard refuses that POST unless allow.json lists it;
//   the page then says nothing reached ManageEngine.
//
// ME resource, template and collection IDs are 17-digit numbers, past what a JS number
// holds exactly, so ME JSON is parsed with long numbers kept as strings and the deploy body
// is written by hand.
// ─────────────────────────────────────────────────────────────────────────────
'use strict';

const fs = require('fs');
const path = require('path');
const express = require('express');
const ldapSecure = require('./ldap-secure'); // ldapjs client with StartTLS before every bind

const DAY = 864e5;
const CACHE_MS = 5 * 60 * 1000, MIN_FORCE_MS = 60 * 1000;
const ME_TIMEOUT = 30000, AD_TIMEOUT = 30000;
const STATUS_MS = 2 * 60 * 1000;           // a collection's execution status is reused for two minutes
const POLL_DAYS = 14;                      // collections older than this are not read again
const QUEUED_DAYS = 7;                     // a run still waiting within this many days blocks another
const MAX_TARGETS = 5;

const TEMPLATE = { id: '17591000065385338', name: 'CorpIT Intune repair pilot' };
const SCRIPT = { file: 'intune-repair-fleet.ps1', stamp: '20261014T012307Z', sha256: 'd210fdea81d0c08c29cf77a73e33f2429cc803783c0f64b676bd58c2a3f07387', loaded: '2026-10-14T01:56:00Z' };
// name -> Entra device ID pinned in that build (targets33.json, 10-13). Same list as the script.
const PINS = {
  '2464QV3': 'b9433d1a-0de3-417a-ac59-d145339131d9', '2K29LR3': 'e3923cee-1807-47e8-a1bd-4813bd7960bb',
  '368RPN3': '7cfbea2f-a943-457d-8004-ad4a7fe20113', '3QXHZM4': 'ed254dda-8308-4c54-9814-24e2f6de5c6c',
  '3V1H3M2': '751e9ac4-7c03-4bc7-8ccd-85e42722d9f6', '49ZS1J3': '97a7abdd-7429-472e-b35e-8203c8f55d67',
  '5CZS1J3': 'da4c70f9-f13b-4f26-9d86-25b4af563606', '6721NN3': '445602a5-499d-4505-b066-d6a0f05e479d',
  '6CDDDK3': 'f4c61b34-d145-44bb-8a8a-f0dc6f9f6b92', '6T087G3': 'ad3ed5f8-35e7-4feb-9231-22eda9e20c0b',
  '710GLM4': '190313e5-7fd9-4bcb-8281-3fd3c21a6821', '7NY56G3': '388f2e27-19a8-4922-9c95-f5afe26cd567',
  '7VDPQW3': '94c2a8ed-b028-40b3-bb47-72223107857c', '8824QV3': '2c8cd06e-0dcc-4f8c-be5e-9572ba0fe0f6',
  '9R7GLM4': '788122c1-5565-4207-8f91-8ba8984bacb5', '9V5Y294': '06bcf7cd-b647-45f5-a18a-b89a08ee885f',
  '9V9DQV3': 'fafc1e93-a41a-4746-84a4-12f75b1972e8', 'C4SBQN3': 'ca0f8e4f-814c-4748-bd90-ebae13b5feb2',
  'CMVTG24': '8e26f5bc-9777-4276-a1bf-e6099433a3e6', 'DJVM1B4': '96a01866-4c2b-422e-8663-fb49fbcc1481',
  'DSQMRQ3': '6e8dbd09-788a-43c0-bf6e-f2f853ce2cf1', 'FWY87G3': 'f10a4c55-e1c0-4dc1-80cf-6fff9fa9c220',
  'GHT23T3': '09b403e5-13b3-445f-8497-d450b7b96703', 'GNK2GY3': 'ced1434d-d5e8-4100-9c49-72b12033605a',
  'GWLS1J3': '624630a7-e6ed-40f3-becf-0a3856961ae1', 'HDTR9K3': '99b19b03-a7b2-48d8-a301-b042a162bd50',
  'J8BGDK3': '63834f19-b01a-4922-80a1-72655d5c5b55', 'JRSW294': '5cd33121-f1fb-4dc0-bacb-efdd2d82627b',
  'NUC-CHICAGO2': '90fc5e53-ea32-40c2-828d-87f6291ea865', 'NUC-HELPDESK': 'e4c8e078-8590-42df-a38b-c959fa2beba6',
  'NUC-LIVEAUCTION': 'bcafedac-89c3-4280-ad6c-7c6c9361c159', 'NUC-MARKETING': '872535af-70ad-409c-9828-fb2e7bdbe8a3',
  'WARROOMTOUCH': 'b0e30a84-751a-42c1-b62d-8199bdb91313',
};
// ME collections deployed from the command line on 10-13/10-14, before this page existed.
const SEED_RUNS = [
  { cid: '17591000065385340', at: Date.parse('2026-10-13T23:30:53Z'), by: 'command line (pilot)' },
  { cid: '17591000065408293', at: Date.parse('2026-10-14T01:05:00Z'), by: 'command line (pilot)' },
  { cid: '17591000065385366', at: Date.parse('2026-10-14T01:32:29Z'), by: 'command line (pilot)' },
  { cid: '17591000065408317', at: Date.parse('2026-10-14T02:01:00Z'), by: 'command line (fleet run)' },
  { cid: '17591000065385386', at: Date.parse('2026-10-14T02:01:00Z'), by: 'command line (fleet run)' },
  { cid: '17591000065408335', at: Date.parse('2026-10-14T02:01:00Z'), by: 'command line (fleet run)' },
  { cid: '17591000065408353', at: Date.parse('2026-10-14T02:01:00Z'), by: 'command line (fleet run)' },
];
// AD OUs that Entra Connect does not sync (its exclusion list, read 2026-10-13).
const UNSYNCED_OUS = [{ dn: 'OU=Conference Rooms,OU=Workstations--Unrestricted,OU=Managed Systems,', read: '2026-10-13' }];

const RUNS_FILE = path.join(__dirname, 'data', 'intune-repair-runs.json');
const NAME_RE = /^[A-Za-z0-9-]{1,15}$/;
const DIGITS = /^\d{1,20}$/;
const WAITING = ['yet to apply', 'in progress', 'retry in progress'];
// a run in one of these states may still run on the PC, so it blocks another; a status not read could be one of them
function blocks(label) { return WAITING.indexOf(String(label).toLowerCase()) !== -1 || label === 'Not read' || label === 'Not confirmed'; }
// ME returns at most this many characters of a script's output (seen 2026-10-15: every long remark was exactly 500)
const ME_REMARKS_MAX = 500;

function codeErr(code, msg) { return Object.assign(new Error(msg), { code: code }); }
// NAME$ is the account-name form of NAME (Entra Connect writes some device records that way)
function key(name) { return String(name || '').split('.')[0].trim().toUpperCase().replace(/\$$/, ''); }
const SERVER_RE = /server/i;
function msOf(v) { const t = typeof v === 'number' ? v : (v ? Date.parse(v) : NaN); return isFinite(t) && t > 0 ? t : null; }
function src(label, request) { return { label: label, request: request, state: 'pending', http: null, ms: null, count: null, at: null, error: null }; }
function done(rec, t0, state, error) { rec.state = state; rec.error = error || null; rec.ms = Date.now() - t0; rec.at = Date.now(); return rec; }
// Long integers become strings before JSON.parse, so no ID loses its last digits.
function parseLong(text) { return JSON.parse(String(text).replace(/([:\[,]\s*)(-?\d{16,})(?=\s*[,\]}])/g, '$1"$2"')); }

// ── ManageEngine ────────────────────────────────────────────────────────────
let meTok = null, meTokP = null, meTokHold = 0;
async function meToken() {
  if (meTok && meTok.exp - 120000 > Date.now()) return meTok.value;
  if (Date.now() < meTokHold) throw codeErr('ME_TOKEN', 'ManageEngine sign-in was refused a few minutes ago; it is not retried until ' + new Date(meTokHold).toISOString().slice(11, 16) + 'Z, so the shared Zoho limit is not used up.');
  if (!meTokP) meTokP = fetchMeToken().finally(function () { meTokP = null; });
  return meTokP;
}
async function fetchMeToken() {
  const id = process.env.ME_CLIENT_ID, sec = process.env.ME_CLIENT_SECRET, rt = process.env.ME_REFRESH_TOKEN;
  if (!id || !sec || !rt || !process.env.ME_BASE_URL) throw codeErr('CONFIG', 'ManageEngine API credentials are not configured on this server.');
  const r = await fetch('https://accounts.zoho.com/oauth/v2/token', { method: 'POST',
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: rt, client_id: id, client_secret: sec }), signal: AbortSignal.timeout(20000) });
  const j = await r.json().catch(function () { return {}; });
  if (!r.ok || !j.access_token) {
    meTokHold = Date.now() + 10 * 60 * 1000;
    throw codeErr('ME_TOKEN', 'ManageEngine sign-in failed (' + String(j.error || ('HTTP ' + r.status)).slice(0, 80) + ').');
  }
  meTok = { value: j.access_token, exp: Date.now() + (Number(j.expires_in) || 3600) * 1000 };
  return meTok.value;
}
function meBase() { return String(process.env.ME_BASE_URL || '').replace(/\/+$/, ''); }
function meWhy(e) {
  if (e && (e.code === 'CONFIG' || e.code === 'ME_TOKEN')) return e.message;
  if (e && e.name === 'TimeoutError') return 'No answer within ' + (ME_TIMEOUT / 1000) + ' s';
  if (e && e.code === 'EDEVGUARD') return "Refused by this server's outbound guard; the request never reached ManageEngine";
  return 'ManageEngine read failed';
}
// One GET; a 429 is retried twice after 3 s and 8 s. Returns { http, body } or throws.
async function meGet(p, accept) {
  const bearer = await meToken();
  let r;
  for (let n = 0; n < 3; n++) {
    if (n) await new Promise(function (res) { setTimeout(res, n === 1 ? 3000 : 8000); });
    r = await fetch(meBase() + p, { headers: { Authorization: 'Zoho-oauthtoken ' + bearer, Accept: accept || 'application/json' }, signal: AbortSignal.timeout(ME_TIMEOUT) });
    if (r.status !== 429) break;
  }
  const text = await r.text();
  let body = null;
  try { body = parseLong(text); } catch (e) { body = null; }   // a Zoho sign-in page comes back as HTML with 200
  return { http: r.status, ok: r.ok && !!body, body: body };
}

const ME_AGENT = { 21: 'Agent not installed yet', 22: 'Agent installed', 23: 'Agent uninstalled', 29: 'Agent install failed' };
async function readMe() {
  const t0 = Date.now(), rec = src('ManageEngine computers', 'GET /api/1.4/som/computers');
  const out = [];
  try {
    let page = 1, total = null;
    while (page <= 20) {
      const r = await meGet('/api/1.4/som/computers?page=' + page + '&pagelimit=200');
      rec.http = r.http;
      const mr = r.ok && r.body && r.body.message_response;
      if (!mr || !Array.isArray(mr.computers)) return { rec: done(rec, t0, r.http === 401 || r.http === 403 ? 'denied' : 'error', r.ok ? 'Unexpected answer' : 'HTTP ' + r.http), items: null };
      mr.computers.forEach(function (c) { out.push(c); });
      // without a total there is no way to know the list is whole
      total = mr.total != null && isFinite(Number(mr.total)) ? Number(mr.total) : NaN;
      if (isNaN(total)) { done(rec, t0, 'partial', 'ManageEngine did not say how many computers it has'); rec.count = out.length; return { rec: rec, items: null }; }
      if (!mr.computers.length || out.length >= total) break;
      page++;
    }
    if (total != null && out.length < total) { done(rec, t0, 'partial', 'Stopped after ' + out.length + ' of ' + total); rec.count = out.length; }
    else { done(rec, t0, 'ok'); rec.count = out.length; }
  } catch (e) {
    return { rec: done(rec, t0, e && e.name === 'TimeoutError' ? 'timeout' : 'error', meWhy(e)), items: null };
  }
  const win = out.filter(function (c) { return String(c.os_platform) === '1'; }).map(function (c) {
    const inst = Number(c.installation_status), man = Number(c.managed_status);
    return {
      name: key(c.resource_name), rid: DIGITS.test(String(c.resource_id_string || '')) ? String(c.resource_id_string) : (DIGITS.test(String(c.resource_id)) ? String(c.resource_id) : null),
      install: inst, installText: ME_AGENT[inst] || ('Install status ' + inst), managed: man,
      reachable: inst === 22 && man === 61,
      live: Number(c.computer_live_status) === 1, lastContact: msOf(Number(c.agent_last_contact_time) || null),
      uninstalled: msOf(Number(c.agent_uninstalled_on) || null),
      domain: String(c.domain_netbios_name || ''), user: String(c.agent_logged_on_users || '').replace(/^--$/, ''),
      os: String(c.os_name || '').replace(/^--$/, ''), server: SERVER_RE.test(String(c.os_name || '')), mdm: String(c['modernappdetails.remarks'] || '').replace(/^--$/, ''),
      mdmContact: msOf(Number(c['modernappdetails.last_contact_time']) || null),
      branch: String(c.branch_office_name || '').replace(/^--$/, ''),
    };
  });
  rec.windows = win.length;
  return { rec: rec, items: win };
}

// ── AD ──────────────────────────────────────────────────────────────────────
function guidOf(b) {
  if (!b || b.length !== 16) return null;
  const h = b.toString('hex'), r = function (s) { return s.match(/../g).reverse().join(''); };
  return [r(h.slice(0, 8)), r(h.slice(8, 12)), r(h.slice(12, 16)), h.slice(16, 20), h.slice(20)].join('-');
}
function fileTime(v) {
  try { const n = BigInt(String(v || '0')); if (n <= 0n || n === 9223372036854775807n) return null; return Number(n / 10000n - 11644473600000n); }
  catch (e) { return null; }
}
function ouPath(dn) {
  return String(dn || '').split(/,(?=(?:OU|DC|CN)=)/i).filter(function (p) { return /^OU=/i.test(p); }).map(function (p) { return p.slice(3); }).reverse().join(' › ');
}
function readAd() {
  // every computer object, servers and objects with no OS too: "AD has no object" must mean none at all
  const t0 = Date.now(), rec = src('AD computers', 'LDAP (objectCategory=computer)');
  return new Promise(function (resolve) {
    let settled = false, client = null;
    const finish = function (state, error, items) {
      if (settled) return; settled = true;
      clearTimeout(timer);
      try { if (client) client.unbind(); } catch (e) { /* closing */ }
      done(rec, t0, state, error);
      if (items) { rec.objects = items.length; rec.count = items.filter(function (a) { return a.windows && !a.server; }).length; }
      resolve({ rec: rec, items: state === 'ok' ? items : null });
    };
    const timer = setTimeout(function () { finish('timeout', 'No answer within ' + (AD_TIMEOUT / 1000) + ' s'); }, AD_TIMEOUT);
    if (!process.env.LDAP_URL || !process.env.LDAP_BIND_USER || !process.env.LDAP_BIND_PASS) return finish('error', 'LDAP is not configured on this server.');
    try {
      client = ldapSecure.createClient({ url: process.env.LDAP_URL, timeout: 15000, connectTimeout: 8000 });
    } catch (e) { return finish('error', 'LDAP connection failed'); }
    client.on('error', function () { finish('error', 'LDAP connection failed'); });
    client.bind(process.env.LDAP_BIND_USER, process.env.LDAP_BIND_PASS, function (err) {
      if (err) return finish('denied', 'LDAP bind failed');
      const items = [];
      client.search(process.env.LDAP_BASE_DN || 'DC=nrpi,DC=local', {
        filter: '(objectCategory=computer)',
        attributes: ['cn', 'distinguishedName', 'objectGUID', 'lastLogonTimestamp', 'userAccountControl', 'operatingSystem', 'whenCreated'],
        scope: 'sub', paged: { pageSize: 500 },
      }, function (e, res) {
        if (e) return finish('error', 'LDAP search failed');
        res.on('searchEntry', function (en) {
          const a = {};
          en.attributes.forEach(function (x) { a[x.type] = x; });
          const v = function (k) { return a[k] && a[k].values && a[k].values.length ? String(a[k].values[0]) : ''; };
          const dn = v('distinguishedName'), uac = parseInt(v('userAccountControl'), 10) || 0;
          const unsynced = UNSYNCED_OUS.filter(function (o) { return dn.toUpperCase().indexOf(o.dn.toUpperCase()) !== -1; })[0] || null;
          items.push({ name: key(v('cn')), dn: dn, ou: ouPath(dn), guid: guidOf(a.objectGUID && a.objectGUID.buffers && a.objectGUID.buffers[0]),
            enabled: !(uac & 2), lastLogon: fileTime(v('lastLogonTimestamp')), os: v('operatingSystem'), unsyncedOu: unsynced ? unsynced.read : null,
            windows: /^windows/i.test(v('operatingSystem')), server: SERVER_RE.test(v('operatingSystem')) });
        });
        // A size-limit stop is a partial read, never a full one.
        res.on('error', function (e2) { finish(/size limit/i.test((e2 && e2.message) || '') ? 'partial' : 'error', /size limit/i.test((e2 && e2.message) || '') ? 'AD stopped at its size limit' : 'LDAP search failed', items); });
        res.on('end', function () { finish('ok', null, items); });
      });
    });
  });
}

// ── runs (collections deployed to ME) ──────────────────────────────────────
// A run ME may have queued without saying so (timeout, no collection ID) has cid null and blocks its PCs.
function runOk(r) { return !!(r && (DIGITS.test(String(r.cid || '')) || (r.cid === null && r.unconfirmed && Array.isArray(r.names) && r.names.length))); }
const memRuns = [];   // runs sent while the file could not be written; kept until the hub restarts
function loadRuns() {
  let raw;
  try { raw = fs.readFileSync(RUNS_FILE, 'utf8'); }
  catch (e) { if (e && e.code === 'ENOENT') return []; throw e; }
  const j = JSON.parse(raw);
  return Array.isArray(j.runs) ? j.runs.filter(runOk) : [];
}
function saveRun(run) {
  const runs = loadRuns().concat([run]).slice(-500);
  const tmp = RUNS_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify({ v: 1, runs: runs }), { mode: 0o640 });
  fs.renameSync(tmp, RUNS_FILE);
}
function allRuns() {
  let page = [];
  try { page = loadRuns(); } catch (e) { console.error('[patch-status] repair runs file unreadable:', e && e.message); }
  return SEED_RUNS.concat(page, memRuns.filter(function (m) { return !page.some(function (r) { return r.at === m.at && r.cid === m.cid; }); }));
}
function keepRun(run) {
  try { saveRun(run); return true; }
  catch (e) { memRuns.push(run); console.error('[patch-status] repair run not saved:', e && e.message); return false; }
}
const statusCache = new Map();   // cid -> { at, rows, http, error }
async function readStatus(cid, force) {
  const hit = statusCache.get(cid);
  if (hit && !force && Date.now() - hit.at < STATUS_MS) return hit;
  let out;
  try {
    const r = await meGet('/dcapi/configuration/' + cid + '/executionStatus', 'application/executionStatus.v1+json');
    const rows = r.ok && r.body && Array.isArray(r.body.execution_status) ? r.body.execution_status : null;
    out = { at: Date.now(), http: r.http, error: rows ? null : 'HTTP ' + r.http, rows: rows ? rows.map(function (x) {
      const rm = String(x.remarks || '').replace(/^--$/, '');
      // the script's last line is "RESULT exit=N msg"; when its output is longer than ME keeps, that line is not there
      const all = rm.match(/RESULT exit=(\d+)[^\S\n]*([^\n]*)/g), last = all ? all[all.length - 1].match(/RESULT exit=(\d+)[^\S\n]*([^\n]*)/) : null;
      return { name: key(x.resource_name), label: String(x.status_label || ''), remarks: rm.slice(0, 600),
        result: last ? { exit: Number(last[1]), msg: last[2].trim().slice(0, 200) } : null, cut: !last && rm.length >= ME_REMARKS_MAX,
        applied: String(x.applied_time || '').replace(/^--$/, '') };   // ME's display text in its own time zone; shown as is
    }) : (hit ? hit.rows : null) };
  } catch (e) {
    out = { at: Date.now(), http: null, error: meWhy(e), rows: hit ? hit.rows : null };
  }
  statusCache.set(cid, out);
  return out;
}
// Latest run per PC: { name -> { cid, at, by, label, remarks, result, cut, applied, statusAt, statusError } }
// and, apart from it, the newest run in the last QUEUED_DAYS that may still run on the PC: { name -> { cid, at, by, label } }.
// A newer run that failed does not cancel an older one ME still has queued.
async function runsByName(force) {
  const runs = allRuns(), recent = Date.now() - POLL_DAYS * DAY, byName = {}, blockers = {}, notes = [];
  const read = await Promise.all(runs.map(function (r) {
    if (!r.cid) return Promise.resolve({ run: r, s: null });   // unconfirmed: there is no collection to read
    return (r.at >= recent ? readStatus(r.cid, force) : Promise.resolve(statusCache.get(r.cid) || null)).then(function (s) { return { run: r, s: s }; });
  }));
  read.forEach(function (x) {
    // ME's rows, plus any PC this page sent that ME does not list (yet): its status is "Not read", never a guess
    const rows = x.s && x.s.rows ? x.s.rows.slice() : [];
    (x.run.names || []).forEach(function (n) { if (!rows.some(function (r) { return r.name === key(n); })) rows.push({ name: key(n), label: '', remarks: '', result: null, cut: false, applied: '' }); });
    if (x.s && x.s.error) notes.push({ cid: x.run.cid, at: x.run.at, error: x.s.error });
    rows.forEach(function (row) {
      const label = x.run.unconfirmed ? 'Not confirmed' : row.label || 'Not read';
      const b = blockers[row.name];
      if (blocks(label) && Date.now() - x.run.at < QUEUED_DAYS * DAY && !(b && b.at > x.run.at)) blockers[row.name] = { cid: x.run.cid, at: x.run.at, by: x.run.by || '', label: label };
      const prev = byName[row.name];
      if (prev && prev.at > x.run.at) return;
      byName[row.name] = { cid: x.run.cid, at: x.run.at, by: x.run.by || '', label: label, remarks: row.remarks, result: row.result || null, cut: !!row.cut, unconfirmed: x.run.unconfirmed || null,
        applied: row.applied, statusAt: x.s ? x.s.at : null, statusError: x.s ? x.s.error : 'Not read' };
    });
  });
  return { byName: byName, blockers: blockers, errors: notes, count: runs.length };
}

// ── the list ────────────────────────────────────────────────────────────────
// Every Windows PC known to AD, ME or Entra (joined, not registered), with the facts
// beside it. Reasons are decided from facts only; an unread source gives 'unknown'.
function build(snap, me, ad, runs) {
  const intuneOk = !!(snap && snap.devicesOk && snap.sources && snap.sources.intune && snap.sources.intune.state === 'ok');
  const entraOk = !!(snap && snap.entra && snap.sources && snap.sources.entra && snap.sources.entra.state === 'ok');
  const meOk = !!me, adOk = !!ad;
  const C = snap && snap.entraCols ? snap.entraCols : [];
  const ix = function (n) { return C.indexOf(n); };
  const E = entraOk ? snap.entra.map(function (e) {
    return { objectId: e[ix('objectId')], deviceId: e[ix('deviceId')], name: key(e[ix('name')]), os: e[ix('os')], trust: e[ix('trust')] || '',
      lastSignIn: e[ix('lastSignIn')], enabled: e[ix('enabled')] === 1, registered: e[ix('registered')] };
  }).filter(function (e) { return /^windows/i.test(e.os || '') && (e.trust === 'ServerAd' || e.trust === 'AzureAd'); }).map(function (e) { e.server = SERVER_RE.test(e.os); return e; }) : [];
  const I = intuneOk ? snap.devices : [];
  const iAad = {}, iName = {};
  I.forEach(function (d) { if (d.aad) iAad[String(d.aad).toLowerCase()] = d; if (d.name) iName[key(d.name)] = d; });
  const adBy = {}, meBy = {}, adGuid = {};
  (ad || []).forEach(function (a) { if (a.name) (adBy[a.name] = adBy[a.name] || []).push(a); if (a.guid) adGuid[a.guid] = a.name; });
  (me || []).forEach(function (m) { if (m.name) (meBy[m.name] = meBy[m.name] || []).push(m); });
  const eByDev = {}, eByName = {};
  E.forEach(function (e) {
    const did = String(e.deviceId || '').toLowerCase();
    if (did) eByDev[did] = e;
    // a record whose device ID is another computer's AD GUID belongs to that computer (it was renamed): it is found by GUID there
    if (did && adGuid[did] && adGuid[did] !== e.name) return;
    (eByName[e.name] = eByName[e.name] || []).push(e);
  });
  // Windows PCs only: a name any source calls a server is left out (AD is read whole, so its servers are known).
  // An AD object alone counts only when AD says it runs Windows.
  const names = {}, servers = {};
  Object.keys(adBy).concat(Object.keys(meBy), Object.keys(eByName)).forEach(function (n) {
    if (!n) return;
    const A = adBy[n] || [], M = meBy[n] || [], N = eByName[n] || [];
    if (A.some(function (a) { return a.server; }) || M.some(function (m) { return m.server; }) || N.some(function (e) { return e.server; })) { servers[n] = 1; return; }
    if (M.length || N.length || A.some(function (a) { return a.windows; })) names[n] = 1;
  });

  const rows = [], inIntune = [];
  // a recent run whose ME status was not read may have any of these PCs queued: nothing is runnable until it reads
  const statusGap = runs ? runs.errors.filter(function (e) { return Date.now() - e.at < QUEUED_DAYS * DAY; }).length : 0;
  Object.keys(names).sort().forEach(function (n) {
    const A = adBy[n] || [], M = meBy[n] || [];
    const a = A[0] || null, m = M[0] || null;
    // Entra records: the one whose device ID is the AD GUID, then any others with this name.
    const byGuid = a && a.guid ? eByDev[a.guid] || null : null;
    const ents = (byGuid ? [byGuid] : []).concat((eByName[n] || []).filter(function (e) { return e !== byGuid; }));
    const ids = ents.map(function (e) { return String(e.deviceId || '').toLowerCase(); }).filter(Boolean);
    if (a && a.guid) ids.unshift(a.guid);
    const hit = ids.map(function (id) { return iAad[id]; }).filter(Boolean)[0] || iName[n] || null;
    if (intuneOk && hit) { inIntune.push({ name: n, id: hit.id, enrolled: hit.enrolled || null, by: ids.some(function (id) { return iAad[id] === hit; }) ? 'device ID' : 'name' }); return; }

    const lastSeen = Math.max(a && a.lastLogon || 0, m && m.lastContact || 0, ents.reduce(function (t, e) { return Math.max(t, e.lastSignIn || 0); }, 0)) || null;
    // why it is not in Intune
    let reason;
    const hyb = byGuid && byGuid.trust === 'ServerAd' ? byGuid : null;
    const ej = ents.filter(function (e) { return e.trust === 'AzureAd'; })[0] || null;
    if (!adOk || !entraOk) reason = 'unknown';
    else if (a && !a.enabled) reason = 'ad_disabled';
    else if (a && hyb && !hyb.enabled) reason = 'entra_disabled';
    else if (a && hyb) reason = 'hybrid';
    else if (a && a.unsyncedOu) reason = 'unsynced_ou';
    else if (a) reason = 'not_synced';
    else if (ej && ej.enabled) reason = 'entra_joined';
    else if (ents.length) reason = 'ad_gone';
    else if (m && /^nrpi$/i.test(m.domain)) reason = 'me_domain_no_ad';
    else if (m && /^workgroup$/i.test(m.domain)) reason = 'workgroup';
    else if (m && m.domain) reason = 'other_domain';
    else if (m) reason = 'me_no_domain';
    else reason = 'unknown';
    // which route can reach it
    const route = !meOk ? 'unknown' : !m ? 'none' : m.reachable ? 'me' : 'me_agent_gone';
    const pin = PINS[n] || null;
    const pinMatch = !!(pin && (ids.indexOf(pin) !== -1));
    // two records with one name: which one the run would reach is not known
    const ambiguous = A.length > 1 || M.length > 1;
    const lr = runs && runs.byName[n] ? runs.byName[n] : null;
    // any run ME may still have queued or running blocks another, not only the latest (the run route refuses it too)
    const blockedBy = runs && runs.blockers[n] ? runs.blockers[n] : null;
    const waiting = !!blockedBy;
    rows.push({
      name: n, reason: reason, route: route, lastSeen: lastSeen,
      ad: a ? { ou: a.ou, enabled: a.enabled, lastLogon: a.lastLogon, guid: a.guid, os: a.os, unsyncedOu: a.unsyncedOu, dupes: A.length - 1 } : null,
      me: m ? { rid: m.rid, installText: m.installText, reachable: m.reachable, live: m.live, lastContact: m.lastContact, uninstalled: m.uninstalled,
        domain: m.domain, user: m.user, os: m.os, mdm: m.mdm, branch: m.branch, dupes: M.length - 1 } : null,
      entra: ents.slice(0, 6).map(function (e) { return { objectId: e.objectId, deviceId: e.deviceId, trust: e.trust, enabled: e.enabled, lastSignIn: e.lastSignIn, byGuid: e === byGuid }; }),
      entraMore: Math.max(0, ents.length - 6),
      pin: pin ? { listed: true, match: pinMatch } : { listed: false, match: false },
      // the run route needs AD and Entra read in full too, so a row is only offered when they were
      runnable: adOk && entraOk && route === 'me' && pinMatch && !!(m && m.rid) && !ambiguous && !waiting && !statusGap, waiting: waiting, ambiguous: ambiguous,
      lastRun: lr, blockedBy: blockedBy,
    });
  });
  // PCs a repair run reached that are in Intune now
  const repaired = runs ? inIntune.filter(function (x) { return runs.byName[x.name]; }).map(function (x) {
    const r = runs.byName[x.name];
    // Intune's enrolment time against the run: an earlier one means it was enrolled before this run reached it
    return { name: x.name, id: x.id, enrolled: x.enrolled, matchedBy: x.by, enrolledAfterRun: x.enrolled ? x.enrolled > r.at : null, run: { cid: r.cid, at: r.at, by: r.by, label: r.label } };
  }).sort(function (p, q) { return (q.enrolled || 0) - (p.enrolled || 0); }) : [];
  return { intuneOk: intuneOk, entraOk: entraOk, meOk: meOk, adOk: adOk, rows: intuneOk ? rows : null, known: Object.keys(names).length,
    inIntune: intuneOk ? inIntune.length : null, repaired: repaired, runStatusGap: statusGap, servers: Object.keys(servers).length };
}

// ── mount ───────────────────────────────────────────────────────────────────
module.exports = function mountRepair(router, ctx) {
  const rbac = ctx.rbac, SA = ctx.SA;
  function canRun(u) { return !!(u && u.isSuperAdmin === true && !u.readOnly); }
  let cache = null, inflight = null, lastTry = 0, running = false;

  async function collect(force) {
    const snap = await ctx.snapshot();
    const [me, ad, runs] = await Promise.all([readMe(), readAd(), runsByName(force)]);
    const b = build(snap, me.items, ad.items, runs);
    return Object.assign({ at: Date.now(), snapAt: snap ? snap.at : null,
      sources: { intune: snap && snap.sources ? snap.sources.intune : null, entra: snap && snap.sources ? snap.sources.entra : null, me: me.rec, ad: ad.rec },
      runErrors: runs.errors, runCount: runs.count }, b);
  }
  function refresh(force) {
    if (!inflight) {
      lastTry = Date.now();
      inflight = collect(force).then(function (x) { cache = x; return x; }).finally(function () { inflight = null; });
    }
    return inflight;
  }

  router.get('/repair', async function (req, res) {
    try {
      const force = req.query.refresh === '1';
      const age = cache ? Date.now() - cache.at : Infinity, sinceTry = Date.now() - lastTry;
      if (!cache || (age > CACHE_MS && sinceTry > CACHE_MS) || (force && age > MIN_FORCE_MS && sinceTry > MIN_FORCE_MS)) await refresh(force);
      res.set('Cache-Control', 'no-store');
      res.json(Object.assign({ ok: true, now: Date.now(), cacheMs: CACHE_MS, minForceMs: MIN_FORCE_MS, canRun: canRun(req.user), maxTargets: MAX_TARGETS,
        template: TEMPLATE, script: Object.assign({ pinned: Object.keys(PINS).length }, SCRIPT), running: running }, cache));
    } catch (e) {
      console.error('[patch-status] repair read failed:', e && e.message);
      res.status(500).json({ ok: false, error: 'INTERNAL' });
    }
  });

  // Runs the pinned ME template on up to five PCs. Every check is made again here.
  router.post('/repair/run', rbac.requireSuperAdmin, express.json({ limit: '4kb' }), async function (req, res) {
    if (!canRun(req.user)) return res.status(403).json({ ok: false, error: 'FORBIDDEN', detail: 'Running a repair is limited to super-admins.' });
    const raw = req.body && Array.isArray(req.body.names) ? req.body.names : null;
    if (!raw || !raw.length || raw.length > MAX_TARGETS || !raw.every(function (n) { return typeof n === 'string' && NAME_RE.test(n); }))
      return res.status(400).json({ ok: false, error: 'INVALID', detail: 'Send 1 to ' + MAX_TARGETS + ' computer names.' });
    const names = raw.map(key).filter(function (n, i, all) { return all.indexOf(n) === i; });
    if (running) return res.status(409).json({ ok: false, error: 'BUSY', detail: 'Another repair run is being sent. Try again in a minute.' });
    running = true;
    const audit = function (ok, extra) {
      return SA.record(rbac, req, 'patch-status', ok ? 'intune_repair_deployed' : ok === null ? 'intune_repair_deploy_unconfirmed' : 'intune_repair_deploy_failed',
        SA.entry({ what: 'intune repair script', op: 'deploy', id: extra.collection_id || null, subject: names.join(', '),
          extra: Object.assign({ template_id: TEMPLATE.id, script_stamp: SCRIPT.stamp }, extra) }));
    };
    try {
      // fresh facts for exactly these PCs: ME and AD are re-read, Intune comes from the snapshot
      // its own read: a GET already under way may have read the runs file before another run was saved
      const x = await collect(true);
      cache = x;
      if (!x.rows) return res.status(503).json({ ok: false, error: 'NOT_READ', detail: 'The Intune device list was not read in full, so nothing can be called missing.' });
      if (!x.meOk) return res.status(503).json({ ok: false, error: 'NOT_READ', detail: 'ManageEngine was not read: ' + (x.sources.me && x.sources.me.error || 'error') });
      if (!x.adOk || !x.entraOk) return res.status(503).json({ ok: false, error: 'NOT_READ', detail: (!x.adOk ? 'AD' : 'Entra') + ' was not read in full, so why these PCs are missing is not known. Nothing was sent.' });
      if (x.runStatusGap) return res.status(503).json({ ok: false, error: 'NOT_READ', detail: "ManageEngine's status for a run sent in the last " + QUEUED_DAYS + ' days was not read, so a PC could already be queued. Nothing was sent.' });
      const pick = names.map(function (n) { return x.rows.filter(function (r) { return r.name === n; })[0] || null; });
      const bad = [];
      names.forEach(function (n, i) {
        const r = pick[i];
        if (!r) bad.push(n + ': not on the list now (in Intune, or no longer known)');
        else if (r.route !== 'me') bad.push(n + ": ManageEngine's agent is not installed");
        else if (!r.pin.listed) bad.push(n + ": not one of the PCs pinned in the script, which would stop without changing anything");
        else if (!r.pin.match) bad.push(n + ": its Entra device ID is not the one pinned in the script");
        else if (r.ambiguous) bad.push(n + ': ' + (r.me.dupes ? (r.me.dupes + 1) + ' ManageEngine records' : (r.ad.dupes + 1) + ' AD objects') + ' have this name, so which one the run would reach is not known');
        else if (r.waiting) bad.push(n + ': a run sent ' + new Date(r.blockedBy.at).toISOString().slice(0, 16) + 'Z ' + (r.blockedBy.label === 'Not read' ? 'has not been read back from ManageEngine yet'
          : r.blockedBy.label === 'Not confirmed' ? 'was not confirmed by ManageEngine (it may be queued); check ManageEngine. It blocks another run for ' + QUEUED_DAYS + ' days'
          : 'is waiting in ManageEngine (' + r.blockedBy.label + ')'));
        else if (!r.runnable) bad.push(n + ': no ManageEngine resource ID');
      });
      if (bad.length) return res.status(409).json({ ok: false, error: 'REFUSED', detail: bad });
      // the template must still be the one tested: same id, same name, a Windows computer configuration
      let tpl = null, off = 0;
      for (let n = 0; n < 10; n++) {
        const r = await meGet('/dcapi/configuration/templates?offset=' + off + '&limit=100', 'application/configTemplates.v1+json');
        const L = r.ok && r.body && Array.isArray(r.body.templates) ? r.body.templates : null;
        if (!L) return res.status(502).json({ ok: false, error: 'READ_FAILED', detail: 'ManageEngine templates could not be read (HTTP ' + r.http + ').' });
        tpl = L.filter(function (t) { return String(t.template_id) === TEMPLATE.id; })[0] || tpl;
        if (tpl || !r.body.has_more_records || !L.length) break;
        off += L.length;
      }
      if (!tpl || String(tpl.name || '').trim() !== TEMPLATE.name || tpl.os_type !== 'windows' || tpl.type !== 'computer')
        return res.status(409).json({ ok: false, error: 'TEMPLATE_CHANGED', detail: 'ManageEngine template ' + TEMPLATE.id + ' is ' + (tpl ? 'now "' + tpl.name + '" (' + tpl.os_type + ' ' + tpl.type + ')' : 'gone') + '. Nothing was sent.' });
      const rids = pick.map(function (r) { return r.me.rid; });
      if (!rids.every(function (v) { return DIGITS.test(v); })) return res.status(500).json({ ok: false, error: 'INTERNAL' });
      // written by hand: the IDs must reach ME as exact integers
      const body = '{"deployImmediate":true,"templateId":' + TEMPLATE.id + ',"targets":{"type":"computer","values":[' + rids.join(',') + '],"isDomainMainTarget":false}}';
      let http = null, text = '', bearer;
      try { bearer = await meToken(); }
      catch (e) {
        await audit(false, { error: 'ME_TOKEN', resource_ids: rids.join(',') });
        return res.status(502).json({ ok: false, error: 'ME_TOKEN', detail: meWhy(e) + ' Nothing was sent.' });
      }
      // ME may have queued a run it did not confirm: it is kept, unconfirmed, and blocks these PCs
      const unconfirmed = async function (why, extra) {
        const run = { cid: null, unconfirmed: why, at: Date.now(), by: (req.user && req.user.email) || '', names: names, rids: rids };
        const saved = keepRun(run);
        await audit(null, Object.assign({ error: why, resource_ids: rids.join(','), run_saved: saved }, extra));
        cache = null;
      };
      try {
        const r = await fetch(meBase() + '/dcapi/configuration/deploy/template', { method: 'POST', body: body, signal: AbortSignal.timeout(ME_TIMEOUT),
          headers: { Authorization: 'Zoho-oauthtoken ' + bearer, 'Content-Type': 'application/deployConfigurationTemplate.v1+json', Accept: 'application/configDeployTemplateStatus.v1+json' } });
        http = r.status; text = await r.text();
      } catch (e) {
        const guard = e && e.code === 'EDEVGUARD', timeout = e && e.name === 'TimeoutError';
        if (guard) {
          await audit(false, { error: 'GUARD', resource_ids: rids.join(',') });
          return res.status(503).json({ ok: false, error: 'GUARD', detail: "This server's outbound guard refused the deploy. Nothing reached ManageEngine." });
        }
        // a dropped connection can happen after ME took the request: not known either way
        await unconfirmed(timeout ? 'TIMEOUT' : 'NETWORK');
        return res.status(502).json({ ok: false, error: timeout ? 'TIMEOUT' : 'NETWORK', detail: (timeout ? 'ManageEngine did not answer in time.' : 'The connection to ManageEngine failed.')
          + ' The run may have been queued; check ManageEngine. These PCs cannot be sent another run from this page for ' + QUEUED_DAYS + ' days.' });
      }
      const m = /"collectionId"\s*:\s*"?(\d{1,20})"?/.exec(text);
      if (http >= 200 && http < 300 && !m) {
        await unconfirmed('NO_ID', { http: http });
        return res.status(502).json({ ok: false, error: 'NOT_CONFIRMED', http: http, detail: 'ManageEngine answered (HTTP ' + http + ') without a collection ID, so whether it queued the run is not known. Check ManageEngine. These PCs cannot be sent another run from this page for ' + QUEUED_DAYS + ' days.' });
      }
      if (!(http >= 200 && http < 300)) {
        let msg = '';
        try { const j = parseLong(text); msg = String((j && (j.error_description || j.message || (j.message_response && j.message_response.error) || j.error_code)) || ''); } catch (e) { msg = ''; }
        msg = (msg || text.replace(/\s+/g, ' ')).slice(0, 300);
        await audit(false, { http: http, error: msg, resource_ids: rids.join(',') });
        return res.status(502).json({ ok: false, error: 'ME_REFUSED', http: http, detail: 'ManageEngine did not queue the run (HTTP ' + http + '): ' + msg });
      }
      const run = { cid: m[1], at: Date.now(), by: (req.user && req.user.email) || '', names: names, rids: rids };
      const saved = keepRun(run);
      await audit(true, { collection_id: run.cid, http: http, resource_ids: rids.join(','), run_saved: saved });
      cache = null;   // the next read shows the run
      res.json({ ok: true, collectionId: run.cid, names: names, saved: saved, at: run.at });
    } catch (e) {
      console.error('[patch-status] repair run failed:', e && e.message);
      res.status(500).json({ ok: false, error: 'INTERNAL' });
    } finally {
      running = false;
    }
  });
};

// for the offline test
module.exports._test = { build: build, parseLong: parseLong, guidOf: guidOf, ouPath: ouPath, key: key, PINS: PINS };
