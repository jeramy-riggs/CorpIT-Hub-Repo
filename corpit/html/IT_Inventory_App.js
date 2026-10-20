// ============================================================
// CLIENT ERROR CAPTURE
// ============================================================
// This console had no window.onerror, no unhandledrejection handler and no
// .catch on init(), so a throw anywhere produced a half-rendered page, a silent
// console and no ticket — the break was invisible, so nobody reported it and it
// never got fixed. This block is the first thing in the file so it also sees
// failures in everything parsed after it (the UX enhancements layer, the inline
// Mission Control blocks, the deferred it-version.js and it-topbar.js). Scripts
// parsed BEFORE it — it-theme.js, it-theme-toggle.js, inventory-config.js,
// rbac-client.js and the SheetJS CDN tag — are out of reach for their own
// load/parse failures; that is the price of not adding a new <script> tag while
// the CSP promotion for this vhost is still being sequenced separately. (A
// missing SheetJS is covered instead by xlsxReady() and by Run Diagnostics.)
//
// Client-side only, deliberately. /api/bugs on :3001 is the human bug-report
// intake (nginx gives it a 12M body for attachments), not a telemetry sink:
// beaconing every render throw there would bury a queue people actually read,
// and this platform has no endpoint shaped for machine error reports. The
// evidence therefore lives in window.__invErrors and is surfaced in the page's
// own Run Diagnostics panel.
(function () {
  'use strict';
  const MAX_ERRORS = 50;     // bounded — a render loop must not be able to eat memory
  const QUIET_MS   = 60000;  // a repeating error is shown once a minute, not once a tick
  const surfaced = new Map();
  const buf = [];
  window.__invErrors = buf;

  // Persistent, dismissible bar. A toast auto-hides after 2.8s, which is fine
  // for 'sync failed' and useless for 'this page is showing you wrong numbers'.
  function errorBar(latest) {
    if (!document.body) return;   // threw before <body> existed — console + buffer only
    let bar = document.getElementById('inv-err-bar');
    if (!bar) {
      bar = document.createElement('div');
      bar.id = 'inv-err-bar';
      bar.setAttribute('role', 'alert');
      // Every style below is set through the CSSOM rather than a style=""
      // attribute, so this survives a strict style-src when CSP is promoted.
      const s = bar.style;
      s.position = 'fixed'; s.top = '0'; s.left = '0'; s.right = '0'; s.zIndex = '9999';
      s.display = 'flex'; s.gap = '12px'; s.alignItems = 'center';
      s.padding = '9px 14px';
      s.background = '#7f1d1d'; s.color = '#fff';
      s.font = '600 12px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif';
      const txt = document.createElement('span');
      txt.id = 'inv-err-bar-msg';
      txt.style.flex = '1';
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.textContent = 'Dismiss';
      btn.setAttribute('aria-label', 'Dismiss error notice');
      btn.style.background = 'transparent';
      btn.style.color = 'inherit';
      btn.style.font = 'inherit';
      btn.style.border = '1px solid rgba(255,255,255,.55)';
      btn.style.borderRadius = '4px';
      btn.style.padding = '3px 10px';
      btn.style.cursor = 'pointer';
      btn.addEventListener('click', () => bar.remove());
      bar.appendChild(txt);
      bar.appendChild(btn);
      document.body.appendChild(bar);
    }
    const msgEl = document.getElementById('inv-err-bar-msg');
    if (msgEl) {
      msgEl.textContent = 'This page hit an error and may be showing incomplete data — reload, and tell IT if it repeats. ('
        + buf.length + (buf.length === 1 ? ' error' : ' errors') + ' this session · latest: ' + latest + ')';
    }
  }

  // The single entry point. Anything that catches an error it cannot actually
  // handle calls this instead of swallowing it: window.__invErr('where', err).
  window.__invErr = function (source, err) {
    const msg = String((err && (err.message || err.reason)) || err || 'unknown error');
    // `currentPage` is a top-level `let` declared further down this file, so an
    // early enough error reads it inside the temporal dead zone — where even
    // `typeof` throws. Read it defensively.
    let page = null;
    try { page = currentPage; } catch (e) {}
    const rec = {
      source: source || 'unknown',
      msg,
      stack: (err && err.stack) || null,
      page,
      url: location.href,
      ts: new Date().toISOString(),
    };
    buf.push(rec);
    if (buf.length > MAX_ERRORS) buf.shift();
    console.error('[inv] ' + rec.source + ':', err);
    // Surface once per unique message per minute. Mission Control re-renders
    // every 30s: a permanently broken panel must not repaint an alarm on every
    // tick forever.
    const key = rec.source + '|' + msg;
    const now = Date.now();
    const last = surfaced.get(key);
    if (last && (now - last) < QUIET_MS) return rec;
    surfaced.set(key, now);
    // The reporter itself must never throw — that would re-enter this handler.
    try { errorBar(msg); } catch (e) {}
    try { if (typeof showToast === 'function') showToast('Error: ' + msg, 'err'); } catch (e) {}
    return rec;
  };

  // Capture phase, because a failed <script>/<link> fires its error event on the
  // element and does not bubble. Those carry no .error.
  window.addEventListener('error', (e) => {
    if (!e) return;
    const tgt = e.target;
    if (e.error) {
      window.__invErr('window.onerror', e.error);
    } else if (tgt && tgt !== window && (tgt.src || tgt.href)) {
      // Only <script>/<link> — a broken one of those is worth a report, because
      // 'failed to load it-topbar.js' beats the downstream symptoms it becomes.
      // Deliberately NOT other elements: it-topbar's avatar <img> 404s BY DESIGN
      // for anyone with no Entra photo and removes itself in its own error
      // handler, so reporting it would raise the red bar on every healthy load —
      // which is exactly how a warning gets trained into background noise.
      if (tgt.tagName === 'SCRIPT' || tgt.tagName === 'LINK') {
        window.__invErr('resource', new Error('failed to load ' + (tgt.src || tgt.href)));
      }
    } else {
      window.__invErr('window.onerror', new Error((e.message || 'script error') + ' @ ' + (e.filename || '?') + ':' + (e.lineno || 0)));
    }
  }, true);

  window.addEventListener('unhandledrejection', (e) => {
    window.__invErr('unhandledrejection', (e && e.reason) || e);
  });
})();

// ============================================================
// API CONFIG
// ============================================================
// Resilient bootstrap: inventory-config.js is the single source of truth, but a
// BARE window.INVENTORY_API.base would throw at parse time if that file failed to
// load - taking every function in this file with it and leaving an inert page.
// The fallback derives from origin (the same expression the config file uses), so
// unlike the hardcoded itam.nrpi.local fallbacks this replaced, it cannot go stale.
const _INV_API      = (window.INVENTORY_API || { base: window.location.origin, hub: window.location.origin + '/hub-api' });
const API_BASE      = _INV_API.base;
const WARRANTY_BASE = _INV_API.hub;
// SECURITY: an IMPORT_KEY constant used to sit here in plain client JS, so any
// browser visitor could read it from page source and call /api/*/import/bulk to
// overwrite the database. It is now gone from BOTH ends — there is no client
// constant, and no server component reads an x-import-key header any more
// (checked against BACKEND-core-api-server.js and the nginx vhost: zero hits).
// Bulk import authenticates on the it_session cookie plus the server-side CSRF
// origin check. The empty-string constant that survived the first cleanup was
// deleted 2026-09-03 — it made `if (IMPORT_KEY)` read like a live credential
// scheme when both ends of it were already gone. Do not reintroduce a key here;
// if a credential is ever needed it belongs in a server-side proxy.

// ── ABM warranty enrichment (read-through cache) ──
let ABM_WARRANTY_MAP = null;
let ABM_WARRANTY_PROMISE = null;
let ABM_WARRANTY_ERROR = false;
// Absence-as-fact guard. ABM only covers devices enrolled in Apple Business
// Manager, so "this serial is not in the feed" is UNKNOWN coverage, not expired
// coverage. ABM_WARRANTY_LOADED says the request finished (so a blank cell is
// no longer indistinguishable from still-loading) and ABM_WARRANTY_COUNT says
// how much the feed actually returned - a 200 carrying zero devices is a feed
// problem, not a fleet of dead warranties.
let ABM_WARRANTY_LOADED = false;
let ABM_WARRANTY_COUNT = 0;
async function loadAbmWarrantyMap() {
  // Cache the promise (not the result) so concurrent callers share the in-flight
  // fetch instead of getting an empty Map back from a still-loading first call.
  if (ABM_WARRANTY_PROMISE) return ABM_WARRANTY_PROMISE;
  ABM_WARRANTY_PROMISE = (async () => {
    const map = new Map();
    try {
      const res = await fetch(`${WARRANTY_BASE}/api/abm/devices?limit=5000`);
      if (!res.ok) { ABM_WARRANTY_ERROR = true; return map; }
      const data = await res.json();
      (data.devices || []).forEach(d => {
        map.set(d.serial_number, {
          active_coverages: parseInt(d.active_coverages) || 0,
          coverage_ends: d.coverage_ends || null,
        });
      });
      ABM_WARRANTY_ERROR = false;
    } catch (e) {
      ABM_WARRANTY_ERROR = true;
      console.warn('loadAbmWarrantyMap failed:', e && e.message);
    }
    ABM_WARRANTY_MAP = map;
    ABM_WARRANTY_COUNT = map.size;
    // buildLifecycleData()'s Apple warranty fallback reads this map.
    bumpDataVersion();
    // Set on the success AND the failure path: the request is over either way,
    // and the cell renderer needs that to stop treating a miss as "still loading".
    ABM_WARRANTY_LOADED = true;
    return map;
  })();
  return ABM_WARRANTY_PROMISE;
}
function abmWarrantyCell(serial) {
  if (!ABM_WARRANTY_MAP || !serial) return '<td><span style="color:var(--text3)">—</span></td>';
  const w = ABM_WARRANTY_MAP.get(serial);
  if (!w) {
    if (ABM_WARRANTY_ERROR) return '<td><span class="badge badge-yellow" title="Warranty data unavailable — backend error">⚠ Unavailable</span></td>';
    // A 200 carrying zero devices means the feed is broken, not that every Mac
    // and iPad in the fleet is out of warranty. Say unavailable, per row.
    if (ABM_WARRANTY_LOADED && ABM_WARRANTY_COUNT === 0) return '<td><span class="badge badge-yellow" title="Apple Business Manager returned no devices — coverage unknown for the whole fleet">⚠ Unavailable</span></td>';
    // The serial was simply absent from the feed. This used to render a red
    // "Expired" badge - a confident negative statement about a company asset
    // that the data never supported, on the exact column an asset manager
    // scans to decide what to replace or claim against. Neutral grey instead,
    // with the reason in the title.
    return '<td><span class="badge badge-gray" title="Serial not found in the Apple Business Manager feed — coverage unknown, not expired">— not in ABM</span></td>';
  }
  if (w.active_coverages === 0) return '<td><span class="badge badge-red">Expired</span></td>';
  if (!w.coverage_ends) return '<td><span class="badge badge-green">Active</span></td>';
  const days = Math.floor((new Date(w.coverage_ends) - Date.now()) / 86400000);
  if (days < 0) return '<td><span class="badge badge-red">Expired</span></td>';
  if (days <= 30) return `<td><span class="badge badge-red">${days}d left</span></td>`;
  if (days <= 180) return `<td><span class="badge badge-amber">${days}d left</span></td>`;
  const dt = new Date(w.coverage_ends).toLocaleDateString('en-US', {month:'short', year:'numeric'});
  return `<td><span class="badge badge-green">Active · ${dt}</span></td>`;
}

// Coverage line for the MacBooks / iPads tables. Rows the ABM feed did not
// answer for now read "not in ABM"; without this line an operator has no way to
// tell a genuine gap in Apple Business Manager enrolment from a broken feed,
// and no number anywhere on screen says how much of the fleet ABM covered.
function renderAbmCoverageNotice(elId, rows) {
  const el = document.getElementById(elId);
  if (!el) return;
  if (!ABM_WARRANTY_LOADED) { el.innerHTML = ''; return; } // still in flight — claim nothing
  if (ABM_WARRANTY_ERROR) {
    el.innerHTML = '<div class="data-gap-notice">⚠ Apple Business Manager warranty feed unavailable (backend error) — the Warranty column below is unknown for every row, not expired.</div>';
    _degrade('abm-warranty-feed:' + elId, 'Apple Business Manager warranty feed unavailable', String(ABM_WARRANTY_ERROR));
    return;
  }
  if (ABM_WARRANTY_COUNT === 0) {
    el.innerHTML = '<div class="data-gap-notice">⚠ Apple Business Manager returned no devices — the Warranty column below is unknown for every row, not expired.</div>';
    return;
  }
  const withSerial = (rows || []).filter(r => r && r['Serial']);
  const covered = withSerial.filter(r => ABM_WARRANTY_MAP.get(r['Serial'])).length;
  el.innerHTML = covered < withSerial.length
    ? `<div class="data-gap-notice">⚠ Apple Business Manager warranty covers ${covered} of ${withSerial.length} devices here — the rest read "not in ABM", which means coverage is unknown, not expired.</div>`
    : '';
}

// ── Shared data accessor — single source of truth for table→array mapping ──
function getDataArr(key) {
  const map = {
    employees:   DATA.activeEmployees,
    terms:       DATA.terms,
    intune:      DATA.intuneDevices,
    macbooks:    DATA.macbooks,
    endpoints:   DATA.endpoints,
    liveauction: DATA.liveAuction,
    tmobile:     DATA.tmobile,
    verizon:     DATA.verizon,
    aws:         DATA.awsWorkspaces,
    ipads:                DATA.ipadDevices,
    tablets:              DATA.tablets,
  };
  return map[key];
}

async function apiGet(route, params = {}) {
  const url = new URL(`${API_BASE}/api/${route}`);
  Object.entries(params).forEach(([k,v]) => url.searchParams.set(k, v));
  const res = await fetch(url);
  if (!res.ok) throw new Error(`API error ${res.status}`);
  return res.json();
}

async function apiPost(route, body) {
  const res = await fetch(`${API_BASE}/api/${route}`, {
    method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body)
  });
  if (!res.ok) throw new Error(`API error ${res.status}`);
  return res.json();
}

async function apiPut(route, id, body) {
  const res = await fetch(`${API_BASE}/api/${route}/${id}`, {
    method: 'PUT', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body)
  });
  if (!res.ok) throw new Error(`API error ${res.status}`);
  return res.json();
}

async function apiDelete(route, id) {
  const res = await fetch(`${API_BASE}/api/${route}/${id}`, { method: 'DELETE' });
  if (!res.ok) throw new Error(`API error ${res.status}`);
  return res.json();
}

async function apiBulkImport(route, records) {
  // Auth here is the it_session cookie (credentials:'include' below) plus the
  // server-side CSRF origin check — no header credential is sent, and none is
  // read. The `if (IMPORT_KEY)` line that used to follow was removed 2026-09-03
  // together with the constant: it was permanently false, and an unreachable
  // credential branch is how the next reader mis-reads the security posture.
  const headers = {'Content-Type':'application/json'};
  const res = await fetch(`${API_BASE}/api/${route}/import/bulk`, {
    method: 'POST',
    credentials: 'include',
    headers,
    body: JSON.stringify(records)
  });
  if (!res.ok) throw new Error(`API error ${res.status}`);
  return res.json();
}

// ============================================================
// STATE
// ============================================================
let DATA = {};
const inventoryLoadState={phase:'loading',sources:{}};
let currentPage = 'dashboard';
let sortState = {};
let searchQuery = '';

// ── SHARED CACHE GENERATION ─────────────────────────────────────────────────
// ONE counter behind every derived cache in this file: the device universe
// (buildDeviceUniverse), the lifecycle rows (buildLifecycleData), the join
// indexes (buildDeviceLookup, buildVerizonIntuneMap, buildTabletIntuneMap,
// _buildEpModelFromIntune) and the per-row search haystacks. Each cache stores
// the DATA_VERSION it was built at and rebuilds as soon as the numbers differ.
//
// bumpDataVersion() MUST be called at EVERY point where a DATA.* array is
// REPLACED or its row objects are MUTATED IN PLACE — init(), triggerIntuneSync,
// triggerKandjiSync, refreshEndpoints, loadPatchHealthCache's write-back,
// saveModal, deleteRecord, both confirmImport paths — and at the two warranty
// map loads the lifecycle rows are derived from. A cache that misses one of
// those points shows stale asset data as current, with no error: worse than no
// cache at all. Add a bump in the same commit as any new write path.
let DATA_VERSION = 0;
function bumpDataVersion() { DATA_VERSION++; }

// One collator for the whole app. String.prototype.localeCompare constructs a
// collator per call in most engines, which dominates a 3,300-row sort.
const _COLLATOR = (typeof Intl !== 'undefined' && Intl.Collator) ? new Intl.Collator() : null;
function cmpText(a, b) {
  return _COLLATOR ? _COLLATOR.compare(String(a), String(b)) : String(a).localeCompare(String(b));
}

// Per-row search haystack. Held in a WeakMap rather than written onto the row:
// exportCSV() and exportAll() derive their headers from Object.keys(rows[0]),
// so an added property would show up as a column in every export. Entries are
// stamped with DATA_VERSION and are collected with the row.
const _HAY_CACHE = new WeakMap();
// U+0001 joins the values. It cannot appear in a typed query, so a match can
// never straddle two fields the way a plain concatenation would allow.
const _HAY_SEP = String.fromCharCode(1);
function rowHaystack(r) {
  if (!r || typeof r !== 'object') return String(r == null ? '' : r).toLowerCase();
  const hit = _HAY_CACHE.get(r);
  if (hit && hit.v === DATA_VERSION) return hit.s;
  let s = '';
  const vals = Object.values(r);
  for (let i = 0; i < vals.length; i++) {
    const v = vals[i];
    if (v) s += String(v).toLowerCase() + _HAY_SEP;  // `if (v)` keeps the old per-value truthiness test
  }
  _HAY_CACHE.set(r, { v: DATA_VERSION, s });
  return s;
}

const PAGE_SIZE = 25;
let pages = {
  employees: 1, terms: 1, intune: 1, macbooks: 1, endpoints: 1,
  liveauction: 1, tmobile: 1, verizon: 1, aws: 1, lifecycle: 1, warranty: 1, ipads: 1,
  tablets: 1, 'device-inventory': 1
};

// ============================================================
// INIT — API mode or embedded data mode
// ============================================================
async function apiGetWithTimeout(route, ms=5000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    const url = new URL(`${API_BASE}/api/${route}`);
    const res = await fetch(url, { signal: controller.signal });
    clearTimeout(timer);
    if (!res.ok) throw new Error(`API error ${res.status}`);
    return res.json();
  } catch(e) {
    clearTimeout(timer);
    throw e;
  }
}

// Default empty shape used when the API is unreachable or any individual
// route returns a non-array body. Centralized so every consumer sees the
// same keys regardless of which fetches succeeded.
const EMPTY_DATA = {
  activeEmployees: [], terms: [], intuneDevices: [], tmobile: [], verizon: [],
  macbooks: [], liveAuction: [], awsWorkspaces: [], endpoints: [],
  ipadDevices: [], tablets: [],
};

async function init() {
  // API mode is the only mode (API_BASE is a constant non-empty string).
  // The previous `if (API_BASE) ... else ...` offline branch was unreachable
  // and has been removed.
  showToast('Connecting to database…');

  // Promise.allSettled — partial backend failures shouldn't blow away every
  // section. Each route is mapped to a DATA key, and rejected routes fall
  // back to an empty array so render code doesn't TypeError on undefined.
  const calls = [
    ['activeEmployees', apiGetWithTimeout('employees')],
    ['terms',           apiGetWithTimeout('terms')],
    ['intuneDevices',   apiGetWithTimeout('intune')],
    ['macbooks',        apiGetWithTimeout('macbooks')],
    ['endpoints',       apiGetWithTimeout('endpoints')],
    ['liveAuction',     apiGetWithTimeout('liveauction')],
    ['tmobile',         apiGetWithTimeout('tmobile')],
    ['verizon',         apiGetWithTimeout('verizon')],
    ['awsWorkspaces',   apiGetWithTimeout('aws')],
    ['ipadDevices',     apiGetWithTimeout('ipads')],
    ['tablets',         apiGetWithTimeout('tablets')],
  ];
  // Establish the empty shape BEFORE awaiting the network round-trip. If the
  // user clicks a nav button mid-init (e.g. Dashboard → buildDashboard()),
  // every consumer sees [] instead of TypeError on undefined.
  DATA = { ...EMPTY_DATA };
  bumpDataVersion();
  const results = await Promise.allSettled(calls.map(([, p]) => p));
  // Fire-and-forget the warranty map; not load-bearing for the first paint.
  loadAbmWarrantyMap();

  let failed = 0;
  results.forEach((r, i) => {
    const key = calls[i][0];
    inventoryLoadState.sources[key]=r.status==='fulfilled'&&Array.isArray(r.value)?'ok':'unavailable';
    if (r.status === 'fulfilled' && Array.isArray(r.value)) {
      DATA[key] = r.value;
      bumpDataVersion();
    } else {
      failed++;
      console.warn('init: route failed for', key, r.reason);
    }
  });

  if (failed === results.length) {
    showToast('API offline — showing empty inventory', 'err');
  } else if (failed > 0) {
    showToast(`Connected — ${failed} section(s) failed to load`, 'warn');
    _degrade('init-sections', failed + ' inventory section(s) failed to load', null);
  } else {
    showToast('Connected to database ✓');
  }

  inventoryLoadState.phase='ready';
  bootstrap();
  if(window.Inventory360)window.Inventory360.renderQueue();
}

// FIX5-20261017 (DR-02): the HR feed keeps some leavers on Active Employees
// as well as on Terminated (same Worker ID, termination date on or after the
// hire date, so not a rehire). They are moved off the Active list, kept in
// DATA.activeTermOverlap, and listed in a notice on the Employees page.
// Rows whose dates don't both parse are left where they are.
function _splitTermOverlap() {
  const act = DATA.activeEmployees;
  if (!Array.isArray(act) || act === DATA._overlapSrc) return;
  const termById = new Map();
  (DATA.terms || []).forEach(t => { const id = String(t['Worker ID'] || '').trim(); if (id) termById.set(id, t); });
  const keep = [], moved = [];
  act.forEach(e => {
    const t = termById.get(String(e['Worker ID'] || '').trim());
    const hire = t ? Date.parse(e['Hire Date']) : NaN;
    const term = t ? Date.parse(t['Termination Date']) : NaN;
    if (t && !isNaN(hire) && !isNaN(term) && term >= hire) moved.push({ emp: e, term: t });
    else keep.push(e);
  });
  DATA.activeTermOverlap = moved;
  DATA.activeEmployees = moved.length ? keep : act;
  DATA._overlapSrc = DATA.activeEmployees;
  if (moved.length) bumpDataVersion();
}
function _renderOverlapNote() {
  const count = document.getElementById('emp-count');
  const bar = count && count.parentElement;
  if (!bar || !bar.parentElement) return;
  let note = document.getElementById('emp-overlap-note');
  const moved = DATA.activeTermOverlap || [];
  if (!moved.length) { if (note) note.remove(); return; }
  if (!note) {
    note = document.createElement('div');
    note.id = 'emp-overlap-note';
    note.className = 'data-gap-notice';
    bar.insertAdjacentElement('afterend', note);
  }
  const names = moved.map(m => esc(m.emp['First/Last'] || m.emp['Employee Name'] || m.emp['Worker ID'])
    + ' <span style="color:var(--text3)">(' + esc(m.term['Status'] || 'Terminated') + ' ' + esc(m.term['Termination Date'] || '') + ')</span>').join(' · ');
  note.innerHTML = '<details><summary>⚠ ' + moved.length + (moved.length === 1 ? ' person is' : ' people are')
    + ' on both the Active and Terminated HR feeds and are not counted here. They are on Terminated Employees.</summary>'
    + '<div style="margin-top:6px;line-height:1.7">' + names + '</div></details>';
}

function bootstrap() {
  _splitTermOverlap();
  // Helper: only set badge text if both the element and the value exist.
  // Previously each line accessed .length directly; if any DATA array was
  // undefined the page died on first paint with a TypeError.
  const setBadge = (id, value) => {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  };
  const arr = (k) => Array.isArray(DATA[k]) ? DATA[k] : [];

  setBadge('badge-emp',     arr('activeEmployees').length);
  setBadge('badge-terms',   arr('terms').length);
  setBadge('badge-intune',  arr('intuneDevices').filter(d => !d['is_historical']).length);
  setBadge('badge-mac',     arr('macbooks').length);
  setBadge('badge-ep',      arr('endpoints').filter(isWindowsEndpoint).length);
  setBadge('badge-la',      arr('liveAuction').length);
  setBadge('badge-tm',      arr('tmobile').length);
  setBadge('badge-vz',      arr('verizon').length);
  setBadge('badge-aws',     arr('awsWorkspaces').length);
  setBadge('badge-ipads',   arr('ipadDevices').length);
  setBadge('badge-tablets', arr('tablets').length);


  // Populate filter dropdowns
  const leaders = [...new Set(DATA.activeEmployees.map(e=>e['Functional Leader']).filter(Boolean))].sort();
  populateSelect('emp-filter-leader', leaders, 'All Leaders');
  populateSelect('terms-filter-leader', [...new Set(DATA.terms.map(e=>e['Functional Leader']).filter(Boolean))].sort(), 'All Leaders');
  populateSelect('di-filter-manager', [...new Set(DATA.activeEmployees.map(e=>e['Manager Name']).filter(Boolean))].sort(), 'All Managers');

  const laStates = [...new Set(DATA.liveAuction.map(d=>d['State']).filter(Boolean))].sort();
  populateSelect('la-filter-state', laStates, 'All States');
  const laRegionals = [...new Set(DATA.liveAuction.map(d=>d['Regional']).filter(Boolean))].sort();
  populateSelect('la-filter-regional', laRegionals, 'All Regionals');

  buildDashboard();
  // Both are async and non-blocking, so a rejection here had nowhere to land:
  // badge-lc simply never updated and the Mission Control 'Lifecycle risk'
  // gauge reported a stale number forever with no sign anything had failed.
  buildLifecycleDashboard().catch(e => window.__invErr && window.__invErr('buildLifecycleDashboard', e));
  loadIntuneGraphMap().catch(e => window.__invErr && window.__invErr('loadIntuneGraphMap', e));
}

function populateSelect(id, opts, placeholder) {
  const el = document.getElementById(id);
  if (!el) return;
  el.innerHTML = `<option value="">${placeholder}</option>` +
    opts.map(o=>`<option value="${esc(o)}">${esc(o)}</option>`).join('');
}

// ============================================================
// SHARED ROUTING — single source of truth
// ============================================================
// Maps a logical table/page name to its render function. Used by showPage,
// onSearch, sortTable, goPage, saveModal, deleteRecord — anywhere that
// needs to "redraw the current view." Previously this dispatch was
// copy-pasted in six places and had drifted (some tables missing from
// some sites). Adding a new table now requires touching only this map.
function renderTable(name) {
  const fn = ({
    employees:           renderEmployees,
    terms:               renderTerms,
    intune:              renderIntune,
    macbooks:            renderMacbooks,
    endpoints:           renderEndpoints,
    liveauction:         renderLiveAuction,
    tmobile:             renderTmobile,
    verizon:             renderVerizon,
    aws:                 renderAWS,
    ipads:               renderIPads,
    tablets:             renderTablets,
    'device-inventory':  renderDeviceInventory,
    lifecycle:           renderLifecycle,
    warranty:            renderWarranty,
  })[name];
  if (typeof fn === 'function') fn();
}

// ============================================================
// NAVIGATION
// ============================================================
function showPage(name) {
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n=>{
    n.classList.remove('active');
    n.removeAttribute('aria-current');
  });
  document.getElementById('page-'+name).classList.add('active');
  const navBtn = document.querySelector(`[onclick="showPage('${name}')"]`);
  if (navBtn) {
    navBtn.classList.add('active');
    navBtn.setAttribute('aria-current', 'page');
  }
  currentPage = name;
  document.getElementById('topbar-title').textContent = {
    dashboard:'Dashboard',employees:'Active Employees',terms:'Terminated Employees',
    intune:'Intune devices',macbooks:'MacBooks (Kandji)',endpoints:'ManageEngine',
    liveauction:'Live Auction Devices',tmobile:'T-Mobile Lines',verizon:'Verizon Lines',
    aws:'AWS Workspaces',
    lifecycle:'Device Lifecycle',
    warranty:'Warranty Tracker',
    executive:'Executive Summary',
    costs:'Hardware Cost Report',
    tablets:'Tablets',
    ipads:'iPads (Kandji)',
    'device-inventory':'Device Inventory'
  }[name]||name;

  // SPA navigation replaced the whole content region and rewrote the topbar
  // title, but focus stayed on the nav button and nothing was announced — a
  // screen-reader user heard silence and had to go hunting. Secondary effect in
  // collapsed-rail mode: closeFlyouts() then hides the still-focused button,
  // dropping focus to <body> so the next Tab restarts at the skip link. Moving
  // focus into #main (already tabindex="-1") fixes both. Guarded on the
  // navigation being user-driven: on the initial render focus is still on
  // <body>, and stealing it there would skip past the skip link.
  const _ae = document.activeElement;
  if (_ae && _ae !== document.body && _ae !== document.documentElement) {
    const mainRegion = document.getElementById('main');
    if (mainRegion && typeof mainRegion.focus === 'function') {
      try { mainRegion.focus(); } catch(_) {}
    }
    announce('Navigated to ' + document.getElementById('topbar-title').textContent);
  }

  // Add button visibility is now owned entirely by JS via the `hidden`
  // attribute (the markup uses `hidden` instead of `style="display:none"`,
  // so visibility has a single source of truth).
  const addBtn = document.getElementById('add-btn');
  if (addBtn) {
    const hideOnPages = new Set(['dashboard','executive','costs','lifecycle','warranty','tablets','ipads','device-inventory']);
    addBtn.hidden = hideOnPages.has(name);
  }

  // Pages that need a side effect before rendering (sync status fetch,
  // dashboard build, etc.) handle that here; everything else delegates
  // to the shared renderTable() dispatcher.
  if      (name === 'dashboard')  { buildDashboard(); }
  else if (name === 'intune')     { loadIntuneSyncStatus();   loadIntuneGraphMap().then(() => renderIntune()); }
  else if (name === 'macbooks')   { loadKandjiSyncStatus();   renderMacbooks(); }
  else if (name === 'endpoints')  { loadEndpointsSyncStatus(); loadIntuneGraphMap().then(() => loadPatchHealthCache().then(() => renderEndpoints())); }
  else if (name === 'ipads')      { loadKandjiSyncStatus();   renderIPads(); }
  else if (name === 'lifecycle')  { buildLifecycleDashboard().then(() => renderLifecycle()); }
  else if (name === 'warranty')   { buildWarrantyDashboard(); }
  else if (name === 'executive')  { buildExecutive(); }
  else if (name === 'costs')      { buildCostReport(); }
  else                            { renderTable(name); }
}

// ============================================================
// SEARCH
// ============================================================
let _searchDebounce = null;
function onSearch(val) {
  clearTimeout(_searchDebounce);
  _searchDebounce = setTimeout(() => {
    searchQuery = val.toLowerCase().trim();
    pages[currentPage] = 1;
    renderTable(currentPage);
    _kit3XS.update();  // KIT3-20261017 (DR-08)
  }, 150);
}

// KIT3-20261017 (DR-08): "Search across all data" only filtered the open page.
// The open page still filters as you type; this panel under the box counts the
// matches on every page and opens the chosen one with the search applied.
// Each count uses that page's own base rows and match rule with its filters
// cleared, which is exactly what the page shows when opened from here.
const _KIT3_XS_PAGES = [   // rail order
  ['employees',        'Active Employees', () => DATA.activeEmployees],
  ['terms',            'Terminated',       () => DATA.terms],
  ['tablets',          'Tablets',          () => DATA.tablets || []],
  ['macbooks',         'MacBooks',         () => DATA.macbooks],
  ['ipads',            'iPads',            () => DATA.ipadDevices],
  ['endpoints',        'ManageEngine',     () => DATA.endpoints.filter(isWindowsEndpoint)],
  ['intune',           'Intune',           () => DATA.intuneDevices.filter(d => !d['is_historical'])],
  ['liveauction',      'Live Auction',     () => DATA.liveAuction],
  ['tmobile',          'T-Mobile',         () => DATA.tmobile],
  ['verizon',          'Verizon',          () => DATA.verizon],
  ['warranty',         'Warranty',         () => _warrantyData,       'values'],
  ['lifecycle',        'Device Lifecycle', () => buildLifecycleData(), 'values'],
  ['device-inventory', 'Device Inventory', () => buildDeviceUniverse()],
  ['aws',              'AWS Workspaces',   () => DATA.awsWorkspaces],
];
const _kit3XS = (() => {
  let pop = null, status = null;
  const input = () => document.getElementById('global-search');
  function count(rows, mode) {
    // Warranty and Lifecycle match on raw values (renderWarranty/renderLifecycle);
    // every other page goes through filterBySearch.
    if (mode === 'values') return rows.filter(r => Object.values(r).some(v => v && String(v).toLowerCase().includes(searchQuery))).length;
    return filterBySearch(rows).length;
  }
  function build() {
    if (pop) return;
    pop = document.createElement('div');
    pop.id = 'kit3-xsearch'; pop.hidden = true;
    pop.setAttribute('role', 'region'); pop.setAttribute('aria-label', 'Matches across all data');
    document.body.appendChild(pop);
    status = document.createElement('div');
    status.className = 'visually-hidden'; status.setAttribute('role', 'status');
    document.body.appendChild(status);
    pop.addEventListener('click', e => { const b = e.target.closest('[data-xs-page]'); if (b) go(b.getAttribute('data-xs-page')); });
    pop.addEventListener('keydown', e => {
      const items = [...pop.querySelectorAll('[data-xs-page]')], i = items.indexOf(document.activeElement);
      if (e.key === 'ArrowDown') { e.preventDefault(); (items[i + 1] || items[0])?.focus(); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); if (i <= 0) input()?.focus(); else items[i - 1].focus(); }
      // Focus first: the box's focus handler reopens the panel, so hide after it.
      else if (e.key === 'Escape') { e.preventDefault(); input()?.focus(); hide(); }
    });
    // Close on a click or focus anywhere else. Not on blur: Safari does not focus
    // a clicked <button>, so a blur rule would close the panel before the click.
    document.addEventListener('mousedown', e => { if (!pop.hidden && !pop.contains(e.target) && e.target !== input()) hide(); });
    document.addEventListener('focusin', e => { if (!pop.hidden && !pop.contains(e.target) && e.target !== input()) hide(); });
    window.addEventListener('resize', place);
    const inp = input();
    if (inp) {
      inp.setAttribute('aria-controls', 'kit3-xsearch'); inp.setAttribute('aria-expanded', 'false');
      inp.addEventListener('keydown', e => {
        if (e.key === 'ArrowDown' && !pop.hidden) { e.preventDefault(); pop.querySelector('[data-xs-page]')?.focus(); }
        else if (e.key === 'Escape' && !pop.hidden) { e.preventDefault(); hide(); }
      });
      inp.addEventListener('focus', () => { if (searchQuery.length >= 2) update(); });
    }
  }
  function place() {
    if (!pop || pop.hidden || !input()) return;
    const r = input().getBoundingClientRect();
    pop.style.top = Math.round(r.bottom + 6) + 'px';
    pop.style.left = Math.round(Math.max(8, Math.min(r.left, innerWidth - pop.offsetWidth - 8))) + 'px';
  }
  function hide() {
    if (!pop || pop.hidden) return;
    pop.hidden = true; input()?.setAttribute('aria-expanded', 'false');
  }
  function update() {
    const q = searchQuery, inp = input();
    // Only while the user is in the box: a profile device-jump also calls
    // onSearch, and should not pop a panel over the page it opened.
    if (!q || q.length < 2 || !inp || document.activeElement !== inp) { hide(); return; }
    build();
    const hits = [], notCounted = [];
    _KIT3_XS_PAGES.forEach(([page, label, rowsOf, mode]) => {
      let rows;
      try { rows = rowsOf(); } catch (e) { notCounted.push(label); setTimeout(() => { throw e; }); return; }
      // _warrantyData stays empty until the warranty feed has loaded.
      if (!Array.isArray(rows) || (page === 'warranty' && !rows.length)) { notCounted.push(label); return; }
      let n;
      try { n = count(rows, mode); } catch (e) { notCounted.push(label); setTimeout(() => { throw e; }); return; }
      if (n) hits.push({page, label, n});
    });
    const total = hits.reduce((a, h) => a + h.n, 0);
    const head = total
      ? `${total.toLocaleString()} match${total === 1 ? '' : 'es'} on ${hits.length} page${hits.length === 1 ? '' : 's'}`
      : 'No matches on any page';
    pop.innerHTML =
      `<div class="xs-h">${head} for “${esc(q)}”</div>` +
      hits.map(h => `<button type="button" class="xs-row${h.page === currentPage ? ' xs-cur' : ''}" data-xs-page="${h.page}">` +
        `<span class="xs-l">${esc(h.label)}</span>${h.page === currentPage ? '<span class="xs-tag">this page</span>' : ''}` +
        `<span class="xs-n">${h.n.toLocaleString()}</span></button>`).join('') +
      (notCounted.length ? `<div class="xs-f">Not counted yet: ${esc(notCounted.join(', '))}</div>` : '') +
      (hits.length ? `<div class="xs-f">Opening a page clears its filters and keeps this search.</div>` : '');
    status.textContent = head + '.';
    pop.hidden = false; inp.setAttribute('aria-expanded', 'true');
    place();
  }
  function go(page) {
    const q = input()?.value || '';
    if (page === currentPage) { input()?.focus(); hide(); return; }
    hide();
    const pg = document.getElementById('page-' + page);
    if (pg) pg.querySelectorAll('select.filter-select').forEach(s => { s.value = ''; });
    // __itamDrilling stops the page's showPage wrapper clearing the search.
    window.__itamDrilling = true;
    try { showPage(page); } finally { window.__itamDrilling = false; }
    const sb = input(); if (sb) sb.value = q;
    searchQuery = q.toLowerCase().trim();
    pages[page] = 1;
    renderTable(page);
  }
  return { update, hide };
})();

// KIT2-20261017 helpers. _kit2NameKey is the same rule fix5 uses for the
// Device Inventory join: lowercase, trailing "(...)" dropped, spaces collapsed.
// HR's own First/Last carries suffixes such as "(SCII)", so both sides of a
// name comparison must go through it.
const _kit2NameKey = s => String(s || '').toLowerCase().replace(/\s*\([^)]*\)\s*$/, '').replace(/\s+/g, ' ').trim();
const _KIT2_US_STATES = new Set('AL AK AZ AR CA CO CT DE DC FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT NE NV NH NJ NM NY NC ND OH OK OR PA PR RI SC SD TN TX UT VT VA WA WV WI WY'.split(' '));
const _kit2IsState = s => _KIT2_US_STATES.has(String(s || '').trim().toUpperCase());
function _kit2StateBadge(s) {
  if (!s) return '—';
  if (_kit2IsState(s)) return badge(s, 'blue');
  return `<span class="badge badge-gray" title="Not a US state code. The source data has a district code in the State field.">${esc(s)}</span>`;
}
// Intune returns ISO timestamps; show them the way the Kandji pages do.
function _kit2FmtIso(v) {
  if (!v) return '—';
  const d = new Date(v);
  if (isNaN(d)) return String(v);
  return d.toLocaleString('en-US', {month:'short', day:'numeric', year:'numeric', hour:'2-digit', minute:'2-digit'});
}
// Intune names Android Enterprise tablets after the enrolment, and copies that
// name into "Primary user display name", so the User column repeated the
// device name on all 374 rows. Fall back to the HR name for the UPN.
function _kit2TabletUser(r) {
  const dn = String(r['Primary user display name'] || '').trim(), dev = String(r['Device name'] || '').trim();
  if (dn && dn !== dev) return dn;
  const upn = String(r['Primary user UPN'] || '').trim();
  let e = null;
  try { e = upn && typeof window.itamEmployeeByUserRef === 'function' ? window.itamEmployeeByUserRef(upn) : null; } catch (_) { e = null; }
  return e ? (e['First/Last'] || upn) : (upn || '—');
}
// Verizon types business gateways as SMARTPHONE.
function _kit2VzType(r) {
  const t = r['Device Type'] || '';
  if (t === 'SMARTPHONE' && /gateway|\bNCM\d|router|hotspot/i.test(String(r['Equipment Model'] || ''))) return 'GATEWAY';
  return t;
}

function filterBySearch(rows) {
  if (!searchQuery) return rows;
  // Was a full Object.values() scan of every row on every keystroke, sort and
  // page click. rowHaystack() builds each row's lowercased haystack once per
  // DATA_VERSION and reuses it for every later search.
  // KIT2-20261017 (DR-11): phone numbers are stored as bare digits (T-Mobile)
  // or dotted (Verizon), so "(214) 998-0010" found nothing. A query made only
  // of digits and phone punctuation also matches each field's digits.
  let digits = searchQuery.replace(/\D/g, '');
  if (digits.length === 11 && digits[0] === '1') digits = digits.slice(1);
  const phoneish = digits.length >= 4 && digits !== searchQuery && /^[\d\s().+\-]+$/.test(searchQuery);
  return rows.filter(r => {
    const h = rowHaystack(r);
    if (h.includes(searchQuery)) return true;
    return phoneish && h.split(_HAY_SEP).some(v => v.replace(/\D/g, '').includes(digits));
  });
}

// ============================================================
// FILTERS
// ============================================================
// The 27 filter <select>s each call their renderer straight from an inline
// onchange and none of them reset the page number, so filtering while on page 8
// sliced past the end of the filtered set: an empty tbody under a correct row
// count, which reads as "this leader has no reports". Reset the page here in
// the CAPTURE phase rather than editing 27 attributes — capture runs before the
// element's own onchange, so the renderer it fires already sees page 1. The
// table key is the page container's id minus 'page-', which is exactly the key
// paginate() and renderPagination() use.
document.addEventListener('change', e => {
  const sel = e.target && e.target.closest ? e.target.closest('.filter-select') : null;
  if (!sel) return;
  const page = sel.closest('.page');
  if (!page || page.id.indexOf('page-') !== 0) return;
  pages[page.id.slice(5)] = 1;
}, true);

// ============================================================
// SORT
// ============================================================
function sortTable(table, col) {
  if (!sortState[table]) sortState[table] = {col:null,dir:1};
  if (sortState[table].col === col) sortState[table].dir *= -1;
  else { sortState[table].col = col; sortState[table].dir = 1; }
  // Re-sorting reorders the whole list, so page 8 of the old order is
  // meaningless in the new one — go back to the top, like the search box does.
  pages[table] = 1;
  applySortIndicators(table);
  renderTable(table);
}

// ── Sort indicator: apply .sort-asc / .sort-desc to the active <th> ──
const _tablePageMap = {
  employees:'page-employees', terms:'page-terms', intune:'page-intune',
  macbooks:'page-macbooks', endpoints:'page-endpoints', liveauction:'page-liveauction',
  tmobile:'page-tmobile', verizon:'page-verizon', aws:'page-aws',
  ipads:'page-ipads', tablets:'page-tablets', 'device-inventory':'page-device-inventory',
  lifecycle:'page-lifecycle', warranty:'page-warranty',
};
function applySortIndicators(table) {
  const pageId = _tablePageMap[table];
  const page = pageId ? document.getElementById(pageId) : null;
  if (!page) return;
  // Reset every sortable header on this page first.
  page.querySelectorAll('th[onclick]').forEach(th => {
    th.classList.remove('sort-asc','sort-desc');
    if (th.hasAttribute('aria-sort')) th.setAttribute('aria-sort', 'none');
  });
  const s = sortState[table];
  if (!s?.col) return;
  // Mark the active column with both the visual class and aria-sort so
  // screen readers announce the current direction.
  page.querySelectorAll('th[onclick]').forEach(th => {
    const onclick = th.getAttribute('onclick') || '';
    if (onclick.includes(`'${s.col}'`)) {
      const dir = s.dir === 1 ? 'asc' : 'desc';
      th.classList.add('sort-' + dir);
      th.setAttribute('aria-sort', dir === 'asc' ? 'ascending' : 'descending');
    }
  });
}

// Per-column comparator kinds. applySorting used to guess from the value with
// parseFloat, which reads "2026-08-31T14:22:00Z" as 2026 — every row in a year
// ties, so the column never moves — and "15.10.1" as 15.1, sorting macOS 15.10.1
// BELOW 15.6.1, exactly backwards on a page used to find laggards. Keys are
// lowercased column names so 'OS version' and 'OS Version' share one entry;
// any column not listed keeps the previous auto behaviour.
const SORT_COL_KINDS = {
  'checked in':'date', 'last check-in':'date',
  'last successful asset scan':'date', 'termination date':'date',
  'os version':'version',
};

// Compare dotted versions segment by segment, so 15.10.1 > 15.6.1. Non-numeric
// segments (build suffixes) count as 0 instead of poisoning the comparison.
function cmpVersion(a, b) {
  const pa = String(a).split('.'), pb = String(b).split('.');
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = parseInt(pa[i], 10), nb = parseInt(pb[i], 10);
    const va = isNaN(na) ? 0 : na, vb = isNaN(nb) ? 0 : nb;
    if (va !== vb) return va - vb;
  }
  return 0;
}

function applySorting(rows, table) {
  const s = sortState[table];
  if (!s || !s.col) return rows;
  const kind = SORT_COL_KINDS[String(s.col).toLowerCase()] || 'auto';
  // Blank/missing sorts last in both directions. The old `||''` coerced a real
  // 0 to '' and pushed every empty cell to the top of an ascending sort.
  const blank = v => v === null || v === undefined || v === '';
  // 'auto' only treats a value as numeric when the WHOLE string is a number, so
  // "2026-08-31" and "15.6.1" fall through to text instead of being half-parsed.
  const numRe = /^-?\d+(\.\d+)?$/;
  return [...rows].sort((a,b)=>{
    const av = a[s.col], bv = b[s.col];
    if (blank(av) || blank(bv)) return blank(av) && blank(bv) ? 0 : (blank(av) ? 1 : -1);
    if (kind === 'date') {
      // parseLastSeen also decodes the Excel serial dates the spreadsheet
      // importers write, which Date.parse would read as a plain number.
      const ad = parseLastSeen(av), bd = parseLastSeen(bv);
      if (!ad && !bd) return cmpText(av, bv) * s.dir;
      if (!ad || !bd) return ad ? -1 : 1;
      return (ad - bd) * s.dir;
    }
    if (kind === 'version') return cmpVersion(av, bv) * s.dir;
    const as = String(av).trim(), bs = String(bv).trim();
    if (numRe.test(as) && numRe.test(bs)) return (parseFloat(as) - parseFloat(bs)) * s.dir;
    return cmpText(as, bs) * s.dir;
  });
}

// ============================================================
// PAGINATION
// ============================================================
// INV-09: the rows each table last rendered (view + filters + search + sort,
// before paging). exportCSV() exports exactly these.
const _VIEW_ROWS = {};
function paginate(rows, table) {
  _VIEW_ROWS[table] = rows;
  const p = pages[table]||1;
  const start = (p-1)*PAGE_SIZE;
  return rows.slice(start, start+PAGE_SIZE);
}

function renderPagination(containerId, infoId, total, table) {
  const totalPages = Math.ceil(total/PAGE_SIZE);
  const cur = pages[table]||1;
  const info = document.getElementById(infoId);
  const cont = document.getElementById(containerId);
  if (info) info.textContent = `Showing ${Math.min((cur-1)*PAGE_SIZE+1,total)}–${Math.min(cur*PAGE_SIZE,total)} of ${total.toLocaleString()}`;
  if (!cont) return;
  let html = `<button class="page-btn" onclick="goPage('${table}',${cur-1})" ${cur<=1?'disabled':''}>‹</button>`;
  const range = pageRange(cur,totalPages);
  range.forEach(p=>{
    if(p==='...') html+=`<span style="color:var(--text3);padding:0 4px">…</span>`;
    else html+=`<button class="page-btn ${p===cur?'active':''}" onclick="goPage('${table}',${p})">${p}</button>`;
  });
  html+=`<button class="page-btn" onclick="goPage('${table}',${cur+1})" ${cur>=totalPages?'disabled':''}>›</button>`;
  cont.innerHTML=html;
}

function pageRange(cur, total) {
  if (total <= 7) return Array.from({length:total},(_,i)=>i+1);
  const r = [1];
  if (cur > 3) r.push('...');
  for (let i=Math.max(2,cur-1);i<=Math.min(total-1,cur+1);i++) r.push(i);
  if (cur < total-2) r.push('...');
  r.push(total);
  return r;
}

function goPage(table, p) {
  pages[table] = p;
  renderTable(table);
}

// ============================================================
// HELPERS
// ============================================================
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function isWindowsEndpoint(r) {
  const os = (r['OS Name']||'').toLowerCase();
  const name = (r['Computer Name']||'').toUpperCase();
  return os.startsWith('windows') && !os.includes('server') && !name.startsWith('WSAMZN-');
}
// Derive LAPTOP/DESKTOP from model when ManageEngine returns blank/Unknown.
// Without this, the Type filter (which only offers LAPTOP/DESKTOP) silently
// hides every device whose chassis type didn't come through cleanly.
function inferEndpointType(r) {
  // ManageEngine surfaces SMBIOS chassis names (Notebook, Portable, Tower,
  // Mini Tower, etc.), not just LAPTOP/DESKTOP — fold them into the two
  // buckets the filter and badge code understand.
  const raw = (r['Computer Type']||'').toString().toUpperCase().trim();
  if (/LAPTOP|NOTEBOOK|PORTABLE|CONVERTIBLE|DETACHABLE|HAND.?HELD|SUB.?NOTEBOOK/.test(raw)) return 'LAPTOP';
  if (/DESKTOP|TOWER|ALL.?IN.?ONE|AIO|SFF|MFF|MICRO|SPACE.?SAVING|PIZZA/.test(raw)) return 'DESKTOP';
  const model = (r['Device Model']||'').toString().toUpperCase();
  if (model) {
    if (/LATITUDE|THINKPAD|ELITEBOOK|PROBOOK|MACBOOK|NOTEBOOK|LAPTOP|XPS\s*1[3-9]|INSPIRON\s*1[3-9]|VOSTRO\s*1[3-9]/.test(model)) return 'LAPTOP';
    if (/SURFACE\s+(LAPTOP|BOOK|GO|PRO)/.test(model)) return 'LAPTOP';
    if (/PRECISION.*MOBILE|MOBILE\s+PRECISION|PRECISION\s*(3|5|7)5\d{2}|PRECISION\s*(3|5|7)7\d{2}/.test(model)) return 'LAPTOP';
    if (/OPTIPLEX|THINKCENTRE|ELITEDESK|PRODESK|IMAC|MAC\s*MINI|TOWER|WORKSTATION|\bDESKTOP\b|\bSFF\b|\bMFF\b|MICRO\b/.test(model)) return 'DESKTOP';
    if (/PRECISION/.test(model)) return 'DESKTOP';
  }
  // Type must never be blank — Windows endpoints with no chassis + no model
  // are overwhelmingly laptops in this fleet, so default rather than render
  // an empty badge the filter can't catch.
  return 'LAPTOP';
}
// Lazy index built from Intune so endpoints with no ME Model can fall back to
// the value Intune saw. Reset on intune sync so refreshed data shows through.
let _epModelFromIntune = null;
let _epModelFromIntuneVersion = -1;
function _buildEpModelFromIntune() {
  const map = Object.create(null);
  (typeof DATA !== 'undefined' && DATA.intuneDevices || []).forEach(d => {
    const m = d && d['Model']; if (!m || m === '—' || m === '--') return;
    const s = (d['Serial number']||'').toLowerCase().trim();
    const n = (d['Device name']||'').toLowerCase().trim();
    if (s) map[s] = m;
    if (n) map['name:'+n] = m;
  });
  return map;
}
function inferEndpointModel(r) {
  const raw = (r['Device Model']||'').toString().trim();
  if (raw && raw !== '—' && raw !== '--') return raw;
  const tag = (r['Service Tag']||'').toLowerCase().trim();
  const nameKey = 'name:' + (r['Computer Name']||'').toLowerCase().trim();
  // Warranty map (built server-side from ManageEngine — sometimes has the
  // model when the per-device record didn't).
  const w = (typeof _warrantyMap !== 'undefined' && _warrantyMap)
    ? (_warrantyMap[tag] || _warrantyMap[nameKey])
    : null;
  const wm = w && w.device_model;
  if (wm && wm !== '—' && wm !== '--') return wm;
  // Version-keyed as well as lazy: the manual `_epModelFromIntune = null` in
  // triggerIntuneSync() was the ONLY thing refreshing this index, so any other
  // path that replaced DATA.intuneDevices (init, import) left it stale.
  if (!_epModelFromIntune || _epModelFromIntuneVersion !== DATA_VERSION) {
    _epModelFromIntune = _buildEpModelFromIntune();
    _epModelFromIntuneVersion = DATA_VERSION;
  }
  return _epModelFromIntune[tag] || _epModelFromIntune[nameKey] || '—';
}
function cell(v,cls=''){return `<td class="${cls}">${esc(v||'—')}</td>`;}
function cellName(v){return `<td class="cell-name">${esc(v||'—')}</td>`;}
function cellMono(v){return `<td class="cell-mono">${esc(v||'—')}</td>`;}
function formatPhone(v){
  if(!v) return '—';
  // Strip trailing .0 from float-stored numbers (e.g. "2145423972.0")
  const s = String(v).replace(/\.0+$/, '');
  const d = s.replace(/\D/g,'');
  if(d.length===11 && d[0]==='1') return '('+d.slice(1,4)+') '+d.slice(4,7)+'-'+d.slice(7);
  if(d.length===10) return '('+d.slice(0,3)+') '+d.slice(3,6)+'-'+d.slice(6);
  if(d.length===7) return d.slice(0,3)+'-'+d.slice(3);
  return d || '—';
}
function cellPhone(v){return '<td class="cell-mono">'+esc(formatPhone(v))+'</td>';}
function badge(label, color='gray'){return `<span class="badge badge-${color}">${esc(label)}</span>`;}
function payClassBadge(p){
  if(!p) return badge('—');
  // KIT2-20261017 (DR-19): the profile drawer reads cell text, which is the
  // short badge ("FT"); data-full carries the real value for it.
  const b = p.includes('FT') ? badge('FT','blue') : p.includes('PT') ? badge('PT','purple') : p.includes('Contingent') ? badge('CW','orange') : badge(p);
  return b.replace('<span ', `<span title="${esc(p)}" data-full="${esc(p)}" `);
}
function statusBadge(s){
  if(!s) return badge('—');
  const u=s.toUpperCase();
  if(u==='ACTIVE'||u==='A'||u==='AVAILABLE') return badge(s,'green');
  if(u==='INACTIVE'||u==='STOPPED'||u==='TERMINATED') return badge(s,'red');
  return badge(s,'gray');
}
// Encode a record reference for an inline onclick handler.
// Prefer stable _id (so re-renders / mutations can't cause a stale-index click to hit the wrong row);
// fall back to numeric idx for legacy callers. Strings get single-quoted/escaped so the resulting
// JS expression is valid inside an onclick="..." attribute.
function _encodeRef(record, idx) {
  if (record && record._id != null) {
    if (typeof record._id === 'number') return String(record._id);
    return "'" + String(record._id).replace(/\\/g, '\\\\').replace(/'/g, "\\'") + "'";
  }
  return String(idx);
}
function actionsCell(table, idx, record) {
  const ref = _encodeRef(record, idx);
  return `<td class="actions">
    ${window.Inventory360?window.Inventory360.sourceAction(table,record):''}
    <button data-rbac-page="it-inventory" data-rbac-level="admin" class="btn btn-ghost btn-sm" onclick="editRecord('${table}',${ref})">Edit</button>
    <button data-rbac-page="it-inventory" data-rbac-level="admin" class="btn btn-danger btn-sm" onclick="deleteRecord('${table}',${ref})" style="margin-left:4px">Del</button>
  </td>`;
}
// ============================================================
// SHARED INTUNE BADGE HELPER
// ============================================================
function intuneBadgeHTML(enrolled, compliance) {
  if (enrolled) {
    const comp = (compliance || 'unknown').toLowerCase();
    const compColor = comp === 'compliant' ? 'var(--green)' : comp === 'noncompliant' ? 'var(--red)' : 'var(--text3)';
    // comp is API/DB data on all four call paths — the live Graph map, intune_devices
    // Compliance, and tmobile intune_compliance — and every one of those is writable
    // through this console's own PUT and bulk-import endpoints, so an unescaped value
    // is STORED XSS that re-renders for every viewer of Endpoints, T-Mobile, Verizon
    // and Tablets. compColor is a fixed ternary and needs no escaping.
    return `<td><span class="badge badge-green" title="Enrolled in Intune">✓ Enrolled</span><div style="font-size:10px;color:${compColor};margin-top:2px;font-weight:600">${esc(comp)}</div></td>`;
  }
  if (typeof _intuneGraphMapError !== 'undefined' && _intuneGraphMapError) {
    return `<td><span class="badge badge-yellow" title="Live Intune status unavailable — backend error">⚠ Status unavailable</span></td>`;
  }
  return `<td><span class="badge badge-gray" title="Not found in Intune">— Not Found</span></td>`;
}

// ============================================================
// DEVICE LOOKUP — builds username -> devices map from device tables
// ============================================================
let _deviceLookup = null;
let _deviceLookupVersion = -1;
function buildDeviceLookup() {
  // Join index over intune + tablets + employees + macbooks + endpoints + aws —
  // very nearly the whole fleet — and it was rebuilt from scratch inside
  // renderEmployees() on every keystroke, sort, filter and page click, plus
  // once per dashboard and cost-report render. Callers only ever read it.
  if (_deviceLookup && _deviceLookupVersion === DATA_VERSION) return _deviceLookup;
  const map = {}; // keyed by lowercase username

  function ensure(username) {
    const k = (username||'').toLowerCase().trim();
    if (!k || k === '--') return null;
    if (!map[k]) map[k] = { laptop:false, macbook:false, iphone:false, tablet:false, ipad:false, aws:false };
    return k;
  }

  function extractUsername(val) {
    if (!val || val === '--') return null;
    // Handle 'email,username' or 'email' or 'username' formats
    const parts = val.split(',').map(s => s.trim());
    for (const p of parts) {
      if (p.toLowerCase().includes('@auction.com')) {
        return p.toLowerCase().replace('@auction.com', '');
      }
    }
    const first = parts[0];
    return first && first !== '--' ? first.toLowerCase() : null;
  }

  // iPhones — from Intune by UPN
  (DATA.intuneDevices||[]).forEach(d => {
    if (d['device_category'] === 'iphone' && !d['is_historical']) {
      const k = ensure(extractUsername(d['Primary user UPN']));
      if (k) map[k].iphone = true;
    }
  });

  // Tablets — from DATA.tablets by UPN
  (DATA.tablets||[]).forEach(d => {
    const k = ensure(extractUsername(d['Primary user UPN']));
    if (k) map[k].tablet = true;
  });

  // MacBooks — User field is full name, match against employee First/Last
  const empByName = {};
  (DATA.activeEmployees||[]).forEach(e => {
    if (e['First/Last'] && e['Username']) {
      empByName[e['First/Last'].toLowerCase().trim()] = e['Username'].toLowerCase();
    }
  });
  (DATA.macbooks||[]).forEach(d => {
    const user = (d['User']||'').trim();
    if (!user || user === '--') return;
    // Try direct username extraction first
    let k = extractUsername(user);
    // If no @ sign, try matching against employee name
    if (!k || !user.includes('@')) {
      const nameKey = user.toLowerCase().trim()
        .replace(/\s*\(sc\d*\)\s*$/i, '').trim(); // strip (SCI), (SCII) suffixes
      k = empByName[nameKey] || k;
    }
    if (k) { ensure(k); map[k].macbook = true; }
  });

  // Laptops/Desktops — from Endpoints
  (DATA.endpoints||[]).filter(isWindowsEndpoint).forEach(d => {
    const k = ensure(extractUsername(d['First/Last']));
    if (k) map[k].laptop = true;
  });

  // AWS Workspaces
  (DATA.awsWorkspaces||[]).forEach(d => {
    const user = (d['Username']||'').trim();
    if (!user || user === '--') return;
    const k = ensure(user.toLowerCase());
    if (k) map[k].aws = true;
  });

  // iPads — skip shared accounts
  const sharedAccounts = ['zoomo365', 'zoom', '--', ''];
  (DATA.ipadDevices||[]).forEach(d => {
    const user = (d['User']||'').trim();
    if (sharedAccounts.includes(user.toLowerCase())) return;
    const k = ensure(extractUsername(user) || user.toLowerCase());
    if (k) map[k].ipad = true;
  });

  _deviceLookup = map;
  _deviceLookupVersion = DATA_VERSION;
  return map;
}

function devicePillsFromLookup(username, deviceMap) {
  const k = (username||'').toLowerCase().trim();
  const devices = deviceMap[k] || {};
  const pills = [];
  if (devices.laptop)  pills.push('<span class="badge badge-blue">Laptop</span>');
  if (devices.macbook) pills.push('<span class="badge badge-purple">MacBook</span>');
  if (devices.iphone)  pills.push('<span class="badge badge-teal">iPhone</span>');
  if (devices.tablet)  pills.push('<span class="badge badge-orange">Tablet</span>');
  if (devices.ipad)    pills.push('<span class="badge badge-yellow">iPad</span>');
  if (devices.aws)     pills.push('<span class="badge badge-gray">AWS</span>');
  return `<td style="white-space:nowrap">${pills.join(' ')||'<span style="color:var(--text3)">None</span>'}</td>`;
}

// ============================================================
// EMPLOYEES
// ============================================================
// ------------------------------------------------------------
// Detailed assigned-device list for one employee (mirrors buildDeviceLookup
// matching). Exposed globally for the employee profile modal.
// Returns [{type, name, detail}]
// ------------------------------------------------------------
function itamDevicesForEmployee(emp) {
  if (!emp) return [];
  function xu(val){
    if (!val || val === '--') return null;
    const parts = val.split(',').map(s=>s.trim());
    for (const pp of parts){ if (pp.toLowerCase().includes('@auction.com')) return pp.toLowerCase().replace('@auction.com',''); }
    const first = parts[0];
    return first && first !== '--' ? first.toLowerCase() : null;
  }
  const u  = (emp['Username']||'').toLowerCase().trim();
  const nm = (emp['First/Last']||'').toLowerCase().trim();
  const out = [];
  const D = (typeof DATA==='object'&&DATA)?DATA:{};

  (D.intuneDevices||[]).forEach(d=>{
    if (d['device_category']==='iphone' && !d['is_historical'] && u && xu(d['Primary user UPN'])===u)
      out.push({type:'iPhone', name:d['Device name']||d['Model']||'iPhone', detail:[d['Model'],d['Serial number']].filter(Boolean).join(' \u00b7 '), page:'intune', query:d['Serial number']||d['Device name']||''});
  });
  (D.tablets||[]).forEach(d=>{
    if (u && xu(d['Primary user UPN'])===u)
      out.push({type:'Tablet', name:d['Device name']||d['Model']||'Tablet', detail:[d['Model'],d['Serial number']].filter(Boolean).join(' \u00b7 '), page:'tablets', query:d['Serial number']||d['Device name']||''});
  });
  (D.macbooks||[]).forEach(d=>{
    const user=(d['User']||'').trim(); if(!user||user==='--') return;
    let k=xu(user);
    const nameKey=user.toLowerCase().trim().replace(/\s*\(sc\d*\)\s*$/i,'').trim();
    const match=(k&&k===u)||(nm&&nameKey===nm);
    if (match)
      out.push({type:'MacBook', name:d['Device Name']||d['Model']||'MacBook', detail:[d['Model'],d['Serial']].filter(Boolean).join(' \u00b7 '), page:'macbooks', query:d['Serial']||d['Device Name']||''});
  });
  (D.endpoints||[]).forEach(d=>{
    if (typeof isWindowsEndpoint==='function' && !isWindowsEndpoint(d)) return;
    if (u && xu(d['First/Last'])===u)
      out.push({type:'Laptop/Desktop', name:d['Computer Name']||'Windows device', detail:d['OS Name']||'', page:'endpoints', query:d['Computer Name']||''});
  });
  (D.awsWorkspaces||[]).forEach(d=>{
    const user=(d['Username']||'').trim().toLowerCase();
    if (u && user && user!=='--' && user===u)
      out.push({type:'AWS Workspace', name:d['Username']||'Workspace', detail:d['User volume']?('Vol '+d['User volume']):'', page:'aws', query:d['Username']||''});
  });
  const shared=['zoomo365','zoom','--',''];
  (D.ipadDevices||[]).forEach(d=>{
    const user=(d['User']||'').trim(); if(shared.includes(user.toLowerCase())) return;
    const k=xu(user)||user.toLowerCase().trim();
    if (u && k===u)
      out.push({type:'iPad', name:d['Device Name']||d['Model']||'iPad', detail:[d['Model'],d['Serial']].filter(Boolean).join(' \u00b7 '), page:'ipads', query:d['Serial']||d['Device Name']||''});
  });
  return out;
}
if (typeof window!=='undefined') window.itamDevicesForEmployee = itamDevicesForEmployee;
if (typeof window!=='undefined') window.itamEmployeeDevices = function(idx){ try{ var e=DATA.activeEmployees[parseInt(idx,10)]; return e?itamDevicesForEmployee(e):null; }catch(_){ return null; } };
if (typeof window!=='undefined') window.itamClearSearch = function(){ try{ clearTimeout(_searchDebounce); searchQuery=''; var sb=document.getElementById('global-search'); if(sb) sb.value=''; _kit3XS.hide(); }catch(_){}; };  // KIT3-20261017: also closes the all-pages panel
if (typeof window!=='undefined') window.itamEmployeeByUserRef = function(ref){
  try{
    if(!ref) return null;
    var raw=String(ref).trim(); if(!raw||raw==='\u2014'||raw==='--') return null;
    function xu(val){
      if(!val) return null;
      var parts=String(val).split(',').map(function(x){return x.trim();});
      for(var i=0;i<parts.length;i++){ if(parts[i].toLowerCase().indexOf('@auction.com')>-1) return parts[i].toLowerCase().replace('@auction.com',''); }
      return parts[0]?parts[0].toLowerCase():null;
    }
    var emps=(DATA.activeEmployees||[]);
    var uname=xu(raw);
    if(uname){ for(var i=0;i<emps.length;i++){ if((emps[i]['Username']||'').toLowerCase().trim()===uname) return emps[i]; } }
    // KIT2-20261017 (DR-16): HR's First/Last also carries "(SCII)"-style
    // suffixes, so only the device side was being stripped and those rows
    // opened nothing. Both sides now use the same key; an email falls back to
    // Business Email.
    var nk=_kit2NameKey(raw);
    for(var j=0;j<emps.length;j++){ if(_kit2NameKey(emps[j]['First/Last'])===nk) return emps[j]; }
    if(raw.indexOf('@')>0){ var em=raw.toLowerCase(); for(var q=0;q<emps.length;q++){ if(String(emps[q]['Business Email']||'').toLowerCase().trim()===em) return emps[q]; } }
    return null;
  }catch(_){ return null; }
};

function renderEmployees() {
  let rows = [...DATA.activeEmployees];
  // KIT2-20261017: options from the data ("Temporary PT" had none).
  _syncFilterOptions('emp-filter-payclass', rows, 'Pay Class', 'All Pay Classes');
  const leader = document.getElementById('emp-filter-leader')?.value;
  // KIT2-20261017 (DR-10): the "Filtered by Leader" banner followed the drill,
  // not the filter, so it stayed after the filter was cleared or changed.
  if (leader) showDrillBanner(`Filtered by Leader: ${leader}`, clearDrill); else hideDrillBanner();
  const payclass = document.getElementById('emp-filter-payclass')?.value;
  const device = document.getElementById('emp-filter-device')?.value;
  // Build the device join from the actual device tables (Intune/Kandji/Endpoints/etc.) instead
  // of reading the often-null inline columns on the employee record. Same source as the dashboard.
  const empDevMap = buildDeviceLookup();
  const hasDevice = (emp, kind) => {
    const k = (emp['Username']||'').toLowerCase().trim();
    const d = empDevMap[k] || {};
    if (kind === 'Desktop/Laptop') return !!d.laptop;
    if (kind === 'MacBook') return !!d.macbook;
    if (kind === 'iPhone') return !!d.iphone;
    if (kind === 'Tablet') return !!d.tablet;
    if (kind === 'iPad') return !!d.ipad;
    if (kind === 'AWS Workspace') return !!d.aws;
    return !!emp[kind];
  };
  if (leader) rows = rows.filter(r=>r['Functional Leader']===leader);
  if (payclass) rows = rows.filter(r=>r['Pay Class']===payclass);
  if (device) rows = rows.filter(r=>hasDevice(r, device));
  rows = filterBySearch(rows);
  rows = applySorting(rows,'employees');
  const total = rows.length;
  document.getElementById('emp-count').textContent = `${total.toLocaleString()} employees`;
  _renderOverlapNote();
  const page = paginate(rows,'employees');
  document.getElementById('emp-tbody').innerHTML = page.map((r,i)=>{
    const globalIdx = DATA.activeEmployees.indexOf(r);
    return `<tr data-emp-idx="${globalIdx}">
      ${cellMono(r['Worker ID'])}
      ${cellName(r['First/Last'])}
      ${cell(r['Job Name'])}
      ${cell(r['Department']?.replace(/^[A-Z0-9]+ - /,''))}
      <td>${payClassBadge(r['Pay Class'])}</td>
      ${cell(r['Functional Leader'])}
      ${devicePillsFromLookup(r['Username'], empDevMap)}
      ${actionsCell('employees',globalIdx,r)}
    </tr>`;
  }).join('') || `<tr><td colspan="8" class="empty-state"><div class="empty-icon">👤</div><div class="empty-title">No employees found</div></td></tr>`;
  renderPagination('emp-pagination','emp-page-info',total,'employees');
}

// ============================================================
// TERMS
// ============================================================
function renderTerms() {
  let rows = [...DATA.terms];
  const leader = document.getElementById('terms-filter-leader')?.value;
  if (leader) rows = rows.filter(r=>r['Functional Leader']===leader);
  rows = filterBySearch(rows);
  rows = applySorting(rows,'terms');
  const total = rows.length;
  document.getElementById('terms-count').textContent = `${total.toLocaleString()} records`;
  const page = paginate(rows,'terms');
  document.getElementById('terms-tbody').innerHTML = page.map((r)=>{
    const globalIdx = DATA.terms.indexOf(r);
    const td = r['Termination Date']||'';
    const dateStr = td.includes('T')?td.split('T')[0]:td.split(' ')[0];
    return `<tr>
      ${cellMono(r['Worker ID'])}
      ${cellName(r['First/Last'])}
      ${cell(r['Job Name'])}
      ${cell(r['Department']?.replace(/^[A-Z0-9]+ - /,''))}
      <td>${payClassBadge(r['Pay Class'])}</td>
      ${cell(dateStr)}
      ${cell(r['Functional Leader'])}
    </tr>`;
  }).join('') || '<tr><td colspan="7" style="text-align:center;padding:40px;color:var(--text3)">No records</td></tr>';
  renderPagination('terms-pagination','terms-page-info',total,'terms');
}

// ============================================================
// INTUNE
// ============================================================
// FIX5-20261017 (DR-06): the OS and compliance selects were hard-coded, so
// Windows (277 devices), In grace and Unknown could not be filtered at all.
// Options are rebuilt from the values actually present; the current choice is
// kept, and the option value is the raw value the filter compares against.
const _COMPLIANCE_LABELS = { compliant: 'Compliant', noncompliant: 'Noncompliant', ingraceperiod: 'In grace period', unknown: 'Unknown', grace: 'In grace period' };
function _syncFilterOptions(id, rows, field, allLabel, labelOf) {
  const sel = document.getElementById(id);
  if (!sel) return;
  const vals = [...new Set(rows.map(r => r[field]).filter(v => v != null && String(v).trim() !== '').map(String))]
    .sort((a, b) => cmpText(a, b));
  const sig = vals.join('\u0001');
  if (sel.dataset.optSig === sig) return;
  const cur = sel.value;
  sel.innerHTML = '';
  sel.appendChild(new Option(allLabel, ''));
  vals.forEach(v => sel.appendChild(new Option(labelOf ? labelOf(v) : v, v)));
  sel.value = vals.some(v => v.toLowerCase() === cur.toLowerCase()) ? vals.find(v => v.toLowerCase() === cur.toLowerCase()) : '';
  sel.dataset.optSig = sig;
}
const _complianceLabel = v => _COMPLIANCE_LABELS[String(v).toLowerCase()] || v;

// One status vocabulary for the dashboard distribution and its filtered list.
function intuneComplianceKey(value) {
  const s = String(value || '').toLowerCase().replace(/[^a-z]/g, '');
  if (s === 'compliant') return 'compliant';
  if (s.includes('grace')) return 'grace';
  if (s === 'noncompliant') return 'noncompliant';
  return 'unknown';
}

function renderIntune() {
  let rows = DATA.intuneDevices.filter(d => !d['is_historical']);
  _syncFilterOptions('intune-filter-os', rows, 'OS', 'All OS');
  _syncFilterOptions('intune-filter-compliance', ['compliant','grace','noncompliant','unknown'].map(Compliance => ({Compliance})), 'Compliance', 'All Compliance', _complianceLabel);
  const os   = document.getElementById('intune-filter-os')?.value;
  const comp = document.getElementById('intune-filter-compliance')?.value;
  const live = document.getElementById('intune-filter-live')?.value;
  if (os)   rows = rows.filter(r=>r['OS']===os);
  if (comp) rows = rows.filter(r => intuneComplianceKey(r['Compliance']) === intuneComplianceKey(comp));
  if (live === 'confirmed') rows = rows.filter(r => {
    const sKey = (r['Serial number']||'').toLowerCase().trim();
    return !!_intuneGraphMap[sKey];
  });
  if (live === 'not-found') rows = rows.filter(r => {
    const sKey = (r['Serial number']||'').toLowerCase().trim();
    return !_intuneGraphMap[sKey];
  });
  rows = filterBySearch(rows);
  rows = applySorting(rows,'intune');
  const total = rows.length;
  document.getElementById('intune-count').textContent = `${total.toLocaleString()} devices`;
  const page = paginate(rows,'intune');
  document.getElementById('intune-tbody').innerHTML = page.map((r)=>{
    const globalIdx = DATA.intuneDevices.indexOf(r);

    // Live Graph lookup by serial number
    const sKey  = (r['Serial number']||'').toLowerCase().trim();
    const live  = _intuneGraphMap[sKey] || null;
    let liveBadge;
    if (!sKey || sKey === '—') {
      liveBadge = `<td><span class="badge badge-gray">⚪ No Serial</span></td>`;
    } else if (live) {
      liveBadge = `<td><span class="badge badge-green" title="Confirmed active in Intune live data">✓ Active</span></td>`;
    } else if (_intuneGraphMapError) {
      liveBadge = `<td><span class="badge badge-yellow" title="Live Intune status unavailable — backend error">⚠ Status unavailable</span></td>`;
    } else {
      liveBadge = `<td><span class="badge badge-yellow" title="In import but not found in live Intune — may be decommissioned">⚠ Not in Live</span></td>`;
    }

    // Combine live status + compliance into one cell
    const compStatus = (r['Compliance']||'').toLowerCase();
    const compFlag = compStatus === 'compliant'
      ? '<div style="font-size:8px;margin-top:2px"><span class="badge badge-green" style="font-size:8px">✓ Compliant</span></div>'
      : compStatus === 'noncompliant'
      ? '<div style="font-size:8px;margin-top:2px"><span class="badge badge-red" style="font-size:8px">✗ Non-Compliant</span></div>'
      : compStatus
      ? '<div style="font-size:8px;margin-top:2px"><span class="badge badge-gray" style="font-size:8px">' + esc(r['Compliance']) + '</span></div>'
      : '';
    const statusCell = '<td style="text-align:center">' + liveBadge.replace('<td>','').replace('</td>','') + compFlag + '</td>';

    return `<tr data-emp-user="${esc(r['Primary user UPN'])}">
      <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(r['Device name']||'—')}">${esc(r['Device name']||'—')}</td>
      <td style="max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(r['Primary user UPN']||'')}"><span class="cell-email">${esc(r['Primary user UPN']||'—')}</span></td>
      ${cell(r['OS']?.replace(' (Fully Managed)','').replace('Android','Android'))}
      ${cellMono(r['OS version'])}
      <td style="max-width:100px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(r['Model']||'')}">${esc(r['Model']||'—')}</td>
      ${cellMono(r['Serial number'])}
      ${cellPhone(r['Phone number'])}
      <td class="cell-mono" style="max-width:120px;overflow:hidden;text-overflow:ellipsis" title="${esc(r['IMEI']||'')}">${esc(r['IMEI']||'—')}</td>
      <td>${carrierBadge(r['Carrier'])}</td>
      ${statusCell}
      ${actionsCell('intune',globalIdx,r)}
    </tr>`;
  }).join('') || '<tr><td colspan="11" style="text-align:center;padding:40px;color:var(--text3)">No devices</td></tr>';
  renderPagination('intune-pagination','intune-page-info',total,'intune');
}

// ============================================================
// MACBOOKS
// ============================================================
function renderMacbooks() {
  let rows = [...DATA.macbooks];
  rows = filterBySearch(rows);
  rows = applySorting(rows,'macbooks');
  const total = rows.length;
  const page = paginate(rows,'macbooks');
  document.getElementById('macbooks-tbody').innerHTML = page.map((r)=>{
    const globalIdx = DATA.macbooks.indexOf(r);
    const ci = r['Checked In']||'';
    // KIT2-20261017 (DR-13): was substring(0,10), which cut "Sep 29, 2026, 03:26 AM"
    // to "Sep 29, 20". Drop only the time; the full value is the cell title.
    const ciShort = ci.replace(/,?\s+\d{1,2}:\d{2}(:\d{2})?\s*(AM|PM)?\s*$/i, '');
    return `<tr data-emp-user="${esc(r['User'])}">
      ${cellMono(r['Device Name'])}
      ${cellName(r['User'])}
      ${cell(r['Model'])}
      ${cell(r['Chip'])}
      ${cellMono(r['OS Version'])}
      ${cellMono(r['Serial'])}
      ${cell(r['Blueprint'])}
      <td title="${esc(ci)}">${esc(ciShort||'—')}</td>
      ${abmWarrantyCell(r['Serial'])}
      ${actionsCell('macbooks',globalIdx,r)}
    </tr>`;
  }).join('') || '<tr><td colspan="10" style="text-align:center;padding:40px;color:var(--text3)">No MacBooks</td></tr>';
  renderAbmCoverageNotice('mac-abm-notice', DATA.macbooks);
  renderPagination('macbooks-pagination','macbooks-page-info', total, 'macbooks');
}

// ============================================================
// IPADS
// ============================================================
function renderIPads() {
  let rows = [...DATA.ipadDevices];
  const missingFilter = document.getElementById('ipad-filter-missing')?.value;
  if (missingFilter === 'missing') rows = rows.filter(r => r['Is Missing'] == 1 || r['Is Missing'] === true);
  if (missingFilter === 'active')  rows = rows.filter(r => !r['Is Missing'] || r['Is Missing'] == 0);
  rows = filterBySearch(rows);
  rows = applySorting(rows,'ipads');
  const total = rows.length;
  document.getElementById('ipad-count').textContent = `${total.toLocaleString()} iPads`;
  const page = paginate(rows,'ipads');
  document.getElementById('ipads-tbody').innerHTML = page.map((r) => {
    const isMissing = r['Is Missing'] == 1 || r['Is Missing'] === true;
    const statusBadgeHtml = isMissing
      ? `<span class="badge badge-red">⚠ Missing</span>`
      : `<span class="badge badge-green">✓ Active</span>`;
    return `<tr data-emp-user="${esc(r['User'])}">
      ${cellMono(r['Device Name'])}
      ${cellName(r['User'])}
      ${cell(r['Model'])}

      ${cellMono(r['OS Version'])}
      ${cellMono(r['Serial'])}
      ${cell(r['Blueprint'])}
      ${cell(r['Checked In'])}
      ${abmWarrantyCell(r['Serial'])}
      <td>${statusBadgeHtml}</td>
      <td>${window.Inventory360?window.Inventory360.sourceAction('ipads',r):'Device details unavailable'}</td>
    </tr>`;
  }).join('') || '<tr><td colspan="10" style="text-align:center;padding:40px;color:var(--text3)">No iPads found</td></tr>';
  renderAbmCoverageNotice('ipad-abm-notice', DATA.ipadDevices);
  renderPagination('ipad-pagination','ipad-page-info', total, 'ipads');
}

// ============================================================
// KANDJI SYNC
// ============================================================
async function loadIntuneSyncStatus() {
  const el = document.getElementById('intune-sync-status');
  try {
    const res = await fetch(`${WARRANTY_BASE}/api/intune-graph/status`);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    if (data.last_synced) {
      const d = new Date(data.last_synced);
      if (el) el.textContent =
        'Last synced: ' + d.toLocaleDateString('en-US', { month:'short', day:'numeric', year:'numeric', hour:'2-digit', minute:'2-digit' });
      const sub = document.getElementById('intune-sync-sub');
      if (sub) sub.textContent = ` · ${data.total} devices · Click "Sync from Intune" to refresh now (~30 sec)`;
    }
  } catch(e) {
    if (el) el.textContent = 'Sync status unavailable — backend error';
    console.warn('loadIntuneSyncStatus failed:', e && e.message);
  }
}

async function triggerIntuneSync() {
  const btn     = document.getElementById('intune-sync-btn');
  const spinner = document.getElementById('intune-sync-spinner');
  btn.disabled  = true;
  btn.textContent = 'Syncing…';
  spinner.classList.add('active');
  document.getElementById('intune-sync-status').textContent = 'Syncing with Intune…';
  try {
    // Step 1: Refresh graph cache from live Intune
    const sync1 = await fetch(`${WARRANTY_BASE}/api/intune-graph/sync`, { method: 'POST' }).then(r => r.json());
    if (!sync1.success) throw new Error(sync1.error || 'Graph sync failed');

    // Step 2: Push cache to intune_devices
    const sync2 = await fetch(`${WARRANTY_BASE}/api/intune-graph/sync-to-devices`, { method: 'POST' }).then(r => r.json());
    if (!sync2.success) throw new Error(sync2.error || 'Sync-to-devices failed');

    showToast(`✓ Synced ${sync2.total} devices (${sync2.historical_tablets?.added || 0} historical tablets)`);

    // Reload intune data
    DATA.intuneDevices = await apiGet('intune');
    bumpDataVersion();
    _epModelFromIntune = null; // endpoints Model fallback indexes Intune — refresh
    document.getElementById('badge-intune').textContent = DATA.intuneDevices.filter(d => !d['is_historical']).length;
    await loadIntuneSyncStatus();
    renderIntune();
  } catch(e) {
    showToast('Intune sync error: ' + e.message, 'err');
  } finally {
    btn.disabled = false;
    btn.textContent = '⟳ Sync from Intune';
    spinner.classList.remove('active');
  }
}

async function loadKandjiSyncStatus() {
  const el = document.getElementById('mac-sync-status');
  const ipadEl = document.getElementById('ipad-sync-status');
  try {
    const res = await fetch(`${WARRANTY_BASE}/api/kandji-sync/status`);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const s = await res.json();
    if (s.last_synced) window._diFeedAsOf.kandji = s.last_synced;
    const sub = document.getElementById('mac-sync-sub');
    if (el && s.last_synced) {
      el.textContent = `Last synced: ${new Date(s.last_synced).toLocaleString()} · ${s.macs} Macs · ${s.ipads} iPads`;
      if (sub) sub.textContent = ' · Click "Sync from Kandji" to refresh now' + _diFeedAgeNote('kandji');
    }
    if (ipadEl && s.last_synced) {
      ipadEl.textContent = `Last synced: ${new Date(s.last_synced).toLocaleString()} · ${s.ipads} iPads`;
    }
  } catch(e) {
    if (el) el.textContent = 'Sync status unavailable — backend error';
    if (ipadEl) ipadEl.textContent = 'Sync status unavailable — backend error';
    console.warn('loadKandjiSyncStatus failed:', e && e.message);
    _degrade('kandji-sync-status', 'Sync status unavailable — backend error', 'GET /api/kandji-sync/status: ' + (e && e.message));
  }
}

// Swap a button's visible label without destroying its leading
// <span class="ms">…</span> icon child. `btn.textContent = …` replaced the whole
// subtree, so after one sync the button permanently lost its icon.
function setBtnLabel(btn, text) {
  if (!btn) return;
  const last = btn.lastChild;
  if (last && last.nodeType === 3) last.nodeValue = ' ' + text;
  else btn.appendChild(document.createTextNode(' ' + text));
}

async function triggerKandjiSync() {
  // Both the MacBooks page and the iPads page mount this same button, so the
  // controls to drive are the ones on the page the click came from. Hardcoding
  // mac-* left an iPad user with no spinner, no disabled state and no status
  // line for the ~30s the sync runs — every affordance fed a hidden page.
  const p       = currentPage === 'ipads' ? 'ipad' : 'mac';
  const btn     = document.getElementById(p + '-sync-btn');
  const spinner = document.getElementById(p + '-sync-spinner');
  const status  = document.getElementById(p + '-sync-status');
  if (btn) btn.disabled = true;
  setBtnLabel(btn, 'Syncing…');
  if (spinner) spinner.classList.add('active');
  if (status) status.textContent = 'Syncing with Kandji…';
  try {
    const res  = await fetch(`${WARRANTY_BASE}/api/kandji-sync/sync`, { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      const removed = data.removed > 0 ? `, ${data.removed} removed` : '';
      showToast(`✓ Synced ${data.synced} MacBooks (${data.errors} errors${removed})`);
      DATA.macbooks    = await apiGet('macbooks');
      DATA.ipadDevices = await apiGet('ipads');
      bumpDataVersion();
      document.getElementById('badge-mac').textContent   = DATA.macbooks.length;
      document.getElementById('badge-ipads').textContent = DATA.ipadDevices.length;
      await loadKandjiSyncStatus();
      renderMacbooks();
      if (currentPage === 'ipads') renderIPads();
    } else {
      showToast('Kandji sync failed: ' + (data.error || 'Unknown error'), 'err');
    }
  } catch(e) {
    showToast('Kandji sync error: ' + e.message, 'err');
  } finally {
    if (btn) btn.disabled = false;
    // No '⟳' prefix: the button already carries a Material Symbols `sync`
    // icon child, which the old textContent write destroyed and replaced.
    setBtnLabel(btn, 'Sync from Kandji');
    if (spinner) spinner.classList.remove('active');
  }
}

// ============================================================
// ENDPOINTS
// ============================================================
function renderEndpoints() {
  // Show only Windows devices — exclude Macs, servers, AWS WorkSpaces
  let rows = DATA.endpoints.filter(isWindowsEndpoint);
  const type = document.getElementById('ep-filter-type')?.value;
  const intuneFilter = document.getElementById('ep-filter-intune')?.value;
  const patchFilter = document.getElementById('ep-filter-patch')?.value;
  if (type) rows = rows.filter(r=>inferEndpointType(r)===type);
  if (intuneFilter === 'enrolled')    rows = rows.filter(r => {
    const k = (r['Service Tag']||r['Computer Name']||'').toLowerCase().trim();
    return _intuneGraphMap[k] || _intuneGraphMap['name:'+r['Computer Name']?.toLowerCase().trim()];
  });
  // KIT2-20261017 (DR-12): devices with no patch data had no option at all.
  if (patchFilter === '__none') rows = rows.filter(r => !r['Patch Health']);
  else if (patchFilter) rows = rows.filter(r => (r['Patch Health'] || '') === patchFilter);
  if (intuneFilter === 'not-enrolled') rows = rows.filter(r => {
    const k = (r['Service Tag']||r['Computer Name']||'').toLowerCase().trim();
    return !_intuneGraphMap[k] && !_intuneGraphMap['name:'+r['Computer Name']?.toLowerCase().trim()];
  });
  rows = filterBySearch(rows);
  rows = applySorting(rows,'endpoints');
  const total = rows.length;
  document.getElementById('ep-count').textContent = `${total.toLocaleString()} endpoints`;
  const page = paginate(rows,'endpoints');
  document.getElementById('endpoints-tbody').innerHTML = page.map((r)=>{
    const globalIdx = DATA.endpoints.indexOf(r);

    // Intune lookup — service tag first, fall back to computer name
    const sKey  = (r['Service Tag']||'').toLowerCase().trim();
    const nKey  = 'name:' + (r['Computer Name']||'').toLowerCase().trim();
    const intune = _intuneGraphMap[sKey] || _intuneGraphMap[nKey] || null;

    const intuneBadge = intuneBadgeHTML(!!intune, intune?.compliance);

    // User field — color-code based on source
    const epUser = r['First/Last'] || r['Currently Logged on Users'] || '';
    const userSource = r['user_source'] || 'me';
    const userCell = userSource === 'intune'
      ? `<td><span style="color:var(--teal);font-weight:500" title="User from Intune — not in ManageEngine">${esc(epUser)}</span><span style="font-size:9px;color:var(--teal);margin-left:4px;opacity:.7">⬡ Intune</span></td>`
      : `<td class="cell-name">${esc(epUser||'—')}</td>`;

    return `<tr data-emp-user="${esc(r['First/Last'])}">
      <td class="cell-mono">${esc(r['Computer Name']||'—')} ${(function(){
        const os = (r['OS Name']||'');
        const ver = (r['OS Version']||'');
        const buildMap = {'10.0.26200':'25H2','10.0.22631':'23H2','10.0.22621':'22H2','10.0.19045':'22H2','10.0.19044':'21H2','10.0.19043':'21H1'};
        const m = ver.match(/Version\s+(\w+)/i) || ver.match(/(\d+H\d)/i);
        const build = m ? m[1] : (buildMap[ver] || '');
        if (os.includes('11') && build) return '<span class="badge badge-blue" style="font-size:9px;margin-left:4px">Win 11 '+build+'</span>';
        if (os.includes('11')) return '<span class="badge badge-blue" style="font-size:9px;margin-left:4px">Win 11</span>';
        if (os.includes('10') && build) return '<span class="badge badge-gray" style="font-size:9px;margin-left:4px">Win 10 '+build+'</span>';
        if (os.startsWith('Windows') && build) return '<span class="badge badge-gray" style="font-size:9px;margin-left:4px">Win '+build+'</span>';
        if (os.startsWith('Windows')) return '<span class="badge badge-gray" style="font-size:9px;margin-left:4px">Windows</span>';
        return '';
      })()}</td>
      ${userCell}
      ${cell(inferEndpointModel(r))}
      <td>${(function(){const t=inferEndpointType(r);return t?badge(t,t==='LAPTOP'?'blue':'gray'):'—';})()}</td>
      ${cellMono(r['Service Tag'])}
      ${cell(r['Last Successful Asset Scan'])}
      ${intuneBadge}
      ${patchHealthBadge(r.resource_id)}
      <td class="actions">
        ${window.Inventory360?window.Inventory360.sourceAction('endpoints',r):''}
        <button data-rbac-page="it-inventory" data-rbac-level="admin" class="btn btn-ghost btn-sm" onclick="editRecord('endpoints',${_encodeRef(r, globalIdx)})">Edit</button>
        <button data-rbac-page="it-inventory" data-rbac-level="admin" class="btn btn-danger btn-sm" onclick="deleteRecord('endpoints',${_encodeRef(r, globalIdx)})" style="margin-left:4px">Del</button>
        ${/* URL/attribute context, not text: resource_id is ManageEngine-supplied, and a
             bare double quote in it closes the href and lets the rest of the value add its
             own attributes to the anchor — no < required, so esc()'s text-context coverage
             is not the point here. encodeURIComponent is the correct escape for a URL path
             segment and neutralises the quote as a side effect. */
          r.resource_id ? `<a class="btn btn-ghost btn-sm" href="https://endpointcentral.manageengine.com/webclient#/uems/patch-mgmt/systems/computer/${encodeURIComponent(r.resource_id)}/summary" target="_blank" rel="noopener" style="margin-left:4px;text-decoration:none" title="Open in ManageEngine">⟳ ME</a>` : ''}
      </td>
    </tr>`;
  }).join('') || '<tr><td colspan="9" style="text-align:center;padding:40px;color:var(--text3)">No endpoints</td></tr>';
  renderPagination('ep-pagination','ep-page-info',total,'endpoints');
}

// ============================================================
// LIVE AUCTION
// ============================================================
function renderLiveAuction() {
  let rows = [...DATA.liveAuction];
  const state = document.getElementById('la-filter-state')?.value;
  const regional = document.getElementById('la-filter-regional')?.value;
  const status = document.getElementById('la-filter-status')?.value;
  if (state) rows = rows.filter(r=>r['State']===state);
  if (regional) rows = rows.filter(r=>r['Regional']===regional);
  if (status) rows = rows.filter(r=>r['Active/Inactive']===status);
  rows = filterBySearch(rows);
  rows = applySorting(rows,'liveauction');
  const total = rows.length;
  document.getElementById('la-count').textContent = `${total.toLocaleString()} devices`;

  // Summary chips
  const active = rows.filter(r=>r['Active/Inactive']==='Active').length;
  const states = new Set(rows.map(r=>r['State']).filter(_kit2IsState)).size;  // KIT2-20261017 (DR-19)
  document.getElementById('la-summary').innerHTML = `
    <div class="summary-chip"><strong>${total}</strong><span>Total Devices</span></div>
    <div class="summary-chip"><strong>${active}</strong><span>Active</span></div>
    <div class="summary-chip"><strong>${total-active}</strong><span>Inactive</span></div>
    <div class="summary-chip"><strong>${states}</strong><span>States Covered</span></div>
  `;

  const page = paginate(rows,'liveauction');
  document.getElementById('la-tbody').innerHTML = page.map((r)=>{
    const globalIdx = DATA.liveAuction.indexOf(r);
    return `<tr data-emp-user="${esc(r['First/Last'])}">
      ${cellMono(r['Device ID1'])}
      ${cellName(r['First/Last'])}
      ${cell(r['Model']?.replace('Samsung Galaxy Tab S7 FE 5G (SMT738UZKA)','Galaxy Tab S7 FE'))}
      ${cell(r['Device Type'])}
      <td>${_kit2StateBadge(r['State'])}</td>
      ${cell(r['Regional'])}
      <td>${statusBadge(r['Active/Inactive'])}</td>
      ${cell(r['Verizon']?'Verizon':'T-Mobile')}
      ${cellMono(r['IMEI'])}
      ${actionsCell('liveauction',globalIdx,r)}
    </tr>`;
  }).join('') || '<tr><td colspan="10" style="text-align:center;padding:40px;color:var(--text3)">No devices</td></tr>';
  renderPagination('la-pagination','la-page-info',total,'liveauction');
}

// ============================================================
// TMOBILE
// ============================================================
function renderTmobile() {
  let rows = [...DATA.tmobile];
  const intuneFilter = document.getElementById('tm-filter-intune')?.value;
  if (intuneFilter) {
    rows = rows.filter(r => {
      const reg = r['Intune Registered'] || 'unknown';
      return intuneFilter === 'enrolled' ? reg === 'yes' : reg !== 'yes';
    });
  }
  rows = filterBySearch(rows);
  rows = applySorting(rows,'tmobile');
  const total = rows.length;
  document.getElementById('tm-count').textContent = `${total.toLocaleString()} lines`;
  const page = paginate(rows,'tmobile');
  document.getElementById('tm-tbody').innerHTML = page.filter(r=>r).map((r)=>{
    const globalIdx = DATA.tmobile.indexOf(r);
    // Raw-DB aliases dropped throughout this row: TABLES.tmobile maps line, imei,
    // device_type, intune_registered and intune_compliance, and dbToApp renames
    // every mapped column before emitting — those lowercase reads could never
    // resolve. ('Line' is neither a mapped app key nor a passthrough column name;
    // passthrough columns arrive under their raw lowercase DB name.) The keys
    // that ARE raw here — rate_plan_cost / total_minutes / total_data and
    // description1 / description3 — are unmapped columns and stay as they are.
    const phone = r['Phone Number'] || '—';
    const user = r['description1'] || r['User'] || '—';
    const dept = r['description3'] || r['Department'] || '—';
    const rawCost = r['rate_plan_cost'] || r['Cost'];
    const cost = rawCost ? '$'+parseFloat(rawCost).toFixed(2) : '—';
    const imei = r['IMEI'] || '—';
    const device = r['Device'] || '—';
    const rawMins = r['total_minutes'] || r['Minutes'];
    const mins = rawMins ? parseFloat(rawMins).toFixed(1) : '—';
    const rawData = r['total_data'] || r['Total Data'];
    const data = rawData ? parseFloat(rawData).toFixed(3)+'GB' : '—';
    const intuneReg = r['Intune Registered'] || 'unknown';
    const intuneComp = r['Intune Compliance'] || 'unknown';
    const intuneBadge = intuneReg === 'yes' ? intuneBadgeHTML(true, intuneComp)
                      : intuneReg === 'no'  ? intuneBadgeHTML(false, null)
                      : '<td><span class="badge badge-gray">— Unknown</span></td>';
    return '<tr data-emp-user="'+esc(user)+'">' +
      cellPhone(phone) +
      cellName(user) +
      cell(dept) +
      cell(cost) +
      cellMono(imei) +
      cell(device) +
      '<td style="font-family:var(--mono);font-size:11px">'+mins+'</td>' +
      '<td style="font-family:var(--mono);font-size:11px">'+data+'</td>' +
      intuneBadge +
      actionsCell('tmobile',globalIdx,r) +
    '</tr>';
  }).join('') || '<tr><td colspan="10" style="text-align:center;padding:40px;color:var(--text3)">No lines</td></tr>';
  renderPagination('tm-pagination','tm-page-info',total,'tmobile');
}

// ============================================================
// VERIZON
// ============================================================
let _vzIntuneMap = null;
let _vzIntuneMapVersion = -1;
function buildVerizonIntuneMap() {
  // Rebuilt over all 1,110 Intune rows inside renderVerizon() on every render.
  if (_vzIntuneMap && _vzIntuneMapVersion === DATA_VERSION) return _vzIntuneMap;
  const map = {};
  (DATA.intuneDevices||[]).forEach(d => {
    if (d['IMEI']) map[String(d['IMEI']).toLowerCase().trim()] = d['Compliance']||'unknown';
    if (d['Phone number']) map[String(d['Phone number']).replace(/\D/g,'').slice(-10)] = d['Compliance']||'unknown';
  });
  _vzIntuneMap = map;
  _vzIntuneMapVersion = DATA_VERSION;
  return map;
}

function renderVerizon() {
  let rows = [...DATA.verizon];
  const type = document.getElementById('vz-filter-type')?.value;
  const vzIntuneFilter = document.getElementById('vz-filter-intune')?.value;
  const vzIntuneMap = buildVerizonIntuneMap();
  // KIT2-20261017 (DR-19): business gateways arrive typed SMARTPHONE.
  _syncFilterOptions('vz-filter-type', DATA.verizon.map(r => ({t: _kit2VzType(r)})), 't', 'All Device Types');
  if (type) rows = rows.filter(r=>_kit2VzType(r)===type);
  if (vzIntuneFilter) {
    rows = rows.filter(r => {
      const imei = String(r['IMEI']||'').toLowerCase().trim();
      const phone = String(r['Phone number']||'').replace(/\D/g,'').slice(-10);
      const found = vzIntuneMap[imei] !== undefined || vzIntuneMap[phone] !== undefined;
      return vzIntuneFilter === 'enrolled' ? found : !found;
    });
  }
  rows = filterBySearch(rows);
  rows = applySorting(rows,'verizon');
  const total = rows.length;
  document.getElementById('vz-count').textContent = `${total.toLocaleString()} lines`;
  const page = paginate(rows,'verizon');
  function vzIntuneBadge(r) {
    const imei = String(r['IMEI']||'').toLowerCase().trim();
    const phone = String(r['Phone number']||'').replace(/\D/g,'').slice(-10);
    const comp = vzIntuneMap[imei] || vzIntuneMap[phone] || null;
    return intuneBadgeHTML(comp !== null, comp);
  }
  document.getElementById('vz-tbody').innerHTML = page.map((r)=>{
    const globalIdx = DATA.verizon.indexOf(r);
    const statusMap = {'A':'Active','I':'Inactive','S':'Suspended'};
    return `<tr data-emp-user="${esc(r['Username'])}">
      ${cellPhone(r['Phone number'])}
      ${cellName(r['Username'])}
      ${cell(r['Department'])}
      ${cell(r['Functional Leader'])}
      ${cell(r['Equipment Model'])}
      ${cell(_kit2VzType(r))}
      <td>${statusBadge(statusMap[r['Service Status']]||r['Service Status'])}</td>
      ${vzIntuneBadge(r)}
      ${actionsCell('verizon',globalIdx,r)}
    </tr>`;
  }).join('') || '<tr><td colspan="10" style="text-align:center;padding:40px;color:var(--text3)">No lines</td></tr>';
  renderPagination('vz-pagination','vz-page-info',total,'verizon');
}

// ============================================================
// AWS
// ============================================================
function renderAWS() {
  let rows = [...DATA.awsWorkspaces];
  rows = filterBySearch(rows);
  rows = applySorting(rows,'aws');
  const total = rows.length;
  const page = paginate(rows,'aws');
  document.getElementById('aws-tbody').innerHTML = page.map((r)=>{
    const globalIdx = DATA.awsWorkspaces.indexOf(r);
    return `<tr data-emp-user="${esc(r['Username'])}">
      ${cellMono(r['WorkSpace ID'])}
      ${cellName(r['First/Last'])}
      ${cell(r['Username'])}
      ${cell(r['Compute'])}
      ${cell(r['Root volume'])}
      ${cell(r['User volume'])}
      ${cell(r['Operating system'])}
      ${cell(r['Running mode'])}
      <td>${statusBadge(r['Status'])}</td>
      ${actionsCell('aws',globalIdx,r)}
    </tr>`;
  }).join('') || '<tr><td colspan="10" style="text-align:center;padding:40px;color:var(--text3)">No workspaces</td></tr>';
  renderPagination('aws-pagination','aws-page-info', total, 'aws');
}

// ============================================================
// DEVICE INVENTORY (v1.3.4 — device-centric)
// One row per selected source record. Unassigned and terminated-user
// devices are visible; source observations of one device can overlap.
// Known redundant endpoint categories are excluded:
//   - endpoints excludes WSAMZN-* (owned by AWS) and Macs (owned by Kandji)
//   - Servers (OS contains 'server') surface as type 'Server'
// ============================================================
// Liveness is judged against the feed's own snapshot time, not the wall clock: a
// Kandji or ManageEngine sync that last ran two weeks ago would otherwise age every
// device into Stale/Inactive while the truth is 'not measured since <date>'. The
// status loaders record the snapshot time when they learn it.
window._diFeedAsOf = window._diFeedAsOf || {};
function _diFeedNow(feed) {
  const at = window._diFeedAsOf[feed];
  const t = at ? new Date(at).getTime() : NaN;
  return isNaN(t) ? Date.now() : t;
}
function _diFeedAgeNote(feed) {
  const at = window._diFeedAsOf[feed];
  if (!at) return '';
  const h = (Date.now() - new Date(at).getTime()) / 3600000;
  return h > 26 ? ' · ⚠ snapshot is ' + Math.floor(h / 24) + 'd old — Active/Stale reflect that date, not today' : '';
}
function _degrade(widget, text, detail) {
  try { if (window.ITObserve && typeof ITObserve.degraded === 'function') ITObserve.degraded(widget, text, detail || null); } catch (e) {}
}
function _diKandjiStatus(r) {
  if (r['Is Missing']) return 'Missing';
  const ci = r['Checked In'];
  if (!ci) return 'Unknown';
  const days = Math.floor((_diFeedNow('kandji') - new Date(ci)) / 86400000);
  if (isNaN(days)) return 'Unknown';
  if (days <= 14) return 'Active';
  if (days <= 60) return 'Stale';
  return 'Inactive';
}

// ManageEngine endpoints carry no Active/Inactive column — that key belongs to
// the liveauction table ('Active/Inactive':'active_inactive' in TABLES.liveauction,
// BACKEND-core-api-server.js), and liveauction is not one of the six sources this
// page consumes. TABLES.endpoints emits only:
//   'Computer Name','Device Model','Computer Type','Currently Logged on Users',
//   'First/Last','Last Successful Asset Scan','Service Tag','OS Name','OS Version'
// so derive liveness from the scan date, mirroring _diKandjiStatus above; the
// Active/Stale/Inactive/Unknown vocabulary is what _diDeviceStatusBadge expects.
function _diEndpointStatus(r) {
  const ls = r['Last Successful Asset Scan'];
  if (!ls) return 'Unknown';
  const days = Math.floor((_diFeedNow('endpoints') - new Date(ls)) / 86400000);
  if (isNaN(days)) return 'Unknown';
  if (days <= 14) return 'Active';
  if (days <= 60) return 'Stale';
  return 'Inactive';
}

function _diDeviceStatusBadge(status) {
  const s = (status || '').toLowerCase();
  if (['active', 'compliant', 'available'].includes(s))
    return `<span class="badge badge-green">${esc(status)}</span>`;
  if (['missing', 'noncompliant', 'inactive', 'unhealthy', 'impaired'].includes(s))
    return `<span class="badge badge-red">${esc(status)}</span>`;
  if (['stale', 'unknown', 'pending'].includes(s))
    return `<span class="badge badge-amber">${esc(status)}</span>`;
  return `<span style="color:var(--text3)">${esc(status || '—')}</span>`;
}

function _diUserStatusBadge(s) {
  if (s === 'Active') return '<span class="badge badge-green">Active</span>';
  if (s === 'Terminated') return '<span class="badge badge-red">Terminated</span>';
  return '<span style="color:var(--text3)">—</span>';
}

function _diExtractUser(val) {
  if (!val || val === '--') return null;
  const parts = String(val).split(',').map(s => s.trim());
  for (const p of parts) {
    if (p.toLowerCase().includes('@auction.com')) {
      return p.toLowerCase().replace('@auction.com', '');
    }
  }
  const first = parts[0];
  return first && first !== '--' ? first.toLowerCase() : null;
}

let _diUniverse = null;
let _diUniverseVersion = -1;
function inventorySupportRef(table,record) {
  const sourceKeys={endpoints:'manageengine',macbooks:'kandji-mac',intune:'intune',ipads:'kandji-ipad',aws:'aws'};
  return {table,sourceKey:sourceKeys[table]||null,rowId:record._id??record.id??null,
    nativeId:table==='endpoints'?record.resource_id:table==='aws'?record['WorkSpace ID']:record.device_id??null};
}
function inventoryDeviceManufacturer(record) {
  return record['Manufacturer']||record['manufacturer']||record['device_manufacturer']||record['Device manufacturer']||record['deviceManufacturer']||null;
}

function buildDeviceUniverse() {
  // ~3,300 records assembled from six source tables and joined against
  // employees + terms. renderDeviceInventory() called this on every keystroke,
  // sort, filter and page click. Cached against the shared counter; every
  // caller treats the result as read-only (filter/slice, never sort-in-place).
  if (_diUniverse && _diUniverseVersion === DATA_VERSION) return _diUniverse;
  const recs = [];

  // Name → username fallback for Kandji 'User' fields stored as full name.
  // FIX5-20261017 (DR-01): Kandji sends display names such as
  // "Moises Ponce (SCII)". _diExtractUser() turns that into the lowercased
  // name, which is truthy, so the old `if (!key ...)` fallback never ran and
  // every MacBook missed the employee join (all 140 counted as unassigned).
  // Names are now resolved through Active AND Terminated, with any trailing
  // "(...)" suffix stripped; the key formats match empMap / termMap below.
  const _diNameKey = s => String(s || '').toLowerCase().replace(/\s*\([^)]*\)\s*$/, '').replace(/\s+/g, ' ').trim();
  const empByName = {}, termByName = {};
  (DATA.activeEmployees || []).forEach(e => {
    if (e['First/Last'] && e['Username']) {
      empByName[_diNameKey(e['First/Last'])] = e['Username'].toLowerCase().trim();
    }
  });
  (DATA.terms || []).forEach(e => {
    const k = (e['Username'] || e['username'] || _diExtractUser(e['Business Email']) || '').toLowerCase().trim();
    if (e['First/Last'] && k) termByName[_diNameKey(e['First/Last'])] = k;
  });

  // 1. ManageEngine endpoints — Windows laptops/desktops + Servers only
  (DATA.endpoints || []).forEach(r => {
    const os = (r['OS Name'] || '').toLowerCase();
    const name = (r['Computer Name'] || '').toUpperCase();
    if (name.startsWith('WSAMZN-')) return;                                   // AWS — owned by aws source
    if (os.includes('mac') || os.includes('darwin') || os.startsWith('os x')) return; // Mac — owned by Kandji
    let type = 'Other';
    if (os.includes('server')) type = 'Server';
    else if (os.startsWith('windows')) type = inferEndpointType(r);
    recs.push({
      type,
      model: inferEndpointModel(r) || '—',
      serial: r['Service Tag'] || r['Computer Name'] || '—',
      source: 'ManageEngine',
      manufacturer: inventoryDeviceManufacturer(r),
      support_ref: inventorySupportRef('endpoints',r),
      status: _diEndpointStatus(r),
      user_raw: r['First/Last'] || null,
      user_key: _diExtractUser(r['First/Last']),
    });
  });

  // 2. MacBooks (Kandji)
  (DATA.macbooks || []).forEach(r => {
    const user = (r['User'] || '').trim();
    let key = _diExtractUser(user);
    if (user && user !== '--' && !user.includes('@')) {
      const nameKey = _diNameKey(user);
      key = empByName[nameKey] || termByName[nameKey] || key;
    }
    recs.push({
      type: 'MacBook',
      model: r['Model'] || '—',
      serial: r['Serial'] || '—',
      source: 'Kandji',
      manufacturer: inventoryDeviceManufacturer(r),
      support_ref: inventorySupportRef('macbooks',r),
      status: _diKandjiStatus(r),
      user_raw: user && user !== '--' ? user : null,
      user_key: key,
    });
  });

  // 3. Intune iPhones (active only)
  (DATA.intuneDevices || []).forEach(r => {
    if (r['device_category'] !== 'iphone') return;
    if (r['is_historical']) return;
    recs.push({
      type: 'iPhone',
      manufacturer: inventoryDeviceManufacturer(r),
      model: r['Model'] || '—',
      serial: r['Serial number'] || r['IMEI'] || '—',
      source: 'Intune',
      support_ref: inventorySupportRef('intune',r),
      status: r['Compliance'] || 'Unknown',
      user_raw: r['Primary user UPN'] || null,
      user_key: _diExtractUser(r['Primary user UPN']),
    });
  });

  // 4. Intune tablets (active only)
  (DATA.intuneDevices || []).forEach(r => {
    if (r['device_category'] !== 'tablet') return;
    if (r['is_historical']) return;
    recs.push({
      type: 'Tablet',
      manufacturer: inventoryDeviceManufacturer(r),
      model: r['Model'] || '—',
      serial: r['Serial number'] || '—',
      source: 'Intune',
      support_ref: inventorySupportRef('intune',r),
      status: r['Compliance'] || 'Unknown',
      user_raw: r['Primary user UPN'] || null,
      user_key: _diExtractUser(r['Primary user UPN']),
    });
  });

  // Current Windows enrollments must also reach the shared HR join and
  // ownership queue. Keep their source identities separate from ME records;
  // Windows alone does not establish laptop/desktop chassis type.
  (DATA.intuneDevices || []).forEach(r => {
    if (r['is_historical'] || !/^windows/i.test(r['OS'] || '')) return;
    recs.push({
      type: 'Windows PC',
      manufacturer: inventoryDeviceManufacturer(r),
      model: r['Model'] || '—',
      serial: r['Serial number'] || r['Device name'] || '—',
      source: 'Intune',
      support_ref: inventorySupportRef('intune',r),
      status: r['Compliance'] || 'Unknown',
      user_raw: r['Primary user UPN'] || null,
      user_key: _diExtractUser(r['Primary user UPN']),
    });
  });

  // 5. iPads (Kandji iPad)
  const sharedIpadAccounts = new Set(['zoomo365', 'zoom', '--', '']);
  (DATA.ipadDevices || []).forEach(r => {
    const user = (r['User'] || '').trim();
    const lower = user.toLowerCase();
    const isShared = sharedIpadAccounts.has(lower);
    let key = null;
    if (!isShared) key = _diExtractUser(user) || lower || null;
    recs.push({
      type: 'iPad',
      manufacturer: inventoryDeviceManufacturer(r),
      model: r['Model'] || '—',
      serial: r['Serial'] || r['Service Tag'] || '—',
      source: 'Kandji iPad',
      support_ref: inventorySupportRef('ipads',r),
      status: _diKandjiStatus(r),
      user_raw: !isShared && user ? user : null,
      user_key: key,
    });
  });

  // 6. AWS WorkSpaces
  (DATA.awsWorkspaces || []).forEach(r => {
    const user = (r['Username'] || '').trim();
    const key = user && user !== '--' ? user.toLowerCase() : null;
    recs.push({
      type: 'AWS WorkSpace',
      model: r['Compute'] || '—',
      serial: r['WorkSpace ID'] || '—',
      source: 'AWS',
      support_ref: inventorySupportRef('aws',r),
      status: r['Status'] || 'Unknown',
      user_raw: key ? user : null,
      user_key: key,
    });
  });

  // Enrich with employee/term join
  const empMap = {}, termMap = {};
  (DATA.activeEmployees || []).forEach(e => {
    const k = (e['Username'] || '').toLowerCase().trim();
    if (k) empMap[k] = e;
  });
  // terminated_employees has no username column, so /api/terms never emits a
  // 'Username' key and termMap was permanently empty — the Terminated filter
  // and the red Terminated badge both returned nothing, forever. TABLES.terms
  // (BACKEND-core-api-server.js) is:
  //   'Worker ID','Status','Employee Name','First/Last','Business Email',
  //   'Job Name','Department','Location Name','Pay Class','Termination Date',
  //   'Functional Leader','Is Termination Reason'
  // Derive the key from Business Email exactly the way _diExtractUser derives
  // user_key from a UPN, so both sides of the join produce the same string. A
  // raw `username` passthrough is honoured first in case the column is added
  // later (dbToApp emits unmapped columns under their raw lowercase name).
  (DATA.terms || []).forEach(e => {
    const k = (e['Username'] || e['username'] || _diExtractUser(e['Business Email']) || '').toLowerCase().trim();
    if (k) termMap[k] = e;
  });
  // Stage / system accounts — not real assigned users
  const _SYSTEM_USERS = new Set([
    'defaultuser0', 'defaultuser1', 'administrator', 'admin',
    'guest', 'system', 'localservice', 'networkservice',
    'it-stage', 'setup'
  ]);
  recs.forEach(d => {
    if (d.user_key && _SYSTEM_USERS.has(d.user_key)) {
      d.user_key = null;
      d.user_raw = null;
    }
    if (!d.user_key) {
      d.user_status = null;
      d.user_name = null;
      d.manager = '';
      d.leader = '';
      return;
    }
    const empE = empMap[d.user_key];
    const termE = termMap[d.user_key];
    const e = empE || termE;
    if (e) {
      d.user_status = empE ? 'Active' : 'Terminated';
      d.user_name = e['First/Last'] || d.user_raw || '';
      d.manager   = e['Manager Name'] || '';
      d.leader    = e['Functional Leader'] || '';
    } else {
      d.user_status = null;
      d.user_name = d.user_raw || '';
      d.manager = '';
      d.leader = '';
    }
  });

  _diUniverse = recs;
  _diUniverseVersion = DATA_VERSION;
  return recs;
}

function renderDeviceInventory() {
  const universe = buildDeviceUniverse();
  let rows = universe;

  const typeF    = document.getElementById('di-filter-type')?.value;
  const sourceF  = document.getElementById('di-filter-source')?.value;
  const assignF  = document.getElementById('di-filter-assignment')?.value;
  const managerF = document.getElementById('di-filter-manager')?.value;

  if (typeF)    rows = rows.filter(r => r.type === typeF);
  if (sourceF)  rows = rows.filter(r => r.source === sourceF);
  if (assignF === 'unassigned')      rows = rows.filter(r => !r.user_key);
  else if (assignF === 'unmatched')  rows = rows.filter(r => r.user_key && r.user_status === null);
  else if (assignF === 'active')     rows = rows.filter(r => r.user_status === 'Active');
  else if (assignF === 'terminated') rows = rows.filter(r => r.user_status === 'Terminated');
  if (managerF) rows = rows.filter(r => r.manager === managerF);

  rows = filterBySearch(rows);
  rows = applySorting(rows, 'device-inventory');

  const total = rows.length;
  document.getElementById('di-count').textContent = total.toLocaleString() + ' source record' + (total===1?'':'s');
  const page = paginate(rows, 'device-inventory');
  document.getElementById('di-tbody').innerHTML = page.map(r => {
    const userInner = r.user_key
      ? esc(r.user_name || r.user_raw || '')
      : '<span style="color:var(--text3)">Unassigned</span>';
    return `<tr data-emp-user="${esc(r.user_key || r.user_name || '')}">
      ${cellMono(r.serial)}
      ${cell(r.model)}
      <td style="white-space:nowrap">${esc(r.source || '—')}</td>
      <td style="white-space:nowrap"><span class="badge badge-blue">${esc(r.type)}</span></td>
      <td style="white-space:nowrap">${_diDeviceStatusBadge(r.status)}</td>
      <td style="white-space:nowrap">${_diUserStatusBadge(r.user_status)}</td>
      <td>${userInner}</td>
      ${cell(r.manager)}
      ${cell(r.leader)}
      <td>${window.Inventory360?window.Inventory360.action(r):'Device details unavailable'}</td>
    </tr>`;
  }).join('') || '<tr><td colspan="10" style="text-align:center;padding:40px;color:var(--text3)">No devices found</td></tr>';
  renderPagination('di-pagination', 'di-page-info', total, 'device-inventory');

  // Populate manager dropdown once from the full unfiltered universe
  const mgrSel = document.getElementById('di-filter-manager');
  if (mgrSel && mgrSel.options.length <= 1) {
    const managers = [...new Set(universe.filter(r => r.manager).map(r => r.manager))].sort();
    const cur = mgrSel.value;
    mgrSel.innerHTML = '<option value="">All Managers</option>' +
      managers.map(m => `<option ${m === cur ? 'selected' : ''}>${esc(m)}</option>`).join('');
  }
}

function exportDeviceInventoryCSV() {
  const rows = buildDeviceUniverse();
  if (!rows.length) { showToast('No data to export', 'warn'); return; }
  const headers = ['Serial', 'Model', 'Source', 'Type', 'Status', 'User Status', 'Assigned User', 'Manager', 'Functional Leader'];
  const out = [headers.map(_csvEscape)];
  rows.forEach(r => out.push([
    r.serial,
    r.model,
    r.source,
    r.type,
    r.status,
    r.user_status || '',
    r.user_key ? (r.user_name || r.user_raw || '') : 'Unassigned',
    r.manager || '',
    r.leader || '',
  ].map(_csvEscape)));
  _downloadBlob(_toCsvBlob(out), `device_inventory_${new Date().toISOString().split('T')[0]}.csv`);
  showToast(`Exported ${rows.length.toLocaleString()} devices`);
}

// ============================================================
// DASHBOARD
// ============================================================
function buildDashboard() {
  if (!window._warrantyPreloaded && typeof loadWarrantyData === 'function') {
    window._warrantyPreloaded = true;
    loadWarrantyData().catch(e => console.warn('warranty preload failed:', e));
  }
  // Everything below renders into <div class="legacy-dash" hidden> in
  // IT_Inventory_App.html — that container is kept only so these DOM targets
  // still exist for this function. Eight panels, a canvas donut and a
  // buildDeviceLookup() pass over the whole fleet, painted for zero visible
  // pixels on every dashboard render. The warranty preload above is the one
  // side effect other pages depend on, so it stays ABOVE this guard; if the
  // container is ever unhidden, rendering resumes with no further change.
  const _legacyDash = document.querySelector('.legacy-dash');
  if (_legacyDash && _legacyDash.hasAttribute('hidden')) return;
  const emp = DATA.activeEmployees;
  const terms = DATA.terms;
  const intune = DATA.intuneDevices.filter(d => !d['is_historical']);
  const laptops  = DATA.endpoints.filter(isWindowsEndpoint).length;
  const iphones  = DATA.intuneDevices.filter(d=>d['device_category']==='iphone'&&!d['is_historical']).length;
  const macbooks = DATA.macbooks.length;
  const tablets  = (DATA.tablets||[]).length;
  const compliant = intune.filter(d=>(d['Compliance']||'').toLowerCase()==='compliant').length;
  const noncompliant = intune.filter(d=>(d['Compliance']||'').toLowerCase()==='noncompliant').length;
  const aws = DATA.awsWorkspaces.filter(w=>w['Status']==='Available').length;

  const meEndpoints = DATA.endpoints.filter(isWindowsEndpoint).length;
  const kandjiMacs = DATA.macbooks.length;
  document.getElementById('stat-cards').innerHTML = `
    ${(function(){ const ft=emp.filter(e=>e['Pay Class']==='Regular FT').length; const pt=emp.filter(e=>e['Pay Class']==='Regular PT').length; const cw=emp.filter(e=>e['Pay Class']==='Contingent Worker').length; return statCard('Active Employees',emp.length,'👤','blue','FT - '+ft+', PT - '+pt+', CW - '+cw,0,'employees'); })()}
    ${(function(){ const intuneTotal=DATA.intuneDevices.filter(d=>!d['is_historical']).length; return statCard('Intune Managed',intuneTotal,'📱','teal',compliant+' compliant',1,'intune'); })()}
    ${statCard('ManageEngine',meEndpoints,'💻','purple','Windows endpoints',2,'endpoints')}
    ${(function(){ const chips={}; DATA.macbooks.forEach(m=>{ const c=m['Chip']; if(c) chips[c]=(chips[c]||0)+1; }); const top=Object.entries(chips).sort((a,b)=>b[1]-a[1]).slice(0,2).map(([c,n])=>c+': '+n).join(' · ')||'No chip data'; return statCard('MacBooks (Kandji)',kandjiMacs,'🍎','indigo',top,3,'macbooks'); })()}
    ${(function(){ const tabCount=(DATA.tablets||[]).length; return statCard('iPhones Issued',iphones,'📞','blue',tabCount+' tablets also issued',4,'intune'); })()}
    ${statCard('Live Auction Devices',DATA.liveAuction.length,'🏷','orange','Auction-specific devices',5,'liveauction')}
    ${statCard('AWS Workspaces',aws,'☁️','green',`${DATA.awsWorkspaces.length} total provisioned`,6,'aws')}
    ${statCard('Terminated',terms.length,'📋','yellow','Historical records',7,'terms')}
  `;
  animateCards('stat-cards');

  // Leader bar chart
  const leaderCounts = {};
  emp.forEach(e=>{ const l=e['Functional Leader']; if(l) leaderCounts[l]=(leaderCounts[l]||0)+1; });
  const topLeaders = Object.entries(leaderCounts).sort((a,b)=>b[1]-a[1]).slice(0,7);
  const maxL = topLeaders[0]?.[1]||1;
  // Use data-leader + delegated click (see initLeaderChartNavigation below) so
  // names with apostrophes/quotes/backslashes (e.g. "O'Hara") don't break the
  // inline JS string. esc() handles attribute-context HTML escaping.
  document.getElementById('leader-chart').innerHTML = topLeaders.map(([name,count])=>`
    <div class="bar-row clickable" data-leader="${esc(name)}" role="button" tabindex="0">
      <div class="bar-label">${esc(name)}</div>
      <div class="bar-track"><div class="bar-fill clickable" style="width:${count/maxL*100}%;background:var(--accent)"></div></div>
      <div class="bar-count">${count}</div>
    </div>`).join('');

  // Donut chart
  const payGroups = {
    'Regular FT': emp.filter(e=>e['Pay Class']==='Regular FT').length,
    'Regular PT': emp.filter(e=>e['Pay Class']==='Regular PT').length,
    'Contingent': emp.filter(e=>e['Pay Class']==='Contingent Worker').length,
  };
  const donutColors = ['#4f8ef7','#a78bfa','#fb923c'];
  const donutTotal = Object.values(payGroups).reduce((a,b)=>a+b,0);
  drawDonut(Object.values(payGroups), donutColors);
  document.getElementById('donut-legend').innerHTML = Object.entries(payGroups).map(([label,count],i)=>`
    <div class="legend-item">
      <div class="legend-dot" style="background:${donutColors[i]}"></div>
      <div class="legend-label">${label}</div>
      <div class="legend-val">${count}</div>
      <div class="legend-pct">${pctText(count, donutTotal)}</div>
    </div>
  `).join('');

  // Compliance chart
  const compData = [
    {label:'Compliant',count:compliant,color:'var(--green)'},
    {label:'Non-Compliant',count:noncompliant,color:'var(--red)'},
  ];
  const maxC = Math.max(compliant,noncompliant);
  document.getElementById('compliance-chart').innerHTML = `<div class="bar-chart">`+
    compData.map(d=>`<div class="bar-row">
      <div class="bar-label">${d.label}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${pctOf(d.count, maxC)}%;background:${d.color}"></div></div>
      <div class="bar-count">${d.count}</div>
    </div>`).join('')+`</div>`;

  // OS chart
  const osCounts = {};
  intune.forEach(d=>{ const o=d['OS']||'Unknown'; osCounts[o]=(osCounts[o]||0)+1; });
  const topOS = Object.entries(osCounts).sort((a,b)=>b[1]-a[1]);
  const maxO = topOS[0]?.[1]||1;
  const osColors = ['#4f8ef7','#34d399','#fbbf24'];
  document.getElementById('os-chart').innerHTML = `<div class="bar-chart">`+
    topOS.map(([os,count],i)=>`<div class="bar-row">
      <div class="bar-label">${esc(os.replace(' (Fully Managed)','').replace('Android','Android'))}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${count/maxO*100}%;background:${osColors[i]||'var(--accent)'}"></div></div>
      <div class="bar-count">${count}</div>
    </div>`).join('')+`</div>`;

  // State chart
  const stateCounts = {};
  DATA.liveAuction.forEach(d=>{ const s=d['State']; if(_kit2IsState(s)) stateCounts[s]=(stateCounts[s]||0)+1; });
  const topStates = Object.entries(stateCounts).sort((a,b)=>b[1]-a[1]).slice(0,7);
  const maxSt = topStates[0]?.[1]||1;
  document.getElementById('state-chart').innerHTML = topStates.map(([st,count])=>`
    <div class="bar-row">
      <div class="bar-label">${esc(st)}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${count/maxSt*100}%;background:var(--orange)"></div></div>
      <div class="bar-count">${count}</div>
    </div>
  `).join('');

  // Recent employees table
  const recent = emp.slice(0,8);
  const dashDevMap = buildDeviceLookup();
  document.getElementById('dash-recent-tbody').innerHTML = recent.map(r=>`<tr>
    ${cellName(r['First/Last'])}
    ${cell(r['Job Name'])}
    ${cell(r['Department']?.replace(/^[A-Z0-9]+ - /,''))}
    <td>${payClassBadge(r['Pay Class'])}</td>
    ${devicePillsFromLookup(r['Username'], dashDevMap)}
  </tr>`).join('');
}

function statCard(label, value, icon, color, sub, idx, pageId) { // PATCH:STATCARD_NAV
  var animClass = idx !== undefined ? ' animate' : '';
  var animStyle = idx !== undefined ? ' style="animation-delay:'+idx*70+'ms"' : '';
  var numVal = typeof value === 'number' ? value : parseInt(String(value).replace(/[^0-9]/g,''),10);
  var dataAttr = (!isNaN(numVal) && numVal > 0 && idx !== undefined) ? ' data-target="'+numVal+'"' : '';
  var clickClass = pageId ? ' clickable' : '';
  // Escape label/icon/sub inside the helper so every caller is covered: one caller builds
  // `sub` from macbooks Chip values, which are Kandji-synced AND editable through this
  // console's own edit modal and bulk import, so markup lands on the main dashboard — the
  // first page every user sees. `label` is additionally concatenated into the double-quoted
  // aria-label below, where an unescaped " breaks out of the attribute.
  var pageAttrs = pageId ? ' data-page="'+pageId+'" role="button" tabindex="0" aria-label="View '+esc(label)+' details"' : '';
  return `<div class="stat-card ${color}${animClass}${clickClass}"${animStyle}${pageAttrs}>
    <div class="stat-icon">${esc(icon)}</div>
    <div class="stat-label">${esc(label)}</div>
    <div class="stat-value"${dataAttr}>${dataAttr ? '0' : value.toLocaleString()}</div>
    <div class="stat-sub">${esc(sub)}</div>
  </div>`;
}

// PATCH:STATCARD_NAV — delegated click + keyboard handler for dashboard cards
(function initStatCardNavigation() {
  var container = document.getElementById('stat-cards');
  if (!container) return;
  function navigate(card) {
    var page = card.getAttribute('data-page');
    if (page && typeof showPage === 'function') showPage(page);
  }
  container.addEventListener('click', function (e) {
    var card = e.target.closest('.stat-card[data-page]');
    if (card) navigate(card);
  });
  container.addEventListener('keydown', function (e) {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    var card = e.target.closest('.stat-card[data-page]');
    if (card) {
      e.preventDefault();
      navigate(card);
    }
  });
})();

// Make all sortable <th> elements keyboard-accessible. Previously the
// markup carried `<th onclick="sortTable(...)">` with no tabindex/key
// handlers — Tab skipped them and Enter did nothing, so 60+ sort controls
// were unreachable for keyboard and screen-reader users. This decorates
// each sortable header once on load: tabindex, aria-sort, and Enter/Space
// key support that triggers the existing onclick handler.
// applySortIndicators() updates aria-sort whenever the sort state changes.
// role="button" is deliberately NOT set here. It replaces the implicit
// columnheader role, so a screen reader stops announcing the column name with
// each cell and a row reads as a bare list of values; and aria-sort, which is
// only valid on a columnheader, is discarded with it — so the role was voiding
// the very state the line beside it was setting. tabindex plus the Enter/Space
// delegation below is enough to operate the header, and the delegation never
// depended on the role.
(function initSortableHeaders() {
  const headers = document.querySelectorAll('th[onclick^="sortTable"], th[onclick^="sortWarranty"]');
  headers.forEach(th => {
    th.setAttribute('tabindex', '0');
    if (!th.hasAttribute('aria-sort')) th.setAttribute('aria-sort', 'none');
  });
  document.addEventListener('keydown', e => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const th = e.target.closest('th[onclick^="sortTable"], th[onclick^="sortWarranty"]');
    if (!th) return;
    e.preventDefault();
    th.click();
  });
})();

// Delegated click + keyboard handler for the leader bar-chart. Reads the
// leader name from data-leader (so names with apostrophes/quotes don't break
// inline JS string templating) and delegates to drillByLeader().
(function initLeaderChartNavigation() {
  var chart = document.getElementById('leader-chart');
  if (!chart) return;
  function trigger(row) {
    var leader = row.getAttribute('data-leader');
    if (leader && typeof drillByLeader === 'function') drillByLeader(leader);
  }
  chart.addEventListener('click', function (e) {
    var row = e.target.closest('[data-leader]');
    if (row) trigger(row);
  });
  chart.addEventListener('keydown', function (e) {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    var row = e.target.closest('[data-leader]');
    if (row) {
      e.preventDefault();
      trigger(row);
    }
  });
})();


function drawDonut(values, colors) {
  const canvas = document.getElementById('donut-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  // HiDPI scaling: the markup canvas is 100×100 logical px. On retina/4K
  // displays the previous code drew at 1x and the browser scaled up,
  // producing a blurry donut. Bumping the backing-store size by DPR and
  // CSS-clamping to 100×100 gives crisp output without changing geometry.
  const dpr = window.devicePixelRatio || 1;
  const SIZE = 100;
  if (canvas.width !== SIZE * dpr) {
    canvas.width  = SIZE * dpr;
    canvas.height = SIZE * dpr;
    canvas.style.width  = SIZE + 'px';
    canvas.style.height = SIZE + 'px';
  }
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

  const cx=50, cy=50, r=40, ir=25;
  const total = values.reduce((a,b)=>a+b,0);
  let angle = -Math.PI/2;
  ctx.clearRect(0,0,SIZE,SIZE);
  values.forEach((v,i)=>{
    const slice = (v/total)*Math.PI*2;
    ctx.beginPath();
    ctx.moveTo(cx,cy);
    ctx.arc(cx,cy,r,angle,angle+slice);
    ctx.closePath();
    ctx.fillStyle = colors[i];
    ctx.fill();
    angle += slice;
  });
  ctx.beginPath();
  ctx.arc(cx,cy,ir,0,Math.PI*2);
  // Dark-only theme: surface color is read from the live CSS custom property
  // so the donut hole tracks any future palette change without code edits.
  const surface = getComputedStyle(document.documentElement)
    .getPropertyValue('--surface').trim() || '#12151c';
  ctx.fillStyle = surface;
  ctx.fill();
}

// ============================================================
// MODAL — Edit / Add
// ============================================================
let _modalTable = null, _modalIdx = null, _modalLastTrigger = null;

// Resolve the click-arg (which may be a stable _id or a legacy numeric index) to the actual array slot.
// Strategy: look up by _id first — that's the click pattern emitted by _encodeRef whenever a record
// has one, and we don't want a numeric _id that happens to fall in [0, arr.length) to be misread
// as a positional index. Only fall back to treating ref as an index if no _id matches.
// Returns { idx, record } with idx === -1 if not found.
function _resolveRecord(table, ref) {
  const arr = getDataArr(table) || [];
  if (ref != null) {
    const refStr = String(ref);
    const byId = arr.findIndex(r => r && r._id != null && String(r._id) === refStr);
    if (byId !== -1) return { idx: byId, record: arr[byId] };
  }
  if (typeof ref === 'number' && Number.isInteger(ref) && ref >= 0 && ref < arr.length) {
    return { idx: ref, record: arr[ref] };
  }
  return { idx: -1, record: null };
}

function _openModalAndFocus() {
  const backdrop = document.getElementById('modal-backdrop');
  backdrop.classList.add('open');
  backdrop.setAttribute('aria-hidden', 'false');
  // Focus the first real input so the user can start typing immediately AND screen readers
  // announce the dialog. Fall back to the dialog itself if there's nothing focusable inside.
  const dlg = backdrop.querySelector('[role="dialog"]') || backdrop;
  const firstField = backdrop.querySelector('#modal-body input, #modal-body select, #modal-body textarea');
  (firstField || dlg).focus();
}

function showAddModal(table) {
  _modalTable = table || currentPage;
  _modalIdx = null;
  _modalLastTrigger = document.activeElement;
  document.getElementById('modal-title').textContent = `Add ${_modalTable === 'employees' ? 'Employee' : 'Record'}`;
  document.getElementById('modal-body').innerHTML = buildForm(_modalTable, null);
  _openModalAndFocus();
}

function editRecord(table, ref) {
  const { idx, record } = _resolveRecord(table, ref);
  if (idx === -1) { showToast('Record not found — list may be out of date', 'warn'); return; }
  _modalTable = table;
  _modalIdx = idx;
  _modalLastTrigger = document.activeElement;
  document.getElementById('modal-title').textContent = 'Edit Record';
  document.getElementById('modal-body').innerHTML = buildForm(table, record);
  _openModalAndFocus();
}

function buildForm(table, record) {
  const r = record || {};
  const fieldId = (key) => 'modal-field-' + String(key).replace(/[^a-z0-9]+/gi, '-').toLowerCase();
  const field = (key, label, type='text', opts=null) => {
    const id = fieldId(key);
    const val = esc(r[key]||'');
    if (opts) {
      const current = r[key];
      const isEmpty = current == null || current === '';
      // Drop any blank entries the caller may have included; we always render a single explicit "None" option first.
      const realOpts = opts.filter(o => o !== '' && o != null);
      return `<div class="form-group"><label for="${id}">${label}</label>
        <select class="form-input" id="${id}" name="${esc(key)}">
          <option value="" ${isEmpty?'selected':''}>None</option>
          ${realOpts.map(o=>`<option value="${esc(o)}" ${current===o?'selected':''}>${esc(o)}</option>`).join('')}
        </select></div>`;
    }
    return `<div class="form-group"><label for="${id}">${label}</label>
      <input class="form-input" id="${id}" type="${type}" name="${esc(key)}" value="${val}"></div>`;
  };
  const formMap = {
    employees: `<div class="form-grid">
      ${field('First/Last','Full Name')} ${field('Business Email','Email','email')}
      ${field('Job Name','Job Title')} ${field('Department','Department')}
      ${field('Pay Class','Pay Class','text',['Regular FT','Regular PT','Contingent Worker'])}
      ${field('Functional Leader','Functional Leader')}
    </div>`,
    intune: `<div class="form-grid">
      ${field('Device name','Device Name')} ${field('Primary user display name','User Name')}
      ${field('Primary user UPN','Email','email')} ${field('Model','Model')}
      ${field('OS','OS','text',['iOS/iPadOS','Android (Fully Managed)'])}
      ${field('OS version','OS Version')}
      ${field('Compliance','Compliance','text',['Compliant','Noncompliant'])}
      ${field('Serial number','Serial Number')}
      ${field('Carrier','Carrier','text',['Verizon','T-Mobile',''])}
    </div>`,
    macbooks: `<div class="form-grid">
      ${field('Device Name','Device Name')} ${field('User','User')}
      ${field('Model','Model')} ${field('OS Version','OS Version')}
      ${field('Serial','Serial Number')} ${field('Blueprint','Blueprint')}
    </div>`,
    endpoints: `<div class="form-grid">
      ${field('Computer Name','Computer Name')} ${field('First/Last','User')}
      ${field('Device Model','Model')} ${field('Computer Type','Type','text',['LAPTOP','DESKTOP'])}
      ${field('Service Tag','Service Tag')}
    </div>`,
    liveauction: `<div class="form-grid">
      ${field('Device ID1','Device ID')} ${field('First/Last','Assigned To')}
      ${field('Model','Model')} ${field('Device Type','Type','text',['Tablet','Phone'])}
      ${field('State','State')} ${field('Regional','Regional')}
      ${field('Active/Inactive','Status','text',['Active','Inactive'])}
      ${field('IMEI','IMEI')}
    </div>`,
    // No 'Functional Leader' field here on purpose. TABLES.tmobile
    // (BACKEND-core-api-server.js) is exactly:
    //   'Phone Number':'line','User':'first_last_name','Email':'email_address',
    //   'Department':'cost_center','Device':'device_type','Status':'line_status',
    //   'IMEI':'imei','Intune Registered':'intune_registered',
    //   'Intune Compliance':'intune_compliance'
    // — no functional_leader column, and appToDb only copies mapped keys, so the
    // field rendered blank, accepted a name, returned 200 and lost it on reload.
    // verizon DOES map 'Functional Leader':'functional_leader'; tmobile does not.
    // Re-add this field only in the same change that adds the column.
    tmobile: `<div class="form-grid">
      ${field('Phone Number','Phone Number')} ${field('User','Name')}
      ${field('Email','Email','email')} ${field('Department','Department')}
      ${field('Device','Device Type','text',['iPhone','Samsung Galaxy Tab','iPad','MIFI'])}
      ${field('Status','Status','text',['Active','Inactive'])}
      ${field('IMEI','IMEI')}
    </div>`,
    verizon: `<div class="form-grid">
      ${field('Phone number','Phone Number')} ${field('Username','Username')}
      ${field('Department','Department')} ${field('Functional Leader','Functional Leader')}
      ${field('Equipment Model','Equipment Model')}
      ${field('Device Type','Device Type','text',['SMARTPHONE','TABLET','MiFi/USB'])}
      ${field('Service Status','Status','text',['A','I','S'])}
    </div>`,
    aws: `<div class="form-grid">
      ${field('WorkSpace ID','Workspace ID')} ${field('First/Last','User')}
      ${field('Username','Username')} ${field('Compute','Compute')}
      ${field('Root volume','Root Volume')} ${field('User volume','User Volume')}
      ${field('Status','Status','text',['Available','Stopped','Maintenance'])}
    </div>`,
  };
  return formMap[table] || `<p style="color:var(--text2)">No form configured for this table.</p>`;
}

async function saveModal() {
  const form = document.querySelector('#modal-body .form-grid');
  if (!form) { closeModal(); return; }
  const inputs = form.querySelectorAll('[name]');
  const record = {};
  inputs.forEach(inp => {
    // For <select>s, treat the explicit empty "None" option as null so we don't write phantom assignments to the server.
    record[inp.name] = (inp.tagName === 'SELECT' && inp.value === '') ? null : inp.value;
  });

  const arr = getDataArr(_modalTable);
  if (!arr) { closeModal(); return; }

  // API persistence — `if (API_BASE)` was always true (constant non-empty
  // string); the check has been removed.
  const routeMap = {employees:'employees',terms:'terms',intune:'intune',macbooks:'macbooks',
    endpoints:'endpoints',liveauction:'liveauction',tmobile:'tmobile',verizon:'verizon',aws:'aws'};
  const route = routeMap[_modalTable];
  if (route) {
    try {
      if (_modalIdx !== null && arr[_modalIdx]?._id) {
        await apiPut(route, arr[_modalIdx]._id, record);
      } else {
        // Merge the server-assigned id back into the row we are about to push.
        // Without it the new row has no `_id`, so the NEXT Edit on that row
        // fails the check above, POSTs again and writes a SECOND database row —
        // and deleteRecord finds no `_id` and never issues the DELETE. `_id` is
        // the only key the app uses to identify a persisted row (the API emits
        // it from dbToApp, and POST replies with { id, ...body }).
        const created = await apiPost(route, record);
        if (created && created.id != null) record._id = created.id;
      }
    } catch(e) { showToast('Save failed: ' + e.message, 'err'); return; }
  }
  if (_modalIdx !== null) {
    Object.assign(arr[_modalIdx], record);
    bumpDataVersion();   // row mutated in place
    showToast('Record updated successfully');
  } else {
    arr.push(record);
    bumpDataVersion();   // array contents changed
    const _badgeMap = {
      employees:'emp',terms:'terms',intune:'intune',macbooks:'mac',
      endpoints:'ep',liveauction:'la',tmobile:'tm',verizon:'vz',aws:'aws',
      ipads:'ipads',tablets:'tablets'
    };
    const _badgeEl = document.getElementById('badge-'+_badgeMap[_modalTable]);
    // Badge counts must use the same definition bootstrap() does — intune
    // excludes historical rows and endpoints counts Windows only — or adding
    // one record makes the sidebar contradict itself until the next reload.
    const _badgeCount = _modalTable === 'intune'    ? arr.filter(d => !d['is_historical']).length
                      : _modalTable === 'endpoints' ? arr.filter(isWindowsEndpoint).length
                      : arr.length;
    if (_badgeEl) _badgeEl.textContent = _badgeCount;
    showToast('Record added successfully');
  }

  closeModal();
  renderTable(_modalTable);
}

async function deleteRecord(table, ref) {
  const { idx, record } = _resolveRecord(table, ref);
  if (idx === -1) { showToast('Record not found — list may be out of date', 'warn'); return; }
  if (!confirm('Delete this record?')) return;
  const arr = getDataArr(table);
  // API delete — `if (API_BASE)` was always true; only the _id check matters.
  const routeMap = {employees:'employees',terms:'terms',intune:'intune',macbooks:'macbooks',
    endpoints:'endpoints',liveauction:'liveauction',tmobile:'tmobile',verizon:'verizon',aws:'aws'};
  const route = routeMap[table];
  if (route) {
    // A server-backed row with no `_id` was never matched to a database row.
    // Splicing it out anyway reported 'Record deleted' while the row stayed in
    // the database and reappeared on the next load — refuse loudly instead.
    if (!record || record._id == null) {
      showToast('Cannot delete: this row has no server id yet — reload the page and try again.', 'err');
      return;
    }
    try { await apiDelete(route, record._id); }
    catch(e) { showToast('Delete failed: ' + e.message, 'err'); return; }
  }
  // Re-resolve idx in case the array mutated during the await above.
  if (arr) {
    const liveIdx = record && record._id != null
      ? arr.findIndex(r => r && r._id === record._id)
      : idx;
    if (liveIdx >= 0) { arr.splice(liveIdx, 1); bumpDataVersion(); }
  }
  showToast('Record deleted','warn');
  renderTable(table);
}

function closeModal() {
  const backdrop = document.getElementById('modal-backdrop');
  backdrop.classList.remove('open');
  backdrop.setAttribute('aria-hidden', 'true');
  // Return focus to whichever element opened the modal so keyboard users don't lose context.
  if (_modalLastTrigger && typeof _modalLastTrigger.focus === 'function') {
    try { _modalLastTrigger.focus(); } catch(_) {}
  }
  _modalLastTrigger = null;
}
document.getElementById('modal-backdrop').addEventListener('click',function(e){
  if(e.target===this) closeModal();
});
// The three dialogs added after #modal-backdrop and #import-backdrop live in
// the page's own inline scripts and were never covered by the Tab trap below,
// so Tab walked straight out of them into the page behind — which is fully
// present in the AT tree (no inert, no aria-hidden on #app) but visually
// covered by the backdrop, so focus vanished with no visible indicator.
// They toggle visibility differently: #health-backdrop and #diag-backdrop set
// style.display, #emp-profile-backdrop toggles .open. Ordered by z-index
// (420 / 400 / 210) so the topmost one wins when two are somehow open.
// Escape is NOT handled here — each of those dialogs already has its own.
function _visibleLateDialog() {
  for (const id of ['health-backdrop', 'diag-backdrop']) {
    const b = document.getElementById(id);
    if (b && b.style.display && b.style.display !== 'none') return b;
  }
  const emp = document.getElementById('emp-profile-backdrop');
  if (emp && emp.classList.contains('open')) return emp;
  return null;
}
// Global keyboard handling for modals: Escape closes; Tab is trapped inside the open dialog.
document.addEventListener('keydown', function(e){
  const main = document.getElementById('modal-backdrop');
  const imp = document.getElementById('import-backdrop');
  const mainOpen = main && main.classList.contains('open');
  const impOpen = imp && imp.classList.contains('open');
  if (e.key === 'Escape') {
    if (mainOpen) { closeModal(); return; }
    if (impOpen && typeof closeImport === 'function') { closeImport(); return; }
    return;
  }
  if (e.key !== 'Tab') return;
  const dialog = mainOpen ? main : (impOpen ? imp : _visibleLateDialog());
  if (!dialog) return;
  // Collect all visible, enabled focusable elements inside the open dialog.
  const SEL = 'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';
  const focusables = Array.from(dialog.querySelectorAll(SEL))
    .filter(el => el.offsetWidth > 0 || el.offsetHeight > 0 || el === document.activeElement);
  if (!focusables.length) return;
  const first = focusables[0], last = focusables[focusables.length - 1];
  if (e.shiftKey && document.activeElement === first) {
    e.preventDefault(); last.focus();
  } else if (!e.shiftKey && document.activeElement === last) {
    e.preventDefault(); first.focus();
  }
});

// ============================================================
// EXPORT
// ============================================================
// Shared CSV serialization. Every previous CSV export reinvented this in a
// slightly different way: some forgot to escape embedded quotes, all of
// them used \n instead of RFC-4180 CRLF, and none prepended a UTF-8 BOM —
// so accented names rendered as mojibake when opened in Excel on Windows.
// Centralizing here means future exporters get the encoding right for free.
function _csvEscape(v) {
  return `"${String(v == null ? '' : v).replace(/"/g, '""')}"`;
}
function _toCsvBlob(rowsOfArrays) {
  // ﻿ = UTF-8 BOM (Excel/Windows recognizes it). \r\n per RFC 4180.
  const text = '﻿' + rowsOfArrays.map(r => r.join(',')).join('\r\n');
  return new Blob([text], {type: 'text/csv;charset=utf-8'});
}
function _downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a);
  a.click();
  // Defer revocation: some browsers (notably older Safari) race the
  // immediate revoke against the download trigger and silently drop the file.
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 0);
}

function exportCSV(section) {
  let rows = _VIEW_ROWS[section] || getDataArr(section);
  if (!rows) { showToast('Export not available for this view — use page-specific exports', 'warn'); return; }
  // Match the visible row filter for each page.
  if (section === 'intune')    rows = rows.filter(d => !d['is_historical']);
  if (section === 'endpoints') rows = rows.filter(isWindowsEndpoint);
  if (!rows.length) { showToast('No data to export','warn'); return; }
  let headers = Object.keys(rows[0]);
  if (section === 'endpoints') headers = headers.filter(h => h !== 'First' && h !== 'Last');
  const out = [headers.map(_csvEscape)];
  rows.forEach(r => out.push(headers.map(h => _csvEscape(r[h]))));
  _downloadBlob(_toCsvBlob(out), `inventory_${section}_${new Date().toISOString().split('T')[0]}.csv`);
  showToast(`Exported ${rows.length.toLocaleString()} records`);
}

// XLSX (SheetJS) is only needed for workbook import/export. Load the vendored
// script on first use, sharing one request between simultaneous actions. The
// pinned integrity hash is the same one the former eager script tag used.
const XLSX_SRC = '/vendor/xlsx-0.18.5.min.js';
const XLSX_INTEGRITY = 'sha384-vtjasyidUo0kW94K5MXDXntzOJpQgBKXmE7e2Ga4LG0skTTLeBi97eFAXsqewJjw';
let _xlsxLoadPromise = null;
let _xlsxLoadError = null;

function xlsxStatus() {
  if (typeof XLSX !== 'undefined') return 'ready';
  if (_xlsxLoadPromise) return 'loading';
  return _xlsxLoadError ? 'failed' : 'idle';
}

function xlsxReady() {
  if (typeof XLSX !== 'undefined') return Promise.resolve(true);
  if (_xlsxLoadPromise) return _xlsxLoadPromise;
  _xlsxLoadError = null;
  _xlsxLoadPromise = new Promise(resolve => {
    const script = document.createElement('script');
    script.src = XLSX_SRC;
    script.integrity = XLSX_INTEGRITY;
    script.async = true;
    let settled = false;
    function fail(error) {
      if (settled) return;
      settled = true;
      _xlsxLoadError = error;
      _xlsxLoadPromise = null; // another click may retry a transient failure
      script.remove();
      if (window.__invErr) window.__invErr('XLSX', error);
      // Name the action that failed, rather than leaving a silent click.
      showToast('Spreadsheet engine did not load — Import/Export unavailable. Tell IT.', 'err');
      resolve(false);
    }
    script.onload = () => {
      if (typeof XLSX === 'undefined') { fail(new Error('SheetJS loaded without XLSX')); return; }
      if (settled) return;
      settled = true;
      resolve(true);
    };
    script.onerror = () => fail(new Error('SheetJS did not load'));
    try { document.head.appendChild(script); }
    catch (error) { fail(error); }
  });
  return _xlsxLoadPromise;
}

let _exportAllLoading = false;
async function exportAll() {
  // Bundle every non-empty dataset into a single XLSX workbook (one sheet per
  // dataset). Beats the previous behavior of triggering 9 separate browser
  // save dialogs.
  if (_exportAllLoading) return;
  _exportAllLoading = true;
  try {
    if (xlsxStatus() !== 'ready') showToast('Preparing spreadsheet export…');
    if (!await xlsxReady()) return;
    const sections = [
      ['activeEmployees', 'Active Employees'],
      ['terms',           'Terminated'],
      ['intuneDevices',   'Intune'],
      ['macbooks',        'MacBooks'],
      ['liveAuction',     'Live Auction'],
      ['tmobile',         'T-Mobile'],
      ['verizon',         'Verizon'],
      ['awsWorkspaces',   'AWS Workspaces'],
      ['endpoints',       'ManageEngine'],
    ];
    const stamp = new Date().toISOString().split('T')[0];
    const wb = XLSX.utils.book_new();
    let sheetCount = 0;
    sections.forEach(([key, sheetName]) => {
      let rows = DATA[key] || [];
      // Match each tab's visible-row filter so the bulk export matches the UI.
      if (key === 'intuneDevices') rows = rows.filter(d => !d['is_historical']);
      if (key === 'endpoints')     rows = rows.filter(isWindowsEndpoint);
      if (!rows.length) return;
      let headers = Object.keys(rows[0]);
      if (key === 'endpoints') headers = headers.filter(h => h !== 'First' && h !== 'Last');
      const aoa = [headers, ...rows.map(r => headers.map(h => r[h] == null ? '' : r[h]))];
      XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet(aoa), sheetName);
      sheetCount++;
    });
    if (!sheetCount) { showToast('Nothing to export', 'warn'); return; }
    XLSX.writeFile(wb, `inventory_full_${stamp}.xlsx`);
    showToast(`Full export — ${sheetCount} sheet(s) in one workbook`);
  } catch (error) {
    if (window.__invErr) window.__invErr('exportAll', error);
    showToast('Spreadsheet export failed — try again or tell IT.', 'err');
  } finally {
    _exportAllLoading = false;
  }
}

// ============================================================
// TOAST
// ============================================================
// Previous version mapped any non-'success' type to a single 'err' class —
// so callers passing 'warn' (which several do) silently rendered as an
// error. Now distinct classes for success / err / warn match the CSS.
function showToast(msg, type='success') {
  const t   = document.getElementById('toast');
  const dot = document.getElementById('toast-dot');
  const msgEl = document.getElementById('toast-msg');
  if (!t || !dot || !msgEl) return;
  msgEl.textContent = msg;
  // The severity word is spoken as well as shown: visually, success / warn /
  // err differ only by an 8px dot's hue with identical text styling, so colour
  // was the only signal for low-vision users too.
  announce((type === 'err' ? 'Error: ' : type === 'warn' ? 'Warning: ' : '') + msg);
  // FU-24 (2026-09-08): the largest page on the platform had zero degraded() calls.
  // An error toast IS this page's degraded paint, and `msg` is the exact text the
  // user saw -- which is what the beacon contract asks for. One hook here covers
  // every current and future catch block that reports through showToast.
  if (type === 'err' && window.ITObserve) { try { ITObserve.degraded('toast', msg); } catch (e) {} }
  dot.className = 'toast-dot' + (type === 'err' ? ' err' : type === 'warn' ? ' warn' : '');
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2800);
}

// The toast is the app's only feedback channel — 'Delete failed: <reason>',
// 'Record deleted', 'Record not found', every import result — and none of it
// ever reached a screen reader: there was no live region anywhere in the app,
// so a user could destroy a record and hear nothing, or get a silent failure
// and assume it worked. announce() writes into the single polite region
// (#a11y-live in IT_Inventory_App.html); showPage() uses it too.
let _announceTimer = null;
function announce(msg) {
  const live = document.getElementById('a11y-live');
  if (!live || !msg) return;
  // A live region only fires when its text actually changes, so two identical
  // messages in a row need the node cleared between them.
  clearTimeout(_announceTimer);
  live.textContent = '';
  _announceTimer = setTimeout(() => { live.textContent = msg; }, 60);
}

// ============================================================
// XLSX IMPORT
// ============================================================

// Sheet name → DATA key mapping (matches the original spreadsheet)
const SHEET_MAP = [
  { sheetNames: ['Active Employees','Active Emp','ActiveEmployees'], key: 'activeEmployees',
    label: 'Active Employees',
    transform: (row) => ({
      'Worker ID': row['Worker ID'],
      'Status': row['Status'],
      'Employee Name': row['Employee Name'],
      'First/Last': row['First/Last'] || row['First/Last Name'] || `${row['Employee Common Name']||row['Common Name']||''} ${row['Employee Preferred Last Name']||row['Preferred Last Name']||''}`.trim(),
      'Business Email': row['Business Email'],
      'Username': row['Username'] || (row['Business Email'] ? row['Business Email'].replace('@auction.com','').replace('@auction.com','') : null),
      'Job Name': row['Job Name'],
      'Business Title': row['Business Title'],
      'Manager Name': row['Manager Name'],
      'Functional Leader': row['Functional Leader'],
      'Department': row['Department'],
      'Pay Class': row['Pay Class'],
      'Location Name': row['Location Name'],
      'Work Assignment Is Virtual': row['Work Assignment Is Virtual'],
      'Hire Date': row['Hire Date'] ? String(row['Hire Date']) : null,
      'Desktop/Laptop': row['Desktop/Laptop'],
      'MacBook': row['MacBook'],
      'AWS Workspace': row['AWS Workspace'],
      'iPhone': row['iPhone'],
      'Tablet': row['Tablet'],
      'iPad': row['iPad'],
    })
  },
  { sheetNames: ['Terms','Termed','Terminated','Terminated Employees'], key: 'terms',
    label: 'Terminated Employees',
    transform: (row) => ({
      'Worker ID': row['Worker ID'],
      'Status': row['Status'],
      'Employee Name': row['Employee Name'],
      'First/Last': row['First/Last'] || row['First/Last Name'] || (row['Employee Name'] ? (row['Employee Name'].includes(',') ? row['Employee Name'].split(',').map(s=>s.trim()).reverse().join(' ') : row['Employee Name']) : null),
      'Business Email': row['Business Email'],
      'Job Name': row['Job Name'],
      'Department': row['Department'],
      'Location Name': row['Location Name'] || row['Location'],
      'Pay Class': row['Pay Class'],
      'Termination Date': row['Termination Date'] ? String(row['Termination Date']) : null,
      'Functional Leader': row['Functional Leader'],
      'Is Termination Reason': row['Is Termination Reason'],
    })
  },
  { sheetNames: ['Intune All','Intune','IntuneAll'], key: 'intuneDevices',
    label: 'Mobile Devices (Intune)',
    transform: (row) => ({
      'Device ID': row['Device ID'],
      'Device name': row['Device name'] || row['Device Name'],
      'Ownership': row['Ownership'],
      'Compliance': row['Compliance'],
      'OS': row['OS'],
      'OS version': row['OS version'] || row['OS Version'],
      'Primary user UPN': row['Primary user UPN'],
      'Last check-in': row['Last check-in'] ? String(row['Last check-in']) : null,
      'Model': row['Model'],
      'Serial number': row['Serial number'] || row['Serial Number'],
      'Phone number': row['Phone number'] || row['Phone Number'],
      'Primary user display name': row['Primary user display name'],
      // Both renderers and the sort header read intune_devices.carrier, so write
      // that column. 'Subscriber carrier' → subscriber_carrier is a second, live
      // but never-displayed column in TABLES.intune; accept either sheet heading
      // so existing workbooks keep importing.
      'Carrier': row['Carrier'] || row['Subscriber carrier'],
    })
  },
  { sheetNames: ['Kandji','MacBooks','Kandji MDM'], key: 'macbooks',
    label: 'MacBooks (Kandji)',
    transform: (row) => ({
      'Device Name': row['Device Name'],
      'Model': row['Model'],
      'OS Version': row['OS Version'],
      'Serial': row['Serial'],
      'Blueprint': row['Blueprint'],
      'User': row['User'],
      'Checked In': row['Checked In'] ? String(row['Checked In']) : null,
    })
  },
  { sheetNames: ['ManageEngine Endpoint Central','ManageEngine','Endpoints','Endpoint Central'], key: 'endpoints',
    label: 'Windows Endpoints',
    transform: (row) => ({
      'Computer Name': row['Computer Name'],
      'Device Model': row['Device Model'],
      'Computer Type': row['Computer Type'],
      'Currently Logged on Users': row['Currently Logged on Users'],
      'First/Last': row['First/Last'] || row['First/Last Name'],
      'Last Successful Asset Scan': row['Last Successful Asset Scan'],
      'Service Tag': row['Service Tag'],
    })
  },
  { sheetNames: ['Live Auction','LiveAuction','Live Auction Devices'], key: 'liveAuction',
    label: 'Live Auction Devices',
    transform: (row) => ({
      'Device Type': row['Device Type'],
      'Device ID1': row['Device ID1'] || row['Device ID'],
      'Phone number': row['Phone number'] ? String(row['Phone number']) : null,
      'IMEI': row['IMEI'] ? String(row['IMEI']) : null,
      'Tmobile': row['Tmobile'] || row['T-Mobile'],
      'Verizon': row['Verizon'],
      'Assigned To': row['Assigned To'],
      'First/Last': row['First/Last'] || row['First/Last Name'],
      'Employee Active': row['Employee Active'],
      'Employee Termed': row['Employee Termed'],
      'Model': row['Model'],
      'EID': row['EID'],
      'State': row['State'],
      'Regional': row['Regional'],
      'Active/Inactive': row['Active/Inactive'],
      'OS': row['OS'],
    })
  },
  { sheetNames: ['Tmobile','T-Mobile','TMobile'], key: 'tmobile',
    label: 'T-Mobile Lines',
    transform: (row) => {
      // Operator-precedence fix: previous form was `a || b ? String(a || b) : null`,
      // which JS reads as `a || (b ? String(...) : null)` — so a truthy `a` was
      // returned UN-stringified. Wrapping the OR in parens forces the intended
      // "any truthy value, stringified" coercion.
      const phone = row['Phone Number'] || row['Line'];
      const imei  = row['IMEI']         || row['imei'];
      return {
        'Phone Number': phone ? String(phone) : null,
        'User': row['User'] || row['First/Last Name'] || row['First/Last'],
        'Email': row['Email'] || row['Email Address'],
        'Department': row['Department'] || row['Cost Center'],
        // 'Functional Leader' intentionally not emitted — tmobile_lines has no
        // functional_leader column, so appToDb dropped it with no warning line
        // in the import log. Matches the edit form above.
        'Device': row['Device'] || row['Type'] || row['Device Type'],
        'Status': row['Status'] || row['Line Status'],
        'IMEI': imei ? String(imei) : null,
      };
    }
  },
  { sheetNames: ['Verizon'], key: 'verizon',
    label: 'Verizon Lines',
    transform: (row) => ({
      'Phone number': row['Phone number'] ? String(row['Phone number']) : (row['Mobile Number'] ? String(row['Mobile Number']) : null),
      'Username': row['Username'],
      'Department': row['Department'] || null,
      'Functional Leader': row['Functional Leader'] || null,
      'Equipment Model': row['Equipment Model'],
      'Service Status': row['Service Status'],
      'Device Type': row['Device Type'] || (function() {
        const m = (row['Equipment Model']||'').toUpperCase();
        if (m.includes('MIFI') || m.includes('JETPACK') || m.includes('MHS') || m.includes('USB') || m.includes('GATEWAY')) return 'MiFi/USB';
        if (m.includes('IPHONE') || m.includes('APPLE') || m.includes('GALAXY S') || m.includes('PIXEL')) return 'SMARTPHONE';
        if (m.includes('TAB') || m.includes('TABLET') || m.includes('IPAD')) return 'TABLET';
        return 'SMARTPHONE';
      })(),
    })
  },
  { sheetNames: ['AWS Workspace','AWS Workspaces','AWS'], key: 'awsWorkspaces',
    label: 'AWS Workspaces',
    transform: (row) => ({
      'WorkSpace ID': row['WorkSpace ID'],
      'Username': row['Username'],
      'First/Last': row['First/Last'] || row['First/Last Name'],
      'Compute': row['Compute'],
      'Root volume': row['Root volume'] || row['Root Volume'],
      'User volume': row['User volume'] || row['User Volume'],
      'Operating system': row['Operating system'] || row['Operating System'],
      'Standby enabled': row['Standby enabled'],
      'Running mode': row['Running mode'] || row['Running Mode'],
      'Protocol': row['Protocol'],
      'Status': row['Status'],
    })
  },
];

let _pendingImport = null;
let _importSelectionVersion = 0;

function openImportModal() {
  const bd = document.getElementById('import-backdrop');
  bd.classList.add('open');
  bd.setAttribute('aria-hidden', 'false');
  resetImportUI();
}

function closeImport() {
  const bd = document.getElementById('import-backdrop');
  bd.classList.remove('open');
  bd.setAttribute('aria-hidden', 'true');
  _importSelectionVersion++; // cancel a file choice still waiting on SheetJS
  _pendingImport = null;
}

function resetImportUI() {
  _importSelectionVersion++;
  document.getElementById('drop-zone').style.display = 'block';
  document.getElementById('import-progress').style.display = 'none';
  document.getElementById('sheet-map').style.display = 'none';
  document.getElementById('import-log').style.display = 'none';
  document.getElementById('import-log').innerHTML = '';
  document.getElementById('file-input').value = '';
  const btn = document.getElementById('import-confirm-btn');
  btn.disabled = true; btn.style.opacity = '.4';
  _pendingImport = null;
  _csvRawText = null;
}

// Drag-and-drop
document.addEventListener('DOMContentLoaded', () => {
  const dz = document.getElementById('drop-zone');
  if (!dz) return;
  dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('drag-over'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('drag-over'));
  dz.addEventListener('drop', e => {
    e.preventDefault();
    dz.classList.remove('drag-over');
    const f = e.dataTransfer.files[0];
    if (f) handleFileSelect(f);
  });
});

async function handleFileSelect(file) {
  if (!file) return;
  const selection = ++_importSelectionVersion;
  const isXLSX = file.name.match(/\.xlsx?$/i);
  const isCSV  = file.name.match(/\.csv$/i);
  if (!isXLSX && !isCSV) {
    showToast('Please select a .xlsx, .xls, or .csv file', 'err');
    return;
  }
  // CSV needs no workbook engine. For XLSX, show progress while the shared
  // script request finishes and stop if the modal closed or a newer file won.
  if (isXLSX) {
    document.getElementById('drop-zone').style.display = 'none';
    document.getElementById('import-progress').style.display = 'block';
    setProgress(5, 'Loading spreadsheet engine…');
    const ready = await xlsxReady();
    if (selection !== _importSelectionVersion) return;
    if (!ready) {
      document.getElementById('drop-zone').style.display = 'block';
      document.getElementById('import-progress').style.display = 'none';
      return;
    }
  }
  document.getElementById('drop-zone').style.display = 'none';
  document.getElementById('import-progress').style.display = 'block';
  setProgress(10, 'Reading file…');

  const reader = new FileReader();
  if (isCSV) {
    reader.onload = (e) => {
      setProgress(30, 'Parsing CSV…');
      setTimeout(() => showCSVSectionPicker(e.target.result, file.name), 50);
    };
    reader.readAsText(file);
  } else {
    reader.onload = (e) => {
      setProgress(30, 'Parsing workbook…');
      setTimeout(() => parseWorkbook(e.target.result, file.name), 50);
    };
    reader.readAsArrayBuffer(file);
  }
}

// For CSV: show a section picker so the user can say which dataset this file represents
let _csvRawText = null;
function showCSVSectionPicker(text, filename) {
  _csvRawText = text;
  setProgress(60, 'Choose target section…');

  // Parse a preview (first 3 rows) to show detected headers
  const lines = text.split(/\r?\n/).filter(l => l.trim());
  const firstRow = parseCSVLine(lines[0] || '');
  const secondRow = parseCSVLine(lines[1] || '');
  const hasTitleRow = firstRow.length <= 2 ||
    String(firstRow[0]).startsWith('auction |') ||
    (secondRow.length > firstRow.length);
  const headers = hasTitleRow ? parseCSVLine(lines[1] || '') : firstRow;
  const previewCount = Math.max(0, lines.length - (hasTitleRow ? 2 : 1));

  document.getElementById('sheet-map').style.display = 'block';
  document.getElementById('sheet-map-rows').innerHTML = `
    <div style="margin-bottom:10px;font-size:12px;color:var(--text2)">
      <strong style="color:var(--text)">${esc(filename)}</strong> — ${previewCount.toLocaleString()} rows detected<br>
      <span style="color:var(--text3);font-size:11px">Columns: ${esc(headers.slice(0,6).join(', '))}${headers.length>6?' …':''}</span>
    </div>
    <div class="sheet-row" style="border-bottom:none;padding-bottom:0">
      <span style="font-size:12px;color:var(--text2);margin-right:10px;white-space:nowrap">Import as:</span>
      <select class="form-input" id="csv-section-select" style="flex:1;font-size:12px;padding:6px 10px">
        <option value="">— Select target section —</option>
        ${SHEET_MAP.map(m => `<option value="${m.key}">${m.label}</option>`).join('')}
      </select>
    </div>
  `;

  const logEl = document.getElementById('import-log');
  logEl.style.display = 'block';
  logEl.innerHTML = `<div class="log-line"><span class="log-dot">ℹ</span><span>CSV detected — select which inventory section this file belongs to, then click Apply Import.</span></div>`;

  setProgress(100, 'Ready — choose a section above');

  // Enable confirm only once a section is chosen
  document.getElementById('csv-section-select').addEventListener('change', function() {
    const btn = document.getElementById('import-confirm-btn');
    if (this.value) { btn.disabled = false; btn.style.opacity = '1'; }
    else            { btn.disabled = true;  btn.style.opacity = '.4'; }
  });
}

function parseCSVLine(line) {
  // RFC-4180 aware CSV line parser
  const result = [];
  let cur = '', inQ = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') {
      if (inQ && line[i+1] === '"') { cur += '"'; i++; }
      else inQ = !inQ;
    } else if (c === ',' && !inQ) {
      result.push(cur.trim()); cur = '';
    } else {
      cur += c;
    }
  }
  result.push(cur.trim());
  return result;
}

function parseCSVToRows(text) {
  const lines = text.split(/\r?\n/).filter(l => l.trim());
  if (lines.length < 2) return [];
  // Detect title row — if first row has only 1-2 cells or doesn't look like headers
  // (e.g. 'WNO_Search_results.csv,3/24/2026' or 'auction | ...')
  const firstRow = parseCSVLine(lines[0]);
  const secondRow = parseCSVLine(lines[1]);
  const hasTitleRow = firstRow.length <= 2 ||
    String(firstRow[0]).startsWith('auction |') ||
    (secondRow.length > firstRow.length);
  const headerLine = hasTitleRow ? 1 : 0;
  const headers = parseCSVLine(lines[headerLine]);
  return lines.slice(headerLine + 1).map(line => {
    const vals = parseCSVLine(line);
    const row = {};
    headers.forEach((h, i) => { row[h] = vals[i] ?? null; });
    return row;
  }).filter(r => Object.values(r).some(v => v !== null && v !== ''));
}

function confirmImportCSV() {
  const select = document.getElementById('csv-section-select');
  if (!select || !select.value) return null;
  const mapping = SHEET_MAP.find(m => m.key === select.value);
  if (!mapping || !_csvRawText) return null;

  const rawRows = parseCSVToRows(_csvRawText);
  const transformed = rawRows.map(r => { try { return mapping.transform(r); } catch(e) { return r; } });

  const result = {};
  result[mapping.key] = transformed;

  // Update log
  const logEl = document.getElementById('import-log');
  logEl.innerHTML += `<div class="log-line"><span class="log-dot">✓</span><span>CSV → ${mapping.label}: ${transformed.length.toLocaleString()} records ready</span></div>`;

  return result;
}

function setProgress(pct, label) {
  document.getElementById('progress-fill').style.width = pct + '%';
  document.getElementById('progress-pct').textContent = pct + '%';
  document.getElementById('progress-label').textContent = label;
}

async function saveBulkImportSections(routeMap, rowsByKey) {
  const summary = { attempted: 0, saved: 0, failed: [] };
  for (const [dataKey, route] of Object.entries(routeMap)) {
    const rows = rowsByKey[dataKey];
    if (!rows?.length) continue;
    summary.attempted++;
    try {
      await apiBulkImport(route, rows);
      summary.saved++;
    } catch(e) {
      console.warn('Bulk import failed for', dataKey, e);
      summary.failed.push({ dataKey, route, message: e?.message || String(e) });
    }
  }
  return summary;
}

function showBulkImportFailures(summary) {
  if (!summary.failed.length) return false;
  const failedRoutes = summary.failed.map(f => f.route).join(', ');
  const detail = `Bulk import failed for ${summary.failed.length} of ${summary.attempted} section(s): ${failedRoutes}. ${summary.saved} section(s) saved.`;
  const logEl = document.getElementById('import-log');
  if (logEl) {
    logEl.style.display = 'block';
    logEl.innerHTML += `<div class="log-line"><span class="log-dot err">✗</span><span style="color:var(--red)">${esc(detail)}</span></div>`;
  }
  showToast(`Bulk import failed for ${summary.failed.length}/${summary.attempted} section(s)`, 'err');
  return true;
}

function parseWorkbook(buffer, filename) {
  try {
    const wb = XLSX.read(buffer, { type: 'array', cellDates: true });
    setProgress(50, 'Matching sheets…');

    const result = {};
    const logs = [];
    const mapRows = [];
    let matched = 0;

    SHEET_MAP.forEach(mapping => {
      // Find matching sheet (case-insensitive)
      const found = wb.SheetNames.find(sn =>
        mapping.sheetNames.some(mn => sn.toLowerCase().trim() === mn.toLowerCase().trim())
      );

      if (!found) {
        logs.push({ type:'skip', text:`Sheet not found: ${mapping.sheetNames[0]} — skipped` });
        mapRows.push({ sheet:'(not found)', label:mapping.label, count:0, matched:false });
        return;
      }

      const ws = wb.Sheets[found];
      // Detect Dayforce title row — if first row has only one key starting with 'auction |'
      // skip it by using range:1 so Row 2 becomes the header row
      const firstRowCheck = XLSX.utils.sheet_to_json(ws, { defval: null, raw: false, header: 1 });
      const hasDayforceTitle = firstRowCheck.length > 0 &&
        Array.isArray(firstRowCheck[0]) &&
        firstRowCheck[0].length >= 1 &&
        String(firstRowCheck[0][0] || '').startsWith('auction |');
      const rawRows = hasDayforceTitle
        ? XLSX.utils.sheet_to_json(ws, { defval: null, raw: false, range: 1 })
        : XLSX.utils.sheet_to_json(ws, { defval: null, raw: false });

      // Filter out completely empty rows
      const rows = rawRows.filter(r => Object.values(r).some(v => v !== null && v !== ''));

      // Apply transform
      const transformed = rows.map(r => {
        try { return mapping.transform(r); }
        catch(e) { return r; }
      });

      result[mapping.key] = transformed;
      matched++;
      logs.push({ type:'ok', text:`"${found}" → ${mapping.label}: ${transformed.length.toLocaleString()} records` });
      mapRows.push({ sheet: found, label: mapping.label, count: transformed.length, matched: true });
    });

    // Check for any unmatched sheets in the workbook
    const matchedSheets = new Set();
    SHEET_MAP.forEach(m => {
      wb.SheetNames.forEach(sn => {
        if (m.sheetNames.some(mn => sn.toLowerCase().trim() === mn.toLowerCase().trim())) {
          matchedSheets.add(sn);
        }
      });
    });
    wb.SheetNames.forEach(sn => {
      if (!matchedSheets.has(sn)) {
        logs.push({ type:'warn', text:`Sheet "${sn}" found but not mapped — ignored` });
      }
    });

    setProgress(90, 'Validating…');
    _pendingImport = result;

    // Render sheet map. Sheet names come straight out of the uploaded workbook via
    // XLSX.read, so they are untrusted strings of arbitrary content — and a hostile
    // .xlsx arrives here as a routine attachment, because ingesting workbooks produced
    // elsewhere (Dayforce, Kandji, ManageEngine, carrier exports) is this modal's whole
    // job. Escape on the way into innerHTML, the same way the CSV branch already does.
    document.getElementById('sheet-map').style.display = 'block';
    document.getElementById('sheet-map-rows').innerHTML = mapRows.map(r => `
      <div class="sheet-row">
        <span class="sheet-status">${r.matched ? '✅' : '⚪'}</span>
        <span class="sheet-name">${r.matched ? esc(r.sheet) : '—'}</span>
        <span class="sheet-arrow">→</span>
        <span class="sheet-target">${r.label}</span>
        <span class="sheet-count">${r.count > 0 ? r.count.toLocaleString() + ' rows' : r.matched ? '0 rows' : 'skipped'}</span>
      </div>
    `).join('');

    // Render log
    const logEl = document.getElementById('import-log');
    logEl.style.display = 'block';
    logEl.innerHTML = logs.map(l => `
      <div class="log-line">
        <span class="log-dot ${l.type==='ok'?'':l.type}">${l.type==='ok'?'✓':l.type==='warn'?'⚠':'○'}</span>
        <span>${esc(l.text)}</span>
      </div>
    `).join('');

    setProgress(100, `Done — ${matched} sheets matched`);

    if (matched > 0) {
      const btn = document.getElementById('import-confirm-btn');
      btn.disabled = false; btn.style.opacity = '1';
    }

  } catch(err) {
    setProgress(100, 'Error reading file');
    document.getElementById('import-log').style.display = 'block';
    // A parse error can quote workbook-derived content back at us, so err.message is
    // untrusted here for the same reason the sheet names are.
    document.getElementById('import-log').innerHTML = `<div class="log-line"><span class="log-dot err">✗</span><span style="color:var(--red)">${esc(err.message)}</span></div>`;
    showToast('Could not parse file — check format', 'err');
  }
}

async function confirmImport() {
  // CSV path
  if (_csvRawText !== null && !_pendingImport) {
    const result = confirmImportCSV();
    if (!result) { showToast('Please select a target section', 'err'); return; }

    // Save to API (the `if (API_BASE)` gate was always true and has been
    // removed). Keep the modal open if any section fails so auth/backend
    // problems are visible instead of looking like a successful import.
    showToast('Saving to database…');
    const routeMap = {activeEmployees:'employees',terms:'terms',intuneDevices:'intune',
      macbooks:'macbooks',endpoints:'endpoints',liveAuction:'liveauction',
      tmobile:'tmobile',verizon:'verizon',awsWorkspaces:'aws'};
    const bulkSummary = await saveBulkImportSections(routeMap, result);
    if (showBulkImportFailures(bulkSummary)) return;

    Object.entries(result).forEach(([key, rows]) => {
      if (rows && rows.length > 0) { DATA[key] = rows; bumpDataVersion(); }
    });
    bootstrap();
    _csvRawText = null;
    closeImport();
    showToast(`✓ CSV import saved to database — ${bulkSummary.saved} sections updated`);
    return;
  }

  // XLSX path
  if (!_pendingImport) return;
  const importedData = {};
  Object.entries(_pendingImport).forEach(([key, rows]) => {
    if (rows && rows.length > 0) importedData[key] = rows;
  });

  // Bulk upload, then repaint from the imported data. The `if (API_BASE)`
  // gate was always true and has been removed.
  showToast('Saving to database…');
  const routeMap = {activeEmployees:'employees',terms:'terms',intuneDevices:'intune',
    macbooks:'macbooks',endpoints:'endpoints',liveAuction:'liveauction',
    tmobile:'tmobile',verizon:'verizon',awsWorkspaces:'aws'};
  const bulkSummary = await saveBulkImportSections(routeMap, importedData);
  if (showBulkImportFailures(bulkSummary)) return;

  Object.entries(importedData).forEach(([key, rows]) => { DATA[key] = rows; bumpDataVersion(); });
  showToast(`✓ Saved to database — ${bulkSummary.saved} sections synced`);
  // Auto-run Intune crossref after T-Mobile import
  if (importedData['tmobile']) {
    fetch(`${WARRANTY_BASE}/api/intune-crossref/sync`, {method:'POST'})
      .then(r=>r.json())
      .then(d=>{ if(d.success) showToast(`⬡ Intune crossref: ${d.tmobile?.matched||0} matched`); })
      .catch(e => console.warn('Intune crossref auto-sync failed:', e && e.message));
  }
  // bootstrap() already calls buildDashboard() internally — no need to repeat.
  bootstrap();
  closeImport();
}


// ============================================================
// LOGIN — REMOVED
// ============================================================
// The previous client-side login was a security liability:
//   - TEAM_CREDENTIALS were hardcoded in plain JS (every visitor could read
//     them from page source).
//   - The "auth" gate was a sessionStorage boolean that any user could set
//     from DevTools (`sessionStorage.setItem('it_inventory_auth','true')`).
//   - The login DOM (#login-screen, #login-user, #login-pass) was never
//     present in the HTML, so the feature was non-functional anyway.
// All of that has been removed. Authentication MUST be enforced server-side
// (e.g., session cookie + SSO) before the page is served to the browser.


// ============================================================
// DRILL-DOWN
// ============================================================
// There is exactly ONE drill-down entry point: the leader chart, which reaches
// drillByLeader() through the delegated click handler further up this file.
// A sibling drillByCompliance() and a _drillFilter state object were deleted
// 2026-09-03 — nothing ever CALLED the former and nothing ever READ the latter,
// so together they made the feature look half-wired when it is simply narrow.
// The active filter is held by the select elements themselves; clearDrill()
// resets those. 'intune-filter-compliance' stays in that reset list on purpose
// — renderIntune() still reads it when the user sets it by hand.
function drillByLeader(leader) {
  showPage('employees');
  // KIT2-20261017 (DR-10): a pay class or device filter left from earlier
  // would hide some of the leader's people under a "Filtered by Leader" banner.
  ['emp-filter-payclass', 'emp-filter-device'].forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
  // Set the leader filter dropdown
  const sel = document.getElementById('emp-filter-leader');
  if (sel) { sel.value = leader; renderEmployees(); }
  // Show active filter banner
  showDrillBanner(`Filtered by Leader: ${leader}`, clearDrill);
}

function clearDrill() {
  // Reset all filters
  ['emp-filter-leader','intune-filter-compliance'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  hideDrillBanner();
  renderEmployees();
}

function showDrillBanner(text, clearFn) {
  let banner = document.getElementById('drill-banner');
  if (!banner) {
    banner = document.createElement('div');
    banner.id = 'drill-banner';
    banner.className = 'drill-active';
    document.getElementById('content').prepend(banner);
  }
  banner.innerHTML = `<span class="drill-active-label">🔍 ${esc(text)}</span><span class="drill-clear" onclick="clearDrill()">✕ Clear filter</span>`;
  banner.style.display = 'flex';
}

function hideDrillBanner() {
  const b = document.getElementById('drill-banner');
  if (b) b.style.display = 'none';
}

// ============================================================
// HARDWARE COST CATALOG
// ============================================================
const HW_COSTS = {
  'LAPTOP':    { label:'Windows Laptop',  cost:1685 },
  'DESKTOP':   { label:'Desktop',         cost:1685 },
  'MacBook':   { label:'MacBook',         cost:2408 },
  'iPhone':    { label:'iPhone',          cost:1000 },
  'Tablet':    { label:'Samsung Tablet',  cost:669  },
  'iPad':      { label:'iPad Air',        cost:749  },
  'AWS':       { label:'AWS Workspace',   cost:0    },
};

function fmt$(n){ return '$'+Math.round(n).toLocaleString(); }
function fmtK(n){ return n>=1000000 ? '$'+(n/1000000).toFixed(2)+'M' : '$'+(n/1000).toFixed(0)+'K'; }
// Percentage guards. init() tolerates a per-route failure, so any denominator
// here can legitimately be 0: dividing produced "NaN%" in three legends and
// `width:NaN%`, which is invalid CSS and silently drops the bar altogether.
// pctOf() is for CSS widths, where 0 is the honest answer. pctText() is for
// anything a person reads as a number, where an unmeasurable value renders as
// an em-dash — a fabricated "0%" would be as wrong as "NaN%".
function pctOf(n, d)   { return d > 0 ? (n/d)*100 : 0; }
function pctText(n, d) { return d > 0 ? Math.round((n/d)*100) + '%' : '—'; }

// ============================================================
// EXECUTIVE SUMMARY PAGE
// ============================================================
function buildExecutive() {
  const emp = DATA.activeEmployees;
  const intune = DATA.intuneDevices.filter(d => !d['is_historical']);
  const terms = DATA.terms;

  document.getElementById('exec-date').textContent =
    'Generated ' + new Date().toLocaleDateString('en-US',{weekday:'long',year:'numeric',month:'long',day:'numeric'});

  const laptops   = DATA.endpoints.filter(isWindowsEndpoint).length;
  const iphones   = DATA.intuneDevices.filter(d=>d['device_category']==='iphone'&&!d['is_historical']).length;
  const macbooks  = DATA.macbooks.length;
  const tablets   = (DATA.tablets||[]).length;
  const compliant = intune.filter(d=>(d['Compliance']||'').toLowerCase()==='compliant').length;
  const noncomp   = intune.filter(d=>(d['Compliance']||'').toLowerCase()==='noncompliant').length;
  const compPct   = intune.length ? Math.round(compliant/intune.length*100) : null; // null = not measured, never 0%
  const laDevices = DATA.liveAuction.length;
  const laStates  = new Set(DATA.liveAuction.map(d=>d['State']).filter(_kit2IsState)).size;  // KIT2-20261017 (DR-19)

  // KPI cards
  const kpis = [
    {icon:'👥',val:emp.length,label:'Active Employees',sub:'FT, PT & Contingent',color:'blue'},
    {icon:'📱',val:intune.length,label:'Managed Devices',sub:compPct==null?'compliance not measured':`${compPct}% compliant`,color:'teal'},
    {icon:'💻',val:laptops+macbooks,label:'Computers',sub:`${macbooks} MacBooks, ${laptops} Windows`,color:'purple'},
    {icon:'🔒',val:compPct==null?'?':compPct,suffix:compPct==null?'':'%',label:'Compliance Rate',sub:compPct==null?'no managed devices reported':`${noncomp} devices at risk`,color:compPct==null?'gray':compPct>=80?'green':'red'},
    {icon:'🏷',val:laDevices,label:'Auction Devices',sub:`${laStates} states covered`,color:'orange'},
    {icon:'📋',val:terms.length,label:'Terminated',sub:'Historical records',color:'yellow'},
    {icon:'☁️',val:DATA.awsWorkspaces.length,label:'Cloud Desktops',sub:'AWS Workspaces',color:'teal'},
    {icon:'📞',val:iphones,label:'iPhones Issued',sub:(DATA.tablets||[]).length+' tablets also issued',color:'blue'},
  ];
  document.getElementById('exec-kpi-grid').innerHTML = kpis.map((k,i)=>`
    <div class="exec-kpi ${k.color} animate" style="animation-delay:${i*70}ms">
      <span class="exec-kpi-icon">${k.icon}</span>
      <div class="exec-kpi-val" data-target="${k.val}" data-suffix="${k.suffix||''}">${(k.val||0).toLocaleString()}${k.suffix||''}</div>
      <div class="exec-kpi-label">${k.label}</div>
      <div class="exec-kpi-sub">${k.sub}</div>
    </div>`).join('');
  animateCards('exec-kpi-grid');

  // Compliance scorecard
  const compColor = compPct==null?'var(--text3)':compPct>=80?'var(--green)':compPct>=60?'var(--yellow)':'var(--red)';
  const riskLabel = compPct==null?'NOT MEASURED':compPct>=80?'LOW RISK':compPct>=60?'MEDIUM RISK':'HIGH RISK';
  document.getElementById('exec-compliance').innerHTML = `
    <div style="text-align:center;padding:10px 0 16px">
      <div style="font-size:52px;font-weight:800;color:${compColor};font-family:var(--mono);letter-spacing:-2px">${compPct==null?'?':compPct+'%'}</div>
      <div style="font-size:12px;color:var(--text3);margin-top:4px">Device Compliance Rate</div>
      <div style="display:inline-flex;align-items:center;gap:6px;margin-top:10px;background:${compPct==null?'rgba(148,163,184,.1)':compPct>=80?'rgba(52,211,153,.1)':compPct>=60?'rgba(251,191,36,.1)':'rgba(248,113,113,.1)'};border:1px solid ${compColor}44;border-radius:20px;padding:4px 14px">
        <div style="width:7px;height:7px;border-radius:50%;background:${compColor}"></div>
        <span style="font-size:10px;font-weight:800;letter-spacing:1.5px;color:${compColor}">${riskLabel}</span>
      </div>
    </div>
    <div class="bar-chart">
      <div class="bar-row"><div class="bar-label">Compliant</div><div class="bar-track"><div class="bar-fill" style="width:${pctOf(compliant, intune.length)}%;background:var(--green)"></div></div><div class="bar-count">${compliant}</div></div>
      <div class="bar-row"><div class="bar-label">Non-Compliant</div><div class="bar-track"><div class="bar-fill" style="width:${pctOf(noncomp, intune.length)}%;background:var(--red)"></div></div><div class="bar-count">${noncomp}</div></div>
    </div>`;

  // Workforce breakdown
  const ft  = emp.filter(e=>e['Pay Class']==='Regular FT').length;
  const pt  = emp.filter(e=>e['Pay Class']==='Regular PT').length;
  const cw  = emp.filter(e=>e['Pay Class']==='Contingent Worker').length;
  const total = emp.length;
  document.getElementById('exec-workforce').innerHTML = [
    {label:'Full-Time',count:ft,color:'var(--accent)'},
    {label:'Part-Time',count:pt,color:'var(--purple)'},
    {label:'Contingent',count:cw,color:'var(--orange)'},
  ].map(r=>`
    <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border)">
      <div style="display:flex;align-items:center;gap:10px">
        <div style="width:10px;height:10px;border-radius:50%;background:${r.color}"></div>
        <span style="font-size:13px;color:var(--text2)">${r.label}</span>
      </div>
      <div style="display:flex;align-items:center;gap:12px">
        <span style="font-size:18px;font-weight:700;font-family:var(--mono);color:var(--text)">${r.count}</span>
        <span style="font-size:11px;color:var(--text3);width:36px;text-align:right">${pctText(r.count, total)}</span>
      </div>
    </div>`).join('');

  // Fleet summary
  const fleetData = [
    {label:'Windows Laptops',count:laptops,color:'var(--accent)'},
    {label:'MacBooks',count:macbooks,color:'var(--purple)'},
    {label:'iPhones',count:iphones,color:'var(--teal)'},
    {label:'Tablets',count:tablets,color:'var(--orange)'},
    {label:'iPads',count:DATA.ipadDevices.length,color:'var(--yellow)'},
  ];
  const maxF = Math.max(...fleetData.map(f=>f.count));
  document.getElementById('exec-fleet').innerHTML = `<div class="bar-chart">` +
    fleetData.map(f=>`<div class="bar-row">
      <div class="bar-label">${f.label}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${maxF?f.count/maxF*100:0}%;background:${f.color}"></div></div>
      <div class="bar-count">${f.count}</div>
    </div>`).join('') + `</div>`;

  // Lifecycle risk summary
  const lcData = buildLifecycleData();
  const lcCrit = lcData.filter(d=>d.risk==='Critical').length;
  const lcWarn = lcData.filter(d=>d.risk==='Warning').length;
  const lcGood = lcData.filter(d=>d.risk==='Good').length;
  const lcTotal = lcData.length;
  document.getElementById('exec-lifecycle').innerHTML = `
    <div style="display:flex;flex-direction:column;gap:10px">
      ${[['🔴 Critical (4+ Win / 3+ Other)',lcCrit,'var(--red)'],['🟡 Warning (3-4 Win / 2-3 Other)',lcWarn,'var(--yellow)'],['🟢 Good',lcGood,'var(--green)']].map(([l,c,col])=>`
      <div style="display:flex;align-items:center;justify-content:space-between;padding:9px 12px;background:var(--surface2);border-radius:8px;">
        <span style="font-size:12px;color:var(--text2)">${l}</span>
        <div style="display:flex;align-items:center;gap:8px">
          <span style="font-size:16px;font-weight:700;font-family:var(--mono);color:${col}">${c}</span>
          <span style="font-size:10px;color:var(--text3)">${lcTotal?Math.round(c/lcTotal*100):0}%</span>
        </div>
      </div>`).join('')}
      <div style="font-size:11px;color:var(--text3);text-align:center;margin-top:4px">${lcTotal} total devices tracked</div>
    </div>`;

  // Auction coverage
  const laActive = DATA.liveAuction.filter(d=>d['Active/Inactive']==='Active').length;
  const stateCounts = {};
  DATA.liveAuction.forEach(d=>{ const s=d['State']; if(_kit2IsState(s)) stateCounts[s]=(stateCounts[s]||0)+1; });
  const topStates = Object.entries(stateCounts).sort((a,b)=>b[1]-a[1]).slice(0,5);
  const maxSt = topStates[0]?.[1]||1;
  document.getElementById('exec-auction').innerHTML = `
    <div style="display:flex;gap:16px;margin-bottom:12px">
      <div style="flex:1;text-align:center;background:var(--surface2);border-radius:8px;padding:10px">
        <div style="font-size:22px;font-weight:700;font-family:var(--mono);color:var(--green)">${laActive}</div>
        <div style="font-size:10px;color:var(--text3)">Active Devices</div>
      </div>
      <div style="flex:1;text-align:center;background:var(--surface2);border-radius:8px;padding:10px">
        <div style="font-size:22px;font-weight:700;font-family:var(--mono);color:var(--accent)">${laStates}</div>
        <div style="font-size:10px;color:var(--text3)">States</div>
      </div>
    </div>
    <div class="bar-chart">` +
    topStates.map(([s,c])=>`<div class="bar-row">
      <div class="bar-label">${esc(s)}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${c/maxSt*100}%;background:var(--orange)"></div></div>
      <div class="bar-count">${c}</div>
    </div>`).join('') + `</div>`;

  // KIT2-20261017 (DR-10): the leader drill-down was only reachable from
  // #leader-chart, which sits hidden on the Overview. The Executive Summary
  // now has its own leader card; rows open Active Employees for that leader.
  const leadEl = document.getElementById('exec-leaders');
  if (leadEl) {
    const lc = {};
    emp.forEach(e => { const l = e['Functional Leader']; if (l) lc[l] = (lc[l] || 0) + 1; });
    const top = Object.entries(lc).sort((a, b) => b[1] - a[1]).slice(0, 8);
    const mx = top[0]?.[1] || 1;
    leadEl.innerHTML = top.length ? `<div class="bar-chart">` + top.map(([n, c]) => `<div class="bar-row" data-leader="${esc(n)}" role="button" tabindex="0" aria-label="Show the ${c} employees under ${esc(n)}">
      <div class="bar-label">${esc(n)}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${c / mx * 100}%;background:var(--accent)"></div></div>
      <div class="bar-count">${c}</div>
    </div>`).join('') + `</div><div style="font-size:11px;color:var(--text3);margin-top:8px">Top ${top.length} of ${Object.keys(lc).length} leaders by active headcount</div>`
      : `<div style="color:var(--text3);font-size:12px">No leader data</div>`;
  }

  // Key insights
  const insights = [];
  if (compPct == null) insights.push({icon:'⚪',text:'Compliance rate is <strong>not measured</strong> — Intune returned no managed devices.',color:'var(--text3)'});
  else if (compPct < 80) insights.push({icon:'🔴',text:`<strong>${noncomp} devices</strong> are non-compliant — ${100-compPct}% of the mobile fleet poses a security risk.`,color:'var(--red)'});
  else insights.push({icon:'🟢',text:`Compliance rate is strong at <strong>${compPct}%</strong>. Only ${noncomp} devices need attention.`,color:'var(--green)'});
  // KIT2-20261017 (DR-20): the rule is 4+ years for Windows, 3+ for the rest.
  if (lcCrit > 0) insights.push({icon:'⚠️',text:`<strong>${lcCrit} devices</strong> are past their replacement age (4+ years Windows, 3+ years other devices) and need replacing.`,color:'var(--yellow)'});
  insights.push({icon:'💰',text:`Total fleet value estimated at <strong>${fmtK(calcFleetValue())}</strong> based on current hardware catalog.`,color:'var(--accent)'});
  insights.push({icon:'📍',text:`Live Auction fleet covers <strong>${laStates} states</strong> with ${laActive} active devices in the field.`,color:'var(--orange)'});
  if (cw > 0) insights.push({icon:'👤',text:`<strong>${cw} contingent workers</strong> (${Math.round(cw/total*100)}% of workforce) may have different device entitlements.`,color:'var(--purple)'});

  document.getElementById('exec-insights').innerHTML = `<div style="display:flex;flex-direction:column;gap:10px">` +
    insights.map(i=>`<div style="display:flex;align-items:flex-start;gap:12px;padding:12px 14px;background:var(--surface2);border-radius:8px;border-left:3px solid ${i.color}">
      <span style="font-size:18px;flex-shrink:0">${i.icon}</span>
      <span style="font-size:13px;color:var(--text2);line-height:1.5">${i.text}</span>
    </div>`).join('') + `</div>`;
}

// KIT2-20261017 (DR-10): click and keyboard for the Executive leader card.
(function initExecLeaders() {
  function go(e) {
    const row = e.target.closest && e.target.closest('#exec-leaders [data-leader]');
    if (!row) return false;
    if (typeof drillByLeader === 'function') drillByLeader(row.getAttribute('data-leader'));
    return true;
  }
  document.addEventListener('click', go);
  document.addEventListener('keydown', e => { if ((e.key === 'Enter' || e.key === ' ') && go(e)) e.preventDefault(); });
})();

// ── Generic KPI count-up animation ──
function animateCards(containerId) {
  var els = document.querySelectorAll('#' + containerId + ' [data-target]');
  // Skip the count-up effect entirely when the tab isn't visible — Chrome
  // throttles requestAnimationFrame in hidden tabs, which used to leave the
  // cards displaying "0" until the user refocused. The inline render now
  // already shows the final value, so skipping the animation is safe.
  var animate = (typeof document.visibilityState === 'undefined') || document.visibilityState === 'visible';
  els.forEach(function(el, i) {
    var target = parseInt(el.dataset.target, 10);
    var suffix = el.dataset.suffix || '';
    if (isNaN(target)) return; // a non-numeric placeholder ('?') stays as rendered
    if (!target) { el.textContent = '0' + suffix; return; }
    if (!animate) { el.textContent = target.toLocaleString() + suffix; return; }
    var duration = 900;
    var delay = i * 70;
    setTimeout(function() {
      var start = performance.now();
      function tick(now) {
        var elapsed = now - start;
        var progress = Math.min(elapsed / duration, 1);
        var eased = 1 - Math.pow(1 - progress, 3);
        var current = Math.round(eased * target);
        el.textContent = current.toLocaleString() + suffix;
        if (progress < 1) requestAnimationFrame(tick);
      }
      requestAnimationFrame(tick);
    }, delay);
  });
}

// ============================================================
// HARDWARE COST REPORT
// ============================================================
function calcFleetValue() {
  const laptops  = DATA.endpoints.filter(isWindowsEndpoint).length;
  const macbooks = DATA.macbooks.length;
  const iphones  = DATA.intuneDevices.filter(d=>d['device_category']==='iphone'&&!d['is_historical']).length;
  const tablets  = (DATA.tablets||[]).length;
  const ipads    = DATA.ipadDevices.length;
  return (laptops * HW_COSTS['LAPTOP'].cost) +
         (macbooks * HW_COSTS['MacBook'].cost) +
         (iphones  * HW_COSTS['iPhone'].cost) +
         (tablets  * HW_COSTS['Tablet'].cost) +
         (ipads    * HW_COSTS['iPad'].cost);
}

function buildCostReport() {
  const emp = DATA.activeEmployees;

  // Hero totals
  const laptopVal  = DATA.endpoints.filter(isWindowsEndpoint).length * HW_COSTS['LAPTOP'].cost;
  const macVal     = DATA.macbooks.length  * HW_COSTS['MacBook'].cost;
  const iphoneVal  = DATA.intuneDevices.filter(d=>d['device_category']==='iphone'&&!d['is_historical']).length * HW_COSTS['iPhone'].cost;
  const tabletVal  = (DATA.tablets||[]).length * HW_COSTS['Tablet'].cost;
  const ipadVal    = DATA.ipadDevices.length   * HW_COSTS['iPad'].cost;
  const totalVal   = laptopVal + macVal + iphoneVal + tabletVal + ipadVal;

  // Replacement estimate (critical devices)
  const lcData = buildLifecycleData();
  // critCost calculated below in replCost loop
  let replCost = 0;
  lcData.filter(d=>d.risk==='Critical'||d.risk==='Warning').forEach(d => {
    if (d.type==='MacBook')       replCost += HW_COSTS['MacBook'].cost;
    else if (d.type==='Windows')  replCost += HW_COSTS['LAPTOP'].cost;
    else if (d.type.includes('iOS')) replCost += HW_COSTS['iPhone'].cost;
    else                          replCost += HW_COSTS['Tablet'].cost;
  });

  document.getElementById('cost-hero').innerHTML = [
    {val:fmtK(totalVal),  label:'Total Fleet Value',   sub:'Current hardware at catalog price', color:'var(--accent)'},
    {val:fmtK(replCost),  label:'Replacement Estimate', sub:'Critical + warning devices',        color:'var(--red)'},
    {val:emp.length ? fmt$(totalVal/emp.length) : '—', label:'Cost Per Employee', sub:'Average across all staff', color:'var(--green)'},
  ].map((h,i)=>`<div class="cost-hero-card animate" style="animation-delay:${i*70}ms">
    <div class="cost-hero-val" style="color:${h.color}">${h.val}</div>
    <div class="cost-hero-label">${h.label}</div>
    <div style="font-size:11px;color:var(--text3);margin-top:4px">${h.sub}</div>
  </div>`).join('');

  // Cost by device type
  const typeData = [
    {label:'Windows Laptops', cost:laptopVal, count:DATA.endpoints.filter(isWindowsEndpoint).length, color:'var(--accent)'},
    {label:'MacBooks',         cost:macVal,    count:DATA.macbooks.length,  color:'var(--purple)'},
    {label:'iPhones',          cost:iphoneVal, count:DATA.intuneDevices.filter(d=>d['device_category']==='iphone'&&!d['is_historical']).length, color:'var(--teal)'},
    {label:'Tablets',          cost:tabletVal, count:(DATA.tablets||[]).length, color:'var(--orange)'},
    {label:'iPads',            cost:ipadVal,   count:DATA.ipadDevices.length,   color:'var(--yellow)'},
  ].filter(d=>d.count>0).sort((a,b)=>b.cost-a.cost);
  const maxCost = typeData[0]?.cost||1;
  document.getElementById('cost-by-type').innerHTML = `<div class="bar-chart">` +
    typeData.map(d=>`<div class="bar-row">
      <div class="bar-label">${d.label}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${d.cost/maxCost*100}%;background:${d.color}"></div></div>
      <div class="bar-count" style="width:80px;color:var(--text)">${fmtK(d.cost)}</div>
    </div>`).join('') + `</div>`;

  // Cost by leader
  const leaderCosts = {};
  // Build device lookup for leader cost breakdown
  const lcDevMap = buildDeviceLookup();
  emp.forEach(e => {
    const l = e['Functional Leader']||'Unknown';
    const k = (e['Username']||'').toLowerCase().trim();
    const d = lcDevMap[k] || {};
    let cost = 0;
    if (d.laptop)  cost += HW_COSTS['LAPTOP'].cost;
    if (d.macbook) cost += HW_COSTS['MacBook'].cost;
    if (d.iphone)  cost += HW_COSTS['iPhone'].cost;
    if (d.tablet)  cost += HW_COSTS['Tablet'].cost;
    if (d.ipad)    cost += HW_COSTS['iPad'].cost;
    leaderCosts[l] = (leaderCosts[l]||0) + cost;
  });
  const topLeaders = Object.entries(leaderCosts).sort((a,b)=>b[1]-a[1]).slice(0,7);
  const maxLC = topLeaders[0]?.[1]||1;
  // KIT2-20261017 (DR-20): the leader and pay-class charts count one device of
  // each type per active employee, so they never add up to the fleet total.
  // Say so, with the numbers.
  const _assigned = Object.values(leaderCosts).reduce((a, b) => a + b, 0);
  const _topSum = topLeaders.reduce((a, [, c]) => a + c, 0);
  const _gapNote = `${fmtK(Math.max(0, totalVal - _assigned))} of the ${fmtK(totalVal)} fleet value is not tied to an active employee (unassigned, shared or leavers' devices, or a second device of the same type).`;
  const _noteDiv = t => `<div style="font-size:11px;color:var(--text3);margin-top:8px;line-height:1.45">${t}</div>`;
  document.getElementById('cost-by-leader').innerHTML = `<div class="bar-chart">` +
    topLeaders.map(([l,c])=>`<div class="bar-row">
      <div class="bar-label">${esc(l)}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${c/maxLC*100}%;background:var(--accent)"></div></div>
      <div class="bar-count" style="width:70px;color:var(--text)">${fmtK(c)}</div>
    </div>`).join('') + `</div>` +
    _noteDiv(`Top ${topLeaders.length} of ${Object.keys(leaderCosts).length} leaders: ${fmtK(_topSum)} of the ${fmtK(_assigned)} assigned to active employees (one device of each type per person). ${_gapNote}`);

  // Replacement cost breakdown
  const replByType = {};
  lcData.filter(d=>d.risk==='Critical'||d.risk==='Warning').forEach(d => {
    const label = d.risk+' - '+d.type;
    let c = 0;
    if (d.type==='MacBook') c=HW_COSTS['MacBook'].cost;
    else if (d.type==='Windows') c=HW_COSTS['LAPTOP'].cost;
    else if (d.type.includes('iOS')) c=HW_COSTS['iPhone'].cost;
    else c=HW_COSTS['Tablet'].cost;
    if (!replByType[d.type]) replByType[d.type]={count:0,cost:0,risk:d.risk};
    replByType[d.type].count++;
    replByType[d.type].cost+=c;
  });
  const replEntries = Object.entries(replByType).sort((a,b)=>b[1].cost-a[1].cost);
  const maxR = replEntries[0]?.[1].cost||1;
  document.getElementById('cost-replacement').innerHTML = replEntries.length ? `<div class="bar-chart">` +
    replEntries.map(([t,v])=>`<div class="bar-row">
      <div class="bar-label">${esc(t)} (${v.count})</div>
      <div class="bar-track"><div class="bar-fill" style="width:${v.cost/maxR*100}%;background:${v.risk==='Critical'?'var(--red)':'var(--yellow)'}"></div></div>
      <div class="bar-count" style="width:70px;color:var(--text)">${fmtK(v.cost)}</div>
    </div>`).join('') + `</div>` :
    `<div style="text-align:center;padding:30px;color:var(--green)">✅ No critical or warning devices found</div>`;

  // Cost by pay class
  // KIT2-20261017 (DR-20): every pay class in the data ("Temporary PT" was
  // dropped), and a missing one is Unknown rather than silently FT.
  const pcCosts = {};
  emp.forEach(e => {
    const pc = e['Pay Class']||'Unknown';
    const k = (e['Username']||'').toLowerCase().trim();
    const d = lcDevMap[k] || {};
    let cost = 0;
    if (d.laptop)  cost += HW_COSTS['LAPTOP'].cost;
    if (d.macbook) cost += HW_COSTS['MacBook'].cost;
    if (d.iphone)  cost += HW_COSTS['iPhone'].cost;
    if (d.tablet)  cost += HW_COSTS['Tablet'].cost;
    if (d.ipad)    cost += HW_COSTS['iPad'].cost;
    pcCosts[pc] = (pcCosts[pc]||0) + cost;
  });
  const pcEntries = Object.entries(pcCosts).filter(([,v])=>v>0).sort((a,b)=>b[1]-a[1]);
  const maxPC = pcEntries[0]?.[1]||1;
  const pcColors = {'Regular FT':'var(--accent)','Regular PT':'var(--purple)','Contingent Worker':'var(--orange)'};
  document.getElementById('cost-by-payclass').innerHTML = `<div class="bar-chart">` +
    pcEntries.map(([l,c])=>`<div class="bar-row">
      <div class="bar-label">${esc(l.replace('Regular ','').replace('Contingent Worker','Contingent'))}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${c/maxPC*100}%;background:${pcColors[l]||'var(--accent)'}"></div></div>
      <div class="bar-count" style="width:70px;color:var(--text)">${fmtK(c)}</div>
    </div>`).join('') + `</div>` +
    _noteDiv(`${fmtK(_assigned)} assigned to active employees. ${_gapNote}`);
}

// ============================================================
// PDF EXPORT (Executive Summary)
// ============================================================
function exportExecPDF() {
  const emp = DATA.activeEmployees;
  const intune = DATA.intuneDevices.filter(d => !d['is_historical']);
  const compliant = intune.filter(d=>(d['Compliance']||'').toLowerCase()==='compliant').length;
  const noncomp   = intune.filter(d=>(d['Compliance']||'').toLowerCase()==='noncompliant').length;
  const compPct   = intune.length ? Math.round(compliant/intune.length*100) : null; // null = not measured, never 0%
  const laptops   = DATA.endpoints.filter(isWindowsEndpoint).length;
  const macbooks  = DATA.macbooks.length;
  const iphones   = DATA.intuneDevices.filter(d=>d['device_category']==='iphone'&&!d['is_historical']).length;
  const tablets   = (DATA.tablets||[]).length;
  const laStates  = new Set(DATA.liveAuction.map(d=>d['State']).filter(_kit2IsState)).size;  // KIT2-20261017 (DR-19)
  const lcData    = buildLifecycleData();
  const lcCrit    = lcData.filter(d=>d.risk==='Critical').length;
  const fleetVal  = calcFleetValue();
  const today     = new Date().toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'});
  // Light-mode branch removed — the popup PDF now always uses a print-friendly
  // light palette regardless of the on-screen theme. Printing dark-on-dark
  // wasted toner and was unreadable on paper.
  const bg     = '#ffffff';
  const surf   = '#f0f2f7';
  const txt    = '#111827';
  const txt3   = '#6b7280';
  const border = '#e5e7eb';

  const w = window.open('','_blank');
  w.document.write(`<!DOCTYPE html><html><head><title>IT Asset Inventory — Executive Summary</title>
<link href="${location.origin}/fonts/fonts.css" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'DM Sans',sans-serif;background:${bg};color:${txt};padding:40px;max-width:900px;margin:0 auto;}
.header{display:flex;align-items:center;justify-content:space-between;margin-bottom:32px;padding-bottom:20px;border-bottom:2px solid #4f8ef7;}
.header-title{font-size:24px;font-weight:800;color:${txt};}
.header-sub{font-size:12px;color:${txt3};margin-top:4px;}
.header-date{font-size:11px;color:${txt3};text-align:right;}
.kpi-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px;}
.kpi{background:${surf};border:1px solid ${border};border-radius:10px;padding:16px;text-align:center;}
.kpi-val{font-size:28px;font-weight:800;font-family:'DM Mono',monospace;color:#4f8ef7;}
.kpi-label{font-size:10px;color:${txt3};margin-top:4px;text-transform:uppercase;letter-spacing:.5px;}
.section{margin-bottom:24px;}
.section-title{font-size:14px;font-weight:700;color:${txt};margin-bottom:12px;padding-bottom:6px;border-bottom:1px solid ${border};}
.row{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid ${border};font-size:12px;}
.row-label{color:${txt3};}
.row-val{font-weight:700;font-family:'DM Mono',monospace;}
.insights{display:flex;flex-direction:column;gap:8px;}
.insight{padding:10px 14px;background:${surf};border-radius:8px;font-size:12px;border-left:3px solid #4f8ef7;color:${txt3};}
.footer{margin-top:32px;padding-top:16px;border-top:1px solid ${border};font-size:10px;color:${txt3};display:flex;justify-content:space-between;}
@media print{body{padding:20px;}@page{margin:0.5in;}}
</style></head><body>
<div class="header">
  <div><div class="header-title">IT Asset Inventory — Executive Summary</div><div class="header-sub">auction.com IT Department</div></div>
  <div class="header-date">Generated: ${today}<br>CONFIDENTIAL — INTERNAL USE ONLY</div>
</div>
<div class="kpi-grid">
  <div class="kpi"><div class="kpi-val">${emp.length}</div><div class="kpi-label">Active Employees</div></div>
  <div class="kpi"><div class="kpi-val">${intune.length}</div><div class="kpi-label">Managed Devices</div></div>
  <div class="kpi"><div class="kpi-val" style="color:${compPct==null?'#94a3b8':compPct>=80?'#34d399':'#f87171'}">${compPct==null?'?':compPct+'%'}</div><div class="kpi-label">Compliance Rate</div></div>
  <div class="kpi"><div class="kpi-val" style="color:${lcCrit>0?'#f87171':'#34d399'}">${lcCrit}</div><div class="kpi-label">Critical Devices</div></div>
</div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px;">
  <div class="section">
    <div class="section-title">Device Fleet</div>
    <div class="row"><span class="row-label">Windows Laptops</span><span class="row-val">${laptops}</span></div>
    <div class="row"><span class="row-label">MacBooks</span><span class="row-val">${macbooks}</span></div>
    <div class="row"><span class="row-label">iPhones</span><span class="row-val">${iphones}</span></div>
    <div class="row"><span class="row-label">Tablets</span><span class="row-val">${tablets}</span></div>
    <div class="row"><span class="row-label">AWS Workspaces</span><span class="row-val">${DATA.awsWorkspaces.length}</span></div>
  </div>
  <div class="section">
    <div class="section-title">Workforce</div>
    <div class="row"><span class="row-label">Full-Time</span><span class="row-val">${emp.filter(e=>e['Pay Class']==='Regular FT').length}</span></div>
    <div class="row"><span class="row-label">Part-Time</span><span class="row-val">${emp.filter(e=>e['Pay Class']==='Regular PT').length}</span></div>
    <div class="row"><span class="row-label">Contingent</span><span class="row-val">${emp.filter(e=>e['Pay Class']==='Contingent Worker').length}</span></div>
    <div class="row"><span class="row-label">Terminated (YTD)</span><span class="row-val">${DATA.terms.length}</span></div>
    <div class="row"><span class="row-label">Live Auction States</span><span class="row-val">${laStates}</span></div>
  </div>
</div>
<div class="section">
  <div class="section-title">Key Insights</div>
  <div class="insights">
    <div class="insight" style="border-color:${compPct==null?'#94a3b8':compPct>=80?'#34d399':'#f87171'}">${compPct==null?'Compliance: not measured — Intune returned no managed devices.':`Compliance: ${compPct}% of managed devices are compliant. ${noncomp} devices require immediate attention.`}</div>
    ${lcCrit>0?`<div class="insight" style="border-color:#fbbf24">${lcCrit} devices are past their replacement threshold and flagged for replacement.</div>`:''}
    <div class="insight" style="border-color:#4f8ef7">Estimated total fleet value: ${fmtK(fleetVal)} based on current hardware catalog pricing.</div>
    <div class="insight" style="border-color:#fb923c">Live Auction fleet covers ${laStates} states with ${DATA.liveAuction.length} total devices.</div>
  </div>
</div>
<div class="footer"><span>auction.com IT Department — Confidential</span><span>IT Asset Inventory v2.0 — ${today}</span></div>
<script>window.onload=()=>{window.print();}<\/script>
</body></html>`);
  w.document.close();
}

// ============================================================
// DEVICE LIFECYCLE
// ============================================================

// Age thresholds in years
const LC_CRITICAL     = 3;
const LC_WARNING      = 2;
const LC_WIN_CRITICAL = 4;   // Windows devices get longer lifecycle (4+ yrs = critical)
const LC_WIN_WARNING  = 3;   // Windows 3-4 yrs = warning

function parseLastSeen(val) {
  if (!val) return null;
  // Handle Excel serial dates (numbers like 45310.79)
  const num = parseFloat(val);
  if (!isNaN(num) && num > 40000 && num < 50000) {
    // Excel date serial — days since 1900-01-01
    const ms = (num - 25569) * 86400 * 1000;
    return new Date(ms);
  }
  const d = new Date(val);
  return isNaN(d.getTime()) ? null : d;
}

function riskLevel(ageYears, deviceType) {
  if (ageYears === null) return 'Unknown';
  const critical = deviceType === 'Windows' ? LC_WIN_CRITICAL : LC_CRITICAL;
  const warning  = deviceType === 'Windows' ? LC_WIN_WARNING  : LC_WARNING;
  if (ageYears >= critical) return 'Critical';
  if (ageYears >= warning)  return 'Warning';
  return 'Good';
}

function riskBadge(risk) {
  const map = {
    Critical: 'risk-badge risk-critical',
    Warning:  'risk-badge risk-warning',
    Good:     'risk-badge risk-good',
    Unknown:  'risk-badge risk-unknown',
  };
  const icons = { Critical:'🔴', Warning:'🟡', Good:'🟢', Unknown:'⚪' };
  return `<span class="${map[risk]||'risk-badge risk-unknown'}">${icons[risk]||'⚪'} ${risk}</span>`;
}

// ── True device age helpers ───────────────────────────────────
const DELL_WARRANTY_YEARS = 4; // Dell ProSupport = 4 years; subtract from expiry to get purchase date

function trueDeviceAge(serial, computerName, lastSeenDate) {
  // Look up warranty record by service tag, fall back to computer name
  const wKey  = serial?.toLowerCase().trim();
  const wKey2 = 'name:' + computerName?.toLowerCase().trim();
  const w     = _warrantyMap[wKey] || _warrantyMap[wKey2] || null;

  // Source 1: warranty expiry date − 4 years = purchase date (most accurate)
  if (w?.warranty_expiry_date && w.warranty_expiry_date !== '--') {
    const expiry = new Date(w.warranty_expiry_date);
    if (!isNaN(expiry)) {
      const purchased = new Date(expiry);
      purchased.setFullYear(purchased.getFullYear() - DELL_WARRANTY_YEARS);
      const age = (new Date() - purchased) / (1000 * 60 * 60 * 24 * 365.25);
      if (age >= 0 && age < 20) return { age, source: 'warranty' };
    }
  }

  // Source 2: agent_installed_on (Unix ms timestamp) = deployment date
  if (w?.agent_installed_on) {
    const deployed = new Date(Number(w.agent_installed_on));
    if (!isNaN(deployed)) {
      const age = (new Date() - deployed) / (1000 * 60 * 60 * 24 * 365.25);
      if (age >= 0 && age < 20) return { age, source: 'deployed' };
    }
  }

  // Source 3: last scan/check-in (least accurate — original behavior)
  if (lastSeenDate) {
    const age = (new Date() - lastSeenDate) / (1000 * 60 * 60 * 24 * 365.25);
    return { age, source: 'lastseen' };
  }

  return { age: null, source: null };
}

let _lcData = null;
let _lcDataVersion = -1;
function buildLifecycleData() {
  // Thousands of Date allocations — parseLastSeen() + trueDeviceAge() +
  // warrantyStatus() per device — rebuilt on every lifecycle render and by five
  // other consumers. Cached against the shared counter, which loadWarrantyMap()
  // and loadAbmWarrantyMap() also bump because every age and warranty field
  // below is derived from those two maps.
  if (_lcData && _lcDataVersion === DATA_VERSION) return _lcData;
  const devices = [];
  const seenSerials = new Set();
  const normSerial = s => {
    const v = (s == null ? '' : String(s)).toLowerCase().trim();
    return (v && v !== '—') ? v : '';
  };

  // Windows endpoints (ManageEngine) — authoritative for Windows hardware
  DATA.endpoints.filter(isWindowsEndpoint).forEach(d => {
    const lastSeen  = parseLastSeen(d['Last Successful Asset Scan']);
    const serial    = d['Service Tag'] || d['Computer Name'] || '—';
    const name      = d['First/Last'] || d['Computer Name'] || '—';
    const { age, source } = trueDeviceAge(serial, name, lastSeen);
    const key = normSerial(serial);
    if (key) seenSerials.add(key);
    devices.push({
      name, serial, lastSeen,
      type:      'Windows',
      model:     d['Device Model'] || '—',
      ageYears:  age,
      ageSource: source,
      risk:      riskLevel(age, 'Windows'),
    });
  });

  // MacBooks (Kandji) — authoritative for Apple laptops
  DATA.macbooks.forEach(d => {
    const serial = d['Serial'] || '—';
    const key = normSerial(serial);
    if (key && seenSerials.has(key)) return;
    if (key) seenSerials.add(key);
    const lastSeen  = parseLastSeen(d['Checked In']);
    const name      = d['User'] || '—';
    const { age, source } = trueDeviceAge(serial, name, lastSeen);
    devices.push({
      name, serial, lastSeen,
      type:      'MacBook',
      model:     d['Model'] || '—',
      ageYears:  age,
      ageSource: source,
      risk:      riskLevel(age, 'MacBook'),
    });
  });

  // Intune devices — classify by actual OS, dedupe against authoritative sources above.
  // Intune may carry Windows laptops and macOS devices in addition to iOS/Android; the
  // previous code mis-tagged anything non-iOS as "Android".
  DATA.intuneDevices.filter(d => !d['is_historical']).forEach(d => {
    const serial = d['Serial number'] || '—';
    const key = normSerial(serial);
    if (key && seenSerials.has(key)) return;
    const os = (d['OS'] || '').toLowerCase();
    let devType;
    if (os.includes('ios') || os.includes('ipados'))   devType = 'iOS/iPadOS';
    else if (os.includes('android'))                   devType = 'Android';
    else if (os.includes('windows'))                   devType = 'Windows';
    else if (os.includes('mac') || os.includes('osx')) devType = 'MacBook';
    else devType = 'Other';
    if (key) seenSerials.add(key);
    const lastSeen  = parseLastSeen(d['Last check-in']);
    const name      = d['Primary user display name'] || d['Primary user UPN'] || '—';
    const { age, source } = trueDeviceAge(serial, name, lastSeen);
    devices.push({
      name, serial, lastSeen,
      type:      devType,
      model:     d['Model'] || '—',
      ageYears:  age,
      ageSource: source,
      risk:      riskLevel(age, devType),
    });
  });

  // Attach warranty fields to each device
  devices.forEach(d => {
    const wKey  = d.serial?.toLowerCase().trim();
    const wKey2 = 'name:' + d.name?.toLowerCase().trim();
    let w       = _warrantyMap[wKey] || _warrantyMap[wKey2] || null;
    // ABM fallback for Apple devices (ManageEngine has no Apple warranty data)
    if (!w?.warranty_expiry_date && d.type === 'MacBook' && ABM_WARRANTY_MAP && d.serial) {
      const abm = ABM_WARRANTY_MAP.get(d.serial);
      if (abm && abm.coverage_ends) {
        w = { warranty_expiry_date: abm.coverage_ends.split('T')[0] };
      }
    }
    const wInfo = warrantyStatus(w?.warranty_expiry_date);
    d.warrantyExpiry = w?.warranty_expiry_date || null;
    d.warrantyDays   = wInfo.days;
  });

  _lcData = devices;
  _lcDataVersion = DATA_VERSION;
  return devices;
}

async function buildLifecycleDashboard() {
  // Load warranty maps in parallel (ManageEngine for Windows, ABM for Apple)
  await Promise.all([loadWarrantyMap(), loadAbmWarrantyMap()]);
  const devices = buildLifecycleData();
  const critical = devices.filter(d => d.risk === 'Critical').length;
  const warning  = devices.filter(d => d.risk === 'Warning').length;
  const good     = devices.filter(d => d.risk === 'Good').length;
  const unknown  = devices.filter(d => d.risk === 'Unknown').length;
  const total    = devices.length;

  document.getElementById('badge-lc').textContent = critical;

  // KPI cards
  document.getElementById('lc-kpi-cards').innerHTML = `
    <div class="stat-card red animate" style="animation-delay:0ms"><div class="stat-icon">🔴</div>
      <div class="stat-label">Critical (4+ Win / 3+ Other)</div>
      <div class="stat-value" data-target="${critical}">0</div>
      <div class="stat-sub">Immediate replacement needed</div>
    </div>
    <div class="stat-card yellow animate" style="animation-delay:70ms"><div class="stat-icon">🟡</div>
      <div class="stat-label">Warning (3-4 Win / 2-3 Other)</div>
      <div class="stat-value" data-target="${warning}">0</div>
      <div class="stat-sub">Plan for replacement soon</div>
    </div>
    <div class="stat-card green animate" style="animation-delay:140ms"><div class="stat-icon">🟢</div>
      <div class="stat-label">Good (&lt;3 Win / &lt;2 Other)</div>
      <div class="stat-value" data-target="${good}">0</div>
      <div class="stat-sub">No action needed</div>
    </div>
    <div class="stat-card blue animate" style="animation-delay:210ms"><div class="stat-icon">📱</div>
      <div class="stat-label">Total Tracked</div>
      <div class="stat-value" data-target="${total}">0</div>
      <div class="stat-sub">${unknown} with unknown age</div>
    </div>
  `;
  animateCards('lc-kpi-cards');

  // Timeline bar
  const pct = v => total ? Math.round(v/total*100) : 0;
  document.getElementById('lc-timeline-bar').innerHTML = `
    <div class="timeline-seg" style="width:${pct(critical)}%;background:#f87171" title="Critical">${pct(critical)>5?pct(critical)+'%':''}</div>
    <div class="timeline-seg" style="width:${pct(warning)}%;background:#fbbf24" title="Warning">${pct(warning)>5?pct(warning)+'%':''}</div>
    <div class="timeline-seg" style="width:${pct(good)}%;background:#34d399" title="Good">${pct(good)>5?pct(good)+'%':''}</div>
    <div class="timeline-seg" style="width:${pct(unknown)}%;background:var(--surface3)" title="Unknown">${pct(unknown)>5?pct(unknown)+'%':''}</div>
  `;
  document.getElementById('lc-timeline-legend').innerHTML = [
    ['#f87171','Critical',critical],['#fbbf24','Warning',warning],
    ['#34d399','Good',good],['var(--surface3)','Unknown',unknown]
  ].map(([c,l,v])=>`<div style="display:flex;align-items:center;gap:6px;font-size:11px">
    <div style="width:10px;height:10px;border-radius:50%;background:${c}"></div>
    <span style="color:var(--text2)">${l}</span>
    <span style="color:var(--text);font-family:var(--mono);font-weight:600">${v}</span>
  </div>`).join('');

  // Age distribution by type
  const types = ['iOS/iPadOS','Android','MacBook','Windows'];
  const typeCounts = {};
  types.forEach(t => {
    const td = devices.filter(d => d.type === t);
    typeCounts[t] = {
      critical: td.filter(d=>d.risk==='Critical').length,
      warning:  td.filter(d=>d.risk==='Warning').length,
      good:     td.filter(d=>d.risk==='Good').length,
      total:    td.length,
    };
  });
  const maxType = Math.max(...types.map(t=>typeCounts[t].total));
  document.getElementById('lc-age-chart').innerHTML = types.map(t => {
    const tc = typeCounts[t];
    if (!tc.total) return '';
    return `<div class="bar-row">
      <div class="bar-label">${t}</div>
      <div class="bar-track" style="height:18px;position:relative">
        <div style="display:flex;height:100%;width:${tc.total/maxType*100}%;border-radius:4px;overflow:hidden">
          <div style="width:${tc.critical/tc.total*100}%;background:#f87171"></div>
          <div style="width:${tc.warning/tc.total*100}%;background:#fbbf24"></div>
          <div style="width:${tc.good/tc.total*100}%;background:#34d399"></div>
        </div>
      </div>
      <div class="bar-count">${tc.total}</div>
    </div>`;
  }).join('');

  // Priority by type
  const critByType = types.map(t=>({t, c:typeCounts[t].critical})).filter(x=>x.c>0).sort((a,b)=>b.c-a.c);
  const maxCrit = critByType[0]?.c || 1;
  document.getElementById('lc-priority-chart').innerHTML = `<div class="bar-chart">` +
    critByType.map(({t,c})=>`<div class="bar-row">
      <div class="bar-label">${t}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${c/maxCrit*100}%;background:#f87171"></div></div>
      <div class="bar-count">${c}</div>
    </div>`).join('') + `</div>`;
}

function renderLifecycle() {
  const riskFilter = document.getElementById('lc-filter-risk')?.value;
  const typeFilter = document.getElementById('lc-filter-type')?.value;

  let devices = buildLifecycleData();
  if (riskFilter) devices = devices.filter(d => d.risk === riskFilter);
  if (typeFilter) devices = devices.filter(d => d.type === typeFilter);
  if (searchQuery) devices = devices.filter(d =>
    Object.values(d).some(v => v && String(v).toLowerCase().includes(searchQuery))
  );

  // Apply sorting
  // One shared risk map. The default branch used to keep its own copy and rank
  // with `||3`, which turned Critical's rank of 0 (falsy) into 3 — so a fresh
  // page load listed Warning devices first and buried every Critical one on the
  // last pages, on the page whose whole job is surfacing them.
  const riskOrder = {Critical:0,Warning:1,Good:2,Unknown:3};
  const s = sortState['lifecycle'];
  if (s?.col) {
    devices = [...devices].sort((a,b) => {
      if (s.col === 'ageYears')     return ((a.ageYears||0) - (b.ageYears||0)) * s.dir;
      if (s.col === 'warrantyDays') return ((a.warrantyDays??99999) - (b.warrantyDays??99999)) * s.dir;
      if (s.col === 'lastSeen') {
        const at = a.lastSeen ? a.lastSeen.getTime() : 0;
        const bt = b.lastSeen ? b.lastSeen.getTime() : 0;
        return (at - bt) * s.dir;
      }
      if (s.col === 'risk') return ((riskOrder[a.risk]??3) - (riskOrder[b.risk]??3)) * s.dir;
      const av = a[s.col]||'', bv = b[s.col]||'';
      return cmpText(av, bv) * s.dir;
    });
  } else {
    // Default: critical first. Copy before sorting: buildLifecycleData() now
    // returns a SHARED cached array, and an in-place sort here would reorder it
    // under buildExecutive(), buildCostReport(), exportExecPDF() and
    // exportLifecycle(), which all read the same array.
    devices = devices.slice().sort((a,b) => (riskOrder[a.risk]??3) - (riskOrder[b.risk]??3));
  }

  const total = devices.length;
  document.getElementById('lc-count').textContent = `${total.toLocaleString()} devices`;

  const p = pages['lifecycle'] || 1;
  const paged = devices.slice((p-1)*PAGE_SIZE, p*PAGE_SIZE);

  document.getElementById('lc-tbody').innerHTML = paged.map(d => {
    const lastSeenStr = d.lastSeen ? d.lastSeen.toLocaleDateString('en-US', {year:'numeric',month:'short',day:'numeric'}) : '—';
    const ageStr = d.ageYears !== null ? `${d.ageYears.toFixed(1)} yrs` : '—';
    const ageSourceIcon = d.ageSource === 'warranty'  ? '<span title="Age from warranty expiry date" style="font-size:9px;color:var(--text3);margin-left:3px">🛡</span>'
                        : d.ageSource === 'deployed'  ? '<span title="Age from deployment date" style="font-size:9px;color:var(--text3);margin-left:3px">📅</span>'
                        : d.ageSource === 'lastseen'  ? '<span title="Age from last scan (less accurate)" style="font-size:9px;color:var(--yellow);margin-left:3px">⚠</span>'
                        : '';

    // Warranty data — read from build pass (handles both ManageEngine and ABM)
    const wInfo = warrantyStatus(d.warrantyExpiry);

    // Warranty expiry display
    const wExpiryStr = d.warrantyExpiry || '—';

    // Days remaining display
    const wDaysStr = wInfo.days !== null
      ? (wInfo.days < 0 ? `${Math.abs(wInfo.days)}d ago` : `${wInfo.days}d`)
      : '—';
    const wDaysColor = wInfo.days === null ? '' 
      : wInfo.days < 0   ? 'color:var(--red);font-weight:700'
      : wInfo.days <= 90 ? 'color:var(--yellow);font-weight:700'
      : 'color:var(--green)';

    // Flag icon if expired
    const wFlag = wInfo.label === 'Expired'
      ? ' <span title="Warranty Expired" style="font-size:12px">🚩</span>' : '';

    return `<tr>
      <td class="cell-name">${esc(d.name)}${wFlag}</td>
      <td>${esc(d.type)}</td>
      <td>${esc(d.model)}</td>
      <td class="cell-mono" style="font-size:11px">${esc(lastSeenStr)}</td>
      <td class="cell-mono">${esc(ageStr)}${ageSourceIcon}</td>
      <td>${riskBadge(d.risk)}</td>
      <td class="cell-mono" style="font-size:11px">${esc(d.serial)}</td>
      <td class="cell-mono" style="font-size:11px">${esc(wExpiryStr)}</td>
      <td class="cell-mono" style="font-size:11px;${wDaysColor}">${esc(wDaysStr)}</td>
    </tr>`;
  }).join('') || '<tr><td colspan="10" style="text-align:center;padding:40px;color:var(--text3)">No devices found</td></tr>';

  renderPagination('lc-pagination','lc-page-info', total, 'lifecycle');
}

function exportLifecycle() {
  const devices = buildLifecycleData().filter(d => d.risk === 'Critical' || d.risk === 'Warning');
  if (!devices.length) { showToast('No flagged devices to export', 'warn'); return; }
  const headers = ['Name','Type','Model','Serial','Last Check-in','Age (Years)','Risk'];
  const out = [headers.map(_csvEscape)];
  devices.forEach(d => {
    out.push([
      d.name, d.type, d.model, d.serial,
      d.lastSeen ? d.lastSeen.toLocaleDateString() : '',
      d.ageYears !== null ? d.ageYears.toFixed(1) : '',
      d.risk,
    ].map(_csvEscape));
  });
  _downloadBlob(_toCsvBlob(out), `device_lifecycle_flagged_${new Date().toISOString().split('T')[0]}.csv`);
  showToast(`Exported ${devices.length} flagged devices`);
}

// ============================================================
// WARRANTY
// ============================================================
let _warrantyData = [];
// True when /hub-api/api/warranty failed on the last load. The Windows fleet is
// the bulk of the ManageEngine estate and the part most likely to be out of
// warranty, so its absence makes this page and the dashboard gauge read BETTER
// than reality. The flag turns that silent narrowing into a visible statement.
let _warrantyMeFailed = false;
let _warrantyMap  = {}; // keyed by service_tag and name: for lifecycle lookup
let _intuneGraphMap = {}; // keyed by serial and name: for endpoint Intune lookup
let _patchHealthCache = {}; // keyed by resource_id — stores patch health per device
let _patchHealthCacheLoaded = false; // true once /api/me-patch/cache has resolved (success or empty)

async function triggerPatchSync() {
  const btn = document.getElementById('ep-patch-sync-btn');
  if (btn) { btn.disabled = true; btn.textContent = '🩹 Syncing…'; }
  try {
    const res  = await fetch('/api/me-patch/sync-all', { method: 'POST' });
    if (!res.ok) throw new Error('HTTP ' + res.status + (res.status === 504 ? ' — the sync outlived the proxy timeout; it may still be running on the server' : ''));
    const data = await res.json();
    if (data.success) {
      // Clear cache so next render reloads from DB
      Object.keys(_patchHealthCache).forEach(k => delete _patchHealthCache[k]);
      _patchHealthCacheLoaded = false;
      await loadPatchHealthCache();
      renderEndpoints();
      showToast(`Patch sync complete: ${data.synced} synced, ${data.errors} errors`, data.errors ? 'warn' : 'success');
    } else {
      showToast('Patch sync failed: ' + (data.error || 'Unknown error'), 'err');
    }
  } catch(e) {
    showToast('Patch sync error: ' + e.message, 'err');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '🩹 Sync Patches'; }
  }
}

// Load patch health from DB cache — one API call for all devices
let _patchHealthCacheErrorAt = 0;
async function loadPatchHealthCache() {
  if (_patchHealthCacheLoaded) return; // already loaded (only on success)
  // After a failure, wait 30s before hammering the backend again
  if (_patchHealthCacheErrorAt && Date.now() - _patchHealthCacheErrorAt < 30000) return;
  try {
    const res  = await fetch('/api/me-patch/cache');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    if (data.success && data.cache) {
      // Normalise at the boundary. This cache had two readers that disagreed on
      // key casing — the write-back just below assumed snake_case, while
      // patchHealthBadge read camelCase — so whichever convention
      // /api/me-patch/cache actually returns, one of them was silently reading
      // undefined: either the Patch Health filter dropped every row, or every
      // badge printed the literal string "undefined". Accept both shapes here
      // and store exactly one, so neither reader can be wrong again.
      Object.keys(data.cache).forEach(rid => {
        const v = data.cache[rid] || {};
        _patchHealthCache[rid] = {
          health:       v.health,
          scanStatus:   v.scan_status ?? v.scanStatus,
          lastScanTime: v.last_scan_time ?? v.lastScanTime,
        };
      });
      // Write health back to DATA rows for sort/filter
      DATA.endpoints.forEach(ep => {
        if (ep.resource_id && _patchHealthCache[ep.resource_id]) {
          const ph = _patchHealthCache[ep.resource_id];
          ep['Patch Health'] = ph.health;
          ep['Patch Scan']   = ph.scanStatus;
          ep['Patch Last Scan'] = ph.lastScanTime;
        }
      });
      // Rows mutated IN PLACE — no array was reassigned, so nothing else would
      // notice. Every cached search haystack and every index derived from
      // DATA.endpoints is now out of date.
      bumpDataVersion();
      _patchHealthCacheLoaded = true;
      _patchHealthCacheErrorAt = 0;
    } else {
      _patchHealthCacheErrorAt = Date.now();
    }
  } catch(e) {
    console.warn('Could not load patch health cache:', e.message);
    _patchHealthCacheErrorAt = Date.now();
  }
}

function patchHealthBadge(resourceId) {
  if (!resourceId) return '<td><span class="badge badge-gray" style="font-size:9px">No ID</span></td>';
  const d = _patchHealthCache[resourceId];
  // class instead of id — multiple rows can share the "loading" state, and
  // duplicate IDs in the DOM are a spec violation that breaks any future
  // querySelector lookup.
  if (!d) {
    // Show "Loading…" only while the cache fetch is in flight; once it's
    // resolved and this device wasn't in it, the cache will never produce a
    // value without an explicit Sync Patches click — so render a terminal
    // "—" instead of a loading state that lies forever.
    if (!_patchHealthCacheLoaded) {
      if (typeof _patchHealthCacheErrorAt !== 'undefined' && _patchHealthCacheErrorAt) {
        return `<td><span class="badge badge-yellow" data-resource-id="${esc(resourceId)}" style="font-size:9px" title="Patch data unavailable — backend error, retrying">⚠ Unavailable</span></td>`;
      }
      return `<td><span class="badge badge-gray patch-health-loading" data-resource-id="${esc(resourceId)}" style="font-size:9px">Loading…</span></td>`;
    }
    return `<td><span class="badge badge-gray" data-resource-id="${esc(resourceId)}" style="font-size:9px" title="Run Sync Patches to fetch health for this device">—</span></td>`;
  }
  const colorMap = { 'Healthy':'green', 'Vulnerable':'yellow', 'Highly Vulnerable':'red', 'Unknown':'gray' };
  // Reads the normalised shape written by loadPatchHealthCache. A missing field
  // is unknown, not bad: render 'Unknown' / '—' rather than the literal string
  // "undefined", which is what the old key-shape mismatch printed under every
  // device that had patch data.
  const health = d.health || 'Unknown';
  const color = colorMap[health] || 'gray';
  const scanFailed = d.scanStatus === 'Failed' || d.scanStatus === 'Not Scanned';
  const sub = scanFailed
    ? `<div style="font-size:9px;color:var(--red);margin-top:2px">${d.scanStatus}</div>`
    : `<div style="font-size:9px;color:var(--text3);margin-top:2px">${d.lastScanTime || '—'}</div>`;
  return `<td><span class="badge badge-${color}" style="font-size:9px">${health}</span>${sub}</td>`;
}
// The row objects carry `days` (spread in from warrantyStatus()); there has
// never been a days_remaining key, so both the default sort and the Days Left
// header compared undefined and left the table in arbitrary order.
let _warrantySortCol = 'days';
let _warrantySortDir = 1;

async function loadWarrantyMap() {
  try {
    const res  = await fetch(`${WARRANTY_BASE}/api/warranty/map`);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    _warrantyMap = await res.json();
  } catch(e) {
    console.warn('Could not load warranty map:', e && e.message);
    _warrantyMap = {};
  }
  // buildLifecycleData() derives every device age and warranty field from this
  // map, so replacing it invalidates the lifecycle cache exactly the way a
  // DATA.* reassignment does. Both branches above replace it.
  bumpDataVersion();
}

let _intuneGraphMapExpiry = 0;
let _intuneGraphMapError = false;
async function loadIntuneGraphMap() {
  // Cache for 5 minutes — avoids refetching on every tab navigation
  if (Date.now() < _intuneGraphMapExpiry && Object.keys(_intuneGraphMap).length > 0) return;
  try {
    const res = await fetch(`${WARRANTY_BASE}/api/intune-graph/map`);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    _intuneGraphMap = await res.json();
    _intuneGraphMapExpiry = Date.now() + 5 * 60 * 1000;
    _intuneGraphMapError = false;
  } catch(e) {
    console.warn('Could not load Intune graph map:', e.message);
    _intuneGraphMap = {};
    _intuneGraphMapError = true;
  }
}

function warrantyStatus(expiryDateStr) {
  if (!expiryDateStr || expiryDateStr === '--') return { label:'Unknown', cls:'risk-unknown', days: null };
  const exp = new Date(expiryDateStr);
  if (isNaN(exp)) return { label:'Unknown', cls:'risk-unknown', days: null };
  const now = new Date();
  const days = Math.round((exp - now) / (1000*60*60*24));
  if (days < 0)   return { label:'Expired',       cls:'risk-critical', days };
  if (days <= 90) return { label:'Expiring Soon', cls:'risk-warning',  days };
  return               { label:'Active',         cls:'risk-good',     days };
}

function warrantyBadge(expiryDateStr) {
  const s = warrantyStatus(expiryDateStr);
  const icons = { 'Expired':'🔴', 'Expiring Soon':'🟡', 'Active':'🟢', 'Unknown':'⚪' };
  return `<span class="risk-badge ${s.cls}">${icons[s.label]||'⚪'} ${s.label}</span>`;
}

async function loadWarrantyData() {
  // Existing ManageEngine warranty (Windows + everything ManageEngine sees)
  let meRows = [];
  _warrantyMeFailed = false; // reset per load so a later success clears the notice
  try {
    const res  = await fetch(`${WARRANTY_BASE}/api/warranty`);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    meRows = (data.computers || []).map(c => ({
      ...c,
      ...warrantyStatus(c.warranty_expiry_date),
    }));
  } catch(e) {
    console.warn('Failed to load ManageEngine warranty data:', e && e.message);
    meRows = [];
    _warrantyMeFailed = true;
  }

  // ABM warranty enrichment for Apple devices already in inventory
  const appleRows = [];
  const appleSerials = new Set();
  try {
    await loadAbmWarrantyMap();
    if (ABM_WARRANTY_MAP && ABM_WARRANTY_MAP.size > 0) {
      const buildAppleRow = (serial, computerName, model, deviceType, user) => {
        const w = ABM_WARRANTY_MAP.get(serial);
        const expiry = w && w.coverage_ends ? w.coverage_ends.split('T')[0] : null;
        return {
          computer_name: computerName || '—',
          service_tag: serial,
          device_model: model || '—',
          device_manufacturer: 'Apple',
          device_type: deviceType,
          logged_on_user: user || '—',
          warranty_expiry_date: expiry,
          ...warrantyStatus(expiry),
        };
      };
      (DATA.macbooks || []).forEach(d => {
        const serial = d['Serial']; if (!serial) return;
        appleSerials.add(serial);
        appleRows.push(buildAppleRow(serial, d['Device Name'], d['Model'], 'MacBook', d['User']));
      });
      (DATA.ipadDevices || []).forEach(d => {
        const serial = d['Serial']; if (!serial) return;
        appleSerials.add(serial);
        appleRows.push(buildAppleRow(serial, d['Device Name'], d['Model'], 'iPad', d['User']));
      });
      (DATA.intuneDevices || []).filter(d => (d['OS'] || '').includes('iOS')).forEach(d => {
        const serial = d['Serial number']; if (!serial) return;
        appleSerials.add(serial);
        const user = d['Primary user display name'] || d['Primary user UPN'] || '—';
        const deviceType = (d['Model'] || '').toLowerCase().includes('ipad') ? 'iPad' : 'iPhone';
        appleRows.push(buildAppleRow(serial, d['Device name'] || serial, d['Model'], deviceType, user));
      });
    }
  } catch(e) {
    console.error('Failed to merge ABM warranty:', e);
  }

  // De-dupe: drop ManageEngine rows whose serial is already covered by an Apple row
  const meDeduped = meRows.filter(r => !appleSerials.has(r.service_tag));
  _warrantyData = meDeduped.concat(appleRows);

  // Update sidebar badge with expired + expiring count. When the ManageEngine
  // half failed the count is known-incomplete, so publish '—' rather than a
  // number: bnum()/val() in the inline dashboard both treat '—' as null, so the
  // Mission Control gauge falls through to its existing 'awaiting warranty data'
  // state and the WARRANTY alert stays silent, instead of reporting a falsely
  // reassuring figure computed from Apple devices alone.
  const flagged = _warrantyData.filter(c => c.label === 'Expired' || c.label === 'Expiring Soon').length;
  document.getElementById('badge-warranty').textContent =
    _warrantyMeFailed ? '—' : (flagged || _warrantyData.length);
}

async function buildWarrantyDashboard() {
  await loadWarrantyData();
  const expired  = _warrantyData.filter(c => c.label === 'Expired').length;
  const expiring = _warrantyData.filter(c => c.label === 'Expiring Soon').length;
  const active   = _warrantyData.filter(c => c.label === 'Active').length;
  const unknown  = _warrantyData.filter(c => c.label === 'Unknown').length;
  const total    = _warrantyData.length;

  // Absence-as-fact: a failed ManageEngine call leaves a fully-chromed page —
  // KPI cards, timeline, sorted table — that is missing the entire Windows
  // fleet. State what is missing rather than quietly showing half of it.
  const noticeEl = document.getElementById('warranty-data-notice');
  if (noticeEl) {
    noticeEl.innerHTML = _warrantyMeFailed
      ? `<div class="data-gap-notice">⚠ ManageEngine warranty data unavailable — showing Apple devices only (${total} of an unknown total). No figure on this page includes the Windows fleet.</div>`
      : '';
    if (_warrantyMeFailed) _degrade('warranty-me-feed', 'ManageEngine warranty data unavailable — showing Apple devices only', null);
  }

  // KPI cards
  document.getElementById('warranty-kpi-cards').innerHTML = `
    <div class="stat-card red animate" style="animation-delay:0ms"><div class="stat-icon">🔴</div>
      <div class="stat-label">Expired</div>
      <div class="stat-value" data-target="${expired}">0</div>
      <div class="stat-sub">Warranty has lapsed</div>
    </div>
    <div class="stat-card yellow animate" style="animation-delay:70ms"><div class="stat-icon">🟡</div>
      <div class="stat-label">Expiring Soon</div>
      <div class="stat-value" data-target="${expiring}">0</div>
      <div class="stat-sub">Within 90 days</div>
    </div>
    <div class="stat-card green animate" style="animation-delay:140ms"><div class="stat-icon">🟢</div>
      <div class="stat-label">Active</div>
      <div class="stat-value" data-target="${active}">0</div>
      <div class="stat-sub">Covered</div>
    </div>
    <div class="stat-card blue animate" style="animation-delay:210ms"><div class="stat-icon">🖥</div>
      <div class="stat-label">Total Tracked</div>
      <div class="stat-value" data-target="${total}">0</div>
      <div class="stat-sub">${unknown} with unknown warranty${_warrantyMeFailed ? ' · Windows fleet not included' : ''}</div>
    </div>
  `;
  animateCards('warranty-kpi-cards');

  // Timeline bar
  const pct = v => total ? Math.round(v/total*100) : 0;
  document.getElementById('warranty-timeline-bar').innerHTML = `
    <div class="timeline-seg" style="width:${pct(expired)}%;background:#f87171">${pct(expired)>5?pct(expired)+'%':''}</div>
    <div class="timeline-seg" style="width:${pct(expiring)}%;background:#fbbf24">${pct(expiring)>5?pct(expiring)+'%':''}</div>
    <div class="timeline-seg" style="width:${pct(active)}%;background:#34d399">${pct(active)>5?pct(active)+'%':''}</div>
    <div class="timeline-seg" style="width:${pct(unknown)}%;background:var(--surface3)">${pct(unknown)>5?pct(unknown)+'%':''}</div>
  `;
  document.getElementById('warranty-timeline-legend').innerHTML = [
    ['#f87171','Expired',expired],
    ['#fbbf24','Expiring Soon',expiring],
    ['#34d399','Active',active],
    ['var(--surface3)','Unknown',unknown]
  ].map(([c,l,v])=>`<div style="display:flex;align-items:center;gap:6px;font-size:11px">
    <div style="width:10px;height:10px;border-radius:50%;background:${c}"></div>
    <span style="color:var(--text2)">${l}</span>
    <span style="color:var(--text);font-family:var(--mono);font-weight:600">${v}</span>
  </div>`).join('');

  // Update sync status
  const wEl = document.getElementById('warranty-sync-status');
  try {
    const res = await fetch(`${WARRANTY_BASE}/api/warranty/status`);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const s = await res.json();
    if (wEl && s.last_synced) {
      wEl.textContent = 'Last synced: ' + new Date(s.last_synced).toLocaleString();
    }
  } catch(e) {
    if (wEl) wEl.textContent = 'Sync status unavailable — backend error';
    console.warn('warranty status failed:', e && e.message);
    _degrade('warranty-sync-status', 'Sync status unavailable — backend error', 'GET /api/warranty/status: ' + (e && e.message));
  }

  renderWarranty();
}

function renderWarranty() {
  // KIT2-20261017 (DR-19): the type options were hard-coded ("Laptop" matched
  // nothing) and covered 412 of 840 devices.
  _syncFilterOptions('warranty-filter-type', _warrantyData.map(r => ({t: String(r.device_type || '--')})), 't', 'All Device Types', v => v === '--' ? 'Not reported' : v);
  const statusFilter = document.getElementById('warranty-filter-status')?.value;
  const typeFilter   = document.getElementById('warranty-filter-type')?.value;

  let rows = [..._warrantyData];
  if (statusFilter === 'at-risk') rows = rows.filter(r => r.label === 'Expired' || r.label === 'Expiring Soon');
  else if (statusFilter) rows = rows.filter(r => r.label === statusFilter);
  if (typeFilter)   rows = rows.filter(r => String(r.device_type || '--') === typeFilter);
  if (searchQuery)  rows = rows.filter(r =>
    Object.values(r).some(v => v && String(v).toLowerCase().includes(searchQuery))
  );

  // Sort
  rows.sort((a, b) => {
    const av = a[_warrantySortCol], bv = b[_warrantySortCol];
    if (_warrantySortCol === 'days') {
      // `== null` catches undefined too — `=== null` let a missing field through
      // as undefined, and one NaN comparison scrambles the entire sort.
      const an = av == null ? 99999 : av;
      const bn = bv == null ? 99999 : bv;
      return (an - bn) * _warrantySortDir;
    }
    return cmpText(av||'', bv||'') * _warrantySortDir;
  });

  const total = rows.length;
  document.getElementById('warranty-count').textContent = `${total.toLocaleString()} devices`;

  if (!pages['warranty']) pages['warranty'] = 1;
  const p = pages['warranty'];
  const paged = rows.slice((p-1)*PAGE_SIZE, p*PAGE_SIZE);

  document.getElementById('warranty-tbody').innerHTML = paged.map(r => {
    const expiryStr = r.warranty_expiry_date || '—';
    const daysStr   = r.days !== null
      ? (r.days < 0 ? `${Math.abs(r.days)}d ago` : `${r.days}d`)
      : '—';
    const daysColor = r.days === null ? '' : r.days < 0 ? 'color:var(--red)' : r.days <= 90 ? 'color:var(--yellow)' : 'color:var(--green)';
    return `<tr>
      <td class="cell-name">${esc(r.computer_name||'—')}</td>
      <td class="cell-mono" style="font-size:11px">${esc(r.service_tag||'—')}</td>
      <td>${esc(r.device_model||'—')}</td>
      <td>${esc(r.device_manufacturer||'—')}</td>
      <td>${esc(r.device_type||'—')}</td>
      <td>${esc(r.logged_on_user||'—')}</td>
      <td class="cell-mono" style="font-size:11px">${esc(expiryStr)}</td>
      <td class="cell-mono" style="${daysColor};font-weight:600">${esc(daysStr)}</td>
      <td>${warrantyBadge(r.warranty_expiry_date)}</td>
    </tr>`;
  }).join('') || '<tr><td colspan="10" style="text-align:center;padding:40px;color:var(--text3)">No devices found</td></tr>';

  renderPagination('warranty-pagination','warranty-page-info', total, 'warranty');
}

function sortWarranty(col) {
  if (_warrantySortCol === col) _warrantySortDir *= -1;
  else { _warrantySortCol = col; _warrantySortDir = 1; }
  // Apply sort indicators (visual class + aria-sort) on the warranty table.
  const page = document.getElementById('page-warranty');
  if (page) {
    page.querySelectorAll('th[onclick]').forEach(th => {
      th.classList.remove('sort-asc','sort-desc');
      if (th.hasAttribute('aria-sort')) th.setAttribute('aria-sort', 'none');
    });
    page.querySelectorAll('th[onclick]').forEach(th => {
      const onclick = th.getAttribute('onclick') || '';
      if (onclick.includes(`'${col}'`)) {
        const dir = _warrantySortDir === 1 ? 'asc' : 'desc';
        th.classList.add('sort-' + dir);
        th.setAttribute('aria-sort', dir === 'asc' ? 'ascending' : 'descending');
      }
    });
  }
  renderWarranty();
}

async function triggerWarrantySync() {
  const btn = document.getElementById('sync-btn');
  const spinner = document.getElementById('sync-spinner');
  btn.disabled = true;
  btn.textContent = 'Syncing…';
  spinner.classList.add('active');
  document.getElementById('warranty-sync-status').textContent = 'Syncing with Endpoint Central…';
  document.getElementById('warranty-sync-sub').textContent = ' This walks every ManageEngine computer and can take several minutes';
  try {
    // The route answers 202 at once and runs the walk in the background (the old
    // synchronous handler outlived nginx's proxy timeout, so the browser saw a 504
    // while the sync kept running). Poll /sync/status until it settles.
    const res  = await fetch(`${WARRANTY_BASE}/api/warranty/sync`, { method:'POST' });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const started = await res.json();
    if (started.alreadyRunning) showToast('A warranty sync is already running — waiting for it to finish', 'warn');
    let data = null;
    for (let i = 0; i < 120; i++) {
      await new Promise(r => setTimeout(r, 5000));
      const sr = await fetch(`${WARRANTY_BASE}/api/warranty/sync/status`);
      if (!sr.ok) throw new Error('status HTTP ' + sr.status);
      const st = await sr.json();
      if (st.state === 'done')   { data = Object.assign({ success: true }, st.result || {}); break; }
      if (st.state === 'failed') { data = { success: false, error: st.error || 'sync failed' }; break; }
      if (st.state === 'idle')   throw new Error('the sync state was lost (API restarted?) — run it again');
      document.getElementById('warranty-sync-status').textContent = 'Syncing with Endpoint Central… (' + ((i + 1) * 5) + 's)';
    }
    if (!data) throw new Error('still running after 10 minutes — it continues on the server; reload later');
    if (data.success) {
      showToast(`✓ Synced ${data.synced} devices (${data.errors} errors)`);
      await loadWarrantyMap(); // refresh map so lifecycle page is up to date
      await buildWarrantyDashboard();
    } else {
      showToast('Sync failed: ' + (data.error||'Unknown error'), 'err');
    }
  } catch(e) {
    showToast('Sync error: ' + e.message, 'err');
  } finally {
    btn.disabled = false;
    btn.textContent = '⟳ Sync Now';
    spinner.classList.remove('active');
    document.getElementById('warranty-sync-sub').textContent = ' · Click "Sync Now" to refresh from Endpoint Central';
  }
}

function exportWarrantyCSV() {
  if (!_warrantyData.length) { showToast('No data to export', 'warn'); return; }
  const headers = ['Computer Name','Service Tag','Model','Manufacturer','Type','Last User','Warranty Expiry','Days Remaining','Status'];
  const out = [headers.map(_csvEscape)];
  _warrantyData.forEach(r => {
    out.push([
      r.computer_name || '',
      r.service_tag || '',
      r.device_model || '',
      r.device_manufacturer || '',
      r.device_type || '',
      r.logged_on_user || '',
      r.warranty_expiry_date || '',
      r.days !== null ? r.days : '',
      r.label || '',
    ].map(_csvEscape));
  });
  _downloadBlob(_toCsvBlob(out), `warranty_report_${new Date().toISOString().split('T')[0]}.csv`);
  showToast(`Exported ${_warrantyData.length} devices`);
}

// One refresh path for the endpoints table. loadPatchHealthCache annotates the
// DATA.endpoints row objects in place and then latches _patchHealthCacheLoaded,
// so a sync that replaces the array leaves 'Patch Health' unset on every row:
// the Patch Health filter returns nothing while the Patch Health column beside
// it still shows green badges (patchHealthBadge reads the cache by resource_id
// directly and is unaffected). Both sync branches call this so the
// invalidate-then-reapply sequence cannot drift between two copies.
async function refreshEndpoints() {
  DATA.endpoints = await apiGet('endpoints');
  bumpDataVersion();
  document.getElementById('badge-ep').textContent = DATA.endpoints.filter(isWindowsEndpoint).length;
  _patchHealthCacheLoaded  = false;
  _patchHealthCacheErrorAt = 0; // explicit user action — do not sit out the 30s backoff
  await loadPatchHealthCache();
  await loadIntuneGraphMap();
  renderEndpoints();
}

async function triggerEndpointsSync() {
  const btn     = document.getElementById('ep-sync-btn');
  const spinner = document.getElementById('ep-sync-spinner');
  btn.disabled  = true;
  btn.textContent = 'Syncing…';
  spinner.classList.add('active');
  document.getElementById('ep-sync-status').textContent = 'Syncing with Endpoint Central…';
  document.getElementById('ep-sync-sub').textContent    = ' This takes about 2 minutes';
  try {
    const res  = await fetch(`${WARRANTY_BASE}/api/endpoints-sync/sync`, { method:'POST' });
    const data = await res.json().catch(() => ({}));
    // Backend is async: returns {started:true} (202) or {alreadyRunning:true}.
    if (data.started || data.alreadyRunning) {
      showToast(data.alreadyRunning
        ? 'A sync is already running — refreshing…'
        : '✓ Sync started (runs in background, ~5 min)');
      let _n = 0;
      const _t = setInterval(async () => {
        // An async setInterval callback catches nothing: apiGet throws on
        // !res.ok, so the poll died as an unhandled rejection. The user had been
        // told '✓ Sync started', waited two minutes, and the table then never
        // refreshed and never said why. Stop the poll and say so instead.
        try {
          await loadEndpointsSyncStatus();
          if (++_n >= 6) {
            clearInterval(_t);
            // MERGED 2026-09-03: two independent fixes landed on this block — the
            // try/catch around the poll (an async setInterval callback catches
            // nothing) and the switch to refreshEndpoints(). Both are needed: the
            // catch stops a silent death, and refreshEndpoints() is the single
            // refresh path that also invalidates the patch-health cache. Reloading
            // inline here instead would leave 'Patch Health' unset on every row, so
            // the Patch Health FILTER returns nothing while the Patch Health COLUMN
            // still shows green badges beside it.
            await refreshEndpoints();
          }
        } catch(e) {
          clearInterval(_t);
          if (window.__invErr) window.__invErr('endpoints sync poll', e);
          showToast('Sync finished but the endpoint list could not be reloaded — refresh the page', 'err');
        }
      }, 20000);
    } else if (data.success) {
      showToast(`✓ Synced ${data.synced} endpoints (${data.skipped} skipped, ${data.errors} errors)`);
      await loadEndpointsSyncStatus();
      await refreshEndpoints();
    } else {
      showToast('Sync failed: ' + (data.error || `HTTP ${res.status}`), 'err');
    }
  } catch(e) {
    showToast('Sync error: ' + e.message, 'err');
  } finally {
    btn.disabled    = false;
    btn.textContent = '⟳ Sync from ME';
    spinner.classList.remove('active');
  }
}

async function loadEndpointsSyncStatus() {
  const el = document.getElementById('ep-sync-status');
  const sub = document.getElementById('ep-sync-sub');
  try {
    // res.ok first: a 401 or a 502 returns nginx HTML, .json() throws a
    // SyntaxError, and the old empty catch ate it — leaving this line frozen on
    // whatever triggerEndpointsSync last wrote ('Syncing with Endpoint
    // Central…'), so a dead sync backend looked exactly like a healthy one.
    const res = await fetch(`${WARRANTY_BASE}/api/endpoints-sync/status`);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const s = await res.json();
    if (s.last_synced) window._diFeedAsOf.endpoints = s.last_synced;
    if (el && s.last_synced) {
      // KIT2-20261017 (DR-12): s.total is every ManageEngine device (Macs,
      // servers and WorkSpaces too); this page lists Windows PCs only.
      const _winN = (DATA.endpoints || []).filter(isWindowsEndpoint).length;
      el.textContent  = `Last synced: ${new Date(s.last_synced).toLocaleString()} · ${s.total} devices in ManageEngine` + (_winN ? ` · ${_winN.toLocaleString()} Windows PCs listed here` : '');
      if (sub) sub.textContent = ' · Click "Sync from ME" to refresh now (~5 min)' + _diFeedAgeNote('endpoints');
    }
  } catch(e) {
    // Same wording as loadKandjiSyncStatus/loadIntuneSyncStatus: could-not-measure
    // must not render as measured-and-fine.
    if (el) el.textContent = 'Sync status unavailable — backend error';
    console.warn('loadEndpointsSyncStatus failed:', e && e.message);
    _degrade('endpoints-sync-status', 'Sync status unavailable — backend error', 'GET /api/endpoints-sync/status: ' + (e && e.message));
  }
}

// ============================================================
// COLUMN PICKER
// ============================================================
function toggleColPicker(id) {
  const el = document.getElementById(id);
  if (!el) return;
  // Close all other open pickers first
  document.querySelectorAll('.col-picker-dropdown.open').forEach(d => {
    if (d.id !== id) d.classList.remove('open');
  });
  el.classList.toggle('open');
}

function toggleCol(tableId, colId, visible) {
  const table = document.getElementById(tableId);
  if (!table) return;
  // Find index of th with data-col matching colId
  const ths = Array.from(table.querySelectorAll('thead th'));
  const idx = ths.findIndex(th => th.dataset.col === colId);
  if (idx === -1) return;
  // Show/hide all cells at that column index
  table.querySelectorAll(`tr`).forEach(row => {
    const cell = row.children[idx];
    if (cell) cell.style.display = visible ? '' : 'none';
  });
}

// Close col picker when clicking outside
document.addEventListener('click', e => {
  if (!e.target.closest('.col-picker-wrap')) {
    document.querySelectorAll('.col-picker-dropdown.open')
      .forEach(d => d.classList.remove('open'));
  }
});

// ============================================================
// THEME TOGGLE — REMOVED
// ============================================================
// `toggleTheme()`, the load-time theme restore IIFE, and the inline
// `document.body.classList.remove('light')` shim in HTML have all been
// removed together. The Light Mode button was a placebo (the runtime
// stripped the class on every load), and three layers fighting over the
// `light` class produced visible flicker. Dark mode is the only mode.
// To reintroduce light mode, restore: (1) the `body.light` rules kept in
// IT_Inventory_App.css — WARNING: that file is NOT linked by this page and is
// a generation behind it (--accent is #4f8ef7 there vs #22D3EE live). The real
// stylesheet is the inline <style> block in IT_Inventory_App.html; treat the
// .css file as an archived token reference only, and never as the place to fix
// a colour — (2) this toggleTheme function, (3) the toggle button in the
// sidebar footer, and (4) any hardcoded color branches (e.g. exportExecPDF)
// that previously read body.classList.

// ============================================================
// BOOT
// ============================================================
// init() is async and was called bare: any throw at or after bootstrap()
// rejected a promise nobody held. The user was left on the static HTML skeleton
// — badges frozen at their markup values, dashboard cards blank — which reads
// as a slow page rather than a dead one, so no ticket was ever filed.
init().catch(e => {
  if (window.__invErr) window.__invErr('init', e);
  // Overwrites __invErr's generic toast on purpose: at boot the sentence that
  // matters is 'it did not start', not the exception text (which is on the bar).
  showToast('Console failed to start — this page is showing incomplete data', 'err');
});

// ============================================================
// CARRIER BADGE
// ============================================================
function carrierBadge(carrier) {
  if (!carrier) return '';
  if (carrier === 'NCF') return '<span style="background:#b08800;color:#fff;font-size:9px;font-weight:700;padding:2px 5px;border-radius:3px;margin-left:4px">NCF</span>';
  if (carrier === 'VZW' || carrier === 'Verizon') return '<span style="background:#cd040b;color:#fff;font-size:9px;font-weight:700;padding:2px 5px;border-radius:3px;margin-left:4px">VZW</span>';
  if (carrier === 'T-Mo' || carrier === 'T-Mobile') return '<span style="background:#e20074;color:#fff;font-size:9px;font-weight:700;padding:2px 5px;border-radius:3px;margin-left:4px">T-Mo</span>';
  return '<span style="background:var(--surface3);color:var(--text2);font-size:9px;font-weight:600;padding:2px 5px;border-radius:3px;margin-left:4px">' + carrier + '</span>';
}

// ============================================================
// TABLETS
// ============================================================
let _tabletIntuneMap = null;
let _tabletIntuneMapVersion = -1;
function buildTabletIntuneMap() {
  // Same story as buildVerizonIntuneMap: a full Intune pass per renderTablets().
  if (_tabletIntuneMap && _tabletIntuneMapVersion === DATA_VERSION) return _tabletIntuneMap;
  const map = {};
  (DATA.intuneDevices||[]).forEach(d => {
    if (d['Serial number']) map[d['Serial number'].toLowerCase().trim()] = d['Compliance']||'unknown';
    if (d['IMEI']) map[String(d['IMEI']).toLowerCase().trim()] = d['Compliance']||'unknown';
  });
  _tabletIntuneMap = map;
  _tabletIntuneMapVersion = DATA_VERSION;
  return map;
}

function renderTablets() {
  let rows = [...(DATA.tablets||[])];
  _syncFilterOptions('tablet-filter-compliance', rows, 'Compliance', 'All Compliance', _complianceLabel);
  const comp = document.getElementById('tablet-filter-compliance')?.value;
  const tabletIntuneFilter = document.getElementById('tablet-filter-intune')?.value;
  const tabletIntuneMap = buildTabletIntuneMap();
  if (comp) rows = rows.filter(r => (r['Compliance']||'').toLowerCase() === comp.toLowerCase());
  if (tabletIntuneFilter) {
    rows = rows.filter(r => {
      const imei = String(r['IMEI']||'').toLowerCase().trim();
      const serial = String(r['Serial number']||'').toLowerCase().trim();
      const found = tabletIntuneMap[serial] !== undefined || tabletIntuneMap[imei] !== undefined;
      return tabletIntuneFilter === 'enrolled' ? found : !found;
    });
  }
  rows = filterBySearch(rows);
  rows = applySorting(rows,'tablets');
  const total = rows.length;
  document.getElementById('tablet-count').textContent = total.toLocaleString() + ' tablets';
  const page = paginate(rows,'tablets');
  function tabletIntuneBadge(r) {
    const imei = String(r['IMEI']||'').toLowerCase().trim();
    const serial = String(r['Serial number']||'').toLowerCase().trim();
    const comp = tabletIntuneMap[serial] || tabletIntuneMap[imei] || null;
    return intuneBadgeHTML(comp !== null, comp);
  }
  document.getElementById('tablets-tbody').innerHTML = page.map(r =>
    '<tr data-emp-user="'+esc(r['Primary user UPN'])+'">' +
    cellMono(r['Device name']) +
    cellName(_kit2TabletUser(r)) +  // KIT2-20261017 (DR-19)
    cell(r['Model']) +
    cellMono(r['OS version']) +
    cellMono(r['Serial number']) +
    cellMono(r['IMEI']||'—') +
    '<td title="'+esc(r['Last check-in']||'')+'">'+esc(_kit2FmtIso(r['Last check-in']))+'</td>' +
    '<td>' + carrierBadge(r['Carrier']) + '</td>' +
    tabletIntuneBadge(r) +
    '</tr>'
  ).join('') || '<tr><td colspan="10" style="text-align:center;padding:40px;color:var(--text3)">No tablets found</td></tr>';
  renderPagination('tablet-pagination','tablet-page-info', total, 'tablets');
}
