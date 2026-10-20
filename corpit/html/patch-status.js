/* Intune health (was Patch status) — DEV. Read only, except the update-ring editor.
   Sources: GET /hub-api/api/patch-status/snapshot (Intune + Entra via the hub's Graph
   app, cached five minutes on the server) and, when a device is opened,
   GET /hub-api/api/patch-status/device/<id> (hardware, Defender, discovered apps,
   compliance policy results, assigned apps) and, when an app is opened,
   GET /hub-api/api/patch-status/app/<id> (devices where it did not install).
   The page asks /api/rbac/me first and loads nothing until the answer allows it;
   the API enforces the same rule.
   Every count on the page comes from derive() and issuesOf(); there is no second
   path that sums differently. Two writes, both super-admins only, re-checked and audited
   by the hub: the ring editor (GET /rings/<id>, POST /rings/<id>/save) and the Repair
   run (GET /repair, POST /repair/run: the ManageEngine repair script on up to five PCs).
   Every other action is a link that opens the record in the admin portal. */
(function () {
  'use strict';
  var D = document;
  var API = '/hub-api/api/patch-status/snapshot';   // hub via the /hub-api/ relay; the dev vhost sends bare /api/* to :3000
  var DEV_API = '/hub-api/api/patch-status/device/';
  var APP_API = '/hub-api/api/patch-status/app/';
  var GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  var DAY = 864e5, STALE_MS = 7 * DAY, AUTO_MS = 5 * 60 * 1000, TIMEOUT_MS = 40000;
  // The snapshot can wait on a whole Intune read (first read after a hub restart, Refresh, a ring
  // save); that has taken over 40 s while Intune throttles. Kept under nginx's 180 s on /hub-api/.
  var SNAP_TIMEOUT_MS = 170000, SLOW_MS = 15000, RECHECK_MS = 20000, RECHECKS = 9;
  var LABEL = { current: 'Current', pending: 'Pending', stale: 'Not checking in', unknown: 'Unrecognised build' };
  var ORDER = { stale: 0, pending: 1, unknown: 2, current: 3 };
  var VIEWS = { overview: 'Intune health', devices: 'Devices', updates: 'Windows updates', security: 'Compliance & security',
    enrollment: 'Enrollment & Autopilot', apps: 'Apps', housekeeping: 'Housekeeping', repair: 'Repair', sources: 'Sources & limits', migration: 'GPO migration' };
  var SUBS = {
    overview: 'What needs a technician today, across every device Intune manages.',
    devices: 'Every device in Intune. Click a name for its full record, Defender state and apps.',
    updates: 'Windows build level against the approved cumulative update, and the Intune update rings as configured.',
    security: 'Compliance policies and the settings devices fail, encryption, Defender and storage, as each device last reported them.',
    enrollment: 'How devices arrive in Intune: Autopilot registrations and profiles, enrollment settings, and machines that should be enrolled but are not.',
    apps: 'Install results for every app Intune deploys. Open an app for the devices where it did not install.',
    housekeeping: 'Records to clean up. Nothing here deletes anything; each row opens the record where the action is taken.',
    repair: 'Windows PCs that AD, ManageEngine or Entra know and Intune does not: why each is missing, and the repair that can reach it.',
    migration: 'Shared GPO plans, linked Intune profiles and pilot readiness. Policy changes stay in their administrative tools.',
    sources: 'What each reading is, where it comes from, and which Graph permissions the hub holds.'
  };
  // Admin-portal links. Formats taken from the portals' own URLs; see Sources > Portal links.
  var PORTAL = {
    device: function (id) { return 'https://intune.microsoft.com/#view/Microsoft_Intune_Devices/DeviceSettingsMenuBlade/~/overview/mdmDeviceId/' + encodeURIComponent(id); },
    entra: function (oid, did) { return 'https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DeviceDetailsMenuBlade/~/Properties/objectId/' + encodeURIComponent(oid) + '/deviceId/' + encodeURIComponent(did || ''); },
    winEnroll: 'https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesEnrollmentMenu/~/windowsEnrollment',
    allDevices: 'https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/allDevices',
    entraDevices: 'https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/Overview/menuId/Overview'
  };
  var ISSUE = {
    malware: { label: 'Active malware', tone: 'bad' },
    noncompliant: { label: 'Not compliant', tone: 'bad' },
    grace: { label: 'In grace period', tone: 'warn' },
    unencrypted: { label: 'Not encrypted', tone: 'bad' },
    behind: { label: 'Behind baseline', tone: 'warn' },
    unknownbuild: { label: 'Unrecognised build', tone: 'warn' },
    quiet: { label: 'No check-in 7+ d', tone: 'warn' },
    lowdisk: { label: 'Disk under 10% free', tone: 'warn' },
    dupe: { label: 'Older duplicate', tone: 'warn' },
    departed: { label: 'User has left', tone: 'warn' },
    nouser: { label: 'No primary user', tone: 'info' },
    mismatch: { label: 'Used by someone else', tone: 'info' }
  };
  var ACCT = { active: 'Active', disabled: 'Disabled in Entra', missing: 'Not in the directory' };
  var COMPLIANCE = { compliant: 'Compliant', noncompliant: 'Not compliant', inGracePeriod: 'In grace period', unknown: 'Unknown', conflict: 'Conflict', error: 'Error', configManager: 'Reported by ConfigMgr' };
  var TRUST = { AzureAd: 'Entra joined', ServerAd: 'Hybrid joined', Workplace: 'Registered', '': 'Not stated' };
  var ENROLL = { windowsCoManagement: 'Co-management', windowsAzureADJoin: 'Entra join', windowsAutoEnrollment: 'Automatic enrollment',
    windowsBulkAzureDomainJoin: 'Bulk Entra join (provisioning package)', windowsAzureADJoinUsingDeviceAuth: 'Entra join (device auth)',
    windowsBulkUserless: 'Bulk, no user', userEnrollment: 'User enrollment', deviceEnrollmentManager: 'Device enrollment manager',
    appleBulkWithUser: 'Apple automated enrollment (with user)', appleBulkWithoutUser: 'Apple automated enrollment (no user)',
    appleUserEnrollment: 'Apple user enrollment', appleUserEnrollmentWithServiceAccount: 'Apple account-driven enrollment',
    androidEnterpriseFullyManaged: 'Android fully managed', androidEnterpriseDedicatedDevice: 'Android dedicated',
    androidEnterpriseCorporateWorkProfile: 'Android corporate work profile', unknown: 'Unknown' };
  // Per-device results on an update ring (Graph complianceStatus). "Succeeded" is the portal's word for compliant.
  var RING_STATUS = { compliant: 'Succeeded', remediated: 'Remediated', nonCompliant: 'Not compliant', error: 'Error', conflict: 'Conflict',
    unknown: 'Unknown', notApplicable: 'Not applicable', notAssigned: 'Not assigned' };
  var POL_TYPE = { windows10CompliancePolicy: 'Windows', androidWorkProfileCompliancePolicy: 'Android personal work profile',
    androidDeviceOwnerCompliancePolicy: 'Android Enterprise (corporate)', androidCompliancePolicy: 'Android device administrator',
    aospDeviceOwnerCompliancePolicy: 'Android (AOSP)', iosCompliancePolicy: 'iOS/iPadOS', macOSCompliancePolicy: 'macOS' };
  var AP_STATE = { enrolled: 'Enrolled', notContacted: 'Not contacted', failed: 'Failed', pendingReset: 'Pending reset', blocked: 'Blocked', unknown: 'Unknown' };
  var AP_PROFILE = { assignedUnkownSyncState: 'Assigned, sync state unknown', assignedInSync: 'Assigned', assignedOutOfSync: 'Assigned, out of sync',
    notAssigned: 'Not assigned', pending: 'Assignment pending', failed: 'Assignment failed', unknown: 'Unknown' };
  var AP_TYPE = { azureADWindowsAutopilotDeploymentProfile: 'Entra join', activeDirectoryWindowsAutopilotDeploymentProfile: 'Hybrid join' };
  var EC_KIND = { deviceEnrollmentLimitConfiguration: 'Device limit', deviceEnrollmentPlatformRestrictionsConfiguration: 'Platform restrictions',
    deviceEnrollmentPlatformRestrictionConfiguration: 'Platform restriction', windows10EnrollmentCompletionPageConfiguration: 'Enrollment Status Page',
    deviceEnrollmentWindowsHelloForBusinessConfiguration: 'Windows Hello for Business', deviceComanagementAuthorityConfiguration: 'Co-management authority',
    windowsRestoreDeviceEnrollmentConfiguration: 'Windows restore' };
  var INTENT = { requiredInstall: 'Required', available: 'Available', requiredUninstall: 'Uninstall', requiredAndAvailableInstall: 'Required and available',
    availableInstallWithoutEnrollment: 'Available without enrollment', notAvailable: 'Not available', exclude: 'Excluded' };
  var INSTALL = { installed: 'Installed', failed: 'Failed', notInstalled: 'Not installed', uninstallFailed: 'Uninstall failed', pendingInstall: 'Install pending',
    unknown: 'Unknown', notApplicable: 'Not applicable' };
  var JOIN = { hybridAzureADJoined: 'Hybrid joined', azureADJoined: 'Entra joined', azureADRegistered: 'Registered', unknown: 'Unknown', '': 'Not stated' };
  // Tested with spaces and punctuation removed: GMKtec boards report "Defaultstring".
  var BAD_SERIAL = /^(0+|defaultstring|tobefilled.*|systemserialnumber|none|na|unknown|chassisserialnumber|notspecified|notapplicable|invalid|oem)$/i;
  function badSerial(s) { return BAD_SERIAL.test(String(s || '').replace(/[\s._\/-]+/g, '')); }

  var snap = null, skew = 0, view = 'overview', reading = false, lastErr = null, timer = null, der = null;
  var filt = { platform: 'all', issue: 'all', ring: 'all', patch: 'all', pol: 'all', q: '' };
  var hk = { intuneAge: 30, entraAge: 90, entraTrust: 'all', entraState: 'all', entraShow: 200, actGone: false };
  var detailCache = {}, appCache = {};
  var apv = { app: null, all: false, q: '' };   // Apps view: open app, show every app or only failing ones, search

  /* ── helpers ─────────────────────────────────────────────────────────── */
  function $(id) { return D.getElementById(id); }
  function h(tag, attrs, kids) {
    var el = D.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (v == null || v === false) return;
      if (k === 'text') el.textContent = v;
      else if (k === 'class') el.className = v;
      else if (k === 'on') Object.keys(v).forEach(function (e) { el.addEventListener(e, v[e]); });
      else if (k === 'style') Object.keys(v).forEach(function (s) { el.style[s] = v[s]; });
      else el.setAttribute(k, v === true ? '' : v);
    });
    (kids || []).forEach(function (c) { if (c != null) el.appendChild(typeof c === 'string' ? D.createTextNode(c) : c); });
    return el;
  }
  function svg(tag, attrs) {
    var el = D.createElementNS('http://www.w3.org/2000/svg', tag);
    Object.keys(attrs || {}).forEach(function (k) { el.setAttribute(k, attrs[k]); });
    return el;
  }
  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }
  function now() { return Date.now() - skew; }   // server clock
  function n(x) { return Number(x).toLocaleString(); }
  function nn(c, one, many) { return n(c) + ' ' + (c === 1 ? one : many); }
  function pct(a, b) { return b ? Math.round(a / b * 100) : null; }
  function ago(t) {
    if (t == null) return 'Never reported';
    var d = now() - t;
    if (d < 6e4) return 'Just now';
    if (d < 36e5) return Math.floor(d / 6e4) + ' min ago';
    if (d < DAY) return Math.floor(d / 36e5) + ' h ago';
    return Math.floor(d / DAY) + ' d ago';
  }
  function ageDays(t) { return t == null ? Infinity : Math.floor((now() - t) / DAY); }
  function stamp(t) { return t == null ? 'Not reported' : new Date(t).toLocaleString(); }
  function day(t) { return t == null ? '—' : new Date(t).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' }); }
  function gb(b) { return b ? (b / 1073741824).toFixed(b < 10737418240 ? 1 : 0) + ' GB' : '—'; }
  function shortBuild(os) { var p = String(os || '').split('.'); return p.length === 4 ? p[2] + '.' + p[3] : (os || 'Not reported'); }
  function human(s) { s = String(s || ''); if (!s) return '—'; s = s.replace(/([a-z0-9])([A-Z])/g, '$1 $2'); return s.charAt(0).toUpperCase() + s.slice(1).toLowerCase(); }
  function label(map, k) { return Object.prototype.hasOwnProperty.call(map, k) ? map[k] : human(k); }

  /* ── the one classification ──────────────────────────────────────────── */
  function isWin(d) { return d.platform === 'Windows'; }
  function classify(d) {   // Windows patch status only
    var B = snap.baseline;
    if (d.base == null || d.rev == null || B.builds.indexOf(d.base) === -1) return 'unknown';
    if (d.rev >= B.revision) return 'current';
    if (d.lastSync == null || now() - d.lastSync > STALE_MS) return 'stale';
    return 'pending';
  }
  function devices() { return snap && snap.devicesOk ? snap.devices : []; }
  function wins() { return devices().filter(isWin); }
  function tally(list) {
    var t = { total: list.length, current: 0, pending: 0, stale: 0, unknown: 0 };
    list.forEach(function (d) { t[classify(d)]++; });
    return t;
  }
  function issuesOf(d) {
    var out = [], g = derive();
    if (d.malware > 0) out.push('malware');
    if (d.compliance === 'noncompliant') out.push('noncompliant');
    if (d.compliance === 'inGracePeriod' || (d.graceUntil && d.graceUntil > now())) out.push('grace');
    if (isWin(d) && d.encrypted === false) out.push('unencrypted');
    if (isWin(d)) { var st = classify(d); if (st === 'pending' || st === 'stale') out.push('behind'); else if (st === 'unknown') out.push('unknownbuild'); }
    if (d.lastSync == null || now() - d.lastSync > STALE_MS) out.push('quiet');
    if (d.totalB > 0 && d.freeB > 0 && d.freeB / d.totalB < 0.10) out.push('lowdisk');   // free 0 = not reported (every Android device)
    if (g.dupOld[d.id]) out.push('dupe');
    if (d.userState === 'disabled' || d.userState === 'missing') out.push('departed');
    if (!d.user) out.push('nouser');
    if (mismatch(d)) out.push('mismatch');
    return out;
  }
  // Windows only (phones report no sign-ins). Intune records who is signed in when the device checks in, so this is
  // "someone else was signed in at a check-in within 30 days and the primary user was not", not a sign-in log.
  function mismatch(d) {
    return isWin(d) && !!d.userId && !!d.lastLogonUserId && d.lastLogonUserId !== d.userId && ageDays(d.lastLogon) <= 30 &&
      (d.primaryLogon == null || ageDays(d.primaryLogon) > 30);   // a shared PC the primary user still uses is not handed on
  }
  function srcState(k) { return snap.sources[k] ? snap.sources[k].state : null; }
  function usersOk() { return !!(snap.sources.users && snap.sources.users.state === 'ok'); }
  // Why the Entra cross-checks are off. An Intune failure must not read as an Entra one.
  function crossWhy() {
    if (srcState('intune') === 'partial') return 'The Intune device list is incomplete, so this cross-check is off';
    if (!snap.devicesOk || srcState('intune') !== 'ok') return 'Intune devices could not be read, so this cross-check is off';
    return 'Entra devices could not be read';
  }
  // Everything computed across the snapshot, once per snapshot.
  function derive() {
    if (der && der.snap === snap) return der;
    var g = { snap: snap, dupOld: {}, dupGroups: [], entra: [], entraById: {}, inIntune: {}, actionsBy: {}, analyticsBy: {}, byUser: {}, byId: {},
      bySerial: {}, apBySerial: {}, apByIntune: {}, polById: {},
      entraOk: !!snap.entra && !!snap.devicesOk && srcState('intune') === 'ok' && srcState('entra') === 'ok' };
    der = g;
    var bySerial = {};
    devices().forEach(function (d) {
      g.byId[d.id] = d;
      if (d.aad) g.inIntune[d.aad] = d;
      if (d.userId) (g.byUser[d.userId] = g.byUser[d.userId] || []).push(d);
      var s = String(d.serial || '').trim();
      if (s.length < 4 || badSerial(s)) return;
      (bySerial[s.toUpperCase()] = bySerial[s.toUpperCase()] || []).push(d);
    });
    g.bySerial = bySerial;
    (snap.apDevices || []).forEach(function (a) {
      if (a.intuneId) g.apByIntune[a.intuneId] = a;
      var s = String(a.serial || '').trim().toUpperCase();
      if (s.length >= 4 && !badSerial(s)) g.apBySerial[s] = a;
    });
    (snap.policies || []).forEach(function (p) { g.polById[p.id] = p; });
    Object.keys(bySerial).forEach(function (k) {
      var grp = bySerial[k];
      if (grp.length < 2) return;
      grp.sort(function (a, b) { return (b.lastSync || 0) - (a.lastSync || 0); });
      grp.slice(1).forEach(function (d) { g.dupOld[d.id] = true; });
      g.dupGroups.push({ serial: grp[0].serial, list: grp });
    });
    g.dupGroups.sort(function (a, b) { return (a.list[0].name || '').localeCompare(b.list[0].name || ''); });
    if (snap.entra) {
      var c = snap.entraCols;
      g.entra = snap.entra.map(function (r) { var o = {}; c.forEach(function (k, i) { o[k] = r[i]; }); o.intune = o.deviceId ? g.inIntune[o.deviceId] || null : null; return o; });
      g.entra.forEach(function (e) { if (e.deviceId) g.entraById[e.deviceId] = e; });
    }
    (snap.actions || []).forEach(function (a) { if (a.deviceId) (g.actionsBy[a.deviceId] = g.actionsBy[a.deviceId] || []).push(a); });
    Object.keys(g.actionsBy).forEach(function (k) { g.actionsBy[k].sort(function (a, b) { return (b.at || 0) - (a.at || 0); }); });
    (snap.analytics || []).forEach(function (x) { g.analyticsBy[x.id] = x; });
    return g;
  }
  // Update rings are read live. Membership is worked out by the hub; when any ring has a target it cannot
  // evaluate, every Windows device's ring is null (unknown), never "not in a ring".
  function ringById(id) { return (snap.rings || []).filter(function (r) { return r.id === id; })[0] || null; }
  function ringsKnown() { return snap.ringsKnown === true; }
  function ringsWhy() {
    if (srcState('rings') !== 'ok') return 'Update rings could not be read.';
    var r = (snap.rings || []).filter(function (x) { return x.scopeWhy; })[0];
    return r ? r.name + ': ' + r.scopeWhy : 'Ring membership could not be worked out.';
  }
  function ringName(d, full) {
    if (!isWin(d)) return '';
    if (d.ring == null) return 'Unknown';
    if (d.ring === 'none') return 'Not in a ring';
    if (d.ring === 'multi') return 'More than one ring' + (full ? ': ' + (d.rings || []).map(function (id) { var r = ringById(id); return r ? r.name : 'a ring not in the list'; }).join(', ') : '');
    var r = ringById(d.ring); return r ? r.name : 'Unknown';
  }
  function ringDevices(r) { return wins().filter(function (d) { return (d.rings || []).indexOf(r.id) !== -1; }); }
  function ringResult(d, id) { var x = (d.ringResults || []).filter(function (y) { return y[0] === id; })[0]; return x ? { status: x[1], at: x[2] } : null; }
  // Baseline due dates for a ring; null when Intune states no deferral or deadline.
  function ringDeadline(r) {
    if (r.deferralDays == null || r.deadlineDays == null) return null;
    var rel = Date.parse(snap.baseline.released + 'T00:00:00');
    return { install: rel + (r.deferralDays + r.deadlineDays) * DAY, restart: rel + (r.deferralDays + r.deadlineDays + (r.graceDays || 0)) * DAY };
  }
  function groupName(id) { var g = snap.groups || {}; return g[id] || 'Group ' + String(id).slice(0, 8) + '… (name not read)'; }
  function targetsText(T) {
    if (T == null) return 'Not read';
    if (!T.length) return 'Not assigned';
    return T.map(function (t) {
      var who = t.kind === 'allDevices' ? 'All devices' : t.kind === 'allUsers' ? 'All users' : t.groupId ? groupName(t.groupId) : 'Another target type';
      return (t.kind === 'exclude' ? 'Excluding ' : '') + who + (t.filter ? ' (with a filter)' : '');
    }).join(' · ');
  }
  function assignedText(T) { return T && !T.length ? 'Not assigned' : 'Assigned to ' + targetsText(T); }
  // Compliance: which policies a device fails (each policy's device results, and the policy states of
  // every device not reporting compliant), then which settings it fails (Intune's per-setting lists).
  function polName(id) { var p = derive().polById[id]; return p ? p.name : 'A policy not in the policy list'; }
  function failSettingsText(d) {
    return (d.failSettings || []).map(function (x) { return settingLabel(x[0]) + (x[1] && x[1] !== 'Not compliant' ? ' (' + x[1] + ')' : ''); }).join(', ');
  }
  function failingText(d) {
    // A device whose own policy states were not read (Intune throttled the read) can also fail
    // policies only that read shows, such as the built-in one; say so rather than look complete.
    if (d.failing && d.failing.length) return d.failing.map(function (x) { return polName(x[0]) + (x[1] ? ' (' + x[1] + ')' : ''); }).join(', ') +
      (!snap.failOk && !d.polStates ? ' · other policies not read' : '') +
      (d.failSettings && d.failSettings.length ? ' · settings: ' + failSettingsText(d) : '');
    return snap.failOk ? '—' : 'Not read';
  }
  function builtInPolicy() { return (snap.policies || []).filter(function (p) { return p.builtIn; })[0] || null; }
  function failsPolicy(d, id) { return (d.failing || []).some(function (x) { return x[0] === id; }); }
  // Autopilot: registered hardware matched to Intune devices by Intune device ID or serial number.
  // Only meaningful when both lists were read in full.
  function apOk() { return !!snap.apDevices && srcState('apDevices') === 'ok'; }
  function apCrossOk() { return apOk() && !!snap.devicesOk && srcState('intune') === 'ok'; }
  function serialKey(s) { s = String(s || '').trim().toUpperCase(); return s.length >= 4 && !badSerial(s) ? s : null; }
  function apFor(d) { var g = derive(), k = serialKey(d.serial); return g.apByIntune[d.id] || (k && g.apBySerial[k]) || null; }
  function apNoIntune() {
    var g = derive();
    // a placeholder serial with no Intune device ID cannot be matched either way, so it is not listed as missing
    return (snap.apDevices || []).filter(function (a) { var k = serialKey(a.serial); return (k || a.intuneId) && !(a.intuneId && g.byId[a.intuneId]) && !(k && g.bySerial[k]); })
      .sort(function (a, b) { return (b.lastContact || 0) - (a.lastContact || 0) || String(a.serial).localeCompare(String(b.serial)); });
  }
  function apUnmatched() { return (snap.apDevices || []).filter(function (a) { return !serialKey(a.serial) && !a.intuneId; }).length; }
  function winNotAp() {
    return wins().filter(function (d) { return serialKey(d.serial) && !apFor(d); }).sort(function (a, b) { return (b.lastSync || 0) - (a.lastSync || 0); });
  }
  function appsFailing() { return snap.appCounts ? (snap.apps || []).filter(function (a) { return a.failed > 0; }) : []; }
  // Housekeeping and enrollment lists (one definition each)
  function intuneQuiet(days) {
    return devices().filter(function (d) { return ageDays(d.lastSync) >= days; })
      .sort(function (a, b) { return (a.lastSync || 0) - (b.lastSync || 0); });
  }
  function entraOrphans() { return derive().entra.filter(function (e) { return !e.intune; }); }
  function entraStale(days, trust, state) {
    return entraOrphans().filter(function (e) {
      if (ageDays(e.lastSignIn) < days) return false;
      if (trust !== 'all' && e.trust !== trust) return false;
      if (state === 'enabled' && !e.enabled) return false;
      if (state === 'disabled' && e.enabled) return false;
      return true;
    }).sort(function (a, b) { return (a.lastSignIn || 0) - (b.lastSignIn || 0); });
  }
  // Windows PCs joined to the domain or Entra, signing in within 30 days, with no Intune record.
  function enrollGap() {
    return entraOrphans().filter(function (e) {
      return e.os === 'Windows' && (e.trust === 'ServerAd' || e.trust === 'AzureAd') && e.enabled && ageDays(e.lastSignIn) <= 30;
    }).sort(function (a, b) { return (b.lastSignIn || 0) - (a.lastSignIn || 0); });
  }
  function pendingActions() {
    return (snap.actions || []).filter(function (a) { return a.state === 'pending'; }).sort(function (a, b) { return (a.at || 0) - (b.at || 0); });
  }
  // Intune never closes an action whose device was deleted or wiped, so pending splits by whether the device is still enrolled.
  function liveAction(a) { return !!a.deviceId && !!derive().byId[a.deviceId]; }
  function pendingLive() { return pendingActions().filter(liveAction); }
  function departedList() {
    return devices().filter(function (d) { return issuesOf(d).indexOf('departed') !== -1; }).sort(function (a, b) { return (b.lastSync || 0) - (a.lastSync || 0); });
  }
  function mismatched() {
    return devices().filter(mismatch).sort(function (a, b) { return (b.lastLogon || 0) - (a.lastLogon || 0); });
  }
  function signedInBy(d) {
    if (!d.lastLogonUserId) return 'Not reported';
    if (!usersOk()) return 'Entra users not read';
    var who = d.lastLogonUser || 'Account not in the directory';
    var many = d.logonUsers > 1 ? ' · ' + d.logonUsers + ' people sign in' : '';
    if (d.lastLogonUserId === d.userId) return who + ' (the primary user)' + many;
    return who + (d.lastLogonUserState === 'disabled' ? ' · disabled' : '') + many;
  }
  function ruleDays() { return snap.cleanupRule && snap.cleanupRule.days ? snap.cleanupRule.days : null; }

  /* ── building blocks (NOC markup) ────────────────────────────────────── */
  function panel(title, body, action, cls) {
    return h('section', { class: 'noc-panel' + (cls ? ' ' + cls : '') }, [
      h('div', { class: 'noc-panel-head' }, [h('h3', { text: title }), action || null])
    ].concat(body));
  }
  function goBtn(label, v, f) {
    return h('button', { type: 'button', text: label + ' ↗', on: { click: function () { if (f) setFilter(f); go(v); } } });
  }
  function ext(label, href, sm) {
    return h('a', { class: 'ps-btn' + (sm ? ' sm' : ''), href: href, target: '_blank', rel: 'noopener noreferrer', text: label + ' ↗' });
  }
  function copyBtn(label, value, sm) {
    var b = h('button', { type: 'button', class: sm ? 'sm' : null, text: label });
    b.addEventListener('click', function () {
      var done = function (ok) { b.textContent = ok ? 'Copied' : 'Copy failed'; setTimeout(function () { b.textContent = label; }, 1400); };
      try { navigator.clipboard.writeText(typeof value === 'function' ? value() : value).then(function () { done(true); }, function () { done(false); }); } catch (e) { done(false); }
    });
    return b;
  }
  // Motion: a dial fills once the first time it shows a reading, then moves only when the reading changes.
  // Nothing animates on a refresh that brings the same number, and nothing animates under reduced motion.
  var EASE_OUT = 'cubic-bezier(0.23, 1, 0.32, 1)', drawn = {};
  function motionOk() { return !(window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches) && typeof Element.prototype.animate === 'function'; }
  function moveOnce(key, val, el, frames, first, change) {
    var prev = drawn[key]; drawn[key] = val;
    if (prev === val || !motionOk()) return;
    try { el.animate(frames(prev), { duration: prev === undefined ? first : change, easing: EASE_OUT }); } catch (e) {}
  }
  function dial(title, value, ratio, detail, action) {
    var known = ratio != null && isFinite(ratio), p = known ? Math.max(0, Math.min(100, ratio)) : 0;
    var s = svg('svg', { viewBox: '0 0 240 125', role: 'img', 'aria-label': title + ': ' + value });
    s.appendChild(svg('path', { d: 'M25 110 A95 95 0 0 1 215 110', pathLength: '100', stroke: 'var(--line)', 'stroke-width': '12', fill: 'none', 'stroke-linecap': 'round' }));
    if (known && p > 0) {
      var arc = svg('path', { d: 'M25 110 A95 95 0 0 1 215 110', pathLength: '100', stroke: 'var(--cy)', 'stroke-width': '12', fill: 'none', 'stroke-linecap': 'round', 'stroke-dasharray': p + ' 100' });
      s.appendChild(arc);
      moveOnce(view + '|' + title, p, arc, function (prev) { return [{ strokeDasharray: (prev || 0) + ' 100' }, { strokeDasharray: p + ' 100' }]; }, 700, 280);
    }
    return h('section', { class: 'noc-panel noc-signal' }, [
      h('h3', { text: title }),
      h('div', { class: 'noc-dial' }, [s, h('strong', { text: value })]),
      h('p', { text: detail }),
      action || null
    ]);
  }
  // Intune's own tenant count of devices by compliance state (deviceCompliancePolicyDeviceStateSummary).
  // These states do not overlap, so they can be drawn as one bar that adds up to the whole.
  var CSTATE = [   // key, label, tone, device filter
    ['compliant', 'Compliant', 'ok', null],
    ['remediated', 'Remediated', 'ok', null],
    ['grace', 'In grace period', 'warn', { issue: 'grace' }],
    ['nonCompliant', 'Not compliant', 'bad', { issue: 'noncompliant' }],
    ['error', 'Error', 'bad', null],
    ['conflict', 'Conflict', 'bad', null],
    ['configManager', 'Reported by ConfigMgr', 'unknown', null],
    ['notApplicable', 'Not applicable', 'unknown', null],
    ['unknown', 'Unknown', 'unknown', null]
  ];
  function complianceMeter() {
    var S = snap.stateSummary;
    if (!S) return panel('Compliance, as Intune counts it', [h('div', { class: 'ps-meter ps-meter-none', role: 'img', 'aria-label': 'Compliance summary not read' }),
      h('p', { class: 'noc-small', text: 'Intune’s compliance summary was not read. See Sources.' })], goBtn('Sources', 'sources'));
    var parts = CSTATE.filter(function (c) { return S[c[0]] > 0; }), total = parts.reduce(function (a, c) { return a + S[c[0]]; }, 0);
    var bar = h('div', { class: 'ps-meter', role: 'img', 'aria-label': parts.map(function (c) { return n(S[c[0]]) + ' ' + c[1].toLowerCase(); }).join(', ') });
    parts.forEach(function (c) { bar.appendChild(h('span', { class: 'ps-meter-seg ps-meter-' + c[2], style: { flexGrow: String(S[c[0]]) }, title: c[1] + ': ' + n(S[c[0]]) })); });
    moveOnce('meter', total, bar, function () { return [{ clipPath: 'inset(0 100% 0 0)' }, { clipPath: 'inset(0 0 0 0)' }]; }, 650, 0);
    var legend = h('div', { class: 'ps-meter-legend' }, parts.map(function (c) {
      var kids = [h('span', { class: 'ps-meter-key ps-meter-' + c[2], 'aria-hidden': 'true' }), h('span', { text: c[1] }), h('strong', { class: 'ps-num', text: n(S[c[0]]) }), h('small', { class: 'ps-num', text: pct(S[c[0]], total) + '%' })];
      return c[3] ? h('button', { type: 'button', class: 'ps-meter-item', on: { click: function () { setFilter(c[3]); go('devices'); } } }, kids.concat([h('span', { class: 'ps-meter-go', text: '↗', 'aria-hidden': 'true' })]))
        : h('div', { class: 'ps-meter-item' }, kids);
    }));
    var list = devices(), same = !snap.devicesOk || total === list.length;
    return panel('Compliance, as Intune counts it · ' + n(total) + ' devices', [bar, legend,
      same ? null : h('p', { class: 'noc-small', text: 'Intune’s summary counts ' + n(total) + ' devices; its device list returned ' + n(list.length) + '.' })], goBtn('Compliance', 'security'));
  }
  function kv(pairs, wrap) {
    var dl = h('dl', { class: 'ps-kv' });
    pairs.forEach(function (p) {
      if (!p) return;
      dl.appendChild(h('dt', null, [p[0]]));
      dl.appendChild(h('dd', { class: wrap ? 'ps-wrap' : null }, [p[1] == null || p[1] === '' ? '—' : (typeof p[1] === 'object' ? p[1] : String(p[1]))]));
    });
    return dl;
  }
  function chips(keys) {
    if (!keys.length) return h('span', { class: 'noc-small', text: 'None' });
    return h('div', { class: 'ps-chips' }, keys.map(function (k) { return h('span', { class: 'ps-chip ' + ISSUE[k].tone, text: ISSUE[k].label }); }));
  }
  function empty(text) { return h('div', { class: 'ps-empty' }, [h('strong', { text: text })]); }
  function nameCell(d) {
    return h('td', null, [h('button', { type: 'button', class: 'ps-link', text: d.name || 'Unnamed', on: { click: function () { openDrawer(d.id); } } }),
      d.model ? h('small', { text: d.model }) : null]);
  }
  function userCell(d) { return h('td', null, [d.user || 'No primary user', d.userName ? h('small', { text: d.userName }) : null]); }
  function syncCell(t) { return h('td', { 'data-sort': t == null ? '' : t }, [ago(t), h('small', { text: stamp(t) })]); }
  var tableStates = {};
  function tableValue(cell) {
    var explicit = cell.getAttribute('data-sort');
    if (explicit != null) return explicit === '' ? null : Number(explicit);
    var primary = cell.firstChild && cell.firstChild.textContent.trim();
    var text = primary || cell.textContent.trim();
    if (!text || /^(—|Not reported|Unknown)$/.test(text)) return null;
    if (cell.classList.contains('ps-mono')) return text;
    var number = text.replace(/,/g, '');
    return /^-?\d+(\.\d+)?%?$/.test(number) ? Number(number.replace('%', '')) : text;
  }
  function compareCells(a, b, direction) {
    if (a == null || b == null) return a == null ? (b == null ? 0 : 1) : -1;
    return direction * (typeof a === 'number' && typeof b === 'number' ? a - b : String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' }));
  }
  function controlledTable(head, rows, opts) {
    var state = tableStates[opts.key] || (tableStates[opts.key] = { page: 0, size: 25, column: -1, direction: 1 });
    var wrap = h('div', { class: 'ps-table-browser' }), tbody = h('tbody'), headers = [];
    var label0 = opts.label || 'Devices';
    var info = h('span', { class: 'ps-table-range', role: 'status', 'aria-live': 'polite' });
    var order = h('span', { class: 'noc-small' });
    var first = h('button', { type: 'button', text: 'First', 'aria-label': label0 + ': first page', on: { click: function () { state.page = 0; draw(); } } });
    var prev = h('button', { type: 'button', text: 'Previous', 'aria-label': label0 + ': previous page', on: { click: function () { state.page--; draw(); } } });
    var next = h('button', { type: 'button', text: 'Next', 'aria-label': label0 + ': next page', on: { click: function () { state.page++; draw(); } } });
    var last = h('button', { type: 'button', text: 'Last', 'aria-label': label0 + ': last page', on: { click: function () { state.page = Math.ceil(rows.length / state.size) - 1; draw(); } } });
    var size = h('select', { 'aria-label': label0 + ': rows per page', on: { change: function () { state.size = Number(size.value); state.page = 0; draw(); } } }, [25, 50, 100].map(function (v) { return h('option', { value: v, selected: state.size === v, text: String(v) }); }));
    var reset = h('button', { type: 'button', text: 'Default order', 'aria-label': label0 + ': restore default order', on: { click: function () { state.column = -1; state.page = 0; draw(); } } });
    var thead = h('thead', null, [h('tr', null, head.map(function (title, column) {
      var th = h('th', { scope: 'col' }); headers.push(th);
      th.appendChild(h('button', { type: 'button', class: 'ps-sort', text: title + ' ↕', 'aria-label': label0 + ': sort by ' + title, on: { click: function () {
        state.direction = state.column === column ? -state.direction : 1; state.column = column; state.page = 0; draw();
      } } }));
      return th;
    }))]);
    function draw() {
      var pages = Math.max(1, Math.ceil(rows.length / state.size));
      state.page = Math.max(0, Math.min(state.page, pages - 1));
      var sorted = rows.map(function (cells, i) { return { cells: cells, index: i }; });
      if (state.column >= 0) sorted.sort(function (a, b) { return compareCells(tableValue(a.cells[state.column]), tableValue(b.cells[state.column]), state.direction) || a.index - b.index; });
      var start = state.page * state.size;
      clear(tbody);
      sorted.slice(start, start + state.size).forEach(function (row) { tbody.appendChild(h('tr', null, row.cells)); });
      headers.forEach(function (th, i) {
        th.setAttribute('aria-sort', i === state.column ? (state.direction === 1 ? 'ascending' : 'descending') : 'none');
        th.firstChild.textContent = head[i] + (i === state.column ? (state.direction === 1 ? ' ↑' : ' ↓') : ' ↕');
      });
      info.textContent = (rows.length ? n(start + 1) : '0') + '–' + n(Math.min(start + state.size, rows.length)) + ' of ' + n(rows.length) + ' · Page ' + (state.page + 1) + ' of ' + pages;
      order.textContent = state.column < 0 ? 'Default: ' + (opts.order || 'source order') : 'Sorted by ' + head[state.column] + (state.direction === 1 ? ' ascending' : ' descending');
      first.disabled = prev.disabled = state.page === 0; next.disabled = last.disabled = state.page >= pages - 1; reset.disabled = state.column < 0;
    }
    wrap.appendChild(h('div', { class: 'ps-table-tools' }, [order, reset]));
    wrap.appendChild(h('div', { class: 'noc-table-scroll' }, [h('table', { class: 'noc-table', 'aria-label': label0 }, [thead, tbody])]));
    wrap.appendChild(h('div', { class: 'ps-table-pager', role: 'group', 'aria-label': label0 + ' pagination' }, [info, h('label', null, ['Rows ', size]), first, prev, next, last]));
    draw(); return wrap;
  }
  function table(head, rows, opts) {
    opts = opts || {};
    if (!rows.length) return empty(opts.empty || 'Nothing to show');
    if (opts.controls) return controlledTable(head, rows, opts);
    var limit = opts.limit || rows.length;
    var body = rows.slice(0, limit).map(function (r) { return h('tr', null, r); });
    return h('div', { class: 'noc-table-scroll' }, [h('table', { class: 'noc-table' }, [
      h('thead', null, [h('tr', null, head.map(function (x) { return h('th', { scope: 'col', text: x }); }))]),
      h('tbody', null, body)
    ])]);
  }
  function statusCell(st) {
    return h('td', { class: 'ps-status' }, [h('span', { class: 'ps-dot ' + st, 'aria-hidden': 'true' }), LABEL[st]]);
  }
  function seg(labelText, values, current, fmt, onPick) {
    var wrap = h('span', { class: 'ps-seg', role: 'group', 'aria-label': labelText });
    values.forEach(function (v) {
      wrap.appendChild(h('button', { type: 'button', 'aria-pressed': String(v === current), text: fmt(v), on: { click: function () { onPick(v); } } }));
    });
    return h('span', null, [h('span', { class: 'ps-seg-label', text: labelText + ' ' }), wrap]);
  }
  function patchTable(list, opts) {
    return table(['Device', 'User', 'Build', 'Status', 'Last check-in', 'Ring'], list.map(function (d) {
      return [nameCell(d), userCell(d), h('td', { class: 'ps-mono', text: shortBuild(d.os) }), statusCell(classify(d)), syncCell(d.lastSync),
        h('td', { text: ringName(d) })];
    }), Object.assign({ controls: true, key: 'patch', label: 'Patch devices', order: 'oldest builds first' }, opts));
  }
  function sortedPatch(list) {
    return list.slice().sort(function (a, b) {
      var sa = ORDER[classify(a)], sb = ORDER[classify(b)];
      if (sa !== sb) return sa - sb;
      if ((a.rev || 0) !== (b.rev || 0)) return (a.rev || 0) - (b.rev || 0);
      return String(a.name).localeCompare(String(b.name));
    });
  }

  /* ── sources (one definition, used by the strip and the Sources view) ─── */
  var STATE_WORD = { ok: 'Read available', partial: 'Partial result', denied: 'Read denied', error: 'Unavailable', timeout: 'Timed out', pending: 'Reading…' };
  function srcRows(r, countLabel) {
    return [['Request', r.request], ['Result', r.http ? 'HTTP ' + r.http : 'No response'], ['Duration', r.ms != null ? r.ms + ' ms' : '—'], [countLabel || 'Rows', r.count != null ? n(r.count) : '—'], ['Read at', stamp(r.at)]];
  }
  function sourceDefs() {
    var s = snap.sources, B = snap.baseline;
    function cnt(k) { return n(s[k] && s[k].count || 0); }
    function def(key, name, note, limit, countLabel) {
      var r = s[key] || { state: 'unknown', error: 'Not in this read' };
      return { key: key, name: name, tone: r.state, status: STATE_WORD[r.state] || 'Unknown', note: r.state === 'ok' ? note : (r.error || 'No rows'), rows: srcRows(r, countLabel), limit: limit };
    }
    return [
      def('intune', 'Intune devices', n(s.intune.count) + ' devices, all platforms', 'Every value is what the device reported at its last check-in. A device that has not checked in may already be fixed.'),
      def('entra', 'Entra devices', n(s.entra && s.entra.count || 0) + ' device records', 'Entra keeps a record for every joined, hybrid-joined or registered device, including ones Intune never manages. Last sign-in is approximate (Entra updates it about once every 14 days).'),
      def('protection', 'Defender', 'Fleet protection summary', 'Counts as Intune reports them from Defender on Windows devices. Per-device detail is read when a device is opened.', 'Objects'),
      def('autopilot', 'Autopilot deployments', n(s.autopilot && s.autopilot.count || 0) + ' recent deployments', 'Intune keeps a short deployment history. The registered hardware is a separate read (Autopilot devices).'),
      def('actions', 'Remote actions', n(s.actions && s.actions.count || 0) + ' audit entries', 'Who ran which remote action (wipe, retire, delete, sync…) and whether the device has acknowledged it.'),
      def('malware', 'Malware detections', n(s.malware && s.malware.count || 0) + ' distinct detections', 'Every malware item Intune has on record for Windows devices, newest first. Older items may already be remediated.'),
      def('enrollFail', 'Enrollment failures', n(s.enrollFail && s.enrollFail.count || 0) + ' recent failures', 'Enrollment attempts that failed, as Intune troubleshooting records them.'),
      def('cleanup', 'Clean-up rule', snap.cleanupRule ? 'Retire after ' + snap.cleanupRule.days + ' days' : 'No rule', 'Intune removes devices that have not checked in for this many days. Read from Intune, not stated here.'),
      def('users', 'Entra users', n(s.users && s.users.count || 0) + ' user accounts', 'Used only to tell whether a device’s primary user, and the last person to sign in, still has an enabled account. A deleted account is not returned at all, so it shows as “Not in the directory”.', 'Accounts'),
      def('analytics', 'Endpoint analytics', n(s.analytics && s.analytics.count || 0) + ' devices scored', 'Only devices enrolled in Endpoint analytics have scores.'),
      def('rings', 'Update rings', nn((snap.rings || []).length, 'Windows update ring', 'Windows update rings'), 'Ring settings and assignments as configured in Intune now.', 'Rings'),
      def('ringGroups', 'Ring group members', cnt('ringGroups') + ' users and devices in ring groups', 'Nested groups included. A Windows device is in a ring when its Intune primary user or the device itself is in an assigned group and in no excluded group. Another person signing in to the PC is not reflected. An assignment to all users, a filter, or a group whose members cannot be read makes every device’s ring unknown.', 'Members'),
      def('ringResults', 'Ring results', cnt('ringResults') + ' device results', 'What each device last reported to Intune for each ring. A device that has not reported yet has no result.', 'Results'),
      def('policies', 'Compliance policies', cnt('policies') + ' policies', 'Policies and their assignments as configured. Microsoft’s built-in Default Device Compliance Policy is not in this list; it comes from the per-device policy states below.', 'Policies'),
      def('compliance', 'Device results per policy', cnt('compliance') + ' device results', 'Each listed policy’s result for every device it reaches, as Intune holds them. Counts per policy come from here; rows for devices no longer in Intune are dropped.', 'Results'),
      def('complianceDevices', 'Policy states per device', cnt('complianceDevices') + ' of ' + n(snap.stateIds || 0) + ' devices read', 'Read for every device not reporting compliant (not compliant, in grace period, error, unknown), sent 20 at a time as Graph batches of GETs. This is the only read that names Microsoft’s built-in Default Device Compliance Policy, so its counts cover these devices only and it has no compliant count. Intune throttles this read: a device’s answer is reused until it checks in again (6 hours at most), and devices Intune refused are read again on the next refresh, devices not compliant first.', 'Devices'),
      def('settingDevices', 'Failing devices per setting', cnt('settingDevices') + ' device results', 'Read for each compliance setting that has a failing device. Intune does not say which policy a setting result belongs to, so a device lists its failing settings beside its failing policies.', 'Results'),
      def('stateSummary', 'Compliance state summary', snap.stateSummary ? n(snap.stateSummary.nonCompliant) + ' not compliant · ' + n(snap.stateSummary.grace) + ' in grace' : 'Not read', 'Intune’s own tenant-wide device count by compliance state.', 'Objects'),
      def('settings', 'Compliance settings', cnt('settings') + ' settings', 'Devices per compliance setting across all policies.', 'Settings'),
      def('apDevices', 'Autopilot devices', cnt('apDevices') + ' registered devices', 'Every registered hardware hash: serial, group tag, profile assignment and whether it has enrolled. The record’s secrets (device account password, product key) are dropped by the hub and never sent to this page.', 'Devices'),
      def('apProfiles', 'Autopilot profiles', cnt('apProfiles') + ' deployment profiles', 'Deployment profiles and the groups they are assigned to.', 'Profiles'),
      def('enrollConfig', 'Enrollment settings', cnt('enrollConfig') + ' settings', 'Device limits, platform restrictions, the Enrollment Status Page and Windows Hello settings, by priority.', 'Settings'),
      def('apps', 'App install summary', cnt('apps') + ' apps', 'Install counts per app as Intune reports them. Open an app on the Apps view for the devices where it did not install. Intune has no GET for install counts; they come only from its report service.', 'Apps'),
      def('appInventory', 'Assigned apps', cnt('appInventory') + ' assigned apps', 'Every app Intune has an assignment for, with who it is assigned to and how (required, available, uninstall). Listed on the Apps view even when the install counts cannot be read.', 'Apps'),
      def('groups', 'Group names', cnt('groups') + ' groups named', 'Names of the groups that rings, policies, profiles and apps are assigned to.', 'Groups'),
      { key: 'baseline', name: 'Baseline', tone: 'ok', status: 'Configured', note: '.' + B.revision + ' · released ' + B.released,
        rows: [['Update', B.label], ['Revision', String(B.revision)], ['Released', B.released], ['Feature builds', B.builds.join(', ')]],
        limit: 'Set in the hub route. It is changed by hand when a new monthly update is approved. Older revisions are not mapped to months.' }
    ];
  }
  function strip() {
    var keys = ['intune', 'entra', 'compliance', 'rings', 'apps'];
    return h('div', { class: 'noc-source-strip' }, sourceDefs().filter(function (s) { return keys.indexOf(s.key) !== -1; }).map(function (s) {
      return h('button', { type: 'button', on: { click: function () { go('sources', s.key); } } }, [
        h('b', { text: s.name.toUpperCase() }),
        h('span', { class: 'noc-tone-' + s.tone, text: s.status }),
        h('span', { class: 'noc-small', text: s.note })
      ]);
    }));
  }

  /* ── needs attention ─────────────────────────────────────────────────── */
  function countIssue(k, list) { return (list || devices()).filter(function (d) { return issuesOf(d).indexOf(k) !== -1; }).length; }
  function issues() {
    var out = [], g = derive(), wl = wins(), t = tally(wl), B = snap.baseline, rd = ruleDays();
    if (!snap.devicesOk) out.push({ pin: true, sev: 'bad', title: 'Intune device read failed', detail: 'No device data is available. Open Sources for the error.', v: 'sources', src: 'intune' });
    // pinned first, because every count below it is low
    if (snap.devicesOk && srcState('intune') === 'partial') out.push({ pin: true, sev: 'warn', title: 'Intune device list is incomplete', detail: 'Graph stopped before the last page. Every count below is low and the Entra cross-checks are off.', v: 'sources', src: 'intune' });
    var c;
    if ((c = countIssue('malware'))) out.push({ sev: 'bad', title: nn(c, 'device reports', 'devices report') + ' active malware', detail: 'Defender reports malware it has not cleaned. Open each device.', v: 'devices', f: { issue: 'malware' } });
    if ((c = countIssue('noncompliant'))) out.push({ sev: 'bad', title: nn(c, 'device is', 'devices are') + ' not compliant', detail: 'Conditional Access may already be blocking these users.', v: 'security' });
    if (ringsKnown()) (snap.rings || []).forEach(function (r) {
      var dl = ringDeadline(r);
      if (!r.assigned || !dl || (r.quality && r.quality.paused)) return;
      var rt = tally(ringDevices(r));
      if (now() > dl.restart && rt.pending + rt.stale) out.push({ sev: 'warn', title: nn(rt.pending + rt.stale, 'device', 'devices') + ' in ' + r.name + ' behind the baseline after the estimated ring target', detail: 'Estimated restart target: ' + day(dl.restart) + '. Actual enforcement depends on device discovery and restart state.', v: 'devices', f: { platform: 'Windows', issue: 'behind', ring: r.id } });
    });
    var bp = builtInPolicy(), bpDev = bp && snap.failOk ? devices().filter(function (d) { return failsPolicy(d, bp.id); }) : [];
    if (bpDev.length) {
      var bpOk = bpDev.filter(function (d) { return d.compliance === 'compliant'; }).length;
      out.push({ sev: 'warn', title: nn(bpDev.length, 'device fails', 'devices fail') + ' Microsoft’s built-in compliance checks', detail: (bpOk ? n(bpOk) + ' of them still report Compliant. ' : '') + 'The built-in policy checks that a compliance policy is assigned, the device is active and its user exists. Open a device for the failing check.', v: 'devices', f: { pol: bp.id } });
    }
    var af = appsFailing();
    if (af.length) out.push({ sev: 'warn', title: nn(af.length, 'app has', 'apps have') + ' failed installs', detail: n(af.reduce(function (t, a) { return t + a.failed; }, 0)) + ' failed device installs in all. Open an app for the devices and error codes.', v: 'apps' });
    if (ringsKnown() && (c = wl.filter(function (d) { return d.ring === 'none'; }).length)) out.push({ sev: 'warn', title: nn(c, 'Windows device is', 'Windows devices are') + ' in no update ring', detail: 'No Intune update ring reaches them. Their update behaviour comes from settings this page cannot read (Group Policy, ManageEngine).', v: 'devices', f: { platform: 'Windows', ring: 'none' } });
    (snap.rings || []).forEach(function (r) {
      var bad = r.results ? (r.results.error || 0) + (r.results.conflict || 0) + (r.results.nonCompliant || 0) : 0;
      if (bad) out.push({ sev: 'warn', title: nn(bad, 'device reports', 'devices report') + ' a problem with ' + r.name, detail: 'Error, conflict or not compliant on the ring itself. Open the ring for the devices.', v: 'updates', src: 'ring-' + r.id });
    });
    if ((c = countIssue('unencrypted'))) out.push({ sev: 'warn', title: nn(c, 'Windows device', 'Windows devices') + ' not encrypted', detail: 'The device reports BitLocker off.', v: 'security' });
    if ((c = countIssue('grace'))) out.push({ sev: 'warn', title: nn(c, 'device', 'devices') + ' in a compliance grace period', detail: 'They become non-compliant when the grace period ends.', v: 'security' });
    var gap = g.entraOk ? enrollGap().length : 0;
    if (gap) out.push({ sev: 'warn', title: nn(gap, 'Windows PC', 'Windows PCs') + ' active but not in Intune', detail: 'Entra records joined to the domain or Entra and signing in within 30 days, with no Intune record. Repair also checks AD and ManageEngine, so its population can be larger.', v: 'enrollment' });
    if (t.stale) out.push({ sev: 'warn', title: nn(t.stale, 'Windows device', 'Windows devices') + ' behind and not checking in', detail: 'No check-in for over 7 days; real build unknown.', v: 'devices', f: { platform: 'Windows', patch: 'stale' } });
    if (t.pending) out.push({ sev: 'warn', title: nn(t.pending, 'Windows device', 'Windows devices') + ' pending the baseline', detail: 'Checked in within 7 days and still below .' + B.revision + '.', v: 'updates' });
    if (t.unknown) out.push({ sev: 'warn', title: nn(t.unknown, 'Windows device is', 'Windows devices are') + ' on a build the baseline does not list', detail: 'Windows 10, or a build newer than the baseline. Its patch level is not judged here.', v: 'devices', f: { platform: 'Windows', patch: 'unknown' } });
    if ((c = countIssue('lowdisk'))) out.push({ sev: 'warn', title: nn(c, 'device has', 'devices have') + ' under 10% disk free', detail: 'Low disk stops updates from installing.', v: 'security' });
    if (usersOk() && (c = departedList().length)) out.push({ sev: 'warn', title: nn(c, 'device belongs', 'devices belong') + ' to people who have left', detail: 'The primary user is disabled or no longer in Entra. Recover the device or change its primary user.', v: 'housekeeping', src: 'departed' });
    if (rd) {
      var soon = devices().filter(function (d) { var a = ageDays(d.lastSync); return a >= rd - 30 && a < rd; }).length;
      if (soon) out.push({ sev: 'info', title: nn(soon, 'device', 'devices') + ' within 30 days of auto-removal', detail: 'The Intune clean-up rule removes devices after ' + rd + ' days without a check-in.', v: 'housekeeping', hk: { intuneAge: rd - 30 >= 30 ? rd - 30 : 30 } });
    }
    if (apCrossOk() && (c = apNoIntune().length)) out.push({ sev: 'info', title: nn(c, 'Autopilot registration has', 'Autopilot registrations have') + ' no Intune device', detail: 'Registered hardware with no Intune record for its serial number: not deployed yet, or reset, sold or recycled without being deregistered.', v: 'enrollment', src: 'apnointune' });
    if (apCrossOk() && (c = winNotAp().length)) out.push({ sev: 'info', title: nn(c, 'Windows device is', 'Windows devices are') + ' not registered in Autopilot', detail: 'A reset sends them to the standard out-of-box setup, not Autopilot.', v: 'enrollment', src: 'apmissing' });
    if (g.dupGroups.length) out.push({ sev: 'info', title: nn(g.dupGroups.length, 'serial number has', 'serial numbers have') + ' more than one Intune record', detail: 'Usually a re-enrolled device whose old record was left behind.', v: 'housekeeping' });
    if ((c = mismatched().length)) out.push({ sev: 'info', title: nn(c, 'Windows PC is', 'Windows PCs are') + ' used by someone other than the primary user', detail: 'At check-ins in the last 30 days someone else was signed in and the primary user was not. Ring membership and user-targeted apps follow the primary user.', v: 'housekeeping', src: 'mismatch' });
    var pa = pendingLive().filter(function (a) { return ageDays(a.at) >= 7; }).length;
    if (pa) out.push({ sev: 'info', title: nn(pa, 'remote action', 'remote actions') + ' pending over 7 days', detail: 'The device is still in Intune and has not acknowledged them.', v: 'housekeeping', src: 'actions' });
    if (!ringsKnown()) out.push({ sev: 'info', title: 'Update ring membership is unknown', detail: ringsWhy() + ' Ring deadlines and the “in no ring” count are off.', v: 'updates' });
    if (snap.sources.users && snap.sources.users.state !== 'ok') out.push({ sev: 'info', title: 'Entra users could not be read', detail: 'Devices of people who have left cannot be listed.', v: 'sources', src: 'users' });
    if (snap.sources.entra && snap.sources.entra.state !== 'ok') out.push({ sev: 'warn', title: 'Entra devices could not be read', detail: 'Enrollment gap and Entra housekeeping are empty.', v: 'sources', src: 'entra' });
    (snap.rings || []).filter(function (r) { return !r.assigned; }).forEach(function (r) {
      out.push({ sev: 'info', title: r.name + ' has no assignment', detail: 'The ring is configured in Intune but reaches no device.', v: 'updates', src: 'ring-' + r.id });
    });
    var miss = missingPerms();
    if (miss.length) out.push({ sev: 'warn', title: nn(miss.length, 'read permission is', 'read permissions are') + ' missing from the hub app', detail: miss.join(', ') + '. The data it covers shows as not read.', v: 'sources', src: 'perms' });
    var failed = NEW_SRC.filter(function (k) { return snap.sources[k] && snap.sources[k].state !== 'ok'; });
    if (failed.length) out.push({ sev: 'info', title: nn(failed.length, 'read', 'reads') + ' did not complete', detail: failed.map(function (k) { return SRC_NAME[k]; }).join(', ') + '. What depends on them shows as not read.', v: 'sources', src: failed[0] });
    // most serious first (the help says so); sort is stable, so push order breaks ties
    var RANK = { bad: 1, warn: 2, info: 3 };
    return out.sort(function (a, b) { return (a.pin ? 0 : RANK[a.sev]) - (b.pin ? 0 : RANK[b.sev]); });
  }
  var NEW_SRC = ['rings', 'ringGroups', 'ringResults', 'policies', 'compliance', 'complianceDevices', 'settingDevices', 'stateSummary', 'settings', 'apDevices', 'apProfiles', 'enrollConfig', 'apps', 'appInventory', 'groups'];
  var SRC_NAME = { rings: 'Update rings', ringGroups: 'Ring group members', ringResults: 'Ring results', policies: 'Compliance policies', compliance: 'Device results per policy',
    complianceDevices: 'Policy states per device', settingDevices: 'Failing devices per setting', stateSummary: 'Compliance state summary', settings: 'Compliance settings',
    apDevices: 'Autopilot devices', apProfiles: 'Autopilot profiles', enrollConfig: 'Enrollment settings', apps: 'App install summary', appInventory: 'Assigned apps', groups: 'Group names' };
  function missingPerms() { return snap.permissions ? snap.permissions.needed.filter(function (x) { return !x.held; }).map(function (x) { return x.perm; }) : []; }
  function queue() {
    var items = issues();
    function item(i) {
      return h('button', { type: 'button', class: 'noc-issue', on: { click: function () {
        if (i.f) setFilter(i.f);
        if (i.hk) Object.keys(i.hk).forEach(function (k) { hk[k] = i.hk[k]; });
        go(i.v, i.src);
      } } }, [
        h('strong', { class: 'noc-tone-' + i.sev, text: i.title }),
        h('span', { class: 'noc-small', text: i.detail })
      ]);
    }
    if (!items.length) return empty('No attention items in the current read');
    var wrap = h('div', { class: 'ps-attention' }, [h('p', { class: 'noc-small', text: nn(items.length, 'attention group', 'attention groups') + ' · most serious first. A device can appear in more than one group.' }), h('div', { class: 'noc-issues ps-attention-grid' }, items.slice(0, 6).map(item))]);
    if (items.length > 6) wrap.appendChild(h('details', { class: 'ps-attention-more' }, [h('summary', { text: 'Show ' + n(items.length - 6) + ' more attention groups' }), h('div', { class: 'noc-issues ps-attention-grid' }, items.slice(6).map(item))]));
    return wrap;
  }

  /* ── overview ────────────────────────────────────────────────────────── */
  function platforms() {
    var by = {};
    devices().forEach(function (d) { (by[d.platform] = by[d.platform] || []).push(d); });
    return Object.keys(by).sort(function (a, b) { return by[b].length - by[a].length; }).map(function (k) { return { name: k, list: by[k] }; });
  }
  function platformTable() {
    return table(['Platform', 'Devices', 'Compliant', 'Checked in 7 d', 'Encrypted', ''], platforms().map(function (p) {
      var L = p.list, comp = L.filter(function (d) { return d.compliance === 'compliant'; }).length,
        fresh = L.filter(function (d) { return d.lastSync != null && now() - d.lastSync <= STALE_MS; }).length,
        enc = p.name === 'Windows' ? L.filter(function (d) { return d.encrypted === true; }).length : null;
      return [h('td', { text: p.name }), h('td', { class: 'ps-num', text: n(L.length) }),
        h('td', { class: 'ps-num', text: n(comp) + ' · ' + pct(comp, L.length) + '%' }),
        h('td', { class: 'ps-num', text: n(fresh) + ' · ' + pct(fresh, L.length) + '%' }),
        h('td', { class: 'ps-num', text: enc == null ? '—' : n(enc) + ' · ' + pct(enc, L.length) + '%' }),
        h('td', null, [goBtn('List', 'devices', { platform: p.name })])];
    }), { empty: 'No device reading' });
  }
  function overview() {
    var list = devices(), wl = wins(), t = tally(wl), g = derive(), rd = ruleDays();
    var frag = D.createDocumentFragment();
    var comp = list.filter(function (d) { return d.compliance === 'compliant'; }).length;
    var fresh = list.filter(function (d) { return d.lastSync != null && now() - d.lastSync <= STALE_MS; }).length;
    var note = !snap.devicesOk ? 'Intune did not return devices. Nothing below is a reading of the estate.'
      : n(list.length) + ' devices in Intune. ' + n(comp) + ' compliant, ' + n(fresh) + ' checked in this week, ' + n(t.current) + ' of ' + n(t.total) + ' Windows devices on the ' + snap.baseline.label + '.';
    frag.appendChild(h('div', { class: 'noc-note', text: note }));
    var ok = snap.devicesOk && list.length > 0;
    frag.appendChild(panel('Needs attention', [queue()], null, 'ps-attention-first'));
    frag.appendChild(strip());
    frag.appendChild(complianceMeter());
    frag.appendChild(h('div', { class: 'noc-signals' }, [
      dial('Compliant', ok ? pct(comp, list.length) + '%' : 'Unknown', ok ? pct(comp, list.length) : null,
        ok ? n(comp) + ' of ' + n(list.length) + ' devices, all platforms' : 'No device reading', goBtn('Compliance', 'security')),
      dial('On the current update', ok && t.total ? pct(t.current, t.total) + '%' : 'Unknown', ok && t.total ? pct(t.current, t.total) : null,
        ok ? n(t.current) + ' of ' + n(t.total) + ' Windows devices on .' + snap.baseline.revision + '+' : 'No device reading', goBtn('Updates', 'updates')),
      dial('Checked in within 7 days', ok ? pct(fresh, list.length) + '%' : 'Unknown', ok ? pct(fresh, list.length) : null,
        ok ? nn(list.length - fresh, 'device has', 'devices have') + ' gone quiet' : 'No device reading', goBtn('Housekeeping', 'housekeeping'))
    ]));
    var orphans = g.entraOk ? entraOrphans() : [];
    function dn(x) { return ok ? n(x) : 'Not read'; }
    var hkPairs = [
      ['Intune: no check-in 30+ days', dn(intuneQuiet(30).length)],
      ['Intune: older duplicate records', dn(Object.keys(g.dupOld).length)],
      ['Intune: primary user has left', usersOk() ? dn(departedList().length) : 'Not read'],
      ['Windows: signed in by someone else', dn(mismatched().length)],
      ['Entra: no Intune record, no sign-in 90+ days', g.entraOk ? n(entraStale(90, 'all', 'all').length) : 'Not read'],
      ['Entra: disabled, no Intune record', g.entraOk ? n(orphans.filter(function (e) { return !e.enabled; }).length) : 'Not read'],
      ['Remote actions pending, device still in Intune', snap.actions && ok ? n(pendingLive().length) : 'Not read'],
      ['Clean-up rule', rd ? 'Removes after ' + rd + ' days' : 'Not read']
    ];
    var recent = list.filter(function (d) { return ageDays(d.enrolled) <= 30; }).length;
    var apFail = (snap.autopilot || []).filter(function (a) { return a.state === 'failure'; }).length;
    var ux = snap.analytics || [], uxOk = !!(snap.sources.analytics && snap.sources.analytics.state === 'ok');
    var enPairs = [
      ['Enrolled in the last 30 days', dn(recent)],
      ['Windows PCs active, not in Intune', g.entraOk ? n(enrollGap().length) : 'Not read'],
      ['Windows enrolled through Autopilot', dn(wl.filter(function (d) { return d.autopilot; }).length)],
      ['Registered in Autopilot', apOk() ? n(snap.apDevices.length) : 'Not read'],
      ['Registered, no Intune device', apCrossOk() ? n(apNoIntune().length) : 'Not read'],
      ['Apps with failed installs', snap.apps && snap.appCounts ? n(appsFailing().length) + ' of ' + n(snap.apps.length) : 'Not read'],
      ['Autopilot deployments failed (log)', snap.autopilot ? n(apFail) + ' of ' + n(snap.autopilot.length) : 'Not read'],
      ['Enrollment failures (log)', snap.enrollFailures ? n(snap.enrollFailures.length) : 'Not read'],
      ['Scored by Endpoint analytics', uxOk ? n(ux.length) + (ok ? ' of ' + n(list.length) : '') + ' · ' + n(ux.filter(function (x) { return x.health === 'meetingGoals'; }).length) + ' meeting goals, ' + n(ux.filter(function (x) { return x.health === 'needsAttention'; }).length) + ' need attention' : 'Not read']
    ];
    var main = h('div', { class: 'noc-stack' }, [
      panel('Platforms', [platformTable()], goBtn('All devices', 'devices', {})),
      h('div', { class: 'noc-pair' }, [
        panel('Housekeeping backlog', [kv(hkPairs)], goBtn('Open', 'housekeeping')),
        panel('Enrollment', [kv(enPairs)], goBtn('Open', 'enrollment'))
      ]),
      trendPanel()
    ]);
    var aside = h('aside', { class: 'noc-stack' }, [
      panel('Evidence quality', quality(), goBtn('Sources', 'sources'))
    ]);
    frag.appendChild(h('div', { class: 'noc-columns' }, [main, aside]));
    frag.appendChild(h('div', { class: 'noc-related' }, [goBtn('Find a device', 'devices', {}), goBtn('Clean up records', 'housekeeping'), goBtn('Check enrollment', 'enrollment'), ext('Intune: all devices', PORTAL.allDevices)]));
    return frag;
  }
  /* ── trend (one row per day, saved by the hub) ───────────────────────── */
  var TREND = [   // key, label, which way is better, unit
    ['devices', 'Devices in Intune', null, ''],
    ['noncompliant', 'Not compliant', 'down', ''],
    ['quiet30', 'No check-in 30+ days', 'down', ''],
    ['winPct', 'Windows on the current update', 'up', '%'],
    ['unencrypted', 'Windows not encrypted', 'down', ''],
    ['departed', 'Primary user has left', 'down', ''],
    ['pendingActions', 'Remote actions pending', 'down', ''],
    ['enrollGap', 'Active PCs not in Intune', 'down', ''],
    ['appsFailing', 'Apps with failed installs', 'down', '']
  ];
  function trendVal(r, k) {
    if (k === 'winPct') return r.winTotal ? Math.round(r.winCurrent / r.winTotal * 100) : null;
    return r[k] == null ? null : r[k];
  }
  function spark(vals) {
    var pts = []; vals.forEach(function (v, i) { if (v != null) pts.push([i, v]); });
    if (pts.length < 2) return h('div', { class: 'ps-spark' });
    var lo = Infinity, hi = -Infinity; pts.forEach(function (p) { lo = Math.min(lo, p[1]); hi = Math.max(hi, p[1]); });
    var W = 120, H = 28, span = hi - lo || 1, step = W / (vals.length - 1);
    var xy = pts.map(function (p) { return [p[0] * step, hi === lo ? H / 2 : H - 3 - (p[1] - lo) / span * (H - 6)]; });
    var s = svg('svg', { viewBox: '0 0 ' + W + ' ' + H, class: 'ps-spark', preserveAspectRatio: 'none', 'aria-hidden': 'true' });
    s.appendChild(svg('polyline', { points: xy.map(function (q) { return q[0].toFixed(1) + ',' + q[1].toFixed(1); }).join(' '), fill: 'none', stroke: 'var(--cy)', 'stroke-width': '1.5', 'stroke-linejoin': 'round', 'vector-effect': 'non-scaling-stroke' }));
    return s;
  }
  function dayOfRow(r) { return r.day ? new Date(r.day + 'T00:00:00Z').toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' }) : day(r.at); }
  function trendPanel() {
    var rows = (snap.trend || []).slice(-30);
    var note = 'One point per day: the hub keeps its last good read of each UTC day, counted with the same rules as this page.';
    if (rows.length < 2) return panel('Trend', [h('p', { class: 'noc-small', text: rows.length ? 'The trend starts ' + dayOfRow(rows[0]) + '. One point is saved per day, so the lines appear after the next day’s read.' : 'No trend recorded yet. ' + note })]);
    var last = rows[rows.length - 1];
    return panel('Trend · ' + rows.length + ' days recorded', [h('div', { class: 'ps-trend' }, TREND.map(function (t) {
      var vals = rows.map(function (r) { return trendVal(r, t[0]); }), cur = trendVal(last, t[0]);
      var bi = -1; vals.some(function (v, i) { if (v != null) { bi = i; return true; } return false; });
      var diff = cur != null && bi !== -1 && bi < rows.length - 1 ? cur - vals[bi] : null;
      var tone = diff && t[2] ? ((diff < 0) === (t[2] === 'down') ? 'ok' : 'warn') : null;
      var txt = diff == null ? 'No earlier point' : (diff === 0 ? 'No change' : (diff > 0 ? '+' : '−') + n(Math.abs(diff)) + (t[3] ? ' pts' : '')) + ' since ' + dayOfRow(rows[bi]);
      return h('div', { class: 'ps-trend-cell' }, [
        h('span', { class: 'noc-small', text: t[1] }),
        h('strong', { class: 'ps-num', text: cur == null ? 'Not read' : n(cur) + t[3] }),
        spark(vals),
        h('small', { class: tone ? 'noc-tone-' + tone : null, text: txt })
      ]);
    })), h('p', { class: 'noc-small', text: note })]);
  }
  function quality() {
    var s = snap.sources, keys = Object.keys(s), ok = keys.filter(function (k) { return s[k] && s[k].state === 'ok'; }).length;
    return [
      h('p', { text: ok + ' / ' + keys.length + ' reads available' }),
      h('p', { class: 'noc-small', text: 'Read ' + ago(snap.at) + '. The hub reuses a read for ' + Math.round(snap.cacheMs / 6e4) + ' minutes; Refresh re-reads at most once a minute.' }),
      h('p', { class: 'noc-small', text: !snap.permissions ? 'The hub’s permissions could not be read from its token.' : missingPerms().length ? 'Missing read permissions: ' + missingPerms().join(', ') + '.' : 'The hub holds every read permission this page uses.' }),
      h('p', { class: 'noc-small', text: 'See Sources for what each number can and cannot show.' })
    ];
  }

  /* ── devices ─────────────────────────────────────────────────────────── */
  function filtered() {
    var q = filt.q.trim().toLowerCase();
    return devices().filter(function (d) {
      if (filt.platform !== 'all' && d.platform !== filt.platform) return false;
      if (filt.ring !== 'all' && d.ring !== filt.ring && (d.rings || []).indexOf(filt.ring) === -1) return false;
      if (filt.pol !== 'all' && !failsPolicy(d, filt.pol)) return false;
      if (filt.patch !== 'all' && !(isWin(d) && classify(d) === filt.patch)) return false;
      if (filt.issue !== 'all') {
        var is = issuesOf(d);
        if (filt.issue === 'any' ? !is.filter(function (k) { return ISSUE[k].tone !== 'info'; }).length : is.indexOf(filt.issue) === -1) return false;
      }
      if (q && (d.name + ' ' + d.user + ' ' + d.userName + ' ' + (d.lastLogonUser || '') + ' ' + d.os + ' ' + d.serial + ' ' + d.model).toLowerCase().indexOf(q) === -1) return false;
      return true;
    }).sort(function (a, b) {
      var ia = issuesOf(a).length, ib = issuesOf(b).length;
      return ib - ia || String(a.name).localeCompare(String(b.name));
    });
  }
  function setFilter(f) { if (tableStates.devices) tableStates.devices.page = 0; filt = { platform: 'all', issue: 'all', ring: 'all', patch: 'all', pol: 'all', q: '' }; Object.keys(f).forEach(function (k) { filt[k] = f[k]; }); }
  function select(labelText, key, opts) {
    var s = h('select', { on: { change: function () { filt[key] = s.value; renderDeviceRows(true); } } }, opts.map(function (o) {
      return h('option', { value: o[0], text: o[1], selected: filt[key] === o[0] });
    }));
    return h('label', null, [labelText, s]);
  }
  var rowsHost = null, countHost = null, filterHost = null;
  function renderFilterChips() {
    if (!filterHost) return;
    clear(filterHost);
    var names = { platform: 'Platform', issue: 'Issue', ring: 'Ring', patch: 'Update status', pol: 'Policy', q: 'Search' };
    Object.keys(FILT0).forEach(function (key) {
      if (filt[key] === FILT0[key]) return;
      var value = key === 'issue' ? (ISSUE[filt[key]] ? ISSUE[filt[key]].label : 'Has an issue') : key === 'patch' ? LABEL[filt[key]] : key === 'pol' ? polName(filt[key]) : key === 'ring' ? (filt[key] === 'none' ? 'Not in a ring' : filt[key] === 'multi' ? 'More than one ring' : (ringById(filt[key]) || {}).name || filt[key]) : filt[key];
      filterHost.appendChild(h('button', { type: 'button', class: 'ps-filter-chip', text: names[key] + ': ' + value + ' ×', 'aria-label': 'Remove ' + names[key].toLowerCase() + ' filter', on: { click: function () { filt[key] = FILT0[key]; if (tableStates.devices) tableStates.devices.page = 0; render(); } } }));
    });
    if (filterHost.children.length) filterHost.appendChild(h('button', { type: 'button', text: 'Reset filters', on: { click: function () { setFilter({}); if (tableStates.devices) tableStates.devices.page = 0; render(); } } }));
  }
  function deviceRows(list) {
    return table(['Device', 'User', 'Platform', 'Compliance', 'Last check-in', 'Issues'], list.map(function (d) {
      return [nameCell(d), userCell(d), h('td', null, [d.platform, h('small', { class: 'ps-mono', text: isWin(d) ? shortBuild(d.os) : d.os })]),
        h('td', null, [label(COMPLIANCE, d.compliance), d.failing && d.failing.length ? h('small', { text: 'Fails ' + d.failing.map(function (x) { return polName(x[0]); }).join(', ') }) : null]),
        syncCell(d.lastSync), h('td', null, [chips(issuesOf(d))])];
    }), { controls: true, key: 'devices', label: 'Devices', order: 'most issues first', empty: snap.devicesOk ? 'No devices match these filters' : 'No device reading' });
  }
  function renderDeviceRows(resetPage) {
    if (!rowsHost) return;
    if (resetPage && tableStates.devices) tableStates.devices.page = 0;
    var list = filtered();
    renderFilterChips();
    countHost.textContent = snap.devicesOk ? n(list.length) + ' of ' + n(devices().length) + ' devices' : '';
    syncHash();
    clear(rowsHost);
    rowsHost.appendChild(deviceRows(list));
  }
  function devicesView() {
    var search = h('input', { type: 'search', placeholder: 'Name, user, serial, model or build', value: filt.q, 'aria-label': 'Search devices',
      on: { input: function () { filt.q = search.value; renderDeviceRows(true); } } });
    countHost = h('p', { class: 'ps-count' });
    filterHost = h('div', { class: 'ps-active-filters', 'aria-label': 'Active device filters' });
    rowsHost = h('div');
    var plats = [['all', 'All platforms']].concat(platforms().map(function (p) { return [p.name, p.name + ' (' + n(p.list.length) + ')']; }));
    if (!plats.some(function (o) { return o[0] === filt.platform; })) filt.platform = 'all';   // a shared link to a platform with no devices now
    var iss = [['all', 'Any state'], ['any', 'Has an issue']].concat(Object.keys(ISSUE).map(function (k) { return [k, ISSUE[k].label]; }));
    var rings = [['all', 'All devices']];
    if (ringsKnown()) {
      var multi = wins().filter(function (d) { return d.ring === 'multi'; }).length;
      rings = rings.concat((snap.rings || []).filter(function (r) { return r.members > 0; }).map(function (r) { return [r.id, r.name + ' (' + n(r.members) + ')']; }),
        [['none', 'Not in a ring (' + n(wins().filter(function (d) { return d.ring === 'none'; }).length) + ')']], multi ? [['multi', 'More than one ring (' + n(multi) + ')']] : []);
    }
    if (!rings.some(function (o) { return o[0] === filt.ring; })) filt.ring = 'all';   // a link to a ring that is gone, or membership unknown now
    var pols = [['all', 'Any policy']].concat((snap.policies || []).map(function (pp) {
      return [pp.id, pp.name, devices().filter(function (d) { return failsPolicy(d, pp.id); }).length];
    }).filter(function (o) { return o[2] > 0; }).sort(function (a, b) { return b[2] - a[2]; }).map(function (o) { return [o[0], o[1] + ' (' + n(o[2]) + ')']; }));
    if (!pols.some(function (o) { return o[0] === filt.pol; })) filt.pol = 'all';
    var p = panel('Devices in Intune', [
      h('div', { class: 'noc-filter' }, [
        select('Platform', 'platform', plats),
        select('Issue', 'issue', iss),
        select(ringsKnown() ? 'Update ring (Windows)' : 'Update ring (membership unknown)', 'ring', rings),
        pols.length > 1 ? select('Failing compliance policy', 'pol', pols) : null,
        select('Update status (Windows)', 'patch', [['all', 'All devices']].concat(['current', 'pending', 'stale', 'unknown'].map(function (k) { return [k, LABEL[k]]; }))),
        h('label', null, ['Search', search])
      ]),
      filterHost, countHost, rowsHost
    ], h('div', { class: 'ps-row-actions' }, [copyBtn('Copy link', function () { return location.href; }, true), ext('Open Intune', PORTAL.allDevices, true)]));
    var f = D.createDocumentFragment(); f.appendChild(p);
    setTimeout(renderDeviceRows, 0);
    return f;
  }

  /* ── updates (Windows) ───────────────────────────────────────────────── */
  function buildSpread() {
    var by = {};
    wins().forEach(function (d) {
      var k = d.os || 'Not reported';
      if (!by[k]) by[k] = { os: k, n: 0, st: classify(d) === 'unknown' ? 'unknown' : (d.rev >= snap.baseline.revision ? 'current' : 'behind'), rev: d.rev || 0 };
      by[k].n++;
    });
    var rows = Object.keys(by).map(function (k) { return by[k]; }).sort(function (a, b) { return b.n - a.n || b.rev - a.rev; });
    var max = rows.reduce(function (m, r) { return Math.max(m, r.n); }, 0);
    var shown = rows.slice(0, 10), rest = rows.slice(10).reduce(function (s, r) { return s + r.n; }, 0);
    return [h('div', { class: 'ps-bars' }, shown.map(function (r) {
      return h('div', { class: 'ps-bar ' + r.st }, [
        h('span', { class: 'ps-mono', text: shortBuild(r.os) }),
        h('div', { class: 'ps-track', 'aria-hidden': 'true' }, [h('div', { class: 'ps-fill', style: { width: (max ? r.n / max * 100 : 0) + '%' } })]),
        h('span', { class: 'ps-n ps-num', text: n(r.n) })
      ]);
    })),
      rest ? h('p', { class: 'noc-small', text: nn(rest, 'more device', 'more devices') + ' on ' + nn(rows.length - 10, 'other build', 'other builds') + '.' }) : null,
      h('div', { class: 'ps-legend' }, [
        h('span', null, [h('span', { class: 'ps-dot current' }), 'At or past .' + snap.baseline.revision]),
        h('span', null, [h('span', { class: 'ps-dot pending' }), 'Below the baseline']),
        h('span', null, [h('span', { class: 'ps-dot' }), 'Unrecognised'])
      ])];
  }
  function resultsText(r) {
    if (!r.results) return 'Not read';
    var k = Object.keys(r.results).sort(function (a, b) { return r.results[b] - r.results[a]; });
    return k.length ? k.map(function (x) { return n(r.results[x]) + ' ' + label(RING_STATUS, x).toLowerCase(); }).join(', ') : 'No device has reported';
  }
  function pauseText(q) { return q.paused ? 'Paused' + (q.pauseUntil ? ' until ' + day(q.pauseUntil) : '') : null; }
  function ringPanels() {
    var cols = h('div', { class: 'noc-pair' });
    if (!(snap.rings || []).length) { cols.appendChild(panel('Update rings', [empty(srcState('rings') === 'ok' ? 'Intune has no Windows update rings' : 'Update rings could not be read')])); return cols; }
    snap.rings.forEach(function (r) {
      var t = ringsKnown() ? tally(ringDevices(r)) : null, dl = ringDeadline(r);
      var p = panel(r.name, [kv([
        ['Assigned to', targetsText(r.targets)],
        ['Windows devices in the ring', r.members != null ? n(r.members) : 'Unknown · ' + (r.scopeWhy || ringsWhy())],
        ['On the current update', t && t.total ? n(t.current) + ' of ' + n(t.total) : '—'],
        ['Results reported to Intune', resultsText(r)],
        ['Quality updates', pauseText(r.quality) || (r.deferralDays ? 'Offered ' + r.deferralDays + ' days after release' : r.deferralDays === 0 ? 'Offered on release' : 'Deferral not stated')],
        ['Install deadline', r.deadlineDays != null ? r.deadlineDays + ' days after the update is offered' : 'Not set'],
        ['Restart grace', r.graceDays != null ? r.graceDays + ' days' : 'Not set'],
        ['Estimated install target', r.assigned && dl && !r.quality.paused ? day(dl.install) : '—'],
        ['Estimated restart target', r.assigned && dl && !r.quality.paused ? day(dl.restart) : '—'],
        ['Feature updates', pauseText(r.feature) || (r.feature.deferral ? 'Deferred ' + r.feature.deferral + ' days' : 'No deferral')],
        ['Changed in Intune', day(r.modified)]
      ], true)], h('span', { class: 'ps-head-acts' }, [
        snap.canEditRings ? h('button', { type: 'button', text: 'Edit ring', on: { click: function () { openRingEditor(r.id); } } }) : null,
        r.assigned && ringsKnown() && r.members ? goBtn('Devices', 'devices', { platform: 'Windows', ring: r.id }) : null]), 'ps-sec');
      p.id = 'ps-sec-ring-' + r.id;
      cols.appendChild(p);
    });
    return cols;
  }
  function ringDeviceTable(r) {
    var L = sortedPatch(ringDevices(r));
    return table(['Device', 'User', 'Build', 'Status', 'Ring result', 'Last check-in'], L.map(function (d) {
      var x = ringResult(d, r.id);
      return [nameCell(d), userCell(d), h('td', { class: 'ps-mono', text: shortBuild(d.os) }), statusCell(classify(d)),
        h('td', null, [x ? label(RING_STATUS, x.status) : 'Not reported', x && x.at ? h('small', { text: day(x.at) }) : null]), syncCell(d.lastSync)];
    }), { limit: 25, empty: 'No Windows device is in this ring' });
  }
  function updatesView() {
    var f = D.createDocumentFragment(), wl = wins(), t = tally(wl), ok = snap.devicesOk && t.total > 0;
    var inRing = wl.filter(function (d) { return d.ring && d.ring !== 'none'; }).length, rk = ringsKnown();
    var day1 = wl.filter(function (d) { return d.lastSync != null && now() - d.lastSync <= DAY; }).length;
    f.appendChild(h('div', { class: 'noc-signals' }, [
      dial('On the current update', ok ? pct(t.current, t.total) + '%' : 'Unknown', ok ? pct(t.current, t.total) : null,
        ok ? n(t.current) + ' of ' + n(t.total) + ' on .' + snap.baseline.revision + ' or later' : 'No device reading'),
      dial('Checked in within 24 h', ok ? pct(day1, t.total) + '%' : 'Unknown', ok ? pct(day1, t.total) : null, ok ? n(day1) + ' of ' + n(t.total) + ' Windows devices' : 'No device reading'),
      dial('In an update ring', ok && rk ? pct(inRing, t.total) + '%' : 'Unknown', ok && rk ? pct(inRing, t.total) : null,
        !ok ? 'No device reading' : rk ? n(inRing) + ' of ' + n(t.total) + ' Windows devices' : 'Ring membership unknown',
        rk && inRing < t.total ? goBtn('Not in a ring', 'devices', { platform: 'Windows', ring: 'none' }) : null)
    ]));
    var pending = sortedPatch(wl.filter(function (d) { return classify(d) === 'pending'; }));
    var stale = sortedPatch(wl.filter(function (d) { return classify(d) === 'stale'; }));
    f.appendChild(h('div', { class: 'noc-columns' }, [
      h('div', { class: 'noc-stack' }, [
        panel('Active patch backlog · ' + (snap.devicesOk ? n(pending.length) : 'Not read'), [
          h('p', { class: 'noc-small', text: 'Below the baseline and checked in within 7 days. Review update delivery and device details for the next step.' }),
          patchTable(pending, { key: 'patch-pending', label: 'Active patch backlog', empty: snap.devicesOk ? 'No recently reporting Windows device is behind the baseline' : 'No device reading' })
        ], goBtn('Open filtered list', 'devices', { platform: 'Windows', patch: 'pending' })),
        panel('Behind with stale check-ins · ' + (snap.devicesOk ? n(stale.length) : 'Not read'), [
          h('p', { class: 'noc-small', text: 'Last reported below the baseline, with no check-in for over 7 days or no check-in time. Confirm contact and ownership before treating the reported build as current.' }),
          patchTable(stale, { key: 'patch-stale', label: 'Stale patch check-ins', empty: snap.devicesOk ? 'No Windows device is behind with a stale check-in' : 'No device reading' })
        ], goBtn('Open filtered list', 'devices', { platform: 'Windows', patch: 'stale' })),
        panel('Build spread', snap.devicesOk ? buildSpread() : [empty('No device reading')])
      ]),
      h('aside', { class: 'noc-stack' }, [
        panel('Baseline', [kv([['Update', snap.baseline.label], ['Revision', '.' + snap.baseline.revision], ['Released', snap.baseline.released]]),
          h('p', { class: 'noc-small', text: 'Set in the hub route and changed by hand each month.' })]),
        panel('About rings', [h('p', { class: 'noc-small', text: 'Ring settings, assignments and per-device results are read from Intune at each snapshot. Membership is worked out by the hub: a Windows device is in a ring when its Intune primary user or the device itself is in an assigned group and in no excluded group. Target dates estimate release date plus deferral, deadline and grace settings. They are not device enforcement deadlines: discovery and pending-restart times are not read here.' }),
          rk ? null : h('p', { class: 'noc-small noc-tone-warn', text: ringsWhy() })])
      ])
    ]));
    var rp = ringPanels(); rp.classList.add('ps-panel-gap'); f.appendChild(rp);
    if (rk) (snap.rings || []).filter(function (r) { return r.assigned && r.members; }).forEach(function (r) {
      f.appendChild(h('div', { class: 'ps-panel-gap' }, [panel('Devices in ' + r.name, [
        h('p', { class: 'ps-count', text: nn(r.members, 'Windows device', 'Windows devices') + (r.members > 25 ? ' · 25 shown, oldest builds first' : ' · oldest builds first') }),
        ringDeviceTable(r)
      ], r.members > 25 ? goBtn('All ' + n(r.members), 'devices', { platform: 'Windows', ring: r.id }) : null)]));
    });
    return f;
  }

  /* ── compliance & security ───────────────────────────────────────────── */
  var PROT_LABEL = { totalReportedDeviceCount: 'Devices reporting', cleanDeviceCount: 'Clean', criticalFailuresDeviceCount: 'Critical failures',
    inactiveThreatAgentDeviceCount: 'Defender agent inactive', unknownStateThreatAgentDeviceCount: 'Defender state unknown',
    pendingSignatureUpdateDeviceCount: 'Signature update pending', pendingFullScanDeviceCount: 'Full scan pending', pendingQuickScanDeviceCount: 'Quick scan pending',
    pendingRestartDeviceCount: 'Restart pending', pendingManualStepsDeviceCount: 'Manual steps pending', pendingOfflineScanDeviceCount: 'Offline scan pending' };
  function verCmp(a, b) {
    var x = a.split('.'), y = b.split('.');
    for (var i = 0; i < Math.max(x.length, y.length); i++) { var d = (Number(y[i]) || 0) - (Number(x[i]) || 0); if (d) return d; }
    return 0;
  }
  function osVersions() {
    var by = {};
    devices().filter(function (d) { return !isWin(d); }).forEach(function (d) {
      var p = String(d.os || '').split('.'), k = !d.os ? '' : /android/i.test(d.platform) ? p[0] : p.slice(0, 2).join('.');
      var P = by[d.platform] = by[d.platform] || {}, r = P[k] = P[k] || { v: k, n: 0, nc: 0, quiet: 0 };
      r.n++; if (d.compliance === 'noncompliant') r.nc++; if (ageDays(d.lastSync) >= 30) r.quiet++;
    });
    return Object.keys(by).sort(function (a, b) { return a.localeCompare(b); }).map(function (k) {
      var rows = Object.keys(by[k]).map(function (v) { return by[k][v]; });
      rows.sort(function (a, b) { return !a.v ? 1 : !b.v ? -1 : verCmp(a.v, b.v); });
      return { name: k, rows: rows, total: rows.reduce(function (s, r) { return s + r.n; }, 0) };
    });
  }
  function osPanel() {
    var groups = osVersions();
    if (!groups.length) return panel('Phone, tablet and Mac OS versions', [empty(snap.devicesOk ? 'No phones, tablets or Macs in Intune' : 'No device reading')]);
    var body = [];
    groups.forEach(function (gp) {
      body.push(h('div', { class: 'ps-toolbar ps-os-h' }, [h('strong', { text: gp.name }), h('span', { class: 'noc-small', text: nn(gp.total, 'device', 'devices') }), h('span', { class: 'grow' }), goBtn('List', 'devices', { platform: gp.name })]));
      body.push(table(['Version', 'Devices', 'Not compliant', 'No check-in 30+ d'], gp.rows.map(function (r) {
        return [h('td', { class: 'ps-mono', text: r.v || 'Not reported' }), h('td', { class: 'ps-num', text: n(r.n) }),
          h('td', { class: 'ps-num' + (r.nc ? ' noc-tone-warn' : ''), text: n(r.nc) }), h('td', { class: 'ps-num', text: n(r.quiet) })];
      }), { limit: 12 }));
      if (gp.rows.length > 12) body.push(h('p', { class: 'noc-small', text: nn(gp.rows.slice(12).reduce(function (s, r) { return s + r.n; }, 0), 'more device', 'more devices') + ' on ' + nn(gp.rows.length - 12, 'older version', 'older versions') + '.' }));
    });
    body.push(h('p', { class: 'noc-small', text: 'Newest version first, as each device last reported it (Android by major version). This page sets no minimum: the Intune compliance policy decides which versions pass, and “Not compliant” counts devices failing it for any reason.' }));
    return panel('Phone, tablet and Mac OS versions', body);
  }
  function policyPanel() {
    var P = (snap.policies || []).slice().sort(function (a, b) {
      var x = a.counts ? (a.counts.nonCompliant || 0) + (a.counts.error || 0) + (a.counts.conflict || 0) : -1, y = b.counts ? (b.counts.nonCompliant || 0) + (b.counts.error || 0) + (b.counts.conflict || 0) : -1;
      return y - x || a.name.localeCompare(b.name);
    });
    function c(v, tone) { return h('td', { class: 'ps-num' + (v && tone ? ' noc-tone-' + tone : ''), text: v == null ? '—' : n(v) }); }
    var p = panel('Compliance policies', [
      table(['Policy', 'Assigned to', 'Compliant', 'Not compliant', 'Error', 'Conflict', 'Changed', ''], P.map(function (x) {
        var k = x.counts || {}, nf = devices().filter(function (d) { return failsPolicy(d, x.id); }).length;
        var note = x.builtIn ? 'Built in: checks that a compliance policy is assigned, the device is active and its user exists' : x.unlisted ? 'Reported by Intune, not in the compliance policy list' : null;
        if (x.partialCounts) note = [note, 'counts from an incomplete read'].filter(Boolean).join(' · ');
        return [h('td', null, [x.name, h('small', { text: [x.type ? label(POL_TYPE, x.type) : x.platform, note].filter(Boolean).join(' · ') })]),
          h('td', { class: 'ps-wrap', text: x.builtIn ? 'Every enrolled device' : targetsText(x.targets) }),
          c(k.compliant), c(k.nonCompliant, 'bad'), c(k.error, 'warn'), c(k.conflict, 'warn'), h('td', { text: day(x.modified) }),
          h('td', null, [nf ? goBtn('Devices', 'devices', { pol: x.id }) : null])];
      }), { empty: snap.policies ? 'Intune has no compliance policies' : 'Compliance policies could not be read' }),
      h('p', { class: 'noc-small', text: 'Counts are devices per policy from Intune’s per-device results; a device under two policies counts in both. The built-in policy is counted only over the devices not reporting compliant, so it has no compliant count. A device fails a policy when any one of its settings fails.' }),
      snap.stateSummary ? h('p', { class: 'noc-small', text: 'Intune’s tenant summary: ' + [['compliant', 'compliant'], ['nonCompliant', 'not compliant'], ['grace', 'in grace period'], ['error', 'error'], ['conflict', 'conflict'], ['unknown', 'unknown']]
        .filter(function (k) { return snap.stateSummary[k[0]] != null && (snap.stateSummary[k[0]] || k[0] === 'compliant' || k[0] === 'nonCompliant'); }).map(function (k) { return n(snap.stateSummary[k[0]]) + ' ' + k[1]; }).join(' · ') + '.' }) : null
    ], null, 'ps-sec');
    p.id = 'ps-sec-policies';
    return p;
  }
  var SET_PLATFORM = { windows10AndLater: 'Windows 10 and later', windows81AndLater: 'Windows 8.1 and later', android: 'Android device administrator',
    androidForWork: 'Android for Work', androidWorkProfile: 'Android work profile', androidEnterprise: 'Android Enterprise', androidAOSP: 'Android (AOSP)',
    iOS: 'iOS/iPadOS', macOS: 'macOS', all: 'All platforms' };
  // "AndroidDeviceOwnerCompliancePolicy.PasswordRequired" reads as "Password required"; plain names pass through.
  function settingLabel(x) {
    var t = String(x || '').split('.').pop();
    if (!/^[A-Za-z0-9]+$/.test(t) || !/[a-z][A-Z]/.test(t)) return x || 'Unnamed setting';
    t = t.replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase();
    return t.charAt(0).toUpperCase() + t.slice(1);
  }
  function settingsPanel() {
    var S = (snap.settings || []).filter(function (x) { return x.nonCompliant + x.error + x.conflict > 0; })
      .sort(function (a, b) { return (b.nonCompliant + b.error + b.conflict) - (a.nonCompliant + a.error + a.conflict) || a.setting.localeCompare(b.setting); });
    return panel('Settings devices fail', [
      table(['Setting', 'Platform', 'Not compliant', 'Error', 'Conflict', 'Compliant'], S.map(function (x) {
        var nice = settingLabel(x.setting), pl = String(x.platform || '');
        return [h('td', { class: 'ps-wrap' }, [nice, nice !== x.setting ? h('small', { class: 'ps-mono', text: x.setting }) : null]),
          h('td', { text: SET_PLATFORM[pl] || SET_PLATFORM[pl.charAt(0).toLowerCase() + pl.slice(1)] || human(pl) || '—' }),
          h('td', { class: 'ps-num' + (x.nonCompliant ? ' noc-tone-bad' : ''), text: n(x.nonCompliant) }), h('td', { class: 'ps-num', text: n(x.error) }),
          h('td', { class: 'ps-num', text: n(x.conflict) }), h('td', { class: 'ps-num', text: n(x.compliant) })];
      }), { limit: 15, empty: snap.settings ? 'No device fails a compliance setting' : 'Compliance settings could not be read' }),
      S.length > 15 ? h('p', { class: 'noc-small', text: nn(S.length - 15, 'more setting', 'more settings') + ' with failures not shown.' }) : null,
      h('p', { class: 'noc-small', text: 'Across every compliance policy, as Intune counts them. Most failures first.' })
    ]);
  }
  function securityView() {
    var f = D.createDocumentFragment(), list = devices(), wl = wins(), P = snap.protection;
    var comp = list.filter(function (d) { return d.compliance === 'compliant'; }).length;
    var enc = wl.filter(function (d) { return d.encrypted === true; }).length;
    var ok = snap.devicesOk && list.length;
    f.appendChild(h('div', { class: 'noc-signals' }, [
      dial('Compliant', ok ? pct(comp, list.length) + '%' : 'Unknown', ok ? pct(comp, list.length) : null, ok ? n(comp) + ' of ' + n(list.length) + ' devices' : 'No device reading'),
      dial('Windows encrypted', ok && wl.length ? pct(enc, wl.length) + '%' : 'Unknown', ok && wl.length ? pct(enc, wl.length) : null, ok ? n(enc) + ' of ' + n(wl.length) + ' report BitLocker on' : 'No device reading'),
      dial('Defender clean', P && P.totalReportedDeviceCount ? pct(P.cleanDeviceCount, P.totalReportedDeviceCount) + '%' : 'Unknown', P && P.totalReportedDeviceCount ? pct(P.cleanDeviceCount, P.totalReportedDeviceCount) : null,
        P ? n(P.cleanDeviceCount || 0) + ' of ' + n(P.totalReportedDeviceCount || 0) + ' reporting devices' : 'Defender summary not read')
    ]));
    var nonc = list.filter(function (d) { return d.compliance !== 'compliant' || issuesOf(d).indexOf('grace') !== -1; })
      .sort(function (a, b) { return (a.graceUntil || Infinity) - (b.graceUntil || Infinity); });
    var unenc = wl.filter(function (d) { return d.encrypted === false; }).sort(function (a, b) { return (b.lastSync || 0) - (a.lastSync || 0); });
    var low = list.filter(function (d) { return issuesOf(d).indexOf('lowdisk') !== -1; }).sort(function (a, b) { return a.freeB / a.totalB - b.freeB / b.totalB; });
    var mal = (snap.malware || []).slice().sort(function (a, b) { return (b.last || 0) - (a.last || 0); });
    var main = h('div', { class: 'noc-stack' }, [
      panel('Not reporting compliant', [table(['Device', 'User', 'Platform', 'State', 'Failing policy', 'Grace period', 'Last check-in'], nonc.map(function (d) {
        return [nameCell(d), userCell(d), h('td', { text: d.platform }), h('td', { text: label(COMPLIANCE, d.compliance) }), h('td', { class: 'ps-wrap', text: failingText(d) }),
          h('td', { text: !d.graceUntil ? '—' : d.graceUntil > now() ? 'Ends ' + day(d.graceUntil) : 'Ended ' + day(d.graceUntil) }), syncCell(d.lastSync)];
      }), { empty: snap.devicesOk ? 'Every device reports compliant' : 'No device reading' }),
        h('p', { class: 'noc-small', text: snap.failOk ? 'Failing policy is from each policy’s device results and each device’s own policy states; failing settings are from Intune’s per-setting lists, which do not name the policy.' : 'Which policy each device fails could not be read in full; a dash may hide a failure. See Sources.' })]),
      policyPanel(),
      settingsPanel(),
      panel('Windows devices not encrypted', [table(['Device', 'User', 'Build', 'Last check-in', ''], unenc.map(function (d) {
        return [nameCell(d), userCell(d), h('td', { class: 'ps-mono', text: shortBuild(d.os) }), syncCell(d.lastSync), h('td', null, [ext('Intune', PORTAL.device(d.id), true)])];
      }), { empty: snap.devicesOk ? 'Every Windows device reports encryption on' : 'No device reading' })]),
      panel('Low disk space', [table(['Device', 'User', 'Free', 'Total', 'Last check-in'], low.map(function (d) {
        return [nameCell(d), userCell(d), h('td', { class: 'ps-num', text: gb(d.freeB) + ' · ' + pct(d.freeB, d.totalB) + '%' }), h('td', { class: 'ps-num', text: gb(d.totalB) }), syncCell(d.lastSync)];
      }), { empty: snap.devicesOk ? 'No device is under 10% free' : 'No device reading' })]),
      osPanel()
    ]);
    var protPairs = P ? Object.keys(PROT_LABEL).filter(function (k) { return k in P; }).map(function (k) { return [PROT_LABEL[k], n(P[k])]; }) : [];
    var aside = h('aside', { class: 'noc-stack' }, [
      panel('Defender', P ? [kv(protPairs), h('p', { class: 'noc-small', text: 'Open a device for its own signature, scan and tamper-protection state.' })] : [h('p', { class: 'noc-small', text: 'Defender summary could not be read.' })]),
      panel('Malware detections', snap.malware ? [
        snap.malwareOverview ? h('p', { class: 'noc-small', text: n(snap.malwareOverview.devices) + ' devices currently report malware state · ' + n(countIssue('malware')) + ' report it active' }) : null,
        mal.length ? h('div', { class: 'ps-log' }, mal.slice(0, 12).map(function (m) {
          return h('div', null, [h('span', { text: m.name || 'Unnamed' }), h('span', { class: 'noc-small', text: day(m.last) }),
            h('small', null, [human(m.severity) + ' · ' + human(m.category) + (m.url ? ' · ' : ''), m.url ? h('a', { href: m.url, target: '_blank', rel: 'noopener noreferrer', text: 'Microsoft info ↗' }) : null])]);
        })) : h('p', { class: 'noc-small', text: 'No detections on record.' }),
        mal.length > 12 ? h('p', { class: 'noc-small', text: n(mal.length - 12) + ' older detections not shown.' }) : null
      ] : [h('p', { class: 'noc-small', text: 'Malware detections could not be read.' })])
    ]);
    f.appendChild(h('div', { class: 'noc-columns' }, [main, aside]));
    return f;
  }

  /* ── enrollment & autopilot ──────────────────────────────────────────── */
  function countBy(list, fn) {
    var m = {};
    list.forEach(function (x) { var k = fn(x); m[k] = (m[k] || 0) + 1; });
    return Object.keys(m).sort(function (a, b) { return m[b] - m[a]; }).map(function (k) { return [k, m[k]]; });
  }
  function entraRow(e) {
    return [h('td', null, [e.name || 'Unnamed', h('small', { text: e.os })]), h('td', { text: label(TRUST, e.trust) }),
      h('td', null, [e.lastSignIn ? ago(e.lastSignIn) : 'Never', h('small', { text: e.lastSignIn ? day(e.lastSignIn) : 'No sign-in recorded' })]),
      h('td', { text: day(e.registered) }), h('td', { text: e.enabled ? 'Enabled' : 'Disabled' }),
      h('td', null, [h('div', { class: 'ps-row-actions' }, [ext('Entra', PORTAL.entra(e.objectId, e.deviceId), true), copyBtn('Copy name', e.name, true)])])];
  }
  var ENTRA_HEAD = ['Device', 'Join type', 'Last sign-in', 'Registered', 'State', ''];
  function enrollmentView() {
    var f = D.createDocumentFragment(), list = devices(), wl = wins(), g = derive();
    f.appendChild(h('div', { class: 'ps-actions-strip' }, [ext('Intune: Windows enrollment', PORTAL.winEnroll), ext('Intune: all devices', PORTAL.allDevices), ext('Entra: devices', PORTAL.entraDevices)]));
    var gap = g.entraOk ? enrollGap() : [];
    var recent = list.filter(function (d) { return ageDays(d.enrolled) <= 14; }).sort(function (a, b) { return (b.enrolled || 0) - (a.enrolled || 0); });
    var ap = (snap.autopilot || []).slice().sort(function (a, b) { return (b.at || 0) - (a.at || 0); });
    var fails = (snap.enrollFailures || []).slice().sort(function (a, b) { return (b.at || 0) - (a.at || 0); });
    var main = h('div', { class: 'noc-stack' }, [
      panel('Active Windows PCs with no Intune record', [
        g.entraOk ? h('p', { class: 'ps-count', text: nn(gap.length, 'PC', 'PCs') + ' in Entra, joined to the domain or Entra, signed in within 30 days, with no Intune record · newest sign-in first' }) : null,
        table(ENTRA_HEAD, gap.map(entraRow), { empty: g.entraOk ? 'Every active joined Windows PC has an Intune record' : crossWhy() }),
        h('p', { class: 'noc-small', text: 'Hybrid-joined PCs enroll through the domain auto-enrollment policy or co-management. A PC here has the Entra record but never completed Intune enrollment, or its Intune record was deleted. Entra sign-in time can lag by up to 14 days. This list uses Entra only; Repair also checks AD and ManageEngine and can find additional active missing PCs.' })
      ], gap.length ? h('button', { type: 'button', text: 'Export', on: { click: function () { exportEntra(gap, 'enrollment-gap'); } } }) : null),
      apNoIntunePanel(),
      apMissingPanel(),
      panel('Autopilot deployments', [table(['Device', 'User', 'Profile', 'Result', 'Took', 'When'], ap.map(function (a) {
        return [h('td', null, [a.device || 'Unnamed', h('small', { class: 'ps-mono', text: a.serial })]), h('td', { text: a.user || '—' }),
          h('td', null, [a.profile || '—', a.esp ? h('small', { text: 'ESP: ' + a.esp }) : null]),
          h('td', null, [h('span', { class: 'noc-tone-' + (a.state === 'success' ? 'ok' : a.state === 'failure' ? 'bad' : 'info'), text: human(a.state) }), a.failure ? h('small', { text: a.failure }) : null]),
          h('td', { class: 'ps-mono', text: isoDur(a.total) }), h('td', { text: day(a.at) })];
      }), { empty: snap.autopilot ? 'No Autopilot deployments on record' : 'Autopilot deployments could not be read' })]),
      panel('Enrolled in the last 14 days', [table(['Device', 'User', 'Platform', 'How', 'Enrolled'], recent.map(function (d) {
        return [nameCell(d), userCell(d), h('td', { text: d.platform }), h('td', { text: label(ENROLL, d.enrollType) + (d.autopilot ? ' · Autopilot' : '') }), h('td', { text: day(d.enrolled) })];
      }), { empty: snap.devicesOk ? 'Nothing enrolled in the last 14 days' : 'No device reading' })])
    ]);
    var aside = h('aside', { class: 'noc-stack' }, [
      panel('How devices are enrolled', snap.devicesOk ? [kv(countBy(list, function (d) { return label(ENROLL, d.enrollType || 'unknown'); }).map(function (p) { return [p[0], n(p[1])]; }))] : [empty('No device reading')]),
      panel('Windows join and Autopilot', snap.devicesOk ? [kv(
        countBy(wl, function (d) { return label(JOIN, d.join); }).map(function (p) { return [p[0], n(p[1])]; })
          .concat([['Enrolled through Autopilot', n(wl.filter(function (d) { return d.autopilot; }).length)], ['Corporate-owned', n(wl.filter(function (d) { return d.owner === 'company'; }).length)]])
      )] : [empty('No device reading')]),
      apSummaryPanel(),
      apProfilesPanel(),
      enrollConfigPanel(),
      panel('Enrollment failures', fails.length ? [h('div', { class: 'ps-log' }, fails.slice(0, 10).map(function (x) {
        return h('div', null, [h('span', { text: x.platform + (x.os ? ' ' + x.os : '') }), h('span', { class: 'noc-small', text: day(x.at) }),
          h('small', { text: human(x.category) + (x.reason && x.reason !== x.category ? ' · ' + x.reason : '') + (x.type ? ' · ' + label(ENROLL, x.type) : '') })]);
      }))] : [h('p', { class: 'noc-small', text: snap.enrollFailures ? 'No enrollment failures on record.' : 'Enrollment failures could not be read.' })])
    ]);
    f.appendChild(h('div', { class: 'noc-columns' }, [main, aside]));
    return f;
  }
  function apRow(a) {
    return [h('td', null, [h('span', { class: 'ps-mono', text: a.serial || '—' }), h('small', { text: [a.make, a.model].filter(Boolean).join(' ') })]),
      h('td', { text: a.tag || '—' }), h('td', { text: label(AP_STATE, a.state) }), h('td', { text: label(AP_PROFILE, a.profile) }),
      h('td', null, [a.lastContact ? ago(a.lastContact) : 'Never', a.lastContact ? h('small', { text: day(a.lastContact) }) : null]),
      h('td', null, [a.serial ? copyBtn('Copy serial', a.serial, true) : null])];
  }
  function apNoIntunePanel() {
    var ok = apCrossOk(), L = ok ? apNoIntune() : [];
    var p = panel('Autopilot registrations with no Intune device', [
      ok ? h('p', { class: 'ps-count', text: nn(L.length, 'registration', 'registrations') + ' whose serial number matches no Intune device · last contact first' }) : null,
      table(['Serial', 'Group tag', 'Autopilot state', 'Profile', 'Last contact', ''], L.map(apRow), { limit: 100,
        empty: ok ? 'Every Autopilot registration has an Intune device' : !apOk() ? 'Autopilot devices could not be read' : 'The Intune device list was not read in full, so this cross-check is off' }),
      L.length > 100 ? h('p', { class: 'noc-small', text: n(L.length - 100) + ' more not shown. Export lists them all.' }) : null,
      h('p', { class: 'noc-small', text: 'Hardware that is not deployed yet, or that was reset, sold or recycled without being deregistered. Deregister retired hardware in Intune (Devices › Windows › Enrollment › Devices) so it cannot rejoin the tenant.' + (ok && apUnmatched() ? ' ' + nn(apUnmatched(), 'registration has', 'registrations have') + ' a placeholder serial number and no Intune device ID, so it cannot be matched and is not listed.' : '') })
    ], L.length ? h('button', { type: 'button', text: 'Export', on: { click: function () { exportAp(L, 'autopilot-no-intune'); } } }) : null, 'ps-sec');
    p.id = 'ps-sec-apnointune';
    return p;
  }
  function apMissingPanel() {
    var ok = apCrossOk(), L = ok ? winNotAp() : [], bad = wins().filter(function (d) { return !serialKey(d.serial); }).length;
    var p = panel('Windows devices not registered in Autopilot', [
      ok ? h('p', { class: 'ps-count', text: nn(L.length, 'Windows device', 'Windows devices') + ' in Intune with no Autopilot registration for its serial number · newest check-in first' }) : null,
      table(['Device', 'User', 'Serial', 'Enrolled', 'Last check-in', ''], L.map(function (d) {
        return [nameCell(d), userCell(d), h('td', { class: 'ps-mono', text: d.serial || '—' }), h('td', { text: day(d.enrolled) }), syncCell(d.lastSync), h('td', null, [ext('Intune', PORTAL.device(d.id), true)])];
      }), { empty: ok ? 'Every Windows device with a real serial number is registered' : !apOk() ? 'Autopilot devices could not be read' : 'The Intune device list was not read in full, so this cross-check is off' }),
      h('p', { class: 'noc-small', text: 'A reset sends these to the standard out-of-box setup instead of Autopilot. Registering needs the hardware hash from the device.' + (bad ? ' ' + nn(bad, 'Windows device has', 'Windows devices have') + ' a placeholder serial number and cannot be matched.' : '') })
    ], L.length ? h('button', { type: 'button', text: 'Export', on: { click: function () { exportDevices(L, 'windows-not-in-autopilot'); } } }) : null, 'ps-sec');
    p.id = 'ps-sec-apmissing';
    return p;
  }
  function apSummaryPanel() {
    var A = snap.apDevices;
    if (!A) return panel('Autopilot registrations', [h('p', { class: 'noc-small', text: 'Autopilot devices could not be read.' })]);
    var tags = countBy(A, function (a) { return a.tag || 'No group tag'; });
    return panel('Autopilot registrations', [kv([['Registered', n(A.length)]].concat(
      countBy(A, function (a) { return label(AP_STATE, a.state); }).map(function (x) { return [x[0], n(x[1])]; }),
      countBy(A, function (a) { return 'Profile: ' + label(AP_PROFILE, a.profile).toLowerCase(); }).map(function (x) { return [x[0], n(x[1])]; }),
      tags.slice(0, 6).map(function (x) { return ['Tag: ' + x[0], n(x[1])]; })
    )), h('p', { class: 'noc-small', text: '“Not contacted” means the device has not reached the Autopilot service; a device enrolled another way (for example domain join) stays not contacted.' })]);
  }
  function apProfilesPanel() {
    var L = snap.apProfiles;
    return panel('Deployment profiles', L ? (L.length ? [h('div', { class: 'ps-log' }, L.map(function (x) {
      return h('div', null, [h('span', { text: x.name }), h('span', { class: 'noc-small', text: label(AP_TYPE, x.type) }),
        h('small', { text: assignedText(x.targets) + (x.nameTemplate ? ' · names ' + x.nameTemplate : '') + (x.preprovision ? ' · pre-provisioning allowed' : '') + ' · changed ' + day(x.modified) })]);
    }))] : [h('p', { class: 'noc-small', text: 'No Autopilot deployment profiles.' })]) : [h('p', { class: 'noc-small', text: 'Deployment profiles could not be read.' })]);
  }
  function enrollConfigPanel() {
    var L = snap.enrollConfigs;
    return panel('Enrollment settings', L ? [h('div', { class: 'ps-log' }, L.map(function (x) {
      var dflt = !x.priority;
      return h('div', null, [h('span', { text: x.name }), h('span', { class: 'noc-small', text: label(EC_KIND, x.kind) }),
        h('small', { text: (dflt ? 'Default, applies to everyone not covered above' : 'Priority ' + x.priority + ' · ' + (x.targets && !x.targets.length ? 'not assigned' : 'assigned to ' + targetsText(x.targets))) + (x.limit != null ? ' · limit ' + x.limit + ' devices per user' : '') + ' · changed ' + day(x.modified) })]);
    })), h('p', { class: 'noc-small', text: 'Highest priority first. A user gets the highest-priority setting of each kind assigned to them.' })] : [h('p', { class: 'noc-small', text: 'Enrollment settings could not be read.' })]);
  }
  function isoDur(s) {
    var m = /^P(?:(\d+)D)?T?(?:(\d+)H)?(?:(\d+)M)?(?:([\d.]+)S)?$/.exec(String(s || ''));
    if (!m) return '—';
    var mins = (Number(m[1] || 0) * 1440) + Number(m[2] || 0) * 60 + Number(m[3] || 0) + Math.round(Number(m[4] || 0) / 60);
    return mins >= 60 ? Math.floor(mins / 60) + ' h ' + (mins % 60) + ' min' : mins + ' min';
  }

  /* ── apps ────────────────────────────────────────────────────────────── */
  var APP_TYPE = { win32LobApp: 'Windows app (Win32)', winGetApp: 'Microsoft Store app (new)', windowsMobileMSI: 'Windows MSI line-of-business app', officeSuiteApp: 'Microsoft 365 Apps',
    windowsMicrosoftEdgeApp: 'Microsoft Edge', windowsStoreApp: 'Microsoft Store app (legacy)', windowsUniversalAppX: 'Windows universal line-of-business app',
    androidManagedStoreApp: 'Managed Google Play app', androidManagedStoreWebApp: 'Managed Google Play web link', androidStoreApp: 'Android store app', androidLobApp: 'Android line-of-business app',
    iosVppApp: 'iOS volume-purchase app', iosStoreApp: 'iOS store app', iosLobApp: 'iOS line-of-business app', webApp: 'Web link',
    macOSLobApp: 'macOS line-of-business app', macOSDmgApp: 'macOS app (DMG)', macOSPkgApp: 'macOS app (PKG)', macOsVppApp: 'macOS volume-purchase app', macOSMicrosoftEdgeApp: 'Microsoft Edge for macOS', macOSOfficeSuiteApp: 'Microsoft 365 Apps for macOS' };
  var INTENT = { required: 'Required', available: 'Available', availableWithoutEnrollment: 'Available without enrollment', uninstall: 'Uninstall' };
  function appTypeText(a) { return a.type ? APP_TYPE[a.type] || human(a.type) : ''; }
  function appAssignText(a) {
    if (!a.targets) return 'Not read';
    if (!a.targets.length) return 'Not assigned';
    // An exclusion belongs to the intent it was added under, so each intent lists its own.
    var by = {}, order = [];
    a.targets.forEach(function (t) { var k = t.intent || ''; if (!by[k]) { by[k] = []; order.push(k); } by[k].push(t); });
    return order.map(function (k) {
      var T = by[k].filter(function (t) { return t.kind !== 'exclude'; }).concat(by[k].filter(function (t) { return t.kind === 'exclude'; }));
      return (INTENT[k] || (k ? human(k) : 'Assigned')) + ': ' + targetsText(T);
    }).join('; ');
  }
  function appsView() {
    var f = D.createDocumentFragment(), A = snap.apps;
    if (!A) { f.appendChild(panel('Apps', [empty('Apps could not be read' + (snap.sources.apps && snap.sources.apps.error ? ': ' + snap.sources.apps.error : ''))])); return f; }
    if (!snap.appCounts) return appsNoCounts(f, A);
    var bad = appsFailing(), sum = function (L, k) { return L.reduce(function (t, a) { return t + (a[k] || 0); }, 0); };
    f.appendChild(h('div', { class: 'noc-note', text: n(A.length) + ' apps deployed by Intune. ' + n(bad.length) + ' have failed installs: ' + nn(sum(A, 'failed'), 'failed device install', 'failed device installs') + ', ' + n(sum(A, 'pending')) + ' pending.' }));
    var sel = apv.app ? A.filter(function (a) { return a.id === apv.app; })[0] : null;
    if (apv.app && !sel) apv.app = null;                    // a link to an app that is gone
    if (sel) f.appendChild(appDetail(sel));
    var shown = [];
    var search = h('input', { type: 'search', placeholder: 'App, publisher or platform', value: apv.q, 'aria-label': 'Search apps',
      on: { input: function () { apv.q = search.value; if (tableStates.apps) tableStates.apps.page = 0; drawRows(); } } });
    var host = h('div'), cnt = h('span', { class: 'noc-small' });
    function drawRows() {
      var q2 = apv.q.trim().toLowerCase();
      var rows = (apv.all ? A : bad).filter(function (a) { return !q2 || (a.name + ' ' + a.publisher + ' ' + a.platform).toLowerCase().indexOf(q2) !== -1; })
        .slice().sort(function (a, b) { return b.failed - a.failed || b.pending - a.pending || a.name.localeCompare(b.name); });
      shown = rows;
      cnt.textContent = nn(rows.length, 'app', 'apps');
      clear(host);
      host.appendChild(table(['App', 'Platform', 'Installed', 'Failed', 'Pending', 'Not installed', 'Not applicable'], rows.map(function (a) {
        return [h('td', null, [h('button', { type: 'button', class: 'ps-link', text: a.name, on: { click: function () { apv.app = a.id; rerender(); var el = $('ps-sec-app'); if (el) el.scrollIntoView({ block: 'start' }); } } }),
          h('small', { text: [a.publisher, a.version].filter(Boolean).join(' · ') })]),
          h('td', { text: a.platform || '—' }), h('td', { class: 'ps-num', text: n(a.installed) }),
          h('td', { class: 'ps-num' + (a.failed ? ' noc-tone-bad' : ''), text: n(a.failed) }), h('td', { class: 'ps-num', text: n(a.pending) }),
          h('td', { class: 'ps-num', text: n(a.notInstalled) }), h('td', { class: 'ps-num', text: n(a.notApplicable) })];
      }), { controls: true, key: 'apps', label: 'Apps', order: 'most failures first', empty: apv.all ? 'No apps match' : q2 ? 'No failing app matches' : 'No app has a failed install' }));
      syncHash();
    }
    f.appendChild(panel(apv.all ? 'Every app' : 'Apps with failed installs', [
      h('div', { class: 'ps-toolbar' }, [seg('Show', [false, true], apv.all, function (v) { return v ? 'All apps' : 'Failed installs'; }, function (v) { apv.all = v; if (tableStates.apps) tableStates.apps.page = 0; rerender(); }),
        h('label', null, [search]), h('span', { class: 'grow' }), cnt]),
      host,
      h('p', { class: 'noc-small', text: 'Device counts as Intune reports them for each app. Click an app for the devices where it did not install, with the error Intune recorded.' })
    ], h('button', { type: 'button', text: 'Export', on: { click: function () { exportApps(shown); } } })));
    drawRows();
    return f;
  }
  // Install counts not read (on the dev server Intune's report service is refused by the outbound guard):
  // the assigned-app list from Intune, with no counts and no failure list.
  function appsNoCounts(f, A) {
    var src = snap.sources.apps || {};
    apv.app = null;                                          // no per-app install list without the report
    f.appendChild(h('div', { class: 'noc-note', text: n(A.length) + ' apps assigned in Intune. Install counts could not be read' + (src.error ? ': ' + src.error : '') + '. Failed and pending installs are unknown, not zero.' }));
    var shown = [];
    var search = h('input', { type: 'search', placeholder: 'App, publisher or type', value: apv.q, 'aria-label': 'Search apps',
      on: { input: function () { apv.q = search.value; if (tableStates.apps) tableStates.apps.page = 0; drawRows(); } } });
    var host = h('div'), cnt = h('span', { class: 'noc-small' });
    function drawRows() {
      var q2 = apv.q.trim().toLowerCase();
      var rows = A.filter(function (a) { return !q2 || (a.name + ' ' + a.publisher + ' ' + appTypeText(a)).toLowerCase().indexOf(q2) !== -1; })
        .slice().sort(function (a, b) { return a.name.localeCompare(b.name); });
      shown = rows;
      cnt.textContent = nn(rows.length, 'app', 'apps');
      clear(host);
      host.appendChild(table(['App', 'Type', 'Assigned'], rows.map(function (a) {
        return [h('td', null, [a.name, h('small', { text: [a.publisher, a.version].filter(Boolean).join(' · ') })]),
          h('td', { text: appTypeText(a) || '—' }), h('td', { class: 'ps-wrap', text: appAssignText(a) })];
      }), { empty: q2 ? 'No app matches' : 'Intune has no assigned apps' }));
      syncHash();
    }
    f.appendChild(panel('Assigned apps', [
      h('div', { class: 'ps-toolbar' }, [h('label', null, [search]), h('span', { class: 'grow' }), cnt]),
      host,
      h('p', { class: 'noc-small', text: 'Apps and assignments as configured in Intune. Install results per app come only from Intune’s report service; see Sources.' })
    ], h('button', { type: 'button', text: 'Export', on: { click: function () { exportApps(shown); } } })));
    drawRows();
    return f;
  }
  function appDetail(a) {
    var host = h('div', null, [h('p', { class: 'ps-loading', text: 'Reading install results for every device…' })]);
    var p = panel(a.name, [
      kv([['Publisher', a.publisher], ['Platform', a.platform], ['Type', appTypeText(a)], ['Version', a.version], ['Assigned', appAssignText(a)],
        ['Installed', n(a.installed)], ['Failed', n(a.failed)], ['Pending', n(a.pending)], ['Not installed', n(a.notInstalled)]]),
      host
    ], h('button', { type: 'button', class: 'sm', text: 'Close', on: { click: function () { apv.app = null; rerender(); } } }), 'ps-sec');
    p.id = 'ps-sec-app';
    loadApp(a, host);
    p.style.marginBottom = '12px';
    return p;
  }
  function loadApp(a, host) {
    var id = a.id;
    var fill = function (j) {
      if (apv.app !== id || !host.isConnected) return;
      clear(host);
      if (!j) { host.appendChild(h('p', { class: 'ps-loading', text: 'Install results could not be read for this app.' })); return; }
      if (!j.rows) { host.appendChild(h('p', { class: 'ps-loading', text: 'Install results could not be read: ' + (j.source && j.source.error || 'no rows') })); return; }
      var st = j.states || {}, keys = Object.keys(st).sort(function (x, y) { return st[y] - st[x]; });
      host.appendChild(h('p', { class: 'ps-count', text: 'Install report records: ' + keys.map(function (k) { return n(st[k]) + ' ' + (k || 'no state').toLowerCase(); }).join(' · ') + (j.source && j.source.state === 'partial' ? ' · list incomplete' : '') }));
      var unique = {};
      j.rows.forEach(function (r) { if (r.stateCode === 2 && r.deviceId) unique[r.deviceId] = true; });
      host.appendChild(h('p', { class: 'noc-small', text: 'App summary: ' + n(a.failed) + ' failed device installs at the snapshot read (' + stamp(snap.at) + '). Detail counts are report records, which can include several device/user contexts for one device and can differ from the summary. The detail read contains ' + n(Object.keys(unique).length) + ' distinct device IDs with failures; records without a device ID cannot be deduplicated reliably.' }));
      var g = derive();
      host.appendChild(table(['Device', 'User', 'State', 'Error', 'Version', 'When'], j.rows.map(function (r) {
        var dv = r.deviceId && g.byId[r.deviceId];
        return [h('td', null, [dv ? h('button', { type: 'button', class: 'ps-link', text: r.device || dv.name || 'Unnamed', on: { click: function () { openDrawer(dv.id); } } }) : (r.device || 'Unnamed'), h('small', { text: r.platform })]),
          h('td', { text: r.user || '—' }),
          h('td', null, [h('span', { class: r.stateCode === 2 ? 'noc-tone-bad' : null, text: r.state || '—' }), r.detail ? h('small', { text: r.detail }) : null]),
          h('td', { class: 'ps-mono', text: r.hex || '—' }), h('td', { class: 'ps-mono', text: r.version || '—' }), h('td', { text: day(r.at) })];
      }), { limit: 200, empty: 'Every device that has this app reports it installed' }));
      if (j.rows.length > 200) host.appendChild(h('p', { class: 'noc-small', text: n(j.rows.length - 200) + ' more not shown. Export lists them all.' }));
      host.appendChild(h('div', { class: 'ps-row-actions' }, [j.rows.length ? h('button', { type: 'button', class: 'sm', text: 'Export devices', on: { click: function () { exportAppRows(a, j.rows); } } }) : null,
        h('span', { class: 'noc-small', text: 'Installed devices are counted, not listed. Read ' + ago(j.at) + '.' })]));
    };
    if (appCache[id] && Date.now() - appCache[id].t < 120000) return fill(appCache[id].j);
    var ctl = new AbortController(), t = setTimeout(function () { ctl.abort(); }, 40000);
    fetch(APP_API + encodeURIComponent(id), { credentials: 'same-origin', headers: { Accept: 'application/json' }, signal: ctl.signal })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (j) { j = j && j.ok ? j : null; if (j && j.source && j.source.state === 'ok') appCache[id] = { t: Date.now(), j: j }; fill(j); })
      .catch(function () { fill(null); })
      .then(function () { clearTimeout(t); });
  }

  /* ── housekeeping ────────────────────────────────────────────────────── */
  // 30/60/90, then the clean-up rule's own edges (rule - 30 and rule) so "about to be removed" is one click.
  function ageSteps(rd) {
    var v = rd ? [30, 60, 90, rd - 30, rd] : [30, 60, 90, 180];
    return v.filter(function (x, i) { return x >= 30 && v.indexOf(x) === i; }).sort(function (a, b) { return a - b; });
  }
  function rerender() { var y = window.scrollY; render(); window.scrollTo(0, y); }
  function housekeepingView() {
    var f = D.createDocumentFragment(), g = derive(), rd = ruleDays();
    f.appendChild(h('div', { class: 'ps-actions-strip' }, [copyBtn('Copy link to this view', function () { return location.href; })]));
    f.appendChild(h('div', { class: 'noc-note', text: 'Nothing on this page deletes or retires a device. Each row opens the record in Intune or Entra, where the action is taken and audited. Check Last check-in before removing anything: a laptop in a drawer is not a lost laptop.' }));

    // 1. Intune devices that stopped checking in
    var quiet = intuneQuiet(hk.intuneAge);
    // Same edges as the overview dial (within 7 x 24 h) and the 30+ / 90+ lists, so the numbers agree across views.
    var buckets = [
      [function (d) { return d.lastSync != null && now() - d.lastSync <= STALE_MS; }, 'Within 7 days', 'var(--gr-dot)'],
      [function (d) { return d.lastSync != null && now() - d.lastSync > STALE_MS && ageDays(d.lastSync) < 30; }, '7 to 30 days', 'var(--cy)'],
      [function (d) { var a = ageDays(d.lastSync); return a >= 30 && a < 90; }, '30 to 90 days', 'var(--am-dot)'],
      [function (d) { return ageDays(d.lastSync) >= 90; }, '90 days or more, or never', 'var(--rd-dot)']];
    var all = devices(), counts = buckets.map(function (b) { return all.filter(b[0]).length; });
    var bar = h('div', { class: 'ps-stack', role: 'img', 'aria-label': snap.devicesOk ? buckets.map(function (b, i) { return b[1] + ' ' + counts[i]; }).join(', ') : 'No device reading' },
      counts.map(function (v, i) { return v ? h('span', { style: { width: (v / all.length * 100) + '%', background: buckets[i][2] } }) : null; }));
    var legend = h('div', { class: 'ps-legend' }, buckets.map(function (b, i) { return h('span', null, [h('span', { class: 'ps-dot', style: { background: b[2] } }), b[1] + ' · ' + (snap.devicesOk ? n(counts[i]) : '—')]); }));
    f.appendChild(panel('Intune devices that stopped checking in', [
      bar, legend,
      h('div', { class: 'ps-toolbar ps-panel-gap' }, [seg('No check-in for', ageSteps(rd), hk.intuneAge, function (v) { return v + '+ days'; }, function (v) { hk.intuneAge = v; rerender(); }),
        h('span', { class: 'grow' }), h('span', { class: 'noc-small', text: snap.devicesOk ? nn(quiet.length, 'device', 'devices') + ' · oldest first' : '' })]),
      table(['Device', 'User', 'Platform', 'Last check-in', 'Clean-up rule', ''], quiet.map(function (d) {
        var a = ageDays(d.lastSync), left = rd && d.lastSync != null ? rd - a : null;
        return [nameCell(d), userCell(d), h('td', { text: d.platform }), syncCell(d.lastSync),
          h('td', { class: left != null && left <= 30 ? 'noc-tone-warn' : null, text: d.lastSync == null ? 'No check-in on record' : left == null ? '—' : left > 0 ? 'Removed in ' + left + ' d' : 'Past the rule (' + rd + ' d)' }),
          h('td', null, [ext('Intune', PORTAL.device(d.id), true)])];
      }), { empty: snap.devicesOk ? 'Every device checked in within ' + hk.intuneAge + ' days' : 'No device reading' }),
      h('p', { class: 'noc-small', text: rd ? 'Intune clean-up rule: devices that do not check in for ' + rd + ' days are removed automatically (' + (snap.cleanupRule.platform === 'all' ? 'all platforms' : human(snap.cleanupRule.platform)) + ', last changed ' + day(snap.cleanupRule.modified) + ').' : 'The Intune clean-up rule could not be read.' })
    ], h('button', { type: 'button', text: 'Export', on: { click: function () { exportDevices(quiet, 'intune-no-checkin-' + hk.intuneAge + 'd'); } } })));

    // 2. Devices whose primary user has left
    var goneOk = snap.devicesOk && usersOk(), gone = goneOk ? departedList() : [];
    var goneP = panel('Devices assigned to people who have left', [
      goneOk ? h('p', { class: 'ps-count', text: nn(gone.length, 'device', 'devices') + ' whose primary user is disabled or no longer in Entra · newest check-in first' }) : null,
      table(['Device', 'Primary user', 'Account', 'Last check-in', 'Last seen signed in', ''], gone.map(function (d) {
        return [nameCell(d), userCell(d), h('td', { class: 'noc-tone-warn', text: ACCT[d.userState] }), syncCell(d.lastSync),
          h('td', null, [signedInBy(d), d.lastLogon ? h('small', { text: day(d.lastLogon) }) : null]), h('td', null, [ext('Intune', PORTAL.device(d.id), true)])];
      }), { empty: goneOk ? 'Every primary user still has an enabled account' : !snap.devicesOk ? 'No device reading' : 'Entra users could not be read' }),
      h('p', { class: 'noc-small', text: 'A device still checking in is probably with someone: recover it, or change its primary user in Intune. One that stopped checking in when the person left is a recovery or retire case.' })
    ], gone.length ? h('button', { type: 'button', text: 'Export', on: { click: function () { exportDevices(gone, 'intune-primary-user-left'); } } }) : null, 'ps-sec');
    goneP.id = 'ps-sec-departed';
    f.appendChild(h('div', { class: 'ps-panel-gap' }, [goneP]));

    // 3. Duplicate records for one serial number
    var dupRows = [];
    g.dupGroups.forEach(function (grp) {
      grp.list.forEach(function (d, i) {
        dupRows.push([h('td', { class: 'ps-mono', text: i === 0 ? grp.serial : '' }), nameCell(d), userCell(d), syncCell(d.lastSync), h('td', { text: day(d.enrolled) }),
          h('td', { class: i === 0 ? 'noc-tone-ok' : 'noc-tone-warn', text: i === 0 ? 'Newest check-in' : 'Older record' }), h('td', null, [ext('Intune', PORTAL.device(d.id), true)])]);
      });
    });
    f.appendChild(h('div', { class: 'ps-panel-gap' }, [panel('Duplicate Intune records', [
      h('p', { class: 'ps-count', text: g.dupGroups.length ? nn(g.dupGroups.length, 'serial number', 'serial numbers') + ' with more than one record · ' + nn(Object.keys(g.dupOld).length, 'older record', 'older records') : 'Grouped by serial number' }),
      table(['Serial', 'Device', 'User', 'Last check-in', 'Enrolled', 'Record', ''], dupRows, { empty: snap.devicesOk ? 'No serial number has more than one record' : 'No device reading' }),
      h('p', { class: 'noc-small', text: 'Usually a device that was reset or re-enrolled, leaving its old record behind. Placeholder serials (for example “Default string”) are ignored.' })
    ], dupRows.length ? h('button', { type: 'button', text: 'Export', on: { click: function () {
      var rows = []; g.dupGroups.forEach(function (grp) { grp.list.forEach(function (d, i) { rows.push(d); d._rec = i === 0 ? 'Newest check-in' : 'Older record'; }); });
      exportDevices(rows, 'intune-duplicates', true);
    } } }) : null)]));

    // 4. Windows PCs signed in to by someone other than the primary user
    var mm = mismatched();
    var mmP = panel('Primary user is not who signs in', [
      snap.devicesOk ? h('p', { class: 'ps-count', text: nn(mm.length, 'Windows PC', 'Windows PCs') + ' where someone else was signed in at a check-in within 30 days and the primary user was not · newest first' }) : null,
      table(['Device', 'Primary user', 'Last seen signed in', 'Seen', 'Last check-in', ''], mm.map(function (d) {
        return [nameCell(d), userCell(d), h('td', { text: signedInBy(d) }), h('td', null, [ago(d.lastLogon), h('small', { text: stamp(d.lastLogon) })]), syncCell(d.lastSync),
          h('td', null, [ext('Intune', PORTAL.device(d.id), true)])];
      }), { empty: snap.devicesOk ? 'Every Windows PC used in the last 30 days was used by its primary user' : 'No device reading' }),
      h('p', { class: 'noc-small', text: 'Usually a PC handed on without updating Intune. The pilot ring, user-targeted apps and this page’s user columns follow the primary user. Shared and loaner PCs belong here legitimately. Intune can change the primary user from the device’s Properties page.' })
    ], mm.length ? h('button', { type: 'button', text: 'Export', on: { click: function () { exportDevices(mm, 'intune-primary-user-mismatch'); } } }) : null, 'ps-sec');
    mmP.id = 'ps-sec-mismatch';
    f.appendChild(h('div', { class: 'ps-panel-gap' }, [mmP]));

    // 5. Entra device records with no Intune record
    if (!g.entraOk) {
      f.appendChild(h('div', { class: 'ps-panel-gap' }, [panel('Entra device records with no Intune record', [empty(crossWhy())])]));
    } else {
      var orphans = entraOrphans();
      if (hk.entraTrust !== 'all' && !orphans.some(function (e) { return e.trust === hk.entraTrust; })) hk.entraTrust = 'all';   // shared link, value gone
      var st = entraStale(hk.entraAge, hk.entraTrust, hk.entraState);
      var trustSel = h('select', { 'aria-label': 'Join type', on: { change: function () { hk.entraTrust = trustSel.value; hk.entraShow = 200; rerender(); } } },
        [['all', 'All join types']].concat(countBy(orphans, function (e) { return e.trust; }).map(function (p) { return [p[0], label(TRUST, p[0]) + ' (' + n(p[1]) + ')']; }))
          .map(function (o) { return h('option', { value: o[0], text: o[1], selected: hk.entraTrust === o[0] }); }));
      var stateSel = h('select', { 'aria-label': 'State', on: { change: function () { hk.entraState = stateSel.value; hk.entraShow = 200; rerender(); } } },
        [['all', 'Enabled and disabled'], ['enabled', 'Enabled only'], ['disabled', 'Disabled only']].map(function (o) { return h('option', { value: o[0], text: o[1], selected: hk.entraState === o[0] }); }));
      var shown = st.slice(0, hk.entraShow);
      f.appendChild(h('div', { class: 'ps-panel-gap' }, [panel('Entra device records with no Intune record', [
        kv([['Entra records with no Intune record', n(orphans.length)],
          ['Of those, disabled', n(orphans.filter(function (e) { return !e.enabled; }).length)],
          ['Of those, no sign-in for ' + hk.entraAge + '+ days', n(entraStale(hk.entraAge, 'all', 'all').length)]]),
        h('div', { class: 'ps-toolbar ps-panel-gap' }, [
          seg('No sign-in for', [30, 90, 180, 365], hk.entraAge, function (v) { return v === 365 ? '1 yr+' : v + '+ days'; }, function (v) { hk.entraAge = v; hk.entraShow = 200; rerender(); }),
          trustSel, stateSel, h('span', { class: 'grow' }), h('span', { class: 'noc-small', text: nn(st.length, 'record', 'records') + ' · oldest sign-in first' })]),
        table(ENTRA_HEAD, shown.map(entraRow), { empty: 'No records match' }),
        st.length > shown.length ? h('div', { class: 'ps-more' }, [h('button', { type: 'button', text: st.length - shown.length <= 500 ? 'Show the other ' + n(st.length - shown.length) : 'Show 500 more · ' + n(st.length - shown.length) + ' not shown', on: { click: function () { hk.entraShow += 500; rerender(); } } })]) : null,
        h('p', { class: 'noc-small', text: '“Registered” records come from personal or BYOD sign-ins (Workplace join) and pile up when people replace phones and PCs. Hybrid-joined records with no sign-in are often computers already removed from Active Directory. Phones and tablets managed by Intune are matched by their Entra device ID and never appear here.' })
      ], h('button', { type: 'button', text: 'Export', on: { click: function () { exportEntra(st, 'entra-no-intune-' + hk.entraAge + 'd'); } } }))]));
    }

    // 6. Remote actions
    // Without the full Intune device list a live action looks like one on a deleted device, so there is no split.
    var devOk = !!snap.devicesOk && srcState('intune') === 'ok';
    var pendAll = pendingActions(), pend = devOk ? pendAll.filter(liveAction) : pendAll, gone = devOk ? pendAll.filter(function (a) { return !liveAction(a); }) : [], recent = (snap.actions || []).filter(function (a) { return ageDays(a.at) <= 14; }).sort(function (a, b) { return (b.at || 0) - (a.at || 0); });
    function actRow(a) {
      return [h('td', { text: human(a.action) }), h('td', null, [a.device || 'Unnamed', a.owner ? h('small', { text: a.owner }) : null]),
        h('td', null, [ago(a.at), h('small', { text: stamp(a.at) })]), h('td', { text: human(a.state) }), h('td', { text: a.by || '—' }),
        h('td', null, [liveAction(a) || (!devOk && a.deviceId) ? ext('Intune', PORTAL.device(a.deviceId), true) : h('span', { class: 'noc-small', text: devOk ? 'Record gone' : '—' })])];
    }
    var ACT_HEAD = ['Action', 'Device', 'Requested', 'State', 'By', ''];
    f.appendChild(h('div', { class: 'noc-pair ps-panel-gap' }, [
      (function () {
        var shown = hk.actGone ? pend.concat(gone) : pend, kinds = {}, lim = hk.actGone ? 400 : 50;
        gone.forEach(function (a) { var k = human(a.action).toLowerCase(); kinds[k] = (kinds[k] || 0) + 1; });
        var kindTxt = Object.keys(kinds).sort(function (a, b) { return kinds[b] - kinds[a]; }).map(function (k) { return n(kinds[k]) + ' ' + k; }).join(', ');
        var p = panel('Remote actions still pending', [snap.actions ? h('p', { class: 'ps-count', text: devOk ? nn(pend.length, 'action', 'actions') + ' on devices still in Intune, not yet acknowledged · oldest first'
            : nn(pend.length, 'action', 'actions') + ' not yet acknowledged · oldest first. The Intune device list was not read in full, so these are not split by whether the device is still enrolled.' }) : null,
          table(ACT_HEAD, shown.map(actRow), { limit: lim, empty: !snap.actions ? 'Remote actions could not be read' : devOk ? 'Nothing pending on a device that is still in Intune' : 'Nothing pending' }),
          shown.length > lim ? h('p', { class: 'noc-small', text: n(shown.length - lim) + ' more not shown.' }) : null,
          gone.length ? h('p', { class: 'noc-small', text: nn(gone.length, 'more is', 'more are') + (hk.actGone ? ' listed above' : ' not listed') + ': the device is no longer in Intune (' + kindTxt + '). Intune does not close an action when the device is deleted or wiped, so these never clear.' }) : null],
          gone.length ? h('button', { type: 'button', class: 'sm', 'aria-pressed': String(!!hk.actGone), text: hk.actGone ? 'Hide gone devices' : 'Include gone devices', on: { click: function () { hk.actGone = !hk.actGone; rerender(); } } }) : null, 'ps-sec');
        p.id = 'ps-sec-actions';
        return p;
      })(),
      panel('Remote actions in the last 14 days', [table(ACT_HEAD, recent.map(actRow), { limit: 50, empty: snap.actions ? 'No remote actions in 14 days' : 'Remote actions could not be read' }),
        recent.length > 50 ? h('p', { class: 'noc-small', text: n(recent.length - 50) + ' more not shown. Intune lists them all.' }) : null])
    ]));
    return f;
  }

  /* ── sources ─────────────────────────────────────────────────────────── */
  var PERM_USE = {
    'DeviceManagementManagedDevices.Read.All': 'Devices, compliance state, hardware, Defender, discovered apps, remote-action history',
    'DeviceManagementConfiguration.Read.All': 'Update rings and ring results, compliance policies, which policy and setting a device fails',
    'DeviceManagementServiceConfig.Read.All': 'Autopilot registrations, deployment profiles, enrollment settings',
    'DeviceManagementApps.Read.All': 'App install results per app and per device, apps assigned to a device',
    'Directory.Read.All': 'Entra device records, user accounts, group names and members for ring targeting'
  };
  var LINKS = [
    ['Device in Intune', 'intune.microsoft.com/#view/Microsoft_Intune_Devices/DeviceSettingsMenuBlade/~/overview/mdmDeviceId/<id>'],
    ['Device in Entra', 'entra.microsoft.com/#view/Microsoft_AAD_Devices/DeviceDetailsMenuBlade/~/Properties/objectId/<objectId>/deviceId/<deviceId>'],
    ['Windows enrollment', PORTAL.winEnroll.replace('https://', '')],
    ['All devices', PORTAL.allDevices.replace('https://', '')],
    ['Entra devices', PORTAL.entraDevices.replace('https://', '')]
  ];
  function sourcesView(focus) {
    var f = D.createDocumentFragment();
    sourceDefs().forEach(function (s) {
      var dl = h('dl');
      s.rows.forEach(function (r) { dl.appendChild(h('dt', { text: r[0] })); dl.appendChild(h('dd', { class: r[0] === 'Request' ? 'ps-mono' : null, text: r[1] == null ? '—' : String(r[1]) })); });
      if (snap.sources[s.key] && snap.sources[s.key].error) { dl.appendChild(h('dt', { text: 'Error' })); dl.appendChild(h('dd', { text: snap.sources[s.key].error })); }
      var p = panel(s.name, [h('p', null, [h('span', { class: 'noc-tone-' + s.tone, text: s.status }), ' · ' + s.note]), dl, h('p', { class: 'noc-small', text: s.limit })],
        null, 'noc-evidence ps-src' + (focus === s.key ? ' ps-flash' : ''));
      p.id = 'ps-src-' + s.key; p.style.marginBottom = '12px';
      f.appendChild(p);
    });
    var P = snap.permissions;
    var perms = panel('Graph permissions', P ? [
      h('p', { class: 'noc-small', text: 'Read from the hub’s own Microsoft Graph token at the last refresh (' + ago(P.at) + '). The hub app is IT-Command-IdentityDiag. These are the permissions this page reads with; the app holds ' + nn(P.total, 'application permission', 'application permissions') + ' in all.' }),
      table(['Permission', 'Held', 'Used for'], P.needed.map(function (x) {
        return [h('td', { class: 'ps-mono', text: x.perm }), h('td', { class: x.held ? null : 'noc-tone-bad', text: !x.held ? 'No' : x.held === x.perm ? 'Yes' : 'Yes, as ' + x.held }), h('td', { text: PERM_USE[x.perm] || '' })];
      })),
      h('p', { class: 'noc-small', text: 'Migration register saves change shared CorpIT planning metadata only. Most other views read data only. Super-admins can edit update rings in Intune and run the pinned enrollment repair through ManageEngine on up to five eligible PCs; both actions require review and are audited by the hub. Other administrative actions open Intune or Entra and use your role there.' })
    ] : [h('p', { class: 'noc-small', text: 'The hub could not read its token’s permissions on the last refresh.' })], null, 'noc-evidence ps-src' + (focus === 'perms' ? ' ps-flash' : ''));
    perms.id = 'ps-src-perms'; perms.style.marginBottom = '12px';
    f.appendChild(perms);
    f.appendChild(panel('Portal links', [
      h('p', { class: 'noc-small', text: 'These links open the Intune or Entra admin center, which checks your own admin role. Ring edits and ManageEngine repair runs are separate in-page actions available to super-admins.' }),
      table(['Opens', 'Address'], LINKS.map(function (r) { return [h('td', { text: r[0] }), h('td', { class: 'ps-mono', text: r[1] })]; }))
    ], null, 'noc-evidence'));
    return f;
  }

  /* ── device drawer ───────────────────────────────────────────────────── */
  var lastFocus = null, drawerId = null, closeT = null;
  function reduced() { try { return window.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch (e) { return false; } }
  function openDrawer(id) {
    var d = devices().filter(function (x) { return x.id === id; })[0];
    if (!d) return;
    if (ed) return;
    clearTimeout(closeT);
    if (!drawerId) lastFocus = D.activeElement;
    drawerId = id;
    var dr = $('ps-drawer'), sc = $('ps-scrim');
    clear(dr);
    var g = derive(), e = d.aad ? g.entraById[d.aad] : null, is = issuesOf(d), ux = g.analyticsBy[d.id];
    var close = h('button', { type: 'button', class: 'ps-dr-close', 'aria-label': 'Close device details', text: '✕', on: { click: closeDrawer } });
    dr.appendChild(h('div', { class: 'ps-dr-head' }, [
      h('div', { class: 'grow' }, [h('h3', { id: 'ps-dr-h', text: d.name || 'Unnamed device' }), h('p', { text: [d.model, d.platform + (d.os ? ' ' + d.os : '')].filter(Boolean).join(' · ') })]),
      close
    ]));
    var body = h('div', { class: 'ps-dr-body' });
    body.appendChild(h('div', { class: 'ps-row-actions' }, [ext('Open in Intune', PORTAL.device(d.id)), e ? ext('Open in Entra', PORTAL.entra(e.objectId, e.deviceId)) : null,
      copyBtn('Copy name', d.name), d.serial ? copyBtn('Copy serial', d.serial) : null]));
    body.appendChild(h('div', { class: 'noc-panel' }, [h('h4', { text: 'Issues' }), chips(is)]));
    var st = isWin(d) ? classify(d) : null;
    body.appendChild(h('div', { class: 'noc-panel' }, [h('h4', { text: 'Intune record' }), kv([
      ['Primary user', d.user ? d.user + (d.userName ? ' (' + d.userName + ')' : '') : 'None'],
      d.userId ? ['Primary user account', usersOk() ? ACCT[d.userState] || '—' : 'Entra users not read'] : null,
      ['Compliance', label(COMPLIANCE, d.compliance) + (!d.graceUntil ? '' : d.graceUntil > now() ? ' · grace ends ' + day(d.graceUntil) : ' · grace ended ' + day(d.graceUntil))],
      d.failing && d.failing.length ? ['Fails', failingText(d)] : null,
      ['Last check-in', ago(d.lastSync) + ' · ' + stamp(d.lastSync)],
      ['Last seen signed in', d.lastLogon ? stamp(d.lastLogon) + ' (Intune records this at check-in, not at the moment of sign-in)' : 'Not reported'],
      isWin(d) ? ['Seen signed in', signedInBy(d)] : null,
      st ? ['Patch status', LABEL[st] + ' · build ' + shortBuild(d.os)] : null,
      isWin(d) ? ['Update ring', ringName(d, true) + ringResultsText(d)] : null,
      ['Encryption', d.encrypted == null ? 'Not reported' : d.encrypted ? 'On' : 'Off'],
      ['Storage', !d.totalB ? 'Not reported' : d.freeB > 0 ? gb(d.freeB) + ' free of ' + gb(d.totalB) : gb(d.totalB) + ' · free space not reported'],
      d.memB ? ['Memory', gb(d.memB)] : null,
      ['Enrolled', day(d.enrolled) + ' · ' + label(ENROLL, d.enrollType || 'unknown')],
      isWin(d) ? ['Join type', label(JOIN, d.join)] : null,
      isWin(d) ? ['Autopilot enrollment', d.autopilot ? 'Enrolled through Autopilot' : 'Not through Autopilot'] : null,
      isWin(d) ? ['Autopilot registration', apRegText(d)] : null,
      ['Ownership', human(d.owner)],
      ['Serial', d.serial || '—'],
      d.sku ? ['Edition', d.sku] : null,
      d.category ? ['Category', d.category] : null,
      d.patchLevel ? ['Security patch level', d.patchLevel] : null,
      d.certExp ? ['Management certificate expires', day(d.certExp)] : null,
      ['Entra record', e ? label(TRUST, e.trust) + ' · ' + (e.enabled ? 'enabled' : 'disabled') + ' · last sign-in ' + (e.lastSignIn ? day(e.lastSignIn) : 'never') : (g.entraOk ? 'Not found' : 'Not read')]
    ], true)]));
    if (d.userId) {
      var others = (g.byUser[d.userId] || []).filter(function (x) { return x.id !== d.id; }).sort(function (a, b) { return (b.lastSync || 0) - (a.lastSync || 0); });
      body.appendChild(h('div', { class: 'noc-panel' }, [h('h4', { text: 'Other devices for this primary user' }), others.length ? h('div', { class: 'ps-log' }, others.map(function (o) {
        var oi = issuesOf(o).filter(function (k) { return ISSUE[k].tone !== 'info'; });
        return h('div', null, [h('button', { type: 'button', class: 'ps-link', text: o.name || 'Unnamed', on: { click: function () { openDrawer(o.id); } } }), h('span', { class: 'noc-small', text: ago(o.lastSync) }),
          h('small', { text: [o.platform, o.model, label(COMPLIANCE, o.compliance)].filter(Boolean).join(' · ') + (oi.length ? ' · ' + oi.map(function (k) { return ISSUE[k].label; }).join(', ') : '') })]);
      })) : h('p', { class: 'noc-small', text: 'No other Intune device has this primary user.' })]));
    }
    if (ux) body.appendChild(h('div', { class: 'noc-panel' }, [h('h4', { text: 'Endpoint analytics' }), kv([
      ['Overall score', score(ux.score)], ['Startup', score(ux.startup)], ['App reliability', score(ux.apps)], ['Work from anywhere', score(ux.wfa)], ['Battery', score(ux.battery)], ['Status', human(ux.health)]
    ])]));
    var acts = g.actionsBy[d.id] || [];
    body.appendChild(h('div', { class: 'noc-panel' }, [h('h4', { text: 'Remote actions on this device' }), acts.length ? h('div', { class: 'ps-log' }, acts.slice(0, 8).map(function (a) {
      return h('div', null, [h('span', { text: human(a.action) + ' · ' + human(a.state) }), h('span', { class: 'noc-small', text: day(a.at) }), h('small', { text: 'By ' + (a.by || 'unknown') })]);
    })) : h('p', { class: 'noc-small', text: 'None on record.' })]));
    var live = h('div', { class: 'ps-dr-live' }, [h('p', { class: 'ps-loading', text: 'Reading Defender, hardware and apps from Intune…' })]);
    body.appendChild(live);
    dr.appendChild(body);
    body.scrollTop = 0;
    dr.hidden = false; sc.hidden = false;
    void dr.offsetWidth;                         // commit the closed position so the open transition runs
    dr.setAttribute('data-open', ''); sc.setAttribute('data-open', '');
    close.focus({ preventScroll: true });
    loadDetail(d, live);
  }
  function ringResultsText(d) {
    var R0 = d.ringResults || [], own = R0.length === 1 && R0[0][0] === d.ring;   // the device's own ring needs no second name
    var L = R0.map(function (x) { var r = ringById(x[0]); return (own ? '' : (r ? r.name : 'A ring') + ': ') + label(RING_STATUS, x[1]) + (x[2] ? ' ' + day(x[2]) : ''); });
    if (L.length) return ' · ' + L.join('; ');
    return (ringById(d.ring) || d.ring === 'multi') && srcState('ringResults') === 'ok' ? ' · no result reported yet' : '';
  }
  function apRegText(d) {
    var a = apFor(d);
    if (a) return 'Registered' + (a.tag ? ' · group tag ' + a.tag : ' · no group tag') + ' · profile ' + label(AP_PROFILE, a.profile).toLowerCase();
    if (!apOk()) return 'Not read';
    return serialKey(d.serial) ? 'Not registered' : 'Cannot match: placeholder serial number';
  }
  function score(v) { return v == null || v < 0 ? 'No data' : Math.round(v) + ' / 100'; }
  function closeDrawer() {
    if (!drawerId) return;
    if (drawerId === 'repair' && rpRun) {
      if (rpRun.step === 'sending') return;   // the answer is still coming; closing would hide it
      var sent = rpRun.sent, done0 = rpRun.step === 'done'; rpRun = null;
      if (sent) rp.pick = [];
      if (done0) setTimeout(function () { loadRepair(false); }, 0);   // the hub drops its cache after a run, sent or unconfirmed
    }
    if (ed && drawerId === 'ring:' + ed.id) {
      if (ed.step === 'saving') return;   // the answer is still coming; closing would hide it
      if ((ed.step === 'edit' || ed.step === 'review') && ringDiff().rows.length && !window.confirm('Discard your changes to this ring? Nothing has been sent to Intune.')) return;
      var reread = ed.saved; ed = null;
      if (reread) setTimeout(function () { load(false); }, 0);   // the hub re-reads Intune after a ring save
    }
    drawerId = null;
    var dr = $('ps-drawer'), sc = $('ps-scrim');
    dr.removeAttribute('data-open'); sc.removeAttribute('data-open');
    var done = function () { if (!drawerId) { dr.hidden = true; sc.hidden = true; clear(dr); } };
    if (reduced()) done(); else closeT = setTimeout(done, 180);
    if (lastFocus && lastFocus.isConnected) lastFocus.focus({ preventScroll: true });
  }
  function loadDetail(d, host) {
    var id = d.id;
    var fill = function (j) {
      if (drawerId !== id) return;
      clear(host);
      if (!j) { host.appendChild(h('p', { class: 'ps-loading', text: 'Device detail could not be read. The Intune record above is from the last snapshot.' })); return; }
      host.appendChild(polDetail(j));
      host.appendChild(assignedDetail(j));
      var W = j.defender;
      if (isWin(d)) host.appendChild(h('div', { class: 'noc-panel' }, [h('h4', { text: 'Defender' }), W ? kv([
        ['State', human(W.state)],
        ['Real-time protection', yn(W.realTime)], ['Tamper protection', yn(W.tamper)], ['Network protection', yn(W.network)],
        ['Signature', (W.signatureOverdue ? 'Out of date · ' : '') + (W.signature || '—')],
        ['Last quick scan', W.lastQuick ? stamp(W.lastQuick) : 'Never'], ['Last full scan', W.lastFull ? stamp(W.lastFull) : 'Never'],
        ['Restart required', yn(W.rebootRequired)], ['Engine / platform', (W.engine || '—') + ' / ' + (W.platform || '—')],
        ['Reported', W.reported ? stamp(W.reported) : '—']
      ], true) : h('p', { class: 'noc-small', text: 'Defender state could not be read for this device.' })]));
      var H = j.hardware || {};
      var hwPairs = [
        H.tpmSpecificationVersion ? ['TPM', H.tpmSpecificationVersion] : null,
        H.operatingSystemEdition ? ['Windows edition', H.operatingSystemEdition] : null,
        H.deviceGuardVirtualizationBasedSecurityState ? ['Virtualization-based security', human(H.deviceGuardVirtualizationBasedSecurityState)] : null,
        H.deviceGuardLocalSystemAuthorityCredentialGuardState ? ['Credential Guard', human(H.deviceGuardLocalSystemAuthorityCredentialGuardState)] : null,
        H.batteryLevelPercentage != null ? ['Battery level at report', H.batteryLevelPercentage + '%'] : null,
        H.batteryHealthPercentage != null ? ['Battery health', H.batteryHealthPercentage + '%'] : null,
        H.ipAddressV4 ? ['IPv4 address', H.ipAddressV4] : null,
        H.deviceFullQualifiedDomainName ? ['FQDN', H.deviceFullQualifiedDomainName] : null,
        H.systemManagementBIOSVersion ? ['BIOS', H.systemManagementBIOSVersion] : null,
        H.operatingSystemLanguage ? ['Language', H.operatingSystemLanguage] : null
      ].filter(Boolean);
      host.appendChild(h('div', { class: 'noc-panel' }, [h('h4', { text: 'Hardware inventory' }), hwPairs.length ? kv(hwPairs, true) : h('p', { class: 'noc-small', text: j.hardware ? 'Intune holds no hardware inventory for this device yet.' : 'Hardware inventory could not be read.' })]));
      var apps = j.apps;
      var appHost = h('ul', { class: 'ps-applist' }), cnt = h('p', { class: 'noc-small' });
      var q = h('input', { type: 'search', placeholder: 'Filter apps', 'aria-label': 'Filter discovered apps' });
      var draw = function () {
        clear(appHost);
        var t = q.value.trim().toLowerCase(), L = (apps || []).filter(function (a) { return !t || (a.name + ' ' + a.publisher).toLowerCase().indexOf(t) !== -1; });
        cnt.textContent = n(L.length) + ' of ' + nn((apps || []).length, 'app', 'apps');
        L.slice(0, 400).forEach(function (a) { appHost.appendChild(h('li', null, [h('span', { text: a.name || 'Unnamed' }), h('span', { text: a.version })])); });
      };
      q.addEventListener('input', draw);
      host.appendChild(h('div', { class: 'noc-panel' }, [h('h4', { text: 'Discovered apps' }), apps ? h('div', null, [q, cnt, appHost]) : h('p', { class: 'noc-small', text: 'Discovered apps could not be read.' }),
        h('p', { class: 'noc-small', text: 'Software Intune found on the device at its last inventory, not what was deployed.' })]));
      if (apps) draw();
      host.appendChild(h('p', { class: 'noc-small', text: 'Read ' + ago(j.at) + '.' }));
    };
    if (detailCache[id] && Date.now() - detailCache[id].t < 120000) return fill(detailCache[id].j);
    var ctl = new AbortController(), t = setTimeout(function () { ctl.abort(); }, 30000);
    fetch(DEV_API + encodeURIComponent(id), { credentials: 'same-origin', headers: { Accept: 'application/json' }, signal: ctl.signal })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (j) {
        j = j && j.ok ? j : null;
        // Only a reading with every part in is kept; one Intune refused is read again on the next open.
        var whole = j && Object.keys(j.sources || {}).every(function (k) { return !j.sources[k] || j.sources[k].state === 'ok'; });
        if (whole) detailCache[id] = { t: Date.now(), j: j };
        fill(j);
      })
      .catch(function () { fill(null); })
      .then(function () { clearTimeout(t); });
  }
  function polDetail(j) {
    var P = j.policies, bad = function (x) { return x.code !== 1 && x.code !== 2; };
    var ps = j.sources && j.sources.policies;
    if (!P) return h('div', { class: 'noc-panel' }, [h('h4', { text: 'Compliance policies' }), h('p', { class: 'noc-small', text: ps && ps.http === 429
      ? 'Compliance policies could not be read for this device: Intune is limiting how fast this server reads (TooManyRequests). Open the device again in a minute.'
      : 'Compliance policies could not be read for this device.' })]);
    return h('div', { class: 'noc-panel' }, [h('h4', { text: 'Compliance policies' }), P.length ? h('div', { class: 'ps-log' }, P.map(function (x) {
      var S = x.settings, kids = [h('span', { text: x.name }), h('span', { class: bad(x) ? 'noc-tone-bad' : 'noc-small', text: x.status || '—' })];
      if (x.at) kids.push(h('small', { text: 'Reported ' + day(x.at) }));
      if (bad(x)) kids.push(h('small', { text: S && S.length ? S.map(function (z) { return settingLabel(z.name || z.raw) + ': ' + z.status + (z.detail ? ' (' + z.detail + ')' : '') + (z.error ? ' · error ' + z.error : ''); }).join(' · ') :
        'Intune names no failing setting for this policy.' }));
      return h('div', null, kids);
    })) : h('p', { class: 'noc-small', text: 'Intune reports no compliance policy for this device.' }),
      j.failSettings && j.failSettings.length ? h('p', { class: 'noc-small', text: 'Settings this device fails, from Intune’s per-setting lists (they do not name the policy): ' +
        j.failSettings.map(function (x) { return settingLabel(x[0]) + (x[1] && x[1] !== 'Not compliant' ? ' (' + x[1] + ')' : ''); }).join(', ') + '.' }) : null]);
  }
  function assignedDetail(j) {
    var A = j.assigned, src = j.sources && j.sources.assigned;
    if (!A) return h('div', { class: 'noc-panel' }, [h('h4', { text: 'Assigned apps' }), h('p', { class: 'noc-small', text: src ? 'Assigned apps could not be read' + (src.error ? ': ' + src.error : '.') : 'Not shown: Intune lists assigned apps per primary user, and this device has none. Device-targeted apps appear under Apps.' })]);
    var rank = function (a) { return a.state === 'failed' || a.state === 'uninstallFailed' ? 0 : a.state === 'pendingInstall' ? 1 : a.state === 'installed' ? 3 : 2; };
    var L = A.slice().sort(function (a, b) { return rank(a) - rank(b) || a.name.localeCompare(b.name); });
    var bad = L.filter(function (a) { return rank(a) === 0; }).length;
    return h('div', { class: 'noc-panel' }, [h('h4', { text: 'Assigned apps' }),
      h('p', { class: 'noc-small', text: nn(L.length, 'app', 'apps') + ' assigned to the primary user on this device' + (bad ? ' · ' + n(bad) + ' failed' : '') + '.' }),
      L.length ? h('div', { class: 'ps-log' }, L.slice(0, 60).map(function (a) {
        return h('div', null, [h('span', { text: a.name || 'Unnamed app' }), h('span', { class: rank(a) === 0 ? 'noc-tone-bad' : 'noc-small', text: label(INSTALL, a.state || 'unknown') }),
          h('small', { text: [label(INTENT, a.intent || ''), a.version].filter(function (x) { return x && x !== '—'; }).join(' · ') })]);
      })) : null,
      L.length > 60 ? h('p', { class: 'noc-small', text: n(L.length - 60) + ' more not shown.' }) : null]);
  }
  function yn(v) { return v === true ? 'Yes' : v === false ? 'No' : 'Not reported'; }
  function trapFocus(e) {
    if (!drawerId || e.key !== 'Tab') return;
    var f = $('ps-drawer').querySelectorAll('button:not(:disabled), a[href], input:not(:disabled), select:not(:disabled)');
    if (!f.length) return;
    var first = f[0], last = f[f.length - 1];
    if (e.shiftKey && D.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && D.activeElement === last) { e.preventDefault(); first.focus(); }
  }

  /* ── ring editor (super-admins) ──────────────────────────────────────── */
  // Reads the ring fresh from Intune, edits a copy, shows Intune's value next to the new one,
  // and sends one save. The hub checks every value again, refuses the save if the ring changed
  // in Intune after it was read, and writes an audit row (who, when, old -> new).
  var RING_API = '/hub-api/api/patch-status/rings/', GROUP_API = '/hub-api/api/patch-status/groups?q=';
  // [Graph field, label, kind, min, max, help]. The limits are Intune's.
  var RING_EDIT = [
    ['Quality updates', [
      ['qualityUpdatesDeferralPeriodInDays', 'Deferral', 'int', 0, 30, 'Days after release before it is offered'],
      ['deadlineForQualityUpdatesInDays', 'Deadline', 'int', 0, 30, 'Days after it is offered before it installs on its own'],
      ['qualityUpdatesPaused', 'Paused', 'pause', 0, 0, 'Intune ends a pause after 35 days']]],
    ['Feature updates', [
      ['featureUpdatesDeferralPeriodInDays', 'Deferral', 'int', 0, 365, 'Days after release before it is offered'],
      ['deadlineForFeatureUpdatesInDays', 'Deadline', 'int', 0, 30, 'Days after it is offered before it installs on its own'],
      ['featureUpdatesPaused', 'Paused', 'pause', 0, 0, 'Intune ends a pause after 35 days']]],
    ['Restarts', [
      ['deadlineGracePeriodInDays', 'Grace period', 'int', 0, 7, 'Days after the deadline before a restart is forced'],
      ['postponeRebootUntilAfterDeadline', 'Restart only after the deadline', 'bool', 0, 0, 'Intune asks this as “Auto reboot before deadline”, with the opposite answer']]],
    ['Active hours', [
      ['activeHoursStart', 'Start', 'hour', 0, 0, 'No automatic restart from this hour'], ['activeHoursEnd', 'End', 'hour', 0, 0, 'until this hour']]],
    ['What users can do', [
      ['userPauseAccess', 'Pause updates', 'access', 0, 0, ''], ['userWindowsUpdateScanAccess', 'Check for updates', 'access', 0, 0, '']]]
  ];
  var PART = { saved: 'Saved to Intune', failed: 'Failed', unchanged: 'No change', 'not sent': 'Not sent: the settings save failed first', pending: 'Not sent' };
  var ed = null;   // the open editor: { id, ring, f, err, sc0, sc, names, step, saved }
  function hh(v) { return (v < 10 ? '0' : '') + v + ':00'; }
  function ringVal(kind, v) {
    if (v == null) return 'Not set';
    if (kind === 'int') return v + (v === 1 ? ' day' : ' days');
    if (kind === 'pause') return v ? 'Paused' : 'Not paused';
    if (kind === 'bool') return v ? 'Yes' : 'No';
    if (kind === 'access') return v === 'enabled' ? 'Allowed' : v === 'disabled' ? 'Blocked' : human(v);
    if (kind === 'hour') return hh(v);
    return String(v);
  }
  function call(url, opt, ms) {
    var ctl = new AbortController(), t = setTimeout(function () { ctl.abort(); }, ms || TIMEOUT_MS);
    return fetch(url, Object.assign({ credentials: 'same-origin', headers: { Accept: 'application/json' }, signal: ctl.signal }, opt || {}))
      .then(function (r) { return r.json().catch(function () { return null; }).then(function (j) { return { http: r.status, j: j || {} }; }); },
        function (e) { return { http: 0, j: {}, timeout: !!(e && e.name === 'AbortError') }; })
      .then(function (x) { clearTimeout(t); return x; });
  }
  function readFail(x) {
    var c = x.j.error || x.j.code;
    if (x.http === 401) return 'Your session is not active. Sign in again, then reopen the ring.';
    if (x.http === 403) return 'Your account cannot open this. Only super-admins change update rings.';
    if (c === 'NOT_FOUND' || c === 'NOT_A_RING') return 'Intune has no Windows update ring with this id.';
    if (c === 'THROTTLED') return 'Intune is throttling reads right now. Try again in a minute.';
    if (x.http === 0) return x.timeout ? 'No answer from the hub within ' + TIMEOUT_MS / 1000 + ' s.' : 'Could not reach the hub.';
    return 'The ring could not be read from Intune' + (x.j.detail ? ': ' + x.j.detail : '.');
  }
  function edHead(title, sub) {
    var dr = $('ps-drawer'); clear(dr);
    var close = h('button', { type: 'button', class: 'ps-dr-close', 'aria-label': 'Close the ring editor', text: '✕', on: { click: closeDrawer } });
    dr.appendChild(h('div', { class: 'ps-dr-head' }, [h('div', { class: 'grow' }, [h('h3', { id: 'ps-dr-h', text: title }), h('p', { text: sub })]), close]));
    var body = h('div', { class: 'ps-dr-body' }), foot = h('div', { class: 'ps-dr-foot' });
    dr.appendChild(body); dr.appendChild(foot);
    return { body: body, foot: foot, close: close };
  }
  function openRingEditor(id) {
    if (!GUID_RE.test(id)) return;
    clearTimeout(closeT);
    if (!drawerId) lastFocus = D.activeElement;
    drawerId = 'ring:' + id;
    var r0 = ringById(id);
    ed = { id: id, step: 'loading', saved: false };
    var p = edHead('Edit ' + (r0 ? r0.name : 'update ring'), 'Windows update ring · nothing is sent to Intune until you save');
    p.body.appendChild(h('p', { class: 'ps-loading', text: 'Reading this ring from Intune…' }));
    var dr = $('ps-drawer'), sc = $('ps-scrim');
    dr.hidden = false; sc.hidden = false;
    void dr.offsetWidth;
    dr.setAttribute('data-open', ''); sc.setAttribute('data-open', '');
    p.close.focus({ preventScroll: true });
    readRingEd(id);
  }
  function readRingEd(id) {
    call(RING_API + encodeURIComponent(id)).then(function (x) {
      if (!ed || ed.id !== id || drawerId !== 'ring:' + id) return;
      if (x.http !== 200 || !x.j.ok || !x.j.ring) {
        ed.step = 'failed';
        var p = edHead('Edit update ring', 'Not read');
        p.body.appendChild(h('div', { class: 'noc-panel' }, [h('p', { class: 'noc-tone-bad', text: readFail(x) })]));
        p.foot.appendChild(h('span', { class: 'grow' }));
        p.foot.appendChild(h('button', { type: 'button', text: 'Try again', on: { click: function () { openRingEditor(id); } } }));
        return;
      }
      var r = x.j.ring, f = {}, names = {};
      Object.keys(r.fields).forEach(function (k) { f[k] = r.fields[k]; });
      r.targets.forEach(function (t) { if (t.groupId) names[t.groupId] = t.name || null; });
      var sc0 = {
        include: r.targets.filter(function (t) { return t.kind === 'group'; }).map(function (t) { return t.groupId; }),
        exclude: r.targets.filter(function (t) { return t.kind === 'exclude'; }).map(function (t) { return t.groupId; }),
        allUsers: r.targets.some(function (t) { return t.kind === 'allUsers'; }), allDevices: r.targets.some(function (t) { return t.kind === 'allDevices'; })
      };
      ed = { id: id, ring: r, canEdit: x.j.canEdit === true, f: f, err: {}, sc0: sc0, sc: JSON.parse(JSON.stringify(sc0)), names: names, step: 'edit', saved: ed.saved };
      drawEdit();
    });
  }
  function scopeKey(s) { return JSON.stringify([s.include.slice().sort(), s.exclude.slice().sort(), !!s.allUsers, !!s.allDevices]); }
  function gName(id) { return ed.names[id] || 'Group ' + id.slice(0, 8) + '… (name not read)'; }
  function scopeLine(s) {
    var a = [];
    if (s.allUsers) a.push('All users');
    if (s.allDevices) a.push('All devices');
    s.include.forEach(function (g) { a.push(gName(g)); });
    s.exclude.forEach(function (g) { a.push('excluding ' + gName(g)); });
    return a.length ? a.join(' · ') : 'Not assigned';
  }
  function ringDiff() {
    var rows = [], set = {}, scope = null;
    RING_EDIT.forEach(function (sec) {
      sec[1].forEach(function (fd) {
        var k = fd[0], a = ed.ring.fields[k], b = ed.f[k];
        if (a !== b) { set[k] = b; rows.push([sec[0] + ' · ' + fd[1], ringVal(fd[2], a), ringVal(fd[2], b)]); }
      });
    });
    if (ed.ring.scopeEditable && scopeKey(ed.sc) !== scopeKey(ed.sc0)) {
      scope = { include: ed.sc.include.slice(), exclude: ed.sc.exclude.slice(), allUsers: ed.sc.allUsers, allDevices: ed.sc.allDevices };
      rows.push(['Assigned to', scopeLine(ed.sc0), scopeLine(ed.sc)]);
    }
    return { rows: rows, set: set, scope: scope };
  }
  function edErrors() {
    var e = Object.keys(ed.err).filter(function (k) { return ed.err[k]; });
    if (ed.ring.activeHoursSchedule && ed.f.activeHoursStart === ed.f.activeHoursEnd) e.push('hours');
    return e;
  }
  function drawEdit() {
    ed.step = 'edit';
    var r = ed.ring;
    var p = edHead('Edit ' + r.name, 'Windows update ring · read from Intune just now · last changed in Intune ' + day(r.version ? Date.parse(r.version) : null));
    if (!ed.canEdit) {
      p.body.appendChild(h('div', { class: 'noc-panel' }, [h('p', { class: 'noc-tone-warn', text: 'Only super-admins can change update rings. Your account can read them on this page.' })]));
      return;
    }
    var foot = p.foot, note = h('span', { class: 'grow' }), go = h('button', { type: 'button', class: 'ps-go', text: 'Review changes', on: { click: drawReview } });
    function sync() {
      var d = ringDiff(), bad = edErrors();
      go.disabled = !d.rows.length || bad.length > 0;
      note.textContent = bad.length ? 'Fix the marked fields first' : d.rows.length ? (d.rows.length === 1 ? '1 change' : d.rows.length + ' changes') + ' · not sent yet' : 'No changes';
      p.body.querySelectorAll('[data-k]').forEach(function (el) {
        var k = el.getAttribute('data-k');
        if (ed.f[k] !== r.fields[k]) el.setAttribute('data-changed', ''); else el.removeAttribute('data-changed');
        if (ed.err[k]) el.setAttribute('data-bad', ''); else el.removeAttribute('data-bad');
      });
      var hw = $('ps-re-hours'); if (hw) hw.hidden = !(r.activeHoursSchedule && ed.f.activeHoursStart === ed.f.activeHoursEnd);
    }
    RING_EDIT.forEach(function (sec) {
      var grid = h('div', { class: 'ps-re-grid' }), box = h('div', { class: 'noc-panel' }, [h('h4', { text: sec[0] })]);
      if (sec[0] === 'Active hours' && !r.activeHoursSchedule) {
        box.appendChild(h('p', { class: 'noc-small', text: 'This ring does not schedule installs around active hours' + (r.installMode ? ' (install mode in Intune: ' + human(r.installMode) + ')' : '') + '. Change the install mode in Intune to use them.' }));
        p.body.appendChild(box); return;
      }
      sec[1].forEach(function (fd) { grid.appendChild(fieldFor(fd, sync)); });
      box.appendChild(grid);
      if (sec[0] === 'Active hours') box.appendChild(h('p', { id: 'ps-re-hours', class: 'noc-small noc-tone-bad', text: 'Start and end cannot be the same hour.', hidden: true }));
      p.body.appendChild(box);
    });
    p.body.appendChild(scopeBox(sync));
    foot.appendChild(note); foot.appendChild(go);
    sync();
  }
  function fieldFor(fd, sync) {
    var k = fd[0], kind = fd[2], cur = ed.ring.fields[k], v = ed.f[k], id = 'ps-re-' + k, ctl;
    var help = h('small', { text: fd[5] || '' });
    if (kind === 'int') {
      ctl = h('input', { id: id, type: 'number', inputmode: 'numeric', min: String(fd[3]), max: String(fd[4]), step: '1', value: v == null ? '' : String(v),
        on: { input: function () {
          var s = ctl.value.trim();
          if (s === '' && cur == null) { ed.f[k] = null; ed.err[k] = null; }
          else if (!/^\d+$/.test(s) || Number(s) < fd[3] || Number(s) > fd[4]) { ed.err[k] = 'A whole number from ' + fd[3] + ' to ' + fd[4]; }
          else { ed.f[k] = Number(s); ed.err[k] = null; }
          help.textContent = ed.err[k] || fd[5]; help.className = ed.err[k] ? 'noc-tone-bad' : '';
          sync();
        } } });
    } else {
      var opts = kind === 'hour' ? Array.apply(null, Array(24)).map(function (_, i) { return [String(i), hh(i)]; })
        : kind === 'access' ? [['enabled', 'Allowed'], ['disabled', 'Blocked']]
        : kind === 'pause' ? [['false', 'Not paused'], ['true', 'Paused']] : [['true', 'Yes'], ['false', 'No']];
      var asText = function (x) { return x == null ? '' : String(x); };
      if (!opts.some(function (o) { return o[0] === asText(cur); })) opts.unshift([asText(cur), ringVal(kind, cur) + ' (as Intune has it)']);
      ctl = h('select', { id: id, on: { change: function () {
        var s = ctl.value;
        ed.f[k] = s === asText(cur) ? cur : kind === 'hour' ? Number(s) : kind === 'access' ? s : s === 'true';
        sync();
      } } }, opts.map(function (o) { return h('option', { value: o[0], text: o[1] }); }));
      ctl.value = asText(v);
      if (kind === 'pause') {
        var until = k === 'qualityUpdatesPaused' ? ed.ring.qualityPauseUntil : ed.ring.featurePauseUntil;
        if (cur === true && until) help.textContent = 'Paused until ' + day(Date.parse(until)) + ' · ' + fd[5];
      }
    }
    return h('div', { class: 'ps-re-field', 'data-k': k }, [h('label', { for: id, text: fd[1] }), ctl, help]);
  }
  function scopeBox(sync) {
    var r = ed.ring, box = h('div', { class: 'noc-panel' }, [h('h4', { text: 'Assigned to' })]);
    if (!r.scopeEditable) {
      box.appendChild(h('p', { text: r.targets.length ? r.targets.map(function (t) {
        var who = t.kind === 'allUsers' ? 'All users' : t.kind === 'allDevices' ? 'All devices' : t.groupId ? gName(t.groupId) : 'Another target type';
        return (t.kind === 'exclude' ? 'Excluding ' : '') + who + (t.filter ? ' (with a filter)' : '');
      }).join(' · ') : 'Not assigned' }));
      box.appendChild(h('p', { class: 'noc-small noc-tone-warn', text: 'This ring uses an assignment filter or a target type this page cannot set. Change its assignments in Intune.' }));
      return box;
    }
    var list = h('div', { class: 'ps-re-list' }), found = h('div', { class: 'ps-re-list' }), seq = 0, tmr = null, last = [];
    function inScope(g) { return ed.sc.include.indexOf(g) !== -1 || ed.sc.exclude.indexOf(g) !== -1; }
    function drawList() {
      clear(list);
      var rows = [];
      if (ed.sc.allUsers) rows.push(['allUsers', null, 'All users', 'Included']);
      if (ed.sc.allDevices) rows.push(['allDevices', null, 'All devices', 'Included']);
      ed.sc.include.forEach(function (g) { rows.push(['include', g, gName(g), 'Included']); });
      ed.sc.exclude.forEach(function (g) { rows.push(['exclude', g, gName(g), 'Excluded']); });
      if (!rows.length) list.appendChild(h('p', { class: 'noc-small noc-tone-warn', text: 'Not assigned: no device gets this ring.' }));
      rows.forEach(function (x) {
        var was = x[0] === 'allUsers' ? ed.sc0.allUsers : x[0] === 'allDevices' ? ed.sc0.allDevices : ed.sc0[x[0]].indexOf(x[1]) !== -1;
        list.appendChild(h('div', { class: 'ps-re-row' }, [
          h('span', { class: 'ps-re-tag' + (x[0] === 'exclude' ? ' exc' : ''), text: x[3] }),
          h('span', { class: 'grow' }, [x[2], was ? null : h('small', { text: 'Added · not sent yet' })]),
          h('button', { type: 'button', class: 'sm', text: 'Remove', 'aria-label': 'Remove ' + x[2], on: { click: function () {
            if (x[0] === 'allUsers') ed.sc.allUsers = false; else if (x[0] === 'allDevices') ed.sc.allDevices = false;
            else ed.sc[x[0]] = ed.sc[x[0]].filter(function (g) { return g !== x[1]; });
            drawList(); drawFound(); sync();
          } } })
        ]));
      });
      var gone = ed.sc0.include.concat(ed.sc0.exclude).filter(function (g) { return !inScope(g); });
      if (!ed.sc.allUsers && ed.sc0.allUsers) gone.push('All users');
      if (!ed.sc.allDevices && ed.sc0.allDevices) gone.push('All devices');
      if (gone.length) list.appendChild(h('p', { class: 'noc-small', text: 'Removed, not sent yet: ' + gone.map(function (g) { return GUID_RE.test(g) ? gName(g) : g; }).join(', ') }));
      var add = [];
      if (!ed.sc.allUsers) add.push(h('button', { type: 'button', class: 'sm', text: '+ All users', on: { click: function () { ed.sc.allUsers = true; drawList(); sync(); } } }));
      if (!ed.sc.allDevices) add.push(h('button', { type: 'button', class: 'sm', text: '+ All devices', on: { click: function () { ed.sc.allDevices = true; drawList(); sync(); } } }));
      if (add.length) list.appendChild(h('div', { class: 'ps-row-actions ps-re-add' }, add));
    }
    function drawFound() {
      clear(found);
      last.forEach(function (g) {
        var meta = [g.security ? 'Security group' : 'Microsoft 365 group', g.synced ? 'synced from AD' : 'cloud only', g.dynamic ? 'dynamic' : null].filter(Boolean).join(' · ');
        var pick = function (as) { return function () { ed.names[g.id] = g.name; ed.sc[as].push(g.id); drawList(); drawFound(); sync(); }; };
        found.appendChild(h('div', { class: 'ps-re-row' }, [h('span', { class: 'grow' }, [g.name || g.id, h('small', { text: meta })]),
          inScope(g.id) ? h('span', { class: 'noc-small', text: 'In the list' }) : h('button', { type: 'button', class: 'sm', text: 'Include', 'aria-label': 'Include ' + g.name, on: { click: pick('include') } }),
          inScope(g.id) ? null : h('button', { type: 'button', class: 'sm', text: 'Exclude', 'aria-label': 'Exclude ' + g.name, on: { click: pick('exclude') } })]));
      });
    }
    var q = h('input', { type: 'search', placeholder: 'Find an Entra group by name', 'aria-label': 'Find an Entra group by name', autocomplete: 'off', on: { input: function () {
      clearTimeout(tmr);
      var s = q.value.trim(), my = ++seq;
      if (s.length < 2) { last = []; drawFound(); return; }
      tmr = setTimeout(function () {
        clear(found); found.appendChild(h('p', { class: 'noc-small', text: 'Searching Entra…' }));
        call(GROUP_API + encodeURIComponent(s)).then(function (x) {
          if (my !== seq || !ed || ed.step !== 'edit') return;
          if (x.http !== 200 || !x.j.ok) { last = []; clear(found); found.appendChild(h('p', { class: 'noc-small noc-tone-bad', text: 'Group search failed' + (x.http ? ' (HTTP ' + x.http + ')' : '') + '.' })); return; }
          last = x.j.groups || [];
          drawFound();
          if (!last.length) found.appendChild(h('p', { class: 'noc-small', text: 'No Entra group matches “' + s + '”.' }));
        });
      }, 300);
    } } });
    drawList();
    box.appendChild(list);
    box.appendChild(h('div', { class: 'ps-re-search' }, [q, found]));
    box.appendChild(h('p', { class: 'noc-small', text: 'Saving replaces the ring’s whole assignment list with this one. Microsoft does not support mixing user groups and device groups across include and exclude on one ring.' }));
    return box;
  }
  function drawReview() {
    var d = ringDiff();
    if (!d.rows.length || edErrors().length) return;
    ed.step = 'review';
    var p = edHead('Review: ' + ed.ring.name, 'Check each change. Nothing has been sent to Intune yet.');
    p.body.appendChild(h('div', { class: 'noc-panel' }, [table(['Setting', 'In Intune now', 'After save'], d.rows.map(function (x) {
      return [h('td', { text: x[0] }), h('td', { class: 'ps-re-old', text: x[1] }), h('td', { text: x[2] })];
    }))]));
    var warn = [];
    if (d.scope && !d.scope.include.length && !d.scope.allUsers && !d.scope.allDevices) warn.push('After this save no device gets this ring.');
    if (d.set.qualityUpdatesPaused === true || d.set.featureUpdatesPaused === true) warn.push('A pause stops those updates on every device in the ring until it is resumed or Intune ends it after 35 days.');
    if (d.scope) warn.push('Assignments are replaced as a whole list.');
    warn.forEach(function (w) { p.body.appendChild(h('p', { class: 'noc-small noc-tone-warn', text: w })); });
    p.body.appendChild(h('p', { class: 'noc-small', text: 'The save is checked against the ring as Intune holds it at that moment. If someone changed it after you opened it, nothing is sent. The save is recorded under your name in User activity.' }));
    var back = h('button', { type: 'button', text: 'Back to edit', on: { click: function () { drawEditKeep(); } } });
    var save = h('button', { type: 'button', class: 'ps-go', text: 'Save to Intune', on: { click: function () { sendRing(d, save, back); } } });
    p.foot.appendChild(h('span', { class: 'grow', text: d.rows.length === 1 ? '1 change' : d.rows.length + ' changes' }));
    p.foot.appendChild(back); p.foot.appendChild(save);
    // Save sits where Review was: a double click on Review must not send the save.
    save.disabled = true;
    setTimeout(function () { if (ed && ed.step === 'review') save.disabled = false; }, 700);
    back.focus({ preventScroll: true });
  }
  function drawEditKeep() { drawEdit(); }   // ed.f and ed.sc keep the edits
  function sendRing(d, save, back) {
    ed.step = 'saving';
    save.disabled = true; back.disabled = true; save.textContent = 'Saving to Intune…';
    var id = ed.id, body = { version: ed.ring.version, set: d.set };
    if (d.scope) body.scope = d.scope;
    call(RING_API + encodeURIComponent(id) + '/save', { method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, body: JSON.stringify(body) }, 90000)
      .then(function (x) { if (ed && ed.id === id) drawResult(x, d); });
  }
  function drawResult(x, d) {
    var j = x.j, c = j.error || j.code, id = ed.id;
    ed.step = 'done';
    if (j.settings === 'saved' || j.scope === 'saved') ed.saved = true;
    var ok = x.http === 200 && j.ok;
    var p = edHead((ok ? 'Saved: ' : ed.saved ? 'Partly saved: ' : 'Not saved: ') + ed.ring.name, ok ? 'Intune accepted the change' : 'Read what happened below');
    var lines = [];
    if (x.http === 409) lines.push(['noc-tone-warn', 'This ring was changed in Intune after you opened it, so nothing was sent. Reopen it to start from Intune’s current values.']);
    else if (x.http === 400) lines.push(['noc-tone-bad', 'The hub refused the change' + (j.detail ? ': ' + j.detail : '.') + ' Nothing was sent.']);
    else if (x.http === 401) lines.push(['noc-tone-bad', 'Your session ended. Nothing was sent. Sign in again and reopen the ring.']);
    else if (x.http === 403) lines.push(['noc-tone-bad', 'Only super-admins can change update rings. Nothing was sent.']);
    else if (x.http === 0) lines.push(['noc-tone-warn', 'No answer from the hub. The change may or may not have reached Intune. Reopen the ring to see what Intune holds now.']);
    else if (c === 'GUARD' || c === 'INTERNAL' || !j.settings) lines.push(['noc-tone-bad', (j.detail || 'The save failed in the hub (HTTP ' + x.http + ').') + (c === 'GUARD' ? '' : ' Reopen the ring to see what Intune holds now.')]);
    var box = h('div', { class: 'noc-panel' }, lines.map(function (l) { return h('p', { class: l[0], text: l[1] }); }));
    if (j.settings) {
      var part = function (s, http, msg) { return (PART[s] || s) + (s === 'failed' ? (http ? ' (HTTP ' + http + ')' : '') + (msg ? ': ' + msg : '') : ''); };
      box.appendChild(kv([['Settings', part(j.settings, j.settingsHttp, j.settingsMessage)], ['Assignments', part(j.scope, j.scopeHttp, j.scopeMessage)]], true));
    }
    p.body.appendChild(box);
    if (j.ring) {
      var after = j.ring, rows = [];
      RING_EDIT.forEach(function (sec) { sec[1].forEach(function (fd) { if (fd[0] in d.set) rows.push([sec[0] + ' · ' + fd[1], ringVal(fd[2], after.fields[fd[0]])]); }); });
      if (d.scope) {
        after.targets.forEach(function (t) { if (t.groupId && t.name) ed.names[t.groupId] = t.name; });
        rows.push(['Assigned to', scopeLine({ include: after.targets.filter(function (t) { return t.kind === 'group'; }).map(function (t) { return t.groupId; }),
          exclude: after.targets.filter(function (t) { return t.kind === 'exclude'; }).map(function (t) { return t.groupId; }),
          allUsers: after.targets.some(function (t) { return t.kind === 'allUsers'; }), allDevices: after.targets.some(function (t) { return t.kind === 'allDevices'; }) })]);
      }
      p.body.appendChild(h('div', { class: 'noc-panel' }, [h('h4', { text: j.settings ? 'Read back from Intune after the save' : 'What Intune holds now' }), kv(rows, true)]));
    } else if (j.settings && (j.settings === 'saved' || j.scope === 'saved')) {
      p.body.appendChild(h('p', { class: 'noc-small noc-tone-warn', text: 'Saved, but the ring could not be read back. Reopen it to check what Intune holds.' }));
    }
    if (ed.saved) p.body.appendChild(h('p', { class: 'noc-small', text: 'Device results on this page update at the next Intune read, which starts when you close this.' }));
    p.foot.appendChild(h('span', { class: 'grow' }));
    if (!ok) p.foot.appendChild(h('button', { type: 'button', text: x.http === 400 ? 'Back to edit' : 'Reopen the ring', on: { click: function () {
      if (x.http === 400) { ed.step = 'edit'; drawEditKeep(); } else { var s = ed.saved; openRingEditor(id); ed.saved = s; }
    } } }));
    p.foot.appendChild(h('button', { type: 'button', class: ok ? 'ps-go' : null, text: 'Close', on: { click: closeDrawer } }));
  }

  /* ── repair (build 9) ────────────────────────────────────────────────── */
  // Windows PCs that AD, ManageEngine or Entra know and Intune does not, why, and which repair
  // can reach them. GET /repair joins the four sources on the hub; the page only filters and shows.
  // Super-admins can run the ManageEngine repair script on up to five PCs (POST /repair/run),
  // which the hub re-checks against fresh reads and audits.
  var REPAIR_API = '/hub-api/api/patch-status/repair';
  var REASON = {
    hybrid: ['Hybrid joined, not enrolled', 'warn', 'AD and Entra both have it, so the domain auto-enrollment policy should enroll it and has not. This is what the repair script fixes: it removes a stale ManageEngine MDM enrollment and runs Intune enrollment again.'],
    not_synced: ['In AD, not synced to Entra', 'warn', 'Entra Connect has not written this computer to Entra, so it cannot enroll. Check that it is in a synced OU and has a userCertificate, then wait for a sync.'],
    unsynced_ou: ['In an OU Entra Connect does not sync', 'info', 'Its OU is on Entra Connect’s exclusion list (read 2026-10-13). Enrolling it means moving it or changing the sync scope; that is a decision, not a repair.'],
    ad_disabled: ['Disabled in AD', 'info', 'A disabled computer account cannot enroll. Retire it, or enable it if it is still in use.'],
    entra_disabled: ['Disabled in Entra', 'bad', 'Its hybrid Entra record is disabled, which blocks enrollment. Enable it in Entra if the PC is in use.'],
    entra_joined: ['Entra joined, not enrolled', 'warn', 'The domain policy does not apply to an Entra-joined PC. It enrolls through the MDM user scope or Settings › Access work or school.'],
    ad_gone: ['In Entra, not in AD', 'bad', 'The AD computer object is gone. Rejoin the PC to the domain, or retire it and its Entra record.'],
    me_domain_no_ad: ['In ManageEngine as NRPI, not in AD', 'bad', 'ManageEngine still reports the domain, but AD has no computer object with this name. Rejoin the domain, or retire it.'],
    workgroup: ['Not on the domain (workgroup)', 'info', 'Not domain joined, so no automatic enrollment applies. Join it to the domain or enroll it by hand.'],
    other_domain: ['On another domain', 'info', 'ManageEngine reports a domain other than NRPI. It is outside this AD and the domain enrollment policy.'],
    me_no_domain: ['ManageEngine reports no domain', 'unknown', 'ManageEngine does not say which domain it is on, and AD and Entra have no record.'],
    unknown: ['Not known', 'unknown', 'AD or Entra was not read in full, so why it is missing cannot be said.']
  };
  var ROUTE = { me: 'ManageEngine agent installed', me_agent_gone: 'ManageEngine agent removed', none: 'Not in ManageEngine', unknown: 'ManageEngine not read' };
  var EXIT = [['0', 'Enrolled, or already healthy'], ['10', 'Stopped: not one of the pinned PCs or its device ID differs. Nothing changed.'], ['20', 'Not enrolled within 3 minutes of the repair'], ['30', 'A repair step failed']];
  var rp = { data: null, reading: false, err: null, at: 0, days: 30, reason: 'all', route: 'all', q: '', pick: [] };
  var rpRun = null;   // the open run drawer: { step, names, j }
  function loadRepair(force) {
    if (rp.reading) return;
    rp.reading = true;
    setTimeout(function () { if (view === 'repair' && rp.reading) rerenderRepair(); }, 0);   // never re-render from inside a render
    call(REPAIR_API + (force ? '?refresh=1' : ''), null, 90000).then(function (x) {
      rp.reading = false;
      if (x.http === 200 && x.j.ok && x.j.sources) { rp.data = x.j; rp.err = null; rp.at = Date.now(); rp.pick = rp.pick.filter(function (n0) { return rpRow(n0) && rpRow(n0).runnable; }); }
      else rp.err = x.http === 401 ? 'Your session is not active. Sign in again.' : x.http === 403 ? 'Your account cannot read this.' : x.http === 0 ? (x.timeout ? 'No answer from the hub within 90 s.' : 'Could not reach the hub.') : 'The hub could not build the list (HTTP ' + x.http + ').';
      if (view === 'repair') rerenderRepair();
    });
  }
  function rerenderRepair() {
    var typing = D.activeElement && /INPUT|SELECT/.test(D.activeElement.tagName) && $('ps-body').contains(D.activeElement);
    if (typing && rpHost) return drawRepairRows();
    // a rebuild replaces the Run button; keep keyboard focus there (or on Export when it is disabled)
    var wasRun = rpRunBtn && D.activeElement === rpRunBtn;
    rerender();
    if (wasRun && rpRunBtn) (rpRunBtn.disabled ? rpRunBtn.nextSibling : rpRunBtn).focus({ preventScroll: true });
  }
  function rpRow(name) { return rp.data && rp.data.rows ? rp.data.rows.filter(function (r) { return r.name === name; })[0] || null : null; }
  function rpSeen(r) {
    var A = [];
    if (r.ad && r.ad.lastLogon) A.push(['AD logon', r.ad.lastLogon]);
    if (r.me && r.me.lastContact) A.push(['ManageEngine contact', r.me.lastContact]);
    r.entra.forEach(function (e) { if (e.lastSignIn) A.push(['Entra sign-in', e.lastSignIn]); });
    return A.sort(function (a, b) { return b[1] - a[1]; })[0] || null;
  }
  function rpFiltered() {
    var q = rp.q.trim().toLowerCase();
    return (rp.data.rows || []).filter(function (r) {
      if (rp.days !== 'all' && !(r.lastSeen && ageDays(r.lastSeen) <= rp.days)) return false;
      if (rp.reason !== 'all' && r.reason !== rp.reason) return false;
      if (rp.route === 'runnable' ? !r.runnable : rp.route !== 'all' && r.route !== rp.route) return false;
      if (q && (r.name + ' ' + (r.ad ? r.ad.ou : '') + ' ' + (r.me ? r.me.user + ' ' + r.me.domain : '')).toLowerCase().indexOf(q) === -1) return false;
      return true;
    }).sort(function (a, b) { return (b.runnable ? 1 : 0) - (a.runnable ? 1 : 0) || (b.lastSeen || 0) - (a.lastSeen || 0) || a.name.localeCompare(b.name); });
  }
  function rpSrcLine(label0, s, countWord) {
    if (!s) return h('span', null, [h('span', { class: 'noc-tone-unknown', text: label0 + ': not read' })]);
    var ok = s.state === 'ok';
    return h('span', { title: s.request || '' }, [h('span', { class: ok ? 'noc-tone-ok' : 'noc-tone-bad', text: label0 + ': ' + (ok ? (s.count != null ? n(s.count) + ' ' + countWord : 'read') : STATE_WORD[s.state] || s.state) }),
      ok ? h('small', { text: ' · ' + ago(s.at) }) : h('small', { text: ' · ' + (s.error || 'no detail') })]);
  }
  var rpHost = null, rpCount = null, rpRunBtn = null;
  function repairView() {
    var f = D.createDocumentFragment(), X = rp.data;
    if (!X) {
      if (!rp.reading && !rp.err) loadRepair(false);
      f.appendChild(panel('Windows PCs not in Intune', [rp.err ? h('div', { class: 'ps-empty' }, [h('strong', { text: 'The list did not load' }), h('span', { class: 'noc-small', text: rp.err }),
        h('button', { type: 'button', text: 'Try again', on: { click: function () { rp.err = null; loadRepair(false); } } })]) : h('p', { class: 'ps-loading', text: 'Reading ManageEngine and AD, and joining them to Intune and Entra… this takes up to a minute.' })]));
      return f;
    }
    if (rp.at && Date.now() - rp.at > 5 * 60 * 1000 && !rp.reading) loadRepair(false);
    var S = X.sources || {};
    f.appendChild(h('div', { class: 'noc-source-strip ps-rp-src' }, [rpSrcLine('Intune', S.intune, 'devices'), rpSrcLine('Entra', S.entra, 'records'), rpSrcLine('ManageEngine', S.me, 'computers'), rpSrcLine('AD', S.ad, 'Windows PCs'),
      h('button', { type: 'button', class: 'sm', disabled: rp.reading, title: 'Reads ManageEngine, AD and the repair runs again. Intune and Entra come from the page\'s last read (Refresh).', text: rp.reading ? 'Reading…' : 'Read ME and AD again', on: { click: function () { loadRepair(true); } } })]));
    if (!X.rows) {
      f.appendChild(panel('Windows PCs not in Intune', [empty('The Intune device list was not read in full, so no PC can be called missing. See Sources.')]));
      return f;
    }
    f.appendChild(h('p', { class: 'noc-small', text: 'Scope: Repair combines AD, ManageEngine and Entra. Enrollment uses Entra records only. Their active-missing totals can differ; last-seen evidence and read times are shown for each source.' }));
    var R = X.rows, active = R.filter(function (r) { return r.lastSeen && ageDays(r.lastSeen) <= 30; });
    var cnt = function (L, fn) { return L.filter(fn).length; };
    // A source that was not read makes every count a lower bound; the runnable count needs all of them.
    var miss = [!X.adOk ? 'AD' : null, !X.entraOk ? 'Entra' : null, !X.meOk ? 'ManageEngine' : null].filter(Boolean);
    var low = function (v) { return n(v) + (miss.length ? '+' : ''); }, lowNote = miss.length ? 'At least: ' + miss.join(' and ') + ' not read. ' : '';
    var runnable = cnt(R, function (r) { return r.runnable; });
    f.appendChild(h('div', { class: 'noc-signals ps-rp-kpis' }, [
      rpKpi('Known Windows PCs', low(X.known), lowNote + 'In AD, ManageEngine or Entra (joined)' + (X.servers ? '; ' + nn(X.servers, 'server', 'servers') + ' left out' : '')),
      rpKpi('In Intune', low(X.inIntune), lowNote + 'Matched by Entra device ID or name'),
      rpKpi('Not in Intune, seen in 30 days', low(active.length), lowNote + n(R.length) + ' in all', 'warn'),
      miss.length || X.runStatusGap ? rpKpi('The repair script can run on', 'Not read', miss.length ? 'Needs AD, Entra and ManageEngine read in full' : 'ManageEngine’s status for a recent run was not read')
        : rpKpi('The repair script can run on', n(runnable), 'Pinned PCs with ManageEngine’s agent', runnable ? 'ok' : null)
    ]));
    if (miss.length) f.appendChild(h('div', { class: 'noc-note noc-tone-warn', text: miss.join(' and ') + (miss.length > 1 ? ' were' : ' was') +
      ' not read in full. Reasons or routes that depend on it say “Not known” instead of guessing, and no repair can be run until it reads.' }));
    if (X.runErrors && X.runErrors.length) f.appendChild(h('div', { class: 'noc-note noc-tone-warn', text: 'ManageEngine’s status was not read for ' + nn(X.runErrors.length, 'repair run', 'repair runs') + ' (' +
      X.runErrors.slice(0, 3).map(function (e) { return e.cid + ': ' + e.error; }).join('; ') + '). Those PCs show “Not read”' + (X.runStatusGap ? ', and no repair can be run until it reads, since a PC could already be queued.' : '.') }));
    // filters
    var reasons = [['all', 'Any reason']].concat(Object.keys(REASON).map(function (k) { return [k, REASON[k][0], cnt(R, function (r) { return r.reason === k; })]; })
      .filter(function (o) { return o[2]; }).map(function (o) { return [o[0], o[1] + ' (' + n(o[2]) + ')']; }));
    if (!reasons.some(function (o) { return o[0] === rp.reason; })) rp.reason = 'all';
    var routes = [['all', 'Any route'], ['runnable', 'Repair script can run (' + n(cnt(R, function (r) { return r.runnable; })) + ')']].concat(Object.keys(ROUTE).map(function (k) { return [k, ROUTE[k], cnt(R, function (r) { return r.route === k; })]; })
      .filter(function (o) { return o[2]; }).map(function (o) { return [o[0], o[1] + ' (' + n(o[2]) + ')']; }));
    var sel = function (labelText, key, opts) {
      var s = h('select', { on: { change: function () { rp[key] = s.value; drawRepairRows(); } } }, opts.map(function (o) { return h('option', { value: o[0], text: o[1], selected: rp[key] === o[0] }); }));
      return h('label', null, [labelText, s]);
    };
    var search = h('input', { type: 'search', placeholder: 'Name, OU, signed-in user or domain', value: rp.q, 'aria-label': 'Search PCs', on: { input: function () { rp.q = search.value; drawRepairRows(); } } });
    rpCount = h('p', { class: 'ps-count' }); rpHost = h('div');
    rpRunBtn = X.canRun ? h('button', { type: 'button', class: 'ps-go', on: { click: openRunDrawer } }) : null;
    var main = h('div', { class: 'noc-stack' }, [
      panel('Windows PCs not in Intune', [
        h('div', { class: 'ps-toolbar ps-panel-gap' }, [seg('Seen within', [7, 30, 90, 'all'], rp.days, function (v) { return v === 'all' ? 'Any time' : v + ' days'; }, function (v) { rp.days = v; rerender(); })]),
        h('div', { class: 'noc-filter' }, [sel('Why', 'reason', reasons), sel('Repair route', 'route', routes), h('label', null, ['Search', search])]),
        rpCount, rpHost,
        X.canRun ? null : h('p', { class: 'noc-small', text: 'Running the repair is limited to super-admins. This list is the same for everyone who can open this page.' }),
        h('p', { class: 'noc-small', text: 'Seen means the latest of AD logon (replicates within 14 days), ManageEngine agent contact and Entra sign-in (can lag 14 days). A PC with no time in any source shows only under Any time.' })
      ], h('span', { class: 'ps-head-acts' }, [rpRunBtn, h('button', { type: 'button', text: 'Export', on: { click: function () { exportRepair(rpFiltered()); } } })])),
      repairedPanel(X)
    ]);
    var aside = h('aside', { class: 'noc-stack' }, [scriptPanel(X), reasonsPanel(R)]);
    f.appendChild(h('div', { class: 'noc-columns' }, [main, aside]));
    drawRepairRows();
    return f;
  }
  function rpKpi(title, value, detail, tone) {
    return h('section', { class: 'noc-panel noc-signal ps-rp-kpi' }, [h('h3', { text: title }), h('strong', { class: 'ps-num' + (tone ? ' noc-tone-' + tone : ''), text: value }), h('p', { text: detail })]);
  }
  function drawRepairRows() {
    if (!rpHost || !rp.data || !rp.data.rows) return;
    var L = rpFiltered(), can = rp.data.canRun, LIMIT = 300;
    rpCount.textContent = nn(L.length, 'PC', 'PCs') + ' of ' + n(rp.data.rows.length) + ' not in Intune · runnable first, then most recently seen';
    if (rpRunBtn) { rpRunBtn.textContent = rp.pick.length ? 'Run repair on ' + nn(rp.pick.length, 'PC', 'PCs') + '…' : 'Run repair…'; rpRunBtn.disabled = !rp.pick.length; }
    syncHash();
    clear(rpHost);
    var head = (can ? [''] : []).concat(['PC', 'Why it is not in Intune', 'Repair route', 'Last seen', 'Last repair run']);
    rpHost.appendChild(table(head, L.slice(0, LIMIT).map(function (r) {
      var why = REASON[r.reason] || REASON.unknown, seen = rpSeen(r), lr = r.lastRun;
      var cells = [];
      if (can) {
        var picked = rp.pick.indexOf(r.name) !== -1, full = rp.pick.length >= rp.data.maxTargets;
        cells.push(h('td', { class: 'ps-rp-pick' }, [r.runnable ? h('input', { type: 'checkbox', checked: picked, disabled: !picked && full, 'aria-label': 'Select ' + r.name + ' for a repair run',
          title: !picked && full ? 'At most ' + rp.data.maxTargets + ' PCs a run' : null,
          on: { change: function (e) { if (e.target.checked) { if (rp.pick.indexOf(r.name) === -1 && rp.pick.length < rp.data.maxTargets) rp.pick.push(r.name); } else rp.pick = rp.pick.filter(function (x) { return x !== r.name; }); drawRepairRows(); } } }) : null]));
      }
      cells.push(h('td', null, [h('span', { class: 'ps-mono', text: r.name }), h('small', { text: r.ad ? r.ad.ou || 'AD' : r.me && r.me.domain ? 'ManageEngine · ' + r.me.domain : r.entra.length ? (rp.data.adOk && rp.data.meOk ? 'Entra only' : 'In Entra') : '' }),
        r.me && r.me.user ? h('small', { text: 'Signed in: ' + r.me.user }) : null]));
      cells.push(h('td', null, [h('span', { class: 'ps-chip ' + why[1], text: why[0] }), h('small', { text: rpFacts(r) })]));
      cells.push(h('td', null, [h('span', { class: r.route === 'me' ? null : r.route === 'unknown' ? 'noc-tone-unknown' : 'noc-small', text: ROUTE[r.route] || r.route }),
        h('small', { class: r.runnable ? 'noc-tone-ok' : null, text: r.route !== 'me' ? (r.me && r.route === 'me_agent_gone' ? r.me.installText + (r.me.uninstalled ? ' ' + day(r.me.uninstalled) : '') : '')
          : r.runnable ? 'Repair script can run' : r.waiting ? rpWaitText(r.blockedBy || r.lastRun) : rp.data.runStatusGap ? 'Run status not read' : !r.pin.listed ? 'Not one of the script’s pinned PCs' : !r.pin.match ? 'Pinned to a different Entra device ID'
          : r.ambiguous ? (r.me.dupes ? (r.me.dupes + 1) + ' ManageEngine records' : (r.ad.dupes + 1) + ' AD objects') + ' have this name'
          : !rp.data.adOk || !rp.data.entraOk ? 'Needs AD and Entra read in full' : !r.me.rid ? 'No ManageEngine resource ID' : '' })]));
      cells.push(h('td', null, seen ? [ago(seen[1]), h('small', { text: seen[0] })] : ['No time in any source']));
      cells.push(h('td', null, lr ? [h('span', { class: /succeeded/i.test(lr.label) ? 'noc-tone-ok' : /failed/i.test(lr.label) ? 'noc-tone-bad' : /not confirmed/i.test(lr.label) ? 'noc-tone-warn' : /not read/i.test(lr.label) ? 'noc-tone-unknown' : null, text: lr.label || 'Not read' }),
        h('small', { text: 'Sent ' + day(lr.at) + (lr.applied ? ' · ran ' + lr.applied : '') }), rpResult(lr), lr.remarks ? h('small', { class: 'ps-mono ps-rp-rem', text: lr.remarks.slice(0, 140) }) : null] : ['—']));
      return cells;
    }), { empty: 'No PC matches these filters' }));
    if (L.length > LIMIT) rpHost.appendChild(h('p', { class: 'noc-small', text: n(L.length - LIMIT) + ' more not shown. Export lists them all.' }));
  }
  function rpWaitText(lr) {
    return lr.label === 'Not read' ? 'A run sent ' + day(lr.at) + ' has no status yet' : lr.label === 'Not confirmed' ? 'ManageEngine did not confirm a run sent ' + day(lr.at) + '; check it there'
      : 'A run sent ' + day(lr.at) + ' is waiting in ManageEngine (' + lr.label + ')';
  }
  // The script's own result line when ManageEngine kept it; otherwise say plainly that it was not kept
  function rpResult(lr) {
    if (lr.result) return h('small', { class: lr.result.exit === 0 ? 'noc-tone-ok' : 'noc-tone-bad', text: 'Script exit ' + lr.result.exit + (lr.result.msg ? ': ' + lr.result.msg : '') });
    if (lr.cut) return h('small', { class: 'noc-tone-unknown', text: 'Script result not shown: ManageEngine keeps only the first 500 characters of the output, and there is no result line in them' });
    return null;
  }
  function rpFacts(r) {
    var A = [];
    if (r.ad) A.push('AD ' + (r.ad.enabled ? 'enabled' : 'disabled') + (r.ad.dupes ? ' · ' + (r.ad.dupes + 1) + ' objects' : ''));
    else if (rp.data.adOk) A.push('No AD object');
    if (r.entra.length) A.push('Entra: ' + r.entra.map(function (e) { return label(TRUST, e.trust) + (e.enabled ? '' : ' (disabled)'); }).join(', ') + (r.entraMore ? ' +' + r.entraMore : ''));
    else if (rp.data.entraOk) A.push('No Entra record');
    if (r.me && r.me.mdm) A.push('ME MDM: ' + r.me.mdm.replace(/^(dc\.)?mdm\.(db\.)?/, '').replace(/[._]/g, ' '));
    return A.join(' · ');
  }
  function repairedPanel(X) {
    var L = X.repaired || [];
    return panel('In Intune after a repair run', [
      table(['PC', 'Run', 'Result in ManageEngine', 'Enrolled in Intune'], L.map(function (x) {
        return [h('td', { class: 'ps-mono', text: x.name }), h('td', null, [day(x.run.at), h('small', { class: 'ps-mono', text: x.run.cid })]),
          h('td', { text: x.run.label || 'Not read' }), h('td', null, [x.enrolled ? day(x.enrolled) : '—', h('small', { class: x.enrolledAfterRun === false ? 'noc-tone-warn' : null,
            text: (x.enrolledAfterRun === true ? 'After this run' : x.enrolledAfterRun === false ? 'Before this run was sent' : 'No enrolment time') + ' · matched by ' + x.matchedBy })])];
      }), { empty: 'No PC that a repair run reached is in Intune yet' }),
      h('p', { class: 'noc-small', text: 'PCs sent a repair run (from this page, or the command-line runs of 13–14 Oct) that Intune now holds, with the latest run for each. Enrolled is Intune’s own date: “Before this run was sent” means the PC was already enrolled when that run reached it.' })
    ]);
  }
  function scriptPanel(X) {
    var T = X.template, Sc = X.script;
    return panel('The repair script', [kv([
      ['ManageEngine template', T.name], ['Template ID', h('span', { class: 'ps-mono', text: T.id })], ['Script build', h('span', { class: 'ps-mono', text: Sc.stamp })],
      ['SHA-256', h('span', { class: 'ps-mono ps-wrap', text: Sc.sha256 })], ['Acts on', nn(Sc.pinned, 'pinned PC', 'pinned PCs') + ', each only when its Entra device ID matches'], ['Runs as', 'SYSTEM, from ManageEngine']
    ], true), h('p', { class: 'noc-small', text: 'It removes ManageEngine’s MDM enrollment and stale enrollments left by earlier attempts, then runs Intune enrollment through the domain policy and waits up to 3 minutes. It stops without changing anything when no domain user is signed in or the tenant MDM address is blank.' }),
      h('div', { class: 'ps-log' }, EXIT.map(function (e) { return h('div', null, [h('span', { class: 'ps-mono', text: 'Exit ' + e[0] }), h('small', { text: e[1] })]); })),
      h('p', { class: 'noc-small', text: 'Adding a PC to the script is a new build, uploaded to ManageEngine by a person. This page runs only the build above.' })]);
  }
  function reasonsPanel(R) {
    return panel('Why PCs are missing', [kv(Object.keys(REASON).map(function (k) { var c = R.filter(function (r) { return r.reason === k; }).length; return c ? [REASON[k][0], n(c)] : null; })),
      h('div', { class: 'ps-log' }, Object.keys(REASON).filter(function (k) { return R.some(function (r) { return r.reason === k; }); }).map(function (k) {
        return h('div', null, [h('span', { text: REASON[k][0] }), h('small', { text: REASON[k][2] })]);
      }))]);
  }
  function exportRepair(L) {
    download('windows-not-in-intune', ['PC', 'Why', 'Next step', 'Repair route', 'Repair script can run', 'Pinned in script', 'Last seen (UTC)', 'Seen by', 'AD OU', 'AD enabled', 'AD object GUID', 'Entra records', 'ManageEngine agent', 'ManageEngine domain', 'ManageEngine signed-in user', 'ManageEngine MDM remark', 'ManageEngine resource ID', 'Last run collection', 'Last run sent (UTC)', 'Last run status', 'Last run script result', 'Blocked by run sent (UTC)'], L.map(function (r) {
      var s = rpSeen(r), why = REASON[r.reason] || REASON.unknown;
      return [r.name, why[0], why[2], ROUTE[r.route] || r.route, r.runnable ? 'Yes' : 'No', r.pin.listed ? (r.pin.match ? 'Yes' : 'Yes, different device ID') : 'No', s ? iso(s[1]) : '', s ? s[0] : '',
        r.ad ? r.ad.ou : '', r.ad ? (r.ad.enabled ? 'Yes' : 'No') : '', r.ad ? r.ad.guid : '', r.entra.map(function (e) { return label(TRUST, e.trust) + ' ' + e.deviceId + (e.enabled ? '' : ' (disabled)'); }).join('; '),
        r.me ? r.me.installText : '', r.me ? r.me.domain : '', r.me ? r.me.user : '', r.me ? r.me.mdm : '', r.me ? r.me.rid : '', r.lastRun ? r.lastRun.cid : '', r.lastRun ? iso(r.lastRun.at) : '', r.lastRun ? r.lastRun.label : '',
        r.lastRun ? (r.lastRun.result ? 'exit ' + r.lastRun.result.exit + (r.lastRun.result.msg ? ' ' + r.lastRun.result.msg : '') : r.lastRun.cut ? 'Not in the 500 characters ManageEngine keeps' : '') : '',
        r.blockedBy ? iso(r.blockedBy.at) + ' (' + r.blockedBy.label + ')' : ''];
    }));
  }
  // The run: a review step that names every PC and what happens, then one POST. The hub checks it all again.
  function rpHead(title, sub) {
    var p = edHead(title, sub);
    p.close.setAttribute('aria-label', 'Close the repair run');
    return p;
  }
  function openRunDrawer() {
    if (!rp.data || !rp.data.canRun || !rp.pick.length || ed) return;
    var rows = rp.pick.map(rpRow).filter(function (r) { return r && r.runnable; });
    if (!rows.length) return;
    clearTimeout(closeT);
    if (!drawerId) lastFocus = D.activeElement;
    drawerId = 'repair';
    rpRun = { step: 'review', names: rows.map(function (r) { return r.name; }) };
    var p = rpHead('Run the Intune repair on ' + nn(rows.length, 'PC', 'PCs'), 'Review · nothing is sent to ManageEngine until you run it');
    p.body.appendChild(h('div', { class: 'noc-panel' }, [table(['PC', 'Why it is not in Intune', 'ManageEngine', 'Last seen'], rows.map(function (r) {
      var s = rpSeen(r);
      return [h('td', null, [h('span', { class: 'ps-mono', text: r.name }), h('small', { text: r.ad ? r.ad.ou : '' })]), h('td', { text: (REASON[r.reason] || REASON.unknown)[0] }),
        h('td', null, [r.me.live ? 'Agent online' : 'Agent offline', h('small', { class: 'ps-mono', text: r.me.rid })]), h('td', { text: s ? ago(s[1]) : '—' })];
    }))]));
    p.body.appendChild(h('div', { class: 'noc-panel' }, [h('h4', { text: 'What happens' }), h('ol', { class: 'ps-rp-steps' }, [
      h('li', { text: 'The hub reads ManageEngine and AD again and checks each PC is still missing from Intune, still pinned, and has an installed agent. Template ' + rp.data.template.id + ' must still be “' + rp.data.template.name + '”.' }),
      h('li', { text: 'ManageEngine queues the script on these PCs. A PC that is offline runs it when its agent next connects.' }),
      h('li', { text: 'On each PC it checks the Entra device ID against its pin, removes ManageEngine’s MDM enrollment and stale enrollments, and runs Intune enrollment.' })
    ]), h('div', { class: 'ps-log' }, EXIT.map(function (e) { return h('div', null, [h('span', { class: 'ps-mono', text: 'Exit ' + e[0] }), h('small', { text: e[1] })]); }))]));
    p.body.appendChild(h('p', { class: 'noc-small noc-tone-warn', text: 'If Intune enrollment then fails, the PC is left with no MDM until it is repaired again or enrolled by hand. ManageEngine’s agent (inventory, patching, scripts) is not touched.' }));
    if (rows.some(function (r) { return !r.me.live; })) p.body.appendChild(h('p', { class: 'noc-small', text: 'An offline PC shows “Yet to apply” in ManageEngine until it connects. Another run cannot be sent to it while that run waits (up to 7 days).' }));
    p.body.appendChild(h('p', { class: 'noc-small', text: 'The run is recorded under your name in User activity with the ManageEngine collection ID.' }));
    var back = h('button', { type: 'button', text: 'Back', on: { click: closeDrawer } });
    var go0 = h('button', { type: 'button', class: 'ps-go', text: 'Run on ' + nn(rows.length, 'PC', 'PCs'), on: { click: function () { sendRun(go0, back); } } });
    p.foot.appendChild(h('span', { class: 'grow', text: rows.map(function (r) { return r.name; }).join(', ') }));
    p.foot.appendChild(back); p.foot.appendChild(go0);
    // Run sits where the opening button was: a double click must not send it.
    go0.disabled = true;
    setTimeout(function () { if (rpRun && rpRun.step === 'review') go0.disabled = false; }, 700);
    var dr = $('ps-drawer'), sc = $('ps-scrim');
    dr.hidden = false; sc.hidden = false;
    void dr.offsetWidth;
    dr.setAttribute('data-open', ''); sc.setAttribute('data-open', '');
    back.focus({ preventScroll: true });
  }
  function sendRun(btn, back) {
    if (!rpRun || rpRun.step !== 'review') return;
    rpRun.step = 'sending';
    btn.disabled = true; back.disabled = true; btn.textContent = 'Sending to ManageEngine…';
    var names = rpRun.names.slice();
    call(REPAIR_API + '/run', { method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, body: JSON.stringify({ names: names }) }, 120000)
      .then(function (x) { if (rpRun && drawerId === 'repair') runResult(x, names); });
  }
  function runResult(x, names) {
    var j = x.j, c = j.error, ok = x.http === 200 && j.ok;
    rpRun.step = 'done'; rpRun.sent = ok;
    var unsure = c === 'TIMEOUT' || c === 'NETWORK' || c === 'NOT_CONFIRMED' || x.http === 0;   // ME may have queued it
    var p = rpHead(ok ? 'Repair queued in ManageEngine' : unsure ? 'Repair not confirmed' : 'Repair not sent', names.join(', '));
    var lines = [];
    if (ok) {
      lines.push(['noc-tone-ok', 'ManageEngine queued the script on ' + nn(names.length, 'PC', 'PCs') + '.']);
      lines.push([null, 'Each PC runs it when its agent picks it up. ManageEngine reports the result under the collection ID below; this page reads it on each refresh.']);
      if (!j.saved) lines.push(['noc-tone-warn', 'The hub could not record the run in its own list, so this page will not show its status. It is in User activity and in ManageEngine.']);
    } else if (x.http === 409 && c === 'REFUSED') {
      lines.push(['noc-tone-warn', 'The hub refused the run after reading the sources again. Nothing was sent.']);
      (j.detail || []).forEach(function (d) { lines.push(['noc-small', d]); });
    } else if (c === 'TEMPLATE_CHANGED') lines.push(['noc-tone-bad', j.detail]);
    else if (c === 'GUARD') lines.push(['noc-tone-bad', j.detail + ' On the dev server a deploy needs an allow rule for ManageEngine’s deploy endpoint.']);
    else if (x.http === 401) lines.push(['noc-tone-bad', 'Your session ended. Nothing was sent. Sign in again.']);
    else if (x.http === 403) lines.push(['noc-tone-bad', 'Only super-admins can run a repair. Nothing was sent.']);
    else if (c === 'TIMEOUT' || c === 'NETWORK' || c === 'NOT_CONFIRMED') lines.push(['noc-tone-warn', j.detail]);
    else if (x.http === 0) lines.push(['noc-tone-warn', 'No answer from the hub. The run may have been sent; check ManageEngine before running it again.']);
    else lines.push(['noc-tone-bad', (j.detail ? (Array.isArray(j.detail) ? j.detail.join(' ') : j.detail) : 'The run failed in the hub (HTTP ' + x.http + ').')]);
    p.body.appendChild(h('div', { class: 'noc-panel' }, lines.map(function (l) { return h('p', { class: l[0], text: l[1] }); }).concat(ok ? [kv([['Collection ID', h('span', { class: 'ps-mono', text: j.collectionId })], ['Sent', stamp(j.at)]])] : [])));
    p.foot.appendChild(h('span', { class: 'grow' }));
    if (ok) p.foot.appendChild(copyBtn('Copy collection ID', j.collectionId));
    var close = h('button', { type: 'button', class: 'ps-go', text: 'Close', on: { click: closeDrawer } });
    p.foot.appendChild(close);
    close.focus({ preventScroll: true });
  }

  /* ── shareable links: #devices?issue=unencrypted, #housekeeping?age=150 ─ */
  var migration = null, migrationGuid = null;
  function migrationView() {
    if (!window.CorpITMigration) return panel('GPO migration', [empty('Migration tools did not load. Reload the page to retry.')]);
    if (!migration) migration = window.CorpITMigration.create({ h: h, panel: panel, table: table, download: download,
      openDevice: openDrawer, onState: status, selectedGuid: function () { return migrationGuid; },
      selectGuid: function (guid) { migrationGuid = guid; syncHash(); },
      resetTable: function (key) { if (tableStates[key]) tableStates[key].page = 0; } });
    return migration.view();
  }
  var FILT0 = { platform: 'all', issue: 'all', ring: 'all', patch: 'all', pol: 'all', q: '' };
  var HKQ = { intuneAge: ['age', 30], entraAge: ['eage', 90], entraTrust: ['trust', 'all'], entraState: ['state', 'all'] };
  function hashFor() {
    if (view === 'overview') return '';
    var q = [];
    if (view === 'migration' && migrationGuid) q.push('gpo=' + encodeURIComponent(migrationGuid));
    if (view === 'devices') Object.keys(FILT0).forEach(function (k) { if (filt[k] !== FILT0[k]) q.push(k + '=' + encodeURIComponent(filt[k])); });
    if (view === 'housekeeping') Object.keys(HKQ).forEach(function (k) { if (hk[k] !== HKQ[k][1]) q.push(HKQ[k][0] + '=' + encodeURIComponent(hk[k])); });
    if (view === 'apps') { if (apv.app) q.push('app=' + encodeURIComponent(apv.app)); if (apv.all) q.push('show=all'); }
    if (view === 'repair') { if (rp.days !== 30) q.push('days=' + rp.days); if (rp.reason !== 'all') q.push('why=' + encodeURIComponent(rp.reason)); if (rp.route !== 'all') q.push('route=' + encodeURIComponent(rp.route)); }
    return '#' + view + (q.length ? '?' + q.join('&') : '');
  }
  function syncHash() {
    var want = hashFor();
    if (location.hash === want || (!want && !location.hash)) return;
    var cur = location.hash.replace(/^#/, '').split('?')[0] || 'overview';
    var push = cur !== view && Object.prototype.hasOwnProperty.call(VIEWS, cur);   // an alias or junk hash is replaced, never stacked
    try { history[push ? 'pushState' : 'replaceState'](null, '', location.pathname + location.search + want); } catch (e) { /* ignore */ }
  }
  // Reads view and filters from the address. Anything unrecognised falls back to the default.
  function readHash() {
    var raw = location.hash.replace(/^#/, ''), i = raw.indexOf('?'), p = {};
    var v = i === -1 ? raw : raw.slice(0, i);
    (i === -1 ? '' : raw.slice(i + 1)).split('&').forEach(function (pair) {
      if (!pair) return;
      var j = pair.indexOf('=');
      try { p[decodeURIComponent(j === -1 ? pair : pair.slice(0, j))] = decodeURIComponent((j === -1 ? '' : pair.slice(j + 1)).replace(/\+/g, ' ')); } catch (e) { /* malformed escape: skip */ }
    });
    if (v === 'rings') v = 'updates';             // build 1 bookmark
    if (!Object.prototype.hasOwnProperty.call(VIEWS, v)) v = 'overview';
    if (v === 'migration') migrationGuid = GUID_RE.test(p.gpo || '') ? p.gpo.toLowerCase() : null;
    if (v === 'devices') {
      setFilter({});
      if (p.platform) filt.platform = p.platform.slice(0, 40);
      if (p.issue === 'any' || Object.prototype.hasOwnProperty.call(ISSUE, p.issue)) filt.issue = p.issue;
      if (p.ring === 'none' || p.ring === 'multi' || GUID_RE.test(p.ring || '')) filt.ring = p.ring;
      if (GUID_RE.test(p.pol || '')) filt.pol = p.pol;
      if (Object.prototype.hasOwnProperty.call(LABEL, p.patch)) filt.patch = p.patch;
      if (p.q) filt.q = p.q.slice(0, 100);
    }
    if (v === 'apps') apv = { app: GUID_RE.test(p.app || '') ? p.app : null, all: p.show === 'all', q: '' };
    if (v === 'repair') {
      rp.days = ['7', '30', '90'].indexOf(p.days) !== -1 ? Number(p.days) : p.days === 'all' ? 'all' : 30;
      rp.reason = Object.prototype.hasOwnProperty.call(REASON, p.why) ? p.why : 'all';
      rp.route = p.route === 'runnable' || Object.prototype.hasOwnProperty.call(ROUTE, p.route) ? p.route : 'all';
    }
    if (v === 'housekeeping') {
      hk = { intuneAge: 30, entraAge: 90, entraTrust: 'all', entraState: 'all', entraShow: 200, actGone: false };
      var a = parseInt(p.age, 10), ea = parseInt(p.eage, 10);
      if (a >= 1 && a <= 3650) hk.intuneAge = a;
      if (ea >= 1 && ea <= 3650) hk.entraAge = ea;
      if (Object.prototype.hasOwnProperty.call(p, 'trust')) hk.entraTrust = p.trust.slice(0, 40);
      if (p.state === 'enabled' || p.state === 'disabled') hk.entraState = p.state;
    }
    return v;
  }

  /* ── render + navigation ─────────────────────────────────────────────── */
  function render(focus) {
    rowsHost = null; countHost = null; filterHost = null; rpHost = null; rpCount = null; rpRunBtn = null;
    $('ps-title').textContent = VIEWS[view];
    $('crumb').textContent = VIEWS[view];
    D.title = VIEWS[view] + (view === 'overview' ? '' : ' — Intune Health');
    $('ps-sub').textContent = SUBS[view];
    $('ps-export').textContent = { migration: 'Export shared records', devices: 'Export all matches', updates: 'Export all Windows', apps: 'Export app summary', repair: 'Export all matches' }[view] || 'Export CSV';
    Array.prototype.forEach.call(D.querySelectorAll('[data-go]'), function (b) {
      if (b.getAttribute('data-go') === view) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
    });
    var body = $('ps-body'); clear(body);
    if (!snap && view !== 'migration') {
      body.appendChild(h('div', { class: 'ps-empty' }, [h('strong', { text: lastErr ? 'Intune data did not load' : 'Reading Intune…' }),
        lastErr ? h('span', { class: 'noc-small', text: lastErr })
          : slow ? h('span', { class: 'noc-small', text: 'The hub has no saved read, so it is reading Intune now. This can take a few minutes while Intune limits how fast it answers.' }) : null]));
      status();
      return;
    }
    var V = { migration: migrationView, devices: devicesView, updates: updatesView, security: securityView, enrollment: enrollmentView, housekeeping: housekeepingView, repair: repairView, apps: appsView, sources: sourcesView }[view];
    body.appendChild(V ? V(focus) : overview());
    if (focus) { var el = $('ps-src-' + focus) || $('ps-sec-' + focus); if (el) el.scrollIntoView({ block: 'start' }); }
    syncHash();
    status();
  }
  function go(v, focus) {
    if (!Object.prototype.hasOwnProperty.call(VIEWS, v)) v = 'overview';
    if (view === 'migration' && v !== 'migration' && migration && migration.hasEdits()) {
      if (!window.confirm('Leave unsaved migration register edits?')) { syncHash(); return; }
      migration.discardEdits();
    }
    view = v;
    D.body.classList.remove('ps-nav-open');
    $('noc-menu').setAttribute('aria-expanded', 'false');
    render(focus);
    if (!focus) window.scrollTo(0, 0);
  }

  function status() {
    var live = $('ps-live'), st = $('ps-stale'), ref = $('ps-refresh');
    ref.disabled = reading;
    ref.textContent = reading ? 'Reading…' : 'Refresh';
    $('ps-export').disabled = view === 'migration' ? !(migration && migration.canExport()) : !snap || !snap.devicesOk;
    if (!snap) { live.textContent = reading ? 'Reading Intune…' : 'No completed read'; st.hidden = true; return; }
    live.textContent = (reading ? 'Reading… · ' : snap.refreshing ? 'Updating in the background · ' : '') + 'Read ' + ago(snap.at);
    $('ps-stamp').textContent = 'Intune read ' + stamp(snap.at);
    var warn = '';
    if (lastErr) warn = 'The latest refresh failed (' + lastErr + '). Showing the read from ' + stamp(snap.at) + '.';
    else if (snap.refreshError) warn = 'The hub could not re-read Intune at ' + stamp(snap.refreshError.at) + ' (' + (snap.refreshError.source && snap.refreshError.source.error || 'error') + '). Showing the read from ' + stamp(snap.at) + '.';
    st.hidden = !warn; st.textContent = warn;
  }

  /* ── network ─────────────────────────────────────────────────────────── */
  var fetchedAt = 0, slow = false, rechecks = 0, recheckT = null;
  function load(force) {
    if (reading) return;
    var prevAt = snap ? snap.at : null;
    reading = true; slow = false; clearTimeout(recheckT); status();
    var ctl = new AbortController(), t = setTimeout(function () { ctl.abort(); }, SNAP_TIMEOUT_MS);
    var slowT = setTimeout(function () { slow = true; if (!snap && reading && !$('ps-work').hidden) rerender(); }, SLOW_MS);
    fetch(API + (force ? '?refresh=1' : ''), { credentials: 'same-origin', headers: { Accept: 'application/json' }, signal: ctl.signal })
      .then(function (r) {
        if (r.status === 401) throw { gate: 'auth' };
        if (r.status === 403) throw { gate: 'denied' };
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(function (j) {
        if (!j || j.ok !== true || !j.sources || !j.baseline) throw new Error('unexpected response');
        snap = j; skew = Date.now() - j.now; lastErr = null; der = null;
      })
      .catch(function (e) {
        if (e && e.gate === 'auth') return gate('Session required', 'Your session is not active. Sign in, then return here.', signIn());
        if (e && e.gate === 'denied') return gate('Not available to your account', 'Intune health is limited to super-admins and SaaS-ITH-HD. The server refused this account.');
        lastErr = e && e.name === 'AbortError' ? 'no answer within ' + SNAP_TIMEOUT_MS / 1000 + ' s' : (e && e.message) || 'could not reach the hub';
      })
      .then(function () {
        clearTimeout(t); clearTimeout(slowT); reading = false; slow = false; fetchedAt = Date.now();
        // The hub answered with its last read and is reading Intune again: look back soon for the new one.
        if (snap && snap.refreshing && !lastErr && rechecks < RECHECKS) { rechecks++; recheckT = setTimeout(function () { load(false); }, RECHECK_MS); }
        else rechecks = 0;
        if ($('ps-work').hidden) return;
        // A background refresh does not rebuild a view the technician is typing in or scrolled into.
        var typing = D.activeElement && /INPUT|SELECT/.test(D.activeElement.tagName) && $('ps-body').contains(D.activeElement);
        // A look-back that found the same read only updates the status line.
        if (typing || (view === 'migration' && migration && migration.hasEdits()) || (prevAt && snap && snap.at === prevAt && !lastErr)) status(); else rerender();
        if (drawerId && drawerId.indexOf('ring:') !== 0 && drawerId !== 'repair' && !devices().some(function (d) { return d.id === drawerId; })) closeDrawer();
      });
  }

  /* ── access gate ─────────────────────────────────────────────────────── */
  function signIn() { return h('a', { href: '/login.html?return=' + encodeURIComponent(location.pathname), text: 'Sign in' }); }
  function gate(title, text, action) {
    clearInterval(timer); clearTimeout(recheckT);
    $('ps-work').hidden = true;
    var g = $('ps-gate'); g.hidden = false;
    $('ps-gate-h').textContent = title; $('ps-gate-p').textContent = text;
    var a = $('ps-gate-a'); clear(a); if (action) a.appendChild(action);
  }
  function allowed(me) {
    return !!me && (me.isSuperAdmin === true || (me.isActive === true && Array.isArray(me.roles) && me.roles.indexOf('tier2') !== -1));
  }
  function gateCheck() {
    var rb = window.itRbac;
    var ready = rb && typeof rb.ready === 'function' ? Promise.resolve(rb.ready()).catch(function () { return null; }) : Promise.resolve(null);
    return ready.then(function () {
      var state = '', me = null;
      try { state = rb && rb.state ? rb.state() : ''; me = state === 'ok' ? rb.me() : null; } catch (e) { state = ''; }
      if (state === 'unauthenticated') { gate('Session required', 'Your session is not active. Sign in, then return here.', signIn()); return false; }
      if (state !== 'ok' || !(me && me.email)) {
        gate('Access check did not complete', 'The permission service did not answer, so this page cannot confirm who you are. This is not a sign-out. Retry; if it keeps happening the hub API is unavailable.',
          h('button', { type: 'button', text: 'Retry', on: { click: function () { location.reload(); } } }));
        return false;
      }
      if (!allowed(me)) { gate('Not available to your account', 'Intune health is available to super-admins and members of SaaS-ITH-HD. Ask a platform owner if you need it.'); return false; }
      return true;
    });
  }

  /* ── CSV ─────────────────────────────────────────────────────────────── */
  function csvCell(v) {
    var s = v == null ? '' : String(v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;          // keep spreadsheet formulas inert
    return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  }
  function iso(t) { return t ? new Date(t).toISOString() : ''; }
  function download(name, header, rows) {
    var lines = [header.map(csvCell).join(',')].concat(rows.map(function (r) { return r.map(csvCell).join(','); }));
    var a = h('a', { href: URL.createObjectURL(new Blob(['﻿' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' })), download: name + '-' + new Date().toISOString().slice(0, 10) + '.csv' });
    D.body.appendChild(a); a.click(); setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 0);
  }
  function exportDevices(list, name, withRecord) {
    var head = ['Device', 'Primary user', 'User name', 'Primary user account', 'Last signed-in user', 'Platform', 'OS version', 'Serial', 'Model', 'Compliance', 'Encrypted', 'Last check-in (UTC)', 'Enrolled (UTC)', 'Enrollment type', 'Patch status', 'Ring', 'Failing policies', 'Issues', 'Intune link'];
    if (withRecord) head.push('Record');
    download(name, head, list.map(function (d) {
      var r = [d.name, d.user, d.userName, d.userState && usersOk() ? ACCT[d.userState] : '', d.lastLogonUser || '', d.platform, d.os, d.serial, d.model, label(COMPLIANCE, d.compliance), d.encrypted == null ? '' : d.encrypted ? 'Yes' : 'No',
        iso(d.lastSync), iso(d.enrolled), label(ENROLL, d.enrollType || 'unknown'), isWin(d) ? LABEL[classify(d)] : '', ringName(d, true), d.failing && d.failing.length ? failingText(d) : snap.failOk ? '' : 'Not read',
        issuesOf(d).map(function (k) { return ISSUE[k].label; }).join('; '), PORTAL.device(d.id)];
      if (withRecord) r.push(d._rec || '');
      return r;
    }));
  }
  function exportEntra(list, name) {
    download(name, ['Device', 'OS', 'Join type', 'Last sign-in (UTC)', 'Registered (UTC)', 'Enabled', 'Entra object ID', 'Entra device ID', 'Entra link'], list.map(function (e) {
      return [e.name, e.os, label(TRUST, e.trust), iso(e.lastSignIn), iso(e.registered), e.enabled ? 'Yes' : 'No', e.objectId, e.deviceId, PORTAL.entra(e.objectId, e.deviceId)];
    }));
  }
  function exportAp(list, name) {
    download(name, ['Serial', 'Make', 'Model', 'Group tag', 'Autopilot state', 'Profile', 'Last contact (UTC)', 'Assigned user', 'Intune device ID'], list.map(function (a) {
      return [a.serial, a.make, a.model, a.tag, label(AP_STATE, a.state), label(AP_PROFILE, a.profile), iso(a.lastContact), a.user, a.intuneId];
    }));
  }
  function exportApps(list) {
    download('intune-apps', ['App', 'Publisher', 'Platform', 'Type', 'Version', 'Assigned', 'Installed', 'Failed', 'Pending', 'Not installed', 'Not applicable', 'App ID'], list.map(function (a) {
      return [a.name, a.publisher, a.platform, appTypeText(a), a.version, appAssignText(a), a.installed, a.failed, a.pending, a.notInstalled, a.notApplicable, a.id];
    }));
  }
  function exportAppRows(a, rows) {
    download('app-install-' + String(a.name).replace(/[^A-Za-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40).toLowerCase(), ['Device', 'User', 'Platform', 'State', 'Detail', 'Error code', 'Version', 'When (UTC)', 'Intune device ID'], rows.map(function (r) {
      return [r.device, r.user, r.platform, r.state, r.detail, r.hex, r.version, iso(r.at), r.deviceId];
    }));
  }
  function exportCsv() {
    if (view === 'migration') return migration && migration.exportRows();
    if (!snap || !snap.devicesOk) return;
    if (view === 'devices') return exportDevices(filtered(), 'intune-devices');
    if (view === 'updates') return exportDevices(sortedPatch(wins()), 'windows-patch-status');
    if (view === 'security') return exportDevices(devices().filter(function (d) { return issuesOf(d).some(function (k) { return ['malware', 'noncompliant', 'grace', 'unencrypted', 'lowdisk'].indexOf(k) !== -1; }); }), 'intune-security-issues');
    if (view === 'enrollment') return exportEntra(enrollGap(), 'enrollment-gap');
    if (view === 'apps') return snap.apps ? exportApps(snap.apps) : undefined;
    if (view === 'repair') return rp.data && rp.data.rows ? exportRepair(rpFiltered()) : undefined;
    if (view === 'housekeeping') return exportDevices(intuneQuiet(hk.intuneAge), 'intune-no-checkin-' + hk.intuneAge + 'd');
    exportDevices(devices(), 'intune-devices');
  }

  /* ── boot ────────────────────────────────────────────────────────────── */
  function wire() {
    Array.prototype.forEach.call(D.querySelectorAll('[data-go]'), function (b) {
      b.addEventListener('click', function () { go(b.getAttribute('data-go')); });
    });
    $('ps-refresh').addEventListener('click', function () { load(true); });
    $('ps-export').addEventListener('click', exportCsv);
    var hb = $('ps-help-btn');
    hb.addEventListener('click', function () { var o = $('ps-help').hidden; $('ps-help').hidden = !o; hb.setAttribute('aria-expanded', String(o)); });
    var mb = $('noc-menu');
    mb.addEventListener('click', function () { var o = D.body.classList.toggle('ps-nav-open'); mb.setAttribute('aria-expanded', String(o)); });
    $('ps-scrim').addEventListener('click', closeDrawer);
    // Back/forward and pasted #view links: same-document hash changes do not reload the page.
    // pushState and replaceState never fire this, so every hashchange is a pasted link, an edit or back/forward.
    window.addEventListener('hashchange', function () {
      if (location.hash === hashFor()) return;
      // Decide before readHash changes the selected GPO. Cancel must retain both
      // the original address and its visible draft, including same-view links.
      if (view === 'migration' && migration && migration.hasEdits()) {
        if (!window.confirm('Leave unsaved migration register edits?')) { syncHash(); return; }
        migration.discardEdits();
      }
      closeDrawer(); go(readHash());
    });
    window.addEventListener('beforeunload', function (e) {
      if (migration && migration.hasEdits()) { e.preventDefault(); e.returnValue = ''; }
    });
    D.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && drawerId) { e.preventDefault(); closeDrawer(); return; }
      if (e.key === 'Escape' && D.body.classList.contains('ps-nav-open')) { D.body.classList.remove('ps-nav-open'); mb.setAttribute('aria-expanded', 'false'); mb.focus(); }
      trapFocus(e);
    });
    function due() { return snap && now() - snap.at > AUTO_MS && Date.now() - fetchedAt > 60000; }
    timer = setInterval(function () { if (!D.hidden) { if (due()) load(false); else status(); } }, 30000);
    D.addEventListener('visibilitychange', function () { if (!D.hidden && due()) load(false); });
  }
  function boot() {
    gateCheck().then(function (ok) {
      if (!ok) return;
      $('ps-gate').hidden = true;
      $('ps-work').hidden = false;
      wire();
      view = readHash();
      render();
      load(false);
    });
  }
  if (D.readyState === 'loading') D.addEventListener('DOMContentLoaded', boot); else boot();
})();
