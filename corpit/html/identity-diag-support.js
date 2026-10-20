/* Technician workflow and source coverage for Identity Diagnostics only. */
'use strict';
var identityFeeds = null;
var identityPendingTask = '';
var identityFreshnessReady;

function identityFeedCurrent(key) {
  var f = identityFeeds && identityFeeds.find(function (row) { return row.key === key; });
  return !!(f && f.state === 'ok' && !f.producerFailing && !f.producerOverdue && !f.producerAbandoned && f.collectionMode !== 'manual_test');
}
function identityFeedMetric(key, count) {
  return identityFeedCurrent(key) ? num(count) : count ? num(count) + ' recorded' : '—';
}
function identityFeedDescription(f) {
  if (!f) return 'Source freshness could not be checked.';
  var sourceDate = f.newest ? ' Latest recorded source event: ' + ft(f.newest) + '.' : '';
  if (f.collectionMode === 'manual_test') return 'DEV test snapshot; recurring collection is not enabled here.' + sourceDate;
  if (f.state === 'stale') return 'Source events are old; recent activity cannot be assessed.' + sourceDate;
  if (f.state === 'empty') return 'No source records have been collected on this host.';
  if (f.state !== 'ok') return 'Source freshness could not be checked.' + sourceDate;
  if (f.producerFailing) return 'Source events are recent, but the collector last failed; records may be incomplete.' + sourceDate;
  if (f.producerAbandoned) return 'Source events are recent, but the collector has no completed outcome; coverage is unverified.' + sourceDate;
  if (f.producerOverdue) return 'Source events are recent, but collection is overdue; newer activity may be missing.' + sourceDate;
  return 'Source events are within the monitored freshness window.' + sourceDate;
}
function identityFeedNotice(key) {
  var f = identityFeeds && identityFeeds.find(function (row) { return row.key === key; });
  var current = identityFeedCurrent(key);
  return '<div class="support-feed-note ' + (current ? '' : 'support-feed-gap') + '" role="status"><strong>'
    + x(current ? 'Source coverage checked' : 'Recent activity unavailable') + '</strong><span>'
    + x(identityFeedDescription(f)) + '</span></div>';
}
async function identityLoadFreshness() {
  var controller = new AbortController();
  var timer = setTimeout(function () { controller.abort(); }, 10000);
  try {
    var response = await fetch('/api/feeds/freshness?page=identity-diag', { credentials: 'same-origin', signal: controller.signal });
    if (!response.ok) throw new Error('HTTP ' + response.status);
    var data = await response.json();
    if (!Array.isArray(data.feeds)) throw new Error('No feed measurements');
    identityFeeds = data.feeds.filter(function (f) { return f.state !== 'not_included'; });
  } catch (e) { identityFeeds = null; }
  finally { clearTimeout(timer); }
  identityRenderSources();
}
function identityRenderSources() {
  var host = document.getElementById('identity-source-status');
  if (!host) return;
  var summary = host.querySelector('summary');
  var body = host.querySelector('.support-source-body');
  var gaps = identityFeeds ? identityFeeds.filter(function (f) { return !identityFeedCurrent(f.key); }) : null;
  summary.textContent = !gaps ? 'Data sources · freshness unavailable' : gaps.length
    ? 'Data sources · ' + gaps.length + ' need attention' : 'Data sources · monitored feeds current';
  host.classList.toggle('has-gaps', !gaps || gaps.length > 0);
  body.innerHTML = '<p>Source event age and collector status are separate from the time a page query ran. Missing measurements are not clean results.</p>'
    + (identityFeeds ? '<ul>' + identityFeeds.map(function (f) {
      return '<li><strong>' + x(f.label || f.key) + '</strong><span>' + x(identityFeedDescription(f)) + '</span>'
        + '<small>Collector: ' + x(f.collector || 'Not reported') + '</small></li>';
    }).join('') + '</ul>' : '<p>Could not read source freshness. Recent feed-backed counts remain unverified.</p>')
    + '<button class="btn btn-ghost btn-sm" type="button" data-support-refresh>Refresh data status</button>';
  if (window.ITObserve && window.ITObserve.degraded && gaps) gaps.forEach(function (f) {
    window.ITObserve.degraded('feed:' + f.key, f.label + ': coverage unverified', 'state=' + f.state);
  });
}
function identityContext() {
  document.body.dataset.supportPage = _page;
  var host = document.getElementById('identity-person-context');
  if (!host) return;
  host.hidden = !_D;
  if (!_D) { host.textContent = ''; return; }
  host.innerHTML = '<div><small>Selected person</small><strong>' + x(_D.displayName || _D.samAccountName)
    + '</strong><span>' + x(_D.samAccountName || _D.email || '') + '</span></div>'
    + '<div class="support-context-actions"><button class="btn btn-ghost btn-sm" type="button" data-support-account>Open account</button>'
    + '<button class="btn btn-ghost btn-sm" type="button" data-support-groups data-rbac-page="user-provisioning" data-rbac-action="hide">Review groups</button></div>';
  _rbacApply(host);
  if(window.IdentityDeviceContext)IdentityDeviceContext.context();
}
function identityStartTask(task) {
  identityPendingTask = task;
  if (!_D) {
    var hint = document.getElementById('support-task-hint');
    hint.hidden = false;
    hint.textContent = 'Find the person above to continue with ' + ({ signin: 'sign-in checks', devices: 'device review', access: 'group review', offboarding: 'offboarding review' }[task] || 'this task') + '.';
    go('overview');
    document.getElementById('heroSearch').focus();
    return;
  }
  identityAccountLoaded();
}
function identityAccountLoaded() {
  var task = identityPendingTask;
  identityPendingTask = '';
  var hint = document.getElementById('support-task-hint');
  if (hint) hint.hidden = true;
  if (task === 'signin') { go('detail'); runDiagnostics(); }
  else if (task === 'devices') go('devices');
  else if (task === 'access') go('provisioning');
  else if (task === 'offboarding') go('offboarding');
}
function identitySyncPane() {
  var pane = document.getElementById('pane');
  var narrow = matchMedia('(max-width:880px)').matches;
  pane.inert = narrow && !pane.classList.contains('open');
  if (pane.inert) pane.setAttribute('aria-hidden', 'true');
  else pane.removeAttribute('aria-hidden');
}
function identitySupportInit() {
  var work = document.getElementById('work');
  var sources = document.createElement('details');
  sources.id = 'identity-source-status';
  sources.className = 'support-source-status';
  sources.innerHTML = '<summary>Data sources · checking coverage…</summary><div class="support-source-body"></div>';
  work.prepend(sources);
  var context = document.createElement('div');
  context.id = 'identity-person-context';
  context.className = 'support-person-context';
  context.setAttribute('aria-label', 'Selected person');
  context.hidden = true;
  sources.after(context);
  // Exact targets and roles stay unchanged; short labels are visible at every width.
  var names = { accounts: 'Support', devices: 'Devices', activity: 'Sign-ins', security: 'Security', provisioning: 'Group access', projects: 'Projects' };
  document.querySelectorAll('.rail-btn[data-ws]').forEach(function (button) { button.setAttribute('aria-label', names[button.dataset.ws]); });
  document.getElementById('devQuery').closest('.pane-search').hidden = true;
  document.addEventListener('click', function (event) {
    var task = event.target.closest('[data-support-task]');
    if (task) { identityStartTask(task.dataset.supportTask); return; }
    if (event.target.closest('[data-support-account]')) { go('detail'); return; }
    if (event.target.closest('[data-support-groups]')) { go('provisioning'); return; }
    if (event.target.closest('[data-support-refresh]')) {
      identityFreshnessReady = identityLoadFreshness();
      identityFreshnessReady.then(function () { loadSprayBadge(); if (_tool === 'failures' || _tool === 'entrafailures') runTool(); });
    }
  });
  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape' && document.getElementById('pane').classList.contains('open')) {
      closePane(); document.getElementById('paneToggle').focus();
    }
    if (event.key === 'Escape' && sources.open) { sources.open = false; sources.querySelector('summary').focus(); }
  });
  window.addEventListener('resize', identitySyncPane);
  identityContext(); identitySyncPane(); identityRenderSources();
}
identityFreshnessReady = identityLoadFreshness();
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', identitySupportInit);
else identitySupportInit();
