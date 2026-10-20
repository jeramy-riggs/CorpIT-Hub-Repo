/* SharePoint dashboard presentation. Uses the existing page's state and drill-downs. */
'use strict';
const SPG_QUEUE = { priority: '', search: '' };
let SPG_FEEDS = { state: 'loading', feeds: [] };
const SPG_ICONS = {
  grid: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
  sites: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M8 9v11"/>',
  hub: '<rect x="9" y="3" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="5" rx="1"/><rect x="16" y="16" width="6" height="5" rx="1"/><path d="M12 9v4M5 16v-3h14v3"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  storage: '<path d="M4 4h16v16H4zM4 14h16"/><path d="M8 17h.01M12 17h.01"/>',
  trend: '<path d="M3 3v18h18M6 15l5-5 4 3 6-8"/>',
  search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
  cost: '<circle cx="12" cy="12" r="9"/><path d="M12 5v14M16 8H10a2 2 0 0 0 0 4h4a2 2 0 0 1 0 4H8"/>',
  share: '<path d="M14 3h7v7M21 3l-9 9M10 5H5a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-5"/>',
  lock: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/>',
  tag: '<path d="M3 3h8l10 10-8 8L3 11z"/><circle cx="7.5" cy="7.5" r="1"/>',
  report: '<path d="M14 2H5v20h14V7zM14 2v6h5M8 12h8M8 16h8"/>',
  settings: '<circle cx="12" cy="12" r="3"/><path d="m9 3-1 3-3 1-2 5 2 5 3 1 1 3h6l1-3 3-1 2-5-2-5-3-1-1-3z"/>',
  arrow: '<path d="M5 12h14M13 6l6 6-6 6"/>',
  refresh: '<path d="M20 7V3l-4 4M20 7a9 9 0 1 0 1 8"/>',
  download: '<path d="M12 3v12M7 10l5 5 5-5M4 16v5h16v-5"/>',
  menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
  shield: '<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6zM9 12l2 2 4-4"/>'
};
function spgIcon(name) {
  return `<svg class="spg-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${SPG_ICONS[name] || SPG_ICONS.grid}</svg>`;
}
function spgNumber(n) { return Number(n || 0).toLocaleString('en-US'); }
function spgDlpText(t) { return t.n ? (t.stale ? 'Last known: ' : '') + spgNumber(t.n) + ' files with loan-number pattern matches' : t.sub; }
function spgMoney(n) { return '$' + Math.round(Number(n || 0)).toLocaleString('en-US'); }
function spgDate(value) {
  const d = new Date(value);
  return value && !isNaN(d) ? d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : 'date unavailable';
}
function spgQueueCopy(r) {
  const groups = { 'inactive-critical': CRITICAL_SITES, 'inactive-high': HIGH_SITES, 'inactive-medium': MEDIUM_SITES, watch: WATCH_SITES, 'ext-sharing': EXT_ON_SITES, 'no-hub': NO_HUB_SITES };
  const sites = groups[r.id] || [];
  const shared = sites.filter(s => s.ext_sharing === 'On').length;
  const copy = {
    'inactive-critical': ['Review dormant sites', 'No activity for 2+ years or never active', `${spgNumber(shared)} allow external sharing`],
    'inactive-high': ['Confirm whether inactive sites are needed', 'No activity for 1–2 years', `${spgNumber(shared)} allow external sharing`],
    'ext-sharing': ['Audit external sharing', 'Check which sites still need external collaboration', 'Sharing enabled; access is not confirmed'],
    'no-hub': ['Review sites without a department hub', 'Confirm classification and department assignment', 'Hub assignment does not establish ownership'],
    'inactive-medium': ['Review sites approaching one year inactive', 'No activity for 6–12 months', `${spgNumber(shared)} allow external sharing`],
    watch: ['Check sites showing early inactivity', 'No activity for 90–180 days', `${spgNumber(shared)} allow external sharing`]
  };
  const [title, reason, context] = copy[r.id] || [r.title, r.subtitle, 'Review the available site evidence'];
  return { title, reason, context, count: sites.length };
}
function spgQueueRow(r) {
  const q = spgQueueCopy(r);
  const priority = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Watch' }[r.priority] || r.priority;
  return `<li class="spg-queue-row" data-priority="${esc(r.priority)}">
    <div class="spg-queue-main"><span class="spg-priority spg-priority-${esc(r.priority)}">${esc(priority)}</span>
      <div class="spg-queue-copy"><h3>${esc(q.title)}</h3><p>${esc(q.reason)}</p><span>${esc(q.context)}</span></div></div>
    <div class="spg-queue-scope"><strong>${spgNumber(q.count)}</strong><span>sites</span></div>
    <button type="button" class="spg-review" onclick="spgOpenReview('${r.id}',this)" aria-label="Open review: ${esc(q.title)}">Review ${spgIcon('arrow')}</button>
  </li>`;
}
let spgReviewTrigger = null;
function spgOpenReview(id, trigger) {
  spgReviewTrigger = trigger;
  openPanel(id);
  const panel = document.getElementById('panel');
  panel.setAttribute('role', 'dialog'); panel.setAttribute('aria-modal', 'true');
  panel.setAttribute('aria-label', 'Site review');
  panel.querySelector('button')?.focus();
}
function spgFilterQueue() {
  const list = document.getElementById('rec-grid'); if (!list) return;
  const query = SPG_QUEUE.search.trim().toLowerCase();
  const rows = RECS.filter(r => (!SPG_QUEUE.priority || r.priority === SPG_QUEUE.priority) &&
    (!query || [spgQueueCopy(r).title, spgQueueCopy(r).reason, spgQueueCopy(r).context, r.title, r.subtitle].join(' ').toLowerCase().includes(query)));
  list.innerHTML = rows.map(spgQueueRow).join('') || `<li class="spg-empty"><strong>No matching reviews</strong><p>Try a different search or priority.</p><button type="button" class="spg-text-button" onclick="spgResetQueue()">Clear filters</button></li>`;
  const count = document.getElementById('spg-queue-count'); if (count) count.textContent = `${rows.length} review areas`;
  const pf = document.getElementById('pf'); if (pf) pf.value = SPG_QUEUE.priority;
}
function spgResetQueue() {
  SPG_QUEUE.priority = ''; SPG_QUEUE.search = '';
  const search = document.getElementById('gsearch'); if (search) search.value = '';
  spgFilterQueue(); search?.focus();
}
function spgRenderDashboard() {
  const health = computeHealthScore();
  const criticalShared = CRITICAL_SITES.filter(s => s.ext_sharing === 'On').length;
  const inactive = CRITICAL_SITES.length + HIGH_SITES.length + MEDIUM_SITES.length + WATCH_SITES.length;
  const cost = SUMMARY.total_gb * ((typeof CA_STATE !== 'undefined' && CA_STATE.rate) || .20) * 12;
  const dlp = DLP_TILE();
  const focusTitle = criticalShared ? `${spgNumber(criticalShared)} dormant sites still allow external sharing.` : CRITICAL_SITES.length ? `${spgNumber(CRITICAL_SITES.length)} dormant sites need a lifecycle review.` : 'Keep site access and lifecycle decisions current.';
  document.getElementById('content').innerHTML = `<div class="spg-dashboard">
    <header class="spg-page-heading"><div><h1>SharePoint governance</h1><p>Access, ownership and the lifecycle of your tenant.</p></div><span class="spg-tenant">auctiondotcom.sharepoint.com</span></header>
    <div id="spg-feed-notice" class="spg-feed-notice" role="status">${spgFeedNotice()}</div>
    <section class="spg-briefing" aria-label="Tenant summary">
      <div class="spg-focus"><span class="spg-focus-label">${spgIcon('shield')} ${criticalShared || CRITICAL_SITES.length ? 'Priority review' : 'Governance review'}</span><h2>${focusTitle}</h2>
        <p>${criticalShared ? `These are among ${spgNumber(CRITICAL_SITES.length)} sites with no activity for at least two years or no recorded activity. Review their sharing settings and confirm whether the content is still needed.` : 'Use the review queue to check site activity, sharing settings and department assignments.'}</p>
        <button class="spg-primary" type="button" onclick="spgOpenReview('inactive-critical',this)">Review dormant sites ${spgIcon('arrow')}</button>
        <span class="spg-focus-note">Sharing enabled does not confirm external access.</span>
      </div>
      <div class="spg-estate"><h2>Tenant at a glance</h2><div class="spg-estate-main"><div><strong>${spgNumber(SUMMARY.total_sites)}</strong><span>SharePoint sites</span></div><div><strong>${(SUMMARY.total_gb / 1024).toFixed(2)}<small> TB</small></strong><span>Reported storage</span></div></div>
        <dl><div><dt>Flagged for inactivity</dt><dd>${spgNumber(inactive)}</dd></div><div><dt>External sharing enabled</dt><dd>${spgNumber(SUMMARY.ext_on_count)}</dd></div><div><dt>Tenant health <span class="spg-muted">(calculated)</span></dt><dd>${health.score}<span class="spg-muted"> / 100</span></dd></div></dl>
        <p class="spg-estate-source">${DATA_SOURCE === 'live' ? 'Graph response' : 'Baseline export'}: ${esc(spgDate(SUMMARY.refreshed_at || SUMMARY.seed_as_of))}<br>Sharing and hub export: ${esc(seedAsOfLabel())}</p>
      </div>
    </section>
    <div class="spg-workspace"><section class="spg-queue" aria-labelledby="spg-queue-title"><div class="spg-section-heading"><div><h2 id="spg-queue-title">Action queue</h2><p>Review the evidence before changing site access.</p></div><span id="spg-queue-count">${RECS.length} review areas</span></div>
      <div class="spg-queue-tools"><label class="spg-search">${spgIcon('search')}<input type="search" id="gsearch" aria-label="Search action queue" placeholder="Find a review…" value="${esc(SPG_QUEUE.search)}" oninput="gSearch(this.value)"></label>
        <label class="spg-filter"><span class="spg-sr-only">Filter action queue by priority</span><select id="pf" onchange="filterP()"><option value="">All priorities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Watch</option></select></label></div>
      <ul id="rec-grid" class="spg-queue-list">${RECS.map(spgQueueRow).join('')}</ul><p class="spg-queue-footnote">Review areas can include the same site. Counts are not additive.</p>
    </section>
    <aside class="spg-context" aria-label="Storage and sensitive data"><section class="spg-economics"><div class="spg-section-heading"><h2>Storage economics</h2>${spgIcon('storage')}</div>
      <div class="spg-cost"><span>Estimated annual active-tier cost</span><strong>${spgMoney(cost)}<small> / yr</small></strong><span>${spgMoney(cost / 12)} per month at the configured rate</span></div>
      <div class="spg-reclaim"><span>Potential annual archive savings</span><strong id="hero-reclaim">Calculating…</strong><p id="hero-reclaim-sub">Waiting for stale-file totals.</p></div>
      <p class="spg-assumption">Illustrative estimate. Actual billing depends on tenant allowance and overage. Savings assume eligible content moves to the archive tier.</p><button type="button" class="spg-text-button" onclick="setPage('cost-analysis')">Explore cost assumptions ${spgIcon('arrow')}</button>
    </section>
    <section class="spg-sensitive" id="dash-dlp-card"><div class="spg-section-heading"><h2>Sensitive data</h2>${spgIcon('lock')}</div><strong id="dash-dlp-value">${dlp.n ? spgNumber(dlp.n) : esc(String(dlp.value))}</strong><p id="dash-dlp-sub">${esc(spgDlpText(dlp))}</p><button type="button" class="spg-text-button" onclick="setPage('dlp-alerts')">Review DLP findings ${spgIcon('arrow')}</button><p class="spg-assumption">Detection matches require review; they do not establish a confirmed incident.</p></section></aside></div>
    <details class="spg-analytics"><summary>Storage and risk detail<span>Trends, inventory and site risk distribution</span></summary><div class="spg-analytics-body">
      <div class="dash-2col"><div class="chart-wrap"><div class="dash-cardhead"><span>Tenant storage trend</span><span id="dash-trend-note"></span></div><div style="height:210px"><canvas id="dashTrend"></canvas></div></div><div class="chart-wrap"><div class="dash-cardhead"><span>Departments by estimated annual cost</span></div><div style="height:210px"><canvas id="dashDeptBars"></canvas></div></div></div>
      <div id="dash-storage"></div><div class="scatter-section"><div class="scatter-header"><div class="scatter-title">Storage and inactivity risk</div><span class="spg-muted">Further right = longer inactivity; higher = more storage</span></div><canvas id="riskScatter" style="max-height:240px"></canvas></div>
      <div id="dash-alerts-wrap"><button type="button" class="spg-text-button" onclick="toggleDashAlerts()"><span id="dash-alerts-summary">Growth and DLP alerts</span><span id="dash-alerts-caret">▸</span><span id="dash-alerts-counts"></span></button><div id="dash-alerts-body" style="display:none"><div id="growth-banner" class="growth-banner"></div><div id="dlp-banner" class="dlp-banner"></div></div></div>
    </div></details></div>`;
  spgFilterQueue(); renderGrowthBanner(); renderDlpBanner(); loadDashStorage(); updateHeroCost();
  document.querySelector('.spg-analytics').addEventListener('toggle', event => {
    if (event.target.open) { drawDashTrend(); drawDashDeptBars(); drawScatterChart(); }
  });
  saveTrendSnapshot();
}
function spgUpdateCost() {
  const value = document.getElementById('hero-reclaim'), sub = document.getElementById('hero-reclaim-sub');
  if (!value || !sub) return;
  const st = DASH_STORAGE && DASH_STORAGE.stale;
  if (!st || st.error || st.total_bytes == null || !Number.isFinite(Number(st.total_bytes))) {
    const failed = !!st && (st.error || st.total_bytes == null || !Number.isFinite(Number(st.total_bytes)));
    value.textContent = failed ? 'Unavailable' : 'Calculating…';
    sub.textContent = failed ? 'Stale-file totals could not be read. Savings are not measured.' : 'Waiting for stale-file totals.';
    return;
  }
  const rate = (typeof CA_STATE !== 'undefined' && CA_STATE.rate) || .20;
  const archive = (typeof CA_STATE !== 'undefined' && CA_STATE.arate) || .05;
  const gb = Number(st.total_bytes || 0) / 1024 ** 3;
  value.textContent = spgMoney(gb * (rate - archive) * 12) + ' / yr';
  sub.textContent = `${(gb / 1024).toFixed(2)} TB untouched for 5+ years across ${spgNumber(st.count)} files. Scan: ${spgDate(st.generated_at)}.`;
}
function spgFeedProblem(f) {
  return f.state !== 'not_included' && (f.state !== 'ok' || f.producerFailing || f.producerAbandoned || f.producerOverdue);
}
function spgFeedNotice() {
  if (SPG_FEEDS.state === 'loading') return `<span class="spg-status-dot"></span><span>Checking data sources…</span><button class="spg-text-button" type="button" onclick="spgOpenDataStatus()">View sources</button>`;
  if (SPG_FEEDS.state === 'error') return `<span class="spg-status-dot"></span><span><strong>Data freshness unavailable.</strong> Source ages could not be checked.</span><button class="spg-text-button" type="button" onclick="spgOpenDataStatus()">View sources</button>`;
  const bad = SPG_FEEDS.feeds.filter(spgFeedProblem);
  const stale = bad.filter(f => f.state === 'stale');
  const ages = stale.map(f => Number(f.ageHours)).filter(Number.isFinite);
  const age = ages.length ? ` Last updates up to ${Math.round(Math.max(...ages) / 24)} days ago.` : '';
  return `<span class="spg-status-dot ${bad.length ? '' : 'spg-status-ok'}"></span><span>${bad.length ? `<strong>${bad.length} data source${bad.length === 1 ? '' : 's'} need attention.</strong>${age} Some counts may be out of date.` : '<strong>Source checks passed.</strong> See individual sources for their latest collection dates.'}</span><button class="spg-text-button" type="button" onclick="spgOpenDataStatus()">View sources</button>`;
}
async function spgLoadFeedStatus() {
  try {
    const response = await fetch('/api/feeds/freshness?page=sharepoint-governance', { credentials: 'same-origin' });
    if (!response.ok) throw new Error('Freshness unavailable');
    const data = await response.json();
    if (!Array.isArray(data.feeds)) throw new Error('No freshness measurement');
    SPG_FEEDS = { state: 'loaded', feeds: data.feeds };
    data.feeds.filter(spgFeedProblem).forEach(f => {
      if (window.ITObserve) ITObserve.degraded('feed:' + f.key, f.label + ': source needs attention', 'state=' + f.state);
    });
  } catch { SPG_FEEDS = { state: 'error', feeds: [] }; }
  const notice = document.getElementById('spg-feed-notice'); if (notice) notice.innerHTML = spgFeedNotice();
}
function spgFeedDescription(f) {
  if (f.state === 'unknown') return 'Freshness could not be checked';
  if (f.state === 'empty') return 'No data collected';
  if (f.state === 'stale') return `Out of date${f.ageHours != null ? ' · ' + Math.round(f.ageHours / 24) + ' days since update' : ''}`;
  if (f.producerFailing) return 'Collector last failed; data may be incomplete';
  if (f.producerAbandoned) return 'Collector did not complete; verify coverage';
  if (f.producerOverdue) return 'Collector is overdue';
  return 'Within expected update interval';
}
function spgOpenDataStatus() {
  let dialog = document.getElementById('spg-sources');
  if (!dialog) {
    dialog = document.createElement('dialog'); dialog.id = 'spg-sources'; dialog.className = 'spg-source-dialog';
    dialog.setAttribute('aria-labelledby', 'spg-sources-title'); document.body.appendChild(dialog);
    dialog.addEventListener('click', e => { if (e.target === dialog) dialog.close(); });
  }
  dialog.innerHTML = `<div class="spg-dialog-heading"><h2 id="spg-sources-title">Data sources</h2><button type="button" class="spg-review" onclick="document.getElementById('spg-sources').close()" aria-label="Close data sources">Close</button></div><p>Counts reflect each source’s last update. An empty result from a stale feed is not an all-clear.</p><ul>${SPG_FEEDS.feeds.filter(f => f.state !== 'not_included').map(f => `<li><strong>${esc(f.label || f.key)}</strong><span>${esc(spgFeedDescription(f))}</span>${f.collector ? `<details><summary>Collector details</summary><code>${esc(f.collector)}</code></details>` : ''}</li>`).join('') || `<li>${SPG_FEEDS.state === 'loading' ? 'Source checks are in progress. Reopen this panel when they finish.' : 'Source ages are unavailable. Retry the source check.'}</li>`}</ul><button class="spg-text-button" type="button" onclick="spgRetrySources()">Check sources again ${spgIcon('refresh')}</button>`;
  if (!dialog.open) dialog.showModal();
}
async function spgRetrySources() { await spgLoadFeedStatus(); spgOpenDataStatus(); }
function spgToggleNav() {
  const app = document.querySelector('.app'); const open = app.classList.toggle('spg-nav-open');
  document.getElementById('spg-menu').setAttribute('aria-expanded', String(open));
}
document.addEventListener('DOMContentLoaded', () => {
  const map = { dashboard: 'grid', 'all-sites': 'sites', 'hub-sites': 'hub', 'inactive-sites': 'clock', 'by-dept': 'storage', 'storage-growth': 'trend', 'storage-explorer': 'search', 'cost-analysis': 'cost', 'ext-sharing': 'share', 'dlp-alerts': 'lock', 'stale-files': 'clock', 'tag-scan': 'tag', 'risk-report': 'report', settings: 'settings' };
  document.querySelectorAll('.sidebar .nav-item').forEach(el => {
    const text = [...el.childNodes].find(n => n.nodeType === Node.TEXT_NODE);
    if (text) text.textContent = text.textContent.replace(/^[^A-Za-z]+/, '');
    el.insertAdjacentHTML('afterbegin', spgIcon(map[el.id.replace('nav-', '')]));
    el.setAttribute('role', 'button'); el.tabIndex = 0;
    el.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); el.click(); } });
    el.addEventListener('click', () => {
      document.querySelector('.app').classList.remove('spg-nav-open');
      document.getElementById('spg-menu').setAttribute('aria-expanded', 'false');
      if (innerWidth <= 768) document.getElementById('spg-menu').focus();
    });
  });
  document.querySelector('.logo-icon').innerHTML = spgIcon('shield');
  document.querySelector('.logo-name').textContent = 'SharePoint';
  document.querySelector('.logo-sub').textContent = 'Governance workspace';
  document.querySelectorAll('.sidebar-section').forEach(el => { el.textContent = el.textContent.charAt(0).toUpperCase() + el.textContent.slice(1).toLowerCase(); });
  spgLoadFeedStatus();
});
document.addEventListener('keydown', event => {
  const overlay = document.getElementById('overlay');
  if (overlay?.classList.contains('open') && spgReviewTrigger) {
    if (event.key === 'Escape') { event.preventDefault(); closePanel(); return; }
    if (event.key === 'Tab') {
      const focusable = [...document.getElementById('panel').querySelectorAll('button:not(:disabled),input:not(:disabled),select:not(:disabled),a[href],[tabindex="0"]')].filter(el => el.getClientRects().length);
      const first = focusable[0], last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
    }
  } else if (event.key === 'Escape' && document.querySelector('.app.spg-nav-open')) {
    spgToggleNav(); document.getElementById('spg-menu').focus();
  }
});
