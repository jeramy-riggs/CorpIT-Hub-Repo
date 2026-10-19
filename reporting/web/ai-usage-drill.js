/* ai-usage-drill.js — drill-downs for every KPI tile, card row and pill on ai-usage-credits.html
 *
 * Plain JS, no framework. Loaded AFTER the page's inline script so it shares its
 * top-level state (AI_USERS, AI_ORG, LIVE, CP_USERS …) and helpers (usd, escH, cssv …).
 * Everything here is opened through ONE delegated click/keyboard handler on
 * [data-drill] elements, so the page templates only carry data attributes —
 * no inline handlers were added (CSP-friendly) and removing this file removes
 * the feature without touching anything else.
 *
 * Motion (Emil Kowalski's rules): the sheet reuses the existing right-hand drawer
 * (same direction every time = spatial consistency), enters in 240ms on an iOS-style
 * ease, exits faster (160ms), rows stagger 30ms up to 8, tiles/chips scale to .97 on
 * press, everything drops to opacity-only under prefers-reduced-motion. Keyboard:
 * Enter/Space open, Esc closes, focus returns to the opener. Nothing animates from
 * scale(0). */
'use strict';

const DRILL = { stack: [], opener: null, chart: null, cache: {} };

/* ---------- tiny view helpers ------------------------------------------------ */
const dlN = (v, d = 0) => (Number(v) || 0).toLocaleString('en-US', { minimumFractionDigits: d, maximumFractionDigits: d });
const dlPct = (a, b) => (b ? Math.round((a / b) * 100) : null);
// cache hit rate over all three (disjoint) input counters; cache writes are misses
const dlHit = (cr, un, cc) => { const i = (Number(cr) || 0) + (Number(un) || 0) + (Number(cc) || 0); return i ? (Number(cr) || 0) / i * 100 : null; };
const dlKv = (items) => '<div class="dl-kv">' + items.map((i) =>
  `<div class="dl-k"><div class="l">${i.term?'<span class="term-tip" data-term="'+i.term+'">'+escH(i.l)+'</span>':escH(i.l)}</div><div class="n" style="color:${i.c || 'var(--ink)'}">${i.n}</div>${i.s ? `<div class="s">${i.s}</div>` : ''}</div>`).join('') + '</div>';
const dlBar = (pct, color) => `<div class="dl-bar"><div style="width:${Math.max(0, Math.min(100, pct || 0)).toFixed(1)}%;background:${color || 'var(--accent)'}"></div></div>`;
const dlRow = (main, right, sub, extra) =>
  `<div class="a dl-row" ${extra || ''} style="display:block;padding:9px 12px">
     <div style="display:flex;justify-content:space-between;gap:8px;align-items:baseline"><span>${main}</span><span class="mono" style="color:var(--ink);white-space:nowrap">${right}</span></div>
     ${sub ? `<div style="font-size:11.5px;color:var(--ink-3);margin-top:2px">${sub}</div>` : ''}</div>`;
const dlH4 = (t, term) => `<h4>${term ? escH(t).replace('requests', '<span class="term-tip" data-term="requests">requests</span>') : escH(t)}</h4>`;
const dlNote = (t) => `<div class="sub" style="margin:-4px 0 14px">${t}</div>`;
const dlChips = (chips) => '<div class="dl-act">' + chips.map((c) =>
  `<button type="button" class="chip" data-dl-action="${escH(c.a)}" data-dl-arg="${escH(c.arg || '')}">${escH(c.l)}</button>`).join('') + '</div>';
const memberRow = (u, right, sub) => dlRow(`<b>${escH(u.name || u.email || '—')}</b> <span style="color:var(--ink-3);font-size:11px">${escH(u.dept || u.department || '')}</span>`, right, sub,
  `data-drill="member" data-arg="${escH(u.email || '')}" tabindex="0" role="button" title="Open member"`);
const median = (a) => { if (!a.length) return 0; const s = [...a].sort((x, y) => x - y); const m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const pctile = (a, p) => { if (!a.length) return 0; const s = [...a].sort((x, y) => x - y); return s[Math.min(s.length - 1, Math.floor(p * (s.length - 1)))]; };
const scoped = () => (deptFilter ? AI_USERS.filter((u) => u.dept === deptFilter) : AI_USERS);
const ym = () => (AI_MONTH ? String(AI_MONTH).slice(0, 7) : new Date().toISOString().slice(0, 7));
const isCurrentMonth = () => ym() === new Date().toISOString().slice(0, 7);
const getJ = (u) => fetch(u, { credentials: 'same-origin' }).then((r) => { if (!r.ok) throw new Error(u + ' -> ' + r.status); return r.json(); });
async function cached(key, fn) { if (!DRILL.cache[key]) DRILL.cache[key] = fn(); return DRILL.cache[key]; }

/* ---------- Cost Analysis drill-through (org -> dept -> manager -> employee) --
   Reuses the SAME /api/claude-analytics/rollup endpoint ai-usage-rollup.js
   already calls (confirmed scope-safe), scoped to the page's reporting period.
   One cached fetch per level+filter combination, shared across all 6 Cost
   Analysis drills so opening several in one session never re-fetches the
   same level twice. ------------------------------------------------------- */
const COST_LEVEL_LABEL = { leader: 'Department Leader', department: 'Department', manager: 'Manager', user: 'Employee' };
async function costFetchLevel(qs) {
  const params = new URLSearchParams(qs || 'level=leader');
  if (!params.get('level')) params.set('level', 'leader');
  const P = periodBounds(); params.delete('months'); params.set('from', P.from); params.set('to', P.to);
  const key = 'costLevel:' + params.toString();
  const d = await cached(key, () => getJ('/api/claude-analytics/rollup?' + params.toString()));
  if (d.error) throw new Error(d.error);
  return { d, params };
}
function costRenderRows(d, params) {
  const level = params.get('level') || 'leader';
  const rows = (d.rows || []).slice().sort((a, b) => b.total - a.total);
  const total = rows.reduce((s, r) => s + r.total, 0) || 1;
  if (!rows.length) return dlNote('No spend recorded in this period at this level.');
  return rows.map((r) => {
    const pct = Math.round((r.total / total) * 100);
    const canDrill = !!d.nextLevel && r.key !== '__none__';
    let extra = '';
    if (canDrill) {
      const np = new URLSearchParams(params); np.delete('months'); np.delete('from'); np.delete('to'); np.set('level', d.nextLevel);
      if (level === 'leader') np.set('leader', r.key);
      else if (level === 'department') np.set('department', r.key);
      else if (level === 'manager') np.set('manager', r.key);
      extra = `data-drill="costOrgLevel" data-arg="${escH(np.toString())}" tabindex="0" role="button" title="Drill into ${escH(r.name)}"`;
    }
    return dlRow(escH(r.name) + (canDrill ? ' <span style="color:var(--ink-3)">›</span>' : ''),
      usd(r.total) + ' <span style="color:var(--ink-3);font-weight:400">(' + pct + '%)</span>',
      r.users + ' ' + (r.users === 1 ? 'person' : 'people') + ' with spend · usage-based spend, ' + pct + '% of the period total' + (r.users ? ' · ' + usd(r.total / r.users) + ' per person' : ''), extra);
  }).join('');
}
async function costOrgSection(qs) {
  const { d, params } = await costFetchLevel(qs);
  const level = params.get('level') || 'leader';
  return dlH4('Spend by ' + (COST_LEVEL_LABEL[level] || 'organization').toLowerCase() + ' — ' + periodShort())
    + costRenderRows(d, params);
}

/* ---------- open / close ---------------------------------------------------- */
function openDrill(kind, arg, opener) {
  const fn = DRILLS[kind];
  if (!fn) return;
  if (opener && !DRILL.opener) DRILL.opener = opener;
  const d = document.getElementById('drawer');
  const backable = DRILL.stack.length > 0;
  d.innerHTML = `<div class="dh"><span class="x" id="dx" role="button" tabindex="0" aria-label="Close">✕</span>
      <div class="sub">loading…</div></div>`;
  d.setAttribute('role', 'dialog'); d.setAttribute('aria-modal', 'true');
  d.classList.add('show'); document.getElementById('scrim').classList.add('show');
  Promise.resolve().then(() => fn(arg)).then((v) => {
    if (!v) return;
    if (DRILL.chart) { try { DRILL.chart.destroy(); } catch (e) {} DRILL.chart = null; }
    d.innerHTML = `
      <div class="dh">
        <span class="x" id="dx" role="button" tabindex="0" aria-label="Close">✕</span>
        ${backable ? '<div class="sub" style="margin-bottom:4px"><span data-dl-action="back" style="cursor:pointer" tabindex="0" role="button">← Back</span></div>' : ''}
        <h2 style="margin:0 0 2px">${v.title}</h2>
        <div class="sub">${v.sub || ''}</div>
      </div>
      <div class="db">${v.html}</div>`;
    if (v.after) v.after(d);
    const x = document.getElementById('dx'); if (x) { x.onclick = closeDrillAll; x.focus({ preventScroll: true }); }
  }).catch((e) => {
    d.innerHTML = `<div class="dh"><span class="x" id="dx">✕</span><h2>Unavailable</h2><div class="sub">${escH(e.message || e)}</div></div>`;
    document.getElementById('dx').onclick = closeDrillAll;
  });
  DRILL.stack.push({ kind, arg });
}
function closeDrillAll() {
  DRILL.stack = [];
  if (DRILL.chart) { try { DRILL.chart.destroy(); } catch (e) {} DRILL.chart = null; }
  closeDrawer();
  const o = DRILL.opener; DRILL.opener = null;
  if (o && document.contains(o)) { try { o.focus({ preventScroll: true }); } catch (e) {} }
}
function drillBack() {
  DRILL.stack.pop();                      // current
  const prev = DRILL.stack.pop();         // re-open previous (openDrill pushes it again)
  if (prev) openDrill(prev.kind, prev.arg); else closeDrillAll();
}

/* ---------- delegated events ------------------------------------------------ */
document.addEventListener('click', (e) => {
  const act = e.target.closest('[data-dl-action]');
  if (act) { e.preventDefault(); return drillAction(act.dataset.dlAction, act.dataset.dlArg); }
  const t = e.target.closest('[data-drill]');
  if (!t) return;
  e.preventDefault(); e.stopPropagation();
  if (t.dataset.drill === 'member') { openMemberFromDrill(t.dataset.arg, t); return; }
  openDrill(t.dataset.drill, t.dataset.arg || '', t);
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && document.getElementById('drawer').classList.contains('show')) { closeDrillAll(); return; }
  if (e.key !== 'Enter' && e.key !== ' ') return;
  const t = e.target.closest && e.target.closest('[data-drill],[data-dl-action]');
  if (!t) return;
  e.preventDefault(); t.click();
});
// the page's own close paths (scrim click, drawer ✕) must also clear the stack
document.getElementById('scrim').addEventListener('click', () => { DRILL.stack = []; DRILL.opener = null; });

function openMemberFromDrill(email, opener) {
  if (!DRILL.stack.length) DRILL.opener = opener || null;
  // the review drawer only knows the roster (AI_USERS); anyone else gets the live-spend sheet
  if (!AI_USERS.find((x) => x.email === email)) return openDrill('liveMember', email, opener);
  DRILL.stack.push({ kind: 'member', arg: email });
  openReviewDrawer(email);
  // add a Back link to the review drawer when we came from a drill
  const d = document.getElementById('drawer'); const dh = d.querySelector('.dh');
  if (dh && DRILL.stack.length > 1) {
    const b = document.createElement('div'); b.className = 'sub'; b.style.marginBottom = '6px';
    b.innerHTML = '<span data-dl-action="back" style="cursor:pointer" tabindex="0" role="button">← Back</span>';
    dh.insertBefore(b, dh.querySelector('h2'));
  }
  const x = document.getElementById('dx'); if (x) x.onclick = closeDrillAll;
}
function drillAction(a, arg) {
  if (a === 'back') return drillBack();
  if (a === 'filter') {           // apply a members-table filter and jump to it
    aiUserFilter = arg || 'all'; renderAIUserTable(aiTab === 'copilot' ? 'copilot' : 'claude'); closeDrillAll();
    const el = document.getElementById('aiMembersTitle'); if (el) el.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
    return;
  }
  if (a === 'tab') { aiTab = arg; closeDrillAll(); renderAI(); return; }
  if (a === 'drill') { const [k, x] = String(arg || '').split('|'); openDrill(k, x || ''); return; }
  if (a === 'dept') { deptFilter = arg || ''; closeDrillAll(); renderAI(); return; }
}

/* ---------- data loaders ---------------------------------------------------- */
async function liveData() { return loadLiveData(); }                 // defined in the page (live-analytics loader)
async function monthStats(m) {                                       // summary + breakdown for the SELECTED month
  return cached('month:' + m, async () => {
    const [summary, breakdown] = await Promise.all([getJ('/api/claude-analytics/summary?month=' + m), getJ('/api/claude-analytics/breakdown?month=' + m)]);
    return { summary, breakdown };
  });
}
async function trendFor(m) {                                          // daily series for the selected month (current month only)
  const d = await liveData();
  return (d.trend.series || []).filter((x) => x.day.slice(0, 7) === m);
}
function drawBars(canvasId, labels, data, color, fmt) {
  const el = document.getElementById(canvasId); if (!el || typeof Chart === 'undefined') return;
  DRILL.chart = new Chart(el, { type: 'bar',
    data: { labels, datasets: [{ data, backgroundColor: color, borderRadius: 3, barPercentage: .7 }] },
    options: { responsive: true, maintainAspectRatio: false, animation: matchMedia('(prefers-reduced-motion: reduce)').matches ? false : { duration: 240, easing: 'easeOutQuart' },
      plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => (fmt || usd)(c.parsed.y) } } },
      scales: { x: { ticks: { font: { size: 9 }, color: cssv('--ink-3'), maxTicksLimit: 12 }, grid: { display: false } },
                y: { ticks: { font: { size: 10 }, color: cssv('--ink-3'), callback: (v) => (fmt || usd0)(v) }, grid: { color: cssv('--grid') } } } } });
}

/* ---------- the drills ------------------------------------------------------ */
const DRILLS = {

  async deptDetail(arg) {
    if (!SESS.data) {
      try { await loadSessions(); } catch (e) { throw new Error('Could not load department details — ' + (e.message || e)); }
    }
    const d = SESS.data;
    const x = (d.departments || []).find((r) => r.department === arg);
    if (!x) return { title: arg || 'Department', sub: '', html: dlNote('No data for this department in the selected window.') };
    // Financial-review audience (CFO / analysts): every figure below carries its own
    // formula as permanent sub-text, not a hover-only tooltip, so it still explains
    // itself in a screenshot or a printed copy. Nothing here is recomputed from a
    // different source than the inline "Cost by department" table — same SESS.data.
    const windowLabel = 'in ' + periodShort();
    const smallN = x.members > 0 && x.members < 5;
    // Full per-member roster for this department, straight from the same SESS.data.members
    // array that feeds the Person view — every member, including $0-spend ones, sorted
    // highest-to-lowest by usage-based spend. Intentionally not a top-N cut.
    const deptMembers = (d.members || [])
      .filter((m) => m.department === x.department)
      .sort((a, b) => (b.spend || 0) - (a.spend || 0) || (a.name || '').localeCompare(b.name || ''));
    return {
      title: x.department,
      sub: periodShort() + ' \u00b7 ' + x.pctOfSpend + '% of total org usage-based spend',
      html: dlKv([
        { l: 'Total cost', n: usd(x.totalCost), c: cssv('--accent'), s: usd(x.seatCostTotal) + ' seat/license + ' + usd(x.spend) + ' usage-based' },
        { l: 'Usage-based spend', n: usd(x.spend), s: 'metered Claude usage only — excludes seat/license fees' },
        { l: 'Seat/license cost', n: usd(x.seatCostTotal), s: x.members + ' seat' + (x.members === 1 ? '' : 's') + ' × $' + SEAT_COST + ' per calendar month held — no proration' },
        { l: 'People (active)', n: x.members + ' (' + x.activeMembers + ')', s: x.activeMembers === x.members ? 'all ' + x.members + ' on the roster were active' : (x.members - x.activeMembers) + ' of ' + x.members + ' had no activity ' + windowLabel },
        { l: 'Avg usage / person', n: usd(x.avgSpendPerUser), s: usd(x.spend) + ' usage-based ÷ ' + x.members + ' total people on the roster' },
        { l: 'Avg usage / active', n: x.avgSpendPerActiveUser == null ? '—' : usd(x.avgSpendPerActiveUser), s: x.activeMembers ? usd(x.spend) + ' usage-based ÷ ' + x.activeMembers + ' active people' : 'no active members ' + windowLabel },
        { l: 'Tokens', n: compact(x.tokens), s: 'total Claude token consumption ' + windowLabel },
      ]) +
      (smallN ? dlNote('This department has only ' + x.members + ' people — averages above can be skewed heavily when one person accounts for most of the total. See the individual breakdown below for the actual split.') : '') +
      dlBar(x.pctOfSpend, 'var(--accent)') +
      dlKv([{ l: 'People (Active)', n: String(deptMembers.length), s: 'every current member of ' + x.department + ' — including $0 spend' }]) +
      dlH4('Individual Spender') +
      dlNote('Every member of this department, sorted highest to lowest by usage-based spend. Not a top-N list — $0-spend members are included. Click a name to open their own breakdown.') +
      (deptMembers.length
        ? deptMembers.map((m) => memberRow(m, usd(m.spend || 0))).join('')
        : dlNote('No members found for this department in the member roster.')),
    };
  },

  glossary() {
    const term = (t, d) => `<div style="margin:0 0 12px"><b>${escH(t)}</b><div style="color:var(--ink-2);font-size:12.5px;margin-top:2px;line-height:1.5">${d}</div></div>`;
    return {
      title: 'Glossary — what these terms mean',
      sub: 'Plain-language definitions for labels used across this dashboard',
      html: dlH4('Member status (Session breakdown → Person view)')
        + term('Increase', 'At or over their spend limit — raising it keeps their work from being throttled.')
        + term('Watch', 'Using most of their allowance — likely to hit the limit soon.')
        + term('Right-sized', 'Using a healthy share of their allowance — no change needed.')
        + term('Decrease', 'Using only a small share of their allowance — the limit could be lowered.')
        + term('Reclaim', 'No sessions, tokens, or spend in the selected window — the seat is idle and its limit could be given back.')
        + term('Departed', 'No longer an active member. Their past spend stays on the books, but their seat is not billed and there is nothing to reclaim.')
        + term('No limit', 'No spend limit currently applies to this member.')
        + dlH4('Reporting period')
        + term('30 / 60 / 90 days', 'The last 1 / 2 / 3 FULL calendar months. Every tile, table, chart, drawer and export on the page follows the same period.')
        + term('MTD', 'Month-to-date — the current, incomplete month through today. Always shown separately; never summed into a 30/60/90 period.')
        + term('Full Month', 'A completed calendar month. Picking one in the dropdown shows that month alone.')
        + term('Seat cost', '$' + SEAT_COST + ' per seat per calendar month (contracted). Charged for each whole month a seat is held — a one-seat department is $' + SEAT_COST + ' for one month, never a prorated $19.19.')
        + dlH4('Billing (Spend snapshot)')
        + term('Usage spend', 'What Anthropic metered — the consumption figure this dashboard tracks. It is drawn from prepaid credits, so it does not appear as its own invoice.')
        + term('Seat & plan invoices', 'The annual plan and each added seat, invoiced up front for the remaining term as "Remaining time on N ×" net of "Unused time on N−1 ×".')
        + term('Credits purchased', 'Prepaid usage credits (auto-reload top-ups). Credits purchased − usage metered ≈ the credit balance on the Billing page.')
        + term('Net invoiced / Paid / Open', 'Everything invoiced less refunds; Paid and Open as marked on the Billing page. Net invoiced = Paid + Open.')
        + dlH4('Copilot licences')
        + term('Assigned licences', 'Copilot licences assigned to people (Microsoft Graph). The only seat count used on this page — × $' + COPILOT_UNIT_COST + ' per licence per month.')
        + term('Idle licences / reclaim candidates', 'An assigned Copilot licence nobody has used recently. "Reclaiming" it means cancelling or reassigning the licence so the org stops paying for it — a different "reclaim" than the one above; same word, two different tools.')
        + dlH4('Claude model tiers')
        + term('Haiku', 'The fastest and cheapest tier — built for quick, simple, high-volume tasks. $1 / $5 per million tokens (input/output), Haiku 4.5.')
        + term('Sonnet', 'The everyday workhorse — balanced capability and cost, used for most day-to-day work. This is where most usage on this dashboard runs. $2 / $10 per million tokens (input/output), Sonnet 5.')
        + term('Opus', 'A higher-capability tier for harder, more complex work — costs more per request than Sonnet. $5 / $25 per million tokens (input/output), Opus 5.')
        + term('Fable', 'The newest, top tier — used for the hardest, most autonomous, longest-running work; priced highest. $10 / $50 per million tokens (input/output), Fable 5.1 and Fable 5.')
        + term('Version numbers (e.g. "Sonnet 5")', 'Just the release/generation — a higher number is a newer version of the same tier, not a different capability level. Earlier versions still in use: Opus 4.5–4.8 $5 / $25, Sonnet 4.5–4.6 $3 / $15 per million tokens.')
        + term('Average per request / $ per M tokens paid', 'Calculated from our own usage — spend ÷ requests, or spend ÷ tokens × 1,000,000. They sit below list price because most input is served from cache at a fraction of the rate.')
        + dlNote('Prices shown are Anthropic\'s standard list rates per million tokens as of September 2026 (source: platform.claude.com pricing docs). Actual invoiced rates may differ under an enterprise agreement, and prompt caching / batch processing carry separate discounted rates not shown here.')
        + dlH4('Products (by-product breakdowns)')
        + term('Chat', 'The standard Claude chat interface — conversations, questions, and general assistance.')
        + term('Cowork', 'Claude Cowork — automating files and tasks in a shared workspace.')
        + term('Claude Code', 'The command-line coding agent that writes, edits, and runs code from a terminal.')
        + term('Claude in Chrome', 'The browser extension that reads pages, clicks, types, and fills forms in an existing Chrome tab on the user\'s behalf.')
        + term('Claude Design', 'Claude\'s design/canvas surface for visual mockups and design assets.')
        + term('Research', 'Claude\'s extended research mode — multi-step tasks that search and synthesize many sources.')
        + term('Other', 'Usage that doesn\'t fall into a named product category above.')
        + dlH4('Usage terms')
        + term('Request', 'One exchange with Claude — a single prompt sent and a single reply received. Spend, limits, and usage are all counted per request.')
        + term('Tokens', 'The unit Claude uses to measure and bill usage — pieces of text, roughly 4 characters each. Every prompt in and reply out is counted in tokens; this is the detail behind the dollar figures shown elsewhere.')
        + term('Tokens per request', 'Average tokens consumed per request. A high number usually means long conversations or large documents/context, not necessarily inefficiency — a lot of it is often re-read cache rather than new content.')
        + term('Cache hit rate / "From cache"', 'The share of input tokens served from Claude\'s prompt cache instead of being processed fresh. A higher rate means cheaper, faster requests — the same context is being reused rather than resent.')
        + term('Cost per M tokens', 'Blended price paid per one million tokens this month, across every model tier used. It moves with the mix of models in use — more Opus/Fable usage raises it, more Haiku lowers it.')
        + term('Seat', 'A paid license for one person, billed whether or not they used it that month. Separate from usage-based spend, which only applies when someone actually sends requests.')
        + term('Web searches', 'Server-side web searches Claude performed on the user\'s behalf as part of answering a request — a tool call, not a separate product.'),
    };
  },

  /* Claude tab — KPI tiles ------------------------------------------------- */
  async members() {
    const all = scoped(), active = all.filter((u) => rowActive(u)), inactive = all.filter((u) => !rowActive(u));
    const review = all.filter((u) => u.needsReview), disabled = all.filter((u) => u.accountEnabled === 0 || u.accountEnabled === false);
    const seats = AI_ORG.assignedSeats, live = AI_ORG.rosterSource === 'members-api';
    const roles = {}; all.forEach((u) => { if (u.role) roles[u.role] = (roles[u.role] || 0) + 1; });
    return {
      title: 'Members', sub: (seats ? seats + ' seats assigned · ' : '') + all.length + ' known' + (deptFilter ? ' in ' + escH(deptFilter) : '') +
        ' · roster ' + (live ? 'live from the Members API' : 'from the last CSV import' + (AI_ORG.rosterAsOf ? ' (' + String(AI_ORG.rosterAsOf).slice(0, 7) + ')' : '')),
      html: dlKv([
        { l: 'Active in period', n: active.length, c: cssv('--pass') },
        { l: 'Not yet active', n: inactive.length, c: cssv('--ink-2') },
        { l: 'Custom limits', n: all.filter((u) => u.customLimit).length, c: cssv('--low') },
        { l: 'Needs directory review', n: review.length, c: review.length ? cssv('--high') : cssv('--ink-2') },
        { l: 'Disabled account', n: disabled.length, c: disabled.length ? cssv('--crit') : cssv('--ink-2'), s: 'seat still held' },
        { l: 'Seats vs known', n: seats ? (seats - all.length >= 0 ? '+' : '') + (seats - all.length) : '—', s: seats ? 'assigned minus known' : 'seat count needs the API' },
      ]) +
      dlChips([{ l: 'Show all in table', a: 'filter', arg: 'all' }, { l: 'Active only', a: 'filter', arg: 'active' }, { l: 'Inactive only', a: 'filter', arg: 'inactive' }]) +
      (Object.keys(roles).length ? dlH4('By role') + Object.entries(roles).sort((a, b) => b[1] - a[1]).map(([r, n]) => dlRow(escH(r.replace(/_/g, ' ')), n + ' <span style="color:var(--ink-3);font-weight:400">members</span>')).join('') : '') +
      (disabled.length ? dlH4('Disabled accounts still holding a seat') + disabled.map((u) => memberRow(u, usd(u.mtd), escH(u.email))).join('') : '') +
      (review.length ? dlH4('No directory match (' + review.length + ')') + review.slice(0, 15).map((u) => memberRow(u, usd(u.mtd), escH(u.email) + ' · not in Entra, no override')).join('')
        + (review.length > 15 ? dlNote(review.length - 15 + ' more — use the table filter') : '') : ''),
    };
  },

  async active() {
    const act = scoped().filter((u) => rowActive(u)).sort((a, b) => b.mtd - a.mtd);
    const sp = act.map((u) => u.mtd), max = sp[0] || 1;
    const buckets = [['1–5 days', 1, 5], ['6–10', 6, 10], ['11–20', 11, 20], ['21+', 21, 99]].map(([l, a, b]) => [l, act.filter((u) => u.daysActive != null && u.daysActive >= a && u.daysActive <= b).length]);
    const noDays = act.filter((u) => u.daysActive == null).length;
    return {
      title: 'Active in period', sub: act.length + ' members with recorded activity, usage or spend · ' + periodShort() + (deptFilter ? ' · ' + escH(deptFilter) : ''),
      html: dlKv([
        { l: 'Total spend', n: usd(sp.reduce((a, b) => a + b, 0)), c: cssv('--accent') },
        { l: 'Median (typical member)', n: usd(median(sp)) }, { l: '90% spend less than', n: usd(pctile(sp, .9)) },
        { l: 'Top spender', n: usd(max), s: escH((act[0] || {}).name || '') },
        { l: 'Near or over limit', n: act.filter((u) => { const l = rowLimitP(u); return l && u.mtd / l >= .75; }).length, c: cssv('--high'), s: 'vs monthly limit × ' + limMonths() + ' mo' },
        { l: 'No limit on file', n: act.filter((u) => (_limLive() ? u.unlimited : !(u.customLimit || u.groupLimit))).length, c: cssv('--ink-2') },
      ]) +
      dlChips([{ l: 'Active in table', a: 'filter', arg: 'active' }, { l: 'Over / near limit', a: 'filter', arg: 'custom' }]) +
      dlH4('Days active in period — how many members were active on that many days') + buckets.map(([l, n]) => dlRow(escH(l) + ' days', n + ' <span style="color:var(--ink-3);font-weight:400">members · ' + dlPct(n, act.length || 1) + '%</span>' + dlBar(dlPct(n, act.length || 1), 'var(--pass)'))).join('') +
      (noDays ? dlNote(noDays + ' with no activity record yet (activity lags a day)') : '') +
      dlH4('Highest-spending members') + act.slice(0, 12).map((u) => memberRow(u, usd(u.mtd) + dlBar(dlPct(u.mtd, max)), (u.daysActive != null ? u.daysActive + ' active days · ' : '') + dlN(u.requests) + ' <span class="term-tip" data-term="requests">requests</span>')).join(''),
    };
  },

  async limits() {
    const all = scoped(); const live = _limLive();
    // cap = the MONTHLY limit × months in the reporting period (same rule as rowPct everywhere)
    const withCap = all.map((u) => ({ u, capM: live ? (u.unlimited ? null : u.effectiveLimit) : (u.customLimit || u.groupLimit || null) })).map((x) => ({ ...x, cap: x.capM == null ? null : x.capM * limMonths() })).filter((x) => x.cap);
    withCap.sort((a, b) => (b.u.mtd / b.cap) - (a.u.mtd / a.cap));
    const over = withCap.filter((x) => x.u.mtd >= x.cap).length, near = withCap.filter((x) => x.u.mtd / x.cap >= .75 && x.u.mtd < x.cap).length;
    const custom = all.filter((u) => u.customLimit).length;
    let req = '';
    if (live) {
      try {
        const rq = await cached('limit-requests', () => getJ('/api/claude-analytics/limit-requests'));
        if (rq.available) req = dlH4('Pending limit increase requests', true) + ((rq.pending || []).map((r) => dlRow(`<b>${escH(r.name || r.email || '—')}</b>`, (r.currentLimit != null ? usd(r.ptdSpend || 0) + ' / ' + usd(r.currentLimit) : '—'), 'pending since ' + escH(String(r.createdAt || '').slice(0, 10)))).join('') || dlNote('No pending <span class="term-tip" data-term="requests">requests</span>.'));
      } catch (e) { /* not available */ }
    }
    const tag = (u) => live ? escH(u.limitLabel || '') : (u.customLimit ? 'Custom limit' : 'Group limit');
    return {
      title: live ? 'Spend limits' : 'Custom limits',
      sub: live ? 'Live · Spend Limits API · as of ' + escH(String(AI_ORG.memberLimitsAsOf || '').replace('T', ' ').slice(0, 16)) + ' UTC' + (AI_ORG.memberDefaultLimit != null ? ' · default ' + usd0(AI_ORG.memberDefaultLimit) : '')
                : 'From the CSV import' + (AI_ORG.memberLimitsAsOf ? ' (' + String(AI_ORG.memberLimitsAsOf).slice(0, 7) + ')' : '') + ' · not live until the key carries read:spend_limits',
      html: dlKv([
        { l: 'Custom overrides', n: custom, c: cssv('--low') }, { l: 'With any limit', n: withCap.length },
        { l: 'Over limit', n: over, c: over ? cssv('--crit') : cssv('--ink-2') }, { l: 'Near limit (≥75%)', n: near, c: near ? cssv('--high') : cssv('--ink-2') },
        { l: 'Unlimited', n: live ? all.filter((u) => u.unlimited).length : all.length - withCap.length, c: cssv('--ink-2') },
        { l: 'Default limit', n: AI_ORG.memberDefaultLimit != null ? usd0(AI_ORG.memberDefaultLimit) : (AI_ORG.groupLimit ? usd0(AI_ORG.groupLimit) : '—'), s: live ? escH(String(AI_ORG.memberDefaultSource || '').replace(/_/g, ' ')) : 'group default (CSV)' },
      ]) +
      dlChips([{ l: 'Custom limit in table', a: 'filter', arg: 'custom' }]) + req +
      dlNote('Limits are monthly caps; usage for ' + periodShort() + ' is measured against the limit × ' + limMonths() + ' month' + (limMonths() > 1 ? 's' : '') + '.') +
      dlH4('Utilization, highest first') + withCap.slice(0, 25).map(({ u, cap, capM }) => {
        const p = dlPct(u.mtd, cap); const col = p >= 100 ? 'var(--crit)' : p >= 75 ? 'var(--high)' : 'var(--accent)';
        return memberRow(u, `<span style="color:${col}">${p}%</span> · ${usd(u.mtd)} / ${usd0(cap)}` + dlBar(p, col), tag(u) + (limMonths() > 1 ? ' · ' + usd0(capM) + '/mo' : ''));
      }).join('') + (withCap.length > 25 ? dlNote(withCap.length - 25 + ' more') : ''),
    };
  },

  async spend() {
    const P = periodBounds(); const d = await liveData();
    const sc = scoped();
    const top = sc.filter((u) => u.mtd > 0).sort((a, b) => b.mtd - a.mtd).slice(0, 6);
    const activeCount = sc.filter((u) => rowActive(u)).length;
    // Period figures come from the same /sessions rows as the tiles and the department
    // table; the org-wide product split from /tokens (period). With a department filter
    // only the department's own member rows are used and org-wide splits are hidden.
    const spend = deptFilter ? sc.reduce((a, u) => a + (u.mtd || 0), 0) : (AI_ORG.periodSpend || sc.reduce((a, u) => a + (u.mtd || 0), 0));
    const reqCount = sc.reduce((a, u) => a + (u.requests || 0), 0);
    const seatCost = deptFilter ? sc.reduce((a, u) => a + (u.seatCost || 0), 0) : (AI_ORG.periodSeatCost || 0);
    const pl = ((d.tokens && d.tokens.byProduct) || []).map((x) => ({ product: x.product, spend: Number(x.spend) || 0, requests: Number(x.requests) || 0 })).filter((x) => x.spend > 0).sort((a, b) => b.spend - a.spend);
    const plT = pl.reduce((s, x) => s + x.spend, 0) || 1;
    const series = (P.mode === 'month' ? (d.trend.series || []) : ((d.trendP && d.trendP.series) || [])).filter((x) => x.day >= P.from && x.day <= P.to);
    const su = d.summary;
    const rows = [
      { l: 'Usage spend', n: usd(spend), c: cssv('--accent'), term: 'usageSpend' },
      { l: 'Seat cost', n: usd(seatCost), s: (deptFilter ? sc.filter((u) => !u.departed).length + ' seat holders × $' + SEAT_COST + (P.n > 1 ? ' × ' + P.n + ' mo' : '') : seatLabelP(P) + (P.n > 1 ? ' (' + (AI_ORG.assignedSeats || '—') + ' seats assigned now)' : '')), term: 'seatMonths' },
      { l: 'Total cost', n: usd(spend + seatCost), c: cssv('--ink'), term: 'totalCost' },
    ];
    if (P.mode === 'month' && P.mtd && !deptFilter) {
      rows.push({ l: 'Projected month-end', n: su.projectedMonthEnd != null ? usd0(su.projectedMonthEnd) : '—', s: 'at ' + usd(su.runRatePerDay) + '/day · day ' + su.daysElapsed + ' of ' + su.daysInMonth, term: 'projectedMonthEnd' });
      rows.push({ l: 'vs last month', n: su.momPct == null ? '—' : (su.momPct >= 0 ? '+' : '') + su.momPct.toFixed(0) + '%', s: 'same ' + su.daysElapsed + ' days: ' + usd0(su.prevMonthSameSpan), term: 'vsLastMonth' });
    }
    rows.push({ l: 'Cost per request', n: reqCount ? usd(spend / reqCount) : '—', term: 'costPerRequest' });
    rows.push({ l: 'Active members', n: activeCount, s: 'avg ' + usd(spend / (activeCount || 1)), term: 'activeMembers' });
    rows.push({ l: 'Months in period', n: P.n, s: P.months.map((m) => ymShort(m)).join(' · ') + (P.mode === 'month' && P.mtd ? ' (MTD)' : '') });
    return {
      title: 'Usage spend · ' + P.short + (deptFilter ? ' · ' + escH(deptFilter) : ''),
      sub: liveStar('Live from the Claude Analytics API') + usd(spend) + ' usage · ' + dlN(reqCount) + ' <span class="term-tip" data-term="requests">requests</span>' + (deptFilter ? '' : ' · ' + series.length + ' days recorded'),
      html: dlKv(rows) +
      dlNote('Seat cost = each calendar month\'s seats × $' + SEAT_COST + ' (whole months, no proration). Usage is what Anthropic metered in the same months; Anthropic revises recent days for up to 30 days.') +
      (!deptFilter && series.length ? dlH4('Daily usage spend') + '<div style="height:150px;margin-bottom:14px"><canvas id="dlChart"></canvas></div>' : '') +
      (deptFilter
        ? dlNote('The daily trend and the by-product split are org-wide only — not available broken down by department.')
        : dlH4('By product') + pl.map((x) => dlRow(`<span style="display:inline-block;width:9px;height:9px;border-radius:2px;background:${PRODUCT_COLOR[x.product] || PRODUCT_COLOR.other};margin-right:7px"></span><span class="term-tip" data-term="${escH(x.product||'other')}">${escH(prettyProduct(x.product))}</span>`,
            usd(x.spend) + ' <span style="color:var(--ink-3)">' + dlPct(x.spend, plT) + '%</span>' + dlBar(dlPct(x.spend, plT), PRODUCT_COLOR[x.product] || PRODUCT_COLOR.other), dlN(x.requests) + ' <span class="term-tip" data-term="requests">requests</span> · ' + (x.requests ? usd(x.spend / x.requests) : '—') + ' <span class="term-tip" data-term="perRequest">per request</span>')).join('')
      ) +
      dlH4('Highest-spending members') + top.map((u) => memberRow(u, usd(u.mtd), dlN(u.requests) + ' <span class="term-tip" data-term="requests">requests</span>')).join(''),
      after: () => { if (!deptFilter && series.length) drawBars('dlChart', series.map((x) => x.day.slice(5)), series.map((x) => x.total), cssv('--accent')); },
    };
  },

  async avg() {
    const act = scoped().filter((u) => rowActive(u)); const sp = act.map((u) => u.mtd);
    const total = sp.reduce((a, b) => a + b, 0), mean = act.length ? total / act.length : 0;
    const reqs = act.reduce((a, u) => a + (u.requests || 0), 0);
    const buckets = [['under $10', 0, 10], ['$10–50', 10, 50], ['$50–100', 50, 100], ['$100–300', 100, 300], ['$300+', 300, 1e12]].map(([l, a, b]) => [l, sp.filter((v) => v >= a && v < b).length]);
    const bmax = Math.max(...buckets.map((b) => b[1]), 1);
    return {
      title: 'How spend varies across active members', sub: act.length + ' active · ' + usd(total) + ' total · ' + periodShort(),
      html: dlKv([
        { l: 'Average', n: usd(mean), c: cssv('--low') }, { l: 'Median (typical member)', n: usd(median(sp)) }, { l: '90% spend less than', n: usd(pctile(sp, .9)) },
        { l: 'Highest', n: usd(Math.max(0, ...sp)) }, { l: 'Requests per active member', n: dlN(act.length ? reqs / act.length : 0) }, { l: 'Cost per request', n: reqs ? usd(total / reqs) : '—' },
      ]) +
      dlH4('Distribution — how many active members spent this much in the period') + buckets.map(([l, n]) => dlRow(escH(l), n + ' <span style="color:var(--ink-3);font-weight:400">members · ' + dlPct(n, act.length || 1) + '%</span>' + dlBar(dlPct(n, bmax), 'var(--low)'))).join('') +
      dlNote('The average (' + usd(mean) + ') looks high because a handful of heavy users spend much more than everyone else. Half of active members actually spend less than ' + usd(median(sp)) + ' — that is a better sense of what a typical person spends.') +
      dlH4('Highest-spending members') + [...act].sort((a, b) => b.mtd - a.mtd).slice(0, 8).map((u) => memberRow(u, usd(u.mtd), (u.requests ? dlN(u.requests) + ' <span class="term-tip" data-term="requests">requests</span> · ' + usd(u.mtd / u.requests) + '/req' : ''))).join(''),
    };
  },

  async reset() {
    const m = ym(); const { summary: su } = await monthStats(m); const cur = isCurrentMonth();
    const next = new Date(Date.UTC(+m.slice(0, 4), +m.slice(5, 7), 1));
    const msLeft = next.getTime() - Date.now(); const dLeft = Math.max(0, Math.floor(msLeft / 864e5)), hLeft = Math.max(0, Math.floor((msLeft % 864e5) / 36e5));
    return {
      title: 'Reset cycle', sub: 'Resets ' + escH(AI_ORG.resetDate) + ' at 00:00 UTC · monthly period (the only period Anthropic offers)',
      html: dlKv([
        { l: 'Time to reset', n: cur ? dLeft + 'd ' + hLeft + 'h' : 'ended', c: cssv('--accent') },
        { l: 'Average Daily Spend', n: usd(su.runRatePerDay) },
        { l: 'Projected month-end', n: su.projectedMonthEnd != null ? usd0(su.projectedMonthEnd) : usd0(su.spend), c: cssv('--ink') },
        { l: 'Previous month', n: usd(su.prevMonthSpend) },
      ]) +
      '<div class="sub" style="margin:12px 0 0;line-height:1.6">Member limits reset with the org on the 1st; a member who is paused for exceeding their limit regains access automatically then. Cost figures are revised by Anthropic for up to 30 days.</div>',
    };
  },

  /* Live analytics — headline tiles ------------------------------------------ */
  async liveSpend() {
    const d = await liveData(); const su = d.summary; const m = su.month;
    const series = await trendFor(m); const prods = [...new Set(series.flatMap((x) => Object.keys(x.products || {})))];
    const tot = series.reduce((s, x) => s + x.total, 0);
    return {
      title: 'Spend this month · ' + m, sub: usd(su.spend) + ' · ' + su.daysWithData + ' day(s) recorded · data as of ' + escH(String(su.dataRefreshedAt || '').replace('T', ' ').slice(0, 16)) + ' UTC',
      html: dlKv([{ l: 'Month-to-date', n: usd(su.spend), c: cssv('--accent') }, { l: 'Best day', n: series.length ? usd(Math.max(...series.map((x) => x.total))) : '—', s: series.length ? series.slice().sort((a, b) => b.total - a.total)[0].day : '' }, { l: 'Average / recorded day', n: usd(series.length ? tot / series.length : 0) }]) +
      '<div style="height:150px;margin-bottom:14px"><canvas id="dlChart"></canvas></div>' +
      dlH4('Day by day') + '<div style="overflow-x:auto"><table style="font-size:12px"><thead><tr><th>Day</th>' + prods.map((p) => '<th>' + escH(prettyProduct(p)) + '</th>').join('') + '<th>Total</th><th><span class="term-tip" data-term="requests">Req</span></th></tr></thead><tbody>' +
      series.slice().reverse().map((x) => '<tr><td class="mono">' + x.day.slice(5) + '</td>' + prods.map((p) => '<td class="mono">' + (x.products[p] ? usd(x.products[p]) : '—') + '</td>').join('') + '<td class="mono"><b>' + usd(x.total) + '</b></td><td class="mono">' + dlN(x.requests) + '</td></tr>').join('') + '</tbody></table></div>',
      after: () => drawBars('dlChart', series.map((x) => x.day.slice(8)), series.map((x) => x.total), cssv('--accent')),
    };
  },
  async liveProjected() {
    const d = await liveData(); const su = d.summary;
    return {
      title: 'Projection', sub: 'mean daily spend so far, extended to month end',
      html: dlKv([
        { l: 'Spend so far', n: usd(su.spend) }, { l: 'Days elapsed', n: su.daysElapsed + ' / ' + su.daysInMonth }, { l: 'Average Daily Spend', n: usd(su.runRatePerDay), c: cssv('--accent') },
        { l: 'Projected month-end', n: su.projectedMonthEnd != null ? usd0(su.projectedMonthEnd) : '—', c: cssv('--v-claude') },
      ]) +
      '<div class="sub" style="margin-top:12px;line-height:1.6">Projection = spend ÷ days elapsed × days in month. It assumes the rest of the month looks like the start; weekends and month-end pushes both bend it. Recent days are provisional for up to 30 days.</div>',
    };
  },
  async liveMoM() {
    const d = await liveData(); const su = d.summary; const months = (d.breakdown.months || []).slice().reverse();
    const mx = Math.max(...months.map((x) => x.spend), 1);
    return {
      title: 'Month over month', sub: su.momBasis === 'same-span' ? 'compared over the same ' + su.daysElapsed + ' day(s) of last month' : 'full month vs full month',
      html: dlKv([
        { l: 'This month so far', n: usd(su.spend), c: cssv('--accent') }, { l: 'Last month, same span', n: usd(su.prevMonthSameSpan) }, { l: 'Last month, full', n: usd(su.prevMonthSpend) },
        { l: 'Change', n: su.momPct == null ? '—' : (su.momPct >= 0 ? '+' : '') + su.momPct.toFixed(0) + '%', c: su.momPct >= 0 ? cssv('--high') : cssv('--pass') },
      ]) +
      dlH4('All months on record') + months.map((x) => dlRow('<span class="mono">' + escH(x.month) + '</span>', usd(x.spend) + dlBar(dlPct(x.spend, mx), x.month === su.month ? 'var(--accent)' : 'var(--line-2)'))).join(''),
    };
  },
  async liveEngagement() {
    const d = await liveData(); const su = d.summary; const e = su.engagement || {};
    const st = e.dau && e.mau ? dlPct(e.dau, e.mau) : null;
    return {
      title: 'Engagement', sub: 'active-user counts from the Analytics API · ' + escH(String(e.day || '').slice(0, 10)),
      html: dlKv([
        { l: 'Daily active', n: e.dau ?? '—' }, { l: 'Weekly active', n: e.wau ?? '—', c: cssv('--pass') }, { l: 'Monthly active', n: e.mau ?? '—' },
        { l: 'Assigned seats', n: e.assigned_seats ?? '—' }, { l: 'Pending invites', n: e.pending_invites ?? '—', c: e.pending_invites ? cssv('--high') : cssv('--ink-2') },
        { l: 'Stickiness (DAU/MAU)', n: st != null ? st + '%' : '—', s: 'how much of the monthly base shows up daily' },
      ]) +
      dlH4('Adoption rates') + [['Daily', e.daily_adoption_rate], ['Weekly', e.weekly_adoption_rate], ['Monthly', e.monthly_adoption_rate]].map(([l, v]) => dlRow(escH(l), (v != null ? Number(v).toFixed(0) + '%' : '—') + dlBar(Number(v) || 0, 'var(--low)'))).join('') +
      dlNote('A member counts as active on a day with a chat message, a Claude Code session with tool use or git activity, or a Cowork session with activity.'),
    };
  },
  async liveRequests() {
    const d = await liveData(); const P = periodBounds();
    const pl = ((d.tokens && d.tokens.byProduct) || []).map((x) => ({ ...x, requests: Number(x.requests) || 0, spend: Number(x.spend) || 0, tokens: Number(x.tokens) || 0 })).sort((a, b) => b.requests - a.requests);
    const ml = ((d.tokens && d.tokens.byModel) || []).map((x) => ({ ...x, requests: Number(x.requests) || 0, spend: Number(x.spend) || 0, tokens: Number(x.tokens) || 0 })).sort((a, b) => b.requests - a.requests);
    const series = (d.trendP && d.trendP.series) || [];
    const req = series.reduce((s, x) => s + (Number(x.requests) || 0), 0) || pl.reduce((s, x) => s + x.requests, 0);
    const spend = series.reduce((s, x) => s + (Number(x.total) || 0), 0);
    const rT = pl.reduce((s, x) => s + x.requests, 0) || 1, mT = ml.reduce((s, x) => s + x.requests, 0) || 1;
    return {
      title: 'Requests · ' + P.short, sub: dlN(req) + ' <span class="term-tip" data-term="requests">requests</span> · ' + usd(spend) + ' usage · ' + usd(spend / (req || 1)) + ' average <span class="term-tip" data-term="perRequest">per request</span> · Anthropic direct',
      html: dlNote('One <b>request</b> = one prompt sent and one reply received. The big number on each row is how many requests that product or model handled in the period; the share is its slice of all requests. <b>Average per request</b> = that row\'s usage spend ÷ its requests — a calculated average, not a price. Hover any product or model name for what it is (and, for models, Anthropic\'s list price). Counted from Anthropic\'s Analytics API; no AWS / Bedrock usage is included.') +
        dlKv([{ l: 'Requests in period', n: dlN(req), term: 'requests' }, { l: 'Usage spend', n: usd(spend), c: cssv('--accent'), term: 'usageSpend' }, { l: 'Average per request', n: usd(spend / (req || 1)), s: 'spend ÷ requests', term: 'perRequest' }]) +
        dlH4('By product — which Claude surface the requests came from') + pl.map((x) => dlRow(productTip(x.product),
          dlN(x.requests) + ' <span style="color:var(--ink-3)">' + dlPct(x.requests, rT) + '%</span>' + dlBar(dlPct(x.requests, rT), PRODUCT_COLOR[x.product] || PRODUCT_COLOR.other),
          dlN(x.requests) + ' requests = ' + dlPct(x.requests, rT) + '% of all requests · ' + (x.spend > 0 ? usd(x.spend) + ' usage · ' + perReq(x.spend, x.requests) + ' average per request' : 'usage recorded, nothing billed') + (x.tokens ? ' · ' + compact(x.tokens) + ' tokens' : ''))).join('') +
        dlH4('By model — which Claude model answered them') + ml.map((x) => { const mi = modelInfo(x.model); return dlRow(modelTip(x.model) + ' <span style="color:var(--ink-3);font-size:10.5px">' + escH(mi.tier) + '</span>',
          dlN(x.requests) + ' <span style="color:var(--ink-3)">' + dlPct(x.requests, mT) + '%</span>' + dlBar(dlPct(x.requests, mT), 'var(--accent)'),
          dlN(x.requests) + ' requests = ' + dlPct(x.requests, mT) + '% of all requests · ' + usd(x.spend) + ' usage spend on this model · ' + perReq(x.spend, x.requests) + ' average per request · list price ' + escH(mi.priceText) + (x.tokens && x.spend ? ' · paid ' + usd(x.spend / x.tokens * 1e6) + ' per M tokens blended' : '')); }).join('') +
        dlNote('Why the same tier can show different averages: a request that re-reads a lot of cached context costs far less than one that sends fresh context, and long replies cost more than short ones. List prices are Anthropic\'s standard rates (platform.claude.com pricing, Sep 2026); enterprise rates may differ.'),
    };
  },

  /* Live analytics — engineering & cache tiles, list rows ---------------------- */
  async liveProd(metric) {
    const d = await liveData(); const p = d.productivity; const t = p.totals || {};
    const keys = { sessions: ['cc_sessions', 'Code sessions', (x) => dlN(x.cc_sessions)], loc: ['loc_added', 'Lines added', (x) => compact(x.loc_added) + ' +/ ' + compact(x.loc_removed) + ' −'], commits: ['commits', 'Commits', (x) => dlN(x.commits) + ' · ' + dlN(x.prs) + ' PRs'], accept: ['accepted', 'Edits accepted', (x) => { const a = Number(x.accepted) || 0, r = Number(x.rejected) || 0; return p.rejectedReported ? (a + r ? Math.round(a / (a + r) * 100) + '% · ' + a + ' / ' + r : '—') : (a ? dlN(a) + ' accepted · rate —' : '—'); }] };
    const [k, label, fmt] = keys[metric] || keys.sessions;
    const people = (p.people || []).filter((x) => Number(x[k]) > 0 || (metric === 'accept' && Number(x.accepted) + Number(x.rejected) > 0)).sort((a, b) => Number(b[k]) - Number(a[k]));
    return {
      title: label, sub: 'Claude Code · last ' + p.days + ' days · ' + people.length + ' people',
      html: dlKv([{ l: 'Code sessions', n: dlN(t.cc_sessions) }, { l: 'Commits / PRs', n: dlN(t.commits) + ' / ' + dlN(t.prs) }, { l: 'Net lines', n: compact((Number(t.loc_added) || 0) - (Number(t.loc_removed) || 0)), s: compact(t.loc_added) + ' added · ' + compact(t.loc_removed) + ' removed' },
        { l: 'Edit acceptance rate', n: p.rejectedReported && t.acceptanceRate != null ? t.acceptanceRate.toFixed(0) + '%' : '—', s: p.rejectedReported ? dlN(t.accepted) + ' accepted · ' + dlN(t.rejected) + ' rejected' : dlN(t.accepted) + ' accepted · rejections not reported by the Analytics API' }, { l: 'Cowork sessions', n: dlN(t.cowork_sessions) }, { l: 'Cowork file edits', n: dlN(t.cowork_file_edits) }]) +
      dlH4('People, by ' + label.toLowerCase()) + people.slice(0, 20).map((x) => memberRow({ name: x.name, email: x.email, dept: x.department }, fmt(x), 'last active ' + escH(String(x.last_active || '').slice(0, 10)))).join(''),
    };
  },
  async liveCache(metric) {
    const d = await liveData(); const c = d.cache; const bm = (c.byModel || []).map((x) => ({ ...x, hit: dlHit(x.cache_read, x.uncached_input, x.cache_created) }));
    const titles = { hit: 'Cache hit rate', cached: 'Cached input tokens', uncached: 'Uncached input tokens', output: 'Output tokens', search: 'Web searches' };
    return {
      title: titles[metric] || 'Prompt cache', sub: 'last ' + c.days + ' days · by model',
      html: dlNote('Every request sends input tokens (the prompt plus context) and gets back output tokens (the reply). Input that was recently processed is served from the prompt cache at a fraction of the price; the hit rate is the share of input that came from cache. Hover any column header for its definition.') +
        dlKv([{ l: 'Hit rate', n: c.cacheHitRate != null ? c.cacheHitRate.toFixed(1) + '%' : '—', c: cssv('--pass'), term: 'cacheHitRate' }, { l: 'Cached input', n: compact(c.totals.cache_read), term: 'cachedInput' }, { l: 'Cache writes', n: compact(c.totals.cache_created), term: 'cacheWrite' }, { l: 'Uncached input', n: compact(c.totals.uncached_input), c: cssv('--high'), term: 'uncachedInput' }, { l: 'Output', n: compact(c.totals.output_tokens), term: 'outputTokens' }, { l: 'Requests', n: dlN(c.totals.requests), term: 'requests' }]) +
      '<div style="overflow-x:auto"><table style="font-size:12px"><thead><tr><th>Model</th><th><span class="term-tip" data-term="cacheHitRate">Hit</span></th><th><span class="term-tip" data-term="cachedInput">Cached</span></th><th><span class="term-tip" data-term="cacheWrite">Writes</span></th><th><span class="term-tip" data-term="uncachedInput">Uncached</span></th><th><span class="term-tip" data-term="outputTokens">Output</span></th><th><span class="term-tip" data-term="requests">Req</span></th></tr></thead><tbody>' +
      bm.map((x) => `<tr><td>${modelTip(x.model)}</td><td class="mono" style="color:${x.hit == null ? 'var(--ink-3)' : x.hit >= 70 ? 'var(--pass)' : x.hit >= 40 ? 'var(--high)' : 'var(--crit)'}">${x.hit == null ? '—' : x.hit.toFixed(0) + '%'}</td><td class="mono">${compact(x.cache_read)}</td><td class="mono">${compact(x.cache_created)}</td><td class="mono">${compact(x.uncached_input)}</td><td class="mono">${compact(x.output_tokens)}</td><td class="mono">${dlN(x.requests)}</td></tr>`).join('') + '</tbody></table></div>' +
      dlNote(escH(c.note || '')),
    };
  },
  async liveProduct(product) {
    const d = await liveData(); const P = periodBounds();
    const pl = ((d.tokens && d.tokens.byProduct) || []).map((x) => ({ product: x.product, spend: Number(x.spend) || 0, requests: Number(x.requests) || 0 }));
    const row = pl.find((x) => x.product === product) || {};
    // A product can report usage and bill nothing (research; also claude_code in 2026-06).
    // Two things break then, not one: /breakdown drops it entirely (its query ends
    // `HAVING spend > 0`), so `row` is {} and the KV block has no numbers at all; and the
    // member list is ranked by spend, so every member filters out. Fall back to the
    // /tokens row this panel is itself drawn from — the number the user just clicked — and
    // rank members by requests. Billed products take the original path untouched.
    const trow = ((d.tokens && d.tokens.byProduct) || []).find((x) => x.product === product) || {};
    const billed = Number(row.spend) > 0;
    const reqTot = Number(row.requests) || Number(trow.requests) || 0;
    const val = (m) => (billed ? m.ps : m.pq);
    const members = (d.members.members || []).map((m) => ({ ...m, ps: (m.products || {})[product] || 0, pq: (m.productRequests || {})[product] || 0 })).filter((m) => val(m) > 0).sort((a, b) => val(b) - val(a));
    const tot = members.reduce((s, m) => s + val(m), 0) || 1, all = pl.reduce((s, x) => s + x.spend, 0) || 1;
    return {
      title: prettyProduct(product), sub: (billed ? usd(row.spend || 0) + ' · ' + dlPct(row.spend || 0, all) + '% of usage · ' : 'not billed · ') + P.short + ' · member split for ' + d.breakdown.month,
      html: dlNote(escH(productDesc(product))) + dlKv([{ l: 'Spend', n: billed ? usd(row.spend || 0) : 'not billed', c: PRODUCT_COLOR[product] || PRODUCT_COLOR.other, s: 'usage-based spend from this product in the period' }, { l: 'Requests', n: billed ? dlN(row.requests) : (reqTot ? dlN(reqTot) : '—'), term: 'requests' }, { l: 'Cost / request', n: billed && row.requests ? usd(row.spend / row.requests) : '—', term: 'costPerRequest' }]) +
        dlH4('Members using ' + prettyProduct(product) + ' — ' + escH(String(d.breakdown.month))) + dlNote('Per-member product detail is monthly; the headline figures above are for the period.') + (billed ? '' : dlNote('This product is not billed, so members are ranked by <span class="term-tip" data-term="requests">requests</span>.')) +
        (members.length ? members.slice(0, 25).map((m) => memberRow({ name: m.name, email: m.email, dept: m.department }, (billed ? usd(m.ps) : dlN(m.pq) + ' req') + ' <span style="color:var(--ink-3)">' + dlPct(val(m), tot) + '%</span>' + dlBar(dlPct(val(m), val(members[0])), PRODUCT_COLOR[product] || PRODUCT_COLOR.other), billed ? dlPct(m.ps, m.spend || 1) + '% of their total' : dlN(m.pq) + ' <span class="term-tip" data-term="requests">requests</span>')).join('')
          : '<div class="sub">No member-level rows for this product in ' + escH(String(d.breakdown.month)) + '.</div>'),
    };
  },
  async liveModel(model) {
    const d = await liveData(); const P = periodBounds();
    const ml = ((d.tokens && d.tokens.byModel) || []).map((x) => ({ model: x.model, spend: Number(x.spend) || 0, requests: Number(x.requests) || 0, tokens: Number(x.tokens) || 0 })).sort((a, b) => b.spend - a.spend);
    const row = ml.find((x) => x.model === model) || {};
    const all = ml.reduce((s, x) => s + x.spend, 0) || 1; const cm = (d.cache.byModel || []).find((x) => x.model === model) || {};
    const hit = dlHit(cm.cache_read, cm.uncached_input, cm.cache_created);
    return {
      title: modelLabel(model), sub: escH(modelInfo(model).tier) + ' · ' + usd(row.spend || 0) + ' · ' + dlPct(row.spend || 0, all) + '% of usage · ' + P.short + ' · Anthropic direct',
      html: dlNote(escH(modelInfo(model).desc)) +
        dlKv([{ l: 'Spend', n: usd(row.spend || 0), c: cssv('--accent'), s: 'usage billed to this model in the period' }, { l: 'Requests', n: dlN(row.requests), term: 'requests' }, { l: 'Cost / request', n: row.requests ? usd(row.spend / row.requests) : '—', term: 'costPerRequest' },
        { l: 'List price', n: modelInfo(model).price ? '$' + modelInfo(model).price[0] + ' / $' + modelInfo(model).price[1] : '—', s: 'per million tokens, input / output' }, { l: 'Paid per M tokens', n: row.tokens && row.spend ? usd(row.spend / row.tokens * 1e6) : '—', s: 'blended — cached input is cheaper than list' }, { l: 'Tokens', n: compact(row.tokens), term: 'tokens' },
        { l: 'Cache hit (30d)', n: hit == null ? '—' : hit.toFixed(0) + '%', c: hit == null ? cssv('--ink-2') : hit >= 70 ? cssv('--pass') : cssv('--high') }, { l: 'Cache read / write / uncached', n: compact(cm.cache_read) + ' / ' + compact(cm.cache_created) + ' / ' + compact(cm.uncached_input) }, { l: 'Output tokens (30d)', n: compact(cm.output_tokens) }]) +
        dlH4('All models in period') + ml.map((x) => dlRow(modelTip(x.model) + (x.model === model ? ' <span style="color:var(--accent);font-size:10px">this</span>' : '') + ' <span style="color:var(--ink-3);font-size:10.5px">' + escH(modelInfo(x.model).tier) + '</span>', usd(x.spend) + ' <span style="color:var(--ink-3)">' + dlPct(x.spend, all) + '% of usage</span>' + dlBar(dlPct(x.spend, (ml[0] || {}).spend || 1), x.model === model ? 'var(--accent)' : 'var(--line-2)'), dlN(x.requests) + ' <span class="term-tip" data-term="requests">requests</span> · ' + perReq(x.spend, x.requests) + ' <span class="term-tip" data-term="perRequest">average per request</span> · ' + compact(x.tokens) + ' tokens · list ' + escH(modelInfo(x.model).priceText))).join(''),
    };
  },

  async liveMember(email) {
    const d = await liveData(); const m = (d.members.members || []).find((x) => x.email === email);
    if (!m) throw new Error('No live record for ' + email);
    const pr = m.products || {}; const tot = Object.values(pr).reduce((s, v) => s + v, 0) || 1;
    const pp = (d.productivity.people || []).find((x) => x.email === email) || {};
    return {
      title: escH(m.name || m.email), sub: escH(m.department || '—') + ' · ' + escH(m.email) + (m.matched ? '' : ' · <span style="color:var(--high)">no directory match</span>'),
      html: dlKv([{ l: 'Spend this month', n: usd(m.spend), c: cssv('--accent') }, { l: 'Requests', n: dlN(m.requests), term: 'requests' }, { l: 'Cost / request', n: m.requests ? usd(m.spend / m.requests) : '—', term: 'costPerRequest' },
        { l: 'Limit', n: m.unlimited ? '∞' : (m.effectiveLimit != null ? usd0(m.effectiveLimit) : '—'), s: escH(m.limitLabel || '') }, { l: 'vs limit', n: m.pctOfLimit != null ? m.pctOfLimit.toFixed(0) + '%' : '—', c: m.pctOfLimit >= 100 ? cssv('--crit') : m.pctOfLimit >= 80 ? cssv('--high') : cssv('--ink') }, { l: 'Code / Cowork sessions (30d)', n: dlN(pp.cc_sessions) + ' / ' + dlN(pp.cowork_sessions) }]) +
        dlH4('By product') + Object.entries(pr).sort((a, b) => b[1] - a[1]).map(([p, v]) => dlRow(escH(prettyProduct(p)), usd(v) + ' <span style="color:var(--ink-3)">' + dlPct(v, tot) + '%</span>' + dlBar(dlPct(v, tot), PRODUCT_COLOR[p] || PRODUCT_COLOR.other))).join(''),
    };
  },

  /* Overview and Copilot tabs ---------------------------------------------- */
  async ovTotal() {
    // Same basis as the Total AI Spend tile that opens this drawer: Claude usage + Claude
    // seats for the period + assigned Copilot licences × $28 × months in the period.
    const P = periodBounds();
    const claude = AI_ORG.periodSpend || 0, seatCost = AI_ORG.periodSeatCost || 0, seats = seatMonthsP() || AI_ORG.assignedSeats || AI_USERS.filter((u) => !u.departed).length;
    const cpSeats = cpAssignedCount();
    const cp = cpSeats * COPILOT_UNIT_COST * P.n, tot = claude + seatCost + cp || 1;
    const people = new Set([...AI_USERS.filter((u) => !u.departed), ...CP_USERS].map((u) => (u.email || '').toLowerCase()).filter(Boolean)).size;
    return { title: 'Total AI spend', sub: usd(tot) + ' · ' + P.short + ' · Claude = seats × ' + usd(SEAT_COST) + ' per month + metered usage, Copilot = assigned licences × ' + usd(COPILOT_UNIT_COST) + ' per month',
      html: dlKv([{ l: 'Claude seat cost', n: usd(seatCost), c: cssv('--v-claude'), s: dlPct(seatCost, tot) + '% · ' + seats + (P.n > 1 ? ' seat-months' : ' seats') + ' × ' + usd(SEAT_COST) + (P.n > 1 ? ' (' + (AI_ORG.assignedSeats || '—') + ' seats assigned now)' : '') }, { l: 'Claude usage', n: usd(claude), c: cssv('--v-claude'), s: dlPct(claude, tot) + '% · metered' }, { l: 'Copilot licences', n: usd(cp), c: cssv('--v-copilot'), s: dlPct(cp, tot) + '% · ' + cpSeats + ' assigned × ' + usd(COPILOT_UNIT_COST) + (P.n > 1 ? ' × ' + P.n + ' mo' : '') + ' · ' + CP_USERS.filter((u) => u.active).length + ' active' }, { l: 'Per person using AI', n: usd(tot / (people || 1)), s: people + ' unique people' }]) +
        dlBar(dlPct(claude + seatCost, tot), cssv('--v-claude')) + dlNote('Claude total (' + usd(claude + seatCost) + ') + Copilot (' + usd(cp) + ') = ' + usd(tot) + '. Seat and licence figures are flat per-month prices; Claude usage is metered and revised by Anthropic for up to 30 days.') + dlChips([{ l: 'Claude tab', a: 'tab', arg: 'claude' }, { l: 'Copilot tab', a: 'tab', arg: 'copilot' }]) };
  },

  async ovClaude() { return DRILLS.spend(); },
  async ovCopilot() { return DRILLS.cpCost(); },
  async ovUnique() {
    const P = periodBounds();
    const c = new Set(AI_USERS.filter((u) => !u.departed).map((u) => (u.email || '').toLowerCase())), p = new Set(CP_USERS.map((u) => (u.email || '').toLowerCase()));
    const both = [...c].filter((e) => p.has(e)), cOnly = [...c].filter((e) => !p.has(e)), pOnly = [...p].filter((e) => !c.has(e));
    return { title: 'Unique People Using AI', sub: (c.size + p.size - both.length) + ' distinct people hold a Claude seat or a Copilot licence · a person with both counts once',
      html: dlKv([{ l: 'Both tools', n: both.length, c: cssv('--accent') }, { l: 'Claude only', n: cOnly.length, c: cssv('--v-claude') }, { l: 'Copilot only', n: pOnly.length, c: cssv('--v-copilot') }]) +
        dlNote('This is a head count of licence / seat holders, not an active-user count — see Usage & tokens for weekly and monthly actives.') +
        dlH4('Using both') + both.slice(0, 20).map((e) => { const u = AI_USERS.find((x) => (x.email || '').toLowerCase() === e) || { email: e }; return memberRow(u, usd(u.mtd || 0) + ' + ' + usd(COPILOT_UNIT_COST * P.n), escH(e)); }).join('') };
  },
  async cpSeats() {
    const P = periodBounds(); const assigned = cpAssignedCount(), active = CP_USERS.filter((u) => u.active).length;
    return { title: 'Copilot licences', sub: assigned + ' assigned · ' + active + ' active in the 30 days ending ' + escH(CP_AS_OF || 'today'),
      html: dlKv([{ l: 'Assigned', n: assigned, c: cssv('--accent') }, { l: 'Active (30d)', n: active, c: cssv('--pass') }, { l: 'Idle assigned', n: Math.max(0, assigned - active), c: cssv('--high'), s: usd0(Math.max(0, assigned - active) * COPILOT_UNIT_COST) + '/mo' }, { l: 'Monthly cost', n: usd0(assigned * COPILOT_UNIT_COST), s: assigned + ' × $' + COPILOT_UNIT_COST }, { l: 'Cost in period', n: usd0(assigned * COPILOT_UNIT_COST * P.n), s: P.n + ' month' + (P.n > 1 ? 's' : '') }, { l: 'Licence holders mapped', n: CP_USERS.length, s: 'people in the Graph sync' }]) +
        dlChips([{ l: 'Inactive licences in table', a: 'filter', arg: 'inactive' }]) + dlNote('Assigned licences are the only seat basis on this page (review decision, 2026-09-15); purchased and unassigned counts are not used. Licence data is from the Microsoft Graph licence sync; activity is the 30 days ending ' + escH(CP_AS_OF || 'today') + ', the as-of date of the usage snapshot.') };
  },
  async cpActive() {
    const act = CP_USERS.filter((u) => u.active).sort((a, b) => String(b.lastActive || '').localeCompare(String(a.lastActive || ''))), idle = CP_USERS.filter((u) => !u.active);
    return { title: 'Copilot active seats', sub: act.length + ' active · ' + idle.length + ' idle · 30 days ending ' + escH(CP_AS_OF || 'today'),
      html: dlKv([{ l: 'Active', n: act.length, c: cssv('--pass') }, { l: 'Idle', n: idle.length, c: cssv('--high'), s: usd0(idle.length * COPILOT_UNIT_COST) + '/mo unused' }, { l: 'Active in final week', n: act.filter((u) => u.lastActive && cpDaysSince(u.lastActive) < 7).length }]) +
        dlChips([{ l: 'Active in table', a: 'filter', arg: 'active' }, { l: 'Idle in table', a: 'filter', arg: 'inactive' }]) +
        dlH4('Idle seats (reclaim candidates)') + idle.slice(0, 20).map((u) => dlRow(`<b>${escH(u.name || u.email)}</b> <span style="color:var(--ink-3);font-size:11px">${escH(u.department || '')}</span>`, usd(COPILOT_UNIT_COST) + '/mo', u.lastActive ? 'last active ' + escH(u.lastActive) : 'never active')).join('') };
  },
  async cpCost() {
    const P = periodBounds();
    const by = {}; CP_USERS.forEach((u) => { const d = u.department || '—'; by[d] = by[d] || { n: 0, a: 0 }; by[d].n++; if (u.active) by[d].a++; });
    const rows = Object.entries(by).sort((a, b) => b[1].n - a[1].n);
    const seats = cpAssignedCount();
    const total = seats * COPILOT_UNIT_COST;
    return { title: 'Copilot cost', sub: usd(total) + '/mo across ' + seats + ' assigned licences at ' + usd(COPILOT_UNIT_COST) + ' · ' + usd(total * P.n) + ' in ' + P.short,
      html: dlKv([{ l: 'Monthly', n: usd0(total), c: cssv('--v-copilot') }, { l: 'In period', n: usd0(total * P.n), s: P.n + ' month' + (P.n > 1 ? 's' : '') }, { l: 'Annual', n: usd0(total * 12) }, { l: 'Per active licence', n: usd(total / (CP_USERS.filter((u) => u.active).length || 1)), s: 'monthly cost spread over licences actually used' }]) +
        dlH4('By department (assigned licences)') + rows.slice(0, 25).map(([d, v]) => dlRow(escH(d), usd0(v.n * COPILOT_UNIT_COST) + '/mo' + dlBar(dlPct(v.a, v.n), 'var(--pass)'), v.a + ' active of ' + v.n + ' licences', `data-drill="cpDept" data-arg="${escH(d)}" tabindex="0" role="button" title="People in this department"`)).join('') };
  },

  async costOrgLevel(arg) {
    const { d, params } = await costFetchLevel(arg);
    const level = params.get('level') || 'leader';
    return {
      title: 'Spend by ' + (COST_LEVEL_LABEL[level] || 'organization'),
      sub: periodShort() + ' · usage-based spend · click a row to drill further',
      html: costRenderRows(d, params),
    };
  },

  async costCurrentMonth() {
    const mtd = AI_ORG.mtd || 0, seats = AI_ORG.assignedSeats || AI_USERS.length, seatCost = seats * SEAT_COST;
    return {
      title: 'Current Month Spend', sub: usd(mtd) + ' month-to-date',
      html: dlNote('The total AI usage spend recorded so far this month, org-wide, from ' + (AI_ORG.source === 'analytics-api' ? 'the live Analytics API' : 'the last CSV import') + '.') +
        dlKv([
          { l: 'Usage spend (MTD)', n: usd(mtd), c: cssv('--accent') },
          { l: 'Seat/license cost', n: usd0(seatCost), s: seats + ' seats × ' + usd0(SEAT_COST) },
          { l: 'Combined total', n: usd(mtd + seatCost) },
        ]) +
        (await costOrgSection('level=leader')) +
        dlNote('Calculation: sum of all Claude usage charges billed so far this calendar month, org-wide.'),
    };
  },

  async costYtd() {
    const d = COST_ROLLUP.data;
    const thisYear = String(new Date().getUTCFullYear());
    const MON_NAMES = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
    const monthLabel = (m) => { const p = String(m).split('-'); return MON_NAMES[(+p[1]) - 1] + ' ' + p[0]; };
    const monthly = d && Array.isArray(d.months) ? d.months.map((m) => ({ m, total: (d.rows || []).reduce((s, r) => s + (Number(r.months[m]) || 0), 0) })) : [];
    const ytdMonths = monthly.filter((x) => x.m.slice(0, 4) === thisYear);
    const ytd = ytdMonths.reduce((s, x) => s + x.total, 0);
    const mx = Math.max(...ytdMonths.map((x) => x.total), 1);
    return {
      title: 'YTD Spend', sub: usd(ytd) + ' · calendar ' + thisYear,
      html: dlNote('Usage-based (metered) Claude spend across the organization since January 1, ' + thisYear + ', from Anthropic\'s Analytics API. Seats, credits and invoices are separate tiles on the Spend snapshot.') +
        dlKv([
          { l: 'YTD total', n: usd(ytd), c: cssv('--accent') },
          { l: 'Months included', n: ytdMonths.length },
          { l: 'Average / month', n: usd(ytdMonths.length ? ytd / ytdMonths.length : 0) },
        ]) +
        dlH4('By month — click a month for details') + ytdMonths.map((x) => dlRow('<span class="mono">' + escH(monthLabel(x.m)) + ' <span style="color:var(--ink-3)">›</span></span>', usd(x.total) + ' <span style="color:var(--ink-3);font-weight:400">(' + dlPct(x.total, ytd) + '%)</span>' + dlBar(dlPct(x.total, mx), 'var(--accent)'), '', `data-drill="costMonthDetail" data-arg="${escH(x.m)}" tabindex="0" role="button" title="Open ${escH(monthLabel(x.m))} details"`)).join('') +
        dlRow('<b>YTD Total</b>', '<b>' + usd(ytd) + '</b> <span style="color:var(--ink-3);font-weight:400">(100%)</span>') +
        dlNote('YTD Total is the sum of the monthly amounts above.'),
    };
  },

  async costAvgDaily() {
    const mtd = AI_ORG.mtd || 0, dayOfMonth = new Date().getUTCDate(), avg = dayOfMonth ? mtd / dayOfMonth : 0;
    const dLive = await liveData();
    const series = (dLive.trend.series || []).filter((x) => String(x.day || '').slice(0, 7) === new Date().toISOString().slice(0, 7));
    return {
      title: 'Average Daily Spend', sub: usd(avg) + ' / day so far this month',
      html: dlNote('Month-to-date spend divided by the number of calendar days elapsed this month. Not a forecast — it does not assume the rest of the month looks like the days so far.') +
        dlKv([
          { l: 'MTD spend', n: usd(mtd) }, { l: 'Days elapsed', n: dayOfMonth },
          { l: 'Average / day', n: usd(avg), c: cssv('--accent') },
        ]) +
        (series.length ? '<div style="height:150px;margin:4px 0 14px"><canvas id="dlChart"></canvas></div>' : dlNote('Daily series not available yet.')) +
        (await costOrgSection('level=leader')) +
        dlNote('Calculation: usage spend (MTD) ÷ calendar days elapsed.'),
      after: () => { if (series.length) drawBars('dlChart', series.map((x) => x.day.slice(8)), series.map((x) => x.total), cssv('--pass')); },
    };
  },

  async costTrend() {
    const d = COST_ROLLUP.data;
    const monthly = d && Array.isArray(d.months) ? d.months.map((m) => ({ m, total: (d.rows || []).reduce((s, r) => s + (Number(r.months[m]) || 0), 0) })) : [];
    const mx = Math.max(...monthly.map((x) => x.total), 1);
    const MON_NAMES = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
    const monthLabel = (m) => { const p = String(m).split('-'); return MON_NAMES[(+p[1]) - 1] + ' ' + p[0]; };

    const now = new Date();
    const dayOfMonth = now.getUTCDate();
    const curYM = now.toISOString().slice(0, 7);
    const prevYM = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1)).toISOString().slice(0, 7);
    const prevMonthLastDay = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 0)).getUTCDate();
    const curSpend = AI_ORG.mtd || 0;
    let prevSpend = null, pct = null, dailyErr = null;
    try {
      const r = await fetch('/api/claude-analytics/trend?days=' + (dayOfMonth + prevMonthLastDay + 3), { credentials: 'same-origin' });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const dd = await r.json();
      if (dd.error) throw new Error(dd.error);
      prevSpend = (dd.series || [])
        .filter((x) => String(x.day || '').slice(0, 7) === prevYM && Number(String(x.day).slice(8, 10)) <= dayOfMonth)
        .reduce((s, x) => s + (Number(x.total) || 0), 0);
      pct = prevSpend ? ((curSpend - prevSpend) / prevSpend * 100) : null;
    } catch (e) {
      dailyErr = String(e.message || e);
    }
    const dir = pct == null ? null : (pct > 1 ? 'higher' : pct < -1 ? 'lower' : null);
    const dirTxt = dir || 'about the same';
    const headline = pct == null
      ? 'Not enough daily data yet to compare to the same period last month.'
      : (dir ? ('Claude spending is ' + Math.abs(pct).toFixed(0) + '% ' + dir + ' than the same period last month.')
        : 'Claude spending is about the same as the same period last month.');

    return {
      title: 'Spend Trend', sub: headline,
      html: dlNote('Compares Claude spending so far this month with spending during the same number of days last month. A change here is informational — it is not automatically a problem.') +
        (pct != null ? dlH4('What does this trend mean?') +
          dlKv([
            { l: 'This month so far (' + monthLabel(curYM) + ' 1–' + dayOfMonth + ')', n: usd(curSpend) },
            { l: 'Same period last month (' + monthLabel(prevYM) + ' 1–' + dayOfMonth + ')', n: usd(prevSpend) },
            { l: 'Difference', n: (curSpend - prevSpend >= 0 ? '+' : '') + usd(curSpend - prevSpend) },
            { l: 'Change', n: (pct >= 0 ? '+' : '') + pct.toFixed(0) + '% ' + dirTxt, c: pct >= 0 ? cssv('--high') : cssv('--pass') },
          ])
          : dlNote(dailyErr ? 'Could not load daily spend data — ' + dailyErr : 'Not enough daily data yet.')) +
        '<div style="height:150px;margin:4px 0 14px"><canvas id="dlChart"></canvas></div>' +
        dlH4('Monthly history — click a month for details') + monthly.map((x, i) => {
          const isLast = i === monthly.length - 1;
          let chgTxt;
          if (isLast) {
            // Current month is partial — reuse the same-period-days comparison
            // above rather than the naive partial-vs-full-month math below.
            chgTxt = pct == null ? '—' : (pct > 1 ? 'Higher' : pct < -1 ? 'Lower' : 'About the same');
          } else {
            const prevTotal = i > 0 ? monthly[i - 1].total : null;
            const chg = prevTotal ? ((x.total - prevTotal) / prevTotal * 100) : null;
            chgTxt = chg == null ? '—' : (chg > 1 ? 'Higher' : chg < -1 ? 'Lower' : 'About the same');
          }
          const label = monthLabel(x.m) + (isLast ? ' (MTD)' : '');
          const extra = `data-drill="costMonthDetail" data-arg="${escH(x.m)}" tabindex="0" role="button" title="Open ${escH(monthLabel(x.m))} details"`;
          return dlRow('<span class="mono">' + escH(label) + ' <span style="color:var(--ink-3)">›</span></span>', usd(x.total) + ' <span style="color:var(--ink-3);font-weight:400">(' + chgTxt + ')</span>' + dlBar(dlPct(x.total, mx), 'var(--accent)'), '', extra);
        }).join(''),
      after: () => drawBars('dlChart', monthly.map((x) => x.m.slice(5)), monthly.map((x) => x.total), cssv('--accent')),
    };
  },

  async costMonthDetail(monthArg) {
    const d = COST_ROLLUP.data;
    const monthly = d && Array.isArray(d.months) ? d.months.map((m) => ({ m, total: (d.rows || []).reduce((s, r) => s + (Number(r.months[m]) || 0), 0) })) : [];
    const MON_NAMES = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
    const monthLabel = (m) => { const p = String(m).split('-'); return MON_NAMES[(+p[1]) - 1] + ' ' + p[0]; };
    const idx = monthly.findIndex((x) => x.m === monthArg);
    const total = idx >= 0 ? monthly[idx].total : 0;
    const isCurrent = monthArg === new Date().toISOString().slice(0, 7);

    if (isCurrent) {
      const now = new Date();
      const dayOfMonth = now.getUTCDate();
      const prevYM = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1)).toISOString().slice(0, 7);
      const prevMonthLastDay = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 0)).getUTCDate();
      let prevSpend = null, pct = null, dailyErr = null;
      try {
        const r = await fetch('/api/claude-analytics/trend?days=' + (dayOfMonth + prevMonthLastDay + 3), { credentials: 'same-origin' });
        if (!r.ok) throw new Error('HTTP ' + r.status);
        const dd = await r.json();
        if (dd.error) throw new Error(dd.error);
        prevSpend = (dd.series || [])
          .filter((x) => String(x.day || '').slice(0, 7) === prevYM && Number(String(x.day).slice(8, 10)) <= dayOfMonth)
          .reduce((s, x) => s + (Number(x.total) || 0), 0);
        pct = prevSpend ? ((total - prevSpend) / prevSpend * 100) : null;
      } catch (e) {
        dailyErr = String(e.message || e);
      }
      const dir = pct == null ? null : (pct > 1 ? 'higher' : pct < -1 ? 'lower' : null);
      const dirTxt = dir || 'about the same';
      return {
        title: monthLabel(monthArg) + ' (MTD)', sub: usd(total) + ' so far this month',
        html: dlNote('This month is still in progress, so its total is compared with the same number of days last month rather than a full previous month.') +
          dlKv([
            { l: 'Spend so far this month', n: usd(total) },
            { l: 'Same period last month', n: prevSpend != null ? usd(prevSpend) : '—' },
            { l: 'Change', n: pct == null ? '—' : (pct >= 0 ? '+' : '') + pct.toFixed(0) + '% ' + dirTxt, c: pct == null ? 'var(--ink)' : (pct >= 0 ? cssv('--high') : cssv('--pass')) },
          ]) +
          (dailyErr ? dlNote('Could not load daily comparison data — ' + dailyErr) : ''),
      };
    }

    const prevRow = idx > 0 ? monthly[idx - 1] : null;
    const chg = prevRow && prevRow.total ? ((total - prevRow.total) / prevRow.total * 100) : null;
    const dir2 = chg == null ? null : (chg > 1 ? 'higher' : chg < -1 ? 'lower' : null);
    const dir2Txt = dir2 || 'about the same';
    return {
      title: monthLabel(monthArg), sub: usd(total) + ' total',
      html: dlNote('A completed month, compared with the full previous month.') +
        dlKv([
          { l: monthLabel(monthArg) + ' spend', n: usd(total) },
          { l: prevRow ? monthLabel(prevRow.m) + ' spend' : 'Previous month', n: prevRow ? usd(prevRow.total) : '—' },
          { l: 'Difference', n: prevRow ? (total - prevRow.total >= 0 ? '+' : '') + usd(total - prevRow.total) : '—' },
          { l: 'Change', n: chg == null ? '—' : (chg >= 0 ? '+' : '') + chg.toFixed(0) + '% ' + dir2Txt, c: chg == null ? 'var(--ink)' : (chg >= 0 ? cssv('--high') : cssv('--pass')) },
        ]),
    };
  },

  async costTopOrg() {
    const { d, params } = await costFetchLevel('level=leader');
    const P = periodBounds();
    const rows = (d.rows || []).slice().sort((a, b) => b.total - a.total);
    const top = rows.find((r) => r.key !== '__none__') || rows[0];
    const totalAll = rows.reduce((s, r) => s + r.total, 0);
    const topPct = top && totalAll ? Math.round((top.total / totalAll) * 100) : null;
    return {
      title: 'Highest Spending Org', sub: top ? escH(top.name) + ' · ' + usd(top.total) + ' · ' + P.short : 'No spend recorded in ' + P.short,
      html: (top ? dlNote('The department leader whose teams spent the most usage in the selected period. It follows the 30 / 60 / 90-day control and the month picker like everything else — it is not a running year-to-date total and not a comparison to a target. Click any row below to see that leader\'s departments, managers and individual users.') : '') +
        (top ? dlKv([
          { l: 'Top spender', n: escH(top.name) },
          { l: 'Their usage spend', n: usd(top.total) },
          { l: 'Share of the period\'s usage', n: topPct != null ? topPct + '%' : '\u2014' },
        ]) : '') +
        costRenderRows(d, params),
    };
  },

  /* Reporting period (2026-09-15) — current-month MTD tile and the billing ledger ---- */
  async mtdCurrent() {
    const cur = curYM();
    const [su, tr] = await Promise.all([
      cached('summary:' + cur, () => getJ('/api/claude-analytics/summary?month=' + cur)),
      cached('trend:' + cur, () => getJ('/api/claude-analytics/trend?month=' + cur)),
    ]);
    const series = (tr.series || []).filter((x) => String(x.day || '').slice(0, 7) === cur);
    const prods = [...new Set(series.flatMap((x) => Object.keys(x.products || {})))];
    return {
      title: 'Current month — ' + ymLong(cur) + ' (MTD)', sub: usd(su.spend) + ' usage so far · through ' + todayISO() + ' · day ' + su.daysElapsed + ' of ' + su.daysInMonth,
      html: dlNote('The current month is incomplete, so it is always shown on its own and never summed into a 30/60/90-day period. Seats for this month are a whole-month commitment (' + (AI_ORG.assignedSeats || '—') + ' × ' + usd0(SEAT_COST) + ').') +
        dlKv([
          { l: 'Usage so far', n: usd(su.spend), c: cssv('--high') },
          { l: 'Average per day', n: usd(su.runRatePerDay) },
          { l: 'Projected month-end', n: su.projectedMonthEnd != null ? usd0(su.projectedMonthEnd) : '—', term: 'projectedMonthEnd' },
          { l: 'Same days last month', n: usd(su.prevMonthSameSpan), s: 'first ' + su.daysElapsed + ' days of the previous month' },
          { l: 'vs last month', n: su.momPct == null ? '—' : (su.momPct >= 0 ? '+' : '') + su.momPct.toFixed(0) + '%', term: 'vsLastMonth' },
          { l: 'Requests', n: dlN(su.requests), term: 'requests' },
        ]) +
        (series.length ? '<div style="height:150px;margin-bottom:14px"><canvas id="dlChart"></canvas></div>' : '') +
        dlH4('Day by day') + '<div style="overflow-x:auto"><table style="font-size:12px"><thead><tr><th>Day</th>' + prods.map((p) => '<th>' + escH(prettyProduct(p)) + '</th>').join('') + '<th>Total</th><th><span class="term-tip" data-term="requests">Req</span></th></tr></thead><tbody>' +
        series.slice().reverse().map((x) => '<tr><td class="mono">' + x.day.slice(5) + '</td>' + prods.map((p) => '<td class="mono">' + (x.products[p] ? usd(x.products[p]) : '—') + '</td>').join('') + '<td class="mono"><b>' + usd(x.total) + '</b></td><td class="mono">' + dlN(x.requests) + '</td></tr>').join('') + '</tbody></table></div>',
      after: () => { if (series.length) drawBars('dlChart', series.map((x) => x.day.slice(8)), series.map((x) => x.total), cssv('--high')); },
    };
  },

  async billRows(kind) {
    const B = BILLING.data; if (!B || B.scoped) throw new Error('Billing ledger not available for this view');
    const all = B.rows || [];
    const sel = kind === 'seat' ? all.filter((r) => r.type === 'plan' || r.type === 'seat' || r.type === 'plan_refunded')
      : kind === 'credit' ? all.filter((r) => r.type === 'credit')
      : kind === 'paid' ? all.filter((r) => r.status === 'Paid')
      : kind === 'open' ? all.filter((r) => r.status === 'Open')
      : kind === 'other' ? all.filter((r) => r.type === 'other')
      : all;
    const titles = { seat: 'Seat & plan invoices', credit: 'Credit purchases', paid: 'Paid invoices', open: 'Open invoices', other: 'Other invoices — neither seats nor credits', all: 'All invoices' };
    const TYPE = { plan: 'Plan (annual)', plan_refunded: 'Plan — refunded', seat: 'Seat added', credit: 'Credit purchase', other: 'Other' };
    const gross = sel.reduce((s, r) => s + r.amount, 0), refunded = sel.filter((r) => r.status === 'Refunded').reduce((s, r) => s + r.amount, 0);
    // Seats on refunded invoices were never on the plan (the 27 Apr plan invoice was re-billed
    // 1 May), so they are excluded here — the same rule the server's seat timeline applies.
    const seats = sel.filter((r) => r.status !== 'Refunded').reduce((s, r) => s + (Number(r.seats_added) || 0), 0);
    const seatsRefunded = sel.filter((r) => r.status === 'Refunded').reduce((s, r) => s + (Number(r.seats_added) || 0), 0);
    const byMonth = {}; sel.forEach((r) => { const m = r.invoice_date.slice(0, 7); byMonth[m] = (byMonth[m] || 0) + (r.status === 'Refunded' ? 0 : r.amount); });
    const months = Object.keys(byMonth).sort();
    /* Change #7 (2026-09-23): invoice-level CSV of exactly what this drawer lists, plus month subtotals.
       Columns that are not captured yet (invoice #, paid date) export empty until the data exists. */
    {
      const cap = B.ledgerUpdatedAt ? String(B.ledgerUpdatedAt).slice(0, 10) : '';
      let run = 0; const ordered = sel.slice().sort((a, b) => (a.invoice_date + a.id) < (b.invoice_date + b.id) ? -1 : 1);
      const csv = [['Month', 'Invoice date', 'Due date', 'Invoice #', 'Type', 'Description', 'Seats added', 'Running seats (invoiced)', 'Gross', 'Refunded', 'Net', 'Status', 'Paid date', 'Ledger updated']];
      ordered.forEach((r) => {
        const refunded = r.status === 'Refunded';
        if (!refunded && (r.type === 'seat' || r.type === 'plan') && r.seats_added) run += Number(r.seats_added);
        csv.push([r.invoice_date.slice(0, 7), r.invoice_date, r.due_date || '', r.invoice_no || '', TYPE[r.type] || r.type, r.description || '',
          r.seats_added || '', (r.type === 'seat' || r.type === 'plan') && !refunded ? run : '', r.amount.toFixed(2), refunded ? r.amount.toFixed(2) : '0.00',
          refunded ? '0.00' : r.amount.toFixed(2), r.status, r.paid_date || '', cap]);
      });
      csv.push([]); csv.push(['Month subtotals', 'Gross', 'Refunded', 'Net', 'Paid', 'Open']);
      months.forEach((m) => { const rows = sel.filter((r) => r.invoice_date.slice(0, 7) === m);
        const g = rows.reduce((a, r) => a + r.amount, 0), rf = rows.filter((r) => r.status === 'Refunded').reduce((a, r) => a + r.amount, 0);
        csv.push([ymLong(m), g.toFixed(2), rf.toFixed(2), (g - rf).toFixed(2), rows.filter((r) => r.status === 'Paid').reduce((a, r) => a + r.amount, 0).toFixed(2), rows.filter((r) => r.status === 'Open').reduce((a, r) => a + r.amount, 0).toFixed(2)]); });
      csv.push(['Total', gross.toFixed(2), refunded.toFixed(2), (gross - refunded).toFixed(2), sel.filter((r) => r.status === 'Paid').reduce((a, r) => a + r.amount, 0).toFixed(2), sel.filter((r) => r.status === 'Open').reduce((a, r) => a + r.amount, 0).toFixed(2)]);
      window.__billCsv = csv; window.__billCsvName = 'claude-invoices-' + kind + '-' + String(B.from || '').slice(0, 4) + '.csv';
    }
    return {
      title: titles[kind] || titles.all, sub: sel.length + ' invoices' + (sel.some((r) => r.status === 'Refunded') ? ' (' + sel.filter((r) => r.status === 'Refunded').length + ' refunded)' : '') + ' · ' + usd(gross - refunded) + ' net · calendar ' + String(B.from || '').slice(0, 4) + ' · captured from the claude.ai Billing page',
      html: '<div style="display:flex;justify-content:flex-end;margin:-4px 0 6px"><button type="button" class="chip" onclick="downloadCSVRows(window.__billCsv, window.__billCsvName)" title="Every invoice listed in this drawer, one row each, with month subtotals">⬇ CSV — invoice detail</button></div>' +
        dlKv([
        { l: 'Net amount', n: usd(gross - refunded), c: cssv('--accent'), s: refunded ? usd(gross) + ' gross − ' + usd(refunded) + ' refunded' : '' },
        { l: 'Paid / Open', n: usd(sel.filter((r) => r.status === 'Paid').reduce((s, r) => s + r.amount, 0)) + ' / ' + usd(sel.filter((r) => r.status === 'Open').reduce((s, r) => s + r.amount, 0)) },
        kind === 'seat' ? { l: 'Seats invoiced', n: seats, s: 'on the plan per the invoices' + (seatsRefunded ? ' · ' + seatsRefunded + ' on the refunded invoice not counted' : '') + (B.seatsFromApi ? ' · Anthropic shows ' + B.seatsFromApi + ' assigned' : '') } : { l: 'Invoices', n: sel.length },
      ]) +
        (kind === 'seat' ? dlNote('Anthropic invoices each added seat for the remaining months of the annual term (May → May) at $' + (SEAT_COST * 12) + '/seat/year, as a "Remaining time on N ×" line net of "Unused time on N−1 ×". That is why seat invoices arrive in odd amounts while the dashboard\'s monthly seat cost stays at ' + usd0(SEAT_COST) + ' per seat per month.') : '') +
        (kind === 'other' ? dlNote('These invoices carry a description that the importer could not map to a seat or a credit purchase, so they sit in no tile except Net invoiced and Paid / Open. Read the description; if they are credit purchases they belong in Credits purchased.') : '') +
        ((kind === 'all' || kind === 'seat') && sel.some((r) => r.status === 'Refunded') ? dlH4('Refunded') + sel.filter((r) => r.status === 'Refunded').map((r) => {
          const re = all.find((x) => x.status !== 'Refunded' && x.amount === r.amount && (x.seats_added || 0) === (r.seats_added || 0) && x.invoice_date > r.invoice_date);
          return dlRow('<span class="mono">' + escH(r.invoice_date) + '</span> ' + usd(r.amount) + (r.seats_added ? ' · ' + r.seats_added + ' seats' : '') + ' <span style="color:var(--ink-3);font-size:11px">— not counted in Net, Paid, Open or seats</span>',
            '<span style="color:var(--ink-3)">Refunded</span>',
            escH(r.description || 'refunded invoice') + (re ? ' · re-issued ' + escH(re.invoice_date) + ' (' + usd(re.amount) + ', ' + escH(re.status) + ')' : ''));
        }).join('') : '') +
        (kind === 'credit' ? dlNote('Usage credits are prepaid. Most purchases here are automatic top-ups charged to the card as usage draws the balance down; others were bought by invoice on 30-day terms. Credits purchased − usage metered ≈ the balance shown on the Billing page.') : '') +
        (months.length > 1 ? dlH4('By month') + months.map((m) => { const refM = sel.filter((r) => r.invoice_date.slice(0, 7) === m && r.status === 'Refunded').reduce((a, r) => a + r.amount, 0);
          return dlRow('<span class="mono">' + escH(ymLong(m)) + '</span>' + (refM ? ' <span style="color:var(--ink-3);font-size:11px">' + usd(refM) + ' refunded, not counted</span>' : ''), usd(byMonth[m]) + dlBar(dlPct(byMonth[m], Math.max(...months.map((k) => byMonth[k]))), 'var(--accent)')); }).join('') : '') +
        dlH4('Invoices') + '<div style="overflow-x:auto"><table style="font-size:12px"><thead><tr><th>Date</th><th>Due</th><th>Type</th><th>Seats</th><th>Amount</th><th>Status</th><th>Invoice #</th></tr></thead><tbody>' +
        sel.slice().reverse().map((r) => '<tr><td class="mono">' + escH(r.invoice_date) + '</td><td class="mono">' + escH(r.due_date || '—') + '</td><td>' + escH(TYPE[r.type] || r.type) + (r.description ? '<div style="color:var(--ink-3);font-size:10.5px">' + escH(r.description) + '</div>' : '') + '</td><td class="mono">' + (r.seats_added || '') + '</td><td class="mono"><b>' + usd(r.amount) + '</b></td><td style="color:' + (r.status === 'Paid' ? 'var(--pass)' : r.status === 'Open' ? 'var(--high)' : 'var(--ink-3)') + '">' + escH(r.status) + '</td><td class="mono" style="color:var(--ink-3)">' + escH(r.invoice_no || '') + '</td></tr>').join('') + '</tbody></table></div>',
    };
  },

  async billBalance() {
    const B = BILLING.data; if (!B || B.scoped) throw new Error('Billing ledger not available for this view');
    const c = B.credits || {};
    return {
      title: 'Credit balance', sub: (c.balance != null ? usd(c.balance) + ' as of ' + escH(c.balanceAsOf) : 'not entered yet') + ' · from the claude.ai Billing page',
      html: dlNote('Anthropic draws metered usage from a prepaid credit balance and auto-reloads it. The dashboard checks the entered balance against its own numbers: credits purchased − usage metered to the same date should land on the balance, give or take the day\'s usage that had not yet been drawn.') +
        dlKv([
          (c.purchasedToAsOf != null
            ? { l: 'Credits purchased to ' + escH(c.balanceAsOf || '—'), n: usd(c.purchasedToAsOf), s: usd(c.purchased) + ' all time — purchases dated after the balance\'s as-of date are left out of the check below' }
            : { l: 'Credits purchased (all time)', n: usd(c.purchased), s: 'includes any purchase dated after the balance\'s as-of date — those cannot yet be in the balance' }),
          { l: 'Usage metered to ' + escH(c.balanceAsOf || '—'), n: usd(c.usageToAsOf), s: 'Anthropic Analytics API' },
          { l: 'Implied balance', n: c.implied != null ? usd(c.implied) : '—', s: 'purchased − usage' },
          { l: 'Balance on Billing page', n: c.balance != null ? usd(c.balance) : '—', c: cssv('--accent2') },
          { l: 'Difference', n: c.implied != null && c.balance != null ? usd(c.implied - c.balance) : '—', s: c.implied != null && c.balance != null ? (Math.abs(c.implied - c.balance) < 50 ? 'ties within a day\'s usage ✓' : Math.abs(c.implied - c.balance) < 400 ? 'about a day of usage not yet drawn' : 'larger than a day\'s usage — the balance is probably out of date (entered ' + escH(c.balanceAsOf || '—') + ') or a credit purchase dated after that date is being counted; re-enter the balance from the Billing page to re-check') : '' },
          { l: 'Seats on plan', n: (B.seatsFromInvoices || '—') + ' / ' + (B.seatsFromApi || '—'), s: 'invoices / Analytics API' },
        ]) +
        dlChips([{ l: 'Credit purchases', a: 'drill', arg: 'billRows|credit' }, { l: 'All invoices', a: 'drill', arg: 'billRows|all' }]),
    };
  },

  /* Spend by Department → Copilot licences in one department ------------------- */
  async cpDept(dept) {
    const P = periodBounds();
    const list = CP_USERS.filter((u) => (u.department || '—') === dept);
    const act = list.filter((u) => u.active);
    return {
      title: escH(dept) + ' — Copilot', sub: list.length + ' assigned licences · ' + act.length + ' active in the last 30 days · ' + usd0(list.length * COPILOT_UNIT_COST) + '/mo',
      html: dlKv([{ l: 'Assigned licences', n: list.length }, { l: 'Active (30d)', n: act.length, c: cssv('--pass') }, { l: 'Cost in period', n: usd0(list.length * COPILOT_UNIT_COST * P.n), s: list.length + ' × $' + COPILOT_UNIT_COST + ' × ' + P.n + ' mo' }]) +
        dlH4('People') + list.sort((a, b) => String(b.lastActive || '').localeCompare(String(a.lastActive || ''))).map((u) => dlRow('<b>' + escH(u.name || u.email) + '</b> <span style="color:var(--ink-3);font-size:11px">' + escH(u.manager || '') + '</span>', usd0(COPILOT_UNIT_COST) + '/mo', u.lastActive ? 'last active ' + escH(u.lastActive) : 'never active')).join(''),
    };
  },

  /* Model cost & efficiency (2026-09-25) — who used which model, and what it cost ------ */
  async mcModel(model) {
    const d = await loadModelCost(); const P = periodBounds();
    const m = (d.byModel || []).find((x) => x.model === model);
    if (!m) throw new Error('No per-model detail for ' + prettyModel(model) + ' in this window');
    const all = (d.byModel || []).reduce((a, x) => a + x.spend, 0) || 1;
    const users = (d.byUser || []).map((u) => ({ ...u, um: (u.models || []).find((x) => x.model === model) })).filter((u) => u.um && u.um.spend > 0).sort((a, b) => b.um.spend - a.um.spend);
    const prods = (d.byModelProduct || []).filter((x) => x.model === model).sort((a, b) => b.spend - a.spend);
    const deptOf = (email) => { const au = AI_USERS.find((x) => String(x.email || '').toLowerCase() === email) || {}; return au.dept || au.department || ''; };
    const win = d.effectiveFrom + ' → ' + d.effectiveTo;
    const csv = [['Person', 'Email', 'Department', 'Usage $ on ' + modelLabel(model), 'Share of model %', 'Requests', 'Tokens', '$ / request', 'Their total usage $', 'Share of their own usage %', 'Window'],
      ...users.map((u) => [u.name, u.email, deptOf(u.email), u.um.spend.toFixed(2), (u.um.spend / m.spend * 100).toFixed(1), u.um.requests, u.um.tokens, u.um.requests ? (u.um.spend / u.um.requests).toFixed(4) : '', u.spend.toFixed(2), u.spend ? (u.um.spend / u.spend * 100).toFixed(1) : '', win])];
    window.__mcCsv = csv; window.__mcCsvName = 'model-cost-' + prettyModel(model) + '-' + d.effectiveFrom + '_' + d.effectiveTo + '.csv';
    return {
      title: modelLabel(model), sub: escH(modelInfo(model).tier) + ' · ' + usd(m.spend) + ' · ' + dlPct(m.spend, all) + '% of usage · ' + m.people + ' people · ' + escH(win) + (d.scoped ? ' · your reporting line' : '') + ' · Anthropic direct',
      html: dlNote(escH(modelInfo(model).desc)) +
        dlKv([{ l: 'Spend', n: usd(m.spend), c: cssv('--accent'), s: 'billed to this model in the window' }, { l: 'People', n: dlN(m.people), s: 'anyone with spend on it' }, { l: 'Requests', n: dlN(m.requests), term: 'requests' },
          { l: 'Cost / request', n: perReq(m.spend, m.requests), term: 'perRequest' }, { l: 'Paid per M tokens', n: mcPerM(m.spend, m.tokens), term: 'mcBlend', s: compact(m.tokens) + ' tokens' }]) +
        '<div style="display:flex;justify-content:flex-end;margin:-4px 0 6px"><button type="button" class="chip" onclick="downloadCSVRows(window.__mcCsv, window.__mcCsvName)" title="Every person with spend on this model in the window">⬇ CSV — people on this model</button></div>' +
        (prods.length ? dlH4('By product') + prods.map((p) => dlRow(productTip(p.product || 'other'), usd(p.spend) + ' <span style="color:var(--ink-3)">' + dlPct(p.spend, m.spend) + '%</span>' + dlBar(dlPct(p.spend, prods[0].spend), 'var(--line-2)'), dlN(p.requests) + ' <span class="term-tip" data-term="requests">requests</span> · ' + perReq(p.spend, p.requests) + ' per request')).join('') : '') +
        dlH4('People on this model') + dlNote('Ranked by what they spent on <b>this</b> model. The second figure is how much of their own usage went to it. Click a person for their split across every model.') +
        (users.length ? users.map((u) => dlRow('<b>' + escH(u.name || u.email) + '</b> <span style="color:var(--ink-3);font-size:11px">' + escH(deptOf(u.email)) + '</span>',
          usd(u.um.spend) + ' <span style="color:var(--ink-3)">' + dlPct(u.um.spend, m.spend) + '% of model</span>' + dlBar(dlPct(u.um.spend, users[0].um.spend)),
          dlN(u.um.requests) + ' <span class="term-tip" data-term="requests">requests</span> · ' + perReq(u.um.spend, u.um.requests) + ' per request · ' + (u.spend ? dlPct(u.um.spend, u.spend) : 0) + '% of their ' + usd(u.spend) + ' usage',
          'data-drill="mcPerson" data-arg="' + escH(u.email) + '" tabindex="0" role="button" title="This person across all models"')).join('') : '<div class="sub">No person is attributed to this model in the window.</div>'),
    };
  },

  async mcPerson(email) {
    const d = await loadModelCost();
    const u = (d.byUser || []).find((x) => x.email === String(email || '').toLowerCase());
    if (!u) throw new Error('No per-model detail for ' + email + ' in this window');
    const au = AI_USERS.find((x) => String(x.email || '').toLowerCase() === u.email) || {};
    const ms = (u.models || []).slice().sort((a, b) => b.spend - a.spend);
    return {
      title: escH(u.name || u.email), sub: escH(au.dept || au.department || '') + (au.dept ? ' · ' : '') + usd(u.spend) + ' across ' + ms.length + ' model' + (ms.length === 1 ? '' : 's') + ' · ' + escH(d.effectiveFrom + ' → ' + d.effectiveTo),
      html: dlNote('One person’s usage split by model — Anthropic’s billed dollars per model, from the same table as the Model cost card. Seats and credits are not part of this figure.') +
        dlKv([{ l: 'Usage in window', n: usd(u.spend), c: cssv('--accent') }, { l: 'Requests', n: dlN(u.requests), term: 'requests' }, { l: 'Cost / request', n: perReq(u.spend, u.requests), term: 'perRequest' }, { l: 'Tokens', n: compact(u.tokens), s: mcPerM(u.spend, u.tokens) + ' per M paid' }]) +
        (AI_USERS.find((x) => String(x.email || '').toLowerCase() === u.email) ? '<div class="dl-act"><button type="button" class="chip" data-drill="member" data-arg="' + escH(u.email) + '">Open member record →</button></div>' : '') +
        dlH4('By model') + ms.map((x) => dlRow(modelTip(x.model) + ' <span style="color:var(--ink-3);font-size:10.5px">' + escH(modelInfo(x.model).tier) + '</span>',
          usd(x.spend) + ' <span style="color:var(--ink-3)">' + dlPct(x.spend, u.spend) + '%</span>' + dlBar(dlPct(x.spend, ms[0].spend), 'var(--accent)'),
          dlN(x.requests) + ' <span class="term-tip" data-term="requests">requests</span> · ' + perReq(x.spend, x.requests) + ' per request · ' + compact(x.tokens) + ' tokens · ' + mcPerM(x.spend, x.tokens) + ' per M',
          'data-drill="mcModel" data-arg="' + escH(x.model) + '" tabindex="0" role="button" title="Everyone on this model"')).join(''),
    };
  },

  async mcModels() {
    const d = await loadModelCost(); const ml = d.byModel || []; const all = ml.reduce((a, x) => a + x.spend, 0) || 1;
    return {
      title: 'Models in use', sub: ml.length + ' models · ' + escH(d.effectiveFrom + ' → ' + d.effectiveTo) + ' · click one for who used it',
      html: dlNote('Every Claude model that carried any billed usage in the window, ranked by spend. A higher version number is a newer release of the same tier, not a different capability level; hover a name for what the tier is and its list price.') +
        ml.map((x) => dlRow(modelTip(x.model) + ' <span style="color:var(--ink-3);font-size:10.5px">' + escH(modelInfo(x.model).tier) + '</span>', usd(x.spend) + ' <span style="color:var(--ink-3)">' + dlPct(x.spend, all) + '%</span>' + dlBar(dlPct(x.spend, ml[0].spend)),
          dlN(x.people) + ' people · ' + dlN(x.requests) + ' <span class="term-tip" data-term="requests">requests</span> · ' + perReq(x.spend, x.requests) + ' per request', 'data-drill="mcModel" data-arg="' + escH(x.model) + '" tabindex="0" role="button"')).join(''),
    };
  },

  async mcBlend() {
    const d = await loadModelCost(); const ml = (d.byModel || []).slice().sort((a, b) => (b.tokens ? b.spend / b.tokens : 0) - (a.tokens ? a.spend / a.tokens : 0));
    const T = ml.reduce((a, x) => ({ spend: a.spend + x.spend, tokens: a.tokens + x.tokens, list: a.list + x.list }), { spend: 0, tokens: 0, list: 0 });
    return {
      title: 'Blended cost per million tokens', sub: mcPerM(T.spend, T.tokens) + ' across all models · ' + escH(d.effectiveFrom + ' → ' + d.effectiveTo),
      html: dlNote('Usage spend ÷ tokens, × 1,000,000. It is a blended rate: cache reads bill at a fraction of list, output tokens bill far above input, so the figure sits well under the list price for input. Use it to compare models on the same footing; it is not a price Anthropic quotes.') +
        dlKv([{ l: 'Blended, all models', n: mcPerM(T.spend, T.tokens), c: cssv('--accent') }, { l: 'Spend', n: usd(T.spend) }, { l: 'Tokens', n: compact(T.tokens) }]) +
        dlH4('Per model — most to least expensive per token') + ml.map((x) => dlRow(modelTip(x.model), mcPerM(x.spend, x.tokens) + ' <span style="color:var(--ink-3)">per M</span>' + dlBar(x.tokens && ml[0].tokens ? (x.spend / x.tokens) / (ml[0].spend / ml[0].tokens) * 100 : 0, 'var(--accent)'),
          usd(x.spend) + ' · ' + compact(x.tokens) + ' tokens · list ' + escH(modelInfo(x.model).priceText), 'data-drill="mcModel" data-arg="' + escH(x.model) + '" tabindex="0" role="button"')).join(''),
    };
  },

  async mcPerReq() {
    const d = await loadModelCost(); const ml = (d.byModel || []).filter((x) => x.requests > 0).sort((a, b) => b.spend / b.requests - a.spend / a.requests);
    const T = ml.reduce((a, x) => ({ spend: a.spend + x.spend, requests: a.requests + x.requests }), { spend: 0, requests: 0 });
    return {
      title: 'Average cost per request', sub: perReq(T.spend, T.requests) + ' across all models · ' + dlN(T.requests) + ' requests · ' + escH(d.effectiveFrom + ' → ' + d.effectiveTo),
      html: dlNote('Spend ÷ requests for each model. One request = one prompt sent and one reply received. A higher tier costs more per request because of its per-token price, but also because people bring it longer, harder work — so this is a usage pattern, not a price list.') +
        ml.map((x) => dlRow(modelTip(x.model) + ' <span style="color:var(--ink-3);font-size:10.5px">' + escH(modelInfo(x.model).tier) + '</span>', perReq(x.spend, x.requests) + ' <span style="color:var(--ink-3)">per request</span>' + dlBar((x.spend / x.requests) / (ml[0].spend / ml[0].requests) * 100, 'var(--v-copilot)'),
          dlN(x.requests) + ' <span class="term-tip" data-term="requests">requests</span> · ' + usd(x.spend) + ' · ' + dlN(x.people) + ' people', 'data-drill="mcModel" data-arg="' + escH(x.model) + '" tabindex="0" role="button"')).join(''),
    };
  },

};
