/* ai-usage-rollup.js — AI spend rolled up the org chart, with drill-down.
 *
 *   Company -> Department Leader -> Department -> Manager -> Employee
 *
 * Self-contained and additive: it owns one card (#orgRollupCard) and touches
 * nothing else on the page. Delete this file and the <script> tag and the rest
 * of the page is unchanged. No inline handlers — one delegated listener per
 * concern, so the page stays CSP-clean.
 *
 * Motion follows the same rules as ai-usage-drill.js: this is a table people
 * will operate many times a day, so it gets press feedback and nothing else.
 * No row animations, no fades on re-render — a table that re-animates on every
 * sort feels slow, and the frequency of use is exactly what argues against it.
 */
'use strict';

(function () {
  const API = '/api/claude-analytics';
  const LEVELS = ['leader', 'department', 'manager', 'user'];
  const LABEL = { leader: 'Department Leader', department: 'Department', manager: 'Manager', user: 'Employee' };

  const S = {
    level: 'leader',
    months: 6,          // fallback only — the page's reporting period (periodBounds) drives the window
    filters: { leader: null, department: null, manager: null },
    crumbs: [{ level: 'leader', label: 'Company', filters: {} }],
    sort: { col: 'total', dir: 'desc' },
    data: null,
    loading: false,
  };

  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const money = (v) => (Number(v) || 0).toLocaleString('en-US', { style: 'currency', currency: 'USD' });
  const moShort = (m) => {
    const [y, mm] = m.split('-');
    return new Date(Date.UTC(+y, +mm - 1, 1)).toLocaleDateString('en-US', { month: 'short', timeZone: 'UTC' })
      + (mm === '01' ? " '" + y.slice(2) : '');
  };
  const $ = (id) => document.getElementById(id);

  async function load() {
    if (S.loading) return;
    S.loading = true;
    paint();
    const p = new URLSearchParams({ level: S.level });
    let P = null; try { P = periodBounds(); } catch (e) { /* page state not ready (auth bootstrap reload) */ }   // page's global 30/60/90 or picked month
    if (P) { p.set('from', P.from); p.set('to', P.to); } else p.set('months', String(S.months));
    for (const k of ['leader', 'department', 'manager']) if (S.filters[k]) p.set(k, S.filters[k]);
    try {
      const r = await fetch(`${API}/rollup?${p}`, { credentials: 'same-origin' });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      S.data = await r.json();
    } catch (e) {
      S.data = { error: e.message };
    }
    S.loading = false;
    paint();
  }

  async function loadCoverage() {
    try {
      let P = null; try { P = periodBounds(); } catch (e) { /* not ready yet */ }
      const r = await fetch(`${API}/rollup/coverage` + (P ? `?from=${P.from}&to=${P.to}` : ''), { credentials: 'same-origin' });
      if (!r.ok) return;
      const c = await r.json();
      const un = (c.byResolution || []).find((x) => x.resolution === 'unresolved');
      const el = $('orgRollupCoverage');
      if (!el) return;
      const attributed = (c.byResolution || []).filter((x) => x.resolution !== 'unresolved')
        .reduce((s, x) => s + x.pct, 0);
      const roster = c.roster || {};
      el.innerHTML =
        (P ? `<span>${esc(P.short)}</span> &middot; ` : '')
        + `<span class="term-tip" data-term="attributed" title="Share of usage spend attributable to a person in the org chart">`
        + `${attributed.toFixed(1)}% attributed</span>`
        + (un && un.usd > 0
          ? ` &middot; <span style="color:var(--warn,var(--ink-3))">${money(un.usd)} unassigned `
            + `(${un.users} ${un.users === 1 ? 'account' : 'accounts'})</span>`
          : ' &middot; nothing unassigned')
        + (roster.people ? ` &middot; roster ${roster.people} people` : '')
        + ` &middot; <span class="term-tip" data-term="deptSourceHR">cost centre and leader per HR roster &middot; people = those with usage spend</span>`;
    } catch (e) { /* coverage is informational; never block the table */ }
  }

  function sortRows(rows) {
    const { col, dir } = S.sort;
    const val = (r) => (col === 'name' ? String(r.name).toLowerCase()
      : col === 'users' ? r.users
      : col === 'total' ? r.total
      : (r.months && r.months[col]) || 0);
    return rows.slice().sort((a, b) => {
      const x = val(a), y = val(b);
      const c = typeof x === 'string' ? x.localeCompare(y) : x - y;
      return dir === 'asc' ? c : -c;
    });
  }

  function paint() {
    const body = $('orgRollupBody');
    const crumbEl = $('orgRollupCrumbs');
    if (!body || !crumbEl) return;

    crumbEl.innerHTML = S.crumbs.map((c, i) =>
      i === S.crumbs.length - 1
        ? `<span class="orgc cur">${esc(c.label)}</span>`
        : `<button type="button" class="orgc lnk" data-crumb="${i}">${esc(c.label)}</button>`
          + '<span class="orgc sep">&rsaquo;</span>'
    ).join('');

    if (S.loading && !S.data) { body.innerHTML = '<div class="sub" style="padding:14px 2px">Loading…</div>'; return; }
    const d = S.data;
    if (!d) { body.innerHTML = ''; return; }
    if (d.error) {
      body.innerHTML = `<div class="sub" style="padding:14px 2px;color:var(--bad,var(--ink-2))">`
        + `Could not load the rollup (${esc(d.error)}).</div>`;
      return;
    }
    if (!d.rows.length) {
      body.innerHTML = '<div class="sub" style="padding:14px 2px">No usage-based spend recorded here in this period.</div>';
      return;
    }

    const months = d.months || [];
    const rows = sortRows(d.rows);
    const drillable = !!d.nextLevel;
    const arrow = (c) => (S.sort.col === c ? (S.sort.dir === 'asc' ? ' ▲' : ' ▼') : '');

    const head = `<tr>
        <th class="orgs" data-sort="name">${esc(LABEL[d.level] || 'Name')}${arrow('name')}</th>
        <th class="orgs num" data-sort="users" title="Distinct people with usage-based spend in the period under this row">People${arrow('users')}</th>
        ${months.map((m) => `<th class="orgs num" data-sort="${m}" title="Usage-based (metered) Claude spend attributed to this row in ${esc(moShort(m))} — seats not included">${esc(moShort(m))}${arrow(m)}</th>`).join('')}
        <th class="orgs num" data-sort="total" title="Usage-based spend for the whole period — the sum of the month columns">Total${arrow('total')}</th>
      </tr>`;

    const tbody = rows.map((r) => {
      const unassigned = r.key === '__none__';
      const attrs = drillable
        ? ` data-drillkey="${esc(r.key)}" tabindex="0" role="button"`
          + ` aria-label="Drill into ${esc(r.name)}" class="orgrow drill"`
        : ' class="orgrow"';
      return `<tr${attrs}>
        <td>${unassigned ? '<span style="color:var(--ink-3)">' : ''}${esc(r.name)}${unassigned ? '</span>' : ''}
            ${drillable ? '<span class="orgchev" aria-hidden="true">›</span>' : ''}</td>
        <td class="num">${r.users}</td>
        ${months.map((m) => `<td class="num${r.months[m] ? '' : ' zero'}">${r.months[m] ? money(r.months[m]) : '—'}</td>`).join('')}
        <td class="num strong">${money(r.total)}</td>
      </tr>`;
    }).join('');

    const g = d.grand || { byMonth: {}, total: 0, users: 0 };
    const foot = `<tr class="orgtot">
        <td>Total</td><td class="num">${g.users}</td>
        ${months.map((m) => `<td class="num">${money(g.byMonth[m] || 0)}</td>`).join('')}
        <td class="num strong">${money(g.total)}</td>
      </tr>`;

    body.innerHTML = `<div class="orgwrap"><table class="orgtbl">
        <thead>${head}</thead><tbody>${tbody}</tbody><tfoot>${foot}</tfoot></table></div>`;
    publishCsv();
  }

  function csvRows() {
    const d = S.data; if (!d || !d.rows) return null;
    const months = d.months || [];
    const rows = sortRows(d.rows);
    const out = [['Level', LABEL[d.level] || d.level, 'Path', S.crumbs.map((c) => c.label).join(' › ')],
      [LABEL[d.level] || 'Name', 'People', ...months.map(moShort), 'Total']];
    rows.forEach((r) => out.push([r.name, r.users, ...months.map((m) => (Number(r.months[m]) || 0).toFixed(2)), (Number(r.total) || 0).toFixed(2)]));
    const g = d.grand || { byMonth: {}, total: 0, users: 0 };
    out.push(['Total', g.users, ...months.map((m) => (Number(g.byMonth[m]) || 0).toFixed(2)), (Number(g.total) || 0).toFixed(2)]);
    return out;
  }
  function publishCsv() { try { if (typeof CSVX !== 'undefined') CSVX.org = csvRows(); } catch (e) {} }

  function drill(key, label) {
    const d = S.data;
    if (!d || !d.nextLevel) return;
    const f = { ...S.filters };
    if (d.level === 'leader') f.leader = key;
    else if (d.level === 'department') f.department = key;
    else if (d.level === 'manager') f.manager = key;
    S.crumbs.push({ level: d.nextLevel, label, filters: { ...f } });
    S.filters = f;
    S.level = d.nextLevel;
    S.sort = { col: 'total', dir: 'desc' };
    load();
  }

  function toCrumb(i) {
    const c = S.crumbs[i];
    if (!c) return;
    S.crumbs = S.crumbs.slice(0, i + 1);
    S.filters = { leader: null, department: null, manager: null, ...c.filters };
    S.level = c.level;
    S.sort = { col: 'total', dir: 'desc' };
    load();
  }

  function wire() {
    const card = $('orgRollupCard');
    if (!card) return;

    card.addEventListener('click', (ev) => {
      const crumb = ev.target.closest('[data-crumb]');
      if (crumb) { toCrumb(Number(crumb.dataset.crumb)); return; }

      const sort = ev.target.closest('[data-sort]');
      if (sort) {
        const c = sort.dataset.sort;
        S.sort = S.sort.col === c
          ? { col: c, dir: S.sort.dir === 'asc' ? 'desc' : 'asc' }
          : { col: c, dir: c === 'name' ? 'asc' : 'desc' };
        paint();
        return;
      }

      const csv = ev.target.closest('[data-org-csv]');
      if (csv) {
        const rows = csvRows(); if (!rows) return;
        if (typeof downloadCSVRows === 'function') downloadCSVRows(rows, 'spend-by-organization.csv');
        return;
      }

      const row = ev.target.closest('[data-drillkey]');
      if (row) drill(row.dataset.drillkey, row.querySelector('td')?.textContent.trim() || '—');
    });

    card.addEventListener('keydown', (ev) => {
      const row = ev.target.closest('[data-drillkey]');
      if (row && (ev.key === 'Enter' || ev.key === ' ')) {
        ev.preventDefault();
        drill(row.dataset.drillkey, row.querySelector('td')?.textContent.trim() || '—');
      }
    });

    load();
    loadCoverage();
  }

  // The page calls this after every period / month change so the table follows the
  // global control; the drill path is kept so a leader stays open across a re-load.
  window.orgRollupReload = function () { S.data = null; S.loading = false; load(); loadCoverage(); };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire);
  else wire();
})();
