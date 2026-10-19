/* index.js — the reporting landing.
 * Everything here is already scope-enforced server-side: /rollup intersects with
 * the caller's resolved scope, so this page never filters anything itself. It
 * asks what the viewer's scope IS only to LABEL the screen - an unlabelled
 * number is how someone reports a bug against data that was never theirs. */
'use strict';
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const money = (n) => '$' + (Number(n) || 0).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });

let SCOPE = null, VIEWAS = null, TRAIL = [];

async function api(p) {
  const r = await fetch(p, { credentials: 'same-origin' });
  if (!r.ok) { const e = new Error('HTTP ' + r.status); e.status = r.status; throw e; }
  return r.json();
}
const qs = () => new URLSearchParams(location.search);
const viewAsParam = () => { const v = qs().get('viewAs'); return v ? '&viewAs=' + encodeURIComponent(v) : ''; };

// Where a scope should START. Showing a self-scoped person a table of
// departments they cannot open would be a menu of locked doors.
const START_LEVEL = { org: 'leader', leader: 'department', team: 'department', self: 'user', unknown: 'user' };

async function boot() {
  try {
    const [s, v] = await Promise.all([
      api('/api/rbac/me/scope'),
      api('/api/rbac/me/view-as').catch(() => ({ grant: null })),
    ]);
    SCOPE = s.scope; VIEWAS = v.grant;
  } catch (e) {
    $('scopeLine').innerHTML = '<span class="bad">Could not determine what you are allowed to see.</span>';
    return;
  }
  const impersonating = qs().get('viewAs');
  $('scopeLine').innerHTML = impersonating
    ? `<span class="warnbar">Viewing as <b>${esc(impersonating)}</b> &mdash; ${esc(SCOPE.label || '')}
       <a href="/">exit</a></span>`
    : `You are seeing <b>${esc(SCOPE.label || SCOPE.kind)}</b>`;

  if (SCOPE.deny) {
    $('body-main').innerHTML = `<section class="card"><h2>Nothing to show yet</h2>
      <p class="dim">We could not place you on the HR roster, so there is no dashboard to build.
      That is deliberate &mdash; showing an empty department would look like zero spend rather
      than an unanswered question. Ask IT to check your roster record.</p></section>`;
    return;
  }
  const links = [];
  links.push('<a class="btn" href="/ai-usage-credits.html">Full AI usage report</a>');
  // The view-as "Access & dashboards" button pointed at /scope-admin.html, a page
  // that exists on no host. Scope assignment is API-only for now (PUT
  // /api/rbac/users/:email/scope, super-admin); the button returns with a real page.
  $('links').innerHTML = links.join(' ');

  TRAIL = [{ level: START_LEVEL[SCOPE.kind] || 'department', filters: {}, label: 'Overview' }];
  render();
}

async function render() {
  const cur = TRAIL[TRAIL.length - 1];
  const f = cur.filters || {};
  const q = ['level=' + encodeURIComponent(cur.level), 'months=6'];
  ['leader', 'department', 'manager'].forEach((k) => { if (f[k]) q.push(k + '=' + encodeURIComponent(f[k])); });
  $('rows').innerHTML = '<tr><td colspan="4" class="dim pad">Loading&hellip;</td></tr>';
  let d;
  try { d = await api('/api/claude-analytics/rollup?' + q.join('&') + viewAsParam()); }
  catch (e) {
    $('rows').innerHTML = `<tr><td colspan="4" class="bad pad">Could not load (${e.status || 'error'}).</td></tr>`;
    return;
  }

  const months = d.months || [];
  const thisM = months[months.length - 1], prevM = months[months.length - 2];
  const tot = (m) => (d.rows || []).reduce((a, r) => a + (r.months?.[m] || 0), 0);
  const now = tot(thisM), was = tot(prevM);
  const delta = was ? ((now - was) / was) * 100 : null;

  $('tiles').innerHTML = `
    <div class="tile"><div class="k">${(d.rows || []).reduce((a, r) => a + (r.users || 0), 0)}</div><div class="l">People with AI usage</div></div>
    <div class="tile"><div class="k">${money(now)}</div><div class="l">Spend this month</div></div>
    <div class="tile"><div class="k">${delta === null ? '&mdash;' : (delta >= 0 ? '+' : '') + delta.toFixed(0) + '%'}</div>
         <div class="l">vs last month ${prevM ? '(' + money(was) + ')' : ''}</div></div>
    <div class="tile"><div class="k">${money(d.grand?.total || 0)}</div><div class="l">Total, last 6 months</div></div>`;

  const LEVEL_NOUN = { leader: 'Organisation', department: 'Department', manager: 'Manager', user: 'Person' };
  $('tblHead').textContent = LEVEL_NOUN[cur.level] || 'Group';
  const canDrill = !!d.nextLevel;
  $('rows').innerHTML = (d.rows || []).length ? d.rows.map((r) => `
    <tr${canDrill ? ` class="drill" data-key="${esc(r.key)}" data-name="${esc(r.name)}"` : ''}>
      <td><b>${esc(r.name)}</b>${canDrill ? '<span class="chev">›</span>' : ''}</td>
      <td class="num">${r.users || 0}</td>
      <td class="num">${money(r.months?.[thisM] || 0)}</td>
      <td class="num">${money(r.total || 0)}</td></tr>`).join('')
    : '<tr><td colspan="4" class="dim pad">No AI usage recorded in this view.</td></tr>';

  $('crumb').innerHTML = TRAIL.map((t, i) =>
    i === TRAIL.length - 1 ? `<span>${esc(t.label)}</span>`
                           : `<a href="#" data-crumb="${i}">${esc(t.label)}</a> <span class="sep">/</span>`).join(' ');
  $('levelNote').textContent = canDrill ? `Select a row to open its ${d.nextLevel}.` : '';
}

document.addEventListener('click', (ev) => {
  const c = ev.target.closest('[data-crumb]');
  if (c) { ev.preventDefault(); TRAIL = TRAIL.slice(0, Number(c.dataset.crumb) + 1); render(); return; }
  const row = ev.target.closest('tr.drill');
  if (!row) return;
  const cur = TRAIL[TRAIL.length - 1];
  const next = { leader: 'department', department: 'manager', manager: 'user' }[cur.level];
  if (!next) return;
  const filters = { ...cur.filters };
  filters[cur.level === 'leader' ? 'leader' : cur.level === 'department' ? 'department' : 'manager'] = row.dataset.key;
  TRAIL.push({ level: next, filters, label: row.dataset.name });
  render();
});
document.addEventListener('DOMContentLoaded', boot);
