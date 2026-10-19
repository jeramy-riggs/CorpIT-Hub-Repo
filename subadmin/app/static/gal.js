// Directory Sync dashboard - CSP-clean (script-src 'self'): no inline handlers.
(function () {
  'use strict';

  var dataEl = document.getElementById('galdata');
  var GAL = dataEl ? JSON.parse(dataEl.textContent) : [];
  var byUpn = {};
  GAL.forEach(function (m) { byUpn[m.upn.toLowerCase()] = m; });

  function $(id) { return document.getElementById(id); }

  function fly(id) {
    var el = $(id);
    if (!el) return;
    el.classList.add('open');
    if ($('bk')) $('bk').classList.add('open');
  }
  function flyclose() {
    document.querySelectorAll('.msx-fly.open').forEach(function (e) { e.classList.remove('open'); });
    if ($('bk')) $('bk').classList.remove('open');
  }

  var f = { q: '', status: 'all', list: 'all' };
  function applyFilters() {
    var q = $('q'), lsel = $('lsel');
    f.q = q ? q.value.toLowerCase() : '';
    f.list = lsel ? lsel.value : 'all';
    var n = 0;
    document.querySelectorAll('#ptable tbody tr[data-upn]').forEach(function (tr) {
      var ok = true;
      if (f.q && tr.dataset.name.indexOf(f.q) < 0 && tr.dataset.upn.indexOf(f.q) < 0) ok = false;
      if (ok && f.status !== 'all' && tr.dataset.status !== f.status) ok = false;
      if (ok && f.list !== 'all') {
        var ls = tr.dataset.lists ? tr.dataset.lists.split(',') : [];
        if (f.list === '__none__') { if (ls.length) ok = false; }
        else if (ls.indexOf(f.list) < 0) ok = false;
      }
      tr.style.display = ok ? '' : 'none';
      if (ok) n++;
    });
    if ($('pcount')) $('pcount').textContent = n;
  }

  function person(upn) {
    var m = byUpn[upn];
    if (!m) return;
    var S = function (id, v) { if ($(id)) $(id).textContent = v; };
    S('pd-name', m.name);
    S('pd-upn', m.upn);
    S('pd-mail', m.mail || '—');
    S('pd-status', m.status === 'synced' ? 'Synced' : m.status === 'pending' ? 'Pending first sync' : 'Needs attention');
    S('pd-fence', m.inFence ? 'Yes' : 'NO — writes refused until added');
    S('pd-owned', m.owned === null ? '— (mailbox not readable last run)' : m.owned + ' directory contacts');
    S('pd-delta', m.inLastRun
      ? ('+' + (m.creates || 0) + ' created, ~' + (m.updates || 0) + ' updated, −' + (m.deletes || 0) + ' deleted')
      : 'not in last run');
    S('pd-lists', m.lists.length ? m.lists.join(', ') : 'none — cleanup only (cards removed on next run)');
    var ew = $('pd-errwrap');
    if (ew) {
      if (m.errorRaw) { ew.style.display = ''; S('pd-err', m.errorRaw); }
      else { ew.style.display = 'none'; }
    }
    S('pd-note', (m.status === 'error' && m.errorRaw && m.errorRaw.indexOf('403') >= 0)
      ? 'A 403 here is almost always the Exchange access-policy cache after a membership change. It clears on its own; the nightly run and retries cover it.'
      : '');
    var sel = $('pd-rm-list');
    if (sel) {
      sel.innerHTML = '';
      m.lists.forEach(function (l) {
        var o = document.createElement('option');
        o.value = l; o.textContent = l;
        sel.appendChild(o);
      });
    }
    if ($('pd-rm-upn')) $('pd-rm-upn').value = m.upn;
    if ($('pd-rm')) $('pd-rm').style.display = m.lists.length ? '' : 'none';
    fly('fl-person');
  }

  document.addEventListener('click', function (e) {
    var t;
    if ((t = e.target.closest('[data-fly]')))      { fly(t.dataset.fly); return; }
    if (e.target.closest('[data-flyclose]') || e.target.id === 'bk') { flyclose(); return; }
    if ((t = e.target.closest('.fchip'))) {
      document.querySelectorAll('.fchip').forEach(function (b) { b.classList.remove('on'); });
      t.classList.add('on');
      f.status = t.dataset.f;
      applyFilters();
      return;
    }
    if ((t = e.target.closest('[data-viewlist]'))) {
      var lsel = $('lsel');
      if (lsel) lsel.value = t.dataset.viewlist;
      applyFilters();
      var pt = $('ptable');
      if (pt) pt.scrollIntoView({ behavior: 'smooth', block: 'start' });
      return;
    }
    // row click opens the person pane - but not when a button/link/form control was hit
    if ((t = e.target.closest('tr.rowlink')) && !e.target.closest('button, a, input, select, form')) {
      person(t.dataset.upn);
    }
  });

  document.addEventListener('input', function (e) {
    if (e.target.id === 'q') applyFilters();
  });
  document.addEventListener('change', function (e) {
    if (e.target.id === 'lsel') applyFilters();
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') flyclose();
  });

  // ---- Group type-ahead for the New-list flyout ------------------------------
  // Fetched once per page load (server caches ~10 min); filtered locally.
  var GROUPS = null, groupsLoading = false;

  function ensureGroups(cb) {
    if (GROUPS) { cb(); return; }
    if (groupsLoading) return;
    groupsLoading = true;
    note('Loading group directory…');
    fetch('/gal/groups', { credentials: 'same-origin' })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        groupsLoading = false;
        if (d.ok) { GROUPS = d.groups; note(d.count + ' groups loaded'); cb(); }
        else note('Group directory unavailable: ' + (d.error || 'error'));
      })
      .catch(function () { groupsLoading = false; note('Group directory unavailable'); });
  }
  function note(t) { var n = $('ta-note'); if (n) n.textContent = t; }

  function renderTA(q) {
    var box = $('ta-group');
    if (!box || !GROUPS) return;
    q = q.toLowerCase().trim();
    var hits = !q ? GROUPS.slice(0, 12) : GROUPS.filter(function (g) {
      return g.name.toLowerCase().indexOf(q) >= 0 || (g.mail && g.mail.toLowerCase().indexOf(q) >= 0);
    }).slice(0, 12);
    box.innerHTML = '';
    if (!hits.length) {
      var d = document.createElement('div');
      d.style.cssText = 'padding:10px 12px;color:#8a8886;font-size:12.5px';
      d.textContent = 'No matching groups';
      box.appendChild(d);
    }
    hits.forEach(function (g) {
      var b = document.createElement('button');
      b.type = 'button';
      b.style.cssText = 'display:block;width:100%;text-align:left;border:0;background:none;' +
        'padding:8px 12px;font:inherit;font-size:13px;cursor:pointer;border-bottom:1px solid #f5f5f5';
      b.addEventListener('mouseenter', function () { b.style.background = '#f3f9fd'; });
      b.addEventListener('mouseleave', function () { b.style.background = 'none'; });
      var top = document.createElement('div');
      top.textContent = g.name;
      top.style.fontWeight = '600';
      var sub = document.createElement('div');
      sub.textContent = g.kind + (g.mail ? ' · ' + g.mail : '');
      sub.style.cssText = 'color:#8a8886;font-size:11.5px';
      b.appendChild(top); b.appendChild(sub);
      b.addEventListener('mousedown', function (ev) {
        ev.preventDefault();
        $('inp-group').value = g.name;
        $('inp-group-id').value = g.id;
        var radio = $('src-group-radio');
        if (radio) radio.checked = true;
        note('Selected: ' + g.name + ' (' + g.kind + ')');
        box.style.display = 'none';
      });
      box.appendChild(b);
    });
    box.style.display = '';
  }

  document.addEventListener('focusin', function (e) {
    if (e.target.id === 'inp-group') ensureGroups(function () { renderTA(e.target.value); });
  });
  document.addEventListener('input', function (e) {
    if (e.target.id === 'inp-group') {
      $('inp-group-id').value = '';           // typing invalidates a prior pick
      ensureGroups(function () { renderTA(e.target.value); });
      if (GROUPS) renderTA(e.target.value);
    }
  });
  document.addEventListener('focusout', function (e) {
    if (e.target.id === 'inp-group') {
      setTimeout(function () { var b = $('ta-group'); if (b) b.style.display = 'none'; }, 150);
    }
  });

  // confirm() dialogs, CSP-clean: forms carry data-confirm with an optional
  // {upn}/{list} placeholder filled at submit time.
  document.addEventListener('submit', function (e) {
    var form = e.target;
    if (!form.dataset || !form.dataset.confirm) return;
    var msg = form.dataset.confirm;
    var upnEl = form.querySelector('[name=upn]');
    var listEl = form.querySelector('[name=list]');
    msg = msg.replace('{upn}', upnEl ? upnEl.value : '')
             .replace('{list}', listEl ? listEl.value : '');
    if (!window.confirm(msg)) e.preventDefault();
  });
})();
