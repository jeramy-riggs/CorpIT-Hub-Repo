// ================================================================
// IT COMMAND — UX ENHANCEMENTS LAYER
// Additive-only: augments IT_Inventory_App.js without modifying it
// ================================================================

(function() {
  'use strict';

  // ── COMMAND PALETTE — REMOVED 2026-09-03 ────────────────────
  // ~150 lines here implemented a ⌘K palette (CMD_PAGES / CMD_ACTIONS /
  // openCmdPalette / closeCmdPalette / renderCmdResults / window._cmdSelect /
  // scrollCmdItemIntoView / an ArrowUp-ArrowDown-Enter branch) against the ids
  // #cmd-backdrop, #cmd-input and #cmd-results. Those ids appear in NO html,
  // and .cmd-item / .cmd-kbd appear in NO stylesheet — not on corpit and not on
  // itam before it. Every entry point bailed on its own null guard, so the
  // palette never ran once in either deployment.
  //
  // It was not harmless while it sat there. The keydown handler called
  // e.preventDefault() BEFORE reaching that guard, so ⌘K/Ctrl+K was swallowed
  // page-wide: the user lost the browser's own address-bar shortcut and got
  // nothing back. Two of the palette's targets ('mobile-historical' and
  // 'tablets-historical') named pages that do not exist either, and showPage()
  // dereferences getElementById('page-'+name) with no null check AFTER it has
  // already stripped .active off every page — so selecting one would have left
  // the content area blank until reload.
  //
  // Deleted rather than built: this project does not ship a control that cannot
  // do its job. If a palette is wanted later, add the markup FIRST (a real
  // combobox/listbox/option structure — not .cmd-item divs carrying inline
  // onmouseenter/onclick, which have no keyboard semantics and would not
  // survive CSP enforcement), and keep preventDefault() INSIDE the branch that
  // actually opens something so the key falls through when it does not.
  document.addEventListener('DOMContentLoaded', function() {

    // ── SEARCH BAR: Focus on "/" key ──────────────────────────
    document.addEventListener('keydown', function(e) {
      if (e.key === '/' && !e.metaKey && !e.ctrlKey && !e.altKey) {
        const active = document.activeElement;
        const tag = active ? active.tagName.toLowerCase() : '';
        if (tag === 'input' || tag === 'textarea' || tag === 'select') return;
        e.preventDefault();
        const search = document.getElementById('global-search');
        if (search) search.focus();
      }
    });

    // ── CLICK OUTSIDE column picker → close ──────────────────
    document.addEventListener('click', function(e) {
      if (!e.target.closest('.col-picker-wrap')) {
        document.querySelectorAll('.col-picker-dropdown').forEach(d => d.classList.remove('show'));
      }
    });

    // ── ENHANCED TABLE ROW HOVER → show row number ───────────
    // (Purely visual, no DOM mutation needed — handled by CSS nth-child)

    // ── TOPBAR SHADOW ON SCROLL ──────────────────────────────
    const content = document.getElementById('content');
    const topbar = document.getElementById('topbar');
    if (content && topbar) {
      content.addEventListener('scroll', function() {
        if (content.scrollTop > 4) {
          topbar.style.boxShadow = '0 1px 6px rgba(0,0,0,0.15)';
        } else {
          topbar.style.boxShadow = 'none';
        }
      });
    }

    // ── DRAG-OVER STYLING FOR DROP ZONE ──────────────────────
    const dropZone = document.getElementById('drop-zone');
    if (dropZone) {
      dropZone.addEventListener('dragover', () => dropZone.classList.add('drag-over'));
      dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
      dropZone.addEventListener('drop', () => dropZone.classList.remove('drag-over'));
    }
  });

  // ── ENHANCED TOAST (extend existing showToast if available) ──
  const _origShowToast = window.showToast;
  window.showToast = function(msg, type) {
    if (_origShowToast) {
      _origShowToast(msg, type);
    }
    // Ensure the toast dot color matches type
    const dot = document.getElementById('toast-dot');
    if (dot) {
      dot.className = 'toast-dot';
      if (type === 'err') dot.classList.add('err');
      else if (type === 'warn') dot.classList.add('warn');
    }
  };

  // ── TABLE ROW CLICK → SELECT (visual feedback) ─────────────
  document.addEventListener('click', function(e) {
    const row = e.target.closest('tbody tr');
    if (!row) return;
    // Don't select if clicking a button or link
    if (e.target.closest('button') || e.target.closest('a')) return;
    // Toggle selected state
    const wasSelected = row.classList.contains('row-selected');
    row.closest('tbody').querySelectorAll('tr.row-selected').forEach(r => r.classList.remove('row-selected'));
    if (!wasSelected) row.classList.add('row-selected');
  });

  // Inject minimal style for row selection
  const style = document.createElement('style');
  style.textContent = `
    tbody tr.row-selected td {
      background: var(--accent-muted) !important;
      border-color: var(--accent-border) !important;
    }
    tbody tr.row-selected td:first-child {
      box-shadow: inset 2px 0 0 var(--accent);
    }
  `;
  document.head.appendChild(style);

})();

/* MY-PROFILE-RECENTS (2026-09-05): tell My Profile which records this technician opened.
   Wraps the page's global editRecord(table, ref) — the only entry point for the record
   modal — and never changes its behaviour; a failed beacon is swallowed. */
(function () {
  function wrap() {
    var orig = window.editRecord;
    if (typeof orig !== 'function' || orig.__profileWrapped) return false;
    var w = function (table, ref) {
      try {
        var rec = (typeof window._resolveRecord === 'function') ? (window._resolveRecord(table, ref) || {}).record : null;
        var r = rec || {};
        var label = r.hostname || r.device_name || r.computer_name || r.name || r.display_name || r.serial_number || r.serial || r.email || r.user_principal_name || r.asset_tag || ('record ' + ref);
        var id = String(r.id || r.serial_number || r.serial || r.hostname || ref);
        if (window.itProfile) window.itProfile.view('asset', table + ':' + id, 'Viewed ' + table.replace(/_/g, ' ') + ' record ' + String(label).slice(0, 80), '/IT_Inventory_App.html', { table: table });
      } catch (e) {}
      return orig.apply(this, arguments);
    };
    w.__profileWrapped = true;
    window.editRecord = w;
    return true;
  }
  if (!wrap()) document.addEventListener('DOMContentLoaded', wrap);
})();

/* MY-PROFILE-DEEPLINK (2026-09-05): My Profile links devices as
   /IT_Inventory_App.html#table=<tab>&find=<serial or name>. Open that tab and pre-fill the
   global search. Data loads asynchronously, so the search is re-applied a few times; the
   app keeps searchQuery across renders, so the filter sticks once rows arrive. */
(function () {
  var preferHash=false;
  function params() {
    var query = new URLSearchParams(location.search);
    if(!preferHash && (query.has('table') || query.has('find')))return {table:query.get('table') || '',find:query.get('find') || ''};
    var h = String(location.hash || '').replace(/^#/, '');
    if (!/(^|&)(table|find)=/.test(h)) return null;
    var out = {}; h.split('&').forEach(function (kv) { var i = kv.indexOf('='); if (i > 0) { try { out[decodeURIComponent(kv.slice(0, i))] = decodeURIComponent(kv.slice(i + 1)); } catch (e) {} } });
    return out;
  }
  function apply() {
    var p = params(); if (!p) return;
    try {
      if (p.table && typeof window.showPage === 'function' && document.getElementById('page-' + p.table)) window.showPage(p.table);
      if (p.find) {
        var box = document.getElementById('global-search');
        if (box) box.value = p.find;
        if (typeof window.onSearch === 'function') window.onSearch(p.find);
      }
    } catch (e) {}
  }
  function boot() { apply(); setTimeout(apply, 1200); setTimeout(apply, 3000); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
  window.addEventListener('hashchange', function(){preferHash=true;apply();});
})();
