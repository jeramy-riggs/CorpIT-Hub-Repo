// CorpIT Hub deployment. Ported from itam.nrpi.local/it-security-posture.js
// (source md5 ec12188b50c6fcda9e633e849110ffe0) on 2026-09-06. ITAM copy untouched.
// Removed here: the hardcoded WORK{} dictionary of per-finding exploitation
// write-ups. It described ITAM's F1-F12 (not this host's findings) and, as a
// static asset, put an attack path in client-reachable code. Finding detail
// and fix text still come from the gated /api/system findings response.
/* it-security-posture.js v2 — "Typeset Report" Security tab for Server Health.
   Self-contained: injects its own scoped styles (prefixed #tab-security, so nothing
   leaks to the shell or other tabs), its own nav button + panel, and talks to the
   real /api/system/security-posture. Colors come from the page's own theme tokens so
   it coheres in light and dark with no external fonts (CSP-safe). Every dynamic string
   is HTML-escaped — this is a security tool, it does not add a sink. */
(function () {
  'use strict';
  var API = '/api/system';
  var SERIF = "Georgia,'Times New Roman',Times,serif";
  var data = null, loaded = false;

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function get(p) { return fetch(API + p).then(function (r) { return r.json().then(function (j) { return { ok: r.ok, status: r.status, body: j }; }); }); }
  function post(p, b) {
    return fetch(API + p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b || {}) })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, status: r.status, body: j }; }); });
  }
  function sevColor(s) { return s === 'high' ? 'var(--down)' : s === 'medium' ? 'var(--warn)' : s === 'low' ? 'var(--muted)' : 'var(--faint)'; }
  function gradeColor(g) { return (g === 'A' || g === 'B') ? 'var(--ok)' : g === 'C' ? 'var(--warn)' : 'var(--down)'; }
  function stColor(st) { return st === 'fixed' ? 'var(--ok)' : st === 'in_progress' ? 'var(--warn)' : st === 'unknown' ? 'var(--muted)' : 'var(--down)'; }
  var SEVLABEL = { high: 'HIGH', medium: 'MED', low: 'LOW', info: 'INFO' };
  var STLABEL = { open: 'Open', in_progress: 'In progress', fixed: 'Fixed', unknown: 'Unverified' };

  var COPY_ICON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/></svg>';

  // Assemble one finding into a self-contained plaintext work brief (id, severity,
  // status, evidence and fix) for the clipboard.
  function buildBrief(f) {
    var L = [];
    L.push('[' + f.id + '] ' + f.title);
    L.push('Severity: ' + (SEVLABEL[f.severity] || f.severity) +
      '  ·  Risk-points: ' + f.points +
      '  ·  Category: ' + f.category +
      '  ·  Status: ' + (STLABEL[f.state] || f.state));
    if (f.detail) { L.push(''); L.push('Evidence: ' + f.detail); }
    if (f.fix) { L.push(''); L.push('Fix: ' + f.fix); }
    L.push(''); L.push('— corpit.nrpi.local · Server Health › Security posture (' + f.id + ')');
    return L.join('\n');
  }
  function copyFallback(text) {
    try {
      var ta = document.createElement('textarea');
      ta.value = text; ta.setAttribute('readonly', '');
      ta.style.position = 'fixed'; ta.style.top = '0'; ta.style.left = '0'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      var ok = document.execCommand('copy'); document.body.removeChild(ta); return ok;
    } catch (e) { return false; }
  }
  function copyBrief(f, btn) {
    var text = buildBrief(f);
    function done(ok) {
      if (!btn) return;
      var lbl = btn.querySelector('.lbl');
      if (lbl) lbl.textContent = ok ? 'Copied' : 'Copy failed';
      btn.classList.toggle('ok', ok);
      setTimeout(function () { if (lbl) lbl.textContent = 'Copy brief'; btn.classList.remove('ok'); }, 1500);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(copyFallback(text)); });
    } else { done(copyFallback(text)); }
  }

  function ensureStyle() {
    if (document.getElementById('sw-style')) return;
    var css =
      '#tab-security{font-family:var(--font)}' +
      '#tab-security .sw-h1{font-family:' + SERIF + ';font-weight:600;font-size:27px;letter-spacing:-.01em;margin:0 0 5px;color:var(--ink)}' +
      '#tab-security .sw-sf{color:var(--muted);font-size:14px;max-width:64ch;margin:0 0 20px}' +
      '#tab-security .sw-plate{display:grid;grid-template-columns:auto 1fr;gap:28px;align-items:center;padding:22px 24px;border:1px solid var(--line);border-radius:16px;background:var(--card)}' +
      '#tab-security .sw-gauge{position:relative;width:140px;height:140px;flex:none}' +
      '#tab-security .sw-gauge svg{transform:rotate(-90deg)}' +
      '#tab-security .sw-gc{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}' +
      '#tab-security .sw-num{font-family:' + SERIF + ';font-weight:600;font-size:52px;line-height:.9;letter-spacing:-.02em;color:var(--ink);font-variant-numeric:tabular-nums}' +
      '#tab-security .sw-of{font-family:var(--mono);font-size:11px;color:var(--muted);margin-top:2px}' +
      '#tab-security .sw-verdict{font-family:' + SERIF + ';font-size:21px;font-weight:500;line-height:1.35;color:var(--ink);max-width:36ch}' +
      '#tab-security .sw-grade{display:inline-block;font-family:var(--mono);font-size:14px;font-weight:600;padding:0 9px;border-radius:6px;vertical-align:3px;margin-left:6px;border:1px solid currentColor}' +
      '#tab-security .sw-prog{margin-top:16px;max-width:440px}' +
      '#tab-security .sw-track{height:7px;border-radius:5px;background:var(--surf2);overflow:hidden}' +
      '#tab-security .sw-fill{height:100%;width:100%;transform:scaleX(0);transform-origin:left;transition:transform .9s cubic-bezier(.22,1,.36,1)}' +
      '#tab-security .sw-pc{margin-top:7px;font-family:var(--mono);font-size:12px;color:var(--muted)}' +
      '#tab-security .sw-ledger{display:flex;flex-wrap:wrap;margin:18px 0 4px;border:1px solid var(--line);border-radius:12px;overflow:hidden}' +
      '#tab-security .sw-led{flex:1;min-width:120px;padding:13px 16px;border-right:1px solid var(--line)}' +
      '#tab-security .sw-led:last-child{border-right:0}' +
      '#tab-security .sw-led b{display:block;font-family:' + SERIF + ';font-weight:600;font-size:25px;line-height:1;font-variant-numeric:tabular-nums}' +
      '#tab-security .sw-led span{font-size:11px;letter-spacing:.04em;text-transform:uppercase;color:var(--muted)}' +
      '#tab-security .sw-tools{display:flex;align-items:center;gap:12px;margin:24px 0 6px;flex-wrap:wrap}' +
      '#tab-security .sw-note{margin-left:auto;font-size:12px;color:var(--muted)}' +
      '#tab-security .sw-btn{height:34px;padding:0 14px;border:1px solid var(--ink);border-radius:8px;background:var(--ink);color:var(--card);font:inherit;font-size:13px;cursor:pointer;display:inline-flex;align-items:center;gap:7px}' +
      '#tab-security .sw-btn:hover{opacity:.9}' +
      '#tab-security .sw-sevband{display:flex;align-items:baseline;gap:12px;margin:24px 0 2px;padding-bottom:7px;border-bottom:1.5px solid var(--ink)}' +
      '#tab-security .sw-sevband h3{font-family:' + SERIF + ';font-weight:600;font-size:16px;margin:0;color:var(--ink)}' +
      '#tab-security .sw-sevband .c{font-family:var(--mono);font-size:12px;color:var(--muted)}' +
      '#tab-security .sw-f{display:grid;grid-template-columns:78px 1fr auto;gap:20px;padding:16px 4px;border-bottom:1px solid var(--line);align-items:start}' +
      '#tab-security .sw-st2{font-family:var(--mono);font-size:11px;font-weight:600;letter-spacing:.05em}' +
      '#tab-security .sw-st2 .pts{display:block;margin-top:5px;font-size:18px;font-family:' + SERIF + ';font-weight:600;color:var(--ink);font-variant-numeric:tabular-nums;letter-spacing:0}' +
      '#tab-security .sw-st2 .pl{font-size:10px;color:var(--muted);font-family:var(--font);letter-spacing:.03em;text-transform:uppercase}' +
      '#tab-security .sw-ft{font-family:' + SERIF + ';font-weight:600;font-size:16px;color:var(--ink);line-height:1.3}' +
      '#tab-security .sw-fid{font-family:var(--mono);font-size:12px;font-weight:400;color:var(--muted);margin-left:7px}' +
      '#tab-security .sw-evi{font-family:var(--mono);font-size:12px;color:var(--ink);margin-top:6px;background:var(--surf2);border-radius:6px;padding:6px 10px;display:inline-block;line-height:1.5}' +
      '#tab-security .sw-fix{font-size:13px;color:var(--muted);margin-top:8px;line-height:1.5}' +
      '#tab-security .sw-fix b{color:var(--ink);font-weight:600}' +
      '#tab-security .sw-fs{text-align:right;white-space:nowrap;display:flex;flex-direction:column;align-items:flex-end;gap:8px}' +
      '#tab-security .sw-tag{font-family:var(--mono);font-size:11px;font-weight:600;padding:3px 9px;border-radius:6px;border:1px solid currentColor}' +
      '#tab-security .sw-auto{font-family:var(--mono);font-size:10px;letter-spacing:.06em;color:var(--muted);border:1px solid var(--line2);border-radius:5px;padding:1px 6px}' +
      '#tab-security .sw-seg{display:inline-flex;border:1px solid var(--line2);border-radius:8px;overflow:hidden}' +
      '#tab-security .sw-seg button{border:0;background:none;font:inherit;font-size:11.5px;padding:5px 10px;color:var(--muted);cursor:pointer;border-right:1px solid var(--line)}' +
      '#tab-security .sw-seg button:last-child{border-right:0}' +
      '#tab-security .sw-seg button:hover{background:var(--surf2);color:var(--ink)}' +
      '#tab-security .sw-seg button.on{background:var(--ink);color:var(--card)}' +
      '#tab-security .sw-seg button.on.fx{background:var(--ok);color:#fff}' +
      '#tab-security .sw-copy{margin-top:2px;height:26px;padding:0 11px;border:1px solid var(--line2);border-radius:7px;background:none;color:var(--muted);font-family:var(--mono);font-size:11px;letter-spacing:.02em;cursor:pointer;display:inline-flex;align-items:center;gap:6px;transition:border-color .14s,color .14s}' +
      '#tab-security .sw-copy:hover{border-color:var(--ink);color:var(--ink)}' +
      '#tab-security .sw-copy svg{width:12px;height:12px;flex:none}' +
      '#tab-security .sw-copy.ok{border-color:var(--ok);color:var(--ok)}' +
      '#tab-security .sw-empty{padding:24px;color:var(--muted)}' +
      '@media(max-width:820px){#tab-security .sw-plate{grid-template-columns:1fr;text-align:center;justify-items:center}#tab-security .sw-f{grid-template-columns:56px 1fr}#tab-security .sw-fs{grid-column:1/-1;align-items:flex-start;flex-direction:row;flex-wrap:wrap}}';
    var st = document.createElement('style'); st.id = 'sw-style'; st.textContent = css;
    document.head.appendChild(st);
  }

  var R = 62, C = 2 * Math.PI * R;

  function verdictLine(d) {
    if (d.counts.fixed === d.total) return 'All tracked findings cleared — hold the line.';
    if (d.counts.openHigh > 0) return d.counts.openHigh + ' high-severity finding' + (d.counts.openHigh > 1 ? 's' : '') + ' still open — clear those first.';
    return 'No high-severity findings open; working down the remainder.';
  }

  function render() {
    var host = document.getElementById('tab-security');
    if (!host) return;
    if (!data) { host.innerHTML = '<div class="sw-empty">Loading security posture…</div>'; return; }
    var d = data, gc = gradeColor(d.grade);
    var pct = d.maxPoints ? d.remediatedPoints / d.maxPoints : 0;
    var lowInfo = (d.counts.low || 0) + (d.counts.info || 0) - d.items.filter(function (i) { return (i.severity === 'low' || i.severity === 'info') && i.state === 'fixed'; }).length;

    var head =
      '<h1 class="sw-h1">Security posture</h1>' +
      '<p class="sw-sf">Live checks re-run on load; tracked remediations an admin confirms. The score climbs toward 100 as each finding closes.</p>' +
      '<div class="sw-plate">' +
        '<div class="sw-gauge"><svg width="140" height="140" viewBox="0 0 140 140">' +
          '<circle cx="70" cy="70" r="' + R + '" fill="none" stroke="var(--line)" stroke-width="11"/>' +
          '<circle id="sw-arc" cx="70" cy="70" r="' + R + '" fill="none" stroke="' + gc + '" stroke-width="11" stroke-linecap="round" stroke-dasharray="' + C.toFixed(1) + '" stroke-dashoffset="' + C.toFixed(1) + '"/>' +
        '</svg><div class="sw-gc"><div class="sw-num" id="sw-num">0</div><div class="sw-of">out of 100</div></div></div>' +
        '<div>' +
          '<div class="sw-verdict">' + esc(verdictLine(d)) + '<span class="sw-grade" id="sw-grade" style="color:' + gc + '">' + esc(d.grade) + '</span></div>' +
          '<div class="sw-prog"><div class="sw-track"><div class="sw-fill" id="sw-fill" style="background:' + gc + '"></div></div>' +
          '<div class="sw-pc"><span id="sw-rem">' + d.remediatedPoints + '</span> of ' + d.maxPoints + ' risk-points cleared</div></div>' +
        '</div>' +
      '</div>' +
      '<div class="sw-ledger">' +
        '<div class="sw-led"><b style="color:var(--down)" id="sw-chi">' + d.counts.openHigh + '</b><span>Open · high</span></div>' +
        '<div class="sw-led"><b style="color:var(--warn)" id="sw-cmed">' + d.counts.medium + '</b><span>Open · medium</span></div>' +
        '<div class="sw-led"><b style="color:var(--ink)" id="sw-clow">' + lowInfo + '</b><span>Open · low / info</span></div>' +
        '<div class="sw-led"><b style="color:var(--ok)" id="sw-cfix">' + d.counts.fixed + '</b><span>Fixed of ' + d.total + '</span></div>' +
      '</div>' +
      '<div class="sw-tools"><button class="sw-btn" id="sw-rerun">Re-run live checks</button>' +
      '<span class="sw-note">Auto checks read live state · manual items need a server-health admin to confirm</span></div>';

    var groups = [['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['info', 'Informational']];
    var body = '';
    groups.forEach(function (g) {
      var items = d.items.filter(function (f) { return f.severity === g[0]; }).sort(function (a, b) { return b.points - a.points; });
      if (!items.length) return;
      body += '<div class="sw-sevband"><h3>' + g[1] + '</h3><span class="c">' + items.length + ' finding' + (items.length > 1 ? 's' : '') + '</span></div>';
      items.forEach(function (f) {
        var ctrl;
        if (f.mode === 'manual') {
          ctrl = '<div class="sw-seg" data-fid="' + esc(f.id) + '">' + ['open', 'in_progress', 'fixed'].map(function (s) {
            return '<button data-st="' + s + '" class="' + (f.state === s ? 'on' + (s === 'fixed' ? ' fx' : '') : '') + '">' + esc(STLABEL[s]) + '</button>';
          }).join('') + '</div>';
        } else {
          ctrl = '<span class="sw-tag" style="color:' + stColor(f.state) + '">' + esc(STLABEL[f.state] || f.state) + '</span> <span class="sw-auto">AUTO</span>';
        }
        var who = f.updatedBy ? '<div style="font-size:10.5px;color:var(--muted)">set by ' + esc(f.updatedBy) + '</div>' : '';
        var copyBtn = '<button class="sw-copy" data-fid="' + esc(f.id) + '" title="Copy this finding as a work brief">' + COPY_ICON + '<span class="lbl">Copy brief</span></button>';
        body += '<div class="sw-f">' +
          '<div class="sw-st2" style="color:' + sevColor(f.severity) + '">' + esc(SEVLABEL[f.severity] || f.severity) + '<span class="pts">' + f.points + '<span class="pl"> pts</span></span></div>' +
          '<div><div class="sw-ft">' + esc(f.title) + '<span class="sw-fid">' + esc(f.id) + '</span></div>' +
          (f.detail ? '<div class="sw-evi">' + esc(f.detail) + '</div>' : '') +
          '<div class="sw-fix"><b>Fix</b> — ' + esc(f.fix) + '</div></div>' +
          '<div class="sw-fs">' + ctrl + who + copyBtn + '</div>' +
        '</div>';
      });
    });

    host.innerHTML = head + body;
    var rr = document.getElementById('sw-rerun');
    if (rr) rr.addEventListener('click', function () { load(true); });
    Array.prototype.forEach.call(host.querySelectorAll('.sw-seg button'), function (b) {
      b.addEventListener('click', function () {
        var fid = b.parentNode.getAttribute('data-fid'), val = b.getAttribute('data-st');
        note('Saving…');
        post('/security-posture/status', { id: fid, status: val }).then(function (r) {
          if (r.ok && r.body && r.body.ok) { load(false); }
          else if (r.status === 401 || r.status === 403) note('Server-health admin required to change status.');
          else note((r.body && r.body.error) || ('Save failed (HTTP ' + r.status + ')'));
        }).catch(function () { note('Save failed (network).'); });
      });
    });
    Array.prototype.forEach.call(host.querySelectorAll('.sw-copy'), function (b) {
      b.addEventListener('click', function () {
        var fid = b.getAttribute('data-fid');
        var f = (data && data.items) ? data.items.filter(function (x) { return x.id === fid; })[0] : null;
        if (f) copyBrief(f, b);
      });
    });
    animate(d);
  }
  function note(t) { var n = document.querySelector('#tab-security .sw-note'); if (n) n.textContent = t; }

  function animate(d) {
    var arc = document.getElementById('sw-arc'), fill = document.getElementById('sw-fill'), num = document.getElementById('sw-num');
    if (!arc) return;
    var off = C * (1 - d.score / 100), pct = d.maxPoints ? d.remediatedPoints / d.maxPoints : 0;
    requestAnimationFrame(function () {
      arc.style.transition = 'stroke-dashoffset .9s cubic-bezier(.22,1,.36,1)';
      arc.style.strokeDashoffset = off;
      if (fill) fill.style.transform = 'scaleX(' + pct.toFixed(4) + ')';
    });
    countTo(num, d.score);
  }
  function countTo(el, target) {
    if (!el) return;
    var start = parseInt(el.textContent, 10) || 0, t0 = null, dur = 800;
    function step(ts) { if (!t0) t0 = ts; var p = Math.min(1, (ts - t0) / dur); var e = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(start + (target - start) * e); if (p < 1) requestAnimationFrame(step); else el.textContent = target; }
    requestAnimationFrame(step);
    setTimeout(function () { el.textContent = target; }, dur + 160);
  }

  function load(force) {
    if (loaded && !force && data) { render(); return; }
    render();
    get('/security-posture').then(function (r) {
      if (r.ok && r.body && typeof r.body.score === 'number') { data = r.body; loaded = true; render(); }
      else {
        var host = document.getElementById('tab-security');
        if (host) host.innerHTML = '<div class="sw-empty">Could not load security posture' +
          (r.status === 401 || r.status === 403 ? ' — this view needs a server-health grant.' : ' (HTTP ' + esc(String(r.status)) + ').') + '</div>';
      }
    }).catch(function () {
      var host = document.getElementById('tab-security');
      if (host) host.innerHTML = '<div class="sw-empty">Could not reach the security posture API.</div>';
    });
  }

  function inject() {
    var nav = document.querySelector('nav.rail');
    if (!nav || document.querySelector('.navitem[data-tab="security"]')) return;
    ensureStyle();
    var btn = document.createElement('button');
    btn.className = 'navitem'; btn.setAttribute('role', 'tab'); btn.setAttribute('data-tab', 'security');
    btn.innerHTML = '<svg class="icon"><use href="#i-alert"/></svg>Security score';
    btn.addEventListener('click', function () { if (typeof window.showTab === 'function') window.showTab('security', btn); load(false); });
    var anchor = nav.querySelector('.navitem[data-tab="findings"]');
    if (anchor && anchor.nextSibling) nav.insertBefore(btn, anchor.nextSibling); else nav.appendChild(btn);

    var anyPanel = document.querySelector('.tabpanel');
    if (anyPanel && anyPanel.parentNode && !document.getElementById('tab-security')) {
      var panel = document.createElement('div');
      panel.className = 'tabpanel'; panel.id = 'tab-security'; panel.setAttribute('role', 'tabpanel');
      panel.innerHTML = '<div class="sw-empty">Loading…</div>';
      anyPanel.parentNode.appendChild(panel);
    }
    if ((location.hash || '').replace('#', '') === 'security') {
      if (typeof window.showTab === 'function') window.showTab('security', btn);
      load(false);
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', inject); else inject();
})();
