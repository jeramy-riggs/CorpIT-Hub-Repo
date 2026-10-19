/* System > Web watch. Talks only to /system/webwatch/* (owner-gated); those talk to the root
   corpit-webwatch service. Everything shown is what the HA monitor last read - a reading that
   is too old shows as unknown, never as fine. The service decides whether a clear may run and
   says why when it refuses; the button is disabled here only for reasons the page can see. */
(function(){
  var root = document.querySelector('[data-webwatch-panel]');
  if(!root) return;
  var tabPanel = root.closest('[data-tabpanel]');
  var badge = document.querySelector('[data-webwatch-badge]');
  var $ = function(sel){ return root.querySelector(sel); };
  var csrf = root.dataset.csrf;
  var state = { data: null, me: null, timer: null, inflight: false, lastOk: 0, pending: null, started: null };

  var WEB = { ready: ['p-good', '200 · serving'], not_ready: ['p-mut', '503 · not serving'],
    error: ['p-warn', 'check failed'], unknown: ['p-mut', 'no fresh reading'] };
  var FENCE = { started: ['p-good', 'started'], started_with_failures: ['p-warn', 'started · failure recorded'],
    failed: ['p-crit', 'FAILED'], stopped: ['p-crit', 'stopped'], unknown: ['p-mut', 'unknown'] };
  var KIND = { open: 'opened', escalate: 'escalated', resolve: 'resolved', remind: 'still open (reminder)' };
  var HELPER = { installed: 'installed', not_installed: 'not installed', unreachable: 'unreachable', unknown: 'not checked yet' };

  function el(tag, attrs, kids){
    var n = document.createElement(tag);
    if(attrs) Object.keys(attrs).forEach(function(k){
      if(k === 'text') n.textContent = attrs[k];
      else if(k === 'cls') n.className = attrs[k];
      else n.setAttribute(k, attrs[k]);
    });
    (kids || []).forEach(function(c){ if(c != null) n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); });
    return n;
  }
  function pill(cls, text){ return el('span', { cls: 'pill ' + cls, text: text }); }
  function rel(iso){
    if(!iso) return '—';
    var t = Date.parse(iso); if(isNaN(t)) return iso;
    var s = Math.round((Date.now() - t) / 1000), a = Math.abs(s), out;
    if(a < 60) out = a + ' s'; else if(a < 3600) out = Math.round(a / 60) + ' min';
    else if(a < 172800) out = Math.round(a / 3600) + ' h'; else out = Math.round(a / 86400) + ' days';
    return s >= 0 ? out + ' ago' : 'in ' + out;
  }
  function timeEl(iso){ return el('time', { datetime: iso || '', title: iso || '', text: rel(iso) }); }
  function msg(text, kind){ var m = $('[data-ww-msg]'); m.textContent = text || ''; m.className = 'ww-msg' + (kind ? ' is-' + kind : ''); }
  function clear(node){ node.textContent = ''; return node; }

  function request(url, opts){
    return fetch(url, Object.assign({ credentials: 'same-origin', headers: { 'Accept': 'application/json' } }, opts || {}))
      .then(function(r){
        var ct = r.headers.get('Content-Type') || '';
        if(ct.indexOf('application/json') < 0){
          var e = new Error(r.status === 400 ? 'The form token is stale - reload the page and try again.'
            : r.status === 403 ? 'Only a platform owner can use the web watch.'
            : 'Your console session has ended - reload the page to sign in again.');
          e.fatal = true; throw e;
        }
        return r.json().then(function(j){ if(!j.ok){ var e = new Error(j.error || ('HTTP ' + r.status)); e.status = r.status; throw e; } return j; });
      });
  }

  /* ---------- rendering ---------- */
  function verdict(web){
    var box = clear($('[data-ww-verdict]'));
    var w = web || { state: 'unknown' };
    if(w.state === 'up') box.appendChild(pill('p-good', 'up · served by ' + w.servedBy.join(', ')));
    else if(w.state === 'down') box.appendChild(pill('p-crit', 'DOWN'));
    else box.appendChild(pill('p-mut', 'unknown'));
    box.title = w.why || '';
  }

  function nodeCard(label, v, helper){
    var ws = (v && v.web && v.web.state) || 'unknown', wp = WEB[ws] || WEB.unknown;
    var card = el('article', { cls: 'ww-node is-' + ws });
    card.appendChild(el('header', null, [el('b', { text: label }), el('span', { cls: 'host mono', text: (v && v.host) || '' }), pill(wp[0], wp[1])]));
    var dl = el('dl');
    function row(k, val){ dl.appendChild(el('dt', { text: k })); var dd = el('dd'); if(typeof val === 'string') dd.textContent = val; else if(val) dd.appendChild(val); dl.appendChild(dd); }
    if(v && v.sampleAt) row('Read', el('span', null, [timeEl(v.sampleAt), v.fresh ? '' : ' — too old to trust']));
    else row('Read', 'never — the monitor has no sample for this node');
    if(v && v.web){
      if(v.web.probeError) row('Check error', el('span', { cls: 'mono', text: v.web.probeError }));
      else if(v.web.httpStatus) row('NLB check', el('span', { cls: 'mono', text: 'HTTP ' + v.web.httpStatus }));
    }
    if(v && v.collector && v.collector !== 'ok') row('Collector', v.collector);
    var h = helper || { state: 'unknown' };
    var hv = HELPER[h.state] || h.state;
    if(h.state === 'installed' && h.readiness){
      var r = h.readiness;
      row('Readiness', el('span', null, [r.ready === true ? 'ready' : r.ready === false ? 'not ready' : 'unknown', r.reason ? el('span', { cls: 'mono ww-why', text: ' · ' + r.reason }) : null]));
    }
    row('Clear helper', el('span', { title: h.detail || '' }, [hv + (h.version ? ' (' + h.version + ')' : ''), h.checkedAt ? el('span', { cls: 'ww-dim' }, [' · checked ', timeEl(h.checkedAt)]) : null]));
    card.appendChild(dl);
    return card;
  }

  function fenceRow(name, f, me, running){
    var fp = FENCE[f.state] || FENCE.unknown;
    var row = el('div', { cls: 'ww-fence is-' + f.state });
    var main = el('div', { cls: 'ww-fence-main' }, [
      el('b', { cls: 'mono', text: name }), pill(fp[0], fp[1]),
      el('small', { text: 'fences ' + f.target + ' · normally runs on ' + f.runsOn +
        (f.nodes && f.nodes.length ? ' · running on ' + f.nodes.join(', ') : f.state === 'unknown' ? '' : ' · not running') +
        (f.source ? ' · as ' + f.source + ' sees it' : '') })]);
    if(f.failCounts && f.failCounts.length){
      var fc = el('small', { cls: 'mono ww-fc' });
      fc.textContent = f.failCounts.map(function(c){ return c.name + '=' + c.value + ' on ' + c.node; }).join('  ');
      main.appendChild(fc);
    }
    row.appendChild(main);
    var why = null;
    if(running) why = 'A clear of ' + running.resource + ' is running.';
    else if(!me.allowed) why = me.actor + ' is not on the list in Settings > Prod web watch.';
    else if(f.state === 'unknown') why = 'The monitor has no fresh Pacemaker reading.';
    else if(!f.needsClear) why = 'Nothing to clear: started with no failure recorded.';
    else if(!f.clearVia) why = 'Unavailable: the clear helper is not installed on A or B yet.';
    var b = el('button', { cls: 'btn' + (f.needsClear ? ' pri' : ''), type: 'button', 'data-ww-clear': name, text: 'Clear failure…' });
    b.disabled = !!why;
    if(why) b.title = why;
    row.appendChild(el('div', { cls: 'ww-fence-act' }, [b, why && f.needsClear ? el('small', { cls: 'ww-why-off', text: why }) : null]));
    if(f.needsClear && !f.clearVia){
      row.appendChild(el('p', { cls: 'ww-manual' }, ['Until the helper is on A/B, the fix is by hand on ' + f.runsOn + ': ',
        el('code', { text: 'sudo crm_resource --cleanup --resource ' + name })]));
    }
    return row;
  }

  function renderRunning(run){
    var box = $('[data-ww-running]');
    if(!run){ box.hidden = true; return; }
    box.hidden = false; clear(box);
    box.appendChild(el('p', null, [pill('p-warn', 'clearing'), ' ', el('b', { cls: 'mono', text: run.resource }),
      ' for ' + run.actor + ', started ', timeEl(run.at), '. Pacemaker gets up to 40 s to start it again; this updates by itself.']));
  }

  function mailCell(m){
    if(!m) return el('span', { cls: 'ww-dim', text: 'no mail record yet', title: 'The mailer has not recorded this one: queued, held by the 20/h cap, or not sent' });
    if(m.result === 'sent') return el('span', null, [pill('p-good', 'sent'), ' ', timeEl(m.at)]);
    return el('span', null, [pill('p-warn', m.result || '?'), ' ', timeEl(m.at)]);
  }

  function renderAlerts(a, policy){
    var meta = clear($('[data-ww-alerts-meta]'));
    meta.appendChild(document.createTextNode('evaluated ')); meta.appendChild(timeEl(a.evaluatedAt));
    meta.appendChild(document.createTextNode(' · last mail ')); meta.appendChild(a.lastMailAt ? timeEl(a.lastMailAt) : document.createTextNode(a.ledgerReadable ? 'none in the last hour' : 'ledger unreadable'));
    var act = clear($('[data-ww-active]'));
    if(!a.active || !a.active.length) act.appendChild(el('p', { cls: 'ww-none', text: 'No HA alert is open.' }));
    else {
      var ul = el('ul', { cls: 'ww-active' });
      a.active.forEach(function(x){
        var sev = x.severity === 'critical' ? 'p-crit' : x.severity === 'warning' ? 'p-warn' : 'p-mut';
        var li = el('li', null, [pill(sev, x.severity || '?'), ' ', el('b', { text: x.title || x.ruleId }),
          el('small', null, [' opened ', timeEl(x.openedAt),
            x.reminders ? ' · ' + x.reminders + ' reminder' + (x.reminders === 1 ? '' : 's') : '',
            x.lastNoticeAt ? ' · last mailed ' : '', x.lastNoticeAt ? timeEl(x.lastNoticeAt) : null])]);
        ul.appendChild(li);
      });
      act.appendChild(ul);
    }
    var rp = $('[data-ww-repeat]'), want = policy && policy.repeatCriticalMinutes, have = a.repeatCriticalMinutes;
    if(have == null) rp.textContent = 'The alert evaluator (rules ' + (a.rulesVersion || '?') + ') mails each alert once. Reminders for open critical alerts start with rules 1.7.0.';
    else if(have === 0) rp.textContent = 'Reminders are off: each alert is mailed once (Settings > Prod web watch).';
    else rp.textContent = 'An open critical alert is mailed again every ' + have + ' min until it resolves' +
      (a.repeatSource === 'policy' ? ' (Settings > Prod web watch).' : ' (default; ' + (a.repeatSource || 'no setting read') + ').');
    if(have != null && want != null && want !== have) rp.textContent += ' The setting says ' + want + ' min; the evaluator picks it up within a minute.';
    var tb = clear($('[data-ww-recent]'));
    if(!a.recent || !a.recent.length){ tb.appendChild(el('tr', null, [el('td', { colspan: '4', cls: 'hint', text: 'No recent alert events.' })])); return; }
    a.recent.forEach(function(r){
      tb.appendChild(el('tr', null, [el('td', { cls: 'mono' }, [timeEl(r.createdAt)]), el('td', { text: KIND[r.kind] || r.kind }),
        el('td', { text: r.title || r.ruleId }), el('td', null, [mailCell(r.mail)])]));
    });
  }

  function clearResult(c){
    if(c.state === 'running') return pill('p-warn', 'running');
    if(c.ok && c.result && c.result.settled) return pill('p-good', 'cleared · started');
    if(c.ok) return pill('p-warn', 'cleared · not started yet');
    return el('span', { title: c.detail || '' }, [pill(c.sent ? 'p-crit' : 'p-mut', c.sent ? 'refused / failed' : 'not sent'), ' ', el('span', { cls: 'ww-dim', text: c.error || '' })]);
  }

  function renderClears(rows){
    var tb = clear($('[data-ww-clears]'));
    if(!rows || !rows.length){ tb.appendChild(el('tr', null, [el('td', { colspan: '5', cls: 'hint', text: 'Nothing has been cleared from here.' })])); return; }
    rows.forEach(function(c){
      tb.appendChild(el('tr', null, [el('td', { cls: 'mono' }, [timeEl(c.at)]),
        el('td', { cls: 'mono', text: c.resource + (c.node ? ' via ' + c.node : '') }), el('td', { text: c.actor || '' }),
        el('td', null, [clearResult(c)]), el('td', { text: c.reason || '' })]));
    });
  }

  function render(){
    var d = state.data, me = state.me, nodes = d.nodes || {}, helpers = d.helpers || {};
    verdict(d.web);
    var read = clear($('[data-ww-read]'));
    read.appendChild(document.createTextNode(d.web && d.web.why ? d.web.why : ''));
    var wrap = clear($('[data-ww-nodes]'));
    ['A', 'B'].forEach(function(l){ wrap.appendChild(nodeCard(l, nodes[l], helpers[l])); });
    var fences = clear($('[data-ww-fences]'));
    ['fence-A', 'fence-B'].forEach(function(n){ if(d.fences && d.fences[n]) fences.appendChild(fenceRow(n, d.fences[n], me, d.running)); });
    renderRunning(d.running);
    renderAlerts(d.alerts || {}, d.policy);
    renderClears(d.clears);
    $('[data-ww-who]').textContent = 'Signed in as ' + me.actor + (me.allowed ? ' — may clear a fence failure.' : ' — NOT on the list in Settings > Prod web watch, so Clear stays off.');

    if(state.started && !d.running){
      var done = (d.clears || []).filter(function(c){ return c.id === state.started; })[0];
      if(done){
        msg(done.ok && done.result && done.result.settled ? done.resource + ' cleared and started again via ' + done.node + '.'
          : done.ok ? done.resource + ' cleared via ' + done.node + ', but Pacemaker had not started it within 40 s. Watch the row above.'
          : 'The clear of ' + done.resource + ' did not run: ' + (done.error || 'refused') + (done.detail ? ' (' + done.detail + ')' : '') + '.',
          done.ok && done.result && done.result.settled ? 'ok' : 'err');
        state.started = null;
      }
    }

    if(badge){
      var down = d.web && d.web.state === 'down';
      var fence = ['fence-A', 'fence-B'].some(function(n){ return d.fences && d.fences[n] && d.fences[n].needsClear; });
      var open = ((d.alerts || {}).active || []).length;
      badge.hidden = !(down || fence || open || d.running);
      badge.className = 'pill ' + (down ? 'p-crit' : fence || open || d.running ? 'p-warn' : 'p-mut');
      badge.textContent = down ? 'down' : d.running ? 'clearing' : fence ? 'fence' : open + ' open';
    }
  }

  /* ---------- loading & polling ---------- */
  function visible(){ return tabPanel && !tabPanel.hidden && !document.hidden; }
  function schedule(){
    clearTimeout(state.timer);
    if(document.hidden) return;
    var ms = !visible() ? 300000 : (state.data && state.data.running) || state.started ? 3000 : 15000;
    state.timer = setTimeout(load, ms);
  }
  function load(){
    if(state.inflight) return;
    state.inflight = true;
    request('/system/webwatch/status').then(function(j){
      state.data = j.data; state.me = j.me; state.lastOk = Date.now();
      render();
      var m = $('[data-ww-msg]'); if(m.dataset.transport){ msg(''); delete m.dataset.transport; }
    }).catch(function(e){
      if(e.fatal){ msg(e.message, 'err'); state.inflight = false; return; }
      msg('Could not read the web watch service: ' + e.message + '. Retrying.', 'err');
      $('[data-ww-msg]').dataset.transport = '1';
      verdict({ state: 'unknown', why: 'the web watch service did not answer' });
    }).then(function(){ state.inflight = false; schedule(); });
  }

  /* ---------- clearing ---------- */
  var dlg = $('[data-ww-dialog]'), form = $('[data-ww-form]');
  var reasonIn = $('[data-ww-reason]'), confirmIn = $('[data-ww-confirm]'), goBtn = $('[data-ww-go]');
  function phrase(){ return 'CLEAR ' + state.pending; }
  function validate(){ goBtn.disabled = !(reasonIn.value.trim().length >= 3 && confirmIn.value.trim() === phrase()); }
  function openDialog(name){
    var f = state.data.fences[name];
    state.pending = name;
    $('[data-ww-dlg-title]').textContent = 'Clear the ' + name + ' failure';
    var ol = clear($('[data-ww-dlg-plan]'));
    ['Runs crm_resource --cleanup --resource ' + name + ' on ' + f.clearVia + ', through the web watch helper. Nothing else.',
     'Pacemaker forgets the failure and starts ' + name + ' again on ' + f.runsOn + '. It does not move web, fence a node or touch DRBD.',
     'The helper refuses if ' + name + ' is already started with no failure, or if ' + f.clearVia + ' has lost quorum.',
     'If the cause is still there (for example AWS metadata not answering on ' + f.runsOn + '), the device fails again and this page shows it.'
    ].forEach(function(t){ ol.appendChild(el('li', { text: t })); });
    $('[data-ww-phrase]').textContent = phrase();
    reasonIn.value = ''; confirmIn.value = ''; $('[data-ww-dlg-err]').textContent = '';
    validate();
    if(dlg.showModal) dlg.showModal(); else dlg.setAttribute('open', '');
    reasonIn.focus();
  }
  function closeDialog(){ if(dlg.open){ if(dlg.close) dlg.close(); else dlg.removeAttribute('open'); } state.pending = null; }

  root.addEventListener('click', function(e){
    var b = e.target.closest('[data-ww-clear]');
    if(b && !b.disabled && state.data) openDialog(b.dataset.wwClear);
  });
  reasonIn.addEventListener('input', validate);
  confirmIn.addEventListener('input', validate);
  $('[data-ww-dlg-cancel]').addEventListener('click', closeDialog);
  form.addEventListener('submit', function(e){
    e.preventDefault();
    var name = state.pending; if(!name) return;
    goBtn.disabled = true;
    var fd = new FormData();
    fd.append('csrf', csrf); fd.append('resource', name); fd.append('reason', reasonIn.value.trim()); fd.append('confirm', confirmIn.value.trim());
    request('/system/webwatch/clear', { method: 'POST', body: fd }).then(function(j){
      closeDialog(); state.started = j.clear.id; msg('Clearing ' + name + '…', 'ok'); load();
    }).catch(function(err){ $('[data-ww-dlg-err]').textContent = err.message; validate(); });
  });

  window.addEventListener('console-route', function(){ if(visible()) load(); else schedule(); });
  document.addEventListener('visibilitychange', function(){ if(!document.hidden) load(); else clearTimeout(state.timer); });
  load();
})();
