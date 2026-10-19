/* System > Updates. Talks only to /system/updates/* (owner-gated); those talk to the root
   corpit-updates service. The page never decides what is safe - the service does, and
   says why when it refuses. Buttons here are disabled only for reasons the page can see. */
(function(){
  var root = document.querySelector('[data-updates-panel]');
  if(!root) return;
  var tabPanel = root.closest('[data-tabpanel]');
  var badge = document.querySelector('[data-updates-badge]');
  var $ = function(sel){ return root.querySelector(sel); };
  var csrf = root.dataset.csrf;
  var state = { data: null, me: null, timer: null, inflight: false, lastOk: 0, pendingAction: null };

  var ACTION_LABEL = { 'refresh': 'Check for updates', 'apply-itam': 'Install updates on itam',
    'reboot-itam': 'Reboot itam', 'apply-standby': 'Install updates on the standby',
    'switch-reboot': 'Kernel reboot with HA switch' };
  var PHRASE = { 'reboot-itam': 'REBOOT ITAM', 'switch-reboot': 'SWITCH REBOOT' };
  var STATE_PILL = { queued: ['p-mut', 'queued'], running: ['p-warn', 'running'], rebooting: ['p-warn', 'rebooting'],
    succeeded: ['p-good', 'done'], needs_attention: ['p-crit', 'needs attention'], failed: ['p-crit', 'failed'],
    cancelled: ['p-mut', 'stopped'] };

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
  function timeEl(iso){ var t = el('time', { datetime: iso || '', title: iso || '', text: rel(iso) }); return t; }
  function msg(text, kind){ var m = $('[data-upd-msg]'); m.textContent = text || ''; m.className = 'upd-msg' + (kind ? ' is-' + kind : ''); }

  function request(url, opts){
    return fetch(url, Object.assign({ credentials: 'same-origin', headers: { 'Accept': 'application/json' } }, opts || {}))
      .then(function(r){
        var ct = r.headers.get('Content-Type') || '';
        if(ct.indexOf('application/json') < 0){
          var e = new Error(r.status === 400 ? 'The form token is stale - reload the page and try again.'
            : r.status === 403 ? 'Only a platform owner can use server updates.'
            : 'Your console session has ended - reload the page to sign in again.');
          e.fatal = true; throw e;
        }
        return r.json().then(function(j){ if(!j.ok){ var e = new Error(j.error || ('HTTP ' + r.status)); e.status = r.status; throw e; } return j; });
      });
  }

  /* ---------- rendering ---------- */
  function nodeCard(label, v){
    var card = el('article', { cls: 'upd-node' });
    if(!v || !v.reachable){
      card.classList.add('is-down');
      card.appendChild(el('header', null, [el('b', { text: label }), pill('p-crit', 'unreachable')]));
      card.appendChild(el('p', { cls: 'hint', text: (v && v.error) || 'No reading from this server yet.' }));
      return card;
    }
    var role = v.role === 'owner' ? 'serving web' : v.role === 'standby' ? 'standby' : v.role === 'itam' ? 'dev / tooling' : (v.role || 'role unknown');
    var needs = (v.pendingCount || 0) > 0 || v.rebootRequired;
    var head = el('header', null, [el('b', { text: label }), el('span', { cls: 'role', text: role }),
      v.overdue ? pill('p-warn', 'overdue') : needs ? pill('p-mut', v.rebootRequired && !v.pendingCount ? 'reboot pending' : 'updates pending') : pill('p-good', 'current')]);
    card.appendChild(head);
    if(v.overdue) card.classList.add('is-overdue');
    var dl = el('dl');
    function row(k, val){ dl.appendChild(el('dt', { text: k })); var dd = el('dd'); if(typeof val === 'string') dd.textContent = val; else if(val) dd.appendChild(val); dl.appendChild(dd); }
    var pc = v.pendingCount == null ? 'unknown' : String(v.pendingCount);
    if(v.securityCount) pc += ' (' + v.securityCount + ' security)';
    row('Packages', pc + ' pending');
    if(v.clusterStackPending && v.clusterStackPending.length) row('Held for reboot', v.clusterStackPending.length + ' cluster stack');
    if(v.keptBack && v.keptBack.length) row('Kept back', String(v.keptBack.length));
    var inst = Array.isArray(v.kernelInstalled) ? v.kernelInstalled.slice().sort(function(a, b){ return a.localeCompare(b, undefined, { numeric: true }); }).pop() : v.kernelInstalled;
    var k = el('span', null, [el('span', { cls: 'mono', text: v.kernelRunning || '?' })]);
    if(inst && inst !== v.kernelRunning) k.appendChild(el('span', { cls: 'upd-next' }, [' → ', el('span', { cls: 'mono', text: inst }), ' after reboot']));
    row('Kernel', k);
    if(v.rebootRequired){ var rr = el('span', null, ['needed since ', timeEl(v.rebootRequiredSince)]); row('Reboot', rr); }
    else row('Reboot', 'not needed');
    if(v.pendingSince) row('Pending since', timeEl(v.pendingSince));
    if(v.role === 'owner' || v.role === 'standby'){
      var web = v.web || {};
      var wtxt = web.ready === true ? 'yes' : web.ready === false ? (v.role === 'standby' ? 'no — standby, as expected' : 'NO (' + (web.httpStatus || web.error || '?') + ')') : 'unknown';
      row('Serving web', wtxt);
      var d = v.drbd || {};
      if(d.configured) row('DRBD', [d.role, d.disk, d.cs].filter(Boolean).join(' · ') || 'unknown');
      if(v.fenceConstraints && v.fenceConstraints.length) row('Fence constraint', pill('p-crit', String(v.fenceConstraints.length)));
    }
    row('Auto-upgrades', v.unattended === '1' ? 'ON (system timer)' : v.unattended === '0' ? 'off' : (v.unattended || 'unknown'));
    if(v.listsUpdatedAt) row('Lists read', timeEl(v.listsUpdatedAt));
    card.appendChild(dl);
    if(v.pending && v.pending.length){
      var ul = el('ul');
      v.pending.slice(0, 80).forEach(function(p){ ul.appendChild(el('li', { cls: 'mono', text: typeof p === 'string' ? p : [p.name, p.to || p.version].filter(Boolean).join(' ') })); });
      if(v.pending.length > 80) ul.appendChild(el('li', { text: '… and ' + (v.pending.length - 80) + ' more' }));
      card.appendChild(el('details', null, [el('summary', { text: 'Which packages' }), ul]));
    }
    return card;
  }

  function roles(nodes){
    var owner = null, standby = null;
    ['A', 'B'].forEach(function(l){ var v = nodes[l]; if(v && v.reachable){ if(v.role === 'owner') owner = l; else if(v.role === 'standby') standby = l; } });
    return { owner: owner, standby: standby };
  }

  function renderJob(job, me){
    var card = $('[data-upd-job]');
    if(!job){ card.hidden = true; return; }
    card.hidden = false;
    var sp = STATE_PILL[job.state] || ['p-mut', job.state];
    var title = $('[data-upd-job-title]'); title.textContent = '';
    title.appendChild(document.createTextNode((ACTION_LABEL[job.action] || job.action) + ' '));
    title.appendChild(pill(sp[0], sp[1]));
    var meta = $('[data-upd-job-meta]'); meta.textContent = '';
    meta.appendChild(document.createTextNode(job.jobId + ' · ' + job.actor + ' · '));
    meta.appendChild(timeEl(job.startedAt || job.createdAt));
    var active = job.state === 'queued' || job.state === 'running';
    var cancel = $('[data-upd-cancel]');
    cancel.hidden = !(active && me && me.allowed);
    cancel.disabled = !!job.cancelRequested;
    cancel.textContent = job.cancelRequested ? 'Stopping after this step…' : 'Stop after this step';
    cancel.dataset.job = job.jobId;
    var ol = $('[data-upd-steps]'); ol.textContent = '';
    (job.steps || []).forEach(function(s){
      var li = el('li', { cls: 'is-' + (s.state || 'pending') }, [el('b', { text: s.title || s.name }),
        el('span', { cls: 't', text: s.state === 'running' ? 'started ' + rel(s.startedAt) : s.endedAt ? rel(s.endedAt) : '' })]);
      if(s.detail) li.appendChild(el('span', { cls: 'd', text: s.detail }));
      var notes = s.notes || [];
      if(s.state === 'running' && notes.length) li.appendChild(el('span', { cls: 'n', text: notes[notes.length - 1] }));
      ol.appendChild(li);
    });
    if(job.state === 'queued' && !(job.steps || []).length) ol.appendChild(el('li', null, [el('b', { text: 'Waiting for the worker to start' })]));
    if(job.error) ol.appendChild(el('li', { cls: 'is-failed' }, [el('b', { cls: 'upd-err', text: job.error })]));
    if(job.reason) ol.appendChild(el('li', null, [el('span', { cls: 'd', text: 'Why: ' + job.reason })]));
  }

  function renderJobs(jobs){
    var tb = $('[data-upd-jobs]'); tb.textContent = '';
    if(!jobs || !jobs.length){ tb.appendChild(el('tr', null, [el('td', { colspan: '5', cls: 'hint', text: 'Nothing has been run from here yet.' })])); return; }
    jobs.forEach(function(j){
      var sp = STATE_PILL[j.state] || ['p-mut', j.state];
      var what = ACTION_LABEL[j.action] || j.action;
      if(j.action === 'switch-reboot') what += j.switchBack ? ' (switch back)' : ' (stay switched)';
      tb.appendChild(el('tr', null, [el('td', { cls: 'mono' }, [timeEl(j.startedAt || j.createdAt)]), el('td', { text: what }),
        el('td', { text: j.actor || '' }), el('td', null, [pill(sp[0], sp[1])]), el('td', { text: j.error ? j.reason + ' — ' + j.error : (j.reason || '') })]));
    });
  }

  function setBtn(action, ok, why){
    var b = root.querySelector('[data-upd-start="' + action + '"]');
    if(!b) return;
    b.disabled = !ok;
    if(why && !ok) b.title = why; else b.removeAttribute('title');
  }

  function render(){
    var d = state.data, me = state.me;
    var summary = d.summary || {}, nodes = summary.nodes || {};
    var checked = $('[data-upd-checked]'); checked.textContent = '';
    if(summary.generatedAt){ checked.appendChild(document.createTextNode('checked ')); checked.appendChild(timeEl(summary.generatedAt)); checked.appendChild(document.createTextNode(' · every ' + (d.policy && d.policy.checkHours) + ' h')); }
    else checked.textContent = 'not checked yet';
    var wrap = $('[data-upd-nodes]'); wrap.textContent = '';
    ['A', 'B', 'itam'].forEach(function(l){ wrap.appendChild(nodeCard(l, nodes[l])); });

    var r = roles(nodes);
    $('[data-upd-pair]').textContent = r.owner && r.standby ? r.owner + ' serving · ' + r.standby + ' standby' : 'roles unclear';
    var active = d.active;
    renderJob(active || (d.jobs && d.jobs[0]) || null, me);
    renderJobs(d.jobs);

    var busy = active ? 'Job ' + active.jobId + ' is ' + active.state + '. One run at a time.' : null;
    var notAllowed = me.allowed ? null : me.actor + ' is not on the list in Settings > Server updates.';
    var block = busy || notAllowed;
    var itam = nodes.itam || {}, pair = r.owner && r.standby;
    setBtn('refresh', !block, block);
    setBtn('apply-itam', !block && itam.reachable && itam.pendingCount > 0, block || (!itam.reachable ? 'itam was not read.' : 'Nothing pending on itam.'));
    setBtn('reboot-itam', !block && itam.reachable, block || 'itam was not read.');
    var sb = pair ? nodes[r.standby] : null;
    setBtn('apply-standby', !block && sb && sb.pendingCount > 0, block || (!pair ? 'A and B must both be read with one serving and one standby.' : 'Nothing pending on the standby ' + r.standby + '.'));
    var pairNeeds = pair && [nodes.A, nodes.B].some(function(v){ return v.rebootRequired || v.pendingCount > 0 || (v.clusterStackPending || []).length; });
    var switchWhy = block || (!me.canSwitch ? 'The planned HA switch accepts only ' + d.controllerActor + '.' : !pair ? 'A and B must both be read with one serving and one standby.' : 'Neither A nor B needs updates or a reboot.');
    setBtn('switch-reboot', !block && me.canSwitch && pair && pairNeeds, switchWhy);
    if(pair) $('[data-upd-switch-plan]').textContent = 'Install and reboot ' + r.standby + ', switch web to it, install and reboot ' + r.owner + ', then switch back to ' + r.owner + ' if chosen. Web is down about a minute at each switch.';

    var who = $('[data-upd-who]');
    who.textContent = 'Signed in as ' + me.actor + (me.allowed ? ' — on the updates list.' : ' — NOT on the updates list (Settings > Server updates), so the buttons stay off.') +
      ' Kernel reboot with switch: ' + d.controllerActor + ' only.';

    if(badge){
      var over = (summary.overdue || []).length, down = (summary.unreachable || []).length;
      var pend = ['A', 'B', 'itam'].filter(function(l){ var v = nodes[l]; return v && v.reachable && (v.pendingCount > 0 || v.rebootRequired); }).length;
      badge.hidden = !(over || down || pend || active);
      badge.className = 'pill ' + (down ? 'p-crit' : over ? 'p-warn' : active ? 'p-warn' : 'p-mut');
      badge.textContent = down ? down + ' unreachable' : active ? 'running' : over ? over + ' overdue' : pend + ' pending';
    }
  }

  /* ---------- loading & polling ---------- */
  function visible(){ return tabPanel && !tabPanel.hidden && !document.hidden; }
  function schedule(){
    clearTimeout(state.timer);
    if(document.hidden) return;
    var active = state.data && state.data.active;
    var ms = !visible() ? 300000 : active ? 4000 : 60000;
    if(Date.now() - state.lastOk > 20000 && state.lastOk) ms = Math.min(ms, 10000);
    state.timer = setTimeout(load, ms);
  }
  function load(){
    if(state.inflight) return;
    state.inflight = true;
    request('/system/updates/summary').then(function(j){
      state.data = j.data; state.me = j.me; state.lastOk = Date.now();
      render();
      var m = $('[data-upd-msg]'); if(m.classList.contains('is-err') && m.dataset.transport) { msg(''); delete m.dataset.transport; }
    }).catch(function(e){
      var m = $('[data-upd-msg]');
      if(e.fatal){ msg(e.message, 'err'); state.inflight = false; return; }
      var rebooting = state.data && state.data.active && state.data.active.action === 'reboot-itam';
      msg(rebooting ? 'itam is rebooting. This page reconnects by itself.' : 'Could not read the updates service: ' + e.message + '. Retrying.', 'err');
      m.dataset.transport = '1';
    }).then(function(){ state.inflight = false; schedule(); });
  }

  /* ---------- starting a run ---------- */
  var dlg = $('[data-upd-dialog]'), form = $('[data-upd-form]');
  var reasonIn = $('[data-upd-reason]'), confirmIn = $('[data-upd-confirm]'), goBtn = $('[data-upd-go]'), backIn = $('[data-upd-back]');
  function planFor(action){
    var nodes = (state.data.summary || {}).nodes || {}, r = roles(nodes);
    switch(action){
      case 'apply-itam': return ['apt upgrade on itam (' + ((nodes.itam || {}).pendingCount || 0) + ' packages). Services keep running.', 'A new kernel needs "Reboot itam" afterwards.'];
      case 'reboot-itam': return ['Refused if a release is publishing, rolling back, or an HA switch is running.', 'itam reboots 10 s after you start. The console, launch pad and dev sites are gone for 1-3 minutes.', 'Prod (A/B) is not touched.'];
      case 'apply-standby': return ['apt upgrade on ' + r.standby + ' only - it is not serving web.', 'pacemaker, corosync and DRBD are held back for the kernel reboot.'];
      case 'switch-reboot': return [
        'Check: ' + r.owner + ' serving, ' + r.standby + ' standby, DRBD in sync, no fence constraints, no release running.',
        'Install updates on ' + r.standby + ', stop its cluster stack gracefully, reboot it, wait for it to rejoin in sync.',
        'Planned switch: web moves to ' + r.standby + ' (about a minute of downtime).',
        'Install updates on ' + r.owner + ', reboot it, wait for it to rejoin as standby.',
        'If "switch back" is on: planned switch back to ' + r.owner + ' (another minute).',
        'Any check that fails stops the run where it is, with prod still served, and says why here.',
        'Expect HA alert mails during each reboot (peer unknown / monitor blind); they resolve when the node rejoins.'];
    }
    return [];
  }
  function validate(){
    var a = state.pendingAction, ok = reasonIn.value.trim().length >= 3;
    if(PHRASE[a]) ok = ok && confirmIn.value.trim() === PHRASE[a];
    goBtn.disabled = !ok;
  }
  function openDialog(action){
    state.pendingAction = action;
    var nodes = (state.data.summary || {}).nodes || {}, r = roles(nodes);
    $('[data-upd-dlg-title]').textContent = ACTION_LABEL[action];
    var ol = $('[data-upd-dlg-plan]'); ol.textContent = '';
    planFor(action).forEach(function(t){ ol.appendChild(el('li', { text: t })); });
    var sw = action === 'switch-reboot';
    $('[data-upd-back-row]').hidden = !sw;
    if(sw){ backIn.checked = !!(state.data.policy && state.data.policy.switchBackDefault); $('[data-upd-back-label]').textContent = 'Switch back to ' + r.owner + ' afterwards'; }
    $('[data-upd-confirm-row]').hidden = !PHRASE[action];
    $('[data-upd-phrase]').textContent = PHRASE[action] || '';
    reasonIn.value = ''; confirmIn.value = ''; $('[data-upd-dlg-err]').textContent = '';
    goBtn.textContent = action === 'switch-reboot' ? 'Start the reboot' : action === 'reboot-itam' ? 'Reboot itam' : 'Start';
    validate();
    if(dlg.showModal) dlg.showModal(); else dlg.setAttribute('open', '');
    reasonIn.focus();
  }
  function closeDialog(){ if(dlg.open){ if(dlg.close) dlg.close(); else dlg.removeAttribute('open'); } state.pendingAction = null; }
  function start(action, reason, extra){
    var fd = new FormData();
    fd.append('csrf', csrf); fd.append('action', action); fd.append('reason', reason);
    Object.keys(extra || {}).forEach(function(k){ fd.append(k, extra[k]); });
    return request('/system/updates/start', { method: 'POST', body: fd });
  }

  root.addEventListener('click', function(e){
    var b = e.target.closest('[data-upd-start]');
    if(b && !b.disabled && state.data){
      var action = b.dataset.updStart;
      if(action === 'refresh'){
        b.disabled = true; msg('Updating package lists on A, B and itam…');
        start('refresh', 'Check for updates from System > Updates').then(function(j){ msg('Checking - ' + j.job.jobId + '.', 'ok'); load(); })
          .catch(function(err){ msg(err.message, 'err'); b.disabled = false; });
        return;
      }
      openDialog(action);
      return;
    }
    var c = e.target.closest('[data-upd-cancel]');
    if(c && !c.disabled){
      if(!window.confirm('Stop this run after the step that is running now? The current step finishes first - a node mid-reboot is never left half-done.')) return;
      c.disabled = true;
      var fd = new FormData(); fd.append('csrf', csrf); fd.append('job_id', c.dataset.job);
      request('/system/updates/cancel', { method: 'POST', body: fd }).then(function(){ msg('Stop requested; the run ends after the current step.', 'ok'); load(); })
        .catch(function(err){ msg(err.message, 'err'); c.disabled = false; });
    }
  });
  reasonIn.addEventListener('input', validate);
  confirmIn.addEventListener('input', validate);
  $('[data-upd-dlg-cancel]').addEventListener('click', closeDialog);
  form.addEventListener('submit', function(e){
    e.preventDefault();
    var action = state.pendingAction; if(!action) return;
    goBtn.disabled = true;
    var extra = {};
    if(PHRASE[action]) extra.confirm = confirmIn.value.trim();
    if(action === 'switch-reboot') extra.switch_back = backIn.checked ? '1' : '0';
    start(action, reasonIn.value.trim(), extra).then(function(j){
      closeDialog(); msg('Started ' + j.job.jobId + '.', 'ok'); load();
    }).catch(function(err){ $('[data-upd-dlg-err]').textContent = err.message; validate(); });
  });

  window.addEventListener('console-route', function(){ if(visible()) load(); else schedule(); });
  document.addEventListener('visibilitychange', function(){ if(!document.hidden) load(); else clearTimeout(state.timer); });
  load();
})();
