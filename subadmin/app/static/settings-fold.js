/* Settings > editors folded in from their own sites (2026-10-12, CORPIT-SETTINGS-FOLD).

   This file only draws and submits. Every read and write goes to the API that owns the setting,
   on this origin, through nginx locations that allow exact paths and methods only:
     Certificates       Hub :3000  /api/cert-config, /api/prtg/config       (cert-watchtower read / admin)
     Sign-In Watch      Hub :3001  /api/signin-watch/{watchlist,networks,channels}   (Hub super admin)
     Identity digest    Hub :3001  /api/user-project/settings                (user-projects read / admin)
     Zscaler AI report  Hub :3001  /api/zscaler/zia/ai/{report-config,watchlist}     (zscaler-diag read / admin)
     Launch pad         itam only  /__dev/api/cab/settings  -> devrel :8480 (Hub super admin)
     Backup & HA        itam only  /bkp-api/settings, /bkp-api/ha/settings -> bkp-console :8470
     Darktrace email    Hub :3001  /api/sentinel/darktrace-email/config{,/test}  (Hub super admin; DARKTRACE-EMAIL 2026-10-14)
     AI Governance sync Hub :3001  /api/zscaler/governance/portal-sync/config{,/run}  (Hub super admin; AI-GOVERNANCE PORTAL SYNC 2026-10-15)
     Onboarding mail    Hub :3001  /api/workflow/settings/config              (Hub super admin; ONBOARDING WORKFLOW 2026-10-21)
   The owning API decides who may read and who may save. A tab button appears after a successful read or a temporary availability failure. Denied
   and absent editors stay hidden; unavailable editors show the owning error with Reload. A host without the
   API (prod has no launch pad or backup proxy) never shows it. A refused save is shown as refused. */
(function(){
  'use strict';
  var view = document.querySelector('[data-view="settings"]');
  if(!view) return;
  var tablist = view.querySelector('[data-tabs="settings"]');
  var ORDER = ['certs', 'signin', 'digest', 'zscaler-ai', 'launchpad', 'backup', 'darktrace-email', 'aigov-portal', 'onboarding-mail'];
  var CONSOLE_HDR = { 'X-Subadmin-Console': '1' };
  var DEV = /^dev-/.test(location.hostname);
  var WARN_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg>';
  var INFO_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/></svg>';

  var esc = function(s){ return String(s == null ? '' : s).replace(/[&<>"']/g, function(c){
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var has = function(o, k){ return o != null && Object.prototype.hasOwnProperty.call(o, k); };
  var each = function(list, fn){ Array.prototype.forEach.call(list, fn); };
  var filter = function(list, fn){ return Array.prototype.filter.call(list, fn); };
  function hubUrl(path){ return 'https://' + (DEV ? 'dev-corpit' : 'corpit') + '.nrpi.local' + path; }
  function when(v){
    if(!v) return '';
    var d = new Date(v);
    return isNaN(d) ? String(v) : d.toISOString().replace('T', ' ').slice(0, 16) + 'Z';
  }
  function truthy(v){ return v === true || v === 1 || v === '1' || v === 'true'; }

  /* ---------- plumbing ---------- */
  function errText(j, status){
    if(!j) return 'HTTP ' + status;
    var e = j.error;
    if(e && typeof e === 'object') e = e.message || e.code;
    return e || j.message || j.code || ('HTTP ' + status);
  }
  function api(method, url, body, extra){
    var headers = { 'Accept': 'application/json' };
    if(body !== undefined) headers['Content-Type'] = 'application/json';
    if(extra) Object.keys(extra).forEach(function(k){ headers[k] = extra[k]; });
    return fetch(url, {
      method: method, credentials: 'same-origin', cache: 'no-store', headers: headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    }).then(function(r){
      var ct = r.headers.get('Content-Type') || '';
      if(ct.indexOf('application/json') < 0){
        var e;
        if(r.status === 404 || r.status === 405 || r.status >= 500){
          e = new Error('This server has no such editor, or it did not answer (HTTP ' + r.status + ').');
          e.absent = true;
        } else {
          // The gate answers an expired session with its HTML sign-in page, not JSON.
          e = new Error(r.status === 403 ? 'The sign-in gate refused this request.'
            : 'Your console session has ended. Reload the page to sign in again.');
          e.fatal = true;
        }
        e.status = r.status; throw e;
      }
      return r.json().then(function(j){
        if(!r.ok || (j && j.ok === false)){
          var e = new Error(errText(j, r.status));
          e.status = r.status; e.body = j;
          if(r.status === 401 || r.status === 403) e.denied = true;
          throw e;
        }
        return j;
      });
    });
  }

  /* ---------- fields ----------
     Every editable control carries data-k (its key), data-t (how its value is sent) and data-o
     (the value it was drawn with). An editor is any element with data-sf-ed; it is dirty when
     one of its controls no longer matches data-o. */
  var uid = 0;
  function cur(el){ return el.type === 'checkbox' ? String(el.checked) : el.value; }
  function typed(el){
    var t = el.dataset.t || 'str', v = el.value;
    if(el.type === 'checkbox'){
      if(t === 'b01') return el.checked ? '1' : '0';
      if(t === 'i01') return el.checked ? 1 : 0;
      if(t === 'bstr') return el.checked ? 'true' : 'false';
      return el.checked;
    }
    if(t === 'int') return v.trim() === '' ? '' : Number(v);
    if(t === 'lines') return v.split('\n').map(function(x){ return x.trim(); }).filter(Boolean);
    if(t === 'trim') return v.trim();
    return v;
  }
  function attrs(o){
    var a = ' data-k="' + esc(o.k) + '"' + (o.t ? ' data-t="' + esc(o.t) + '"' : '');
    if(o.min !== undefined) a += ' min="' + esc(o.min) + '"';
    if(o.max !== undefined) a += ' max="' + esc(o.max) + '"';
    if(o.ml) a += ' maxlength="' + esc(o.ml) + '"';
    if(o.ph) a += ' placeholder="' + esc(o.ph) + '"';
    if(o.req) a += ' required';
    if(o.dis) a += ' disabled';
    if(o.aria) a += ' aria-label="' + esc(o.aria) + '"';
    return a;
  }
  function control(o, id){
    var v = o.v == null ? '' : o.v, idA = id ? ' id="' + id + '"' : '';
    if(o.kind === 'check'){
      return '<input type="checkbox"' + idA + attrs(o) + ' data-o="' + (o.v ? 'true' : 'false') + '"' + (o.v ? ' checked' : '') + '>';
    }
    if(o.kind === 'select'){
      var opts = o.opts.slice();
      if(String(v) !== '' && !opts.some(function(p){ return String(p[0]) === String(v); })) opts.push([v, String(v)]);
      return '<select' + idA + attrs(o) + ' data-o="' + esc(v) + '">' + opts.map(function(p){
        return '<option value="' + esc(p[0]) + '"' + (String(p[0]) === String(v) ? ' selected' : '') + '>' + esc(p[1]) + '</option>'; }).join('') + '</select>';
    }
    if(o.kind === 'area'){
      return '<textarea' + idA + attrs(o) + ' rows="' + (o.rows || 3) + '" data-o="' + esc(v) + '">' + esc(v) + '</textarea>';
    }
    var type = { num: 'number', email: 'email', time: 'time', pw: 'password' }[o.kind] || 'text';
    return '<input type="' + type + '"' + idA + attrs(o) + (type === 'number' ? ' step="1"' : '') +
           (type === 'password' ? ' autocomplete="new-password"' : ' autocomplete="off"') +
           ' value="' + esc(v) + '" data-o="' + esc(v) + '">';
  }
  function field(o){
    var id = 'sf-f' + (++uid), hint = o.h ? '<span class="hint">' + o.h + '</span>' : '';
    if(o.kind === 'check'){
      return '<div class="f sf-f"><label class="f-inline" for="' + id + '">' + control(o, id) + '<span>' + esc(o.l) + '</span></label>' + hint + '</div>';
    }
    return '<div class="f sf-f' + (o.wide ? ' sf-wide' : '') + '"' + (o.wrap ? ' ' + o.wrap : '') + '><label for="' + id + '">' + esc(o.l) + '</label>' + control(o, id) + hint + '</div>';
  }
  function changed(ed){
    return filter(ed.querySelectorAll('[data-k]'), function(el){ return !el.disabled && cur(el) !== el.dataset.o; });
  }
  function invalid(ed){
    var bad = filter(ed.querySelectorAll('input,select,textarea'), function(el){ return !el.disabled && el.checkValidity && !el.checkValidity(); })[0];
    if(!bad) return null;
    var lab = bad.id && ed.querySelector('label[for="' + bad.id + '"]');
    return (lab ? lab.textContent.trim() : (bad.getAttribute('aria-label') || bad.dataset.k)) + ': ' + bad.validationMessage;
  }
  function foot(name, saveLabel, extra){
    return '<div class="sf-foot"><button type="button" class="btn pri" data-sf-save="' + esc(name) + '" disabled>' + esc(saveLabel || 'Save changes') + '</button>' +
           '<button type="button" class="btn" data-sf-discard="' + esc(name) + '" disabled>Discard</button>' +
           '<span class="hint" data-sf-state>No unsaved changes</span>' + (extra || '') + '</div>';
  }
  function rowActions(name, del){
    return '<td class="sf-act"><button type="button" class="btn sm pri" data-sf-save="' + esc(name) + '" disabled>Save</button>' +
           (del ? '<button type="button" class="btn sm danger" data-sf-delete="' + esc(name) + '">Delete</button>' : '') + '</td>';
  }
  function edDirty(ed){
    var fn = ed.dataset.sfEd && DIRTY[ed.dataset.sfEd.split(':')[0]];
    return fn ? fn(ed) : changed(ed).length > 0;
  }
  function refreshEd(ed){
    var dirty = edDirty(ed), busy = ed.classList.contains('is-busy');
    var ro = ed.hasAttribute('data-sf-readonly');
    each(ed.querySelectorAll('[data-sf-save]'), function(b){ if(b.closest('[data-sf-ed]') === ed) b.disabled = ro || busy || !dirty; });
    each(ed.querySelectorAll('[data-sf-discard]'), function(b){ if(b.closest('[data-sf-ed]') === ed) b.disabled = busy || !dirty; });
    each(ed.querySelectorAll('[data-sf-state]'), function(s){
      if(s.closest('[data-sf-ed]') === ed) s.textContent = busy ? 'Saving…' : dirty ? 'Unsaved changes' : 'No unsaved changes'; });
    ed.classList.toggle('is-dirty', dirty);
  }
  function resetEd(ed){
    each(ed.querySelectorAll('[data-k]'), function(el){
      if(el.type === 'checkbox') el.checked = el.dataset.o === 'true'; else el.value = el.dataset.o;
    });
    var fn = RESET[ed.dataset.sfEd.split(':')[0]];
    if(fn) fn(ed);
    refreshEd(ed);
  }
  function anyDirty(box){
    return filter((box || view).querySelectorAll('[data-sf-ed]'), function(ed){ return ed.classList.contains('is-busy') || edDirty(ed); }).length > 0;
  }
  function busy(ed, on){
    ed.classList.toggle('is-busy', !!on); ed.setAttribute('aria-busy', String(!!on));
    each(ed.querySelectorAll('input,select,textarea,button'), function(el){
      if(on){el.dataset.sfWasDisabled = String(el.disabled);el.disabled=true;}
      else if(has(el.dataset,'sfWasDisabled')){el.disabled=el.dataset.sfWasDisabled==='true';delete el.dataset.sfWasDisabled;}
    });refreshEd(ed);
  }

  /* ---------- panel state ---------- */
  var ST = {};
  ORDER.forEach(function(t){ ST[t] = { probe: null, built: false, loading: false, loaded: false, data: null }; });
  function box(tab){ return view.querySelector('[data-sf="' + tab + '"]'); }
  function q(tab, sel){ return box(tab).querySelector(sel); }
  var msgT = {};
  function msg(tab, html, kind){
    var m = q(tab, '[data-sf-msg]');
    if(!m) return;
    m.innerHTML = html || '';
    m.className = 'sf-msg' + (kind ? ' is-' + kind : '');
    clearTimeout(msgT[tab]);
    if(html && kind === 'ok') msgT[tab] = setTimeout(function(){ m.innerHTML = ''; m.className = 'sf-msg'; }, 6000);
  }
  function saveErr(tab, e){
    var d = DEF[tab];
    if(e && e.denied) return '<b>You don’t have permission to change this.</b> ' + d.guard + ' It said: ' + esc(e.message);
    return '<b>Not saved.</b> ' + esc(e ? e.message : 'unknown error');
  }
  function blockedHtml(tab, e){
    var d = DEF[tab], back = ' <a href="#settings/directory">Back to the settings directory</a>.';
    if(e && e.denied) return '<b>You don’t have permission to open this.</b>' + d.guard + ' It said: ' + esc(e.message) + back;
    if(e && e.absent) return '<b>Not available here.</b>' + esc(e.message) + back;
    return '<b>Could not load ' + esc(d.what) + '.</b>' + esc(e ? e.message : 'unknown error') + back;
  }
  function scaffold(tab){
    var d = DEF[tab], links = (d.links || []).map(function(l){
      return '<a class="btn sm" href="' + esc(l[0]) + '" target="_blank" rel="noopener">' + esc(l[1]) + '</a>'; }).join('');
    box(tab).innerHTML =
      '<div class="sf-lede"><p>' + d.lede + '</p><div class="sf-lede-a">' + links +
      '<button type="button" class="btn sm" data-sf-reload disabled>Reload</button></div></div>' +
      '<p class="sf-msg" data-sf-msg role="status" aria-live="polite"></p>' +
      '<div class="sf-skel" aria-hidden="true"><i></i><i></i><i></i><i></i><i></i></div>' +
      '<div class="note crit sf-blocked" data-sf-blocked hidden></div>' +
      '<div class="sf-body" data-sf-body hidden></div>';
    ST[tab].built = true;
  }
  function load(tab){
    var s = ST[tab], b = box(tab);
    s.loading = true;
    b.classList.add('is-loading');
    q(tab, '[data-sf-reload]').disabled = true;
    return DEF[tab].load().then(function(data){
      s.data = data; s.loaded = true;
      draw(tab);
      q(tab, '[data-sf-blocked]').hidden = true;
      q(tab, '[data-sf-body]').hidden = false;
    }).catch(function(e){
      var bl = q(tab, '[data-sf-blocked]');
      bl.innerHTML = WARN_SVG + '<div>' + blockedHtml(tab, e) + '</div>';
      bl.hidden = false;
      q(tab, '[data-sf-body]').hidden = true;
    }).then(function(){
      s.loading = false;
      b.classList.remove('is-loading');
      q(tab, '[data-sf-reload]').disabled = false;
    });
  }
  function draw(tab, preserve){
    var body = q(tab, '[data-sf-body]');
    // Keep live sibling editor nodes, including custom recipient rows, row drafts and secret inputs.
    // Only the submitted editor is replaced by the owner's readback. Never serialize secrets into storage.
    var drafts = preserve ? filter(body.querySelectorAll('[data-sf-ed]'), function(ed){return !ed.classList.contains('is-busy') && edDirty(ed);}) : [];
    var focused=document.activeElement, focusedEd=focused&&focused.closest('[data-sf-ed]');
    drafts.forEach(function(ed){ed.remove();});
    body.innerHTML = DEF[tab].render(ST[tab].data);
    each(body.querySelectorAll('[data-sf-ed]'), refreshEd);
    if(DEF[tab].after) DEF[tab].after(body, ST[tab].data);
    drafts.forEach(function(ed){var fresh=filter(body.querySelectorAll('[data-sf-ed]'),function(n){return n.dataset.sfEd===ed.dataset.sfEd;})[0];if(fresh){fresh.replaceWith(ed);refreshEd(ed);}else{body.append(ed);refreshEd(ed);}});
    if(focusedEd&&drafts.indexOf(focusedEd)>=0&&document.contains(focused))focused.focus({preventScroll:true});
  }
  function openTab(tab){
    if(!ST[tab].built) scaffold(tab);
    if(!ST[tab].loaded && !ST[tab].loading) load(tab);
  }
  // After a save, re-read from the owner so the panel shows what is stored, not what was typed.
  function reread(tab){ return DEF[tab].load().then(function(data){ ST[tab].data = data; draw(tab, true); return data; }); }

  /* ---------- Certificates (Hub cert-watchtower) ---------- */
  var CERT_FIELDS = [
    { k: 'threshold_info_days', l: 'Info threshold (days)', min: 1, max: 365, h: 'Below this, an Info alert fires.' },
    { k: 'threshold_warning_days', l: 'Warning threshold (days)', min: 1, max: 365, h: 'Below this, a Warning alert fires.' },
    { k: 'threshold_critical_days', l: 'Critical threshold (days)', min: 1, max: 365, h: 'Below this, a Critical alert fires.' },
    { k: 'unreachable_alert_days', l: 'Unreachable grace period (days)', min: 0, max: 30, h: 'How long a host stays unreachable before alerting.' },
    { k: 'history_retention_days', l: 'History retention (days)', min: 30, max: 3650, h: 'Older check records are pruned daily.' },
    { k: 'manual_check_cooldown_s', l: 'Manual check cooldown (seconds)', min: 0, max: 3600, h: 'Minimum delay between manual Check Now runs per monitor.' },
  ];
  function certsRender(d){
    var c = d.cfg || {}, p = d.prtg || {};
    var certFields = CERT_FIELDS.map(function(f){
      return field({ kind: 'num', k: f.k, l: f.l, v: c[f.k], min: f.min, max: f.max, req: true, t: 'str', h: esc(f.h) }); }).join('') +
      field({ kind: 'email', k: 'fallback_alert_email', l: 'Fallback alert email', v: c.fallback_alert_email, t: 'trim', h: 'Used when a monitor has no owner email of its own.' });
    var tokenState = p.prtg_summary_sensor_token_set ? 'A token is saved; it is never sent back to the browser. Leave blank to keep it.' : 'No summary sensor token is saved.';
    var prtg =
      '<div class="sf-grid">' +
      field({ kind: 'check', k: 'prtg_enabled', l: 'PRTG push enabled', v: truthy(p.prtg_enabled), t: 'b01', h: 'Master switch. Off: no pushes go out from any run or transition.' }) +
      field({ kind: 'check', k: 'prtg_heartbeat_enabled', l: 'Heartbeat push on every run', v: truthy(p.prtg_heartbeat_enabled == null ? '1' : p.prtg_heartbeat_enabled), t: 'b01', h: 'Lets PRTG tell when Certificate Watchtower stops running.' }) +
      field({ kind: 'check', k: 'prtg_push_on_transition', l: 'Push on alert transition', v: truthy(p.prtg_push_on_transition == null ? '1' : p.prtg_push_on_transition), t: 'b01', h: 'Pushes the moment a certificate changes status.' }) +
      field({ kind: 'check', k: 'prtg_verify_tls', l: 'Verify the PRTG TLS certificate', v: truthy(p.prtg_verify_tls), t: 'b01', h: 'Only meaningful over HTTPS.' }) +
      field({ kind: 'text', k: 'prtg_core_host', l: 'PRTG core host', v: p.prtg_core_host, t: 'trim', ph: 'prtg01awsw2us.nrpi.local', h: 'FQDN or IP of the PRTG probe that receives pushes.' }) +
      field({ kind: 'num', k: 'prtg_push_port', l: 'Push port', v: p.prtg_push_port == null ? '5050' : p.prtg_push_port, min: 1, max: 65535, req: true, h: 'Default 5050 (HTTP) or 5051 (HTTPS).' }) +
      field({ kind: 'select', k: 'prtg_push_protocol', l: 'Protocol', v: p.prtg_push_protocol || 'http', opts: [['http', 'HTTP'], ['https', 'HTTPS']] }) +
      field({ kind: 'num', k: 'prtg_timeout_ms', l: 'Push timeout (ms)', v: p.prtg_timeout_ms == null ? '5000' : p.prtg_timeout_ms, min: 100, max: 60000, req: true, h: 'Default 5000.' }) +
      field({ kind: 'num', k: 'prtg_retry_count', l: 'Retry count', v: p.prtg_retry_count == null ? '2' : p.prtg_retry_count, min: 0, max: 10, req: true, h: 'Retries on a transient failure. Default 2.' }) +
      '</div>' +
      '<div class="sf-grid">' +
      field({ kind: 'pw', k: 'prtg_summary_sensor_token', l: 'Summary sensor token', v: '', ph: 'Leave blank to keep the saved token', h: esc(tokenState) }) +
      field({ kind: 'check', k: '__clear_token', l: 'Clear the saved summary sensor token', v: false, h: 'Optional sensor that receives fleet-wide counts on every run.' }) +
      '</div>';
    return '<section class="card" data-sf-ed="cert"><div class="card-h"><h3>Alert thresholds and retention</h3><span class="meta">Hub table cert_config · changes apply on the next check</span></div>' +
           '<div class="card-b"><div class="sf-grid">' + certFields + '</div></div>' + foot('cert') + '</section>' +
           '<section class="card" data-sf-ed="prtg"><div class="card-h"><h3>PRTG push</h3><span class="meta">test pushes and per-certificate tokens stay on Certificate Watchtower</span></div>' +
           '<div class="card-b">' + prtg + '</div>' + foot('prtg') + '</section>';
  }
  function certsSave(ed){
    var name = ed.dataset.sfEd, sent = {};
    var isPrtg = name === 'prtg';
    changed(ed).forEach(function(el){
      if(el.dataset.k === '__clear_token' || el.dataset.k === 'prtg_summary_sensor_token') return;
      sent[el.dataset.k] = String(typed(el));
    });
    if(isPrtg){
      var clr = ed.querySelector('[data-k="__clear_token"]'), tok = ed.querySelector('[data-k="prtg_summary_sensor_token"]');
      if(clr.checked) sent.prtg_summary_sensor_token = '';
      else if(tok.value.trim()) sent.prtg_summary_sensor_token = tok.value.trim();
    }
    if(!Object.keys(sent).length) return Promise.resolve();
    var url = isPrtg ? '/api/prtg/config' : '/api/cert-config';
    return api('PUT', url, sent).then(function(){ return reread('certs'); }).then(function(d){
      var back = isPrtg ? d.prtg : d.cfg, missed = Object.keys(sent).filter(function(k){
        if(k === 'prtg_summary_sensor_token') return !!back.prtg_summary_sensor_token_set !== (sent[k] !== '');
        return !has(back, k) || String(back[k]) !== sent[k];
      });
      if(missed.length) throw new Error('the Hub answered OK but reading back shows these did not change: ' + missed.join(', ') + '.');
      return 'Saved ' + Object.keys(sent).length + ' setting' + (Object.keys(sent).length === 1 ? '' : 's') + '; read back from the Hub.';
    });
  }

  /* ---------- Sign-In Watch (Hub, super admin) ---------- */
  var SW = '/api/signin-watch';
  var CENR_MARK = 'CENR auto-import';
  var NET_TYPES = [['office-plano', 'Office — Plano'], ['office-irvine', 'Office — Irvine'], ['other', 'Other']];
  var TIERS = [['standard', 'Standard'], ['vip', 'VIP']];
  var FIRE = [['all', 'All results'], ['failure', 'Failures only'], ['success', 'Successes only']];
  var TFILT = [['all', 'All tiers'], ['vip', 'VIP only'], ['standard', 'Standard only']];
  function signinRender(d){
    var wl = d.watch.map(function(r){
      var paused = r.pause_ticket_id ? ' <span class="pill p-warn" title="Paused by ' + esc(r.paused_by || '') + '">paused · ' + esc(r.pause_ticket_display || r.pause_ticket_id) + '</span>' : '';
      return '<tr data-sf-ed="wl:' + esc(r.id) + '">' +
        '<td><span class="mono">' + esc(r.upn) + '</span>' + paused + '<small class="sf-sub">added by ' + esc(r.added_by || 'unknown') + '</small></td>' +
        '<td>' + control({ kind: 'select', k: 'tier', v: r.tier || 'standard', opts: TIERS, aria: 'Tier for ' + r.upn }) + '</td>' +
        '<td class="sf-c">' + control({ kind: 'check', k: 'watch_okta', v: !!r.watch_okta, aria: 'Watch Okta for ' + r.upn }) + '</td>' +
        '<td class="sf-c">' + control({ kind: 'check', k: 'watch_entra', v: !!r.watch_entra, aria: 'Watch Entra for ' + r.upn }) + '</td>' +
        '<td>' + control({ kind: 'text', k: 'note', v: r.note, ml: 500, aria: 'Note for ' + r.upn }) + '</td>' +
        '<td class="sf-c">' + control({ kind: 'check', k: 'active', v: !!r.active, aria: 'Active for ' + r.upn }) + '</td>' +
        rowActions('wl:' + r.id, true) + '</tr>';
    }).join('');
    // Rows marked 'CENR auto-import' belong to zscaler-cenr-sync-job.js, which re-enables and disables them
    // to follow Zscaler's published ranges; an edit here would be undone, so they are listed read-only.
    var autoNets = d.nets.filter(function(r){ return r.note === CENR_MARK; });
    var manNets = d.nets.filter(function(r){ return r.note !== CENR_MARK; });
    var autoOn = autoNets.filter(function(r){ return !!r.enabled; }).length;
    var autoList = autoNets.length ? '<details class="sf-auto"><summary>' + autoNets.length + ' Zscaler ranges from the CENR sync (' + autoOn + ' enabled), read-only</summary>' +
      '<p class="hint">These carry the note <span class="mono">' + esc(CENR_MARK) + '</span>. The CENR sync job owns them: it adds new ranges and disables ranges Zscaler no longer publishes, so they are not edited here.</p>' +
      '<div class="tblwrap"><table class="grid sf-tbl"><thead><tr><th>CIDR</th><th>Label</th><th>State</th></tr></thead><tbody>' +
      autoNets.map(function(r){ return '<tr><td class="mono">' + esc(r.cidr) + '</td><td>' + esc(r.label) + '</td><td>' + (r.enabled ? 'Enabled' : '<span class="sf-dim">Disabled</span>') + '</td></tr>'; }).join('') +
      '</tbody></table></div></details>' : '';
    var nets = manNets.map(function(r){
      return '<tr data-sf-ed="net:' + esc(r.id) + '">' +
        '<td>' + control({ kind: 'text', k: 'label', v: r.label, ml: 120, req: true, aria: 'Label for ' + r.cidr }) + '</td>' +
        '<td>' + control({ kind: 'text', k: 'cidr', v: r.cidr, t: 'trim', req: true, aria: 'CIDR for ' + r.label }) + '</td>' +
        '<td>' + control({ kind: 'select', k: 'type', v: r.type, opts: NET_TYPES, aria: 'Type for ' + r.label }) + '</td>' +
        '<td>' + control({ kind: 'text', k: 'note', v: r.note, ml: 500, aria: 'Note for ' + r.label }) + '</td>' +
        '<td class="sf-c">' + control({ kind: 'check', k: 'enabled', v: !!r.enabled, aria: 'Enabled for ' + r.label }) + '</td>' +
        rowActions('net:' + r.id, true) + '</tr>';
    }).join('');
    var chans = d.chans.map(function(r){
      var test = r.last_test_at ? esc(r.last_test_result || '') + '<small class="sf-sub">' + esc(when(r.last_test_at)) + '</small>' : '<span class="sf-dim">never tested</span>';
      return '<tr data-sf-ed="ch:' + esc(r.id) + '">' +
        '<td>' + control({ kind: 'text', k: 'name', v: r.name, ml: 120, req: true, aria: 'Name for channel ' + r.id }) + '</td>' +
        '<td class="mono">' + esc(r.type) + '</td>' +
        '<td>' + control({ kind: 'select', k: 'fire_on', v: r.fire_on || 'all', opts: FIRE, aria: 'Fires on for ' + r.name }) + '</td>' +
        '<td>' + control({ kind: 'select', k: 'tier_filter', v: r.tier_filter || 'all', opts: TFILT, aria: 'Tier filter for ' + r.name }) + '</td>' +
        '<td class="sf-c">' + control({ kind: 'check', k: 'auto_investigate', v: !!r.auto_investigate, aria: 'Auto-investigate for ' + r.name }) + '</td>' +
        '<td class="sf-c">' + control({ kind: 'check', k: 'enabled', v: !!r.enabled, aria: 'Enabled for ' + r.name }) + '</td>' +
        '<td class="sf-test">' + test + '</td>' + rowActions('ch:' + r.id, false) + '</tr>';
    }).join('');
    function table(cols, rows, empty){
      return '<div class="tblwrap"><table class="grid sf-tbl"><thead><tr>' + cols.map(function(c){ return '<th>' + c + '</th>'; }).join('') +
             '<th><span class="sr-only">Actions</span></th></tr></thead><tbody>' +
             (rows || '<tr><td colspan="' + (cols.length + 1) + '"><div class="empty">' + empty + '</div></td></tr>') + '</tbody></table></div>';
    }
    return '<section class="card"><div class="card-h"><h3>Watched accounts</h3><span class="meta">' + d.watch.length + ' on the watchlist · pause and resume stay on Sign-In Watch</span></div>' +
      table(['Account', 'Tier', 'Okta', 'Entra', 'Note', 'Active'], wl, 'No accounts are watched.') +
      '<div class="card-b sf-add" data-sf-ed="wl:new"><h4>Watch an account</h4><div class="sf-grid">' +
      field({ kind: 'email', k: 'upn', l: 'UPN (email)', v: '', t: 'trim', req: true, ph: 'user@auction.com' }) +
      field({ kind: 'select', k: 'tier', l: 'Tier', v: 'standard', opts: TIERS, h: 'VIP accounts show on the VIP board and are investigated on every violation.' }) +
      field({ kind: 'text', k: 'note', l: 'Note', v: '', ml: 500 }) +
      field({ kind: 'check', k: 'watch_okta', l: 'Watch Okta', v: true }) +
      field({ kind: 'check', k: 'watch_entra', l: 'Watch Entra', v: true }) +
      '</div>' + foot('wl:new', 'Add to watchlist') + '</div></section>' +
      '<section class="card"><div class="card-h"><h3>Trusted networks</h3><span class="meta">' + manNets.length + ' added by hand · ' + autoNets.length + ' from the Zscaler CENR sync</span></div>' +
      table(['Label', 'CIDR', 'Type', 'Note', 'Enabled'], nets, 'No networks were added by hand.') + autoList +
      '<div class="card-b sf-add" data-sf-ed="net:new"><h4>Add a trusted network</h4><div class="sf-grid">' +
      field({ kind: 'text', k: 'label', l: 'Label', v: '', ml: 120, req: true, ph: 'Office name or description' }) +
      field({ kind: 'text', k: 'cidr', l: 'CIDR', v: '', t: 'trim', req: true, ph: '10.0.0.0/24 or 2001:db8::/32' }) +
      field({ kind: 'select', k: 'type', l: 'Type', v: 'office-plano', opts: NET_TYPES }) +
      field({ kind: 'text', k: 'note', l: 'Note', v: '', ml: 500 }) +
      '</div>' + foot('net:new', 'Add network') + '</div></section>' +
      '<section class="card"><div class="card-h"><h3>Alert channels</h3><span class="meta">' + d.chans.length + ' channels · testing, deleting and replacing a webhook stay on Sign-In Watch</span></div>' +
      table(['Name', 'Type', 'Fires on', 'Tiers', 'Investigate', 'Enabled', 'Last test'], chans, 'No alert channels.') +
      '<div class="card-b sf-add" data-sf-ed="ch:new"><h4>Add an alert channel</h4><div class="sf-grid">' +
      field({ kind: 'text', k: 'name', l: 'Name', v: '', ml: 120, req: true, ph: 'IT-Security Teams' }) +
      field({ kind: 'select', k: 'type', l: 'Type', v: 'teams', opts: [['teams', 'Teams webhook'], ['webhook', 'Generic webhook'], ['sdp', 'SDP ticket']] }) +
      field({ kind: 'select', k: 'fire_on', l: 'Fires on', v: 'all', opts: FIRE }) +
      field({ kind: 'select', k: 'tier_filter', l: 'Tier filter', v: 'all', opts: TFILT }) +
      field({ kind: 'area', k: 'config_json', l: 'Configuration (JSON)', v: '', req: true, wide: true, ph: '{"webhook_url":"https://..."}',
              h: 'Teams: <span class="mono">{"webhook_url":"..."}</span> · SDP: <span class="mono">{"requester_email":"..."}</span>. The Hub never sends it back.' }) +
      field({ kind: 'text', k: 'mentions', l: '@mentions (Teams, optional)', v: '', ph: 'user@auction.com, other@auction.com', h: 'Comma-separated UPNs to @mention on Teams alerts.' }) +
      field({ kind: 'check', k: 'auto_investigate', l: 'Auto-investigate before alerting', v: false }) +
      '</div>' + foot('ch:new', 'Add channel') + '</div></section>';
  }
  function signinSave(ed){
    var parts = ed.dataset.sfEd.split(':'), kind = parts[0], id = parts[1], body = {};
    var base = { wl: '/watchlist', net: '/networks', ch: '/channels' }[kind];
    if(id === 'new'){
      each(ed.querySelectorAll('[data-k]'), function(el){ body[el.dataset.k] = typed(el); });
      if(kind === 'ch'){
        try { body.config_json = JSON.parse(body.config_json); }
        catch(e){ return Promise.reject(new Error('Configuration is not valid JSON.')); }
        var m = String(body.mentions || '').split(',').map(function(s){ return s.trim(); }).filter(Boolean);
        delete body.mentions;
        if(m.length) body.mention_config = { mentions: m.map(function(u){ return { id: u, name: u.split('@')[0] }; }) };
      }
      if(kind === 'wl') body.upn = String(body.upn).toLowerCase();
      return api('POST', SW + base, body).then(function(){ return reread('signin'); })
        .then(function(){ return kind === 'wl' ? 'Added ' + body.upn + ' to the watchlist.' : kind === 'net' ? 'Added ' + body.label + '.' : 'Added the ' + body.name + ' channel.'; });
    }
    changed(ed).forEach(function(el){ body[el.dataset.k] = typed(el); });
    return api('PATCH', SW + base + '/' + encodeURIComponent(id), body).then(function(j){
      return reread('signin').then(function(){
        if(!j.changed) throw new Error('the Hub changed nothing; the row may have been removed. The list was reloaded.');
        return 'Saved.';
      });
    });
  }
  function signinDelete(ed){
    var parts = ed.dataset.sfEd.split(':'), kind = parts[0], id = parts[1];
    var what = kind === 'wl' ? ed.querySelector('.mono').textContent : ed.querySelector('[data-k="label"]').dataset.o;
    var text = kind === 'wl' ? 'Remove ' + what + ' from the watchlist? This deletes the entry. To stop watching for now, untick Active instead.'
                             : 'Delete the trusted network ' + what + '? Sign-ins from it will no longer count as trusted.';
    if(!confirm(text)) return null;
    return api('DELETE', SW + (kind === 'wl' ? '/watchlist/' : '/networks/') + encodeURIComponent(id)).then(function(j){
      return reread('signin').then(function(){
        if(!j.deleted) throw new Error('the Hub deleted nothing; it may already be gone. The list was reloaded.');
        return 'Deleted ' + what + '.';
      });
    });
  }

  /* ---------- Identity digest (Hub user-projects) ---------- */
  var DIGEST_SECTIONS = [
    ['activity_7d', 'Last 7 days activity', 'Actions logged in the last 7 days across all projects.'],
    ['snapshot', 'Current group snapshot', 'For each preset AD group: everyone currently in it, from which project, with expiry.'],
    ['expiring_14d', 'Expiring in the next 14 days', 'Grants whose expiry date falls within two weeks.'],
    ['recently_removed', 'Recently removed', 'Grants that expired or were revoked in the last 7 days.'],
  ];
  var DOW7 = [[1, 'Monday'], [2, 'Tuesday'], [3, 'Wednesday'], [4, 'Thursday'], [5, 'Friday'], [6, 'Saturday'], [7, 'Sunday']];
  function sv(s, k, dflt){ var e = s[k], v = (e && typeof e === 'object') ? e.value : e; return (v == null || v === '') ? dflt : v; }
  function jsonList(v){ try { var a = JSON.parse(v); return Array.isArray(a) ? a : []; } catch(e){ return []; } }
  function digestRender(d){
    var s = d.settings || {}, sent = sv(s, 'digest_last_sent_at', null), sweep = sv(s, 'expiry_check_last_run_at', null);
    var sect = null; try { sect = JSON.parse(sv(s, 'digest_sections', 'null')); } catch(e){}
    if(!Array.isArray(sect)) sect = DIGEST_SECTIONS.map(function(x){ return x[0]; });
    var changedBy = ['digest_enabled', 'digest_recipients', 'digest_sections', 'sensitive_group_blocklist'].map(function(k){ return s[k]; })
      .filter(function(e){ return e && e.updated_at; }).sort(function(a, b){ return String(b.updated_at).localeCompare(String(a.updated_at)); })[0];
    return (sent ? '' : '<div class="note warn">' + WARN_SVG + '<div><b>No digest has ever been sent.</b> The Hub has no record of a send (<span class="mono">digest_last_sent_at</span> is empty). Saving stores these settings; it sends nothing by itself. <em>Send a test now</em> stays on Identity diagnostics.</div></div>') +
      (sweep ? '' : '<div class="note crit">' + WARN_SVG + '<div><b>The expiry sweep has never reported a run.</b> The Hub has no record of <span class="mono">user-project-expiry-job.js</span> running (<span class="mono">expiry_check_last_run_at</span> is empty), so grants past their expiry date may still be in AD. Treat every expiry date as a reminder, not an automatic removal.</div></div>') +
      '<div data-sf-ed="digest">' +
      '<section class="card"><div class="card-h"><h3>Weekly digest</h3><span class="meta">last sent: ' + (sent ? esc(when(sent)) : 'never') +
      (changedBy ? ' · last changed ' + esc(when(changedBy.updated_at)) + ' by ' + esc(changedBy.updated_by || 'unknown') : '') + '</span></div><div class="card-b"><div class="sf-grid">' +
      field({ kind: 'check', k: 'digest_enabled', l: 'Digest enabled', v: String(sv(s, 'digest_enabled', 'true')) === 'true', t: 'bstr' }) +
      field({ kind: 'select', k: 'digest_day_of_week', l: 'Day of week', v: parseInt(sv(s, 'digest_day_of_week', '2'), 10) || 2, opts: DOW7 }) +
      field({ kind: 'area', k: 'digest_recipients', l: 'Recipients (one email per line)', v: jsonList(sv(s, 'digest_recipients', '[]')).join('\n'), t: 'lines', wide: true }) +
      '</div></div></section>' +
      '<section class="card"><div class="card-h"><h3>Report sections</h3><span class="meta">which sections the digest email includes</span></div><div class="card-b sf-checks">' +
      DIGEST_SECTIONS.map(function(x){ return field({ kind: 'check', k: 'sec:' + x[0], l: x[1], v: sect.indexOf(x[0]) >= 0, h: esc(x[2]) }); }).join('') +
      '</div></section>' +
      '<section class="card"><div class="card-h"><h3>Sensitive group blocklist</h3><span class="meta">AD groups listed here cannot be used by any project</span></div><div class="card-b">' +
      field({ kind: 'area', k: 'sensitive_group_blocklist', l: 'One group name per line', v: jsonList(sv(s, 'sensitive_group_blocklist', '[]')).join('\n'), t: 'lines', rows: 6, ph: 'Domain Admins\nEnterprise Admins' }) +
      '<p class="hint">Expiry sweep last run: ' + (sweep ? esc(when(sweep)) : 'never; the sweep has not reported') + '</p>' +
      '</div>' + foot('digest') + '</section></div>';
  }
  function digestSave(ed){
    var body = {}, secChanged = false;
    changed(ed).forEach(function(el){
      if(el.dataset.k.indexOf('sec:') === 0){ secChanged = true; return; }
      body[el.dataset.k] = el.dataset.k === 'digest_day_of_week' ? String(el.value) : typed(el);
    });
    if(secChanged){
      body.digest_sections = JSON.stringify(DIGEST_SECTIONS.map(function(x){ return x[0]; })
        .filter(function(k){ return ed.querySelector('[data-k="sec:' + k + '"]').checked; }));
    }
    return api('PATCH', '/api/user-project/settings', body).then(function(j){
      var s = j.settings || {}, missed = Object.keys(body).filter(function(k){
        var want = Array.isArray(body[k]) ? JSON.stringify(body[k]) : String(body[k]);
        return String(sv(s, k, '')) !== want;
      });
      ST.digest.data = j; draw('digest');
      if(missed.length) throw new Error('the Hub answered but these were not stored: ' + missed.join(', ') + '.');
      return 'Saved; the Hub sent back the stored values.';
    });
  }

  /* ---------- Zscaler AI report and watchlist (Hub zscaler-diag) ---------- */
  var ZB = '/api/zscaler/zia/ai';
  var WINDOWS = [[24, '24 hours'], [72, '3 days'], [168, '7 days'], [336, '14 days'], [720, '30 days']];
  var DOW_SUN = [[0, 'Sunday'], [1, 'Monday'], [2, 'Tuesday'], [3, 'Wednesday'], [4, 'Thursday'], [5, 'Friday'], [6, 'Saturday']];
  var REPORT_KEYS = ['enabled', 'recipients', 'frequency', 'send_hour_utc', 'send_dow', 'send_dom', 'window_hours', 'include_governed'];
  function zscalerRender(d){
    var c = d.report, html;
    if(!c){
      html = '<section class="card"><div class="card-h"><h3>Scheduled Gen AI email report</h3></div><div class="card-b"><div class="note quiet">' + INFO_SVG +
             '<div><b>The Hub has no report configuration row.</b>' + esc(d.reportMissing || '') + ' There is nothing to edit until the ai_report_config table is seeded.</div></div></div></section>';
    } else {
      var f = c.frequency || 'weekly';
      html = '<section class="card" data-sf-ed="zrep"><div class="card-h"><h3>Scheduled Gen AI email report</h3><span class="meta">' +
        (c.last_sent_at ? 'last sent ' + esc(when(c.last_sent_at)) + ' · ' + esc(c.last_status || '') : 'never sent') +
        (c.updated_at ? ' · changed ' + esc(when(c.updated_at)) + (c.updated_by ? ' by ' + esc(c.updated_by) : '') : '') + '</span></div>' +
        '<div class="card-b">' +
        // Host-gated: only the dev server is known to run the schedule, and there in practice mode
        // (corpit-ai-report-dryrun.timer). Prod shows no claim about sending, because its cron is unverified.
        (DEV ? '<div class="note quiet">' + INFO_SVG + '<div><b>Practice mode.</b> On this dev server the schedule runs in practice mode: when the report is due it is built and logged, never sent.</div></div>' : '') +
        '<div class="sf-grid">' +
        field({ kind: 'check', k: 'enabled', l: 'Report enabled', v: truthy(c.enabled), t: 'i01', h: 'Saved schedule. Sending depends on the hourly report job on the server.' }) +
        field({ kind: 'check', k: 'include_governed', l: 'Include the governed usage table', v: truthy(c.include_governed), t: 'i01' }) +
        field({ kind: 'text', k: 'recipients', l: 'Recipients (comma or space separated)', v: c.recipients, t: 'trim', wide: true, ph: 'user@auction.com' }) +
        field({ kind: 'select', k: 'frequency', l: 'Frequency', v: f, opts: [['daily', 'Daily'], ['weekly', 'Weekly'], ['monthly', 'Monthly']] }) +
        field({ kind: 'num', k: 'send_hour_utc', l: 'Send hour (UTC, 0–23)', v: c.send_hour_utc == null ? 15 : c.send_hour_utc, min: 0, max: 23, req: true, t: 'int' }) +
        field({ kind: 'select', k: 'send_dow', l: 'Day of week', v: c.send_dow == null ? 1 : c.send_dow, opts: DOW_SUN, t: 'int', wrap: 'data-sf-when="weekly"' }) +
        field({ kind: 'num', k: 'send_dom', l: 'Day of month (1–28)', v: c.send_dom == null ? 1 : c.send_dom, min: 1, max: 28, req: true, t: 'int', wrap: 'data-sf-when="monthly"' }) +
        field({ kind: 'select', k: 'window_hours', l: 'Report window', v: c.window_hours || 168, opts: WINDOWS, t: 'int' }) +
        '</div></div>' + foot('zrep', 'Save changes', '<span class="hint">Send now stays on Zscaler Command Center.</span>') + '</section>';
    }
    var rows = d.watch.map(function(r){
      return '<tr data-sf-ed="zw:' + esc(r.id) + '"><td class="mono">' + esc(r.subject) + '</td><td>' + esc(r.subject_type) + '</td>' +
        '<td>' + control({ kind: 'select', k: 'status', v: r.status, opts: [['open', 'Open'], ['monitoring', 'Monitoring'], ['closed', 'Closed']], aria: 'Status for ' + r.subject }) + '</td>' +
        '<td>' + control({ kind: 'text', k: 'notes', v: r.notes, aria: 'Notes for ' + r.subject }) + '</td>' +
        '<td><small class="sf-sub">' + esc(r.updated_by || r.created_by || '') + '</small><small class="sf-sub">' + esc(when(r.updated_at)) + '</small></td>' +
        rowActions('zw:' + r.id, false) + '</tr>';
    }).join('');
    return html + '<section class="card"><div class="card-h"><h3>AI watchlist</h3><span class="meta">' + d.watch.length + ' subjects</span></div>' +
      '<div class="tblwrap"><table class="grid sf-tbl"><thead><tr><th>Subject</th><th>Type</th><th>Status</th><th>Notes</th><th>Updated</th><th><span class="sr-only">Actions</span></th></tr></thead><tbody>' +
      (rows || '<tr><td colspan="6"><div class="empty">Nothing on the AI watchlist.</div></td></tr>') + '</tbody></table></div>' +
      '<div class="card-b sf-add" data-sf-ed="zw:new"><h4>Watch a subject</h4><div class="sf-grid">' +
      field({ kind: 'text', k: 'subject', l: 'Subject', v: '', t: 'trim', req: true, ph: 'user@auction.com, an app or a host' }) +
      field({ kind: 'select', k: 'subject_type', l: 'Type', v: 'user', opts: [['user', 'User'], ['app', 'App'], ['host', 'Host']] }) +
      field({ kind: 'text', k: 'notes', l: 'Notes', v: '' }) +
      '</div>' + foot('zw:new', 'Add to watchlist') + '</div></section>';
  }
  function zscalerAfter(body){
    var ed = body.querySelector('[data-sf-ed="zrep"]');
    if(!ed) return;
    var f = ed.querySelector('[data-k="frequency"]').value;
    each(ed.querySelectorAll('[data-sf-when]'), function(w){
      var on = w.dataset.sfWhen === f;
      w.hidden = !on;
      each(w.querySelectorAll('[data-k]'), function(el){ el.disabled = !on; });
    });
  }
  function zscalerSave(ed){
    var name = ed.dataset.sfEd;
    if(name === 'zrep'){
      // The Command Center sends the whole row on every save; this does the same, then checks
      // the row the Hub sends back, because an UPDATE that matched nothing still answers 200.
      var body = {}, c = ST['zscaler-ai'].data.report;
      REPORT_KEYS.forEach(function(k){
        var el = ed.querySelector('[data-k="' + k + '"]');
        body[k] = el.disabled ? (c[k] == null ? (k === 'send_dom' ? 1 : 1) : Number(c[k])) : typed(el);
      });
      return api('POST', ZB + '/report-config', body).then(function(row){
        var missed = REPORT_KEYS.filter(function(k){ return String(row[k]) !== String(body[k]); });
        return reread('zscaler-ai').then(function(){
          if(missed.length) throw new Error('the Hub answered but its stored row still differs for: ' + missed.join(', ') + '. Nothing you see here was saved for those fields.');
          return 'Saved; the Hub sent back the stored row.';
        });
      });
    }
    var id = name.split(':')[1], b = {};
    if(id === 'new'){
      each(ed.querySelectorAll('[data-k]'), function(el){ b[el.dataset.k] = typed(el); });
      return api('POST', ZB + '/watchlist', b).then(function(){ return reread('zscaler-ai'); }).then(function(){ return 'Added ' + b.subject + '.'; });
    }
    b.id = Number(id);
    changed(ed).forEach(function(el){ b[el.dataset.k] = typed(el); });
    return api('POST', ZB + '/watchlist', b).then(function(){ return reread('zscaler-ai'); }).then(function(d){
      var row = d.watch.filter(function(r){ return String(r.id) === id; })[0];
      if(!row) throw new Error('that subject is no longer on the watchlist.');
      if(b.status && row.status !== b.status) throw new Error('the Hub answered but the status is still ' + row.status + '.');
      return 'Saved.';
    });
  }

  /* ---------- Launch pad CAB, hotfix, Verify & close, evidence (itam only) ---------- */
  function cabGroup(k){
    if(/^life_/.test(k)) return 'life';
    if(/^evidence_/.test(k)) return 'evidence';
    if(/^gate_/.test(k)) return 'gate';
    return 'cab';
  }
  var CAB_GROUPS = [['cab', 'CAB gate and the SDP change', 'what sign-off files and what Publish waits for'],
                    ['gate', 'Gate review', 'applies while the CAB gate is off'],
                    ['life', 'Verify & close', 'after a launch'],
                    ['evidence', 'Test evidence', 'Prepare and Launch']];
  function cabField(x, d){
    var v = d.values[x.key], hint = x.help ? esc(x.help) : '';
    if(x.type === 'bool') return field({ kind: 'check', k: x.key, l: x.label, v: !!v, t: 'bool', h: hint });
    if(x.type === 'int') return field({ kind: 'num', k: x.key, l: x.label, v: v, min: x.min, max: x.max, req: true, t: 'int',
                                        h: (hint ? hint + ' ' : '') + esc(x.min + ' to ' + x.max + '.') });
    if(x.type === 'text') return field({ kind: 'text', k: x.key, l: x.label, v: v, ml: 100, req: !x.optional, t: 'trim',
                                         h: (hint ? hint + ' ' : '') + (x.optional ? 'May be blank.' : '') });
    var keys = x.type === 'field_map' ? d.fields.map(function(f){ return [f.key, f.label]; }) : d.sites.map(function(s){ return [s.id, s.title]; });
    var map = v || {};
    return '<fieldset class="sf-map sf-wide"><legend>' + esc(x.label) + '</legend>' + (hint ? '<p class="hint">' + hint + '</p>' : '') +
      '<div class="sf-map-grid">' + keys.map(function(p){
        var val = map[p[0]];
        if(x.type === 'site_list') val = (val || []).join(' ');
        return field({ kind: 'text', k: x.key + '.' + p[0], l: p[1], v: val, t: 'trim',
                       ph: x.type === 'field_map' ? 'udf_char1' : (x.placeholder || ''), req: x.type === 'site_map' });
      }).join('') + '</div></fieldset>';
  }
  function launchpadRender(d){
    var reg = d.registry, on = !!d.values.enabled, cn = d.connection || {}, ck = d.checked, ch = d.changed;
    var facts = '<div class="sf-facts">' +
      '<div><span>CAB gate</span><b>' + (on ? '<span class="pill p-info">on</span> Publish waits for CAB approval' : '<span class="pill p-mut">off</span> Publish does not wait for CAB') + '</b></div>' +
      '<div><span>SDP connection</span><b>' + (cn.stored ? 'connected' + (cn.portal ? ' to <span class="mono">' + esc(cn.portal) + '</span>' : '') + (cn.stored_by ? ' by ' + esc(cn.stored_by) : '') + (cn.stored_at ? ' · ' + esc(when(cn.stored_at)) : '')
                                              : '<span class="pill p-warn">not connected</span> connect it on the launch pad') + '</b></div>' +
      '<div><span>Last SDP check</span><b>' + (ck ? (ck.ok ? '<span class="pill p-good">passed</span> ' : '<span class="pill p-crit">failed</span> ') + esc(when(ck.at)) + (ck.by ? ' by ' + esc(ck.by) : '') : '<span class="sf-dim">never checked</span>') + '</b></div>' +
      '<div><span>Last change</span><b>' + (ch ? esc(when(ch.at)) + (ch.by ? ' by ' + esc(ch.by) : '') : '<span class="sf-dim">never changed</span>') + '</b></div>' +
      '</div>';
    return facts + '<div data-sf-ed="cab">' + CAB_GROUPS.map(function(g){
      var items = reg.filter(function(x){ return cabGroup(x.key) === g[0]; });
      if(!items.length) return '';
      return '<section class="card"><div class="card-h"><h3>' + esc(g[1]) + '</h3><span class="meta">' + esc(g[2]) + '</span></div><div class="card-b"><div class="sf-grid">' +
             items.map(function(x){ return cabField(x, d); }).join('') + '</div></div></section>';
    }).join('') + '<div class="sf-savebar">' + foot('cab', 'Save launch pad settings', '<span class="hint">Turning the CAB gate on, or changing an SDP name while it is on, makes the launch pad check SDP first; Check SDP and Connect stay on the launch pad.</span>') + '</div></div>';
  }
  function launchpadSave(ed){
    var d = ST.launchpad.data, values = {};
    changed(ed).forEach(function(el){
      var k = el.dataset.k, dot = k.indexOf('.');
      if(dot > 0){
        var top = k.slice(0, dot);
        values[top] = values[top] || {};
        values[top][k.slice(dot + 1)] = typed(el);
      } else {
        values[k] = el.dataset.t === 'int' ? String(el.value).trim() : typed(el);
      }
    });
    if(has(values, 'enabled')){
      var ask = values.enabled
        ? 'Turn the CAB gate on? The launch pad checks every SDP name with SDP first; if that check fails, the gate stays off and nothing is saved.'
        : 'Turn the CAB gate off? Publish will stop waiting for CAB approval.';
      if(!confirm(ask)) return null;
    }
    return api('POST', '/__dev/api/cab/settings', { values: values }, CONSOLE_HDR).then(function(j){
      ST.launchpad.data = j; draw('launchpad');
      if(j.saved === false) return 'Nothing changed; the launch pad already had these values.';
      var c = j.check;
      return 'Saved and audited by the launch pad.' + (c ? (c.ok ? ' The SDP check passed.' : ' The SDP check did not pass.') : '');
    }).catch(function(e){
      if(e.body && e.body.code === 'cab_check' && e.body.check && e.body.check.items){
        var items = e.body.check.items.filter(function(i){ return !i.ok; });
        e.message = e.message + '. ' + items.map(function(i){ return i.what + (i.name ? ' "' + i.name + '"' : '') + ': ' + (i.detail || 'failed'); }).join('; ');
      }
      throw e;
    });
  }

  /* ---------- Backup schedule/retention/maintenance and A/B availability (itam only) ---------- */
  var DAY_MON0 = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
  var HA_EVENTS = [['failover_started', 'Failover started'], ['failover_succeeded', 'Failover succeeded'], ['failover_blocked', 'Failover blocked'],
                   ['failover_failed', 'Failover failed'], ['failback_started', 'Failback started'], ['failback_succeeded', 'Failback succeeded'],
                   ['failback_failed', 'Failback failed'], ['replication_degraded', 'Replication degraded']];
  var HA_FIELDS = [
    ['replication', 'enabled', 'Request replication', 'check'],
    ['replication', 'mode', 'Replication mode', 'mode'],
    ['replication', 'maxDataLossSeconds', 'Maximum data loss (seconds)', 'num', 0, 300],
    ['replication', 'checkIntervalSeconds', 'Replication check interval (seconds)', 'num', 5, 300],
    ['replication', 'maxEvidenceAgeSeconds', 'Maximum evidence age (seconds)', 'num', 5, 600],
    ['failover', 'automaticEnabled', 'Automatic failover', 'check'],
    ['failover', 'manualEnabled', 'Manual failover and failback', 'check'],
    ['failover', 'failureThreshold', 'Consecutive failed health checks', 'num', 2, 10],
    ['failover', 'probeIntervalSeconds', 'Health check interval (seconds)', 'num', 5, 60],
    ['failover', 'recoveryStableSeconds', 'Recovery stability window (seconds)', 'num', 30, 3600],
    ['notifications', 'enabled', 'Email alerts', 'check'],
    ['notifications', 'repeatAfterMinutes', 'Repeat unresolved alerts (minutes)', 'num', 1, 1440],
  ];
  function bkpRender(d){
    var reg = d.settings.registry || {}, vals = d.settings.values || {};
    var fields = Object.keys(reg).sort().map(function(name){
      var spec = reg[name], sk = name.split('.'), v = (vals[sk[0]] || {})[sk[1]];
      var h = esc(spec.unit ? name + ' · ' + spec.unit : name);
      if(spec.type === 'boolean') return field({ kind: 'check', k: name, l: spec.label, v: truthy(v), h: '<span class="mono">' + h + '</span>' });
      if(spec.type === 'choice') return field({ kind: 'select', k: name, l: spec.label, v: v, h: '<span class="mono">' + h + '</span>',
        opts: (spec.choices || []).map(function(c){ return [c, name === 'maintenance.weekday' ? (DAY_MON0[c] || c) : c]; }) });
      if(spec.type === 'time') return field({ kind: 'time', k: name, l: spec.label, v: v, req: true, h: '<span class="mono">' + h + '</span>' });
      return field({ kind: 'num', k: name, l: spec.label, v: v, min: spec.min, max: spec.max, req: true, h: '<span class="mono">' + h + '</span>' });
    }).join('');
    var out = '<section class="card" data-sf-ed="bkp"><div class="card-h"><h3>Backup schedule, retention and maintenance</h3><span class="meta">times are UTC · each change is saved and audited one at a time</span></div>' +
              '<div class="card-b"><div class="sf-grid">' + fields + '</div></div>' + foot('bkp') + '</section>';
    return out + haRender(d.ha, d.haErr);
  }
  function haRender(doc, err){
    var head = '<section class="card"><div class="card-h"><h3>A/B availability: desired settings</h3><span class="meta">';
    if(!doc){
      return head + 'not loaded</span></div><div class="card-b"><div class="note crit">' + WARN_SVG + '<div><b>Could not load the availability settings.</b>' +
        esc(err ? (err.denied ? 'The backup console refused: ' + err.message : err.message) : '') + '</div></div></div></section>';
    }
    var des = doc.desired || {}, v = des.values || {}, canEdit = !!(doc.capabilities && doc.capabilities.canEdit);
    var blocked = (doc.apply && doc.apply.blockedReasons) || [];
    var body = HA_FIELDS.map(function(f){
      var cur = (v[f[0]] || {})[f[1]], k = f[0] + '.' + f[1];
      if(f[3] === 'check') return field({ kind: 'check', k: k, l: f[2], v: !!cur, t: 'bool', dis: !canEdit });
      if(f[3] === 'mode') return field({ kind: 'select', k: k, l: f[2], v: cur, opts: [['synchronous', 'Synchronous']], dis: !canEdit });
      return field({ kind: 'num', k: k, l: f[2], v: cur, min: f[4], max: f[5], req: true, t: 'int', dis: !canEdit, h: esc(f[4] + ' to ' + f[5] + '.' + (f[0] === 'notifications' ? '' : ' Recorded only.') + (f[1] === 'repeatAfterMinutes' ? ' Recorded only.' : '')) });
    }).join('');
    var nv = v.notifications || {}, ev = nv.events || [];
    var recips = (nv.recipients || []).map(function(r){ return haRecipient(r, !canEdit); }).join('');
    return head + 'revision ' + esc(des.revision) + (des.updatedAt ? ' · ' + esc(when(des.updatedAt)) + (des.updatedBy ? ' by ' + esc(des.updatedBy) : '') : '') + '</span></div>' +
      '<div class="card-b" data-sf-ed="ha"' + (canEdit ? '' : ' data-sf-readonly') + '>' +
      // Mirrors /usr/local/lib/corpit-ha-alerts/deliver_alerts.py (saved_recipients / apply_saved_recipients) as installed by W2 on 2026-10-12.
      '<div class="note">' + INFO_SVG + '<div><b>Email alerts and recipients.</b> Alert delivery uses the saved recipients only if the latest save was by an @auction.com admin, ' +
      'Email alerts is on, and there are 1 to 30 recipients, all @auction.com. Otherwise it falls back to the baseline list in delivery.json.</div></div>' +
      '<div class="note warn">' + WARN_SVG + '<div><b>Recorded only.</b> Replication, failover, events and repeat are recorded only; saving them changes nothing that runs.' +
      (blocked.length ? '<ul>' + blocked.map(function(r){ return '<li>' + esc(r) + '</li>'; }).join('') + '</ul>' : '') + '</div></div>' +
      (canEdit ? '' : '<div class="note quiet">' + INFO_SVG + '<div>The backup console lets you read these settings but not change them.</div></div>') +
      '<div class="sf-grid">' + body + '</div>' +
      '<fieldset class="sf-map"><legend>Email recipients</legend><div data-sf-recips>' + recips + '</div>' +
      (canEdit ? '<button type="button" class="btn sm" data-sf-addrecip>Add recipient</button>' : '') + '<span class="hint">Up to 30, each email once. Used for delivery only when every address is @auction.com.</span></fieldset>' +
      '<fieldset class="sf-map"><legend>Events to send</legend><span class="hint">Recorded only; delivery does not use this list.</span><div class="sf-events">' + HA_EVENTS.map(function(e){
        var id = 'sf-f' + (++uid);
        return '<label class="f-inline" for="' + id + '"><input type="checkbox" id="' + id + '" data-ha-event value="' + esc(e[0]) + '"' + (ev.indexOf(e[0]) >= 0 ? ' checked' : '') + (canEdit ? '' : ' disabled') + '><span>' + esc(e[1]) + '</span></label>';
      }).join('') + '</div></fieldset>' +
      (canEdit ? '<div class="f sf-f sf-wide"><label for="sf-ha-reason">Reason for this change</label><input type="text" id="sf-ha-reason" data-ha-reason maxlength="500" autocomplete="off"><span class="hint">Required, one line. Recorded with the revision.</span></div>' : '') +
      foot('ha', 'Save desired settings') + '</div></section>';
  }
  function haRecipient(r, dis){
    var a = 'sf-f' + (++uid), b = 'sf-f' + (++uid), d = dis ? ' disabled' : '';
    return '<div class="sf-recip"><label for="' + a + '">Name</label><input type="text" id="' + a + '" data-ha-rname maxlength="100" required value="' + esc(r.name) + '"' + d + '>' +
           '<label for="' + b + '">Email address</label><input type="email" id="' + b + '" data-ha-remail maxlength="254" required value="' + esc(r.email) + '"' + d + '>' +
           (dis ? '' : '<button type="button" class="btn sm" data-sf-delrecip aria-label="Remove recipient ' + esc(r.name || r.email || '') + '">Remove</button>') + '</div>';
  }
  function haValues(ed){
    var out = { replication: {}, failover: {}, notifications: {} };
    HA_FIELDS.forEach(function(f){
      var el = ed.querySelector('[data-k="' + f[0] + '.' + f[1] + '"]');
      out[f[0]][f[1]] = el.type === 'checkbox' ? el.checked : f[3] === 'num' ? Number(el.value) : el.value;
    });
    out.notifications.recipients = Array.prototype.map.call(ed.querySelectorAll('.sf-recip'), function(row){
      return { name: row.querySelector('[data-ha-rname]').value.trim(), email: row.querySelector('[data-ha-remail]').value.trim() }; });
    out.notifications.events = filter(ed.querySelectorAll('[data-ha-event]'), function(i){ return i.checked; }).map(function(i){ return i.value; });
    return out;
  }
  function canon(v){
    if(Array.isArray(v)) return v.every(function(i){ return typeof i === 'string'; }) ? v.slice().sort() : v.map(canon);
    if(v && typeof v === 'object'){ var o = {}; Object.keys(v).sort().forEach(function(k){ o[k] = canon(v[k]); }); return o; }
    return v;
  }
  var DIRTY = {
    ha: function(ed){
      var doc = ST.backup.data && ST.backup.data.ha;
      return !!doc && JSON.stringify(canon(haValues(ed))) !== JSON.stringify(canon(doc.desired.values));
    },
  };
  var RESET = {
    ha: function(ed){
      var doc = ST.backup.data.ha, nv = doc.desired.values.notifications || {};
      ed.querySelector('[data-sf-recips]').innerHTML = (nv.recipients || []).map(function(r){ return haRecipient(r, false); }).join('');
      each(ed.querySelectorAll('[data-ha-event]'), function(i){ i.checked = (nv.events || []).indexOf(i.value) >= 0; });
      var r = ed.querySelector('[data-ha-reason]'); if(r) r.value = '';
    },
  };
  function backupSave(ed){
    if(ed.dataset.sfEd === 'bkp'){
      var list = changed(ed), done = [];
      // The backup console saves one setting per request; send them in order and stop at the first refusal.
      return list.reduce(function(p, el){
        return p.then(function(){
          var value = el.type === 'checkbox' ? String(el.checked) : el.value;
          return api('POST', '/bkp-api/settings', { name: el.dataset.k, value: value }, CONSOLE_HDR).then(function(){ done.push(el.dataset.k); });
        });
      }, Promise.resolve()).then(function(){
        return reread('backup').then(function(d){
          var missed = list.filter(function(el){
            var sk = el.dataset.k.split('.'), back = (d.settings.values[sk[0]] || {})[sk[1]];
            return String(back) !== (el.type === 'checkbox' ? String(el.checked) : el.value);
          }).map(function(el){ return el.dataset.k; });
          if(missed.length) throw new Error('the backup console answered but reading back shows these unchanged: ' + missed.join(', ') + '.');
          return 'Saved ' + done.length + ' setting' + (done.length === 1 ? '' : 's') + '; read back from the backup console.';
        });
      }, function(e){
        e.message = (done.length ? 'Saved ' + done.join(', ') + ', then stopped: ' : '') + e.message;
        return reread('backup').then(function(){ throw e; }, function(){ throw e; });
      });
    }
    var doc = ST.backup.data.ha, reasonEl = ed.querySelector('[data-ha-reason]'), reason = reasonEl.value.trim();
    if(!reason) return Promise.reject(new Error('Enter a reason for this configuration change.'));
    if(/[\u0000-\u001f\u007f]/.test(reasonEl.value)) return Promise.reject(new Error('Enter the reason on a single line.'));
    var body = { schemaVersion: 1, expectedRevision: doc.desired.revision, reason: reason, values: haValues(ed) };
    return api('POST', '/bkp-api/ha/settings', body, CONSOLE_HDR).then(function(j){
      if(j.saved !== true || j.durable !== true) throw new Error('the backup console did not confirm a durable save. Reload before trying again.');
      ST.backup.data.ha = j; draw('backup', true);
      return 'Saved revision ' + esc(j.desired && j.desired.revision) + '. Replication and failover values stay recorded only.';
    }).catch(function(e){
      if(e.status === 409 || (e.body && e.body.saveUnknown === true)){
        e.message = (e.body && e.body.saveUnknown) ? 'The save result is uncertain. Reload before trying again; do not resend it blindly.'
          : 'Someone else saved a newer revision' + (e.body && Number.isInteger(e.body.currentRevision) ? ' (' + e.body.currentRevision + ')' : '') + '. Reload, then make your change again.';
      }
      throw e;
    });
  }

  /* ---------- Darktrace email (Hub darktrace-email-routes.js) ---------- */
  // DARKTRACE-EMAIL 2026-10-14. The Hub answers /config only to a Hub super admin and audits every save and test.
  // Tokens are write-only: the Hub returns only whether each one is saved.
  var DT = '/api/sentinel/darktrace-email/config';
  function dtRender(d){
    var c = d.config || {}, r = d.last_run;
    var tok = function(set, which){ return set ? 'A ' + which + ' token is saved; it is never sent back to the browser. Leave blank to keep it.' : 'No ' + which + ' token is saved.'; };
    var cfg =
      '<div class="sf-grid">' +
      field({ kind: 'check', k: 'enabled', l: 'Scheduled pull enabled', v: !!c.enabled, t: 'bool', h: 'Off: the scheduler does not pull. The data already pulled stays.' }) +
      field({ kind: 'text', k: 'host', l: 'Darktrace host', v: c.host, t: 'trim', ml: 253, ph: 'azeus1-30575-01.cloud.darktrace.com', h: 'Host name only, no https:// and no path.' }) +
      field({ kind: 'num', k: 'cadence_min', l: 'Pull interval (minutes)', v: c.cadence_min, min: 15, max: 1440, req: true, t: 'int', h: '15 to 1440.' }) +
      '</div><div class="sf-grid">' +
      field({ kind: 'pw', k: 'public_token', l: 'Public token', v: '', ml: 200, ph: 'Leave blank to keep the saved token', h: esc(tok(c.public_token_set, 'public')) }) +
      field({ kind: 'check', k: '__clear_public', l: 'Clear the saved public token', v: false }) +
      field({ kind: 'pw', k: 'private_token', l: 'Private token', v: '', ml: 200, ph: 'Leave blank to keep the saved token', h: esc(tok(c.private_token_set, 'private')) }) +
      field({ kind: 'check', k: '__clear_private', l: 'Clear the saved private token', v: false }) +
      '</div>' +
      '<div class="sf-foot"><button type="button" class="btn" data-sf-dttest' + (d.configured ? '' : ' disabled') + '>Test connection</button>' +
      '<span class="hint">' + (d.configured ? 'Uses the saved host and tokens, not unsaved edits: one read of threat counts and one email search, last hour.' : 'Save the host and both tokens first.') + '</span></div>' +
      '<div data-sf-dtres></div>';
    var meta = c.updated_at ? 'saved ' + esc(when(c.updated_at)) + (c.updated_by ? ' by ' + esc(c.updated_by) : '') : 'never saved';
    var n = function(v){ return v == null ? '—' : esc(v); };
    var run = r
      ? '<div class="sf-facts">' +
        '<div><span>State</span><b>' + esc(r.state || 'unknown') + '</b></div>' +
        '<div><span>Started · finished</span><b>' + esc(when(r.started_at)) + ' · ' + (r.finished_at ? esc(when(r.finished_at)) : 'not finished') + '</b></div>' +
        '<div><span>Held · critical · threats, 7 days</span><b>' + [r.held_7d, r.critical_7d, r.threats_7d].map(n).join(' · ') + '</b></div>' +
        '<div><span>Messages · recipients · pages</span><b>' + [r.messages, r.rcpts, r.pages].map(n).join(' · ') + '</b></div></div>' +
        (r.note ? '<p class="sf-dim">' + esc(r.note) + '</p>' : '')
      : '<p class="sf-dim">No pull has run yet.</p>';
    return '<section class="card" data-sf-ed="dt"><div class="card-h"><h3>Darktrace /EMAIL connection</h3><span class="meta">Hub table dt_email_config · ' + meta + '</span></div>' +
           '<div class="card-b">' + cfg + '</div>' + foot('dt') + '</section>' +
           '<section class="card"><div class="card-h"><h3>Last pull</h3><span class="meta">read-only · ' + (d.configured ? 'configured' : 'not configured') + '</span></div>' +
           '<div class="card-b">' + run + '</div></section>';
  }
  function dtSave(ed){
    var sent = {};
    changed(ed).forEach(function(el){
      var k = el.dataset.k;
      if(k === 'public_token' || k === 'private_token' || k === '__clear_public' || k === '__clear_private') return;
      sent[k] = typed(el);
    });
    [['public_token', '__clear_public'], ['private_token', '__clear_private']].forEach(function(p){
      var tok = ed.querySelector('[data-k="' + p[0] + '"]'), clr = ed.querySelector('[data-k="' + p[1] + '"]');
      if(clr.checked) sent[p[0]] = '';
      else if(tok.value.trim()) sent[p[0]] = tok.value.trim();
    });
    if(!Object.keys(sent).length) return Promise.resolve();
    return api('PUT', DT, sent).then(function(){ return reread('darktrace-email'); }).then(function(d){
      var back = d.config || {}, missed = Object.keys(sent).filter(function(k){
        if(k === 'public_token' || k === 'private_token') return !!back[k + '_set'] !== (sent[k] !== '');
        if(k === 'host') return String(back.host || '') !== String(sent.host).toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
        if(k === 'enabled') return !!back.enabled !== !!sent.enabled;
        return String(back[k]) !== String(sent[k]);
      });
      if(missed.length) throw new Error('the Hub answered OK but reading back shows these did not change: ' + missed.join(', ') + '.');
      return 'Saved ' + Object.keys(sent).length + ' setting' + (Object.keys(sent).length === 1 ? '' : 's') + '; read back from the Hub.';
    });
  }
  function dtTest(ed, tab){
    var out = ed.querySelector('[data-sf-dtres]');
    busy(ed, true);
    msg(tab, 'Testing the connection…');
    out.innerHTML = '';
    var line = function(name, s){
      return '<li><b>' + esc(name) + ':</b> ' + (s.ok ? 'answered' : 'failed' + (s.status ? ' (HTTP ' + esc(s.status) + ')' : '') + (s.error ? ': ' + esc(s.error) : '')) + ' · ' + esc(s.ms) + ' ms</li>';
    };
    api('POST', DT + '/test', {}).then(function(j){
      if(document.contains(ed)) busy(ed, false);
      out.innerHTML = '<div class="note' + (j.passed ? '' : ' warn') + '">' + (j.passed ? INFO_SVG : WARN_SVG) + '<div><b>' + (j.passed ? 'Connection test passed.' : 'Connection test failed.') + '</b>' +
        '<ul>' + line('Threat counts (GET)', j.get || {}) + line('Email search (POST, read-only)', j.search || {}) + '</ul></div></div>';
      msg(tab, j.passed ? 'Connection test passed; recorded in the Hub audit.' : 'Connection test failed; recorded in the Hub audit.', j.passed ? 'ok' : 'err');
    }, function(e){
      if(document.contains(ed)) busy(ed, false);
      msg(tab, '<b>Test not run.</b> ' + esc(e.message), 'err');
    });
  }

  /* ---------- AI Governance <-> Access Portal sync (Hub ai-governance-portal-routes.js) ---------- */
  // AI-GOVERNANCE PORTAL SYNC 2026-10-15. Hourly: pull approved AIA intake from the Access Portal, push the
  // at-a-glance summary back. The Hub answers only to a Hub super admin and audits every save and run.
  // The Portal service token is write-only: the Hub returns only whether one is saved.
  var AP = '/api/zscaler/governance/portal-sync/config';
  function apStep(name, s){
    var det = s.detail || {}, facts;
    if(name === 'pull') facts = det.total == null ? '' : det.total + ' requests held · ' + det.approved + ' approved · last run +' + (det.added || []).length + ' new, ' + (det.changed || []).length + ' changed';
    else facts = det.status ? det.status.apps + ' apps · ' + det.attention + ' attention · ' + det.due_soon + ' due soon · ' + det.recent + ' recent · ' + det.bytes + ' bytes' : '';
    return '<div><span>' + (name === 'pull' ? 'Pull (AIA intake → Hub)' : 'Push (summary → Portal)') + '</span><b>' +
      (s.at ? esc(s.status || 'unknown') + ' · ' + esc(when(s.at)) : 'not run yet') + '</b>' +
      (s.error ? '<span class="sf-dim">' + esc(s.error) + '</span>' : facts ? '<span class="sf-dim">' + esc(facts) + '</span>' : '') + '</div>';
  }
  function apRender(d){
    var c = d.config || {}, sc = d.schedule || {};
    var cfg =
      '<div class="sf-grid">' +
      field({ kind: 'check', k: 'enabled', l: 'Hourly sync enabled', v: !!c.enabled, t: 'bool', h: 'Off: the worker does not pull or push. Intake already pulled stays; Portal marks the summary stale after 2 hours.' }) +
      '</div><div class="sf-grid">' +
      field({ kind: 'pw', k: 'token', l: 'Portal service token', v: '', ml: 200, ph: 'Leave blank to keep the saved token',
        h: esc(c.token_set ? 'A token is saved; it is never sent back to the browser. Leave blank to keep it.' : 'No token is saved. The Access Portal administrator issues it (Approver console → AI Governance → Integration).') }) +
      field({ kind: 'check', k: '__clear_token', l: 'Clear the saved token', v: false }) +
      '</div>' +
      '<div class="sf-foot"><button type="button" class="btn" data-sf-aprun' + (d.configured ? '' : ' disabled') + '>Run now</button>' +
      '<span class="hint">' + (d.configured ? 'Uses the saved token, not unsaved edits: pulls the AIA feed, then pushes the summary. Runs even when the hourly sync is off.' : 'Save the token first.') + '</span></div>' +
      '<div data-sf-apres></div>';
    var meta = c.saved_at ? 'saved ' + esc(when(c.saved_at)) + (c.saved_by ? ' by ' + esc(c.saved_by) : '') : 'never saved';
    var st = '<div class="sf-facts">' + apStep('pull', d.pull || {}) + apStep('push', d.push || {}) +
      '<div><span>Last run · next scheduled</span><b>' + (sc.last_run_at ? esc(when(sc.last_run_at)) + (sc.last_run_by ? ' by ' + esc(sc.last_run_by) : '') : 'never') + ' · ' +
      (c.enabled ? (sc.next_run_at ? esc(when(sc.next_run_at)) : 'next worker minute') : 'off') + '</b></div></div>' +
      '<p class="sf-dim">Portal on this host: <span class="mono">' + esc((d.endpoint || {}).origin || '') + '</span>. The pull reads every AIA request since 2026-01-01 each hour and keeps the request id, status, tool, purpose, requester name and department only.</p>';
    return '<section class="card" data-sf-ed="ap"><div class="card-h"><h3>Access Portal connection</h3><span class="meta">Hub table ai_governance_portal_sync · ' + meta + '</span></div>' +
           '<div class="card-b">' + cfg + '</div>' + foot('ap') + '</section>' +
           '<section class="card"><div class="card-h"><h3>Last sync</h3><span class="meta">read-only · ' + (d.configured ? 'configured' : 'not configured') + '</span></div>' +
           '<div class="card-b">' + st + '</div></section>';
  }
  function apSave(ed){
    var sent = {}, en = ed.querySelector('[data-k="enabled"]'), tok = ed.querySelector('[data-k="token"]'), clr = ed.querySelector('[data-k="__clear_token"]');
    if(String(en.checked) !== en.dataset.o) sent.enabled = en.checked;
    if(clr.checked) sent.token = '';
    else if(tok.value.trim()) sent.token = tok.value.trim();
    if(!Object.keys(sent).length) return Promise.resolve();
    return api('PUT', AP, sent).then(function(){ return reread('aigov-portal'); }).then(function(d){
      var back = d.config || {}, missed = Object.keys(sent).filter(function(k){
        if(k === 'token') return !!back.token_set !== (sent.token !== '');
        return !!back.enabled !== !!sent.enabled;
      });
      if(missed.length) throw new Error('the Hub answered OK but reading back shows these did not change: ' + missed.join(', ') + '.');
      return 'Saved ' + Object.keys(sent).length + ' setting' + (Object.keys(sent).length === 1 ? '' : 's') + '; read back from the Hub.' + (back.enabled && back.token_set ? ' The worker runs it within a minute.' : '');
    });
  }
  function apRun(ed, tab){
    var out = ed.querySelector('[data-sf-apres]');
    busy(ed, true);
    msg(tab, 'Running the Portal sync…');
    out.innerHTML = '';
    var line = function(name, s){ return '<li><b>' + esc(name) + ':</b> ' + (s && s.ok ? 'done' : 'failed' + (s && s.error ? ': ' + esc(s.error) : '')) + '</li>'; };
    api('POST', AP + '/run', {}).then(function(j){
      if(document.contains(ed)) busy(ed, false);
      var r = j.run || {};
      out.innerHTML = '<div class="note' + (j.passed ? '' : ' warn') + '">' + (j.passed ? INFO_SVG : WARN_SVG) + '<div><b>' + (j.passed ? 'Sync ran.' : 'Sync ran with errors.') + '</b>' +
        '<ul>' + line('Pull AIA intake', r.pull) + line('Push summary', r.push) + '</ul></div></div>';
      msg(tab, (j.passed ? 'Sync ran' : 'Sync ran with errors') + '; recorded in the Hub audit.', j.passed ? 'ok' : 'err');
      ST[tab].data = j; var held = out.innerHTML; draw(tab, true); var o2 = q(tab, '[data-sf-apres]'); if(o2) o2.innerHTML = held;
    }, function(e){
      if(document.contains(ed)) busy(ed, false);
      msg(tab, '<b>Not run.</b> ' + esc(e.message), 'err');
    });
  }

  /* ---------- Onboarding workflow mail (Hub workflow-settings-routes.js) ---------- */
  // ONBOARDING WORKFLOW 2026-10-21. Mail mode and the links and addresses the onboarding templates fill in.
  // 'log' records every message in the Hub mail log and sends nothing; 'live' sends through Graph.
  // The Hub answers only to a Hub super admin and audits every save.
  var WF = '/api/workflow/settings/config';
  var WF_KEYS = ['mail_mode', 'app_url', 'documentation_link', 'helpdesk', 'distribution_list', 'facility_notification_email'];
  function wfRender(d){
    var v = d.values || {};
    var meta = d.saved_at ? 'saved ' + esc(when(d.saved_at)) + (d.saved_by ? ' by ' + esc(d.saved_by) : '') : 'never saved';
    var live = v.mail_mode === 'live';
    return '<section class="card" data-sf-ed="wf"><div class="card-h"><h3>Mail and links</h3><span class="meta">Hub table wf_setting · ' + meta + '</span></div>' +
      '<div class="card-b">' +
      (live ? '' : '<div class="note">' + INFO_SVG + '<div><b>Log only.</b> Every onboarding and offboarding message, including the new hire’s temporary password message, is written to the mail log on the Onboarding page and nothing is sent.</div></div>') +
      '<div class="sf-grid">' +
      field({ kind: 'select', k: 'mail_mode', l: 'Mail mode', v: live ? 'live' : 'log', opts: [['log', 'Log only (send nothing)'], ['live', 'Live (send through Microsoft Graph)']],
        h: 'Live sends real email to approvers, the new hire and the distribution list. Switch back to Log only at any time.' }) +
      '</div><div class="sf-grid">' +
      field({ k: 'app_url', l: 'App link in emails', v: v.app_url || '', t: 'trim', ml: 500, ph: 'https://dev-corpit.nrpi.local/onboarding.html', wide: true,
        h: 'The link approval emails open. https only. Blank leaves the link out.' }) +
      field({ k: 'documentation_link', l: 'How-to link', v: v.documentation_link || '', t: 'trim', ml: 500, ph: 'https://…', wide: true,
        h: 'Shown on the Onboarding page and in emails as the how-to guide. https only.' }) +
      field({ k: 'helpdesk', l: 'Helpdesk address', v: v.helpdesk || '', t: 'trim', ml: 1000, ph: 'helpdesk@…', wide: true,
        h: 'Copied on IT steps. Separate several addresses with ;' }) +
      field({ k: 'distribution_list', l: 'Distribution list', v: v.distribution_list || '', t: 'trim', ml: 1000, ph: 'list@…', wide: true,
        h: 'Receives the completed-request notices. Separate several addresses with ;' }) +
      field({ k: 'facility_notification_email', l: 'Facilities shipment recipient', v: v.facility_notification_email || '', t: 'trim', ml: 190, ph: 'facilities@…', wide: true,
        h: 'One email address for shipment-required notifications. Leave blank until the Facilities mailbox is ready; an unaddressed notification is logged as failed.' }) +
      '</div></div>' + foot('wf') + '</section>';
  }
  function wfSave(ed){
    var sent = {};
    changed(ed).forEach(function(el){ sent[el.dataset.k] = el.value.trim(); });
    if(!Object.keys(sent).length) return Promise.resolve();
    if(sent.mail_mode === 'live' && !confirm('Switch onboarding mail to Live? Approvers, new hires and the distribution list will get real email from the next action on.')) return null;
    return api('PUT', WF, sent).then(function(){ return reread('onboarding-mail'); }).then(function(d){
      var back = d.values || {}, missed = Object.keys(sent).filter(function(k){
        var a = String(back[k] == null ? '' : back[k]), b = sent[k];
        if(k === 'helpdesk' || k === 'distribution_list') { a = a.replace(/\s/g, ''); b = b.split(/[;,]/).map(function(x){ return x.trim(); }).filter(Boolean).join(';'); }
        return a !== b;
      });
      if(missed.length) throw new Error('the Hub answered OK but reading back shows these did not change: ' + missed.join(', ') + '.');
      return 'Saved ' + Object.keys(sent).length + ' setting' + (Object.keys(sent).length === 1 ? '' : 's') + '; read back from the Hub. Mail mode: ' + (back.mail_mode === 'live' ? 'Live' : 'Log only') + '.';
    });
  }

  /* ---------- tab definitions ---------- */
  var DEF = {
    certs: {
      label: 'Certificates', what: 'Certificate Watchtower settings',
      lede: 'Certificate Watchtower’s alert thresholds, retention and PRTG push, stored in the Hub. Anyone with read on Certificate Watchtower sees them; the Hub saves a change only from someone with admin on that page (<span class="mono">cert-watchtower</span>).',
      guard: ' Saving needs admin on the Hub page Certificate Watchtower (<span class="mono">cert-watchtower</span>).',
      links: [[hubUrl('/cert-watchtower.html'), 'Open Certificate Watchtower']],
      probe: function(){ return api('GET', '/api/cert-config').then(function(j){ return !!(j && j.config && typeof j.config === 'object'); }); },
      load: function(){ return Promise.all([api('GET', '/api/cert-config'), api('GET', '/api/prtg/config')]).then(function(r){ return { cfg: r[0].config || {}, prtg: r[1].config || {} }; }); },
      render: certsRender, save: certsSave,
    },
    signin: {
      label: 'Sign-In Watch', what: 'Sign-In Watch settings',
      lede: 'The watchlist, trusted networks and alert channels Sign-In Watch uses. The Hub accepts reads and changes only from a Hub super admin (<span class="mono">SaaS-ITH-SA</span>) and records every use.',
      guard: ' Sign-In Watch is Hub super admin only (<span class="mono">SaaS-ITH-SA</span>).',
      links: [[hubUrl('/signin-watch.html'), 'Open Sign-In Watch']],
      probe: function(){ return api('GET', SW + '/watchlist').then(function(j){ return !!(j && j.ok === true && Array.isArray(j.rows)); }); },
      load: function(){ return Promise.all([api('GET', SW + '/watchlist'), api('GET', SW + '/networks'), api('GET', SW + '/channels')])
        .then(function(r){ return { watch: r[0].rows || [], nets: r[1].rows || [], chans: r[2].rows || [] }; }); },
      render: signinRender, save: signinSave, del: signinDelete,
    },
    digest: {
      label: 'Identity digest', what: 'identity digest settings',
      lede: 'The weekly identity-project digest and the sensitive-group blocklist, stored in the Hub. Anyone with read on <span class="mono">user-projects</span> sees them; the Hub saves only from admin on <span class="mono">user-projects</span> and audits each change.',
      guard: ' Saving needs admin on the Hub page <span class="mono">user-projects</span>.',
      links: [[hubUrl('/identity-diag.html'), 'Open Identity diagnostics']],
      probe: function(){ return api('GET', '/api/user-project/settings').then(function(j){ return !!(j && j.settings && typeof j.settings === 'object'); }); },
      load: function(){ return api('GET', '/api/user-project/settings'); },
      render: digestRender, save: digestSave,
    },
    'zscaler-ai': {
      label: 'Zscaler AI report', what: 'Zscaler AI report settings',
      lede: 'The scheduled Gen AI usage email and the AI watchlist from Zscaler Command Center, stored in the Hub. Anyone with read on <span class="mono">zscaler-diag</span> sees them; the Hub saves only from admin on <span class="mono">zscaler-diag</span>.',
      guard: ' Saving needs admin on the Hub page <span class="mono">zscaler-diag</span>.',
      links: [[hubUrl('/zscaler-command-center.html'), 'Open Zscaler Command Center']],
      probe: function(){
        return api('GET', ZB + '/report-config').then(function(j){ return !!(j && typeof j === 'object'); },
          function(e){ if(e.status === 404 && e.body) return true; throw e; });
      },
      load: function(){
        return Promise.all([
          api('GET', ZB + '/report-config').then(function(j){ return { row: j }; }, function(e){ if(e.status === 404 && e.body) return { row: null, why: e.message }; throw e; }),
          api('GET', ZB + '/watchlist'),
        ]).then(function(r){ return { report: r[0].row, reportMissing: r[0].why, watch: r[1].rows || [] }; });
      },
      render: zscalerRender, after: zscalerAfter, save: zscalerSave,
    },
    launchpad: {
      label: 'Launch pad', what: 'launch pad settings',
      lede: 'The launch pad’s CAB gate, hotfix, gate review, Verify & close and test-evidence settings (itam dev only). The launch pad checks and audits every change, and accepts it only from a Hub super admin (<span class="mono">SaaS-ITH-SA</span>). Connecting SDP and running the SDP check stay on the launch pad.',
      guard: ' The launch pad accepts these only from a Hub super admin (<span class="mono">SaaS-ITH-SA</span>).',
      links: [['https://dev-releases.nrpi.local/?view=settings', 'Open the launch pad']],
      probe: function(){ return api('GET', '/__dev/api/cab/settings', undefined, CONSOLE_HDR).then(function(j){ return !!(j && Array.isArray(j.registry) && j.values); }); },
      load: function(){ return api('GET', '/__dev/api/cab/settings', undefined, CONSOLE_HDR); },
      render: launchpadRender, save: launchpadSave,
    },
    backup: {
      label: 'Backup & HA', what: 'backup and availability settings',
      lede: 'Backup schedule, retention and maintenance, and the A/B availability desired settings, from the backup console (itam dev only). The backup console decides who may read and change them. Running backups, restores and pruning stay there.',
      guard: ' The backup console accepts these only from a Hub super admin (<span class="mono">SaaS-ITH-SA</span>).',
      links: [['https://backup.nrpi.local/', 'Open the backup console'], ['https://backup.nrpi.local/availability/', 'Open availability']],
      probe: function(){ return api('GET', '/bkp-api/settings', undefined, CONSOLE_HDR).then(function(j){ return !!(j && j.registry && typeof j.registry === 'object' && j.values); }); },
      load: function(){
        return Promise.all([
          api('GET', '/bkp-api/settings', undefined, CONSOLE_HDR),
          api('GET', '/bkp-api/ha/settings', undefined, CONSOLE_HDR).then(function(j){ return { doc: j }; }, function(e){ return { err: e }; }),
        ]).then(function(r){
          var doc = r[1].doc;
          if(doc && !(doc.desired && doc.desired.values && Number.isInteger(doc.desired.revision))) { r[1] = { err: new Error('The availability settings came back in a shape this page does not know.') }; doc = null; }
          return { settings: r[0], ha: doc || null, haErr: r[1].err };
        });
      },
      render: bkpRender, save: backupSave,
    },
    'darktrace-email': {
      label: 'Darktrace email', what: 'Darktrace email settings',
      lede: 'The Darktrace /EMAIL connection the Hub pulls held mail, threat counts, data-loss senders, anomaly mailboxes and audit events with, stored in the Hub. The Hub accepts reads and changes only from a Hub super admin (<span class="mono">SaaS-ITH-SA</span>) and audits every save and test. The pulled data is shown only to SaaS-ITH-HD.',
      guard: ' Darktrace email settings are Hub super admin only (<span class="mono">SaaS-ITH-SA</span>).',
      links: [],
      probe: function(){ return api('GET', DT).then(function(j){ return !!(j && j.ok === true && j.config && typeof j.config === 'object'); }); },
      load: function(){ return api('GET', DT); },
      render: dtRender, save: dtSave,
    },
    'aigov-portal': {
      label: 'AI Governance sync', what: 'AI Governance Portal sync settings',
      lede: 'The hourly exchange between AI Governance and the Access Portal: approved AI intake (AIA) requests come in, the governance at-a-glance summary goes out. Stored in the Hub. The Hub accepts reads and changes only from a Hub super admin (<span class="mono">SaaS-ITH-SA</span>) and audits every save and run.',
      guard: ' AI Governance sync settings are Hub super admin only (<span class="mono">SaaS-ITH-SA</span>).',
      links: [[hubUrl('/ai-governance.html'), 'Open AI Governance']],
      probe: function(){ return api('GET', AP).then(function(j){ return !!(j && j.ok === true && j.config && typeof j.config === 'object'); }); },
      load: function(){ return api('GET', AP); },
      render: apRender, save: apSave,
    },
    'onboarding-mail': {
      label: 'Onboarding mail', what: 'onboarding workflow mail settings',
      lede: 'Whether the Onboarding &amp; Offboarding workflow sends real email or only logs it, and the links and addresses its emails fill in. Stored in the Hub. The Hub accepts reads and changes only from a Hub super admin (<span class="mono">SaaS-ITH-SA</span>) and audits every save. Choice lists and email templates are edited on the Onboarding page.',
      guard: ' Onboarding mail settings are Hub super admin only (<span class="mono">SaaS-ITH-SA</span>).',
      links: [[hubUrl('/onboarding.html'), 'Open Onboarding']],
      probe: function(){ return api('GET', WF).then(function(j){ return !!(j && j.ok === true && j.values && typeof j.values === 'object'); }); },
      load: function(){ return api('GET', WF); },
      render: wfRender, save: wfSave,
    },
  };
  DIRTY.digest = null;

  /* ---------- the directory and command search follow the tabs that answered ---------- */
  // On itam the launch pad and backup rows in the Settings directory point at the in-place tab once it
  // answers; elsewhere (prod) the rows keep their links. The catalog file itself never changes per host.
  var CATALOG_ROWS = { launchpad: 'Release console administration', backup: 'A/B availability and backup health' };
  var CATALOG_OWNER = { launchpad: 'Launch pad settings edited here; the rest on the launch pad', backup: 'Backup and availability settings edited here' };
  function pointCatalog(tab){
    var title = CATALOG_ROWS[tab], cat = window.CorpITHealthCatalog;
    if(!title || !cat || !cat.settings) return;
    cat.settings.forEach(function(r){ if(r[1] === title){ r[3] = 'subadmin'; r[4] = '/console#settings/' + tab; r[5] = CATALOG_OWNER[tab]; } });
    [window.CONSOLE_SETTINGS_SEARCH, window.CMDK_ITEMS].forEach(function(list){
      (list || []).forEach(function(it){ if(it && it.t === title && it.g === 'Settings') it.url = '#settings/' + tab; });
    });
    var qy = document.getElementById('settings-query');
    if(qy) qy.dispatchEvent(new Event('input', { bubbles: true }));
  }

  var probed = false;
  function probeAll(){
    if(probed) return;
    probed = true;
    Promise.all(ORDER.map(function(tab){
      return DEF[tab].probe().then(function(ok){ ST[tab].probe = ok ? 'ok' : 'no'; }, function(e){ ST[tab].probe = e.denied || e.fatal || e.status===404 || e.status===405 ? 'no' : 'unavailable'; }).then(function(){
        if(ST[tab].probe !== 'ok' && ST[tab].probe !== 'unavailable') return;
        var b = tablist && tablist.querySelector('[data-tab="' + tab + '"]');
        if(b) b.hidden = false;
        if(tablist) tablist.hidden = false;
        pointCatalog(tab);
        syncSwitcher();
      });
    }));
  }

  function curTab(){ var m = /^#settings\/([a-z0-9-]+)/.exec(location.hash || ''); return m ? m[1] : null; }
  // console-hybrid.js rebuilds the breadcrumb workspace switcher on every route from a fixed list;
  // add the tabs that answered and select the open one.
  function syncSwitcher(){
    var sel = document.getElementById('hybrid-workspace');
    if(!sel || (document.body.dataset.hybridModule!=='settings' && !/^#?settings(\/|$)/.test(location.hash || ''))) return;
    var opts = sel.options, find = function(v){ return Array.prototype.filter.call(opts, function(o){ return o.value === v; })[0]; };
    var anchor = find('settings');
    if(!anchor) return;
    var after = anchor;
    ORDER.forEach(function(tab){
      if(ST[tab].probe !== 'ok' && ST[tab].probe !== 'unavailable') return;
      var o = find('settings/' + tab);
      if(!o){ o = new Option(DEF[tab].label, 'settings/' + tab); sel.add(o, after.nextSibling); }
      after = o;
    });
    var t = curTab();
    if(t && DEF[t] && find('settings/' + t)) sel.value = 'settings/' + t;
  }

  function onRoute(){
    syncSwitcher();
    if(view.hidden && document.body.dataset.hybridModule!=='settings') return;
    probeAll();
    if(view.hidden) return;
    var t = curTab();
    if(t && DEF[t]){
      var p = view.querySelector('[data-tabpanel="' + t + '"]');
      if(p && !p.hidden) openTab(t);
    }
  }

  /* ---------- events, scoped to the settings view ---------- */
  function onEdit(e){
    var ed = e.target.closest && e.target.closest('[data-sf-ed]');
    if(!ed || !view.contains(ed)) return;
    if(ed.dataset.sfEd === 'zrep' && e.target.dataset.k === 'frequency') zscalerAfter(ed.parentNode);
    refreshEd(ed);
    var bx = ed.closest('[data-sf]');
    if(bx) msg(bx.dataset.sf, '');
  }
  view.addEventListener('input', onEdit);
  view.addEventListener('change', onEdit);
  view.addEventListener('click', function(e){
    var bx = e.target.closest('[data-sf]');
    if(!bx) return;
    var tab = bx.dataset.sf, ed;
    if(bx.querySelector('.is-busy')){msg(tab, 'A save is in progress. Wait for its result before another action.');return;}
    if(e.target.closest('[data-sf-reload]')){
      if(anyDirty(bx) && !confirm('Reloading discards your unsaved changes here. Continue?')) return;
      msg(tab, '');
      load(tab).then(function(){ if(ST[tab].loaded) msg(tab, 'Reloaded.', 'ok'); });
      return;
    }
    var addR = e.target.closest('[data-sf-addrecip]');
    if(addR){
      ed = addR.closest('[data-sf-ed]');
      var wrap = ed.querySelector('[data-sf-recips]');
      wrap.insertAdjacentHTML('beforeend', haRecipient({ name: '', email: '' }, false));
      wrap.lastElementChild.querySelector('input').focus();
      refreshEd(ed); return;
    }
    var delR = e.target.closest('[data-sf-delrecip]');
    if(delR){
      ed = delR.closest('[data-sf-ed]');
      delR.closest('.sf-recip').remove();
      refreshEd(ed); return;
    }
    var dtt = e.target.closest('[data-sf-dttest]');
    if(dtt){ dtTest(dtt.closest('[data-sf-ed]'), tab); return; }
    var apr = e.target.closest('[data-sf-aprun]');
    if(apr){ apRun(apr.closest('[data-sf-ed]'), tab); return; }
    var dis = e.target.closest('[data-sf-discard]');
    if(dis){ resetEd(dis.closest('[data-sf-ed]')); msg(tab, ''); return; }
    var sv = e.target.closest('[data-sf-save]'), del = e.target.closest('[data-sf-delete]');
    if(!sv && !del) return;
    ed = (sv || del).closest('[data-sf-ed]');
    if(sv){
      var bad = invalid(ed);
      if(bad){ msg(tab, '<b>Not saved.</b> ' + esc(bad), 'err'); return; }
    }
    var p = sv ? DEF[tab].save(ed) : DEF[tab].del(ed);
    if(!p) return;                                         // the person cancelled a confirm
    busy(ed, true);
    msg(tab, 'Saving…');
    p.then(function(text){
      if(document.contains(ed)) busy(ed, false);
      msg(tab, esc(text || 'Saved.'), 'ok');
    }, function(err){
      if(document.contains(ed)) busy(ed, false);
      msg(tab, saveErr(tab, err), 'err');
    });
  });
  window.addEventListener('beforeunload', function(e){
    if(anyDirty()){ e.preventDefault(); e.returnValue = ''; }
  });
  window.addEventListener('console-route', onRoute);
  window.addEventListener('hashchange', onRoute);
  if(document.readyState === 'loading') document.addEventListener('DOMContentLoaded', onRoute); else onRoute();
})();
