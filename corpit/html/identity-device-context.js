/* Shared person/device context. Stage 1 uses the existing read-only discovery response. */
(function () {
  'use strict';
  var state = { query: '', payload: null, key: '', wanted: '', notice: '', restoring: false, pendingView: null, skipHash: '' };
  var detail = {key:'',data:null,status:'idle',error:'',controller:null,sequence:0};
  var initial = new URL(location.href);
  state.wanted = initial.searchParams.get('device') || '';
  state.pendingView = initial.searchParams.get('view') || null;
  var bootRoute = !!initial.searchParams.get('q') || /^#user\//.test(initial.hash);
  function esc(v) { return window.x ? x(v == null ? '' : String(v)) : String(v || '').replace(/[&<>"']/g, function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];}); }
  function groups() { return state.payload && Array.isArray(state.payload.deviceGroups) ? state.payload.deviceGroups : []; }
  function selected() { return groups().find(function(g){ return g.deviceKey === state.key || (state.key && (g.sourceRefs || []).some(function(r){return r.recordKey === state.key;})); }) || null; }
  function matches(q) {
    var v = String(q || '').trim().toLowerCase();
    var aliases = window._D ? [_D.samAccountName, _D.email, _D.upn] : [state.query, window._curQuery];
    return !!v && aliases
      .some(function(k){return k && String(k).toLowerCase() === v;});
  }
  function route(mode) {
    if (state.restoring || !window._D) return;
    var u = new URL(location.href);
    u.searchParams.set('q', _D.samAccountName || state.query);
    u.searchParams.set('view', _page);
    if (state.key || state.wanted) u.searchParams.set('device', state.key || state.wanted); else u.searchParams.delete('device');
    u.hash = _page === 'detail' ? 'user/' + encodeURIComponent(_D.samAccountName || state.query) : _page;
    if (u.href !== location.href) history[mode === 'push' ? 'pushState' : 'replaceState'](null, '', u);
  }
  function beginPerson(q) {
    resetDetail();
    if(window.IdentityDeviceNetwork)IdentityDeviceNetwork.beginPerson(q,state.restoring||bootRoute);
    var same = matches(q);
    if (!state.restoring && !bootRoute) {
      var u = new URL(location.href); u.searchParams.set('q', q); u.searchParams.set('view','detail'); u.searchParams.delete('device'); u.hash = 'user/' + encodeURIComponent(q);
      if (u.href !== location.href) history.pushState(null,'',u);
    }
    if (!same) { state.key = ''; if (!state.restoring && !bootRoute) state.wanted = ''; }
    state.query = q; state.payload = null; state.notice = ''; render();
  }
  function loadedPerson() {
    if (state.pendingView) {
      var view = state.pendingView; state.pendingView = null;
      if (typeof PAGE_TITLES !== 'undefined' && Object.prototype.hasOwnProperty.call(PAGE_TITLES,view)) go(view);
      else state.notice = 'The requested view is unavailable. Open a workspace from the menu.';
    }
    if(window.IdentityDeviceNetwork)IdentityDeviceNetwork.loadedPerson();
    bootRoute = false; state.restoring = false; route('replace'); render();
  }
  function accept(payload,q,generation) {
    if (!window._D || !matches(q) || (generation !== undefined && generation !== window._gen)) return false;
    state.payload = payload;
    if (payload && payload.__err) {
      state.wanted = state.wanted || state.key; state.key = ''; resetDetail();
      state.notice = 'Device inventory could not be read. Retry from Devices; the selected endpoint has not been verified.';
      route('replace'); render(); return true;
    }
    var wanted = state.wanted || state.key;
    if (wanted) {
      state.key = wanted;
      var found = selected();
      if (found) { state.key = found.deviceKey; state.notice = ''; }
      else { state.key = ''; resetDetail(); state.notice = (payload && payload.unavailable && payload.unavailable.length)
        ? 'The requested device could not be verified because inventory results are partial. Choose from the available records or retry.'
        : 'The requested device is no longer available for this person. Choose another device.'; }
    }
    state.wanted = ''; route('replace'); render(); ensureDetail(); return true;
  }
  function clear() { resetDetail(); if(window.IdentityDeviceNetwork)IdentityDeviceNetwork.clear(); state.query = ''; state.payload = null; state.key = ''; state.wanted = ''; state.notice = '';
    var u=new URL(location.href);['q','device','view'].forEach(function(k){u.searchParams.delete(k);});history.replaceState(null,'',u);
    render(); }
  function setSelected(key) {
    if (key && !groups().some(function(g){return g.deviceKey === key;})) return;
    if (state.key !== (key || '')) resetDetail();
    state.key = key || ''; state.wanted = ''; state.notice = ''; route('push'); render(); ensureDetail();
  }
  function choiceLabel(g) { return (g.deviceName || 'Unnamed device') + ' · ' + (g.model || g.type || '') + (g.match && g.match.status === 'ambiguous' ? ' · ambiguous serial' : ''); }
  function context() {
    var host = document.getElementById('identity-person-context'); if (!host) return;
    var old = document.getElementById('identity-selected-device'); if (old) old.remove();
    if (!window._D) return;
    var box = document.createElement('div'); box.id = 'identity-selected-device'; box.className = 'identity-selected-device';
    var list = groups();
    box.innerHTML = '<label for="identity-device-select">Selected device</label><div class="identity-device-controls"><select id="identity-device-select" class="env-select" aria-label="Selected device">'
      + '<option value="">' + (state.payload ? 'Choose a device…' : 'Reading assigned devices…') + '</option>'
      + list.filter(function(g){return g.deviceKey;}).map(function(g){return '<option value="'+esc(g.deviceKey)+'"'+(g.deviceKey===state.key?' selected':'')+'>'+esc(choiceLabel(g))+'</option>';}).join('')
      + '</select><button class="btn btn-ghost btn-sm" type="button" data-device-review>Review</button><button class="btn btn-ghost btn-sm" type="button" data-device-network>Network &amp; Access</button></div>';
    box.querySelector('select').disabled = !list.length;
    host.appendChild(box);
  }
  function pane() {
    var host = document.getElementById('identity-assigned-devices');
    if (!host) {
      var p = document.getElementById('pane'); if (!p) return;
      host = document.createElement('section'); host.id = 'identity-assigned-devices'; host.className = 'identity-assigned-devices'; host.setAttribute('aria-label','Assigned devices'); p.appendChild(host);
    }
    host.hidden = !window._D;
    if (host.hidden) { host.innerHTML = ''; return; }
    var list = groups();
    var body = !state.payload ? '<p class="pane-note">Reading assigned devices…</p>'
      : state.payload.__err ? '<p class="pane-note">Inventory unavailable. Retry from Devices.</p>'
      : !Array.isArray(state.payload.deviceGroups) ? '<p class="pane-note">Grouped device context is unavailable. The existing device lookup remains available.</p>'
      : !list.length ? '<p class="pane-note">'+(state.payload.unavailable && state.payload.unavailable.length ? 'No records returned; some sources were unavailable.' : 'No assigned device records returned.')+'</p>'
      : '<div class="identity-device-list">'+list.map(function(g){return '<button type="button" class="acct identity-device-choice'+(g.deviceKey && g.deviceKey===state.key?' sel':'')+'" data-device-key="'+esc(g.deviceKey || '')+'" aria-pressed="'+Boolean(g.deviceKey && g.deviceKey===state.key)+'"'+(!g.deviceKey?' disabled':'')+'><span class="acct-main"><span class="acct-n">'+esc(g.deviceName)+'</span><span class="acct-s">'+esc(g.model || g.type || 'Device')+'</span><span class="acct-s">'+esc(Array.from(new Set((g.records || []).map(function(r){return r.source;}))).join(' + '))+'</span>'+(g.match && ['ambiguous','unverified'].indexOf(g.match.status)>-1?'<span class="identity-device-match">'+esc(g.match.status==='ambiguous'?'Ambiguous serial · kept separate':'Match not verified · kept separate')+'</span>':'')+'</span></button>';}).join('')+'</div>';
    host.innerHTML = '<div class="pane-hd"><h2>Assigned devices</h2><span class="pane-count">'+(state.payload?list.length:'—')+'</span></div>'+body;
    if (state.payload && state.payload.unavailable && state.payload.unavailable.length) host.innerHTML += '<p class="pane-note">Partial inventory · '+esc(state.payload.unavailable.join(', '))+'</p>';
  }
  function panelHtml() {
    var g = selected();
    var body = state.notice ? '<div class="note warn" role="status">'+esc(state.notice)+'</div>' : '';
    if (!g) body += '<p class="ls">Choose an assigned device in the context panel or selected-device menu. Account checks remain scoped to the person.</p>';
    else {
      body += '<div class="facts">'+factRow('Device',esc(g.deviceName))+factRow('Model',esc(g.model || 'Not reported'))+factRow('Serial',esc(g.serial || 'Not reported'))
        +factRow('Match',esc(g.match.status==='confirmed'?'Unique serial and platform matched across sources':g.match.status==='ambiguous'?'Ambiguous serial; records kept separate':g.match.status==='unverified'?'Cross-source match not verified':'One source record'))+'</div>';
      body += detailHtml();
      body += '<div class="note">Source records below belong to the selected workspace entry. Account sign-ins and existing network checks remain person-scoped.</div>';
      body += table([{t:'Source'},{t:'Device / OS'},{t:'Compliance'},{t:'Last check-in'}],(g.records || []).map(function(r){return '<tr><td>'+esc(r.source)+'</td><td>'+esc(r.deviceName)+'<div class="ls">'+esc([r.os,r.osVersion].filter(Boolean).join(' '))+'</div></td><td>'+esc(r.compliance == null?'Not reported':r.compliance)+'</td><td>'+esc(r.lastCheckin || 'Not reported')+'</td></tr>';}),'No source records.');
      body += '<details class="support-evidence"><summary>Source identifiers</summary><div class="identity-device-identifiers">'+(g.sourceRefs || []).map(function(r){return '<p><strong>'+esc(r.sourceKey)+'</strong><br>Record: '+esc(r.recordKey || 'Not reported')+'<br>Inventory row: '+esc(r.rowId || 'Not reported')+'<br>Native ID: '+esc(r.nativeId || 'Not reported')+'</p>';}).join('')+'</div></details>';
    }
    if (state.payload && state.payload.groupingWarnings && state.payload.groupingWarnings.length) body += '<div class="note warn">'+esc(state.payload.groupingWarnings.join('; '))+'</div>';
    return panel('Device context',state.payload ? groups().length+' workspace entries · '+(state.payload.sourceRecordCount == null?'unknown':state.payload.sourceRecordCount)+' source records' : 'Select a person to read assigned devices.',body);
  }
  function placeholder(payload) {
    // A manually entered tool query can refer to another person; never attach selected-person evidence to it.
    if (!window._D || payload !== state.payload) return '';
    return '<div class="identity-device-panel">'+panelHtml()+'</div>';
  }
  function resetDetail() {
    if(detail.controller)detail.controller.abort();
    detail.sequence++; detail.key=''; detail.data=null; detail.status='idle'; detail.error=''; detail.controller=null;
  }
  async function ensureDetail() {
    var g=selected();
    if(!g || !window._D){resetDetail();return;}
    if(detail.key===g.deviceKey && detail.status!=='idle')return;
    resetDetail(); detail.key=g.deviceKey; detail.status='loading';
    var seq=detail.sequence, personGeneration=window._gen, key=g.deviceKey;
    var controller=new AbortController(); detail.controller=controller;
    var timeout=setTimeout(function(){controller.abort();},12000);
    render();
    try {
      var response=await fetch('/api/identity/device-detail?q='+encodeURIComponent(_D.samAccountName || state.query)+'&deviceKey='+encodeURIComponent(key),{signal:controller.signal,cache:'no-store'});
      var data=await response.json();
      if(seq!==detail.sequence || personGeneration!==window._gen || !selected() || selected().deviceKey!==key)return;
      if(!response.ok)throw Error(data.error || 'Device evidence request failed (HTTP '+response.status+').');
      if(!data || data.deviceKey!==key)throw Error('The returned evidence did not identify the selected device.');
      detail.data=data;detail.status='ready';
    } catch(e) {
      if(seq!==detail.sequence || personGeneration!==window._gen)return;
      detail.status='error';detail.error=e.name==='AbortError'?'Device evidence timed out. Retry when ready.':e.message;
    } finally {
      clearTimeout(timeout);
      if(seq===detail.sequence){detail.controller=null;render();if(window._page==='summary' && typeof renderSummaryTool==='function')renderSummaryTool();}
    }
  }
  function display(v) {return v==null || v===''?'Not reported':String(v);}
  function truth(v) {return v===true?'Yes':v===false?'No':'Unknown';}
  function registration(v) {return v==='1'?'Registered':v==='0'?'Unregistered':display(v);}
  function allowedLinks(d) {
    return (d.links || []).filter(function(link){try{var u=new URL(link.href,location.origin);return u.origin===location.origin && ['/IT_Inventory_App.html','/zscaler-command-center.html'].indexOf(u.pathname)>-1;}catch(e){return false;}});
  }
  function sectionHtml(title,section,columns,row) {
    if(!section)return '';
    var status=section.status || 'unavailable';
    var h='<h4 class="identity-evidence-heading">'+esc(title)+' <span class="ls">'+esc(status)+'</span></h4>';
    if(section.reason)h+='<p class="ls">'+esc(section.reason)+'</p>';
    (section.sources || []).filter(function(s){return ['unavailable','partial','denied'].indexOf(s.status)>-1;}).forEach(function(s){h+='<p class="note warn">'+esc(s.source)+': '+esc(s.status)+(s.reason?' · '+esc(s.reason):'')+'</p>';});
    if(section.records && section.records.length)h+=table(columns.map(function(c){return {t:c};}),section.records.map(row),'');
    else h+='<p class="ls">'+esc(status==='denied'?'Read permission required.':status==='unavailable'?'This source could not be read.':'No selected-device evidence reported.')+'</p>';
    return h;
  }
  function detailHtml() {
    if(detail.status==='idle' || detail.status==='loading')return '<p class="note" role="status">Reading selected-device evidence…</p>';
    if(detail.status==='error')return '<div class="note warn" role="status">'+esc(detail.error)+' <button type="button" class="btn btn-ghost btn-sm" data-device-retry>Retry device evidence</button></div>';
    var d=detail.data;if(!d)return '';
    var h='<div class="identity-device-evidence"><p class="ls">Evidence read: '+esc(d.readAt)+' · Source observation dates are shown below.</p>';
    h+=sectionHtml('Inventory',d.inventory,['Source / observation','Owner / ownership','Compliance / check-in'],function(r){return '<tr><td>'+esc(r.source)+'<div class="ls">'+esc(display(r.observedAt))+'</div></td><td>'+esc(display(r.owner))+'<div class="ls">'+esc(display(r.ownership))+'</div></td><td>'+esc(display(r.compliance))+'<div class="ls">'+esc(display(r.lastCheckin))+'</div></td></tr>';});
    h+=sectionHtml('Encryption',d.encryption,['Source / observation','Encrypted','Escrow status'],function(r){return '<tr><td>'+esc(r.source)+(r.preferred?' · preferred':'')+'<div class="ls">'+esc(display(r.observedAt))+'</div></td><td>'+truth(r.encrypted)+'</td><td>'+truth(r.recoveryKeyEscrowed)+'</td></tr>';});
    if(d.encryption && d.encryption.conflict)h+='<p class="note warn">Sources report conflicting encryption values. Keep their observation dates and preferred source in view.</p>';
    h+=sectionHtml('Warranty',d.warranty,['Source / observation','Coverage','Recorded end date'],function(r){return '<tr><td>'+esc(r.source)+'<div class="ls">'+esc(display(r.observedAt))+'</div><div class="ls">'+esc(r.coverageId || r.resourceId || '')+'</div></td><td>'+esc(display(r.coverage))+(r.association?'<div class="ls">'+esc(r.association)+'</div>':'')+(r.reportedStatus?'<div class="ls">Reported: '+esc(r.reportedStatus)+'</div>':'')+'</td><td>'+esc(display(r.endDate))+'</td></tr>';});
    h+=sectionHtml('Zscaler Client Connector',d.zcc,['Association','Stored export','Person lookup · joined by UDID'],function(r){
      function fields(v,live){if(!v)return 'Not returned';return '<strong>'+esc(r.udid)+'</strong><div>'+esc(display(v.hostname))+'</div><div>Registration: '+esc(registration(v.registration))+'</div><div>Registered at: '+esc(display(v.registeredAt))+'</div><div>Agent: '+esc(display(v.agentVersion))+'</div><div>Tunnel: '+esc(display(v.tunnelVersion))+'</div><div>Policy: '+esc(display(v.policy))+'</div><div>VPN state: '+esc(display(v.vpnState))+'</div><div>Reported activity: '+esc(display(v.reportedActivity))+'</div>'+(!live?'<div>ZIA activity: '+esc(display(v.lastSeenZia))+'</div><div>ZPA activity: '+esc(display(v.lastSeenZpa))+'</div><div class="ls">Snapshot observed: '+esc(display(v.observedAt))+'</div>':'');}
      return '<tr><td>'+esc(r.match.status)+'<div class="ls">'+esc(r.match.basis)+'</div><div class="ls">Live join: '+esc(r.liveStatus)+'</div></td><td>'+fields(r.snapshot,false)+'</td><td>'+fields(r.live,true)+'</td></tr>';
    });
    if(d.zcc && d.zcc.unmatchedLive && d.zcc.unmatchedLive.length)h+='<p class="note">'+d.zcc.unmatchedLive.length+' additional person-scoped ZCC record(s) were not matched to this endpoint. They are not selected-device evidence.</p>';
    if(d.zdx)h+='<h4 class="identity-evidence-heading">ZDX experience · '+esc(d.zdx.state || 'unavailable')+'</h4><p class="ls">'+esc(d.zdx.reason || 'Experience evidence unavailable.')+'</p>';
    if(d.limitations && d.limitations.length)h+='<p class="note warn">'+esc(d.limitations.join(' · '))+'</p>';
    var links=allowedLinks(d);
    if(links.length)h+='<div class="identity-device-links">'+links.map(function(link){return '<a class="btn btn-ghost btn-sm" href="'+esc(link.href)+'" target="_blank" rel="noopener" title="'+esc(link.basis)+'">'+esc(link.label)+'</a>';}).join('')+'</div>';
    return h+'<button type="button" class="btn btn-ghost btn-sm" data-device-retry>Refresh device evidence</button></div>';
  }
  function summaryLines() {
    var g=selected();if(!g)return [];
    var lines=['','SELECTED DEVICE: '+g.deviceName,'  Device key: '+g.deviceKey,'  Serial: '+display(g.serial),'  Match: '+g.match.status+' · '+g.match.basis];
    (g.sourceRefs || []).forEach(function(r){lines.push('  Source ID: '+r.sourceKey+' · '+r.recordKey+' · native '+display(r.nativeId)+' · inventory row '+display(r.rowId));});
    lines.push('  Device evidence: '+detail.status+(detail.error?' · '+detail.error:''));
    var d=detail.data;if(!d)return lines;
    lines.push('  Evidence read: '+d.readAt);
    ['inventory','encryption','warranty','zcc'].forEach(function(key){var section=d[key];if(!section)return;lines.push('  '+key.toUpperCase()+': '+section.status+(section.reason?' · '+section.reason:''));
      (section.sources || []).forEach(function(source){lines.push('    Source: '+source.source+' · '+source.status+(source.reason?' · '+source.reason:''));});
      (section.records || []).forEach(function(r){
        if(key==='inventory')lines.push('    '+r.source+' · '+r.recordKey+' · owner '+display(r.owner)+' · ownership '+display(r.ownership)+' · compliance '+display(r.compliance)+' · check-in '+display(r.lastCheckin)+' · observed '+display(r.observedAt));
        if(key==='encryption')lines.push('    '+r.source+(r.preferred?' (preferred)':'')+' · device '+display(r.deviceId || r.recordKey)+' · encrypted '+truth(r.encrypted)+' · key escrowed '+truth(r.recoveryKeyEscrowed)+' · observed '+display(r.observedAt));
        if(key==='warranty')lines.push('    '+r.source+' · coverage '+display(r.coverage)+' · recorded status '+display(r.reportedStatus)+' · end '+display(r.endDate)+' · observed '+display(r.observedAt));
        if(key==='zcc'){lines.push('    UDID '+r.udid+' · '+r.match.status+' · '+r.match.basis+' · live join '+r.liveStatus);['snapshot','live'].forEach(function(kind){var v=r[kind];if(v)lines.push('      '+kind+' · registration '+registration(v.registration)+' · agent '+display(v.agentVersion)+' · tunnel '+display(v.tunnelVersion)+' · policy '+display(v.policy)+' · VPN state '+display(v.vpnState)+' · activity '+display(v.reportedActivity)+' · ZIA '+display(v.lastSeenZia)+' · ZPA '+display(v.lastSeenZpa)+' · registered '+display(v.registeredAt)+' · observed '+display(v.observedAt));});}
      });
    });
    if(d.encryption && d.encryption.conflict)lines.push('  Limitation: conflicting encryption values across sources.');
    if(d.zcc && d.zcc.unmatchedLive?.length)lines.push('  Limitation: '+d.zcc.unmatchedLive.length+' person-scoped ZCC records were not matched to the endpoint.');
    if(d.zdx)lines.push('  ZDX: '+d.zdx.state+' · '+display(d.zdx.reason));
    (d.limitations || []).forEach(function(v){lines.push('  Limitation: '+v);});
    lines.push('  Account checks and sign-ins remain person-scoped.');
    return lines;
  }
  function render() {
    context(); pane();
    document.querySelectorAll('.identity-device-panel').forEach(function(el){el.innerHTML=panelHtml();});
    var status = document.getElementById('identity-device-announcement');
    if (status) status.textContent = state.notice || (selected() ? 'Selected device: '+selected().deviceName : 'No device selected');
    if(window.IdentityDeviceNetwork)IdentityDeviceNetwork.contextChanged();
  }
  function beforeNavigate() { return location.href; }
  function afterNavigate(previous) {
    if (state.restoring || bootRoute) return;
    // Legacy navigation writes the hash with replaceState; preserve its previous entry before adding this one.
    if (previous && previous !== location.href) { var next = location.href; history.replaceState(null,'',previous); history.pushState(null,'',next); }
    route('replace'); render();
  }
  function restoreLocation() {
    if(window.IdentityDeviceNetwork)IdentityDeviceNetwork.restore();
    var u = new URL(location.href), q = u.searchParams.get('q');
    if (!q) {
      state.restoring = true; state.skipHash = location.href;
      if (typeof newGen === 'function') newGen();
      window._D = null; window._curQuery = ''; window._toolQ = '';
      clear(); if(typeof identityContext==='function')identityContext(); go('overview');
      state.restoring = false; return;
    }
    state.restoring = true; state.wanted = u.searchParams.get('device') || ''; state.key = '';
    state.pendingView = u.searchParams.get('view') || 'detail';
    state.skipHash = location.href;
    if (!window._D || !matches(q)) runSearch(q);
    else { loadedPerson(); if (state.payload) accept(state.payload,q,window._gen); }
  }
  function handleHash() {
    if (state.skipHash && state.skipHash===location.href) { state.skipHash=''; return true; }
    state.skipHash=''; return false;
  }
  document.addEventListener('change',function(e){
    if (e.target.id==='identity-device-select') { setSelected(e.target.value); var select=document.getElementById('identity-device-select'); if(select)select.focus(); }
  });
  document.addEventListener('click',function(e){
    var b=e.target.closest('[data-device-key]');
    if(b){var key=b.getAttribute('data-device-key');setSelected(key);var buttons=document.querySelectorAll('[data-device-key]');for(var i=0;i<buttons.length;i++)if(buttons[i].getAttribute('data-device-key')===key){buttons[i].focus();break;}return;}
    if(e.target.closest('[data-device-retry]')){resetDetail();ensureDetail();return;}
    if(e.target.closest('[data-device-review]')){go('devices');closePane();}
  });
  window.addEventListener('popstate',restoreLocation);
  function init(){var live=document.createElement('div');live.id='identity-device-announcement';live.className='sr-only';live.setAttribute('role','status');live.setAttribute('aria-live','polite');document.body.appendChild(live);render();}
  window.IdentityDeviceContext={summaryLines:summaryLines,detailState:function(){return detail;},beginPerson:beginPerson,loadedPerson:loadedPerson,accept:accept,clear:clear,render:render,context:context,placeholder:placeholder,
    beforeNavigate:beforeNavigate,afterNavigate:afterNavigate,handleHash:handleHash,selected:selected,matches:matches,getState:function(){return state;}};
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
})();
