/* Selected-device network evidence. Stage 3A reads stored observations only. */
(function(){
  'use strict';
  var state={scope:'',deviceKey:'',key:'',wanted:'',options:[],data:null,status:'idle',error:'',sequence:0,controller:null,restoring:true,section:null,changing:false,adapterStatus:'',adapterBusy:false,adapterController:null};
  function captureRoute(){var u=new URL(location.href);state.wanted=u.searchParams.get('interface')||'';state.section=u.searchParams.get('section')||null;}
  captureRoute();
  function esc(v){return x(v==null?'':String(v));}
  function val(v){return v==null||v===''?'Not reported':String(v);}
  function selectedDevice(){return window.IdentityDeviceContext && IdentityDeviceContext.selected();}
  function reset(preserve){
    if(window.IdentityDeviceLive)IdentityDeviceLive.reset();
    if(state.adapterController)state.adapterController.abort();state.adapterController=null;
    if(state.controller)state.controller.abort();state.sequence++;state.scope='';state.deviceKey='';state.key='';state.options=[];state.data=null;state.status='idle';state.error='';state.controller=null;state.adapterStatus='';state.adapterBusy=false;
    if(!preserve){state.wanted='';state.section=null;}
  }
  function beginPerson(q,preserve){reset(preserve);if(!preserve)removeInterface();}
  function restore(){reset(true);captureRoute();state.restoring=true;}
  function removeInterface(){var u=new URL(location.href);u.searchParams.delete('interface');history.replaceState(null,'',u);}
  function clear(){reset(false);var u=new URL(location.href);u.searchParams.delete('interface');u.searchParams.delete('section');history.replaceState(null,'',u);render();}
  function syncRoute(mode){
    if(!window._D || state.restoring || state.changing)return;
    var u=new URL(location.href),key=state.key||state.wanted;
    if(key)u.searchParams.set('interface',key);else u.searchParams.delete('interface');
    if(window._page==='detail' && window._curTab)u.searchParams.set('section',_curTab.replace(/^t-/,''));else u.searchParams.delete('section');
    if(u.href!==location.href)history[mode==='push'?'pushState':'replaceState'](null,'',u);
  }
  function loadedPerson(){
    var section=state.section;state.section=null;
    if(section && window._page==='detail' && Object.prototype.hasOwnProperty.call(TAB_BUILDERS,'t-'+section))switchTab('t-'+section);
    state.restoring=false;contextChanged();syncRoute('replace');
  }
  function contextChanged(){
    var g=selectedDevice(),scope=g&&window._D?(_D.samAccountName||_curQuery)+'|'+_gen+'|'+g.deviceKey:'';
    if(scope!==state.scope){
      var previous=state.scope,wanted=state.wanted;
      reset(true);state.scope=scope;state.deviceKey=g?g.deviceKey:'';
      if(previous && !state.restoring){state.wanted='';removeInterface();}else state.wanted=wanted;
    }
    var deviceState=window.IdentityDeviceContext && IdentityDeviceContext.getState();
    if(!g && deviceState?.payload && !deviceState.payload.__err && !deviceState.wanted && !state.restoring){state.wanted='';removeInterface();}
    render();
    if(window.IdentityDeviceLive)IdentityDeviceLive.contextChanged();
    if(g && ((window._page==='detail' && window._curTab==='t-network') || state.wanted))ensure();
  }
  function afterTab(){syncRoute('push');contextChanged();}
  function open(){state.changing=true;go('detail');switchTab('t-network');state.changing=false;syncRoute('replace');ensure();closePane();}
  async function ensure(force){
    var g=selectedDevice();if(!g||!window._D)return;
    if(!force && state.status!=='idle')return;
    if(state.controller)state.controller.abort();
    var seq=++state.sequence,generation=_gen,key=state.key||state.wanted,device=g.deviceKey;
    var controller=new AbortController();state.controller=controller;state.status='loading';state.data=null;state.error='';render();
    var timeout=setTimeout(function(){controller.abort();},20000);
    try{
      var url='/api/identity/device-network?q='+encodeURIComponent(_D.samAccountName||_curQuery)+'&deviceKey='+encodeURIComponent(device)+'&mode=cached';
      if(key)url+='&interfaceKey='+encodeURIComponent(key);
      var response=await fetch(url,{signal:controller.signal,cache:'no-store'}),data=await response.json();
      if(seq!==state.sequence || generation!==_gen || selectedDevice()?.deviceKey!==device)return;
      if(data.deviceKey && data.deviceKey!==device)throw Error('Network evidence did not identify the selected device.');
      if(!response.ok){
        if(data.deviceKey===device && data.identifiers)state.options=data.identifiers.interfaces||[];
        if(response.status===404 || response.status===409){state.key='';state.wanted='';syncRoute('replace');}
        throw Error(data.error||'Cached network evidence request failed.');
      }
      if(data.deviceKey!==device || data.mode!=='cached' || (key && data.selectedInterfaceKey!==key && ['denied','unavailable'].indexOf(data.status)<0))throw Error('Network evidence did not match the selected device and interface.');
      state.data=data;state.options=data.identifiers?.interfaces||[];state.key=data.selectedInterfaceKey||'';state.wanted='';state.status='ready';syncRoute('replace');
    }catch(e){if(seq!==state.sequence || generation!==_gen)return;state.status='error';state.error=e.name==='AbortError'?'Cached network evidence timed out. Retry when ready.':e.message;}
    finally{clearTimeout(timeout);if(seq===state.sequence){state.controller=null;render();if(window._page==='summary')renderSummaryTool();}}
  }
  async function discoverAdapters(){
    var g=selectedDevice();if(!g||!window._D||state.adapterBusy)return;
    var device=g.deviceKey,generation=_gen,controller=new AbortController();
    state.adapterController=controller;state.adapterBusy=true;state.adapterStatus='Reading managed Wi-Fi and Ethernet adapters…';render();
    var timeout=setTimeout(function(){controller.abort();},18000);
    try{
      var response=await fetch('/api/identity/device-network-adapters',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({q:_D.samAccountName||_curQuery,deviceKey:device}),signal:controller.signal}),data=await response.json();
      if(generation!==_gen||selectedDevice()?.deviceKey!==device||state.adapterController!==controller)return;
      if(!response.ok)throw Error(data.error||data.reason||'Adapter discovery unavailable.');
      if(data.deviceKey!==device)throw Error('Adapter results did not match the selected device.');
      state.adapterStatus=data.reason||'Adapter read completed.';
    }catch(e){if(generation!==_gen||selectedDevice()?.deviceKey!==device||state.adapterController!==controller)return;state.adapterStatus=e.name==='AbortError'?'Adapter discovery timed out. Retry when ready.':e.message;}
    finally{
      clearTimeout(timeout);
      if(generation===_gen&&selectedDevice()?.deviceKey===device&&state.adapterController===controller){state.adapterController=null;state.adapterBusy=false;await ensure(true);}
    }
  }
  function choose(key){
    if(key && !state.options.some(i=>i.interfaceKey===key && i.selectable))return;
    state.key=key;state.wanted='';state.status='idle';state.data=null;syncRoute('push');ensure();
  }
  function statusLabel(s){return {ok:'Cached records',empty:'No records',partial:'Partial',unavailable:'Unavailable',denied:'Permission required',not_associated:'Not associated',not_selected:'Choose an interface'}[s]||val(s);}
  function tableSection(title,section,heads,row){
    if(!section)return '';
    var h='<h4 class="identity-evidence-heading">'+esc(title)+' <span class="ls">'+esc(statusLabel(section.status))+'</span></h4>';
    if(section.reason)h+='<p class="ls">'+esc(section.reason)+'</p>';
    if(section.records?.length)h+=table(heads.map(function(t){return {t:t};}),section.records.map(row),'');
    else h+='<p class="ls">'+esc(section.status==='unavailable'?'This cache section could not be read.':section.status==='not_associated'?'No verified hardware MAC is associated with this IP-only observation.':'No matching stored observation in the stated scope. This does not establish that the device is offline.')+'</p>';
    return h;
  }
  function cells(values){return '<tr>'+values.map(function(v){return '<td>'+esc(val(v))+'</td>';}).join('')+'</tr>';}
  function html(){
    var g=selectedDevice();if(!g)return '<p class="note">Choose an assigned device to review its cached network evidence.</p>';
    var h='<p class="ls">Selected device: <strong>'+esc(g.deviceName)+'</strong>. Addresses and network observations retain their own source dates. No active diagnostics run here.</p>';
    h+='<div class="identity-network-controls"><label for="identity-network-interface">Network interface or address</label><select class="env-select" id="identity-network-interface" aria-label="Network interface or address"><option value="">Choose an interface or address…</option>'
      +state.options.map(function(i){return '<option value="'+esc(i.interfaceKey)+'"'+(i.interfaceKey===state.key?' selected':'')+(!i.selectable?' disabled':'')+'>'+esc(i.source+' · '+(i.mac||i.reportedIp)+(i.selectable?'':' · association not confirmed'))+'</option>';}).join('')+'</select>'
      +'<button type="button" class="btn btn-ghost btn-sm" data-network-refresh>Refresh cached evidence</button></div>';
    if(g.records?.some(function(r){return r.sourceRef?.sourceKey==='intune' && /windows/i.test(r.os||'');}))h+='<p><button type="button" class="btn btn-ghost btn-sm" data-network-adapters'+(state.adapterBusy?' disabled':'')+'>Discover managed adapters</button></p>';
    if(state.adapterStatus)h+='<p class="note" role="status">'+esc(state.adapterStatus)+'</p>';
    if(window.IdentityDeviceLive)h+='<p><button type="button" class="btn btn-ghost btn-sm" data-live-open>Open explicit network checks</button></p>';
    if(state.status==='loading')h+='<p class="note" role="status">Reading cached network evidence…</p>';
    if(state.error)h+='<p class="note warn" role="status">'+esc(state.error)+'</p>';
    var d=state.data;if(!d)return h;
    if(d.identifiers?.reason)h+='<p class="ls">'+esc(d.identifiers.reason)+'</p>';
    (d.identifiers?.sources||[]).filter(function(s){return ['denied','unavailable'].indexOf(s.status)>-1;}).forEach(function(s){h+='<p class="note warn">'+esc(s.source)+': '+esc(statusLabel(s.status))+' · '+esc(s.reason)+'</p>';});
    if(!state.options.some(function(i){return i.selectable;}))h+='<p class="note">No selectable network address is available from these source results. Available hostname checks are listed under explicit network checks below. MAC-based checks require a source MAC.</p>';
    if(d.identifiers?.hostnames?.length)h+='<details class="support-evidence"><summary>Inventory hostnames · no DNS lookup performed</summary>'+d.identifiers.hostnames.map(function(r){return '<p>'+esc(r.value)+' · '+esc(r.source)+'</p>';}).join('')+'</details>';
    if(!d.network)return h;
    var n=d.network,i=state.options.find(function(o){return o.interfaceKey===d.selectedInterfaceKey;});
    h+='<div class="facts">'+factRow('Source',esc(i?.source||''))+factRow('Address',esc(i?.mac||i?.reportedIp||''))+factRow('Identifier observed',esc(val(i?.observedAt)))+factRow('Inventory-reported IP',esc(val(i?.reportedIp)))+factRow('Association',esc(i?.basis||''))+factRow('Network snapshot',esc(val(n.snapshotAt)))+'</div>';
    h+='<p class="note">'+esc({uplinks_only:'Only uplink-pattern sightings were found. No endpoint edge port is established.',one_edge_candidate:'One edge-port candidate was found. Port naming does not confirm a physical connection.',multiple_edge_candidates:'Several edge-port candidates were found. No location was selected automatically.',no_cached_location:'No matching CAM observation was recorded in this snapshot.',unverified_ip:'This recorded IP is a candidate. Cached ARP was not followed to a port without a verified MAC.',unavailable:'Network location evidence is unavailable.'}[n.locationAssessment]||'Review each stored observation separately.')+'</p>';
    h+=tableSection('Switch / port / VLAN observations',n.locations,['Switch','Port / role','VLAN','Observed'],function(r){return cells([r.switch||r.switch_ip,r.port+' · '+(r.role==='uplink'?'uplink pattern':'edge candidate'),r.vlan,r.observedAt]);});
    h+=tableSection('ARP observations',n.bindings,['IP','MAC','Association','Observed'],function(r){return cells([r.ip,r.mac,r.association==='exact-selected-mac'?'Exact selected MAC':'Unverified IP-only binding',r.observedAt]);});
    h+=tableSection('Port health',n.portHealth,['Switch / port','Link / admin','Speed / duplex','Errors in / out / CRC / discards','Observed'],function(r){return cells([r.switch_ip+' · '+r.port,val(r.oper)+' / '+val(r.admin),val(r.speed)+' / '+val(r.duplex),[r.in_err,r.out_err,r.crc,r.out_disc].map(val).join(' / '),r.observedAt]);});
    h+=tableSection('Issues on observed ports',n.issues,['Switch / port','Severity / kind','Reported detail','Observed'],function(r){return cells([r.switch_ip+' · '+r.port,val(r.severity)+' / '+val(r.kind),r.detail,r.observedAt]);});
    var w=n.historyWindow;
    if(w)h+='<p class="ls">History window: '+esc(w.since)+' through '+esc(w.through)+' · '+esc(w.basis)+'.</p>';
    h+='<details class="support-evidence"><summary>Recorded location and port history</summary>'
      +tableSection('Historical CAM observations',n.locationHistory,['Switch / port','VLAN','First observed','Last observed'],function(r){return cells([r.switch_ip+' · '+r.port,r.vlan,r.firstSeenAt,r.lastSeenAt]);})
      +tableSection('Port counter samples',n.portHistory,['Switch / interface','Link state','Errors in / out / CRC / discards','Observed'],function(r){return cells([r.switch_ip+' · '+r.ifindex,r.oper,[r.in_err,r.out_err,r.crc,r.out_disc].map(val).join(' / '),r.observedAt]);})+'</details>';
    if(d.limitations?.length)h+='<p class="note warn">'+esc(d.limitations.join(' · '))+'</p>';
    var links=(d.links||[]).filter(function(link){try{var u=new URL(link.href,location.origin);return u.origin===location.origin&&u.pathname==='/network-switches.html';}catch(e){return false;}});
    if(links.length)h+='<div class="identity-device-links">'+links.map(function(link){return '<a class="btn btn-ghost btn-sm" target="_blank" rel="noopener" href="'+esc(link.href)+'" title="'+esc(link.basis)+'">'+esc(link.label)+'</a>';}).join('')+'</div>';
    return h;
  }
  function placeholder(){return panel('Selected device · cached network','Stored identifiers, fabric observations and port evidence. Account checks below retain their existing person scope.','<div class="identity-network-panel">'+html()+'</div>')+(window.IdentityDeviceLive?IdentityDeviceLive.placeholder():'');}
  function render(){
    var active=document.activeElement,focusInterface=active?.id==='identity-network-interface';
    var focusRefresh=active?.matches('[data-network-refresh]');
    document.querySelectorAll('.identity-network-panel').forEach(function(el){el.innerHTML=html();});
    if(focusInterface)document.getElementById('identity-network-interface')?.focus();
    else if(focusRefresh)document.querySelector('.identity-network-panel [data-network-refresh]')?.focus();
    if(window.IdentityDeviceLive)IdentityDeviceLive.contextChanged();
  }
  function summaryLines(){
    var g=selectedDevice();if(!g || (!state.data && !state.key && !state.wanted && state.status==='idle'))return [];
    var out=['','SELECTED DEVICE NETWORK · CACHED ONLY','  Device key: '+g.deviceKey,'  Read state: '+state.status];
    if(state.error)out.push('  Limitation: '+state.error);
    var d=state.data;if(!d)return out;
    var i=state.options.find(function(o){return o.interfaceKey===state.key;});
    if(i)out.push('  Interface: '+i.interfaceKey,'  Source: '+i.source+' · observed '+val(i.observedAt),'  MAC: '+val(i.mac)+' · inventory-reported IP: '+val(i.reportedIp),'  Association: '+i.basis);
    if(!d.network){out.push('  No interface selected or no usable cached identifier available.');return out;}
    var n=d.network;out.push('  Network snapshot: '+val(n.snapshotAt),'  Location assessment: '+n.locationAssessment);
    if(n.historyWindow)out.push('  History: '+n.historyWindow.since+' through '+n.historyWindow.through+' · '+n.historyWindow.basis);
    ['locations','bindings','portHealth','issues','locationHistory','portHistory'].forEach(function(k){var s=n[k];out.push('  '+k+': '+s.status+(s.truncated?' (capped)':''));(s.records||[]).forEach(function(r){out.push('    '+Object.keys(r).map(function(field){return field+'='+val(r[field]);}).join(' · '));});});
    (d.limitations||[]).forEach(function(v){out.push('  Limitation: '+v);});
    out.push('  No active trace or online/offline determination was performed.');return out;
  }
  document.addEventListener('change',function(e){if(e.target.id==='identity-network-interface'){choose(e.target.value);document.getElementById('identity-network-interface')?.focus();}});
  document.addEventListener('click',function(e){if(e.target.closest('[data-network-adapters]'))discoverAdapters();if(e.target.closest('[data-device-network]'))open();if(e.target.closest('[data-network-refresh]'))ensure(true);});
  window.IdentityDeviceNetwork={beginPerson,restore,clear,loadedPerson,contextChanged,afterTab,open,placeholder,render,summaryLines,getState:function(){return state;}};
})();
