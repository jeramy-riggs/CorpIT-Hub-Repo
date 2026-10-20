/* Device 360 inventory/status insights. On-demand, read-only evidence through existing gated APIs. */
(function(){
  'use strict';
  const str=v=>v==null?'':String(v),esc=v=>str(v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const guid=v=>/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(str(v));
  const serial=v=>{const s=str(v).trim().toUpperCase();return /^(?:|0+|UNKNOWN|N\/A|NONE|DEFAULT STRING|TO BE FILLED BY O\.?E\.?M\.?|[-—]+)$/.test(s)?'':s;};
  const boolean=v=>v===true||v===1||v==='true'?true:v===false||v===0||v==='false'?false:null;
  const show=v=>v==null||v===''?'Not reported':typeof v==='boolean'?(v?'Yes':'No'):String(v);
  const dated=v=>{if(!v)return 'Not reported';const d=new Date(v);return Number.isFinite(d.getTime())?d.toLocaleString(undefined,{year:'numeric',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',timeZoneName:'short'}):'Not reported';};
  const readable=s=>!!s&&['ok','partial'].includes(s.state);
  const windows=(row,result)=>/windows/i.test(row.type||'')||(result.group?.records||[]).some(r=>/windows/i.test(r.os||''));
  function intuneReference(group){
    const refs=(group?.sourceRefs||[]).filter(r=>r.sourceKey==='intune');
    if(refs.length!==1||!guid(refs[0].nativeId))return null;
    return str(refs[0].nativeId).toLowerCase();
  }
  function selectHealth(snapshot,group){
    const id=intuneReference(group);
    if(!id)throw Error('No single verified Intune enrollment is associated with this device. Open People & Devices to review its source links.');
    if(!snapshot||snapshot.ok!==true||snapshot.devicesOk!==true||!Array.isArray(snapshot.devices)||!readable(snapshot.sources?.intune))throw Error('The Intune device source is unavailable. No device match or comparison was made.');
    const matches=snapshot.devices.filter(d=>str(d.id).toLowerCase()===id);
    if(matches.length!==1)throw Error(matches.length?'The Intune enrollment is ambiguous in this snapshot.':'The verified Intune enrollment is absent from this snapshot. No serial-only fallback was used.');
    const device=matches[0];
    if(device.platform!=='Windows')throw Error('The matched Intune enrollment is not a Windows device.');
    const a=serial(group.serial),b=serial(device.serial);
    if(a&&b&&a!==b)throw Error('The enrollment ID matches but its serial differs. Review the device association before using this evidence.');
    return {device,at:snapshot.at,now:snapshot.now,baseline:snapshot.baseline,source:snapshot.sources.intune,refreshError:!!snapshot.refreshError,count:snapshot.devices.length,serialVerified:!!a&&!!b};
  }
  function compareValues(before,after){
    const fields=[['Owner','owner'],['OS version','os'],['Compliance','compliance'],['Encrypted','encrypted'],['Last check-in','lastCheckin'],['Serial','serial']];
    const normalize=(v,key)=>{
      if(v==null||v===''||/^(?:unknown|not reported|[-—]+)$/i.test(str(v)))return null;
      if(key==='lastCheckin'){const n=new Date(v).getTime();return Number.isFinite(n)?n:null;}
      if(key==='compliance')return str(v).toLowerCase().replace(/[^a-z]/g,'');
      return typeof v==='boolean'?v:str(v).trim().toLowerCase();
    };
    return fields.map(([label,key])=>{const a=normalize(before[key],key),b=normalize(after[key],key);return {label,key,before:before[key],after:after[key],state:a==null||b==null?'missing':a===b?'same':'different'};});
  }
  function updateStatus(health){
    const d=health.device,b=health.baseline;
    if(!b||!Array.isArray(b.builds)||!b.builds.includes(d.base)||!Number.isFinite(d.rev)||!Number.isFinite(b.revision))return 'Build not recognized';
    if(d.rev>=b.revision)return 'At or above baseline';
    const now=Number(health.now)||Date.now();
    return !d.lastSync||now-d.lastSync>7*86400000?'Below baseline; old check-in':'Below baseline';
  }
  function validateDetail(detail,id){
    if(!detail||detail.ok!==true||str(detail.id).toLowerCase()!==id)throw Error('Windows health detail did not identify the selected enrollment.');
    return detail;
  }
  function validateNetwork(data,key,interfaceKey){
    if(!data||data.deviceKey!==key||data.mode!=='cached'||!data.identifiers||!Array.isArray(data.identifiers.interfaces))throw Error('Network evidence did not identify the selected device in cached mode.');
    if(['denied','unavailable'].includes(data.status))return data;
    if(data.identifiers.interfaces.some(i=>!i||typeof i.interfaceKey!=='string'||!i.interfaceKey||typeof i.selectable!=='boolean'))throw Error('Network interface evidence was incomplete.');
    if(new Set(data.identifiers.interfaces.map(i=>i.interfaceKey)).size!==data.identifiers.interfaces.length)throw Error('Network interface references were ambiguous.');
    if(interfaceKey&&data.selectedInterfaceKey!==interfaceKey)throw Error('Network evidence did not match the selected interface.');
    if(interfaceKey&&!data.identifiers.interfaces.some(i=>i.interfaceKey===interfaceKey&&i.selectable===true))throw Error('The network interface is no longer verified for this device.');
    return data;
  }
  async function request(url,signal,fetcher,kind){
    const controller=new AbortController(),abort=()=>controller.abort();
    if(signal?.aborted)abort();else signal?.addEventListener('abort',abort,{once:true});
    const timer=setTimeout(abort,kind==='health'?45000:20000);
    try{
      const r=await fetcher(url,{method:'GET',credentials:'same-origin',cache:'no-store',signal:controller.signal,headers:{Accept:'application/json'}});
      if(r.status===401)throw Error('Your session has expired. Sign in again before retrying.');
      if(r.status===403)throw Error(kind==='health'?'Intune health requires super-admin or active Tier2 access.':'Network Diagnostics read permission is required.');
      if(!r.ok)throw Error('This source could not be read (HTTP '+r.status+'). Retry or open its owning page.');
      let data;try{data=await r.json();}catch(_){throw Error('The source did not return readable evidence.');}
      if(!data||typeof data!=='object'||Array.isArray(data))throw Error('The source response was incomplete.');
      return data;
    }finally{clearTimeout(timer);signal?.removeEventListener('abort',abort);}
  }
  function createReader(result,fetcher,signal){
    let pending=null;
    return {
      health(){
        if(!intuneReference(result.group))return Promise.reject(Error('No single verified Intune enrollment is associated with this device.'));
        if(!pending)pending=request('/hub-api/api/patch-status/snapshot',signal,fetcher,'health').then(s=>selectHealth(s,result.group)).catch(e=>{pending=null;throw e;});
        return pending;
      },
      async detail(health){return validateDetail(await request('/hub-api/api/patch-status/device/'+encodeURIComponent(health.device.id),signal,fetcher,'health'),str(health.device.id).toLowerCase());},
      async network(interfaceKey){
        if(!result.q||!result.group?.deviceKey)throw Error('A verified assigned device is required for network context.');
        const u='/api/identity/device-network?q='+encodeURIComponent(result.q)+'&deviceKey='+encodeURIComponent(result.group.deviceKey)+'&mode=cached'+(interfaceKey?'&interfaceKey='+encodeURIComponent(interfaceKey):'');
        return validateNetwork(await request(u,signal,fetcher,'network'),result.group.deviceKey,interfaceKey);
      }
    };
  }
  if(typeof module==='object'&&module.exports&&typeof document==='undefined'){module.exports={intuneReference,selectHealth,compareValues,updateStatus,validateDetail,validateNetwork,request,createReader,boolean,networkSummary,renderHealth,renderComparison};return;}
  let context=null,sequence=0;
  const titles={health:['Windows health','health_and_safety'],network:['Network context','lan'],compare:['Source comparison','compare_arrows']};
  function reset(){sequence++;if(context)context.controller.abort();context=null;}
  function placeholder(row,result){
    const keys=result.localReason?['compare']:windows(row,result)?['health','network','compare']:['network','compare'];
    return '<div id="iv360-insights">'+keys.map(k=>'<details class="iv360-disclosure iv360-insight" data-iv-insight="'+k+'"><summary><span class="ms iv360-detail-icon" aria-hidden="true">'+titles[k][1]+'</span><span class="iv360-detail-title">'+titles[k][0]+'</span><span class="iv360-detail-meta">'+(k==='network'?'Stored observations':'Open to read')+'</span><span class="ms iv360-chevron" aria-hidden="true">expand_more</span></summary><div class="iv360-disclosure-body"><p class="iv360-note">Expand to read this device’s evidence.</p></div></details>').join('')+'</div>';
  }
  function importedRecord(row,result){
    const ref=row.support_ref||{},keys={endpoints:'endpoints',macbooks:'macbooks',intune:'intuneDevices',ipads:'ipadDevices',aws:'awsWorkspaces'};
    const rawRows=typeof DATA==='object'?DATA[keys[ref.table]]||[]:[];
    const rows=rawRows.filter(r=>ref.rowId!=null?str(r._id??r.id)===str(ref.rowId):ref.nativeId!=null&&str(ref.table==='endpoints'?r.resource_id:ref.table==='aws'?r['WorkSpace ID']:r.device_id)===str(ref.nativeId));
    const raw=rows.length===1?rows[0]:{};
    const groupRefs=(result.group?.sourceRefs||[]).filter(r=>r.sourceKey===ref.sourceKey&&(ref.rowId!=null?str(r.rowId)===str(ref.rowId):str(r.nativeId)===str(ref.nativeId)));
    const records=['ok','partial'].includes(result.detail?.inventory?.status)?result.detail.inventory.records||[]:[];
    const matching=groupRefs.length===1&&typeof groupRefs[0].recordKey==='string'?records.filter(r=>r.recordKey===groupRefs[0].recordKey):[];
    const own=raw['Primary user UPN']||raw['User']||raw['First/Last']||raw['Username']||row.user_raw;
    return {source:row.source,owner:own,os:raw['OS version']||raw['OS Version'],compliance:raw['Compliance']??null,encrypted:boolean(raw.is_encrypted??raw['Encrypted']??raw.filevault_enabled),lastCheckin:raw['Last check-in']||raw['Last Successful Asset Scan']||raw['Last Check-in']||raw.checked_in,observedAt:raw.updated_at||raw.details_synced_at,evidenceObservedAt:matching.length===1?matching[0].observedAt:null,serial:row.serial,rawVerified:rows.length===1};
  }
  function mount(row,result){
    reset();const controller=new AbortController();
    context={row,result,controller,epoch:sequence,reader:createReader(result,window.fetch.bind(window),controller.signal),imported:importedRecord(row,result),loaded:{},busy:{},network:null,interfaceKey:'',networkSequence:0};
  }
  function alive(c){return context===c&&c.epoch===sequence&&!c.controller.signal.aborted&&document.getElementById('iv360-dialog')?.open;}
  function section(c,key){return alive(c)?document.querySelector('#iv360-insights [data-iv-insight="'+key+'"]'):null;}
  function setMeta(c,key,label,warn){const el=section(c,key)?.querySelector('.iv360-detail-meta');if(el){el.textContent=label;if(warn)el.setAttribute('data-tone','warn');else el.removeAttribute('data-tone');}}
  function body(c,key,html){const el=section(c,key)?.querySelector('.iv360-disclosure-body');if(el)el.innerHTML=html;}
  function facts(rows){return '<dl class="iv360-facts">'+rows.map(([k,v])=>'<div><dt>'+esc(k)+'</dt><dd>'+esc(show(v))+'</dd></div>').join('')+'</dl>';}
  function note(s){return '<p class="iv360-note">'+esc(s)+'</p>';}
  function notice(s){return '<p class="iv360-notice">'+esc(s)+'</p>';}
  function link(href,label){
    try{const u=new URL(href,location.origin);if(u.origin!==location.origin||u.username||u.password||!['/identity-diag.html','/patch-status.html'].includes(u.pathname))return '';return '<a class="btn btn-ghost btn-sm" href="'+esc(u.href)+'" target="_blank" rel="noopener">'+esc(label)+'<span class="ms" aria-hidden="true">open_in_new</span></a>';}catch(_){return '';}
  }
  function healthLink(h){return link('/patch-status.html#devices?platform=Windows&q='+encodeURIComponent(h.device.serial||h.device.name),'Open filtered Intune health');}
  function networkLink(c){
    if(!c.result.group||!c.result.q)return '';
    const p=new URLSearchParams({q:c.result.q,device:c.result.group.deviceKey,view:'detail',section:'network'});if(c.interfaceKey)p.set('interface',c.interfaceKey);
    return link('/identity-diag.html?'+p,'Advanced network tools');
  }
  function sourceNotes(sources){return Object.values(sources||{}).filter(s=>s&&s.state!=='ok').map(s=>notice((s.label||'Source')+': '+(s.state||'unavailable')+'. '+(s.state==='partial'?'Counts cover returned results only.':'Missing values stay unknown.'))).join('');}
  function renderHealth(c,h,d){
    const v=h.device,def=readable(d.sources?.defender)?d.defender:null,hw=readable(d.sources?.hardware)?d.hardware:null;
    const assigned=readable(d.sources?.assigned)&&Array.isArray(d.assigned)?d.assigned:null;
    const failed=assigned?assigned.filter(a=>['failed','uninstallfailed'].includes(str(a.state).toLowerCase())):null;
    const policies=readable(d.sources?.policies)&&Array.isArray(d.policies)?d.policies:null;
    const badPolicies=policies?policies.filter(p=>p.code===0):null;
    let html='<div class="iv360-health-strip">'+[['Windows update',updateStatus(h)],['Reboot required',show(def?.rebootRequired)],['Failed app installs',failed?String(failed.length):'Unknown']].map(([k,v])=>'<div><span>'+esc(k)+'</span><strong>'+esc(v)+'</strong></div>').join('')+'</div>';
    html+='<dl class="iv360-health-brief"><div><dt>Real-time protection</dt><dd>'+esc(show(def?.realTime))+'</dd></div><div'+(badPolicies?.length?' data-tone="warn"':'')+'><dt>Policies needing review</dt><dd>'+(badPolicies?badPolicies.length:'Unknown')+'</dd></div></dl>';
    html+=note('Device check-in '+dated(v.lastSync)+'.');
    let details='';
    details+=facts([['OS version',v.os],['Approved baseline',h.baseline?.label],['Last device check-in',dated(v.lastSync)],['Intune snapshot read',dated(h.at)],['Hardware/Defender read',dated(d.at)],['Free storage',Number.isFinite(v.freeB)&&Number.isFinite(v.totalB)&&v.totalB>0?(v.freeB/1073741824).toFixed(1)+' GiB of '+(v.totalB/1073741824).toFixed(1)+' GiB':null],['Reported battery health',typeof hw?.batteryHealthPercentage==='number'&&hw.batteryHealthPercentage>=0&&hw.batteryHealthPercentage<=100?hw.batteryHealthPercentage+'%':null],['Real-time protection',def?.realTime],['Tamper protection',def?.tamper],['Signatures overdue',def?.signatureOverdue],['Defender last reported',dated(def?.reported)],['Compliance',v.compliance]]);
    if(badPolicies?.length)details+='<div class="iv360-mini-list"><strong>Policy results needing review</strong>'+badPolicies.slice(0,6).map(p=>'<p>'+esc(p.name)+' — '+esc(p.status)+'</p>').join('')+'</div>';
    if(failed?.length)details+='<div class="iv360-mini-list"><strong>App installs needing review</strong>'+failed.slice(0,6).map(a=>'<p>'+esc(a.name)+' — '+esc(a.state)+'</p>').join('')+'</div>';
    if((badPolicies?.length||0)>6||(failed?.length||0)>6)details+=note('Showing the first six results in each list. Open Intune health for the full lists.');
    details+=note('Matched by verified Intune enrollment ID'+(h.serialVerified?' and serial.':'; serial is not reported by both sources.'));
    details+=note('Device readings describe the reported check-in, not current reachability. The link opens a filtered list; review the matching record there.')+healthLink(h);
    if(h.refreshError)html+=notice('The latest fleet refresh failed. This is the retained last-good Intune snapshot.');
    if(h.source.state==='partial')html+=notice('The Intune device source is partial; only the returned selected-device evidence is shown.');
    html+=sourceNotes(d.sources)+disclosure('Detailed Windows readings',details,false);
    return html;
  }
  function renderComparison(c,h){
    const imported=c.imported;
    let html=note('Reported values remain side by side. Missing data is not a disagreement. This comparison does not change inventory or the status summary above.');
    if(!imported.rawVerified)html+=notice('The original source row could not be uniquely recovered from the loaded inventory. Only the selected record’s known fields are shown.');
    if(!h){
      html+=facts([['Inventory source',imported.source],['Recorded owner',imported.owner],['Serial',imported.serial]]);
      const records=['ok','partial'].includes(c.result.detail?.inventory?.status)?c.result.detail.inventory.records||[]:[];
      html+=records.map(r=>'<article class="iv360-source-record"><strong>'+esc(r.source)+'</strong>'+facts([['Reported owner',r.owner],['Compliance',r.compliance],['Last check-in',r.lastCheckin]])+'</article>').join('');
      html+=disclosure('Source timestamps & counts',facts([['Inventory observed',dated(imported.observedAt)]])+records.map(r=>'<article class="iv360-source-record"><strong>'+esc(r.source)+'</strong>'+facts([['Source observed',dated(r.observedAt)]])+'</article>').join(''),false);
      return html+note(intuneReference(c.result.group)&&windows(c.row,c.result)?'The Intune comparison is unavailable. Stored source observations remain available; no substitute device was selected.':'No single verified Windows Intune enrollment is linked to this record. Stored source observations are shown without a live Intune comparison.');
    }
    const d=h.device,rows=compareValues(imported,{owner:d.user,os:d.os,compliance:d.compliance,encrypted:d.encrypted,lastCheckin:d.lastSync,serial:d.serial}),differences=rows.filter(r=>r.state==='different').length;
    html+='<p class="iv360-comparison-result">'+(differences?differences+' reported value'+(differences===1?' differs':'s differ'):'Reported values agree where both sources have data')+'</p>';
    html+='<div class="iv360-comparison-table"><table><caption>Selected device source comparison</caption><thead><tr><th scope="col">Field</th><th scope="col">'+esc(imported.source)+' inventory</th><th scope="col">Intune health</th></tr></thead><tbody>'+rows.map(r=>'<tr'+(r.state==='different'?' class="iv360-difference"':'')+'><th scope="row">'+esc(r.label)+(r.state==='different'?'<small>Values differ</small>':'')+'</th><td>'+esc(r.key==='lastCheckin'?dated(r.before):show(r.before))+'</td><td>'+esc(r.key==='lastCheckin'?dated(r.after):show(r.after))+'</td></tr>').join('')+'</tbody></table></div>';
    let collection=facts([['Loaded inventory row timestamp',dated(imported.observedAt)],['Stored source evidence observed',dated(imported.evidenceObservedAt)],['Intune snapshot read',dated(h.at)],['Current inventory rows, all OS',typeof DATA==='object'&&Array.isArray(DATA.intuneDevices)?DATA.intuneDevices.filter(r=>!r.is_historical).length:null],['Rows in Intune snapshot, all OS',h.count]]);
    collection+=note('Inventory fields are the loaded page snapshot. The stored-source time comes from the verified source row and may differ from the loaded snapshot. Historical imports are excluded from the current inventory total. These totals cover separate collection times and populations; a count difference alone does not identify a missing device.');
    if(h.refreshError)html+=notice('The latest Intune refresh failed; the retained snapshot is used.');
    if(h.source.state==='partial')html+=notice('The Intune device source is partial; the snapshot total covers returned rows only.');
    return html+disclosure('Source timestamps & counts',collection+healthLink(h),false);
  }
  function disclosure(title,content,open,extra){return '<details class="iv360-disclosure iv360-network-detail"'+(open?' open':'')+(extra||'')+'><summary><span class="iv360-detail-title">'+esc(title)+'</span><span class="ms iv360-chevron" aria-hidden="true">expand_more</span></summary><div class="iv360-disclosure-body">'+content+'</div></details>';}
  function evidenceTable(title,s,heads,row){
    if(!s)return note(title+': not reported.');
    let html='<div class="iv360-network-table"><table><caption>'+esc(title)+' · '+esc({ok:'Stored observations',empty:'No records',partial:'Partial evidence',unavailable:'Unavailable',denied:'Permission required',not_associated:'Not associated'}[s.status]||s.status||'Unknown')+'</caption><thead><tr>'+heads.map(h=>'<th scope="col">'+esc(h)+'</th>').join('')+'</tr></thead><tbody>';
    const records=['ok','empty','partial'].includes(s.status)&&Array.isArray(s.records)?s.records:[];
    html+=records.slice(0,12).map(r=>'<tr>'+row(r).map(v=>'<td>'+esc(show(v))+'</td>').join('')+'</tr>').join('');
    html+='</tbody></table></div>';
    if(s.reason)html+=note(s.reason);
    if(!records.length)html+=note(['ok','empty','partial'].includes(s.status)?'No matching stored observations; this does not establish offline state.':'This source could not establish evidence.');
    if(records.length>12||s.truncated)html+=note('Showing up to 12 returned records. Advanced network tools has the extended evidence.');
    return html;
  }
  function networkSummary(data){
    if(['denied','unavailable'].includes(data.status))return {choice:null,ips:[],vlans:[],switchCount:null,partial:false};
    const choice=data.identifiers?.interfaces?.find(i=>i.interfaceKey===data.selectedInterfaceKey),n=data.network;
    const records=s=>['ok','partial','empty'].includes(s?.status)&&Array.isArray(s.records)?s.records:[];
    const locations=records(n?.locations),bindings=records(n?.bindings);
    const unique=values=>[...new Set(values.filter(v=>v!=null&&v!=='').map(String))];
    return {choice,ips:unique([choice?.reportedIp,...bindings.filter(b=>!choice?.mac||b.association==='exact-selected-mac').map(b=>b.ip)]),vlans:unique(locations.map(r=>r.vlan)),switchCount:['ok','partial','empty'].includes(n?.locations?.status)?locations.length:null,partial:[n?.locations,n?.bindings].some(s=>s?.status==='partial')};
  }
  function networkControls(c,data){
    const options=data.identifiers.interfaces;
    if(!options.length)return '';
    return '<label class="iv360-interface-label" for="iv360-network-interface">Recorded network interface</label><select id="iv360-network-interface" aria-label="Recorded network interface"><option value="">Choose a recorded interface…</option>'+options.map(i=>'<option value="'+esc(i.interfaceKey)+'"'+(i.interfaceKey===c.interfaceKey?' selected':'')+(!i.selectable?' disabled':'')+'>'+esc(i.source+' · '+(i.mac||i.reportedIp||'No address')+(!i.selectable?' · association unconfirmed':''))+'</option>').join('')+'</select>';
  }
  function renderNetwork(c,data){
    let html=note('Recorded network context. Source dates describe stored observations, not a current connection.');
    if(['denied','unavailable'].includes(data.status))return html+notice(data.identifiers.reason||'Network evidence is '+data.status+'.')+networkLink(c);
    html+=networkControls(c,data);
    const n=data.network,s=networkSummary(data),choice=s.choice;
    if(!data.identifiers.interfaces.some(i=>i.selectable))html+=note('No verified network address is recorded. Advanced network tools can review additional sources.');
    if(data.identifiers.sources)html+=data.identifiers.sources.filter(s=>['denied','unavailable'].includes(s.status)).map(s=>notice(s.source+': '+s.status)).join('');
    if(n){
      const list=values=>values.length?values.slice(0,3).join(', ')+(values.length>3?' +'+(values.length-3)+' more':''):'Not reported';
      html+='<div class="iv360-health-strip iv360-network-overview">'+[['Recorded IP',list(s.ips)],['Recorded VLAN',list(s.vlans)],['Switch sightings',s.switchCount===null?'Unknown':String(s.switchCount)]].map(([label,value])=>'<div><span>'+esc(label)+'</span><strong>'+esc(value)+'</strong></div>').join('')+'</div>';
      const assessment={one_edge_candidate:'One recorded edge-port candidate; physical connection is unconfirmed.',multiple_edge_candidates:'Several recorded edge-port candidates; no location is confirmed.',uplinks_only:'Recorded sightings are uplinks; an endpoint port is not established.',unverified_ip:'Recorded IP only; hardware association is unverified.',no_cached_location:'No matching switch sighting in this snapshot.',unavailable:'Stored network observations are unavailable.'};
      html+=note(assessment[n.locationAssessment]||'Review the source dates before using these observations.');
      if(s.partial)html+=note('Network coverage is partial; only returned observations are summarized.');
      html+=note('Network snapshot '+dated(n.snapshotAt)+'.');
    }else if(data.identifiers.interfaces.some(i=>i.selectable))html+=note('Choose a recorded interface to view its stored network summary.');
    let details=facts([['Identifier source',choice?.source],['Recorded MAC',choice?.mac],['Inventory-reported IP',choice?.reportedIp],['Identifier observed',dated(choice?.observedAt)],['Network snapshot',dated(n?.snapshotAt)],['Evidence read',dated(data.readAt)]])+note(choice?.basis||'No interface selected.');
    if(n){
      details+=evidenceTable('Recorded switch / port / VLAN',n.locations,['Switch / port','Role / VLAN','Observed'],r=>[show(r.switch||r.switch_ip)+' · '+show(r.port),(r.role==='uplink'?'Uplink pattern':r.role==='edge_candidate'?'Edge candidate':show(r.role))+' / '+show(r.vlan),dated(r.observedAt)]);
      details+=evidenceTable('Recorded IP bindings',n.bindings,['IP / MAC','Association','Observed'],r=>[show(r.ip)+' / '+show(r.mac),r.association==='exact-selected-mac'?'Exact selected MAC':show(r.association),dated(r.observedAt)]);
    }
    html+=disclosure('Recorded network details',details,false);
    return html+'<div class="iv360-links">'+networkLink(c)+'</div>';
  }
  async function load(key,force){
    const c=context;if(!c||!section(c,key)||(c.loaded[key]&&!force)||c.busy[key])return;
    c.busy[key]=true;setMeta(c,key,'Reading…');body(c,key,'<p class="iv360-note" role="status">Reading '+esc(titles[key][0].toLowerCase())+'…</p>');
    try{
      if(key==='compare'){
        const h=intuneReference(c.result.group)&&windows(c.row,c.result)?await c.reader.health():null;
        if(!alive(c))return;body(c,key,renderComparison(c,h));setMeta(c,key,h?'Compared by ID':'Stored sources');
      }else if(key==='health'){
        const h=await c.reader.health(),d=await c.reader.detail(h);
        if(!alive(c))return;body(c,key,renderHealth(c,h,d));const partial=Object.values(d.sources||{}).some(s=>s&&s.state!=='ok')||h.source.state==='partial';setMeta(c,key,partial?'Partial health':'Reported health',partial);
      }else{
        const seq=++c.networkSequence,data=await c.reader.network(c.interfaceKey||null);
        if(!alive(c)||seq!==c.networkSequence)return;c.network=data;c.interfaceKey=data.selectedInterfaceKey||'';
        body(c,key,renderNetwork(c,data));setMeta(c,key,data.status==='denied'?'Permission required':data.status==='unavailable'?'Source unavailable':'Cached evidence',['denied','unavailable','partial'].includes(data.status));
        if(c.networkFocus){section(c,key)?.querySelector('select')?.focus({preventScroll:true});c.networkFocus=false;}
      }
      c.loaded[key]=true;
    }catch(error){
      if(!alive(c))return;
      body(c,key,notice(error.name==='AbortError'?'The evidence read timed out. Retry when ready.':error.message)+(key==='compare'?renderComparison(c,null):'')+'<button type="button" class="btn btn-ghost btn-sm" data-iv-insight-retry="'+key+'">Retry read</button>');setMeta(c,key,'Read unavailable',true);
    }finally{if(alive(c))c.busy[key]=false;}
  }
  document.addEventListener('toggle',event=>{const d=event.target;if(d.matches?.('#iv360-insights details[data-iv-insight]')&&d.open)load(d.getAttribute('data-iv-insight'));},true);
  document.addEventListener('click',event=>{const b=event.target.closest('[data-iv-insight-retry]');if(b)load(b.getAttribute('data-iv-insight-retry'),true);});
  document.addEventListener('change',event=>{
    if(event.target.id!=='iv360-network-interface'||!context)return;
    const c=context,value=event.target.value;
    if(value&&!c.network?.identifiers.interfaces.some(i=>i.interfaceKey===value&&i.selectable))return;
    c.interfaceKey=value;c.loaded.network=false;c.networkFocus=true;load('network',true);
  });
  window.Inventory360Insights={placeholder,mount,reset};
})();
