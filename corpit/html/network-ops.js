/* Network Operations: one shell, isolated views, existing APIs and entry URLs. */
(function(){
'use strict';
const E=NOC.esc, AS=window.NetworkOpsAssets, entry={overview:'/network-health.html',switches:'/network-switches.html',investigate:'/device-trace.html'};
const names={overview:'Overview',traffic:'Traffic',switches:'Switches',investigate:'Investigate'};
let state=parse(location), initial=true, navigating=0, modules={}, chromeStates={}, cache=new Map(), inventory=null, claims=[], watches=[], templates,evidenceSnapshot=null, permissionKeys={overview:'network-diag',traffic:'network-diag',switches:'network-diag',investigate:'network-diag'}, returnView='overview', suppressClose=false, currentView=null;
const initializing={},scrolls={}, generation={overview:0,traffic:0,switches:0,investigate:0};let revision=0,watchLoaded=false;
function parse(loc){
 const p=new URLSearchParams(loc.search), aliases={health:'overview',fabric:'switches',trace:'investigate',overview:'overview',traffic:'traffic',switches:'switches',investigate:'investigate'};
 const fallback=loc.pathname==='/network-switches.html'?'switches':loc.pathname==='/device-trace.html'?'investigate':'overview';
 const section=loc.hash.slice(1), range=Number(p.get('range')||p.get('hours')||72);
 const view=aliases[p.get('view')]||fallback;
 return {view,site:p.get('site')||(view==='traffic'?'SNA01':'ALL'),range:[24,48,72,120,168,720].includes(range)?range:72,q:p.get('q')||'',as:p.get('as')==='device'?'device':'',trafficWindow:['today','24h','7d'].includes(p.get('trafficWindow'))?p.get('trafficWindow'):'today',trafficFrom:p.get('trafficFrom')||'',trafficTo:p.get('trafficTo')||'',trafficIp:p.get('trafficIp')||'',trafficDest:p.get('trafficDest')||'',switch:p.get('switch')||'',port:p.get('port')||'',portName:p.get('portName')||'',portSearch:p.get('portSearch')||'',portCondition:['errors','devices','up','down','uplinks'].includes(p.get('portCondition'))?p.get('portCondition'):'all',panel:['port','switch'].includes(p.get('panel'))?p.get('panel'):(p.get('port')?'port':''),severity:['critical','warn','info'].includes(p.get('severity'))?p.get('severity'):'all',faultSearch:p.get('faultSearch')||'',condition:['offline','offstd','core'].includes(p.get('condition'))?p.get('condition'):'all',switchSearch:p.get('switchSearch')||'',section:({firewalls:'fw',firewall:'fw',wifi:'wifi',watch:'watch',fw:'fw'})[section]||'',from:aliases[p.get('from')]||'',originSwitch:p.get('originSwitch')||'',originPort:p.get('originPort')||'',originPortName:p.get('originPortName')||'',faultSort:p.get('faultSort')||'',faultDir:p.get('faultDir')==='descending'?'descending':'ascending',switchSort:p.get('switchSort')||'',switchDir:p.get('switchDir')==='descending'?'descending':'ascending'};
}
function stateURL(st,path=location.pathname){
 const u=new URL(path,location.origin),defs={site:'ALL',range:72,trafficWindow:'today',severity:'all',condition:'all',portCondition:'all',faultDir:'ascending',switchDir:'ascending'};
 Object.keys(st).forEach(k=>{if(k==='section')return;const v=st[k];if(v!==''&&v!=null&&v!==defs[k])u.searchParams.set(k,v);});
 if(st.section)u.hash=st.section;return u.pathname+u.search+u.hash;
}
function persist(){if(initial)return;history.replaceState({networkOps:true,scroll:scrollY},'',stateURL(state));syncControls();}
function filters(p){Object.assign(state,p);persist();}
async function json(url,opts={}){
 const key=url, cached=cache.get(key), now=Date.now();
 if(!opts.fresh&&cached&&cached.expires>now)return structuredClone(await cached.promise);
 const promise=(async()=>{const ctl=new AbortController(),timer=setTimeout(()=>ctl.abort(),20000);
  try{const r=await fetch(url,{credentials:'include',signal:ctl.signal});if(r.status===401)throw Object.assign(Error('Your session expired. Sign in again.'),{code:401});if(!r.ok)throw Error('Request failed (HTTP '+r.status+').');const d=await r.json();if(d?.ok===false)throw Error(typeof d.detail==='string'?d.detail:typeof d.error==='string'?d.error:'Data is unavailable.');if(url==='/api/netswitch/overview')acceptInventory(d);if(url==='/api/netswitch/claims')claims=d.claims||[];if(url==='/api/netswitch/watch'){watches=d.items||[];watchLoaded=true;}return d;
  }catch(e){if(e.name==='AbortError')throw Error('This lookup took too long. Try again or choose another device.');throw e;}finally{clearTimeout(timer);}})();
 cache.set(key,{expires:now+30000,promise});promise.catch(()=>{if(cache.get(key)?.promise===promise)cache.delete(key);});
 return structuredClone(await promise);
}
function can(view){return !!(itRbac.isVerified()&&(itRbac.me()?.isSuperAdmin||permissionKeys[view]&&itRbac.canAccess(permissionKeys[view])));}
function scopeDevices(ds){return (ds||[]).filter(d=>state.site==='ALL'||d.site===state.site);}
function scopeIssues(rows,devices){const by=new Map((devices||inventory?.devices||[]).map(d=>[d.ip,d.site]));return (rows||[]).filter(i=>state.site==='ALL'||(i.site||by.get(i.switch_ip))===state.site);}
function summarize(ds){const rows=scopeDevices(ds),up=rows.filter(d=>d.reachable).length;return {switches:rows.length,switches_up:up,switches_down:rows.length-up,ports_up:rows.reduce((n,d)=>n+(d.if_up||0),0),ports:rows.reduce((n,d)=>n+(d.if_total||0),0)};}
function acceptInventory(d){inventory=d;syncSites();}
function syncSites(){const el=document.getElementById('opsSite');if(!el)return;const sites=[...new Set((inventory?.devices||[]).map(d=>d.site).filter(Boolean))].sort();if(state.site!=='ALL'&&!sites.includes(state.site))sites.push(state.site);const choices=state.view==='traffic'?['SNA01','DFW02']:['ALL',...sites];el.replaceChildren(...choices.map(site=>{const o=document.createElement('option');o.value=site;o.textContent=site==='ALL'?'All sites':site==='SNA01'?'Irvine':site==='DFW02'?'Plano':site;return o;}));el.value=state.site;}
function notify(s){document.getElementById('opsMessage').textContent=s;}
function syncControls(){
 document.getElementById('opsRange').value=String(state.range);document.getElementById('opsRange').closest('label').hidden=state.view==='traffic';syncSites();
 document.querySelector('.ncrumb .sub').textContent=(state.site==='ALL'?'All sites':state.site)+' · '+names[state.view];
 document.title='Network Operations · '+names[state.view]+' — IT Command';
 document.querySelectorAll('[data-ops-view]').forEach(b=>{const on=b.dataset.opsView===state.view;b.setAttribute('aria-selected',String(on));b.tabIndex=on?0:-1;b.classList.toggle('on',on);b.hidden=!can(b.dataset.opsView);});
 document.querySelectorAll('#nSide [data-nav]').forEach(a=>{const v={health:'overview',fabric:'switches',trace:'investigate'}[a.dataset.nav];if(v){a.querySelector('.lbl').textContent=names[v];a.setAttribute('aria-current',v===state.view||v==='overview'&&state.view==='traffic'?'page':'false');a.hidden=!can(v);}});
 document.getElementById('opsScopeNote').textContent=state.view==='overview'?(state.site==='ALL'?'Fleet overview':'Switches and faults: '+state.site+' · wireless, firewalls and trend: fleet'):state.view==='traffic'?'One site · source freshness and scope shown for each layer':state.view==='switches'?'Inventory scoped to '+(state.site==='ALL'?'all sites':state.site):'Lookups can resolve devices across sites'+(state.range>168?' · Wi-Fi history is limited to 7 days':'');
 const back=document.getElementById('opsBack'),target=backTarget();back.hidden=!target||(state.view==='overview'&&!state.port);back.textContent='Back to '+(names[target]||'overview').toLowerCase();
 document.getElementById('opsSelected').textContent=[state.switch, state.portName].filter(Boolean).join(' · ');
}
function backTarget(){const preferred=state.from||returnView;if(preferred!==state.view&&can(preferred))return preferred;if(state.view!=='overview'&&can('overview'))return 'overview';return Object.keys(names).find(v=>v!==state.view&&can(v))||null;}
function chromeFor(view){const c=chromeStates[view]={vitals:[],stamp:['Ready',false]};return Object.assign({},NOC,{act(html){document.getElementById('opsActions-'+view).innerHTML=html;},vitals(v){c.vitals=v;if(state.view===view)NOC.vitals(v);},stamp(...a){c.stamp=a;if(state.view===view)NOC.stamp(...a);},badge(k,n,t){NOC.badge(k,n,t);},sortable(table){NOC.sortable(table);restoreSort(view);}});}
function asset(name){return AS[name]||'/'+name;}
function script(name){return new Promise((resolve,reject)=>{const s=document.createElement('script');s.src=asset(name);s.onload=resolve;s.onerror=()=>{s.remove();reject(Error('Could not load this view. Retry the workspace.'));};document.head.appendChild(s);});}
function getModule(view){if(initializing[view])return initializing[view];if(modules[view])return Promise.resolve(modules[view]);initializing[view]=constructModule(view).finally(()=>delete initializing[view]);return initializing[view];}
async function constructModule(view){if(modules[view])return modules[view];
 const root=document.getElementById('ops-'+view);root.innerHTML=templates[view];await script('network-ops-'+view+'.js');
 const context={state:()=>state,json,chrome:chromeFor(view),filters:p=>{if(state.view===view&&!initializing[view])filters(p);},navigate,inventory:acceptInventory,scopeIssues,scopeDevices,summarize,copy,watch,watchChanged:()=>window.NetworkOps.watchChanged(),selectSwitch:ip=>{state.switch=ip;persist();},evidence:renderEvidence,clearEvidence,beginTrace,write,notify,search,root};
 const m=window.NetworkOpsModules[view](context);modules[view]=m;const ok=await m.ready;if(ok===false){delete modules[view];throw Error('Could not read this view. Retry the workspace.');}generation[view]=revision;return m;
}
async function render({restoreScroll=null,focus=false}={}){
 const request=++navigating;const view=state.view;
 suppressClose=true;ITDrawer.close();suppressClose=false;
 closeSearch();document.getElementById('nQ').removeAttribute('aria-invalid');
 document.body.dataset.opPage={overview:'network-health',traffic:'network-health',switches:'network-switches',investigate:'device-trace'}[view];
 document.querySelectorAll('.ops-view').forEach(el=>el.hidden=el.id!=='ops-'+view);
 document.querySelectorAll('.ops-actions').forEach(el=>el.hidden=el.id!=='opsActions-'+view);
 syncControls();if(!can(view)){document.getElementById('ops-'+view).innerHTML='<div class="nempty"><b>This view is not available to your account</b>Your existing page permissions still apply.</div>';notify('Choose a view available to your account.');return;}
 const root=document.getElementById('ops-'+view);root.setAttribute('aria-busy','true');
 try{const m=await getModule(view);if(request!==navigating)return;
  // Bootstrap filters are suppressed; live controls remain authoritative while loading.
  if(generation[view]<revision){const ok=await m.refresh();if(ok!==false)generation[view]=revision;else notify('Could not refresh this view. Previous loaded data is shown; retry Refresh.');if(request!==navigating)return;}
  document.getElementById('nQ').value=view==='investigate'?state.q:'';
  if(view==='investigate'){if(modules[view].query?.()===state.q&&evidenceSnapshot?.seq===state.q)renderEvidence(evidenceSnapshot);else clearEvidence();}m.activate(state);restoreSort(view);currentView=view;const c=chromeStates[view];NOC.vitals(c.vitals);NOC.stamp(...c.stamp);syncControls();
  if(state.panel==='port'&&state.switch&&state.port){ITDrill.setHours(state.range);const d=inventory?.devices?.find(d=>d.ip===state.switch);await ITDrill.portDetail(state.switch,d?.name||state.switch,state.port,state.portName||'Port '+state.port);}
  else if(state.panel==='switch'&&state.switch){const d=inventory?.devices?.find(d=>d.ip===state.switch);await ITDrill.switchDetail(state.switch,d?.name||state.switch);}
  if(request!==navigating){if(state.panel!=='port'&&state.panel!=='switch'){suppressClose=true;ITDrawer.close();suppressClose=false;}return;}
  if(state.section&&view==='overview')document.getElementById('oh-'+state.section)?.scrollIntoView({block:'center'});
  else if(restoreScroll!=null)window.scrollTo(0,restoreScroll);else window.scrollTo(0,scrolls[view]||0);
  if(focus&&!state.panel){root.tabIndex=-1;root.focus({preventScroll:true});}
  initial=false;persist();
 }catch(e){if(request!==navigating)return;notify(e.message);root.innerHTML='<div class="nempty"><b>This view could not be loaded</b>'+E(e.message)+' <button class="nbtn" data-ops-retry>Retry</button></div>';delete modules[view];}
 finally{root.removeAttribute('aria-busy');}
}
async function navigate(patch,options={}){
 notify('');const leaving=state.view;scrolls[leaving]=scrollY;
 if(modules[leaving])Object.assign(state,modules[leaving].capture());
 // Save the outgoing history entry before clearing its drawer or section.
 history.replaceState({networkOps:true,scroll:scrollY},'',stateURL(state));
 const next={...state,...patch};
 if(next.view==='traffic'&&next.site==='ALL')next.site='SNA01';
 if(patch.view&&patch.view!==leaving){modules[leaving]?.deactivate();
  for(const key of ['panel','port','portName','section'])if(!Object.prototype.hasOwnProperty.call(patch,key))next[key]='';
  document.getElementById('opsEvidence').hidden=patch.view!=='investigate';
  if(!Object.prototype.hasOwnProperty.call(patch,'from')&&leaving!=='investigate'){returnView=leaving;next.from=leaving;}
 }
 state=next;history[options.replace?'replaceState':'pushState']({networkOps:true,scroll:scrolls[next.view]||0},'',stateURL(state));await render({focus:options.focus!==false&&!!patch.view});
}
async function refresh(){cache.clear();revision++;const view=state.view,m=modules[view];if(!m)return;notify('Refreshing the current view…');try{const ok=await m.refresh();if(ok===false){if(state.view===view)notify('Refresh did not complete. See the view error and retry.');return;}generation[view]=revision;if(state.view!==view)return;await render();notify('View refreshed.');}catch(e){notify(e.message);}}
function saveSort(target){const th=target.closest?.('th[data-key][aria-sort]');if(!th)return;const view=th.closest('.ops-view')?.id;if(view==='ops-overview')filters({faultSort:th.dataset.key,faultDir:th.getAttribute('aria-sort')});if(view==='ops-switches')filters({switchSort:th.dataset.key,switchDir:th.getAttribute('aria-sort')});}
function restoreSort(view){const key=view==='overview'?state.faultSort:view==='switches'?state.switchSort:'',dir=view==='overview'?state.faultDir:state.switchDir;if(!key)return;const th=[...document.querySelectorAll('#ops-'+view+' th[data-key]')].find(th=>th.dataset.key===key);if(!th)return;if(th.getAttribute('aria-sort')!==dir){th.click();if(th.getAttribute('aria-sort')!==dir)th.click();}}
document.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' ')saveSort(e.target);});
function closeSearch(){const box=document.getElementById('opsSearchResults');box.hidden=true;document.getElementById('nQ').setAttribute('aria-expanded','false');}
function searchResults(){const q=document.getElementById('nQ').value.trim(),box=document.getElementById('opsSearchResults');box.replaceChildren();if(!q){closeSearch();return;}
 const matches=can('switches')?(inventory?.devices||[]).filter(d=>[d.name,d.ip,d.serial,d.model].some(v=>String(v||'').toLowerCase().includes(q.toLowerCase()))).slice(0,6):[];
 for(const d of matches){const b=document.createElement('button');b.type='button';b.textContent=d.name+' · '+d.ip+' · '+(d.site||'');b.onclick=()=>{closeSearch();navigate({view:'switches',site:d.site||state.site,switch:d.ip,switchSearch:'',condition:'all'});};box.appendChild(b);}
 if(can('investigate')){const b=document.createElement('button');b.type='button';b.textContent='Investigate “'+q+'”';b.onclick=()=>trace(q);box.appendChild(b);}
 box.hidden=!box.children.length;document.getElementById('nQ').setAttribute('aria-expanded',String(!box.hidden));
}
async function search(q){q=String(q||'').trim();if(!q)return;
 const d=can('switches')&&(inventory?.devices||[]).find(d=>[d.name,d.ip,d.serial].some(v=>String(v||'').toLowerCase()===q.toLowerCase()));
 if(d)return navigate({view:'switches',switch:d.ip,site:d.site||state.site,condition:'all',switchSearch:''});
 if(!can('investigate')){notify('Choose a matching switch from the search results.');searchResults();return;}
 return trace(q);
}
function originFor(q,as){
 if(state.panel==='port')return {originSwitch:state.switch,originPort:state.port,originPortName:state.portName};
 return q===state.q&&as===state.as?{originSwitch:state.originSwitch,originPort:state.originPort,originPortName:state.originPortName}:{originSwitch:'',originPort:'',originPortName:''};
}
function clearEvidence(){evidenceSnapshot=null;const el=document.getElementById('opsEvidence');el.replaceChildren();el.hidden=true;}
function beginTrace(q,as=''){const origin=originFor(q,as);clearEvidence();filters({...origin,q,as});}
function trace(q,as=''){if(!can('investigate')){notify('Device investigation is not available to your account.');return;}
 closeSearch();return navigate({...originFor(String(q).trim(),as),view:'investigate',q:String(q).trim(),as,from:state.view==='investigate'?state.from:state.view,panel:'',port:'',section:''});}
function openPort(ip,name,ifx,pt){return navigate({switch:String(ip),port:String(ifx),portName:String(pt||''),panel:'port',section:''});}
function drawerClosed(){if(suppressClose)return;filters({panel:'',port:'',portName:''});}
function range(h){return navigate({range:Number(h)});}
function related(ip,ifx,pt){return (inventory?.issues||[]).filter(i=>i.switch_ip===ip&&(String(i.ifindex)===String(ifx)||pt&&i.port===pt));}
function portEvidence(ip,name,ifx,pt){const issues=related(ip,ifx,pt),ref=ip+':'+ifx,pinned=watches.find(w=>w.kind==='port'&&w.ref===ref);let html='<section class="ops-related"><h3>Related evidence</h3>';
 html+=(inventory?issues.length?issues.map(i=>'<div class="ops-finding"><span class="sev '+({critical:'crit',warn:'warn',info:'info'}[i.severity]||'info')+'">'+E(i.severity)+'</span> '+E(i.title||(typeof i.diag==='string'?safeJSON(i.diag):i.diag)?.title||i.kind||'Port finding')+(claims.find(c=>c.ref===ip+':'+i.port)?'<span> · Owner: '+E(claims.find(c=>c.ref===ip+':'+i.port).claimed_by)+'</span>':'')+'</div>').join(''):'<p>No matching findings in the loaded overview.</p>':'<p>Fault evidence is unavailable for this account or request.</p>');
 html+='<p>'+E(!watchLoaded?'Watch status unavailable':pinned?'On the watch list':'Not on the loaded watch list')+'</p><div class="op-tools">';
 if(can('switches'))html+='<button class="nbtn" data-ops-switch="'+E(ip)+'">View switch</button>';
 if(can('overview'))html+='<button class="nbtn" data-ops-faults="'+E(ip)+'">Faults on this switch</button>';
 html+='<button class="nbtn" data-ops-copy>Copy investigation link</button><button class="nbtn" data-ops-summary>Copy support summary</button>';
 if(!pinned&&!window.ITWatch)html+='<button class="nbtn" data-ops-watch-port="'+E(ref)+'" data-ops-label="'+E(pt+' · '+name)+'" data-ops-ip="'+E(ip)+'" data-ops-name="'+E(name)+'" data-ops-port="'+E(pt)+'">Watch this port</button>';
 return html+'</div></section>';
}
async function loadEvidence(){await Promise.allSettled([(can('overview')||can('switches'))?json('/api/netswitch/overview'):Promise.resolve(),can('overview')?json('/api/netswitch/claims'):Promise.resolve(),json('/api/netswitch/watch')]);}
async function watch(item){if(!item)return;if(item.kind==='port'){const [ip,ifx]=item.ref.split(':');const meta=typeof item.meta==='string'?safeJSON(item.meta):item.meta||{};return openPort(ip,meta.switch||ip,ifx,meta.port||'Port '+ifx);}if(item.kind==='device')return trace(item.ref);notify('This watch item can be inspected in Live Building.');}
async function write(url,method,body){
 const r=await fetch(url,{method,credentials:'include',headers:{'Content-Type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})});
 const d=await r.json().catch(()=>({}));if(!r.ok||d.ok===false)throw Error(d.detail||d.error||'Action failed (HTTP '+r.status+').');
 cache.delete('/api/netswitch/claims');return d;
}
function supportSummary(){
 const lines=['Network Operations support summary','Captured: '+new Date().toISOString(),'View: '+names[state.view],'Site: '+(state.site==='ALL'?'All sites':state.site),'History window: '+(state.view==='traffic'?(state.trafficFrom?state.trafficFrom+' to '+state.trafficTo:state.trafficWindow):state.range/24+' days'),'Link: '+new URL(stateURL(state),location.origin).href];
 const add=(label,el)=>{if(el&&!el.hidden){const text=el.innerText.trim();if(text)lines.push('',label+':',text);}};
 add('Loaded status',document.getElementById('nVit'));
 if(state.view==='overview'){lines.push('Fault filter: '+state.severity+(state.faultSearch?' / '+state.faultSearch:''));add('Fault totals',document.getElementById('oh-fFoot'));}
 if(state.view==='traffic'){lines.push('Source IP: '+(state.trafficIp||'All'),'Destination IP: '+(state.trafficDest||'All'));add('WAN meters',document.querySelector('#ops-traffic .traffic-gauges'));add('Firewall destinations',document.getElementById('tr-dest'));add('Firewall sources',document.getElementById('tr-sources'));add('Observed proxy users',document.getElementById('tr-users'));add('Observed proxy domains',document.getElementById('tr-web'));add('Switch sample status',document.getElementById('tr-switches'));}
 if(state.view==='switches')add('Selected switch',document.getElementById('os-detail'));
 if(state.view==='investigate'){lines.push('Query: '+(state.q||'None'));add('Investigation context',document.getElementById('opsEvidence'));add('Result',document.getElementById('ot-out'));}
 const drawer=document.querySelector('.u-drawer[aria-hidden="false"]');if(drawer){add('Port / switch',document.getElementById('uDTitle'));add('Detail evidence',document.getElementById('uDBody'));}
 lines.push('','This summary reflects loaded evidence. Inventory and history may be delayed; a learned device does not establish user impact.');
 return lines.join('\n');
}
// The message changes only once the write has resolved, and an older click can't overwrite
// a newer one's message. A rejected write falls back to a selected textarea copy.
let copySeq=0;
async function clip(text,done,failed){const seq=++copySeq;notify('Copying…');let ok=false;
 try{await navigator.clipboard.writeText(text);ok=true;}catch{const t=document.createElement('textarea');t.value=text;t.setAttribute('readonly','');t.style.cssText='position:fixed;top:-9999px';document.body.appendChild(t);t.select();try{ok=document.execCommand('copy');}catch{ok=false;}t.remove();}
 if(seq===copySeq)notify(ok?done:failed);return ok;}
async function copySummary(){let text;try{text=supportSummary();}catch(e){notify('Could not build the support summary: '+e.message);return;}
 await clip(text,'Support summary copied ('+text.length.toLocaleString()+' characters) with the current evidence, capture time and workspace link.','Could not copy the support summary. Check clipboard access and try again.');}
function safeJSON(s){try{return JSON.parse(s)}catch{return{}}}
async function copy(){await clip(new URL(stateURL(state),location.origin).href,'Workspace link copied, including the current filters and selection.','Could not copy automatically. Copy the address from your browser.');}
async function renderEvidence(ev){if(state.view!=='investigate'||state.q!==ev.seq)return;evidenceSnapshot=ev;const host=document.getElementById('opsEvidence');host.hidden=false;let html='<div class="nch"><h2>Investigation context</h2></div><div class="ncb"><p>'+E([ev.ip,ev.mac,ev.person?.displayName||ev.person?.name].filter(Boolean).join(' · ')||ev.query)+'</p>';
 if(ev.edge){const e=ev.edge;html+='<div class="op-tools"><button class="nbtn" data-ops-port-ip="'+E(e.switch_ip)+'" data-ops-ifx="'+E(e.ifindex||'')+'" data-ops-port-name="'+E(e.port)+'">Inspect '+E(e.switch)+' / '+E(e.port)+'</button>'+(can('switches')?'<button class="nbtn" data-ops-switch="'+E(e.switch_ip)+'">View switch</button>':'')+'</div><p>Switch attachment is observed evidence; a device learned on a port is not automatically an affected user.</p>';
 }else html+='<p>No switch attachment was resolved for this lookup.</p>';
 if(ev.ip&&can('traffic'))html+='<button class="nbtn" data-ops-traffic-ip="'+E(ev.ip)+'">View traffic for '+E(ev.ip)+'</button>';
 if(state.originSwitch&&state.originPort){const d=inventory?.devices?.find(d=>d.ip===state.originSwitch);html+='<p>Opened from '+E(d?.name||state.originSwitch)+' / '+E(state.originPortName||state.originPort)+' in the last learned port inventory.</p><button class="nbtn" data-ops-port-ip="'+E(state.originSwitch)+'" data-ops-ifx="'+E(state.originPort)+'" data-ops-port-name="'+E(state.originPortName)+'">Inspect originating port</button>';}

 host.innerHTML=html+'</div>';
}
window.NetworkOps={search,trace,range,openPort,drawerClosed,portEvidence,loadEvidence,parse,stateURL,read:json,isWatched:(kind,ref)=>watches.some(w=>w.kind===kind&&w.ref===ref),watchChanged:async item=>{cache.delete('/api/netswitch/watch');if(item)watches.push(item);try{await json('/api/netswitch/watch');}catch{watchLoaded=false;}}};
NOC.mount({page:'health',title:'Network Operations',sub:'Loading workspace…'});
const main=document.getElementById('nocContent');
main.innerHTML='<div class="ops-workspace"><div class="ops-toolbar"><div role="tablist" aria-label="Network Operations views" class="nseg ops-tabs">'+Object.keys(names).map(v=>'<button role="tab" id="ops-tab-'+v+'" data-ops-view="'+v+'" aria-controls="ops-'+v+'" aria-selected="false">'+names[v]+'</button>').join('')+'</div><label>Site <select class="op-input" id="opsSite"><option value="ALL">All sites</option></select></label><label>History <select class="op-input" id="opsRange"><option value="24">1 day</option><option value="48">2 days</option><option value="72">3 days</option><option value="120">5 days</option><option value="168">7 days</option><option value="720">30 days</option></select></label><button class="nbtn" id="opsCopy">Copy workspace link</button><button class="nbtn" id="opsSummary">Copy support summary</button></div><div class="ops-context"><button class="nbtn" id="opsBack" hidden>Back to overview</button><span id="opsScopeNote"></span><span id="opsSelected"></span></div><p id="opsMessage" role="status" aria-live="polite"></p><section class="ncard" id="opsEvidence" hidden></section>'+Object.keys(names).map(v=>'<section class="ops-view" role="tabpanel" id="ops-'+v+'" aria-labelledby="ops-tab-'+v+'" hidden></section>').join('')+'</div>';
NOC.act(Object.keys(names).map(v=>'<div class="ops-actions" id="opsActions-'+v+'" hidden></div>').join(''));
const searchInput=document.getElementById('nQ');searchInput.setAttribute('aria-label','Search switches, devices, addresses or people');searchInput.placeholder='Search switches, devices, IP, MAC or people…';searchInput.setAttribute('aria-controls','opsSearchResults');searchInput.setAttribute('aria-expanded','false');
searchInput.parentElement.insertAdjacentHTML('beforeend','<div id="opsSearchResults" class="ops-search-results" aria-label="Network search results" hidden></div>');
searchInput.addEventListener('input',searchResults);
searchInput.addEventListener('keydown',e=>{const results=document.getElementById('opsSearchResults');if(e.key==='Escape'){closeSearch();e.stopPropagation();}if(e.key==='ArrowDown'&&!results.hidden){e.preventDefault();results.querySelector('button')?.focus();}});
document.getElementById('opsSearchResults').addEventListener('keydown',e=>{const bs=[...e.currentTarget.querySelectorAll('button')],i=bs.indexOf(document.activeElement);if(e.key==='ArrowDown'||e.key==='ArrowUp'){e.preventDefault();bs[(i+(e.key==='ArrowDown'?1:bs.length-1))%bs.length]?.focus();}if(e.key==='Escape'){closeSearch();searchInput.focus();}});
document.getElementById('opsSite').onchange=e=>navigate({site:e.target.value,switch:'',port:'',panel:''});
document.getElementById('opsRange').onchange=e=>range(e.target.value);
document.getElementById('opsCopy').onclick=copy;
document.getElementById('opsSummary').onclick=copySummary;
document.getElementById('opsBack').onclick=()=>{const target=backTarget();if(target)navigate({view:target,panel:'',port:'',section:'',from:''});};
document.querySelector('.ops-tabs').addEventListener('keydown',e=>{if(!['ArrowLeft','ArrowRight','Home','End'].includes(e.key))return;const tabs=[...e.currentTarget.querySelectorAll('button')].filter(b=>!b.hidden),i=tabs.indexOf(e.target);if(i<0)return;e.preventDefault();const n=e.key==='Home'?0:e.key==='End'?tabs.length-1:(i+(e.key==='ArrowRight'?1:tabs.length-1))%tabs.length;tabs[n].click();tabs[n].focus();});
document.addEventListener('click',e=>{if(e.target.closest('#oh-nRefresh,#os-nRefresh')){e.preventDefault();e.stopImmediatePropagation();refresh();}},true);
document.addEventListener('click',async e=>{
 saveSort(e.target);
 const view=e.target.closest('[data-ops-view]');if(view){navigate({view:view.dataset.opsView},{focus:false});return;}
 if(e.target.closest('[data-ops-retry]')){render();return;}
 const a=e.target.closest('a[href]');if(a&&!e.ctrlKey&&!e.metaKey&&!e.shiftKey&&!e.altKey&&a.target!=='_blank'){
  const u=new URL(a.href,location.href),view=Object.keys(entry).find(v=>entry[v]===u.pathname);
  if(view&&u.origin===location.origin){e.preventDefault();const incoming=parse(u),patch={view:incoming.view};for(const k of new URLSearchParams(u.search).keys())if(k in incoming)patch[k]=incoming[k];if(u.searchParams.has('hours'))patch.range=incoming.range;if(u.hash)patch.section=incoming.section;document.body.classList.remove('nav-open');document.getElementById('nBurger').setAttribute('aria-expanded','false');navigate(patch);return;}
 }
 const sw=e.target.closest('[data-ops-switch]');if(sw){const d=inventory?.devices?.find(d=>d.ip===sw.dataset.opsSwitch);navigate({view:'switches',switch:sw.dataset.opsSwitch,site:d?.site||state.site,condition:'all',switchSearch:'',panel:'',port:''});return;}
 const traffic=e.target.closest('[data-ops-traffic-ip],[data-ops-traffic]');if(traffic){navigate({view:'traffic',site:state.site==='ALL'?'SNA01':state.site,trafficIp:traffic.dataset.opsTrafficIp||'',trafficDest:'',trafficFrom:'',trafficTo:''});return;}
 const faults=e.target.closest('[data-ops-faults]');if(faults){navigate({view:'overview',faultSearch:faults.dataset.opsFaults,severity:'all',panel:'',port:''});return;}
 const pt=e.target.closest('[data-ops-port-ip]');if(pt){let ifx=pt.dataset.opsIfx;if(!ifx){try{const d=await json('/api/netswitch/switch/'+encodeURIComponent(pt.dataset.opsPortIp));ifx=d.ports?.find(p=>p.port===pt.dataset.opsPortName)?.ifindex;}catch(err){notify(err.message);return;}}if(ifx)openPort(pt.dataset.opsPortIp,'',ifx,pt.dataset.opsPortName);else notify('The port identifier was not available in this snapshot.');return;}
 if(e.target.closest('[data-ops-summary]')){copySummary();return;}
 if(e.target.closest('[data-ops-copy]')){copy();return;}
 const pin=e.target.closest('[data-ops-watch-port]');if(pin){pin.disabled=true;try{const r=await fetch('/api/netswitch/watch',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({kind:'port',ref:pin.dataset.opsWatchPort,label:pin.dataset.opsLabel,meta:{switch:pin.dataset.opsName,port:pin.dataset.opsPort,switch_ip:pin.dataset.opsIp}})});const j=await r.json();if(!r.ok||!j.ok)throw Error(j.detail||'Could not watch this port.');cache.delete('/api/netswitch/watch');pin.textContent='Watching this port';notify('Port added to the watch list.');}catch(err){pin.disabled=false;notify(err.message);}return;}
 if(!e.target.closest('.nsearch'))closeSearch();
});
// Capture existing fault/faceplate requests and route them into the common drawer.
const originalPort=ITDrill.portDetail;ITDrill.portDetail=function(ip,name,ifx,pt){ITDrill.setHours(state.range);filters({switch:String(ip),port:String(ifx),portName:String(pt||''),panel:'port'});return originalPort(ip,name,ifx,pt);};
window.addEventListener('popstate',()=>{modules[state.view]?.deactivate();state=parse(location);render({restoreScroll:history.state?.scroll||0});});
window.addEventListener('hashchange',()=>{const next=parse(location);if(next.section&&(state.section!==next.section||state.view!=='overview')){navigate({view:'overview',section:next.section},{replace:true});}});
(async()=>{try{
 await itRbac.ready();const profile=itRbac.me();
 try{const registry=await json('/api/rbac/pages');for(const p of registry.pages||[]){let path;try{path=new URL(p.url_path,location.origin).pathname}catch{continue}const v=Object.keys(entry).find(v=>entry[v]===path);if(v)permissionKeys[v]=p.page_key;}}catch(e){if(!profile?.isSuperAdmin)throw e;}
 // All three existing network API surfaces use network-diag; honor any explicit registry override.
 for(const v of Object.keys(names)){for(const el of [document.getElementById('ops-'+v),document.getElementById('ops-tab-'+v)])el.setAttribute('data-rbac-page',permissionKeys[v]);}
 document.getElementById('opsEvidence').setAttribute('data-rbac-page',permissionKeys.investigate);itRbac.applyDomGuards();
 templates=await json(asset('network-ops-views.json'));await render();
 }catch(e){notify('Could not open Network Operations: '+e.message);document.getElementById('ops-overview').hidden=false;document.getElementById('ops-overview').innerHTML='<div class="nempty"><b>Workspace unavailable</b><button class="nbtn" onclick="location.reload()">Retry</button></div>';}})();
})();
