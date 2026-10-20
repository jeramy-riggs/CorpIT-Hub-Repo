'use strict';
const net=require('net'),crypto=require('crypto');
const detail=require('./identity-device-detail'),network=require('./identity-device-network');
const providers=require('./network-device-live');
const historySites=[{key:'SNA01',label:'Irvine'},{key:'DFW02',label:'Plano TX'}];
const text=v=>typeof v==='string'?v.trim():'';
const hostname=v=>/^[A-Za-z0-9._-]{1,64}$/.test(v);
function privateIp(v){if(!net.isIPv4(v))return false;const a=v.split('.').map(Number);return a[0]===10 || a[0]===192&&a[1]===168 || a[0]===172&&a[1]>=16&&a[1]<=31;}
const ticketStore=new Map(),inflight=new Set(),lastRun=new Map();
const actor=req=>String(req.user?.id||req.user?.email||req.user?.upn||req.currentUser?.id||req.currentUser?.email||req.auth?.sub||'');
function identity(req,context){return actor(req)+'|'+context.group.deviceKey+'|'+context.q.toLowerCase()+'|'+(context.choice?.interfaceKey||'');}
function ticket(req,context,row,now=Date.now()){
  for(const [key,v] of ticketStore)if(v.expires<now)ticketStore.delete(key);
  while(ticketStore.size>=300)ticketStore.delete(ticketStore.keys().next().value);
  const key=crypto.randomBytes(24).toString('hex');ticketStore.set(key,{scope:identity(req,context),row,expires:Math.min(now+300000,Number.isFinite(Date.parse(row.expiresAt))?Date.parse(row.expiresAt):Infinity)});return key;
}
function leaseTarget(req,context,key,now=Date.now()){
  const v=ticketStore.get(key);return v && v.expires>now && v.scope===identity(req,context)?v.row:null;
}
// Short-lived opaque references are scoped to the operator, selected source and exact interval.
const peerTicketStore=new Map();
function peerTicket(req,c,row,now=Date.now()){
 for(const [key,v] of peerTicketStore)if(v.expires<=now)peerTicketStore.delete(key);
 while(peerTicketStore.size>=3000)peerTicketStore.delete(peerTicketStore.keys().next().value);
 const key=crypto.randomBytes(24).toString('hex'),expires=now+300000;
 peerTicketStore.set(key,{scope:identity(req,c),row,expires});return {peerRef:key,peerRefExpiresAt:new Date(expires).toISOString()};
}
function peerTarget(req,c,key,target,now=Date.now()){
 const v=typeof key==='string'&&/^[a-f0-9]{48}$/.test(key)?peerTicketStore.get(key):null;
 return v&&v.expires>now&&v.scope===identity(req,c)&&['mac','site','band','start','end'].every(k=>v.row.target[k]===target[k])?v.row.peer:null;
}
function attachPeerReferences(req,c,evidence){
 const s=evidence?.scope,w=evidence?.window;
 if(!s?.apSerial||!s.networkId||!w?.start||!w.end)return;
 for(const p of evidence.peerRoaming?.excludedCandidates||[]){
  if(p.conflict)continue;
  Object.assign(p,peerTicket(req,c,{target:{mac:s.mac,site:s.site,band:s.band,start:w.start,end:w.end},peer:{mac:p.mac,clientId:p.clientId,selectedClientId:s.clientId,apSerial:s.apSerial,networkId:s.networkId}}));
 }
}
async function context(req,input,deps){
  if(!actor(req))throw {status:401,message:'An authenticated operator is required.'};
  const q=text(input.q),key=text(input.deviceKey),interfaceKey=text(input.interfaceKey);
  if(!q || q.length>256 || !key || key.length>512 || interfaceKey.length>1024)throw {status:400,message:'A valid person, selected device and optional interface are required.'};
  const resolved=await detail.resolveDevice(q,key,deps.discover);
  if(resolved.status!==200)throw {status:resolved.status,message:resolved.error};
  const access=await detail.permission(deps.rbac,req,'network-diag');
  if(access!=='ok')throw {status:access==='denied'?403:503,message:'Network Diagnostics read permission is required or unavailable.'};
  const inv=await detail.permission(deps.rbac,req,'it-inventory'),zcc=await detail.permission(deps.rbac,req,'zscaler-diag');
  const identifiers=await network.collectInterfaces({pool:deps.pool(),group:resolved.group,person:resolved.discovery.resolvedUser,inventoryAccess:inv,zscalerAccess:zcc});
  const choice=interfaceKey?identifiers.interfaces.find(i=>i.interfaceKey===interfaceKey && i.selectable):null;
  if(interfaceKey && !choice)throw {status:identifiers.status==='unavailable'?503:409,message:'The selected interface could not be reverified. Refresh source options.'};
  return {q,group:resolved.group,discovery:resolved.discovery,identifiers,choice,inventoryAccess:inv};
}
async function options(context,deps){
  const {choice,identifiers}=context,targets=[],ports=[],queries=[],seen=new Set();
  function add(ip,key,source,observedAt,basis){if(privateIp(ip))targets.push({key,ip,source,observedAt:observedAt||null,basis});}
  if(choice?.mac)queries.push({key:'selected-mac',mac:choice.mac,label:'Selected MAC · '+choice.mac,basis:choice.basis});
  for(const h of identifiers.hostnames){if(hostname(h.value)){
    const key='hostname:'+h.recordKey+':'+h.value.toLowerCase();if(!seen.has(key)){seen.add(key);queries.push({key,hostname:h.value,label:h.value+' · '+h.source,basis:'Exact inventory hostname; no substring or DNS lookup'});}
  }}
  if(choice?.reportedIp)add(choice.reportedIp,'inventory-ip','Selected '+choice.source,choice.observedAt,'Recorded source IP; ownership can change. This is an explicit target candidate.');
  let cached=null;
  if(choice?.mac){
    cached=await deps.readCache({mac:choice.mac,ip:choice.reportedIp,days:1});
    for(const b of cached.bindings.records)add(b.ip,'arp:'+b.ip,'Stored ARP · exact selected MAC',b.observedAt,'Historical ARP target candidate; not live IP ownership.');
    for(const p of cached.locations.records){const idx=Number(p.ifindex),vlan=Number(p.vlan);
      if(privateIp(p.switch_ip) && Number.isInteger(idx)&&idx>0&&idx<=2147483647 && Number.isInteger(vlan)&&vlan>0&&vlan<=4094){
        const key=p.switch_ip+':'+idx+':'+vlan;
        if(!ports.some(r=>r.key===key))ports.push({key,switch_ip:p.switch_ip,ifindex:idx,vlan,port:p.port,switch:p.switch,role:p.role,observedAt:p.observedAt,mac:choice.mac});
      }
    }
  }
  return {mode:'explicit',deviceKey:context.group.deviceKey,interfaceKey:choice?.interfaceKey||'',readAt:new Date().toISOString(),
    dhcpQueries:queries,ipTargets:targets,switchPorts:ports,firewalls:[{key:'irvine',label:'Irvine'},{key:'dallas',label:'Dallas / Plano'}],
    merakiEligible:!!choice?.mac,currentApPortEligible:!!choice?.mac,historySites,selectedMac:choice?.mac||null,cacheStatus:cached?{bindings:cached.bindings.status,locations:cached.locations.status,snapshotAt:cached.snapshotAt}:null,
    sources:identifiers.sources,limitations:['No live checks have run while loading these options.','Choose each target and firewall explicitly. Old source IPs and cached ARP bindings may have been reassigned.',...(context.discovery.unavailable?.length?['Assigned-device discovery is partial.']:[])]};
}
async function metadata(req,res,deps){try{const c=await context(req,req.query,deps);return res.json(await options(c,deps));}catch(e){return res.status(e.status||500).json({error:e.status?e.message:'Live check options could not be read.'});}}
async function check(req,res,deps){
  const requestStarted=Date.now(),b=req.body||{},tool=text(b.tool);
  if(!['dhcp','meraki','reachability','switch','firewall','ap-port','history','history-context','history-peer-context'].includes(tool) || ['targetKey','queryKey','portKey','leaseToken','firewall','historySite','historyBand','historyStart','historyEnd','peerRef'].some(k=>b[k]!=null && (typeof b[k]!=='string'||b[k].length>1024)))return res.status(400).json({error:'Choose a supported check and valid references.'});
  // No arbitrary destination, port, hostname or switch can be supplied by a client.
  if(['ip','mac','hostname','switchIp','port','url','server','apSerial','networkId','clientId','cursor','peers','peerMac','peerId','peerCandidate'].some(k=>b[k]!=null))return res.status(400).json({error:'Use server-verified source references, not raw targets.'});
  if((tool==='history-peer-context'&&(!/^[a-f0-9]{48}$/.test(b.peerRef||'')))||(tool!=='history-peer-context'&&b.peerRef!=null))return res.status(400).json({error:'Choose an available excluded-candidate reference.'});
  let lock,acquired=false;
  try{
    const c=await context(req,b,deps);
    if(tool==='meraki'||tool==='ap-port'||tool==='history'||tool==='history-context'||tool==='history-peer-context'){
      const access=await detail.permission(deps.rbac,req,'meraki-noc');
      if(access!=='ok')throw {status:access==='denied'?403:503,message:'Meraki NOC read permission is required or unavailable.'};
    }
    const o=(tool==='history'||tool==='history-context'||tool==='history-peer-context')?{historySites}:await options(c,deps),result={mode:'explicit',tool,deviceKey:c.group.deviceKey,interfaceKey:c.choice?.interfaceKey||'',startedAt:new Date().toISOString(),target:null,evidence:null};
    let target,requestedPeer;
    if(tool==='dhcp'){
      target=o.dhcpQueries.find(q=>q.key===b.queryKey);if(!target)throw {status:409,message:'Choose an available exact DHCP query.'};
    }else if(tool==='history'||tool==='history-context'||tool==='history-peer-context'){
      if(!c.choice?.mac||!o.historySites.some(s=>s.key===b.historySite)||!['2.4','5','6'].includes(b.historyBand))throw {status:400,message:'Select a verified source MAC, history site and radio band.'};
      const window=((tool==='history-context'||tool==='history-peer-context')?require('./network-interval-context').intervalWindow:require('./network-device-history').historyWindow)({start:b.historyStart,end:b.historyEnd});
      target={mac:c.choice.mac,site:b.historySite,band:b.historyBand,start:window.start,end:window.end};
      if(tool==='history-peer-context'){requestedPeer=peerTarget(req,c,b.peerRef,target);if(!requestedPeer)throw {status:409,message:'This candidate reference expired or does not match the selection. Read interval context again.'};}
    }else if(tool==='meraki'){
      if(!c.choice?.mac)throw {status:409,message:'Select a verified source MAC before a Meraki read.'};target={mac:c.choice.mac};
    }else if(tool==='ap-port'){
      target=b.leaseToken?leaseTarget(req,c,b.leaseToken):null;
      if(!c.choice?.mac || !target || !privateIp(target.ip) || target.mac!==c.choice.mac || target.queryKey!=='selected-mac')throw {status:409,message:'Read exact selected-MAC DHCP and choose its fresh lease before finding the current AP port.'};
    }else if(tool==='switch'){
      target=o.switchPorts.find(p=>p.key===b.portKey);if(!target)throw {status:409,message:'Choose a cached port observed for this exact selected MAC.'};
    }else{
      if(tool==='firewall' && !o.firewalls.some(f=>f.key===b.firewall))throw {status:400,message:'Choose Irvine or Dallas explicitly; no firewall is assumed.'};
      if(tool==='firewall' && !b.leaseToken)throw {status:409,message:'Read exact selected-MAC DHCP and choose its fresh lease before reading firewall sessions.'};
      if(b.leaseToken){
        target=leaseTarget(req,c,b.leaseToken);
        if(target && !o.dhcpQueries.some(q=>q.key===target.queryKey))target=null;
      }
      else target=o.ipTargets.find(t=>t.key===b.targetKey);
      if(!target || !privateIp(target.ip))throw {status:409,message:'Choose an available source IP or rerun DHCP for a fresh lease reference.'};
      if(tool==='firewall' && (!c.choice?.mac || target.mac!==c.choice.mac || target.queryKey!=='selected-mac'))throw {status:409,message:'The firewall target must be a fresh exact lease for the selected source MAC. Rerun selected-MAC DHCP.'};
    }
    lock=identity(req,c)+'|'+(tool==='history-peer-context'?'history-context':tool);
    const throttleKey=identity(req,c)+'|'+tool;
    if(inflight.has(lock))throw {status:429,message:'This check is already running for the selected device.'};
    const now=Date.now();if((lastRun.get(throttleKey)||0)>now-(tool==='history'?30000:5000) && !deps.noThrottle)throw {status:429,message:tool==='history'?'Wait 30 seconds before repeating history analysis for this selection.':'Wait a few seconds before repeating this check.'};
    inflight.add(lock);acquired=true;lastRun.set(throttleKey,now);
    if(lastRun.size>1000)for(const [k,time] of lastRun)if(time<now-60000)lastRun.delete(k);
    result.target=tool==='history-peer-context'?{...target,peerRef:b.peerRef}:target;
    const api=deps.providers||providers;
    if(tool==='dhcp'){
      result.evidence=await api.dhcp(target,{timeoutMs:Math.max(1,26000-(Date.now()-requestStarted))});
      result.leaseTargets=result.evidence.records.filter(r=>privateIp(r.ip)).map(r=>({key:'lease:'+ticket(req,c,{ip:r.ip,source:'Exact DHCP '+r.server,observedAt:result.startedAt,basis:result.evidence.basis,mac:r.mac,hostname:r.hostname,queryKey:target.key,expiresAt:r.expiresAt}),ip:r.ip,source:'Exact DHCP '+r.server,observedAt:result.startedAt,basis:result.evidence.basis,firewallEligible:target.key==='selected-mac' && !!c.choice?.mac && r.mac===c.choice.mac}));
    }else if(tool==='ap-port'){
      result.evidence=await (api.currentApPort||require('./network-ap-port').currentApPort)(target);
      if(!leaseTarget(req,c,b.leaseToken)){result.evidence={status:'unavailable',reason:'The DHCP reference expired during verification; reread exact DHCP and retry. Port health withheld.'};}
    }else if(tool==='history')result.evidence=await (api.history||require('./network-device-history').collectHistory)(target,{budgetMs:Math.max(1,45000-(Date.now()-requestStarted))});
    else if(tool==='history-context'||tool==='history-peer-context'){
      result.evidence=await (api.historyContext||require('./network-interval-context').collectIntervalContext)(target,{budgetMs:Math.max(1,35000-(Date.now()-requestStarted)),...(requestedPeer?{peerCandidate:requestedPeer}:{})});
      if(tool==='history-context')attachPeerReferences(req,c,result.evidence);
    }
    else if(tool==='meraki')result.evidence=await api.meraki(target.mac);
    else if(tool==='firewall'){result.target={...target,firewall:b.firewall};result.evidence=await api.firewall(target.ip,b.firewall);}
    else result.evidence=await api.probe(tool,target);
    result.completedAt=new Date().toISOString();
    return res.json(result);
  }catch(e){return res.status(e.status||500).json({error:e.status?e.message:'The selected-device check could not complete.'});}
  finally{if(acquired)inflight.delete(lock);}
}
function register(router,deps){
  const shared={...deps,pool:()=>router._devicePool,readCache:deps.readCache||(opts=>require('./network-device-cache').readCachedNetwork(opts))};
  router.get('/device-network-options',deps.rbac.requirePage('identity-diag','read'),(req,res)=>metadata(req,res,shared));
  router.post('/device-network-check',deps.rbac.requirePage('identity-diag','read'),(req,res)=>check(req,res,shared));
}
module.exports={register,metadata,check,privateIp,options,context,leaseTarget,ticket,peerTicket,peerTarget};
