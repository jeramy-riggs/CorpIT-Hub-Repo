'use strict';
const net=require('net');
const model=require('./identity-device-model');
const detail=require('./identity-device-detail');
const adapters=require('./identity-device-adapters');
const text=v=>v==null?'':String(v).trim();
function macAddress(value){
  const s=text(value);if(!/^(?:[0-9a-f]{12}|[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}|[0-9a-f]{4}(?:\.[0-9a-f]{4}){2})$/i.test(s))return null;
  const digits=s.replace(/[^0-9a-f]/gi,'').toLowerCase();
  if(/^(0{12}|f{12})$/.test(digits) || (parseInt(digits.slice(0,2),16)&1))return null;
  return digits.match(/../g).join(':');
}
function ipAddress(v){const s=text(v);return net.isIP(s) && s!=='0.0.0.0' && s!=='::' ? s.toLowerCase() : null;}
function iso(v){if(!v)return null;const d=new Date(v);return Number.isFinite(d.getTime())?d.toISOString():null;}
async function collectInterfaces({pool,group,person,inventoryAccess,zscalerAccess}){
  const interfaces=[],sources=[],hostnames=[];
  function add({source,recordKey,mac,ip,observedAt,basis,association='source-record',selectable=true}){
    const m=macAddress(mac),address=ipAddress(ip);if(!m && !address)return;
    const key=recordKey+':'+(m?'mac:'+m:'ip:'+address);
    interfaces.push({interfaceKey:key,source,recordKey,kind:m?'mac':'ip',mac:m,reportedIp:address,observedAt:iso(observedAt),basis,association,selectable,
      locallyAdministered:m?!!(parseInt(m.slice(0,2),16)&2):null});
  }
  async function read(source,sql,args){
    try{const [rows]=await pool.query(sql,args);sources.push({source,status:rows.length?'ok':'empty'});return rows;}
    catch(_){sources.push({source,status:'unavailable',reason:'Network identifiers could not be read from this source.'});return [];}
  }
  if(inventoryAccess==='ok'){
    for(const r of group.records){
      const ref=r.sourceRef;
      if(r.deviceName)hostnames.push({value:r.deviceName,source:r.source,recordKey:ref.recordKey,basis:'Selected inventory record; no DNS lookup performed'});
      if(ref.sourceKey==='kandji-mac'){
        const rows=await read('Kandji network identifiers','SELECT id,device_name,local_hostname,mac_address,ip_address,details_synced_at,updated_at FROM it_inventory.macbooks WHERE id=?',[ref.rowId]);
        for(const row of rows){
          add({source:'Kandji inventory',recordKey:ref.recordKey,mac:row.mac_address,ip:row.ip_address,observedAt:row.details_synced_at || row.updated_at,basis:'Network fields on the selected Kandji row'});
          if(row.local_hostname)hostnames.push({value:row.local_hostname,source:'Kandji inventory',recordKey:ref.recordKey,basis:'Selected inventory row'});
        }
      }else sources.push({source:r.source+' network identifiers',status:'not_collected',reason:'This inventory feed does not directly provide network MAC/IP fields. No hostname or DNS resolution was attempted.'});
    }
    const managed=adapters.cached(group,person);
    if(adapters.reference(group)){
      sources.push({source:'Intune managed adapters',status:managed?'ok':'not_collected',reason:managed?'Explicit selected-enrollment read; expires '+new Date(managed.expires).toISOString():'Use Discover managed adapters to read Wi-Fi and Ethernet for this selected enrollment.'});
      if(managed)for(const [field,label] of [['wiFiMacAddress','Wi-Fi'],['ethernetMacAddress','Ethernet']]){
        add({source:'Intune '+label,recordKey:'intune-adapter:device:'+managed.device.id+':'+field,mac:managed.device[field],observedAt:managed.device.lastSyncDateTime,
          basis:'Explicit Intune '+field+' read by selected enrollment ID; serial, Windows platform and owner verified. Read '+managed.readAt+'; valid until '+new Date(managed.expires).toISOString()+'. Intune sync time is not proof of current connection.',association:'confirmed'});
      }
    }
    if(group.records.some(r=>model.family(r)==='windows')){
      const ref=group.sourceRefs.find(r=>r.sourceKey==='manageengine' && r.nativeId),serial=model.serialKey(group.serial);
      if(ref || (serial && detail.serialAssociationAllowed(group))){
        const rows=await read('ManageEngine recorded network identifiers',
          'SELECT resource_id,service_tag,ip_address,last_synced FROM it_inventory.warranty_cache WHERE '+(ref?'resource_id=?':'UPPER(TRIM(service_tag))=?'),[ref?ref.nativeId:serial]);
        for(const row of rows)add({source:'ManageEngine warranty cache',recordKey:'manageengine-warranty:resource:'+row.resource_id,ip:row.ip_address,observedAt:row.last_synced,
          basis:ref?'Recorded IP for the selected ManageEngine resource':'Recorded IP candidate matched by unique inventory serial',association:'ip-only-candidate',selectable:rows.length===1});
      }
    }
  }else sources.push({source:'Inventory network identifiers',status:inventoryAccess,reason:'Inventory read permission is required.'});
  if(zscalerAccess==='ok'){
    const serial=model.serialKey(group.serial);
    if(serial){
      const rows=await read('Stored ZCC network identifiers','SELECT udid,user_upn,hostname,serial_number,device_type,mac_address,updated_at FROM zcc_devices WHERE UPPER(TRIM(serial_number))=?',[serial]);
      for(const row of rows){const snapshot=detail.storedRecord(row),match=detail.zccSnapshotMatch(group,snapshot,person);
        add({source:'ZCC stored export',recordKey:'zcc:udid:'+row.udid,mac:row.mac_address,observedAt:row.updated_at,basis:match.status==='confirmed'?'Stored ZCC UDID matched by unique inventory serial, platform and owner; no live lookup':match.basis,association:match.status,selectable:match.status==='confirmed'});
      }
    }
  }else sources.push({source:'ZCC network identifiers',status:zscalerAccess,reason:'Zscaler read permission is required.'});
  const failed=sources.some(s=>['unavailable','denied'].includes(s.status));
  return {status:failed?(interfaces.length?'partial':sources.some(s=>s.status==='unavailable')?'unavailable':sources.every(s=>s.status==='denied')?'denied':'partial'):interfaces.length?'ok':'empty',interfaces,hostnames,sources,
    reason:'Each choice preserves its source and observation date. Different MACs are not merged into one interface. IP-only candidates do not establish a hardware association.'};
}
async function respond(req,res,{rbac,discover,pool,readCache}){
  const q=text(req.query.q),key=text(req.query.deviceKey),requested=text(req.query.interfaceKey),mode=text(req.query.mode || 'cached');
  const days=req.query.days==null?7:Number(req.query.days);
  if(!q || q.length>256 || !key || key.length>512 || requested.length>1024 || mode!=='cached' || !Number.isInteger(days) || days<1 || days>30)
    return res.status(400).json({error:'A valid person, device reference and cached mode are required. History days must be 1–30.'});
  try{
    const resolved=await detail.resolveDevice(q,key,discover);
    if(resolved.status!==200)return res.status(resolved.status).json({error:resolved.error});
    const {group,discovery}=resolved;
    const networkAccess=await detail.permission(rbac,req,'network-diag');
    const result={mode:'cached',deviceKey:group.deviceKey,readAt:new Date().toISOString(),selectedInterfaceKey:null,identifiers:null,network:null,links:[],limitations:[],discoveryUnavailable:discovery.unavailable || []};
    if(networkAccess!=='ok')return res.json({...result,status:networkAccess,identifiers:{status:networkAccess,interfaces:[],hostnames:[],sources:[],reason:'Network Diagnostics read permission is required.'}});
    const inventoryAccess=await detail.permission(rbac,req,'it-inventory'),zscalerAccess=await detail.permission(rbac,req,'zscaler-diag');
    result.identifiers=await collectInterfaces({pool:pool(),group,person:discovery.resolvedUser,inventoryAccess,zscalerAccess});
    result.status=result.identifiers.status;
    if(result.discoveryUnavailable.length)result.limitations.push('Assigned inventory is partial: '+result.discoveryUnavailable.join(', '));
    if(!requested){result.selectionRequired=true;return res.json(result);}
    const choice=result.identifiers.interfaces.find(i=>i.interfaceKey===requested);
    if(!choice)return res.status(result.identifiers.sources.some(s=>s.status==='unavailable')?503:404).json({error:'The requested interface could not be verified for this device. Choose an available interface.',code:'INTERFACE_UNVERIFIED',...result});
    if(!choice.selectable)return res.status(409).json({error:'This interface association is ambiguous and cannot be used as selected-device evidence.',code:'INTERFACE_AMBIGUOUS',...result});
    result.selectedInterfaceKey=choice.interfaceKey;result.selectionRequired=false;
    result.network=await readCache({mac:choice.mac,ip:choice.reportedIp,days});
    const sections=['locations','bindings','portHealth','issues','locationHistory','portHistory'].map(k=>result.network[k]?.status);
    result.status=sections.every(s=>s==='unavailable')?'unavailable':sections.includes('unavailable') || sections.includes('partial') || result.identifiers.status==='partial' || result.discoveryUnavailable.length?'partial':'ok';
    if(choice.mac && choice.reportedIp && result.network.bindings.records.length && !result.network.bindings.records.some(r=>r.ip===choice.reportedIp))result.limitations.push('The inventory-reported IP differs from cached ARP observations; source dates and values are retained separately.');
    result.limitations.push(...result.network.limitations);
    const switches=[...new Set(result.network.locations.records.map(r=>r.switch_ip))];
    switches.forEach(ip=>{if(net.isIP(ip))result.links.push({label:'Open switch '+ip,href:'/network-switches.html?switch='+encodeURIComponent(ip),basis:'Switch observed in the stored network cache; no active trace'});});
    return res.json(result);
  }catch(_){return res.status(500).json({error:'Cached selected-device network evidence could not be read.'});}
}
async function discoverAdapters(req,res,deps){
  const b=req.body||{},q=text(b.q),key=text(b.deviceKey);
  if(!q||q.length>256||!key||key.length>512||Object.keys(b).some(k=>!['q','deviceKey'].includes(k)))return res.status(400).json({error:'Use a person and selected inventory reference only.'});
  if(!text(req.user?.id||req.user?.email||req.user?.upn||req.currentUser?.id||req.currentUser?.email||req.auth?.sub))return res.status(401).json({error:'An authenticated operator is required.'});
  try{
    for(const page of ['network-diag','it-inventory']){
      const access=await detail.permission(deps.rbac,req,page);
      if(access!=='ok')return res.status(access==='denied'?403:503).json({error:'Network Diagnostics and Inventory read permissions are required or unavailable.'});
    }
    const resolved=await detail.resolveDevice(q,key,deps.discover);
    if(resolved.status!==200)return res.status(resolved.status).json({error:resolved.error});
    const result=await (deps.discoverAdapters||adapters.discover)(resolved.group,resolved.discovery.resolvedUser);
    return res.status(result.status==='busy'?429:200).json({deviceKey:resolved.group.deviceKey,...result});
  }catch(_){return res.status(503).json({error:'Selected-device adapter discovery could not complete.'});}
}
function register(router,deps){
  router.post('/device-network-adapters',deps.rbac.requirePage('identity-diag','read'),(req,res)=>discoverAdapters(req,res,deps));
  router.get('/device-network',deps.rbac.requirePage('identity-diag','read'),(req,res)=>respond(req,res,{...deps,pool:()=>router._devicePool,
    readCache:deps.readCache || (opts=>require('./network-device-cache').readCachedNetwork(opts))}));
}
module.exports={macAddress,ipAddress,collectInterfaces,respond,discoverAdapters,register};
