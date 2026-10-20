'use strict';

// Selected records only. No collector, export, OTP, recovery key or vendor mutation.
const model = require('./identity-device-model');
const text = v => v == null ? '' : String(v).trim();
function boolean(v) {
  if (v === true || v === 1 || v === '1' || v === 'true') return true;
  if (v === false || v === 0 || v === '0' || v === 'false') return false;
  return null;
}
function date(v) {
  if (!v || /^(?:0|--|unknown)$/i.test(text(v))) return null;
  const d = new Date(v); return Number.isFinite(d.getTime()) ? d.toISOString() : null;
}
function coverage(end, canceled, now = Date.now()) {
  if (boolean(canceled) === true) return 'canceled';
  const d = date(end); return d ? (Date.parse(d) < now ? 'expired' : 'active') : 'unknown';
}
function activityDate(v) {
  if (v == null || v === '' || String(v) === '0') return null;
  if (typeof v === 'number' || /^\d{10,13}$/.test(String(v))) {
    const n=Number(v); return date(n<1e11?n*1000:n);
  }
  return date(v);
}
async function permission(rbac, req, page) {
  let granted = false, status = 403;
  const response = {status(n){status=n;return this;},json(){return this;}};
  try { await rbac.requirePage(page,'read')(req,response,()=>{granted=true;}); }
  catch (_) { status = 500; }
  return granted ? 'ok' : status >= 500 ? 'unavailable' : 'denied';
}
function outcome(status, source, records = [], reason = '') { return {status,source,records,reason}; }
async function read(pool, source, sql, args, normalize = r=>r) {
  try { const [rows] = await pool.query(sql,args); return outcome(rows.length ? 'ok' : 'empty',source,rows.map(normalize)); }
  catch (_) { return outcome('unavailable',source,[],'Source could not be read.'); }
}
function bounded(fn, ms) {
  let timer;
  return Promise.race([Promise.resolve().then(fn),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('timeout')),ms);})]).finally(()=>clearTimeout(timer));
}
function liveRecord(r) {
  const pick = (...keys) => { for (const k of keys) if (r[k] != null && r[k] !== '') return r[k]; return null; };
  const state = pick('registrationState','registration_state','state','deviceState','device_state');
  return {udid:text(r.udid),hostname:pick('machineHostname','hostName','hostname','machineName'),
    user:pick('user','username','userName','user_upn'),registration:state == null ? null : String(state),
    agentVersion:pick('agentVersion','clientConnectorVersion','zcc_version'),tunnelVersion:pick('tunnelVersion','tunnel_version'),
    policy:pick('policyName','policy_name'),reportedActivity:activityDate(pick('last_seen_time','lastSeenTime','lastSeen','last_seen_active','lastConnectedTime','keepAliveTime')),
    registeredAt:activityDate(pick('registrationTime','registration_time','registration_ts')),
    vpnState:pick('vpnState','vpn_state')};
}
function storedRecord(r) {
  return {udid:r.udid,hostname:r.hostname,user:r.user_upn,serial:r.serial_number,platform:r.device_type,
    registration:r.device_state,agentVersion:r.zcc_version,tunnelVersion:r.tunnel_version,policy:r.policy_name,
    vpnState:r.vpn_state,lastSeenZia:r.last_seen_zia,lastSeenZpa:r.last_seen_zpa,
    reportedActivity:r.last_seen_active,registeredAt:r.registration_ts,observedAt:r.updated_at};
}
const ZCC_FIELDS = 'udid,user_upn,hostname,serial_number,device_type,device_state,zcc_version,tunnel_version,policy_name,vpn_state,last_seen_zia,last_seen_zpa,last_seen_active,registration_ts,updated_at';
async function intuneCrosslink(pool, snapshot) {
  const serial = model.serialKey(snapshot.serial_number);
  if (!serial) return {intune_id:null,intune_device_name:null,intuneMatches:[],intuneMatch:{status:'unmatched',basis:'No usable serial number'}};
  const [rows] = await pool.query('SELECT id,device_id,device_name,serial_number FROM it_inventory.intune_devices WHERE UPPER(TRIM(serial_number))=? AND is_historical=0',[serial]);
  const [enrollments] = await pool.query('SELECT udid FROM zcc_devices WHERE UPPER(TRIM(serial_number))=?',[serial]);
  return {intune_id:rows.length === 1 ? rows[0].id : null,intune_device_name:rows.length === 1 ? rows[0].device_name : null,
    intuneMatches:rows,intuneMatch:{status:rows.length === 1 ? 'confirmed' : rows.length ? 'ambiguous' : 'unmatched',basis:'Normalized serial; current Intune records',enrollmentCount:enrollments.length}};
}
function serialAssociationAllowed(group) {
  return !!model.serialKey(group.serial) && group.match.status!=='ambiguous' && group.match.status!=='unverified' && group.records.every(r=>r.serialMultiplicity===1);
}
function zccSnapshotMatch(group,snapshot,person) {
  const email=group.records.map(r=>r.user).find(v=>/^[^\s@]+@[^\s@]+$/.test(text(v))) || (person && person.username ? person.username+'@auction.com' : '');
  const aliases=new Set([email,...group.records.map(r=>r.user)].map(v=>text(v).toLowerCase()).filter(Boolean));
  const confirmed=serialAssociationAllowed(group) && model.serialKey(snapshot.serial)===model.serialKey(group.serial)
    && model.family({os:snapshot.platform})===model.family(group.records[0]) && aliases.has(text(snapshot.user).toLowerCase());
  return {status:confirmed?'confirmed':'candidate',basis:confirmed?'Unique inventory serial + platform + owner; live joined by UDID when available':'Serial candidate; endpoint association is not confirmed'};
}
async function resolveDevice(q,key,discover) {
  let discovery,status=200;
  await discover({query:{q}},{status(n){status=n;return this;},json(body){discovery=body;return this;}});
  if(status!==200 || !discovery)return {status:status===200?503:status,error:'Assigned inventory could not be read.'};
  const group=(discovery.deviceGroups || []).find(g=>g.deviceKey===key || g.sourceRefs.some(r=>r.recordKey===key));
  if(!group)return {status:discovery.unavailable?.length?503:404,error:'The selected device could not be verified for this person. Reopen assigned devices.'};
  return {status:200,group,discovery};
}
async function enrich({pool, group, person, inventoryAccess, zscalerAccess, zccList, zdx, now = Date.now()}) {
  const result = {deviceKey:group.deviceKey,device:group,readAt:new Date(now).toISOString(),
    inventory:outcome(inventoryAccess,'Inventory'),encryption:outcome(inventoryAccess,'Encryption'),
    warranty:outcome(inventoryAccess,'Warranty'),zcc:outcome(zscalerAccess,'ZCC'),
    zdx:zscalerAccess === 'ok' ? {...zdx} : {state:zscalerAccess,api:false,reason:'Zscaler read permission is required.'},links:[],limitations:[]};
  const serial = model.serialKey(group.serial);
  const trustworthy = serialAssociationAllowed(group);
  const inventory = [], encryption = [], inventorySources = [], encryptionSources = [], warrantySources = [];
  if (inventoryAccess === 'ok') {
    const tables = {intune:'intune',manageengine:'endpoints','kandji-mac':'macbooks','kandji-ipad':'ipads',aws:'aws'};
    for (const r of group.records) {
      const ref = r.sourceRef;
      const filter = ref.sourceKey === 'aws' ? ref.nativeId : serial || r.deviceName;
      if (tables[ref.sourceKey] && filter) result.links.push({label:'Open '+r.source+' Inventory',kind:'inventory',recordKey:ref.recordKey,
        href:'/IT_Inventory_App.html?table='+encodeURIComponent(tables[ref.sourceKey])+'&find='+encodeURIComponent(filter),basis:'Filtered list; not exact row selection'});
      let source;
      if (ref.sourceKey === 'intune') {
        source = await read(pool,'Intune inventory','SELECT id,device_id,primary_user_upn,ownership,compliance,last_checkin,updated_at,is_encrypted FROM it_inventory.intune_devices WHERE id=? AND device_id=? AND is_historical=0',[ref.rowId,ref.nativeId]);
        for (const row of source.records) encryption.push({source:'Intune inventory',deviceId:row.device_id,encrypted:boolean(row.is_encrypted),observedAt:row.updated_at,preferred:false});
        if (model.family(r) === 'windows') {
          const preferred = await read(pool,'Sentinel Intune','SELECT device_id,is_encrypted,compliance_state,last_sync_dt,collected_at FROM sentinel_intune_device WHERE device_id=?',[ref.nativeId]);
          encryptionSources.push(preferred);
          for (const row of preferred.records) encryption.push({source:'Sentinel Intune',deviceId:row.device_id,encrypted:boolean(row.is_encrypted),compliance:row.compliance_state,lastCheckin:row.last_sync_dt,observedAt:row.collected_at,preferred:true});
        }
      } else if (ref.sourceKey === 'kandji-mac') {
        source = await read(pool,'Kandji Mac','SELECT id,user_name,checked_in,updated_at,filevault_enabled,filevault_prk_escrowed,details_synced_at FROM it_inventory.macbooks WHERE id=?',[ref.rowId]);
        for (const row of source.records) encryption.push({source:'Kandji FileVault',recordKey:ref.recordKey,encrypted:boolean(row.filevault_enabled),recoveryKeyEscrowed:boolean(row.filevault_prk_escrowed),observedAt:row.details_synced_at,preferred:true});
      } else if (ref.sourceKey === 'manageengine') source = await read(pool,'ManageEngine','SELECT id,resource_id,first_last,logged_on_user,last_asset_scan,updated_at FROM it_inventory.endpoints WHERE id=? AND resource_id=?',[ref.rowId,ref.nativeId]);
      else if (ref.sourceKey === 'kandji-ipad') source = await read(pool,'Kandji iPad','SELECT id,device_id,user_name,checked_in,updated_at FROM it_inventory.ipad_devices WHERE id=? AND device_id=?',[ref.rowId,ref.nativeId]);
      else if (ref.sourceKey === 'aws') source = await read(pool,'AWS','SELECT id,workspace_id,username,status,updated_at FROM it_inventory.aws_workspaces WHERE id=? AND workspace_id=?',[ref.rowId,ref.nativeId]);
      if (source) {
        inventorySources.push(source);
        source.records.forEach(row=>inventory.push({source:source.source,recordKey:ref.recordKey,deviceId:ref.nativeId,
          owner:row.primary_user_upn || row.user_name || row.first_last || row.logged_on_user || row.username || r.user || null,
          ownership:row.ownership ?? r.ownership ?? null,compliance:row.compliance ?? r.compliance ?? null,
          lastCheckin:row.last_checkin || row.checked_in || row.last_asset_scan || r.lastCheckin || null,observedAt:row.updated_at}));
        if (['intune','kandji-mac'].includes(ref.sourceKey)) encryptionSources.push(source);
      }
    }
    const apple = group.records.some(r=>['kandji-mac','kandji-ipad'].includes(r.sourceRef.sourceKey) || ['mac','ipad','ios'].includes(model.family(r)));
    if (trustworthy && apple) warrantySources.push(await read(pool,'Apple Business Manager',
      'SELECT coverage_id,description,status,end_date_time,is_canceled,last_synced_at FROM abm_warranty WHERE UPPER(TRIM(serial_number))=? AND is_active=1 ORDER BY end_date_time DESC',[serial],r=>({source:'Apple Business Manager',coverageId:r.coverage_id,description:r.description,reportedStatus:r.status,endDate:r.end_date_time,coverage:coverage(r.end_date_time,r.is_canceled,now),observedAt:r.last_synced_at})));
    if (trustworthy && group.records.some(r=>model.family(r)==='windows')) {
      const ref=group.sourceRefs.find(r=>r.sourceKey==='manageengine' && r.nativeId);
      const warranty=await read(pool,'ManageEngine warranty',
        'SELECT resource_id,service_tag,warranty_expiry_date,last_synced FROM it_inventory.warranty_cache WHERE UPPER(TRIM(service_tag))=?'+(ref?' AND resource_id=?':''),ref?[serial,ref.nativeId]:[serial],
        r=>({source:'ManageEngine warranty',resourceId:r.resource_id,endDate:r.warranty_expiry_date,coverage:coverage(r.warranty_expiry_date,null,now),observedAt:r.last_synced}));
      if (warranty.records.length>1) {
        warranty.status='partial';warranty.reason='Multiple warranty records share this serial; coverage candidates are not confirmed for this endpoint.';
        warranty.records.forEach(r=>{r.reportedCoverage=r.coverage;r.coverage='unknown';r.association='ambiguous serial';});
      }
      warrantySources.push(warranty);
    }
    function section(source, sources, records, reason) {
      const failed=sources.some(s=>['unavailable','partial'].includes(s.status));
      return {...outcome(failed ? (records.length?'partial':'unavailable') : records.length?'ok':'empty',source,records,reason),sources:sources.map(s=>({source:s.source,status:s.status,reason:s.reason}))};
    }
    result.inventory=section('Inventory',inventorySources,inventory);
    result.encryption=section('Encryption',encryptionSources,encryption,'Sentinel Intune is preferred for Windows; missing values remain unknown.');
    const preferred=encryption.filter(r=>r.preferred);
    result.encryption.preferred=preferred.length ? preferred : encryption.filter(r=>r.source==='Intune inventory');
    result.encryption.conflict=new Set(encryption.map(r=>r.encrypted).filter(v=>v!==null)).size>1;
    result.warranty=section('Warranty',warrantySources,warrantySources.flatMap(s=>s.records),trustworthy?'Missing coverage is unknown, not expired.':'A unique usable serial is required; warranty association was not attempted.');
  }
  if (zscalerAccess === 'ok') {
    const stored = serial ? await read(pool,'ZCC stored export','SELECT '+ZCC_FIELDS+' FROM zcc_devices WHERE UPPER(TRIM(serial_number))=? ORDER BY updated_at DESC',[serial],storedRecord) : outcome('empty','ZCC stored export',[],'No usable serial; no endpoint association attempted.');
    let live = outcome('empty','ZCC person lookup',[],'No usable serial; no endpoint association attempted.');
    const email = group.records.map(r=>r.user).find(v=>/^[^\s@]+@[^\s@]+$/.test(text(v))) || (person && person.username ? person.username+'@auction.com' : '');
    if (email && serial) {
      try {
        const response = await bounded(()=>zccList(email),8000);
        live = response.status === 200 ? outcome(response.body.truncated?'partial':'ok','ZCC person lookup',(response.body.devices || []).map(liveRecord),response.body.truncatedReason || '') : outcome('unavailable','ZCC person lookup',[],'ZCC lookup did not answer successfully.');
        live.observedAt=new Date(now).toISOString();
        live.records.forEach(r=>{r.observedAt=live.observedAt;});
      } catch (_) {live=outcome('unavailable','ZCC person lookup',[],'ZCC lookup unavailable or timed out.');}
    }
    const records=stored.records.map(snapshot=>{
      const joins=live.records.filter(r=>r.udid === snapshot.udid);
      const match=zccSnapshotMatch(group,snapshot,person);
      if(joins.length>1){match.status='candidate';match.basis='Multiple live records share this UDID; association is ambiguous';}
      return {udid:snapshot.udid,match,snapshot,live:joins.length===1?joins[0]:null,liveStatus:joins.length>1?'ambiguous':joins.length===1?'matched-by-udid':'not-returned'};
    });
    const degraded=[stored,live].some(s=>['unavailable','partial'].includes(s.status));
    result.zcc={...outcome(degraded?(records.length?'partial':'unavailable'):records.length?'ok':'empty','ZCC',records),sources:[{...stored,records:undefined},{...live,records:undefined}],
      unmatchedLive:live.records.filter(r=>!records.some(s=>s.udid===r.udid)),reason:'Registration, reported activity and VPN state are separate observations; they do not establish current connection or offline state.'};
    records.filter(r=>r.match.status==='confirmed').forEach(r=>result.links.push({label:'Open ZCC device '+r.udid,kind:'zcc',href:'/zscaler-command-center.html?v=zcc&udid='+encodeURIComponent(r.udid),basis:r.match.basis}));
    if (records.length>1) result.limitations.push('Multiple ZCC enrollments share this serial; each UDID remains separate.');
  }
  for (const key of ['inventory','encryption','warranty','zcc']) if (['partial','unavailable','denied'].includes(result[key].status)) result.limitations.push(key+': '+result[key].status);
  if (!trustworthy) result.limitations.push('Serial-based associations are not confirmed for this selected inventory record.');
  return result;
}
function register(router, {rbac, discover, zccList, zdx}) {
  router.get('/device-detail',rbac.requirePage('identity-diag','read'),async(req,res)=>{
    const q=text(req.query.q), key=text(req.query.deviceKey);
    if (!q || q.length>256 || !key || key.length>512) return res.status(400).json({error:'A person and device key are required (maximum 256 / 512 characters).'});
    try {
      const resolved=await resolveDevice(q,key,discover);
      if(resolved.status!==200)return res.status(resolved.status).json({error:resolved.error});
      const {group,discovery}=resolved;
      const inventoryAccess=await permission(rbac,req,'it-inventory'),zscalerAccess=await permission(rbac,req,'zscaler-diag');
      const result=await enrich({pool:router._devicePool,group,person:discovery.resolvedUser,inventoryAccess,zscalerAccess,zccList,zdx});
      result.discoveryUnavailable=discovery.unavailable || [];
      if (result.discoveryUnavailable.length) result.limitations.push('Assigned inventory is partial: '+result.discoveryUnavailable.join(', '));
      return res.json(result);
    } catch (_) {return res.status(500).json({error:'Selected device evidence could not be read.'});}
  });
}
module.exports={serialAssociationAllowed,zccSnapshotMatch,resolveDevice,boolean,date,coverage,permission,liveRecord,storedRecord,intuneCrosslink,enrich,register};
