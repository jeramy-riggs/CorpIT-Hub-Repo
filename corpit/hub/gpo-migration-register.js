'use strict';
// Shared DEV planning metadata only. Outbound operations in this module are GETs.
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const STAGES = ['assessed', 'mapping_review', 'draft_linked', 'pilot', 'pilot_validated', 'rollout', 'retirement_review'];
const TRACKS = ['review', 'workstation', 'user', 'domain_server', 'alternative'];
const KINDS = { catalog: '/beta/deviceManagement/configurationPolicies', configuration: '/beta/deviceManagement/deviceConfigurations' };
const FIELDS = { catalog: 'id,name,lastModifiedDateTime,platforms,technologies', configuration: 'id,displayName,lastModifiedDateTime' };
const DAY = 86400000;
function id(value) { return typeof value === 'string' && GUID.test(value.replace(/[{}]/g, '')) ? value.replace(/[{}]/g, '').toLowerCase() : null; }
function fail(status, message) { return Object.assign(new Error(message), { status }); }
function text(value, max) { if (typeof value !== 'string' || value.length > max || /[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(value)) throw fail(400, 'Invalid or oversized text field'); return value.trim(); }
function normalize(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw fail(400, 'A register record is required');
  const keys = ['version','owner','stage','track','profiles','pilotGroupId','notes','successCriteria','validationEvidence'];
  if (Object.keys(body).some(k => !keys.includes(k))) throw fail(400, 'Unknown register field');
  if (!Number.isSafeInteger(body.version) || body.version < 0) throw fail(400, 'A valid record version is required');
  if (!STAGES.includes(body.stage) || !TRACKS.includes(body.track)) throw fail(400, 'Choose a valid stage and review track');
  if (!Array.isArray(body.profiles) || body.profiles.length > 10) throw fail(400, 'Link at most 10 profiles');
  const profiles = body.profiles.map(p => {
    if (!p || !Object.prototype.hasOwnProperty.call(KINDS,p.kind) || !id(p.id) || Object.keys(p).some(k => !['kind','id'].includes(k))) throw fail(400, 'Invalid profile reference');
    return { kind: p.kind, id: id(p.id) };
  });
  if (new Set(profiles.map(p => p.kind + ':' + p.id)).size !== profiles.length) throw fail(400, 'Duplicate profile reference');
  const pilotGroupId = body.pilotGroupId === '' || body.pilotGroupId == null ? null : id(body.pilotGroupId);
  if (body.pilotGroupId && !pilotGroupId) throw fail(400, 'Invalid pilot group');
  return { version: body.version, owner: text(body.owner, 254), stage: body.stage, track: body.track, profiles, pilotGroupId,
    notes: text(body.notes, 3000), successCriteria: text(body.successCriteria, 2000), validationEvidence: text(body.validationEvidence, 3000) };
}
function decode(row) {
  const p = typeof row.payload === 'string' ? JSON.parse(row.payload) : row.payload;
  return Object.assign({}, p, { guid: row.gpo_guid, version: Number(row.version), updatedAt: row.updated_at, updatedBy: row.updated_by });
}
function profileView(kind, item) {
  return { kind, id: id(item.id), name: String(item.name || item.displayName || 'Unnamed profile').slice(0, 300),
    modified: item.lastModifiedDateTime || null, type: item['@odata.type'] || item.technologies || kind,
    platforms: item.platforms || null };
}
function pilotReadiness(members, snapshot, at = Date.now()) {
  if (!snapshot || !snapshot.devicesOk || !snapshot.sources || !snapshot.sources.intune || snapshot.sources.intune.state !== 'ok')
    return { known: false, why: 'A complete Intune device read is required. Missing enrollment cannot be inferred.', rows: null };
  const windows = snapshot.devices.filter(d => d.platform === 'Windows'), rows = new Map();
  const byAad = new Map(), byUser = new Map();
  for (const d of windows) {
    if (id(d.aad)) { const k=id(d.aad); if(!byAad.has(k))byAad.set(k,[]); byAad.get(k).push(d); }
    if (id(d.userId)) { const k=id(d.userId); if(!byUser.has(k))byUser.set(k,[]); byUser.get(k).push(d); }
  }
  let nested = 0, other = 0, usersWithoutWindows = 0, unknownDeviceIds = 0, duplicateRecords = 0;
  function put(d, reason) { rows.set('intune:' + d.id, { id:d.id, name:d.name || 'Unnamed device', enrollment:'Matched in Intune', reason,
    lastSync:d.lastSync, recent:d.lastSync != null && at - d.lastSync <= 7 * DAY,
    compliance:d.compliance || 'unknown', user:d.user || '', duplicate: (byAad.get(id(d.aad)) || []).length > 1 }); }
  for (const m of members) {
    const type = m['@odata.type'];
    if (type === '#microsoft.graph.device') {
      if (m.operatingSystem && !/^windows$/i.test(m.operatingSystem)) { other++; continue; }
      const k=id(m.deviceId), matches=k && byAad.get(k);
      if(matches && matches.length) { matches.forEach(d=>put(d,'Device group member')); if(matches.length>1)duplicateRecords+=matches.length-1; }
      else { if(!k)unknownDeviceIds++; rows.set('entra:'+m.id,{id:null,name:m.displayName || 'Unnamed Entra device',enrollment:k?'No Windows Intune match':'Device identifier not readable',reason:'Device group member',lastSync:null,recent:null,compliance:'Not read',user:'',duplicate:false}); }
    } else if (type === '#microsoft.graph.user') {
      const matches = byUser.get(id(m.id)) || [];
      if(matches.length)matches.forEach(d=>put(d,'Primary user is a group member'));
      else usersWithoutWindows++;
    } else if (type === '#microsoft.graph.group') nested++;
    else other++;
  }
  const all=[...rows.values()], matched=all.filter(r=>r.id), missing=all.filter(r=>!r.id);
  return { known:true, rows:all, counts:{ matched:matched.length, recent:matched.filter(r=>r.recent).length,
    stale:matched.filter(r=>!r.recent).length, notCompliant:matched.filter(r=>r.compliance==='noncompliant').length,
    otherCompliance:matched.filter(r=>!['compliant','noncompliant'].includes(r.compliance)).length,
    noMatch:missing.filter(r=>r.enrollment==='No Windows Intune match').length, unknownDeviceIds, usersWithoutWindows, nested, other, duplicateRecords },
    deviceReadAt:snapshot.at, limited:nested>0 || unknownDeviceIds>0 || usersWithoutWindows>0,
    scope:'Direct group members only. User members map to Windows devices by Intune primary user. Nested groups, secondary users, assignment filters and exclusions are not evaluated. This is planning readiness, not profile assignment or application evidence.' };
}
function mount(router, deps) {
  const { pool, rbac, json, readAll, readOne, snapshot } = deps;
  let profileCache = null, profileFlight = null;
  const pilotCache = new Map();
  async function sources() {
    const [uploads] = await pool.query('SELECT id, filename, uploaded_at FROM gpo_uploads WHERE is_active=1 ORDER BY id DESC LIMIT 1');
    const upload=uploads[0] || null;
    if(!upload)return { upload:null, gpos:[] };
    const [gpos] = await pool.query('SELECT guid,name,domain,modified_time,user_enabled,computer_enabled,wmi_filter_name,setting_count_user,setting_count_computer,link_count FROM gpo_inventory WHERE upload_id=? ORDER BY name',[upload.id]);
    return { upload, gpos:gpos.map(g=>Object.assign({},g,{guid:id(g.guid)})).filter(g=>g.guid) };
  }
  async function profiles(force) {
    if(profileCache && !force && Date.now()-profileCache.at<300000)return profileCache;
    if(profileFlight)return profileFlight;
    profileFlight=(async()=>{
      const kinds=Object.keys(KINDS), results=await Promise.all(kinds.map(k=>readAll('Migration '+k+' profiles',KINDS[k]+'?$select='+FIELDS[k]+'&$top=100')));
      const records=[], sources={};
      results.forEach((r,i)=>{sources[kinds[i]]=r.rec;if(r.rec.state==='ok' && r.items)r.items.forEach(x=>{const v=profileView(kinds[i],x);if(v.id)records.push(v);});});
      const result={at:Date.now(),records,sources,complete:results.every(r=>r.rec.state==='ok')};
      // Never replace a complete read with a silent partial list.
      if(result.complete)profileCache=result;
      return result;
    })().finally(()=>{profileFlight=null;});
    return profileFlight;
  }
  const wrap = fn => async (req,res) => {res.set('Cache-Control','no-store');try{await fn(req,res);}catch(e){console.error('[gpo-migration]',e.message);res.status(e.status || 500).json({ok:false,error:e.status?e.message:'Migration data could not be read or saved. Retry; contact the platform owner if it continues.'});}};
  const superOnly = (req,res,next) => { if(!req.user || req.user.isSuperAdmin!==true)return res.status(req.user?403:401).json({ok:false,error:'The shared GPO migration register is limited to super-admins, matching AD GPO access.'});return next(); };
  router.get('/migration', superOnly, wrap(async(req,res)=>{
    const [source, stored] = await Promise.all([sources(), pool.query('SELECT gpo_guid,version,payload,updated_at,updated_by FROM gpo_migration_register ORDER BY updated_at DESC')]);
    res.json({ok:true,source,records:stored[0].map(decode),canEdit:!req.user.readOnly,at:Date.now()});
  }));
  router.get('/migration/profiles',superOnly,wrap(async(req,res)=>res.json(Object.assign({ok:true},await profiles(req.query.refresh==='1')))));
  router.get('/migration/:guid/evidence',superOnly,wrap(async(req,res)=>{
    const guid=id(req.params.guid);if(!guid)throw fail(400,'Invalid GPO identifier');
    const [stored]=await pool.query('SELECT gpo_guid,version,payload,updated_at,updated_by FROM gpo_migration_register WHERE gpo_guid=?',[guid]);
    if(!stored.length)throw fail(404,'Track this GPO before reading its linked evidence');
    const record=decode(stored[0]);
    const linked=await Promise.all(record.profiles.map(async p=>{
      const base=KINDS[p.kind]+'/'+p.id;
      const [one,assignments]=await Promise.all([readOne('Linked '+p.kind+' profile',base+'?$select='+FIELDS[p.kind]),readAll('Linked profile assignments',base+'/assignments')]);
      const targets=assignments.rec.state==='ok'?(assignments.items || []).map(a=>{const t=a.target || {};return {type:t['@odata.type'] || 'unknown',groupId:t.groupId || null,filterId:t.deviceAndAppManagementAssignmentFilterId || null,filterType:t.deviceAndAppManagementAssignmentFilterType || null};}):null;
      return {ref:p,profile:one.item?profileView(p.kind,one.item):null,source:one.rec,assignmentSource:assignments.rec,targets};
    }));
    let pilot=null;
    if(record.pilotGroupId){
      let membership=pilotCache.get(record.pilotGroupId);
      if(!membership || req.query.refresh==='1' || Date.now()-membership.at>300000){
        const [group,members]=await Promise.all([readOne('Pilot group','/v1.0/groups/'+record.pilotGroupId+'?$select=id,displayName'),readAll('Pilot direct members','/v1.0/groups/'+record.pilotGroupId+'/members?$top=999')]);
        membership={group:group.item?{id:group.item.id,name:group.item.displayName}:null,groupSource:group.rec,members,at:Date.now()};
        if(group.rec.state==='ok' && members.rec.state==='ok'){pilotCache.set(record.pilotGroupId,membership);if(pilotCache.size>100)pilotCache.delete(pilotCache.keys().next().value);}
      }
      const snap=await snapshot();
      pilot={group:membership.group,groupSource:membership.groupSource,memberSource:membership.members.rec,
        readiness:membership.groupSource.state==='ok' && membership.members.rec.state==='ok'?pilotReadiness(membership.members.items,snap):{known:false,rows:null,why:'Pilot group membership was not read completely. No readiness total is inferred.'}};
    }
    const [history]=await pool.query('SELECT version,actor,created_at,change_json FROM gpo_migration_history WHERE gpo_guid=? ORDER BY version DESC LIMIT 20',[guid]);
    res.json({ok:true,version:record.version,linked,pilot,history:history.map(x=>({version:x.version,actor:x.actor,at:x.created_at,changes:typeof x.change_json==='string'?JSON.parse(x.change_json):x.change_json})),at:Date.now()});
  }));
  router.post('/migration/:guid',superOnly,json({limit:'20kb'}),wrap(async(req,res)=>{
    if(req.user.readOnly)throw fail(403,'This session is read-only');
    if(req.get('origin')!=='https://dev-corpit.nrpi.local')throw fail(403,'Save the register from the DEV CorpIT page');
    const guid=id(req.params.guid);if(!guid)throw fail(400,'Invalid GPO identifier');
    const input=normalize(req.body), source=await sources(), currentGpo=source.gpos.find(g=>g.guid===guid);
    const [beforeRows]=await pool.query('SELECT gpo_guid,version,payload,updated_at,updated_by FROM gpo_migration_register WHERE gpo_guid=?',[guid]);
    const before=beforeRows[0]?decode(beforeRows[0]):null;
    if((before?before.version:0)!==input.version)throw fail(409,'Another person saved this record. Reload the register before editing again.');
    if(!before && !currentGpo)throw fail(400,'Choose a GPO from the current saved AD snapshot');
    // Validate only new links. Existing links can be retained when a source is temporarily unavailable.
    const oldProfiles=new Set((before && before.profiles || []).map(p=>p.kind+':'+p.id));
    for(const p of input.profiles){if(oldProfiles.has(p.kind+':'+p.id))continue;const r=await readOne('Validate profile link',KINDS[p.kind]+'/'+p.id+'?$select='+FIELDS[p.kind]);if(r.rec.state!=='ok' || !r.item || id(r.item.id)!==p.id)throw fail(400,'A new profile link could not be verified. Reload profiles and retry.');}
    if(input.pilotGroupId && input.pilotGroupId!==(before && before.pilotGroupId)){
      const r=await readOne('Validate pilot group','/v1.0/groups/'+input.pilotGroupId+'?$select=id,displayName');if(r.rec.state!=='ok'||!r.item||id(r.item.id)!==input.pilotGroupId)throw fail(400,'The pilot group could not be verified. Check its ID and retry.');
    }
    const actor=String(req.user.email || req.user.upn || 'unknown').slice(0,254);
    const after=Object.assign({},input,{guid,sourceSnapshotId:before?before.sourceSnapshotId:source.upload.id,sourceName:before?before.sourceName:currentGpo.name});
    delete after.version;
    const changes=Object.keys(input).filter(k=>k!=='version' && JSON.stringify(before?before[k]:null)!==JSON.stringify(input[k]));
    const conn=await pool.getConnection();
    try{
      await conn.beginTransaction();
      if(before){const [r]=await conn.query('UPDATE gpo_migration_register SET payload=?,version=version+1,updated_by=?,updated_at=UTC_TIMESTAMP() WHERE gpo_guid=? AND version=?',[JSON.stringify(after),actor,guid,input.version]);if(r.affectedRows!==1)throw fail(409,'Another person saved this record. Reload before editing again.');}
      else{try{await conn.query('INSERT INTO gpo_migration_register (gpo_guid,version,payload,updated_by) VALUES (?,1,?,?)',[guid,JSON.stringify(after),actor]);}catch(e){if(e.code==='ER_DUP_ENTRY')throw fail(409,'This GPO was just registered. Reload before editing.');throw e;}}
      await conn.query('INSERT INTO gpo_migration_history (gpo_guid,version,actor,change_json) VALUES (?,?,?,?)',[guid,input.version+1,actor,JSON.stringify({fields:changes,before:before?Object.fromEntries(changes.map(k=>[k,before[k]])):null,after:Object.fromEntries(changes.map(k=>[k,after[k]]))})]);
      await conn.commit();
    }catch(e){await conn.rollback();throw e;}finally{conn.release();}
    res.json({ok:true,guid,version:input.version+1,message:'Shared register saved. No AD or Intune policy was changed.'});
  }));
}
module.exports={mount,normalize,pilotReadiness,profileView,id,STAGES,TRACKS};
