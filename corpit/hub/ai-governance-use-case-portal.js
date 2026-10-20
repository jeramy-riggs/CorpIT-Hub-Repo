'use strict';
// Governance-side, read-only Access Portal lookup. The only Portal operation is
// intakeClient.read(), which makes a bounded GET through the existing approver gate.
const M=require('./ai-governance-maintenance');
const model=require('./ai-governance-use-case-model');
const enrich=require('./ai-governance-use-case-enrich');

const fail=(message,status=400)=>{throw Object.assign(new Error(message),{status});};
const text=v=>typeof v==='string'?v.trim():'';
const same=(a,b)=>!!M.norm(a)&&M.norm(a)===M.norm(b);
const iso=v=>M.stamp(v)?.toISOString()||null;
const sqlTime=v=>iso(v)?.slice(0,19).replace('T',' ')||null;
const cut=(v,n)=>String(v??'').slice(0,n);

function facts(row){
 const d=row.details&&typeof row.details==='object'?row.details:{};
 const sub=row.submitter&&typeof row.submitter==='object'?row.submitter:{};
 const out=[];
 const add=(field,value,sourceField)=>{if(text(value))out.push({field,value:text(value),source_field:sourceField,source_value:text(value)});};
 add('dept',sub.dept,'submitter.dept');
 add('what',d.use_case,'details.use_case');
 add('vendor',d.tool_vendor,'details.tool_vendor');
 const systems=[text(d.adc_systems),text(d.client_systems)].filter(Boolean);
 if(systems.length)add('systems',[...new Set(systems)].join('; '),systems.length===2?'details.adc_systems + details.client_systems':text(d.adc_systems)?'details.adc_systems':'details.client_systems');
 add('notes',d.notes,'details.notes');
 if(row.id)out.push({field:'intake',value:'Yes',source_field:'id',source_value:String(row.id)});
 return out.flatMap(f=>{const valid=enrich.clean(f.field,f.value);return valid.problem?[]:[{...f,value:valid.value}];});
}

function match(row,uc,link){
 let detail=link?.detail;
 if(typeof detail==='string'){try{detail=JSON.parse(detail);}catch{detail=null;}}
 if(link&&Number(link.use_case_id)===Number(uc.id)&&link.status==='linked'&&detail?.confirmed_by_reviewer===true)return {level:'Exact Match',reason:'This request was previously confirmed for this use case.'};
 const d=row.details||{},sub=row.submitter||{};
 const app=same(d.tool_name,uc.app_name)||String(uc.aliases||'').split('\n').some(a=>same(d.tool_name,a));
 const purpose=same(d.use_case,uc.profile.what)||same(d.use_case,uc.profile.name);
 const department=same(sub.dept,uc.profile.dept);
 if(app&&(purpose||department))return {level:'Probable Match',reason:'Application and '+(purpose?'business purpose':'department')+' agree. Reviewer confirmation is required.'};
 if(app||purpose)return {level:'Possible Match',reason:(app?'Application':'Business purpose')+' agrees. Reviewer confirmation is required.'};
 return {level:'No Match',reason:'No supported identifier agrees with this use case.'};
}

async function useCase(pool,id){
 const n=Number(id);if(!Number.isSafeInteger(n)||n<1)fail('Choose a use case');
 const [rows]=await pool.query('SELECT u.id,u.catalog_id,u.profile,u.revision,c.app_name,c.aliases FROM ai_governance_use_case u JOIN ai_catalog c ON c.id=u.catalog_id WHERE u.id=?',[n]);
 if(!rows.length)fail('Use case not found',404);
 return {...rows[0],profile:model.parsed(rows[0].profile)};
}
async function lastSuccess(pool,actor){
 const [rows]=await pool.query("SELECT created_at FROM ai_governance_audit WHERE actor=? AND action IN ('use_case_portal_lookup','use_case_portal_match_confirmed') ORDER BY id DESC LIMIT 1",[actor]);
 return iso(rows[0]?.created_at);
}
async function audit(pool,actor,action,uc,before,after){
 await pool.query('INSERT INTO ai_governance_audit(actor,action,catalog_id,entity_id,before_json,after_json) VALUES(?,?,?,?,?,?)',[actor,action,uc?.catalog_id||null,uc?.id||null,before?JSON.stringify(before):null,JSON.stringify(after||{})]);
}
const terms=r=>[r.id,r.app_name,r.business_purpose,r.vendor,r.requester,r.department,r.status,r.manager,r.requester_email,r.requester_title,...Object.values(r.details||{}).flat()].filter(v=>typeof v==='string');

async function lookup(pool,{client,cookie,actor,use_case_id,q}){
 const uc=await useCase(pool,use_case_id),query=text(q);
 if(query.length<2||query.length>120)fail('Enter 2 to 120 characters to search Portal requests');
 const source=await client.read(cookie);
 const records=M.intakeRequests(source.rows,[],client.origin);
 const needle=query.toLocaleLowerCase();
 const filtered=records.filter(r=>terms(r).some(v=>v.toLocaleLowerCase().includes(needle)));
 const [links]=await pool.query("SELECT source_record_id,use_case_id,status,detail FROM ai_governance_uc_candidate WHERE source_key='intake' AND source_record_id IN (?)",[filtered.length?filtered.map(r=>r.id):['']]);
 const byId=new Map(links.map(r=>[r.source_record_id,r]));
 const raw=new Map(source.rows.map(r=>[r.id,r]));
 const matches=filtered.slice(0,50).map(r=>{
  const row=raw.get(r.id),m=match(row,uc,byId.get(r.id));
  return {request_id:r.id,use_case_name:r.business_purpose||null,requested_application:r.app_name||null,department:r.department||null,business_owner:null,technical_owner:null,requester:r.requester||null,vendor:r.vendor||null,request_status:r.status,approval_status:r.status,archived:r.archived,source_url:r.source_url,source_updated_at:r.updated_at,match_level:m.level,match_reason:m.reason,linked_to_other:!!byId.get(r.id)?.use_case_id&&Number(byId.get(r.id).use_case_id)!==Number(uc.id),proposals:facts(row).map(f=>({field:f.field,label:model.fields.find(x=>x.key===f.field)?.label||f.field,value:f.value,source_value:f.source_value,source_field:f.source_field,existing:uc.profile[f.field]||'',conflict:!!uc.profile[f.field]&&String(uc.profile[f.field]).trim()!==f.value}))};
 });
 await audit(pool,actor,'use_case_portal_lookup',uc,null,{ref:model.ref(uc.id),query,results:filtered.length,retrieved_at:source.checked_at,source_origin:client.origin,note:'Searched Access Portal for "'+query+'"; '+filtered.length+' search result'+(filtered.length===1?'':'s')+'.'});
 return {use_case_id:uc.id,ref:model.ref(uc.id),revision:uc.revision,query,results:filtered.length,shown:matches.length,records:matches,retrieved_at:source.checked_at,last_success_at:source.checked_at,source_origin:client.origin,stale:false};
}

async function confirm(pool,{client,cookie,actor,use_case_id,request_id,expected_revision,expected_updated_at}){
 const uc=await useCase(pool,use_case_id);
 if(Number(expected_revision)!==Number(uc.revision))fail('Use case changed. Search again before confirming.',409);
 if(!/^AIA-\d{4}-\d{5}$/.test(String(request_id||'')))fail('Choose a valid Access Portal request');
 const source=await client.read(cookie),row=source.rows.find(r=>r.id===request_id&&r.type==='aia');
 if(!row)fail('Request is no longer available. Search again.',409);
 if((iso(row.updated_at)||'')!==(iso(expected_updated_at)||''))fail('Access Portal request changed. Search again before confirming.',409);
 const c=await pool.getConnection();
 try{
  await c.beginTransaction();
  const [current]=await c.query('SELECT revision FROM ai_governance_use_case WHERE id=? FOR UPDATE',[uc.id]);
  if(!current.length||Number(current[0].revision)!==Number(expected_revision))fail('Use case changed. Search again before confirming.',409);
  const [links]=await c.query("SELECT * FROM ai_governance_uc_candidate WHERE source_key='intake' AND source_record_id=? FOR UPDATE",[request_id]);
  const link=links[0];
  if(link?.use_case_id&&Number(link.use_case_id)!==Number(uc.id))fail('This request is already linked to another use case. Review that link first.',409);
  const m=match(row,uc,link);
  if(m.level==='No Match')fail('No supported match was found. Review the source record and use case before linking.',409);
  const basic=M.intake(row,client.origin);
  if(!basic)fail('Request is not a valid AI intake record',409);
  const detail={request_id,app_name:basic.app_name,department:basic.department,requester:basic.requester,status:basic.status,source_url:basic.source_url,source_updated_at:iso(row.updated_at),retrieved_at:source.checked_at,match_level:m.level,match_reason:m.reason,confirmed_by_reviewer:true};
  let candidateId;
  if(link){candidateId=link.id;await c.query("UPDATE ai_governance_uc_candidate SET status='linked',use_case_id=?,reviewer=?,reviewed_at=UTC_TIMESTAMP(),detail=?,match_status='matched',observed_at=? WHERE id=?",[uc.id,actor,JSON.stringify(detail),sqlTime(source.checked_at),candidateId]);}
  else{const [r]=await c.query("INSERT INTO ai_governance_uc_candidate(kind,source_key,source_system,source_record_id,name,catalog_id,match_status,detail,status,use_case_id,reviewer,reviewed_at,observed_at) VALUES('intake','intake','Access Portal – AI use-case intake',?,?,?,'matched',?,'linked',?,?,UTC_TIMESTAMP(),?)",[request_id,cut((basic.app_name||'AI intake')+' – '+request_id,255),uc.catalog_id,JSON.stringify(detail),uc.id,actor,sqlTime(source.checked_at)]);candidateId=r.insertId;}
  const list=facts(row);let proposed=0;
  for(const f of list){
   const fp=enrich.fingerprint('uc:'+uc.id,f.field,'intake_lookup',request_id,f.value);
   const [existing]=await c.query('SELECT id,status FROM ai_governance_uc_proposal WHERE fingerprint=? FOR UPDATE',[fp]);
   const note=cut('Source field: '+f.source_field+'; source updated: '+(iso(row.updated_at)||'not recorded')+'; retrieved: '+source.checked_at+'; match: '+m.level,1000);
   const status=String(uc.profile[f.field]||'').trim().toLowerCase()===f.value.toLowerCase()?'matched':'open';
   if(existing.length){if(['open','matched','withdrawn'].includes(existing[0].status)){await c.query('UPDATE ai_governance_uc_proposal SET use_case_id=?,candidate_id=?,source_value=?,observed_at=?,confidence=?,match_method=?,evidence_note=?,evidence_url=?,status=? WHERE id=?',[uc.id,candidateId,f.source_value,sqlTime(source.checked_at),'needs_review',m.level+'; reviewer confirmed '+request_id,note,basic.source_url,status,existing[0].id]);proposed++;}continue;}
   await c.query('INSERT INTO ai_governance_uc_proposal(use_case_id,candidate_id,field_key,proposed_value,source_value,source_key,source_system,source_record_id,observed_at,confidence,match_method,evidence_note,evidence_url,fingerprint,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',[uc.id,candidateId,f.field,f.value,f.source_value,'intake_lookup','Access Portal – AI use-case intake',request_id,sqlTime(source.checked_at),'needs_review',m.level+'; reviewer confirmed '+request_id,note,basic.source_url,fp,status]);proposed++;
  }
  await c.query('INSERT INTO ai_governance_audit(actor,action,catalog_id,entity_id,before_json,after_json) VALUES(?,?,?,?,?,?)',[actor,'use_case_portal_match_confirmed',uc.catalog_id,uc.id,null,JSON.stringify({ref:model.ref(uc.id),request_id,match_level:m.level,match_method:m.reason,retrieved_at:source.checked_at,source_updated_at:iso(row.updated_at),source_url:basic.source_url,proposals:proposed,note:request_id+' confirmed as '+m.level+'; '+proposed+' Portal values proposed for review. No governance field was changed.'})]);
  await c.commit();return {ref:model.ref(uc.id),request_id,match_level:m.level,proposals:proposed,retrieved_at:source.checked_at};
 }catch(e){await c.rollback();throw e;}finally{c.release();}
}
module.exports={lookup,confirm,lastSuccess,facts,match};
