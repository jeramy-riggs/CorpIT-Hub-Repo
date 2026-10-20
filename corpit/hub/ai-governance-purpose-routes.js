'use strict';
const crypto=require('node:crypto');
const parse=x=>typeof x==='string'?JSON.parse(x):x;
function fail(message,status=400){throw Object.assign(new Error(message),{status});}
function text(b,k,max,required=false){if(b[k]!=null&&typeof b[k]!=='string')fail('Invalid '+k);const s=(b[k]||'').trim();if(s.length>max)fail(k+' is too long');if(required&&!s)fail(k+' is required');return s||null;}
function choice(b,k,allowed){const v=text(b,k,40,true);if(!allowed.includes(v))fail('Invalid '+k);return v;}
function date(v){if(!v)return null;if(!/^\d{4}-\d{2}-\d{2}$/.test(v)||!Number.isFinite(Date.parse(v))||new Date(v).toISOString().slice(0,10)!==v)fail('Invalid source date');return v;}
function link(v){if(!v)return null;let u;try{u=new URL(v);}catch{fail('Use a valid evidence URL');}if(!['https:','http:'].includes(u.protocol)||u.username||u.password||u.search||u.hash)fail('Use an http(s) evidence URL without credentials, query parameters or fragments');return u.href;}
function input(b){
 const field=choice(b,'field_key',['owner','business_purpose']),scope_type=choice(b,'scope_type',['app_wide','departmental']),scope_description=text(b,'scope_description',500,true),use_case=text(b,'use_case',190,true);
 const origin=choice(b,'origin',['owner_response','source_record','analyst_suggestion','ai_suggestion']),state=choice(b,'state',['suggested','submitted']);
 if(['analyst_suggestion','ai_suggestion'].includes(origin)&&state!=='suggested')fail('Suggestions must stay Suggested until evidence is reviewed');
 return {field_key:field,scope_type,scope_description,use_case,value:text(b,'value',field==='owner'?190:6000,true),state,origin,
 source_system:text(b,'source_system',100,true),source_record_id:text(b,'source_record_id',190,true),source_revision:text(b,'source_revision',100),source_url:link(text(b,'source_url',2000,true)),source_date:date(text(b,'source_date',10)),
 respondent:text(b,'respondent',190),relationship:text(b,'relationship',255),capability:text(b,'capability',255),business_task:text(b,'business_task',1500),expected_output:text(b,'expected_output',1500),benefit:text(b,'benefit',1500),human_review:text(b,'human_review',1500),data_categories:text(b,'data_categories',1000),limitations:text(b,'limitations',1500),
 model:origin==='ai_suggestion'?text(b,'model',190,true):null,model_version:origin==='ai_suggestion'?text(b,'model_version',190,true):null};
}
function scopeKey(p){return crypto.createHash('sha256').update(p.scope_type==='app_wide'?'app_wide':JSON.stringify([p.use_case.toLowerCase(),p.scope_description.toLowerCase()])).digest('hex');}
function transition(row,b,reviewer,at){
 const p=parse(row.payload),confirmed=parse(row.confirmed_payload),action=choice(b,'action',['revise','confirm','dispute','withdraw']);
 if(Number(b.revision)!==Number(row.revision))fail('This answer changed. Reload before reviewing.',409);
 let next,accepted=confirmed;
 if(action==='revise'){
  next=input(b);if(next.field_key!==row.field_key||scopeKey(next)!==row.scope_key)fail('Keep the field and use-case scope unchanged; create a separate answer for another scope');
 }else{
  if(['withdrawn','disputed'].includes(p.state)&&action!=='revise')fail('Revise this answer before another review');
  next={...p,state:action==='confirm'?'confirmed':action==='dispute'?'disputed':'withdrawn',review_rationale:text(b,'review_rationale',3000,true),reviewed_by:reviewer,reviewed_at:at};
  if(action==='confirm'){
   if(p.state==='confirmed')fail('This version is already confirmed',409);
   if(b.attestation_checked!==true||b.exact_answer_checked!==true)fail('Confirm both the owner attestation and exact answer review');
   next.respondent=text(b,'respondent',190,true);next.relationship=text(b,'relationship',255,true);
   next.attestation_reference=text(b,'attestation_reference',1000,true);
   next.confirmed_at=at;next.confirmed_by=reviewer;next.confirmed_revision=Number(row.revision)+1;accepted={...next};
  }else accepted=null;
 }
 next.revision=Number(row.revision)+1;next.recorded_at=at;
 return {payload:next,confirmed_payload:accepted,action};
}
function summary(rows){const apps=new Map();for(const row of rows){const p=parse(row.payload),c=parse(row.confirmed_payload),id=Number(row.catalog_id);if(!apps.has(id))apps.set(id,{catalog_id:id,answers:0,suggested:0,submitted:0,disputed:0,withdrawn:0,confirmed_answers:0,confirmed_owner:false,confirmed_purpose:false,departmental_confirmed:0});const a=apps.get(id);a.answers++;if(p.state in a&&p.state!=='confirmed')a[p.state]++;if(c){a.confirmed_answers++;if(c.scope_type==='app_wide')a[c.field_key==='owner'?'confirmed_owner':'confirmed_purpose']=true;else a.departmental_confirmed++;}}return [...apps.values()];}
module.exports=function({router,pool,admin,wrap,actor,id}){
 const noStore=(req,res,next)=>{res.set('Cache-Control','no-store, private');next();};
 router.get('/purpose-intake-summary',noStore,wrap(async(req,res)=>{const [rows]=await pool.query('SELECT a.catalog_id,a.payload,a.confirmed_payload FROM ai_governance_purpose_answer a JOIN ai_catalog c ON c.id=a.catalog_id WHERE c.retired=0 ORDER BY a.id');res.json({apps:summary(rows),read_at:new Date().toISOString(),note:'Confirmation counts are separate from recorded inventory completeness. Departmental answers do not confirm an application-wide purpose.'});}));
 router.get('/purpose-intake',admin,noStore,wrap(async(req,res)=>{const [rows]=await pool.query('SELECT a.* FROM ai_governance_purpose_answer a JOIN ai_catalog c ON c.id=a.catalog_id WHERE c.retired=0 ORDER BY a.updated_at DESC,a.id DESC LIMIT 1001');res.json({rows:rows.slice(0,1000).map(r=>({...r,payload:parse(r.payload),confirmed_payload:parse(r.confirmed_payload)})),partial:rows.length>1000,limit:1000,read_at:new Date().toISOString()});}));
 router.get('/purpose-intake/:id/history',admin,noStore,wrap(async(req,res)=>{const [rows]=await pool.query('SELECT revision,payload,actor,created_at FROM ai_governance_purpose_revision WHERE answer_id=? ORDER BY revision DESC LIMIT 101',[id(req.params.id)]);res.json({rows:rows.slice(0,100).map(r=>({...r,payload:parse(r.payload)})),partial:rows.length>100});}));
 async function save(req,res,edit){const c=await pool.getConnection();try{await c.beginTransaction();let catalogId,answerId,before=null,after,confirmed=null,action,rev;
  if(edit){const [rows]=await c.query('SELECT * FROM ai_governance_purpose_answer WHERE id=? FOR UPDATE',[id(req.params.id)]);if(!rows.length)fail('Answer not found',404);before=rows[0];catalogId=Number(before.catalog_id);answerId=Number(before.id);const result=transition(before,req.body,actor(req),new Date().toISOString());after=result.payload;confirmed=result.confirmed_payload;action=result.action;rev=after.revision;
  }else{catalogId=id(req.body.catalog_id);after={...input(req.body),revision:1,recorded_at:new Date().toISOString()};rev=1;action='created';}
  const [apps]=await c.query('SELECT id FROM ai_catalog WHERE id=? AND retired=0',[catalogId]);if(!apps.length)fail('Application not found',404);
  if(edit)await c.query('UPDATE ai_governance_purpose_answer SET payload=?,confirmed_payload=?,revision=?,updated_by=? WHERE id=?',[JSON.stringify(after),confirmed?JSON.stringify(confirmed):null,rev,actor(req),answerId]);
  else{const [r]=await c.query('INSERT INTO ai_governance_purpose_answer(catalog_id,field_key,scope_key,payload,updated_by) VALUES(?,?,?,?,?)',[catalogId,after.field_key,scopeKey(after),JSON.stringify(after),actor(req)]);answerId=r.insertId;}
  await c.query('INSERT INTO ai_governance_purpose_revision(answer_id,revision,payload,actor) VALUES(?,?,?,?)',[answerId,rev,JSON.stringify(after),actor(req)]);
  // Answer text stays in the restricted revision table; general audit stores references only.
  await c.query('INSERT INTO ai_governance_audit(actor,action,catalog_id,entity_id,before_json,after_json) VALUES(?,?,?,?,?,?)',[actor(req),'purpose_answer_'+action,catalogId,answerId,before?JSON.stringify({revision:before.revision}):null,JSON.stringify({answer_id:answerId,revision:rev,field_key:after.field_key,state:after.state,scope_type:after.scope_type})]);
  await c.commit();res.status(edit?200:201).json({id:answerId,revision:rev,note:'Answer saved separately. Inventory, access and approval decisions were not changed.'});
 }catch(e){await c.rollback();if(e.code==='ER_DUP_ENTRY')fail('An answer already exists for this application, field and scope. Open it to add a revision.',409);throw e;}finally{c.release();}}
 router.post('/purpose-intake',admin,noStore,wrap((req,res)=>save(req,res,false)));
 router.patch('/purpose-intake/:id',admin,noStore,wrap((req,res)=>save(req,res,true)));
};
module.exports.test={input,scopeKey,transition,summary,link,date};
