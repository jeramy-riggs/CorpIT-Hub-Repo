'use strict';
// AI USE-CASE INVENTORY 2026-10-20 — one record per use case from the InfoSec / Legal
// "AI/ML Use Inventory" workbook, each linked to one catalog application. Mounted inside the
// governance router (/api/zscaler/governance/use-cases), so the page read gate and the
// 'ai-governance' schema check have already run; these routes add their own slice so a
// missing ai_governance_use_case table refuses only this view. Uploads arrive as base64 JSON
// under the hub's global 1 MB body limit (server.js): a 640 KB file is ~874 KB of base64,
// leaving room for 2000 import row picks.
// Records only: nothing here changes access, approval, the catalog or the app assessment.
// There is no delete route.
const contract=require('./schema/contract');
const model=require('./ai-governance-use-case-model');
const xlsx=require('./ai-governance-use-case-xlsx');
const fs=require('node:fs'),path=require('node:path');
const SLICE='ai-governance-use-case',MAX_FILE=640*1024,MAX_ROWS=2000;
const TEMPLATE=path.join(__dirname,'ai-governance-use-case-template.xlsx');
const NOTE='Use-case records from the InfoSec / Legal workbook. They do not approve an application, grant access, or change the app-level assessment.';
function fail(message,status=400){throw Object.assign(new Error(message),{status});}
const norm=v=>String(v||'').normalize('NFKC').toLowerCase().replace(/[^\p{L}\p{N}]/gu,'');
// "Fill blanks from app": the app's own catalog record, corporate account and app-level
// assessment, in workbook form. Name, Category (the catalog's list differs) and the
// InfoSec / Legal review section are left for the use case itself.
const NO_FILL=new Set(['name','cat','window','tier','capprov','revby','revdate','followup']);
const SSO={configured:'Yes',reported:'Partial',not_applicable:'N/A'}; // as ai-risk-model assessment()
function prefill(a){
 const src={...model.parsed(a.risk_profile),what:a.business_purpose,bowner:a.owner,vendor:a.vendor,sso:SSO[model.parsed(a.corporate_account).sso_status]||''},out={};
 for(const f of model.fields){if(NO_FILL.has(f.key)||typeof src[f.key]!=='string'||!src[f.key].trim())continue;const r=model.check({name:'-',[f.key]:src[f.key]});if(!r.problems.length)out[f.key]=r.profile[f.key];}
 return out;
}
let template=null;
module.exports=function({router,pool,rbac,admin,wrap,transaction,actor,id}){
 const ready=contract.SLICES.includes(SLICE)?require('./schema/readiness').requireSchema(SLICE):(req,res)=>res.status(503).json({error:'SCHEMA_NOT_READY',slice:SLICE});
 const appId=v=>{if(v==null||v==='')fail('Choose the catalog application this use case belongs to');return id(v);};
 async function canEdit(req){if(req.user.isSuperAdmin)return true;const [p]=await pool.query("SELECT access_policy FROM rbac_pages WHERE page_key='ai-governance' LIMIT 1");return p.length?await rbac.effectiveLevelForPage(req.user.email,req.user.roles||[],'ai-governance',p[0].access_policy)==='admin':false;}
 async function apps(c=pool){const [r]=await c.query('SELECT id,app_name,aliases FROM ai_catalog WHERE retired=0 ORDER BY app_name');return r;}
 async function liveApp(c,n){const [a]=await c.query('SELECT id FROM ai_catalog WHERE id=? AND retired=0 FOR SHARE',[n]);if(!a.length)fail('Choose a current catalog application');}
 async function audit(c,req,action,catalogId,entityId,before,after){await c.query('INSERT INTO ai_governance_audit(actor,action,catalog_id,entity_id,before_json,after_json) VALUES(?,?,?,?,?,?)',[actor(req),action,catalogId,entityId,before?JSON.stringify(before):null,JSON.stringify(after||{})]);}
 function decode(b){
  if(typeof b.data_base64!=='string'||!b.data_base64)fail('Choose the returned .xlsx workbook');
  if(b.data_base64.length>Math.ceil(MAX_FILE/3)*4)fail('The file is larger than 640 KB');
  if(!/^[A-Za-z0-9+/]*={0,2}$/.test(b.data_base64))fail('The file could not be read');
  const buf=Buffer.from(b.data_base64,'base64');if(buf.length>MAX_FILE)fail('The file is larger than 640 KB');
  return {file:String(b.file_name||'').slice(0,190),buf};
 }
 // Compares the workbook with the saved records. Used by preview and, inside the import
 // transaction (rows locked), to re-check exactly what the reviewer saw.
 async function plan(buf,c=pool,lock=false){
  const book=xlsx.parseInventory(buf,{maxRows:MAX_ROWS});
  const [saved]=await c.query('SELECT id,catalog_id,profile,revision FROM ai_governance_use_case ORDER BY id'+(lock?' FOR UPDATE':''));
  const list=await apps(c),byId=new Map(saved.map(r=>[r.id,{...r,profile:model.parsed(r.profile)}]));
  const names=new Map();for(const a of list)for(const n of [a.app_name,...String(a.aliases||'').split('\n')]){const k=norm(n);if(k)names.set(k,[...new Set([...(names.get(k)||[]),a.id])]);}
  const key=p=>norm(p.name)+'\u0001'+norm(p.dept),inFile=new Map(),usedIds=new Map(),rows=[];
  for(const r of book.rows){
   const {profile,problems}=model.check(r.values),all=[...r.problems,...problems],notes=[];
   let use=null;
   if(r.id){const n=model.refId(r.id);
    if(n&&byId.has(n)){if(usedIds.has(n))all.push(model.ref(n)+' is also on row '+usedIds.get(n));else{usedIds.set(n,r.row);use=byId.get(n);}}
    else if(n)notes.push(r.id+' is not in this inventory; it will be added as a new record.');
    else notes.push('Column A "'+r.id.slice(0,40)+'" is not a use-case ID (UC-0000); it will be added as a new record.');}
   const changes=use?model.fields.filter(f=>(use.profile[f.key]||'')!==(profile[f.key]||'')).map(f=>f.label):[];
   if(use&&!changes.length)notes.push('No changes from the saved record.');
   let duplicate_of=null;
   if(profile.name){const k=key(profile);
    if(inFile.has(k))duplicate_of='row '+inFile.get(k);
    else{const twin=[...byId.values()].find(x=>x.id!==(use&&use.id)&&key(x.profile)===k);if(twin)duplicate_of=model.ref(twin.id);inFile.set(k,r.row);}
    if(duplicate_of)notes.push('Same name and department as '+duplicate_of+'.');}
   let catalog_id=use?use.catalog_id:null,app_guess=false;
   if(!use)for(const v of [profile.vendor,profile.name]){const hit=names.get(norm(v))||[];if(hit.length===1){catalog_id=hit[0];app_guess=true;break;}}
   const importable=!all.length;
   rows.push({row:r.row,id_text:r.id,action:use?'update':'add',use_case_id:use?use.id:null,ref:use?model.ref(use.id):null,revision:use?use.revision:null,
    values:profile,calc:model.calc(profile),problems:all,notes,changes,duplicate_of,catalog_id,app_guess,importable,
    default_selected:importable&&!!catalog_id&&!duplicate_of&&(!use||changes.length>0)});
  }
  return {sheet:book.sheet,rows,skipped:book.skipped,apps:list.map(a=>({id:a.id,app_name:a.app_name}))};
 }
 router.get('/use-cases',ready,wrap(async(req,res)=>{
  const [rows]=await pool.query('SELECT u.id,u.catalog_id,u.profile,u.revision,u.created_by,u.created_at,u.updated_by,u.updated_at,c.app_name,c.retired AS app_retired FROM ai_governance_use_case u LEFT JOIN ai_catalog c ON c.id=u.catalog_id ORDER BY u.id');
  const edit=await canEdit(req),[list]=await pool.query('SELECT c.id,c.app_name,g.vendor,g.business_purpose,g.owner,ac.profile AS corporate_account,r.profile AS risk_profile FROM ai_catalog c LEFT JOIN ai_governance_app g ON g.catalog_id=c.id LEFT JOIN ai_governance_account ac ON ac.catalog_id=c.id LEFT JOIN ai_governance_risk r ON r.catalog_id=c.id WHERE c.retired=0 ORDER BY c.app_name');
  res.set('Cache-Control','no-store, private');
  res.json({rows:rows.map(r=>{const profile=model.parsed(r.profile);return {id:r.id,ref:model.ref(r.id),catalog_id:r.catalog_id,app_name:r.app_name||null,app_retired:!!r.app_retired,profile,calc:model.calc(profile),revision:r.revision,created_by:r.created_by,created_at:r.created_at,updated_by:r.updated_by,updated_at:r.updated_at};}),
   apps:list.map(a=>({id:a.id,app_name:a.app_name,...(edit?{prefill:prefill(a)}:{})})),fields:model.fields,columns:model.COLUMNS.map(({col,key,label,calculated})=>({col,key,label,calculated:!!calculated})),
   can_edit:edit,max_upload_bytes:MAX_FILE,max_rows:MAX_ROWS,received_at:new Date().toISOString(),note:NOTE});
 }));
 router.post('/use-cases',ready,admin,wrap(async(req,res)=>{
  const b=req.body||{},n=appId(b.catalog_id),profile=model.validate(b.profile);
  const r=await transaction(req,'use_case_added',n,async c=>{
   await liveApp(c,n);
   const [x]=await c.query('INSERT INTO ai_governance_use_case(catalog_id,profile,created_by,updated_by) VALUES(?,?,?,?)',[n,JSON.stringify(profile),actor(req),actor(req)]);
   return {id:x.insertId,after:{ref:model.ref(x.insertId),catalog_id:n,profile,revision:1,note:NOTE}};
  });
  res.status(201).json({id:r.id,ref:model.ref(r.id),revision:1});
 }));
 router.patch('/use-cases/:id',ready,admin,wrap(async(req,res)=>{
  const b=req.body||{},n=id(req.params.id),app=appId(b.catalog_id),profile=model.validate(b.profile),revision=Number(b.revision);
  if(!Number.isSafeInteger(revision)||revision<1)fail('A current revision is required');
  await transaction(req,'use_case_updated',app,async c=>{
   const [rows]=await c.query('SELECT * FROM ai_governance_use_case WHERE id=? FOR UPDATE',[n]),old=rows[0];
   if(!old)fail('Use case not found',404);
   if(old.revision!==revision)fail('Use case changed. Reload before saving.',409);
   // A record may stay on an application retired since; moving it needs a current one.
   if(app!==old.catalog_id)await liveApp(c,app);
   await c.query('UPDATE ai_governance_use_case SET catalog_id=?,profile=?,revision=revision+1,updated_by=? WHERE id=?',[app,JSON.stringify(profile),actor(req),n]);
   return {id:n,before:{ref:model.ref(n),catalog_id:old.catalog_id,profile:model.parsed(old.profile),revision:old.revision},after:{ref:model.ref(n),catalog_id:app,profile,revision:revision+1,note:NOTE}};
  });
  res.json({id:n,revision:revision+1});
 }));
 router.post('/use-cases/import-preview',ready,admin,wrap(async(req,res)=>{
  const {file,buf}=decode(req.body||{}),p=await plan(buf);
  res.set('Cache-Control','no-store, private');
  res.json({file_name:file,...p,counts:{rows:p.rows.length,importable:p.rows.filter(r=>r.importable).length,selected:p.rows.filter(r=>r.default_selected).length,problems:p.rows.filter(r=>!r.importable).length,skipped:p.skipped.length}});
 }));
 router.post('/use-cases/import',ready,admin,wrap(async(req,res)=>{
  const b=req.body||{},{file,buf}=decode(b);
  if(!Array.isArray(b.rows)||!b.rows.length)fail('Choose at least one row to import');
  if(b.rows.length>MAX_ROWS)fail('Too many rows');
  const picks=new Map();
  for(const x of b.rows){
   const row=Number(x&&x.row);if(!Number.isSafeInteger(row)||row<6)fail('Invalid row number');
   if(picks.has(row))fail('Row '+row+' is listed twice');
   picks.set(row,{catalog_id:appId(x.catalog_id),use_case_id:x.use_case_id==null?null:id(x.use_case_id),revision:x.revision==null?null:Number(x.revision)});
  }
  const c=await pool.getConnection(),added=[],updated=[];
  try{
   await c.beginTransaction();
   const p=await plan(buf,c,true),byRow=new Map(p.rows.map(r=>[r.row,r]));
   const [ok]=await c.query('SELECT id FROM ai_catalog WHERE retired=0 AND id IN (?) FOR SHARE',[[...new Set([...picks.values()].map(x=>x.catalog_id))]]);
   const live=new Set(ok.map(a=>a.id)),source={file_name:file};
   for(const [row,pick] of [...picks].sort((a,b)=>a[0]-b[0])){
    const r=byRow.get(row);
    if(!r)fail('Row '+row+' is not a use-case row in this file. Preview the file again.',409);
    if(!r.importable)fail('Row '+row+' cannot be imported: '+r.problems[0]);
    if(r.use_case_id!==pick.use_case_id||r.revision!==pick.revision)fail('Row '+row+(r.ref?' ('+r.ref+')':'')+' changed since the preview. Preview the file again.',409);
    if(!live.has(pick.catalog_id)&&!(r.use_case_id&&pick.catalog_id===r.catalog_id))fail('Row '+row+': choose a current catalog application');
    if(r.use_case_id){
     await c.query('UPDATE ai_governance_use_case SET catalog_id=?,profile=?,revision=revision+1,updated_by=? WHERE id=?',[pick.catalog_id,JSON.stringify(r.values),actor(req),r.use_case_id]);
     await audit(c,req,'use_case_import_updated',pick.catalog_id,r.use_case_id,{ref:r.ref,catalog_id:r.catalog_id,revision:r.revision},{ref:r.ref,catalog_id:pick.catalog_id,profile:r.values,revision:r.revision+1,changes:r.changes,source:{...source,row},note:NOTE});
     updated.push(r.ref);
    }else{
     const [x]=await c.query('INSERT INTO ai_governance_use_case(catalog_id,profile,created_by,updated_by) VALUES(?,?,?,?)',[pick.catalog_id,JSON.stringify(r.values),actor(req),actor(req)]);
     await audit(c,req,'use_case_imported',pick.catalog_id,x.insertId,null,{ref:model.ref(x.insertId),catalog_id:pick.catalog_id,profile:r.values,revision:1,source:{...source,row},note:NOTE});
     added.push(model.ref(x.insertId));
    }
   }
   await c.commit();
  }catch(e){await c.rollback();throw e;}finally{c.release();}
  res.json({added,updated});
 }));
 router.get('/use-cases/export',ready,wrap(async(req,res)=>{
  const [rows]=await pool.query('SELECT id,profile FROM ai_governance_use_case ORDER BY id');
  if(!template)template=fs.readFileSync(TEMPLATE);
  const buf=xlsx.buildExport(template,rows.map(r=>{const profile=model.parsed(r.profile);return {ref:model.ref(r.id),profile,calc:model.calc(profile)};}));
  res.set({'Content-Type':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','Content-Disposition':'attachment; filename="AI_ML_Use_Inventory_'+new Date().toISOString().slice(0,10)+'.xlsx"','Cache-Control':'no-store, private','X-Content-Type-Options':'nosniff'});
  res.send(buf);
 }));
};
