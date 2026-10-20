'use strict';
// AI-GOVERNANCE PORTAL SYNC 2026-10-15 — CorpIT half of the Access Portal integration (Rey, 2026-10-15).
//   PULL  GET  http://127.0.0.1:8001/api/portal/sync/aia                  AIA intake feed
//   PUSH  POST http://127.0.0.1:8001/api/portal/sync/governance-summary   at-a-glance snapshot
// Both use the X-Portal-Service-Token header. The token lives in ai_governance_portal_sync (row 1) and is
// set from subadmin Settings by a Hub super admin; it is never returned, logged or written to an audit row.
// Runs hourly from the refresh worker (after the source refreshes) and on demand from Settings.
//
// Pull: the whole feed since 2026-01-01 on every run, cursor paging inside the run. Portal's archive,
// unarchive and sweep do not move updated_at, so an incremental since would miss archive changes.
// Rows are upserted by request id into ai_governance_source 'portal_aia' and never deleted. Only the
// allowlisted fields below are kept: no email addresses, signatures, approval comments or audit bodies.
//
// Push reasons reuse the AI Governance page's own rules (ai-governance-overview-model.js, ai-risk-model.js,
// ai-governance-maintenance.js health): flagged_high = high-risk indicator awaiting assessment; overdue =
// review date passed; no_tier = assessment started, no tier recorded; missing_owner / missing_evidence =
// the inventory health gaps. Attention covers applications with a Portal-approved request, a started or
// recorded assessment, or an overdue review; unassessed catalog apps with nothing else count in status only.
const http=require('node:http'),crypto=require('node:crypto');
const M=require('./ai-governance-maintenance'),risk=require('./ai-risk-model');
const ORIGIN='http://127.0.0.1:8001',FEED='/api/portal/sync/aia',SUMMARY='/api/portal/sync/governance-summary';
const SINCE='2026-01-01T00:00:00+00:00',KEY='portal_aia',SYSTEM='system:ai-governance-portal-sync',INTERVAL=60;
const LIMIT=200,MAX_PAGES=50,MAX_BYTES=8*1024*1024,TIMEOUT=15000,PUSH_MAX=262144,DAY=86400000;
const ID=/^AIA-\d{4}-\d{5}$/;
const OWNER={overdue:'infosec',flagged_high:'infosec',no_tier:'legal',new_unassessed:'both'};
const EXPOSURE=[['npi','Yes','NPI = Yes'],['client','Yes','client data = Yes'],['consumer','Yes','consumer data = Yes'],['ext','Yes','external output = Yes'],['oversight','Fully automated','fully automated decisions']];
const ACTION={application_created:'added',application_reviewed:'updated the governance record for',risk_assessment_reviewed:'saved the risk assessment for',site_approval_reviewed:'recorded the site decision for',corporate_account_reviewed:'reviewed the corporate account for',access_recorded:'recorded access for',access_record_closed:'closed an access record for',project_linked:'linked a project to',project_unlinked:'unlinked a project from',source_evidence_attached:'attached source evidence to',zscaler_candidate_imported:'imported from Zscaler:',category_added:'added a category'};
const parse=v=>v==null?null:typeof v==='string'?JSON.parse(v):v;
const obj=v=>v&&typeof v==='object'&&!Array.isArray(v)?v:{};
const str=(v,max=190)=>typeof v==='string'?v.trim().slice(0,max):'';
const iso=v=>{if(!v)return null;const d=v instanceof Date?v:new Date(/^\d{4}-\d{2}-\d{2} \d{2}:/.test(String(v))?String(v).replace(' ','T')+'Z':String(v));return Number.isFinite(+d)?d.toISOString():null;};
const day=v=>iso(v)?.slice(0,10)||null;
const fail=(message,status=null)=>Object.assign(new Error(message),{status,safe:true});
function nextRunAt(at){const step=INTERVAL*60000;return new Date((Math.floor(at/step)+1)*step);}

// The allowlist kept per request. Portal's governance block is authoritative for approved/archived.
function project(row){
 const d=obj(row.details),s=obj(row.submitter),g=obj(row.governance);
 const approvedAt=(Array.isArray(row.audit)?row.audit:[]).filter(a=>a&&a.event==='Request Fully Approved').map(a=>iso(a.created_at)).filter(Boolean).pop()||null;
 return {id:row.id,status:str(g.status||row.status,30),approved:g.approved===true,archived:g.archived===true,archived_at:iso(g.archived_at),
  created_at:iso(row.created_at),updated_at:iso(g.updated_at||row.updated_at),approved_at:approvedAt,
  app_name:str(d.tool_name),vendor:str(d.tool_vendor),business_purpose:str(d.use_case,6000),requester:str(s.name),department:str(s.dept)};
}
const hash=p=>crypto.createHash('sha256').update(JSON.stringify(p)).digest('hex');

// Pure: previous snapshot + fetched rows -> next snapshot and the import record.
function merge(previous,rows,{now,pages,generatedAt}){
 const at=new Date(now).toISOString(),map=new Map((previous?.requests||[]).map(r=>[r.id,r])),added=[],changed=[];let unchanged=0,invalid=0;
 for(const row of rows){
  if(!row||!ID.test(row.id||'')){invalid++;continue;}
  const p=project(row),h=hash(p),old=map.get(p.id);
  if(!old)added.push(p.id);else if(old.hash!==h)changed.push(p.id);else unchanged++;
  map.set(p.id,{...p,hash:h,first_pulled_at:old?.first_pulled_at||at,last_pulled_at:at});
 }
 const requests=[...map.values()].sort((a,b)=>a.id.localeCompare(b.id));
 const snapshot={checked_at:at,feed_generated_at:generatedAt||null,since:SINCE,pages,fetched:rows.length,invalid,total:requests.length,
  approved:requests.filter(r=>r.approved).length,requests,
  note:'Access Portal AIA feed, upserted by request id; rows are never deleted. approved = Portal status approved and not archived.'};
 return {snapshot,record:{since:SINCE,pages,fetched:rows.length,invalid,added,changed,unchanged,total:requests.length,approved:snapshot.approved}};
}

// Pure: the at-a-glance payload. apps = maintenance-routes catalog() rows; sources = refresh_config rows.
function summarize({apps,sources,intake,audit,now}){
 const at=new Date(now),today=at.toISOString().slice(0,10),horizon=new Date(+at+30*DAY).toISOString().slice(0,10);
 const health=M.health(apps,sources,{now:at}),rows=new Map(health.rows.map(r=>[r.id,r]));
 const approved=(intake?.requests||[]).filter(r=>r.approved&&ID.test(r.id||''));
 const byApp=new Map(),unmatched=[];
 for(const r of approved){const m=M.match(r.app_name,apps);if(m.length===1){const k=Number(m[0].id);if(!byApp.has(k))byApp.set(k,[]);byApp.get(k).push(r);}else unmatched.push({...r,matches:m.length});}
 const first=list=>list.slice().sort((a,b)=>String(a.approved_at||a.updated_at||'').localeCompare(String(b.approved_at||b.updated_at||'')))[0];
 const attention=[],dueSoon=[];
 for(const a of apps){
  const id=Number(a.id),h=rows.get(id),r=risk.assessment(a,at),reqs=byApp.get(id)||[],req=reqs.length?first(reqs):null;
  const recorded=r.review_status==='Recorded',started=r.review_status==='In progress',due=/^\d{4}-\d{2}-\d{2}$/.test(h?.review_due||'')?h.review_due:null,overdue=!!h?.overdue;
  const exposures=EXPOSURE.filter(([k,v])=>r.coverage.some(c=>c.key===k&&c.state==='available'&&c.value===v));
  const dept=r.coverage.find(c=>c.key==='dept'&&c.state==='available')?.value||req?.department||'';
  if(due&&!overdue&&due>=today&&due<=horizon)dueSoon.push({app_id:id,name:a.app_name,tier:r.tier||null,due,link:'?riskApp='+id+'#risk'});
  if(!(reqs.length||started||recorded||overdue))continue;
  let reason=null,detail='',since=null;
  const riskDay=day(a.risk_updated_at)||day(h?.updated_at)||day(a.first_seen);
  if(overdue){reason='overdue';detail='review due '+due;since=due;}
  else if(exposures.length&&!recorded){reason='flagged_high';detail=exposures.map(x=>x[2]).join(', ');since=riskDay;}
  else if(reqs.length&&r.review_status==='Unassessed'){reason='new_unassessed';detail=reqs.length>1?reqs.length+' approved requests':'';since=day(req.approved_at||req.updated_at);}
  else if(started){reason='no_tier';detail=r.required_gaps?r.required_gaps+' required answers missing':'tier not recorded';since=riskDay;}
  else if(h?.gaps.some(g=>g.key==='owner')){reason='missing_owner';since=day(h.first_seen)||day(h.updated_at);}
  else if(h?.gaps.some(g=>g.key==='evidence')){reason='missing_evidence';since=day(h.first_seen)||day(h.updated_at);}
  if(!reason)continue;
  const row={app_id:id,name:a.app_name,dept:str(dept),reason,detail,since,link:['missing_owner','missing_evidence'].includes(reason)?'?app='+id+'#inventory':'?riskApp='+id+'#risk'};
  if(OWNER[reason])row.owner=OWNER[reason];
  if(req){row.request_id=req.id;row.requester=req.requester;}
  attention.push(row);
 }
 // An approved request whose tool is not exactly one catalog application: nothing has been assessed.
 for(const r of unmatched)attention.push({app_id:null,name:r.app_name||r.id,dept:r.department,request_id:r.id,requester:r.requester,owner:'both',reason:'new_unassessed',
  detail:r.matches>1?'matches '+r.matches+' catalog applications':'not in the AI catalog',since:day(r.approved_at||r.updated_at),link:'#intake-enrichment'});
 attention.sort((x,y)=>(x.since||'9999').localeCompare(y.since||'9999')||String(x.name).localeCompare(String(y.name)));
 dueSoon.sort((x,y)=>x.due.localeCompare(y.due)||x.name.localeCompare(y.name));
 const names=new Map(apps.map(a=>[Number(a.id),a.app_name]));
 const recent=[];
 for(const e of audit){
  const after=obj(parse(e.after_json));let actor,text;
  if(e.action==='portal_intake_imported'){const n=(after.added||[]).length,c=(after.changed||[]).length;if(!n&&!c)continue;actor='worker';text=[n?n+' AIA request'+(n===1?'':'s')+' imported from Portal':'',c?c+' updated':''].filter(Boolean).join(', ');}
  else if(String(e.actor).startsWith('system:'))continue;
  else{actor=String(e.actor).split('@')[0];const verb=ACTION[e.action]||e.action.replace(/_/g,' ');const app=e.catalog_id?names.get(Number(e.catalog_id)):null;text=app&&e.action!=='category_added'?verb+' '+app:verb;}
  recent.push({at:iso(e.created_at),actor,text});if(recent.length>=50)break;
 }
 return {as_of:at.toISOString(),status:{apps:health.total,approved:health.counts.approved,need_work:health.rows.filter(x=>x.gaps.length).length},
  attention:attention.slice(0,100),due_soon:dueSoon.slice(0,50),recent};
}

module.exports=function create({pool,request=http.request,now=Date.now}={}){
 function call(method,path,token,body){
  return new Promise((resolve,reject)=>{
   const data=body?Buffer.from(JSON.stringify(body)):null;let done=false;const end=(f,v)=>{if(!done){done=true;f(v);}};
   const req=request(new URL(path,ORIGIN),{method,timeout:TIMEOUT,headers:{Accept:'application/json','User-Agent':'corpit-ai-governance-portal-sync/1','X-Portal-Service-Token':token,...(data?{'Content-Type':'application/json','Content-Length':data.length}:{})}},res=>{
    let size=0;const chunks=[];
    res.on('data',ch=>{size+=ch.length;if(size>MAX_BYTES){end(reject,fail('Portal response exceeded the 8 MiB read limit'));req.destroy();}else chunks.push(ch);});
    res.on('error',()=>end(reject,fail('Portal response was interrupted')));
    res.on('end',()=>{let j=null;try{j=JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{}
     if(res.statusCode!==200||!j||j.ok!==true)return end(reject,fail(res.statusCode===401?'Portal refused the service token (HTTP 401)':'Portal answered HTTP '+res.statusCode,res.statusCode));
     end(resolve,j.data);});
   });
   req.on('timeout',()=>{end(reject,fail('Portal did not answer within 15 s'));req.destroy();});
   req.on('error',()=>end(reject,fail('Portal could not be reached on 127.0.0.1:8001')));
   if(data)req.write(data);req.end();
  });
 }
 async function config(c=pool){const [r]=await c.query('SELECT * FROM ai_governance_portal_sync WHERE id=1');return r[0]||null;}
 async function snapshot(c=pool){const [r]=await c.query('SELECT payload FROM ai_governance_source WHERE source_key=?',[KEY]);return r.length?parse(r[0].payload):null;}
 async function audit(c,actor,action,after){await c.query('INSERT INTO ai_governance_audit(actor,action,after_json) VALUES(?,?,?)',[actor,action,JSON.stringify(after)]);}
 async function catalog(c){const [rows]=await c.query('SELECT c.id,c.app_name,c.aliases,c.first_seen,c.last_seen,g.vendor,g.business_purpose,g.owner,g.category,g.ai_type,g.approval_status,g.evidence_url,g.review_due,g.updated_at,g.version,r.profile AS risk_profile,r.revision AS risk_revision,r.updated_at AS risk_updated_at,a.profile AS corporate_account,(SELECT COUNT(*) FROM ai_governance_access x WHERE x.catalog_id=c.id AND x.status=\'recorded\') AS manual_access_count FROM ai_catalog c LEFT JOIN ai_governance_app g ON g.catalog_id=c.id LEFT JOIN ai_governance_risk r ON r.catalog_id=c.id LEFT JOIN ai_governance_account a ON a.catalog_id=c.id WHERE c.retired=0 ORDER BY c.app_name');return rows;}

 async function pull(c,token,actor){
  const rows=[];let cursor='',pages=0,generatedAt=null;
  for(;;){
   if(++pages>MAX_PAGES)throw fail('Portal feed exceeded '+MAX_PAGES+' pages; nothing was imported');
   const q=new URLSearchParams({since:SINCE,limit:String(LIMIT)});if(cursor)q.set('cursor',cursor);
   const d=await call('GET',FEED+'?'+q,token);
   if(!d||!Array.isArray(d.rows))throw fail('Portal feed answered without rows; nothing was imported');
   rows.push(...d.rows);generatedAt=generatedAt||d.generated_at||null;
   if(!d.next_cursor)break;
   if(!ID.test(d.next_cursor)||d.next_cursor<=cursor)throw fail('Portal feed returned an unusable cursor; nothing was imported');
   cursor=d.next_cursor;
  }
  const {snapshot:next,record}=merge(await snapshot(c),rows,{now:now(),pages,generatedAt});
  await c.beginTransaction();
  try{
   await c.query('INSERT INTO ai_governance_source(source_key,payload,checked_by) VALUES(?,?,?) ON DUPLICATE KEY UPDATE payload=VALUES(payload),checked_by=VALUES(checked_by)',[KEY,JSON.stringify(next),actor]);
   await audit(c,actor,'portal_intake_imported',record);
   await c.commit();
  }catch(e){await c.rollback();throw e;}
  return record;
 }
 async function push(c,token,actor){
  const [sources]=await c.query('SELECT source_key,enabled,interval_minutes,last_success_at,last_status FROM ai_governance_refresh_config ORDER BY source_key');
  const [events]=await c.query("SELECT actor,action,catalog_id,after_json,created_at FROM ai_governance_audit WHERE created_at>=? AND (actor NOT LIKE 'system:%' OR action='portal_intake_imported') ORDER BY id DESC LIMIT 500",[new Date(now()-7*DAY)]);
  const body=summarize({apps:await catalog(c),sources,intake:await snapshot(c),audit:events,now:now()});
  const size=Buffer.byteLength(JSON.stringify(body));
  if(size>PUSH_MAX)throw fail('Summary is '+size+' bytes, over Portal\'s 256 KiB limit; not sent');
  const r=await call('POST',SUMMARY,token,body);
  const record={as_of:body.as_of,status:body.status,attention:body.attention.length,due_soon:body.due_soon.length,recent:body.recent.length,bytes:size,received_at:r?.received_at||null};
  await audit(c,actor,'portal_summary_pushed',record);
  return record;
 }

 // One run: pull, then push (the push still runs if the pull fails; it reports governance data, and the
 // previous intake snapshot is kept). A named lock keeps the worker and a Settings "Run now" from overlapping.
 async function run({actor=SYSTEM,trigger='scheduled'}={}){
  const c=await pool.getConnection();let held=false;
  const [[database]]=await c.query('SELECT DATABASE() AS name');
  const lock='ai-governance-portal-sync:'+crypto.createHash('sha256').update(database.name).digest('hex').slice(0,12);
  try{
   const [[l]]=await c.query('SELECT GET_LOCK(?,0) AS held',[lock]);if(!l.held)return {skipped:true,reason:'running'};held=true;
   const cfg=await config(c);
   if(!cfg||!cfg.token)return {skipped:true,reason:'not_configured'};
   if(trigger==='scheduled'&&(!cfg.enabled||cfg.next_run_at&&+new Date(cfg.next_run_at)>now()))return {skipped:true,reason:cfg.enabled?'not_due':'disabled'};
   const started=new Date(now());
   await c.query('UPDATE ai_governance_portal_sync SET next_run_at=?,last_run_at=?,last_run_by=? WHERE id=1',[nextRunAt(now()),started,actor]);
   const out={trigger,started_at:started.toISOString()};
   for(const [step,fn] of [['pull',pull],['push',push]]){
    try{out[step]={ok:true,...await fn(c,cfg.token,actor)};
     await c.query(`UPDATE ai_governance_portal_sync SET last_${step}_at=?,last_${step}_status='ok',last_${step}_error=NULL,last_${step}_detail=? WHERE id=1`,[new Date(now()),JSON.stringify(out[step])]);}
    catch(e){
     // Only our own messages reach the table and the audit row: no Portal bodies, URLs with tokens, or stack text.
     const error=e.safe?e.message:'Portal '+step+' failed ('+(e.code||e.name||'error')+')';out[step]={ok:false,error};
     await c.query(`UPDATE ai_governance_portal_sync SET last_${step}_at=?,last_${step}_status='failed',last_${step}_error=? WHERE id=1`,[new Date(now()),error.slice(0,255)]).catch(()=>{});
     await audit(c,actor,step==='pull'?'portal_intake_import_failed':'portal_summary_push_failed',{trigger,error}).catch(()=>{});
     console.error('[ai-governance-portal]',step,e.safe?e.status||'failed':e.code||e.name);
    }
   }
   return out;
  }finally{if(held)await c.query('SELECT RELEASE_LOCK(?)',[lock]).catch(()=>{});c.release();}
 }
 async function state(){
  const cfg=await config();const snap=await snapshot();const det=v=>{try{return parse(v);}catch{return null;}};
  return {config:{enabled:!!cfg?.enabled,token_set:!!cfg?.token,saved_at:cfg?.saved_at||null,saved_by:cfg?.saved_by||null},configured:!!cfg?.token,
   schedule:{interval_minutes:INTERVAL,next_run_at:cfg?.next_run_at||null,last_run_at:cfg?.last_run_at||null,last_run_by:cfg?.last_run_by||null},
   pull:{at:cfg?.last_pull_at||null,status:cfg?.last_pull_status||null,error:cfg?.last_pull_error||null,detail:det(cfg?.last_pull_detail)},
   push:{at:cfg?.last_push_at||null,status:cfg?.last_push_status||null,error:cfg?.last_push_error||null,detail:det(cfg?.last_push_detail)},
   intake:snap?{checked_at:snap.checked_at,total:snap.total,approved:snap.approved}:null,endpoint:{origin:ORIGIN,feed:FEED,summary:SUMMARY}};
 }
 return {run,state,config,snapshot};
};
module.exports.project=project;
module.exports.merge=merge;
module.exports.summarize=summarize;
module.exports.nextRunAt=nextRunAt;
module.exports.SINCE=SINCE;
