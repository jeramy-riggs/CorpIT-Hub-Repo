'use strict';
// AI USE-CASE ENRICHMENT 2026-10-20 — review of proposed workbook values for use cases
// (ai-governance-use-case-enrich.js). Mounted inside the governance router after the
// use-case routes, so the page read gate has already run. Editors (ai-governance admin)
// see proposals, drafts and evidence and decide them; readers see counts, Summary and
// Sources only. Access Portal is read only through the explicit lookup and
// confirmation routes, with the reviewer's session and Approver Portal read access.
const contract=require('./schema/contract');
const enrich=require('./ai-governance-use-case-enrich');
const portalLookup=require('./ai-governance-use-case-portal');
const SLICES=['ai-governance-use-case','ai-governance-use-case-enrich'];
module.exports=function({router,pool,rbac,admin,wrap,actor,id,intakeClient=require('./ai-governance-intake-client')()}){
 const readiness=require('./schema/readiness');
 const ready=SLICES.every(s=>contract.SLICES.includes(s))?SLICES.map(s=>readiness.requireSchema(s)):[(req,res)=>res.status(503).json({error:'SCHEMA_NOT_READY',slice:SLICES[1]})];
 const portalRead=rbac.requirePage('approver-portal','read');
 async function level(req,key){if(req.user.isSuperAdmin)return 'admin';const [p]=await pool.query('SELECT access_policy FROM rbac_pages WHERE page_key=? LIMIT 1',[key]);return p.length?rbac.effectiveLevelForPage(req.user.email,req.user.roles||[],key,p[0].access_policy):'none';}
 router.get('/use-cases/enrichment',...ready,wrap(async(req,res)=>{
  const editor=await level(req,'ai-governance')==='admin';
  res.json(await enrich.view(pool,{editor}));
 }));
 router.post('/use-cases/enrichment/run',admin,...ready,wrap(async(req,res)=>{
  const r=await enrich.run(pool,{trigger:'manual',actor:actor(req)});
  if(r.skipped)return res.status(409).json({error:'An enrichment run is already in progress. Try again in a minute.'});
  await pool.query('INSERT INTO ai_governance_audit(actor,action,catalog_id,entity_id,before_json,after_json) VALUES(?,?,?,?,?,?)',[actor(req),'use_case_enrichment_run',null,null,null,JSON.stringify({run_id:r.id,sources:r.sources.map(s=>({key:s.key,status:s.status,records:s.records??null})),counts:r.counts})]);
  res.json({ok:true,run:r});
 }));
 router.post('/use-cases/enrichment/decide',admin,...ready,wrap(async(req,res)=>res.json({ok:true,...await enrich.decide(pool,actor(req),req.body)})));
 router.post('/use-cases/enrichment/candidates/:id',admin,...ready,wrap(async(req,res)=>res.json({ok:true,...await enrich.candidateAction(pool,actor(req),id(req.params.id),req.body)})));
 router.get('/use-cases/enrichment/portal-status',admin,portalRead,...ready,wrap(async(req,res)=>{
  res.set('Cache-Control','no-store, private');
  res.json({last_success_at:await portalLookup.lastSuccess(pool,actor(req)),source_origin:intakeClient.origin});
 }));
 router.get('/use-cases/enrichment/portal-lookup',admin,portalRead,...ready,wrap(async(req,res)=>{
  res.set('Cache-Control','no-store, private');
  try{res.json(await portalLookup.lookup(pool,{client:intakeClient,cookie:req.headers.cookie,actor:actor(req),use_case_id:req.query.use_case_id,q:req.query.q}));}
  catch(e){if(e.status===424||e.status===502)return res.status(e.status).json({error:e.message,last_success_at:await portalLookup.lastSuccess(pool,actor(req)),source_origin:intakeClient.origin});throw e;}
 }));
 router.post('/use-cases/enrichment/portal-confirm',admin,portalRead,...ready,wrap(async(req,res)=>{
  res.set('Cache-Control','no-store, private');
  const b=req.body||{};
  res.json({ok:true,...await portalLookup.confirm(pool,{client:intakeClient,cookie:req.headers.cookie,actor:actor(req),use_case_id:b.use_case_id,request_id:b.request_id,expected_revision:b.expected_revision,expected_updated_at:b.expected_updated_at})});
 }));
 router.get('/use-cases/enrichment/audit',...ready,wrap(async(req,res)=>{
  if(await level(req,'ai-governance')!=='admin')return res.json({rows:[],can_edit:false,note:'The audit trail is shown to editors.'});
  res.json({rows:await enrich.auditTrail(pool),limit:300,can_edit:true});
 }));
};
