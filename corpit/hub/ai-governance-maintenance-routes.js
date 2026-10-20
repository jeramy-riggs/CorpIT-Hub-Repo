'use strict';
const M=require('./ai-governance-maintenance'),metrics=require('./ai-governance-metrics');
module.exports=function({router,pool,rbac,admin,wrap,actor,id,intakeClient=require('./ai-governance-intake-client')()}){
 const portal=rbac.requirePage('approver-portal','read');
 async function level(req,key){if(req.user.isSuperAdmin)return 'admin';const [p]=await pool.query('SELECT access_policy FROM rbac_pages WHERE page_key=? LIMIT 1',[key]);return p.length?rbac.effectiveLevelForPage(req.user.email,req.user.roles||[],key,p[0].access_policy):'none';}
 async function catalog(c=pool){const [rows]=await c.query('SELECT c.id,c.app_name,c.aliases,c.first_seen,c.last_seen,g.vendor,g.business_purpose,g.owner,g.category,g.ai_type,g.approval_status,g.evidence_url,g.review_due,g.updated_at,g.version,r.profile AS risk_profile,r.revision AS risk_revision,a.profile AS corporate_account,(SELECT COUNT(*) FROM ai_governance_access x WHERE x.catalog_id=c.id AND x.status=\'recorded\') AS manual_access_count FROM ai_catalog c LEFT JOIN ai_governance_app g ON g.catalog_id=c.id LEFT JOIN ai_governance_risk r ON r.catalog_id=c.id LEFT JOIN ai_governance_account a ON a.catalog_id=c.id WHERE c.retired=0 ORDER BY c.app_name');return rows;}
 router.get('/inventory-health',wrap(async(req,res)=>{
  const projectRead=['read','admin'].includes(await level(req,'user-projects')),apps=await catalog();
  if(projectRead){const [rows]=await pool.query("SELECT p.catalog_id,COUNT(*) AS n FROM ai_governance_project p JOIN user_project_grants g ON g.project_id=p.project_id AND g.ad_group_name=p.ad_group_name WHERE g.status='active' GROUP BY p.catalog_id");const map=new Map(rows.map(r=>[r.catalog_id,r.n]));apps.forEach(a=>a.project_access_count=map.get(a.id)||0);}
  const [sources]=await pool.query('SELECT source_key,enabled,interval_minutes,last_success_at,last_status FROM ai_governance_refresh_config ORDER BY source_key');
  res.set('Cache-Control','no-store, private');res.json({...M.health(apps,sources,{project_read:projectRead}),trends:await metrics.read(pool)});
 }));

 const readIntakes=wrap(async(req,res)=>{
  res.set('Cache-Control','no-store, private');
  let source;try{source=await intakeClient.read(req.headers.cookie);}catch(e){if(e.status===424)return res.status(424).json({error:e.message,source_origin:intakeClient.origin});throw e;}
  const apps=await catalog();
  res.json({checked_at:source.checked_at,source_origin:intakeClient.origin,intake_summary:M.intakeSummary(source.rows,intakeClient.origin),visible_ai_requests:source.rows.filter(x=>x.type==='aia').length,
   requests:M.intakeRequests(source.rows,apps,intakeClient.origin),records:M.proposals(source.rows,apps,intakeClient.origin),can_edit:false,
   note:'Read-only Access Portal intake and approval history visible to your existing Portal account. Submit, approve, reject or return requests in Access Portal. Source approval applies to the requested use case; it does not establish application-wide approval or provision access.'});
 });
 router.get('/intake-requests',portal,readIntakes);
 router.get('/intake-evidence',portal,readIntakes);
 // Retired enrichment action: intake records are a read-only mirror, even for administrators.
 router.post('/intake-enrichment/:id',portal,(req,res)=>res.status(405).json({error:'Intake is read-only in AI Governance. Use Access Portal for intake and approval actions.'}));
};
