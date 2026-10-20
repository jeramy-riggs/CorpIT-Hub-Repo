'use strict';
const model=require('./ai-risk-model');
module.exports=function({router,pool,rbac,admin,wrap,transaction,actor,id,appInput,categories}) {
  router.get('/risk-inventory',wrap(async(req,res)=>{
    const [apps]=await pool.query(`SELECT c.id,c.app_name,c.source AS discovery_source,c.last_seen,g.vendor,g.owner,g.category,g.ai_type,g.review_due,g.business_purpose,g.approval_status,g.evidence_url,g.version AS governance_version,ac.profile AS corporate_account,r.profile AS risk_profile,r.revision AS risk_revision,r.updated_at AS risk_updated_at,r.updated_by AS risk_updated_by FROM ai_catalog c LEFT JOIN ai_governance_app g ON g.catalog_id=c.id LEFT JOIN ai_governance_account ac ON ac.catalog_id=c.id LEFT JOIN ai_governance_risk r ON r.catalog_id=c.id WHERE c.retired=0 ORDER BY c.app_name`);
    const [decisions]=await pool.query("SELECT a.catalog_id,a.actor,a.created_at,a.after_json FROM ai_governance_audit a JOIN (SELECT MAX(id) AS id FROM ai_governance_audit WHERE action='site_approval_reviewed' GROUP BY catalog_id) latest ON latest.id=a.id");
    const latest=new Map();for(const d of decisions){if(!latest.has(d.catalog_id)){const after=model.parsed(d.after_json);latest.set(d.catalog_id,{...after.approval_decision,actor:d.actor,created_at:d.created_at,current:Number(after.governance_version)===Number(apps.find(a=>a.id===d.catalog_id)?.governance_version)});}}
    let canEdit=!!req.user.isSuperAdmin;
    if(!canEdit) {const [p]=await pool.query("SELECT access_policy FROM rbac_pages WHERE page_key='ai-governance' LIMIT 1");if(p.length)canEdit=await rbac.effectiveLevelForPage(req.user.email,req.user.roles||[],'ai-governance',p[0].access_policy)==='admin';}
    res.set('Cache-Control','no-store, private');
    res.json({apps:apps.map(a=>({id:a.id,app_name:a.app_name,owner:a.owner,vendor:a.vendor,category:a.category,ai_type:a.ai_type||'unclassified',review_due:a.review_due instanceof Date?a.review_due.toISOString().slice(0,10):a.review_due||null,business_purpose:a.business_purpose,approval_status:a.approval_status||'unreviewed',governance_version:Number(a.governance_version)||0,approval_decision:latest.get(a.id)||null,evidence_url:a.evidence_url,discovery_source:a.discovery_source,assessment:model.assessment(a)})),fields:model.fields,editable:model.editable.map(f=>f.key),can_edit:canEdit,received_at:new Date().toISOString(),note:'One shared application catalog. App-level assessments do not replace use-case reviews, provision access, or establish complete discovery.'});
  }));
  router.patch('/site-approval/:id',admin,wrap(async(req,res)=>{
    const n=id(req.params.id),version=Number(req.body.version);
    if(!Number.isSafeInteger(version)||version<0)throw Object.assign(new Error('A current governance version is required'),{status:400});
    if(typeof req.body.decision_note!=='string'||req.body.conditions!=null&&typeof req.body.conditions!=='string')throw Object.assign(new Error('Decision rationale and conditions must be text'),{status:400});
    const note=String(req.body.decision_note||'').trim(),conditions=String(req.body.conditions||'').trim();
    if(!note||note.length>4000||conditions.length>4000)throw Object.assign(new Error('Provide a decision note of up to 4000 characters'),{status:400});
    const allowed=await categories();
    await transaction(req,'site_approval_reviewed',n,async c=>{
      const [apps]=await c.query('SELECT id FROM ai_catalog WHERE id=? AND retired=0 FOR UPDATE',[n]);
      if(!apps.length)throw Object.assign(new Error('Application not found'),{status:404});
      const [rows]=await c.query('SELECT * FROM ai_governance_app WHERE catalog_id=? FOR UPDATE',[n]);const old=rows[0]||null;
      if(version!==(old?old.version:0))throw Object.assign(new Error('Application changed. Reload before recording a decision.'),{status:409});
      const data=appInput({...old,review_due:old?.review_due instanceof Date?old.review_due.toISOString().slice(0,10):old?.review_due||null,approval_status:req.body.approval_status,owner:req.body.owner,evidence_url:req.body.evidence_url,business_purpose:req.body.business_purpose},allowed);
      if(!['under_review','approved','restricted','rejected'].includes(data.approval_status))throw Object.assign(new Error('Choose a review decision'),{status:400});
      if(data.approval_status==='approved'&&!data.business_purpose)throw Object.assign(new Error('Approved use / business purpose is required'),{status:400});
      if(data.approval_status==='restricted'&&!conditions)throw Object.assign(new Error('Restricted decisions require explicit conditions'),{status:400});
      if(old)await c.query('UPDATE ai_governance_app SET ?,version=version+1 WHERE catalog_id=?',[{...data,updated_by:actor(req)},n]);
      else await c.query('INSERT INTO ai_governance_app SET ?',{catalog_id:n,...data,updated_by:actor(req)});
      return {id:n,before:old,after:{...data,governance_version:version+1,approval_decision:{status:data.approval_status,note,conditions,version:version+1},note:'Governance decision only. No access, licenses, groups or Zscaler policy changed.'}};
    });res.json({id:n,version:version+1});
  }));
  router.get('/project-audit',rbac.requirePage('user-projects','read'),wrap(async(req,res)=>{
    const [rows]=await pool.query(`SELECT a.id,a.project_id,a.grant_id,a.action,a.actor,a.details,a.created_at,p.name AS project_name,g.user_sam AS user_identity FROM user_project_audit a LEFT JOIN user_projects p ON p.id=a.project_id LEFT JOIN user_project_grants g ON g.id=a.grant_id ORDER BY a.id DESC LIMIT 500`);
    const [grants]=await pool.query(`SELECT g.id,g.project_id,p.name AS project_name,g.ad_group_name,g.user_sam AS user_identity,g.user_display_name,g.user_dept,g.status,g.expires_at,g.granted_at,g.granted_by,g.ad_action_on_add,g.ad_action_on_remove,g.removed_at,g.removed_by FROM user_project_grants g JOIN user_projects p ON p.id=g.project_id ORDER BY g.id DESC LIMIT 2000`);
    res.set('Cache-Control','no-store, private');res.json({rows,grants,limit:500,grant_limit:2000,note:'Recorded User Projects events and grants. These are not live directory membership or vendor entitlement checks.'});
  }));
  router.patch('/risk-assessments/:id',admin,wrap(async(req,res)=>{
    const n=id(req.params.id),profile=model.validate(req.body.profile),revision=Number(req.body.revision);
    if(!Number.isSafeInteger(revision)||revision<0)throw Object.assign(new Error('A valid assessment revision is required'),{status:400});
    await transaction(req,'risk_assessment_reviewed',n,async c=>{
      // Serialize first creation as well as updates for this application.
      const [apps]=await c.query('SELECT id FROM ai_catalog WHERE id=? AND retired=0 FOR UPDATE',[n]);
      if(!apps.length)throw Object.assign(new Error('Application not found'),{status:404});
      const [rows]=await c.query('SELECT * FROM ai_governance_risk WHERE catalog_id=? FOR UPDATE',[n]);
      const old=rows[0]||null;
      if(revision!==(old?old.revision:0))throw Object.assign(new Error('Assessment changed. Reload before saving.'),{status:409});
      if(old)await c.query('UPDATE ai_governance_risk SET profile=?,revision=revision+1,updated_by=? WHERE catalog_id=?',[JSON.stringify(profile),actor(req),n]);
      else await c.query('INSERT INTO ai_governance_risk(catalog_id,profile,updated_by) VALUES(?,?,?)',[n,JSON.stringify(profile),actor(req)]);
      return {id:n,before:old?{profile:model.parsed(old.profile),revision:old.revision}:null,after:{profile,revision:revision+1,note:'App-level risk record only. Governance approval and access are unchanged.'}};
    });
    res.json({id:n,revision:revision+1});
  }));
};
