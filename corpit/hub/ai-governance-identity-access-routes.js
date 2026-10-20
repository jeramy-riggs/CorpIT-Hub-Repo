'use strict';
const A=require('./ai-governance-identity-access');
module.exports=function({router,pool,rbac,wrap,id}){
 const identity=rbac.requirePage('identity-diag','read');
 async function snapshot(){const [r]=await pool.query("SELECT payload FROM ai_governance_source WHERE source_key='identity_access'");return r.length?(typeof r[0].payload==='string'?JSON.parse(r[0].payload):r[0].payload):null;}
 router.get('/identity-access',identity,wrap(async(req,res)=>{res.set('Cache-Control','no-store');res.json(A.summary(await snapshot()));}));
 router.get('/identity-access/users',identity,wrap(async(req,res)=>{const d=await snapshot();res.set('Cache-Control','no-store');res.json({checked_at:d?.checked_at||null,run_id:d?.run_id||null,status:d?.status||'not_collected',retained:!!d?.retained,rows:d?.users||[],note:d?.note||'No saved access evidence.'});}));
 router.get('/identity-access/:id/users',identity,wrap(async(req,res)=>{const catalogId=id(req.params.id),d=await snapshot();res.set('Cache-Control','no-store');res.json({checked_at:d?.checked_at||null,run_id:d?.run_id||null,status:d?.status||'not_collected',retained:!!d?.retained,last_attempt:d?.last_attempt||null,rows:(d?.users||[]).filter(x=>Number(x.catalog_id)===catalogId),note:d?.note||'No saved access evidence.'});}));
};
