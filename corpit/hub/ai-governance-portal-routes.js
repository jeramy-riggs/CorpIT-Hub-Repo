'use strict';
// AI-GOVERNANCE PORTAL SYNC 2026-10-15 — Settings API for the Access Portal sync (ai-governance-portal.js).
// Mounted inside the governance router (/api/zscaler/governance/portal-sync/config), so schema readiness and
// the page read gate have already run. Every route here is Hub super admin only, the same gate as the other
// editors folded into subadmin Settings. The service token is write-only: no route returns it and the
// settings audit row records only (set)/(changed)/(cleared).
const SA=require('./settings-audit');
const PAGE_KEY='ai-governance',KEYS=['enabled','token'],SECRET=['token'];
module.exports=function({router,pool,rbac,wrap,actor,portal=require('./ai-governance-portal')({pool})}){
 const only=rbac.requireSuperAdmin,snap=()=>SA.snap(pool,'SELECT '+KEYS.join(',')+' FROM ai_governance_portal_sync WHERE id=1');
 router.get('/portal-sync/config',only,wrap(async(req,res)=>{res.set('Cache-Control','no-store, private');res.json({ok:true,...await portal.state()});}));
 router.put('/portal-sync/config',only,wrap(async(req,res)=>{
  const b=req.body&&typeof req.body==='object'?req.body:{},set={};
  if('enabled' in b)set.enabled=b.enabled===true||b.enabled===1||b.enabled==='1'||b.enabled==='true'?1:0;
  if('token' in b){const v=b.token==null?'':String(b.token).trim();if(v.length>200||/\s/.test(v))return res.status(400).json({ok:false,error:'That is not a Portal service token'});set.token=v||null;}
  const keys=Object.keys(set);if(!keys.length)return res.status(400).json({ok:false,error:'nothing to save'});
  const before=await snap();
  // next_run_at is cleared so an enabled sync runs on the worker's next minute tick, not an hour later.
  const cols=keys.concat('saved_by'),vals=keys.map(k=>set[k]).concat(actor(req));
  await pool.query('INSERT INTO ai_governance_portal_sync(id,'+cols.join(',')+',next_run_at) VALUES(1,'+cols.map(()=>'?').join(',')+',NULL) ON DUPLICATE KEY UPDATE '+cols.map(c=>c+'=VALUES('+c+')').join(',')+',next_run_at=NULL',vals);
  await SA.record(rbac,req,PAGE_KEY,'settings_saved',SA.entry({what:'ai-governance portal sync',id:1,before,after:await snap(),keys:KEYS,secretKeys:SECRET}));
  res.json({ok:true,...await portal.state()});
 }));
 // Runs the saved settings now (pull, then push), whether or not the hourly schedule is enabled.
 router.post('/portal-sync/config/run',only,wrap(async(req,res)=>{
  const r=await portal.run({actor:actor(req),trigger:'manual'});
  if(r.skipped)return res.status(r.reason==='running'?409:400).json({ok:false,error:r.reason==='running'?'A Portal sync is already running.':'Save the Portal service token first.'});
  const passed=r.pull.ok&&r.push.ok;
  await SA.record(rbac,req,PAGE_KEY,passed?'settings_test_sent':'settings_test_failed',SA.entry({what:'ai-governance portal sync run',op:'test',extra:{pull_ok:r.pull.ok,push_ok:r.push.ok}}));
  res.json({ok:true,passed,run:r,...await portal.state()});
 }));
};
