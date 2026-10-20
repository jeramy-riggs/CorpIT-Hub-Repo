'use strict';
const crypto=require('crypto'),Z=require('./ai-governance-zscaler'),R=require('./ai-governance-rapid7'),E=require('./ai-governance-entra'),A=require('./ai-governance-identity-access');
const SOURCES=['zscaler','entra','rapid7'],SYSTEM='system:ai-governance-refresh';
const parse=v=>typeof v==='string'?JSON.parse(v):v;
// Stable wall-clock boundaries: manual runs and restarts never move the cadence.
function nextRunAt(minutes,at=Date.now()){const step=minutes*60000;if(!Number.isFinite(step)||step<=0||!Number.isFinite(at))throw new Error('Invalid refresh clock');return new Date((Math.floor(at/step)+1)*step);}
function nextMinuteDelay(at=Date.now()){return 60000-(at%60000);}
module.exports=function create({pool,zscalerCollect=()=>Z.collect(Z.client()),entraCollect=E.collect,accessCollect=A.collect,rapid7Client=()=>R.client(),rapid7Collect=R.collect,now=Date.now}){
 async function audit(c,actor,action,after,before=null){await c.query('INSERT INTO ai_governance_audit(actor,action,before_json,after_json) VALUES(?,?,?,?)',[actor,action,before?JSON.stringify(before):null,JSON.stringify(after)]);}
 async function tx(c,fn){await c.beginTransaction();try{const r=await fn();await c.commit();return r;}catch(e){await c.rollback();throw e;}}
 async function snapshot(key){const [r]=await pool.query('SELECT payload FROM ai_governance_source WHERE source_key=?',[key]);return r.length?parse(r[0].payload):null;}
 async function job(key){const [r]=await pool.query('SELECT r.* FROM ai_governance_refresh_run r JOIN ai_governance_refresh_config c ON c.last_run_id=r.id WHERE c.source_key=?',[key]);return r.length?{...r[0],error:r[0].error||null}:null;}
 async function status(){const [rows]=await pool.query('SELECT * FROM ai_governance_refresh_config ORDER BY FIELD(source_key,\'zscaler\',\'entra\',\'rapid7\')');const [worker]=await pool.query('SELECT last_seen_at,TIMESTAMPDIFF(SECOND,last_seen_at,UTC_TIMESTAMP(3)) AS age_seconds FROM ai_governance_refresh_worker WHERE id=1');const [history]=await pool.query('SELECT * FROM ai_governance_refresh_run ORDER BY started_at DESC,id DESC LIMIT 15');return {sources:rows,history,worker:{last_seen_at:worker[0]?.last_seen_at||null,healthy:!!worker.length&&worker[0].age_seconds<180},server_time:new Date(now()).toISOString(),note:'Zscaler labels take precedence. Schedules refresh evidence only; new candidates require review.'};}
 async function configure(key,enabled,minutes,actor){if(!SOURCES.includes(key)||typeof enabled!=='boolean'||!Number.isInteger(minutes)||minutes<60||minutes>1440)throw Object.assign(new Error('Choose a source, enabled state and interval from 60 to 1440 minutes'),{status:400});const c=await pool.getConnection();try{await tx(c,async()=>{const [old]=await c.query('SELECT * FROM ai_governance_refresh_config WHERE source_key=? FOR UPDATE',[key]);await c.query('UPDATE ai_governance_refresh_config SET enabled=?,interval_minutes=?,next_run_at=?,updated_by=? WHERE source_key=?',[enabled?1:0,minutes,enabled?nextRunAt(minutes,now()):null,actor,key]);await audit(c,actor,'source_refresh_schedule_changed',{source:key,enabled,interval_minutes:minutes},old[0]);});}finally{c.release();}}
 async function start(key,{actor=SYSTEM,trigger='scheduled',hours=24}={}){
  if(!SOURCES.includes(key))throw Object.assign(new Error('Unknown refresh source'),{status:400});
  const c=await pool.getConnection();const [[database]]=await c.query('SELECT DATABASE() AS name');const lock='ai-governance-refresh:'+crypto.createHash('sha256').update(database.name).digest('hex').slice(0,12)+':'+key;let held=false,lost=false,timer;
  const onLoss=()=>{lost=true;};c.on('error',onLoss);c.on('end',onLoss);
  async function assertLease(){if(lost)throw new Error('Refresh lock lost');const [[r]]=await c.query('SELECT IS_USED_LOCK(?)=CONNECTION_ID() AS held',[lock]);if(!r.held)throw new Error('Refresh lock lost');}
  const release=async()=>{if(timer)clearInterval(timer);if(held&&!lost)await c.query('SELECT RELEASE_LOCK(?)',[lock]).catch(()=>{lost=true;});c.removeListener('error',onLoss);c.removeListener('end',onLoss);if(lost)c.destroy();else c.release();};
  try{
   const [[l]]=await c.query('SELECT GET_LOCK(?,0) AS held',[lock]);if(!l.held){await release();return {skipped:true,reason:'running',job:await job(key)};}held=true;
   const id=crypto.randomUUID(),started=new Date(now());
   const claimed=await tx(c,async()=>{
    const [cfg]=await c.query('SELECT * FROM ai_governance_refresh_config WHERE source_key=? FOR UPDATE',[key]);if(!cfg.length)throw new Error('Refresh schedule is not initialized');
    if(trigger==='scheduled'&&(!cfg[0].enabled||(cfg[0].next_run_at&&new Date(cfg[0].next_run_at).getTime()>now())))return false;
    const [stale]=await c.query("SELECT id FROM ai_governance_refresh_run WHERE source_key=? AND status='running'",[key]);
    if(stale.length){await c.query("UPDATE ai_governance_refresh_run SET status='interrupted',phase='Previous evidence retained',completed_at=?,error='Worker stopped before completion; previous evidence retained' WHERE source_key=? AND status='running'",[started,key]);await audit(c,actor,'source_refresh_interrupted',{source:key,run_ids:stale.map(x=>x.id)});}
    await c.query("INSERT INTO ai_governance_refresh_run(id,source_key,trigger_kind,actor,status,phase,started_at) VALUES(?,?,?,?,'running','Reading source',?)",[id,key,trigger,actor,started]);
    await c.query("UPDATE ai_governance_refresh_config SET last_attempt_at=?,last_run_id=?,last_status='running',last_error=NULL,next_run_at=? WHERE source_key=?",[started,id,nextRunAt(cfg[0].interval_minutes,now()),key]);
    await audit(c,actor,'source_refresh_requested',{source:key,run_id:id,trigger,hours:key==='rapid7'?hours:null});return true;
   });
   if(!claimed){await release();return {skipped:true,reason:'not_due'};}
   timer=setInterval(()=>assertLease().catch(()=>{lost=true;}),15000);timer.unref();
   const j={id,source_key:key,status:'running',phase:'Reading source',started_at:started.toISOString(),hours};
   const completion=(async()=>{
    try{
     const [catalog]=await pool.query('SELECT id,app_name,aliases,domains FROM ai_catalog WHERE retired=0');const refs=require('./ai-governance-sources-routes').references;
     let d,access,observations=[];
     if(key==='zscaler'){
      d=require('./ai-governance-shadow-it').retain(await zscalerCollect(),await snapshot(key));const definitions=(d.sources||[]).find(x=>x.name==='AI application definitions');if(!definitions||definitions.status!==200)throw new Error('Zscaler definitions unavailable');
      // Partial catalog reads cannot erase earlier, positively matched labels.
      if(definitions.partial){const old=await snapshot(key),map=new Map((old?.candidates||[]).map(x=>[x.code,{...x,definition_checked_at:x.definition_checked_at||old.checked_at}]));for(const x of d.candidates)map.set(x.code,{...x,definition_checked_at:d.checked_at});d={...d,candidates:[...map.values()],note:d.note+' Prior definitions outside the partial read remain at their previous evidence time.',candidates_retained_from:old?.checked_at||null};}
      d.candidates=d.candidates.map(x=>({...x,definition_checked_at:x.definition_checked_at||d.checked_at}));
     }else if(key==='entra'){d=await entraCollect({catalog,refs});if(!d.sources?.some(x=>x.status===200)||d.sources.some(x=>x.partial))throw new Error('Entra collection incomplete');
      let attempt;try{attempt=await accessCollect({catalog,runId:id});}catch{attempt={schema_version:1,checked_at:new Date(now()).toISOString(),run_id:id,status:'partial',apps:[],users:[],checks:[],sources:[{name:'Directory access evidence',status:null,partial:true,note:'Access read unavailable; previous evidence retained.'}]};}
      access=A.retained(attempt,await snapshot('identity_access'));d.sources.push(...attempt.sources);d.access_evidence={checked_at:access.checked_at,run_id:access.run_id,status:access.status,retained:access.retained,last_attempt:access.last_attempt};
     }
     else{
      const z=await snapshot('zscaler');const result=await rapid7Collect({api:rapid7Client(),previous:await snapshot('rapid7'),catalog:[...catalog,...refs.map(r=>({id:null,app_name:r.name,aliases:r.aliases.join('\n'),domains:'',reference_only:true}))],definitions:z?.candidates||[],hours,runId:id,onProgress:phase=>{c.query("UPDATE ai_governance_refresh_run SET phase=? WHERE id=? AND status='running'",[phase,id]).catch(()=>{});}});d=result.snapshot;observations=result.observations;
      if(!d.sources?.some(x=>x.status===200))throw new Error('Rapid7 activity unavailable');
     }
     await assertLease();const completed=new Date(now()),partial=d.sources.some(x=>x.status!==200||x.partial),status=partial?'partial':'completed';
     await tx(c,async()=>{
      await assertLease();
      for(const row of observations){const {collector,...record}=row;record.run_id=id;record.occurred_at=new Date(record.occurred_at);await c.query('INSERT INTO ai_governance_rapid7_observation SET ? ON DUPLICATE KEY UPDATE run_id=VALUES(run_id),candidate_key=VALUES(candidate_key),app_name=VALUES(app_name),catalog_id=COALESCE(VALUES(catalog_id),catalog_id),match_basis=VALUES(match_basis),last_collected_at=CURRENT_TIMESTAMP',[record]);}
      await c.query('INSERT INTO ai_governance_source(source_key,payload,checked_by) VALUES(?,?,?) ON DUPLICATE KEY UPDATE payload=VALUES(payload),checked_by=VALUES(checked_by)',[key,JSON.stringify(d),actor]);
      if(access){await c.query('INSERT INTO ai_governance_source(source_key,payload,checked_by) VALUES(?,?,?) ON DUPLICATE KEY UPDATE payload=VALUES(payload),checked_by=VALUES(checked_by)',['identity_access',JSON.stringify(access),actor]);await audit(c,actor,'identity_access_snapshot_saved',{collection_run_id:id,run_id:access.run_id,checked_at:access.checked_at,status:access.status,retained:access.retained,app_provider_groups:access.apps.length,sources:access.sources});}
      await c.query("UPDATE ai_governance_refresh_run SET status=?,phase='Evidence saved',completed_at=?,candidate_count=?,observation_count=? WHERE id=?",[status,completed,d.candidates.length,key==='rapid7'?d.observation_count:null,id]);
      await c.query('UPDATE ai_governance_refresh_config SET last_success_at=?,last_status=?,last_error=NULL WHERE source_key=?',[completed,status,key]);
      await audit(c,actor,'source_refresh_saved',{source:key,run_id:id,trigger,status,checked_at:d.checked_at,candidate_count:d.candidates.length,observation_count:d.observation_count||null,sources:d.sources});
      await assertLease();
     });
     return {...j,status:'completed',coverage:status,phase:'Evidence saved',completed_at:completed.toISOString(),candidate_count:d.candidates.length,observation_count:d.observation_count};
    }catch(e){
     const error=(key==='entra'?'Microsoft Graph':key==='zscaler'?'Zscaler':'Rapid7')+' refresh failed'+(e.status?' (HTTP '+e.status+')':'')+'. Previous evidence retained.';
     // No upstream error bodies, tokens, account strings or URLs in run/audit data.
     if(!lost){const recordFailure=async()=>{await assertLease();await c.query("UPDATE ai_governance_refresh_run SET status='failed',phase='Previous evidence retained',completed_at=?,error=? WHERE id=?",[new Date(now()),error,id]);await c.query("UPDATE ai_governance_refresh_config SET last_status='failed',last_error=? WHERE source_key=?",[error,key]);};await tx(c,async()=>{await recordFailure();await audit(c,actor,'source_refresh_failed',{source:key,run_id:id,trigger,error});}).catch(async()=>{await recordFailure().catch(()=>{});});}
     console.error('[ai-governance-refresh]',key,e.code||e.status||e.name);
     return {...j,status:'failed',phase:'Previous evidence retained',error};
    }finally{await release();}
   })();
   return {job:j,completion};
  }catch(e){await release();throw e;}
 }
 // A new install has no schedule rows: seed the dev defaults once. INSERT IGNORE never overwrites an admin's change.
 let seeded=false;const SEED='system:ai-governance-schedule-seed';
 async function tick(){if(!seeded){await pool.query("INSERT IGNORE INTO ai_governance_refresh_config(source_key,enabled,interval_minutes,updated_by) VALUES('zscaler',1,60,?),('entra',1,60,?),('rapid7',1,60,?)",[SEED,SEED,SEED]);seeded=true;}await pool.query('INSERT INTO ai_governance_refresh_worker(id,last_seen_at) VALUES(1,UTC_TIMESTAMP(3)) ON DUPLICATE KEY UPDATE last_seen_at=VALUES(last_seen_at)');const results=await Promise.allSettled(SOURCES.map(async key=>{const r=await start(key);if(r.completion)await r.completion;}));results.forEach((r,i)=>{if(r.status==='rejected')console.error('[ai-governance-refresh]',SOURCES[i],r.reason.code||r.reason.name);});await pool.query('UPDATE ai_governance_refresh_worker SET last_seen_at=UTC_TIMESTAMP(3) WHERE id=1');}
 return {status,configure,start,tick,snapshot,job};
};
module.exports.SOURCES=SOURCES;

module.exports.nextRunAt=nextRunAt;
module.exports.nextMinuteDelay=nextMinuteDelay;
