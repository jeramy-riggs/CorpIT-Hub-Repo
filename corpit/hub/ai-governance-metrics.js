'use strict';
// Aggregate governance history only. Browser GETs never create snapshots.
const crypto=require('node:crypto'),M=require('./ai-governance-maintenance');
const KEY='governance_quality_history',SCOPE='core-records-v1';
const catalogSQL="SELECT c.id,c.app_name,c.first_seen,g.owner,g.business_purpose,g.approval_status,g.evidence_url,g.review_due,g.updated_at,r.profile AS risk_profile,a.profile AS corporate_account,(SELECT COUNT(*) FROM ai_governance_access x WHERE x.catalog_id=c.id AND x.status='recorded') AS manual_access_count FROM ai_catalog c LEFT JOIN ai_governance_app g ON g.catalog_id=c.id LEFT JOIN ai_governance_risk r ON r.catalog_id=c.id LEFT JOIN ai_governance_account a ON a.catalog_id=c.id WHERE c.retired=0";
const count=v=>(typeof v==='number'||typeof v==='string'&&/^\d+$/.test(v))&&Number.isSafeInteger(Number(v))&&Number(v)>=0?Number(v):null;
function window30(now=new Date()){const end=new Date(now),start=new Date(end);start.setUTCHours(0,0,0,0);start.setUTCDate(start.getUTCDate()-29);return {start,end};}
function history(raw){const d=typeof raw==='string'?JSON.parse(raw):raw;if(raw===undefined)return {version:1,scope:SCOPE,points:[]};if(!d||d.version!==1||d.scope!==SCOPE||!Array.isArray(d.points)||d.points.length>90)throw new Error('Invalid quality history');let last='';for(const p of d.points){if(!/^\d{4}-\d{2}-\d{2}$/.test(p.day||'')||M.stamp(p.day)?.toISOString().slice(0,10)!==p.day||p.day<=last||!M.stamp(p.recorded_at)||M.stamp(p.recorded_at)?.toISOString().slice(0,10)!==p.day||count(p.total)==null||count(p.complete)==null||p.complete>p.total*6||count(p.overdue)==null||p.overdue>p.total||!(p.score===null&&p.total===0||Number.isInteger(p.score)&&p.score>=0&&p.score<=100))throw new Error('Invalid quality point');if(p.total>0&&p.score!==Math.round(p.complete/(p.total*6)*100))throw new Error('Invalid quality score');last=p.day;}return d;}
async function read(pool,{now=new Date()}={}){const {start,end}=window30(now);const [approvals,quality]=await Promise.allSettled([
 pool.query("SELECT DATE_FORMAT(created_at,'%Y-%m-%d') AS day,COUNT(*) AS approvals FROM ai_governance_audit WHERE created_at>=? AND created_at<=? AND catalog_id IS NOT NULL AND action IN ('application_created','application_reviewed','site_approval_reviewed') AND JSON_UNQUOTE(JSON_EXTRACT(after_json,'$.approval_status'))='approved' AND COALESCE(JSON_UNQUOTE(JSON_EXTRACT(before_json,'$.approval_status')),'')<>'approved' GROUP BY DATE_FORMAT(created_at,'%Y-%m-%d') ORDER BY day",[start,end]),
 pool.query('SELECT payload FROM ai_governance_source WHERE source_key=?',[KEY])]);
 let approvalData={available:false,total:null,days:[]},qualityData={available:false,scope:SCOPE,points:[]};
 if(approvals.status==='fulfilled'){const rows=approvals.value[0];if(Array.isArray(rows)&&rows.every(r=>/^\d{4}-\d{2}-\d{2}$/.test(r.day||'')&&count(r.approvals)!=null))approvalData={available:true,total:rows.reduce((sum,r)=>sum+Number(r.approvals),0),days:rows.map(r=>({day:r.day,count:Number(r.approvals)}))};}
 if(quality.status==='fulfilled')try{const d=history(quality.value[0][0]?.payload);qualityData={available:true,scope:SCOPE,points:d.points.filter(p=>p.day>=start.toISOString().slice(0,10)&&p.day<=end.toISOString().slice(0,10))};}catch{}
 return {start:start.toISOString(),end:end.toISOString(),timezone:'UTC',approvals:approvalData,quality:qualityData};
}
async function captureDaily(pool,{now=new Date()}={}){const at=new Date(now),day=at.toISOString().slice(0,10),c=await pool.getConnection();let held=false,begun=false;const lock='ai-governance-quality:';let key;
 try{const [[db]]=await c.query('SELECT DATABASE() AS name');key=lock+crypto.createHash('sha256').update(db.name).digest('hex').slice(0,16);const [[lease]]=await c.query('SELECT GET_LOCK(?,0) AS held',[key]);if(!lease.held)return {skipped:true,reason:'running'};held=true;
  await c.beginTransaction();begun=true;const [rows]=await c.query('SELECT payload FROM ai_governance_source WHERE source_key=? FOR UPDATE',[KEY]);const old=history(rows[0]?.payload),last=old.points.at(-1);
  if(last?.day>=day){await c.commit();begun=false;return {skipped:true,reason:'already sampled'};}
  const [apps]=await c.query(catalogSQL),h=M.health(apps,[],{now:at,project_read:false}),point={day,recorded_at:at.toISOString(),total:h.total,complete:h.rows.reduce((sum,r)=>sum+r.complete,0),score:h.average_score,overdue:h.counts.overdue};
  const payload={version:1,scope:SCOPE,points:[...old.points,point].slice(-90)};
  await c.query('INSERT INTO ai_governance_source(source_key,payload,checked_by) VALUES(?,?,?) ON DUPLICATE KEY UPDATE payload=VALUES(payload),checked_by=VALUES(checked_by)',[KEY,JSON.stringify(payload),'system:ai-governance-quality']);
  await c.query('INSERT INTO ai_governance_audit(actor,action,after_json) VALUES(?,?,?)',['system:ai-governance-quality','metadata_quality_sampled',JSON.stringify({scope:SCOPE,...point})]);await c.commit();begun=false;return {captured:true,point};
 }catch(e){if(begun)await c.rollback();throw e;}finally{if(held)await c.query('SELECT RELEASE_LOCK(?)',[key]).catch(()=>{});c.release();}
}
module.exports={KEY,SCOPE,catalogSQL,window30,history,read,captureDaily};
