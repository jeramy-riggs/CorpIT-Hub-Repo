'use strict';
const crypto=require('node:crypto');
const risk=require('./ai-risk-model');
const norm=v=>String(v||'').normalize('NFKC').toLowerCase().replace(/[^\p{L}\p{N}]/gu,'');
const empty=v=>v==null||String(v).trim()==='';
const known=v=>!empty(v)&&!['unknown','unsure','tbd','unclassified','not recorded','not assigned','n/a','not applicable'].includes(String(v).trim().toLowerCase());
function stamp(v){if(!v)return null;if(v instanceof Date)return Number.isFinite(+v)?v:null;let s=String(v);if(/^\d{4}-\d{2}-\d{2} \d{2}:/.test(s))s=s.replace(' ','T')+'Z';const d=new Date(s);return Number.isFinite(+d)?d:null;}
function day(v){return stamp(v)?.toISOString().slice(0,10)||null;}
function match(name,apps){const key=norm(name);if(!key)return [];return apps.filter(a=>[a.app_name,...String(a.aliases||'').split('\n')].some(n=>norm(n)===key));}
function intake(row,origin){
  if(!row||row.type!=='aia'||!/^AIA-\d{4}-\d{5}$/.test(row.id||''))return null;
  const d=row.details||{},sub=row.submitter||{},issues=[];
  const text=(v,max,label)=>{if(v==null)return '';if(typeof v!=='string'||v.trim().length>max){issues.push(label+' needs manual review');return '';}return v.trim();};
  const data={id:row.id,status:String(row.status||''),archived:!!row.archived_at,updated_at:row.updated_at||null,
    app_name:text(d.tool_name,190,'Application name'),business_purpose:text(d.use_case,6000,'Business purpose'),vendor:text(d.tool_vendor,190,'Vendor'),
    requester:text(sub.name,190,'Requester'),department:text(sub.dept,190,'Department'),
    agentic_use_case:d.access_agent===true,source_url:origin+'/approver.html?open='+encodeURIComponent(row.id),issues};
  return {...data,eligible:data.status==='approved'&&!data.archived,source_hash:crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex')};
}
function proposals(rows,apps,origin){
  const records=[];for(const row of rows){const r=intake(row,origin);if(!r||!r.eligible)continue;const matches=match(r.app_name,apps),a=matches.length===1?matches[0]:null,fill={},conflicts=[];
    if(a){for(const key of ['business_purpose','vendor'])if(r[key]){if(empty(a[key]))fill[key]=r[key];else if(String(a[key]).trim()!==r[key])conflicts.push(key);}
      if(empty(a.evidence_url))fill.evidence_url=r.source_url;
    }
    records.push({...r,catalog_id:a?.id||null,governance_version:Number(a?.version)||0,match_status:matches.length===1?'matched':matches.length>1?'ambiguous':'unmatched',fill,conflicts,
      note:'Approved use-case evidence only; does not approve the application. Requester is not assumed to be the business owner.'});
  }return records;
}

// Read-only Portal register. Explicit allowlist excludes signatures, audit bodies and arbitrary payloads.
function intakeRequests(rows,apps,origin){
 const labels={manager:'Dept. Manager',security:'InfoSec',legal:'Legal'};
 const text=(v,max=6000)=>typeof v==='string'&&v.trim().length<=max?v.trim():'';
 const answer=v=>v===true||['yes','true'].includes(String(v).toLowerCase())?'Yes':v===false||['no','false'].includes(String(v).toLowerCase())?'No':'Not recorded';
 const date=v=>stamp(v)?.toISOString()||null;
 const list=(d,keys)=>keys.filter(([key])=>answer(d[key])==='Yes').map(([,label])=>label);
 return rows.flatMap(row=>{
  const basic=intake(row,origin);if(!basic)return [];
  const d=row.details&&typeof row.details==='object'?row.details:{},sub=row.submitter&&typeof row.submitter==='object'?row.submitter:{};
  const history=(Array.isArray(row.audit)?row.audit:[]).filter(a=>typeof a.event==='string'&&/^(Request Submitted|Request Fully Approved|Approved by |Rejected by |Returned by |Reopened to |request\.(archived|unarchived))/.test(a.event)).slice(-200).map(a=>({event:text(a.event,190),actor:text(a.actor,190),role:text(a.role,100),created_at:date(a.created_at)}));
  const workflow=Array.isArray(row.workflow)?row.workflow.slice(0,20):[],sourceApprovals=Array.isArray(row.approvals)?row.approvals.slice(0,20):[];
  const orders=[...new Set([...workflow.map((_,i)=>i),...sourceApprovals.filter(a=>Number.isSafeInteger(a.step)&&a.step>=0&&a.step<20).map(a=>a.step)])].sort((a,b)=>a-b);
  const approvals=orders.map(step=>{const a=sourceApprovals.find(a=>a.step===step)||{},key=text(a.step_key,100)||text(workflow[step],100);return {step,label:text(a.step_label,190)||labels[key]||key||'Workflow step '+(step+1),status:text(a.status,50)||'not_recorded',reviewer:text(a.approver_name,190),comments:text(a.comments),decided_at:date(a.decided_at)};});
  const matches=match(basic.app_name,apps),a=matches.length===1?matches[0]:null;
  const current=Number.isSafeInteger(row.current_step)?row.current_step:null,at=approvals.find(a=>a.step===current);
  return [{id:basic.id,status:basic.status,archived:basic.archived,created_at:date(row.created_at),updated_at:date(row.updated_at),archived_at:date(row.archived_at),priority:text(row.priority,50),
   app_name:basic.app_name,business_purpose:basic.business_purpose,vendor:basic.vendor,requester:basic.requester,department:basic.department,source_url:basic.source_url,
   requester_email:text(sub.email,254),requester_title:text(sub.title,190),manager:text(sub.manager_name,190),identity_source:text(row.identity_source||d.identity_source||sub.identity_source,100),
   history,history_limit:200,current_step:current,current_step_label:basic.status==='pending'?(at?.label||'Not recorded'):null,approvals,
   catalog_id:a?.id||null,match_status:matches.length===1?'matched':matches.length>1?'ambiguous':'unmatched',issues:basic.issues,
   details:{connected_systems:[text(d.adc_systems),text(d.client_systems)].filter(Boolean),internal_integration:answer(d.adc_integration),client_integration:answer(d.client_integration),
    review_process:text(d.review_process),notes:text(d.notes),third_party:answer(d.is_thirdparty),agentic:answer(d.access_agent)==='Yes'?'Yes':'Not selected / not recorded',
    data_types:list(d,[['data_public','Publicly available information'],['data_thirdparty','Third-party / licensed data'],['data_other_chk','Other data type'],['data_customer_pii','Customer personal information'],['data_employee','Employee information'],['data_confidential','Company confidential / proprietary'],['data_client_sensitive','Client sensitive data']]),
    audience:list(d,[['aud_individual','Individual'],['aud_internal','Internal staff'],['aud_customers','Customers / consumers'],['aud_clients','Clients']]),
    requested_access:list(d,[['access_view','View'],['access_individual','Individual'],['access_team','Team'],['access_enterprise','Enterprise'],['access_sysint','System integration'],['access_agent','Agent'],['access_other_chk','Other access']]),
    intended_use:list(d,[['cat_productivity','Productivity'],['cat_automation','Automation'],['cat_other','Other purpose']]),other_purpose:text(d.cat_other_desc),other_data:text(d.data_other_desc),other_access:text(d.access_other_desc),contract_in_place:answer(d.has_contract),procurement_contacted:answer(d.procurement_contacted),policy_document:text(d.ai_policy_file,190),policy_version:Number.isSafeInteger(d.ai_policy_version)&&d.ai_policy_version>0?d.ai_policy_version:null,policy_acknowledged:answer(d.policy_ack),policy_reviewed:answer(d.policy_reviewed),existing_tool:answer(d.tool_existing),tool_website:text(d.tool_website,2048)}
  }];
 });
}

function intakeSummary(rows,origin,{now=new Date()}={}){
  const at=new Date(now),start=new Date(at);start.setUTCHours(0,0,0,0);start.setUTCDate(start.getUTCDate()-29);
  const createdDays=new Map();let unknownCreated=0;
  const result={visible_ai_requests:0,active_ai_requests:0,archived_ai_requests:0,open_ai_requests:0,unknown_status_records:0,invalid_records:0,status_counts:{pending:0,returned:0,approved:0,rejected:0},open_records:[]};
  for(const row of rows){if(row?.type!=='aia')continue;result.visible_ai_requests++;const r=intake(row,origin);if(!r){result.invalid_records++;unknownCreated++;continue;}const created=stamp(row.created_at);if(!created||+created>+at)unknownCreated++;else if(+created>=+start){const day=created.toISOString().slice(0,10);createdDays.set(day,(createdDays.get(day)||0)+1);}if(r.archived){result.archived_ai_requests++;continue;}result.active_ai_requests++;
    if(Object.hasOwn(result.status_counts,r.status))result.status_counts[r.status]++;else result.unknown_status_records++;
    if(r.status==='pending')result.open_records.push({id:r.id,app_name:r.app_name,status:r.status,updated_at:r.updated_at,source_url:r.source_url});
  }
  result.open_ai_requests=result.open_records.length;result.creation_trend={start:start.toISOString(),end:at.toISOString(),timezone:'UTC',known_total:[...createdDays.values()].reduce((a,b)=>a+b,0),unknown_dates:unknownCreated,days:[...createdDays].sort((a,b)=>a[0].localeCompare(b[0])).map(([day,count])=>({day,count}))};return result;
}
function health(apps,sources,{now=new Date(),project_read=false}={}){
  const nowDate=stamp(now),today=nowDate.toISOString().slice(0,10),recent=+nowDate-30*86400000,stale=+nowDate-90*86400000;
  const rows=apps.map(a=>{const r=risk.assessment(a,nowDate),due=day(a.review_due)||(/^\d{4}-\d{2}-\d{2}$/.test(r.next_review)?r.next_review:null);
    const scheduled=!!due||r.next_review==='On material change';
    const account=risk.parsed(a.corporate_account),recordedAccess=Number(a.manual_access_count)>0||known(account.account_type)||project_read&&Number(a.project_access_count)>0;
    const fields=[['owner','Business owner',known(a.owner)],['purpose','Business purpose',known(a.business_purpose)],['approval','Final governance decision',['approved','restricted','rejected'].includes(a.approval_status)],['evidence','Evidence link',known(a.evidence_url)],['review','Review schedule',scheduled],['access','Recorded access/account information',!!recordedAccess]];
    const complete=fields.filter(f=>f[2]).length,updated=stamp(a.updated_at),first=stamp(a.first_seen);
    return {id:a.id,app_name:a.app_name,owner:a.owner||null,business_purpose_known:known(a.business_purpose),approval_status:a.approval_status||'unreviewed',category:a.category||null,ai_type:a.ai_type||'unclassified',
      score:Math.round(complete/fields.length*100),complete,total:fields.length,gaps:fields.filter(f=>!f[2]).map(([key,label])=>({key,label})),review_due:due||r.next_review||null,overdue:!!due&&due<today,
      updated_at:updated?.toISOString()||null,stale_metadata:!!updated&&+updated<stale,never_recorded:!updated,newly_cataloged:!!first&&+first>=recent&&+first<=+nowDate,
      first_seen:first?.toISOString()||null,access_recorded:!!recordedAccess,project_access_scope:project_read?'included':'not available in this view'};
  });
  const count=f=>rows.filter(f).length;
  return {generated_at:nowDate.toISOString(),rows,total:rows.length,average_score:rows.length?Math.round(rows.reduce((n,a)=>n+a.complete,0)/(rows.length*6)*100):null,
    counts:{approved:count(a=>a.approval_status==='approved'),unreviewed:count(a=>a.approval_status==='unreviewed'),other_decisions:count(a=>!['approved','unreviewed'].includes(a.approval_status)),known_purpose:count(a=>a.business_purpose_known),unknown_purpose:count(a=>!a.business_purpose_known),owner_known:count(a=>known(a.owner)),
      dedicated:count(a=>a.category==='Dedicated AI Platform'),embedded:count(a=>a.category==='Application with Embedded AI Features'||['embedded','both'].includes(a.ai_type)),unclassified:count(a=>!known(a.category)),overdue:count(a=>a.overdue),no_review_schedule:count(a=>!a.review_due),stale_metadata:count(a=>a.stale_metadata),never_recorded:count(a=>a.never_recorded),newly_cataloged:count(a=>a.newly_cataloged)},
    dimensions:['owner','purpose','approval','evidence','review','access'].map(key=>({key,label:rows.length?rows[0].gaps.find(g=>g.key===key)?.label||({owner:'Business owner',purpose:'Business purpose',approval:'Final governance decision',evidence:'Evidence link',review:'Review schedule',access:'Recorded access/account information'})[key]:key,missing:count(a=>a.gaps.some(g=>g.key===key))})),
    sources:sources.map(s=>{const last=stamp(s.last_success_at),threshold=Math.max(60,Number(s.interval_minutes)||60)*2*60000;return {source:s.source_key,enabled:!!s.enabled,interval_minutes:s.interval_minutes,last_success_at:last?.toISOString()||null,last_status:s.last_status,
      state:!s.enabled?'Paused':!last?'No successful collection':s.last_status==='failed'?'Last run failed':+nowDate-+last>threshold?'Stale':s.last_status==='partial'?'Partial coverage':'Current'};}),
    limits:['Quality measures completion of six recorded metadata dimensions, not security risk or control effectiveness.','An approved use case does not approve an application or grant access.','Dedicated and embedded measures can overlap when classification records both capabilities.','Newly cataloged means first seen in this catalog within 30 days; it is not a verified AI feature release date.','Stale metadata means no governance metadata update for 90 days; activity collection never resets that clock.',project_read?'Recorded project grants are included; live directory membership and vendor entitlements are not checked.':'Project-grant information is outside this view; access-information gaps may need verification.']};
}
module.exports={norm,empty,known,stamp,match,intake,proposals,intakeRequests,intakeSummary,health};
