(function(root,factory){const api=factory();if(typeof module==='object'&&module.exports)module.exports=api;else root.AIGovernanceOverviewModel=api;})(typeof window==='object'?window:this,function(){'use strict';
 // Keep the production queue destination explicit across DEV asset host rewriting.
 const portalQueueUrl='https://'+['accessportal','nrpi','local'].join('.')+'/approver.html';
 const labels={owner:'Missing owner',purpose:'Missing business purpose',evidence:'Missing evidence',access:'Access/account information needs verification',classification:'Missing classification',decision:'Governance decision pending',overdue:'Review overdue',schedule:'Review schedule missing',assessment:'Assessment incomplete',controls:'Control follow-up',high_review:'High-risk indicator awaiting assessment',intake_available:'Approved intake evidence available',intake_conflict:'Intake values need reconciliation',intake_source:'Intake source needs review',intake_mapping:'Approved intake needs application mapping',intake_open:'Open intake request',new:'Newly cataloged application',changed:'Decision evidence changed',elevated:'Elevated-risk review required',risk_npi:'NPI exposure',risk_pii:'PII exposure',risk_client:'Client data exposure',risk_consumer:'Consumer data exposure',risk_external:'External output',risk_automated:'Fully automated decisions'};
 const known=v=>v!=null&&!/^(?:\s*|unknown|unsure|tbd|unclassified|n\/a|not applicable|not (?:recorded|assigned|classified))$/i.test(String(v).trim());
 const integer=v=>Number.isSafeInteger(v)&&v>=0;
 const appId=v=>Number.isSafeInteger(Number(v))&&Number(v)>0?Number(v):null;
 const day=v=>typeof v==='string'&&/^\d{4}-\d{2}-\d{2}/.test(v)&&Number.isFinite(Date.parse(v))?v.slice(0,10):null;
 const link=(id,view='inventory')=>'/ai-governance.html?'+(view==='risk'?'riskApp':view==='site-review'?'reviewApp':'app')+'='+id+'#'+view;
 const recentlyCataloged=(a,now=Date.now())=>{const t=Date.parse(a.first_seen||'');return Number.isFinite(t)&&t<=now&&t>=now-30*86400000;};
 const attentionLink=filter=>'/ai-governance.html'+(filter?'?attention='+encodeURIComponent(filter):'')+'#attention';
 function portalLink(record){try{const u=new URL(record.source_url);if(u.protocol==='https:'&&!u.username&&!u.password&&['dev-accessportal.nrpi.local','accessportal.nrpi.local'].includes(u.hostname))return u.href;}catch{}return '/ai-governance.html#intake-enrichment';}
 const classificationDefinitions=[['dedicated','Dedicated AI Platforms','Dedicated AI Platform'],['embedded','Applications with Embedded AI','Application with Embedded AI Features'],['development','AI Development Platforms','AI Development Platform'],['security','AI Security Platforms','AI Security / Operations Tool'],['agents','AI Agents / Automation','AI Agent / Automation Platform']];
 const exposureDefinitions=[['risk_npi','npi','Yes'],['risk_pii','pii','Yes'],['risk_client','client','Yes'],['risk_consumer','consumer','Yes'],['risk_external','ext','Yes'],['risk_automated','oversight','Fully automated']];
 function inClassification(a,key){const d=classificationDefinitions.find(x=>x[0]===key);return !!d&&(a.category===d[2]||key==='embedded'&&['embedded','both'].includes(a.ai_type));}
 function executiveSummaries(apps,riskMap,riskOK,health,intake,intakeOK,now){
  const rows=apps.map(a=>{const r=riskMap.get(Number(a.id))?.assessment,coverage=riskOK&&Array.isArray(r?.coverage)?r.coverage:null,dept=coverage?.find(c=>c.key==='dept');return {id:Number(a.id),name:a.app_name||'Unnamed application',category:a.category,ai_type:a.ai_type,status:a.approval_status||'unreviewed',department:coverage?dept?.state==='available'&&known(dept.value)?dept.value.trim():'Unknown department':'Department source unavailable'};});
  const classifications=classificationDefinitions.map(([key,label])=>({key,label,count:rows.filter(a=>inClassification(a,key)).length}));
  classifications.push({key:'other',label:'Other recorded category',count:rows.filter(a=>known(a.category)&&!classificationDefinitions.some(d=>a.category===d[2])).length},{key:'unknown',label:'Category not recorded',count:rows.filter(a=>!known(a.category)).length});
  const departments=new Map(['Engineering','Legal','Operations','Product','Marketing','HR','Security'].map(label=>[label.toLowerCase(),{key:label,label,count:0}]));
  for(const a of rows){const key=a.department.toLowerCase();if(!departments.has(key))departments.set(key,{key:a.department,label:a.department,count:0});departments.get(key).count++;}
  const start=new Date(now);start.setUTCHours(0,0,0,0);start.setUTCDate(start.getUTCDate()-29);const from=start.toISOString().slice(0,10),to=new Date(now).toISOString().slice(0,10),days=[];for(let i=0;i<30;i++){const d=new Date(start);d.setUTCDate(d.getUTCDate()+i);days.push(d.toISOString().slice(0,10));}
  const newDays=new Map();for(const a of apps){const t=Date.parse(a.first_seen||'');if(Number.isFinite(t)&&t>=+start&&t<=+now){const day=new Date(t).toISOString().slice(0,10);newDays.set(day,(newDays.get(day)||0)+1);}}
  const source=health?.ok?health.data?.trends:null,approvals=source?.approvals,creation=intakeOK?intake.data.intake_summary.creation_trend:null,quality=source?.quality;
  const validDays=arr=>Array.isArray(arr)&&arr.every(p=>days.includes(p.day)&&integer(p.count));
  const approvalOK=!!(approvals?.available&&integer(approvals.total)&&validDays(approvals.days)&&approvals.days.reduce((sum,p)=>sum+p.count,0)===approvals.total);
  const intakeTrendOK=!!(creation&&integer(creation.known_total)&&integer(creation.unknown_dates)&&validDays(creation.days)&&creation.days.reduce((sum,p)=>sum+p.count,0)===creation.known_total);
  const qualityOK=!!(quality?.available&&quality.scope==='core-records-v1'&&Array.isArray(quality.points)&&quality.points.every(p=>days.includes(p.day)&&(p.score===null||integer(p.score)&&p.score<=100)&&integer(p.total)&&integer(p.overdue)));
  const qualityPoints=qualityOK?quality.points:[],qualityFirst=qualityPoints[0],qualityLast=qualityPoints.at(-1),delta=qualityPoints.length>1&&qualityFirst.score!=null&&qualityLast.score!=null?qualityLast.score-qualityFirst.score:null;
  return {summary_apps:rows,classifications,departments:[...departments.values()].sort((a,b)=>b.count-a.count||a.label.localeCompare(b.label)),decision_summary:[['approved','Approved'],['under_review','Under Review'],['restricted','Restricted'],['rejected','Rejected'],['unreviewed','Unreviewed']].map(([key,label])=>({key,label,count:rows.filter(a=>a.status===key).length})),trends:{from,to,timezone:'UTC',days,new_applications:{available:!!health?.ok,total:health?.ok?[...newDays.values()].reduce((a,b)=>a+b,0):null,days:[...newDays].map(([day,count])=>({day,count}))},approvals:approvalOK?approvals:{available:false,total:null,days:[]},intake:{available:intakeTrendOK,total:intakeTrendOK&&creation.unknown_dates===0?creation.known_total:null,known_total:intakeTrendOK?creation.known_total:null,unknown_dates:intakeTrendOK?creation.unknown_dates:null,days:intakeTrendOK?creation.days:[]},quality:{available:qualityOK,points:qualityPoints,delta,stale:!!qualityLast&&Date.parse(to)-Date.parse(qualityLast.day)>2*86400000},overdue_history:qualityPoints.map(p=>({day:p.day,count:p.overdue})),quality_scope:'Core records only: owner, purpose, decision, evidence, review schedule and account/manual access. Project grants excluded for a consistent daily scope.'}};
 }
 function build({inventory=[],health,risk,intake,now=new Date()}){
  const today=new Date(now).toISOString().slice(0,10),warnings=[],intakeExternal=intake?.external===true;
  const healthOK=!!(health?.ok&&Array.isArray(health.data?.rows)&&health.data.total===health.data.rows.length&&health.data.rows.every(r=>appId(r.id)&&Array.isArray(r.gaps)));
  const riskOK=!!(risk?.ok&&Array.isArray(risk.data?.apps));
  const summary=intake?.data?.intake_summary;
  const intakeOK=!!(intake?.ok&&summary&&integer(summary.open_ai_requests)&&Array.isArray(summary.open_records)&&summary.open_records.length===summary.open_ai_requests&&summary.open_records.every(r=>/^AIA-\d{4}-\d{5}$/.test(r.id||'')&&r.status==='pending')&&Array.isArray(intake.data.records));
  if(!healthOK)warnings.push('Inventory health: '+(health?.error||'Health summary unavailable. Completeness and newly cataloged counts are unknown.'));
  if(!riskOK)warnings.push('Risk assessments: '+(risk?.error||'Assessment source unavailable. Assessment coverage is incomplete.'));
  if(!intakeOK&&!intakeExternal)warnings.push('Intake: '+(intake?.error||'Portal summary unavailable. Open intake and source evidence counts are unknown.'));
  if(intakeOK&&summary.unknown_status_records)warnings.push(summary.unknown_status_records+' active intake records have an unrecognized status and are not counted as open.');
  if(intakeOK&&summary.invalid_records)warnings.push(summary.invalid_records+' intake records have invalid source identifiers and need source review.');
  const inventoryMap=new Map(inventory.filter(a=>appId(a.id)).map(a=>[Number(a.id),a]));
  const canonical=healthOK?health.data.rows.map(h=>({...inventoryMap.get(Number(h.id)),...h})):inventory.filter(a=>appId(a.id));
  const riskMap=new Map((riskOK?risk.data.apps:[]).map(a=>[Number(a.id),a]));
  const tasks=new Map(),counts={total:canonical.length,approved:0,under_review:0,unreviewed:0,classification:0,unknown_owner:0,unknown_purpose:0,overdue:0,newly_discovered:healthOK?0:null,quality:healthOK&&Number.isFinite(health.data.average_score)&&health.data.average_score>=0&&health.data.average_score<=100?health.data.average_score:null,open_intake:intakeOK?summary.open_ai_requests:null,enrichment_available:intakeOK?0:null,immediate:0,attention_apps:0,assessment_incomplete:0,assessment_unavailable:0,high_risk_review:0};
  const add=(item,key)=>{if(!item.reasons.some(r=>r.key===key))item.reasons.push({key,label:labels[key]});};
  for(const a of canonical){
   const id=Number(a.id),rr=riskMap.get(id),r=rr?.assessment,riskKnown=!!(riskOK&&r&&Array.isArray(r.coverage)&&integer(r.required_gaps)&&Array.isArray(r.control_gaps));
   const pending=!['approved','restricted','rejected'].includes(a.approval_status),due=day(a.review_due)||day(r?.next_review),overdue=!!due&&due<today;
   const purposeKnown=healthOK?a.business_purpose_known===true:known(a.business_purpose),classificationKnown=known(a.category)&&['standalone','embedded','both'].includes(a.ai_type);
   if(a.approval_status==='approved')counts.approved++;if(a.approval_status==='under_review')counts.under_review++;if(!a.approval_status||a.approval_status==='unreviewed')counts.unreviewed++;
   if(!known(a.owner))counts.unknown_owner++;if(!purposeKnown)counts.unknown_purpose++;if(!classificationKnown)counts.classification++;if(overdue)counts.overdue++;if(healthOK&&a.newly_cataloged)counts.newly_discovered++;
   const item={id:'app:'+id,catalog_id:id,kind:'Application',status:a.approval_status||'unreviewed',name:a.app_name||'Unnamed application',owner:known(a.owner)?a.owner:'Not assigned',priority:'Review',reasons:[],newly_cataloged:!!a.newly_cataloged,actions:[{label:'Open application',url:link(id)},{label:'Assess risk',url:link(id,'risk')},{label:'Review decision',url:link(id,'site-review')}]};
   if(!known(a.owner))add(item,'owner');if(!purposeKnown)add(item,'purpose');if(!classificationKnown)add(item,'classification');
   const evidenceKnown=healthOK?!a.gaps.some(g=>g.key==='evidence'):known(a.evidence_url);if(!evidenceKnown)add(item,'evidence');if(healthOK&&a.gaps.some(g=>g.key==='access')){add(item,'access');item.actions.push({label:'Review account / SSO',url:'/ai-governance.html?accountApp='+id+'#access'});}if(pending)add(item,'decision');if(overdue)add(item,'overdue');
   if(healthOK&&a.gaps.some(g=>g.key==='review'))add(item,'schedule');
   if(riskKnown){if(r.review_status!=='Recorded'||r.required_gaps>0){add(item,'assessment');counts.assessment_incomplete++;}if(r.control_gaps.length)add(item,'controls');}else{counts.assessment_unavailable++;}
   if(rr?.approval_decision?.current===false)add(item,'changed');
   const exposures=riskKnown?exposureDefinitions.filter(([,key,value])=>r.coverage.some(c=>c.key===key&&c.state==='available'&&c.value===value)):[];const elevated=exposures.length&&(r.review_status!=='Recorded'||r.required_gaps>0||r.control_gaps.length>0||overdue);if(elevated){counts.high_risk_review++;add(item,'elevated');for(const [key] of exposures)add(item,key);}
   const highIndicators=riskKnown&&r.coverage.some(c=>[['npi','Yes'],['client','Yes'],['consumer','Yes'],['ext','Yes'],['oversight','Fully automated']].some(([key,value])=>c.key===key&&c.state==='available'&&c.value===value));
   if(highIndicators&&r.review_status!=='Recorded')add(item,'high_review');
   if(overdue||highIndicators&&r.review_status!=='Recorded'){item.priority='Immediate';counts.immediate++;}
   if(item.reasons.length&&a.newly_cataloged)add(item,'new');
   tasks.set(item.id,item);
  }
  if(intakeOK){
   for(const r of intake.data.records){if(!/^AIA-\d{4}-\d{5}$/.test(r.id||''))continue;const item=tasks.get('app:'+Number(r.catalog_id)),hasFill=r.match_status==='matched'&&r.fill&&Object.keys(r.fill).length>0;
    if(hasFill)counts.enrichment_available++;
    if(item){if(hasFill){add(item,'intake_available');item.actions.push({label:'View approved intake evidence',url:'/ai-governance.html#intake-enrichment'});}if(Array.isArray(r.conflicts)&&r.conflicts.length)add(item,'intake_conflict');if(Array.isArray(r.issues)&&r.issues.length)add(item,'intake_source');if(item.reasons.some(x=>x.key.startsWith('intake_'))&&!item.actions.some(x=>x.url.endsWith('#intake-enrichment')))item.actions.push({label:'Review intake evidence',url:'/ai-governance.html#intake-enrichment'});}
    else if(r.match_status==='matched'&&(hasFill||r.conflicts?.length||r.issues?.length)){tasks.set('intake-fill:'+r.id,{id:'intake-fill:'+r.id,kind:'Intake evidence',name:r.id+' · '+(r.app_name||'Name needs review'),owner:'Inventory snapshot changed',priority:'Review',reasons:[{key:hasFill?'intake_available':'intake_source',label:hasFill?labels.intake_available:labels.intake_source}],actions:[{label:'Review intake evidence',url:'/ai-governance.html#intake-enrichment'}]});warnings.push('An intake match is outside this inventory snapshot. Refresh before reviewing the source evidence.');}
    else if(r.match_status!=='matched')tasks.set('intake-map:'+r.id,{id:'intake-map:'+r.id,kind:'Intake mapping',name:r.id+' · '+(r.app_name||'Name needs review'),owner:'Not assigned',priority:'Review',reasons:[{key:'intake_mapping',label:labels.intake_mapping}],actions:[{label:'Review intake mapping',url:'/ai-governance.html#intake-enrichment'},{label:'Open source request',url:portalLink(r)}]});
   }
   for(const r of summary.open_records){if(!/^AIA-\d{4}-\d{5}$/.test(r.id||''))continue;tasks.set('intake:'+r.id,{id:'intake:'+r.id,kind:'Intake request',name:r.id+' · '+(r.app_name||'Name not supplied'),owner:'Portal workflow',priority:'Review',status:r.status,reasons:[{key:'intake_open',label:labels.intake_open+' · '+r.status}],actions:[{label:'Open intake request',url:portalLink(r)}]});}
  }
  const rank={Immediate:0,Review:1,Routine:2},items=[...tasks.values()].filter(t=>t.reasons.length).sort((a,b)=>rank[a.priority]-rank[b.priority]||a.name.localeCompare(b.name));
  counts.immediate_known=counts.immediate;if(!riskOK||counts.assessment_unavailable){counts.immediate=null;counts.high_risk_review=null;}counts.overdue_known=counts.overdue;if(!healthOK&&(!riskOK||counts.assessment_unavailable))counts.overdue=null;
  counts.attention_apps=items.filter(t=>t.kind==='Application').length;counts.intake_tasks=items.filter(t=>t.kind!=='Application').length;
  if(counts.assessment_unavailable&&riskOK)warnings.push(counts.assessment_unavailable+' applications have no complete assessment response in this read.');
  return {...executiveSummaries(canonical,riskMap,riskOK,health,intake,intakeOK,new Date(now)),counts,items,warnings,health_available:healthOK,risk_available:riskOK,intake_available:intakeOK,intake_external:intakeExternal,quality_dimensions:6,sources:healthOK&&Array.isArray(health.data.sources)?health.data.sources:[],generated_at:new Date(now).toISOString(),complete_sources:healthOK&&riskOK&&(intakeOK||intakeExternal)&&counts.assessment_unavailable===0&&warnings.length===0};
 }
 return {build,portalQueueUrl,labels,known,recentlyCataloged,attentionLink,inClassification,classificationDefinitions};
});
