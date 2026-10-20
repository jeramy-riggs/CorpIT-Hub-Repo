/* AI USE-CASE ENRICHMENT 2026-10-20. Review, Governance Queue, Summary, Sources and Audit
   trail tabs of the Use-Case Inventory. Proposed values come from the sources configured on
   this server, each with its source system, record ID, date observed, confidence and match
   method. Nothing proposed is inventory data until a reviewer accepts it; low-risk
   authoritative facts may fill blank fields automatically and are shown in the Audit trail.
   Risk tier and the InfoSec / Legal review section are never proposed. */
(function(root){'use strict';
const E=v=>String(v==null?'':v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const API='/api/zscaler/governance/use-cases/enrichment';
const badge=(s,t='')=>'<span class="sai-badge '+t+'">'+E(s)+'</span>';
const when=v=>{if(!v)return '';const d=new Date(v);return Number.isFinite(d.getTime())?d.toLocaleString([], {dateStyle:'medium',timeStyle:'short'}):'';};
const day=v=>{if(!v)return '';const d=new Date(v);return Number.isFinite(d.getTime())?d.toLocaleDateString():'';};
const CONF_TONE={verified:'ok',confirmed:'ok',inferred:'info',needs_review:'warn',unknown:''};
const STATE_TONE={complete:'ok',prefilled:'info',conflicting:'warn',unknown:'warn',missing:'warn',not_applicable:''};
const SRC_TONE={current:'ok',stale:'warn',failed:'warn',partial:'warn',paused:'',no_data:'warn',manual_only:'',lookup_only:'',not_authorized:'warn',not_configured:'',not_used:'',off:'',not_run:''};
const SRC_LABEL={current:'Current',stale:'Stale',failed:'Failed',partial:'Partial',paused:'Paused',no_data:'No data yet',manual_only:'Manual runs only',lookup_only:'Reviewer lookup',not_authorized:'Not authorized',not_configured:'Not configured',not_used:'Not used for AI use cases',off:'Off',not_run:'Not run yet'};
const ACTION={use_case_proposal_accepted:'Accepted',use_case_proposal_auto_accepted:'Auto-filled',use_case_proposal_kept:'Kept existing',use_case_proposal_merged:'Merged',use_case_proposal_marked_unknown:'Marked Unknown',use_case_proposal_rejected:'Rejected',use_case_candidate_created:'Draft → use case created',use_case_candidate_linked:'Draft linked',use_case_candidate_dismissed:'Draft dismissed',use_case_enrichment_run:'Enrichment run',use_case_portal_lookup:'Portal lookup',use_case_portal_match_confirmed:'Portal match confirmed',use_case_added:'Use case added',use_case_updated:'Use case edited',use_case_imported:'Imported',use_case_import_updated:'Updated by import'};
async function request(path,options={},ms=20000){
  const ctrl=new AbortController(),timer=setTimeout(()=>ctrl.abort(),ms);
  try{const r=await fetch(API+path,{credentials:'same-origin',...options,headers:{'Content-Type':'application/json'},signal:ctrl.signal});let j;try{j=await r.json();}catch{throw new Error('Unexpected response. Refresh the page and try again.');}if(!r.ok){const e=new Error(r.status===503?'Enrichment is not available on this server yet.':j.error||'Request failed');e.status=r.status;e.last_success_at=j.last_success_at;throw e;}return j;}
  catch(e){if(e.name==='AbortError')throw new Error('Request timed out. Reload to check whether the change was saved before trying again.');throw e;}
  finally{clearTimeout(timer);}
}
function mount(el,opts={}){
  const listeners=new AbortController(),dialogs=new Set(),toast=opts.toast||(()=>{}),changed=opts.onChange||(()=>{});
  let data=null,error='',audit=null,auditError='',tab='review',inflight=0,alive=true,running=false;
  const portal={query:'',use_case_id:'',response:null,error:'',loading:false,message:'',last_success_at:null};
  const f={uc:'',state:'',source:'',confidence:''},picked=new Set();
  const track=async p=>{inflight++;try{return await p;}finally{inflight--;}};
  const field=k=>data.fields.find(x=>x.key===k)||{key:k,label:k};
  const uc=id=>data.use_cases.find(r=>r.id===id);
  const appName=id=>((opts.catalog?.()||[]).find(a=>a.id===id)||data.apps.find(a=>a.catalog_id===id)||{}).app_name||(id?'Application '+id:'No catalog match');
  async function load(){try{data=await track(request(''));error='';}catch(e){error=e.message;}if(alive){render();opts.onLoad?.();}}
  async function loadAudit(){try{audit=(await track(request('/audit'))).rows;auditError='';}catch(e){auditError=e.message;}if(alive&&tab==='audit')render();}
  function show(t){tab=t;if(t==='audit'&&!audit)loadAudit();if(t==='portal'&&!portal.last_success_at)track(request('/portal-status')).then(s=>{portal.last_success_at=s.last_success_at;if(alive&&tab==='portal')render();}).catch(()=>{});render();}
  function shell(body){return '<div class="sai uc-view ucr">'+(error&&data?'<p role="alert">'+E(error)+'</p>':'')+body+'</div>';}
  function render(){
    if(!data){el.innerHTML=shell(error?'<h2>Enrichment unavailable</h2><p role="alert">'+E(error)+'</p><button type="button" data-ucr-reload>Try again</button>':'<p role="status">Loading proposals and sources…</p>');return;}
    el.innerHTML=shell(({portal:portalView,review,queue,summary,sources,audit:auditView})[tab]());
  }
  // ---- Access Portal lookup --------------------------------------------------------------
  function portalView(){
    if(!data.can_edit)return '<div class="empty"><strong>Portal lookup is available to governance editors with Access Portal read access.</strong></div>';
    const selected=data.use_cases.find(r=>String(r.id)===String(portal.use_case_id));
    const form='<form data-ucr-portal-search class="sai-controls ucr-portal-search"><label>Governance use case<select name="use_case_id" required><option value="">Choose a use case</option>'
      +data.use_cases.filter(r=>r.profile).map(r=>'<option value="'+r.id+'"'+(String(portal.use_case_id)===String(r.id)?' selected':'')+'>'+E(r.ref+' · '+r.profile.name)+'</option>').join('')+'</select></label>'
      +'<label>Search Access Portal<input name="q" type="search" minlength="2" maxlength="120" required value="'+E(portal.query)+'" placeholder="Request ID, application, purpose, requester, department, vendor or status"></label>'
      +'<button type="submit" class="sai-primary"'+(portal.loading?' disabled':'')+'>'+(portal.loading?'Searching…':'Search requests')+'</button></form>';
    const response=portal.response;
    const cards=response?response.records.map(r=>{
      const missing=selected?data.fields.filter(f=>f.required&&!String(selected.profile[f.key]||'').trim()&&!r.proposals.some(p=>p.field===f.key)).map(f=>f.label):[];
      const proposed=r.proposals.map(p=>'<tr><td>'+E(p.label)+'<small>'+E(p.source_field)+'</small></td><td>'+E(p.existing||'Missing')+'</td><td><strong>'+E(p.value)+'</strong>'+((p.source_value&&p.source_value!==p.value)?'<small>Original: '+E(p.source_value)+'</small>':'')+'</td><td>'+(p.conflict?badge('Conflict','warn'):badge('Needs review','info'))+'</td></tr>').join('');
      const canConfirm=r.match_level!=='No Match'&&!r.linked_to_other;
      return '<section class="ucr-uc ucr-portal-result"><header><strong>'+E(r.request_id)+'</strong>'+badge(r.match_level,r.match_level==='No Match'?'warn':r.match_level==='Exact Match'?'ok':'info')+(r.archived?badge('Archived','warn'):'')+'<span>'+E(r.requested_application||'Application not recorded')+'</span></header>'
        +'<p class="ucr-fine">'+E(r.match_reason)+(r.linked_to_other?' This request is already linked to another use case.':'')+'</p>'
        +'<dl class="ucr-portal-facts"><div><dt>Use case / purpose</dt><dd>'+E(r.use_case_name||'Not recorded')+'</dd></div><div><dt>Department</dt><dd>'+E(r.department||'Not recorded')+'</dd></div><div><dt>Requestor</dt><dd>'+E(r.requester||'Not recorded')+'</dd></div><div><dt>Business owner</dt><dd>'+E(r.business_owner||'Not recorded in source')+'</dd></div><div><dt>Technical owner</dt><dd>'+E(r.technical_owner||'Not recorded in source')+'</dd></div><div><dt>Vendor / platform</dt><dd>'+E(r.vendor||'Not recorded')+'</dd></div><div><dt>Request status</dt><dd>'+E(r.request_status||'Not recorded')+'</dd></div><div><dt>Approval status</dt><dd>'+E(r.approval_status||'Not recorded')+'</dd></div></dl>'
        +'<p class="ucr-fine">Retrieved '+E(when(response.retrieved_at))+(r.source_updated_at?' · Source updated '+E(when(r.source_updated_at)):'')+(r.source_url&&/^https:\/\//.test(r.source_url)?' · <a href="'+E(r.source_url)+'" target="_blank" rel="noopener noreferrer">Open source request</a>':'')+'</p>'
        +'<details><summary>Review '+r.proposals.length+' available field'+(r.proposals.length===1?'':'s')+' before proposing</summary>'+(r.proposals.length?'<div class="sai-table"><table><thead><tr><th>Governance field / source field</th><th>Existing value</th><th>Portal value</th><th>State</th></tr></thead><tbody>'+proposed+'</tbody></table></div>':'<p>No usable governance fields are present in this source record.</p>')+(missing.length?'<p class="ucr-fine">Still missing after this request: '+E(missing.join(', '))+'.</p>':'')+'</details>'
        +(canConfirm?'<div class="ucr-acts"><label><input type="checkbox" data-ucr-portal-verify="'+E(r.request_id)+'"> I confirm this request belongs to '+E(response.ref)+'.</label><button type="button" class="sai-primary" data-ucr-portal-confirm="'+E(r.request_id)+'"'+(portal.loading?' disabled':'')+'>Confirm match and propose values</button></div>':'')+'</section>';
    }).join(''):'';
    return '<div class="sai-note">Search the existing Access Portal through its authorized read-only endpoint. Confirm a request before its available fields become proposals. No Portal value changes a governance record until you review it in the Review tab. Missing fields stay missing.</div>'
      +form+(portal.error?'<p role="alert">'+E(portal.error)+'</p>':'')+(portal.message?'<p role="status">'+E(portal.message)+'</p>':'')
      +(portal.last_success_at?'<p class="ucr-fine">Most recent successful retrieval: '+E(when(portal.last_success_at))+'.</p>':'')
      +(response?'<p class="sai-count">'+response.results+' matching requests · showing '+response.shown+' · retrieved '+E(when(response.retrieved_at))+' from '+E(response.source_origin)+'. Results are live and are cleared if a read fails.</p>'+(cards||'<div class="empty"><strong>No requests matched.</strong><p>Try a request ID, application, purpose, requester, department, vendor or status.</p></div>'):'');
  }
  async function portalSearch(form){
    portal.use_case_id=form.elements.use_case_id.value;portal.query=form.elements.q.value.trim();portal.loading=true;portal.error='';portal.message='';portal.response=null;render();
    try{const p=new URLSearchParams({use_case_id:portal.use_case_id,q:portal.query});portal.response=await track(request('/portal-lookup?'+p.toString(),{},30000));portal.last_success_at=portal.response.last_success_at;}
    catch(e){portal.error=e.message;portal.last_success_at=e.last_success_at||portal.last_success_at;portal.response=null;}
    finally{portal.loading=false;if(alive&&tab==='portal')render();}
  }
  async function portalConfirm(requestId){
    const r=portal.response?.records.find(x=>x.request_id===requestId);
    if(!r)return;
    if(!el.querySelector('[data-ucr-portal-verify="'+requestId+'"]')?.checked){portal.error='Confirm that this source request belongs to the selected use case.';render();return;}
    portal.loading=true;portal.error='';render();
    try{const result=await track(request('/portal-confirm',{method:'POST',body:JSON.stringify({use_case_id:portal.response.use_case_id,request_id:requestId,expected_revision:portal.response.revision,expected_updated_at:r.source_updated_at})},30000));
      portal.message='Confirmed '+result.request_id+' for '+result.ref+'. '+result.proposals+' field proposals are ready for review.';portal.response=null;await load();opts.goto?.('review');toast(portal.message);audit=null;changed();}
    catch(e){portal.error=e.message;}
    finally{portal.loading=false;if(alive&&tab==='portal')render();}
  }
  // ---- Review --------------------------------------------------------------------------
  function runBar(){
    const r=data.run;
    return '<div class="ucr-run"><div><strong>'+(r?'Last enrichment '+E(when(r.completed_at||r.started_at)):'Enrichment has not run yet')+'</strong><small>'+(r?E((r.trigger==='scheduled'?'Hourly run':'Run by '+r.actor))+' · '+E(r.counts?.inserted??0)+' new, '+E(r.counts?.auto_accepted??0)+' auto-filled, '+E(r.counts?.withdrawn??0)+' withdrawn':'Runs hourly from the source snapshots, or now from here.')+'</small></div>'
      +(data.can_edit?'<button type="button" class="sai-primary" data-ucr-run'+(running?' disabled':'')+'>'+(running?'Running…':'Run enrichment now')+'</button>':'')+'</div>'
      +(data.can_edit?'<p class="ucr-fine">Access Portal requests are searched and confirmed in Portal lookup. Enrichment runs do not read or apply Portal values. '+E(data.policy.note)+'</p>':'');
  }
  function proposalRow(p,cur,editable){
    const fl=field(p.field),blank=!String(cur||'').trim();
    const acts=editable?'<div class="ucr-acts"><button type="button" data-ucr-act="accept" data-ucr-id="'+p.id+'">Accept</button>'+(blank?'':'<button type="button" data-ucr-act="keep" data-ucr-id="'+p.id+'">Keep existing</button>')+'<button type="button" data-ucr-act="merge" data-ucr-id="'+p.id+'">Merge…</button>'+(fl.unknown_value?'<button type="button" data-ucr-act="unknown" data-ucr-id="'+p.id+'">Mark '+E(fl.unknown_value)+'</button>':'')+'<button type="button" data-ucr-act="reject" data-ucr-id="'+p.id+'">Reject</button></div>':'';
    return '<tr>'+(editable?'<td><input type="checkbox" data-ucr-pick="'+p.id+'" aria-label="Select proposal '+p.id+'"'+(picked.has(p.id)?' checked':'')+'></td>':'')
      +'<td><strong class="ucr-value">'+E(p.value)+'</strong>'+(p.source_value&&p.source_value!==p.value?'<small>Source value: '+E(p.source_value)+'</small>':'')+'</td>'
      +'<td>'+badge(p.confidence_label,CONF_TONE[p.confidence])+(p.auto?'<small>Auto-fill field</small>':'')+'</td>'
      +'<td>'+E(p.source_system)+'<small>'+E(p.source_record_id)+(p.observed_at?' · observed '+E(day(p.observed_at)):'')+'</small></td>'
      +'<td><small class="ucr-method">'+E(p.match_method)+'</small>'+(p.evidence_note?'<small>'+E(p.evidence_note)+'</small>':'')+(p.evidence_url&&/^https:\/\//.test(p.evidence_url)?'<small><a href="'+E(p.evidence_url)+'" target="_blank" rel="noopener noreferrer">Source record</a></small>':'')+acts+'</td></tr>';
  }
  function review(){
    if(!data.can_edit){const n=k=>(data.queue.find(q=>q.key===k)||{}).count||0;
      return runBar()+'<div class="empty"><strong>Proposed values and drafts are shown to editors.</strong><p>'+n('prefilled')+' field'+(n('prefilled')===1?' is':'s are')+' prefilled and awaiting review; '+n('conflicting')+' '+(n('conflicting')===1?'has':'have')+' conflicting evidence. The Summary and Enrichment sources tabs are open to you.</p></div>';}
    const open=data.proposals.filter(p=>p.status==='open'&&p.use_case_id),srcs=[...new Set(open.map(p=>p.source_system))].sort();
    const keep=p=>(!f.uc||String(p.use_case_id)===f.uc)&&(!f.source||p.source_system===f.source)&&(!f.confidence||p.confidence===f.confidence)&&(!f.state||uc(p.use_case_id)?.states?.[p.field]===f.state);
    const list=open.filter(keep),byUc=new Map();
    for(const p of list){if(!byUc.has(p.use_case_id))byUc.set(p.use_case_id,new Map());const m=byUc.get(p.use_case_id);if(!m.has(p.field))m.set(p.field,[]);m.get(p.field).push(p);}
    for(const id of [...picked])if(!list.some(p=>p.id===id))picked.delete(id);
    const opt=(v,l,cur)=>'<option value="'+E(v)+'"'+(String(v)===cur?' selected':'')+'>'+E(l)+'</option>';
    const order=new Map(data.fields.map((x,i)=>[x.key,i]));
    const groups=[...byUc].sort((a,b)=>a[0]-b[0]).map(([id,fields])=>{
      const r=uc(id);if(!r)return '';const ev=data.evidence[r.catalog_id]||[];
      return '<section class="ucr-uc"><header><button type="button" class="sai-link" data-uc-open="'+id+'">'+E(r.ref)+'</button><strong>'+E(r.profile.name)+'</strong><span>'+E(r.app_name||appName(r.catalog_id))+'</span>'+badge(r.completeness.complete+' of '+r.completeness.total+' required complete',r.completeness.complete===r.completeness.total?'ok':'')+'</header>'
        +'<div class="sai-table"><table><thead><tr>'+(data.can_edit?'<th></th>':'')+'<th>Proposed value</th><th>Confidence</th><th>Source / record</th><th>How it was matched</th></tr></thead><tbody>'
        +[...fields].sort((a,b)=>order.get(a[0])-order.get(b[0])).map(([k,ps])=>{const fl=field(k),cur=r.profile[k]||'',st=r.states[k];
          return '<tr class="ucr-field"><th colspan="'+(data.can_edit?5:4)+'">'+E(fl.label)+(fl.required?' *':'')+' '+badge(data.states[st]||st,STATE_TONE[st])+'<span>Saved value: '+(cur?'<strong>'+E(cur)+'</strong>':'<em>blank</em>')+'</span></th></tr>'+ps.map(p=>proposalRow(p,cur,data.can_edit)).join('');}).join('')
        +'</tbody></table></div>'
        +(ev.length?'<details class="ucr-evidence"><summary>Evidence for '+E(r.app_name||appName(r.catalog_id))+' ('+ev.length+') — shown for context, never filled into fields</summary><ul>'+ev.map(x=>'<li>'+E(x.text)+(x.observed_at?' <small>'+E(day(x.observed_at))+'</small>':'')+'</li>').join('')+'</ul></details>':'')+'</section>';}).join('');
    const sel=[...picked].map(id=>open.find(p=>p.id===id)).filter(Boolean);
    return runBar()
      +'<div class="sai-note">'+E(data.note)+' Zscaler shows observation, not approval. Entra and Okta show assignment, not active use. Rapid7 shows telemetry, not purpose. Vendor documentation shows availability, not configuration.</div>'
      +'<div class="sai-controls"><label>Use case<select data-ucr-filter="uc">'+opt('','All use cases',f.uc)+data.use_cases.filter(r=>r.profile).map(r=>opt(r.id,r.ref+' · '+r.profile.name,f.uc)).join('')+'</select></label>'
      +'<label>Field state<select data-ucr-filter="state">'+opt('','All states',f.state)+['prefilled','conflicting','complete','unknown','not_applicable'].map(s=>opt(s,data.states[s],f.state)).join('')+'</select></label>'
      +'<label>Source<select data-ucr-filter="source">'+opt('','All sources',f.source)+srcs.map(s=>opt(s,s,f.source)).join('')+'</select></label>'
      +'<label>Confidence<select data-ucr-filter="confidence">'+opt('','All confidence',f.confidence)+Object.entries(data.confidence).map(([k,l])=>opt(k,l,f.confidence)).join('')+'</select></label>'
      +(data.can_edit?'<div class="uc-actions"><button type="button" data-ucr-bulk'+(sel.length?'':' disabled')+'>Accept '+sel.length+' selected</button></div>':'')+'</div>'
      +'<p class="sai-count">'+list.length+' proposal'+(list.length===1?'':'s')+' awaiting review across '+byUc.size+' use case'+(byUc.size===1?'':'s')+'. Bulk accept needs the same source, field and confidence, no conflicting evidence, and a blank saved value.</p>'
      +(groups||'<div class="empty"><strong>'+(open.length?'No proposals match these filters.':'No proposals are waiting for review.')+'</strong><p>'+(data.run?'Proposals appear here after each enrichment run.':'Run enrichment to propose values from the configured sources.')+'</p></div>')
      +candidates();
  }
  function candidates(){
    const list=data.candidates;if(!data.can_edit)return '';
    const props=id=>data.proposals.filter(p=>p.candidate_id===id&&!p.use_case_id&&p.status==='open');
    return '<h3 class="ucr-h">Draft use cases from sources ('+list.length+')</h3><p class="ucr-fine">Drafts come from approved intake requests and from apps with Entra / Okta assignments or Rapid7 activity that have no use case yet. They are not use cases until you create one; owner and purpose must be confirmed. A possible new application is handled in Sources, not here.</p>'
      +(list.length?list.map(c=>{const ps=props(c.id);
        return '<section class="ucr-uc ucr-cand"><header><strong>'+E(c.name)+'</strong>'+badge(c.kind==='intake'?'Approved intake request':'Observed in telemetry',c.kind==='intake'?'info':'')+badge(c.match_status==='matched'?'App: '+appName(c.catalog_id):c.match_status==='ambiguous'?'Several apps match':'No catalog app match',c.match_status==='matched'?'':'warn')+'</header>'
          +'<p class="ucr-fine">'+E(c.source_system)+' · '+E(c.source_record_id)+(c.observed_at?' · updated '+E(day(c.observed_at)):'')+(c.detail?.source_url&&/^https:\/\//.test(c.detail.source_url)?' · <a href="'+E(c.detail.source_url)+'" target="_blank" rel="noopener noreferrer">Open request</a>':'')+(c.detail?.note?' · '+E(c.detail.note):'')+(c.detail?.review_process?'<br>Review process as described on the request (evidence for Human oversight, not filled): '+E(c.detail.review_process):'')+'</p>'
          +(ps.length?'<details><summary>'+ps.length+' proposed value'+(ps.length===1?'':'s')+' (decided after the use case exists)</summary><ul class="ucr-plist">'+ps.map(p=>'<li><strong>'+E(field(p.field).label)+':</strong> '+E(p.value)+' '+badge(p.confidence_label,CONF_TONE[p.confidence])+' <small>'+E(p.source_system)+'</small></li>').join('')+'</ul></details>':'')
          +'<div class="ucr-acts"><button type="button" class="sai-primary" data-ucr-cand="create" data-ucr-id="'+c.id+'">Create use case…</button><button type="button" data-ucr-cand="link" data-ucr-id="'+c.id+'">Link to existing…</button><button type="button" data-ucr-cand="dismiss" data-ucr-id="'+c.id+'">Dismiss</button></div></section>';}).join(''):'<div class="empty"><strong>No open drafts.</strong></div>');
  }
  // ---- Queue -----------------------------------------------------------------------------
  // Field items with proposals open the Review tab filtered to that use case; the rest open the
  // use case itself in the inventory form.
  const TO_REVIEW=new Set(['prefilled','conflicting','high_risk']),MATCH={matched:'app matched',ambiguous:'several apps match',unmatched:'no catalog app match'};
  function queueItem(q,i){
    if(q.key==='unmatched_apps')return E(i.name)+' <small>'+E([i.source,i.code,i.users!=null?i.users+' users':'',i.events!=null?i.events+' events':'',i.category,i.observed_at?'seen '+day(i.observed_at):''].filter(Boolean).join(' · '))+'</small>';
    if(q.key==='stale'||q.key==='failed')return '<button type="button" class="sai-link" data-ucr-tab="sources">'+E(i.name)+'</button> <small>'+E(i.detail)+'</small>';
    if(i.candidate_id)return '<button type="button" class="sai-link" data-ucr-tab="review">'+E(i.name)+'</button> <small>'+E(MATCH[i.match_status]||i.match_status)+'</small>';
    return '<button type="button" class="sai-link" '+(TO_REVIEW.has(q.key)?'data-ucr-goto':'data-uc-open')+'="'+i.use_case_id+'">'+E(i.ref)+'</button> '+E(i.name||'')+(i.label||i.detail?' <small>'+E(i.label||i.detail)+'</small>':'');
  }
  function queue(){
    return '<div class="sai-note">What still needs a person, from the saved use cases and the latest enrichment run. Nothing in this list is decided automatically.'+(data.can_edit?'':' Item lists are shown to editors.')+'</div><div class="ucr-queue">'
      +data.queue.map(q=>'<details class="ucr-q"'+(q.count?'':' data-empty')+'><summary><strong>'+E(q.count)+'</strong><span>'+E(q.label)+'</span></summary>'+(q.note?'<p class="ucr-fine">'+E(q.note)+'</p>':'')
        +(q.items.length?'<ul>'+q.items.map(i=>'<li>'+queueItem(q,i)+'</li>').join('')+'</ul>'+(q.count>q.items.length?'<p class="ucr-fine">Showing '+q.items.length+' of '+q.count+'.</p>':''):'')
        +(q.href?'<p><a href="'+E(q.href)+'">Open Sources</a> · <a href="#discovery">Open Discovery</a></p>':'')+'</details>').join('')+'</div>';
  }
  // ---- Summary ---------------------------------------------------------------------------
  function summary(){
    const groups=[...new Set(data.summary.map(s=>s.group))];
    return '<div class="sai-note">The workbook\'s Summary sheet, recalculated from the saved use cases (approved values only). Proposals awaiting review are not counted.</div>'
      +'<div class="ucr-summary">'+groups.map(g=>'<section><h3>'+E(g)+'</h3><dl>'+data.summary.filter(s=>s.group===g).map(s=>'<div><dt>'+E(s.label)+'</dt><dd>'+E(s.count)+'</dd></div>').join('')+'</dl></section>').join('')+'</div>'
      +'<h3 class="ucr-h">Completeness of required fields</h3><p class="ucr-fine">Complete or N/A counts; Unknown, Unsure, TBD, prefilled-awaiting-review and conflicting do not.</p>'
      +'<div class="sai-table"><table><thead><tr><th>Application</th><th>Use cases</th><th>Required complete</th></tr></thead><tbody>'+(data.apps.map(a=>'<tr><td>'+E(a.app_name||appName(a.catalog_id))+'</td><td>'+a.use_cases+'</td><td>'+a.pct+'%</td></tr>').join('')||'<tr><td colspan="3">No use cases recorded.</td></tr>')+'</tbody></table></div>'
      +'<div class="sai-table"><table><thead><tr><th>Use case</th><th>Complete</th><th>Prefilled</th><th>Conflicting</th><th>Unknown</th><th>Missing</th><th>N/A</th></tr></thead><tbody>'+data.use_cases.map(r=>'<tr><td>'+(r.profile?'<button type="button" class="sai-link" data-ucr-goto="'+r.id+'">'+E(r.ref)+'</button> '+E(r.profile.name):E(r.ref))+'</td><td>'+r.completeness.complete+' / '+r.completeness.total+'</td><td>'+r.counts.prefilled+'</td><td>'+r.counts.conflicting+'</td><td>'+r.counts.unknown+'</td><td>'+r.counts.missing+'</td><td>'+r.counts.not_applicable+'</td></tr>').join('')+'</tbody></table></div>';
  }
  // ---- Sources ---------------------------------------------------------------------------
  function sources(){
    const used=data.sources.filter(s=>s.proves),other=data.sources.filter(s=>!s.proves);
    return '<div class="sai-note">Only sources configured on this server are read. Each proposal names its source; a source that fails or is not configured adds nothing.</div>'
      +'<div class="sai-table"><table><thead><tr><th>Source</th><th>Status</th><th>What it can show</th><th>Limit</th></tr></thead><tbody>'
      +used.map(s=>'<tr><td><strong>'+E(s.name)+'</strong><small>'+(s.key==='intake'?(s.checked_at?'Most recent successful retrieval '+E(when(s.checked_at)):'No successful lookup yet'):(s.checked_at?'Checked '+E(when(s.checked_at)):'Not checked yet'))+(s.records!=null?' · '+E(s.records)+' records':'')+(s.instances!=null?' · '+E(s.read??0)+' of '+E(s.instances)+' app instances read':'')+'</small></td><td>'+badge(SRC_LABEL[s.status]||s.status,SRC_TONE[s.status])+(s.error?'<small>'+E(s.error)+'</small>':'')+(s.note?'<small>'+E(s.note)+'</small>':'')+(Array.isArray(s.errors)&&s.errors.length?'<small>'+E(s.errors.length+' instance(s) not read: '+s.errors.slice(0,5).map(x=>x.provider+' '+x.error).join('; '))+'</small>':'')+'</td><td>'+E(s.proves)+'</td><td>'+E(s.limit)+'</td></tr>').join('')
      +'</tbody></table></div><h3 class="ucr-h">Not read for AI use cases</h3><div class="sai-table"><table><tbody>'
      +other.map(s=>'<tr><td><strong>'+E(s.name)+'</strong></td><td>'+badge(SRC_LABEL[s.status]||s.status,SRC_TONE[s.status])+'</td><td>'+E(s.note||'')+'</td></tr>').join('')+'</tbody></table></div>'
      +'<p class="ucr-fine">Apps found in Entra, Rapid7 or Zscaler but not in the catalog are added or matched in <a href="#sources">Sources</a> and <a href="#discovery">Discovery</a>; they need approval before they become catalog apps.</p>';
  }
  // ---- Audit -----------------------------------------------------------------------------
  function auditView(){
    if(!data.can_edit)return '<div class="empty"><strong>The audit trail is shown to editors.</strong></div>';
    if(auditError)return '<p role="alert">'+E(auditError)+'</p><button type="button" data-ucr-audit-reload>Try again</button>';
    if(!audit)return '<p role="status">Loading the audit trail…</p>';
    const ref=a=>a.after_json?.ref||a.before_json?.ref||(a.after_json?.candidate?'Draft: '+a.after_json.candidate.name:'');
    return '<div class="sai-note">Every accepted, auto-filled, kept, merged, marked Unknown and rejected proposal, every draft decision and every enrichment run, newest first (latest 300).</div><div class="sai-table"><table><thead><tr><th>When</th><th>Who</th><th>Action</th><th>Use case</th><th>Field and value</th><th>Source</th></tr></thead><tbody>'
      +(audit.map(a=>{const x=a.after_json||{},b=a.before_json||{};return '<tr><td>'+E(when(a.created_at))+'</td><td>'+E(a.actor)+'</td><td>'+E(ACTION[a.action]||a.action)+'</td><td>'+E(ref(a))+'<small>'+E(a.app_name||'')+'</small></td>'
        +'<td>'+(x.field?'<strong>'+E(x.label||field(x.field).label)+'</strong><small>'+(b.value!=null&&b.value!==x.value?E(b.value||'blank')+' → ':'')+E(x.value??'')+(x.proposed_value&&x.proposed_value!==x.value?' (proposed '+E(x.proposed_value)+')':'')+'</small>':a.action==='use_case_enrichment_run'?'<small>'+E((x.sources||[]).map(s=>s.key+': '+s.status).join(', '))+'</small>':'<small>'+E(x.note||'')+'</small>')+'</td>'
        +'<td>'+(x.source_system?E(x.source_system)+'<small>'+E(x.source_record_id||'')+(x.confidence?' · '+E(x.confidence):'')+'</small>'+(x.evidence_note?'<small>'+E(x.evidence_note)+'</small>':''):'')+'</td></tr>';}).join('')||'<tr><td colspan="6">No use-case activity recorded yet.</td></tr>')+'</tbody></table></div>';
  }
  // ---- Actions ---------------------------------------------------------------------------
  function dialog(cls,html){
    const d=document.createElement('dialog');d.className='sai sai-dialog uc-dialog ucr-dialog '+cls;d.innerHTML=html;document.body.appendChild(d);dialogs.add(d);
    d.addEventListener('close',()=>{dialogs.delete(d);d.remove();});d.addEventListener('click',e=>{if(e.target.closest('[data-ucr-close]'))d.close();});d.showModal();return d;
  }
  async function decide(decisions,bulk=false){
    try{const r=await track(request('/decide',{method:'POST',body:JSON.stringify({decisions,bulk})},30000));picked.clear();toast('Recorded '+r.decided+' decision'+(r.decided===1?'':'s')+' in the audit trail.');audit=null;await load();changed();return true;}
    catch(e){toast(e.message);if(e.status===409)await load();return false;}
  }
  function expected(p){return String(uc(p.use_case_id)?.profile?.[p.field]||'');}
  function act(action,id){
    const p=data.proposals.find(x=>x.id===id);if(!p)return;
    if(action!=='merge')return decide([{id,action,...(['accept','unknown'].includes(action)?{expected:expected(p)}:{})}]);
    const fl=field(p.field),cur=expected(p);
    const input=fl.allowed?'<select name="v">'+fl.allowed.map(a=>'<option'+(a===p.value?' selected':'')+'>'+E(a)+'</option>').join('')+'</select>':fl.kind==='long'?'<textarea name="v" maxlength="4000">'+E(cur&&cur!==p.value?cur+'\n'+p.value:p.value)+'</textarea>':'<input name="v" maxlength="255" value="'+E(cur&&cur!==p.value?cur+'; '+p.value:p.value)+'">';
    const d=dialog('ucr-merge','<form><header class="sai-head"><div><p class="sai-eyebrow">MERGE · '+E(uc(p.use_case_id)?.ref)+'</p><h2>'+E(fl.label)+'</h2><p>Saved value: '+E(cur||'blank')+' · Proposed: '+E(p.value)+' ('+E(p.source_system)+')</p></div><button type="button" data-ucr-close aria-label="Close">×</button></header><label class="sai-full"><span>Value to save</span>'+input+'</label><p role="alert" data-ucr-error hidden></p><footer><span>Recorded as merged by you, with this source as evidence.</span><button type="button" data-ucr-close>Cancel</button><button type="submit" class="sai-primary">Save merged value</button></footer></form>');
    d.querySelector('form').onsubmit=async e=>{e.preventDefault();const v=new FormData(e.target).get('v');if(await decide([{id,action:'merge',value:String(v||''),expected:cur}]))d.close();};
  }
  function bulk(){
    const open=data.proposals.filter(p=>picked.has(p.id));if(!open.length)return;
    const keys=new Set(open.map(p=>[p.source_system,p.field,p.confidence].join('|')));
    if(keys.size>1)return toast('Bulk accept needs proposals with the same source, field and confidence.');
    decide(open.map(p=>({id:p.id,action:'accept',expected:expected(p)})),true);
  }
  function candidateAction(action,id){
    const c=data.candidates.find(x=>x.id===id);if(!c)return;
    const props=data.proposals.filter(p=>p.candidate_id===id&&!p.use_case_id&&p.status==='open'),fromIntake=k=>(props.find(p=>p.field===k&&p.source_key==='intake')||{}).value||'';
    const send=async(body,d)=>{const err=d?.querySelector('[data-ucr-error]');try{const r=await track(request('/candidates/'+id,{method:'POST',body:JSON.stringify(body)},30000));d?.close();toast(r.status==='created'?'Created '+r.ref+'.':r.status==='linked'?'Linked to '+r.ref+'.':'Draft dismissed.');audit=null;await load();changed();}catch(e){if(err){err.textContent=e.message;err.hidden=false;}else toast(e.message);}};
    if(action==='dismiss'){if(confirm('Dismiss this draft? Its proposed values are withdrawn. Nothing else changes.'))send({action:'dismiss'});return;}
    if(action==='link'){
      const d=dialog('ucr-link','<form><header class="sai-head"><div><p class="sai-eyebrow">LINK DRAFT</p><h2>'+E(c.name)+'</h2><p>Its proposed values move to the use case you choose and wait for review there.</p></div><button type="button" data-ucr-close aria-label="Close">×</button></header><label class="sai-full"><span>Use case</span><select name="u" required><option value="">Choose use case</option>'+data.use_cases.filter(r=>r.profile).sort((a,b)=>(b.catalog_id===c.catalog_id)-(a.catalog_id===c.catalog_id)||a.id-b.id).map(r=>'<option value="'+r.id+'">'+E(r.ref+' · '+r.profile.name+' · '+(r.app_name||''))+'</option>').join('')+'</select><small>Use cases of the same application are listed first.</small></label><p role="alert" data-ucr-error hidden></p><footer><span></span><button type="button" data-ucr-close>Cancel</button><button type="submit" class="sai-primary">Link</button></footer></form>');
      d.querySelector('form').onsubmit=e=>{e.preventDefault();send({action:'link',use_case_id:Number(new FormData(e.target).get('u'))},d);};return;
    }
    const apps=opts.catalog?.()||[];
    const d=dialog('ucr-create','<form><header class="sai-head"><div><p class="sai-eyebrow">CREATE USE CASE FROM DRAFT</p><h2>'+E(c.name)+'</h2><p>'+E(c.source_system)+' · '+E(c.source_record_id)+'</p></div><button type="button" data-ucr-close aria-label="Close">×</button></header>'
      +'<div class="sai-fields"><label class="sai-full"><span>Application this use case belongs to *</span><select name="app" required><option value="">Choose application</option>'+apps.map(a=>'<option value="'+a.id+'"'+(a.id===c.catalog_id?' selected':'')+'>'+E(a.app_name)+'</option>').join('')+'</select></label>'
      +'<label class="sai-full"><span>Name of AI/ML use or system *</span><input name="name" maxlength="255" required value="'+E(c.name)+'"></label>'
      +'<label><span>Business owner (name, title) *</span><input name="bowner" maxlength="255" required value="'+E(fromIntake('bowner'))+'"><small>'+(fromIntake('bowner')?'The requester on the intake request. Change it if the business owner is someone else.':'Not known from any source. Ask the department.')+'</small></label>'
      +'<label class="sai-full"><span>What it does / business process it supports *</span><textarea name="what" maxlength="4000" required>'+E(fromIntake('what'))+'</textarea><small>'+(fromIntake('what')?'As written on the intake request.':'Telemetry does not show purpose. Enter what the department told you.')+'</small></label>'
      +'<label class="sai-full ucr-confirm"><input type="checkbox" name="ok" required> I confirmed the business owner and purpose with the department.</label></div>'
      +'<p class="ucr-fine">Department, vendor, SSO, intake, connected systems and notes from Verified or Confirmed sources are filled when nothing disagrees. Every other proposed value moves to the new use case for review.</p><p role="alert" data-ucr-error hidden></p><footer><span>Creating a use case does not approve the application or grant access.</span><button type="button" data-ucr-close>Cancel</button><button type="submit" class="sai-primary">Create use case</button></footer></form>');
    d.querySelector('form').onsubmit=e=>{e.preventDefault();const fd=new FormData(e.target);send({action:'create',catalog_id:Number(fd.get('app')),name:String(fd.get('name')||''),bowner:String(fd.get('bowner')||''),what:String(fd.get('what')||''),confirmed:fd.get('ok')==='on'},d);};
  }
  async function run(b){
    running=true;b.disabled=true;b.textContent='Running…';
    try{const r=await track(request('/run',{method:'POST',body:'{}'},90000));const c=r.run.counts;toast('Enrichment finished: '+c.inserted+' new proposal'+(c.inserted===1?'':'s')+', '+c.auto_accepted+' auto-filled, '+c.withdrawn+' withdrawn.');audit=null;}
    catch(e){toast(e.message);}finally{running=false;}
    await load();changed();
  }
  el.addEventListener('click',e=>{
    const b=e.target.closest('[data-ucr-run],[data-ucr-act],[data-ucr-bulk],[data-ucr-cand],[data-ucr-goto],[data-ucr-tab],[data-ucr-reload],[data-ucr-audit-reload],[data-ucr-portal-confirm]');if(!b)return;
    if(b.hasAttribute('data-ucr-reload')){b.disabled=true;load();}
    else if(b.hasAttribute('data-ucr-audit-reload')){audit=null;auditError='';render();loadAudit();}
    else if(!data)return;
    else if(b.hasAttribute('data-ucr-portal-confirm'))portalConfirm(b.dataset.ucrPortalConfirm);
    else if(b.hasAttribute('data-ucr-run'))run(b);
    else if(b.hasAttribute('data-ucr-act'))act(b.dataset.ucrAct,Number(b.dataset.ucrId));
    else if(b.hasAttribute('data-ucr-bulk'))bulk();
    else if(b.hasAttribute('data-ucr-cand'))candidateAction(b.dataset.ucrCand,Number(b.dataset.ucrId));
    else if(b.hasAttribute('data-ucr-goto')){f.uc=b.dataset.ucrGoto;f.state='';f.source='';f.confidence='';opts.goto?.('review');}
    else if(b.hasAttribute('data-ucr-tab'))opts.goto?.(b.dataset.ucrTab);
  },{signal:listeners.signal});
  el.addEventListener('submit',e=>{if(e.target.matches('[data-ucr-portal-search]')){e.preventDefault();portalSearch(e.target);}},{signal:listeners.signal});
  el.addEventListener('change',e=>{
    if(e.target.matches('[data-ucr-filter]')){const k=e.target.dataset.ucrFilter;f[k]=e.target.value;render();el.querySelector('[data-ucr-filter="'+k+'"]')?.focus();}
    else if(e.target.matches('[data-ucr-pick]')){const id=Number(e.target.dataset.ucrPick);e.target.checked?picked.add(id):picked.delete(id);const b=el.querySelector('[data-ucr-bulk]');if(b){b.disabled=!picked.size;b.textContent='Accept '+picked.size+' selected';}}
  },{signal:listeners.signal});
  load();
  return {
    show,reload:load,
    // Field-state hints for the use-case form: what the sources say about each field.
    hints(id){
      if(!data)return {};const r=uc(id);if(!r||!r.states)return {};const out={};
      for(const [k,st] of Object.entries(r.states)){const n=data.proposals.filter(p=>p.use_case_id===id&&p.field===k&&p.status==='open').length;
        if(st==='prefilled')out[k]='Prefilled – awaiting review: '+n+' proposed value'+(n===1?'':'s')+' in the Review tab.';
        else if(st==='conflicting')out[k]='Conflicting: '+n+' source value'+(n===1?'':'s')+' differ from the saved answer. See the Review tab.';
        else if(st==='unknown')out[k]='Recorded as unknown: not counted as complete.';}
      return out;
    },
    // Tab badges: open proposals and drafts for editors, prefilled fields for readers.
    counts(){if(!data)return null;const q=k=>(data.queue.find(x=>x.key===k)||{}).count||0;return {review:data.can_edit?data.proposals.filter(p=>p.status==='open'&&p.use_case_id).length+data.candidates.length:q('prefilled')+q('conflicting'),failed:q('failed')+q('stale')};},
    destroy(){alive=false;listeners.abort();for(const d of [...dialogs])d.close();el.replaceChildren();},
    busy(){return dialogs.size>0||inflight>0||running||portal.loading;}
  };
}
root.AIGovernanceUseCaseReview={mount};
})(window);
