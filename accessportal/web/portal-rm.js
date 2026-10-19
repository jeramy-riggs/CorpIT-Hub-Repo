/* portal-rm.js — Request Management (2026-09-24; v2: Word/PDF/Print exports in the request drawer). One place to find and manage every request across
   every form. Loads after the console's own script and REPLACES its list/dashboard/audit renderers with
   registry-driven versions; everything else (roles, drawer, decisions, Approval Access, admin pages,
   authentication) is the console's own code, untouched.
     Overview        attention cards · needs-me shortlist · recent activity · per-type tiles
     Needs my action what the signed-in approver can decide, oldest first (page id 'pending')
     All requests    unified feed (requests + acknowledgment records) · search with prefixes · chips · saved views · paging
     Completed       finished workflows + records · outcome / completed-date filters
     Audit trail     one chronological stream across every request in scope
   Data: S.reqs (console's own /api/portal/requests, server-scoped) + /api/portal/acknowledgments (admin) or
   ?scope=team (managers) via the ack module. No new write paths. */
(function(){
  'use strict';
  var X=window.APX; if(!X||!X.S){ console.warn('[rm] console hooks missing (approver.html not patched)'); return; }
  var S=X.S, esc=X.esc, typeIc=X.typeIc, typeLabel=X.typeLabel, stepLabel=X.stepLabel, isMine=X.isMine, myReqs=X.myReqs, curStepKey=X.curStepKey, fmtDate=X.fmtDate, fmtDT=X.fmtDT, ago=X.ago, toast=X.toast, prettyNote=X.prettyNote, loadRequests=X.loadRequests;
  var RM=window.RM={};
  var PAGE_SIZE=50, STORE='apv4_rm_views_v1';
  var F={q:'',type:'',status:'',stage:'',approver:'',dept:'',from:'',to:'',cfrom:'',cto:'',outcome:'',page:1,sort:'newest'};
  var A={q:'',event:'',actor:'',type:'',from:'',to:'',page:1};
  var acks=null, ackAt=0, ackScope=null;
  var LABELS={dashboard:'Overview',pending:'Needs my action',all:'All requests',completed:'Completed',audit:'Audit trail'};
  var E=esc; function $(id){ return document.getElementById(id); }

  /* ── registry: every form the dashboard knows about ─────────────────────── */
  function registry(){
    var out={}, rt=(S.roles&&S.roles.request_types)||{};
    Object.keys(rt).forEach(function(k){ out[k]={key:k,label:rt[k].label||k,prefix:rt[k].prefix||k.toUpperCase(),kind:'approval',workflow:rt[k].workflow||[]}; });
    if(ackVisible()) out.ack={key:'ack',label:'Claude Access – Artificial Intelligence Policy Acknowledgment',prefix:'ACK',kind:'record',workflow:[]};
    return out;
  }
  function ackVisible(){ return S.role==='admin' || ((S.me||{}).team_ack_count|0)>0; }
  function typeChip(k){
    if(k==='ack') return '<span style="display:inline-flex;align-items:center;gap:7px"><span class="apv4-type-ic art" style="background:linear-gradient(135deg,#0d2818,#166534);color:#78BE20;width:26px;height:26px;border-radius:7px;display:inline-flex;align-items:center;justify-content:center;font-size:12px">✍</span><span style="font-weight:700;color:#111827">Claude Access &ndash; Artificial Intelligence Policy Acknowledgment</span></span>';
    return '<span style="display:inline-flex;align-items:center;gap:7px">'+(window.typeIc?typeIc(k):'')+'<span style="font-weight:700;color:#111827">'+E(typeLabel(k))+'</span></span>';
  }

  /* ── unified row model ──────────────────────────────────────────────────── */
  function stageOf(r){
    var wf=r.workflow||[], n=wf.length;
    if(r.status==='pending') return {done:r.current_step|0,total:n,cur:true,label:((r.current_step|0)+1)+'/'+n+' '+stepLabel(wf[r.current_step]||'')};
    if(r.status==='approved') return {done:n,total:n,cur:false,label:n+'/'+n+' done'};
    var lastIdx=(r.approvals||[]).filter(function(a){return a.status&&a.status!=='pending';}).length;
    return {done:Math.max(0,lastIdx-1),total:n,cur:false,fail:r.status==='rejected',label:(r.status==='rejected'?'stopped at ':'returned at ')+stepLabel(wf[Math.max(0,lastIdx-1)]||'')};
  }
  function awaiting(r){
    if(r.status!=='pending') return '—';
    var k=(r.workflow||[])[r.current_step]; if(!k) return '—';
    var you=isMine(r);
    var who='';
    if(k==='manager'){ var s=r.submitter||{}; who=s.manager_name||s.manager_email||''; }
    else { var st=(S.roles.steps||[]).find(function(x){return x.step===k;}); who=(st&&st.recipient&&(st.recipient.name||st.recipient.email))||''; }
    return (you?'<b style="color:#b45309">You</b>':E(who||'—'))+'<div style="font-size:11px;color:#6b7280">'+E(stepLabel(k))+'</div>';
  }
  function completedAt(r){
    if(r.status==='pending') return '';
    var d=(r.approvals||[]).filter(function(a){return a.decided_at;}).map(function(a){return a.decided_at;}).sort().pop();
    return d||r.updated_at||'';
  }
  function ARC(){ return window.RMARC||null; }   /* ARCHIVE hooks (portal-archive.js) */
  function unify(){
    var rows=myReqs().filter(function(r){ return !r.archived_at; }).map(function(r){ var s=r.submitter||{}; return {kind:'approval',id:r.id,type:r.type,name:s.name||'',email:s.email||'',dept:s.dept||'',manager:s.manager_email||'',created:r.created_at||'',updated:r.updated_at||'',completed:completedAt(r),status:r.status,stage:stageOf(r),stageKey:curStepKey(r),mine:isMine(r),priority:r.priority,raw:r}; });
    (acks||[]).forEach(function(a){ rows.push({kind:'record',id:'ACK-'+String(a.id).padStart(6,'0'),ackId:a.id,type:'ack',name:a.name||'',email:a.email||'',dept:a.dept||'',manager:a.manager_email||'',created:a.created_at||'',updated:a.created_at||'',completed:a.created_at||'',status:a.status==='completed'?'completed':'requires_reack',stage:{done:1,total:1,cur:false,label:'AI Policy v'+a.policy_version},stageKey:'',mine:false,raw:a}); });
    return rows;
  }
  function loadAcks(){
    if(!ackVisible()) { acks=[]; return Promise.resolve(); }
    var scope=S.role==='admin'?'all':'team';
    if(acks&&ackScope===scope&&Date.now()-ackAt<60000) return Promise.resolve();
    return fetch('/api/portal/acknowledgments?form=cla'+(scope==='team'?'&scope=team':''),{credentials:'same-origin'}).then(function(r){return r.json();}).then(function(j){ acks=(j&&j.data&&j.data.rows)||[]; ackAt=Date.now(); ackScope=scope; }).catch(function(){ acks=[]; });
  }

  /* ── presentation ───────────────────────────────────────────────────────── */
  function pill(st){
    var m={pending:['#fef3c7','#d97706','⏳ Awaiting approval'],approved:['#d1fae5','#059669','✓ Approved'],rejected:['#fee2e2','#dc2626','✕ Rejected'],returned:['#e0f2fe','#0284c7','↩ Returned'],completed:['#d1fae5','#059669','✓ Completed'],requires_reack:['#e0f2fe','#0284c7','↻ Re-acknowledge'],draft:['#f3f4f6','#6b7280','Draft']}[st]||['#f3f4f6','#6b7280',E(st)];
    return '<span class="apv4-pill" style="background:'+m[0]+';color:'+m[1]+';white-space:nowrap">'+m[2]+'</span>';
  }
  function dots(sg){ var h=''; for(var i=0;i<sg.total;i++){ var c=i<sg.done?'#059669':(sg.fail&&i===sg.done?'#dc2626':(sg.cur&&i===sg.done?'#d97706':'#e5e7eb')); var ring=(sg.cur&&i===sg.done)?';box-shadow:0 0 0 3px #fef3c7':''; h+='<i style="width:9px;height:9px;border-radius:50%;background:'+c+';display:inline-block'+ring+'"></i>'; } return '<span style="display:inline-flex;gap:3px;align-items:center">'+h+'<small style="margin-left:6px;color:#6b7280;font-size:11px">'+E(sg.label)+'</small></span>'; }
  function fmtD(s){ return s?fmtDate(s):'—'; }
  function ageDays(s){ return s?Math.floor((Date.now()-new Date(s).getTime())/86400000):0; }
  function openRow(u){ if(u.kind==='record'){ if(window.portalAck&&window.portalAck.openRecord) window.portalAck.openRecord(u.ackId); else toast('Acknowledgment module not loaded',true); } else AP.openReq(u.id); }
  window.__rmOpen=function(kind,id){ var u=unify().find(function(x){return x.kind===kind&&String(x.kind==='record'?x.ackId:x.id)===String(id);}); if(u) openRow(u); };

  function tr(u,opts){
    opts=opts||{};
    var hl=u.mine?' style="background:#fffdf5"':'';
    var open='onclick="window.__rmOpen(\''+u.kind+'\','+(u.kind==='record'?u.ackId:'\''+E(u.id)+'\'')+')"';
    return '<tr class="click"'+hl+' '+open+' data-rm-kind="'+u.kind+'" data-rm-id="'+E(u.kind==='record'?u.ackId:u.id)+'">'
      +(ARC()&&opts.sel?ARC().selCell(u):'')
      +'<td>'+typeChip(u.type)+'<div style="font-family:ui-monospace,monospace;font-size:11.5px;color:#147299;margin:2px 0 0 33px">'+E(u.id)+'</div></td>'
      +'<td><b style="color:#111827">'+E(u.name||'—')+'</b><div style="font-size:11.5px;color:#6b7280">'+E(u.dept||'')+'</div></td>'
      +'<td style="white-space:nowrap">'+fmtD(u.created)+(u.kind==='approval'&&u.status==='pending'&&ageDays(u.created)>5?'<div style="font-size:11px;color:#dc2626">'+ageDays(u.created)+'d old</div>':'')+'</td>'
      +'<td>'+dots(u.stage)+'</td>'
      +(opts.completed?'<td style="white-space:nowrap">'+fmtD(u.completed)+'</td>':'<td>'+(u.kind==='record'?'—':awaiting(u.raw))+'</td>')
      +'<td>'+pill(u.status)+(u.raw&&u.raw.priority==='high'&&u.status==='pending'?' <span class="apv4-pill" style="background:#fee2e2;color:#dc2626">High</span>':'')+'</td>'
      +'<td style="white-space:nowrap;color:#6b7280">'+(ago?ago(u.updated):fmtD(u.updated))+'</td>'
      +'<td style="text-align:right;white-space:nowrap"><button class="apv4-btn sm" '+open.replace('onclick="','onclick="event.stopPropagation();')+'>Open</button></td></tr>';
  }
  function thead(completed,sel){ return '<thead><tr>'+(sel&&ARC()?ARC().selHead():'')+'<th>Request</th><th>Requester</th><th>Submitted</th><th>Workflow</th><th>'+(completed?'Completed':'Awaiting')+'</th><th>'+(completed?'Outcome':'Status')+'</th><th>Updated</th><th></th></tr></thead>'; }
  function empty(msg){ return '<div class="apv4-empty" style="padding:28px;text-align:center;color:#6b7280">'+msg+'</div>'; }

  /* ── search: free text + prefixes ───────────────────────────────────────── */
  function parseQ(q){
    var out={text:[]}; String(q||'').split(/\s+/).forEach(function(t){ if(!t) return; var m=t.match(/^(id|type|dept|department|approver|status|stage|requester|manager|completed|submitted):(.+)$/i); if(m){ var k=m[1].toLowerCase(); if(k==='department')k='dept'; out[k]=m[2].toLowerCase(); } else out.text.push(t.toLowerCase()); });
    return out;
  }
  function matches(u,f,pq){
    if(f.type&&u.type!==f.type) return false;
    if(f.status&&u.status!==f.status) return false;
    if(f.stage&&u.stageKey!==f.stage) return false;
    if(f.dept&&(u.dept||'').toLowerCase().indexOf(f.dept.toLowerCase())<0) return false;
    if(f.from&&u.created.slice(0,10)<f.from) return false;
    if(f.to&&u.created.slice(0,10)>f.to) return false;
    if(f.cfrom&&(!u.completed||u.completed.slice(0,10)<f.cfrom)) return false;
    if(f.cto&&(!u.completed||u.completed.slice(0,10)>f.cto)) return false;
    if(f.approver){ var ap=f.approver.toLowerCase(); if(ap==='me'){ if(!u.mine) return false; } else { var hay=awaitingText(u).toLowerCase(); if(hay.indexOf(ap)<0) return false; } }
    if(pq.id&&u.id.toLowerCase().indexOf(pq.id)<0) return false;
    if(pq.type){ var reg=registry()[u.type]||{}; if(u.type!==pq.type&&(reg.prefix||'').toLowerCase()!==pq.type&&(reg.label||'').toLowerCase().indexOf(pq.type)<0) return false; }
    if(pq.dept&&(u.dept||'').toLowerCase().indexOf(pq.dept)<0) return false;
    if(pq.status&&u.status.indexOf(pq.status)<0) return false;
    if(pq.stage&&(u.stageKey.indexOf(pq.stage)<0&&stepLabel(u.stageKey).toLowerCase().indexOf(pq.stage)<0)) return false;
    if(pq.requester&&((u.name||'')+' '+(u.email||'')).toLowerCase().indexOf(pq.requester)<0) return false;
    if(pq.manager&&(u.manager||'').toLowerCase().indexOf(pq.manager)<0) return false;
    if(pq.approver){ if(pq.approver==='me'){ if(!u.mine) return false; } else if(awaitingText(u).toLowerCase().indexOf(pq.approver)<0) return false; }
    if(pq.completed&&(u.completed||'').indexOf(pq.completed)<0) return false;
    if(pq.submitted&&(u.created||'').indexOf(pq.submitted)<0) return false;
    if(pq.text.length){ var blob=(u.id+' '+u.name+' '+u.email+' '+u.dept+' '+u.manager+' '+typeLabel(u.type)+' '+(registry()[u.type]||{}).label+' '+u.status+' '+awaitingText(u)+' '+JSON.stringify(u.raw&&u.raw.details||{})).toLowerCase(); for(var i=0;i<pq.text.length;i++) if(blob.indexOf(pq.text[i])<0) return false; }
    return true;
  }
  function awaitingText(u){ if(u.kind!=='approval'||u.status!=='pending') return ''; var k=u.stageKey; var s=u.raw.submitter||{}; if(k==='manager') return (s.manager_name||'')+' '+(s.manager_email||'')+' manager'; var st=(S.roles.steps||[]).find(function(x){return x.step===k;}); return stepLabel(k)+' '+((st&&st.recipient&&((st.recipient.name||'')+' '+(st.recipient.email||'')))||''); }
  function sortRows(rows,how){
    var key={newest:function(a,b){return (b.created||'').localeCompare(a.created||'');},oldest:function(a,b){return (a.created||'').localeCompare(b.created||'');},updated:function(a,b){return (b.updated||'').localeCompare(a.updated||'');},completed:function(a,b){return (b.completed||'').localeCompare(a.completed||'');}}[how]||null;
    return key?rows.slice().sort(key):rows;
  }

  /* ── saved views (per user, this browser) ───────────────────────────────── */
  function views(){ try{ return JSON.parse(localStorage.getItem(STORE)||'[]'); }catch(e){ return []; } }
  function saveViews(v){ try{ localStorage.setItem(STORE,JSON.stringify(v)); }catch(e){} }
  function viewChips(page){
    var built=[{n:'My open reviews',f:{approver:'me',status:'pending'}},{n:'Older than 5 days',f:{status:'pending',to:new Date(Date.now()-5*86400000).toISOString().slice(0,10)}},{n:'High priority',f:{q:'',status:'pending',prio:'high'}}];
    var mine=views(), all=built.concat(mine.map(function(v){return {n:v.n,f:v.f,user:true};}));
    return '<div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:10px"><span style="font-size:11px;color:#6b7280;font-weight:800;letter-spacing:.05em">VIEWS</span>'
      +all.map(function(v,i){ return '<span class="apv4-pill rm-view" data-i="'+i+'" style="background:#fff;border:1px solid #cbd5e1;color:#334155;cursor:pointer;padding:4px 10px">'+E(v.n)+(v.user?' <b data-del="'+(i-built.length)+'" style="margin-left:4px;color:#9ca3af">×</b>':'')+'</span>'; }).join('')
      +'<span class="apv4-pill rm-save" style="background:#fff;border:1px dashed #cbd5e1;color:#6b7280;cursor:pointer;padding:4px 10px">＋ Save current filter</span></div>';
  }
  function applyView(page,i){
    var built=[{approver:'me',status:'pending'},{status:'pending',to:new Date(Date.now()-5*86400000).toISOString().slice(0,10)},{status:'pending',prio:'high'}];
    var mine=views().map(function(v){return v.f;}); var f=(built.concat(mine))[i]; if(!f) return;
    resetF(); Object.keys(f).forEach(function(k){F[k]=f[k];}); RM.renderList(page);
  }

  /* ── filter bar ─────────────────────────────────────────────────────────── */
  function sel(id,label,opts,val){ return '<select class="apv4-field rm-f" id="'+id+'" style="margin:0;width:auto;max-width:200px"><option value="">'+label+'</option>'+opts.map(function(o){return '<option value="'+E(o[0])+'"'+(String(val)===String(o[0])?' selected':'')+'>'+E(o[1])+'</option>';}).join('')+'</select>'; }
  function filterBar(page,rows){
    var reg=registry(), types=Object.keys(reg).map(function(k){return [k,reg[k].label];});
    var depts=[]; rows.forEach(function(u){ if(u.dept&&depts.indexOf(u.dept)<0) depts.push(u.dept); }); depts.sort();
    var stages=(S.roles.steps||[]).map(function(s){return [s.step,s.label];});
    var statuses=page==='completed'?[['approved','Approved'],['rejected','Rejected'],['returned','Returned'],['completed','Completed (record)'],['requires_reack','Re-acknowledge']]:[['pending','Awaiting approval'],['approved','Approved'],['rejected','Rejected'],['returned','Returned'],['completed','Completed (record)'],['requires_reack','Re-acknowledge']];
    return '<div class="apv4-card" style="margin-bottom:12px"><div style="padding:12px 16px;display:flex;gap:8px;align-items:center;flex-wrap:wrap;border-bottom:1px solid #e5e7eb">'
      +'<input class="apv4-field" id="rm-q" style="flex:1;min-width:260px;margin:0" placeholder="Search — ID, requester, department, approver… or type:aia dept:finance approver:me status:pending" value="'+E(F.q)+'">'
      +'<button class="apv4-btn sm pri" id="rm-go">Search</button><button class="apv4-btn sm" id="rm-clear">Clear</button>'
      +'<span style="margin-left:auto;display:flex;gap:6px"><button class="apv4-btn sm" id="rm-csv">⬇ CSV</button><button class="apv4-btn sm" id="rm-refresh" title="Refresh">↻</button></span></div>'
      +'<div style="padding:10px 16px;display:flex;gap:6px;flex-wrap:wrap;align-items:center;background:#fafafa">'
      +'<span style="font-size:11px;color:#6b7280;font-weight:800;letter-spacing:.05em;margin-right:4px">FILTERS</span>'
      +sel('rm-type','Type: all',types,F.type)+sel('rm-status',(page==='completed'?'Outcome':'Status')+': all',statuses,F.status)
      +(page!=='completed'?sel('rm-stage','Stage: any',stages,F.stage):'')
      +sel('rm-dept','Department: any',depts.map(function(d){return [d,d];}),F.dept)
      +(page!=='completed'?'<input class="apv4-field rm-f" id="rm-approver" style="margin:0;width:150px" placeholder="Approver (or me)" value="'+E(F.approver)+'">':'')
      +'<span style="font-size:11px;color:#6b7280;margin-left:6px">Submitted</span><input type="date" class="apv4-field rm-f" id="rm-from" style="margin:0;width:140px" value="'+E(F.from)+'"><input type="date" class="apv4-field rm-f" id="rm-to" style="margin:0;width:140px" value="'+E(F.to)+'">'
      +(page!=='pending'?'<span style="font-size:11px;color:#6b7280;margin-left:6px">Completed</span><input type="date" class="apv4-field rm-f" id="rm-cfrom" style="margin:0;width:140px" value="'+E(F.cfrom)+'"><input type="date" class="apv4-field rm-f" id="rm-cto" style="margin:0;width:140px" value="'+E(F.cto)+'">':'')
      +sel('rm-sort','Sort',[['newest','Newest first'],['oldest','Oldest first'],['updated','Recently updated'],['completed','Recently completed']],F.sort)
      +'</div></div>';
  }
  function bindBar(page,rows,all){
    var pg=$('apv4-page-'+page); function Q(id){ return pg.querySelector('#'+id); }
    function read(){ F.q=Q('rm-q').value; ['type','status','stage','dept','approver','from','to','cfrom','cto','sort'].forEach(function(k){ var e=Q('rm-'+k); if(e) F[k]=e.value; }); F.page=1; }
    Q('rm-go').onclick=function(){ read(); RM.renderList(page); };
    Q('rm-q').onkeydown=function(e){ if(e.key==='Enter'){ read(); RM.renderList(page); } };
    Q('rm-clear').onclick=function(){ resetF(); RM.renderList(page); };
    pg.querySelectorAll('.rm-f').forEach(function(e){ e.onchange=function(){ read(); RM.renderList(page); }; });
    Q('rm-csv').onclick=function(){ csv(rows,page); };
    Q('rm-refresh').onclick=function(){ acks=null; if(window.AP&&typeof AP.refresh==='function') AP.refresh(); else loadRequests(); };
    pg.querySelectorAll('.rm-view').forEach(function(c){ c.onclick=function(e){ var d=e.target.getAttribute&&e.target.getAttribute('data-del'); if(d!=null){ var v=views(); v.splice(+d,1); saveViews(v); RM.renderList(page); return; } applyView(page,+c.getAttribute('data-i')); }; });
    var sv=pg.querySelector('.rm-save'); if(sv) sv.onclick=function(){ var n=prompt('Name this view'); if(!n) return; var v=views(); var f={}; Object.keys(F).forEach(function(k){ if(F[k]&&k!=='page') f[k]=F[k]; }); v.push({n:n,f:f}); saveViews(v); RM.renderList(page); };
    pg.querySelectorAll('[data-pg]').forEach(function(b){ b.onclick=function(){ F.page=+b.getAttribute('data-pg'); RM.renderList(page); }; });
  }
  function csv(rows,page){
    var cols=['id','type','name','email','dept','manager','status','stage','awaiting','created','completed','updated'];
    var lines=[cols.join(',')].concat(rows.map(function(u){ var o={id:u.id,type:(registry()[u.type]||{}).label||u.type,name:u.name,email:u.email,dept:u.dept,manager:u.manager,status:u.status,stage:u.stage.label,awaiting:awaitingText(u).trim(),created:u.created,completed:u.completed,updated:u.updated}; return cols.map(function(c){var v=o[c]==null?'':String(o[c]); return /[",\n]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v;}).join(','); }));
    var a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([lines.join('\n')],{type:'text/csv'})); a.download='requests-'+page+'-'+new Date().toISOString().slice(0,10)+'.csv'; a.click();
  }
  function pager(total,page){
    var n=Math.max(1,Math.ceil(total/PAGE_SIZE)); if(n<=1) return '<span>'+total+' result'+(total===1?'':'s')+'</span>';
    var h='<span>'+total+' results · page '+page+' of '+n+'</span><span style="display:flex;gap:4px">';
    if(page>1) h+='<button class="apv4-btn sm" data-pg="'+(page-1)+'">←</button>';
    for(var i=Math.max(1,page-2);i<=Math.min(n,page+2);i++) h+='<button class="apv4-btn sm'+(i===page?' pri':'')+'" data-pg="'+i+'">'+i+'</button>';
    if(page<n) h+='<button class="apv4-btn sm" data-pg="'+(page+1)+'">→</button>';
    return h+'</span>';
  }

  /* ── views ──────────────────────────────────────────────────────────────── */
  RM.renderList=function(page){
    var el=$('apv4-page-'+page); if(!el) return;
    el.innerHTML='<div style="padding:8px 0;color:#6b7280;font-size:13px">Loading…</div>';
    loadAcks().then(function(){
      var all=unify(), pq=parseQ(F.q);
      var base=page==='pending'?all.filter(function(u){return u.mine;}):page==='completed'?all.filter(function(u){return u.status!=='pending';}):all;
      var how=(page==='pending'&&F.sort==='newest')?'oldest':F.sort;
      var rows=sortRows(base.filter(function(u){ return matches(u,F,pq)&&(!F.prio||(u.raw&&u.raw.priority===F.prio)); }),how);
      var total=rows.length, start=(F.page-1)*PAGE_SIZE, slice=rows.slice(start,start+PAGE_SIZE);
      var old=base.filter(function(u){return u.status==='pending'&&ageDays(u.created)>5;}).length;
      var sub={pending:(S.role==='admin'||S.role==='all')?'Requests waiting at a step you can decide · oldest first':'Requests waiting at your step · oldest first',all:'Every request and record in your scope · '+Object.keys(registry()).length+' form types',completed:'Workflows that have finished — approved, rejected, returned — and acknowledgment records'}[page];
      var selOn=!!(ARC()&&ARC().enabled(page));
      el.innerHTML='<div style="margin-bottom:12px"><div class="apv4-page-title">'+LABELS[page]+'</div><div class="apv4-page-sub">'+sub+' · '+base.length+' total'+(page==='pending'&&old?' · <span style="color:#dc2626;font-weight:700">'+old+' older than 5 days</span>':'')+'</div></div>'
        +(page==='all'?viewChips(page):'')
        +filterBar(page,base)
        +(selOn?ARC().bulkBar(page):'')
        +'<div class="apv4-card">'+(slice.length?'<div style="overflow-x:auto"><table class="apv4-tbl">'+thead(page==='completed',selOn)+'<tbody>'+slice.map(function(u){return tr(u,{completed:page==='completed',sel:selOn});}).join('')+'</tbody></table></div>':empty(page==='pending'?'Nothing is waiting at your step.':'No requests match.'))
        +'<div style="padding:10px 16px;font-size:12px;color:#6b7280;display:flex;justify-content:space-between;align-items:center;border-top:1px solid #f3f4f6">'+pager(total,F.page)+'</div></div>';
      bindBar(page,rows,all);
      if(selOn) ARC().bind(page);
    });
  };


  RM.renderDashboard=function(){
    var el=$('apv4-page-dashboard'); if(!el) return;
    el.innerHTML='<div style="padding:8px 0;color:#6b7280;font-size:13px">Loading…</div>';
    loadAcks().then(function(){
      var all=unify(), reg=registry();
      var mine=all.filter(function(u){return u.mine;}).sort(function(a,b){return (a.created||'').localeCompare(b.created||'');});
      var old=mine.filter(function(u){return ageDays(u.created)>5;}).length;
      var inrev=all.filter(function(u){return u.kind==='approval'&&u.status==='pending';}).length;
      var cut=new Date(Date.now()-30*86400000).toISOString();
      var done30=all.filter(function(u){return u.kind==='approval'&&u.status!=='pending'&&u.completed>=cut;});
      var ackRows=all.filter(function(u){return u.kind==='record';}), ackOk=ackRows.filter(function(u){return u.status==='completed';}).length;
      function stat(n,label,sub,bg,ic,page,hot){ return '<div class="apv4-stat-card" onclick="AP.nav(\''+page+'\')" style="'+(hot?'border-color:#fcd34d;background:#fffbeb':'')+'"><div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px"><div class="apv4-type-ic art" style="background:'+bg+';color:#fff;width:34px;height:34px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:16px">'+ic+'</div><span style="font-size:13px;color:#9ca3af">›</span></div><div class="apv4-stat-n">'+n+'</div><div class="apv4-stat-l">'+label+'</div><div class="apv4-stat-s">'+sub+'</div></div>'; }
      var ev=auditStream(all).filter(function(e){return e.kind!=='notification';}).slice(0,6);
      var byType=Object.keys(reg).map(function(k){ var n=k==='ack'?ackRows.length:all.filter(function(u){return u.type===k&&u.status==='pending';}).length; return '<div class="rm-tile" data-type="'+k+'" style="border:1px solid #e5e7eb;border-radius:10px;padding:10px 12px;cursor:pointer;background:#fff"><div style="display:flex;justify-content:space-between;align-items:center;gap:6px">'+(k==='ack'?typeChip(k).replace(/<span style="font-weight:700;color:#111827">[^<]*<\/span>/,'<span style="font-weight:700;color:#111827">'+E(reg[k].prefix)+'</span>'):typeChip(k).replace(E(reg[k].label),E(reg[k].prefix)))+'<b style="font-size:18px">'+n+'</b></div><div style="font-size:11px;color:#6b7280;margin-top:4px">'+E(reg[k].label)+(k==='ack'?' · records':' · open')+'</div></div>'; }).join('');
      var adminNote=''; if(S.role==='admin'){ var un=(S.roles.steps||[]).filter(function(s){return !s.routable;}); if(un.length) adminNote='<div class="apv4-note warn" style="max-width:none"><strong>'+un.length+' approval step'+(un.length===1?' has':'s have')+' no notification recipient:</strong> '+un.map(function(s){return E(s.label);}).join(', ')+'. Set them under Notification Emails.</div>'; }
      el.innerHTML=adminNote
        +'<div class="apv4-grid4">'+stat(mine.length,'Needs my action',old?old+' older than 5 days':'waiting at a step you approve','linear-gradient(135deg,#78350f,#d97706)','⏱','pending',mine.length>0)
        +stat(inrev,'In review','at any step · all forms','linear-gradient(135deg,#075985,#0284c7)','↻','all')
        +stat(done30.length,'Completed · 30 days',done30.filter(function(u){return u.status==='approved';}).length+' approved · '+done30.filter(function(u){return u.status==='rejected';}).length+' rejected · '+done30.filter(function(u){return u.status==='returned';}).length+' returned','linear-gradient(135deg,#065f46,#059669)','✓','completed')
        +(ackVisible()?stat(ackRows.length,'Acknowledgments',ackOk+' on current AI Policy · '+(ackRows.length-ackOk)+' to re-acknowledge','linear-gradient(135deg,#0d2818,#3a7d2c)','✍','completed'):stat(all.filter(function(u){return u.status==='pending'&&u.raw.priority==='high';}).length,'High priority','pending across your scope','linear-gradient(135deg,#4a0d2e,#831843)','⚑','pending'))+'</div>'
        +'<div style="display:grid;grid-template-columns:3fr 2fr;gap:14px;margin-bottom:14px">'
        +'<div class="apv4-card"><div class="apv4-card-hd"><div><b>Needs my action</b><span>oldest first</span></div><button class="apv4-link" onclick="AP.nav(\'pending\')">View all '+mine.length+' →</button></div>'+(mine.length?'<div style="overflow-x:auto"><table class="apv4-tbl"><tbody>'+mine.slice(0,5).map(function(u){ return '<tr class="click" style="background:#fffdf5" onclick="AP.openReq(\''+E(u.id)+'\')"><td>'+typeChip(u.type)+'<div style="font-family:ui-monospace,monospace;font-size:11.5px;color:#147299;margin:2px 0 0 33px">'+E(u.id)+'</div></td><td><b>'+E(u.name)+'</b><div style="font-size:11.5px;color:#6b7280">'+E(u.dept)+'</div></td><td>'+dots(u.stage)+'</td><td>'+pill('pending')+'<div style="font-size:11px;color:#6b7280">'+ageDays(u.created)+'d at your step</div></td><td style="text-align:right"><button class="apv4-btn sm" onclick="event.stopPropagation();AP.openReq(\''+E(u.id)+'\')">Open</button></td></tr>'; }).join('')+'</tbody></table></div>':empty('Nothing is waiting at your step.'))+'</div>'
        +'<div class="apv4-card"><div class="apv4-card-hd"><div><b>Recent activity</b><span>latest events in your scope</span></div><button class="apv4-link" onclick="AP.nav(\'audit\')">Audit trail →</button></div>'+(ev.length?ev.map(evRow).join(''):empty('No activity yet.'))+'</div></div>'
        +'<div class="apv4-card"><div class="apv4-card-hd"><div><b>By request type</b><span>open items per form · click a tile to filter All requests</span></div></div><div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:10px;padding:14px 16px">'+byType+'</div></div>';
      el.querySelectorAll('.rm-tile').forEach(function(t){ t.onclick=function(){ resetF(); F.type=t.getAttribute('data-type'); AP.nav('all'); }; });
    });
  };

  /* ── audit trail: one stream ─────────────────────────────────────────────── */
  var EV={submitted:['#d97706','＋ Submitted'],approved:['#059669','✓ Approved'],rejected:['#dc2626','✕ Rejected'],returned:['#0284c7','↩ Returned'],notification:['#6b7280','✉ Notification'],acknowledged:['#3a7d2c','✍ Acknowledged'],assigned:['#6b7280','⇄ Assigned'],edited:['#6b7280','✎ Edited'],other:['#9ca3af','• Event']};
  function evKind(e){ var s=String(e||'').toLowerCase(); if(s.indexOf('submit')>-1||s==='created') return 'submitted'; if(s.indexOf('reject')>-1) return 'rejected'; if(s.indexOf('return')>-1) return 'returned'; if(s.indexOf('approv')>-1) return 'approved'; if(s.indexOf('notif')>-1||s.indexOf('mail')>-1) return 'notification'; if(s.indexOf('acknowledg')>-1) return 'acknowledged'; if(s.indexOf('assign')>-1||s.indexOf('reassign')>-1) return 'assigned'; if(s.indexOf('edit')>-1||s.indexOf('correct')>-1) return 'edited'; return 'other'; }
  function auditStream(all){
    var out=[];
    all.forEach(function(u){
      if(u.kind==='approval') (u.raw.audit||[]).forEach(function(e){ out.push({when:e.created_at||'',event:e.event||'',kind:evKind(e.event),actor:e.actor||'',role:e.role||'',note:(window.prettyNote?prettyNote(e.note):e.note)||'',u:u}); });
      else out.push({when:u.created,event:'acknowledgment.recorded',kind:'acknowledged',actor:u.email,role:'employee',note:'AI Policy v'+(u.raw.policy_version||'')+(u.raw.signature_kind?' · '+u.raw.signature_kind+' signature':''),u:u});
    });
    return out.sort(function(a,b){return (b.when||'').localeCompare(a.when||'');});
  }
  function evRow(e){ var k=EV[e.kind]||EV.other; return '<div style="display:flex;gap:12px;padding:10px 16px;border-bottom:1px solid #f3f4f6;font-size:12.5px;align-items:flex-start;cursor:pointer" onclick="window.__rmOpen(\''+e.u.kind+'\','+(e.u.kind==='record'?e.u.ackId:'\''+E(e.u.id)+'\'')+')"><span style="width:10px;height:10px;border-radius:50%;margin-top:4px;flex:none;background:'+k[0]+'"></span><span style="color:#6b7280;font-size:11.5px;white-space:nowrap;width:118px;flex:none">'+fmtDT(e.when)+'</span><span style="min-width:0"><b>'+E(e.actor)+'</b> '+E(k[1].replace(/^\S+\s/,'').toLowerCase())+' <span style="font-family:ui-monospace,monospace;color:#147299">'+E(e.u.id)+'</span>'+(e.note?' · <span style="color:#4b5563">'+E(String(e.note).slice(0,140))+'</span>':'')+'</span></div>'; }
  RM.renderAudit=function(){
    var el=$('apv4-page-audit'); if(!el) return;
    el.innerHTML='<div style="padding:8px 0;color:#6b7280;font-size:13px">Loading…</div>';
    loadAcks().then(function(){
      var all=unify(), reg=registry(), stream=auditStream(all);
      var actors=[]; stream.forEach(function(e){ if(e.actor&&actors.indexOf(e.actor)<0) actors.push(e.actor); }); actors.sort();
      var rows=stream.filter(function(e){
        if(A.event&&e.kind!==A.event) return false; if(A.actor&&e.actor!==A.actor) return false; if(A.type&&e.u.type!==A.type) return false;
        if(A.from&&e.when.slice(0,10)<A.from) return false; if(A.to&&e.when.slice(0,10)>A.to) return false;
        if(A.q){ var q=A.q.toLowerCase(); if((e.u.id+' '+e.actor+' '+e.event+' '+e.note+' '+e.u.name).toLowerCase().indexOf(q)<0) return false; }
        return true; });
      var total=rows.length, start=(A.page-1)*PAGE_SIZE, slice=rows.slice(start,start+PAGE_SIZE);
      el.innerHTML='<div style="margin-bottom:12px"><div class="apv4-page-title">Audit trail</div><div class="apv4-page-sub">Who did what, when — every request and record in your scope · '+stream.length+' events</div></div>'
        +'<div class="apv4-card" style="margin-bottom:12px"><div style="padding:12px 16px;display:flex;gap:8px;align-items:center;flex-wrap:wrap"><input class="apv4-field" id="rm-aq" style="flex:1;min-width:240px;margin:0" placeholder="Search actor, request ID, note…" value="'+E(A.q)+'">'
        +sel('rm-aev','Event: all',Object.keys(EV).filter(function(k){return k!=='other';}).map(function(k){return [k,EV[k][1].replace(/^\S+\s/,'')];}),A.event)+sel('rm-aactor','Actor: anyone',actors.map(function(a){return [a,a];}),A.actor)+sel('rm-atype','Type: all',Object.keys(reg).map(function(k){return [k,reg[k].label];}),A.type)
        +'<input type="date" class="apv4-field rm-af" id="rm-afrom" style="margin:0;width:140px" value="'+E(A.from)+'"><input type="date" class="apv4-field rm-af" id="rm-ato" style="margin:0;width:140px" value="'+E(A.to)+'"><button class="apv4-btn sm pri" id="rm-ago">Apply</button><button class="apv4-btn sm" id="rm-aclear">Clear</button><button class="apv4-btn sm" id="rm-acsv" style="margin-left:auto">⬇ CSV</button></div></div>'
        +'<div class="apv4-card"><div style="overflow-x:auto"><table class="apv4-tbl"><thead><tr><th>When</th><th>Event</th><th>Request</th><th>Actor</th><th>Detail</th><th></th></tr></thead><tbody>'
        +(slice.length?slice.map(function(e){ var k=EV[e.kind]||EV.other; var open='onclick="window.__rmOpen(\''+e.u.kind+'\','+(e.u.kind==='record'?e.u.ackId:'\''+E(e.u.id)+'\'')+')"'; return '<tr class="click" '+open+'><td style="white-space:nowrap;font-family:ui-monospace,monospace;font-size:12px">'+fmtDT(e.when)+'</td><td><span class="apv4-pill" style="background:#f3f4f6;color:'+k[0]+';white-space:nowrap">'+k[1]+'</span><div style="font-size:10.5px;color:#9ca3af;margin-top:2px">'+E(e.event)+'</div></td><td>'+typeChip(e.u.type)+'<div style="font-family:ui-monospace,monospace;font-size:11.5px;color:#147299;margin:2px 0 0 33px">'+E(e.u.id)+'</div></td><td>'+E(e.actor)+(e.role?'<div style="font-size:11.5px;color:#6b7280">'+E(e.role)+'</div>':'')+'</td><td style="font-size:12.5px;color:#4b5563;max-width:420px">'+E(String(e.note).slice(0,240))+'</td><td style="text-align:right"><button class="apv4-btn sm" '+open.replace('onclick="','onclick="event.stopPropagation();')+'>Open</button></td></tr>'; }).join(''):'<tr><td colspan="6">'+empty('No events match.')+'</td></tr>')
        +'</tbody></table></div><div style="padding:10px 16px;font-size:12px;color:#6b7280;display:flex;justify-content:space-between;align-items:center;border-top:1px solid #f3f4f6">'+pager(total,A.page)+'</div></div>';
      function read(){ A.q=$('rm-aq').value; A.event=$('rm-aev').value; A.actor=$('rm-aactor').value; A.type=$('rm-atype').value; A.from=$('rm-afrom').value; A.to=$('rm-ato').value; A.page=1; }
      $('rm-ago').onclick=function(){ read(); RM.renderAudit(); }; $('rm-aq').onkeydown=function(e){ if(e.key==='Enter'){ read(); RM.renderAudit(); } };
      el.querySelectorAll('select.rm-f,.rm-af').forEach(function(x){ x.onchange=function(){ read(); RM.renderAudit(); }; });
      $('rm-aclear').onclick=function(){ A={q:'',event:'',actor:'',type:'',from:'',to:'',page:1}; RM.renderAudit(); };
      $('rm-acsv').onclick=function(){ var lines=['when,event,request,type,actor,role,detail'].concat(rows.map(function(e){ return [e.when,e.event,e.u.id,(reg[e.u.type]||{}).label||e.u.type,e.actor,e.role,e.note].map(function(v){v=v==null?'':String(v);return /[",\n]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v;}).join(','); })); var a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([lines.join('\n')],{type:'text/csv'})); a.download='audit-trail-'+new Date().toISOString().slice(0,10)+'.csv'; a.click(); };
      el.querySelectorAll('[data-pg]').forEach(function(b){ b.onclick=function(){ A.page=+b.getAttribute('data-pg'); RM.renderAudit(); }; });
    });
  };

  /* ── chrome: labels, global search (called by the console's hooks) ─────── */
  RM.afterSidebar=function(el){
    Object.keys(LABELS).forEach(function(p){ var it=$('apv4-sb-'+p); if(!it) return; var span=it.querySelector('span[style*="flex:1"]'); if(span) span.textContent=LABELS[p]; });
    el.querySelectorAll('.apv4-sb-head').forEach(function(h){ if(/^approvals$/i.test(h.textContent.trim())) h.textContent='Requests'; });
  };
  RM.afterTabs=function(){ Object.keys(LABELS).forEach(function(p){ var t=$('apv4-tab-'+p); if(t) t.textContent=LABELS[p]; }); };
  function resetF(){ F={q:'',type:'',status:'',stage:'',approver:'',dept:'',from:'',to:'',cfrom:'',cto:'',outcome:'',page:1,sort:'newest'}; }
  function globalSearch(){
    if(document.getElementById('rm-gsearch')) return;
    var bar=document.querySelector('#apv4-dash-screen .apv4-bar'); if(!bar) return;
    var brand=bar.querySelector('.apv4-brand'); if(!brand) return;
    var box=document.createElement('div'); box.id='rm-gsearch';
    box.style.cssText='flex:0 1 230px;min-width:150px;margin:0 12px;display:flex;align-items:center;gap:8px;background:#111827;border:1px solid #374151;border-radius:10px;padding:0 10px;height:34px';
    box.innerHTML='<span style="color:#9ca3af;font-size:13px">🔍</span><input id="rm-gq" placeholder="Find a request…  ( / )" style="flex:1;background:transparent;border:0;outline:0;color:#fff;font-size:13px;font-family:inherit"><kbd style="font-size:10px;background:#374151;color:#d1d5db;padding:1px 6px;border-radius:5px">/</kbd>';
    brand.parentNode.insertBefore(box, brand.nextSibling);
    var inp=box.querySelector('#rm-gq');
    inp.onkeydown=function(e){ if(e.key==='Enter'){ var v=inp.value.trim(); if(!v) return; if(/^[A-Z]{3}-\d{4}-\d{5}$/i.test(v)&&S.reqs.some(function(r){return r.id.toUpperCase()===v.toUpperCase();})){ AP.openReq(v.toUpperCase()); inp.value=''; return; } resetF(); F.q=v; AP.nav('all'); } };
    document.addEventListener('keydown',function(e){ if(e.key==='/'&&!/INPUT|TEXTAREA|SELECT/.test((e.target||{}).tagName||'')&&$('apv4-dash-screen')&&$('apv4-dash-screen').classList.contains('on')){ e.preventDefault(); inp.focus(); } });
  }
  /* ── request drawer: Word / PDF / printable exports (console's own drawer, buttons injected) ── */
  function drawerExports(){
    var hd=document.querySelector('#apv4-drawer .apv4-draw-hd'); if(!hd) return;
    var r=S.open; var box=document.getElementById('rm-dl');
    if(!r){ if(box) box.remove(); return; }
    var base='/api/portal/requests/'+encodeURIComponent(r.id)+'/record';
    if(!box){ box=document.createElement('div'); box.id='rm-dl'; box.style.cssText='display:flex;gap:6px;align-items:center;margin:0 10px 0 auto;flex:none';
      box.innerHTML='<span style="font-size:11px;color:#6b7280;font-weight:700;letter-spacing:.04em">DOWNLOAD</span>'
        +'<a class="apv4-btn sm rm-dl-a" data-f="docx" style="text-decoration:none" title="Word document">Word</a>'
        +'<a class="apv4-btn sm rm-dl-a" data-f="pdf" style="text-decoration:none" title="PDF">PDF</a>'
        +'<a class="apv4-btn sm rm-dl-a" data-f="html" target="_blank" rel="noopener" style="text-decoration:none" title="Printable view">Print</a>';
      var x=hd.querySelector('.apv4-x'); if(x) hd.insertBefore(box,x); else hd.appendChild(box); }
    box.querySelectorAll('.rm-dl-a').forEach(function(a){ var f=a.getAttribute('data-f'); a.href=base+'?format='+f; });
    if(ARC()) ARC().drawer(hd,r);
  }
  var _dm=new MutationObserver(function(){ drawerExports(); });
  var _dr=document.getElementById('apv4-drawer'); if(_dr) _dm.observe(_dr,{childList:true,subtree:true,characterData:true});
  RM.invalidateAcks=function(){ acks=null; };
  RM.onRole=function(id){ resetF(); acks=null; globalSearch(); if(ARC()) ARC().onRole(id); var sg=$('apv4-subgreeting'); if(sg&&!window.portalContentGreeting) sg.textContent='Request Management — everything waiting on you, and every request across every form.'; };
  console.info('[rm] Request Management loaded');
})();
