/* portal-governance.js — AI Governance at-a-glance + link-out (v10, 2026-10-19).
   InfoSec / Legal / administrators only (server flag). Work queue from CorpIT's hourly push,
   live Portal queue, due-soon, recent changes, workspace CTA + section tiles, admin token card. */
(function(){
  'use strict';
  var X=window.APX; if(!X||!X.S){ console.warn('[governance] console hooks missing'); return; }
  var S=X.S, esc=X.esc, toast=X.toast, fmtDT=X.fmtDT, fmtDate=X.fmtDate; var E=esc;
  function $(id){ return document.getElementById(id); }
  var PAGE='apv4-page-governance', SB='apv4-sb-governance';
  var HOST='https://corpit.nrpi.local', URL=HOST+'/ai-governance.html';
  var DATA=null, QF='all';
  function allowed(){ return !!((S.me||{}).inventory); }
  function isAdmin(){ return S.role==='admin'; }
  function api(method,path,body){
    var o={method:method,credentials:'same-origin',headers:{}};
    if(body){ o.body=JSON.stringify(body); o.headers['Content-Type']='application/json'; }
    return fetch(path,o).then(function(r){ return r.json().catch(function(){return {};}).then(function(j){ if(!r.ok||j.ok===false) throw new Error((j&&(j.error||j.message))||('HTTP '+r.status)); return j.data!==undefined?j.data:j; }); });
  }
  function pill(t,bg,fg){ return '<span class="apv4-pill" style="background:'+bg+';color:'+fg+';font-size:10.5px">'+t+'</span>'; }
  function ago(iso){ if(!iso) return ''; var d=(Date.now()-new Date(iso).getTime())/864e5; if(d<1) return '<1d'; return Math.floor(d)+'d'; }
  function dt(iso){ try{ return fmtDT?fmtDT(iso):iso; }catch(e){ return iso||''; } }
  var REASON={new_unassessed:['New approved use case','#e3f4fb','#0b5d80','Assess'],flagged_high:['Flagged: Review for High','#fee2e2','#b91c1c','Review'],no_tier:['No risk tier','#fef3c7','#b45309','Set tier'],overdue:['Review overdue','#fef3c7','#b45309','Re-review'],missing_owner:['No business owner','#e5e7eb','#4b5563','Open'],missing_evidence:['No evidence','#e5e7eb','#4b5563','Open']};
  var OWNER={infosec:['InfoSec','#e0f2fe','#0369a1'],legal:['Legal','#ede9fe','#6d28d9'],both:['InfoSec + Legal','#e5e7eb','#374151']};
  function ownerPill(o){ var m=OWNER[o]||OWNER.both; return pill(m[0],m[1],m[2]); }
  function chain(wf){ return (wf||[]).map(function(w){ var c=w.state==='done'?'#059669':w.state==='current'?'#b45309':'#9ca3af'; return '<span style="color:'+c+';font-weight:'+(w.state==='current'?'800':'600')+'">'+(w.state==='done'?'✓ ':w.state==='current'?'● ':'')+E(w.label)+'</span>'; }).join(' <span style="color:#d1d5db">→</span> '); }
  var OF='all';
  var TILES=[['Governance Dashboard','Decisions, classification, overdue work','#dashboard'],['AI Inventory','Master application catalog','#inventory'],['Risk Assessments','All 41 fields, tier, review date','#risk'],['App Coverage Gaps','Missing assessment information','#coverage'],['Governance Queue','Missing owner, purpose, evidence','#attention'],['Executive Reports','CSV export, Legal brief','#reports']];
  function link(l){ if(!l) return URL; if(l.indexOf('http')===0) return l; return URL+(l.charAt(0)==='?'||l.charAt(0)==='#'?l:'#'+l); }

  function render(){
    var el=$(PAGE); if(!el) return;
    el.innerHTML='<div style="padding:8px 0;color:#6b7280;font-size:13px">Loading…</div>';
    api('GET','/api/portal/sync/governance-summary').then(function(d){ DATA=d; draw(); }).catch(function(e){ el.innerHTML='<div class="apv4-card" style="padding:14px 18px;color:#b91c1c">'+E(e.message||'Failed to load')+'</div>'; });
  }
  function draw(){
    var el=$(PAGE); if(!el||!DATA) return;
    var sn=DATA.snapshot, st=(sn&&sn.status)||{}, att=(sn&&sn.attention)||[], due=(sn&&sn.due_soon)||[], rec=(sn&&sn.recent)||[], pq=DATA.portal_queue||[];
    var stale=sn&&((Date.now()-new Date(sn.received_at).getTime())>2*36e5);
    var counts={all:att.length}; att.forEach(function(a){ counts[a.reason]=(counts[a.reason]||0)+1; });
    var list=att.filter(function(a){ return (QF==='all'||a.reason===QF)&&(OF==='all'||(a.owner||'both')===OF||(OF!=='both'&&(a.owner||'both')==='both')); });
    var oc={all:att.length}; att.forEach(function(a){ var o=a.owner||'both'; oc[o]=(oc[o]||0)+1; });
    var held=DATA.held||[], heldLbl=held.map(function(k){ return k==='security'?'InfoSec':k==='legal'?'Legal':k; });
    var h='';
    h+='<div style="display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;margin-bottom:12px"><div><div class="apv4-page-title">AI Governance</div><div class="apv4-page-sub">'
      +(sn?'<b>'+E(st.apps!=null?st.apps:'—')+'</b> apps · <b>'+E(st.approved!=null?st.approved:'—')+'</b> approved · <b>'+E(st.need_work!=null?st.need_work:'—')+'</b> need work · synced '+E(dt(sn.received_at))+(stale?' '+pill('stale — no push in 2h','#fef3c7','#b45309'):''):'Waiting for the first CorpIT push — the work queue fills in once the AI Governance worker starts sending snapshots.')
      +'</div>'+(heldLbl.length?'<div style="font-size:12px;color:#4b5563;margin-top:2px">You hold: <b>'+E(heldLbl.join(', '))+'</b></div>':'')+'</div><div style="text-align:right"><div style="display:flex;gap:8px;justify-content:flex-end;align-items:center"><button class="apv4-btn" id="gov-refresh">↻ Refresh</button><a class="apv4-btn pri" href="'+URL+'" target="_blank" rel="noopener" style="text-decoration:none">Open AI Governance Workspace ↗</a></div><div style="font-size:11.5px;color:#6b7280;margin-top:8px;line-height:1.5"><span id="gov-refresh-msg"></span><span id="gov-cta-cap">Opens in a new tab<br>CorpIT sign-in and access rules apply</span></div></div></div>';
    h+='<div style="margin-bottom:14px;padding:10px 14px;font-size:13px;color:#92400e;border-left:4px solid #f59e0b;background:#fff7ed;border-radius:0 8px 8px 0;display:flex;gap:10px;align-items:flex-start"><span style="font-size:16px;line-height:1.2">⚠</span><div><b>Two different approvals.</b> Intake stays here: approving a <b>use case</b> in this portal and approving an <b>application</b> in AI Governance are separate decisions — one does not complete the other.</div></div>';
    // attention
    h+='<div class="apv4-card" style="margin-bottom:12px"><div style="padding:12px 14px;border-bottom:1px solid #e5e7eb;display:flex;flex-wrap:wrap;gap:8px;align-items:center;justify-content:space-between"><div><b style="font-size:13.5px">Needs InfoSec / Legal attention</b> '+(att.length?pill(att.length,'#fef3c7','#b45309'):'')+'<div style="font-size:11.5px;color:#6b7280">From AI Governance · oldest first · click a row to open it there</div></div>'
      +'<div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center"><span style="font-size:11px;color:#6b7280">Owner</span>'+[['all','All'],['infosec','InfoSec'],['legal','Legal'],['both','Both']].filter(function(c){ return c[0]==='all'||oc[c[0]]; }).map(function(c){ return '<span class="apv4-pill gov-ochip" data-q="'+c[0]+'" style="cursor:pointer;'+(OF===c[0]?'background:#147299;color:#fff':'background:#fff;border:1px solid #e5e7eb;color:#111827')+'">'+c[1]+' '+(oc[c[0]]||0)+'</span>'; }).join('')+'<span style="font-size:11px;color:#6b7280;margin-left:6px">Reason</span>'+[['all','All']].concat(Object.keys(REASON).filter(function(k){return counts[k];}).map(function(k){return [k,REASON[k][0]];})).map(function(c){ return '<span class="apv4-pill gov-chip" data-q="'+c[0]+'" style="cursor:pointer;'+(QF===c[0]?'background:#147299;color:#fff':'background:#fff;border:1px solid #e5e7eb;color:#111827')+'">'+E(c[1])+' '+(counts[c[0]]||0)+'</span>'; }).join('')+'</div></div>'
      +'<div style="overflow-x:auto"><table class="apv4-tbl"><thead><tr><th>Application / use case</th><th>Owner</th><th>Department</th><th>Why it needs you</th><th>Age</th><th></th></tr></thead><tbody>'
      +(list.length?list.map(function(a){ var R=REASON[a.reason]||[a.reason||'Needs review','#e5e7eb','#4b5563','Open']; return '<tr class="click" onclick="window.open(\''+E(link(a.link))+'\',\'_blank\',\'noopener\')"><td><b style="color:#111827">'+E(a.name||'(unnamed)')+'</b>'+(a.request_id||a.requester?'<div style="font-family:ui-monospace,monospace;font-size:11px;color:#147299">'+E(a.request_id||'')+(a.requester?' · '+E(a.requester):'')+'</div>':'')+'</td><td>'+ownerPill(a.owner||'both')+'</td><td>'+E(a.dept||'—')+'</td><td>'+pill(E(R[0]),R[1],R[2])+(a.detail?' <span style="font-size:12px;color:#4b5563">'+E(a.detail)+'</span>':'')+'</td><td>'+ago(a.since)+'</td><td style="text-align:right"><a href="'+E(link(a.link))+'" target="_blank" rel="noopener" onclick="event.stopPropagation()" style="color:#147299;font-weight:700;text-decoration:none">'+R[3]+' ↗</a></td></tr>'; }).join('')
        :'<tr><td colspan="6" style="text-align:center;color:#6b7280;padding:22px">'+(sn?'Nothing waiting on InfoSec / Legal right now.':'No snapshot yet.')+'</td></tr>')
      +'</tbody></table></div><div style="padding:8px 14px;font-size:11.5px;color:#6b7280"><a href="'+URL+'#attention" target="_blank" rel="noopener" style="color:#147299">Full Governance Queue ↗</a></div></div>';
    // three cards
    h+='<div class="apv4-grid4" style="grid-template-columns:repeat(auto-fit,minmax(320px,1fr));margin-bottom:12px">';
    h+='<div class="apv4-card" style="padding:12px 14px"><b style="font-size:13px">Due in the next 30 days</b><div style="font-size:11px;color:#6b7280;margin-bottom:6px">Scheduled re-reviews by assigned tier</div>'
      +(due.length?'<table class="apv4-tbl" style="font-size:12.5px"><tbody>'+due.map(function(x){ return '<tr><td>'+E(x.due||'')+' · <b>'+E(x.name||'')+'</b>'+(x.tier?' · '+E(x.tier):'')+'</td><td style="text-align:right"><a href="'+E(link(x.link||(x.app_id?'?riskApp='+x.app_id+'#risk':'#risk')))+'" target="_blank" rel="noopener" style="color:#147299;font-weight:700;text-decoration:none">Open ↗</a></td></tr>'; }).join('')+'</tbody></table>':'<div style="font-size:12.5px;color:#6b7280">'+(sn?'No reviews due.':'No snapshot yet.')+'</div>')+'</div>';
    h+='<div class="apv4-card" style="padding:12px 14px"><b style="font-size:13px">Changed recently</b><div style="font-size:11px;color:#6b7280;margin-bottom:6px">Governance audit, last 7 days</div>'
      +(rec.length?'<table class="apv4-tbl" style="font-size:12.5px"><tbody>'+rec.map(function(x){ return '<tr><td>'+(x.actor?'<b>'+E(x.actor)+'</b> ':'')+E(x.text||'')+'</td><td style="text-align:right;font-size:11px;color:#6b7280;white-space:nowrap">'+E(fmtDate?fmtDate(x.at):x.at)+'</td></tr>'; }).join('')+'</tbody></table>':'<div style="font-size:12.5px;color:#6b7280">'+(sn?'No recent changes.':'No snapshot yet.')+'</div>')
      +'<div style="font-size:11.5px;margin-top:6px"><a href="'+URL+'#audit" target="_blank" rel="noopener" style="color:#147299">Audit Trail ↗</a> · <a href="'+URL+'#discovery" target="_blank" rel="noopener" style="color:#147299">Discovery ↗</a></div></div>';
    h+='</div>';
    // CTA + tiles
    h+='<div class="apv4-card" style="padding:14px 18px;margin-bottom:12px"><b style="font-size:13.5px">Jump to a section</b><div class="apv4-grid4" style="grid-template-columns:repeat(auto-fill,minmax(190px,1fr));margin-top:10px">'+TILES.map(function(t){ return '<a href="'+URL+t[2]+'" target="_blank" rel="noopener" class="apv4-stat" style="text-decoration:none;color:inherit;display:block"><div style="font-weight:800;font-size:13px">'+t[0]+'</div><div style="font-size:11.5px;color:#6b7280">'+t[1]+'</div><div style="font-family:ui-monospace,monospace;font-size:11px;color:#147299;margin-top:3px">'+t[2]+'</div></a>'; }).join('')+'</div></div>';
    if(isAdmin()) h+='<div class="apv4-card" id="gov-int" style="padding:14px 18px"><b style="font-size:13.5px">Integration — Portal ↔ CorpIT service token</b><div style="font-size:12px;color:#6b7280;margin:2px 0 10px">CorpIT pulls approved AI Use Case Intake requests from <code>/api/portal/sync/aia</code> and pushes the at-a-glance snapshot to <code>/api/portal/sync/governance-summary</code> with this token (header <code>X-Portal-Service-Token</code>). Every call is audited.</div><div id="gov-int-body" style="font-size:13px;color:#6b7280">Loading…</div></div>';
    el.innerHTML=h;
    el.querySelectorAll('.gov-chip').forEach(function(x){ x.onclick=function(){ QF=x.dataset.q; draw(); }; });
    el.querySelectorAll('.gov-ochip').forEach(function(x){ x.onclick=function(){ OF=x.dataset.q; draw(); }; });
    var rb=$('gov-refresh'); if(rb) rb.onclick=function(){ rb.disabled=true; rb.textContent='↻ Refreshing…';
      api('POST','/api/portal/sync/governance-refresh').then(function(r){
        var d=DATA||{}; d.snapshot=r.snapshot; DATA=d; draw();
        var m=$('gov-refresh-msg'), c=$('gov-cta-cap'); if(m){ m.textContent=(r.refresh.pushed?'Updated from CorpIT just now':r.refresh.message); if(c) c.style.display='none'; }
        toast&&toast(r.refresh.pushed?'AI Governance data refreshed':'Showing latest available snapshot');
      }).catch(function(e){ rb.disabled=false; rb.textContent='↻ Refresh'; var m=$('gov-refresh-msg'), c=$('gov-cta-cap'); if(m){ m.textContent=e.message||'Refresh failed'; if(c) c.style.display='none'; } }); };
    badge(att.length);
    if(isAdmin()) renderInt();
  }
  function openReq(id){
    var AP=window.AP||{};
    var fn=AP.openReq||AP.openRequest||AP.open;
    if(typeof fn==='function'){ try{ fn(id); return; }catch(e){} }
    var q=$('apv4-search')||document.querySelector('input[placeholder^="Find a request"]');
    if(q){ q.value=id; q.dispatchEvent(new Event('input',{bubbles:true})); q.focus(); return; }
    toast&&toast('Open '+id+' from Needs my action');
  }
  function badge(n){ var el=$(SB); if(!el) return; var b=el.querySelector('.gov-badge'); if(!b){ b=document.createElement('span'); b.className='gov-badge'; b.style.cssText='margin-left:auto;background:#f59e0b;color:#111827;border-radius:999px;font-size:11px;font-weight:800;padding:0 7px;line-height:18px'; el.appendChild(b); } b.textContent=n||''; b.style.display=n?'':'none'; }
  function renderInt(){
    var b=$('gov-int-body'); if(!b) return;
    Promise.all([api('GET','/api/portal/sync/token'),api('GET','/api/portal/sync/refresh-url').catch(function(){return {};})]).then(function(arr){ var t=arr[0]; t.refresh_url=(arr[1]||{}).refresh_url||'';
      var lu=t.last_used;
      b.innerHTML='<div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center">'
        +(t.configured?pill('Token active','#d1fae5','#059669')+'<span>issued '+E(dt(t.created_at))+' by '+E(t.created_by||'')+'</span>':pill('No token','#e5e7eb','#4b5563')+'<span>feed is off until a token is issued</span>')
        +'<span style="margin-left:auto"></span><button class="apv4-btn sm" id="gov-tok-gen">'+(t.configured?'Re-issue token':'Generate token')+'</button>'+(t.configured?'<button class="apv4-btn sm no" id="gov-tok-rev">Revoke</button>':'')+'</div>'
        +'<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:10px"><label style="font-size:12px;color:#4b5563">Refresh hook (CorpIT “push now” URL)</label><input id="gov-hook" class="apv4-field" style="margin:0;flex:1;min-width:280px" placeholder="http://127.0.0.1:3001/api/zscaler/governance/portal-push" value="'+E(t.refresh_url||'')+'"><button class="apv4-btn sm" id="gov-hook-save">Save</button></div><div style="font-size:11px;color:#9ca3af">The Refresh button calls this URL with POST; CorpIT recomputes and pushes a snapshot. Leave blank to rely on the hourly push.</div>'
        +'<div style="font-size:12px;color:#6b7280;margin-top:6px">Last pull: '+(lu?E(dt(lu.at))+' · '+lu.count+' rows':'never')+' · Last push: '+(DATA&&DATA.snapshot?E(dt(DATA.snapshot.received_at)):'never')+'</div><div id="gov-tok-out" style="margin-top:8px"></div>';
      $('gov-tok-gen').onclick=function(){ confirmBox(t.configured?'Re-issuing replaces the current token. The CorpIT worker stops until it has the new one. Continue?':'Issue a service token for the CorpIT AI Governance worker?', function(){
        api('POST','/api/portal/sync/token').then(function(r){
          $('gov-tok-out').innerHTML='<div style="border:1px solid #f59e0b;background:#fff7ed;border-radius:8px;padding:10px 12px"><b style="color:#92400e">Copy this token now — it is shown once.</b><div style="display:flex;gap:8px;align-items:center;margin-top:6px"><code id="gov-tok-val" style="flex:1;word-break:break-all;font-size:12px">'+E(r.token)+'</code><button class="apv4-btn sm" id="gov-tok-copy">Copy</button></div></div>';
          $('gov-tok-copy').onclick=function(){ (navigator.clipboard&&navigator.clipboard.writeText?navigator.clipboard.writeText(r.token):Promise.reject()).then(function(){ toast&&toast('Token copied'); }).catch(function(){ var rg=document.createRange(); rg.selectNodeContents($('gov-tok-val')); var s=window.getSelection(); s.removeAllRanges(); s.addRange(rg); }); };
        }).catch(function(e){ toast&&toast(e.message||'Failed'); });
      }); };
      $('gov-hook-save').onclick=function(){ api('PUT','/api/portal/sync/refresh-url',{refresh_url:$('gov-hook').value}).then(function(){ toast&&toast('Refresh hook saved'); }).catch(function(e){ toast&&toast(e.message||'Failed'); }); };
      if($('gov-tok-rev')) $('gov-tok-rev').onclick=function(){ confirmBox('Revoke the service token? CorpIT gets 401 until a new token is issued.', function(){ api('DELETE','/api/portal/sync/token').then(function(){ toast&&toast('Token revoked'); renderInt(); }).catch(function(e){ toast&&toast(e.message||'Failed'); }); }); };
    }).catch(function(e){ b.textContent='Unavailable: '+(e.message||e); });
  }
  function confirmBox(msg,yes){
    var m=document.createElement('div'); m.id='gov-confirm'; m.style.cssText='position:fixed;inset:0;background:rgba(17,24,39,.45);z-index:9999;display:flex;align-items:center;justify-content:center';
    m.innerHTML='<div style="background:#fff;border-radius:12px;max-width:420px;width:92%;padding:18px 20px;box-shadow:0 20px 50px rgba(0,0,0,.25);font-size:14px;color:#111827"><div>'+E(msg)+'</div><div style="display:flex;gap:8px;justify-content:flex-end;margin-top:14px"><button class="apv4-btn" id="gov-c-no">Cancel</button><button class="apv4-btn pri" id="gov-c-yes">Continue</button></div></div>';
    document.body.appendChild(m); $('gov-c-no').onclick=function(){ m.remove(); }; $('gov-c-yes').onclick=function(){ m.remove(); yes(); };
  }
  function showPage(){
    document.querySelectorAll('[id^="apv4-page-"]').forEach(function(p){ p.style.display='none'; });
    var pg=$(PAGE); if(pg) pg.style.display='block';
    document.querySelectorAll('[id^="apv4-sb-"]').forEach(function(s){ s.classList.remove('on'); s.style.background=''; s.style.color=''; });
    var el=$(SB); if(el) el.classList.add('on');
    S.page='governance'; var sc=$('apv4-scroll'); if(sc) sc.scrollTop=0;
  }
  function inject(){
    if(!allowed()) return;
    var root=$('apv4-root'); if(!root) return;
    var anyPage=root.querySelector('[id^="apv4-page-"]'); if(!anyPage) return;
    if(!$(PAGE)){ var pg=document.createElement('div'); pg.id=PAGE; pg.style.display='none'; anyPage.parentNode.appendChild(pg); }
    var items=[].slice.call(root.querySelectorAll('[id^="apv4-sb-"]'));
    var after=$('apv4-sb-audit')||items[items.length-1]; if(!after) return;
    if($(SB)){ if(S.page==='governance') $(SB).classList.add('on'); return; }
    var el=after.cloneNode(false); el.id=SB; el.removeAttribute('onclick'); el.classList.remove('on'); el.style.background=''; el.style.color='';
    el.innerHTML='<span class="ic">◈</span><span style="flex:1">AI Governance</span>';
    el.onclick=function(e){ e.preventDefault(); showPage(); render(); };
    after.parentNode.insertBefore(el,after.nextSibling);
    if(S.page==='governance') el.classList.add('on');
    // badge without opening the page
    api('GET','/api/portal/sync/governance-summary').then(function(d){ DATA=d; badge(((d.snapshot||{}).attention||[]).length); }).catch(function(){});
  }
  if(window.RM){ var _prev=RM.afterSidebar; RM.afterSidebar=function(el){ if(_prev) _prev(el); inject(); }; }
  var _prevRole=window.RM&&RM.onRole; if(window.RM) RM.onRole=function(id){ if(_prevRole) _prevRole(id); DATA=null; setTimeout(inject,50); };
  inject();
  window.portalGovernance={render:render,url:URL};
  console.info('[governance] loaded v10');
})();
