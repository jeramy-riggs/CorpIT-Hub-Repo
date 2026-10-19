/* portal-ack-admin.js — AI Policy Acknowledgments (v5, 2026-09-24: + eligibility panel, Claude access wording, Word/PDF exports).
   Mounts into the approver console the same way portal-content-admin.js does: a sidebar item + a page
   container beside the other apv4 pages. Two modes, decided by /api/portal/auth/me:
     admin  : every record · search/filters · CSV · audit pack (ZIP) · record drawer with audit events,
              identity correction, download · policy version history (also fills #pc-cla-versions)
     team   : (non-admin with team_ack_count > 0) records that name this person as manager · read-only ·
              record drawer (no correction, no raw audit table) · download record · CSV of own team
   Reads:
     GET  /api/portal/acknowledgments?form=cla[&scope=team][&q=&status=&version=&manager=&from=&to=]
     GET  /api/portal/acknowledgments/<id>            GET …/<id>/record (printable)   GET …/export.zip (admin)
     PATCH /api/portal/acknowledgments/<id>/identity   (admin)
     GET  /api/portal/policy-versions?form=cla · POST …/<id>/retire   (admin)
   Nothing here touches requests, approvals or authentication; the server enforces every scope. */
(function(){
  'use strict';
  var FORM='cla', PAGE='apv4-page-ack-admin', SB='apv4-sb-ack-admin', mode=null, me=null, cache=null;
  function esc(s){ return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];}); }
  function api(m,p,body){ return fetch(p,{method:m,credentials:'same-origin',headers:{'Content-Type':'application/json','Accept':'application/json'},body:body?JSON.stringify(body):undefined})
    .then(function(r){ return r.json().catch(function(){return {};}).then(function(j){ if(!r.ok||j.ok===false){ var e=new Error((j&&j.error)||('HTTP '+r.status)); e.status=r.status; throw e; } return j.data; }); }); }
  function fmtD(s){ if(!s) return '—'; var d=new Date(s); return isNaN(d)?s.slice(0,10):d.toLocaleDateString('en-US',{month:'2-digit',day:'2-digit',year:'numeric'}); }
  function fmtDT(s){ if(!s) return '—'; var d=new Date(s); return isNaN(d)?s:d.toLocaleString('en-US',{month:'short',day:'numeric',year:'numeric',hour:'numeric',minute:'2-digit'}); }
  function pill(st){ var m={completed:['#d1fae5','#059669','✓ Completed'],requires_reack:['#e0f2fe','#0284c7','↻ Requires re-acknowledgment'],pending:['#fef3c7','#d97706','⏳ Pending']}[st]||['#f3f4f6','#6b7280',st];
    return '<span class="apv4-pill" style="background:'+m[0]+';color:'+m[1]+';font-size:11px">'+m[2]+'</span>'; }
  function eligPill(src){ return src==='admin_grant'?'<span class="apv4-pill" style="background:#ede9fe;color:#5b21b6;font-size:11px">Admin grant</span>':(src==='hr_roster'?'<span style="font-size:12px;color:#374151">HR status</span>':'<span style="color:#9ca3af">—</span>'); }
  function rid(id){ return 'ACK-'+String(id).padStart(6,'0'); }
  function recordUrl(id){ return '/api/portal/acknowledgments/'+id+'/record'; }
  function css(){ if(document.getElementById('ack-admin-css')) return; var st=document.createElement('style'); st.id='ack-admin-css'; st.textContent=
    '.aa2-cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px}.aa2-cards.three{grid-template-columns:repeat(3,1fr)}'+
    '.aa2-kv td{padding:9px 14px;font-size:13px;border-bottom:1px solid #f3f4f6;vertical-align:top}.aa2-kv td:first-child{width:200px;color:#6b7280;font-weight:600}'+
    '.aa2-field{display:block;width:100%;box-sizing:border-box;border:1px solid #d1d5db;border-radius:8px;padding:8px 10px;font-size:13px;margin:4px 0 10px}'+
    '.aa2-toast{position:fixed;left:50%;bottom:28px;transform:translateX(-50%);background:#111827;color:#fff;padding:10px 16px;border-radius:10px;font-size:13px;z-index:99999}'+
    '.aa2-filters{padding:12px 16px;display:flex;gap:8px;align-items:center;flex-wrap:wrap;border-bottom:1px solid #e5e7eb}.aa2-filters .apv4-field{margin:0}'+
    '.aa2-dl{text-decoration:none}';
    document.head.appendChild(st); }
  function toast(m){ var t=document.createElement('div'); t.className='aa2-toast'; t.textContent=m; document.body.appendChild(t); setTimeout(function(){t.remove();},3600); }
  function stat(n,label,sub,color,ic){ return '<div class="apv4-stat-card" style="cursor:default"><div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px"><div class="apv4-type-ic art" style="background:'+color+';color:#fff;width:34px;height:34px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:16px">'+ic+'</div></div><div class="apv4-stat-n">'+n+'</div><div class="apv4-stat-l">'+label+'</div><div class="apv4-stat-s">'+sub+'</div></div>'; }
  function val(pg,id){ var e=pg.querySelector('#'+id); return e?e.value:''; }
  function filterQs(pg){
    var q={form:FORM,q:val(pg,'aa2-q'),status:val(pg,'aa2-st'),version:val(pg,'aa2-ver'),manager:val(pg,'aa2-mgr'),from:val(pg,'aa2-from'),to:val(pg,'aa2-to')};
    if(mode==='team') q.scope='team';
    return Object.keys(q).filter(function(k){return q[k];}).map(function(k){return k+'='+encodeURIComponent(q[k]);}).join('&');
  }

  function render(keep){
    var pg=document.getElementById(PAGE); if(!pg) return;
    var f=keep||{}; ['aa2-q','aa2-st','aa2-ver','aa2-mgr','aa2-from','aa2-to'].forEach(function(id){ if(!(id in f)) f[id]=val(pg,id); });
    var qs=filterQs({querySelector:function(sel){ var id=sel.slice(1); return {value:f[id]||''}; }});
    pg.innerHTML='<div style="padding:8px 0;color:#6b7280;font-size:13px">Loading acknowledgments…</div>';
    api('GET','/api/portal/acknowledgments?'+qs).then(function(d){
      cache=d; var s=d.summary||{}, rows=d.rows||[], admin=(mode==='admin');
      var versions=[]; rows.forEach(function(r){ if(versions.indexOf(r.policy_version)<0) versions.push(r.policy_version); }); if(s.current_version&&versions.indexOf(s.current_version)<0) versions.push(s.current_version); versions.sort(function(a,b){return b-a;});
      pg.innerHTML=
        '<div style="margin-bottom:14px;display:flex;justify-content:space-between;align-items:flex-end;gap:12px;flex-wrap:wrap"><div><div class="apv4-page-title">'+(admin?esc(d.label||'Claude Access – Artificial Intelligence Policy Acknowledgment')+' — status':'Team Acknowledgments — AI Policy')+'</div>'
        +'<div class="apv4-page-sub">'+(admin?'':'People who list you as their manager · read-only · ')+'Current policy <b>version '+(s.current_version||'—')+'</b>'+(s.current_file?' · '+esc(s.current_file):'')+(s.current_effective?' · effective '+esc(s.current_effective):'')+(admin?' · '+(s.live?'<span style="color:#059669;font-weight:700">released</span>':'<span style="color:#92400e;font-weight:700">not released</span>'):'')+'</div></div>'
        +'<div style="display:flex;gap:8px"><button class="apv4-btn sm" id="aa2-csv">Export CSV</button>'+(admin?'<button class="apv4-btn sm pri" id="aa2-zip" title="ZIP: index.csv + one printable audit record per acknowledgment in the current filter">⬇ Audit pack</button>':'')+'<button class="apv4-btn sm" id="aa2-refresh">Refresh</button></div></div>'
        /* ACK-REACK: broadcast to everyone whose latest record is not on the current version */
        +(admin&&(s.requires_reack||0)>0?'<div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;border:1px solid #bae6fd;background:#f0f9ff;border-radius:10px;padding:10px 14px;margin-bottom:14px"><span style="font-size:13px;color:#0c4a6e;flex:1"><b>'+(s.requires_reack||0)+'</b> '+((s.requires_reack||0)===1?'person':'people')+' must acknowledge again (signed an older version, or an administrator requested it). Send one email with a link to the acknowledgement. People already emailed for version '+(s.current_version||'—')+' are skipped.</span><button class="apv4-btn sm pri" id="aa2-notify-all">✉ Notify everyone who must re-acknowledge</button></div>':'')
        +'<div class="aa2-cards'+(admin?'':' three')+'">'
        +(admin?stat(s.roster_known?(s.eligible_people||0):(s.people||0),s.roster_known?'Eligible people':'People acknowledged',(s.roster_known?'HR status + ':'')+(s.admin_allows||0)+' admin grant'+((s.admin_allows||0)===1?'':'s')+' · '+(s.admin_blocks||0)+' blocked · '+(s.records||0)+' records','linear-gradient(135deg,#0f172a,#334155)','👥')
               :stat(s.people||0,'Team members with records','distinct signers · '+(s.records||0)+' records','linear-gradient(135deg,#0f172a,#334155)','👥'))
        +stat(s.completed||0,'Completed','on the current version','linear-gradient(135deg,#065f46,#059669)','✓')
        +(admin?stat(s.roster_known?(s.not_yet_acknowledged||0):'—','Not yet acknowledged',s.roster_known?'eligible minus signers':'needs the HR roster count — not exposed to the portal yet','linear-gradient(135deg,#92400e,#d97706)','⏳'):'')
        +stat(s.requires_reack||0,'Requires re-acknowledgment','signed an older version','linear-gradient(135deg,#075985,#0284c7)','↻')+'</div>'
        +'<div class="apv4-card"><div class="aa2-filters">'
        +'<input class="apv4-field" id="aa2-q" style="flex:1;min-width:200px" placeholder="Search name, email, department'+(admin?', manager, employee ID':'')+'…" value="'+esc(f['aa2-q'])+'">'
        +'<select class="apv4-field" id="aa2-st" style="width:190px"><option value="">Status: All</option><option value="completed"'+(f['aa2-st']==='completed'?' selected':'')+'>Completed</option><option value="requires_reack"'+(f['aa2-st']==='requires_reack'?' selected':'')+'>Requires re-acknowledgment</option></select>'
        +'<select class="apv4-field" id="aa2-ver" style="width:130px"><option value="">Version: any</option>'+versions.map(function(v){ return '<option value="'+v+'"'+(String(f['aa2-ver'])===String(v)?' selected':'')+'>v'+v+'</option>'; }).join('')+'</select>'
        +(admin?'<input class="apv4-field" id="aa2-mgr" style="width:170px" placeholder="Manager email…" value="'+esc(f['aa2-mgr'])+'">':'')
        +'<input class="apv4-field" id="aa2-from" type="date" style="width:150px" value="'+esc(f['aa2-from'])+'" title="From"><input class="apv4-field" id="aa2-to" type="date" style="width:150px" value="'+esc(f['aa2-to'])+'" title="To">'
        +'<button class="apv4-btn sm" id="aa2-go">Apply</button>'
        +'<span style="font-size:12px;color:#6b7280;margin-left:auto">Showing '+rows.length+' of '+(s.people||0)+(admin&&s.archived_records?' · <a href="#" id="aa2-arch" style="color:#147299">'+s.archived_records+' archived</a>':'')+'</span></div>'
        +'<div style="overflow-x:auto"><table class="apv4-tbl"><thead><tr><th>Person</th><th>Department</th><th>Worker type</th>'+(admin?'<th>Eligible via</th><th>Manager</th>':'')+'<th>Status</th><th>Version</th><th>Acknowledged</th><th>Record</th><th></th></tr></thead><tbody>'
        +(rows.length?rows.map(function(r){ return '<tr class="click" data-id="'+r.id+'"><td><div style="font-weight:700;color:#111827">'+esc(r.name||'—')+'</div><div style="font-size:11px;color:#6b7280">'+esc(r.email)+'</div></td><td>'+esc(r.dept||'—')+'</td><td>'+esc(r.employment_class||'—')+(r.employment_matched==='true'?'':' <span style="color:#9ca3af">(unverified)</span>')+'</td>'+(admin?'<td>'+eligPill(r.eligibility_source)+'</td><td>'+esc(r.manager_email||'—')+'</td>':'')+'<td>'+pill(r.status)+'</td><td style="font-family:ui-monospace,monospace">v'+r.policy_version+(r.sample?' <span class="apv4-pill" style="background:#fef3c7;color:#92400e">test</span>':'')+'</td><td style="white-space:nowrap">'+fmtD(r.created_at)+'</td><td style="font-family:ui-monospace,monospace;font-size:12px;color:#147299">'+rid(r.id)+'</td><td style="white-space:nowrap"><button class="apv4-btn sm" data-open="'+r.id+'">Open</button> <a class="apv4-btn sm aa2-dl" href="'+recordUrl(r.id)+'?format=pdf" title="Download the audit record as PDF">⬇ PDF</a></td></tr>'; }).join('')
          :'<tr><td colspan="9" class="apv4-empty" style="padding:26px;text-align:center;color:#6b7280">'+(admin?'No acknowledgments recorded yet.':'None of your team members has acknowledged the AI Policy yet.')+'</td></tr>')
        +'</tbody></table></div></div>'
        +(admin?'<div id="aa2-elig" style="margin-top:14px"></div><div id="aa2-versions" style="margin-top:14px"></div>':'<div style="font-size:11.5px;color:#6b7280;margin-top:10px">Details are what the employee saw at signing. Corrections go through the IT Service Desk (portal administrator).</div>');
      var nb=pg.querySelector('#aa2-notify-all'); if(nb) nb.onclick=function(){
        if(!confirm('Email everyone whose acknowledgment is not on the current version?\n\nOne email each, with a link to the acknowledgement. People already emailed for this version are skipped.')) return;
        nb.disabled=true; nb.textContent='Sending…';
        api('POST','/api/portal/acknowledgments/notify-outdated',{form:FORM}).then(function(d){ toast('Sent '+d.sent+' · skipped '+d.skipped+(d.failed?' · FAILED '+d.failed:'')); render(); }).catch(function(e){ toast(e.message); nb.disabled=false; nb.textContent='✉ Notify everyone who must re-acknowledge'; });
      };
      var al=pg.querySelector('#aa2-arch'); if(al) al.onclick=function(e){ e.preventDefault(); if(window.RMARC) window.RMARC.showArchived(); };
      pg.querySelector('#aa2-refresh').onclick=function(){ render(); };
      pg.querySelector('#aa2-go').onclick=function(){ render(); };
      pg.querySelectorAll('.aa2-filters input').forEach(function(i){ i.onkeydown=function(e){ if(e.key==='Enter') render(); }; });
      pg.querySelectorAll('.aa2-filters select').forEach(function(sl){ sl.onchange=function(){ render(); }; });
      pg.querySelector('#aa2-csv').onclick=function(){ exportCsv(rows); };
      var zip=pg.querySelector('#aa2-zip'); if(zip) zip.onclick=function(){ window.location.href='/api/portal/acknowledgments/export.zip?'+filterQs(pg); };
      pg.querySelectorAll('[data-open]').forEach(function(b){ b.onclick=function(e){ e.stopPropagation(); openRecord(+b.getAttribute('data-open')); }; });
      pg.querySelectorAll('.aa2-dl').forEach(function(a){ a.onclick=function(e){ e.stopPropagation(); }; });
      pg.querySelectorAll('tr.click').forEach(function(tr){ tr.onclick=function(){ openRecord(+tr.getAttribute('data-id')); }; });
      if(admin){ eligibilityInto(pg.querySelector('#aa2-elig')); versionsInto(pg.querySelector('#aa2-versions'), false); }
    }).catch(function(e){ pg.innerHTML='<div class="apv4-note warn">Could not load acknowledgments: '+esc(e.message)+'</div>'; });
  }
  function exportCsv(rows){
    var cols=['id','name','email','employee_id','dept','title','manager_email','employment_class','employment_matched','status','policy_version','policy_sha','ack_via','signature_kind','sample','identity_source','created_at'];
    var lines=[['record_id'].concat(cols).join(',')].concat(rows.map(function(r){ return [rid(r.id)].concat(cols.map(function(c){ var v=r[c]; v=v==null?'':String(v); return /[",\n]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v; })).join(','); }));
    var a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([lines.join('\n')],{type:'text/csv'})); a.download=(mode==='team'?'team-':'')+'ai-policy-acknowledgments-'+new Date().toISOString().slice(0,10)+'.csv'; a.click();
  }

  /* ── eligibility: administrator allow / block list (HR status is the automatic path) ── */
  function eligibilityInto(host){
    if(!host) return;
    api('GET','/api/portal/ack-eligibility?form='+FORM).then(function(d){
      var rows=d.rows||[], removed=d.removed||[];
      var ackp={completed:'<span class="apv4-pill" style="background:#d1fae5;color:#059669;font-size:11px">✓ Completed</span>',requires_reack:'<span class="apv4-pill" style="background:#e0f2fe;color:#0284c7;font-size:11px">↻ Re-acknowledge</span>',pending:'<span class="apv4-pill" style="background:#fef3c7;color:#d97706;font-size:11px">⏳ Not yet acknowledged</span>'};
      host.innerHTML='<div class="apv4-card"><div style="padding:12px 16px;border-bottom:1px solid #e5e7eb;display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap"><div><b style="font-size:13px">Eligibility — administrator grants and blocks</b><div style="font-size:11.5px;color:#6b7280">HR status (Regular FT) makes the acknowledgement available automatically. Use <b>Allow</b> to grant it to someone else (a contractor approved for Claude) and <b>Block</b> to withhold it from an FTE. Every change is audited.</div></div><span style="font-size:12px;color:#6b7280">'+rows.length+' active</span></div>'
        +'<div style="padding:10px 16px;display:flex;gap:8px;align-items:center;flex-wrap:wrap;background:#fafafa;border-bottom:1px solid #e5e7eb">'
        +'<input class="apv4-field" id="el-email" style="margin:0;flex:1;min-width:220px" placeholder="Corporate email (name@auction.com)">'
        +'<input class="apv4-field" id="el-name" style="margin:0;width:180px" placeholder="Name (optional)">'
        +'<select class="apv4-field" id="el-mode" style="margin:0;width:auto"><option value="allow">Allow — grant the acknowledgement option</option><option value="block">Block — withhold from this person</option></select>'
        +'<input class="apv4-field" id="el-reason" style="margin:0;flex:1;min-width:220px" placeholder="Reason (required, audited)">'
        +'<label style="font-size:12px;color:#374151;display:flex;gap:6px;align-items:center;white-space:nowrap"><input type="checkbox" id="el-notify" checked> Email the person</label>'
        +'<button class="apv4-btn sm pri" id="el-add">Add</button><span id="el-err" style="color:#b91c1c;font-size:12px"></span></div>'
        +'<table class="apv4-tbl"><thead><tr><th>Person</th><th>HR status</th><th>Entry</th><th>Reason</th><th>Added by</th><th>Acknowledgement</th><th>Notified</th><th></th></tr></thead><tbody>'
        +(rows.length?rows.map(function(r){ return '<tr><td><b>'+esc(r.name||'—')+'</b><div style="font-size:11px;color:#6b7280">'+esc(r.email)+'</div></td><td>'+esc(r.hr_class||'—')+(r.hr_matched===true?'':' <span style="color:#9ca3af">(no HR match)</span>')+'</td><td>'+(r.mode==='allow'?'<span class="apv4-pill" style="background:#d1fae5;color:#059669;font-size:11px">✓ Allow</span>':'<span class="apv4-pill" style="background:#fee2e2;color:#dc2626;font-size:11px">⛔ Block</span>')+'</td><td style="max-width:260px;font-size:12.5px">'+esc(r.reason)+'</td><td>'+esc(r.added_by)+'<div style="font-size:11px;color:#9ca3af">'+fmtD(r.added_at)+'</div></td><td>'+(r.mode==='allow'?(ackp[r.ack_status]||''):'—')+'</td><td style="font-size:12px;color:#6b7280">'+(r.mode==='allow'?(r.notified_at?fmtD(r.notified_at):'not sent'):'—')+'</td><td style="text-align:right;white-space:nowrap">'+(r.mode==='allow'?'<button class="apv4-btn sm" data-resend="'+r.id+'">Resend email</button> ':'')+'<button class="apv4-btn sm danger" data-remove="'+r.id+'" data-email="'+esc(r.email)+'">Remove</button></td></tr>'; }).join('')
          :'<tr><td colspan="8" style="padding:18px;color:#6b7280;text-align:center">No administrator entries. Everyone with FTE status already has the option.</td></tr>')
        +'</tbody></table>'
        +(removed.length?'<details style="padding:8px 16px;font-size:12px;color:#6b7280"><summary style="cursor:pointer">'+removed.length+' removed entr'+(removed.length===1?'y':'ies')+' (history)</summary>'+removed.map(function(r){ return '<div style="padding:3px 0">'+esc(r.email)+' · '+esc(r.mode)+' · added '+fmtD(r.added_at)+' by '+esc(r.added_by)+' · removed '+fmtD(r.removed_at)+' by '+esc(r.removed_by)+' · '+esc(r.reason)+'</div>'; }).join('')+'</details>':'')
        +'<div style="padding:10px 16px;font-size:11.5px;color:#6b7280;border-top:1px solid #f3f4f6">Removing an Allow hides the option again; any acknowledgement already recorded is kept. Removing a Block restores the HR rule.</div></div>';
      host.querySelector('#el-add').onclick=function(){
        var b={form:FORM,email:host.querySelector('#el-email').value.trim(),name:host.querySelector('#el-name').value.trim(),mode:host.querySelector('#el-mode').value,reason:host.querySelector('#el-reason').value.trim(),notify:host.querySelector('#el-notify').checked};
        var er=host.querySelector('#el-err'); er.textContent='';
        api('POST','/api/portal/ack-eligibility',b).then(function(d){ toast(b.mode==='allow'?('Added · '+(d.notified?'email sent':'no email')):'Blocked'); eligibilityInto(host); render(); }).catch(function(e){ er.textContent=e.message; });
      };
      host.querySelectorAll('[data-remove]').forEach(function(bt){ bt.onclick=function(){ if(!confirm('Remove the entry for '+bt.getAttribute('data-email')+'?')) return; api('DELETE','/api/portal/ack-eligibility/'+bt.getAttribute('data-remove')).then(function(){ toast('Removed'); eligibilityInto(host); render(); }).catch(function(e){ toast('Could not remove: '+e.message); }); }; });
      host.querySelectorAll('[data-resend]').forEach(function(bt){ bt.onclick=function(){ api('POST','/api/portal/ack-eligibility/'+bt.getAttribute('data-resend')+'/resend').then(function(d){ toast(d.notified?'Email sent':'Email could not be sent'); eligibilityInto(host); }).catch(function(e){ toast('Could not send: '+e.message); }); }; });
    }).catch(function(e){ host.innerHTML='<div class="apv4-note warn">Eligibility list unavailable: '+esc(e.message)+'</div>'; });
  }

  /* version history — admin page and, when present, Site Content → Form Policies (#pc-cla-versions) */
  function versionsInto(host, compact){
    if(!host) return;
    api('GET','/api/portal/policy-versions?form='+FORM).then(function(d){
      var v=d.versions||[];
      host.innerHTML='<div class="apv4-card"><div style="padding:12px 16px;border-bottom:1px solid #e5e7eb;display:flex;justify-content:space-between;align-items:center"><b style="font-size:13px">Policy version history</b><span style="font-size:11px;color:#6b7280">each publish adds a version; retiring keeps rows and files</span></div>'
        +'<table class="apv4-tbl"><thead><tr><th>Ver</th><th>Document</th><th>Effective</th><th>Published</th><th>Status</th><th>Acknowledged</th><th></th></tr></thead><tbody>'
        +(v.length?v.map(function(x){ return '<tr><td style="font-family:ui-monospace,monospace"><b>'+x.version+'</b></td><td>'+esc(x.file_name||'')+' <span style="color:#9ca3af;font-family:ui-monospace,monospace;font-size:11px">'+esc(x.sha)+'</span>'+(x.pages?' · '+x.pages+' pp':'')+'</td><td>'+esc(x.effective_date||'—')+'</td><td style="white-space:nowrap">'+fmtD(x.published_at)+'<div style="font-size:11px;color:#9ca3af">'+esc(x.published_by||'')+'</div></td><td>'+(x.current?'<span class="apv4-pill" style="background:#d1fae5;color:#059669">Current</span>':'<span class="apv4-pill" style="background:#f3f4f6;color:#6b7280">Retired '+fmtD(x.retired_at)+'</span>')+'</td><td>'+x.acknowledged+'</td><td style="text-align:right">'+(x.current?'<button class="apv4-btn sm danger" data-retire="'+x.id+'" data-v="'+x.version+'">Retire</button>':'')+(x.url?' <a class="apv4-btn sm" href="'+esc(x.url)+'" target="_blank" rel="noopener" style="text-decoration:none">View</a>':'')+'</td></tr>'; }).join('')
          :'<tr><td colspan="7" style="padding:18px;color:#6b7280;text-align:center">No document published yet.</td></tr>')
        +'</tbody></table></div>';
      host.querySelectorAll('[data-retire]').forEach(function(b){ b.onclick=function(){
        if(!confirm('Retire version '+b.getAttribute('data-v')+'?\n\nThe page will show no document until a new version is published. Records and files are kept.')) return;
        api('POST','/api/portal/policy-versions/'+b.getAttribute('data-retire')+'/retire').then(function(){ toast('Version retired'); versionsInto(host,compact); if(window.portalContent) window.portalContent.refresh().catch(function(){}); }).catch(function(e){ toast('Could not retire: '+e.message); }); }; });
    }).catch(function(e){ host.innerHTML='<div class="apv4-note warn">Version history unavailable: '+esc(e.message)+'</div>'; });
  }

  /* record drawer — admin: full audit + correction; team: read-only view */
  function openRecord(id){
    api('GET','/api/portal/acknowledgments/'+id).then(function(r){
      var admin=(r.viewer==='admin');
      var ov=document.getElementById('aa2-ov'); if(!ov){ ov=document.createElement('div'); ov.id='aa2-ov'; ov.style.cssText='position:fixed;inset:0;background:rgba(17,24,39,.45);z-index:99990;display:flex;justify-content:flex-end'; document.body.appendChild(ov); ov.onclick=function(e){ if(e.target===ov) ov.remove(); }; }
      var stmts=(r.statements||[]).map(function(t){ return '<li style="margin-bottom:4px">'+esc(t)+'</li>'; }).join('');
      var hist=(r.history||[]).map(function(h){ return '<div style="display:flex;gap:10px;align-items:center;padding:8px 10px;border:1px solid '+(h.id===r.id?'#bbf7d0':'#e5e7eb')+';background:'+(h.id===r.id?'#f0fdf4':'#fff')+';border-radius:8px;margin-bottom:6px;font-size:12px"><span style="font-weight:800;color:'+(h.status==='completed'?'#059669':'#6b7280')+'">v'+h.policy_version+'</span><span style="flex:1">'+fmtDT(h.created_at)+' · '+rid(h.id)+(h.sample?' · test':'')+'</span>'+pill(h.status)+'</div>'; }).join('');
      var notif=(r.audit||[]).filter(function(a){ return a.event.indexOf('notify.')===0; }).map(function(a){ var okk=/^sent/.test(a.note), skip=/^(skipped|queued)/.test(a.note); return '<div style="font-size:12px;margin-bottom:3px"><span style="display:inline-block;width:80px;color:#6b7280">'+esc(a.event.slice(7))+'</span><span style="color:'+(okk?'#059669':skip?'#6b7280':'#b91c1c')+'">'+esc(a.note)+'</span></div>'; }).join('');
      var aud=(r.audit||[]).map(function(a){ var n=a.note; try{ var j=JSON.parse(a.note); n=(j.reason?'“'+j.reason+'” — ':'')+(j.changes||[]).map(function(c){return c.field+': '+(c.old||'—')+' → '+(c.new||'—');}).join('; '); }catch(e){} return '<tr><td style="white-space:nowrap;font-size:12px">'+fmtDT(a.created_at)+'</td><td style="font-weight:600">'+esc(a.event)+'</td><td>'+esc(a.actor)+'</td><td style="font-size:12px;color:#4b5563">'+esc(n)+'</td></tr>'; }).join('');
      var vrow=r.version||{};
      ov.innerHTML='<div style="width:min(760px,96vw);height:100%;background:#fff;overflow-y:auto;box-shadow:-12px 0 40px rgba(0,0,0,.2)" onclick="event.stopPropagation()">'
        +'<div style="padding:18px 22px;border-bottom:1px solid #e5e7eb;display:flex;justify-content:space-between;align-items:flex-start;gap:12px;position:sticky;top:0;background:#fff;z-index:1"><div><div style="font-size:16px;font-weight:800;color:#111827">Acknowledgment record · <span style="font-family:ui-monospace,monospace;color:#147299">'+rid(r.id)+'</span></div><div style="font-size:12px;color:#6b7280">'+esc(r.name)+' · '+esc(r.email)+' · '+pill(r.status)+'</div></div>'
        +'<div style="display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end"><span style="font-size:11px;color:#6b7280;font-weight:700;letter-spacing:.04em;align-self:center">DOWNLOAD</span><a class="apv4-btn sm aa2-dl" href="'+recordUrl(r.id)+'?format=docx" style="text-decoration:none" title="Word document">Word</a><a class="apv4-btn sm aa2-dl" href="'+recordUrl(r.id)+'?format=pdf" style="text-decoration:none" title="PDF">PDF</a><a class="apv4-btn sm pri aa2-dl" href="'+recordUrl(r.id)+'" target="_blank" rel="noopener" style="text-decoration:none" title="Printable view">Print</a>'+(admin?'<button class="apv4-btn sm" id="aa2-reack" style="'+(!r.superseded_at&&(r.history||[]).length&&r.history[0].id===r.id?'':'display:none')+'" title="Ask this person to complete the acknowledgement again">↻ Request re-acknowledgment</button><button class="apv4-btn sm" id="aa2-edit">Correct employee details</button>':'')+'<button class="apv4-x lt" id="aa2-close" aria-label="Close">×</button></div></div>'
        +'<div style="padding:18px 22px">'
        /* ACK-REACK: per-record request (latest, not yet superseded) */
        +(admin&&!r.superseded_at&&(r.history||[]).length&&r.history[0].id===r.id?'<div id="aa2-reackbox" style="display:none;border:1px solid #bae6fd;background:#f0f9ff;border-radius:10px;padding:14px 16px;margin-bottom:16px"><div style="font-weight:700;font-size:13px;color:#0c4a6e;margin-bottom:8px">Request re-acknowledgment</div><div style="font-size:12px;color:#0c4a6e;margin-bottom:10px">This record stays on file and is marked superseded. '+esc(r.name||r.email)+' sees the full acknowledgement form again on their next visit, with your reason. Written to the audit trail.</div>'
          +'<label style="font-size:11px;font-weight:700;color:#6b7280;text-transform:uppercase">Reason (required — shown to the person)<input class="aa2-field" id="aa2-reack-reason" placeholder="e.g. Legal revised the provisions; signature did not match directory name"></label>'
          +'<label style="font-size:12px;display:flex;align-items:center;gap:6px;margin:6px 0 10px"><input type="checkbox" id="aa2-reack-notify" checked> Email '+esc(r.email)+' now with a link</label>'
          +'<div style="display:flex;gap:8px;justify-content:flex-end"><button class="apv4-btn sm" id="aa2-reack-cancel">Cancel</button><button class="apv4-btn sm pri" id="aa2-reack-go">Request re-acknowledgment</button></div><div id="aa2-reack-err" style="color:#b91c1c;font-size:12px;margin-top:6px"></div></div>':'')
        +(admin?'<div id="aa2-editbox" style="display:none;border:1px solid #fde68a;background:#fffbeb;border-radius:10px;padding:14px 16px;margin-bottom:16px"><div style="font-weight:700;font-size:13px;color:#92400e;margin-bottom:8px">Administrator correction — identity fields only</div><div style="font-size:12px;color:#92400e;margin-bottom:10px">The statements, signature, version and time of the acknowledgment cannot be changed. Old → new values and your reason are written to the audit trail.</div>'
        +'<div style="display:grid;grid-template-columns:1fr 1fr;gap:0 14px">'+['name','employee_id','dept','title','manager_email'].map(function(f){ return '<label style="font-size:11px;font-weight:700;color:#6b7280;text-transform:uppercase">'+f.replace('_',' ')+'<input class="aa2-field" data-f="'+f+'" value="'+esc(r[f]||'')+'"></label>'; }).join('')+'</div>'
        +'<label style="font-size:11px;font-weight:700;color:#6b7280;text-transform:uppercase">Reason (required)<input class="aa2-field" id="aa2-reason" placeholder="e.g. HR spelling correction, ticket INC-12345"></label>'
        +'<div style="display:flex;gap:8px;justify-content:flex-end"><button class="apv4-btn sm" id="aa2-cancel">Cancel</button><button class="apv4-btn sm pri" id="aa2-save">Save correction</button></div><div id="aa2-err" style="color:#b91c1c;font-size:12px;margin-top:6px"></div></div>':'')
        +'<div class="apv4-card" style="margin-bottom:14px"><table class="apv4-tbl aa2-kv"><tbody>'
        +[['Record ID',rid(r.id)],['Name',r.name],['Email',r.email],['Employee ID',r.employee_id||'—'],['Worker type (HR)',(r.employment_class||'—')+(r.employment_matched==='true'?'':' · unverified')],['Department / Title',[r.dept,r.title].filter(Boolean).join(' · ')||'—'],['Manager (at signing)',r.manager_email||'—'],
          ['Acknowledgment',(cache&&cache.label)||'Claude Access – Artificial Intelligence Policy Acknowledgment'],['Policy version','<b>Version '+r.policy_version+'</b>'+(vrow.file_name?' · '+esc(vrow.file_name):'')+(vrow.effective_date?' · effective '+esc(vrow.effective_date):'')+' · sha '+esc(r.policy_sha)+(r.policy_url?' · <a href="'+esc(r.policy_url)+'" target="_blank" rel="noopener" style="color:#147299">open</a>':'')],
          ['Status',pill(r.status)+(r.sample?' <span class="apv4-pill" style="background:#fef3c7;color:#92400e">test record</span>':'')+(r.superseded_at?'<div style="margin-top:6px;font-size:12px;color:#0c4a6e"><b>Re-acknowledgment requested</b> '+fmtDT(r.superseded_at)+' by '+esc(r.superseded_by||'')+(r.superseded_reason?' — “'+esc(r.superseded_reason)+'”':'')+'</div>':'')+(r.reack_notified_at?'<div style="margin-top:4px;font-size:12px;color:#6b7280">Re-acknowledge email sent '+fmtDT(r.reack_notified_at)+' (for version '+r.reack_notified_version+')</div>':'')],['Acknowledged',fmtDT(r.created_at)+' <span style="color:#9ca3af">('+esc(r.created_at)+')</span>'],
          ['Signature',r.signature_kind==='typed'?'<span style="font-family:Georgia,serif;font-style:italic;font-size:16px">'+esc(r.signature_text)+'</span> · typed':(r.signature_kind==='canvas'?'drawn (image on file)':'—')],['Policy reviewed via',r.ack_via||'—'],
          ['Statements accepted',stmts?'<ol style="margin:0;padding-left:18px">'+stmts+'</ol>':'—'],['Notifications',notif||'<span style="color:#9ca3af">— (recorded before notification logging)</span>'],['Identity source',r.identity_source||'—'],['Eligible via',r.eligibility_source==='admin_grant'?'Administrator grant':(r.eligibility_source==='hr_roster'?'HR status (FTE)':'— (recorded before eligibility tracking)')],
          ['Record integrity',(r.record_sha?'<span style="font-family:ui-monospace,monospace;font-size:11px">sha256 '+esc(r.record_sha)+'</span><br>':'')+'Immutable · a newer version creates a new record · identity fields correctable by an administrator only (audited)']]
          .map(function(kv){ return '<tr><td>'+kv[0]+'</td><td>'+(kv[1]||'—')+'</td></tr>'; }).join('')+'</tbody></table></div>'
        +'<div class="apv4-card" style="margin-bottom:14px"><div style="padding:10px 14px;border-bottom:1px solid #e5e7eb;font-weight:700;font-size:13px">Acknowledgment history — '+esc(r.name)+'</div><div style="padding:12px 14px">'+(hist||'<span style="color:#6b7280;font-size:12px">—</span>')+'</div></div>'
        +(admin?'<div class="apv4-card"><div style="padding:10px 14px;border-bottom:1px solid #e5e7eb;font-weight:700;font-size:13px">Audit events <span style="font-size:10px;font-weight:800;color:#991b1b;background:#fee2e2;border-radius:999px;padding:2px 7px;margin-left:6px">ADMIN ONLY</span></div>'+(aud?'<table class="apv4-tbl"><thead><tr><th>When</th><th>Event</th><th>Actor</th><th>Detail</th></tr></thead><tbody>'+aud+'</tbody></table>':'<div style="padding:12px 14px;color:#6b7280;font-size:12px">No events on this record.</div>')+'</div>':'')
        +'</div></div>';
      ov.querySelector('#aa2-close').onclick=function(){ ov.remove(); };
      if(admin){
        ov.querySelector('#aa2-edit').onclick=function(){ var b=ov.querySelector('#aa2-editbox'); b.style.display=b.style.display==='none'?'block':'none'; };
        ov.querySelector('#aa2-cancel').onclick=function(){ ov.querySelector('#aa2-editbox').style.display='none'; };
        var rb=ov.querySelector('#aa2-reack'), rbox=ov.querySelector('#aa2-reackbox');
        if(rb&&rbox){
          rb.onclick=function(){ rbox.style.display=rbox.style.display==='none'?'block':'none'; if(rbox.style.display==='block') rbox.querySelector('#aa2-reack-reason').focus(); };
          rbox.querySelector('#aa2-reack-cancel').onclick=function(){ rbox.style.display='none'; };
          rbox.querySelector('#aa2-reack-go').onclick=function(){
            var reason=rbox.querySelector('#aa2-reack-reason').value.trim(), notify=rbox.querySelector('#aa2-reack-notify').checked, er=rbox.querySelector('#aa2-reack-err'); er.textContent='';
            if(!reason){ er.textContent='A reason is required.'; return; }
            api('POST','/api/portal/acknowledgments/'+r.id+'/request-reack',{reason:reason,notify:notify}).then(function(d){ toast('Re-acknowledgment requested'+(notify?(d.notified?' · email sent':' · email FAILED'):'')); openRecord(r.id); render(); }).catch(function(e){ er.textContent=e.message; });
          };
        }
        ov.querySelector('#aa2-save').onclick=function(){
          var body={reason:ov.querySelector('#aa2-reason').value.trim()}; ov.querySelectorAll('[data-f]').forEach(function(i){ body[i.getAttribute('data-f')]=i.value.trim(); });
          var err=ov.querySelector('#aa2-err'); err.textContent='';
          api('PATCH','/api/portal/acknowledgments/'+r.id+'/identity',body).then(function(d){ toast(d.changed?('Saved · '+d.changed+' field'+(d.changed===1?'':'s')+' corrected'):'No changes'); openRecord(r.id); render(); }).catch(function(e){ err.textContent=e.message; });
        };
      }
    }).catch(function(e){ toast('Could not open record: '+e.message); });
  }

  function showPage(){
    document.querySelectorAll('[id^="apv4-page-"]').forEach(function(p){ p.style.display='none'; });
    var pg=document.getElementById(PAGE); if(pg){ pg.style.display='block'; render(); }
    document.querySelectorAll('[id^="apv4-sb-"]').forEach(function(s){ s.style.background=''; s.style.color='#9ca3af'; });
    var sb=document.getElementById(SB); if(sb){ sb.style.background='#1f2937'; sb.style.color='#fff'; }
  }
  function hidePage(){ var pg=document.getElementById(PAGE); if(pg) pg.style.display='none'; }
  function wrapNav(){ var n=window.apv4Nav; if(typeof n==='function'&&!n.__aa2){ window.apv4Nav=function(){ hidePage(); return n.apply(this,arguments); }; window.apv4Nav.__aa2=1; } }
  function inject(){
    if(!mode) return;
    var root=document.getElementById('apv4-root'); if(!root) return;
    var anyPage=root.querySelector('[id^="apv4-page-"]');
    if(anyPage && !document.getElementById(PAGE)){ var pg=document.createElement('div'); pg.id=PAGE; pg.style.display='none'; anyPage.parentNode.appendChild(pg); }
    if(!document.getElementById(SB)){
      var items=[].slice.call(root.querySelectorAll('[id^="apv4-sb-"]')), after=null;
      if(mode==='admin'){ items.forEach(function(s){ if(/site content/i.test(s.textContent)) after=s; }); if(!after) items.forEach(function(s){ if(/notification/i.test(s.textContent)) after=s; }); }
      if(!after && items.length) after=items[items.length-1];
      if(after){ var el=after.cloneNode(false); el.id=SB; el.removeAttribute('onclick'); el.innerHTML='<span style="width:18px;display:inline-block;text-align:center">✍</span> '+(mode==='admin'?'Claude Access Acknowledgments':'Team Acknowledgments');
        el.style.background=''; el.style.color='#9ca3af'; el.onclick=function(e){ e.preventDefault(); showPage(); }; after.parentNode.insertBefore(el, after.nextSibling); }
    }
    if(mode==='admin'){ var slot=document.getElementById('pc-cla-versions'); if(slot && !slot.getAttribute('data-filled')){ slot.setAttribute('data-filled','1'); versionsInto(slot, true); } }
    if(mode==='team') roleTile();
    wrapNav();
  }
  /* Team mode on the role screen: a manager who holds no approval access never reaches a dashboard
     sidebar, so the role grid gets a "Team Acknowledgments" tile that opens the page in place. */
  function roleTile(){
    var grid=document.getElementById('apv4-role-grid'); if(!grid || grid.querySelector('[data-role="ack-team"]')) return;
    var empty=grid.querySelector('.apv4-empty'); if(empty) empty.remove();
    var n=(me.team_ack_count|0);
    var t=document.createElement('div'); t.className='apv4-role-tile'; t.setAttribute('data-role','ack-team'); t.setAttribute('role','button'); t.tabIndex=0;
    t.innerHTML='<div class="apv4-role-icon" style="background:#dcfce7">✍</div><div class="apv4-role-body" style="display:flex;flex-direction:column;gap:8px;flex:1;min-width:0"><div data-role-title style="font-size:14px;font-weight:600;color:#111827">Team Acknowledgments</div><div style="font-size:12px;color:#6b7280;line-height:1.55;flex:1">AI Policy acknowledgments completed by people who list you as their manager. View and download the audit record.</div><div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:4px"><span class="apv4-pill" style="background:#e0f2fe;color:#0369a1">Records only · no approvals</span><span class="apv4-pill" style="background:#d1fae5;color:#059669">'+n+' record'+(n===1?'':'s')+'</span></div></div>';
    t.onclick=standalone; t.onkeydown=function(e){ if(e.key==='Enter'||e.key===' '){ e.preventDefault(); standalone(); } };
    grid.appendChild(t);
  }
  function standalone(){
    var grid=document.getElementById('apv4-role-grid'); if(!grid) return;
    var host=grid.parentNode, box=document.getElementById('aa2-standalone');
    if(!box){ box=document.createElement('div'); box.id='aa2-standalone'; box.style.display='none';
      box.innerHTML='<div style="margin-bottom:14px"><button class="apv4-btn sm" id="aa2-back">← Back to roles</button></div><div id="'+PAGE+'"></div>';
      host.appendChild(box); box.querySelector('#aa2-back').onclick=function(){ box.style.display='none'; grid.style.display=''; var nh=document.getElementById('apv4-role-note-host'); if(nh) nh.style.display=''; }; }
    grid.style.display='none'; var nh=document.getElementById('apv4-role-note-host'); if(nh) nh.style.display='none';
    box.style.display='block'; render();
  }
  function boot(){
    css();
    fetch('/api/portal/auth/me',{credentials:'same-origin'}).then(function(r){return r.json();}).then(function(j){
      me=(j&&j.data)||j||{}; var role=me.role||null;
      mode = role==='admin' ? 'admin' : ((me.team_ack_count|0)>0 ? 'team' : null);
      if(!mode) return;
      inject();
      var sb=document.getElementById('apv4-root'), t;
      if(sb&&window.MutationObserver) new MutationObserver(function(){ clearTimeout(t); t=setTimeout(inject,150); }).observe(sb,{childList:true,subtree:true});
      var n=0, iv=setInterval(function(){ if(++n>20){clearInterval(iv);return;} inject(); },700);
    }).catch(function(e){ console.warn('[ack-admin]',e); });
  }
  window.portalAck={openRecord:openRecord,recordUrl:recordUrl,mode:function(){return mode;}};
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',boot); else boot();
})();
