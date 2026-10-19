/* portal-archive.js — Archiving for the approver console (v2, 2026-09-30: filter bar on the Archived page; opened archived rows no longer linger in the console's counts).
   Archive = a flag, never a delete. Archived requests / acknowledgments leave every working list and count;
   they stay in the database, audit trail, exports and the requester's tracker, and can be un-archived.
     • Any approver: archive COMPLETED requests in their own scope (drawer button, or select + "Archive selected")
     • Administrator: also pending requests, acknowledgments, un-archive, and the date sweep (Administration → Archive)
     • Everyone: sidebar "Archived" page, scoped to what the role can see
   Hooks used by portal-rm.js: RMARC.enabled/selHead/selCell/bulkBar/bind/drawer/onRole. */
(function(){
  'use strict';
  var X=window.APX; if(!X||!X.S){ console.warn('[archive] console hooks missing'); return; }
  var S=X.S, esc=X.esc, toast=X.toast, fmtDate=X.fmtDate, fmtDT=X.fmtDT, typeLabel=X.typeLabel, statusPill=X.statusPill, loadRequests=X.loadRequests;
  var E=esc; function $(id){ return document.getElementById(id); }
  var PAGE='apv4-page-archived', SB='apv4-sb-archived', APAGE='apv4-page-archive-admin', ASB='apv4-sb-archive-admin';
  var sel={};            // key "approval:ID" | "record:ID" -> true
  var A=window.RMARC={};

  function admin(){ return S.role==='admin'; }
  function api(method,path,body){
    return fetch(path,{method:method,credentials:'same-origin',headers:{'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined})
      .then(function(r){ return r.json().catch(function(){return {};}).then(function(j){ if(!r.ok||j.ok===false){ var e=new Error((j&&j.error)||('HTTP '+r.status)); throw e; } return j.data!==undefined?j.data:j; }); });
  }
  function canArchiveRow(u){ if(u.kind==='record') return admin(); if(u.status==='pending') return admin(); return true; }
  function key(u){ return u.kind+':'+(u.kind==='record'?u.ackId:u.id); }
  function count(){ return Object.keys(sel).length; }

  /* ── hooks for portal-rm.js lists ─────────────────────────────────────── */
  A.enabled=function(page){ return page==='all'||page==='completed'; };
  A.selHead=function(){ return '<th style="width:34px"><input type="checkbox" id="arc-all" title="Select all on this page"></th>'; };
  A.selCell=function(u){
    var ok=canArchiveRow(u), k=key(u);
    return '<td onclick="event.stopPropagation()" style="width:34px"><input type="checkbox" class="arc-sel" data-k="'+E(k)+'" '+(sel[k]?'checked':'')+(ok?'':' disabled title="Still pending — administrators only"')+'></td>';
  };
  A.bulkBar=function(page){
    var n=count();
    return '<div id="arc-bulk" style="display:'+(n?'flex':'none')+';gap:10px;align-items:center;background:#111827;color:#fff;border-radius:10px;padding:9px 14px;margin:0 0 10px;font-size:13px">'
      +'<b id="arc-n">'+n+' selected</b>'
      +'<button class="apv4-btn sm" id="arc-go" style="background:#f59e0b;border-color:#f59e0b;color:#111">▣ Archive selected…</button>'
      +'<button class="apv4-btn sm" id="arc-clear" style="background:#374151;border-color:#374151;color:#fff">Clear</button>'
      +'<span style="margin-left:auto;color:#9ca3af;font-size:12px">Archived items leave every list and count · nothing is deleted · reason required</span></div>'
      +'<div id="arc-box" style="display:none;border:1px solid #fcd34d;background:#fffbeb;border-radius:10px;padding:12px 14px;margin:0 0 10px">'
      +'<div style="font-weight:700;font-size:13px;color:#92400e;margin-bottom:6px">Archive <span id="arc-box-n"></span></div>'
      +'<div style="font-size:12px;color:#92400e;margin-bottom:8px">They move to <b>Archived</b> in the sidebar. Records, history and Word/PDF exports stay available'+(admin()?'; an administrator can un-archive':'')+'.</div>'
      +'<input class="apv4-field" id="arc-reason" placeholder="Reason (required · written to the audit trail) — e.g. Pre-go-live test data" style="width:100%;margin:0 0 8px">'
      +'<div style="display:flex;gap:8px;justify-content:flex-end"><button class="apv4-btn sm" id="arc-cancel">Cancel</button><button class="apv4-btn sm pri" id="arc-confirm">▣ Archive</button></div><div id="arc-err" style="color:#b91c1c;font-size:12px;margin-top:6px"></div></div>';
  };
  A.bind=function(page){
    var pg=$('apv4-page-'+page); if(!pg) return;
    function refreshBar(){ var n=count(); var b=pg.querySelector('#arc-bulk'); if(b){ b.style.display=n?'flex':'none'; var nn=b.querySelector('#arc-n'); if(nn) nn.textContent=n+' selected'; } }
    pg.querySelectorAll('.arc-sel').forEach(function(c){ c.onchange=function(){ var k=c.getAttribute('data-k'); if(c.checked) sel[k]=true; else delete sel[k]; refreshBar(); }; });
    var all=pg.querySelector('#arc-all'); if(all) all.onchange=function(){ pg.querySelectorAll('.arc-sel:not(:disabled)').forEach(function(c){ c.checked=all.checked; var k=c.getAttribute('data-k'); if(all.checked) sel[k]=true; else delete sel[k]; }); refreshBar(); };
    var clr=pg.querySelector('#arc-clear'); if(clr) clr.onclick=function(){ sel={}; pg.querySelectorAll('.arc-sel').forEach(function(c){ c.checked=false; }); refreshBar(); };
    var go=pg.querySelector('#arc-go'), box=pg.querySelector('#arc-box');
    if(go&&box){ go.onclick=function(){ box.style.display='block'; box.querySelector('#arc-box-n').textContent=count()+' item'+(count()===1?'':'s'); box.querySelector('#arc-reason').focus(); };
      box.querySelector('#arc-cancel').onclick=function(){ box.style.display='none'; };
      box.querySelector('#arc-confirm').onclick=function(){ var reason=box.querySelector('#arc-reason').value.trim(), er=box.querySelector('#arc-err'); er.textContent=''; if(!reason){ er.textContent='A reason is required.'; return; }
        archive(Object.keys(sel),reason,false).then(function(d){ toast('Archived '+d.count+(d.skipped.length?' · skipped '+d.skipped.length:'')); sel={}; }).catch(function(e){ er.textContent=e.message; }); };
    }
  };
  function archive(keys,reason,undo){
    var body={reason:reason,undo:!!undo,requests:[],acknowledgments:[]};
    keys.forEach(function(k){ var p=k.split(':'); if(p[0]==='record') body.acknowledgments.push(+p[1]); else body.requests.push(p[1]); });
    return api('POST','/api/portal/archive',body).then(function(d){ if(d.skipped&&d.skipped.length) console.info('[archive] skipped',d.skipped); if(window.RM&&RM.invalidateAcks) RM.invalidateAcks(); if(window.AP&&typeof AP.closeDrawer==='function') AP.closeDrawer(); loadRequests(); if(S.page==='archived') setTimeout(renderArchived,300); return d; });
  }

  /* ── drawer: Archive / Un-archive + banner; approvals hidden while archived ─ */
  A.drawer=function(hd,r){
    /* called from a MutationObserver on the drawer: only touch the DOM when the record or its archive state changed */
    var k=r?(r.id+'|'+(r.archived_at||'')+'|'+(r.status||'')):'';
    if(hd.getAttribute('data-arc')===k) return; hd.setAttribute('data-arc',k);
    var old=$('arc-dbtn'); if(old) old.remove(); var ob=$('arc-banner'); if(ob) ob.remove(); var obx=$('arc-dbox'); if(obx) obx.remove();
    var actions=$('apv4-draw-actions'); if(actions) actions.style.display='';
    if(!r) return;
    var box=document.createElement('div'); box.id='arc-dbtn'; box.style.cssText='display:flex;gap:6px;align-items:center;flex:none;margin-left:8px';
    var body=document.querySelector('#apv4-drawer .apv4-draw-body')||hd.parentNode.querySelector('[class*="draw-body"]')||hd.nextElementSibling;
    if(r.archived_at){
      if(admin()) box.innerHTML='<button class="apv4-btn sm" id="arc-undo" title="Return this request to the working lists">↶ Un-archive</button>';
      var ban=document.createElement('div'); ban.id='arc-banner'; ban.style.cssText='margin:0 22px 12px;border:1px solid #d1d5db;background:#f3f4f6;border-radius:10px;padding:10px 14px;font-size:12.5px;color:#374151';
      ban.innerHTML='<b>▣ Archived</b> '+fmtDT(r.archived_at)+' by '+E(r.archived_by||'')+(r.archived_reason?' — “'+E(r.archived_reason)+'”':'')+(r.archived_batch?' <span style="color:#6b7280">('+E(r.archived_batch)+')</span>':'')+(r.status==='pending'?'<div style="margin-top:4px;color:#92400e">Approvals are disabled while archived'+(admin()?' — un-archive to act.':'.')+'</div>':'');
      if(body) body.insertBefore(ban, body.firstChild);
      if(actions) actions.style.display='none';
    } else if(canArchiveRow({kind:'approval',status:r.status})){
      box.innerHTML='<button class="apv4-btn sm" id="arc-do" style="border-color:#f59e0b;color:#92400e" title="Move out of the working lists (nothing is deleted)">▣ Archive</button>';
    }
    if(!box.innerHTML) return;
    var x=hd.querySelector('.apv4-x'); if(x) hd.insertBefore(box,x); else hd.appendChild(box);
    var d=box.querySelector('#arc-do'), u=box.querySelector('#arc-undo');
    if(d) d.onclick=function(){
      var ex=$('arc-dbox'); if(ex){ ex.remove(); return; }
      var bx=document.createElement('div'); bx.id='arc-dbox'; bx.style.cssText='margin:0 22px 12px;border:1px solid #fcd34d;background:#fffbeb;border-radius:10px;padding:12px 14px;font-size:12.5px';
      bx.innerHTML='<div style="font-weight:700;color:#92400e;margin-bottom:6px">Archive '+E(r.id)+'</div><div style="color:#92400e;margin-bottom:8px">It leaves every working list and count. The record, its history and exports stay available under <b>Archived</b>'+(r.status==='pending'?'. <b>This request is still pending</b> — while archived no approver can act on it and no notifications are sent':'')+'.</div>'
        +'<input class="apv4-field" id="arc-dreason" placeholder="Reason (required · shown in the audit trail)" style="width:100%;margin:0 0 8px"><div style="display:flex;gap:8px;justify-content:flex-end"><button class="apv4-btn sm" id="arc-dcancel">Cancel</button><button class="apv4-btn sm" id="arc-dgo" style="background:#f59e0b;border-color:#f59e0b;color:#111">▣ Archive request</button></div><div id="arc-derr" style="color:#b91c1c;font-size:12px;margin-top:6px"></div>';
      if(body) body.insertBefore(bx, body.firstChild);
      bx.querySelector('#arc-dcancel').onclick=function(){ bx.remove(); };
      bx.querySelector('#arc-dgo').onclick=function(){ var reason=bx.querySelector('#arc-dreason').value.trim(), er=bx.querySelector('#arc-derr'); er.textContent=''; if(!reason){ er.textContent='A reason is required.'; return; }
        archive(['approval:'+r.id],reason,false).then(function(dd){ toast(dd.count?'Archived '+r.id:'Not archived — '+((dd.skipped[0]||{}).why||'')); }).catch(function(e){ er.textContent=e.message; }); };
      bx.querySelector('#arc-dreason').focus();
    };
    if(u) u.onclick=function(){ var reason=prompt('Reason for un-archiving '+r.id+' (audited):'); if(!reason) return; archive(['approval:'+r.id],reason,true).then(function(dd){ toast(dd.count?'Un-archived '+r.id:'Not changed'); }).catch(function(e){ toast(e.message); }); };
  };

  /* ── Archived page (everyone, scoped) ─────────────────────────────────── */
  var arch={reqs:[],acks:[],at:0,q:''};
  var AF={type:'',status:'',dept:'',by:'',sfrom:'',sto:'',afrom:'',ato:'',sort:'newest'};
  function resetAF(){ AF={type:'',status:'',dept:'',by:'',sfrom:'',sto:'',afrom:'',ato:'',sort:'newest'}; }
  function loadArchived(){
    var p=[fetch('/api/portal/requests?archived=1',{credentials:'same-origin'}).then(function(r){return r.json();}).then(function(j){ arch.reqs=(j&&j.data)||[]; }).catch(function(){ arch.reqs=[]; })];
    if(admin()) p.push(fetch('/api/portal/acknowledgments?form=cla&archived=1',{credentials:'same-origin'}).then(function(r){return r.json();}).then(function(j){ arch.acks=(j&&j.data&&j.data.rows)||[]; }).catch(function(){ arch.acks=[]; }));
    else arch.acks=[];
    return Promise.all(p).then(function(){ arch.at=Date.now(); });
  }
  var injected={};
  function openArchivedReq(id){
    var r=arch.reqs.find(function(x){return x.id===id;}); if(!r) return;
    if(!S.reqs.some(function(x){return x.id===id;})) { S.reqs.push(r); injected[id]=true; } else S.reqs=S.reqs.map(function(x){return x.id===id?r:x;});
    AP.openReq(id);
  }
  /* an archived row is lent to the console only while its drawer is open; on close it is removed so sidebar badges stay right */
  if(window.AP&&typeof AP.closeDrawer==='function'&&!AP.closeDrawer.__arc){ var _cd=AP.closeDrawer; AP.closeDrawer=function(){ var out=_cd.apply(this,arguments); var ids=Object.keys(injected); if(ids.length){ S.reqs=S.reqs.filter(function(x){ return !injected[x.id]; }); injected={}; loadRequests(); } return out; }; AP.closeDrawer.__arc=1; }
  window.__arcOpen=function(kind,id){ if(kind==='record'){ if(window.portalAck&&window.portalAck.openRecord) window.portalAck.openRecord(+id); } else openArchivedReq(id); };
  function renderArchived(){
    var el=$(PAGE); if(!el) return;
    el.innerHTML='<div style="padding:8px 0;color:#6b7280;font-size:13px">Loading…</div>';
    loadArchived().then(function(){
      var q=arch.q.toLowerCase();
      var rows=arch.reqs.map(function(r){ var s=r.submitter||{}; return {kind:'approval',id:r.id,type:typeLabel(r.type),name:s.name||'',dept:s.dept||'',created:r.created_at,status:r.status,archived_at:r.archived_at,archived_by:r.archived_by,archived_reason:r.archived_reason,raw:r}; })
        .concat(arch.acks.map(function(a){ return {kind:'record',id:'ACK-'+String(a.id).padStart(6,'0'),ackId:a.id,type:'Claude Access – AI Policy Acknowledgment',name:a.name||'',dept:a.dept||'',created:a.created_at,status:a.status,archived_at:a.archived_at,archived_by:a.archived_by,archived_reason:a.archived_reason}; }));
      var allRows=rows.slice();
      if(q) rows=rows.filter(function(u){ return (u.id+' '+u.type+' '+u.name+' '+u.dept+' '+(u.archived_reason||'')+' '+(u.archived_by||'')).toLowerCase().indexOf(q)>-1; });
      function d10(x){ return String(x||'').slice(0,10); }
      rows=rows.filter(function(u){
        if(AF.type&&u.type!==AF.type) return false;
        if(AF.status&&(u.kind==='record'?'acknowledged':u.status)!==AF.status) return false;
        if(AF.dept&&u.dept!==AF.dept) return false;
        if(AF.by&&(u.archived_by||'')!==AF.by) return false;
        if(AF.sfrom&&d10(u.created)<AF.sfrom) return false; if(AF.sto&&d10(u.created)>AF.sto) return false;
        if(AF.afrom&&d10(u.archived_at)<AF.afrom) return false; if(AF.ato&&d10(u.archived_at)>AF.ato) return false;
        return true; });
      rows.sort(function(a,b){ var A=a.archived_at||'', B=b.archived_at||''; if(AF.sort==='oldest') return A.localeCompare(B); if(AF.sort==='submitted') return (b.created||'').localeCompare(a.created||''); if(AF.sort==='name') return (a.name||'').localeCompare(b.name||''); return B.localeCompare(A); });
      function uniq(f){ var m={}; allRows.forEach(function(u){ var v=f(u); if(v) m[v]=1; }); return Object.keys(m).sort(); }
      function sel(id,label,opts,val){ return '<select class="apv4-field arc-f" id="'+id+'" style="margin:0;width:auto;max-width:220px"><option value="">'+label+'</option>'+opts.map(function(o){ var v=typeof o==='string'?o:o[0], t=typeof o==='string'?o:o[1]; return '<option value="'+E(v)+'"'+(val===v?' selected':'')+'>'+E(t)+'</option>'; }).join('')+'</select>'; }
      var filterBar='<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:10px 14px;border-bottom:1px solid #e5e7eb;background:#fafafa;font-size:12px"><span style="font-size:10.5px;font-weight:800;letter-spacing:.06em;color:#6b7280">FILTERS</span>'
        +sel('arc-f-type','Type: all',uniq(function(u){return u.type;}),AF.type)
        +sel('arc-f-status','Status at archive: all',[['pending','Awaiting approval'],['approved','Approved'],['rejected','Rejected'],['returned','Returned'],['closed','Closed'],['acknowledged','Acknowledged']].filter(function(o){ return allRows.some(function(u){ return (u.kind==='record'?'acknowledged':u.status)===o[0]; }); }),AF.status)
        +sel('arc-f-dept','Department: any',uniq(function(u){return u.dept;}),AF.dept)
        +sel('arc-f-by','Archived by: anyone',uniq(function(u){return u.archived_by;}),AF.by)
        +'<span style="color:#6b7280">Submitted</span><input class="apv4-field arc-f" type="date" id="arc-f-sfrom" value="'+E(AF.sfrom)+'" style="margin:0;width:150px"><input class="apv4-field arc-f" type="date" id="arc-f-sto" value="'+E(AF.sto)+'" style="margin:0;width:150px">'
        +'<span style="color:#6b7280">Archived</span><input class="apv4-field arc-f" type="date" id="arc-f-afrom" value="'+E(AF.afrom)+'" style="margin:0;width:150px"><input class="apv4-field arc-f" type="date" id="arc-f-ato" value="'+E(AF.ato)+'" style="margin:0;width:150px">'
        +sel('arc-f-sort','Sort',[['newest','Archived: newest first'],['oldest','Archived: oldest first'],['submitted','Submitted: newest first'],['name','Requester A–Z']],AF.sort).replace('<option value="">Sort</option>','')
        +'</div>';
      el.innerHTML='<div style="margin-bottom:12px"><div class="apv4-page-title">Archived</div><div class="apv4-page-sub">Requests'+(admin()?' and acknowledgments':'')+' moved out of the working views · nothing here is deleted · '+rows.length+' item'+(rows.length===1?'':'s')+(admin()?' · un-archive from a record or select below':'')+'</div></div>'
        +'<div class="apv4-card"><div style="padding:10px 14px;border-bottom:1px solid #e5e7eb;display:flex;gap:8px;align-items:center;flex-wrap:wrap"><input class="apv4-field" id="arc-q" placeholder="Search ID, name, department, reason…" value="'+E(arch.q)+'" style="flex:1;min-width:220px;margin:0"><button class="apv4-btn sm" id="arc-qgo">Search</button><button class="apv4-btn sm" id="arc-fclear">Clear</button><button class="apv4-btn sm" id="arc-csv">Export CSV</button>'+(admin()?'<button class="apv4-btn sm" id="arc-unsel" style="display:none">↶ Un-archive selected…</button>':'')+'<span style="font-size:12px;color:#6b7280;margin-left:auto">Showing '+rows.length+' of '+allRows.length+'</span></div>'+filterBar
        +(rows.length?'<div style="overflow-x:auto"><table class="apv4-tbl"><thead><tr>'+(admin()?'<th style="width:34px"><input type="checkbox" id="arc-uall"></th>':'')+'<th>Record</th><th>Requester</th><th>Submitted</th><th>Status at archive</th><th>Archived</th><th>Reason</th><th></th></tr></thead><tbody>'
          +rows.map(function(u){ var open='onclick="window.__arcOpen(\''+u.kind+'\',\''+E(u.kind==='record'?u.ackId:u.id)+'\')"'; return '<tr class="click" '+open+' style="opacity:.75">'+(admin()?'<td onclick="event.stopPropagation()"><input type="checkbox" class="arc-usel" data-k="'+E(u.kind+':'+(u.kind==='record'?u.ackId:u.id))+'"></td>':'')
            +'<td><span class="apv4-pill" style="background:#e5e7eb;color:#4b5563;font-size:10.5px">▣ Archived</span><div style="font-weight:700;color:#111827;margin-top:3px">'+E(u.type)+'</div><div style="font-family:ui-monospace,monospace;font-size:11.5px;color:#147299">'+E(u.id)+'</div></td>'
            +'<td><b style="color:#111827">'+E(u.name||'—')+'</b><div style="font-size:11.5px;color:#6b7280">'+E(u.dept||'')+'</div></td><td style="white-space:nowrap">'+fmtDate(u.created)+'</td><td>'+(u.kind==='record'?'<span class="apv4-pill" style="background:#d1fae5;color:#059669">Acknowledged</span>':statusPill(u.status))+'</td>'
            +'<td style="white-space:nowrap">'+fmtDT(u.archived_at)+'<div style="font-size:11px;color:#6b7280">'+E(u.archived_by||'')+'</div></td><td style="font-size:12px;color:#4b5563;max-width:260px">'+E(u.archived_reason||'')+'</td>'
            +'<td style="text-align:right"><button class="apv4-btn sm" '+open.replace('onclick="','onclick="event.stopPropagation();')+'>Open</button></td></tr>'; }).join('')+'</tbody></table></div>'
          :'<div class="apv4-empty" style="padding:28px;text-align:center;color:#6b7280">'+(allRows.length?'No archived items match the filters.':'Nothing archived.')+'</div>')+'</div>';
      el.querySelector('#arc-qgo').onclick=function(){ arch.q=el.querySelector('#arc-q').value; renderArchived(); };
      el.querySelector('#arc-fclear').onclick=function(){ arch.q=''; resetAF(); renderArchived(); };
      el.querySelectorAll('.arc-f').forEach(function(f){ f.onchange=function(){ AF.type=el.querySelector('#arc-f-type').value; AF.status=el.querySelector('#arc-f-status').value; AF.dept=el.querySelector('#arc-f-dept').value; AF.by=el.querySelector('#arc-f-by').value; AF.sfrom=el.querySelector('#arc-f-sfrom').value; AF.sto=el.querySelector('#arc-f-sto').value; AF.afrom=el.querySelector('#arc-f-afrom').value; AF.ato=el.querySelector('#arc-f-ato').value; AF.sort=el.querySelector('#arc-f-sort').value; arch.q=el.querySelector('#arc-q').value; renderArchived(); }; });
      el.querySelector('#arc-q').onkeydown=function(e){ if(e.key==='Enter'){ arch.q=e.target.value; renderArchived(); } };
      el.querySelector('#arc-csv').onclick=function(){ var h=['Record','Type','Requester','Department','Submitted','Status','Archived at','Archived by','Reason']; var lines=[h.join(',')].concat(rows.map(function(u){ return [u.id,u.type,u.name,u.dept,u.created,u.status,u.archived_at,u.archived_by,u.archived_reason].map(function(v){ return '"'+String(v==null?'':v).replace(/"/g,'""')+'"'; }).join(','); })); var b=new Blob([lines.join('\n')],{type:'text/csv'}); var a=document.createElement('a'); a.href=URL.createObjectURL(b); a.download='archived.csv'; a.click(); };
      if(admin()){ var usel={}; function ub(){ var b=el.querySelector('#arc-unsel'); if(b){ var n=Object.keys(usel).length; b.style.display=n?'':'none'; b.textContent='↶ Un-archive selected ('+n+')…'; } }
        el.querySelectorAll('.arc-usel').forEach(function(c){ c.onchange=function(){ var k=c.getAttribute('data-k'); if(c.checked) usel[k]=true; else delete usel[k]; ub(); }; });
        var ua=el.querySelector('#arc-uall'); if(ua) ua.onchange=function(){ el.querySelectorAll('.arc-usel').forEach(function(c){ c.checked=ua.checked; var k=c.getAttribute('data-k'); if(ua.checked) usel[k]=true; else delete usel[k]; }); ub(); };
        var ub2=el.querySelector('#arc-unsel'); if(ub2) ub2.onclick=function(){ var reason=prompt('Reason for un-archiving '+Object.keys(usel).length+' item(s) (audited):'); if(!reason) return; archive(Object.keys(usel),reason,true).then(function(d){ toast('Un-archived '+d.count); renderArchived(); }).catch(function(e){ toast(e.message); }); };
      }
    });
  }
  A.showArchived=function(){ showPage(PAGE,SB); renderArchived(); };

  /* ── Administration → Archive (sweep + recent) ────────────────────────── */
  function renderAdmin(){
    var el=$(APAGE); if(!el) return;
    var today=new Date(); var d=today.toISOString().slice(0,10);
    el.innerHTML='<div style="margin-bottom:12px"><div class="apv4-page-title">Archive</div><div class="apv4-page-sub">Move test or obsolete records out of the working views. Nothing is deleted; every action is audited and reversible.</div></div>'
      +'<div style="display:grid;grid-template-columns:3fr 2fr;gap:14px"><div class="apv4-card"><div style="padding:10px 14px;border-bottom:1px solid #e5e7eb;font-weight:700;font-size:13px">Archive by date — go-live sweep</div><div style="padding:14px 16px;font-size:13px">'
      +'<label style="font-size:11px;font-weight:700;color:#6b7280;text-transform:uppercase">Everything submitted before</label><div style="display:flex;gap:8px;margin:4px 0 10px;flex-wrap:wrap"><input class="apv4-field" type="date" id="arc-before" value="'+d+'" style="width:170px;margin:0">'
      +'<select class="apv4-field" id="arc-scope" style="width:auto;margin:0"><option value="both">Requests + acknowledgments</option><option value="requests">Requests only</option><option value="acknowledgments">Acknowledgments only</option></select></div>'
      +'<label style="font-size:13px;display:flex;gap:6px;align-items:center;margin:0 0 10px"><input type="checkbox" id="arc-pending" checked> Include still-pending requests (closed as “Archived”, nobody is notified)</label>'
      +'<label style="font-size:11px;font-weight:700;color:#6b7280;text-transform:uppercase">Reason (required · audited)</label><input class="apv4-field" id="arc-sreason" placeholder="e.g. Pre-go-live test data — portal live '+d+'" style="width:100%;margin:4px 0 10px">'
      +'<div id="arc-preview" style="border:1px solid #e5e7eb;background:#f9fafb;border-radius:10px;padding:10px 12px;font-size:12.5px;color:#4b5563">Click <b>Preview</b> to count what would be archived.</div>'
      +'<div style="display:flex;gap:8px;margin-top:12px;align-items:center;flex-wrap:wrap"><button class="apv4-btn sm" id="arc-prev">Preview</button><span id="arc-confirm-wrap" style="display:none;gap:8px;align-items:center"><input class="apv4-field" id="arc-typed" placeholder="Type ARCHIVE" style="width:150px;margin:0"><button class="apv4-btn sm pri" id="arc-run">▣ Archive <span id="arc-runn"></span></button></span><span id="arc-serr" style="color:#b91c1c;font-size:12px"></span></div>'
      +'</div></div>'
      +'<div class="apv4-card"><div style="padding:10px 14px;border-bottom:1px solid #e5e7eb;font-weight:700;font-size:13px">Recent archive actions</div><div id="arc-recent" style="padding:8px 0;font-size:12.5px;color:#6b7280"><div style="padding:8px 16px">Loading…</div></div>'
      +'<div style="padding:12px 16px;font-size:12px;color:#4b5563;line-height:1.7;border-top:1px solid #f3f4f6"><b>Rules</b><ul style="margin:4px 0 0;padding-left:18px"><li>Approvers archive completed requests in their scope; administrators archive anything and un-archive.</li><li>Reason required on every action; events: request.archived / unarchived, acknowledgment.archived / unarchived, archive.sweep.</li><li>Un-archive restores the prior state (a pending request re-enters its approver’s queue).</li><li>Archived acknowledgments do not count toward “Requires re-acknowledgment” and are skipped by the notify-all email; the person is treated as not yet acknowledged.</li></ul></div></div></div>';
    var last=null;
    function body(preview){ return {before:el.querySelector('#arc-before').value,scope:el.querySelector('#arc-scope').value,include_pending:el.querySelector('#arc-pending').checked,reason:el.querySelector('#arc-sreason').value.trim(),preview:preview,confirm:(el.querySelector('#arc-typed')||{}).value||''}; }
    el.querySelector('#arc-prev').onclick=function(){ var er=el.querySelector('#arc-serr'); er.textContent='';
      api('POST','/api/portal/archive/sweep',body(true)).then(function(p){ last=p; var bs=Object.keys(p.by_status||{}).map(function(k){ return p.by_status[k]+' '+k; }).join(' · ');
        el.querySelector('#arc-preview').innerHTML='<b>Preview:</b> '+p.requests+' request'+(p.requests===1?'':'s')+(bs?' ('+bs+')':'')+' and '+p.acknowledgments+' acknowledgment'+(p.acknowledgments===1?'':'s')+' submitted before '+E(p.before)+'. Nothing on or after that date is touched.'+(p.already_archived?' '+p.already_archived+' already archived — skipped.':'');
        el.querySelector('#arc-preview').style.background=p.total?'#f0fdf4':'#f9fafb'; var w=el.querySelector('#arc-confirm-wrap'); w.style.display=p.total?'inline-flex':'none'; el.querySelector('#arc-runn').textContent=p.total+' record'+(p.total===1?'':'s'); }).catch(function(e){ er.textContent=e.message; }); };
    el.querySelector('#arc-run').onclick=function(){ var er=el.querySelector('#arc-serr'); er.textContent=''; var b=body(false); if(!b.reason){ er.textContent='A reason is required.'; return; } if(b.confirm!=='ARCHIVE'){ er.textContent='Type ARCHIVE to confirm.'; return; }
      api('POST','/api/portal/archive/sweep',b).then(function(p){ toast('Archived '+p.total+' record'+(p.total===1?'':'s')+' · '+p.batch); if(window.RM&&RM.invalidateAcks) RM.invalidateAcks(); loadRequests(); renderAdmin(); }).catch(function(e){ er.textContent=e.message; }); };
    api('GET','/api/portal/archive/recent').then(function(d){ var ev=d.events||[]; var box=el.querySelector('#arc-recent');
      box.innerHTML='<div style="padding:6px 16px 10px;font-size:12px;color:#374151"><b>'+d.archived.requests+'</b> request'+(d.archived.requests===1?'':'s')+' · <b>'+d.archived.acknowledgments+'</b> acknowledgment'+(d.archived.acknowledgments===1?'':'s')+' currently archived · <a href="#" id="arc-view" style="color:#147299">view</a></div>'
        +(ev.length?ev.slice(0,25).map(function(e){ var n=e.note; if(e.event==='archive.sweep'){ try{ var j=JSON.parse(e.note); n=j.requests+' requests + '+j.acknowledgments+' acknowledgments before '+j.before+' · “'+(j.reason||'')+'” · '+j.batch; }catch(x){} } return '<div style="display:flex;gap:10px;padding:7px 16px;border-top:1px solid #f3f4f6"><span style="white-space:nowrap;color:#9ca3af;font-size:11.5px">'+fmtDT(e.created_at)+'</span><span style="flex:1;min-width:0"><b style="color:#111827">'+E(e.actor||'')+'</b> <code style="font-size:11px">'+E(e.event)+'</code>'+(e.request_id?' <span style="font-family:ui-monospace,monospace;color:#147299">'+E(e.request_id)+'</span>':'')+'<div style="color:#6b7280;overflow:hidden;text-overflow:ellipsis">'+E(n||'')+'</div></span></div>'; }).join(''):'<div style="padding:8px 16px;border-top:1px solid #f3f4f6">No archive actions yet.</div>');
      var v=box.querySelector('#arc-view'); if(v) v.onclick=function(e){ e.preventDefault(); A.showArchived(); }; }).catch(function(){});
  }

  /* ── pages + sidebar injection (same pattern as the acknowledgments module) ─ */
  function showPage(page,sb){
    document.querySelectorAll('[id^="apv4-page-"]').forEach(function(p){ p.style.display='none'; });
    var pg=$(page); if(pg) pg.style.display='block';
    document.querySelectorAll('[id^="apv4-sb-"]').forEach(function(s){ s.classList.remove('on'); s.style.background=''; s.style.color=''; });
    var el=$(sb); if(el){ el.classList.add('on'); }
    S.page=page===PAGE?'archived':'archive-admin';
    var sc=$('apv4-scroll'); if(sc) sc.scrollTop=0;
  }
  function inject(){
    var root=$('apv4-root'); if(!root) return;
    var anyPage=root.querySelector('[id^="apv4-page-"]'); if(!anyPage) return;
    [PAGE,APAGE].forEach(function(id){ if(!$(id)){ var pg=document.createElement('div'); pg.id=id; pg.style.display='none'; anyPage.parentNode.appendChild(pg); } });
    var items=[].slice.call(root.querySelectorAll('[id^="apv4-sb-"]'));
    if(!$(SB)){ var after=$('apv4-sb-completed')||items[items.length-1];
      if(after){ var el=after.cloneNode(false); el.id=SB; el.removeAttribute('onclick'); el.classList.remove('on'); el.innerHTML='<span class="ic">▣</span><span style="flex:1">Archived</span>'; el.style.background=''; el.style.color=''; el.onclick=function(e){ e.preventDefault(); A.showArchived(); }; after.parentNode.insertBefore(el, after.nextSibling); } }
    if(admin()&&!$(ASB)){ var aft=null; items.forEach(function(s){ if(/site content/i.test(s.textContent)) aft=s; }); var ack=$('apv4-sb-ack-admin'); if(ack) aft=ack; if(!aft) aft=$('apv4-sb-notifications')||items[items.length-1];
      if(aft){ var e2=aft.cloneNode(false); e2.id=ASB; e2.removeAttribute('onclick'); e2.classList.remove('on'); e2.innerHTML='<span class="ic">🗄</span><span style="flex:1">Archive</span>'; e2.style.background=''; e2.style.color=''; e2.onclick=function(ev){ ev.preventDefault(); showPage(APAGE,ASB); renderAdmin(); }; aft.parentNode.insertBefore(e2, aft.nextSibling); } }
  }
  A.onRole=function(){ sel={}; arch={reqs:[],acks:[],at:0,q:''}; resetAF(); injected={}; setTimeout(inject,50); };
  /* the console rebuilds the sidebar on every render — re-inject after portal-rm.js has relabelled it */
  if(window.RM){ var _prevAS=RM.afterSidebar; RM.afterSidebar=function(el){ if(_prevAS) _prevAS(el); inject(); if(S.page==='archived'){ var x=$(SB); if(x) x.classList.add('on'); } if(S.page==='archive-admin'){ var y=$(ASB); if(y) y.classList.add('on'); } }; }
  inject();
  console.info('[archive] loaded');
})();
