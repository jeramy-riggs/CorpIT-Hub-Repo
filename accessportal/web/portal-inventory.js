/* portal-inventory.js — AI/ML Use Inventory for the approver console (v1, 2026-10-14).
   InfoSec / Legal / administrators only (server-enforced). The workbook AI_ML_Use_Inventory_Tracker,
   column for column, inside the portal: dashboard + table, fully editable record drawer, import from
   the workbook, export back to it, and the intake coverage map. Rows appear automatically when an
   AI Use Case Intake request is approved; the intake form itself is unchanged. */
(function(){
  'use strict';
  var X=window.APX; if(!X||!X.S){ console.warn('[inventory] console hooks missing'); return; }
  var S=X.S, esc=X.esc, toast=X.toast, fmtDate=X.fmtDate, fmtDT=X.fmtDT;
  var E=esc; function $(id){ return document.getElementById(id); }
  var PAGE='apv4-page-inventory', SB='apv4-sb-inventory', PAGE2='apv4-page-inventory-gaps', SB2='apv4-sb-inventory-gaps', PAGE3='apv4-page-inventory-import', SB3='apv4-sb-inventory-import';
  var cache=null, FIELDS=[], QF='all', F={q:'',status:'',cat:'',tier:'',dept:'',archived:''}, EDIT=false, CUR=null, COV=null;
  var SECTIONS=['Identity & ownership','Platform & access','Data','Third party & monitoring','Users & oversight','Governance','InfoSec / Legal review'];
  var SRC={intake:['From intake','#d1fae5','#059669'],intake_partial:['Partial / derived','#fef3c7','#b45309'],infosec:['Entered by InfoSec','#e0f2fe','#0369a1'],import:['Imported','#e0f2fe','#0369a1'],missing:['Missing','#fee2e2','#b91c1c'],calc:['Calculated','#e5e7eb','#4b5563']};
  function allowed(){ return !!((S.me||{}).inventory); }
  function api(method,path,body,raw){
    var o={method:method,credentials:'same-origin',headers:{}};
    if(raw){ o.body=raw.body; o.headers['Content-Type']='application/octet-stream'; o.headers['X-File-Name']=raw.name; }
    else if(body){ o.body=JSON.stringify(body); o.headers['Content-Type']='application/json'; }
    return fetch(path,o).then(function(r){ return r.json().catch(function(){return {};}).then(function(j){ if(!r.ok||j.ok===false){ throw new Error((j&&j.error)||('HTTP '+r.status)); } return j.data!==undefined?j.data:j; }); });
  }
  function pill(t,bg,fg,extra){ return '<span class="apv4-pill" style="background:'+bg+';color:'+fg+';font-size:10.5px;'+(extra||'')+'">'+t+'</span>'; }
  function tier(t){ var m={High:['#fee2e2','#b91c1c'],Medium:['#fef3c7','#b45309'],Low:['#d1fae5','#059669']}; return t?pill(t,m[t][0],m[t][1]):pill('Not set','#e5e7eb','#4b5563'); }
  function yn(v){ return v==='Yes'?pill('Yes','#fee2e2','#b91c1c'):v==='Unsure'?pill('Unsure','#fef3c7','#b45309'):v?pill(E(v),'#e5e7eb','#4b5563'):'<span style="color:#b91c1c;font-weight:700">—</span>'; }
  function load(force){
    if(cache&&!force) return Promise.resolve(cache);
    return api('GET','/api/portal/inventory?archived='+(F.archived||'')).then(function(d){ cache=d; FIELDS=d.fields||[]; return d; });
  }

  /* ── dashboard + table ────────────────────────────────────────────────── */
  function parseQ(q){ var f={}; q=q.replace(/(\w+):(\S+)/g,function(m,k,v){ f[k.toLowerCase()]=v.toLowerCase(); return ''; }); return [f,q.trim().toLowerCase()]; }
  function render(){
    var el=$(PAGE); if(!el) return;
    el.innerHTML='<div style="padding:8px 0;color:#6b7280;font-size:13px">Loading…</div>';
    load(true).then(function(d){
      var s=d.summary, rows=d.rows, pq=parseQ(F.q), pf=pq[0], free=pq[1];
      var depts=[]; rows.forEach(function(r){ var v=r.data.dept; if(v&&depts.indexOf(v)<0) depts.push(v); }); depts.sort();
      var list=rows.filter(function(r){ var D=r.data;
        if(F.status&&D.status!==F.status) return false; if(F.cat&&D.cat!==F.cat) return false; if(F.dept&&D.dept!==F.dept) return false;
        if(F.tier==='none'?D.tier:(F.tier&&D.tier!==F.tier)) return false;
        if(pf.dept&&(D.dept||'').toLowerCase().indexOf(pf.dept)<0) return false; if(pf.vendor&&(D.vendor||'').toLowerCase().indexOf(pf.vendor)<0) return false; if(pf.tier&&((D.tier||'none').toLowerCase()!==pf.tier)) return false; if(pf.status&&(D.status||'').toLowerCase().indexOf(pf.status)<0) return false;
        if(free&&(r.inv_id+' '+r.request_id+' '+D.name+' '+D.what+' '+D.dept+' '+D.bowner+' '+D.towner+' '+D.vendor+' '+D.model).toLowerCase().indexOf(free)<0) return false;
        switch(QF){case 'flag':return r.flag==='Review for High';case 'untiered':return !D.tier;case 'due':return r.overdue;case 'gaps':return r.blank>0;case 'nointake':return D.intake!=='Yes';case 'client':return D.client==='Yes';case 'agentic':return D.agentic==='Yes';default:return true;} });
      function st(n,l,m,bg,ic,q){ return '<div class="apv4-stat" style="cursor:pointer" data-q="'+q+'"><div style="display:inline-flex;width:30px;height:30px;border-radius:8px;align-items:center;justify-content:center;font-weight:900;background:'+bg+';margin-bottom:6px">'+ic+'</div><div style="font-size:26px;font-weight:800;line-height:1.1">'+n+'</div><div style="font-size:12.5px;font-weight:700">'+l+'</div><div style="font-size:11px;color:#6b7280">'+m+'</div></div>'; }
      function kv(obj){ return '<div style="display:grid;grid-template-columns:1fr auto;gap:3px 10px;font-size:12px">'+obj.map(function(p){ return '<span>'+p[0]+'</span><b>'+p[1]+'</b>'; }).join('')+'</div>'; }
      var bs=s.by_status, bt=s.by_tier, rk=s.risk, ct=s.controls;
      el.innerHTML='<div style="margin-bottom:12px"><div class="apv4-page-title">AI/ML Use Inventory</div><div class="apv4-page-sub">One row per use case. Rows appear automatically when an AI Use Case Intake request is approved; InfoSec / Legal complete and review them. <b>Complete as of '+E(s.as_of)+'</b>'+(s.archived?' · <a href="#" id="inv-arch" style="color:#147299">'+s.archived+' archived</a>':'')+'</div></div>'
        +'<div class="apv4-grid4" style="grid-template-columns:repeat(auto-fit,minmax(170px,1fr));margin-bottom:12px">'
        +st(s.total,'Use cases recorded',bs['Production']+' production · '+bs['Pilot / POC']+' pilot · '+bs['In development']+' in development','#dbeafe','#','all')
        +st(s.untiered,'No risk tier yet','awaiting InfoSec / Legal review','#fef3c7','?','untiered')
        +st(s.flagged,'Auto-flag: Review for High','NPI, client, consumer data, external output or fully automated','#fee2e2','!','flag')
        +st(s.overdue,'Review overdue','next review due before today','#fef3c7','⏰','due')
        +st(s.needs_details,'Needs inventory details','rows with 1+ required column blank','#fee2e2','▢','gaps')
        +st(s.no_intake,'No intake form','never submitted via the portal','#e5e7eb','✎','nointake')+'</div>'
        +'<div class="apv4-grid4" style="grid-template-columns:repeat(auto-fit,minmax(230px,1fr));margin-bottom:14px">'
        +'<div class="apv4-card" style="padding:12px 14px"><b style="font-size:12.5px">Risk indicators</b><div style="font-size:11px;color:#6b7280;margin-bottom:6px">rows answering Yes</div>'+kv([['Processes NPI',rk.npi],['Processes client data',rk.client],['Consumer (SmartSale) data',rk.consumer],['Output reaches external parties',rk.ext],['Agentic',rk.agentic],['Fully automated',rk.automated],['Public / consumer instance',rk.public]])+'</div>'
        +'<div class="apv4-card" style="padding:12px 14px"><b style="font-size:12.5px">Control gaps</b><div style="font-size:11px;color:#6b7280;margin-bottom:6px">rows needing follow-up</div>'+kv([['Not using Okta / SSO',ct.no_sso],['Logs not fully in SIEM',ct.siem_gap],['Vendor training Unknown / Not prohibited',rk.training_gap],['Data retained by third party',rk.third],['No intake form submitted',s.no_intake]])+'</div>'
        +'<div class="apv4-card" style="padding:12px 14px"><b style="font-size:12.5px">Review status</b><div style="font-size:11px;color:#6b7280;margin-bottom:6px">InfoSec / Legal tier</div>'+kv([[tier('High'),bt.High],[tier('Medium'),bt.Medium],[tier('Low'),bt.Low],[tier(''),s.untiered],['Client approval required',ct.capprov]])+'</div>'
        +'<div class="apv4-card" style="padding:12px 14px"><b style="font-size:12.5px">By category</b><div style="font-size:11px;color:#6b7280;margin-bottom:6px">workbook categories</div>'+kv(Object.keys(s.by_cat).map(function(k){ return [E(k.replace(/ \(.*\)/,'')),s.by_cat[k]]; }))+'<a href="#" id="inv-gaps-link" style="font-size:12px;font-weight:700;display:inline-block;margin-top:6px;color:#147299">Coverage gaps →</a></div></div>'
        +'<div class="apv4-card"><div style="padding:10px 14px;border-bottom:1px solid #e5e7eb;display:flex;gap:8px;align-items:center;flex-wrap:wrap">'
        +'<input class="apv4-field" id="inv-q" style="flex:1;min-width:220px;margin:0" placeholder="Search name, department, owner, vendor… or dept:Engineering vendor:bedrock tier:high" value="'+E(F.q)+'">'
        +sel('inv-f-status','Status: all',['Production','Pilot / POC','In development','Retired'],F.status)+sel('inv-f-cat','Category: all',(FIELDS.find(function(f){return f.key==='cat';})||{}).allowed||[],F.cat)+sel('inv-f-tier','Tier: any',[['High','High'],['Medium','Medium'],['Low','Low'],['none','Not set']],F.tier)+sel('inv-f-dept','Department: any',depts,F.dept)
        +'<button class="apv4-btn sm" id="inv-clear">Clear</button><a class="apv4-btn sm" href="/api/portal/inventory/export?format=xlsx" style="text-decoration:none">⬇ Excel</a><a class="apv4-btn sm" href="/api/portal/inventory/export?format=csv" style="text-decoration:none">⬇ CSV</a><button class="apv4-btn sm" id="inv-import">⬆ Import from workbook</button><button class="apv4-btn sm pri" id="inv-add">+ Add use case</button></div>'
        +'<div style="display:flex;gap:6px;flex-wrap:wrap;padding:8px 14px;border-bottom:1px solid #e5e7eb;align-items:center;font-size:11.5px;color:#6b7280"><span>Quick filters</span>'+[['all','All'],['flag','Auto-flag: Review for High'],['untiered','No tier'],['due','Review overdue'],['gaps','Needs inventory details'],['nointake','No intake form'],['client','Client data'],['agentic','Agentic']].map(function(c){ return '<span class="apv4-pill inv-chip" data-q="'+c[0]+'" style="cursor:pointer;'+(QF===c[0]?'background:#147299;color:#fff':'background:#fff;border:1px solid #e5e7eb;color:#111827')+'">'+c[1]+'</span>'; }).join('')+'</div>'
        +'<div style="overflow-x:auto"><table class="apv4-tbl"><thead><tr><th>ID · Use case</th><th>Dept / owners</th><th>Category · Status</th><th>Vendor · Access</th><th>Data</th><th>Auto-flag</th><th>Tier</th><th>Next review</th><th>Blank</th><th>Intake</th><th></th></tr></thead><tbody>'
        +(list.length?list.map(function(r){ var D=r.data; return '<tr class="click" data-id="'+r.id+'"'+(r.archived_at?' style="opacity:.6"':'')+'>'
          +'<td><b style="color:#111827">'+E(D.name||'(unnamed)')+'</b><div style="font-family:ui-monospace,monospace;font-size:11px;color:#147299">'+r.inv_id+(r.request_id?' · '+E(r.request_id):'')+(r.archived_at?' · <span style="color:#6b7280">archived</span>':'')+'</div></td>'
          +'<td>'+E(D.dept||'—')+'<div style="font-size:11px;color:#6b7280">'+E(D.bowner||'—')+' · '+(D.towner?E(D.towner):'<span style="color:#b91c1c;font-weight:700">tech owner missing</span>')+'</div></td>'
          +'<td>'+E((D.cat||'—').replace(/ \(.*\)/,''))+'<div style="font-size:11px;color:#6b7280">'+E(D.status||'—')+(D.golive?' · go-live '+E(D.golive):'')+'</div></td>'
          +'<td>'+(D.vendor?E(D.vendor):'<span style="color:#b91c1c;font-weight:700">—</span>')+'<div style="font-size:11px;color:#6b7280">'+E(D.access||'—')+' · '+(D.instance?E(D.instance):'<span style="color:#b91c1c">instance?</span>')+(D.agentic==='Yes'?' · <b>agentic</b>':'')+'</div></td>'
          +'<td style="white-space:nowrap;font-size:11px">NPI '+yn(D.npi)+' Client '+yn(D.client)+'<br>Consumer '+yn(D.consumer)+' Ext '+yn(D.ext)+'</td>'
          +'<td>'+(r.flag==='Review for High'?pill('⚑ Review for High','#fee2e2','#b91c1c'):pill('—','#e5e7eb','#4b5563'))+'</td><td>'+tier(D.tier)+'</td>'
          +'<td style="white-space:nowrap">'+(r.next?(r.overdue?pill('⏰ '+E(r.next),'#fef3c7','#b45309'):E(r.next)):'<span style="color:#b91c1c">—</span>')+'<div style="font-size:11px;color:#6b7280">'+(D.revdate?'reviewed '+E(D.revdate)+' · '+E(D.revby||''):'not reviewed')+'</div></td>'
          +'<td>'+(r.blank?pill(String(r.blank),'#fef3c7','#b45309'):pill('0','#d1fae5','#059669'))+'</td><td>'+(D.intake==='Yes'?pill('Yes','#d1fae5','#059669'):pill(E(D.intake||'No'),'#fee2e2','#b91c1c'))+'</td>'
          +'<td style="text-align:right"><button class="apv4-btn sm inv-open" data-id="'+r.id+'">Open</button></td></tr>'; }).join(''):'<tr><td colspan="11" style="text-align:center;color:#6b7280;padding:26px">'+(rows.length?'No use cases match.':'No use cases yet. Rows appear when an AI Use Case Intake request is approved, or add one / import the workbook.')+'</td></tr>')
        +'</tbody></table></div><div style="padding:9px 14px;font-size:11.5px;color:#6b7280;display:flex;justify-content:space-between;flex-wrap:wrap;gap:6px"><span>Showing '+list.length+' of '+rows.length+'</span><span>Every column is in the record · exports match the workbook layout</span></div></div>';
      function sel(id,label,opts,val){ return '<select class="apv4-field" id="'+id+'" style="margin:0;width:auto;max-width:220px"><option value="">'+label+'</option>'+opts.map(function(o){ var v=typeof o==='string'?o:o[0], t=typeof o==='string'?o:o[1]; return '<option value="'+E(v)+'"'+(val===v?' selected':'')+'>'+E(t)+'</option>'; }).join('')+'</select>'; }
      function read(){ F.q=$('inv-q').value; F.status=$('inv-f-status').value; F.cat=$('inv-f-cat').value; F.tier=$('inv-f-tier').value; F.dept=$('inv-f-dept').value; }
      el.querySelectorAll('.apv4-stat').forEach(function(x){ x.onclick=function(){ QF=x.dataset.q; render(); }; });
      el.querySelectorAll('.inv-chip').forEach(function(x){ x.onclick=function(){ QF=x.dataset.q; render(); }; });
      ['inv-f-status','inv-f-cat','inv-f-tier','inv-f-dept'].forEach(function(i){ $(i).onchange=function(){ read(); render(); }; });
      $('inv-q').onkeydown=function(e){ if(e.key==='Enter'){ read(); render(); } };
      $('inv-clear').onclick=function(){ F={q:'',status:'',cat:'',tier:'',dept:'',archived:F.archived}; QF='all'; render(); };
      $('inv-add').onclick=function(){ openNew(); };
      $('inv-import').onclick=function(){ showPage(PAGE3,SB3); renderImport(); };
      var gl=$('inv-gaps-link'); if(gl) gl.onclick=function(e){ e.preventDefault(); showPage(PAGE2,SB2); renderGaps(); };
      var al=$('inv-arch'); if(al) al.onclick=function(e){ e.preventDefault(); F.archived=F.archived?'':'all'; render(); };
      el.querySelectorAll('tr.click').forEach(function(tr){ tr.onclick=function(){ openDr(+tr.dataset.id); }; });
      el.querySelectorAll('.inv-open').forEach(function(b){ b.onclick=function(e){ e.stopPropagation(); openDr(+b.dataset.id); }; });
    }).catch(function(e){ el.innerHTML='<div class="apv4-note warn">'+E(e.message)+'</div>'; });
  }

  /* ── record drawer (all columns editable) ─────────────────────────────── */
  function ov(){ var o=$('inv-ov'); if(!o){ o=document.createElement('div'); o.id='inv-ov'; o.style.cssText='position:fixed;inset:0;background:rgba(17,24,39,.45);z-index:99990;display:flex;justify-content:flex-end'; document.body.appendChild(o); o.onclick=function(e){ if(e.target===o) closeDr(); }; } return o; }
  function closeDr(){ var o=$('inv-ov'); if(o) o.remove(); EDIT=false; CUR=null; }
  function openNew(){ CUR='new'; EDIT=true; drawDr({id:null,inv_id:'(new)',request_id:'',data:{},sources:{},blank:0,flag:'-',next:'',audit:[]}); }
  function openDr(id){ api('GET','/api/portal/inventory/'+id).then(function(r){ CUR=r.id; drawDr(r); }).catch(function(e){ toast('Could not open record: '+e.message); }); }
  function drawDr(r){
    var D=r.data, SRCS=r.sources||{}, o=ov();
    var blanks=FIELDS.filter(function(f){ return f.required&&!D[f.key]; }).map(function(f){ return f.label; });
    var h='';
    if(r.id&&blanks.length) h+='<div class="apv4-note warn" style="max-width:none;margin:0 0 12px"><b>'+blanks.length+' required field'+(blanks.length===1?'':'s')+' still blank:</b> '+E(blanks.join(' · '))+'. Fill from the request, the vendor, or the business owner — "Unsure" is allowed.</div>';
    h+='<div style="display:flex;gap:8px;flex-wrap:wrap;font-size:11px;margin:0 0 12px">'+Object.keys(SRC).map(function(k){ return pill(SRC[k][0],SRC[k][1],SRC[k][2]); }).join('')+'</div>';
    SECTIONS.forEach(function(sec){
      var fs=FIELDS.filter(function(f){ return f.section===sec; }); if(!fs.length) return;
      var legal=sec==='InfoSec / Legal review';
      h+='<div class="apv4-card" style="margin-bottom:12px"><div style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-weight:700;font-size:12.5px;display:flex;align-items:center;gap:8px"><span style="width:4px;height:16px;border-radius:2px;background:'+(legal?'#1e3a8a':'#147299')+'"></span>'+E(sec)+'<span style="margin-left:auto">'+(legal?pill('review fields','#dbeafe','#1e3a8a'):pill(EDIT?'editing':'editable','#e5e7eb','#4b5563'))+'</span></div><div style="display:grid;grid-template-columns:230px 1fr 120px;font-size:12.5px">';
      fs.forEach(function(f){
        var k=f.key, v=D[k]||'', src=SRCS[k]||(v?'infosec':'missing'); var s=SRC[src]||SRC.infosec; var val;
        if(EDIT){
          if(f.allowed) val='<select class="apv4-field inv-ed" data-k="'+k+'" style="margin:0;width:100%"><option value="">— select —</option>'+f.allowed.map(function(a){ return '<option'+(v===a?' selected':'')+'>'+E(a)+'</option>'; }).join('')+'</select>';
          else if(f.kind==='long') val='<textarea class="apv4-field inv-ed" data-k="'+k+'" rows="2" style="margin:0;width:100%">'+E(v)+'</textarea>';
          else if(f.kind==='date') val='<input class="apv4-field inv-ed" data-k="'+k+'" type="date" value="'+E(v)+'" style="margin:0">';
          else val='<input class="apv4-field inv-ed" data-k="'+k+'" value="'+E(v)+'" style="margin:0;width:100%">';
        } else val=v?E(v):(legal?'<span style="color:#b91c1c;font-style:italic">not set</span>':'<span style="color:#b91c1c;font-style:italic">missing</span>');
        var cov=(COV||[]).find(function(c){ return c.key===k; }); var map=cov&&cov.intake_field&&cov.intake_field!=='—'?'<div style="font-size:11px;color:#6b7280">↳ '+E(cov.intake_field)+'</div>':'';
        h+='<div style="padding:7px 12px;border-bottom:1px solid #f3f4f6;color:#6b7280;font-weight:700">'+E(f.label)+(f.required?' <span style="color:#b91c1c">*</span>':'')+'</div><div style="padding:7px 12px;border-bottom:1px solid #f3f4f6;min-width:0">'+val+(EDIT?'':map)+'</div><div style="padding:7px 12px;border-bottom:1px solid #f3f4f6;text-align:right">'+pill(s[0],s[1],s[2])+'</div>';
      });
      h+='</div></div>';
    });
    if(r.id) h+='<div class="apv4-card" style="margin-bottom:12px"><div style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-weight:700;font-size:12.5px;display:flex;gap:8px;align-items:center"><span style="width:4px;height:16px;border-radius:2px;background:#4b5563"></span>Calculated <span style="margin-left:auto">'+pill('read-only · workbook formulas','#e5e7eb','#4b5563')+'</span></div><div style="display:grid;grid-template-columns:230px 1fr;font-size:12.5px"><div style="padding:7px 12px;color:#6b7280;font-weight:700">Required fields still blank</div><div style="padding:7px 12px">'+r.blank+'</div><div style="padding:7px 12px;color:#6b7280;font-weight:700;border-top:1px solid #f3f4f6">Auto-flag: high-risk trigger present</div><div style="padding:7px 12px;border-top:1px solid #f3f4f6">'+(r.flag==='Review for High'?pill('⚑ Review for High','#fee2e2','#b91c1c'):'—')+'</div><div style="padding:7px 12px;color:#6b7280;font-weight:700;border-top:1px solid #f3f4f6">Next review due</div><div style="padding:7px 12px;border-top:1px solid #f3f4f6">'+(r.next?E(r.next)+(r.overdue?' '+pill('overdue','#fef3c7','#b45309'):''):'—')+'</div></div></div>'
      +'<div class="apv4-card"><div style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-weight:700;font-size:12.5px">History</div>'+((r.audit||[]).length?'<table class="apv4-tbl"><tbody>'+r.audit.map(function(a){ var n=a.note; try{ var j=JSON.parse(a.note); n=(j.reason?'“'+j.reason+'” — ':'')+(j.changes||[]).map(function(c){ var lab=(FIELDS.find(function(f){return f.key===c.field;})||{}).label||c.field; return lab+': '+(c.old||'—')+' → '+(c.new||'—'); }).join('; '); }catch(e){} return '<tr><td style="white-space:nowrap;font-size:12px">'+fmtDT(a.created_at)+'</td><td style="font-weight:600">'+E(a.event)+'</td><td>'+E(a.actor)+'</td><td style="font-size:12px;color:#4b5563">'+E(n)+'</td></tr>'; }).join('')+'</tbody></table>':'<div style="padding:10px 12px;color:#6b7280;font-size:12px">—</div>')+'</div>';
    o.innerHTML='<div style="width:min(780px,96vw);height:100%;background:#fff;overflow-y:auto;box-shadow:-12px 0 40px rgba(0,0,0,.2);display:flex;flex-direction:column" onclick="event.stopPropagation()">'
      +'<div style="padding:16px 22px;border-bottom:1px solid #e5e7eb;display:flex;justify-content:space-between;align-items:flex-start;gap:12px;position:sticky;top:0;background:#fff;z-index:1"><div><div style="font-size:16px;font-weight:800;color:#111827">'+E(D.name||'New use case')+' · <span style="font-family:ui-monospace,monospace;color:#147299">'+E(r.inv_id)+'</span></div><div style="font-size:12px;color:#6b7280">'+E(D.dept||'')+(D.status?' · '+E(D.status):'')+(r.request_id?' · from intake <span style="font-family:ui-monospace,monospace">'+E(r.request_id)+'</span>':(r.id?' · entered by InfoSec / Legal':''))+' · '+(r.flag==='Review for High'?pill('⚑ Review for High','#fee2e2','#b91c1c'):'')+' '+tier(D.tier)+(r.archived_at?' '+pill('archived','#e5e7eb','#4b5563'):'')+'</div></div><button class="apv4-btn sm" id="inv-x">✕</button></div>'
      +'<div style="padding:18px 22px;flex:1">'+h+'</div>'
      +'<div style="padding:12px 22px;border-top:1px solid #e5e7eb;display:flex;gap:8px;flex-wrap:wrap;align-items:center;background:#fafafa;position:sticky;bottom:0"><span style="font-size:11.5px;color:#6b7280;margin-right:auto" id="inv-note">'+(EDIT?'Changing a field writes old → new to the audit trail':'Every column is editable by InfoSec / Legal · every change audited')+'</span>'
      +(r.id&&!EDIT?'<button class="apv4-btn sm" id="inv-arc">'+(r.archived_at?'↶ Un-archive':'▣ Archive')+'</button>':'')+(EDIT?'<button class="apv4-btn sm" id="inv-cancel">Cancel</button><button class="apv4-btn sm pri" id="inv-save">Save changes</button>':'<button class="apv4-btn sm pri" id="inv-edit">✎ Edit all fields</button>')+'</div></div>';
    $('inv-x').onclick=closeDr;
    var eb=$('inv-edit'); if(eb) eb.onclick=function(){ EDIT=true; drawDr(r); };
    var cb=$('inv-cancel'); if(cb) cb.onclick=function(){ EDIT=false; if(r.id) openDr(r.id); else closeDr(); };
    var sb=$('inv-save'); if(sb) sb.onclick=function(){ var data={}; o.querySelectorAll('.inv-ed').forEach(function(e){ data[e.dataset.k]=e.value; });
      var p=r.id?api('PATCH','/api/portal/inventory/'+r.id,{data:data}):api('POST','/api/portal/inventory',{data:data});
      p.then(function(d){ toast(r.id?('Saved · '+(d.changed||0)+' field'+(d.changed===1?'':'s')+' changed'):('Created '+d.inv_id)); EDIT=false; cache=null; openDr(d.id); render(); }).catch(function(e){ $('inv-note').textContent=e.message; $('inv-note').style.color='#b91c1c'; }); };
    var ab=$('inv-arc'); if(ab) ab.onclick=function(){ var reason=prompt((r.archived_at?'Un-archive':'Archive')+' '+r.inv_id+' — reason (audited):'); if(!reason) return; api('POST','/api/portal/inventory/'+r.id+'/'+(r.archived_at?'unarchive':'archive'),{reason:reason}).then(function(){ toast(r.archived_at?'Un-archived':'Archived'); closeDr(); cache=null; render(); }).catch(function(e){ toast(e.message); }); };
  }

  /* ── coverage gaps ────────────────────────────────────────────────────── */
  var GF='';
  function renderGaps(){
    var el=$(PAGE2); if(!el) return; el.innerHTML='<div style="padding:8px 0;color:#6b7280;font-size:13px">Loading…</div>';
    (COV?Promise.resolve(COV):api('GET','/api/portal/inventory/coverage').then(function(d){ COV=d; return d; })).then(function(cov){
      var L={ok:['Available','#d1fae5','#059669'],warn:['Partial','#fef3c7','#b45309'],bad:['Missing','#fee2e2','#b91c1c'],calc:['Calculated','#e5e7eb','#4b5563'],legal:['InfoSec / Legal','#dbeafe','#1e3a8a']};
      var cnt={}; cov.forEach(function(c){ cnt[c.coverage]=(cnt[c.coverage]||0)+1; });
      var rows=cov.filter(function(c){ return !GF||c.coverage===GF; });
      el.innerHTML='<div style="margin-bottom:12px"><div class="apv4-page-title">Coverage gaps — inventory fields vs. the AI Use Case Intake</div><div class="apv4-page-sub">What the intake form already provides, what it provides partly, and what InfoSec / Legal fill in. The intake form is unchanged.</div></div>'
        +'<div class="apv4-grid4" style="grid-template-columns:repeat(auto-fit,minmax(150px,1fr));margin-bottom:12px">'+Object.keys(L).map(function(k){ return '<div class="apv4-card" style="padding:10px 12px"><b style="font-size:22px;display:block">'+(cnt[k]||0)+'</b>'+pill(L[k][0],L[k][1],L[k][2])+'</div>'; }).join('')+'</div>'
        +'<div class="apv4-note" style="max-width:none;margin-bottom:12px">The workbook\'s Field Guide names intake fields the live form does not have (Target Go-Live, Business Owner, Risk Assessment, Training Restrictions, Data Retention, External Consumption, Intended Use, Use Case / Project Name). Those rows are marked Missing with the expectation noted.</div>'
        +'<div class="apv4-card"><div style="display:flex;gap:6px;flex-wrap:wrap;padding:8px 14px;border-bottom:1px solid #e5e7eb;align-items:center;font-size:11.5px;color:#6b7280"><span>Show</span>'+[['','All 45']].concat(Object.keys(L).map(function(k){ return [k,L[k][0]]; })).map(function(c){ return '<span class="apv4-pill inv-gchip" data-g="'+c[0]+'" style="cursor:pointer;'+(GF===c[0]?'background:#147299;color:#fff':'background:#fff;border:1px solid #e5e7eb;color:#111827')+'">'+c[1]+'</span>'; }).join('')+'</div>'
        +'<div style="overflow-x:auto"><table class="apv4-tbl"><thead><tr><th>#</th><th>Inventory field</th><th>Req.</th><th>Coverage</th><th>Intake field that maps</th><th>How it is filled</th></tr></thead><tbody>'+rows.map(function(c,i){ var l=L[c.coverage]; return '<tr><td style="font-family:ui-monospace,monospace">'+(cov.indexOf(c)+1)+'</td><td><b>'+E(c.field)+'</b><div style="font-size:11px;color:#6b7280">'+E(c.section)+'</div></td><td>'+(c.required?'<b>*</b>':'')+'</td><td>'+pill(l[0],l[1],l[2])+'</td><td>'+(c.intake_field==='—'?'<span style="color:#b91c1c;font-weight:700">— none</span>':E(c.intake_field))+'</td><td>'+E(c.how)+'</td></tr>'; }).join('')+'</tbody></table></div></div>';
      el.querySelectorAll('.inv-gchip').forEach(function(x){ x.onclick=function(){ GF=x.dataset.g; renderGaps(); }; });
    }).catch(function(e){ el.innerHTML='<div class="apv4-note warn">'+E(e.message)+'</div>'; });
  }

  /* ── import from workbook ─────────────────────────────────────────────── */
  var IMP={file:null,preview:null};
  function renderImport(){
    var el=$(PAGE3); if(!el) return;
    el.innerHTML='<div style="margin-bottom:12px"><div class="apv4-page-title">Import from workbook</div><div class="apv4-page-sub">Load rows from <b>AI_ML_Use_Inventory_Tracker.xlsx</b> (Inventory tab). Same columns, same allowed values; the example row is skipped; the ID column is ignored and assigned here. Existing rows (same Department + Name) gain only their blank fields — intake values are never overwritten. Nothing is written until you confirm.</div></div>'
      +'<div class="apv4-card" style="margin-bottom:12px;padding:16px;display:flex;gap:14px;align-items:center;flex-wrap:wrap"><label style="border:2px dashed #cbd5e1;border-radius:12px;padding:18px 22px;flex:1;min-width:260px;text-align:center;color:#6b7280;cursor:pointer">'+(IMP.file?'<b>'+E(IMP.file.name)+'</b> · '+Math.round(IMP.file.size/1024)+' KB':'Choose the workbook (.xlsx)')+'<input type="file" id="inv-file" accept=".xlsx" style="display:none"></label><button class="apv4-btn sm pri" id="inv-prev" '+(IMP.file?'':'disabled')+'>Preview</button></div>'
      +'<div id="inv-imp-out"></div>';
    $('inv-file').onchange=function(e){ IMP.file=e.target.files[0]||null; IMP.preview=null; renderImport(); };
    $('inv-prev').onclick=function(){ doImport(false); };
    if(IMP.preview) drawPreview(IMP.preview);
  }
  function doImport(commit){
    var out=$('inv-imp-out'); out.innerHTML='<div style="padding:8px 0;color:#6b7280">'+(commit?'Importing…':'Reading the workbook…')+'</div>';
    IMP.file.arrayBuffer().then(function(buf){ return api('POST','/api/portal/inventory/import'+(commit?'?commit=1':''),null,{body:buf,name:IMP.file.name}); })
      .then(function(d){ IMP.preview=d; drawPreview(d); if(commit){ cache=null; toast('Imported · '+d.summary.create+' created · '+d.summary.update+' updated · '+d.summary.rejected+' rejected'); } })
      .catch(function(e){ out.innerHTML='<div class="apv4-note warn" style="max-width:none">'+E(e.message)+'</div>'; });
  }
  function drawPreview(d){
    var s=d.summary, out=$('inv-imp-out'); var R={create:['Create','#d1fae5','#059669'],update:['Update existing','#e0f2fe','#0369a1'],rejected:['Rejected','#fee2e2','#b91c1c'],skipped:['Skipped','#e5e7eb','#4b5563']};
    out.innerHTML='<div class="apv4-card"><div style="padding:10px 14px;border-bottom:1px solid #e5e7eb;display:flex;gap:8px;align-items:center;flex-wrap:wrap"><b style="font-size:13px">'+(d.preview?'Preview':'Result')+'</b><span style="font-size:12px;color:#6b7280">'+E(s.file)+' · '+s.rows+' rows · '+s.create+' to create · '+s.update+' to update · '+s.rejected+' rejected · '+s.skipped+' skipped</span><span style="margin-left:auto"></span>'+(d.preview&&(s.create+s.update)?'<button class="apv4-btn sm pri" id="inv-commit">Import '+(s.create+s.update)+' row'+((s.create+s.update)===1?'':'s')+'</button>':'')+(!d.preview?'<button class="apv4-btn sm" id="inv-goinv">Open the inventory →</button>':'')+'</div>'
      +'<div style="overflow-x:auto"><table class="apv4-tbl"><thead><tr><th>Row</th><th>Department · Name</th><th>Checks</th><th>Result</th></tr></thead><tbody>'+d.results.map(function(x){ var l=R[x.result]; return '<tr><td style="font-family:ui-monospace,monospace">'+x.row+'</td><td><b>'+E(x.dept||'')+'</b> · '+(x.name?E(x.name):'<span style="color:#b91c1c">(blank name)</span>')+'</td><td style="font-size:12px;color:#4b5563">'+E(x.why||'')+'</td><td>'+pill(l[0],l[1],l[2])+(x.inv_id?' <span style="font-family:ui-monospace,monospace;color:#147299">'+E(x.inv_id)+'</span>':'')+'</td></tr>'; }).join('')+'</tbody></table></div>'
      +'<div style="padding:9px 14px;font-size:11.5px;color:#6b7280">Imported values are tagged "Imported" with the file name and row, and written to the audit trail. Allowed values are validated against the Field Guide; rejected rows are listed with the reason — fix them in the workbook and import again.</div></div>';
    var c=$('inv-commit'); if(c) c.onclick=function(){ doImport(true); };
    var g=$('inv-goinv'); if(g) g.onclick=function(){ showPage(PAGE,SB); render(); };
  }

  /* ── pages + sidebar ──────────────────────────────────────────────────── */
  function showPage(page,sb){
    document.querySelectorAll('[id^="apv4-page-"]').forEach(function(p){ p.style.display='none'; });
    var pg=$(page); if(pg) pg.style.display='block';
    document.querySelectorAll('[id^="apv4-sb-"]').forEach(function(s){ s.classList.remove('on'); s.style.background=''; s.style.color=''; });
    var el=$(sb); if(el) el.classList.add('on');
    S.page={ 'apv4-page-inventory':'inventory','apv4-page-inventory-gaps':'inventory-gaps','apv4-page-inventory-import':'inventory-import' }[page];
    var sc=$('apv4-scroll'); if(sc) sc.scrollTop=0;
  }
  function inject(){
    if(!allowed()) return;
    var root=$('apv4-root'); if(!root) return;
    var anyPage=root.querySelector('[id^="apv4-page-"]'); if(!anyPage) return;
    [PAGE,PAGE2,PAGE3].forEach(function(id){ if(!$(id)){ var pg=document.createElement('div'); pg.id=id; pg.style.display='none'; anyPage.parentNode.appendChild(pg); } });
    var items=[].slice.call(root.querySelectorAll('[id^="apv4-sb-"]'));
    var after=$('apv4-sb-audit')||items[items.length-1]; if(!after) return;
    function mk(id,label,icon,indent,fn){ if($(id)) return $(id); var el=after.cloneNode(false); el.id=id; el.removeAttribute('onclick'); el.classList.remove('on'); el.innerHTML='<span class="ic">'+icon+'</span><span style="flex:1">'+label+'</span>'; el.style.background=''; el.style.color=''; if(indent) el.style.paddingLeft='30px'; el.onclick=function(e){ e.preventDefault(); fn(); }; return el; }
    var a=mk(SB,'AI Inventory','🗂',false,function(){ showPage(PAGE,SB); render(); });
    var b=mk(SB3,'Import from workbook','⬆',true,function(){ showPage(PAGE3,SB3); renderImport(); });
    var c=mk(SB2,'Coverage gaps','↳',true,function(){ showPage(PAGE2,SB2); renderGaps(); });
    if(!a.parentNode){ after.parentNode.insertBefore(a,after.nextSibling); a.parentNode.insertBefore(b,a.nextSibling); b.parentNode.insertBefore(c,b.nextSibling); }
    if(S.page==='inventory') a.classList.add('on'); if(S.page==='inventory-gaps') c.classList.add('on'); if(S.page==='inventory-import') b.classList.add('on');
  }
  if(window.RM){ var _prev=RM.afterSidebar; RM.afterSidebar=function(el){ if(_prev) _prev(el); inject(); }; }
  var _prevRole=window.RM&&RM.onRole; if(window.RM) RM.onRole=function(id){ if(_prevRole) _prevRole(id); cache=null; COV=null; setTimeout(inject,50); };
  inject();
  window.portalInventory={open:openDr,render:render};
  console.info('[inventory] loaded');
})();
