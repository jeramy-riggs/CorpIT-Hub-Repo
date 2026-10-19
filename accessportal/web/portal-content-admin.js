(function(){
  if(!/approver\.html$/i.test(location.pathname)) return;
  var API='/api/portal/content', PAGE='apv4-page-site-content', SB='apv4-sb-site-content';
  var content={}, schema={}, dirty={}, invalid={}, tab='general', role=null, canReadAccessGuide=false, docs={}, docsMeta={convert:false,maxBytes:0}, docBusy='';
  var G={oca:'linear-gradient(135deg,#0D1428,#1e3a5f)',aia:'linear-gradient(135deg,#2d1b69,#4c1d95)',wua:'linear-gradient(135deg,#0D4F4F,#0f766e)',
         paa:'linear-gradient(135deg,#4a0000,#7f1d1d)',ser:'linear-gradient(135deg,#3d2000,#78350f)',sir:'linear-gradient(135deg,#1e1b4b,#3730a3)'};
  /* the same artwork the request tiles and the form badge use, so the editor's headers match the portal */
  var ART={"oca": "<svg width=\"60\" height=\"30\" viewBox=\"0 0 180 88\" xmlns=\"http://www.w3.org/2000/svg\"><ellipse cx=\"60\" cy=\"44\" rx=\"22\" ry=\"22\" fill=\"none\" stroke=\"#41B6E6\" stroke-width=\"1.5\"/><ellipse cx=\"60\" cy=\"44\" rx=\"9\" ry=\"22\" fill=\"none\" stroke=\"#41B6E6\" stroke-width=\"1\"/><line x1=\"38\" y1=\"44\" x2=\"82\" y2=\"44\" stroke=\"#41B6E6\" stroke-width=\"1\"/><g transform=\"translate(96,30) rotate(-30)\"><path d=\"M0,0 L18,5 L0,10 L4,5 Z\" fill=\"#78BE20\"/><path d=\"M3,3 L-6,8 L-4,5 L-6,2 Z\" fill=\"rgba(120,190,32,.5)\"/></g><path d=\"M44,54 Q78,14 124,38\" stroke=\"rgba(65,182,230,.4)\" stroke-width=\"1.5\" fill=\"none\" stroke-dasharray=\"4,3\"/><circle cx=\"148\" cy=\"44\" r=\"28\" fill=\"rgba(255,255,255,.03)\"/></svg>", "aia": "<svg width=\"60\" height=\"30\" viewBox=\"0 0 180 88\" xmlns=\"http://www.w3.org/2000/svg\"><circle cx=\"32\" cy=\"28\" r=\"5\" fill=\"#a78bfa\"/><circle cx=\"32\" cy=\"60\" r=\"5\" fill=\"#a78bfa\"/><circle cx=\"60\" cy=\"18\" r=\"4\" fill=\"#c4b5fd\"/><circle cx=\"60\" cy=\"44\" r=\"4\" fill=\"#c4b5fd\"/><circle cx=\"60\" cy=\"70\" r=\"4\" fill=\"#c4b5fd\"/><circle cx=\"88\" cy=\"28\" r=\"5\" fill=\"#7c3aed\"/><circle cx=\"88\" cy=\"60\" r=\"5\" fill=\"#7c3aed\"/><line x1=\"37\" y1=\"28\" x2=\"56\" y2=\"18\" stroke=\"rgba(167,139,250,.4)\" stroke-width=\"1\"/><line x1=\"37\" y1=\"28\" x2=\"56\" y2=\"44\" stroke=\"rgba(167,139,250,.4)\" stroke-width=\"1\"/><line x1=\"37\" y1=\"60\" x2=\"56\" y2=\"44\" stroke=\"rgba(167,139,250,.4)\" stroke-width=\"1\"/><line x1=\"37\" y1=\"60\" x2=\"56\" y2=\"70\" stroke=\"rgba(167,139,250,.4)\" stroke-width=\"1\"/><line x1=\"64\" y1=\"18\" x2=\"83\" y2=\"28\" stroke=\"rgba(167,139,250,.4)\" stroke-width=\"1\"/><line x1=\"64\" y1=\"44\" x2=\"83\" y2=\"28\" stroke=\"rgba(167,139,250,.4)\" stroke-width=\"1\"/><line x1=\"64\" y1=\"44\" x2=\"83\" y2=\"60\" stroke=\"rgba(167,139,250,.4)\" stroke-width=\"1\"/><line x1=\"64\" y1=\"70\" x2=\"83\" y2=\"60\" stroke=\"rgba(167,139,250,.4)\" stroke-width=\"1\"/><rect x=\"108\" y=\"20\" width=\"34\" height=\"46\" rx=\"6\" fill=\"rgba(109,40,217,.55)\" stroke=\"rgba(167,139,250,.5)\" stroke-width=\"1.5\"/><rect x=\"114\" y=\"28\" width=\"10\" height=\"10\" rx=\"2\" fill=\"#c4b5fd\"/><rect x=\"128\" y=\"28\" width=\"10\" height=\"10\" rx=\"2\" fill=\"#c4b5fd\"/><rect x=\"116\" y=\"44\" width=\"20\" height=\"5\" rx=\"2\" fill=\"rgba(167,139,250,.5)\"/></svg>", "wua": "<svg width=\"60\" height=\"30\" viewBox=\"0 0 180 88\" xmlns=\"http://www.w3.org/2000/svg\"><rect x=\"20\" y=\"14\" width=\"86\" height=\"58\" rx=\"5\" fill=\"rgba(255,255,255,.07)\" stroke=\"#14b8a6\" stroke-width=\"1.5\"/><rect x=\"20\" y=\"14\" width=\"86\" height=\"14\" rx=\"5\" fill=\"rgba(20,184,166,.28)\"/><circle cx=\"28\" cy=\"21\" r=\"2.5\" fill=\"#ef4444\"/><circle cx=\"35\" cy=\"21\" r=\"2.5\" fill=\"#f59e0b\"/><circle cx=\"42\" cy=\"21\" r=\"2.5\" fill=\"#22c55e\"/><rect x=\"48\" y=\"16\" width=\"46\" height=\"8\" rx=\"3\" fill=\"rgba(255,255,255,.15)\"/><rect x=\"28\" y=\"36\" width=\"64\" height=\"5\" rx=\"2\" fill=\"rgba(255,255,255,.18)\"/><rect x=\"28\" y=\"46\" width=\"48\" height=\"4\" rx=\"2\" fill=\"rgba(255,255,255,.1)\"/><rect x=\"28\" y=\"56\" width=\"54\" height=\"4\" rx=\"2\" fill=\"rgba(255,255,255,.1)\"/><path d=\"M130,22 L148,14 L166,22 L166,42 Q166,56 148,64 Q130,56 130,42 Z\" fill=\"rgba(20,184,166,.2)\" stroke=\"#14b8a6\" stroke-width=\"1.5\"/><path d=\"M137,40 L144,48 L160,32\" stroke=\"#78BE20\" stroke-width=\"2.5\" fill=\"none\" stroke-linecap=\"round\"/></svg>", "paa": "<svg width=\"60\" height=\"30\" viewBox=\"0 0 180 88\" xmlns=\"http://www.w3.org/2000/svg\"><rect x=\"22\" y=\"12\" width=\"60\" height=\"64\" rx=\"4\" fill=\"rgba(255,255,255,.06)\" stroke=\"rgba(239,68,68,.45)\" stroke-width=\"1.5\"/><rect x=\"26\" y=\"20\" width=\"52\" height=\"8\" rx=\"2\" fill=\"rgba(239,68,68,.2)\"/><circle cx=\"71\" cy=\"24\" r=\"2.5\" fill=\"#ef4444\"/><rect x=\"26\" y=\"33\" width=\"52\" height=\"8\" rx=\"2\" fill=\"rgba(239,68,68,.2)\"/><circle cx=\"71\" cy=\"37\" r=\"2.5\" fill=\"#f59e0b\"/><rect x=\"26\" y=\"46\" width=\"52\" height=\"8\" rx=\"2\" fill=\"rgba(239,68,68,.2)\"/><circle cx=\"71\" cy=\"50\" r=\"2.5\" fill=\"#22c55e\"/><rect x=\"26\" y=\"59\" width=\"52\" height=\"8\" rx=\"2\" fill=\"rgba(239,68,68,.2)\"/><circle cx=\"71\" cy=\"63\" r=\"2.5\" fill=\"#22c55e\"/><circle cx=\"130\" cy=\"38\" r=\"14\" fill=\"none\" stroke=\"#fbbf24\" stroke-width=\"2\"/><line x1=\"140\" y1=\"48\" x2=\"156\" y2=\"66\" stroke=\"#fbbf24\" stroke-width=\"2.5\"/><circle cx=\"130\" cy=\"38\" r=\"6\" fill=\"rgba(251,191,36,.2)\"/></svg>", "ser": "<svg width=\"60\" height=\"30\" viewBox=\"0 0 180 88\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M60,6 L90,0 L120,6 L120,44 Q120,66 90,76 Q60,66 60,44 Z\" fill=\"rgba(245,158,11,.13)\" stroke=\"#f59e0b\" stroke-width=\"1.5\"/><rect x=\"86\" y=\"18\" width=\"8\" height=\"26\" rx=\"4\" fill=\"#fbbf24\"/><circle cx=\"90\" cy=\"54\" r=\"5\" fill=\"#fbbf24\"/></svg>", "sir": "<svg width=\"60\" height=\"30\" viewBox=\"0 0 180 88\" xmlns=\"http://www.w3.org/2000/svg\"><circle cx=\"72\" cy=\"44\" r=\"34\" fill=\"none\" stroke=\"rgba(129,140,248,.2)\" stroke-width=\"1\"/><circle cx=\"72\" cy=\"44\" r=\"24\" fill=\"none\" stroke=\"rgba(129,140,248,.3)\" stroke-width=\"1\"/><circle cx=\"72\" cy=\"44\" r=\"13\" fill=\"none\" stroke=\"rgba(129,140,248,.5)\" stroke-width=\"1.5\"/><circle cx=\"72\" cy=\"44\" r=\"4\" fill=\"#818cf8\"/><line x1=\"72\" y1=\"44\" x2=\"98\" y2=\"20\" stroke=\"rgba(99,102,241,.6)\" stroke-width=\"1.5\"/><circle cx=\"92\" cy=\"24\" r=\"3.5\" fill=\"#ef4444\" opacity=\".9\"/><circle cx=\"142\" cy=\"32\" r=\"14\" fill=\"rgba(239,68,68,.18)\" stroke=\"#ef4444\" stroke-width=\"1.5\"/><rect x=\"139\" y=\"22\" width=\"6\" height=\"13\" rx=\"3\" fill=\"#ef4444\"/><circle cx=\"142\" cy=\"40\" r=\"3.5\" fill=\"#ef4444\"/></svg>"};
  var TABS=[['general','General & Hero'],['types','Request Types'],['contact','Contact & Email'],['footer','Confirmation & Footer'],['emails','Notification Emails'],['policies','Form Policies'],['guides','Guides']];
  var F={
    general:[
      ['site.title','Site name','header · footer · browser tab'],['site.subtitle','Subtitle','under the site name'],
      ['hero.badge','Hero badge','green pill above the heading'],['hero.heading','Hero heading','main page H1'],
      ['hero.body','Hero body','two lines under the heading · line breaks allowed'],
      ['hero.search_placeholder','Search placeholder','track-request box'],['hero.note','Note under search','small lock-icon line'],
      ['types.heading','Request section heading',''],['types.intro','Request section intro','']],
    types:[].concat.apply([],['oca','aia','wua','paa','ser','sir'].map(function(id){return [['type.'+id+'.label','Card title','request ID prefix stays '+id.toUpperCase(),id],['type.'+id+'.desc','Description','',id]];})),
    contact:[['footer.contact_label','Footer button label','"Contact IT Service Desk"'],['footer.contact_email','Footer contact email','opens the visitor\'s mail client · defaults to the IT Helpdesk notification address']],
    footer:[['confirm.heading','Confirmation heading','shown after a request is submitted'],['confirm.body','Confirmation body','{id} inserts the request ID'],
      ['footer.org','Footer organisation line','under the site name'],['approver.role_subtitle','Approver role-picker subtitle','approver.html hero'],
      ['approver.greeting_suffix','Approver dashboard greeting','{role} inserts the role name']],
    emails:[
      ['email.footer','Footer line (every email)','appears at the bottom of every notification'],
      ['email.submitted.intro','Request received — opening line','sent to the requester on submit · {id} {type}'],
      ['email.submitted.closing','Request received — closing line','{id} inserts the request ID'],
      ['email.approver.intro','Approval needed — opening line','sent to the approver · {type} {step} {id}'],
      ['email.approved.closing','Approved — what happens next','sent to the requester · {id} {type}'],
      ['email.rejected.closing','Rejected — what happens next','sent to the requester · {id} {type} {step}'],
      ['email.returned.closing','Returned — what happens next','sent to the requester · {id} {type} {step}']],
    policies:[
      ['policy.aia.ack','AI Policy — restrictions summary (New AI Use Case · step 4)','shown above the acknowledgement checkbox in the request form · the document below is the full policy']],
    /* CLA-ADMIN: the Claude page's own statement, rendered on its own card. */
    policiesCla:[
      ['policy.cla.ack','AI Policy — acknowledgment statements','one required checkbox per line · start a line with "- " for a nested checkbox under the previous one, "* " for a bullet inside it · <strong> allowed']],
    /* ACK-NOTIFY (v5): who else is told when an acknowledgment is completed. The employee always gets their own confirmation. */
    policiesClaNotify:[
      ['policy.cla.notify','Admin / IT notification recipients','one address or distribution list per line · empty = nobody but the employee'],
      ['policy.cla.notify_mode','Notification frequency','each = one email per acknowledgment (default) · daily = one summary at 08:00 server time, only on days with activity'],
      ['policy.cla.notify_manager','Manager copy','1 = the employee\u2019s manager receives a copy of each completed acknowledgment (default) · 0 = off']],
    /* ACK-ELIG (9/24 meeting): visible guardrails + provisioning lead time */
    policiesClaAccess:[
      ['policy.cla.intro','Introduction (blue box at the top of the acknowledgement page)','plain text · empty = built-in wording'],
      ['policy.cla.highlights','Key requirements (shown above the checkboxes)','one per line · the rules that matter most (human review, no automation, no loan/SSN/employee data…) · empty = hidden'],
      ['policy.cla.provision_days','Claude provisioning lead time (business days)','shown on the confirmation page, in the employee email and in the IT notice · default 2']]
  };
  var RT_TAGS=['p','br','strong','b','em','i','u','ul','ol','li','a'];
  function fmtBytes(n){ n=+n||0; return n>=1048576?(n/1048576).toFixed(1)+' MB':n>=1024?Math.round(n/1024)+' KB':n+' B'; }
  function docCard(form,label,where){
    var d=docs[form], mb=Math.max(1,Math.round((docsMeta.maxBytes||26214400)/1048576));
    var accept=docsMeta.convert?'.pdf,.docx,.pptx,.doc,.ppt':'.pdf';
    var kinds=docsMeta.convert?'PDF, Word or PowerPoint (Word/PowerPoint are converted to PDF on the server)':'PDF only on this server (export Word/PowerPoint to PDF first)';
    var cur=d?('<div class="pc-doc-cur"><span class="pc-doc-ic">📄</span><div style="flex:1;min-width:0"><div style="font-size:13px;font-weight:700;color:#111827;word-break:break-all">'+esc(d.name)+'</div>'
        +'<div style="font-size:11.5px;color:#6b7280">'+esc(d.pages)+' page'+(d.pages==1?'':'s')+' · '+fmtBytes(d.size)+(d.converted?' · converted to PDF':'')+' · uploaded '+esc((d.uploaded_at||'').slice(0,10))+'</div></div>'
        +'<a class="pc-btn gh" href="'+esc(d.url)+'" target="_blank" rel="noopener" style="text-decoration:none">View</a>'
        +'<a class="pc-btn gh" href="'+esc(d.url)+'" download="'+esc((d.name||'policy').replace(/\.[^.]+$/,'')+'.pdf')+'" style="text-decoration:none">Download</a>'
        +'<button class="pc-btn gh" data-doc-remove="'+form+'" style="color:#C8443C"'+(docBusy?' disabled':'')+'>Remove</button></div>')
      :'<div class="pc-doc-cur" style="color:#6b7280;font-size:12.5px">No document uploaded — the form shows the fallback text below.</div>';
    return '<div class="pc-card" id="pc-doc-'+form+'"><div class="pc-fh" style="margin-bottom:8px"><span class="pc-lbl">'+esc(label)+' — document</span><span class="pc-where">'+esc(where||'step 4 · replaces the text when present · applies immediately (no publish step)')+'</span></div>'
      +cur
      +'<div class="pc-doc-up"><input type="file" id="pc-doc-file-'+form+'" accept="'+accept+'"'+(docBusy?' disabled':'')+'>'
      +'<label style="font-size:11.5px;color:#6b7280;display:inline-flex;align-items:center;gap:6px">Effective <input type="date" id="pc-doc-eff-'+form+'" style="font-size:12px;padding:3px 6px"'+(docBusy?' disabled':'')+'></label>'
      +'<button class="pc-btn ok" data-doc-upload="'+form+'"'+(docBusy?' disabled':'')+'>'+(docBusy===form?'Uploading…':(d?'Publish new version':'Upload document'))+'</button></div>'
      +(d&&d.version?'<div style="font-size:11.5px;color:#6b7280;margin-top:6px">Current: <b>version '+esc(d.version)+'</b>'+(d.effective_date?' · effective '+esc(d.effective_date):'')+'. Publishing a new one keeps every earlier version, because acknowledgements point at the version that was signed.</div>':'')
      +'<div style="font-size:11.5px;color:#6b7280;margin-top:6px">'+kinds+' · up to '+mb+' MB. Readers see every page inline, fitted to the box, with Download and Open buttons; the acknowledgement unlocks when they reach the last page or download it.</div>'
      +'<div id="pc-doc-msg-'+form+'" style="font-size:12px;margin-top:6px"></div></div>';
  }
  /* CLA-ADMIN: the release switch. Absent or anything but "1" means SAMPLE,
     so a page nobody has explicitly released still says so on its face and
     stamps the records it takes as samples. Writes through the same dirty /
     publish pipeline as every other field -- nothing here goes live until
     Publish is pressed. */
  function claLiveCard(){
    var on=cur('policy.cla.live')==='1';
    var docOk=!!docs['cla'], txtOk=!!String(cur('policy.cla.ack')||'').trim();
    var warn=(!docOk||!txtOk)?('<div style="font-size:11.5px;color:#92400e;margin-top:8px">Still missing: '
        +[docOk?'':'the policy document',txtOk?'':'the acknowledgement statement'].filter(Boolean).join(' and ')
        +'. You can release without them, but the page will have nothing to show.</div>'):'';
    return '<div class="pc-card" id="pc-cla-live"><div class="pc-fh" style="margin-bottom:8px">'
      +'<span class="pc-lbl">Claude Access &ndash; Artificial Intelligence Policy Acknowledgment — release</span>'
      +'<span class="pc-where">controls the SAMPLE banner and how records are stamped</span></div>'
      +'<label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer">'
      +'<input type="checkbox" data-live-toggle="policy.cla.live"'+(on?' checked':'')+' style="margin-top:3px">'
      +'<span style="font-size:13px">Release this page &mdash; it is ready for staff to use.</span></label>'
      +'<div id="pc-live-state-policy-cla-live" style="font-size:12px;color:#6b7280;margin-top:8px">'
      +(on?'Live — requesters see the real page.':'SAMPLE — the page shows a sample banner and anything acknowledged is stored as a sample record.')
      +'</div>'+warn+'</div>';
  }
  function reloadDocs(){
    return fetch(API,{credentials:'same-origin'}).then(function(r){return r.json();}).then(function(j){ var dd=(j&&j.data)||{}; docs=dd.docs||{}; docsMeta={convert:!!dd.docs_convert,maxBytes:dd.docs_max_bytes||0}; });
  }
  function docUpload(form){
    var inp=document.getElementById('pc-doc-file-'+form), msg=document.getElementById('pc-doc-msg-'+form);
    var f=inp&&inp.files&&inp.files[0]; if(!f){ if(msg){msg.style.color='#C8443C';msg.textContent='Choose a file first.';} return; }
    if(docsMeta.maxBytes&&f.size>docsMeta.maxBytes){ if(msg){msg.style.color='#C8443C';msg.textContent='File is larger than '+fmtBytes(docsMeta.maxBytes)+'.';} return; }
    docBusy=form; render();
    var effEl=document.getElementById('pc-doc-eff-'+form);
    var hdrs={'Content-Type':'application/octet-stream','X-File-Name':f.name};
    if(effEl&&effEl.value) hdrs['X-Policy-Effective']=effEl.value;
    fetch('/api/portal/policy-doc/'+form,{method:'POST',credentials:'same-origin',headers:hdrs,body:f})
      .then(function(r){ return r.json().then(function(j){ return {ok:r.ok,j:j}; }); })
      .then(function(x){ if(!x.ok) throw new Error((x.j&&x.j.error)||'Upload failed'); return reloadDocs(); })
      .then(function(){ docBusy=''; render(); var m=document.getElementById('pc-doc-msg-'+form); if(m){m.style.color='#3D7924';m.textContent='✓ Published — it is live in the form now. Earlier versions were kept.';} toast('✓ Policy document published'); })
      .catch(function(e){ docBusy=''; render(); var m=document.getElementById('pc-doc-msg-'+form); if(m){m.style.color='#C8443C';m.textContent='✕ '+e.message;} });
  }
  function docRemove(form){
    if(!confirm('Take this policy document down?\n\nThe form will show the fallback text instead. Anything already acknowledged against it is kept — the document stays retrievable so the record still means something.')) return;
    docBusy=form; render();
    fetch('/api/portal/policy-doc/'+form,{method:'DELETE',credentials:'same-origin'})
      .then(function(r){ return r.json().then(function(j){ return {ok:r.ok,j:j}; }); })
      .then(function(x){ if(!x.ok) throw new Error((x.j&&x.j.error)||'Remove failed'); return reloadDocs().then(function(){ return x; }); })
      .then(function(x2){ docBusy=''; render();
        var kept=x2&&x2.j&&x2.j.data&&x2.j.data.kept_for_acknowledgments;
        toast(kept?'Document taken down — version history kept for existing acknowledgements':'Policy document removed'); })
      .catch(function(e){ docBusy=''; render(); var m=document.getElementById('pc-doc-msg-'+form); if(m){m.style.color='#C8443C';m.textContent='✕ '+e.message;} });
  }
  function D(k){ return (window.portalContent&&window.portalContent.defaults[k])||''; }
  function cur(k){ return dirty.hasOwnProperty(k)?dirty[k]:(content[k]!=null?content[k]:D(k)); }
  function isDefault(k){ return !dirty.hasOwnProperty(k)? content[k]==null : dirty[k]===''; }
  function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
  function validate(k,v){
    var sc=schema[k]||{}; if(v==='') return null;
    if(sc.kind==='email'&&!/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(v)) return 'Enter a complete address, e.g. name@auction.com';
    if(sc.max&&v.length>sc.max) return 'Maximum '+sc.max+' characters';
    if(sc.kind==='richtext'){
      var bad=null; v.replace(/<\/?\s*([a-zA-Z][a-zA-Z0-9]*)/g,function(m,t){ if(RT_TAGS.indexOf(t.toLowerCase())<0&&!bad) bad=t; return m; });
      if(bad) return 'Tag <'+bad+'> is not allowed. Use: '+RT_TAGS.map(function(t){return '<'+t+'>';}).join(' ');
      if(/\son[a-z]+\s*=|javascript:/i.test(v)) return 'Scripts and event handlers are not allowed';
      return null;
    }
    if(/<[^>]*>/.test(v)) return 'HTML tags are not allowed';
    var ok={'confirm.body':['{id}','{email}'],'approver.greeting_suffix':['{role}'],
      'email.submitted.intro':['{id}','{type}'],'email.submitted.closing':['{id}'],
      'email.approver.intro':['{id}','{type}','{step}'],'email.approved.closing':['{id}','{type}'],
      'email.rejected.closing':['{id}','{type}','{step}'],'email.returned.closing':['{id}','{type}','{step}']}[k]||[];
    var bad=(v.match(/\{[a-z_]+\}/g)||[]).filter(function(p){return ok.indexOf(p)<0;});
    if(bad.length) return 'Unknown placeholder '+bad[0];
    return null;
  }
  var CSS='.pc-card{background:#fff;border:1px solid #e5e7eb;border-radius:14px;padding:18px;margin-bottom:14px}'
   +'.pc-tabs{display:flex;gap:2px;border-bottom:1px solid #e5e7eb;margin-bottom:16px}.pc-tab{padding:9px 14px;font-size:12.5px;font-weight:700;color:#6b7280;cursor:pointer;border-bottom:2px solid transparent;display:flex;gap:7px;align-items:center}'
   +'.pc-tab.on{color:#147299;border-bottom-color:#147299}.pc-tab.lock{opacity:.5;cursor:not-allowed}.pc-cnt{font-size:10px;font-weight:800;padding:1px 6px;border-radius:999px;background:#fef3c7;color:#92400e}'
   +'.pc-f{padding:12px 0;border-bottom:1px solid #f3f4f6}.pc-f:last-child{border-bottom:0}.pc-fh{display:flex;align-items:baseline;gap:10px;margin-bottom:6px}'
   +'.pc-lbl{font-size:12.5px;font-weight:800;color:#111827}.pc-where{font-size:10.5px;color:#6b7280}.pc-reset{margin-left:auto;font-size:11px;font-weight:700;color:#147299;cursor:pointer;white-space:nowrap}.pc-reset.dis{color:#9ca3af;cursor:default}'
   +'.pc-in{width:100%;box-sizing:border-box;background:#f9fafb;border:1px solid #e5e7eb;border-radius:7px;padding:8px 11px;font:inherit;font-size:13px;color:#111827;outline:none;line-height:1.45}'
   +'.pc-in:focus{border-color:#147299;box-shadow:0 0 0 3px rgba(20,114,153,.15)}.pc-in.chg{border-left:3px solid #d97706}.pc-in.err{border-color:#C8443C;box-shadow:0 0 0 3px rgba(200,68,60,.14)}textarea.pc-in{resize:vertical;min-height:64px}textarea.pc-rich{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;line-height:1.5}.pc-doc-cur{display:flex;align-items:center;gap:10px;padding:10px 12px;border:1px solid #e5e7eb;border-radius:10px;background:#f9fafb;margin-bottom:10px}.pc-doc-ic{font-size:22px}.pc-doc-up{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.pc-doc-up input[type=file]{font-size:12px}'
   +'.pc-fm{display:flex;gap:10px;margin-top:5px;font-size:11px;color:#6b7280}.pc-fm .cc{margin-left:auto}.pc-fm.bad{color:#C8443C;font-weight:700}.pc-dflt code{background:#f3f4f6;border:1px solid #e5e7eb;padding:0 5px;border-radius:4px;font-size:10.5px}'
   +'.pc-rt{border:1px solid #e5e7eb;border-radius:12px;overflow:hidden;margin-bottom:12px}.pc-rth{display:flex;align-items:center;gap:12px;padding:10px 14px;background:#f9fafb;font-weight:800;font-size:13.5px}.pc-rth .th{width:60px;height:30px;border-radius:7px;display:inline-flex;align-items:center;justify-content:center;overflow:hidden;flex-shrink:0}.pc-rth .th svg{display:block}.pc-rth .code{font-size:10px;letter-spacing:.08em;color:#147299;margin-left:6px}.pc-rtb{padding:6px 16px}'
   +'.pc-save{position:sticky;bottom:0;margin:12px -24px -20px;padding:12px 24px;background:rgba(255,255,255,.94);backdrop-filter:blur(8px);border-top:1px solid #e5e7eb;display:flex;align-items:center;gap:12px;z-index:5}'
   +'.pc-btn{padding:8px 16px;border-radius:8px;font-size:12.5px;font-weight:800;cursor:pointer;font-family:inherit;border:1px solid transparent}.pc-btn.ok{background:#3D7924;color:#fff}.pc-btn.gh{background:#f9fafb;border-color:#e5e7eb;color:#374151}.pc-btn:disabled{opacity:.45;cursor:not-allowed}'
   +'.pc-ov{position:fixed;inset:0;background:rgba(8,12,20,.45);z-index:99990;display:flex;align-items:center;justify-content:center}.pc-dlg{width:480px;max-width:92vw;background:#fff;border:1px solid #d1d5db;border-radius:14px;padding:20px;box-shadow:0 30px 70px -20px rgba(0,0,0,.6);color:#111827}'
   +'.pc-diff{font-size:12px;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;margin:12px 0 14px;max-height:280px;overflow-y:auto}.pc-diff div{padding:7px 11px;border-bottom:1px solid #f3f4f6;display:grid;grid-template-columns:150px 1fr;gap:10px}.pc-diff .o{color:#C8443C;text-decoration:line-through;opacity:.8}.pc-diff .n{color:#3D7924;font-weight:700}'
   +'.pc-toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);z-index:99995;padding:10px 16px;border-radius:10px;background:#142533;color:#EBF1F6;font-size:12.5px;font-weight:700;box-shadow:0 10px 30px -10px rgba(0,0,0,.6)}'
   +'.pc-note{display:flex;gap:8px;align-items:flex-start}.pc-note .pc-i{flex-shrink:0;margin-top:2px;color:#147299}.pc-note{font-size:11.5px;color:#6b7280;background:#f9fafb;border:1px dashed #d1d5db;border-radius:8px;padding:9px 12px;margin-bottom:12px}';
  function css(){ if(document.getElementById('pc-admin-css'))return; var s=document.createElement('style'); s.id='pc-admin-css'; s.textContent=CSS; document.head.appendChild(s); }

  function fieldHTML(f){
    var k=f[0],v=cur(k),sc=schema[k]||{},multi=sc.kind==='multiline',err=invalid[k],d=D(k);
    var rich=sc.kind==='richtext';
    var inp=rich?'<textarea class="pc-in pc-rich" data-k="'+k+'" rows="14" spellcheck="false">'+esc(v)+'</textarea>'
      :multi?'<textarea class="pc-in" data-k="'+k+'" rows="3">'+esc(v)+'</textarea>':'<input class="pc-in" data-k="'+k+'" value="'+esc(v)+'">';
    return '<div class="pc-f"><div class="pc-fh"><span class="pc-lbl">'+esc(f[1])+'</span>'+(f[2]?'<span class="pc-where">'+esc(f[2])+'</span>':'')
      +'<span class="pc-reset'+(isDefault(k)?' dis':'')+'" data-reset="'+k+'">'+(isDefault(k)?'Default':'Reset to default')+'</span></div>'+inp
      +'<div class="pc-fm'+(err?' bad':'')+'">'+(err?'✕ '+esc(err):'<span class="pc-dflt">Default: <code>'+esc(d.length>90?d.slice(0,90)+'…':d)+'</code></span>')
      +'<span class="cc">'+v.length+(sc.max?'/'+sc.max:'')+'</span></div></div>';
  }
  function render(){
    var pg=document.getElementById(PAGE); if(!pg) return;
    var nd=Object.keys(dirty).length, ni=Object.keys(invalid).length;
    var cnt=function(t){ var n=(F[t]||[]).filter(function(f){return dirty.hasOwnProperty(f[0]);}).length; return n?'<span class="pc-cnt">'+n+'</span>':''; };
    var body;
    if(tab==='types'){
      body=['oca','aia','wua','paa','ser','sir'].map(function(id){
        return '<div class="pc-rt"><div class="pc-rth"><span class="th" style="background:'+G[id]+'">'+(ART[id]||'')+'</span><span>'+esc(cur('type.'+id+'.label'))+'<span class="code">'+id.toUpperCase()+'</span></span></div><div class="pc-rtb">'
          +F.types.filter(function(f){return f[3]===id;}).map(fieldHTML).join('')+'</div></div>';}).join('');
      body='<div class="pc-note"><svg class="pc-i" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 16v-4M12 8h.01"/></svg> Approver chains and form fields are managed in <b>Manage Roles</b>. This tab only edits what requesters read on the card.</div>'+body;
    } else if(tab==='emails'){
      body='<div class="pc-note"><svg class="pc-i" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 16v-4M12 8h.01"/></svg> These are the sentences inside the notification emails. The <b>subject lines</b>, layout and the request-detail tables are fixed in the portal service and are not editable here. Recipient <b>addresses</b> are set under <b>Notification Emails</b> in the Administration menu — this tab only changes wording.</div>'
        +'<div class="pc-card">'+F.emails.map(fieldHTML).join('')+'</div>';
    } else if(tab==='policies'){
      body='<div class="pc-note"><span><b>One AI Policy document.</b> The New AI Use Case form (step 4) and the AI Policy Acknowledgment page show the same published document — manage it in the <b>AI Policy — document</b> card below. Publishing a new version updates both at once.</span></div>'
        +'<div class="pc-note"><span><svg class="pc-i" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 16v-4M12 8h.01"/></svg> <b>Fallback text</b> — shown inside the <b>AI Use Case Intake</b> form, step 4, only when no document is uploaded above. Basic HTML is allowed: '
        +'<code>&lt;p&gt; &lt;br&gt; &lt;strong&gt; &lt;em&gt; &lt;u&gt; &lt;ul&gt; &lt;ol&gt; &lt;li&gt; &lt;a href="https://…"&gt;</code>. '
        +'Everything else is removed on publish. Links open in a new tab. The acknowledgement checkbox stays locked until the reader has scrolled to the end of this text <i>or</i> opened one of its links.</span></div>'
        +'<div class="pc-card">'+F.policies.map(fieldHTML).join('')+'</div>'
        /* CLA-ADMIN: the Claude acknowledgement, same machinery, its own
           document and its own wording. It stays behind the release switch
           until Legal's document and statement are both in place. */
        +'<div class="pc-sec" style="margin-top:26px;padding-top:18px;border-top:1px solid #e5e7eb"></div>'
        +claLiveCard()
        +docCard('cla','AI Policy','ONE document for all approved AI products · shown in the New AI Use Case form (step 4) and on the AI Policy Acknowledgment page · each publish adds a version')+'<div id="pc-cla-versions" style="margin-top:12px"></div>'
        +'<div class="pc-note"><span><svg class="pc-i" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 16v-4M12 8h.01"/></svg> <b>Acknowledgment statements</b> — one per line, shown under the document on the AI Policy page, above the checkboxes. Use {V} where the version number should appear. Same HTML allow-list as above. The checkbox stays locked until the reader reaches the last page of the document or downloads it.</span></div>'
        +'<div class="pc-card">'+F.policiesCla.map(fieldHTML).join('')+'</div>'
        /* ACK-NOTIFY (v5) */
        +'<div class="pc-note" style="margin-top:18px"><span><b>Notifications</b> — the employee always receives a confirmation. Below: who else is told, how often, and whether the manager on the record gets a copy. Every send (or skip / failure) is written to the record\u2019s audit trail as notify.employee / notify.manager / notify.admin.</span></div>'
        +'<div class="pc-card">'+F.policiesClaNotify.map(fieldHTML).join('')+'</div>'
        /* ACK-ELIG */
        +'<div class="pc-note" style="margin-top:18px"><span><b>Claude access</b> — the acknowledgement is how standard Claude access is obtained. Who may complete it is decided by HR status plus the administrator Eligibility list (Administration → AI Policy Acknowledgments). Below: the highlighted requirements and the provisioning lead time quoted to employees.</span></div>'
        +'<div class="pc-card">'+F.policiesClaAccess.map(fieldHTML).join('')+'</div>';
    } else if(tab==='guides'){
      body=canReadAccessGuide?'<div class="pc-card"><b>User &amp; Group Access Guide</b><p style="font-size:13px;color:#4b5563;line-height:1.6;margin:8px 0 14px">Assign users to department groups, compare group permissions, create app-only exceptions and verify effective access. Private to Rey Abad and Jeramy Riggs.</p><a class="pc-btn gh" href="/group-access-guide.html" style="display:inline-block;text-decoration:none">Open User &amp; Group Access Guide →</a></div>':'';
    } else {
      body='<div class="pc-card">'+F[tab].map(fieldHTML).join('')+'</div>';
      if(tab==='contact') body='<div class="pc-note"><svg class="pc-i" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 16v-4M12 8h.01"/></svg> Notification recipient addresses (IT Helpdesk, Cyber Security, sender) are managed in <b>Notification Emails</b>. If the footer email is left at default it follows the IT Helpdesk address automatically.</div>'+body;
    }
    pg.innerHTML='<div style="padding:20px 24px">'
      +'<div style="display:flex;align-items:flex-start;gap:14px;flex-wrap:wrap;margin-bottom:14px"><div><h2 style="margin:0 0 3px;font-size:18px;font-weight:800;color:#111827">Site Content</h2><p style="margin:0;font-size:12.5px;color:#6b7280">Edit front-facing text, labels and contact details. Published changes appear on every page immediately.</p></div>'
      +'<div style="margin-left:auto;font-size:11.5px;color:#6b7280">'+(nd?'<span class="pc-cnt" style="font-size:11px;padding:3px 10px">'+nd+' unsaved change'+(nd>1?'s':'')+'</span>':'<span style="color:#3D7924;font-weight:700">All changes published</span>')+'</div></div>'
      +'<div class="pc-tabs">'+TABS.filter(function(t){return t[0]!=='guides'||canReadAccessGuide;}).map(function(t){return '<span class="pc-tab'+(t[0]===tab?' on':'')+'" data-tab="'+t[0]+'">'+t[1]+(t[0]!=='guides'?cnt(t[0]):'')+'</span>';}).join('')+'</div>'
      +body
      +'<div class="pc-save"><span style="font-size:12.5px;color:#374151">'+(ni?'<b style="color:#C8443C">'+ni+' field'+(ni>1?'s':'')+' invalid</b> — fix to publish':nd?'<b style="color:#d97706">'+nd+' change'+(nd>1?'s':'')+'</b> not yet published':'Nothing to publish')+'</span>'
      +'<div style="margin-left:auto;display:flex;gap:9px"><button class="pc-btn gh" id="pc-discard"'+(nd?'':' disabled')+'>Discard</button><button class="pc-btn ok" id="pc-publish"'+(nd&&!ni?'':' disabled')+'>Publish changes</button></div></div></div>';
    wire(pg);
  }
  function wire(pg){
    pg.querySelectorAll('.pc-tab').forEach(function(t){ t.onclick=function(){ tab=t.dataset.tab; render(); }; });
    pg.querySelectorAll('[data-doc-upload]').forEach(function(b){ b.onclick=function(){ docUpload(b.getAttribute('data-doc-upload')); }; });
    pg.querySelectorAll('[data-doc-remove]').forEach(function(b){ b.onclick=function(){ docRemove(b.getAttribute('data-doc-remove')); }; });
    pg.querySelectorAll('[data-live-toggle]').forEach(function(c){ c.onchange=function(){
      var k=c.getAttribute('data-live-toggle'), v=c.checked?'1':'';
      var base=content[k]!=null?content[k]:D(k);
      if(v===base) delete dirty[k]; else dirty[k]=v;
      var st=document.getElementById('pc-live-state-'+k.replace(/\./g,'-'));
      if(st) st.textContent=c.checked?'Live — requesters see the real page.':'SAMPLE — the page shows a sample banner and anything acknowledged is stored as a sample record.';
      refreshBar(); }; });
    pg.querySelectorAll('.pc-in').forEach(function(i){ i.oninput=function(){ var k=i.dataset.k, v=i.value;
      var base=content[k]!=null?content[k]:D(k);
      if(v===base) delete dirty[k]; else dirty[k]=v;
      var e=validate(k,v); if(e) invalid[k]=e; else delete invalid[k];
      i.classList.toggle('chg',dirty.hasOwnProperty(k)); i.classList.toggle('err',!!e);
      var fm=i.parentNode.querySelector('.pc-fm'); if(fm){ fm.className='pc-fm'+(e?' bad':''); fm.innerHTML=(e?'✕ '+esc(e):'<span class="pc-dflt">Default: <code>'+esc(D(k).slice(0,90))+'</code></span>')+'<span class="cc">'+v.length+(schema[k]&&schema[k].max?'/'+schema[k].max:'')+'</span>'; }
      var rs=i.parentNode.querySelector('.pc-reset'); if(rs){ var def=(v===D(k)); rs.className='pc-reset'+(def?' dis':''); rs.textContent=def?'Default':'Reset to default'; }
      refreshBar(); }; });
    pg.querySelectorAll('.pc-reset').forEach(function(r){ r.onclick=function(){ var k=r.dataset.reset; if(content[k]==null&&!dirty.hasOwnProperty(k))return;
      dirty[k]=''; delete invalid[k]; render(); }; });
    var d=pg.querySelector('#pc-discard'); if(d) d.onclick=function(){ dirty={}; invalid={}; render(); };
    var p=pg.querySelector('#pc-publish'); if(p) p.onclick=confirmPublish;
  }
  function refreshBar(){ var pg=document.getElementById(PAGE); if(!pg)return; var nd=Object.keys(dirty).length, ni=Object.keys(invalid).length;
    var pub=pg.querySelector('#pc-publish'), dis=pg.querySelector('#pc-discard'); if(pub) pub.disabled=!(nd&&!ni); if(dis) dis.disabled=!nd;
    var s=pg.querySelector('.pc-save > span'); if(s) s.innerHTML=ni?'<b style="color:#C8443C">'+ni+' field'+(ni>1?'s':'')+' invalid</b> — fix to publish':nd?'<b style="color:#d97706">'+nd+' change'+(nd>1?'s':'')+'</b> not yet published':'Nothing to publish'; }
  function labelOf(k){ for(var t in F){ for(var i=0;i<F[t].length;i++) if(F[t][i][0]===k) return (F[t][i][3]?F[t][i][3].toUpperCase()+' · ':'')+F[t][i][1]; } return k; }
  function confirmPublish(){
    var keys=Object.keys(dirty); if(!keys.length)return;
    var ov=document.createElement('div'); ov.className='pc-ov';
    ov.innerHTML='<div class="pc-dlg"><h4 style="margin:0 0 5px;font-size:15px;font-weight:800">Publish '+keys.length+' change'+(keys.length>1?'s':'')+' to all pages?</h4><p style="margin:0;font-size:12.5px;color:#374151;line-height:1.5">These take effect immediately for every visitor. Each field can be reset to its default afterwards.</p>'
      +'<div class="pc-diff">'+keys.map(function(k){ var o=content[k]!=null?content[k]:D(k), n=dirty[k]===''?D(k):dirty[k]; return '<div><span style="font-weight:800;color:#374151;font-size:11px">'+esc(labelOf(k))+'</span><span><span class="o">'+esc(o)+'</span><br><span class="n">'+esc(n)+(dirty[k]===''?' <span style="color:#6b7280;font-weight:600">(default)</span>':'')+'</span></span></div>'; }).join('')+'</div>'
      +'<div id="pc-err" style="color:#C8443C;font-size:12px;font-weight:700;margin-bottom:8px"></div>'
      +'<div style="display:flex;gap:9px;justify-content:flex-end"><button class="pc-btn gh" id="pc-cancel">Keep editing</button><button class="pc-btn ok" id="pc-go">Publish now</button></div></div>';
    document.body.appendChild(ov);
    ov.querySelector('#pc-cancel').onclick=function(){ ov.remove(); };
    ov.querySelector('#pc-go').onclick=function(){ var b=this; b.disabled=true; b.textContent='Publishing…';
      fetch(API,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({content:dirty})})
      .then(function(r){ return r.json().then(function(j){ return {s:r.status,j:j}; }); })
      .then(function(x){ if(x.s!==200||x.j.ok===false){ throw new Error(x.j.error||('HTTP '+x.s)); }
        var saved=(x.j.data&&x.j.data.saved)||0; content=(x.j.data&&x.j.data.content)||content; dirty={}; invalid={}; ov.remove(); render();
        toast('✓ Published '+saved+' change'+(saved!==1?'s':'')+' · live on all pages');
        if(window.portalContent) window.portalContent.refresh().catch(function(){}); })
      .catch(function(e){ ov.querySelector('#pc-err').textContent=/403|Admin/.test(e.message)?'Admin role required to publish.':e.message; b.disabled=false; b.textContent='Publish now'; }); };
  }
  function toast(m){ var t=document.createElement('div'); t.className='pc-toast'; t.textContent=m; document.body.appendChild(t); setTimeout(function(){t.remove();},3600); }

  function showPage(){
    document.querySelectorAll('[id^="apv4-page-"]').forEach(function(p){ p.style.display='none'; });
    var pg=document.getElementById(PAGE); if(pg){ pg.style.display='block'; if(!pg.innerHTML) render(); }
    document.querySelectorAll('[id^="apv4-sb-"]').forEach(function(s){ s.style.background=''; s.style.color='#9ca3af'; });
    var me=document.getElementById(SB); if(me){ me.style.background='#1f2937'; me.style.color='#fff'; }
    document.querySelectorAll('[id^="apv4-tab-"]').forEach(function(t){ t.style.background='transparent'; t.style.color='#d1d5db'; });
  }
  function hidePage(){ var pg=document.getElementById(PAGE); if(pg) pg.style.display='none'; }
  function wrapNav(){ var n=window.apv4Nav; if(typeof n==='function'&&!n.__pc){ window.apv4Nav=function(){ hidePage(); return n.apply(this,arguments); }; window.apv4Nav.__pc=1; } }

  function inject(){
    if(role!=='admin') return;
    var root=document.getElementById('apv4-root'); if(!root) return;
    // page container beside the other apv4 pages
    var anyPage=root.querySelector('[id^="apv4-page-"]');
    if(anyPage && !document.getElementById(PAGE)){ var pg=document.createElement('div'); pg.id=PAGE; pg.style.display='none'; anyPage.parentNode.appendChild(pg); }
    // sidebar item after Notification Emails
    if(!document.getElementById(SB)){
      var items=[].slice.call(root.querySelectorAll('[id^="apv4-sb-"]')), after=null;
      items.forEach(function(s){ if(/notification/i.test(s.textContent)) after=s; });
      if(!after && items.length) after=items[items.length-1];
      if(after){ var me=after.cloneNode(false); me.id=SB; me.removeAttribute('onclick'); me.innerHTML='<span style="width:18px;display:inline-block;text-align:center">✎</span> Site Content';
        me.style.background=''; me.style.color='#9ca3af'; me.onclick=function(e){ e.preventDefault(); showPage(); };
        after.parentNode.insertBefore(me, after.nextSibling); }
    }
    wrapNav();
  }
  function boot(){
    css();
    fetch('/api/portal/auth/me',{credentials:'same-origin'}).then(function(r){return r.json();}).then(function(j){
      var d=(j&&j.data)||j||{}; canReadAccessGuide=d.can_read_access_guide===true; role=d.role||(d.user&&d.user.role)||(d.session&&d.session.role)||null;
      if(role!=='admin'){ console.log('[site-content] role',role,'— editor hidden'); return; }
      return fetch(API,{credentials:'same-origin'}).then(function(r){return r.json();}).then(function(j2){
        var dd=(j2&&j2.data)||{}; content=dd.content||{}; schema=dd.keys||{}; docs=dd.docs||{}; docsMeta={convert:!!dd.docs_convert,maxBytes:dd.docs_max_bytes||0};
        inject();
        var sb=document.getElementById('apv4-sidebar-inner')||document.getElementById('apv4-root'), t;
        if(sb&&window.MutationObserver) new MutationObserver(function(){ clearTimeout(t); t=setTimeout(inject,150); }).observe(sb,{childList:true,subtree:true});
        var n=0, iv=setInterval(function(){ if(++n>20){clearInterval(iv);return;} inject(); },700);
        console.log('[site-content] editor ready —',Object.keys(schema).length,'keys');
      });
    }).catch(function(e){ console.warn('[site-content]',e); });
  }
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',boot); else boot();
})();
