(function(){
  var KEY='portal_content_v1', DKEY='portal_docs_v1', API='/api/portal/content';
  var docs=null; try{ docs=JSON.parse(localStorage.getItem(DKEY)||'null'); }catch(e){}
  var WKEY='portal_workflows_v1', wfs=null; try{ wfs=JSON.parse(localStorage.getItem(WKEY)||'null'); }catch(e){}
  var D={
    'site.title':'Enterprise Approval Portal','site.subtitle':'IT Security & Compliance',
    'hero.badge':'Secure • Auditable • Compliant','hero.heading':'How can we help you today?',
    'hero.body':"Submit an access or approval request.\nWe'll route it to the right people, so you can get back to what matters.",
    'hero.search_placeholder':'Have a request ID? Enter it here… (e.g. OCA-2026-00001)',
    'hero.note':'No login required to submit. Approvers are notified automatically.',
    'types.heading':'What type of request do you need?',
    'types.intro':'Choose a request type to get started. Each request has its own form and approval workflow.',
    'type.oca.label':'Out-of-Country Access','type.oca.desc':'Access company systems while physically located outside the country.',
    'type.aia.label':'AI Use Case Intake','type.aia.desc':'Propose a new AI tool or agent for use at Auction.com. Required for any new or expanded AI use case.',
    'type.wua.label':'Website / URL Access','type.wua.desc':'Request to unblock a website, domain, or URL category on the company network.',
    'type.paa.label':'Privileged / Admin Access','type.paa.desc':'Request elevated or administrative access to systems, servers, or infrastructure.',
    'type.ser.label':'Security Exception Request','type.ser.desc':'Request a formal exception to ADC information security policies or standard controls. Requires executive approval chain.',
    'type.sir.label':'IT Security Incident Form','type.sir.desc':'Report an IT security incident. Use for any breach, unauthorized access, data exposure, or security event requiring formal documentation.',
    'footer.org':'IT Security & Compliance · auction.com','footer.contact_label':'Contact IT Service Desk','footer.contact_email':'',
    'confirm.heading':'Request Submitted!','confirm.body':"Your request has been received and the first approver has been notified automatically.",
    'approver.role_subtitle':'Select your approver role to continue',
    'approver.greeting_suffix':'{role} Dashboard — Review and manage your assigned requests.',
    'email.footer':'Enterprise Approval Portal · IT Security & Compliance · auction.com',
    'email.submitted.intro':'Your request has been received and the approval workflow has been started.',
    'email.submitted.closing':'Save your Request ID to track status at any time.',
    'email.approver.intro':'A {type} request has been submitted and is pending your review as {step}.',
    'email.approved.closing':"IT will action the access grant. If you don't hear from the IT Service Desk within one business day, please reach out directly.",
    'email.rejected.closing':'What happens next: this request is now closed. If you believe the decision is incorrect, or you can address the reason above, submit a new request with additional justification and reference {id} in it.',
    'email.returned.closing':'What you need to do: this request is now closed and cannot be edited or resubmitted. Please submit a new request that addresses the point above, and reference {id} in it so the approvers have the history.',
    'step.manager.label':'Dept. Manager','step.security.label':'Security & Compliance',
    'step.hr.label':'Human Resources','step.legal.label':'Legal','step.clo.label':'Chief Legal Officer',
    'step.cto.label':'Chief Technology Officer',
    'step.ceo.label':'Chief Executive Officer',
    'policy.aia.ack':'<p>Your use of approved AI tools remains subject to Auction.com\'s Artificial Intelligence Policy. The following uses require <strong>written approval from Legal and Information Security</strong> and may not be used without it:</p><ul><li>Automated employment, hiring, performance, promotion, discipline, termination, or compensation decisions</li><li>Automated credit, lending, underwriting, insurance, eligibility, ranking, bidding, or pricing decisions</li><li>Legal advice or legal conclusions generated for business use</li><li>Customer-facing automated communications</li><li>Use of biometric, sensitive personal, children\'s, health, financial, or government ID data</li><li>Fully automated decision-making without meaningful human review</li><li>Use of AI to monitor employees or customers</li><li>Use of scraped or unapproved third-party data</li><li>Use of sensitive Client, employee, or consumer information (SSNs, account/loan numbers)</li></ul>'
  };
  var MULTI={'hero.body':1,'confirm.body':1,'email.submitted.intro':1,'email.submitted.closing':1,'email.approver.intro':1,'email.approved.closing':1,'email.rejected.closing':1,'email.returned.closing':1}, IDS=['oca','aia','wua','paa','ser','sir'], cache=null;
  try{ cache=JSON.parse(localStorage.getItem(KEY)||'null'); }catch(e){}
  function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
  function val(k){ var c=cache||{}; return (c[k]!=null&&c[k]!=='')?c[k]:D[k]; }
  function confirmId(){ var w=document.querySelector('.confirm-wrap')||document; var m=(w.textContent||'').match(/\b[A-Z]{3}-\d{4}-\d{5}\b/); return m?m[0]:null; }
  function setText(el,k){
    var v=val(k); if(v==null) return;
    if(k==='confirm.body'){ var id=confirmId(); if(id) v=v.replace(/\{id\}/g,id); }
    if(MULTI[k]){ var html=esc(v).replace(/\n/g,'<br>'); if(el.innerHTML!==html) el.innerHTML=html; }
    else if(el.textContent!==v) el.textContent=v;
  }
  function applyTypes(){
    /* Renamed approval steps: patch the page's own STEP_LABELS so the tile
       chains, the form step ladder and the public tracker all show the name an
       administrator set in Manage Roles. Keys are structural and never change. */
    try{ if(typeof STEP_LABELS!=='undefined'){ ['manager','security','hr','legal','clo','infosec','cto','ceo'].forEach(function(k){
      var v=val('step.'+k+'.label'); if(v) STEP_LABELS[k]=v; }); } }catch(e){}
    try{ if(typeof REQUEST_TYPES!=='undefined'){ IDS.forEach(function(id){ var rt=REQUEST_TYPES[id]; if(!rt) return;
      var l=val('type.'+id+'.label'), d=val('type.'+id+'.desc'); if(l) rt.label=l; if(d) rt.desc=d;
      /* administrator-edited approval chain (Manage Roles). The service is the
         authority — this only makes the page SHOW the chain a new request gets. */
      if(!rt.__wf0) rt.__wf0=(rt.workflow||[]).slice();                 /* the page's built-in chain, kept for resets */
      var w=wfs&&wfs.workflows&&wfs.workflows[id]; rt.workflow=(Array.isArray(w)&&w.length)?w.slice():rt.__wf0.slice();
      rt.hidden=!!(wfs&&wfs.hidden&&wfs.hidden.indexOf(id)>-1); }); } }catch(e){}
    var byDef={}; IDS.forEach(function(id){ byDef[D['type.'+id+'.label']]=id; });
    var cards=document.querySelectorAll('.rtype-card');
    for(var i=0;i<cards.length;i++){
      var c=cards[i], n=c.querySelector('.rtype-name'), d=c.querySelector('.rtype-desc'); if(!n) continue;
      var id=c.getAttribute('data-cms-type');
      if(!id){ id=byDef[n.textContent.trim()]; if(!id) continue; c.setAttribute('data-cms-type',id); }
      var l=val('type.'+id+'.label'), dd=val('type.'+id+'.desc');
      if(l&&n.textContent!==l) n.textContent=l;
      if(d&&dd&&d.textContent!==dd) d.textContent=dd;
      /* The approval-chain pills were rendered from STEP_LABELS before this
         script patched it, so patching the object alone leaves stale names on
         screen. Rewrite the pill text in place, in workflow order. */
      try{
        var rtc=(typeof REQUEST_TYPES!=='undefined')&&REQUEST_TYPES[id];
        if(rtc){ var hide=!!rtc.hidden; if((c.style.display==='none')!==hide) c.style.display=hide?'none':''; }
        var wp=c.querySelector('.workflow-pills');
        if(wp&&rtc){
          var wf=rtc.workflow||[];
          var pills=wp.querySelectorAll('.wpill');
          if(pills.length!==wf.length){
            /* the chain itself changed (a step added or removed): rebuild the pills */
            wp.innerHTML=wf.map(function(k){ var lbl=(typeof STEP_LABELS!=='undefined'&&STEP_LABELS[k])||k;
              return '<span class="wpill" style="background:'+esc(rtc.bg||'')+';color:'+esc(rtc.color||'')+'"><span>'+esc(lbl)+'</span></span>'; }).join('');
          } else {
            var spans=wp.querySelectorAll('.wpill span');
            for(var w=0;w<spans.length&&w<wf.length;w++){
              var lbl=(typeof STEP_LABELS!=='undefined'&&STEP_LABELS[wf[w]])||wf[w];
              if(spans[w].textContent!==lbl) spans[w].textContent=lbl;
            }
          }
        }
      }catch(e){}
    }
  }
  function apply(){
    if(val('site.title')) document.title=val('site.title');
    var els=document.querySelectorAll('[data-cms]');
    for(var i=0;i<els.length;i++) setText(els[i],els[i].getAttribute('data-cms'));
    var at=document.querySelectorAll('[data-cms-attr]');
    for(var j=0;j<at.length;j++){ var sp=at[j].getAttribute('data-cms-attr').split(':'), v=val(sp[1]); if(v!=null&&at[j].getAttribute(sp[0])!==v) at[j].setAttribute(sp[0],v); }
    var em=val('footer.contact_email');
    var ml=document.querySelectorAll('[data-cms-mailto]');
    for(var k=0;k<ml.length;k++){ var el=ml[k]; if(!em) continue;
      if(el.tagName==='A'){ el.href='mailto:'+em; continue; }
      el.removeAttribute('onclick'); el.onclick=function(e){ e.preventDefault(); location.href='mailto:'+em; };
    }
    applyTypes();
    /* Guides: approval-chain badges marked data-workflow="<type>" are rebuilt
       from the live chain and step names, so a rename or a chain edit in
       Manage Roles reaches the documentation too. The trailing .wf-time note
       (if any) is kept. Nothing happens until the chains have been fetched. */
    try{
      var wmap=(wfs&&wfs.workflows)||null;
      if(wmap){ var bs=document.querySelectorAll('[data-workflow]');
        for(var b=0;b<bs.length;b++){ var box=bs[b], t=box.getAttribute('data-workflow'), wf=wmap[t];
          if(!Array.isArray(wf)||!wf.length) continue;
          var want=wf.map(function(k){ return val('step.'+k+'.label')||k; });
          var have=[].map.call(box.querySelectorAll('.wf-step'),function(x){return x.textContent.trim();});
          if(have.join('|')===want.join('|')) continue;
          var first=box.querySelector('.wf-step'), tag=first?first.tagName.toLowerCase():'div', time=box.querySelector('.wf-time');
          box.innerHTML=want.map(function(l,i){ return (i?'<'+tag+' class="wf-arrow">→</'+tag+'>':'')+'<'+tag+' class="wf-step"><span>'+esc(l)+'</span></'+tag+'>'; }).join('')+(time?time.outerHTML:'');
          var card=box.closest?box.closest('.step-card'):null, tg=card&&card.querySelector('.step-tag');
          if(tg&&/^\d+ steps?$/i.test(tg.textContent.trim())) tg.textContent=want.length+' steps';
        } }
    }catch(e){}
    var sg=document.getElementById('apv4-subgreeting');
    if(sg && window.__pcRole){ var t=val('approver.greeting_suffix').replace(/\{role\}/g,window.__pcRole); if(sg.textContent!==t) sg.textContent=t; }
  }
  /* Rich text from Site Content (policy.aia.ack). The service sanitizes on
     save; this is the belt to that brace — same allow-list, applied again at
     render so a stale cache or a hand-edited row can never inject markup. */
  var RT_OK={P:1,BR:1,STRONG:1,B:1,EM:1,I:1,U:1,UL:1,OL:1,LI:1,A:1};
  function safeHtml(src){
    var doc; try{ doc=new DOMParser().parseFromString('<div>'+String(src||'')+'</div>','text/html'); }catch(e){ return esc(String(src||'')); }
    var root=doc.body&&doc.body.firstChild; if(!root) return '';
    function walk(n){
      var out='';
      for(var c=n.firstChild;c;c=c.nextSibling){
        if(c.nodeType===3){ out+=esc(c.nodeValue); continue; }
        if(c.nodeType!==1) continue;
        var t=c.tagName.toUpperCase();
        if(t==='SCRIPT'||t==='STYLE'||t==='IFRAME'||t==='OBJECT'||t==='EMBED'||t==='SVG'||t==='TEMPLATE') continue;
        if(!RT_OK[t]){ out+=walk(c); continue; }
        if(t==='BR'){ out+='<br>'; continue; }
        if(t==='A'){
          var h=(c.getAttribute('href')||'').trim();
          if(!/^(https?:\/\/|mailto:|\/)/i.test(h)){ out+=walk(c); continue; }
          out+='<a href="'+esc(h)+'" target="_blank" rel="noopener noreferrer">'+walk(c)+'</a>'; continue;
        }
        var tl=t.toLowerCase(); out+='<'+tl+'>'+walk(c)+'</'+tl+'>';
      }
      return out;
    }
    return walk(root);
  }
  window.portalContentGreeting=function(role){ window.__pcRole=role; return val('approver.greeting_suffix').replace(/\{role\}/g,role); };
  window.portalContent={get:function(){return cache||{};},defaults:D,apply:apply,val:val,safeHtml:safeHtml,
    doc:function(form){ return (docs&&docs[form])||null; },docs:function(){ return docs||{}; },
    workflows:function(){ return (wfs&&wfs.workflows)||{}; },hiddenTypes:function(){ return (wfs&&wfs.hidden)||[]; },
    refresh:function(){ return fetch(API,{credentials:'same-origin'}).then(function(r){return r.json();}).then(function(j){
      var c=(j&&j.data&&j.data.content)||(j&&j.content)||{}; cache=c; try{localStorage.setItem(KEY,JSON.stringify(c));}catch(e){}
      var dd=(j&&j.data&&j.data.docs)||{}; docs=dd; try{localStorage.setItem(DKEY,JSON.stringify(dd));}catch(e){}
      var ww={workflows:(j&&j.data&&j.data.workflows)||null,hidden:(j&&j.data&&j.data.hidden_types)||[]}; wfs=ww; try{localStorage.setItem(WKEY,JSON.stringify(ww));}catch(e){}
      window.portalContentDocsMeta={convert:!!(j&&j.data&&j.data.docs_convert),maxBytes:(j&&j.data&&j.data.docs_max_bytes)||0};
      apply(); return c; }); }};
  function boot(){
    apply();
    window.portalContent.refresh().catch(function(){});
    var g=document.getElementById('home-type-grid'), t;
    if(g&&window.MutationObserver) new MutationObserver(function(){clearTimeout(t);t=setTimeout(applyTypes,60);}).observe(g,{childList:true});
    var n=0, iv=setInterval(function(){ if(++n>12){clearInterval(iv);return;} apply(); },700);
  }
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',boot); else boot();
})();
