/* portal-reopen.js v1 — admin "Reopen to step" for completed requests. */
(function(){
  'use strict';
  function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
  function api(method,url,body){
    return fetch(url,{method:method,headers:{'Content-Type':'application/json'},credentials:'same-origin',body:body?JSON.stringify(body):undefined})
      .then(function(r){return r.json().then(function(j){ if(!r.ok||j.ok===false) throw new Error(j.message||j.error||('HTTP '+r.status)); return j.data||j; });});
  }
  function close(){ var m=document.getElementById('rmreopen-modal'); if(m) m.remove(); }
  function open(id){
    close();
    api('GET','/api/portal/requests/'+encodeURIComponent(id)+'/reopen').then(function(info){
      var steps=info.steps||[];
      var opts=steps.map(function(s){ return '<option value="'+esc(s.key)+'">'+esc(s.label)+(s.status&&s.status!=='pending'?' — '+esc(s.status)+(s.approver?' by '+esc(s.approver):''):'')+'</option>'; }).join('');
      var m=document.createElement('div'); m.id='rmreopen-modal';
      m.style.cssText='position:fixed;inset:0;background:rgba(17,24,39,.45);z-index:9999;display:flex;align-items:center;justify-content:center';
      m.innerHTML='<div style="background:#fff;border-radius:12px;max-width:460px;width:92%;padding:20px 22px;box-shadow:0 20px 50px rgba(0,0,0,.25);font-size:14px">'
        +'<h3 style="margin:0 0 6px;font-size:16px">Reopen '+esc(info.id)+'</h3>'
        +'<div style="color:#6b7280;font-size:12.5px;margin-bottom:14px">Current status: <b>'+esc(info.status)+'</b>. The chosen step and every step after it return to <b>pending</b>; earlier approvals stay. Prior decisions remain in History. The step approvers are notified.</div>'
        +'<label style="display:block;font-weight:600;margin-bottom:4px">Send back to step</label>'
        +'<select id="rmreopen-step" style="width:100%;padding:8px;border:1px solid #d1d5db;border-radius:8px;margin-bottom:12px">'+opts+'</select>'
        +'<label style="display:block;font-weight:600;margin-bottom:4px">Reason <span style="color:#9ca3af;font-weight:400">(required, written to the audit log)</span></label>'
        +'<textarea id="rmreopen-reason" style="width:100%;min-height:64px;padding:8px;border:1px solid #d1d5db;border-radius:8px;box-sizing:border-box"></textarea>'
        +'<div id="rmreopen-err" style="color:#b91c1c;font-size:12.5px;min-height:18px;margin-top:6px"></div>'
        +'<div style="display:flex;gap:8px;justify-content:flex-end;margin-top:10px">'
        +'<button class="apv4-btn" id="rmreopen-cancel">Cancel</button>'
        +'<button class="apv4-btn warn" id="rmreopen-go">↺ Reopen</button></div></div>';
      document.body.appendChild(m);
      document.getElementById('rmreopen-cancel').onclick=close;
      document.getElementById('rmreopen-go').onclick=function(){
        var step=document.getElementById('rmreopen-step').value, reason=(document.getElementById('rmreopen-reason').value||'').trim();
        var errEl=document.getElementById('rmreopen-err'); errEl.textContent='';
        if(!reason){ errEl.textContent='Reason is required.'; return; }
        this.disabled=true;
        api('POST','/api/portal/requests/'+encodeURIComponent(id)+'/reopen',{step:step,reason:reason}).then(function(){
          close();
          try{ if(window.AP&&AP.closeDrawer) AP.closeDrawer(); }catch(e){}
          location.reload();
        }).catch(function(e){ errEl.textContent=e.message||String(e); document.getElementById('rmreopen-go').disabled=false; });
      };
    }).catch(function(e){ alert('Reopen unavailable: '+(e.message||e)); });
  }
  window.RMREOPEN={open:open,close:close};
})();
