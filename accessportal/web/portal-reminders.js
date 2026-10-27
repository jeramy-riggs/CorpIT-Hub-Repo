/* portal-reminders.js — Approval reminders settings card (v1, 2026-10-16). Admin only.
   Appends a card to the Notification Emails page: schedule, cadence, cap, escalation; dry run / send now. */
(function(){
  'use strict';
  var X=window.APX; if(!X||!X.S){ console.warn('[reminders] console hooks missing'); return; }
  var S=X.S, esc=X.esc, toast=X.toast; var E=esc; function $(id){ return document.getElementById(id); }
  var CARD='apv4-reminders-card';
  function api(method,path,body){ var o={method:method,credentials:'same-origin',headers:{}}; if(body){ o.body=JSON.stringify(body); o.headers['Content-Type']='application/json'; }
    return fetch(path,o).then(function(r){ return r.json().catch(function(){return {};}).then(function(j){ if(!r.ok||j.ok===false) throw new Error((j&&(j.error||j.message))||('HTTP '+r.status)); return j.data!==undefined?j.data:j; }); }); }
  function findPage(){
    var p=$('apv4-page-notifications'); if(p) return p;
    var pages=[].slice.call(document.querySelectorAll('[id^="apv4-page-"]'));
    for(var i=0;i<pages.length;i++){ var t=(pages[i].querySelector('.apv4-page-title')||{}).textContent||''; if(/notification/i.test(t)) return pages[i]; }
    return null;
  }
  function num(id,label,val,hint){ return '<label style="display:grid;gap:3px;font-size:12px;color:#4b5563"><span>'+label+'</span><input type="number" id="'+id+'" class="apv4-field" style="margin:0;width:110px" value="'+E(val)+'"><span style="font-size:11px;color:#9ca3af">'+hint+'</span></label>'; }
  function render(card){
    api('GET','/api/portal/reminders/settings').then(function(d){
      var s=d.settings;
      card.innerHTML='<div style="display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;align-items:flex-start"><div><b style="font-size:14px">Approval reminders</b><div style="font-size:12px;color:#6b7280">Daily sweep, all forms and steps. A request waiting at its current step reminds the step approver (direct manager or the step address above); repeats until decided or the cap is reached. From the escalation count onward the Service Desk'+(d.helpdesk?' ('+E(d.helpdesk)+')':'')+' is copied. Last run: '+(d.last_run?E(d.last_run):'never')+'.</div></div>'
        +'<label style="display:flex;align-items:center;gap:6px;font-size:13px;font-weight:700"><input type="checkbox" id="rmd-enabled"'+(s.enabled?' checked':'')+'> Enabled</label></div>'
        +'<div style="display:flex;gap:14px;flex-wrap:wrap;margin:12px 0">'+num('rmd-first','First reminder after',s.first_days,'days at the step')+num('rmd-every','Repeat every',s.every_days,'days')+num('rmd-max','Maximum reminders',s.max,'per request per step')+num('rmd-esc','Escalate from reminder #',s.escalate_after,'cc Service Desk')+num('rmd-hour','Send at hour',s.hour,'server local, 0–23')+'</div>'
        +'<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center"><button class="apv4-btn pri sm" id="rmd-save">Save</button><button class="apv4-btn sm" id="rmd-dry">Preview who would be reminded</button><button class="apv4-btn sm warn" id="rmd-send">Send reminders now</button><span id="rmd-msg" style="font-size:12px;color:#6b7280"></span></div>'
        +'<div id="rmd-out" style="margin-top:10px"></div>';
      $('rmd-save').onclick=function(){ api('PUT','/api/portal/reminders/settings',{enabled:$('rmd-enabled').checked,first_days:$('rmd-first').value,every_days:$('rmd-every').value,max:$('rmd-max').value,escalate_after:$('rmd-esc').value,hour:$('rmd-hour').value}).then(function(){ toast&&toast('Reminder settings saved'); render(card); }).catch(function(e){ $('rmd-msg').textContent=e.message; }); };
      function run(dry){ $('rmd-msg').textContent=dry?'Checking…':'Sending…'; api('POST','/api/portal/reminders/run?dry='+(dry?'1':'0')).then(function(r){
          $('rmd-msg').textContent=(dry?'Preview: ':'Done: ')+r.checked+' pending checked · '+r.due+' due'+(dry?'':' · '+r.sent+' sent');
          var rows=r.rows.filter(function(x){ return x.due; });
          $('rmd-out').innerHTML=rows.length?'<div style="overflow-x:auto"><table class="apv4-tbl" style="font-size:12.5px"><thead><tr><th>Request</th><th>Step</th><th>Waiting</th><th>Reminders sent</th><th>To</th><th>Escalate</th></tr></thead><tbody>'+rows.map(function(x){ return '<tr><td><b>'+E(x.id)+'</b> · '+E(x.submitter||'')+'</td><td>'+E(x.step_label)+'</td><td>'+x.age_days+'d</td><td>'+x.sent+'</td><td>'+(x.to?E(x.to):'<span style="color:#b91c1c">no recipient</span>')+'</td><td>'+(x.escalate?'yes':'—')+'</td></tr>'; }).join('')+'</tbody></table></div>':'<div style="font-size:12.5px;color:#6b7280">Nothing is due right now.</div>';
        }).catch(function(e){ $('rmd-msg').textContent=e.message; }); }
      $('rmd-dry').onclick=function(){ run(true); };
      $('rmd-send').onclick=function(){ confirmBox('Send reminder emails now to every approver with a due request?', function(){ run(false); }); };
    }).catch(function(e){ card.innerHTML='<div style="color:#b91c1c;font-size:13px">Reminders unavailable: '+E(e.message||e)+'</div>'; });
  }
  function confirmBox(msg,yes){ var m=document.createElement('div'); m.style.cssText='position:fixed;inset:0;background:rgba(17,24,39,.45);z-index:9999;display:flex;align-items:center;justify-content:center';
    m.innerHTML='<div style="background:#fff;border-radius:12px;max-width:420px;width:92%;padding:18px 20px;box-shadow:0 20px 50px rgba(0,0,0,.25);font-size:14px;color:#111827"><div>'+E(msg)+'</div><div style="display:flex;gap:8px;justify-content:flex-end;margin-top:14px"><button class="apv4-btn" id="rmd-c-no">Cancel</button><button class="apv4-btn pri" id="rmd-c-yes">Send</button></div></div>';
    document.body.appendChild(m); $('rmd-c-no').onclick=function(){ m.remove(); }; $('rmd-c-yes').onclick=function(){ m.remove(); yes(); }; }
  function inject(){
    if(S.role!=='admin') return;
    var pg=findPage(); if(!pg) return;
    if($(CARD)) return;
    var card=document.createElement('div'); card.id=CARD; card.className='apv4-card'; card.style.cssText='padding:14px 18px;margin-top:14px';
    pg.appendChild(card); render(card);
  }
  var root=$('apv4-root');
  if(root&&window.MutationObserver){ new MutationObserver(function(){ if(!$(CARD)) inject(); }).observe(root,{childList:true,subtree:true}); }
  if(window.RM){ var _p=RM.afterSidebar; RM.afterSidebar=function(el){ if(_p) _p(el); setTimeout(inject,50); }; var _r=RM.onRole; RM.onRole=function(id){ if(_r) _r(id); setTimeout(inject,80); }; }
  inject();
  console.info('[reminders] loaded');
})();
