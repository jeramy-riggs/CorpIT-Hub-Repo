/* Page opt-in helpers; no API calls, telemetry, or operational writes. */
(function(){
 'use strict';
 function csvCell(v){var s=String(v==null?'':v);if(/^\s*[=+@-]/.test(s)||/^[\t\r\n]/.test(s))s="'"+s;return /[",\r\n]/.test(s)?'"'+s.replace(/"/g,'""')+'"':s;}
 function csv(name,headers,rows){
  var text='\ufeff'+[headers].concat(rows).map(function(r){return r.map(csvCell).join(',')}).join('\r\n');
  var url=URL.createObjectURL(new Blob([text],{type:'text/csv;charset=utf-8'})),a=document.createElement('a');a.href=url;a.download=name;document.body.appendChild(a);a.click();a.remove();setTimeout(function(){URL.revokeObjectURL(url)},1000);
 }
 var pages={};
 function page(key,rows,host,render){
  var v=pages[key]||(pages[key]={page:1,size:25,rows:null});
  if(v.rows!==rows){v.page=1;v.rows=rows;}
  var total=Math.max(1,Math.ceil(rows.length/v.size));v.page=Math.min(v.page,total);
  if(!host.children.length){
   host.classList.add('op-pager');
   var info=document.createElement('span');info.setAttribute('role','status');host.appendChild(info);
   var label=document.createElement('label');label.textContent='Rows per page ';
   var size=document.createElement('select');size.className='op-input';size.setAttribute('aria-label',key+' rows per page');
   [25,50,100].forEach(function(n){var o=document.createElement('option');o.value=n;o.textContent=n;size.appendChild(o)});label.appendChild(size);host.appendChild(label);
   var prev=document.createElement('button'),next=document.createElement('button');prev.type=next.type='button';prev.className=next.className='op-btn';prev.textContent='Previous';next.textContent='Next';prev.setAttribute('aria-label','Previous '+key+' page');next.setAttribute('aria-label','Next '+key+' page');host.appendChild(prev);host.appendChild(next);
   size.onchange=function(){v.size=Number(size.value);v.page=1;render()};prev.onclick=function(){v.page--;render()};next.onclick=function(){v.page++;render()};
  }
  var start=(v.page-1)*v.size,end=Math.min(start+v.size,rows.length);
  host.firstElementChild.textContent=(rows.length?start+1:0)+'–'+end+' of '+rows.length+' loaded · Page '+v.page+' of '+total;
  host.querySelector('select').value=v.size;var bs=host.querySelectorAll('button');bs[0].disabled=v.page<=1;bs[1].disabled=v.page>=total;
  return rows.slice(start,end);
 }
 window.OpsPolish={csvCell:csvCell,csv:csv,page:page};
 document.addEventListener('DOMContentLoaded',function(){
  // Name existing inputs without changing their content or handlers.
  document.querySelectorAll('input[placeholder],textarea[placeholder]').forEach(function(e){if(!e.labels?.length&&!e.hasAttribute('aria-label'))e.setAttribute('aria-label',e.placeholder);});
  document.querySelectorAll('.tabs[role="tablist"]').forEach(function(list){
   if(list.dataset.opKeys)return;list.dataset.opKeys='1';
   list.addEventListener('keydown',function(e){
    if(!['ArrowLeft','ArrowRight','Home','End'].includes(e.key))return;
    var tabs=Array.from(list.querySelectorAll('[role="tab"]')),i=tabs.indexOf(e.target);if(i<0)return;
    e.preventDefault();var n=e.key==='Home'?0:e.key==='End'?tabs.length-1:(i+(e.key==='ArrowRight'?1:tabs.length-1))%tabs.length;tabs[n].click();tabs[n].focus();
   });
  });
  // Focus containment and return for the existing drawers/modal backdrops.
  document.querySelectorAll('.modal-backdrop,#drawer,#flyover').forEach(function(overlay){
   var modal=overlay.querySelector('.modal')||overlay,opener=null,opened=false;
   modal.setAttribute('role','dialog');modal.setAttribute('aria-modal','true');modal.tabIndex=-1;
   if(!modal.hasAttribute('aria-label')&&!modal.hasAttribute('aria-labelledby'))modal.setAttribute('aria-label','Details');
   overlay.inert=!overlay.matches('.open,.show');
   overlay.setAttribute('aria-hidden',String(overlay.inert));
   new MutationObserver(function(){
    var on=overlay.matches('.open,.show');
    overlay.inert=!on;overlay.setAttribute('aria-hidden',String(!on));
    if(on&&!opened){opener=document.activeElement;modal.focus();}
    if(!on&&opened&&opener?.isConnected)opener.focus();opened=on;
   }).observe(overlay,{attributes:true,attributeFilter:['class']});
   modal.addEventListener('keydown',function(e){
    if(e.key!=='Tab')return;
    var ns=Array.from(modal.querySelectorAll('button:not(:disabled),input:not(:disabled),select:not(:disabled),textarea:not(:disabled),a[href],[tabindex="0"]')).filter(function(n){return n.getClientRects().length});
    var i=ns.indexOf(document.activeElement);if(!ns.length){e.preventDefault();return;}
    if(e.shiftKey&&(i===0||i<0)){e.preventDefault();ns[ns.length-1].focus();}else if(!e.shiftKey&&(i===ns.length-1||i<0)){e.preventDefault();ns[0].focus();}
   });
  });
 });
})();
