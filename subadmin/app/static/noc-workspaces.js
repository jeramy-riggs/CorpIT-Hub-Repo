(function(){'use strict';
var rail=document.getElementById('noc-workspace-nav'),app=document.querySelector('.app'),menu=document.getElementById('noc-menu');
if(!rail||!app)return;
var moduleNames={health:'Server operations',people:'Access & gating',resources:'Services',operations:'Operations',settings:'Settings'};
function closeMenu(){var wasOpen=app.classList.contains('noc-menu-open');app.classList.remove('noc-menu-open');menu.setAttribute('aria-expanded','false');menu.setAttribute('aria-label','Open workspace navigation');if(wasOpen)menu.focus();}
document.querySelector('.noc-skip').addEventListener('click',function(e){e.preventDefault();document.getElementById('noc-main').focus();});
menu.addEventListener('click',function(){var open=app.classList.toggle('noc-menu-open');menu.setAttribute('aria-expanded',String(open));menu.setAttribute('aria-label',open?'Close workspace navigation':'Open workspace navigation');});
document.addEventListener('keydown',function(e){if(e.key==='Escape'&&app.classList.contains('noc-menu-open')){closeMenu();menu.focus();}});
// Reuse the route registry, including API-probed settings entries. No second source of truth.
function sync(){var select=document.getElementById('hybrid-workspace');if(!select)return;var hash=location.hash.slice(1)||'overview',module=document.body.dataset.hybridModule||'health';
 document.getElementById('noc-context').textContent=moduleNames[module]||'Console';
 var chosen=select.selectedOptions[0];document.getElementById('noc-current').textContent=chosen?chosen.textContent:'Workspace';
 var links=Array.from(select.options).map(function(option){var a=document.createElement('a');a.href='#'+option.value;a.className='noc-workspace-link';a.textContent=option.textContent;var match=option.selected;a.setAttribute('aria-current',match?'page':'false');if(option.dataset.unavailable)a.dataset.unavailable='';return a;});
 var active=document.activeElement,activeHref=active&&active.closest('.noc-workspace-link')&&active.getAttribute('href');rail.replaceChildren.apply(rail,links);
 if(activeHref){var restored=links.find(function(a){return a.getAttribute('href')===activeHref;});if(restored)restored.focus({preventScroll:true});}
 if(hash.startsWith('settings/')){var label=document.querySelector('[data-tabs=settings] [data-tab="'+hash.split('/')[1]+'"]');var heading=document.querySelector('[data-view=settings] .page-h h2');if(heading)heading.textContent=label&&hash!=='settings/directory'?label.textContent:'Settings workspace';}
}
var nav=document.getElementById('module-nav');new MutationObserver(sync).observe(nav,{childList:true,subtree:true});
window.addEventListener('console-route',function(){sync();closeMenu();});window.addEventListener('hashchange',function(){sync();closeMenu();});sync();
// Tab selection is immediate for keyboard users; denied or absent editors never enter the focus order.
document.querySelectorAll('.tabs[role=tablist]:not([data-tabs=directory])').forEach(function(list){
 function visible(){return Array.from(list.querySelectorAll('[role=tab]')).filter(function(b){return !b.hidden;});}
 function roving(){visible().forEach(function(b){b.tabIndex=b.getAttribute('aria-selected')==='true'?0:-1;});}
 list.addEventListener('keydown',function(e){if(!['ArrowLeft','ArrowRight','Home','End'].includes(e.key))return;var tabs=visible(),i=tabs.indexOf(document.activeElement);if(i<0)return;e.preventDefault();var next=e.key==='Home'?0:e.key==='End'?tabs.length-1:(i+(e.key==='ArrowRight'?1:-1)+tabs.length)%tabs.length;tabs[next].click();tabs[next].focus();roving();});
 new MutationObserver(roving).observe(list,{subtree:true,attributes:true,attributeFilter:['hidden','aria-selected']});roving();
});
// Source-aware destinations become part of the existing keyboard command palette.
var extras=[{t:'Operator desk',g:'Workspaces',url:'#overview',meta:'Health triage and source evidence',i:'link'}];
if(document.querySelector('[data-updates-panel]'))extras.push({t:'Server updates',g:'Workspaces',url:'#system/updates',meta:'Controlled package installs and reboots',i:'link'});
window.CONSOLE_WORKSPACE_SEARCH=extras;
window.CMDK_ITEMS=(window.CMDK_ITEMS||[]).concat(extras);
// All console setting controls stay enabled and attached to the one full form.
// This is a visual section editor, not a partial save contract.
var form=document.querySelector('[data-console-settings]');if(form){var controls=Array.from(form.querySelectorAll('input:not([type=hidden]),textarea,select'));var original=new Map(controls.map(function(el){return [el,el.type==='checkbox'?el.checked:el.value];}));var foot=form.querySelector('.settings-save'),indicator=document.createElement('span');indicator.className='noc-draft-indicator';indicator.setAttribute('role','status');foot.append(indicator);
 function dirty(){return controls.filter(function(el){return (el.type==='checkbox'?el.checked:el.value)!==original.get(el);});}
 function paint(){var changed=dirty();controls.forEach(function(el){el.toggleAttribute('data-noc-dirty',changed.includes(el));});indicator.textContent=changed.length?changed.length+' unsaved change'+(changed.length===1?'':'s'):'';}
 form.addEventListener('input',paint);form.addEventListener('change',paint);
 // A refused save (stale form, failed audit, validation) redirects back with data-restore-draft:
 // put the operator's edits back over the freshly drawn values. Secrets are never stored.
 var DKEY='subadmin.settings.draft';
 function keyOf(el){return el.name&&el.type!=='password'?el.name:'';}
 try{var saved=JSON.parse(sessionStorage.getItem(DKEY)||'null');sessionStorage.removeItem(DKEY);
  if(saved&&form.hasAttribute('data-restore-draft')){controls.forEach(function(el){var k=keyOf(el);if(!k||!Object.prototype.hasOwnProperty.call(saved,k))return;if(el.type==='checkbox')el.checked=!!saved[k];else el.value=saved[k];});paint();}}catch(e){/* storage unavailable: the page still works without restore */}
 var submitting=false;form.addEventListener('submit',function(e){if(!e.defaultPrevented){submitting=true;var d={};dirty().forEach(function(el){var k=keyOf(el);if(k)d[k]=el.type==='checkbox'?el.checked:el.value;});try{sessionStorage.setItem(DKEY,JSON.stringify(d));}catch(x){}}});
 window.addEventListener('beforeunload',function(e){if(!submitting&&dirty().length){e.preventDefault();e.returnValue='';}});
}
// Apply the same visual language to embedded diagnostics, keeping its own permission/API logic.
var frame=document.getElementById('health-workspace');if(frame)frame.addEventListener('load',function(){try{var doc=frame.contentDocument;if(!doc||doc.querySelector('[data-noc-theme]'))return;var css=doc.createElement('link');css.rel='stylesheet';css.href='/static/noc-health-embedded.css?v=20261012noc1';css.dataset.nocTheme='';doc.head.append(css);}catch(e){/* Authentication retains its own gate. */}});
})();
