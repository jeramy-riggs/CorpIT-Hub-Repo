/* Presentation and discovery only. No save, grant, repair or lookup requests. */
(function(){'use strict';
var root=document.documentElement;
// Keep explicit appearance choices; new sessions default to the approved palette.
try{root.dataset.theme=localStorage.getItem('corpit-theme')||'dark';}catch(e){root.dataset.theme=root.dataset.theme||'dark';}
function skinFrame(frame){try{var doc=frame.contentDocument;if(!doc||!doc.documentElement||doc.location.origin!==location.origin)return;doc.documentElement.dataset.theme=root.dataset.theme||'dark';doc.documentElement.dataset.consoleSkin='operations';if(!doc.querySelector('[data-console-operations-skin]')){var css=doc.createElement('link');css.rel='stylesheet';css.href='/static/console-operations-skin.css?v=20261013skin3';css.dataset.consoleOperationsSkin='';doc.head.append(css);}}catch(e){/* Cross-origin owning workspaces retain their own presentation. */}}
var bound=new WeakSet();function frames(){document.querySelectorAll('iframe').forEach(function(f){if(!bound.has(f)){bound.add(f);f.addEventListener('load',function(){skinFrame(f);});}skinFrame(f);});}
frames();var observer=new MutationObserver(function(records){if(records.some(function(r){return r.type==='childList';}))frames();});observer.observe(document.body,{subtree:true,childList:true});var themes=new MutationObserver(frames);themes.observe(root,{attributes:true,attributeFilter:['data-theme']});
var names={overview:'Server overview',servers:'Server capacity and A/B continuity',performance:'Response time and request performance',services:'Services and scheduled jobs',databases:'Database health and metadata',backups:'Backup health and recovery',users:'User and sign-in health',logs:'Server request logs',coverage:'Monitoring coverage and missing collectors'};
var extras=Object.keys(names).map(function(k){return {t:names[k],g:'Server operations',url:'#overview'+(k==='overview'?'':'/'+k),meta:'Read-only server diagnostics',i:'link'};});
function merge(items){var seen=new Set();return (items||[]).concat(extras).filter(function(i){var key=(i.url||i.t)+'|'+i.t;if(seen.has(key))return false;seen.add(key);return true;});}
window.CONSOLE_WORKSPACE_SEARCH=merge(window.CONSOLE_WORKSPACE_SEARCH);window.CMDK_ITEMS=merge(window.CMDK_ITEMS);
// Preserve source-owned drafts. Route navigation only closes transient effects.
window.addEventListener('pagehide',function(){observer.disconnect();themes.disconnect();});
})();
