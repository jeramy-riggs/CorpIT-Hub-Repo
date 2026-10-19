(function(){'use strict';if(window.parent===window)return;
 var allowed=['status','settings','journeys'];
 function notify(){var b=document.body;window.parent.postMessage({type:'corpit-health-size',height:Math.ceil(b.getBoundingClientRect().height)},location.origin);}
 window.addEventListener('message',function(e){if(e.origin!==location.origin||e.source!==window.parent)return;var d=e.data||{};if(d.type==='corpit-health-theme'&&['light','dark'].indexOf(d.theme)>=0)document.documentElement.dataset.theme=d.theme;if(d.type==='corpit-health-tab'&&allowed.indexOf(d.section)>=0){var b=document.getElementById('hc-tab-'+d.section);if(b&&b.getAttribute('aria-selected')!=='true')b.click();}});
 document.querySelectorAll('[data-tab]').forEach(function(b){b.addEventListener('click',function(){window.parent.postMessage({type:'corpit-health-tab',section:b.dataset.tab},location.origin);});});
 if(window.ResizeObserver)new ResizeObserver(notify).observe(document.body);else window.addEventListener('resize',notify);
 window.parent.postMessage({type:'corpit-health-ready'},location.origin);notify();
})();