(function(){'use strict';
var frame=document.getElementById('health-workspace');if(!frame)return;
var allowed=['status','settings','journeys'],last='';
function section(){var p=location.hash.slice(1).split('/');return p[0]==='health'?(allowed.includes(p[1])?p[1]:'status'):p[0]==='overview'||!p[0]?'status':null;}
function post(d){if(frame.contentWindow)frame.contentWindow.postMessage(d,location.origin);}
function theme(){post({type:'corpit-health-theme',theme:document.documentElement.dataset.theme==='dark'?'dark':'light'});}
function route(){var s=section();if(s&&!frame.getAttribute('src'))frame.src=frame.dataset.healthSrc+'#'+s;else if(s&&s!==last)post({type:'corpit-health-tab',section:s});post({type:'corpit-health-active',active:s!==null});if(s)last=s;}
window.addEventListener('message',function(e){if(e.origin!==location.origin||e.source!==frame.contentWindow)return;var d=e.data||{};
if(d.type==='corpit-health-size'&&Number.isFinite(d.height))frame.style.height=Math.max(400,Math.min(50000,Math.ceil(d.height)))+'px';
if(d.type==='corpit-health-tab'&&allowed.includes(d.section)&&location.hash.startsWith('#health')){last=d.section;if(section()!==d.section){history.replaceState(null,'','#health/'+d.section);window.dispatchEvent(new CustomEvent('console-route'));}}
if(d.type==='corpit-health-ready'){last='';route();theme();}});
new MutationObserver(theme).observe(document.documentElement,{attributes:true,attributeFilter:['data-theme']});
window.addEventListener('console-route',route);window.addEventListener('hashchange',route);route();
})();
