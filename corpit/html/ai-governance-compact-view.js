/* CorpIT AI Governance compact view. Presentation only: hides secondary text,
   provenance lines and advanced disclosures with CSS. Hidden inputs still submit,
   so no record field is dropped on save. */
(function(){'use strict';
const KEY='corpit:ai:compact-view',root=document.documentElement;
// Rail sections kept in compact view; the current section always stays visible.
const CORE=['dashboard','inventory','use-cases','attention','approved-sites','requests'];
// Compact is the default; only an explicit switch-off is remembered as '0'.
function read(){try{return localStorage.getItem(KEY)!=='0';}catch{return true;}}
function write(on){try{localStorage.setItem(KEY,on?'1':'0');}catch{}}
function apply(on,button){root.classList.toggle('ai-compact',on);if(button){button.setAttribute('aria-checked',String(on));button.title=on?'Showing essentials only. Switch off for full evidence and source detail.':'Hide explanations, source lines and advanced details';}}
apply(read());
function mount(){document.querySelectorAll('#navigation [data-view]').forEach(n=>{if(CORE.includes(n.dataset.view))n.dataset.compactCore='';});const host=document.querySelector('.top-actions');if(!host||document.getElementById('ai-compact-toggle'))return;const b=document.createElement('button');b.type='button';b.id='ai-compact-toggle';b.className='ai-compact-toggle';b.setAttribute('role','switch');b.setAttribute('aria-label','Compact view');b.innerHTML='<span class="ai-compact-track" aria-hidden="true"><span></span></span><span>Compact</span>';b.onclick=()=>{const on=!root.classList.contains('ai-compact');apply(on,b);write(on);};host.insertBefore(b,host.firstChild);apply(root.classList.contains('ai-compact'),b);}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',mount);else mount();
})();
