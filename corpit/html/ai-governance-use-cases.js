/* AI USE-CASE INVENTORY 2026-10-20. One record per AI use case from the InfoSec / Legal
   "AI/ML Use Inventory" workbook, each linked to a catalog application. Import shows the
   returned workbook row by row before anything is saved; export fills the workbook's own
   template. Records only: nothing here approves an application or changes its assessment. */
(function(root){'use strict';
const E=v=>String(v==null?'':v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const API='/api/zscaler/governance/use-cases',HIGH='Review for High';
const NO_FILL='Name, Category and the InfoSec / Legal review section are never filled from the app.';
const today=()=>new Date().toLocaleDateString('en-CA');
const day=v=>{if(!v)return '';const d=new Date(v);return Number.isFinite(d.getTime())?d.toLocaleDateString():'';};
const badge=(s,t='')=>'<span class="sai-badge '+t+'">'+E(s)+'</span>';
const overdue=r=>/^\d{4}-\d{2}-\d{2}$/.test(r.calc.next_review)&&r.calc.next_review<today();
function b64(buf){const u=new Uint8Array(buf);let s='';for(let i=0;i<u.length;i+=0x8000)s+=String.fromCharCode.apply(null,u.subarray(i,i+0x8000));return btoa(s);}
async function request(path,options={},ms=20000){
  const ctrl=new AbortController(),timer=setTimeout(()=>ctrl.abort(),ms);
  try{const r=await fetch(API+path,{credentials:'same-origin',...options,headers:{'Content-Type':'application/json'},signal:ctrl.signal});let j;try{j=await r.json();}catch{throw new Error('Unexpected response. Refresh the page and try again.');}if(!r.ok){const e=new Error(r.status===503?'Use-case records are not available on this server yet.':j.error||'Request failed');e.status=r.status;throw e;}return j;}
  catch(e){if(e.name==='AbortError')throw new Error('Request timed out. Reload to check whether the change was saved before trying again.');throw e;}
  finally{clearTimeout(timer);}
}
function mount(el,opts={}){
  const listeners=new AbortController(),dialogs=new Set(),toast=opts.toast||(()=>{});
  let data=null,error='',q='',app='',status='',flag='',inflight=0,alive=true;
  const track=async p=>{inflight++;try{return await p;}finally{inflight--;}};
  const field=k=>data.fields.find(f=>f.key===k);
  async function load(){
    try{data=await track(request(''));error='';}catch(e){error=e.message;}
    if(alive)render();
  }
  function matching(){
    const s=q.trim().toLowerCase();
    return data.rows.filter(r=>(!app||String(r.catalog_id)===app)&&(!status||r.profile.status===status)
      &&(!flag||(flag==='blank'?r.calc.required_blank>0:flag==='high'?r.calc.auto_flag===HIGH:overdue(r)))
      &&(!s||[r.ref,r.profile.name,r.profile.dept,r.app_name,r.profile.vendor,r.profile.bowner].some(v=>String(v||'').toLowerCase().includes(s))));
  }
  function rows(list){
    if(!list.length)return '<tr><td colspan="8"><div class="empty"><strong>'+(data.rows.length?'No use cases match these filters.':'No use cases recorded yet.')+'</strong>'+(data.rows.length||!data.can_edit?'':'<p>Import the returned workbook or add a use case.</p>')+'</div></td></tr>';
    return list.map(r=>{const p=r.profile,c=r.calc;return '<tr><td><button type="button" class="sai-link" data-uc-open="'+r.id+'">'+E(r.ref)+'</button></td>'
      +'<td><strong>'+E(p.name)+'</strong><small>'+E(p.dept||'Department not recorded')+'</small></td>'
      +'<td>'+E(r.app_name||'Application '+r.catalog_id)+(r.app_retired?' '+badge('Retired app','warn'):'')+'<small>'+E(p.vendor||'Vendor not recorded')+'</small></td>'
      +'<td>'+E(p.status||'Not recorded')+'<small>'+E(p.cat||'Category not recorded')+'</small></td>'
      +'<td>'+(c.required_blank?badge(c.required_blank+' blank','warn'):badge('0'))+'</td>'
      +'<td>'+(c.auto_flag===HIGH?badge(HIGH,'warn'):'-')+'</td>'
      +'<td>'+E(p.tier||'Not assigned')+'<small>'+E(c.next_review?'Next review '+c.next_review:'No review date')+(overdue(r)?' · Overdue':'')+'</small></td>'
      +'<td>'+E(day(r.updated_at))+'<small>'+E(r.updated_by)+'</small></td></tr>';}).join('');
  }
  function results(){const list=matching();el.querySelector('[data-uc-results]').innerHTML=rows(list);el.querySelector('[data-uc-count]').textContent=list.length+' of '+data.rows.length+' use cases';}
  function render(){
    if(error&&!data){el.innerHTML='<div class="sai uc-view"><h2>Use-case inventory unavailable</h2><p role="alert">'+E(error)+'</p><button type="button" data-uc-refresh>Try again</button></div>';return;}
    if(!data){el.innerHTML='<div class="sai uc-view"><p role="status">Loading use cases…</p></div>';return;}
    const all=data.rows,apps=[...new Map(all.map(r=>[r.catalog_id,r.app_name||'Application '+r.catalog_id])).entries()].sort((a,b)=>String(a[1]).localeCompare(String(b[1])));
    if(app&&!apps.some(([n])=>String(n)===app))app='';
    const opt=(v,l,cur)=>'<option value="'+E(v)+'"'+(String(v)===cur?' selected':'')+'>'+E(l)+'</option>';
    el.innerHTML='<div class="sai uc-view">'+(error?'<p role="alert">'+E(error)+'</p>':'')
      +'<div class="sai-note">'+E(data.note)+' Required (*) fields may be left blank; the workbook counts them in "Required fields still blank".</div>'
      +'<div class="sai-metrics" aria-label="Use-case summary"><div><strong>'+all.length+'</strong><span>Use cases recorded</span></div><div><strong>'+all.filter(r=>r.calc.required_blank>0).length+'</strong><span>With required fields still blank</span></div><div><strong>'+all.filter(r=>r.calc.auto_flag===HIGH).length+'</strong><span>Auto-flag: Review for High</span></div><div><strong>'+all.filter(overdue).length+'</strong><span>Next review overdue</span></div></div>'
      +'<div class="sai-controls"><label>Search<input type="search" data-uc-search value="'+E(q)+'" placeholder="Use case, department, application, vendor or ID"></label>'
      +'<label>Application<select data-uc-filter="app">'+opt('','All applications',app)+apps.map(([n,l])=>opt(n,l,app)).join('')+'</select></label>'
      +'<label>Status<select data-uc-filter="status">'+opt('','All statuses',status)+(field('status').allowed||[]).map(s=>opt(s,s,status)).join('')+'</select></label>'
      +'<label>Show<select data-uc-filter="flag">'+opt('','All use cases',flag)+opt('blank','Required fields still blank',flag)+opt('high','Auto-flag: Review for High',flag)+opt('overdue','Next review overdue',flag)+'</select></label>'
      +'<div class="uc-actions">'+(data.can_edit?'<button type="button" class="sai-primary" data-uc-add>Add use case</button><button type="button" data-uc-import>Import workbook</button><input type="file" data-uc-file accept=".xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" hidden>':'')+'<button type="button" data-uc-export>Export workbook</button><button type="button" data-uc-refresh>Refresh</button></div></div>'
      +'<p class="sai-count" data-uc-count></p><div class="sai-table uc-table"><table><thead><tr><th>ID</th><th>Use case / department</th><th>Application / vendor</th><th>Status / category</th><th>Required blank</th><th>Auto-flag</th><th>Risk tier / next review</th><th>Updated</th></tr></thead><tbody data-uc-results></tbody></table></div>'
      +'<p class="sai-count">Data as of '+E(day(data.received_at))+'. Export fills the InfoSec / Legal workbook template with every saved use case.</p></div>';
    results();
  }
  function dialog(cls,html){
    const d=document.createElement('dialog');d.className='sai sai-dialog uc-dialog '+cls;d.innerHTML=html;document.body.appendChild(d);dialogs.add(d);
    d.addEventListener('close',()=>{dialogs.delete(d);d.remove();});
    d.addEventListener('click',e=>{if(e.target.closest('[data-uc-close]'))d.close();});
    d.showModal();return d;
  }
  function form(rec){
    const edit=!!data.can_edit,p=rec?rec.profile:{},sections=[...new Set(data.fields.map(f=>f.section))];
    const apps=data.apps.slice();if(rec&&!apps.some(a=>a.id===rec.catalog_id))apps.unshift({id:rec.catalog_id,app_name:(rec.app_name||'Application '+rec.catalog_id)+' (retired)',prefill:{}});
    const input=f=>{const v=p[f.key]||'';
      const x=f.allowed?'<select name="'+f.key+'"><option value="">Not recorded</option>'+f.allowed.map(a=>'<option'+(a===v?' selected':'')+'>'+E(a)+'</option>').join('')+'</select>'
        :f.kind==='long'?'<textarea name="'+f.key+'" maxlength="4000">'+E(v)+'</textarea>'
        :'<input name="'+f.key+'" type="'+(f.kind==='date'?'date':'text')+'" maxlength="255" value="'+E(v)+'"'+(f.key==='name'?' required':'')+'>';
      return '<label data-ai-help-field="'+E(f.key)+'" class="'+(f.kind==='long'?'sai-full':'')+'"><span>'+E(f.label)+(f.required?' *':'')+'</span>'+x+'<small data-uc-hint="'+E(f.key)+'"></small></label>';};
    const c=rec?rec.calc:null;
    const d=dialog('uc-form','<form><header class="sai-head"><div><p class="sai-eyebrow">AI USE CASE'+(rec?' · '+E(rec.ref):'')+'</p><h2>'+E(rec?p.name:'New use case')+'</h2><p>'+(rec?'Revision '+rec.revision+' · updated '+E(day(rec.updated_at))+' by '+E(rec.updated_by):'Fields marked * are required by the workbook; they may be saved blank and are counted until answered.')+'</p></div><button type="button" data-uc-close aria-label="Close use case">×</button></header>'
      +(rec?'<section class="sai-calculated" aria-label="Workbook calculations"><h3>Workbook calculations</h3><p>The workbook formulas, from the saved answers. They update when you save.</p><dl><div><dt>Required fields still blank</dt><dd>'+E(c.required_blank)+'</dd></div><div><dt>Auto-flag: high-risk trigger present</dt><dd>'+(c.auto_flag===HIGH?badge(HIGH,'warn'):'-')+'</dd></div><div><dt>Next review due</dt><dd>'+E(c.next_review||'Set a risk tier and review date')+(overdue(rec)?' · Overdue':'')+'</dd></div><div><dt>Application</dt><dd>'+E(rec.app_name||'Application '+rec.catalog_id)+'</dd></div></dl></section>':'')
      +'<fieldset'+(edit?'':' disabled')+'><section><h3>Catalog application</h3><div class="uc-app"><label><span>Application this use case belongs to *</span><select data-uc-app required><option value="">Choose application</option>'+apps.map(a=>'<option value="'+a.id+'"'+(rec&&a.id===rec.catalog_id?' selected':'')+'>'+E(a.app_name)+'</option>').join('')+'</select></label>'+(edit?'<button type="button" data-uc-fill>Fill blanks from app</button>':'')+'</div>'
      +(edit?'<p class="uc-fill-note" data-uc-fill-note>Fills only empty fields from the app\'s catalog record, corporate account and app assessment. Review them before saving. '+E(NO_FILL)+'</p>':'')+'</section>'
      +sections.map(s=>'<section><h3>'+E(s)+'</h3><div class="sai-fields">'+data.fields.filter(f=>f.section===s).map(input).join('')+'</div></section>').join('')+'</fieldset>'
      +'<p role="alert" data-uc-error hidden></p><footer><span>Saving records the use case only. It does not approve the application or change its assessment.</span><button type="button" data-uc-close>'+(edit?'Cancel':'Close')+'</button>'+(edit?'<button type="submit" class="sai-primary">'+(rec?'Save use case':'Add use case')+'</button>':'')+'</footer></form>');
    const f=d.querySelector('form'),pick=d.querySelector('[data-uc-app]');
    d.querySelector('[data-uc-fill]')?.addEventListener('click',()=>{
      const note=d.querySelector('[data-uc-fill-note]'),a=apps.find(x=>String(x.id)===pick.value);
      if(!a){note.textContent='Choose the application first.';pick.focus();return;}
      const filled=[];
      for(const [k,v] of Object.entries(a.prefill||{})){const x=f.elements[k];if(!x||String(x.value).trim())continue;x.value=v;if(x.value!==v)continue;filled.push(field(k).label);const h=d.querySelector('[data-uc-hint="'+k+'"]');h.textContent='Filled from '+a.app_name+'. Review before saving.';h.classList.add('uc-filled');}
      note.textContent=filled.length?'Filled '+filled.length+' blank field'+(filled.length===1?'':'s')+' from '+a.app_name+': '+filled.join(', ')+'. Nothing is saved until you save the use case. '+NO_FILL:a.app_name+' has no recorded answers for the fields that are still blank. '+NO_FILL;
    });
    f.addEventListener('input',e=>{const h=e.target.name&&d.querySelector('[data-uc-hint="'+e.target.name+'"].uc-filled');if(h){h.textContent='Filled from app, then edited.';}});
    f.onsubmit=async e=>{
      e.preventDefault();if(!edit)return;
      const submit=f.querySelector('[type=submit]'),err=d.querySelector('[data-uc-error]'),fd=new FormData(f),profile={};
      for(const x of data.fields)profile[x.key]=String(fd.get(x.key)||'');
      submit.disabled=true;err.hidden=true;
      try{
        const body=JSON.stringify({catalog_id:Number(pick.value)||null,profile,...(rec?{revision:rec.revision}:{})});
        const r=await track(request(rec?'/'+rec.id:'',{method:rec?'PATCH':'POST',body}));
        d.close();toast((rec?'Saved ':'Added ')+(rec?rec.ref:r.ref)+'.');await load();
      }catch(x){err.textContent=x.message;err.hidden=false;}finally{submit.disabled=false;}
    };
  }
  async function chooseFile(file){
    if(!file)return;
    if(!/\.xlsx$/i.test(file.name))return toast('Choose the returned .xlsx workbook.');
    if(file.size>data.max_upload_bytes)return toast('The file is larger than '+Math.round(data.max_upload_bytes/1024)+' KB.');
    const d=dialog('uc-import','<header class="sai-head"><div><p class="sai-eyebrow">IMPORT WORKBOOK</p><h2>'+E(file.name)+'</h2><p data-uc-summary>Reading the Inventory sheet. Nothing is saved yet.</p></div><button type="button" data-uc-close aria-label="Close import">×</button></header><div data-uc-body><p role="status">Checking the workbook…</p></div>');
    try{
      const data_base64=b64(await file.arrayBuffer());
      const p=await track(request('/import-preview',{method:'POST',body:JSON.stringify({file_name:file.name,data_base64})},60000));
      if(d.open)preview(d,p,file.name,data_base64);
    }catch(e){if(d.open){d.querySelector('[data-uc-summary]').textContent='The workbook was not read. Nothing was saved.';d.querySelector('[data-uc-body]').innerHTML='<p role="alert">'+E(e.message)+'</p><footer><button type="button" data-uc-close>Close</button></footer>';}}
  }
  function preview(d,p,name,data_base64){
    const c=p.counts,byRow=new Map(p.rows.map(r=>[r.row,r])),known=new Map(data.rows.map(r=>[r.catalog_id,r.app_name]));
    d.querySelector('[data-uc-summary]').textContent=c.rows+' use-case row'+(c.rows===1?'':'s')+' on sheet "'+p.sheet+'" · '+c.importable+' can be imported · '+c.problems+' with problems · '+c.skipped+' skipped. Nothing is saved yet.';
    const appSelect=r=>{const list=p.apps.slice();if(r.catalog_id&&!list.some(a=>a.id===r.catalog_id))list.unshift({id:r.catalog_id,app_name:(known.get(r.catalog_id)||'Application '+r.catalog_id)+' (current, retired)'});
      return '<select data-uc-row-app aria-label="Application for row '+r.row+'"'+(r.importable?'':' disabled')+'><option value="">Choose application</option>'+list.map(a=>'<option value="'+a.id+'"'+(a.id===r.catalog_id?' selected':'')+'>'+E(a.app_name)+'</option>').join('')+'</select>'+(r.app_guess?'<small>Matched on vendor or name. Check it.</small>':'');};
    const line=r=>'<tr data-uc-row="'+r.row+'"><td><input type="checkbox" data-uc-pick aria-label="Import row '+r.row+'"'+(r.importable?'':' disabled')+(r.default_selected?' checked':'')+'></td><td>'+r.row+'</td><td>'+(r.action==='update'?'Update '+E(r.ref):'Add new')+'</td>'
      +'<td><strong>'+E(r.values.name||'(no name)')+'</strong><small>'+E([r.values.dept,r.values.vendor].filter(Boolean).join(' · ')||'No department or vendor')+'</small></td><td>'+appSelect(r)+'</td>'
      +'<td>'+r.problems.map(x=>'<span class="uc-problem">'+E(x)+'</span>').join('')+(r.changes.length?'<small>Changes: '+E(r.changes.join(', '))+'</small>':'')+r.notes.map(x=>'<small>'+E(x)+'</small>').join('')+(r.importable&&!r.problems.length&&!r.changes.length&&!r.notes.length?'<small>'+(r.calc.required_blank?r.calc.required_blank+' required fields blank':'All required fields answered')+'</small>':'')+'</td></tr>';
    d.querySelector('[data-uc-body]').innerHTML='<div class="sai-note">Checked rows are saved when you choose Import. Rows with problems cannot be imported: fix them in the workbook and import it again. Duplicates (same name and department), rows without a matched application and unchanged rows start unchecked. Updates replace every workbook field of that use case with the row.</div>'
      +(p.rows.length?'<div class="sai-table"><table><thead><tr><th><input type="checkbox" data-uc-all aria-label="Select all importable rows"></th><th>Row</th><th>Action</th><th>Use case</th><th>Application</th><th>Review</th></tr></thead><tbody>'+p.rows.map(line).join('')+'</tbody></table></div>':'<div class="empty"><strong>No use-case rows found from row 6 down.</strong></div>')
      +(p.skipped.length?'<details class="uc-skipped"><summary>'+p.skipped.length+' row'+(p.skipped.length===1?'':'s')+' skipped</summary><ul>'+p.skipped.map(s=>'<li>Row '+E(s.row)+': '+E(s.reason)+'</li>').join('')+'</ul></details>':'')
      +'<p role="alert" data-uc-error hidden></p><footer><span data-uc-picked></span><button type="button" data-uc-close>Cancel</button><button type="button" class="sai-primary" data-uc-go>Import</button></footer>';
    const go=d.querySelector('[data-uc-go]'),err=d.querySelector('[data-uc-error]');
    const picked=()=>[...d.querySelectorAll('tr[data-uc-row]')].filter(tr=>tr.querySelector('[data-uc-pick]').checked);
    const update=()=>{const list=picked(),missing=list.find(tr=>!tr.querySelector('[data-uc-row-app]').value);
      d.querySelector('[data-uc-picked]').textContent=missing?'Row '+missing.dataset.ucRow+' needs an application.':list.length+' row'+(list.length===1?'':'s')+' selected.';
      go.disabled=!list.length||!!missing;go.textContent='Import '+list.length+' row'+(list.length===1?'':'s');
      const all=d.querySelector('[data-uc-all]');if(all){const open=[...d.querySelectorAll('[data-uc-pick]:not(:disabled)')];all.checked=open.length>0&&open.every(x=>x.checked);all.disabled=!open.length;}};
    d.addEventListener('change',e=>{if(e.target.matches('[data-uc-all]'))d.querySelectorAll('[data-uc-pick]:not(:disabled)').forEach(x=>{x.checked=e.target.checked;});update();});
    go.onclick=async()=>{
      const rows=picked().map(tr=>{const r=byRow.get(Number(tr.dataset.ucRow));return {row:r.row,catalog_id:Number(tr.querySelector('[data-uc-row-app]').value),use_case_id:r.use_case_id,revision:r.revision};});
      go.disabled=true;err.hidden=true;
      try{const res=await track(request('/import',{method:'POST',body:JSON.stringify({file_name:name,data_base64,rows})},60000));d.close();toast('Imported '+name+': '+res.added.length+' added, '+res.updated.length+' updated.');await load();}
      catch(x){err.textContent=x.message;err.hidden=false;update();}
    };
    update();
  }
  async function exportFile(b){
    b.disabled=true;const ctrl=new AbortController(),timer=setTimeout(()=>ctrl.abort(),60000);
    try{
      const r=await track(fetch(API+'/export',{credentials:'same-origin',signal:ctrl.signal}));
      if(!r.ok){let m='Export failed';if(r.status===503)m='Use-case records are not available on this server yet.';else try{m=(await r.json()).error||m;}catch{}throw new Error(m);}
      const blob=await r.blob(),name=(/filename="([^"]+)"/.exec(r.headers.get('Content-Disposition')||'')||[])[1]||'AI_ML_Use_Inventory.xlsx';
      const u=URL.createObjectURL(blob),a=document.createElement('a');a.href=u;a.download=name;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(u),1000);
      toast('Downloaded '+name+'.');
    }catch(e){toast(e.name==='AbortError'?'Export timed out. Try again.':e.message);}
    finally{clearTimeout(timer);b.disabled=false;}
  }
  el.addEventListener('click',e=>{
    const b=e.target.closest('[data-uc-open],[data-uc-add],[data-uc-import],[data-uc-export],[data-uc-refresh]');if(!b||!data&&!b.hasAttribute('data-uc-refresh'))return;
    if(b.hasAttribute('data-uc-open')){const r=data.rows.find(x=>x.id===Number(b.dataset.ucOpen));if(r)form(r);}
    else if(b.hasAttribute('data-uc-add'))form(null);
    else if(b.hasAttribute('data-uc-import'))el.querySelector('[data-uc-file]').click();
    else if(b.hasAttribute('data-uc-export'))exportFile(b);
    else{b.disabled=true;load();}
  },{signal:listeners.signal});
  el.addEventListener('input',e=>{if(e.target.matches('[data-uc-search]')){q=e.target.value;results();}},{signal:listeners.signal});
  el.addEventListener('change',e=>{
    if(e.target.matches('[data-uc-filter]')){const v=e.target.value,k=e.target.dataset.ucFilter;if(k==='app')app=v;else if(k==='status')status=v;else flag=v;results();}
    else if(e.target.matches('[data-uc-file]')){const file=e.target.files[0];e.target.value='';chooseFile(file);}
  },{signal:listeners.signal});
  render();load();
  return {
    destroy(){alive=false;listeners.abort();for(const d of [...dialogs])d.close();el.replaceChildren();},
    busy(){return dialogs.size>0||inflight>0;}
  };
}
root.AIGovernanceUseCases={mount};
})(window);
