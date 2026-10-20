(function(root,factory){
  var api=factory();
  if(typeof module==='object'&&module.exports)module.exports=api;
  else {root.HKWorkbench=api;api.init(root);}
})(typeof window==='object'?window:this,function(){
  'use strict';
  var win,doc,mode='accounts',selectedView='',detailKey='',lists={audit:null,recovery:null};
  var recoveryPage={page:1,size:25,key:''};
  var labels={stale:'Stale user',disabled:'Disabled',expired:'Expired',pwdstale:'Stale password',nogroup:'No groups',privileged:'Privileged risk'};
  var ranks={high:0,medium:1,low:2};
  var storageKey='ad-housekeeping-views-v1';
  function key(row){return String(row.dn||row.sam||'').toLowerCase();}
  function groupRows(rows){
    var groups=new Map();
    rows.forEach(function(row,index){
      var id=key(row)||'missing-identity-'+index,group=groups.get(id);
      if(!group){group={base:row,findings:[],seen:new Set()};groups.set(id,group);}
      var finding=String(row._cat)+'\u0000'+String(row.reason||'');
      if(!group.seen.has(finding)){group.seen.add(finding);group.findings.push(row);}
      if((ranks[row.risk]??9)<(ranks[group.base.risk]??9))group.base=row;
    });
    return Array.from(groups.values()).map(function(g){return Object.assign({},g.base,{_findings:g.findings});});
  }
  function userRows(rows){return mode==='accounts'?groupRows(rows):rows;}
  function node(tag,cls,text){var e=doc.createElement(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;return e;}
  function button(text,fn,cls){var b=node('button','btn btn-ghost btn-sm '+(cls||''),text);b.type='button';b.addEventListener('click',fn);return b;}
  function fieldValue(id){return doc.getElementById(id).value;}
  function render(){win.findingViews.users.page=1;win.renderUsers();}
  function setMode(next){mode=next==='findings'?'findings':'accounts';render();}
  function state(){return {scope:win.activeScope,mode:mode,category:fieldValue('userCatFilter'),risk:fieldValue('userRiskFilter'),query:fieldValue('userSearchFilter'),sort:fieldValue('usersSort'),size:win.findingViews.users.size};}
  function cleanState(s){
    if(!s||typeof s!=='object')return null;
    var pick=function(v,allowed,fallback){return allowed.indexOf(v)>=0?v:fallback;};
    return {scope:pick(s.scope,['users','service-shared','other'],'users'),mode:pick(s.mode,['accounts','findings'],'accounts'),category:pick(s.category,['all','stale','disabled','expired','pwdstale','nogroup','privileged'],'all'),risk:pick(s.risk,['all','high','medium','low'],'all'),query:typeof s.query==='string'?s.query.slice(0,240):'',sort:pick(s.sort,['risk','name','oldest'],'risk'),size:[25,50,100].indexOf(Number(s.size))>=0?Number(s.size):25};
  }
  function apply(s){
    s=cleanState(s);if(!s)return;
    win.setScope(s.scope);mode=s.mode;
    ['userCatFilter','userRiskFilter','userSearchFilter','usersSort'].forEach(function(id,i){doc.getElementById(id).value=[s.category,s.risk,s.query,s.sort][i];});
    win.findingViews.users.size=s.size;
    var size=doc.getElementById('usersPageSize');if(size)size.value=String(s.size);
    if(win.lastScanMeta.loaded)render();else sync();
  }
  function readViews(){
    try{
      var raw=JSON.parse(win.localStorage.getItem(storageKey)||'[]');
      return Array.isArray(raw)?raw.slice(0,15).filter(function(v){return v&&typeof v.name==='string'&&cleanState(v.state);}).map(function(v){return {name:v.name.slice(0,60),state:cleanState(v.state)};}):[];
    }catch(_){return [];}
  }
  function saveViews(views){try{win.localStorage.setItem(storageKey,JSON.stringify(views));return true;}catch(_){win.showToast('This browser could not save the view. Use Copy view link instead.','error');return false;}}
  function paintViews(){
    var select=doc.getElementById('hkSavedViews');select.replaceChildren(new Option('Choose a saved view',''));
    readViews().forEach(function(v,i){select.add(new Option(v.name,String(i)));});
    select.value=selectedView;doc.getElementById('hkDeleteView').disabled=selectedView==='';
  }
  async function copy(text,message){
    try{await win.navigator.clipboard.writeText(text);win.showToast(message||'Copied','success');}
    catch(_){win.showToast('Copy is unavailable in this browser. Select and copy the value from details.','error');}
  }
  function saveView(){
    var input=doc.getElementById('hkViewName'),name=input.value.trim().slice(0,60);
    if(!name){input.focus();win.showToast('Give this view a name first.','info');return;}
    var views=readViews(),existing=views.findIndex(function(v){return v.name.toLowerCase()===name.toLowerCase();});
    if(existing<0&&views.length>=15){win.showToast('Remove a saved view before adding another (15 maximum).','info');return;}
    var entry={name:name,state:state()};if(existing<0){views.push(entry);existing=views.length-1;}else views[existing]=entry;
    if(saveViews(views)){selectedView=String(existing);paintViews();input.value='';win.showToast('View saved in this browser','success');}
  }
  function sync(){
    if(!doc)return;
    doc.querySelectorAll('[data-hk-mode]').forEach(function(b){var on=b.dataset.hkMode===mode;b.classList.toggle('on',on);b.setAttribute('aria-pressed',String(on));});
    doc.getElementById('hkModeHelp').textContent=mode==='accounts'?'One row per account; risk reflects matching findings.':'One row per finding; an account can appear more than once.';
    doc.getElementById('hkUserCategoryHead').textContent=mode==='accounts'?'Matching findings':'Category';
    doc.getElementById('hkUserReasonHead').textContent=mode==='accounts'?'Why review':'Reason';
    doc.getElementById('btnExportUsers').title=mode==='accounts'?'Export all matching accounts, across pages':'Export all matching findings, across pages';
    var chips=doc.getElementById('hkActiveFilters');chips.replaceChildren();
    [['userCatFilter','Category'],['userRiskFilter','Risk'],['userSearchFilter','Search']].forEach(function(pair){
      var el=doc.getElementById(pair[0]),value=el.value;if(!value||value==='all')return;
      var text=el.tagName==='SELECT'?el.options[el.selectedIndex].text:value;
      var b=button(pair[1]+': '+text+' ×',function(){
        var index=Array.from(chips.children).indexOf(b);
        el.value=el.tagName==='SELECT'?'all':'';render();
        var remaining=chips.querySelectorAll('button');
        (remaining[Math.min(index,remaining.length-1)]||el).focus();
      },'hk-filter-chip');
      b.setAttribute('aria-label','Remove '+pair[1].toLowerCase()+' filter: '+text);chips.appendChild(b);
    });
    chips.hidden=!chips.children.length;
    var scopes=doc.getElementById('hkPrivScopes');scopes.replaceChildren();
    scopes.hidden=fieldValue('userCatFilter')!=='privileged'||!win.scopeCounts;
    if(!scopes.hidden){
      scopes.appendChild(node('span','','Privileged findings by scope:'));
      [['users','Users'],['service-shared','Service & shared'],['other','Other']].forEach(function(pair){
        var count=win.scopeCounts[pair[0]].priv;
        var jump=button(pair[1]+' ('+count+')',function(){win.setScope(pair[0]);doc.getElementById('userCatFilter').value='privileged';render();var current=doc.querySelector('[data-hk-priv-scope="'+pair[0]+'"]');if(current)current.focus();});
        jump.dataset.hkPrivScope=pair[0];jump.disabled=!count;jump.setAttribute('aria-pressed',String(win.activeScope===pair[0]));scopes.appendChild(jump);
      });
    }

    doc.getElementById('hkUserScopeNote').textContent=win.activeScope==='service-shared'?'Service and shared accounts are informational here. Directory actions remain hidden.':'Review the evidence and account owner before making directory changes.';
  }
  function categories(row){return (row._findings||[row]).map(function(f){return '<span class="hk-category">'+win.esc(labels[f._cat]||f._cat)+'</span>';}).join('');}
  function reasons(row){var findings=row._findings||[row];return findings.map(function(f){return f.reason||labels[f._cat]||f._cat;}).join('\n');}
  function enrichDetails(item){
    var content=doc.getElementById('detailContent'),heading=content.querySelector('h3');
    heading.id='hkDetailTitle';content.setAttribute('aria-labelledby','hkDetailTitle');
    detailKey=key(item);
    var all=groupRows(win.allUserItems.filter(function(i){return key(i)===detailKey;}))[0];
    var findings=all?all._findings:[item];
    var toolbar=node('div','hk-detail-tools');
    toolbar.appendChild(button('Copy username',function(){copy(item.sam,'Username copied');}));
    if(item.dn)toolbar.appendChild(button('Copy DN',function(){copy(item.dn,'Distinguished name copied');}));
    var link=node('a','btn btn-ghost btn-sm','Identity diagnostics');link.href='/identity-diag.html?q='+encodeURIComponent(item.mail||item.sam);toolbar.appendChild(link);
    var review=groupRows(win.filteredFindings('users')),index=review.findIndex(function(i){return key(i)===detailKey;});
    var move=function(step){var target=review[index+step];if(target){win.showUserDetail(target.sam,target._cat);content.focus();}};
    var previous=button('Previous account',function(){move(-1);}),next=button('Next account',function(){move(1);});
    previous.disabled=index<=0;next.disabled=index<0||index>=review.length-1;
    toolbar.append(previous,next);heading.after(toolbar);
    var section=node('section','hk-related-findings');section.appendChild(node('h4','',findings.length+' finding'+(findings.length===1?'':'s')+' for this account'));
    var list=node('ul');findings.forEach(function(f){var li=node('li');li.appendChild(node('strong','',labels[f._cat]||f._cat));li.appendChild(node('span','',f.reason||'No additional explanation supplied.'));list.appendChild(li);});section.appendChild(list);toolbar.after(section);
    var originalFields=Array.from(content.querySelectorAll('.modal-field'));
    var findField=function(label){return originalFields.find(function(f){return f.querySelector('.label')?.textContent===label;});};
    var selectedReason=findField('Why Flagged');if(selectedReason)selectedReason.remove();
    if(item.mail){var mail=node('div','modal-field');mail.appendChild(node('div','label','Email'));mail.appendChild(node('div','value',item.mail));(findField('Username')||section).after(mail);}
    if(item.dn){var dn=node('div','modal-field');dn.appendChild(node('div','label','Distinguished name'));dn.appendChild(node('div','value',item.dn));(findField('OU Path')||section).after(dn);}
  }
  function objectDetail(kind,name){
    var source=win.findingSource(kind),item=source.find(function(i){return i.name===name;});if(!item)return;
    var content=doc.getElementById('detailContent');content.replaceChildren();content.setAttribute('aria-labelledby','hkDetailTitle');
    content.appendChild(node('h3','',item.name));content.firstChild.id='hkDetailTitle';
    var fields=kind==='groups'?[['Type','Empty group'],['Description',item.description],['Members','0 in the loaded scan'],['Last changed',win.fmtDate(win.adTimeToIso(item.whenChanged))],['OU',item.ou],['Distinguished name',item.dn]]:[['Type','Stale computer'],['Risk',item.risk],['Operating system',item.os],['Last logon',win.fmtDate(item.lastLogon)],['Days since logon',item.lastLogonDays],['OU',item.ou],['Distinguished name',item.dn]];
    fields.forEach(function(pair){var field=node('div','modal-field');field.appendChild(node('div','label',pair[0]));field.appendChild(node('div','value',pair[1]===undefined||pair[1]===null||pair[1]===''?'—':String(pair[1])));content.appendChild(field);});
    var actions=node('div','modal-actions');actions.appendChild(button('Copy name',function(){copy(item.name,'Name copied');}));if(item.dn)actions.appendChild(button('Copy DN',function(){copy(item.dn,'Distinguished name copied');}));actions.appendChild(button('Close',win.closeModal));content.appendChild(actions);doc.getElementById('detailModal').classList.add('visible');
  }
  function listStart(kind){if(!doc)return;if(kind==='recovery')recoveryBusy('Loading…');lists[kind]=null;doc.getElementById('hk'+kind+'Export').disabled=true;doc.getElementById('hk'+kind+'Results').textContent='Loading…';}
  function readError(label,status,data){if(label==='Recycle Bin'&&data&&data.source==='ldap'&&typeof data.error==='string')return data.error;return data&&typeof data.error==='string'&&data.error.indexOf('DEV-EGRESS-GUARD')>=0?label+' lookup is unavailable on DEV. The server blocks the required directory connection.':label+' request returned HTTP '+status;}
  function listFailed(kind,message){if(!doc)return;if(kind==='recovery')recoveryBusy('Lookup unavailable');lists[kind]=null;doc.getElementById('hk'+kind+'Export').disabled=true;doc.getElementById('hk'+kind+'Results').textContent='Could not load records: '+message;}
  function listLoaded(kind,items,metadata){if(!doc)return;if(kind==='recovery'){recoveryPage.page=1;recoveryPage.key='';}lists[kind]={items:items,metadata:metadata||{},rows:Array.from(doc.querySelectorAll('#'+(kind==='audit'?'auditBody':'recycleBody')+' > tr')),filtered:[]};var select=doc.getElementById('hk'+kind+'Type'),selected=select.value;select.replaceChildren(new Option('All '+(kind==='audit'?'actions':'types'),'all'));Array.from(new Set(items.map(function(i){return String(kind==='audit'?i.action_type:i.objectClass);}))).sort().forEach(function(type){select.add(new Option(type,type));});select.value=Array.from(select.options).some(function(o){return o.value===selected;})?selected:'all';filterList(kind);}
  function matchesList(kind,item,query,type,status){var values=kind==='audit'?[item.created_at,item.action_type,item.object_type,item.object_name,item.performed_by,item.notes]:[item.name,item.objectClass,item.lastKnownParent,item.whenChanged,item.dn];return (!query||values.join(' ').toLowerCase().includes(query))&&(type==='all'||String(kind==='audit'?item.action_type:item.objectClass)===type)&&(kind!=='audit'||status==='all'||(status==='reverted'?!!item.reverted:!item.reverted));}
  function filterList(kind){
    var data=lists[kind];if(!data)return;
    if(kind==='recovery'){filterRecovery(data);return;}
    var query=fieldValue('hk'+kind+'Search').trim().toLowerCase(),type=fieldValue('hk'+kind+'Type'),status=kind==='audit'?fieldValue('hkauditStatus'):'all';
    data.filtered=[];data.items.forEach(function(item,i){var match=matchesList(kind,item,query,type,status);if(data.rows[i])data.rows[i].hidden=!match;if(match)data.filtered.push(item);});
    doc.getElementById('hk'+kind+'Results').textContent=data.filtered.length+' of '+data.items.length+' loaded '+(kind==='audit'?'audit entries':'deleted objects')+(kind==='recovery'&&data.metadata.truncated?' · Lookup limit: '+data.metadata.limit+' objects; filters apply to loaded results.':'');doc.getElementById('hk'+kind+'Export').disabled=!data.filtered.length;
    var body=doc.getElementById(kind==='audit'?'auditBody':'recycleBody'),empty=doc.getElementById('hk'+kind+'Empty');if(empty)empty.remove();
    if(data.items.length&&!data.filtered.length){var tr=node('tr');tr.id='hk'+kind+'Empty';var td=node('td','empty-msg','No records match these filters. Use Reset to see all loaded records.');td.colSpan=kind==='audit'?8:5;tr.appendChild(td);body.appendChild(tr);}
  }
  function recoverySlice(rows,page,size){
    size=[25,50,100].indexOf(Number(size))>=0?Number(size):25;
    var pages=Math.max(1,Math.ceil(rows.length/size));
    page=Math.min(pages,Math.max(1,Math.floor(Number(page))||1));
    var start=(page-1)*size,end=Math.min(start+size,rows.length);
    return {items:rows.slice(start,end),page:page,pages:pages,start:rows.length?start+1:0,end:end,total:rows.length,size:size};
  }
  function recoveryBusy(message){
    ['First','Prev','Next','Last'].forEach(function(name){var b=doc.getElementById('hkrecovery'+name);if(b)b.disabled=true;});
    var size=doc.getElementById('hkrecoveryPageSize');if(size)size.disabled=true;
    var label=doc.getElementById('hkrecoveryPageLabel');if(label)label.textContent=message;
  }
  function filterRecovery(data){
    var query=fieldValue('hkrecoverySearch').trim().toLowerCase(),type=fieldValue('hkrecoveryType'),key=query+'\u0000'+type;
    if(key!==recoveryPage.key){recoveryPage.page=1;recoveryPage.key=key;}
    data.filtered=data.items.filter(function(item){return matchesList('recovery',item,query,type,'all');});
    var page=recoverySlice(data.filtered,recoveryPage.page,recoveryPage.size);recoveryPage.page=page.page;
    var body=doc.getElementById('recycleBody');
    body.innerHTML=page.items.map(function(i){return '<tr><td>'+win.esc(i.name)+'</td><td>'+win.esc(i.objectClass)+'</td><td class="cell-truncate cell-mono" title="'+win.esc(i.lastKnownParent)+'">'+win.esc(i.lastKnownParent)+'</td><td class="cell-mono">'+win.fmtDate(i.whenChanged)+'</td><td><button class="btn btn-green btn-sm" data-rbac-page="ad-housekeeping" data-rbac-level="admin" onclick="restoreObject('+win.jsArg(i.dn)+','+win.jsArg(i.name)+')">Restore</button></td></tr>';}).join('');
    if(!page.items.length){var tr=node('tr');tr.id='hkrecoveryEmpty';var td=node('td','empty-msg',data.items.length?'No records match these filters. Use Reset to see all results.':'No deleted objects are visible to the current directory account.');td.colSpan=5;tr.appendChild(td);body.appendChild(tr);}
    doc.getElementById('hkrecoveryResults').textContent=page.total+' matching deleted object'+(page.total===1?'':'s')+' · '+data.items.length+' total in lookup'+(page.total?' · '+page.start+'–'+page.end+' shown':'')+' · Search covers the full lookup.';
    var exp=doc.getElementById('hkrecoveryExport');exp.disabled=!page.total;exp.title='Export all matching objects across every page';
    var size=doc.getElementById('hkrecoveryPageSize');size.disabled=false;size.value=String(page.size);
    doc.getElementById('hkrecoveryPageLabel').textContent='Page '+page.page+' of '+page.pages;
    ['First','Prev'].forEach(function(name){doc.getElementById('hkrecovery'+name).disabled=page.page===1;});
    ['Next','Last'].forEach(function(name){doc.getElementById('hkrecovery'+name).disabled=page.page===page.pages;});
  }
  function initRecoveryPager(pane){
    var pager=node('div','ad-pager');pager.id='hkrecoveryPager';
    var label=node('label','','Rows per page '),size=node('select','filter-input');size.id='hkrecoveryPageSize';size.setAttribute('aria-label','Recovery rows per page');[25,50,100].forEach(function(n){size.add(new Option(String(n),String(n)));});size.disabled=true;size.addEventListener('change',function(){recoveryPage.size=Number(size.value);recoveryPage.page=1;filterList('recovery');});label.appendChild(size);pager.appendChild(label);
    var status=node('span','','Load the Recycle Bin to browse results.');status.id='hkrecoveryPageLabel';pager.appendChild(status);
    var actions=node('div','ad-page-buttons');[['First','First'],['Prev','Previous'],['Next','Next'],['Last','Last']].forEach(function(pair){var b=button(pair[1],function(){var data=lists.recovery;if(!data)return;var pages=Math.max(1,Math.ceil(data.filtered.length/recoveryPage.size));recoveryPage.page=pair[0]==='First'?1:pair[0]==='Last'?pages:recoveryPage.page+(pair[0]==='Next'?1:-1);filterList('recovery');pane.querySelector('.tbl-wrap').scrollTop=0;});b.id='hkrecovery'+pair[0];b.setAttribute('aria-label',pair[1]+' Recovery page');b.disabled=true;actions.appendChild(b);});pager.appendChild(actions);pane.appendChild(pager);
  }
  function exportList(kind){var data=lists[kind];if(!data||!data.filtered.length)return;var headers=kind==='audit'?['Time','Action','Object type','Object','Performed by','Notes','Reverted']:['Name','Type','Deleted from','When','DN'];var rows=data.filtered.map(function(i){return kind==='audit'?[i.created_at,i.action_type,i.object_type,i.object_name,i.performed_by,i.notes,i.reverted?'Yes':'No']:[i.name,i.objectClass,i.lastKnownParent,i.whenChanged,i.dn];});var blob=new win.Blob(['\ufeff'+[headers].concat(rows).map(function(row){return row.map(win.csvFindingCell).join(',');}).join('\r\n')],{type:'text/csv;charset=utf-8'});var url=win.URL.createObjectURL(blob),a=node('a');a.href=url;a.download='ad-housekeeping-'+kind+'-'+new Date().toISOString().slice(0,10)+'.csv';doc.body.appendChild(a);a.click();a.remove();win.setTimeout(function(){win.URL.revokeObjectURL(url);},1000);win.showToast('Exported '+data.filtered.length+(kind==='recovery'?' matching records':' loaded records'),'success');}
  function initLists(kind){
    var pane=doc.getElementById('pane-'+(kind==='audit'?'audit':'recovery')),bar=pane.querySelector('.filter-row');
    var search=node('input','filter-input');search.id='hk'+kind+'Search';search.placeholder=kind==='audit'?'Search object, operator, action or notes…':'Search all deleted objects, original OU or DN…';search.setAttribute('aria-label',kind==='audit'?'Search audit log':'Search deleted objects');search.addEventListener('input',function(){filterList(kind);});bar.appendChild(search);
    var types=node('select','filter-input');types.id='hk'+kind+'Type';types.setAttribute('aria-label',kind==='audit'?'Filter audit action':'Filter deleted object type');types.add(new Option('All '+(kind==='audit'?'actions':'types'),'all'));types.addEventListener('change',function(){filterList(kind);});bar.appendChild(types);
    if(kind==='audit'){var status=node('select','filter-input');status.id='hkauditStatus';status.setAttribute('aria-label','Filter audit revert status');[['All revert states','all'],['Not reverted','current'],['Reverted','reverted']].forEach(function(o){status.add(new Option(o[0],o[1]));});status.addEventListener('change',function(){filterList(kind);});bar.appendChild(status);}
    bar.appendChild(button('Reset',function(){search.value='';types.value='all';if(kind==='audit')doc.getElementById('hkauditStatus').value='all';else recoveryPage.page=1;filterList(kind);}));var exp=button(kind==='recovery'?'Export all matches CSV':'Export loaded CSV',function(){exportList(kind);});exp.id='hk'+kind+'Export';exp.disabled=true;bar.appendChild(exp);
    var result=node('div','ad-results',kind==='audit'?'Open this tab to load audit history.':'Load the Recycle Bin to search and export its results.');result.id='hk'+kind+'Results';result.setAttribute('role','status');result.setAttribute('aria-live','polite');bar.after(result);if(kind==='recovery')initRecoveryPager(pane);
  }
  function init(w){
    win=w;doc=w.document;
    var ready=function(){
      var bar=doc.getElementById('hkWorkbench');
      bar.innerHTML='<div class="hk-mode-switch" role="group" aria-label="User result layout"><button type="button" class="btn btn-ghost btn-sm" data-hk-mode="accounts">Accounts</button><button type="button" class="btn btn-ghost btn-sm" data-hk-mode="findings">Findings</button></div><span id="hkModeHelp"></span><details class="hk-views"><summary>Views &amp; sharing</summary><div class="hk-view-panel"><label for="hkSavedViews">Personal saved views</label><select class="filter-input" id="hkSavedViews"></select><div class="hk-view-save"><input class="filter-input" id="hkViewName" maxlength="60" placeholder="Name this view" aria-label="Name this view"><button type="button" class="btn btn-ghost btn-sm" id="hkSaveView">Save view</button></div><div class="hk-view-actions"><button type="button" class="btn btn-ghost btn-sm" id="hkCopyView">Copy view link</button><button type="button" class="btn btn-ghost btn-sm" id="hkDeleteView">Remove saved view</button></div><p>Saved in this browser. Links include the current filters.</p></div></details>';
      var disclosure=bar.querySelector('details');
      disclosure.addEventListener('keydown',function(e){if(e.key==='Escape'){e.preventDefault();disclosure.open=false;disclosure.querySelector('summary').focus();}});
      doc.addEventListener('pointerdown',function(e){if(disclosure.open&&!disclosure.contains(e.target))disclosure.open=false;});
      disclosure.addEventListener('focusout',function(e){if(e.relatedTarget&&!disclosure.contains(e.relatedTarget))disclosure.open=false;});
      doc.querySelectorAll('[data-hk-mode]').forEach(function(b){b.addEventListener('click',function(){setMode(b.dataset.hkMode);});});
      doc.getElementById('hkSaveView').addEventListener('click',saveView);
      doc.getElementById('hkViewName').addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();saveView();}});
      doc.getElementById('hkSavedViews').addEventListener('change',function(e){selectedView=e.target.value;var view=readViews()[Number(selectedView)];if(selectedView!==''&&view)apply(view.state);doc.getElementById('hkDeleteView').disabled=selectedView==='';});
      doc.getElementById('hkDeleteView').addEventListener('click',function(){if(selectedView==='')return;var views=readViews();views.splice(Number(selectedView),1);if(saveViews(views)){selectedView='';paintViews();win.showToast('Saved view removed from this browser','success');}});
      doc.getElementById('hkCopyView').addEventListener('click',function(){var url=new win.URL(win.location.pathname,win.location.origin);url.searchParams.set('hkView',JSON.stringify(state()));url.hash='housekeeping';copy(url.href,'View link copied');});
      var focus=button('Focus on results',function(){var cards=doc.getElementById('cards'),on=!cards.hidden;cards.hidden=on;focus.setAttribute('aria-pressed',String(on));focus.textContent=on?'Show summary':'Focus on results';},'hk-focus-button');focus.setAttribute('aria-pressed','false');focus.id='hkFocusResults';doc.querySelector('#modeHousekeeping .page-header').appendChild(focus);
      paintViews();initLists('audit');initLists('recovery');
      var raw=new win.URLSearchParams(win.location.search).get('hkView');if(raw&&raw.length<=2500){try{apply(JSON.parse(raw));}catch(_){win.showToast('This view link could not be read. Showing the default queue.','info');}}
      sync();if(win.lastScanMeta.loaded)win.renderUsers();
    };
    if(doc.readyState==='loading')doc.addEventListener('DOMContentLoaded',ready,{once:true});else ready();
  }
  return {recoverySlice:recoverySlice,init:init,userRows:userRows,groupRows:groupRows,key:key,cleanState:cleanState,matchesList:matchesList,readError:readError,isAccountView:function(){return mode==='accounts';},sync:sync,categories:categories,reasons:reasons,enrichDetails:enrichDetails,objectDetail:objectDetail,listStart:listStart,listLoaded:listLoaded,listFailed:listFailed};
});
