/* DEV shared planning UI. Saves only CorpIT register metadata. */
(function () {
  'use strict';
  var STAGES = { assessed:'Assessed', mapping_review:'Mapping review', draft_linked:'Draft linked', pilot:'Pilot', pilot_validated:'Pilot validated', rollout:'Rollout', retirement_review:'GPO retirement review' };
  var TRACKS = { review:'Needs scope review', workstation:'Windows workstations', user:'User settings', domain_server:'Domain / DC / server review', alternative:'Alternative approach' };
  var API = '/hub-api/api/patch-status/migration';
  var KIND_LABEL = { catalog:'Configuration policy / Settings Catalog', configuration:'Device configuration profile' };
  var TARGET_LABEL = { groupAssignmentTarget:'Included group', exclusionGroupAssignmentTarget:'Excluded group', allLicensedUsersAssignmentTarget:'All users', allDevicesAssignmentTarget:'All devices' };
  var GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  window.CorpITMigration = { create: function (ctx) {
    var h=ctx.h, panel=ctx.panel, table=ctx.table, root=null, data=null, error=null, loading=false, edit=null, profiles=null, evidence={}, q='', track='all', tracked='all', detail=null;
    function clear(el) { while(el.firstChild)el.removeChild(el.firstChild); }
    function date(v) { return v ? new Date(v).toLocaleString() : 'Not read'; }
    function note(text,tone) { return h('p',{class:'noc-small'+(tone?' noc-tone-'+tone:''),text:text}); }
    function btn(text,run,cls) { return h('button',{type:'button',class:cls||null,text:text,on:{click:run}}); }
    function link(text,href) { return h('a',{class:'ps-btn',href:href,text:text}); }
    function adLink(guid) { return '/ad-management.html?gpoPlan='+encodeURIComponent(guid)+'#gpo'; }
    function status(text) { return h('p',{role:'status','aria-live':'polite',text:text}); }
    async function request(path,opt) {
      var ctl=new AbortController(),tm=setTimeout(function(){ctl.abort();},90000);
      try { var r=await fetch(path,Object.assign({credentials:'same-origin',headers:{Accept:'application/json'},signal:ctl.signal},opt||{}));var j=await r.json();if(!r.ok || !j.ok)throw new Error(typeof j.error==='string'?j.error:'Migration request failed ('+r.status+')');return j; }
      catch(e) { if(e.name==='AbortError')throw new Error('The read timed out. Retry without changing your plan.');throw e; }
      finally {clearTimeout(tm);}
    }
    function refresh() {
      if(loading)return;loading=true;error=null;draw();
      request(API).then(function(j){data=j;}).catch(function(e){error=e.message;}).finally(function(){loading=false;draw();if(ctx.onState)ctx.onState();});
    }
    function getRecord(guid) { return data && data.records.find(function(r){return r.guid===guid;}); }
    function getGpo(guid) { return data && data.source.gpos.find(function(g){return g.guid===guid;}); }
    function select(guid) { if(edit && !window.confirm('Discard unsaved register edits?'))return;edit=null;ctx.selectGuid(guid);draw(); }
    function sourceName(guid) { return (getGpo(guid)||{}).name || (getRecord(guid)||{}).sourceName || guid; }
    function merged() {
      var guids=data.source.gpos.map(function(g){return g.guid;});
      data.records.forEach(function(r){if(guids.indexOf(r.guid)<0)guids.push(r.guid);});
      return guids.map(function(guid){return {guid:guid,g:getGpo(guid),r:getRecord(guid)};});
    }
    function optionSelect(label,values,value,onChange) {
      var el=h('select',{'aria-label':label,on:{change:function(){onChange(el.value);}}},values.map(function(o){return h('option',{value:o[0],text:o[1],selected:o[0]===value});}));
      return h('label',null,[label,el]);
    }
    function view() {root=h('div',{class:'ps-migration'});draw();if(!data&&!loading&&!error)refresh();return root;}
    function draw() {
      if(!root)return;clear(root);
      root.appendChild(h('div',{class:'ps-toolbar ps-panel-gap'},[btn(loading?'Reading…':'Reload register',refresh),link('AD migration assessment','/ad-management.html#gpo'),note('Shared planning records. Saving here changes CorpIT metadata only. Super-admin access matches AD GPO plans.') ]));
      if(error)root.appendChild(h('div',{class:'noc-note noc-tone-warn',role:'alert',text:error}));
      if(!data){root.appendChild(panel('GPO migration',[status(loading?'Reading the shared register and saved AD snapshot…':'No register data loaded. Retry Reload register.')]));return;}
      var upload=data.source.upload,age=upload?Math.floor((Date.now()-new Date(upload.uploaded_at).getTime())/86400000):null;
      root.appendChild(h('div',{class:'noc-note'+(age>30?' noc-tone-warn':''),text:upload?'AD snapshot #'+upload.id+' · collected '+date(upload.uploaded_at)+(age>30?' · '+age+' days old. Refresh collection from AD before relying on scope for a migration.':''):'No saved AD snapshot. Collect one from the AD assessment before tracking a GPO.'}));
      root.appendChild(h('div',{class:'ps-mg-summary'},[
        h('div',null,[h('strong',{text:String(data.source.gpos.length)}),h('span',{text:'GPOs in saved snapshot'})]),
        h('div',null,[h('strong',{text:String(data.records.length)}),h('span',{text:'Shared migration records'})]),
        h('div',null,[h('strong',{text:String(data.records.filter(function(r){return r.profiles.length;}).length)}),h('span',{text:'Records with profile links'})])
      ]));
      root.appendChild(note('Stages are recorded by reviewers. A linked profile, compliant device or recent check-in does not establish that GPO settings migrated or applied. Domain, DC and server settings need their own scope review.'));
      var chosen=ctx.selectedGuid();
      if(chosen) { drawDetail(chosen); return; }
      var host=h('div'),search=h('input',{type:'search','aria-label':'Search migration register',placeholder:'GPO, owner or notes',value:q,on:{input:function(){q=search.value;ctx.resetTable('migration');rows();}}});
      var filters=h('div',{class:'noc-filter'},[
        h('label',null,['Search',search]),optionSelect('Tracking',[['all','All GPOs'],['tracked','Tracked'],['untracked','Not tracked']],tracked,function(v){tracked=v;ctx.resetTable('migration');rows();}),
        optionSelect('Review track',[['all','All tracks']].concat(Object.keys(TRACKS).map(function(k){return [k,TRACKS[k]];})),track,function(v){track=v;ctx.resetTable('migration');rows();})
      ]);
      function rows(){clear(host);var lower=q.toLowerCase();var list=merged().filter(function(x){return (!lower||(sourceName(x.guid)+' '+(x.r?x.r.owner+' '+x.r.notes:'')).toLowerCase().indexOf(lower)>=0)&&(tracked==='all'||(tracked==='tracked'?!!x.r:!x.r))&&(track==='all'||(x.r?x.r.track:'review')===track);});
        host.appendChild(note(list.length+' matching GPO'+(list.length===1?'':'s')+'. One record per source GPO; the same target profile may be linked to several GPOs.'));
        host.appendChild(table(['GPO','Recorded stage','Owner','Review track','Linked profiles','Pilot group'],list.map(function(x){return [
          h('td',null,[btn(sourceName(x.guid),function(){select(x.guid);},'ps-link'),h('small',{text:!x.g?'Absent from current snapshot':(Number(x.g.setting_count_user)+Number(x.g.setting_count_computer))+' saved settings · '+x.g.link_count+' recorded links'})]),
          h('td',{text:x.r?STAGES[x.r.stage]:'Not tracked'}),h('td',{text:x.r?x.r.owner||'Unassigned':'—'}),h('td',{text:TRACKS[x.r?x.r.track:'review']}),h('td',{text:x.r?String(x.r.profiles.length):'0'}),h('td',{text:x.r&&x.r.pilotGroupId?'Linked':'Not set'})];}),{controls:true,key:'migration',label:'Migration register',order:'GPO name',empty:'No GPO matches these filters'}));
      }
      root.appendChild(panel('Shared migration register',[filters,host],btn('Reset filters',function(){q='';track='all';tracked='all';ctx.resetTable('migration');draw();})));rows();
    }
    function drawDetail(guid) {
      var g=getGpo(guid),r=getRecord(guid);
      root.appendChild(h('div',{class:'ps-toolbar ps-panel-gap'},[btn('Back to register',function(){select(null);}),link('Open AD plan',adLink(guid))]));
      if(!g&&!r){root.appendChild(panel('GPO not found',[note('This identifier is absent from the saved snapshot and register. Return to the register.')]));return;}
      if(!g)root.appendChild(note('This GPO is absent from the current saved snapshot. Its register record is retained for review.','warn'));
      if(r&&data.source.upload&&r.sourceSnapshotId!==data.source.upload.id)root.appendChild(note('Registered against snapshot #'+r.sourceSnapshotId+'; the active snapshot is #'+data.source.upload.id+'. Review source changes before updating migration decisions.','warn'));
      if(edit&&edit.guid===guid){drawEditor(guid,g,r);return;}
      var pairs=r?[
        ['Recorded stage',STAGES[r.stage]],['Owner',r.owner||'Unassigned'],['Review track',TRACKS[r.track]],['Recorded against','AD snapshot #'+r.sourceSnapshotId],['Last saved',date(r.updatedAt)+' by '+r.updatedBy],['Success criteria',r.successCriteria||'Not recorded'],['Validation evidence',r.validationEvidence||'Not recorded'],['Notes',r.notes||'None']
      ]:[['Tracking','No shared record yet'],['Source',data.source.upload?'AD snapshot #'+data.source.upload.id:'Not read']];
      var dl=h('dl',{class:'ps-mg-kv'});pairs.forEach(function(p){dl.appendChild(h('dt',{text:p[0]}));dl.appendChild(h('dd',{text:p[1]}));});
      root.appendChild(panel(sourceName(guid),[dl],data.canEdit?btn(r?'Edit shared record':'Start tracking',function(){edit={guid:guid,version:r?r.version:0,owner:r?r.owner:'',stage:r?r.stage:'assessed',track:r?r.track:'review',profiles:r?r.profiles.map(function(p){return Object.assign({},p);}):[],pilotGroupId:r?r.pilotGroupId:'',notes:r?r.notes:'',successCriteria:r?r.successCriteria:'',validationEvidence:r?r.validationEvidence:''};draw();}):note('Read-only session')));
      if(!r)return;
      var evHost=h('div',{class:'ps-panel-gap'});root.appendChild(evHost);
      drawEvidence(guid,r,evHost);
    }
    function readEvidence(guid,force) {
      var state=evidence[guid];if(state&&state.loading)return;
      evidence[guid]={loading:true,data:force?null:state&&state.data};draw();
      request(API+'/'+guid+'/evidence'+(force?'?refresh=1':'')).then(function(j){evidence[guid]={data:j};}).catch(function(e){evidence[guid]={error:e.message};}).finally(draw);
    }
    function drawEvidence(guid,r,host) {
      var state=evidence[guid];
      if(!state || state.data&&state.data.version!==r.version){host.appendChild(panel('Linked profiles and pilot readiness',[note('Read the linked profiles, assignments and pilot group. This performs reads only.')],btn('Read linked evidence',function(){readEvidence(guid,false);})));return;}
      if(state.loading){host.appendChild(panel('Linked evidence',[status('Reading profiles, assignments and pilot group…')]));return;}
      if(state.error){host.appendChild(panel('Evidence unavailable',[note(state.error,'warn')],btn('Retry evidence read',function(){readEvidence(guid,true);})));return;}
      var ev=state.data;
      host.appendChild(h('div',{class:'ps-toolbar'},[btn('Refresh linked evidence',function(){readEvidence(guid,true);}),note('Evidence read '+date(ev.at)+'. Profile creation and assignment controls remain in Intune.')]));
      var linked=ev.linked.length?ev.linked.map(function(p){
        var children=[note((p.profile?p.profile.name:'Profile not read')+' · '+p.ref.id),note('Profile read: '+p.source.state+' · '+date(p.source.at)+(p.source.error?' · '+p.source.error:'')),note(p.profile?'Last modified '+date(p.profile.modified):'A failed read does not establish that a profile was deleted.')];
        if(p.targets)children.push(table(['Assignment target','Group ID','Assignment filter'],p.targets.map(function(t){return [h('td',{text:TARGET_LABEL[t.type.replace('#microsoft.graph.','')] || 'Other assignment target'}),h('td',{text:t.groupId||'All users / devices or other target'}),h('td',{text:t.filterId?t.filterType+' '+t.filterId:'None reported'})];}),{empty:'No assignments reported for this linked profile'}));
        else children.push(note('Assignments not read: '+p.assignmentSource.state,'warn'));
        return h('div',{class:'ps-mg-profile'},children);
      }):[note('No Intune profiles linked. Edit the shared record to link existing profiles.')];
      host.appendChild(panel('Linked Intune profiles',linked,link('Open Intune configuration','https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/configuration')));
      if(!ev.pilot)host.appendChild(panel('Pilot readiness',[note('No pilot group recorded. Link an existing Entra group in the shared record; this does not assign any policy.')]));
      else {
        var p=ev.pilot,ready=p.readiness,k=ready.counts,children=[note('Pilot group: '+(p.group?p.group.name:'Not read')+' · '+r.pilotGroupId)];
        children.push(note('Membership read '+date(p.memberSource.at)+' · '+p.memberSource.state));
        if(!ready.known)children.push(note(ready.why,'warn'));
        else {
          children.push(note(k.matched+' Windows Intune records · '+k.recent+' checked in within 7 days · '+k.stale+' stale or missing check-in · '+k.notCompliant+' not compliant · '+k.otherCompliance+' other/unknown compliance states. These counts overlap.'));
          children.push(note(k.noMatch+' direct device members without a Windows Intune match · '+k.usersWithoutWindows+' user members without a linked Windows device · '+k.nested+' nested groups not evaluated · '+k.unknownDeviceIds+' device identifiers not readable · '+k.other+' other/non-Windows members.','warn'));
          if(k.duplicateRecords)children.push(note(k.duplicateRecords+' additional Intune records match the same Entra device ID. Review duplicates before deciding device coverage.','warn'));
          children.push(note(ready.scope));children.push(note('Intune device read '+date(ready.deviceReadAt)));
          children.push(table(['Pilot device','Enrollment evidence','Check-in','Compliance','Matched by'],ready.rows.map(function(d){return [h('td',null,[d.id?btn(d.name,function(){ctx.openDevice(d.id);},'ps-link'):d.name,d.duplicate?h('small',{text:'Multiple Intune records for this Entra device'}):null]),h('td',{text:d.enrollment}),h('td',{'data-sort':d.lastSync==null?'':d.lastSync,text:d.id?date(d.lastSync):'Not read'}),h('td',{text:d.compliance}),h('td',{text:d.reason})];}),{controls:true,key:'migration-pilot',label:'Pilot readiness',order:'group membership',empty:'No Windows device evidence matched these direct members'}));
        }
        host.appendChild(panel('Pilot readiness',children));
      }
      host.appendChild(panel('Shared record history',[table(['Version','Saved by','When','Fields changed'],ev.history.map(function(x){return [h('td',{text:String(x.version)}),h('td',{text:x.actor}),h('td',{text:date(x.at)}),h('td',{text:x.changes.fields.join(', ')})];}),{empty:'No saved history'})]));
    }
    function drawEditor(guid,g,r) {
      var draft=edit, pilotControl=null;
      var box=h('div'),message=status('Editing shared planning metadata. No AD or Intune policy changes are sent.');
      function field(label,key,multiline) {
        var ctl=h(multiline?'textarea':'input',{'aria-label':label,value:edit[key],rows:multiline?3:null,maxlength:key==='owner'?254:key==='successCriteria'?2000:3000,on:{input:function(){edit[key]=ctl.value;}}});
        if(key==='pilotGroupId')pilotControl=ctl;
        if(multiline)ctl.textContent=edit[key];
        return h('label',null,[label,ctl]);
      }
      box.appendChild(h('div',{class:'ps-mg-form'},[field('Review owner','owner'),optionSelect('Recorded stage',Object.keys(STAGES).map(function(k){return[k,STAGES[k]];}),edit.stage,function(v){edit.stage=v;}),optionSelect('Review track',Object.keys(TRACKS).map(function(k){return[k,TRACKS[k]];}),edit.track,function(v){edit.track=v;}),field('Pilot Entra group ID','pilotGroupId'),field('Success criteria','successCriteria',true),field('Validation evidence / references','validationEvidence',true),field('Notes and blockers','notes',true)]));
      var groupSearch=h('input',{type:'search','aria-label':'Find existing pilot group',placeholder:'Existing Entra group name'}),groupResults=h('div'),groupMessage=status('');
      var findGroup=btn('Find group',async function(){
        var term=groupSearch.value.trim();if(term.length<2){groupMessage.textContent='Enter at least two characters.';return;}
        findGroup.disabled=true;groupMessage.textContent='Reading existing Entra groups…';clear(groupResults);
        try {var j=await request('/hub-api/api/patch-status/groups?q='+encodeURIComponent(term));if(edit!==draft || !groupResults.isConnected)return;
          groupMessage.textContent=(j.groups||[]).length+' group'+((j.groups||[]).length===1?'':'s')+' found. Choosing one changes this register reference only.';
          (j.groups||[]).forEach(function(g){groupResults.appendChild(h('div',{class:'ps-mg-profile-link'},[btn('Use '+g.name,function(){edit.pilotGroupId=g.id;pilotControl.value=g.id;groupMessage.textContent='Selected '+g.name+' · '+g.id;clear(groupResults);}),note(g.id)]));});
        }catch(e){groupMessage.textContent=e.message;}finally{findGroup.disabled=false;}
      });
      box.appendChild(h('div',{class:'ps-toolbar ps-panel-gap'},[groupSearch,findGroup]));box.appendChild(groupMessage);box.appendChild(groupResults);
      box.appendChild(note('Use an existing Entra group ID. Pilot membership is assessed from direct members. The record does not change group membership, Intune assignments or AD scope.'));
      var profileHost=h('div',{class:'ps-panel-gap'}),profileMessage=status('');box.appendChild(profileHost);box.appendChild(profileMessage);
      function profileList() {
        clear(profileHost);
        profileHost.appendChild(h('h4',{text:'Linked Intune profiles ('+edit.profiles.length+' / 10)'}));
        edit.profiles.forEach(function(p){var found=profiles&&profiles.records.find(function(x){return x.id===p.id&&x.kind===p.kind;});profileHost.appendChild(h('div',{class:'ps-mg-profile-link'},[h('span',{text:(found?found.name:KIND_LABEL[p.kind])+' · '+p.id}),btn('Unlink from register',function(){edit.profiles=edit.profiles.filter(function(x){return x!==p;});profileList();})]));});
        profileHost.appendChild(btn('Load / refresh Intune profiles',function(){profileMessage.textContent='Reading existing Intune profiles…';request(API+'/profiles?refresh=1').then(function(j){profiles=j;if(edit!==draft || !profileHost.isConnected)return;profileMessage.textContent=j.complete?'Profile inventory read '+date(j.at):'Profile inventory is incomplete. Unavailable sources: '+Object.keys(j.sources).filter(function(k){return j.sources[k].state!=='ok';}).join(', ')+'. Missing profiles are not inferred.';profileList();}).catch(function(e){profileMessage.textContent=e.message;});}));
        if(profiles) {
          var search=h('input',{type:'search','aria-label':'Find existing Intune profiles',placeholder:'Filter profile name or ID'}),choices=h('div',{class:'ps-mg-profile-choices'});
          function choicesDraw(){clear(choices);var term=search.value.toLowerCase(),matches=profiles.records.filter(function(p){return (p.name+' '+p.id).toLowerCase().indexOf(term)>=0&&!edit.profiles.some(function(x){return x.kind===p.kind&&x.id===p.id;});});
            choices.appendChild(note(matches.length+' matching profile'+(matches.length===1?'':'s')+(matches.length>30?' · first 30 shown; narrow the search':'')));
            matches.slice(0,30).forEach(function(p){var b=btn('Link '+p.name,function(){if(edit.profiles.length>=10)return;edit.profiles.push({kind:p.kind,id:p.id});profileList();});b.disabled=edit.profiles.length>=10;choices.appendChild(h('div',{class:'ps-mg-profile-link'},[b,note(KIND_LABEL[p.kind]+' · '+p.id)]));});}
          search.addEventListener('input',choicesDraw);profileHost.appendChild(search);profileHost.appendChild(choices);choicesDraw();
        }
      }
      profileList();box.appendChild(message);
      var save=btn('Save shared record',async function(){
        if(edit.pilotGroupId&&!GUID.test(edit.pilotGroupId.trim())){message.textContent='Enter a valid Entra group ID, or leave it empty.';return;}
        save.disabled=cancel.disabled=true;message.textContent='Saving the shared register…';
        var payload={};['version','owner','stage','track','profiles','pilotGroupId','notes','successCriteria','validationEvidence'].forEach(function(k){payload[k]=edit[k];});
        try {await request(API+'/'+guid,{method:'POST',headers:{Accept:'application/json','Content-Type':'application/json'},body:JSON.stringify(payload)});edit=null;delete evidence[guid];await refreshAfterSave();}
        catch(e){message.textContent=e.message+' Your edits remain here. Copy them before reloading if another person saved this record.';save.disabled=cancel.disabled=false;}
      });
      var cancel=btn('Cancel edit',function(){edit=null;draw();});
      root.appendChild(panel((r?'Edit: ':'Track: ')+sourceName(guid),[box],h('div',{class:'ps-row-actions'},[cancel,save])));
    }
    async function refreshAfterSave() {try{data=await request(API);draw();if(ctx.onState)ctx.onState();}catch(e){error='The record was saved, but the register could not reload. '+e.message;draw();}}
    return {view:view, canExport:function(){return !!(data && data.records.length);}, hasEdits:function(){return !!edit;}, discardEdits:function(){edit=null;}, exportRows:function(){if(!data)return;ctx.download('gpo-migration-register',['GPO GUID','GPO','Recorded stage','Owner','Track','Source snapshot','Linked profiles','Pilot group ID','Notes','Success criteria','Validation evidence','Last saved','Saved by'],data.records.map(function(r){return[r.guid,r.sourceName,STAGES[r.stage],r.owner,TRACKS[r.track],r.sourceSnapshotId,r.profiles.map(function(p){return p.kind+':'+p.id;}).join('; '),r.pilotGroupId,r.notes,r.successCriteria,r.validationEvidence,r.updatedAt,r.updatedBy];}));}};
  }};
})();
