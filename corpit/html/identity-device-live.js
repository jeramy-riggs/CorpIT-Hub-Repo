/* Stage 3B: explicit read-only checks for the selected device and source interface. */
(function(){
  'use strict';
  function initial(sequence){return {scope:'',sequence:sequence||0,controllers:[],loading:false,options:null,error:'',queryKey:'',targetKey:'',portKey:'',firewall:'',historySite:'',historyBand:'',historyRange:'hour',historyStart:'',historyEnd:'',historyTimezone:'local',historyNotice:'',intervalKey:'',peerResults:{},runningPeer:'',leases:[],leaseVersion:0,results:{},running:{}};}
  var state=initial();
  function esc(v){return x(v==null?'':String(v));}
  function val(v){return v==null||v===''?'Not reported':String(v);}
  function group(){return window.IdentityDeviceContext&&IdentityDeviceContext.selected();}
  function interfaceKey(){return window.IdentityDeviceNetwork?.getState().key||'';}
  function scope(){var g=group();return g&&window._D?(_D.samAccountName||_curQuery)+'|'+_gen+'|'+g.deviceKey+'|'+interfaceKey():'';}
  function reset(){state.controllers.forEach(function(c){c.abort();});state=initial(state.sequence+1);render();}
  function current(seq,s){return seq===state.sequence && s===scope() && s===state.scope;}
  function contextChanged(){var s=scope();if(s!==state.scope){reset();state.scope=s;}render();if(s && window._page==='detail' && window._curTab==='t-network' && !state.options && !state.loading && !state.error)load();}
  function requestBody(){return {q:_D.samAccountName||_curQuery,deviceKey:group().deviceKey,interfaceKey:interfaceKey()};}
  function controller(){var c=new AbortController();state.controllers.push(c);return c;}
  async function load(){
    if(!group()||!window._D)return;var seq=state.sequence,s=state.scope,c=controller();state.loading=true;state.error='';render();var timer=setTimeout(function(){c.abort();},20000);
    try{
      var body=requestBody(),u='/api/identity/device-network-options?'+new URLSearchParams(body),r=await fetch(u,{signal:c.signal,cache:'no-store'}),d=await r.json();
      if(!current(seq,s))return;if(!r.ok)throw Error(d.error||'Check options could not be read.');
      if(d.mode!=='explicit'||d.deviceKey!==body.deviceKey||d.interfaceKey!==body.interfaceKey)throw Error('Check options did not match the selected device and interface.');
      state.options=d;
    }catch(e){if(current(seq,s))state.error=e.name==='AbortError'?'Check options timed out. Refresh options to retry.':e.message;}
    finally{clearTimeout(timer);if(current(seq,s)){state.controllers=state.controllers.filter(function(v){return v!==c;});state.loading=false;render();}}
  }
  async function checkResponse(r){
    try{return await r.json();}catch(_){throw Error('The check service '+(r.status>=400?'returned HTTP '+r.status:'returned an invalid response')+'. No result was established; retry when ready.');}
  }
  async function run(tool){
    if(!state.options||state.running[tool]||!group())return;
    if((tool==='history'||tool==='history-context')&&(state.running.history||state.running['history-context']||state.runningPeer))return;
    var body=Object.assign(requestBody(),{tool:tool}),target;
    if(tool==='dhcp'){body.queryKey=state.queryKey;target=state.options.dhcpQueries.find(function(q){return q.key===state.queryKey;});if(!target)return;}
    if(tool==='meraki'&&!state.options.merakiEligible)return;
    if(tool==='history'){
      if(!state.options.merakiEligible||!state.historySite||!state.historyBand)return;
      body.historySite=state.historySite;body.historyBand=state.historyBand;
      var end=new Date(),start=new Date(end.getTime()-(state.historyRange==='six'?21600000:3600000));
      if(state.historyRange==='custom'){start=new Date(state.historyStart);end=new Date(state.historyEnd);}
      if(!Number.isFinite(start.getTime())||!Number.isFinite(end.getTime())||end<=start||end-start>21600000||start.getTime()<Date.now()-7*86400000||end.getTime()>Date.now()+30000){state.results.history={error:'Choose a valid interval up to six hours within the last seven days, ending no later than now.'};render();return;}
      body.historyStart=start.toISOString();body.historyEnd=end.toISOString();state.historyNotice='';
      target={mac:state.options.selectedMac,site:state.historySite,band:state.historyBand,start:body.historyStart,end:body.historyEnd};
    }
    if(tool==='history-context'){
      var previous=state.results.history?.evidence,interval=(previous?.analysis?.timeline||[]).find(function(t){return t.startTs+'|'+t.endTs===state.intervalKey;});
      if(!previous||!interval||previous.scope.mac!==state.options.selectedMac)return;
      body.historySite=previous.scope.site;body.historyBand=previous.scope.band;body.historyStart=interval.startTs;body.historyEnd=interval.endTs;
      target={mac:previous.scope.mac,site:previous.scope.site,band:previous.scope.band,start:interval.startTs,end:interval.endTs};
    }
    if(tool==='switch'){body.portKey=state.portKey;target=state.options.switchPorts.find(function(p){return p.key===state.portKey;});if(!target)return;}
    if(tool==='reachability'||tool==='firewall'||tool==='ap-port'){
      target=state.options.ipTargets.concat(state.leases).find(function(t){return t.key===state.targetKey;});if(!target)return;
      if(target.key.indexOf('lease:')===0)body.leaseToken=target.key.slice(6);else body.targetKey=target.key;
      if(tool==='ap-port'&&(!state.options.currentApPortEligible||!target.firewallEligible||target.key.indexOf('lease:')!==0))return;
      if(tool==='firewall'){if(!state.firewall||!target.firewallEligible)return;body.firewall=state.firewall;}
    }
    var seq=state.sequence,s=state.scope,leaseVersion=state.leaseVersion,c=controller(),timer=setTimeout(function(){c.abort();},55000);
    state.running[tool]=true;delete state.results[tool];if(tool==='dhcp'){state.leaseVersion++;delete state.results['ap-port'];state.leases=[];if(state.targetKey.indexOf('lease:')===0){state.targetKey='';delete state.results.reachability;delete state.results.firewall;}}
    if(tool==='history'||tool==='history-context')state.peerResults={};
    if(tool==='history'){state.intervalKey='';delete state.results['history-context'];}
    render();
    try{
      var r=await fetch('/api/identity/device-network-check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),signal:c.signal,cache:'no-store'}),d=await checkResponse(r);
      if(!current(seq,s)||tool==='ap-port'&&leaseVersion!==state.leaseVersion)return;if(!r.ok)throw Error(d.error||'The check could not complete.');
      if(d.mode!=='explicit'||d.deviceKey!==body.deviceKey||d.interfaceKey!==body.interfaceKey||d.tool!==tool)throw Error('The check result did not match this selection.');
      if((tool==='reachability'||tool==='firewall')&&(d.target?.ip!==target.ip || tool==='firewall'&&d.target?.firewall!==body.firewall))throw Error('The check result did not match the selected IP and firewall.');
      if(tool==='ap-port'&&(d.target?.mac!==state.options.selectedMac||d.target?.ip!==target.ip))throw Error('The AP port result did not match the selected MAC and DHCP IP.');
      if(tool==='switch'&&d.target?.key!==body.portKey)throw Error('The check result did not match the selected switch port.');
      if(tool==='dhcp'&&d.target?.key!==body.queryKey)throw Error('The check result did not match the exact DHCP query.');
      if(tool==='meraki'&&d.target?.mac!==state.options.selectedMac)throw Error('The check result did not match the selected MAC.');
      if(tool==='history'&&(d.target?.mac!==target.mac||d.target?.site!==target.site||d.target?.band!==target.band||d.target?.start!==target.start||!Number.isFinite(Date.parse(d.target?.end))||Date.parse(d.target.end)>Date.parse(target.end)||Date.parse(target.end)-Date.parse(d.target.end)>30000||d.evidence?.window?.start!==d.target.start||d.evidence?.window?.end!==d.target.end||d.evidence?.scope?.mac!==target.mac||d.evidence?.scope?.site!==target.site||d.evidence?.scope?.band!==target.band))throw Error('History did not match the selected MAC, site, band and interval.');
      if(tool==='history-context'&&(d.target?.mac!==target.mac||d.target?.site!==target.site||d.target?.band!==target.band||d.target?.start!==target.start||d.target?.end!==target.end||d.evidence?.window?.start!==target.start||d.evidence?.window?.end!==target.end||d.evidence?.scope?.mac!==target.mac||d.evidence?.scope?.site!==target.site||d.evidence?.scope?.band!==target.band||d.evidence?.scope?.apSerial&&d.evidence.scope.apSerial!==previous.scope.apSerial))throw Error('Interval context did not match the selected MAC, AP, site, band and interval. Refresh history if the AP changed.');
      if(tool==='history-context'&&d.evidence?.peerRoaming?.peers?.some(function(p){var h=p.historicalEvents,e=d.evidence;return h&&(h.scope?.mac!==p.mac||h.scope?.clientId!==p.clientId||h.scope?.networkId!==e.scope?.networkId||h.coverage?.requestedStart!==e.window?.contextStart||h.coverage?.requestedEnd!==e.window?.contextEnd);}))throw Error('Interval context did not match the peer, network and historical window. Read interval context again.');
      state.results[tool]=d;if(tool==='dhcp')state.leases=d.leaseTargets||[];
      if(tool==='history'){var choices=contextIntervals(d.evidence);state.intervalKey=choices[0]?.key||'';}
    }catch(e){if(current(seq,s)&&(tool!=='ap-port'||leaseVersion===state.leaseVersion))state.results[tool]={error:e.name==='AbortError'?'The check timed out. No result was established; retry when ready.':e.message,tool:tool};}
    finally{clearTimeout(timer);if(current(seq,s)){state.controllers=state.controllers.filter(function(v){return v!==c;});var returnFocus=document.activeElement===document.body;state.running[tool]=false;render();if(returnFocus)document.getElementById('identity-live-run-'+tool)?.focus();if(window._page==='summary')renderSummaryTool();}}
  }
  async function inspectPeer(ref){
    var parent=state.results['history-context'],e=parent?.evidence,p=e?.peerRoaming?.excludedCandidates?.find(function(p){return p.peerRef===ref;});
    if(!p||!ref||state.runningPeer||state.running.history||state.running['history-context']||!group()||!e.scope||!e.window)return;
    var seq=state.sequence,s=state.scope,c=controller(),timer=setTimeout(function(){c.abort();},55000),body=Object.assign(requestBody(),{tool:'history-peer-context',historySite:e.scope.site,historyBand:e.scope.band,historyStart:e.window.start,historyEnd:e.window.end,peerRef:ref});
    state.runningPeer=ref;delete state.peerResults[ref];render();
    try{
      var r=await fetch('/api/identity/device-network-check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),signal:c.signal,cache:'no-store'}),d=await checkResponse(r);
      if(!current(seq,s)||state.results['history-context']!==parent)return;
      if(!r.ok)throw Error(d.error||'Excluded candidate context could not be read.');
      var v=d.evidence;
      if(d.mode!=='explicit'||d.tool!=='history-peer-context'||d.deviceKey!==body.deviceKey||d.interfaceKey!==body.interfaceKey||d.target?.peerRef!==ref||d.target?.mac!==e.scope.mac||d.target?.site!==e.scope.site||d.target?.band!==e.scope.band||d.target?.start!==e.window.start||d.target?.end!==e.window.end||v?.window?.start!==e.window.start||v?.window?.end!==e.window.end||v?.scope?.mac!==e.scope.mac||e.scope.clientId&&v?.scope?.clientId!==e.scope.clientId||v?.scope?.site!==e.scope.site||v?.scope?.band!==e.scope.band||v?.scope?.apSerial&&v.scope.apSerial!==e.scope.apSerial||v?.scope?.networkId&&v.scope.networkId!==e.scope.networkId||v?.requestedPeer?.mac!==p.mac||v?.requestedPeer?.clientId!==p.clientId||v?.assessmentChanged!==false||v?.peerRoaming?.peers?.some(function(x){return x.mac!==p.mac||x.clientId!==p.clientId||x.historicalEvents&&(x.historicalEvents.scope?.mac!==p.mac||x.historicalEvents.scope?.clientId!==p.clientId||x.historicalEvents.scope?.networkId!==v.scope.networkId||x.historicalEvents.coverage?.requestedStart!==v.window.contextStart||x.historicalEvents.coverage?.requestedEnd!==v.window.contextEnd);}))throw Error('Peer context did not match this candidate, device, AP and interval. Read interval context again.');
      state.peerResults[ref]=d;
    }catch(err){if(current(seq,s)&&state.results['history-context']===parent)state.peerResults[ref]={error:err.name==='AbortError'?'Peer context timed out; no result established. Retry when ready.':err.message,peerMac:p.mac};}
    finally{clearTimeout(timer);if(current(seq,s)){state.controllers=state.controllers.filter(function(v){return v!==c;});state.runningPeer='';render();document.getElementById('identity-live-peer-'+ref)?.focus();if(window._page==='summary')renderSummaryTool();}}
  }
  function change(field,value){
    state[field]=value;state.sequence++;state.controllers.forEach(function(c){c.abort();});state.controllers=[];state.running={};state.runningPeer='';state.loading=false;
    if(field==='queryKey'){delete state.results['ap-port'];state.leaseVersion++;delete state.results.dhcp;state.leases=[];if(state.targetKey.indexOf('lease:')===0)state.targetKey='';delete state.results.reachability;delete state.results.firewall;}
    if(field==='targetKey'){delete state.results['ap-port'];delete state.results.reachability;delete state.results.firewall;}
    if(field==='firewall')delete state.results.firewall;
    if(field==='portKey')delete state.results.switch;
    if(field.indexOf('history')===0){delete state.results.history;delete state.results['history-context'];state.intervalKey='';state.historyNotice='';}
    if(field==='intervalKey')delete state.results['history-context'];
    if(field.indexOf('history')===0||field==='intervalKey')state.peerResults={};
    render();
  }
  function select(id,label,items,value,labeler){return '<label for="'+id+'">'+esc(label)+'</label><select class="env-select" id="'+id+'"><option value="">Choose…</option>'+items.map(function(i){return '<option value="'+esc(i.key)+'"'+(i.key===value?' selected':'')+'>'+esc(labeler(i))+'</option>';}).join('')+'</select>';}
  function button(tool,label,disabled){return '<button type="button" class="btn btn-ghost btn-sm" id="identity-live-run-'+tool+'" data-device-check="'+tool+'"'+(disabled||state.running[tool]?' disabled':'')+'>'+esc(state.running[tool]?'Running '+label+'…':label)+'</button>';}
  function rows(heads,records,mapper){return records.length?table(heads.map(function(t){return {t:t};}),records.map(function(r){return '<tr>'+mapper(r).map(function(v){return '<td>'+esc(val(v))+'</td>';}).join('')+'</tr>';}),''):'';}
  function historyTime(v){if(!v)return 'Not reported';var d=new Date(v);if(!Number.isFinite(d.getTime()))return 'Invalid date';return new Intl.DateTimeFormat(undefined,{year:'numeric',month:'short',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',timeZoneName:'short',...(state.historyTimezone==='UTC'?{timeZone:'UTC'}:{})}).format(d);}
  function coverageLabel(start,end){
    var zone=historyZone(),a=new Date(start),b=new Date(end),date={timeZone:zone,year:'numeric',month:'2-digit',day:'2-digit'};
    if(!Number.isFinite(a.getTime())||!Number.isFinite(b.getTime()))return 'Invalid interval';
    var sameDay=a.toLocaleDateString('en-CA',date)===b.toLocaleDateString('en-CA',date),options={timeZone:zone,hour:'2-digit',minute:'2-digit',hourCycle:'h23'};
    var first=new Intl.DateTimeFormat(undefined,{...options,month:'short',day:'2-digit'}).format(a),last=new Intl.DateTimeFormat(undefined,sameDay?options:{...options,month:'short',day:'2-digit'}).format(b);
    return first+' — '+last;
  }
  function coverageTable(records){
    return table([{t:'Interval'},{t:'Matching peers initial / final'},{t:'Evidence stage'},{t:'Measured peer MACs'}],records.map(function(t){return '<tr><td style="white-space:nowrap">'+esc(coverageLabel(t.startTs,t.endTs))+'</td><td>'+esc(t.initialPeerCount+' / '+t.peerCount)+'</td><td>'+esc({initial:'Initial',followup:'Follow-up',insufficient:'Insufficient'}[t.stage]||t.stage)+'</td><td>'+esc(t.peerMacs.join(', '))+'</td></tr>';}),'No measured elevated intervals.');
  }
  function historyZone(){return state.historyTimezone==='UTC'?'UTC':Intl.DateTimeFormat().resolvedOptions().timeZone;}
  function contextTime(v){var d=new Date(v);if(!v||!Number.isFinite(d.getTime()))return 'Not reported';return new Intl.DateTimeFormat(undefined,{timeZone:historyZone(),month:'short',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',fractionalSecondDigits:3,hourCycle:'h23'}).format(d);}
  function contextIntervals(e){var labels={client_or_radio_unresolved:'Unresolved',selected_client_pattern:'Client pattern',shared_radio_path_suspected:'Shared radio path',ap_or_uplink_suspected:'AP or uplink',below_threshold:'Below threshold'};return (e?.analysis?.timeline||[]).slice().sort(function(a,b){return Number(b.pattern==='client_or_radio_unresolved')-Number(a.pattern==='client_or_radio_unresolved')||Number(b.flagged)-Number(a.flagged)||String(a.startTs).localeCompare(String(b.startTs));}).map(function(t){return {key:t.startTs+'|'+t.endTs,label:coverageLabel(t.startTs,t.endTs)+' · '+val(t.latencyMs)+' ms · '+(labels[t.pattern]||'Review interval')};});}
  function inspectedPeerText(){
    return Object.values(state.peerResults).flatMap(function(r){var e=r.evidence||{},p=e.requestedPeer||{};if(r.error)return ['EXPLICIT EXCLUDED-PEER CONTEXT · '+val(r.peerMac),r.error];return ['EXPLICIT EXCLUDED-PEER CONTEXT · '+val(p.mac)+' / '+val(p.clientId),'Status: '+val(e.status)+' · read '+val(r.completedAt),'UTC interval: '+val(e.window?.start)+' through '+val(e.window?.end),'Selected AP / band: '+val(e.scope?.apSerial)+' / '+val(e.scope?.band),'Read budget: '+val(e.requestCount)+' / '+val(e.limits?.maxRequests),'Context only; initial exclusions, original assessment and measured peer counts unchanged.',e.reason||'',...(e.peerRoaming?.peers||[]).flatMap(function(x){return ['Peer '+x.mac+': '+val(x.context||x.reason)+' · matching AP/band latency '+val(x.matchingLatencyMs)+' ms · event coverage complete '+!!x.events?.coverage?.complete,...(x.transitions||[]).map(function(t){return 'AP transition: '+t.fromAp+' → '+t.toAp+' · '+val(t.direction)+' · joined '+t.joinedAt+' · left '+t.leftAt;}),...historicalPeerText(x),...(x.events?.records||[]).slice(0,50).map(function(t){return 'Peer event: '+t.occurredAt+' · '+val(t.apSerial)+' · '+t.type+' · band '+val(t.band);})];})];});
  }
  function contextText(){
    var r=state.results['history-context'];if(!r)return [];if(r.error)return ['INTERVAL SAMPLE & ROAMING CONTEXT',r.error];var e=r.evidence||{},s=e.sampleConfidence||{};
    return ['INTERVAL SAMPLE & ROAMING CONTEXT','UTC interval: '+val(e.window?.start)+' through '+val(e.window?.end),'Status: '+val(e.status)+' · read '+val(r.completedAt),'Sample support: '+val(s.sampleCount)+' · '+val(s.support)+' · '+val(s.reason),'Sample scope: '+val(s.scope),'AP-filtered interval measurements: '+JSON.stringify(e.selected||{}),'Context AP event coverage complete: '+!!e.apEvents?.coverage?.complete+' · '+val(e.apEvents?.reason),'Context selected-client event coverage complete: '+!!e.clientEvents?.coverage?.complete+' · '+val(e.clientEvents?.reason),...(s.records||[]).map(function(c){return c.label+': '+val(c.sampleCount)+' samples · '+val(c.averageMs)+' ms · '+c.status;}),...(e.peerRoaming?.peers||[]).flatMap(function(p){return ['Peer '+p.mac+': '+val(p.context||p.reason)+' · matching AP/band interval latency '+val(p.matchingLatencyMs)+' ms · event coverage complete '+!!p.events?.coverage?.complete,...(p.transitions||[]).map(function(t){return 'AP transition: '+t.fromAp+' → '+t.toAp+' · '+(t.direction==='departure'?'departure from selected AP':'arrival at selected AP')+' · joined '+t.joinedAt+' · left '+t.leftAt;}),...historicalPeerText(p),...(p.events?.records||[]).slice(0,50).map(function(x){return 'Peer event: '+x.occurredAt+' · '+val(x.apSerial)+' · '+x.type+' · band '+val(x.band);})];}),...(e.peerRoaming?.excludedCandidates||[]).map(function(p){return 'Excluded candidate '+p.mac+' / '+val(p.clientId)+' · rank '+val(p.selectionRank)+' · '+val(p.reason);}), 'Excluded by two-peer limit: '+val(e.peerRoaming?.excludedCount??Math.max(0,(e.peerRoaming?.candidateCount||0)-(e.peerRoaming?.readCount||0))),'Candidate context: '+val(e.peerRoaming?.readCount)+' of '+val(e.peerRoaming?.candidateCount)+' · limit '+val(e.peerRoaming?.limit),'Context only; original assessment and peer counts unchanged.',...inspectedPeerText(),...(e.limitations||[])];
  }
  function historicalPeerText(p){var h=p.historicalEvents;if(!h)return [];return ['HISTORICAL CLIENT CONNECTIVITY · '+p.mac,...(p.roamingGap?['Roaming gap: '+p.roamingGap.label+' · '+p.roamingGap.code,p.roamingGap.detail]:[]),'Source: '+h.source+' · '+h.status+' · coverage complete '+!!h.coverage?.complete+' · pages '+val(h.coverage?.pages),'Source scope: verified native client; all APs and bands, with per-event band retained.','UTC context: '+val(h.coverage?.requestedStart)+' through '+val(h.coverage?.requestedEnd),h.reason||'',h.apMapping?.reason||'',...(h.reassociations||[]).map(function(r){return 'Reported reassociation: '+val(r.fromApName)+' / '+r.fromAp+' → '+val(r.toApName)+' / '+r.toAp+' · '+r.occurredAt+' · band '+val(r.band)+' · previous AP MAC '+r.fromApMac+' · '+r.basis;}),...(h.otherApReassociations||[]).map(function(r){return 'Other-AP reassociation: '+val(r.fromApName)+' / '+r.fromAp+' → '+val(r.toApName)+' / '+r.toAp+' · '+r.occurredAt+' · band '+val(r.band)+' · previous AP MAC '+r.fromApMac+' · '+r.basis;}),...(h.records||[]).slice(0,50).map(function(e){return 'Connectivity event: '+e.occurredAt+' · '+val(e.apSerial)+' · band '+val(e.band)+' · '+e.description;})];}
  function peerEvidence(p){var h='';h+='<details class="support-evidence" open><summary>'+esc(p.mac)+' · '+esc(p.context||p.reason||p.status)+'</summary><p class="note">Matching AP/band interval latency: '+esc(p.matchingLatencyMs==null?'No matching measurement':val(p.matchingLatencyMs)+' ms')+'. Context does not add this peer to the original comparison.</p>';
      if(p.roamingGap)h+='<p class="ls">'+esc(p.roamingGap.detail)+'</p>';
      (p.transitions||[]).forEach(function(t){h+='<p class="note">'+esc((t.direction==='departure'?'Departure from selected AP: ':'Arrival at selected AP: ')+t.fromAp+' → '+t.toAp)+' · joined '+esc(contextTime(t.joinedAt))+' · left '+esc(contextTime(t.leftAt))+'</p><p class="ls">'+esc(t.basis)+'</p>';});
      var historical=p.historicalEvents;if(historical){h+='<p class="ls">Time-bounded client connectivity · '+esc(historical.status)+' · '+esc(historical.coverage?.complete?'Complete for requested context':'Coverage incomplete or unavailable')+' · '+esc(historical.coverage?.pages)+' pages. All APs and bands; each event retains its reported band. Legacy network event coverage below remains separate.</p>';
        (historical.reassociations||[]).forEach(function(r){h+='<p class="note">Reported reassociation: '+esc(val(r.fromApName)+' / '+r.fromAp+' → '+val(r.toApName)+' / '+r.toAp)+' · '+esc(contextTime(r.occurredAt))+' · '+esc(val(r.band))+' GHz</p><p class="ls">'+esc(r.basis)+'</p>';});
        if(historical.otherApReassociations?.length){h+='<p class="note">Other-AP reassociations · '+esc(historical.otherApReassociations.length)+'</p><p class="ls">Both APs differ from the selected AP. These events do not change its transition evidence or the original latency comparison.</p>';historical.otherApReassociations.forEach(function(r){h+='<p class="note">Other-AP reassociation: '+esc(val(r.fromApName)+' / '+r.fromAp+' → '+val(r.toApName)+' / '+r.toAp)+' · '+esc(contextTime(r.occurredAt))+' · '+esc(val(r.band))+' GHz</p><p class="ls">'+esc(r.basis)+'</p>';});}
        h+='<details class="support-evidence"><summary>Historical client connectivity · '+esc(historical.records?.length||0)+' events</summary><p class="ls">'+esc(historyTime(historical.coverage?.requestedStart)+' — '+historyTime(historical.coverage?.requestedEnd))+' · '+esc(historical.reason||'')+' '+esc(historical.apMapping?.reason||'')+'</p>';
        h+=rows(['Client event time','AP / band','Connectivity event'],(historical.records||[]).slice(0,50),function(e){return [contextTime(e.occurredAt),val(e.apSerial)+' / '+val(e.band),e.description];});h+='</details>';}
      h+='<p class="ls">Event coverage: '+esc(p.events?.coverage?.complete?'complete':'incomplete or unavailable')+'. '+esc(p.events?.reason||p.reason||'')+'</p>';
      h+=rows(['Event time','AP / band','Event'],(p.events?.records||[]).slice(0,50),function(t){return [contextTime(t.occurredAt),val(t.apSerial)+' / '+val(t.band),t.description||t.type];});if(p.events?.records?.length>50)h+='<p class="ls">Showing the first 50 peer events.</p>';h+='</details>';return h;}
  function intervalContext(e){
    var choices=contextIntervals(e),h='<details class="support-evidence" open><summary>Sample-count confidence & peer roaming</summary><p class="ls">Choose one measured five-minute interval. This optional read preserves the original assessment and peer counts. Times shown in '+esc(historyZone())+'.</p>';
    h+='<div class="identity-live-controls">'+select('identity-live-context-interval','Interval for sample & roaming context',choices,state.intervalKey,function(c){return c.label;})+button('history-context','Read sample & roaming context',!state.intervalKey||state.running.history||state.runningPeer)+'</div>';
    h+='<p class="ls">Up to 24 API reads within 32 seconds, two at a time; up to two event-derived peers and three event pages per source. Incomplete peer logs can use time-bounded client connectivity after both peers’ base reads, within the same total budget. Missing counts or events remain unknown.</p>';
    var r=state.results['history-context'];if(!r)return h+'</details>';
    if(r.error)return h+'<p class="note warn" role="status">'+esc(r.error)+'</p></details>';
    var c=r.evidence||{},s=c.sampleConfidence;
    h+='<p class="ls">'+esc(c.status)+' · '+esc(historyTime(c.window?.start)+' — '+historyTime(c.window?.end))+' · read '+esc(historyTime(r.completedAt))+'</p>';
    if(!s)return h+'<p class="note">'+esc(c.reason||'Interval evidence unavailable.')+'</p></details>';
    h+='<h4 class="identity-evidence-heading">Latency sample confidence</h4><p class="note">'+esc(s.reason)+'</p><p class="ls">'+esc(s.scope)+'</p>';
    h+=rows(['Traffic category','Latency samples','Reported average ms'],s.records||[],function(x){return [x.label,x.sampleCount,x.sampleCount?val(x.averageMs):x.sampleCount===0?'No measurements':'Unknown'];});
    h+='<p class="ls">Sample total: '+esc(val(s.sampleCount))+'. Sample count is measurement support, not a probability or root-cause confidence score. Voice is a traffic category, not proof of a voice call.</p>';
    h+=rows(['Selected AP / band interval','Observed value'],['latency','signal','usage'].map(function(key){var x=c.selected?.[key];return {key:key,value:(x?.records||[]).find(function(x){return x.startTs===c.window.start&&x.endTs===c.window.end;})};}),function(x){return [x.key, x.key==='latency'?val(x.value?.avgLatencyMs)+' ms':x.key==='signal'?'RSSI '+val(x.value?.rssi)+' / SNR '+val(x.value?.snr):'Total '+val(x.value?.totalKbps)+' Kbps'];});
    var p=c.peerRoaming||{};h+='<h4 class="identity-evidence-heading">Peer roaming evidence</h4><p class="ls">'+esc(p.readCount)+' of '+esc(p.candidateCount)+' event-derived candidates read · limit '+esc(p.limit)+'. '+esc(p.selectionBasis||'')+'</p>';
    if(p.truncated){h+='<details class="support-evidence" open><summary>Candidates excluded by the two-peer limit · '+esc(p.excludedCount??Math.max(0,(p.candidateCount||0)-(p.readCount||0)))+'</summary><p class="note">These candidates came from selected-AP events in this interval. No additional identity, latency or roaming reads were made for them in the initial context read. Until explicitly inspected, their transition context remains unknown; they are not measured comparison peers.</p>';
      h+=rows(['Event-derived MAC / native ID','Selection order','Why not read'],p.excludedCandidates||[],function(x){return [val(x.mac)+' / '+val(x.clientId),val(x.selectionRank),val(x.reason)];});if(!p.excludedCandidates?.length)h+='<p class="ls">Candidate details were not returned. Read this interval again.</p>';
      h+='<p class="ls">Inspect one candidate on demand. Each check revalidates the selected AP and interval, reads one candidate within 24 API reads / 32 seconds, and preserves the initial two-peer selection. Incomplete legacy logs can use time-bounded client connectivity, with three pages per source inside the same budget. References expire after five minutes; reread interval context to renew them.</p>';
      (p.excludedCandidates||[]).forEach(function(x){var ref=x.peerRef,expired=ref&&Date.parse(x.peerRefExpiresAt)<=Date.now(),busy=state.runningPeer===ref;
        h+='<div class="identity-live-controls"><button type="button" class="btn btn-ghost btn-sm" id="identity-live-peer-'+esc(ref||x.mac)+'"'+(ref?' data-peer-context="'+esc(ref)+'"':'')+(!ref||expired||state.runningPeer||state.running.history||state.running['history-context']?' disabled':'')+'>'+esc(busy?'Inspecting roaming · '+x.mac+'…':'Inspect roaming · '+x.mac)+'</button></div>';
        if(!ref||expired)h+='<p class="ls">'+esc(x.conflict?'Conflicting event identities; candidate cannot be safely inspected.':expired?'Candidate reference expired. Read interval context again.':'Candidate check reference unavailable. Read interval context again.')+'</p>';
        var result=ref&&state.peerResults[ref];if(result){var v=result.evidence||{};h+='<section class="identity-live-result" id="identity-live-peer-result-'+esc(ref)+'" aria-live="polite"><h4 class="identity-evidence-heading">Explicit excluded-peer context · '+esc(x.mac)+'</h4>';
          if(result.error)h+='<p class="note warn" role="status">'+esc(result.error)+'</p>';
          else{h+='<p class="ls">'+esc(v.status)+' · '+esc(historyTime(v.window?.start)+' — '+historyTime(v.window?.end))+' · read '+esc(historyTime(result.completedAt))+'</p><p class="note">Separate on-demand snapshot. Initial exclusions, original assessment and measured peer counts are unchanged.</p>';
            if(v.reason)h+='<p class="note">'+esc(v.reason)+'</p>';(v.peerRoaming?.peers||[]).forEach(function(peer){h+=peerEvidence(peer);});h+='<p class="ls">'+esc(v.requestCount)+' bounded API reads. Missing events remain unknown.</p>';}
          h+='</section>';}
      });h+='</details>';}
    if(!p.peers?.length)h+='<p class="note">No eligible peer transition context was established from returned events. AP event coverage '+esc(c.apEvents?.coverage?.complete?'covers this context window.':'is incomplete; absence is unknown.')+'</p>';
    (p.peers||[]).forEach(function(p){h+=peerEvidence(p);});
    h+='<details class="support-evidence"><summary>Context source coverage and limitations</summary>';
    ['apEvents','clientEvents'].forEach(function(key){h+='<p class="ls">'+esc(key==='apEvents'?'AP event coverage':'Selected-client event coverage')+': '+esc(c[key]?.coverage?.complete?'complete':'incomplete or unavailable')+' · '+esc(c[key]?.records?.length||0)+' events · '+esc(c[key]?.reason||'')+'</p>';});
    (c.limitations||[]).forEach(function(l){h+='<p class="note">'+esc(l)+'</p>';});h+='<p class="ls">'+esc(c.requestCount)+' bounded API reads. Original assessment and thresholds unchanged.</p></details>';
    return h+'</details>';
  }
  function historyText(){
    var r=state.results.history;if(!r)return '';var e=r.evidence||{},a=e.analysis||{},s=e.scope||{};
    return ['NETWORK HISTORY ASSESSMENT','Device: '+group()?.deviceName,'MAC: '+val(s.mac)+' · site: '+val(s.site)+' · AP: '+val(s.apName||s.apSerial)+' · band: '+val(s.band)+' GHz','UTC interval: '+val(e.window?.start)+' through '+val(e.window?.end),'Assessment: '+val(a.verdict||r.error||e.reason),'AP event coverage complete: '+!!e.apEvents?.coverage?.complete,'Client event coverage complete: '+!!e.clientEvents?.coverage?.complete,...(e.peers?.screenedCount!=null?['Peer selection: '+e.peers.screenedCount+' of '+e.peers.candidateCount+' candidates screened; '+e.peers.sampledCount+' cross-band samples; screening '+(e.peers.screeningComplete?'complete':'incomplete')+'.',e.peers.selectionBasis||'',e.peers.screeningStop||'',...(e.peers.followup?['Interval follow-up: '+e.peers.followup.initialMissingIntervals+' initial gaps; '+e.peers.followup.filledIntervals+' filled; '+e.peers.followup.remainingMissingIntervals+' still lack two measured peers.']:[]),...(e.peers.intervalCoverage||[]).filter(function(t){return t.elevated;}).map(function(t){return 'Peer coverage '+t.startTs+' through '+t.endTs+': '+t.initialPeerCount+' initial / '+t.peerCount+' final; '+t.stage+'; '+t.peerMacs.join(', ');})]:[]),...contextText(),'Review rules: '+JSON.stringify(a.rules||{}),...(a.findings||[]).flatMap(function(f){return [f.title+': '+f.detail,'Evidence: '+JSON.stringify(f.evidence),'Next: '+f.next];}),...(a.correlations||[]).slice(0,50).map(function(c){return 'Event '+c.event.occurredAt+' '+c.event.type+' · latency interval '+c.startTs+' through '+c.endTs+' · '+c.relationship;}),...(a.correlations?.length>50?['Correlation export capped at 50 entries; review complete returned evidence in the workspace.']:[]),'Limitations:',...(e.limitations||[]),'Current checks are separate snapshots; IP ownership, endpoint power state and historical cause are not inferred.'].join('\n');
  }
  function historyControls(o){
    var h='<section class="identity-live-result"><h4 class="identity-evidence-heading">Network history & assessment</h4><p class="ls">Read-only Meraki history for the selected source MAC. Choose the site and band; no DHCP lease or active probe is required. The presently reported AP defines the AP history scope.</p>';
    h+='<div class="identity-live-controls">'+select('identity-live-history-site','History site',o.historySites||[],state.historySite,function(s){return s.label;})+select('identity-live-history-band','Radio band',[{key:'2.4',label:'2.4 GHz'},{key:'5',label:'5 GHz'},{key:'6',label:'6 GHz'}],state.historyBand,function(s){return s.label;})+'</div>';
    h+='<div class="identity-live-controls">'+select('identity-live-history-range','Incident window',[{key:'hour',label:'Last hour'},{key:'six',label:'Last six hours'},{key:'custom',label:'Custom interval'}],state.historyRange,function(s){return s.label;})+select('identity-live-history-zone','Display timezone',[{key:'local',label:'Local browser timezone'},{key:'UTC',label:'UTC'}],state.historyTimezone,function(s){return s.label;})+'</div>';
    if(state.historyRange==='custom')h+='<div class="identity-live-controls"><label for="identity-live-history-start">Start · browser local time</label><input class="env-select" style="order:0;flex:1 1 220px;min-width:0;max-width:100%;margin-left:0" type="datetime-local" id="identity-live-history-start" value="'+esc(state.historyStart)+'"><label for="identity-live-history-end">End · browser local time</label><input class="env-select" style="order:0;flex:1 1 220px;min-width:0;max-width:100%;margin-left:0" type="datetime-local" id="identity-live-history-end" value="'+esc(state.historyEnd)+'"></div>';
    h+='<p class="ls">Displayed timezone: '+esc(historyZone())+'. Custom inputs use the browser timezone. Maximum six hours per analysis; seven-day lookback. Eight candidates screened first; up to eight more for elevated-interval peer gaps. All verified same-band readings are used; three clients receive cross-band detail. Up to 60 API reads, two at a time, within 42 seconds; three event pages per scope. Incomplete reads remain visible.</p>';
    h+=button('history','Analyze network history',!o.merakiEligible||!state.historySite||!state.historyBand||!state.historyRange||state.running['history-context']||state.runningPeer);
    return h+'</section>';
  }
  function historyResult(e){
    var s=e.scope||{},a=e.analysis,w=e.window||{},h='<div class="facts">'+factRow('MAC / site',esc(val(s.mac)+' / '+val(s.site)))+factRow('AP / band',esc(val(s.apName||s.apSerial)+' / '+val(s.band)+' GHz'))+factRow('Incident window',esc(historyTime(w.start)+' — '+historyTime(w.end)))+'</div>';
    if(!a)return h+'<p class="note">No assessment established. '+esc(e.reason||'Review source outcomes.')+'</p>';
    h+='<h4 class="identity-evidence-heading">'+esc(a.verdict)+'</h4><p class="ls">'+esc(a.counts.measured)+' measured intervals · '+esc(a.counts.flagged)+' crossed the review threshold · '+esc(a.counts.missing)+' returned intervals without measurements. Missing intervals and gaps do not establish health.</p>';
    h+='<p class="ls">Rules: latency ≥ '+esc(a.rules.highLatencyMs)+' ms; stable peers < '+esc(a.rules.stablePeerMs)+' ms; at least '+esc(a.rules.minIndependentPeers)+' independent peers. Review thresholds, not vendor SLAs or root-cause probabilities.</p>';
    h+=intervalContext(e);
    (a.findings||[]).forEach(function(f){h+='<details class="support-evidence"><summary>'+esc(f.title)+'</summary><p class="note">'+esc(f.detail)+'</p><p class="ls">Evidence: '+esc(JSON.stringify(f.evidence))+'</p><p class="note">Next check: '+esc(f.next)+'</p></details>';});
    h+='<details class="support-evidence"><summary>Latency and event timeline · '+esc(a.timeline.length)+' measured intervals</summary><p class="ls">Events inside each interval are distinguished from nearby events (±15 minutes). AP latency includes this client; it is not independent comparison evidence. Utilization remains a separate ten-minute measurement.</p>';
    h+=rows(['Interval','Client / AP ms','Peer measurements','Pattern','During / nearby events','Utilization / non-Wi-Fi %'],a.timeline,function(t){return [historyTime(t.startTs)+' — '+historyTime(t.endTs),t.latencyMs+' / '+val(t.apBandLatencyMs),'same band '+t.sameBandPeers.length+' · other bands '+t.otherBandPeers.length,t.pattern,t.events.map(function(x){return historyTime(x.occurredAt)+' '+x.type;}).join('; ')+' / nearby '+t.nearbyEvents.length,t.utilization.map(function(x){return historyTime(x.startTs)+' — '+historyTime(x.endTs)+': '+val(x.utilizationTotal)+' / '+val(x.utilizationNon80211);}).join('; ')];});h+='</details>';
    h+='<details class="support-evidence"><summary>Client / AP comparisons · '+esc(e.peers.status)+' · '+(e.peers.sameBandRecords?esc(e.peers.verifiedCount)+' verified same-band candidates · '+esc(e.peers.sampledCount)+' cross-band samples':esc(e.peers.sampledCount)+' sampled of '+esc(e.peers.candidateCount)+' candidate peers')+'</summary><p class="ls">Only overlapping non-null AP- and band-filtered intervals count. Current SSID names do not establish historical SSID membership. Missing peers and unmeasured bands are unknown.</p>';
    if(e.peers.screenedCount!=null)h+='<p class="ls">'+esc(e.peers.screenedCount)+' of '+esc(e.peers.candidateCount)+' candidates screened · limit '+esc(e.peers.screeningLimit)+' · '+esc(e.peers.screeningComplete?'screening complete':'screening incomplete')+'. '+esc(e.peers.selectionBasis||'')+(e.peers.screeningStop?' '+esc(e.peers.screeningStop):'')+'</p>';
    if(e.peers.followup){var f=e.peers.followup;h+='<p class="note">Interval follow-up: '+esc(f.initialMissingIntervals)+' elevated intervals initially lacked two measured peers; '+esc(f.filledIntervals)+' filled; '+esc(f.remainingMissingIntervals)+' still lack two. '+esc(f.reason)+'</p>';
      if(f.window)h+='<p class="ls">Follow-up window: '+esc(historyTime(f.window.start))+' — '+esc(historyTime(f.window.end))+'. Follow-up clients are unobserved outside this range.</p>';
      h+='<details class="support-evidence"><summary>Elevated-interval peer coverage</summary>'+'<p class="ls">Times shown in '+esc(historyZone())+'.</p>'+coverageTable((e.peers.intervalCoverage||[]).filter(function(t){return t.elevated;}))+'</details>';
    }
    h+=rows(['Peer MAC','Reported SSID · current only','Overlapping intervals by band','Same-band intervals'],a.peerGroups,function(p){return [p.mac,p.reportedSsid+(p.crossBandEnriched===false?' · same-band reads only':''),JSON.stringify(p.overlappingMeasuredIntervals),p.sameBand];});
    if(e.peers.screening?.length)h+='<details class="support-evidence"><summary>Candidate screening details</summary>'+rows(['Candidate MAC','Matching same-band intervals','Cross-band sample','Same-band evidence / phase','Read status / coverage'],e.peers.screening,function(p){return [p.mac,p.overlappingMeasuredIntervals,p.selected?'Yes':'No',p.usedForSameBand==null?'Not reported':(p.usedForSameBand?'Used':'No matching measurements')+' · '+val(p.phase),p.status+' · '+val(p.reason)+(p.requestedWindow?' · '+historyTime(p.requestedWindow.start)+' — '+historyTime(p.requestedWindow.end):'')];})+'</details>';
    h+='</details>';
    ['apEvents','clientEvents'].forEach(function(key){var events=e[key];h+='<details class="support-evidence"><summary>'+esc(key==='apEvents'?'AP event log':'Selected-client event log')+' · '+esc(events.status)+' · '+esc(events.records.length)+' events</summary><p class="ls">'+esc(events.coverage.complete?'Provider bounds cover the context window.':'Full context-window coverage not established.')+' '+esc(events.reason)+' Pages: '+esc(events.coverage.pages)+'. Context: '+esc(historyTime(w.contextStart)+' — '+historyTime(w.contextEnd))+'.</p>';
      h+=rows(['Occurred','Type','AP / band','Client MAC','Details'],events.records.slice(0,100),function(r){return [historyTime(r.occurredAt),r.description||r.type,val(r.apSerial)+' / '+val(r.band),r.clientMac,JSON.stringify(r.data)];});if(events.records.length>100)h+='<p class="ls">Table shows the first 100 returned events; assessment uses all returned rows within the stated limits.</p>';h+='</details>';});
    h+='<details class="support-evidence"><summary>Source measurements, coverage and limitations</summary>';
    Object.keys(e.series).forEach(function(k){var x=e.series[k];h+='<details class="support-evidence"><summary>'+esc(k)+' · '+esc(x.status)+' · '+esc(x.measurementCount)+' measured samples</summary><p class="ls">'+esc(x.reason)+(x.coverage?' Measured '+esc(x.coverage.measuredSeconds)+' / '+esc(x.coverage.requestedSeconds)+' requested seconds; '+esc(x.coverage.unmeasuredSeconds)+' seconds without measurements.':'')+'</p>'+rows(['Start','End','Measurements'],x.records||[],function(r){var metrics=Object.assign({},r);delete metrics.startTs;delete metrics.endTs;return [historyTime(r.startTs),historyTime(r.endTs),JSON.stringify(metrics)];})+'</details>';});
    (e.limitations||[]).forEach(function(t){h+='<p class="note">'+esc(t)+'</p>';});h+='<p class="ls">'+esc(e.requestCount)+' bounded API reads. Radio-reset history: unavailable. Spike-specific retry history: unavailable.</p></details>';
    h+='<button type="button" class="btn btn-ghost btn-sm" data-history-copy>Copy network assessment</button> <button type="button" class="btn btn-ghost btn-sm" data-history-download>Download assessment</button><p class="ls" role="status">'+esc(state.historyNotice)+'</p>';
    return h;
  }
  // B3 2026-10-17: where the async clipboard is missing or denied, fall back to execCommand like Copy summary does.
  function copyFallback(text){
    var ta=document.createElement('textarea'),ok=false;ta.value=text;ta.setAttribute('readonly','');ta.style.cssText='position:fixed;top:0;left:-9999px';document.body.appendChild(ta);ta.select();
    try{ok=document.execCommand('copy');}catch(_){}ta.remove();return ok;
  }
  async function copyHistory(download){
    var text=historyText();if(!text)return;var seq=state.sequence,s=state.scope;
    try{if(download){var u=URL.createObjectURL(new Blob([text],{type:'text/plain;charset=utf-8'})),link=document.createElement('a');link.href=u;link.download='network-assessment.txt';document.body.appendChild(link);link.click();link.remove();setTimeout(function(){URL.revokeObjectURL(u);},1000);}
      else{try{if(!navigator.clipboard||!window.isSecureContext)throw Error('clipboard unavailable');await navigator.clipboard.writeText(text);}catch(_){if(!copyFallback(text))throw Error('copy blocked');}}
      if(current(seq,s))state.historyNotice=download?'Assessment downloaded.':'Assessment copied.';}
    catch(_){if(current(seq,s))state.historyNotice=download?'Download unavailable. Use Copy network assessment instead.':'This browser blocked copying. Use Download assessment instead.';}if(current(seq,s))render();
  }
  function result(tool,label){
    var d=state.results[tool];if(!d)return '';
    var h='<section class="identity-live-result"><h4 class="identity-evidence-heading">'+esc(label)+'</h4>';
    if(d.error)return h+'<p class="note warn" role="status">'+esc(d.error)+'</p></section>';
    var e=d.evidence||{},t=d.target||{};
    h+='<p class="ls">'+esc(e.status||'Unknown')+' · started '+esc(d.startedAt)+' · completed '+esc(d.completedAt)+'</p>';
    if(e.reason)h+='<p class="note">'+esc(e.reason)+'</p>';if(e.note)h+='<p class="note">'+esc(e.note)+'</p>';
    if(tool==='history')return h+historyResult(e)+'</section>';
    if(tool==='dhcp'){
      h+='<p class="ls">'+esc(e.basis)+'</p>'+(e.sources||[]).map(function(s){return '<p class="ls">'+esc(s.server)+' · '+esc(s.status)+' · '+esc(s.reason)+'</p>';}).join('');
      h+=rows(['IP / MAC','Hostname / state','DHCP server / scope','Lease expiry'],e.records||[],function(r){return [r.ip+' / '+val(r.mac),r.hostname+' / '+r.state,r.server+' / '+r.scope,r.expiresAt];});
      if(!e.records?.length)h+='<p class="ls">No exact active lease was established from the available responses. Review each server outcome.</p>';
    }else if(tool==='meraki'){
      h+='<p class="ls">Selected MAC: '+esc(t.mac)+' · events and samples: last hour, within stated page limits.</p>';
      (e.records||[]).forEach(function(r){h+='<h4 class="identity-evidence-heading">'+esc(r.site||r.networkId)+' · '+esc(r.status)+'</h4>';if(r.reason)h+='<p class="note">'+esc(r.reason)+'</p>';if(r.client){var c=r.client;h+='<div class="facts">'+factRow('Vendor status',esc(val(c.status)))+factRow('IP / SSID / VLAN',esc(val(c.ip)+' / '+val(c.ssid)+' / '+val(c.vlan)))+factRow('AP / last seen',esc(val(c.apName)+' / '+val(c.lastSeen)))+'</div>';}
        ['events','signal','latency'].forEach(function(key){var s=r[key];if(!s)return;var noMeasurements=s.status==='no_measurements',sampleCount=(s.records||[]).length;
          var count=key==='events'?sampleCount:noMeasurements?sampleCount+' returned samples':s.measurementCount!=null?'Measurements in '+s.measurementCount+' / '+sampleCount+' samples':sampleCount;
          h+='<details class="support-evidence"><summary>'+esc(key)+' · '+esc(noMeasurements?'No measurements':s.status)+' · '+esc(count)+'</summary><p class="ls">'+esc(s.reason)+'</p>';
          h+=key==='events'?rows(['Observed','Event','AP','Detail'],s.records||[],function(v){return [v.occurredAt,v.type,v.apName,v.description];}):key==='signal'?rows(['Through','RSSI / SNR'],s.records||[],function(v){return [v.endTs,val(v.rssi)+' / '+val(v.snr)];}):rows(['Through','Latency (ms)'],s.records||[],function(v){return [v.endTs,v.avgLatencyMs];});h+='</details>';});
      });
      if(!e.records?.length)h+='<p class="ls">No client evidence returned. This does not establish offline state.</p>';
    }else if(tool==='reachability'){
      h+='<p class="ls">IP '+esc(t.ip)+' · '+esc(t.source)+' · identifier observed '+esc(val(t.observedAt))+'</p><p class="note">'+esc(t.basis)+'</p>';
      h+='<div class="facts">'+factRow('ICMP outcome',esc(val(e.icmp?.status)))+factRow('Loss / round-trip',esc(val(e.icmp?.lossPct)+'% / '+val(e.icmp?.rttMs)+' ms'))+'</div>';
      h+=rows(['TCP port','Observed outcome'],e.tcp||[],function(r){return [r.port,r.status==='locally_blocked'?'Locally blocked'+(r.reason?' · '+r.reason:''):r.status];});
    }else if(tool==='firewall'){
      h+='<p class="ls">'+esc(t.firewall)+' · IP '+esc(t.ip)+' · '+esc(t.source)+' · identifier observed '+esc(val(t.observedAt))+'</p><p class="note">'+esc(t.basis)+'</p>';
      if(e.scope?.mode==='exact-ip')h+='<p class="ls">Exact DHCP IP lookup · '+esc(e.scope.matchingReturned)+' matching sessions returned · up to '+esc(e.scope.perDirectionLimit)+' per direction · '+esc(e.scope.complete?'both directional reads complete':'coverage incomplete')+'.</p>';
      (e.sources||[]).forEach(function(s){h+='<p class="ls">'+esc(s.direction)+' · '+esc(s.status)+' · '+esc(s.matchingReturned)+' returned'+(s.reason?' · '+esc(s.reason):'')+'</p>';});
      if(e.scope?.mode==='exact-ip' && !e.records?.length)h+='<p class="ls">'+esc(e.scope.complete?'No matching sessions were returned for this DHCP IP at read time.':'No matching sessions were established; review directional read outcomes.')+'</p>';
      h+=rows(['Source','Destination','Protocol / policy','Direction / egress'],e.records||[],function(r){return [r.sourceIp+':'+val(r.sourcePort),r.destinationIp+':'+val(r.destinationPort),val(r.protocol)+' / '+val(r.policy),r.direction+' / '+val(r.egress)];});
    }else if(tool==='ap-port'){
      h+='<p class="ls">Selected MAC '+esc(t.mac)+' · fresh DHCP IP '+esc(t.ip)+' · lease read '+esc(val(t.observedAt))+'</p>';
      if(e.client)h+='<div class="facts">'+factRow('Wi-Fi / last seen',esc(val(e.client.status)+' / '+val(e.client.lastSeen)))+factRow('SSID',esc(val(e.client.ssid)))+'</div>';
      if(e.ap)h+='<div class="facts">'+factRow('Current AP',esc(val(e.ap.name)+' / '+val(e.ap.serial)))+'</div>';
      if(e.neighbor){var n=e.neighbor;h+='<div class="facts">'+factRow('AP-facing switch / port',esc(n.switch+' / '+n.port))+factRow('VLAN / discovery',esc(n.vlan+' / '+n.protocol))+factRow('VLAN basis',esc(n.vlanBasis))+'</div>';}
      var v=e.verification;
      if(v?.pathVerified && v.values){var a=v.values;h+='<div class="facts">'+factRow('MAC / port verified',esc(t.mac+' / '+a.port))+factRow('Link / admin',esc((a.oper===1?'up':a.oper==null?'Not reported':'state '+a.oper)+' / '+(a.admin===1?'up':a.admin==null?'Not reported':'state '+a.admin)))+factRow('Speed / duplex',esc(val(a.speedMbps)+' Mbps / '+(a.duplex===3?'full':a.duplex===2?'half':'Not reported')))+factRow('Errors in / out / CRC',esc(val(a.inErrors)+' / '+val(a.outErrors)+' / '+val(a.crc)))+factRow('Discards in / out',esc(val(a.inDiscards)+' / '+val(a.outDiscards)))+'</div>';h+='<p class="ls"><a class="btn btn-ghost btn-sm" href="/network-switches.html?switch='+encodeURIComponent(v.switchIp)+'">Open verified switch</a></p>';}
      if(e.note)h+='<p class="note">'+esc(e.note)+'</p>';
    }else if(tool==='switch'){
      h+='<p class="ls">'+esc(t.switch||t.switch_ip)+' · '+esc(t.port)+' · VLAN '+esc(t.vlan)+' · cached role '+esc(t.role)+' · cached at '+esc(val(t.observedAt))+'</p>';
      if(e.values)h+='<div class="facts">'+Object.keys(e.values).map(function(k){return factRow(esc(k),esc(val(e.values[k])));}).join('')+'</div>';
      if(e.observedIfindex!=null)h+='<p class="note">Observed interface index: '+esc(e.observedIfindex)+'. No other port was selected.</p>';
    }
    return h+'</section>';
  }
  function html(){
    if(!group())return '<p class="note">Choose an assigned device first.</p>';
    var h='<p class="ls">Selected device: <strong>'+esc(group().deviceName)+'</strong>.</p><p class="ls">These checks run only when you choose a target and press its button. They preserve the selected device and source interface. Existing account checks remain person-scoped.</p>';
    h+='<button class="btn btn-ghost btn-sm" type="button" data-live-options'+(state.loading?' disabled':'')+'>Refresh check options</button>';
    if(state.loading)h+='<p class="note" role="status">Reading available source targets; no live checks are running.</p>';
    if(state.error)h+='<p class="note warn" role="status">'+esc(state.error)+'</p>';
    var o=state.options;if(!o)return h;h+='<p class="ls">Selected source MAC: '+esc(o.selectedMac||'No MAC selected')+'.</p>';
    h+='<p class="note">Recorded IPs can be reassigned. Choose a freshly read DHCP lease when available. A response to an IP does not verify which device owns it.</p>';
    h+='<div class="identity-live-controls">'+select('identity-live-dhcp','Exact DHCP identifier',o.dhcpQueries,state.queryKey,function(q){return q.label;})+button('dhcp','Read exact DHCP',!state.queryKey)+'</div>';
    h+='<div class="identity-live-controls">'+button('meraki','Read Meraki client & Wi-Fi',!o.merakiEligible)+'<span class="ls">'+esc(o.merakiEligible?'Uses only the selected source MAC.':'Select a source MAC above for Meraki and switch checks.')+'</span></div>';
    h+='<div class="identity-live-controls">'+select('identity-live-target','IP target',o.ipTargets.concat(state.leases),state.targetKey,function(t){return t.ip+' · '+t.source+' · '+val(t.observedAt);})+button('reachability','Probe IP (ICMP / TCP)',!state.targetKey)+'</div>';
    var firewallTarget=o.ipTargets.concat(state.leases).find(function(t){return t.key===state.targetKey;});
    h+='<div class="identity-live-controls">'+select('identity-live-firewall','Firewall site',o.firewalls,state.firewall,function(f){return f.label;})+button('firewall','Read firewall sessions',!firewallTarget?.firewallEligible||!state.firewall)+'</div>';
    h+='<p class="ls">Firewall sessions require a fresh exact-MAC DHCP lease. Read DHCP, then select its IP and firewall site.</p>';
    h+='<div class="identity-live-controls">'+button('ap-port','Find & verify current AP port',!o.currentApPortEligible||!firewallTarget?.firewallEligible||state.targetKey.indexOf('lease:')!==0)+'</div>';
    h+='<p class="ls">Current AP discovery uses the selected MAC and fresh exact-MAC DHCP IP, then verifies the AP-facing switch port with SNMP. Read DHCP and select its IP first.</p>';
    h+='<div class="identity-live-controls">'+select('identity-live-port','Cached switch port to verify',o.switchPorts,state.portKey,function(p){return (p.switch||p.switch_ip)+' · '+p.port+' · VLAN '+p.vlan+' · '+p.role;})+button('switch','Verify MAC & port (SNMP)',!state.portKey)+'</div>';
    if(o.cacheStatus && ['unavailable','partial'].includes(o.cacheStatus.locations))h+='<p class="note warn">Cached port choices are '+esc(o.cacheStatus.locations)+'. Cached-port verification uses only the chosen observation.</p>';
    return h+result('dhcp','Exact DHCP results')+result('meraki','Selected-MAC Meraki evidence')+result('reachability','Selected-IP reachability')+result('firewall','Selected-site firewall sessions')+result('ap-port','Current AP switch port verification')+result('switch','Selected-switch live port verification')+historyControls(o)+result('history','Network history assessment');
  }
  function placeholder(){return panel('Selected device · explicit network checks','Exact DHCP, Meraki, firewall and active probes. Source selection is required; loading this page runs none of these checks.','<div class="identity-live-panel" id="identity-live-checks" tabindex="-1">'+html()+'</div>').replace('<section class="panel">','<section class="panel identity-live-anchor">');}
  function render(){var id=document.activeElement?.id;document.querySelectorAll('.identity-live-panel').forEach(function(el){el.innerHTML=html();});if(id?.indexOf('identity-live-')===0)document.getElementById(id)?.focus();}
  function summaryLines(){
    if(!group()||!Object.keys(state.results).length)return [];
    var out=['','SELECTED DEVICE NETWORK · EXPLICIT CHECKS','  Device key: '+group().deviceKey,'  Source interface: '+(interfaceKey()||'No MAC interface selected')];
    Object.keys(state.results).forEach(function(tool){if(tool==='history-context')return;var r=state.results[tool];out.push('  '+tool+': '+(r.error||r.evidence?.status||'unknown'));if(r.error)return;out.push('  Started: '+r.startedAt+' · completed: '+r.completedAt,'  Target: '+JSON.stringify(r.target));
      // Keep ticket summaries bounded even when the provider returned many events.
      var e=r.evidence||{};if(tool==='history'){var text=historyText();out.push(text.slice(0,20000));if(text.length>20000)out.push('History case summary capped at 20000 characters; download the assessment for more detail.');return;}out.push('  Evidence: '+JSON.stringify(e).slice(0,6000));if(JSON.stringify(e).length>6000)out.push('  Summary evidence text capped at 6000 characters; review the workspace for complete returned rows.');});
    out.push('  IP ownership is not established by a probe or session; no response is not an offline determination.');return out;
  }
  document.addEventListener('change',function(e){var fields={'identity-live-dhcp':'queryKey','identity-live-target':'targetKey','identity-live-port':'portKey','identity-live-firewall':'firewall','identity-live-history-site':'historySite','identity-live-history-band':'historyBand','identity-live-history-range':'historyRange','identity-live-history-start':'historyStart','identity-live-history-end':'historyEnd','identity-live-context-interval':'intervalKey'};if(e.target.id==='identity-live-history-zone'){state.historyTimezone=e.target.value;render();return;}if(fields[e.target.id])change(fields[e.target.id],e.target.value);});
  document.addEventListener('click',function(e){var peerButton=e.target.closest('[data-peer-context]');if(peerButton)inspectPeer(peerButton.getAttribute('data-peer-context'));if(e.target.closest('[data-history-copy]'))copyHistory(false);if(e.target.closest('[data-history-download]'))copyHistory(true);});
  document.addEventListener('click',function(e){var b=e.target.closest('[data-device-check]');if(b)run(b.getAttribute('data-device-check'));if(e.target.closest('[data-live-open]')){var panel=document.getElementById('identity-live-checks');panel?.closest('.panel')?.scrollIntoView({block:'start'});panel?.focus({preventScroll:true});}if(e.target.closest('[data-live-options]')){reset();state.scope=scope();load();}});
  window.IdentityDeviceLive={contextChanged:contextChanged,reset:reset,placeholder:placeholder,render:render,summaryLines:summaryLines,historyText:historyText,getState:function(){return state;}};
})();
