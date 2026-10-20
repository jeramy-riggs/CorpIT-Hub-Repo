'use strict';
const measured=v=>typeof v==='number'&&Number.isFinite(v)&&v>=0;
const key=r=>r.startTs+'|'+r.endTs;
function combinePeers(cross=[],same=[],selectedMac,band,selectedId){
 const byMac=new Map(),conflicts=new Set(),ids=new Map();
 for(const [records,isCross] of [[cross,true],[same,false]])for(const p of records){
  if(!p?.mac||p.mac===selectedMac||p.clientId&&p.clientId===selectedId)continue;
  const old=byMac.get(p.mac);
  if(old?.clientId&&p.clientId&&old.clientId!==p.clientId){conflicts.add(p.mac);continue;}
  if(p.clientId){if(!ids.has(p.clientId))ids.set(p.clientId,new Set());ids.get(p.clientId).add(p.mac);}
  const series=isCross?p.series||{}:p.series?.[band]?{[band]:p.series[band]}:{};
  byMac.set(p.mac,{...old,...p,series:{...old?.series,...series},status:old?.status==='partial'||p.status==='partial'?'partial':p.status,crossBandEnriched:!!old?.crossBandEnriched||isCross});
 }
 for(const macs of ids.values())if(macs.size>1)for(const mac of macs)conflicts.add(mac);
 return [...byMac.values()].filter(p=>!conflicts.has(p.mac));
}
function coverage(selected,peers,band,highMs=100){
 const maps=peers.map(p=>({mac:p.mac,rows:new Set((p.series?.[band]?.records||[]).filter(r=>measured(r.avgLatencyMs)).map(key))}));
 return selected.filter(r=>measured(r.avgLatencyMs)).map(r=>{
  const peerMacs=[...new Set(maps.filter(p=>p.rows.has(key(r))).map(p=>p.mac))];
  return {startTs:r.startTs,endTs:r.endTs,latencyMs:r.avgLatencyMs,elevated:r.avgLatencyMs>=highMs,peerCount:peerMacs.length,peerMacs,missingPeers:Math.max(0,2-peerMacs.length)};
 });
}
function chooseCrossBand(selected,peers,band,limit=3,highMs=100){
 const sorted=peers.slice().sort((a,b)=>(b.overlapCount||0)-(a.overlapCount||0)||Number(!!b.clientId)-Number(!!a.clientId)||a.mac.localeCompare(b.mac));
 if(sorted.length<=limit)return sorted;
 const keys=selected.filter(r=>measured(r.avgLatencyMs)).map(r=>({key:key(r),elevated:r.avgLatencyMs>=highMs}));
 const masks=sorted.map(p=>new Set((p.series?.[band]?.records||[]).filter(r=>measured(r.avgLatencyMs)).map(key)));
 let best=[],bestScore=null;
 function consider(indices){
  let spikeTwo=0,spikeOne=0,allTwo=0,total=0;
  for(const row of keys){const count=indices.reduce((n,i)=>n+Number(masks[i].has(row.key)),0);total+=count;if(count>=2)allTwo++;if(row.elevated){if(count>=2)spikeTwo++;if(count)spikeOne++;}}
  const score=[spikeTwo,spikeOne,allTwo,total];let better=!bestScore;
  if(bestScore)for(let i=0;i<score.length;i++){if(score[i]!==bestScore[i]){better=score[i]>bestScore[i];break;}}
  if(better){best=indices.slice();bestScore=score;}
 }
 function walk(indices,start){if(indices.length===limit){consider(indices);return;}for(let i=start;i<=sorted.length-(limit-indices.length);i++)walk([...indices,i],i+1);}
 walk([],0);return best.map(i=>sorted[i]);
}
module.exports={combinePeers,coverage,chooseCrossBand};
