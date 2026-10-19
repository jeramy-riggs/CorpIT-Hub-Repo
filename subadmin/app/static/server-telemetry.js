/* Read-only, allowlisted projection of existing health payloads. No credentials,
   personal identities, database paths or arbitrary log bodies cross the frame. */
(function(){'use strict';
function number(v){return typeof v==='number'&&Number.isFinite(v)?v:null;}
function text(v){return typeof v==='string'?v.slice(0,240):null;}
function pick(o,keys){var v={};keys.forEach(function(k){var x=o&&o[k];if(typeof x==='string')v[k]=text(x);else if(typeof x==='number')v[k]=number(x);else if(typeof x==='boolean'||x===null)v[k]=x;});return v;}
function list(v,map,cap){return Array.isArray(v)?v.slice(0,cap||200).map(map):[];}
function project(id,d){
 if(!d||typeof d!=='object'||d.ok===false)return null;
 if(id==='signin-service')return pick(d,['status','timestamp']);
 if(id==='servers')return {servers:list(d.servers,function(s){var r=pick(s,['id','hostname','friendlyName','environment','role','isLocal','monitoringEnabled','health','lastCheckIn','uptimeSec','pendingReboot']);r.cpu=pick(s.cpu,['busyPct','state']);r.memory=pick(s.memory,['usedPct','state']);r.disk=pick(s.disk,['usedPct','state','usedBytes','totalBytes']);r.backup=pick(s.backup,['state','latestAgeHours']);r.dataAvailability=pick(s.dataAvailability,['metrics','reachability']);return r;},60)};
 if(id==='pm2')return {processes:list(d.processes,function(p){return pick(p,['name','pmId','status','state','uptimeMs','restarts','unstableRestarts','cpu','memBytes']);}),state:text(d.state)};
 if(id==='observe'){return {hours:number(d.hours),requests:pick(d.requests,['total','e4','e5','aborted','sampled','slowest','note']),dependencies:pick(d.dependencies,['failed','total','vendors']),jobs:{state:text(d.jobs&&d.jobs.state),declared:number(d.jobs&&d.jobs.declared),counts:pick(d.jobs&&d.jobs.counts,['ok','failed','never','stuck','unscheduled','unknown'])},pipeline:pick(d.pipeline,['enabled','buffersMeasured','lastHeartbeatAt','ingestDropped'])};}
 if(id==='database')return {analyzedAt:text(d.analyzedAt),mysql:list(d.mysql,function(x){return pick(x,['table_name','total_mb','free_mb','table_rows','engine']);}),mysqlError:!!d.mysqlError,sqlite:list(d.sqlite,function(x){return pick(x,['name','ok','totalMb','freeMb','checkedAt']);},60)};
 if(id==='backup-details')return {state:text(d.state),nightly:Object.assign(pick(d.nightly,['exists','count','totalBytes','latestAgeHours']),{latest:pick(d.nightly&&d.nightly.latest,['name','sizeBytes','mtime'])}),lastRun:pick(d.lastRun,['status','startedAt','finishedAt','at','failed','failures']),restoreVerifiedAt:text(d.restoreVerifiedAt)};
 if(id==='request-log')return {hours:number(d.hours),recentFailuresTotal:number(d.recentFailuresTotal),truncated:!!d.truncated,routes:list(d.routes,function(x){var r=pick(x,['app','method','n','e5','e4','aborted','avg_ms','max_ms','last_seen']);r.route=text(x.route)&&x.route.split('?')[0].slice(0,180);return r;}),recentFailures:list(d.recentFailures,function(x){var r=pick(x,['at','app','method','status','duration_ms']);r.route=text(x.route)&&x.route.split('?')[0].slice(0,180);return r;},100)};
 if(id==='jobs-detail')return {jobs:list(d.jobs,function(x){return pick(x,['id','name','friendlyName','key','health','state','status','lastRun','last_run','lastSuccess','schedule','enabled','source','durationSec']);})};
 return null;
}
window.ServerTelemetry={project:project};
})();
