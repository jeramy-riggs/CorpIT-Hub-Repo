'use strict';
require('dotenv').config({quiet:true});
const mysql=require('mysql2/promise');
const pool=mysql.createPool({host:process.env.DB_HOST,port:Number(process.env.DB_PORT)||3306,user:process.env.DB_USER,password:process.env.DB_PASSWORD,database:process.env.DB_NAME,connectionLimit:4,charset:'utf8mb4'});
const refresh=require('./ai-governance-refresh'),metrics=require('./ai-governance-metrics'),service=refresh({pool}),portal=require('./ai-governance-portal')({pool});const enrich=require('./ai-governance-use-case-enrich');const ssoScan=require('./ai-governance-sso-scan');const autoAdd=require('./ai-governance-auto-add');let running=false,stopping=false;
async function tick(){if(running||stopping)return;running=true;try{await metrics.captureDaily(pool).catch(e=>console.error('[ai-governance-quality]',e.code||e.name));await service.tick();await portal.run().catch(e=>console.error('[ai-governance-portal]',e.code||e.name));await enrich.scheduled(pool).catch(e=>console.error('[ai-governance-use-case-enrich]',e.code||e.name));await autoAdd.scheduled(pool).catch(e=>console.error('[ai-governance-auto-add]',e.code||e.name));await ssoScan.scheduled(pool).catch(e=>console.error('[ai-governance-sso-scan]',e.code||e.name));}catch(e){console.error('[ai-governance-refresh-worker]',e.code||e.name);}finally{running=false;if(stopping)await shutdown();}}
// AI-GOVERNANCE PORTAL SYNC 2026-10-15: portal.run() is a no-op until a super admin saves the Portal token and
// enables the hourly sync in subadmin Settings; it then pulls the AIA feed and pushes the at-a-glance summary.
// AI USE-CASE ENRICHMENT 2026-10-20: enrich.scheduled() proposes use-case values from the hourly
// snapshots at most once an hour (no Access Portal intake; that needs a reviewer's session).
// AI SSO SCAN 2026-10-28: ssoScan.scheduled() reads the sign-on mode of linked Entra / Okta apps at most
// once an hour; SAML / OIDC instances fill the risk assessment's "Okta / SSO used?".
// AI AUTO-ADD 2026-10-28: autoAdd.scheduled() adds a known AI app (vendor reference / Entra candidate)
// for review once Zscaler Shadow IT shows traffic for it; runs before the SSO scan.
// Heartbeat is separate from collection duration; scheduler health is not a
// claim that a vendor read succeeded. Config/run rows carry the actual result.
const heartbeat=setInterval(()=>{pool.query('INSERT INTO ai_governance_refresh_worker(id,last_seen_at) VALUES(1,UTC_TIMESTAMP(3)) ON DUPLICATE KEY UPDATE last_seen_at=VALUES(last_seen_at)').catch(()=>{});},30000);
// Re-arm on each clock-minute boundary instead of drifting from process start.
let timer;function arm(){if(stopping)return;timer=setTimeout(async()=>{await tick();arm();},refresh.nextMinuteDelay());}
tick();arm();
async function shutdown(){clearTimeout(timer);clearInterval(heartbeat);await pool.end();const e=require.cache[require.resolve('./entra-sync')];if(e?.exports.db)await e.exports.db.end();process.exit(0);}
process.on('SIGINT',()=>{stopping=true;if(!running)shutdown();});process.on('SIGTERM',()=>{stopping=true;if(!running)shutdown();});
