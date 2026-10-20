'use strict';
// Bounded, read-only federation of existing stores. Audit before any personal read.
const obs = require('./obs-lib');
const EMAIL = /^[^\s@<>"'(),;:]{1,64}@[a-z0-9.-]{1,190}\.[a-z]{2,}$/i;
const LIMIT = 500;
function iso(v) { return v instanceof Date ? v.toISOString() : String(v || '').replace(' ', 'T').replace(/(?<!Z)$/, 'Z'); }
function outcome(status) { return status >= 400 ? 'error' : 'info'; }
function clean(v) { return obs.clip(obs.scrubText(String(v || '')), 400); }
// settingsfold W6 follow-up 2026-10-12: settings saves carry their change detail.
// Only these actions' details column is ever selected (CASE in SQL, checked again
// here). settings-audit.js already redacted secrets at write time; this reader
// trusts nothing: it keeps ONLY {route, fields, changes, partial}, drops every
// other key, drops any value that is not the expected scalar shape, masks any
// credential-looking key as "(changed)" and hides any value that looks like a
// URL or credential. Emails, GUIDs and long hex are then masked by clean-style scrubbing.
const SETTINGS_ACTIONS = ['settings_saved', 'settings_deleted', 'settings_test_sent', 'settings_test_failed'];
const SETTINGS_SECRET_KEY = /(token|secret|password|passwd|pwd|api[_-]?key|private[_-]?key|webhook|credential|bearer|cookie|config_json|mention_config|auth|key$)/i;
const SETTINGS_MARKS = ['(set)', '(changed)', '(cleared)'];
const SETTINGS_ROUTE = /^(GET|POST|PUT|PATCH|DELETE) \/api\/[A-Za-z0-9_\/:.-]{1,160}$/;
const SETTINGS_NAME = /^[A-Za-z0-9_.-]{1,64}$/;
const SETTINGS_HIDE = /:\/\/|bearer|token|secret|passw|sig=|key=|webhook/i;
const SETTINGS_MAX = 30;
function settingsValue(v) {
  if (v === null || v === undefined || v === '') return '(empty)';
  if (typeof v === 'boolean' || (typeof v === 'number' && Number.isFinite(v))) return String(v);
  if (typeof v !== 'string') return null;                       // objects, arrays: not the shape
  if (SETTINGS_HIDE.test(v)) return '(hidden)';
  const s = v.replace(/\s+/g, ' ');
  return s.length > 60 ? s.slice(0, 60) + '…' : s;
}
function settingsDetail(action, raw) {
  if (SETTINGS_ACTIONS.indexOf(action) < 0 || raw === null || raw === undefined) return '';
  let d = raw;
  if (typeof d === 'string') { try { d = JSON.parse(d); } catch (e) { return ''; } }
  if (!d || typeof d !== 'object' || Array.isArray(d)) return '';
  const out = [];
  if (typeof d.route === 'string' && SETTINGS_ROUTE.test(d.route)) out.push(d.route);
  const ch = d.changes && typeof d.changes === 'object' && !Array.isArray(d.changes) ? d.changes : null;
  const parts = [];
  let extra = 0;
  if (ch) for (const k of Object.keys(ch)) {
    if (!SETTINGS_NAME.test(k)) continue;
    const c = ch[k];
    let txt = null;
    if (SETTINGS_SECRET_KEY.test(k)) txt = '(changed)';
    else if (typeof c === 'string') txt = SETTINGS_MARKS.indexOf(c) >= 0 ? c : null;
    else if (c && typeof c === 'object' && !Array.isArray(c) && Object.keys(c).every(x => x === 'from' || x === 'to')) {
      const f = settingsValue(c.from), t = settingsValue(c.to);
      if (f !== null && t !== null) txt = f + ' → ' + t;
    }
    if (txt === null) continue;
    if (parts.length >= SETTINGS_MAX) { extra++; continue; }
    parts.push(k + ': ' + txt);
  }
  if (parts.length) out.push('Changed ' + parts.join('; ') + (extra ? '; +' + extra + ' more' : ''));
  else if (Array.isArray(d.fields)) {
    const f = d.fields.filter(x => typeof x === 'string' && SETTINGS_NAME.test(x));
    if (f.length) out.push('Fields: ' + f.slice(0, SETTINGS_MAX).join(', ') + (f.length > SETTINGS_MAX ? ', +' + (f.length - SETTINGS_MAX) + ' more' : ''));
  }
  if (d.partial === true) out.push('partial save');
  return out.join(' · ');
}
function accessDetail(r) {
  const base = clean(r.target_page_key);
  const s = settingsDetail(r.action, r.settings_details);
  return s ? base + ' · ' + obs.clip(obs.scrubText(s), 800) : base;
}
function register({router, pool, rbac, portalCall}) {
  router.get('/activity', rbac.requireSuperAdmin, async function(req, res) {
    res.set('Cache-Control', 'no-store, private');
    const email = String(req.query.email || '').trim().toLowerCase();
    if (!EMAIL.test(email)) return res.status(400).json({ok:false,error:'Enter a full email address or UPN.'});
    const days = Math.max(1, Math.min(90, parseInt(req.query.days,10) || 30));
    try {
      await pool.execute('INSERT INTO rbac_audit_log (actor_email,action,target_email,target_page_key,details) VALUES (?,?,?,?,?)',
        [req.user.email,'user_activity_lookup',email,'health-center',JSON.stringify({days,sources:['portal','portal_audit','api','browser','dependencies','access_audit']})]);
    } catch(e) { return res.status(503).json({ok:false,error:'The audit service could not record this lookup. No personal activity was read.'}); }
    const actor = obs.actorKey(email);
    const sources = [], events = []; let visits = [];
    async function source(id, label, read, map, note) {
      try {
        const rows = await read();
        const truncated = rows.length > LIMIT;
        rows.slice(0,LIMIT).forEach(r=>events.push(Object.assign({source:id,source_label:label},map(r))));
        sources.push({id,label,state:'available',count:Math.min(rows.length,LIMIT),truncated,note});
      } catch(e) { sources.push({id,label,state:'unavailable',count:null,note:'This source could not be read. Other sources are still shown.'}); }
    }
    async function query(sql, args) { const [rows]=await pool.execute({sql,timeout:12000},args);return rows; }
    const sampledNote='Errors and slow requests retained; routine successes sampled. Retention '+obs.CFG.retentionDays+' days. Older rows may have no request ID.';
    const tasks = [
      (async()=>{try{const d=await portalCall('/internal/journey/person',{email,days},18000);visits=d.visits||[];sources.push({id:'portal',label:'Portal visits',state:'available',count:visits.reduce((n,v)=>n+v.events.length,0),truncated:!!d.truncated,note:'90-day history. Browser-reported events are distinct from server evidence; pre-sign-in events share a visit, not a verified identity.'});}catch(e){sources.push({id:'portal',label:'Portal visits',state:'unavailable',count:null,note:'Portal visit history could not be read.'});}})(),
      source('portal_audit','Portal audit',async()=>{const d=await portalCall('/internal/activity/person',{email,days},18000);return d.events;},r=>r,'Recorded actors and request subjects are distinguished; free-text notes and form contents are excluded.'),
      source('access_audit','Access audit',()=>query('SELECT id,created_at,actor_email,target_email,action,target_page_key,CASE WHEN action IN ('+SETTINGS_ACTIONS.map(()=>'?').join(',')+') THEN details END AS settings_details FROM rbac_audit_log WHERE created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? DAY) AND (actor_email=? OR target_email=?) ORDER BY created_at DESC,id DESC LIMIT 501',SETTINGS_ACTIONS.concat([days,email,email])),r=>({id:'access-'+r.id,ts:iso(r.created_at),event:r.action,summary:r.action.replace(/[_-]/g,' '),detail:accessDetail(r),relationship:String(r.actor_email).toLowerCase()===email?'Recorded actor':'Affected person',severity:/denied|fail|reject/i.test(r.action)?'error':'info'}),'Lookup and policy audit metadata. For settings saves, the route and changed fields, with credential values masked; no other audit details.'),
    ];
    if (actor) {
      tasks.push(source('api','API requests',()=>query('SELECT id,at,app,method,route,status,duration_ms,err,sampled,request_id FROM obs_request WHERE actor_key=? AND at>=DATE_SUB(UTC_TIMESTAMP(),INTERVAL ? DAY) ORDER BY at DESC,id DESC LIMIT 501',[actor,days]),r=>({id:'api-'+r.id,ts:iso(r.at),event:'api_request',summary:r.method+' '+clean(r.route),detail:clean(r.err),service:r.app,status:r.status,duration_ms:r.duration_ms,request_id:r.request_id,relationship:'Authenticated actor',severity:outcome(r.status),sampled:!!r.sampled}),sampledNote));
      tasks.push(source('browser','Browser diagnostics',()=>query('SELECT id,occurred_at,kind,severity,page,app_key,widget,message,http_status,duration_ms,request_id FROM obs_client_event WHERE actor_key=? AND occurred_at>=DATE_SUB(UTC_TIMESTAMP(),INTERVAL ? DAY) ORDER BY occurred_at DESC,id DESC LIMIT 501',[actor,days]),r=>({id:'browser-'+r.id,ts:iso(r.occurred_at),event:r.kind,summary:clean(r.message),detail:clean(r.page)+' '+clean(r.widget),service:r.app_key,status:r.http_status,duration_ms:r.duration_ms,request_id:r.request_id,relationship:'Browser report',severity:r.severity}), 'Authenticated identity; event content and request IDs are browser-reported, not proof of a server outcome. Retention '+obs.CFG.retentionDays+' days.'));
      tasks.push(source('dependencies','Upstream calls',()=>query('SELECT id,at,app,vendor,operation,method,path,status,ok,duration_ms,err,request_id FROM obs_dependency WHERE actor_key=? AND at>=DATE_SUB(UTC_TIMESTAMP(),INTERVAL ? DAY) ORDER BY at DESC,id DESC LIMIT 501',[actor,days]),r=>({id:'dependency-'+r.id,ts:iso(r.at),event:'dependency',summary:r.vendor+' · '+clean(r.operation || (r.method+' '+r.path)),detail:clean(r.err),service:r.app,status:r.status,duration_ms:r.duration_ms,request_id:r.request_id,relationship:'Server request context',severity:r.ok?'info':'error'}),'Person correlation begins with this release. Background jobs and uninstrumented HTTP clients are not attributed to a person. Retention '+obs.CFG.retentionDays+' days.'));
    } else {
      ['api','browser','dependencies'].forEach(id=>sources.push({id,label:{api:'API requests',browser:'Browser diagnostics',dependencies:'Upstream calls'}[id],state:'unavailable',count:null,note:'The protected identity key is unavailable.'}));
    }
    await Promise.all(tasks);
    events.sort((a,b)=>b.ts.localeCompare(a.ts));
    return res.json({ok:true,data:{email,days,events,visits,sources,generated_at:new Date().toISOString()}});
  });
}
module.exports={register,iso,settingsDetail};
