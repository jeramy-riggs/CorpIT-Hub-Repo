'use strict';
const express = require('express');
const router  = express.Router();

const mysql      = require('mysql2/promise');
const createRbac = require('./rbac-middleware');
const rbacPool   = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER, password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME, waitForConnections: true, connectionLimit: 5,
});
const rbac = createRbac(rbacPool);
router.use(rbac.loadCurrentUser);

const TENANT_ID     = process.env.SP_TENANT_ID;
const CLIENT_ID     = process.env.SP_CLIENT_ID;
const CLIENT_SECRET = process.env.SP_CLIENT_SECRET;
const GRAPH         = 'https://graph.microsoft.com/v1.0';
const TOKEN_URL     = `https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token`;

let _graphToken = null, _graphExpiry = 0;
let _mgmtToken  = null, _mgmtExpiry  = 0;

async function getGraphToken() {
  if (_graphToken && Date.now() < _graphExpiry - 60000) return _graphToken;
  const body = new URLSearchParams({ grant_type:'client_credentials', client_id:CLIENT_ID, client_secret:CLIENT_SECRET, scope:'https://graph.microsoft.com/.default' });
  const res  = await fetch(TOKEN_URL, { method:'POST', body, headers:{'Content-Type':'application/x-www-form-urlencoded'} });
  const data = await res.json();
  if (!data.access_token) throw new Error('Graph token: ' + JSON.stringify(data));
  _graphToken = data.access_token; _graphExpiry = Date.now() + (data.expires_in||3600)*1000;
  return _graphToken;
}

async function getMgmtToken() {
  if (_mgmtToken && Date.now() < _mgmtExpiry - 60000) return _mgmtToken;
  const body = new URLSearchParams({ grant_type:'client_credentials', client_id:CLIENT_ID, client_secret:CLIENT_SECRET, scope:'https://manage.office.com/.default' });
  const res  = await fetch(TOKEN_URL, { method:'POST', body, headers:{'Content-Type':'application/x-www-form-urlencoded'} });
  const data = await res.json();
  if (!data.access_token) throw new Error('Mgmt token: ' + JSON.stringify(data));
  _mgmtToken = data.access_token; _mgmtExpiry = Date.now() + (data.expires_in||3600)*1000;
  return _mgmtToken;
}

async function gFetch(url) {
  const token = await getGraphToken();
  const res   = await fetch(url, { headers:{ Authorization:`Bearer ${token}` } });
  if (!res.ok) { const t = await res.text().catch(()=>''); throw new Error(`Graph ${res.status} ${url.slice(0,100)} ${t.slice(0,200)}`); }
  return res.json();
}

function resolvePolicy(policyName, ruleName) {
  const p = (policyName||'').toLowerCase();
  const r = (ruleName||'').toLowerCase();
  const combined = p + ' ' + r;
  if (combined.includes('alnum') || combined.includes('alphanumeric') || combined.includes('alnum-002')) {
    return { rule:'rule_2', label:'Loan# Alphanumeric', policy:'SP-DLP-LOAN-ALNUM-002' };
  }
  return { rule:'rule_1', label:'Loan# Numeric', policy:'SP-DLP-LOAN-NUM-001' };
}

function deriveSeverity(n) {
  return n >= 50 ? 'critical' : n >= 10 ? 'high' : n >= 3 ? 'medium' : 'low';
}

function guidToBytes(guid) {
  const hex = guid.replace(/-/g,'');
  const buf = Buffer.from(hex, 'hex');
  const out = Buffer.alloc(16);
  out[0]=buf[3];out[1]=buf[2];out[2]=buf[1];out[3]=buf[0];
  out[4]=buf[5];out[5]=buf[4];
  out[6]=buf[7];out[7]=buf[6];
  buf.copy(out,8,8,16);
  return out;
}
function driveIdFromFileId(rawFileId) {
  if (!rawFileId || !rawFileId.startsWith('SPO_')) return null;
  try {
    const parts = rawFileId.replace('SPO_','').split('_');
    const decoded = Buffer.from(parts[0],'base64').toString('utf8').split(',');
    if (decoded.length !== 3) return null;
    const [siteCollGuid, webGuid, driveGuid] = decoded;
    const combined = Buffer.concat([guidToBytes(siteCollGuid), guidToBytes(webGuid), guidToBytes(driveGuid)]);
    return 'b!' + combined.toString('base64url');
  } catch(e) { return null; }
}
async function resolveFileMeta(siteUrl, fileUrl, siteGuid, fileId, rawFileId) {
  try {
    const driveId = driveIdFromFileId(rawFileId);
    if (!driveId) throw new Error('Cannot construct driveId from FileID');
    const item = await gFetch(`${GRAPH}/drives/${driveId}/items/${fileId}?$expand=permissions`);
    const perms    = item.permissions || [];
    let sharingScope = 'restricted';
    const sharingLinks = [];
    for (const p of perms) {
      const lt = p.link?.scope || '';
      if (lt === 'anonymous') { sharingScope = 'anyone'; sharingLinks.push({ type: 'Anyone with the link', role: p.roles?.[0] || 'read' }); }
      else if (lt === 'organization' && sharingScope !== 'anyone') { sharingScope = 'org'; sharingLinks.push({ type: 'People in your organization', role: p.roles?.[0] || 'read' }); }
      else if (p.grantedTo || p.grantedToV2) {
        const who = p.grantedTo?.user?.displayName || p.grantedToV2?.user?.displayName || p.grantedTo?.user?.email || '—';
        sharingLinks.push({ type: 'direct', user: who, role: p.roles?.[0] || 'read' });
      }
    }
    console.log('[DLP] resolveFileMeta OK:', item.name, '| sharing:', sharingScope);
    return {
      owner:         item.createdBy?.user?.email || '—',
      modified_by:   item.lastModifiedBy?.user?.email || item.lastModifiedBy?.user?.displayName || '—',
      modified_date: item.lastModifiedDateTime || null,
      created_date:  item.createdDateTime || null,
      file_path:     item.parentReference?.path ? `${item.parentReference.path}/${item.name}` : fileUrl,
      sharing_scope: sharingScope,
      sharing_links: sharingLinks,
    };
  } catch(e) {
    console.warn('[DLP] resolveFileMeta failed:', e.message);
    return { owner:'—', modified_by:'—', modified_date:null, created_date:null, file_path:fileUrl, sharing_scope:'unknown', sharing_links:[] };
  }
}

async function ensureSubscription() {
  try {
    const token = await getMgmtToken();
    const base  = `https://manage.office.com/api/v1.0/${TENANT_ID}/activity/feed/subscriptions`;
    const hdrs  = { Authorization:`Bearer ${token}`, 'Content-Type':'application/json' };
    // /start on a content type that is already enabled answers 400 (AF20024 "already
    // enabled") -- that was the "[DLP] DLP.All subscription: 400" logged at every boot.
    // Ask first; only start when the subscription is genuinely missing or disabled.
    const list  = await fetch(`${base}/list`, { headers: hdrs }).then(r => r.ok ? r.json() : null).catch(() => null);
    const cur   = Array.isArray(list) ? list.find(s => s && s.contentType === 'DLP.All') : null;
    if (cur && cur.status === 'enabled') { console.log('[DLP] DLP.All subscription: enabled'); return; }
    const res   = await fetch(`${base}/start?contentType=DLP.All`, { method:'POST', headers:hdrs, body:'{}' });
    const data  = await res.json().catch(()=>({}));
    console.log('[DLP] DLP.All subscription:', data.status || (data.error && data.error.message) || res.status);
  } catch(e) { console.warn('[DLP] Subscription failed:', e.message); }
}

let _cache = null, _cacheExpiry = 0;
const CACHE_TTL = 15 * 60 * 1000;

async function fetchDlpAlerts(force = false) {
  if (!force && _cache && Date.now() < _cacheExpiry) return _cache;

  console.log('[DLP] Fetching from O365 Management Activity API (DLP.All)...');
  const token = await getMgmtToken();
  const now   = new Date();
  const start = new Date(now - 4 * 3600 * 1000);
  const listUrl = `https://manage.office.com/api/v1.0/${TENANT_ID}/activity/feed/subscriptions/content`
    + `?contentType=DLP.All`
    + `&startTime=${start.toISOString().replace('Z','')}&endTime=${now.toISOString().replace('Z','')}`;

  let blobs = [];
  try {
    let nextUrl = listUrl;
    while (nextUrl) {
      const res = await fetch(nextUrl, { headers:{ Authorization:`Bearer ${token}` } });
      if (!res.ok) { const t = await res.text().catch(()=>''); throw new Error(`O365 ${res.status} ${t.slice(0,300)}`); }
      const data = await res.json();
      if (Array.isArray(data)) blobs.push(...data);
      nextUrl = res.headers.get('NextPageUri') || null;
    }
    if (blobs.length > 50) blobs = blobs.slice(-50); // cap to most recent 50
    console.log(`[DLP] Got ${blobs.length} DLP.All content blobs`);
  } catch(e) {
    console.error('[DLP] Blob list failed:', e.message);
    _cache = []; _cacheExpiry = Date.now() + 5*60*1000;
    return [];
  }

  const events = [];
  for (const blob of blobs) {
    try {
      const res  = await fetch(blob.contentUri, { headers:{ Authorization:`Bearer ${token}` } });
      const data = await res.json();
      if (Array.isArray(data)) {
        const ops = [...new Set(data.map(e=>e.Operation))];
        console.log('[DLP] Blob ops:', JSON.stringify(ops));
        events.push(...data);
      }
    } catch(e) { console.warn('[DLP] Blob fetch failed:', e.message); }
  }

  console.log(`[DLP] Total events from DLP.All: ${events.length}`);
  if (events.length > 0) {
    const allOps = [...new Set(events.map(e=>e.Operation))];
    console.log('[DLP] All unique operations:', JSON.stringify(allOps));
  }

  // Filter to SharePoint workload only — excludes Exchange/Teams DLP events
  const spEvents = events.filter(ev =>
    ev.Workload === 'SharePoint' ||
    (ev.SharePointMetaData && ev.SharePointMetaData.FileName) ||
    (ev.ObjectId && ev.ObjectId.toLowerCase().indexOf('sharepoint.com') > -1)
  );
  console.log('[DLP] SharePoint-only events: ' + spEvents.length + ' of ' + events.length);

  // DLP.All API returns operation as 'DlpRuleMatch'
  const dlpEvents = spEvents.filter(ev =>
    ev.Operation && ev.Operation.toLowerCase().indexOf('dlp') > -1
  );
  console.log('[DLP] Filtered to ' + dlpEvents.length + ' DLP events');

  const fileEvents = dlpEvents.filter(ev => {
    const md = ev.SharePointMetaData;
    if (!md || !md.FileID) return false;
    const src = (ev.EvaluationSource || '').toLowerCase();
    if (src.indexOf('crawler') > -1) return false;
    return true;
  });
  console.log('[DLP] Events with file metadata (non-crawler): ' + fileEvents.length + ' of ' + dlpEvents.length);
  const fileMap = new Map();
  for (const ev of fileEvents) {
    const key = ev.SharePointMetaData.FileID;
    const prev = fileMap.get(key);
    if (!prev || new Date(ev.CreationTime || 0) > new Date(prev.CreationTime || 0)) fileMap.set(key, ev);
  }
  const uniqueEvents = Array.from(fileMap.values());
  console.log('[DLP] Deduplicated to ' + uniqueEvents.length + ' unique files');
  const alerts = [];
  for (const ev of uniqueEvents) {
    const spMeta   = ev.SharePointMetaData || {};
    const fileUrl  = spMeta.FilePathUrl || ev.ObjectId || '';
    const siteUrl  = spMeta.SiteCollectionUrl || fileUrl.match(/(https:\/\/[^/]+\/sites\/[^/]+)/)?.[1] || '';
    const siteName = siteUrl.match(/\/sites\/([^/]+)/)?.[1]?.replace(/-/g,' ') || 'SharePoint';
    const fileName = spMeta.FileName || fileUrl.split('/').pop() || 'Unknown';
    const policies = ev.PolicyDetails || [];
    const policyName = policies[0]?.PolicyName || ev.PolicyName || '';
    const ruleName   = policies[0]?.Rules?.[0]?.RuleName || '';
    const ruleInfo   = resolvePolicy(policyName, ruleName);
    const matchCount = policies.reduce((s,p) => s + (p.Rules?.length||1), 0) || 1;
    const rawFileId = spMeta.FileID || null;
    const fileId   = rawFileId ? rawFileId.split('_').pop() : null;
    const meta = (siteUrl && fileId && rawFileId) ? await resolveFileMeta(siteUrl, fileUrl, null, fileId, rawFileId) : { sharing_scope:'unknown', sharing_links:[] };
    alerts.push({
      id:             `dlp-${ev.Id||ev.CreationTime}`,
      file_id:        rawFileId,
      file_name:      fileName,
      file_path:      fileUrl,
      site_url:       siteUrl,
      site_name:      siteName,
      owner:          spMeta.FileOwner || ev.UserId || '—',
      modified_by:    ev.UserId || '—',
      modified_date:  spMeta.ItemLastModifiedTime || ev.CreationTime || null,
      created_date:   spMeta.ItemCreationTime || null,
      rule:           ruleInfo.rule,
      rule_label:     ruleInfo.label,
      purview_policy: ruleInfo.policy,
      match_count:    matchCount,
      severity:       deriveSeverity(matchCount),
      sharing_scope:  meta.sharing_scope || 'unknown',
      sharing_links:  meta.sharing_links || [],
    });
  }

  const seen = new Set();
  const deduped = alerts.filter(a => { if(seen.has(a.file_path)) return false; seen.add(a.file_path); return true; });
  deduped.sort((a,b) => ({critical:0,high:1,medium:2,low:3}[a.severity]||9) - ({critical:0,high:1,medium:2,low:3}[b.severity]||9));

  console.log(`[DLP] Returning ${deduped.length} alerts`);
  // Persist to dlp_alerts (Phase 2). Failure here is non-fatal — the live
  // response still works; we just don't accumulate this batch into history.
  try {
    let upserts = 0, skipped = 0;
    for (const a of deduped) {
      if (!a.file_id) { skipped++; continue; }
      await rbacPool.query(
        `INSERT INTO dlp_alerts (
           file_id, file_name, file_path, site_url, site_name,
           owner, modified_by, modified_date, created_date,
           rule, rule_label, purview_policy, match_count, severity,
           sharing_scope, sharing_links
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
           file_name      = VALUES(file_name),
           file_path      = VALUES(file_path),
           site_url       = VALUES(site_url),
           site_name      = VALUES(site_name),
           owner          = VALUES(owner),
           modified_by    = VALUES(modified_by),
           modified_date  = VALUES(modified_date),
           rule           = VALUES(rule),
           rule_label     = VALUES(rule_label),
           purview_policy = VALUES(purview_policy),
           match_count    = VALUES(match_count),
           severity       = VALUES(severity),
           sharing_scope  = VALUES(sharing_scope),
           sharing_links  = VALUES(sharing_links),
           last_seen      = CURRENT_TIMESTAMP`,
        [
          a.file_id,
          a.file_name || null,
          a.file_path || null,
          a.site_url || null,
          a.site_name || null,
          a.owner || null,
          a.modified_by || null,
          a.modified_date ? new Date(a.modified_date) : null,
          a.created_date ? new Date(a.created_date) : null,
          a.rule || null,
          a.rule_label || null,
          a.purview_policy || null,
          a.match_count || 1,
          a.severity || 'medium',
          a.sharing_scope || 'unknown',
          JSON.stringify(a.sharing_links || [])
        ]
      );
      upserts++;
    }
    console.log(`[DLP] Persisted ${upserts} alerts to dlp_alerts (skipped ${skipped} without file_id)`);
  } catch (e) {
    console.error('[DLP] dlp_alerts persist failed (non-fatal):', e.message);
  }
  _cache = deduped; _cacheExpiry = Date.now() + CACHE_TTL;
  return deduped;
}

router.get('/alerts', rbac.requirePage('sharepoint-gov','read'), async (req,res) => {
  try   { res.json(await fetchDlpAlerts()); }
  catch (e) { console.error('[DLP] /alerts error:', e.message); res.status(500).json({ error:e.message }); }
});
// The dashboard needs counts and the first four banner rows. Fetching the full
// active list there returned ~2.8 MB and still queried all rows on a 304.
// Keep the complete /active-alerts response for the DLP page and modal.
router.get('/active-alerts/summary', rbac.requirePage('sharepoint-gov','read'), async (req,res) => {
  try {
    const [countsResult, topResult] = await Promise.all([
      rbacPool.query(
        `SELECT COUNT(*) total,
                COALESCE(SUM(severity='critical'),0) critical,
                COALESCE(SUM(severity='high'),0) high,
                COALESCE(SUM(severity='medium'),0) medium,
                COALESCE(SUM(severity='low'),0) low
         FROM dlp_alerts WHERE status='active'`),
      rbacPool.query(
        `SELECT file_id AS id, file_name, site_name, owner, modified_by, severity
         FROM dlp_alerts WHERE status='active'
         ORDER BY FIELD(severity,'critical','high','medium','low'), last_seen DESC LIMIT 4`),
    ]);
    const c = countsResult[0][0];
    res.json({ total:Number(c.total), critical:Number(c.critical), high:Number(c.high),
      medium:Number(c.medium), low:Number(c.low), top:topResult[0] });
  } catch (e) {
    console.error('[DLP] /active-alerts/summary error:', e.message);
    res.status(500).json({ error:e.message });
  }
});
router.get('/active-alerts', rbac.requirePage('sharepoint-gov','read'), async (req,res) => {
  try {
    const [rows] = await rbacPool.query(
      `SELECT file_id AS id, file_id, file_name, file_path, site_url, site_name,
              owner, modified_by, modified_date, created_date,
              rule, rule_label, purview_policy, match_count, severity,
              sharing_scope, sharing_links,
              first_seen, last_seen, status, resolved_by, resolved_at, notes
       FROM dlp_alerts
       WHERE status = 'active'
       ORDER BY FIELD(severity,'critical','high','medium','low'), last_seen DESC`
    );
    res.json(rows);
  } catch (e) {
    console.error('[DLP] /active-alerts error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

router.post('/refresh', rbac.requirePage('sharepoint-gov','admin'), async (req,res) => {
  try   { const a = await fetchDlpAlerts(true); res.json({ ok:true, count:a.length, refreshed_at:new Date().toISOString() }); }
  catch (e) { res.status(500).json({ error:e.message }); }
});

router.get('/health', async (req,res) => {
  try {
    await getGraphToken();
    const mgmtOk = await getMgmtToken().then(()=>true).catch(()=>false);
    res.json({ ok:true, cached:!!_cache, alert_count:_cache?.length??null, mgmt_token:mgmtOk });
  } catch(e) { res.status(500).json({ ok:false, error:e.message }); }
});

// F35 purge: rows written before the dlp-search-sync fix still carry each
// sharing link's web_url (for an 'anyone' link that URL is the credential).
// Strip the key from every array element; type/scope stay. Idempotent: once
// clean, each pass matches nothing.
async function purgeStoredLinkUrls(pool) {
  const [[m]] = await pool.query(
    `SELECT COALESCE(MAX(JSON_LENGTH(sharing_links)), 0) AS n FROM dlp_alerts
      WHERE JSON_TYPE(sharing_links) = 'ARRAY'`);
  let total = 0;
  for (let i = 0; i < Number(m.n); i++) {
    const p = `$[${i}].web_url`;
    for (;;) {
      const [r] = await pool.query(
        `UPDATE dlp_alerts SET sharing_links = JSON_REMOVE(sharing_links, ?)
          WHERE JSON_TYPE(sharing_links) = 'ARRAY' AND JSON_CONTAINS_PATH(sharing_links, 'one', ?)
          LIMIT 2000`, [p, p]);
      total += r.affectedRows;
      if (r.affectedRows < 2000) break;
    }
  }
  const [[left]] = await pool.query(
    `SELECT COUNT(*) AS n FROM dlp_alerts
      WHERE JSON_TYPE(sharing_links) = 'ARRAY' AND JSON_CONTAINS_PATH(sharing_links, 'one', '$[*].web_url')`);
  console.log(`[DLP] F35 purge: removed web_url from ${total} link entries; ${left.n} rows still carry one`);
  return { removed: total, remaining: Number(left.n) };
}

ensureSubscription().catch(e => console.warn('[DLP] Startup subscription failed:', e.message));
if (require.main !== module && !process.env.DLP_SKIP_LINK_PURGE) {
  setTimeout(() => purgeStoredLinkUrls(rbacPool)
    .catch(e => console.warn('[DLP] F35 purge failed:', e.message)), 15000).unref();
}

module.exports = router;
module.exports.purgeStoredLinkUrls = purgeStoredLinkUrls;
