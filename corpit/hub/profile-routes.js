// profile-routes.js — My Profile API for corpit.nrpi.local (2026-09-05)
// Mounted at /api/profile in server.js. Every route is SELF-SCOPED by default: the
// subject is req.user.email (set by the deny-by-default blanket in server.js, which
// also runs the CSRF origin guard for cookie-authenticated writes). Two routes read
// beyond self, both authorized server-side and both audited: /ai-team returns the
// roll-up for the caller's resolved reporting scope, and ?email= on /claude is
// allowed for a super-admin or for somebody inside that same scope.
//
// Data sources, and which system owns them:
//   Entra ID (entra_users, entra_auth_methods, entra_signin_logs)  synced nightly, read-only here
//   HR roster (hr_roster)                                          Dayforce export, read-only here
//   Active Directory (rbac_user_roles via LDAP at sign-in)         read-only here, "Refresh from AD" re-resolves
//   ServiceDesk Plus (live API, sdp-lookup.js)                     tickets + changes, live, cached 60s per user
//   Claude Admin API (claude_* tables)                             collector-fed; usage, and the member roster used for entitlement
//   Microsoft Graph (insight_user_activity, copilot_app_usage)     licence assignment + Copilot activity reports
//   Reporting scope (scope-lib.js over hr_roster/rbac_user_scope)  who a manager or director may read
//   CorpIT (rbac_user_prefs, profile_*, feature_suggestions, platform_changes)  the technician's own data
'use strict';

const express = require('express');
const mysql   = require('mysql2/promise');
const fs      = require('fs');
const fsp     = fs.promises;
const path    = require('path');
const crypto  = require('crypto');

const createRbac    = require('./rbac-middleware');
const scopeLib      = require('./scope-lib');
const aiTools       = require('./ai-tools-lib');
const spendAlert    = require('./spend-alert-lib');
const siteAccess    = require('./site-access');
const sessionAuth   = require('./session-auth');
const sessionCookie = require('./session-cookie');
let sdp = null;
try { sdp = require('./sdp-lookup'); } catch (e) { console.warn('[profile] sdp-lookup unavailable:', e.message); }

const router = express.Router();
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 5,
});
const rbac = createRbac(pool);

const LANDING_JSON   = process.env.LANDING_JSON || '/var/www/html/landing/landing.json';
const WEB_ROOT       = process.env.WEB_ROOT || '/var/www/html';
const NGINX_VHOST    = process.env.CORPIT_NGINX_VHOST || '/etc/nginx/sites-enabled/corpit.nrpi.local.conf';
const VERSION_FILE   = '/etc/corpit/VERSION';
const PHOTO_CACHE    = path.join(__dirname, 'cache', 'photos');
const SDP_PORTAL     = process.env.SDP_PORTAL || '';
// -- AI Reporting return-link allowlist ------------------------------------
// Who may see the "Back to AI Reporting" link on My Profile. Console-managed:
// the subadmin Settings page stores reporting_return.allow_emails and the root
// helper (nrpi-subdomain sync-reporting-return) publishes it to this file
// (root:corpit 640); we re-read it on a 30s TTL. REPORTING_RETURN_SEED is the
// cold-start default (the 13 curated leaders) and is the SAME list the console
// registry defaults to and the helper seeds -- in force ONLY when the published
// file is missing or unreadable. A present, valid file wins outright, including
// a deliberately emptied list (which means nobody).
// PATH-RELEASE-20260929: /etc/corpit/shared/reporting-return.json via corpit-paths.js.
const REPORTING_RETURN_PATH   = require('./corpit-paths').sharedFile('reporting-return.json', 'REPORTING_RETURN_CONFIG_PATH');
const REPORTING_RETURN_TTL_MS = 30000;
const REPORTING_RETURN_SEED = [
  'ali@auction.com', 'jasona@auction.com', 'dosborn@auction.com',
  'mkilander@auction.com', 'jcutrona@auction.com', 'glane@auction.com',
  'mbaig@auction.com', 'kboothe@auction.com', 'bsigala@auction.com',
  'snarayan@auction.com', 'asteinhaus@auction.com', 'rabad@auction.com',
  'jriggs@auction.com',
];
let _rrCache = { at: 0, set: null };
function reportingReturnSet() {
  const now = Date.now();
  if (_rrCache.set && (now - _rrCache.at) < REPORTING_RETURN_TTL_MS) return _rrCache.set;
  let set;
  try {
    const doc = JSON.parse(fs.readFileSync(REPORTING_RETURN_PATH, 'utf8'));
    const arr = Array.isArray(doc) ? doc : (doc && Array.isArray(doc.emails) ? doc.emails : null);
    if (!arr) throw new Error('reporting-return file has no email array');
    set = new Set(arr.map(e => String(e).trim().toLowerCase()).filter(Boolean));
  } catch (e) {
    // A present-but-broken file must not silently empty the list (the link would
    // vanish for leadership with nothing on the page to explain it) nor open it
    // to everyone. Missing file is the normal pre-publish state. Either way fall
    // back to the seed, and log the abnormal (non-ENOENT) case.
    if (e.code !== 'ENOENT') console.warn('[profile] reporting-return allowlist unreadable, using seed:', e.message);
    set = new Set(REPORTING_RETURN_SEED);
  }
  _rrCache = { at: now, set };
  return set;
}
function reportingReturnAllows(email) {
  return reportingReturnSet().has(String(email || '').trim().toLowerCase());
}
// [CORPIT-QA 2026-09-07] Was: PROFILE_MAIL_SENDER, defaulting to
// itcommand@auction.com, used as the /users/{id} path segment -- and
// the mail attribute is not an identifier Graph accepts in /users/{...},
// so every send 404'd. The address and the mailbox identifier now live in
// mail-graph.js, which is the single Graph mail path for this host.
const mailGraph = require('./mail-graph');

// ───────────────────────── helpers ─────────────────────────
function who(req) { return String((req.user && req.user.email) || '').trim().toLowerCase(); }
function needUser(req, res) {
  if (!req.user || !who(req)) { res.status(401).json({ error: 'Authentication required', code: req.tokenError || 'UNAUTHENTICATED' }); return false; }
  return true;
}
// The same break-glass floor rbac-middleware reads. Parsed here too because
// req.user only ever describes the CALLER, and a borrowed view has to report the
// SUBJECT's super-admin standing -- reporting the caller's is how somebody who is
// not a super-admin ends up branded as one.
const SUPERADMINS = (process.env.RBAC_SUPERADMINS || '')
  .split(',').map(x => x.trim().toLowerCase()).filter(Boolean);
function superAdminSourceFor(isEnv, roles) {
  const byRole = Array.isArray(roles) && roles.indexOf('superadmin') >= 0;
  if (isEnv && byRole) return 'env+role';
  if (isEnv) return 'env';
  if (byRole) return 'role';
  return null;
}

/** The email named by ?viewAs= / X-View-As, or '' when the request is for the caller. */
function viewAsRequested(req) {
  const raw = (req.query && req.query.viewAs) || (req.get && req.get('x-view-as')) || '';
  const target = String(raw || '').trim().toLowerCase();
  return target && target !== who(req) ? target : '';
}

function str(v, max) { if (v == null) return null; const s = String(v).trim(); return s.length ? s.slice(0, max) : null; }
function n2(v) { return Math.round((Number(v) || 0) * 100) / 100; }
function clientIp(req) {
  const peer = (req.socket && req.socket.remoteAddress) || '';
  const fromProxy = peer === '127.0.0.1' || peer === '::1' || peer === '::ffff:127.0.0.1';
  const chosen = (fromProxy && req.headers['x-real-ip']) || peer;
  return String(chosen || '').split(',')[0].trim().slice(0, 45) || null;
}
function monthOf(s) { return /^\d{4}-(0[1-9]|1[0-2])$/.test(String(s || '')) ? String(s) : null; }
function ymd(d) { return d.toISOString().slice(0, 10); }
function humanize(s) { return String(s || '').replace(/[_-]+/g, ' ').replace(/^\w/, c => c.toUpperCase()); }

const EVENT_VERBS = new Set(['view', 'open', 'search', 'save', 'update', 'submit', 'remove', 'refresh', 'revoke', 'vote']);
const EVENT_TYPES = new Set(['app', 'asset', 'ticket', 'user', 'page', 'search', 'draft', 'suggestion', 'change', 'prefs', 'pins', 'session', 'photo', 'changes', 'access']);

/** Append one product-activity row. Never throws (an activity gap must not break the request). */
async function logEvent(req, ev) {
  try {
    await pool.execute(
      `INSERT INTO profile_events (email, verb, object_type, object_id, label, url, meta, source, ip_address)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [who(req), ev.verb, ev.object_type, str(ev.object_id, 190), str(ev.label, 255), str(ev.url, 512),
       ev.meta ? JSON.stringify(ev.meta) : null, str(ev.source, 48) || 'api', clientIp(req)]);
  } catch (e) { console.error('[profile] event insert failed:', e.message); }
}

/** Read the session token facts (exp/jti/iat/groups) for the caller without a network call. */
function sessionFacts(req) {
  let raw = null;
  const auth = req.get('authorization') || '';
  if (/^Bearer\s+/i.test(auth)) raw = auth.replace(/^Bearer\s+/i, '').trim();
  if (!raw) {
    const m = /(?:^|;\s*)it_session=([^;]+)/.exec(req.headers.cookie || '');
    if (m) raw = decodeURIComponent(m[1]);
  }
  if (!raw) return { via: req.authVia || null };
  const v = sessionAuth.verifySessionToken(raw, { host: req.headers.host });   // MP-SIGNIN-SCOPE
  if (!v.ok) return { via: req.authVia || null, valid: false };
  let iat = null;
  try { iat = JSON.parse(Buffer.from(raw.slice(0, raw.indexOf('.')), 'base64').toString('utf8')).iat || null; } catch (e) {}
  return {
    via: req.authVia || null, valid: true,
    signedInAt: iat ? new Date(iat).toISOString() : null,
    expiresAt: v.exp ? new Date(v.exp).toISOString() : null,
    jtiShort: v.jti ? String(v.jti).slice(0, 8) : null,
    groups: v.groups || null,
  };
}

// ───────────────────────── hub links (landing.json) ─────────────────────────
let _hub = { mtime: 0, links: [], sections: [] };
function hostOf(url) {
  if (!url) return 'unknown';
  if (url.startsWith('/')) return 'corpit';
  try {
    const h = new URL(url).hostname.toLowerCase();
    if (h === 'corpit.nrpi.local') return 'corpit';
    if (h === 'reporting.nrpi.local') return 'reporting';
    if (h.endsWith('accessportal.itam.nrpi.local') || h === 'accessportal.nrpi.local') return 'accessportal';
    if (h === 'itam.nrpi.local') return 'itam';
    if (h === 'subadmin.nrpi.local') return 'subadmin';
    return 'external';
  } catch (e) { return 'unknown'; }
}
async function hubLinks() {
  try {
    const st = await fsp.stat(LANDING_JSON);
    if (st.mtimeMs !== _hub.mtime) {
      const cfg = JSON.parse(await fsp.readFile(LANDING_JSON, 'utf8'));
      const links = [], sections = [];
      (cfg.sections || []).forEach(s => {
        sections.push({ id: 's' + s.id, name: s.name });
        (s.links || []).forEach(l => links.push({
          id: 'l' + l.id, sectionId: 's' + s.id, section: s.name,
          title: l.title, url: l.url, description: l.description || '',
          tone: l.tone || 'blue', iconKind: l.icon_kind || 'glyph', iconHtml: l.icon_html || '',
          newTab: l.new_tab !== false, adminFavorite: !!l.favorite, quick: !!l.quick,
          host: hostOf(l.url),
        }));
      });
      _hub = { mtime: st.mtimeMs, links, sections, generated: cfg.generated || null };
    }
  } catch (e) {
    if (!_hub.links.length) console.warn('[profile] landing.json unreadable:', e.message);
  }
  return _hub;
}

// ───────────────────────── prefs ─────────────────────────
// Superset of rbac-routes' PREF_KEYS. Same table, same self-scoping; values are validated per key.
const PREF_RULES = {
  color_mode:        v => ['light', 'dark', 'system'].includes(v),
  theme:             v => ['ocean', 'reef', 'abyss', 'ember'].includes(v),
  density:           v => ['comfortable', 'compact'].includes(v),
  reduce_motion:     v => ['on', 'off'].includes(v),
  default_landing:   v => v === '' || /^l\d{1,6}$/.test(v) || /^[a-z0-9-]{1,64}$/.test(v),
  pins:              v => v.length <= 2048 && isPinList(v),
  quick_actions:     v => v.length <= 1024,
  timezone:          v => v === '' || isTimeZone(v),
  notifications:     v => v.length <= 512 && isNotifJson(v),
  last_seen_changes: v => /^\d{4}-\d{2}-\d{2}$/.test(v),
  photo_source:      v => ['entra', 'initials'].includes(v),
};
function isTimeZone(tz) { try { Intl.DateTimeFormat(undefined, { timeZone: tz }); return tz.length <= 64; } catch (e) { return false; } }
function isPinList(v) { try { const a = JSON.parse(v); return Array.isArray(a) && a.length <= 40 && a.every(x => typeof x === 'string' && /^l\d{1,6}$/.test(x)); } catch (e) { return false; } }
function isNotifJson(v) { try { const o = JSON.parse(v); return o && typeof o === 'object' && !Array.isArray(o) && Object.values(o).every(x => typeof x === 'boolean'); } catch (e) { return false; } }
async function readPrefs(email) {
  const [rows] = await pool.query('SELECT pref_key, pref_value, updated_at FROM rbac_user_prefs WHERE email = ?', [email]);
  const prefs = {}; let updatedAt = null;
  for (const r of rows) { prefs[r.pref_key] = r.pref_value; if (!updatedAt || r.updated_at > updatedAt) updatedAt = r.updated_at; }
  return { prefs, updatedAt };
}
async function writePrefs(req, entries) {
  if (!entries.length) return 0;
  await pool.query(
    'INSERT INTO rbac_user_prefs (email, pref_key, pref_value) VALUES ? ON DUPLICATE KEY UPDATE pref_value = VALUES(pref_value)',
    [entries.map(([k, v]) => [who(req), k, v])]);
  return entries.length;
}

// View-As is a READ-ONLY borrowed view. The page sends X-View-As on every call it
// makes, saves included, and every write in this file is keyed on who(req) -- so
// without this guard a preference changed while standing in for somebody else lands
// on the VIEWER's own profile, silently. There is no sensible "save as somebody
// else", so the honest answer is to refuse and say why.
const READ_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
router.use((req, res, next) => {
  if (READ_METHODS.has(req.method)) return next();
  if (!req.user || !who(req)) return next();          // let the route's own 401 answer
  const target = viewAsRequested(req);
  if (!target) return next();
  return res.status(403).json({
    error: 'You are viewing this page as ' + target + '. A borrowed view is read-only \u2014 leave it to change your own settings.',
    code: 'VIEW_AS_READ_ONLY', viewingAs: target,
  });
});

router.get('/prefs', async (req, res) => {
  if (!needUser(req, res)) return;
  try { res.json(await readPrefs(who(req))); }
  catch (e) { console.error('[profile] GET /prefs', e.message); res.status(500).json({ error: 'Internal error' }); }
});

router.put('/prefs', express.json({ limit: '8kb' }), async (req, res) => {
  if (!needUser(req, res)) return;
  const body = req.body && req.body.prefs;
  if (!body || typeof body !== 'object' || Array.isArray(body)) return res.status(400).json({ error: 'prefs object required' });
  const entries = [];
  for (const [k, raw] of Object.entries(body)) {
    if (!(k in PREF_RULES)) return res.status(400).json({ error: 'Unknown preference: ' + k });
    if (typeof raw !== 'string') return res.status(400).json({ error: 'Preference values must be strings: ' + k });
    if (!PREF_RULES[k](raw)) return res.status(400).json({ error: 'Invalid value for ' + k });
    entries.push([k, raw]);
  }
  try {
    const before = (await readPrefs(who(req))).prefs;
    const changed = entries.filter(([k, v]) => before[k] !== v);
    await writePrefs(req, entries);
    if (changed.length) {
      const shown = {};
      changed.forEach(([k, v]) => { shown[k] = (k === 'pins' || k === 'notifications' || k === 'quick_actions') ? '(updated)' : v; });
      await logEvent(req, { verb: 'update', object_type: 'prefs', object_id: changed.map(c => c[0]).join(','), label: 'Changed ' + changed.map(c => humanize(c[0]).toLowerCase()).join(', '), meta: shown, source: 'my-profile' });
    }
    res.json({ ok: true, saved: entries.length, changed: changed.map(c => c[0]) });
  } catch (e) { console.error('[profile] PUT /prefs', e.message); res.status(500).json({ error: 'Internal error' }); }
});

// ───────────────────────── hub links + pins ─────────────────────────
router.get('/hub-links', async (req, res) => {
  if (!needUser(req, res)) return;
  const hub = await hubLinks();
  res.json({ generated: hub.generated, sections: hub.sections, links: hub.links });
});

/**
 * GET /api/profile/my-access — every page the SUBJECT can open, as launch tiles.
 *
 * Two layers, both the real gates rather than a copy of the Hub:
 *   sites — per-vhost entitlement by AD group (site-access.js: the same policy nginx
 *           applies). It is decided from the signed-in SESSION's group claims, so it
 *           is only knowable for the viewer themselves. In a borrowed view it is null
 *           and the page says so, instead of showing the viewer's sites under the
 *           subject's name.
 *   pages — rbac_pages (active) resolved for the subject with computeEffectivePages,
 *           the same resolver /me and the admin console use. Hub tiles (landing.json)
 *           lend their artwork and blurb where one exists for the page. Registry pages
 *           with no tile are still listed, but only when the file is actually on this
 *           host (or the URL is absolute) — a tile that 404s is a fake control. Hub
 *           tiles with no registry row are gated by site access alone and say so.
 */
router.get('/my-access', async (req, res) => {
  if (!needUser(req, res)) return;
  const self = who(req);
  try {
    const v = await viewSubject(req);
    const email = v.email, isSelf = email === self;
    const [roleRows] = await pool.query('SELECT role_key FROM rbac_user_roles WHERE email=? ORDER BY role_key', [email]);
    const [[ru]] = await pool.query('SELECT is_active FROM rbac_users WHERE email=? LIMIT 1', [email]);
    const roles = isSelf ? (req.user.roles || []) : roleRows.map(r => r.role_key);
    const isSuperAdmin = isSelf ? !!req.user.isSuperAdmin : (SUPERADMINS.indexOf(email) >= 0 || roles.indexOf('superadmin') >= 0);
    const isActive = isSelf ? !!req.user.isActive : !!(ru && ru.is_active);
    let pages = {};
    if (isSuperAdmin || isActive) {
      try { pages = await rbac.computeEffectivePages(email, roles, isSuperAdmin); } catch (e) { console.warn('[profile] my-access computeEffectivePages', e.message); }
    }

    const [regRows] = await pool.query(
      "SELECT page_key, display_name, url_path, category, access_policy, description, display_order, file_path " +
      "FROM rbac_pages WHERE status = 'active' ORDER BY display_order, display_name");
    const reg = regRows.map(r => Object.assign({}, r, { path: pathKeyOf(r.url_path), host: hostOf(r.url_path) }));
    const hub = await hubLinks();

    const RANK = { admin: 2, read: 1, open: 0 };
    const best = (a, b) => ((RANK[a] || 0) >= (RANK[b] || 0) ? a : b);
    const claimed = new Set();
    const tiles = [];
    const redirects = await nginxRedirects();
    for (const l of hub.links) {
      const p = pathKeyOf(l.url);
      const land = String(l.url).startsWith('/') && redirects.get(p);   // nginx 301s this path elsewhere
      const url = land || l.url, host = land ? hostOf(land) : l.host;
      // Same path = same page. A bare "/" only matches within the same host family,
      // or every site root would claim the Access Portal's registry row.
      const matches = reg.filter(r => r.path === p && (p !== '/' || r.host === l.host));
      let level = null, gate = 'site';
      const keys = [];
      if (matches.length) {
        matches.forEach(r => { claimed.add(r.page_key); if (pages[r.page_key]) { keys.push(r.page_key); level = best(level, pages[r.page_key]); } });
        if (!keys.length) continue;                      // registered page, no grant: not theirs
        gate = matches.every(r => r.access_policy === 'authenticated') ? 'authenticated' : 'page';
      } else {
        level = 'open';                                    // no registry row: site access alone gates it
      }
      tiles.push({ id: l.id, sectionId: l.sectionId, section: l.section, title: l.title, url, description: l.description,
        tone: l.tone, iconKind: l.iconKind, iconHtml: l.iconHtml, newTab: l.newTab, host, level, gate, pageKeys: keys });
    }
    // Registry pages nobody published a tile for. Listed only when they will open.
    // Matching is by where the page finally lands, so a row whose corpit path nginx
    // 301s to the same place a Hub tile already points (Server Health -> subadmin
    // /operations) upgrades that tile's chip instead of standing beside it twice.
    const normUrl = u => String(u || '').replace(/#.*$/, '').replace(/\/+$/, '');
    const byUrl = new Map(tiles.map(t => [normUrl(t.url), t]));
    const extra = [], extraByPath = new Map();
    for (const r of reg) {
      if (claimed.has(r.page_key) || !pages[r.page_key] || r.page_key === 'my-profile') continue;
      const dup = extraByPath.get(r.host + ' ' + r.path);       // two rows, one page (gpo-audit + ad-housekeeping)
      if (dup) { dup.level = best(dup.level, pages[r.page_key]); dup.pageKeys.push(r.page_key); continue; }
      const where = await resolvePage(r, redirects);
      if (!where) continue;                                  // nothing serves it on this host: no tile
      const same = byUrl.get(normUrl(where));
      if (same) {
        same.level = best(same.level === 'open' ? null : same.level, pages[r.page_key]);
        same.gate = r.access_policy === 'authenticated' ? 'authenticated' : 'page';
        same.pageKeys.push(r.page_key); claimed.add(r.page_key);
        continue;
      }
      const key = r.host + ' ' + r.path;
      extra.push({ id: 'p:' + r.page_key, sectionId: 'reg:' + r.category, section: REG_SECTION[r.category] || REG_SECTION.app,
        title: r.display_name, url: where, description: r.description || '',
        tone: r.category === 'admin' ? 'purple' : 'blue', iconKind: 'glyph', iconHtml: '',
        newTab: !where.startsWith('/'), host: hostOf(where), level: pages[r.page_key],
        gate: r.access_policy === 'authenticated' ? 'authenticated' : 'page', pageKeys: [r.page_key] });
      extraByPath.set(key, extra[extra.length - 1]);
    }
    const sections = hub.sections.filter(s => tiles.some(t => t.sectionId === s.id)).map(s => ({ id: s.id, name: s.name }));
    ['app', 'sop', 'admin'].forEach(c => { if (extra.some(t => t.sectionId === 'reg:' + c)) sections.push({ id: 'reg:' + c, name: REG_SECTION[c] }); });

    // Sites: the viewer's own session claims decide, so only for the viewer.
    let sites = null, sitesReason = null;
    if (v.viewingAs) {
      sitesReason = 'view-as';
    } else if (req.sessionClaims) {
      const groups = req.sessionClaims.groups === undefined ? null : req.sessionClaims.groups;
      sites = siteAccess.allowedSitesFor(self, groups).map(s => ({
        host: s.host, label: s.label, url: 'https://' + s.host + '/', family: hostOf('https://' + s.host + '/'),
      }));
    } else {
      sitesReason = 'no-session-claims';
    }

    if (!isSelf) rbac.audit(req, 'profile_my_access_view_other', email, 'my-profile', { via: v.viewingAs && v.viewingAs.via });
    res.json({
      subject: email, viewingAs: v.viewingAs, viewAsDenied: v.viewAsDenied, isSuperAdmin,
      sections, tiles: tiles.concat(extra), sites, sitesReason,
      currentHost: siteAccess.normHost(req.get('X-Original-Host') || req.hostname || ''),
    });
  } catch (e) {
    console.error('[profile] GET /my-access', e.message);
    res.status(500).json({ error: 'Internal error' });
  }
});
const REG_SECTION = { app: 'More pages you can open', sop: 'Procedures (SOPs)', admin: 'Admin' };
function pathKeyOf(u) {
  try { const p = new URL(String(u || ''), 'https://corpit.nrpi.local').pathname.replace(/\/+$/, ''); return p || '/'; }
  catch (e) { return null; }
}
/* Where a registry page really opens, or null. Absolute URLs are another host's
 * business. A root-relative path is checked against what THIS host serves: an
 * nginx exact-match redirect (ai-usage-credits -> reporting, server-health ->
 * subadmin) wins and the tile follows it, so the site filter judges the host it
 * lands on; otherwise the file must be on disk. A path nothing serves
 * (/helpdesk/users has no location block since the ITAM footprint was cut) gets
 * no tile: a launch tile that 404s is a fake control. */
async function resolvePage(r, redirects) {
  const u = String(r.url_path || '');
  if (!u.startsWith('/')) return u;
  const p = pathKeyOf(u);
  if (redirects.has(p)) return redirects.get(p);
  const fp = r.file_path ? String(r.file_path) : '';
  const f = fp ? (fp.startsWith('/var/') ? fp : path.join(WEB_ROOT, fp)) : path.join(WEB_ROOT, p || '/');
  try { await fsp.access(f); return u; } catch (e) { return null; }
}
/* Exact-match `location = /x { return 30x TARGET; }` blocks of this host's vhost,
 * as path -> absolute URL. Read at most once a minute; unreadable = no redirects. */
let _redir = { at: 0, map: new Map() };
async function nginxRedirects() {
  if (Date.now() - _redir.at < 60000) return _redir.map;
  const map = new Map();
  try {
    const txt = await fsp.readFile(NGINX_VHOST, 'utf8');
    const re = /location\s*=\s*(\/\S*)\s*\{([^}]*)\}/g;
    let m;
    while ((m = re.exec(txt))) {
      const body = m[2].replace(/#[^\n]*/g, '');
      const ret = /return\s+30[1278]\s+(\S+?)\s*;/.exec(body);
      if (!ret) continue;
      const from = pathKeyOf(m[1]);
      let to = ret[1].replace(/\$uri|\$request_uri/g, from);
      if (to.startsWith('/')) to = 'https://corpit.nrpi.local' + to;
      if (/^https:\/\//.test(to) && to.indexOf('$') < 0) map.set(from, to);
    }
  } catch (e) { /* not readable here: fall back to the on-disk check */ }
  _redir = { at: Date.now(), map };
  return map;
}

async function currentPins(email) {
  const { prefs } = await readPrefs(email);
  let pins = [];
  try { pins = JSON.parse(prefs.pins || '[]'); } catch (e) { pins = []; }
  if (!Array.isArray(pins)) pins = [];
  const hub = await hubLinks();
  const byId = new Map(hub.links.map(l => [l.id, l]));
  const clean = pins.filter((id, i) => typeof id === 'string' && byId.has(id) && pins.indexOf(id) === i);
  return { pins: clean, links: clean.map(id => byId.get(id)), hub, hasPref: 'pins' in prefs };
}
router.get('/pins', async (req, res) => {
  if (!needUser(req, res)) return;
  try {
    const cur = await currentPins(who(req));
    // A user with no saved pins sees the console's admin favourites as a starting point.
    const fallback = cur.hasPref ? [] : cur.hub.links.filter(l => l.adminFavorite);
    res.json({ pins: cur.pins, links: cur.links, fallback, fromAdminDefaults: !cur.hasPref });
  } catch (e) { console.error('[profile] GET /pins', e.message); res.status(500).json({ error: 'Internal error' }); }
});
async function savePins(req, pins, label) {
  const hub = await hubLinks();
  const valid = new Set(hub.links.map(l => l.id));
  const clean = []; pins.forEach(id => { if (typeof id === 'string' && valid.has(id) && !clean.includes(id)) clean.push(id); });
  if (clean.length > 40) clean.length = 40;
  await writePrefs(req, [['pins', JSON.stringify(clean)]]);
  await logEvent(req, { verb: 'save', object_type: 'pins', object_id: String(clean.length), label, meta: { count: clean.length }, source: req.body && req.body.source });
  const byId = new Map(hub.links.map(l => [l.id, l]));
  return { pins: clean, links: clean.map(id => byId.get(id)) };
}
router.put('/pins', express.json({ limit: '8kb' }), async (req, res) => {
  if (!needUser(req, res)) return;
  const pins = req.body && req.body.pins;
  if (!Array.isArray(pins)) return res.status(400).json({ error: 'pins array required' });
  try { res.json(await savePins(req, pins, 'Reordered favorites')); }
  catch (e) { console.error('[profile] PUT /pins', e.message); res.status(500).json({ error: 'Internal error' }); }
});
router.post('/pins/toggle', express.json({ limit: '2kb' }), async (req, res) => {
  if (!needUser(req, res)) return;
  const id = str(req.body && req.body.id, 16);
  if (!id || !/^l\d{1,6}$/.test(id)) return res.status(400).json({ error: 'id required' });
  try {
    const cur = await currentPins(who(req));
    // First toggle for someone still on the admin defaults starts from those defaults,
    // so pinning one tile does not silently drop the seven they were already seeing.
    let pins = cur.hasPref ? cur.pins.slice() : cur.hub.links.filter(l => l.adminFavorite).map(l => l.id);
    const link = cur.hub.links.find(l => l.id === id);
    if (!link) return res.status(404).json({ error: 'Unknown hub link' });
    const on = !pins.includes(id);
    pins = on ? pins.concat(id) : pins.filter(x => x !== id);
    const out = await savePins(req, pins, (on ? 'Pinned ' : 'Unpinned ') + link.title);
    res.json(Object.assign({ pinned: on, id }, out));
  } catch (e) { console.error('[profile] POST /pins/toggle', e.message); res.status(500).json({ error: 'Internal error' }); }
});

// ───────────────────────── events + recents ─────────────────────────
router.post('/events', express.json({ limit: '4kb' }), async (req, res) => {
  if (!needUser(req, res)) return;
  const b = req.body || {};
  const verb = str(b.verb, 24), type = str(b.object_type, 32);
  if (!EVENT_VERBS.has(verb) || !EVENT_TYPES.has(type)) return res.status(400).json({ error: 'verb/object_type not allowed' });
  const url = str(b.url, 512);
  if (url && !(url.startsWith('/') && !url.startsWith('//')) && !/^https:\/\/[a-z0-9.-]+\.nrpi\.local(\/|$)/i.test(url)) return res.status(400).json({ error: 'url must be same-origin or an nrpi.local https URL' });
  let meta = null;
  if (b.meta && typeof b.meta === 'object' && !Array.isArray(b.meta)) { meta = {}; Object.entries(b.meta).slice(0, 12).forEach(([k, v]) => { meta[str(k, 32)] = (typeof v === 'string') ? v.slice(0, 200) : (typeof v === 'number' || typeof v === 'boolean') ? v : null; }); }
  try {
    // Collapse double-fires: same verb+object within 45s is one event.
    const [[dup]] = await pool.query(
      `SELECT id FROM profile_events WHERE email=? AND verb=? AND object_type=? AND object_id <=> ? AND created_at > DATE_SUB(NOW(), INTERVAL 45 SECOND) LIMIT 1`,
      [who(req), verb, type, str(b.object_id, 190)]);
    if (!dup) await logEvent(req, { verb, object_type: type, object_id: b.object_id, label: b.label, url, meta, source: b.source });
    res.status(204).end();
  } catch (e) { console.error('[profile] POST /events', e.message); res.status(500).json({ error: 'Internal error' }); }
});

router.get('/recent', async (req, res) => {
  if (!needUser(req, res)) return;
  try {
    const [rows] = await pool.query(
      `SELECT e.object_type, e.object_id, e.label, e.url, e.verb, e.created_at, e.source
         FROM profile_events e
         JOIN (SELECT object_type, object_id, MAX(id) AS id FROM profile_events
                WHERE email=? AND verb IN ('view','open') AND object_id IS NOT NULL
                  AND created_at > DATE_SUB(NOW(), INTERVAL 60 DAY)
                GROUP BY object_type, object_id) m ON m.id = e.id
        ORDER BY e.created_at DESC LIMIT 30`, [who(req)]);
    res.json({ items: rows });
  } catch (e) { console.error('[profile] GET /recent', e.message); res.status(500).json({ error: 'Internal error' }); }
});

// ───────────────────────── Microsoft Graph (LIVE) ─────────────────────────
// The signed-in technician's directory record, manager, sign-in methods and sign-ins are
// read live from Graph with the IdentityDiag app registration (same one entra-sync.js uses),
// cached 2 minutes per user. The nightly sync tables are only the fallback when Graph is
// unreachable, and the response says which one answered.
const GRAPH = 'https://graph.microsoft.com/v1.0';
let _gtok = { at: 0, tok: null };
async function graphToken() {
  if (_gtok.tok && Date.now() - _gtok.at < 45 * 60e3) return _gtok.tok;
  const T = process.env.ENTRA_TENANT_ID || process.env.AZURE_TENANT_ID, C = process.env.ENTRA_CLIENT_ID || process.env.AZURE_CLIENT_ID, S = process.env.ENTRA_CLIENT_SECRET || process.env.AZURE_CLIENT_SECRET;
  if (!T || !C || !S || typeof fetch !== 'function') return null;
  const r = await fetch(`https://login.microsoftonline.com/${T}/oauth2/v2.0/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: C, client_secret: S, scope: 'https://graph.microsoft.com/.default', grant_type: 'client_credentials' }), signal: AbortSignal.timeout(8000) });
  const j = await r.json().catch(() => ({}));
  if (!j.access_token) throw new Error('graph token: ' + String(j.error_description || j.error || r.status).slice(0, 120));
  _gtok = { at: Date.now(), tok: j.access_token };
  return j.access_token;
}
async function graphGet(path) {
  const tok = await graphToken();
  if (!tok) return null;
  const r = await fetch(GRAPH + path, { headers: { Authorization: 'Bearer ' + tok }, signal: AbortSignal.timeout(8000) });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error('graph ' + r.status + ' ' + path.split('?')[0]);
  return r.json();
}
const _live = new Map();            // email -> { at, id: {...}, sec: {...} }
const LIVE_TTL = 120e3;
const USER_SELECT = 'id,displayName,givenName,surname,userPrincipalName,mail,jobTitle,department,officeLocation,mobilePhone,businessPhones,accountEnabled,lastPasswordChangeDateTime,employeeId,city,state,country,createdDateTime,onPremisesSyncEnabled,onPremisesLastSyncDateTime';
async function liveIdentity(email) {
  const hit = _live.get(email);
  if (hit && hit.id && Date.now() - hit.at < LIVE_TTL) return hit.id;
  const u = await graphGet(`/users/${encodeURIComponent(email)}?$select=${USER_SELECT}`);
  if (!u) return null;
  let mgr = null, act = null;
  try { mgr = await graphGet(`/users/${encodeURIComponent(email)}/manager?$select=displayName,jobTitle,userPrincipalName,mail`); } catch (e) { mgr = null; }
  try { const a = await graphGet(`/users/${u.id}?$select=signInActivity`); act = a && a.signInActivity ? a.signInActivity : null; } catch (e) { act = null; }
  const id = {
    source: 'live', fetchedAt: new Date().toISOString(), objectId: u.id,
    upn: u.userPrincipalName, mail: u.mail, displayName: u.displayName, givenName: u.givenName, surname: u.surname,
    jobTitle: u.jobTitle, department: u.department, officeLocation: u.officeLocation,
    mobilePhone: u.mobilePhone || null, businessPhones: Array.isArray(u.businessPhones) ? u.businessPhones : [],
    city: u.city, state: u.state, country: u.country, employeeId: u.employeeId,
    accountEnabled: u.accountEnabled === true, lastPasswordChange: u.lastPasswordChangeDateTime || null, createdAt: u.createdDateTime || null,
    onPremSynced: u.onPremisesSyncEnabled === true, onPremLastSync: u.onPremisesLastSyncDateTime || null,
    managerUpn: mgr ? mgr.userPrincipalName : null, managerName: mgr ? mgr.displayName : null, managerTitle: mgr ? mgr.jobTitle : null, managerMail: mgr ? mgr.mail : null,
    lastLogin: act ? (act.lastSignInDateTime || null) : null, lastNonInteractive: act ? (act.lastNonInteractiveSignInDateTime || null) : null,
  };
  _live.set(email, Object.assign(hit || {}, { at: Date.now(), id }));
  return id;
}
function methodType(odata) { return String(odata || '').replace('#microsoft.graph.', '').replace(/AuthenticationMethod$/, 'Method'); }
async function liveSecurity(email) {
  const hit = _live.get(email);
  if (hit && hit.sec && Date.now() - hit.at < LIVE_TTL) return hit.sec;
  const id = await liveIdentity(email);
  if (!id) return null;
  const [m, s] = await Promise.all([
    graphGet(`/users/${id.objectId}/authentication/methods`).catch(() => null),
    graphGet(`/auditLogs/signIns?$filter=userId eq '${id.objectId}'&$top=40`).catch(() => null),
  ]);
  const sec = {
    source: 'live', fetchedAt: new Date().toISOString(),
    methods: m ? (m.value || []).map(x => ({ type: methodType(x['@odata.type']), name: x.displayName || x.deviceTag || x.phoneNumber || x.emailAddress || null, createdAt: x.createdDateTime || null })) : null,
    signins: s ? (s.value || []).map(x => ({ at: x.createdDateTime, ok: !x.status || Number(x.status.errorCode) === 0, app: x.appDisplayName, ip: x.ipAddress,
      city: x.location && x.location.city, state: x.location && x.location.state, country: x.location && x.location.countryOrRegion,
      os: x.deviceDetail && x.deviceDetail.operatingSystem, browser: x.deviceDetail && x.deviceDetail.browser, ca: x.conditionalAccessStatus, risk: x.riskLevelDuringSignIn,
      reason: x.status && x.status.failureReason, interactive: x.isInteractive !== false })) : null,
  };
  _live.set(email, Object.assign(_live.get(email) || { at: Date.now() }, { sec }));
  return sec;
}

// ───────────────────────── identity (/me) ─────────────────────────
router.get('/me', async (req, res) => {
  if (!needUser(req, res)) return;
  const self = who(req);
  try {
    const v = await viewSubject(req);
    const email = v.email, isSelf = email === self;
    let live = null, liveErr = null;
    try { live = await liveIdentity(email); } catch (e) { liveErr = e.message; console.warn('[profile] Graph identity fallback:', e.message); }
    const [[entra]] = await pool.query(
      `SELECT user_principal_name, mail, display_name, given_name, surname, job_title, department, office_location,
              manager_upn, account_enabled, last_login, last_password_change, last_synced_at, entra_id
         FROM entra_users WHERE LOWER(user_principal_name)=? OR LOWER(mail)=? ORDER BY (LOWER(user_principal_name)=?) DESC LIMIT 1`, [email, email, email]);
    let manager = null;
    if (!live && entra && entra.manager_upn) {
      const [[m]] = await pool.query('SELECT display_name, job_title, user_principal_name FROM entra_users WHERE LOWER(user_principal_name)=? LIMIT 1', [String(entra.manager_upn).toLowerCase()]);
      manager = m || null;
    }
    const [[hr]] = await pool.query(
      `SELECT title, department, location, manager_name, manager_email, leader_name, leader_email, hire_date, status, loaded_at, worker_id
         FROM hr_roster WHERE LOWER(email)=? LIMIT 1`, [email]);
    const [[ru]] = await pool.query('SELECT display_name, role_key, is_active, roles_resolved_at, created_at FROM rbac_users WHERE email=? LIMIT 1', [email]);
    const [roleRows] = await pool.query('SELECT role_key, resolved_at FROM rbac_user_roles WHERE email=? ORDER BY role_key', [email]);
    // Resolved for the SUBJECT, the way rbac-middleware resolves them for the
    // caller. Using req.user here is what brands the person you are viewing with
    // your own roles and your own super-admin flag.
    const roles = isSelf ? (req.user.roles || []) : roleRows.map(r => r.role_key);
    const envSA = SUPERADMINS.indexOf(email) >= 0;
    const isSuperAdmin = isSelf ? !!req.user.isSuperAdmin : (envSA || roles.indexOf('superadmin') >= 0);
    const isActive = isSelf ? !!req.user.isActive : !!(ru && ru.is_active);
    let pages = {};
    if (isSuperAdmin || isActive) {
      try { pages = await rbac.computeEffectivePages(email, roles, isSuperAdmin); } catch (e) { console.warn('[profile] computeEffectivePages', e.message); }
    }
    const { prefs, updatedAt } = await readPrefs(email);
    const [[ev]] = await pool.query('SELECT COUNT(*) AS n, MIN(created_at) AS first_at FROM profile_events WHERE email=?', [email]);
    if (!isSelf) rbac.audit(req, 'profile_view_as', email, 'my-profile', { via: v.viewingAs && v.viewingAs.via });
    res.json({
      email, displayName: (isSelf ? req.user.displayName : null) || (entra && entra.display_name) || email,
      isSuperAdmin, superAdminSource: isSelf ? (req.user.superAdminSource || null) : superAdminSourceFor(envSA, roles),
      roles, roleRows, pages,
      // The 'Back to AI Reporting' link is the VIEWER's own nav, so it is
      // decided by who() (self) and not by the subject under View-As.
      canReturnToReporting: reportingReturnAllows(self),
      // Who is actually signed in. The account card and every admin affordance hang
      // off this and never off the subject.
      viewer: isSelf ? null : { email: self, displayName: req.user.displayName || self, isSuperAdmin: !!req.user.isSuperAdmin, session: sessionFacts(req) },
      viewingAs: v.viewingAs, viewAsDenied: v.viewAsDenied,
      rolesResolvedAt: ru ? ru.roles_resolved_at : null, memberSince: ru ? ru.created_at : null,
      entra: live ? live : (entra ? {
        source: 'sync', syncedAt: entra.last_synced_at, liveError: liveErr,
        upn: entra.user_principal_name, mail: entra.mail, displayName: entra.display_name,
        givenName: entra.given_name, surname: entra.surname, jobTitle: entra.job_title,
        department: entra.department, officeLocation: entra.office_location, mobilePhone: null, businessPhones: [],
        managerUpn: entra.manager_upn, managerName: manager ? manager.display_name : null, managerTitle: manager ? manager.job_title : null,
        accountEnabled: entra.account_enabled === 1, lastLogin: entra.last_login, lastPasswordChange: entra.last_password_change,
      } : null),
      hr: hr ? {
        title: hr.title, department: hr.department, location: hr.location, status: hr.status,
        managerName: hr.manager_name, managerEmail: hr.manager_email, leaderName: hr.leader_name, leaderEmail: hr.leader_email,
        hireDate: hr.hire_date, loadedAt: hr.loaded_at,
      } : null,
      // These facts describe THIS browser session, which belongs to the caller.
      // Presenting them as the subject's would be a fabrication, so a borrowed view
      // gets null and the page says the security panel is unavailable.
      session: isSelf ? sessionFacts(req) : null,
      prefs, prefsUpdatedAt: updatedAt,
      photoUrl: '/api/photo?upn=' + encodeURIComponent(email),
      activity: { count: Number(ev.n || 0), firstAt: ev.first_at },
    });
  } catch (e) { console.error('[profile] GET /me', e.message); res.status(500).json({ error: 'Internal error' }); }
});

// ───────────────────────── ServiceDesk Plus (live) ─────────────────────────
const ACTIVE_STATUSES = ['Open', 'On Hold', 'In Progress', 'Pending Verification'];
const _sdpCache = new Map();            // email -> {at, data}
let _changesProbe = { at: 0, ok: null, reason: null };
const TICKET_URL = id => SDP_PORTAL ? `https://sdpondemand.manageengine.com/app/${SDP_PORTAL}/WorkOrder.do?woMode=viewWO&woID=${encodeURIComponent(id)}` : null;
const CHANGE_URL = id => SDP_PORTAL ? `https://sdpondemand.manageengine.com/app/${SDP_PORTAL}/ui/changes/${encodeURIComponent(id)}/details` : null;

function sdpErrBody(e) { try { const d = e.response && e.response.data; return d ? (typeof d === 'string' ? d.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').slice(0, 200) : JSON.stringify(d).slice(0, 300)) : ''; } catch (x) { return ''; } }
function sdpReady() { return !!(sdp && typeof sdp.sdpGet === 'function' && process.env.SDP_REFRESH_TOKEN && SDP_PORTAL); }
// SDP Cloud rejects bursts: a dozen simultaneous calls against a cold token cache came back
// 400 in testing while the same queries passed one at a time. Warm the token with one call,
// then run the rest through a small concurrency gate.
function pLimit(n) {
  let active = 0; const queue = [];
  const next = () => { if (active >= n || !queue.length) return; active++; const { fn, res, rej } = queue.shift(); fn().then(res, rej).finally(() => { active--; next(); }); };
  return fn => new Promise((res, rej) => { queue.push({ fn, res, rej }); next(); });
}
const sdpGate = pLimit(3);
function sdpGetGated(path, input) { return sdpGate(() => sdp.sdpGet(path, input)); }
async function sdpCount(criteria) {
  const d = await sdpGetGated('/requests', { list_info: { row_count: 1, get_total_count: true, search_criteria: criteria } });
  return Number((d.list_info && d.list_info.total_count) || 0);
}
function techIs(email) { return { field: 'technician.email_id', condition: 'is', value: email }; }
function and(c) { return Object.assign({ logical_operator: 'AND' }, c); }
function tsVal(o) { return o && o.value ? new Date(Number(o.value)).toISOString() : null; }
function mapRequest(r) {
  const status = (r.status && r.status.name) || 'Unknown';
  return {
    id: r.id, displayId: (r.display_id && r.display_id.display_value) || r.display_id || r.id,
    subject: r.subject || '', status, priority: (r.priority && r.priority.name) || null,
    requester: r.requester ? (r.requester.name || r.requester.email_id) : null,
    requesterEmail: r.requester ? r.requester.email_id : null,
    technician: r.technician ? r.technician.name : null,
    createdAt: tsVal(r.created_time), dueBy: tsVal(r.due_by_time), updatedAt: tsVal(r.last_updated_time), completedAt: tsVal(r.completed_time),
    overdue: r.is_overdue === true, site: r.site ? r.site.name : null,
    url: TICKET_URL(r.id),
  };
}
const REQ_FIELDS = ['id', 'display_id', 'subject', 'status', 'priority', 'requester', 'technician', 'created_time', 'due_by_time', 'last_updated_time', 'completed_time', 'is_overdue', 'site'];

async function fetchWork(email) {
  const now = new Date();
  const som = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
  const dow = (now.getUTCDay() + 6) % 7;                                // Monday = 0
  const sow = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - dow));
  const d30 = new Date(now.getTime() - 30 * 864e5), d90 = new Date(now.getTime() - 90 * 864e5);
  const me = techIs(email);
  const gt = (field, d) => and({ field, condition: 'greater than', value: String(d.getTime()) });
  await sdpCount([me]);                                                 // warm-up: one call, then the batch
  const [total, open, onHold, inProgress, pendingVer, overdue, closedWeek, closedMonth, closed30, closedMonthPrev, createdMonth, list, doneMonth] = await Promise.all([
    sdpCount([me]),
    sdpCount([me, and({ field: 'status.name', condition: 'is', value: 'Open' })]),
    sdpCount([me, and({ field: 'status.name', condition: 'is', value: 'On Hold' })]),
    sdpCount([me, and({ field: 'status.name', condition: 'is', value: 'In Progress' })]),
    sdpCount([me, and({ field: 'status.name', condition: 'is', value: 'Pending Verification' })]),
    sdpCount([me, and({ field: 'status.in_progress', condition: 'is', value: true }), and({ field: 'is_overdue', condition: 'is', value: true })]),
    sdpCount([me, gt('completed_time', sow)]),
    sdpCount([me, gt('completed_time', som)]),
    sdpCount([me, gt('completed_time', d30)]),
    sdpCount([me, gt('completed_time', new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1))), and({ field: 'completed_time', condition: 'lesser than', value: String(som.getTime()) })]),
    sdpCount([me, gt('created_time', som)]),
    sdpGetGated('/requests', { list_info: { row_count: 25, sort_field: 'created_time', sort_order: 'desc', fields_required: REQ_FIELDS,
      search_criteria: [me, and({ field: 'status.in_progress', condition: 'is', value: true })] } }),
    sdpGetGated('/requests', { list_info: { row_count: 100, sort_field: 'completed_time', sort_order: 'desc', fields_required: ['id', 'created_time', 'completed_time'],
      search_criteria: [me, gt('completed_time', som)] } }),
  ]);
  const closed90 = await sdpCount([me, gt('completed_time', d90)]);
  // Last 8 ISO weeks of closures for the productivity sparkline (oldest first).
  const weekStarts = []; for (let i = 7; i >= 0; i--) weekStarts.push(new Date(sow.getTime() - i * 7 * 864e5));
  const closedWeeks = await Promise.all(weekStarts.map((ws, i) => sdpCount([me, gt('completed_time', ws),
    and({ field: 'completed_time', condition: 'lesser than', value: String((i === 7 ? new Date(now.getTime() + 864e5) : weekStarts[i + 1]).getTime()) })])));
  const psom = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1));
  const donePrev = await sdpGetGated('/requests', { list_info: { row_count: 100, sort_field: 'completed_time', sort_order: 'desc', fields_required: ['id', 'created_time', 'completed_time'],
    search_criteria: [me, gt('completed_time', psom), and({ field: 'completed_time', condition: 'lesser than', value: String(som.getTime()) })] } });
  const pairs = rows => (rows || []).map(r => ({ c: r.created_time && Number(r.created_time.value), d: r.completed_time && Number(r.completed_time.value) })).filter(x => x.c && x.d && x.d >= x.c);
  const avgH = xs => xs.length ? n2(xs.reduce((s, x) => s + (x.d - x.c), 0) / xs.length / 36e5) : null;
  const done = pairs(doneMonth.requests), prevDone = pairs(donePrev.requests);
  const avgResolveHours = avgH(done), avgResolveHoursPrev = avgH(prevDone);
  // Resolve time per week (this month's closures, plus last month's for a longer line), oldest first.
  const byWeek = {}; done.concat(prevDone).forEach(x => { const d = new Date(x.d); const k = ymd(new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() - ((d.getUTCDay() + 6) % 7)))); (byWeek[k] = byWeek[k] || []).push(x); });
  const resolveWeeks = Object.keys(byWeek).sort().slice(-8).map(k => ({ week: k, hours: avgH(byWeek[k]), n: byWeek[k].length }));
  return {
    source: 'servicedesk-plus-live', asOf: now.toISOString(), isTechnician: total > 0,
    counts: { total, open, onHold, inProgress, pendingVerification: pendingVer, active: open + onHold + inProgress + pendingVer, overdue,
              closedWeek, closedMonth, closed30, closed90, closedMonthPrev, createdMonth, avgResolveHours, avgResolveHoursPrev, resolvedSampled: done.length },
    closedWeeks: weekStarts.map((ws, i) => ({ week: ymd(ws), count: closedWeeks[i] })),
    resolveWeeks,
    tickets: (list.requests || []).map(mapRequest),
  };
}

async function changesAvailable() {
  if (!sdpReady()) return { ok: false, reason: 'sdp-not-configured' };
  // A definitive verdict (reachable, or scope refused) holds for 10 minutes; a transient
  // failure is retried after 60s so one bad call cannot hide the panel for long.
  const ttl = (_changesProbe.ok || _changesProbe.reason === 'changes-scope') ? 10 * 60e3 : 60e3;
  if (Date.now() - _changesProbe.at < ttl && _changesProbe.ok !== null) return { ok: _changesProbe.ok, reason: _changesProbe.reason };
  try {
    await sdpGetGated('/changes', { list_info: { row_count: 1, start_index: 1 } });
    _changesProbe = { at: Date.now(), ok: true, reason: null };
  } catch (e) {
    const st = e.response && e.response.status;
    _changesProbe = { at: Date.now(), ok: false, reason: st === 401 || st === 403 ? 'changes-scope' : ('http-' + (st || 'error')) };
  }
  return { ok: _changesProbe.ok, reason: _changesProbe.reason };
}
function mapChange(c) {
  const stage = (c.stage && c.stage.name) || null, status = (c.status && c.status.name) || null;
  const completed = tsVal(c.completed_time);
  const closedLike = !!completed || /^(completed|closed|cancel|rejected)/i.test(String(status || '')) || /^(close|completed)/i.test(String(stage || ''));
  return {
    id: c.id, displayId: (c.display_id && c.display_id.display_value) || c.display_id || c.id,
    title: c.title || '', stage, status, type: (c.change_type && c.change_type.name) || null, priority: (c.priority && c.priority.name) || null,
    requester: c.change_requester ? (c.change_requester.name || c.change_requester.email_id) : null,
    owner: c.change_owner ? (c.change_owner.name || c.change_owner.email_id) : null,
    createdAt: tsVal(c.created_time), scheduledStart: tsVal(c.scheduled_start_time), scheduledEnd: tsVal(c.scheduled_end_time), completedAt: completed,
    closed: closedLike, url: CHANGE_URL(c.id),
  };
}
async function fetchChanges(email) {
  const avail = await changesAvailable();
  if (!avail.ok) return { available: false, reason: avail.reason, open: [], closed: [] };
  const fields = ['id', 'display_id', 'title', 'stage', 'status', 'change_type', 'priority', 'change_requester', 'change_owner', 'created_time', 'scheduled_start_time', 'scheduled_end_time', 'completed_time'];
  const listFor = async (field) => {
    const d = await sdpGetGated('/changes', { list_info: { row_count: 100, sort_field: 'created_time', sort_order: 'desc', fields_required: fields,
      search_criteria: [{ field, condition: 'is', value: email }] } });
    return d.changes || [];
  };
  let rows = [];
  try { rows = await listFor('change_requester.email_id'); } catch (e) { console.warn('[profile] changes by requester failed:', e.message); }
  try { const own = await listFor('change_owner.email_id'); own.forEach(c => { if (!rows.some(r => r.id === c.id)) rows.push(c); }); } catch (e) { /* owner filter is optional */ }
  const all = rows.map(mapChange).sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')));
  return { available: true, reason: null, asOf: new Date().toISOString(), open: all.filter(c => !c.closed), closed: all.filter(c => c.closed) };
}

router.get('/work', async (req, res) => {
  if (!needUser(req, res)) return;
  const email = who(req);
  const force = req.query.refresh === '1';
  try {
    const hit = _sdpCache.get(email);
    let data;
    if (!force && hit && Date.now() - hit.at < 60e3) data = hit.data;
    else {
      if (!sdpReady()) data = { tickets: { available: false, reason: 'sdp-not-configured' }, changes: { available: false, reason: 'sdp-not-configured', open: [], closed: [] } };
      else {
        const [work, changes] = await Promise.all([
          fetchWork(email).then(w => Object.assign({ available: true }, w)).catch(e => { console.error('[profile] SDP work:', e.message, sdpErrBody(e)); return { available: false, reason: 'sdp-error', detail: (e.message + ' ' + sdpErrBody(e)).slice(0, 160) }; }),
          fetchChanges(email).catch(e => ({ available: false, reason: 'sdp-error', open: [], closed: [] })),
        ]);
        data = { tickets: work, changes };
      }
      _sdpCache.set(email, { at: Date.now(), data });
    }
    const [recent, searches, drafts] = await Promise.all([
      pool.query(`SELECT e.object_type, e.object_id, e.label, e.url, e.created_at FROM profile_events e
                    JOIN (SELECT object_type, object_id, MAX(id) AS id FROM profile_events WHERE email=? AND verb IN ('view','open') AND object_type IN ('asset','ticket','user','change') AND object_id IS NOT NULL GROUP BY object_type, object_id) m ON m.id=e.id
                   ORDER BY e.created_at DESC LIMIT 12`, [email]).then(r => r[0]),
      pool.query('SELECT id, name, kind, query, params, use_count, last_used_at, created_at FROM profile_saved_searches WHERE email=? ORDER BY last_used_at DESC, created_at DESC', [email]).then(r => r[0]),
      pool.query('SELECT draft_key, title, source, updated_at, JSON_LENGTH(body) AS fields FROM profile_drafts WHERE email=? ORDER BY updated_at DESC', [email]).then(r => r[0]),
    ]);
    res.json(Object.assign({}, data, { recent, savedSearches: searches, drafts, cachedAt: (_sdpCache.get(email) || {}).at || null }));
  } catch (e) { console.error('[profile] GET /work', e.message); res.status(500).json({ error: 'Internal error' }); }
});

// GET /api/profile/work/assigned -- the landing page's ticket rows.
//
// Deliberately NOT /work: that route fans out to ~20 ServiceDesk calls to build
// the my-profile dashboard, and the landing page is opened by everyone. This
// needs the open tickets assigned to the caller and a total, which is one call.
// Criteria is techIs(session email) -- the caller can only ever see their own.
const _assignedCache = new Map();
router.get('/work/assigned', async (req, res) => {
  if (!needUser(req, res)) return;
  const email = who(req);
  const hit = _assignedCache.get(email);
  if (hit && Date.now() - hit.at < 60e3) return res.json(hit.data);
  if (!sdpReady()) return res.json({ available: false, reason: 'sdp-not-configured', tickets: [] });
  try {
    const d = await sdpGetGated('/requests', { list_info: {
      row_count: 5, sort_field: 'created_time', sort_order: 'desc', fields_required: REQ_FIELDS,
      search_criteria: [techIs(email), and({ field: 'status.in_progress', condition: 'is', value: true })],
      get_total_count: true } });
    const data = { available: true, asOf: new Date().toISOString(),
                   total: Number((d.list_info && d.list_info.total_count) || 0),
                   tickets: (d.requests || []).map(mapRequest) };
    _assignedCache.set(email, { at: Date.now(), data });
    res.json(data);
  } catch (e) {
    console.error('[profile] GET /work/assigned', e.message, sdpErrBody(e));
    res.status(502).json({ available: false, reason: 'sdp-error', tickets: [] });
  }
});

router.get('/work/tickets/search', async (req, res) => {
  if (!needUser(req, res)) return;
  const q = str(req.query.q, 120);
  if (!q || q.length < 2) return res.status(400).json({ error: 'q must be at least 2 characters' });
  if (!sdpReady()) return res.json({ available: false, reason: 'sdp-not-configured', tickets: [] });
  const scope = req.query.scope === 'all' ? 'all' : 'mine';
  try {
    const criteria = [{ field: 'subject', condition: 'contains', value: q }];
    if (scope === 'mine') criteria.push(and(techIs(who(req))));
    if (req.query.status === 'active') criteria.push(and({ field: 'status.in_progress', condition: 'is', value: true }));
    const d = await sdpGetGated('/requests', { list_info: { row_count: 25, sort_field: 'created_time', sort_order: 'desc', fields_required: REQ_FIELDS, search_criteria: criteria, get_total_count: true } });
    await logEvent(req, { verb: 'search', object_type: 'ticket', object_id: q.toLowerCase(), label: 'Searched tickets for "' + q + '"', meta: { scope }, source: 'my-profile' });
    res.json({ available: true, q, scope, total: Number((d.list_info && d.list_info.total_count) || 0), tickets: (d.requests || []).map(mapRequest) });
  } catch (e) { console.error('[profile] ticket search', e.message); res.status(502).json({ available: false, reason: 'sdp-error', tickets: [] }); }
});

// ───────────────────────── saved searches + drafts ─────────────────────────
router.post('/saved-searches', express.json({ limit: '4kb' }), async (req, res) => {
  if (!needUser(req, res)) return;
  const name = str(req.body && req.body.name, 120), query = str(req.body && req.body.query, 512);
  const kind = ['tickets', 'assets', 'users', 'url'].includes(req.body && req.body.kind) ? req.body.kind : 'tickets';
  if (!name || !query) return res.status(400).json({ error: 'name and query required' });
  if (kind === 'url' && !(query.startsWith('/') && !query.startsWith('//')) && !/^https:\/\/[a-z0-9.-]+\.nrpi\.local(\/|$)/i.test(query)) return res.status(400).json({ error: 'url searches must point at an nrpi.local host' });
  const params = (req.body.params && typeof req.body.params === 'object') ? JSON.stringify(req.body.params).slice(0, 1024) : null;
  try {
    const [[cnt]] = await pool.query('SELECT COUNT(*) AS n FROM profile_saved_searches WHERE email=?', [who(req)]);
    if (cnt.n >= 50) return res.status(409).json({ error: 'Saved search limit reached (50)' });
    const [r] = await pool.execute('INSERT INTO profile_saved_searches (email, name, kind, query, params) VALUES (?,?,?,?,?)', [who(req), name, kind, query, params]);
    await logEvent(req, { verb: 'save', object_type: 'search', object_id: String(r.insertId), label: 'Saved search "' + name + '"', source: req.body.source || 'my-profile' });
    res.status(201).json({ id: r.insertId, name, kind, query });
  } catch (e) { console.error('[profile] POST /saved-searches', e.message); res.status(500).json({ error: 'Internal error' }); }
});
router.post('/saved-searches/:id/used', async (req, res) => {
  if (!needUser(req, res)) return;
  try { await pool.execute('UPDATE profile_saved_searches SET use_count=use_count+1, last_used_at=NOW() WHERE id=? AND email=?', [Number(req.params.id) || 0, who(req)]); res.status(204).end(); }
  catch (e) { res.status(500).json({ error: 'Internal error' }); }
});
router.delete('/saved-searches/:id', async (req, res) => {
  if (!needUser(req, res)) return;
  try {
    const [r] = await pool.execute('DELETE FROM profile_saved_searches WHERE id=? AND email=?', [Number(req.params.id) || 0, who(req)]);
    if (r.affectedRows) await logEvent(req, { verb: 'remove', object_type: 'search', object_id: String(req.params.id), label: 'Removed a saved search', source: 'my-profile' });
    res.status(204).end();
  } catch (e) { res.status(500).json({ error: 'Internal error' }); }
});

router.get('/drafts/:key', async (req, res) => {
  if (!needUser(req, res)) return;
  const key = str(req.params.key, 64);
  try {
    const [[d]] = await pool.query('SELECT draft_key, title, body, source, updated_at FROM profile_drafts WHERE email=? AND draft_key=?', [who(req), key]);
    if (!d) return res.status(404).json({ error: 'No draft' });
    res.json(d);
  } catch (e) { res.status(500).json({ error: 'Internal error' }); }
});
router.put('/drafts/:key', express.json({ limit: '32kb' }), async (req, res) => {
  if (!needUser(req, res)) return;
  const key = str(req.params.key, 64);
  if (!key || !/^[a-z0-9:_-]+$/i.test(key)) return res.status(400).json({ error: 'bad key' });
  const body = req.body && req.body.body;
  if (!body || typeof body !== 'object') return res.status(400).json({ error: 'body object required' });
  try {
    await pool.execute('INSERT INTO profile_drafts (email, draft_key, title, body, source) VALUES (?,?,?,?,?) ON DUPLICATE KEY UPDATE title=VALUES(title), body=VALUES(body), source=VALUES(source)',
      [who(req), key, str(req.body.title, 160), JSON.stringify(body).slice(0, 30000), str(req.body.source, 48)]);
    res.status(204).end();
  } catch (e) { console.error('[profile] PUT /drafts', e.message); res.status(500).json({ error: 'Internal error' }); }
});
router.delete('/drafts/:key', async (req, res) => {
  if (!needUser(req, res)) return;
  try { await pool.execute('DELETE FROM profile_drafts WHERE email=? AND draft_key=?', [who(req), str(req.params.key, 64)]); res.status(204).end(); }
  catch (e) { res.status(500).json({ error: 'Internal error' }); }
});

// ───────────────────────── Claude usage (self) ─────────────────────────
router.get('/claude', async (req, res) => {
  if (!needUser(req, res)) return;
  const month = monthOf(req.query.month) || new Date().toISOString().slice(0, 7);
  // Whose page this is. A failure to resolve the delegation must not 500 the route,
  // so it degrades to the caller's own usage.
  const v = await viewSubject(req).catch(e => { console.warn('[profile] claude viewSubject', e.message); return { email: who(req), viewingAs: null, viewAsDenied: null }; });
  let target = v.email;
  const asked = str(req.query.email, 255);
  if (asked && asked.toLowerCase() !== target) {
    // Reading somebody else's usage takes either super-admin, or a reporting scope
    // that actually contains them — the same scope the Team usage tab is built from,
    // resolved here from the roster and never taken from the query string. This is
    // what the team drill-down uses, so the drill-down cannot reach further than the
    // table it was opened from. Either way it is recorded.
    const wanted = asked.toLowerCase();
    let allowed = !!req.user.isSuperAdmin, via = 'super-admin';
    if (!allowed) {
      const scope = await aiTools.resolveTeamScope(pool, v.email);
      allowed = await aiTools.mayViewMember(pool, scope, wanted);
      via = 'reports-to:' + scope.kind;
    }
    if (!allowed) return res.status(403).json({ error: 'You can only view your own Claude usage, or usage for someone you are authorized to report on', code: 'SELF_ONLY' });
    target = wanted;
    rbac.audit(req, 'profile_claude_view_other', target, 'my-profile', { month, via });
  }
  try {
    const now = new Date(), isCurrent = month === now.toISOString().slice(0, 7);
    const daysInMonth = new Date(Date.UTC(+month.slice(0, 4), +month.slice(5, 7), 0)).getUTCDate();
    const elapsed = isCurrent ? now.getUTCDate() : daysInMonth;
    const q = async (sql, p) => (await pool.query(sql, p))[0];
    const [mtd] = await q(`SELECT COALESCE(SUM(amount_cents),0)/100 AS spend, COALESCE(SUM(requests),0) AS requests, COUNT(DISTINCT day) AS days FROM claude_user_cost_daily WHERE LOWER(email)=? AND DATE_FORMAT(day,'%Y-%m')=?`, [target, month]);
    const [prev] = await q(`SELECT COALESCE(SUM(amount_cents),0)/100 AS spend FROM claude_user_cost_daily WHERE LOWER(email)=? AND DATE_FORMAT(day,'%Y-%m')=DATE_FORMAT(DATE_SUB(CONCAT(?,'-01'), INTERVAL 1 MONTH),'%Y-%m')`, [target, month]);
    const [prevSpan] = await q(`SELECT COALESCE(SUM(amount_cents),0)/100 AS spend FROM claude_user_cost_daily WHERE LOWER(email)=? AND DATE_FORMAT(day,'%Y-%m')=DATE_FORMAT(DATE_SUB(CONCAT(?,'-01'), INTERVAL 1 MONTH),'%Y-%m') AND DAYOFMONTH(day)<=?`, [target, month, elapsed]);
    const products = await q(`SELECT product, SUM(amount_cents)/100 AS spend, SUM(requests) AS requests FROM claude_user_cost_daily WHERE LOWER(email)=? AND DATE_FORMAT(day,'%Y-%m')=? GROUP BY product ORDER BY spend DESC`, [target, month]);
    const series = await q(`SELECT day, SUM(amount_cents)/100 AS spend, SUM(requests) AS requests FROM claude_user_cost_daily WHERE LOWER(email)=? AND day > DATE_SUB(CURDATE(), INTERVAL 90 DAY) GROUP BY day ORDER BY day`, [target]);
    const months = await q(`SELECT DATE_FORMAT(day,'%Y-%m') AS month, SUM(amount_cents)/100 AS spend, SUM(requests) AS requests FROM claude_user_cost_daily WHERE LOWER(email)=? AND day > DATE_SUB(CURDATE(), INTERVAL 6 MONTH) GROUP BY month ORDER BY month`, [target]);
    const [tokens] = await q(`SELECT COALESCE(SUM(total_tokens),0) AS total, COALESCE(SUM(uncached_input),0) AS uncachedInput, COALESCE(SUM(cache_read),0) AS cacheRead, COALESCE(SUM(cache_creation_5m+cache_creation_1h),0) AS cacheCreated, COALESCE(SUM(output_tokens),0) AS output, COALESCE(SUM(web_search_requests),0) AS webSearches FROM claude_user_usage_daily WHERE LOWER(email)=? AND DATE_FORMAT(day,'%Y-%m')=?`, [target, month]);
    const [act] = await q(`SELECT COALESCE(SUM(cc_sessions),0) AS ccSessions, COALESCE(SUM(cc_commits),0) AS ccCommits, COALESCE(SUM(cc_prs),0) AS ccPrs, COALESCE(SUM(cc_loc_added),0) AS locAdded, COALESCE(SUM(cc_loc_removed),0) AS locRemoved,
        COALESCE(SUM(cc_edits_accepted),0) AS editsAccepted, COALESCE(SUM(cc_edits_rejected),0) AS editsRejected, COALESCE(SUM(cowork_sessions),0) AS coworkSessions, COALESCE(SUM(cowork_file_edits),0) AS coworkFileEdits,
        COALESCE(SUM(cowork_actions),0) AS coworkActions, COALESCE(SUM(cowork_messages),0) AS coworkMessages, COALESCE(SUM(design_sessions),0) AS designSessions,
        COALESCE(SUM(chat_conversations),0) AS chatConversations, COALESCE(SUM(chat_messages),0) AS chatMessages, COALESCE(SUM(chat_artifacts),0) AS chatArtifacts,
        COALESCE(SUM(chat_projects_used),0) AS chatProjectsUsed, COALESCE(SUM(chat_projects_created),0) AS chatProjectsCreated, COALESCE(SUM(chat_skills_used),0) AS chatSkillsUsed,
        COALESCE(SUM(office_sessions),0) AS officeSessions, COALESCE(SUM(science_sessions),0) AS scienceSessions,
        COALESCE(SUM(web_search_count),0) AS webSearches, MAX(last_activity_date) AS lastActivity, COUNT(DISTINCT day) AS activeDays
        FROM claude_user_activity_daily WHERE LOWER(email)=? AND DATE_FORMAT(day,'%Y-%m')=?`, [target, month]);
    const recent = await q(`SELECT c.day, SUM(c.amount_cents)/100 AS spend, SUM(c.requests) AS requests, MAX(a.cc_sessions) AS ccSessions, MAX(a.cc_edits_accepted) AS edits, GROUP_CONCAT(DISTINCT c.product ORDER BY c.product) AS products
        FROM claude_user_cost_daily c LEFT JOIN claude_user_activity_daily a ON a.day=c.day AND LOWER(a.email)=LOWER(c.email)
        WHERE LOWER(c.email)=? AND c.day > DATE_SUB(CURDATE(), INTERVAL 14 DAY) GROUP BY c.day ORDER BY c.day DESC`, [target]);
    const monthsAct = await q(`SELECT DATE_FORMAT(day,'%Y-%m') AS month, COALESCE(SUM(cc_sessions),0) AS ccSessions, COALESCE(SUM(cc_edits_accepted),0) AS edits, COUNT(DISTINCT day) AS activeDays FROM claude_user_activity_daily WHERE LOWER(email)=? AND day > DATE_SUB(CURDATE(), INTERVAL 6 MONTH) GROUP BY month ORDER BY month`, [target]);
    const [prevAct] = await q(`SELECT COALESCE(SUM(cc_sessions),0) AS ccSessions FROM claude_user_activity_daily WHERE LOWER(email)=? AND DATE_FORMAT(day,'%Y-%m')=DATE_FORMAT(DATE_SUB(CONCAT(?,'-01'), INTERVAL 1 MONTH),'%Y-%m')`, [target, month]);

    // Can whoever is reading this raise THIS person's Claude limit from here? The
    // drill-down is where a manager forms the opinion, so the control belongs here
    // and not only in the table they arrived from. Both refusals the POST can give
    // -- not-your-report (403) and no-limit-row (409) -- are answered before the
    // button is drawn, so the page never offers an action that would be rejected.
    const filer = who(req);
    const monthDaily = await q(`SELECT day, SUM(amount_cents)/100 AS spend FROM claude_user_cost_daily WHERE LOWER(email)=? AND DATE_FORMAT(day,'%Y-%m')=? GROUP BY day ORDER BY day`, [target, month]);
    // The cap can move mid-month, so it is read per day and drawn as a step. Days with
    // no snapshot fall back to the cap in force now, which the client is also given.
    const capDaily = await q(`SELECT day, amount_cents/100 AS cap FROM claude_spend_limit_daily WHERE LOWER(email)=? AND period='monthly' AND DATE_FORMAT(day,'%Y-%m')=? ORDER BY day`, [target, month]);

    // Per-person model usage AND cost. The user reports accept group_by[]=model, which is
    // what claude_user_model_daily stores; the org-only model tables cannot answer this.
    const modelRows = await q(`SELECT model, product, SUM(amount_cents)/100 AS spend, SUM(requests) AS requests,
        SUM(total_tokens) AS tokens, SUM(output_tokens) AS output, SUM(cache_read) AS cacheRead
        FROM claude_user_model_daily WHERE LOWER(email)=? AND DATE_FORMAT(day,'%Y-%m')=?
        GROUP BY model, product ORDER BY SUM(amount_cents) DESC`, [target, month]);

    const limitReq = await (async () => {
      const lrows = await q("SELECT amount_cents, currency, ptd_spend_cents FROM claude_spend_limit WHERE period='monthly' AND deleted=0 AND LOWER(email)=? LIMIT 1", [target]);
      const lim = lrows[0] || null;
      const out = {
        can: false, reason: null,
        current: lim && lim.amount_cents != null ? Math.round(Number(lim.amount_cents)) / 100 : null,
        ptdSpend: lim ? Math.round(Number(lim.ptd_spend_cents) || 0) / 100 : null,
        currency: (lim && lim.currency) || 'USD',
      };
      if (target === filer) { out.reason = 'self'; return out; }
      // A borrowed view is read-only everywhere else on this page; it stays read-only here.
      if (v.viewingAs) { out.reason = 'viewing-as'; return out; }
      const [[person]] = await pool.query('SELECT manager_email FROM org_reporting_person WHERE email = ?', [target]);
      if (!person) { out.reason = 'not-in-tree'; return out; }
      if (String(person.manager_email || '').toLowerCase() !== filer) {
        const [[edge]] = await pool.query('SELECT depth FROM org_reporting_edge WHERE manager_email = ? AND member_email = ? LIMIT 1', [filer, target]);
        if (!edge) { out.reason = 'not-your-report'; return out; }
      }
      if (!lim) { out.reason = 'no-limit-row'; return out; }
      out.can = true;
      return out;
    })();
    const [sync] = await q(`SELECT MAX(ran_at) AS lastRun, MAX(data_refreshed_at) AS dataRefreshedAt FROM claude_sync_log WHERE status='ok'`);
    const [[member]] = await pool.query(`SELECT display_name, MIN(day) AS firstDay FROM claude_user_cost_daily WHERE LOWER(email)=? GROUP BY display_name ORDER BY firstDay LIMIT 1`, [target]);
    // Entitlement travels with the usage so the drill-down can say "no Claude access"
    // instead of drawing a page of zeroes, and so a month outside the collector's
    // coverage window reads as unknown rather than as nothing spent.
    const ent = await aiTools.entitlementFor(pool, target).catch(e => { console.warn('[profile] claude entitlement', e.message); return { entitlement: null, feeds: null }; });
    const coverage = await aiTools.periodCoverage(pool, month, ent.feeds || undefined).catch(() => null);
    const spend = Number(mtd.spend) || 0, base = isCurrent ? Number(prevSpan.spend) : Number(prev.spend);
    if (target === who(req)) logEvent(req, { verb: 'view', object_type: 'page', object_id: 'claude-usage', label: 'Viewed Claude usage for ' + month, source: 'my-profile' });
    res.json({
      // isSelf stays literal -- the signed-in user's own row and nobody else's -- so
      // a borrowed view gets third-person copy instead of words put in its mouth.
      subject: { email: target, isSelf: target === who(req), displayName: member ? member.display_name : null, firstSeen: member ? member.firstDay : null },
      viewingAs: v.viewingAs, viewAsDenied: v.viewAsDenied,
      month, isCurrent, daysElapsed: elapsed, daysInMonth,
      spend: n2(spend), requests: Number(mtd.requests) || 0, daysWithUsage: Number(mtd.days) || 0,
      prevMonthSpend: n2(prev.spend), prevMonthSameSpan: n2(prevSpan.spend),
      momPct: base > 0 ? n2((spend / base - 1) * 100) : null, momBasis: isCurrent ? 'same-span' : 'full-month',
      runRatePerDay: n2(elapsed ? spend / elapsed : 0), projectedMonthEnd: isCurrent ? n2((spend / Math.max(elapsed, 1)) * daysInMonth) : null,
      products: products.map(p => ({ product: p.product || 'other', spend: n2(p.spend), requests: Number(p.requests) || 0 })),
      series: series.map(s => ({ day: ymd(new Date(s.day)), spend: n2(s.spend), requests: Number(s.requests) || 0 })),
      months: months.map(m => ({ month: m.month, spend: n2(m.spend), requests: Number(m.requests) || 0 })),
      monthsActivity: monthsAct.map(m => ({ month: m.month, ccSessions: Number(m.ccSessions) || 0, edits: Number(m.edits) || 0, activeDays: Number(m.activeDays) || 0 })),
      prevMonthSessions: Number(prevAct.ccSessions) || 0,
      tokens: { total: Number(tokens.total), uncachedInput: Number(tokens.uncachedInput), cacheRead: Number(tokens.cacheRead), cacheCreated: Number(tokens.cacheCreated), output: Number(tokens.output), webSearches: Number(tokens.webSearches) },
      activity: Object.fromEntries(Object.entries(act).map(([k, v]) => [k, v instanceof Date ? ymd(v) : (v == null ? null : Number(v))])),
      recent: recent.map(r => ({ day: ymd(new Date(r.day)), spend: n2(r.spend), requests: Number(r.requests) || 0, ccSessions: Number(r.ccSessions) || 0, edits: Number(r.edits) || 0, products: r.products })),
      models: (() => {
        const by = new Map();
        for (const r of modelRows) {
          const k = r.model || 'no-model';
          if (!by.has(k)) by.set(k, { model: k, spend: 0, requests: 0, tokens: 0, output: 0, cacheRead: 0, products: [] });
          const m = by.get(k);
          // Summed raw and rounded once at the end -- the amounts are fractional cents.
          m.spend += Number(r.spend) || 0;
          m.requests += Number(r.requests) || 0;
          m.tokens += Number(r.tokens) || 0;
          m.output += Number(r.output) || 0;
          m.cacheRead += Number(r.cacheRead) || 0;
          m.products.push({ product: r.product || 'other', spend: n2(r.spend),
            requests: Number(r.requests) || 0, tokens: Number(r.tokens) || 0 });
        }
        return [...by.values()].map(m => ({ ...m, spend: n2(m.spend),
          products: m.products.sort((a, b) => b.spend - a.spend) }))
          .sort((a, b) => b.spend - a.spend || b.requests - a.requests);
      })(),
      limitRequest: limitReq,
      limitTrend: {
        cap: limitReq.current, daysInMonth, daysElapsed: elapsed, isCurrent,
        days: monthDaily.map(r => ({ day: ymd(new Date(r.day)), spend: n2(r.spend) })),
        caps: capDaily.map(r => ({ day: ymd(new Date(r.day)), cap: n2(r.cap) })),
      },
      access: ent.entitlement ? { claude: ent.entitlement.claude, copilot: ent.entitlement.copilot } : null,
      periodCoverage: coverage, feeds: ent.feeds || null,
      dataRefreshedAt: sync ? sync.dataRefreshedAt : null, lastSyncAt: sync ? sync.lastRun : null,
    });
  } catch (e) { console.error('[profile] GET /claude', e.message); res.status(500).json({ error: 'Internal error' }); }
});

// ═════════════════════ AI tools & usage ═════════════════════
// Two questions this page has to keep apart, because conflating them is the
// classic reporting bug: "what am I licensed for" (entitlement, from the vendor
// rosters) and "what did I use" (usage, from the cost and activity feeds). A
// seat with no spend is not an absent seat, and spend is never treated as proof
// of a seat. ai-tools-lib.js holds those rules; these routes hold authorization.
//
// Authorization is entirely server-side and comes from scope-lib — the same
// ladder the rest of the platform reports on (assigned → AD group → leader →
// manager → self → unknown, failing closed). Nothing about who a caller may see
// is read from the query string. Holding a Claude seat grants no reporting
// scope, and holding reporting scope grants no seat: personal licensing and
// permission to read team reports are separate all the way down.

// The Hub tile is the console-managed source of truth for where an access
// request goes, so the destination is read from landing.json rather than
// configured a second time here.
// One correction is applied: the tile still points at the accessportal.itam host
// that was retired on 2026-09-09 and now answers 404, while the live portal is
// accessportal.nrpi.local. Flip the tile in the console and this becomes dead code.
const RETIRED_PORTAL_HOSTS = { 'accessportal.itam.nrpi.local': 'accessportal.nrpi.local' };
async function aiRequestAccessLink() {
  try {
    const hub = await hubLinks();
    const tile = (hub.links || []).find(l => /access\s*portal/i.test(l.title || ''));
    if (!tile || !tile.url) return { available: false, reason: 'no-access-portal-tile' };
    let url = tile.url, corrected = false;
    try {
      const u = new URL(url, 'https://corpit.nrpi.local');
      if (RETIRED_PORTAL_HOSTS[u.hostname]) { u.hostname = RETIRED_PORTAL_HOSTS[u.hostname]; url = u.toString(); corrected = true; }
    } catch (e) { /* a relative or malformed tile URL is used as published */ }
    return {
      available: true, url, corrected,
      label: 'Request access', via: 'Access Portal',
      // The portal's intake form for AI tooling. Its SPA has no deep links, so the
      // portal root is the most specific destination that actually resolves —
      // promising a direct link to the form would be a link that does not work.
      form: 'AI Use Case Intake',
      note: 'Opens the Access Portal. Choose “AI Use Case Intake” to request Claude or Microsoft Copilot.',
    };
  } catch (e) { return { available: false, reason: 'unavailable' }; }
}

// Compact usage for one person in one month — what the personal card needs, and
// the only place the three usage states are decided for a single subject.
async function aiSelfUsage(target, month, coverage, claudeAccess) {
  if (!coverage.zeroIsMeasured) return { state: 'unavailable', reason: coverage.state, touched: false };
  const q = async (sql, p) => (await pool.query(sql, p))[0];
  const [[cost], [act], [tok], [prev]] = await Promise.all([
    q("SELECT COALESCE(SUM(amount_cents),0)/100 AS spend, COALESCE(SUM(requests),0) AS requests, COUNT(DISTINCT day) AS days FROM claude_user_cost_daily WHERE LOWER(email)=? AND DATE_FORMAT(day,'%Y-%m')=?", [target, month]),
    q("SELECT COALESCE(SUM(cc_sessions),0) AS ccSessions, COALESCE(SUM(chat_conversations),0) AS chats, COALESCE(SUM(cowork_sessions),0) AS cowork, COALESCE(SUM(cc_edits_accepted),0) AS edits, MAX(last_activity_date) AS lastActivity, COUNT(DISTINCT day) AS activeDays FROM claude_user_activity_daily WHERE LOWER(email)=? AND DATE_FORMAT(day,'%Y-%m')=?", [target, month]),
    q("SELECT COALESCE(SUM(total_tokens),0) AS tokens FROM claude_user_usage_daily WHERE LOWER(email)=? AND DATE_FORMAT(day,'%Y-%m')=?", [target, month]),
    q("SELECT COALESCE(SUM(amount_cents),0)/100 AS spend FROM claude_user_cost_daily WHERE LOWER(email)=? AND DATE_FORMAT(day,'%Y-%m')=DATE_FORMAT(DATE_SUB(CONCAT(?,'-01'), INTERVAL 1 MONTH),'%Y-%m') AND (? = 0 OR DAYOFMONTH(day) <= ?)", [target, month, coverage.isCurrent ? coverage.daysElapsed : 0, coverage.isCurrent ? coverage.daysElapsed : 31]),
  ]);
  const spend = n2(cost.spend), prevSpend = n2(prev.spend);
  const touched = spend > 0 || Number(cost.requests) > 0 || Number(act.activeDays) > 0 || Number(tok.tokens) > 0;
  // Same three-state ladder the team roll-up uses, so both views agree: a period
  // we cannot measure is not "no usage", and someone with no seat is not either.
  return {
    state: claudeAccess === 'none' ? 'no-access' : touched ? 'active' : 'no-usage',
    touched,
    spend, requests: Number(cost.requests) || 0, daysWithSpend: Number(cost.days) || 0,
    sessions: Number(act.ccSessions) || 0, chats: Number(act.chats) || 0,
    coworkSessions: Number(act.cowork) || 0, editsAccepted: Number(act.edits) || 0,
    activeDays: Number(act.activeDays) || 0,
    lastActivity: act.lastActivity ? ymd(new Date(act.lastActivity)) : null,
    tokens: Number(tok.tokens) || 0,
    prevSpend, momPct: prevSpend > 0 ? n2((spend / prevSpend - 1) * 100) : null,
    momBasis: coverage.isCurrent ? 'same-span' : 'full-month',
  };
}

// GET /api/profile/ai-tools — the signed-in person's own entitlement and usage.
// Answered for the View-As subject when one is approved, otherwise the caller.
// There is still no ?email= here: reading an arbitrary person's numbers goes
// through /claude, which checks scope for it.
router.get('/ai-tools', async (req, res) => {
  if (!needUser(req, res)) return;
  const self = who(req);
  const month = monthOf(req.query.month) || new Date().toISOString().slice(0, 7);
  try {
    const v = await viewSubject(req);
    const me = v.email, isSelf = me === self;
    const [{ entitlement, feeds }, periods, link] = await Promise.all([
      aiTools.entitlementFor(pool, me),
      aiTools.availablePeriods(pool, 12),
      aiRequestAccessLink(),
    ]);
    const coverage = await aiTools.periodCoverage(pool, month, feeds);
    const claude = entitlement ? entitlement.claude : { access: 'unavailable', reason: 'not-resolved' };
    const copilot = entitlement ? entitlement.copilot : { access: 'unavailable', reason: 'not-resolved' };
    const usage = await aiSelfUsage(me, month, coverage, claude.access);

    // Scope is resolved even for people who have none, so the page can say
    // plainly that there is no team view rather than silently omitting the tab.
    let scope = null;
    const viewingAs = v.viewingAs, viewAsDenied = v.viewAsDenied;
    try {
      scope = await aiTools.resolveTeamScope(pool, me);
    } catch (e) { console.warn('[profile] ai-tools scope', e.message); }

    // Entitlement and usage disagreeing is a data-quality fact worth surfacing,
    // not something to paper over by promoting usage into a licence.
    const conflict = claude.access === 'none' && usage.touched
      ? (isSelf
          ? 'Usage was recorded for this period but you are not on the Claude member roster. That is a data mismatch, not a licence.'
          : 'Usage was recorded for this period but this person is not on the Claude member roster. That is a data mismatch, not a licence.')
      : null;

    // Activity is the subject's own history. A borrowed read is not their activity
    // and must not be written into it; it is audited instead.
    if (isSelf) logEvent(req, { verb: 'view', object_type: 'page', object_id: 'ai-tools', label: 'Viewed AI tools & usage for ' + month, source: 'my-profile' });
    else rbac.audit(req, 'profile_ai_tools_view_other', me, 'my-profile', { month, via: viewingAs && viewingAs.via });
    res.json({
      subject: { email: me, displayName: (isSelf && req.user && req.user.displayName) || null, isSelf },
      viewingAs, viewAsDenied,
      period: coverage, periods,
      claude, copilot, usage, conflict,
      // Nobody can request a seat on somebody else's behalf from here, so the link is
      // withheld rather than shown pointing at the wrong person's request form.
      requestAccess: isSelf ? link : { available: false, reason: 'not-self' },
      team: Object.assign(aiTools.publicScope(scope, viewingAs), {
        available: !!aiTools.teamScopeKind(scope),
        viewAsDenied,
      }),
      feeds,
    });
  } catch (e) { console.error('[profile] GET /ai-tools', e.message); res.status(500).json({ error: 'Internal error' }); }
});

/**
 * The identity a request is answered for. Normally the signed-in user; with an
 * approved View-As delegation, the person being stood in for. The delegation is
 * checked by scope-lib (`rbac_view_as`) against the CALLER, so naming somebody in
 * the query string grants nothing: an unapproved target falls back to the caller
 * and the refusal travels back as viewAsDenied rather than silently.
 */
async function viewSubject(req) {
  const me = who(req);
  const raw = (req.query && req.query.viewAs) || (req.get && req.get('x-view-as')) || '';
  const target = String(raw || '').trim().toLowerCase();
  if (!target || target === me) return { email: me, viewingAs: null, viewAsDenied: null };
  const v = await scopeLib.canViewAs(pool, me, target);
  if (!v.ok) return { email: me, viewingAs: null, viewAsDenied: v.reason };
  return { email: target, viewingAs: { email: target, label: v.scope && v.scope.label, via: v.level }, viewAsDenied: null };
}

// GET /api/profile/ai-team — the roll-up for everyone the caller is authorized to see.
// Access is the Active Directory reporting line and nothing else: you get a team
// view if people report to you, and it covers your subtree only. The population is
// that subtree, NOT the Claude member list — a manager has to be able to see who on
// their team has no seat, so people without access are rows in this table too.
router.get('/ai-team', async (req, res) => {
  if (!needUser(req, res)) return;
  const month = monthOf(req.query.month) || new Date().toISOString().slice(0, 7);
  try {
    const v = await viewSubject(req);
    const viewingAs = v.viewingAs, viewAsDenied = v.viewAsDenied;
    const scope = await aiTools.resolveTeamScope(pool, v.email);
    if (!aiTools.teamScopeKind(scope)) {
      // Not an error the caller can fix by retrying: they manage nobody. The
      // message says so rather than implying a missing permission.
      return res.status(403).json({
        error: scope.note || 'You do not have any direct reports, so there is no team to report on',
        code: 'NO_TEAM_SCOPE',
        scope: aiTools.publicScope(scope, viewingAs),
      });
    }
    const report = await aiTools.teamReport(pool, scope, { month, viewingAs, viewerEmail: who(req) });
    if (viewAsDenied) report.viewAsDenied = viewAsDenied;
    // Tickets already raised for this period, so the page offers "open the ticket"
    // instead of a button that would be refused as a duplicate.
    try {
      const [tix] = await pool.query(
        `SELECT subject_email, status, sdp_display_id, sdp_url, recommended, created_at
           FROM claude_limit_increase_ticket WHERE period = ? AND manager_email = ?`,
        [month, v.email]);
      report.limitTickets = tix.map((t) => ({
        email: t.subject_email, status: t.status, ticket: t.sdp_display_id,
        url: t.sdp_url, recommended: t.recommended == null ? null : Number(t.recommended),
        filedAt: t.created_at,
      }));
    } catch (e) { console.warn('[profile] limit tickets', e.message); report.limitTickets = []; }
    // A borrowed view is read-only, so the button must not be offered in one --
    // the router guard would refuse the POST anyway, and a dead button is worse
    // than none. `canRequest` is the single flag the page reads.
    report.canRequest = !viewingAs;
    rbac.audit(req, 'profile_ai_team_view', null, 'my-profile', {
      month, scopeKind: scope.kind, directReports: scope.directReports, people: report.members.length,
      viewingAs: viewingAs ? viewingAs.email : null,
    });
    res.json(report);
  } catch (e) { console.error('[profile] GET /ai-team', e.message); res.status(500).json({ error: 'Internal error' }); }
});

/**
 * POST /api/profile/ai-team/limit-request — raise a Claude spend-limit increase
 * with the Service Desk for ONE of the caller's direct reports.
 *
 * Two rules shape this route:
 *  1. Every figure is recomputed here from the spend-limit feed. The client sends
 *     an email address and nothing else -- numbers posted by a browser would end
 *     up quoted as fact inside a ticket a human then acts on.
 *  2. Only the person's OWN manager may raise it. Somebody further up the tree has
 *     a manager between them and this person, and that manager is who should be
 *     having the conversation.
 *
 * The View-As guard earlier in this file already refuses any non-GET carrying
 * X-View-As, so a borrowed view cannot file a ticket in somebody else's name.
 */
router.post('/ai-team/limit-request', async (req, res) => {
  if (!needUser(req, res)) return;
  const self = who(req);
  const target = str(req.body && req.body.email, 255).toLowerCase();
  // The manager may name the ABSOLUTE new monthly total they want this person
  // raised to (dollars: 200 = a $200/mo cap, NOT a $200 increase). Optional — with
  // no figure the server recommends one, exactly as before.
  let askTotal = null;
  {
    const raw = req.body && req.body.newLimit;
    if (raw !== undefined && raw !== null && String(raw).trim() !== '') {
      askTotal = Number(raw);
      if (!Number.isFinite(askTotal) || askTotal <= 0) {
        return res.status(400).json({ error: 'Enter the new monthly total as a number, e.g. 200.', code: 'BAD_AMOUNT' });
      }
      askTotal = Math.round(askTotal * 100) / 100;
      if (askTotal > 1000000) {
        return res.status(400).json({ error: 'That new total looks too high — enter the monthly cap in dollars.', code: 'AMOUNT_TOO_HIGH' });
      }
    }
  }
  const month = new Date().toISOString().slice(0, 7);
  if (!target) return res.status(400).json({ error: 'Which person is this for?', code: 'NO_TARGET' });
  if (target === self) {
    return res.status(400).json({
      error: 'This raises a request for one of your direct reports. To change your own limit, ask your manager.',
      code: 'NOT_A_REPORT',
    });
  }
  try {
    // ── 1. is this actually YOUR direct report? One indexed read, no tree walk.
    const [[person]] = await pool.query(
      `SELECT p.email, p.display_name, p.job_title, p.manager_email, mp.display_name AS manager_name
         FROM org_reporting_person p
         LEFT JOIN org_reporting_person mp ON mp.email = p.manager_email
        WHERE p.email = ?`, [target]);
    if (!person) {
      return res.status(404).json({ error: 'That person is not in the Active Directory org tree.', code: 'NOT_IN_TREE' });
    }
    // A director is accountable for their whole subtree and sees it on the same
    // page, so they may raise this for anyone below them — but only for someone
    // actually below them. The edge table answers that with one indexed read; a
    // missing row is a refusal, so a tree that has not been built yet cannot let
    // anybody file for anybody.
    const directManager = String(person.manager_email || '').toLowerCase() === self;
    let viaDepth = 1;
    if (!directManager) {
      const [[edge]] = await pool.query(
        'SELECT depth FROM org_reporting_edge WHERE manager_email = ? AND member_email = ? LIMIT 1',
        [self, target]);
      if (!edge) {
        return res.status(403).json({
          error: 'You can only raise this for someone in your own reporting line. '
               + (person.manager_name ? person.manager_name + ' is their manager.' : ''),
          code: 'NOT_YOUR_REPORT',
        });
      }
      viaDepth = Number(edge.depth) || 2;
    }

    // ── 2. the figures, from the same feed the page and the ticket both quote.
    const [[lim]] = await pool.query(
      "SELECT amount_cents, currency, source_type, ptd_spend_cents, fetched_at FROM claude_spend_limit "
      + "WHERE period = 'monthly' AND deleted = 0 AND LOWER(email) = ? LIMIT 1", [target]);
    if (!lim) {
      return res.status(409).json({
        error: (person.display_name || target) + ' has no Claude spend limit on record, so there is nothing to raise.',
        code: 'NO_LIMIT_ROW',
      });
    }
    const limit = lim.amount_cents == null ? null : Math.round(Number(lim.amount_cents)) / 100;
    const ptd = Math.round(Number(lim.ptd_spend_cents) || 0) / 100;
    const cfg = await aiTools.spendAlertConfig();
    // The filer's own threshold, so the route refuses on exactly the number the
    // card used to offer the button. A shared default here and a personal number
    // on the page is how a button appears and then says no.
    const ownTh = await aiTools.managerThreshold(pool, self);
    const effTh = spendAlert.effectiveThreshold(ownTh, cfg.threshold);
    cfg.threshold = effTh.threshold;
    // The ticket quotes where the number came from, so "below the threshold" can
    // be checked against a threshold somebody can point at.
    cfg.source = effTh.source === 'manager' ? 'chosen by ' + (req.user.displayName || self)
      : effTh.source === 'console' ? 'platform default, set in the admin console'
        : 'built-in default';
    const now = new Date();
    const daysInMonth = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 0)).getUTCDate();
    const daysElapsed = now.getUTCDate();
    const state = spendAlert.stateFor(ptd, limit, cfg.threshold);
    const pct = spendAlert.pctOf(ptd, limit);
    const rec = spendAlert.recommend({ limit, ptdSpend: ptd, daysElapsed, daysInMonth });

    // An explicit manager amount is a deliberate ask, so it must clear the current
    // cap but is not held to the "near the threshold yet" gates below.
    if (askTotal !== null && limit !== null && askTotal <= limit) {
      return res.status(400).json({
        error: (person.display_name || target) + ' is already at ' + spendAlert.money(limit)
             + '/mo. Enter a higher monthly total.', code: 'AMOUNT_NOT_HIGHER',
      });
    }
    if (state === 'no-limit') {
      return res.status(409).json({
        error: (person.display_name || target) + ' has no monthly cap, so there is no limit to raise.',
        code: 'NO_LIMIT',
      });
    }
    if (state === 'ok' && askTotal === null) {
      return res.status(409).json({
        error: (person.display_name || target) + ' is at ' + (pct == null ? '—' : pct + '%')
             + ' of their limit, below the ' + cfg.threshold + '% threshold. Nothing to raise yet.',
        code: 'BELOW_THRESHOLD',
      });
    }
    // The honest refusal: near the threshold but on course to finish inside the cap.
    if (!rec.needed && state !== 'over' && askTotal === null) {
      return res.status(409).json({
        error: rec.note || 'At the current rate this month closes inside the limit, so an increase is not needed yet.',
        code: 'ON_TRACK', projected: rec.projected,
      });
    }
    // Over the limit with no computable projection still deserves a ticket; give it
    // a recommendation rather than a null the Service Desk has to guess at.
    const recommended = askTotal !== null ? askTotal
      : rec.amount != null ? rec.amount
      : (limit != null ? spendAlert.roundUpTo(Math.max(ptd, limit) * 1.25, spendAlert.stepFor(limit)) : null);

    // ── 3. claim the slot BEFORE calling SDP. The unique key on (subject, period)
    // is what stops a double-click becoming two tickets for the same person.
    // Active Directory's own display name first: it is what the rest of this page
    // calls the manager, and a session displayName can be a bare login handle.
    const managerName = person.manager_name || (req.user && req.user.displayName) || self;
    let rowId = null;
    try {
      const [ins] = await pool.query(
        `INSERT INTO claude_limit_increase_ticket
           (subject_email, subject_name, manager_email, manager_name, period, current_limit,
            ptd_spend, pct, projected, recommended, days_elapsed, days_in_month, status)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?, 'filing')`,
        [target, person.display_name || target, self, managerName, month, limit,
         ptd, pct, rec.projected, recommended, daysElapsed, daysInMonth]);
      rowId = ins.insertId;
    } catch (e) {
      if (e && e.code === 'ER_DUP_ENTRY') {
        const [[open]] = await pool.query(
          'SELECT status, sdp_display_id, sdp_url, recommended, created_at FROM claude_limit_increase_ticket WHERE subject_email = ? AND period = ?',
          [target, month]);
        return res.status(409).json({
          error: 'A request for ' + (person.display_name || target) + ' was already raised this month.',
          code: 'ALREADY_FILED',
          ticket: open ? { status: open.status, ticket: open.sdp_display_id, url: open.sdp_url,
                           recommended: open.recommended == null ? null : Number(open.recommended),
                           filedAt: open.created_at } : null,
        });
      }
      throw e;
    }

    // ── 4. the ticket itself.
    const M = spendAlert.money;
    const monthName = new Date(month + '-01T00:00:00Z').toLocaleString('en-US', { month: 'long', year: 'numeric', timeZone: 'UTC' });
    const basis = lim.source_type === 'user' ? 'individual limit' : 'plan default (' + (lim.source_type || 'inherited') + ')';
    const subject = '[Claude spend] Increase request for ' + (person.display_name || target)
      + ' — ' + (pct == null ? 'at limit' : pct + '% of ' + M(limit)) + ' monthly limit';
    const description = [
      'Raised from CorpIT Hub → My Profile → AI tools & usage.',
      '',
      'PERSON            ' + (person.display_name || target) + ' <' + target + '>'
        + (person.job_title ? ' — ' + person.job_title : ''),
      'MANAGER           ' + managerName + ' <' + self + '>'
        + (directManager ? '' : ' — raised as their director, not their line manager'),
      // Whoever picks this up needs to know they may be talking to somebody other
      // than the person's own manager, and who that manager is.
      (directManager ? null
        : 'LINE MANAGER      ' + (person.manager_name || person.manager_email || 'unknown')
          + (person.manager_email ? ' <' + person.manager_email + '>' : '')
          + '  (requester is ' + viaDepth + ' levels up)'),
      'PERIOD            ' + monthName + ' — day ' + daysElapsed + ' of ' + daysInMonth,
      '',
      'Current limit     ' + M(limit) + ' per month (' + basis + ')',
      'Spent so far      ' + M(ptd) + (pct == null ? '' : '  (' + pct + '% of the limit)'),
      'Projected close   ' + (rec.projected == null ? 'not computable' : M(rec.projected) + ' at the current run rate'),
      (askTotal !== null
        ? 'REQUESTED TOTAL   ' + M(askTotal) + '/mo — the amount ' + managerName + ' asked to raise this person to'
        : 'RECOMMENDED       ' + (recommended == null ? 'review' : M(recommended) + ' for ' + monthName)),
      '',
      rec.note || (state === 'over' ? 'This person has already passed their monthly limit.' : ''),
      '',
      'Action requested: raise the monthly Claude spend limit for ' + target
        + (recommended == null ? '.' : ' to ' + M(recommended) + '.'),
      '',
      'Figures come from the Anthropic Admin API spend-limit feed, which refreshes hourly.',
      'This pull: ' + (lim.fetched_at ? new Date(lim.fetched_at).toISOString().replace('T', ' ').slice(0, 19) + ' UTC' : 'unknown') + '.',
      'Alert threshold: ' + cfg.threshold + '% (' + cfg.source + ').',
    ].filter((l) => l !== null && l !== undefined).join('\n');

    if (!sdp || !sdp.createTicket) {
      await pool.query('DELETE FROM claude_limit_increase_ticket WHERE id = ?', [rowId]);
      return res.status(503).json({ error: 'The Service Desk integration is not available on this host, so no ticket was raised.', code: 'SDP_UNAVAILABLE' });
    }
    let ticket = null, usedFallback = false, firstErr = null;
    try {
      ticket = await sdp.createTicket({ subject, description, requesterEmail: self, requesterName: managerName });
    } catch (e) {
      // The manager may not exist as an SDP requester. Filing it under the IT
      // Command mailbox is better than losing the request -- the description
      // names the manager either way -- but the fallback is recorded, not hidden.
      firstErr = e.message;
      try {
        ticket = await sdp.createTicket({
          subject,
          description: description + '\n\nNOTE: raised under the IT Command mailbox because the requester lookup for ' + self + ' failed (' + e.message + ').',
          requesterEmail: 'itcommand@auction.com', requesterName: 'IT Command',
        });
        usedFallback = true;
      } catch (e2) {
        await pool.query('DELETE FROM claude_limit_increase_ticket WHERE id = ?', [rowId]);
        console.error('[profile] limit-request SDP', e.message, '/', e2.message);
        return res.status(502).json({ error: 'The Service Desk refused the ticket: ' + e2.message + '. Nothing was filed — you can try again.', code: 'SDP_FAILED' });
      }
    }
    await pool.query(
      'UPDATE claude_limit_increase_ticket SET status = ?, sdp_request_id = ?, sdp_display_id = ?, sdp_url = ?, fail_reason = ? WHERE id = ?',
      ['filed', String(ticket.id), String(ticket.display_id), ticket.url,
       usedFallback ? ('requester fallback: ' + String(firstErr).slice(0, 200)) : null, rowId]);

    rbac.audit(req, 'claude_limit_increase_request', target, 'my-profile', {
      period: month, limit, ptd, pct, recommended, ticket: ticket.display_id, fallback: usedFallback,
    });
    res.json({
      ok: true,
      ticket: { id: ticket.id, display: ticket.display_id, url: ticket.url },
      subjectName: person.display_name || target,
      recommended, projected: rec.projected, pct, limit, ptdSpend: ptd,
      filedUnder: usedFallback ? 'itcommand@auction.com' : self,
    });
  } catch (e) {
    console.error('[profile] POST /ai-team/limit-request', e.message);
    res.status(500).json({ error: 'Internal error' });
  }
});

/**
 * What the platform default currently is, and where it came from. READ ONLY.
 *
 * These settings are managed in the admin console (Settings → Claude spend alerts),
 * which publishes them to /etc/corpit/shared/spend-alerts.json through a root helper. This
 * route used to write them too, which gave one setting two homes and no audit trail.
 * A second writer is exactly what the console rule exists to prevent, so the write
 * path is gone rather than deprecated — see the PUT below.
 */
router.get('/ai-team/alert-config', async (req, res) => {
  if (!needUser(req, res)) return;
  if (!req.user.isSuperAdmin) return res.status(403).json({ error: 'Super admin only', code: 'FORBIDDEN' });
  try {
    const cfg = await aiTools.spendAlertConfig();
    res.json(Object.assign({}, cfg, {
      readOnly: true,
      managedIn: 'Admin console → Settings → Claude spend alerts',
    }));
  } catch (e) { res.status(500).json({ error: 'Internal error' }); }
});

/**
 * Gone on purpose. The console is the only writer for these three settings, so
 * that every change is attributable and reversible in one place. Answering 410
 * with the destination beats leaving a route that quietly writes to a table
 * nothing reads any more.
 */
router.put('/ai-team/alert-config', (req, res) => {
  res.status(410).json({
    error: 'Claude spend alert settings are managed in the admin console, under '
         + 'Settings → Claude spend alerts. This endpoint no longer writes.',
    code: 'MANAGED_IN_CONSOLE',
    managedIn: 'Admin console → Settings → Claude spend alerts',
  });
});

/**
 * A manager's OWN threshold, for their OWN list. This is a preference, not an admin
 * setting: it changes who this one person is told about and nobody else's page, so
 * it belongs to them rather than to the console.
 *
 * Send a whole number 1-99 to choose one, or null to go back to the platform default.
 */
router.put('/ai-team/alert-threshold', async (req, res) => {
  if (!needUser(req, res)) return;
  if (req.viewingAs) {
    return res.status(403).json({
      error: 'A borrowed view is read-only, so you cannot change somebody else\'s alert threshold.',
      code: 'VIEW_AS_READ_ONLY',
    });
  }
  const self = String(req.user.email || '').toLowerCase();
  const b = req.body || {};
  try {
    // Only somebody with reports has a list for this to govern. Without the check
    // the setting would be stored, honoured by nothing, and look like it worked.
    const [[me]] = await pool.query(
      'SELECT direct_reports FROM org_reporting_person WHERE email = ?', [self]);
    if (!me || !Number(me.direct_reports)) {
      return res.status(403).json({
        error: 'Nobody reports to you in Active Directory, so there is no alert list to tune.',
        code: 'NOT_A_MANAGER',
      });
    }
    const cfg = await aiTools.spendAlertConfig();
    if (b.threshold === null) {
      // Only the threshold is cleared; the row may also hold this manager's email
      // opt-in, so it is set NULL rather than deleted.
      await pool.query('UPDATE ai_spend_alert_manager SET threshold = NULL, updated_by = ? WHERE manager_email = ?', [who(req), self]);
      rbac.audit(req, 'claude_spend_alert_threshold', null, 'my-profile', { cleared: true });
      return res.json({ threshold: cfg.threshold, source: 'console', consoleThreshold: cfg.threshold, managerThreshold: null });
    }
    // Same validator the readers use, so what the route accepts and what the
    // alert code will honour cannot drift apart.
    const t = spendAlert.usableThreshold(b.threshold);
    if (t === null) {
      return res.status(400).json({ error: 'Pick a whole number between 1 and 99 percent.', code: 'BAD_THRESHOLD' });
    }
    await pool.query(
      'INSERT INTO ai_spend_alert_manager (manager_email, threshold, updated_by) VALUES (?,?,?) '
      + 'ON DUPLICATE KEY UPDATE threshold = VALUES(threshold), updated_by = VALUES(updated_by)',
      [self, t, who(req)]);
    rbac.audit(req, 'claude_spend_alert_threshold', null, 'my-profile', { threshold: t });
    res.json({ threshold: t, source: 'manager', consoleThreshold: cfg.threshold, managerThreshold: t });
  } catch (e) {
    console.error('[profile] PUT alert-threshold', e.message);
    res.status(500).json({ error: 'Internal error' });
  }
});

/**
 * GET /api/profile/ai-team/alert-email — what the sidebar "Email alerts" switch
 * needs at boot, before any team report is loaded: does the subject manage anyone
 * (otherwise there is no switch to show), is their alert email on, and at what
 * percentage the digest fires, so "On" can say what it means. View-As aware: a
 * borrowed view shows the borrowed-from manager's setting and cannot change it.
 */
router.get('/ai-team/alert-email', async (req, res) => {
  if (!needUser(req, res)) return;
  try {
    const v = await viewSubject(req);
    const [[me]] = await pool.query(
      'SELECT direct_reports FROM org_reporting_person WHERE email = ?', [v.email]);
    const manager = !!(me && Number(me.direct_reports));
    let emailAlert = false, threshold = null;
    if (manager) {
      emailAlert = await aiTools.managerEmailAlert(pool, v.email);
      const own = await aiTools.managerThreshold(pool, v.email);
      const cfg = await aiTools.spendAlertConfig();
      threshold = spendAlert.effectiveThreshold(own, cfg.threshold).threshold;
    }
    res.json({ manager, emailAlert, threshold, canChange: manager && !v.viewingAs, viewingAs: v.viewingAs });
  } catch (e) {
    console.error('[profile] GET alert-email', e.message);
    res.status(500).json({ error: 'Internal error' });
  }
});

/**
 * PUT /api/profile/ai-team/alert-email — a manager switches their OWN Claude
 * spend-alert emails on or off. Default off; this belongs to the manager, not the
 * console, so it is theirs to enable as they see fit. Stored on the same
 * per-manager row as their threshold; the digest job reads it to decide who to mail.
 */
router.put('/ai-team/alert-email', async (req, res) => {
  if (!needUser(req, res)) return;
  const self = who(req);
  const b = req.body || {};
  if (typeof b.enabled !== 'boolean') {
    return res.status(400).json({ error: 'Send { enabled: true | false }.', code: 'BAD_BODY' });
  }
  try {
    const [[me]] = await pool.query(
      'SELECT direct_reports FROM org_reporting_person WHERE email = ?', [self]);
    if (!me || !Number(me.direct_reports)) {
      return res.status(403).json({ error: 'Nobody reports to you in Active Directory, so there is nothing to alert on.', code: 'NOT_A_MANAGER' });
    }
    await pool.query(
      'INSERT INTO ai_spend_alert_manager (manager_email, email_alert, updated_by) VALUES (?,?,?) '
      + 'ON DUPLICATE KEY UPDATE email_alert = VALUES(email_alert), updated_by = VALUES(updated_by)',
      [self, b.enabled ? 1 : 0, who(req)]);
    rbac.audit(req, 'claude_spend_alert_email', null, 'my-profile', { enabled: b.enabled });
    res.json({ emailAlert: b.enabled });
  } catch (e) {
    console.error('[profile] PUT alert-email', e.message);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ───────────────────────── My Devices (ITAM inventory snapshot on corpit) ─────────────────────────
// The inventory database (it_inventory) was copied over from ITAM; it is a snapshot, so every
// row carries the table's own last-update stamp. A technician's devices are matched on the
// identities the sources actually store: UPN/email, the sAMAccountName-style username
// ("jriggs"), the full display name, and the admin-account form ("itjeramy.riggs").
const invPool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost', port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.INVENTORY_DB || 'it_inventory',
  waitForConnections: true, connectionLimit: 3,
});
// Ownership identities only: UPN/email, the sAMAccountName-style username and the display
// name. The admin-account form (it<first>.<last>) is deliberately NOT here — it is what a
// technician signs onto servers with, and ManageEngine's logged_on_user records the last
// logon, not who owns the machine. (Jeramy, 09-05: "why is it showing servers?")
function identityKeys(email, displayName, entra) {
  const local = String(email).split('@')[0].toLowerCase();
  const keys = new Set([String(email).toLowerCase(), local]);
  const name = String(displayName || '').trim();
  if (name) keys.add(name.toLowerCase());
  const given = (entra && entra.givenName) || name.split(/\s+/)[0] || '';
  const sur = (entra && entra.surname) || name.split(/\s+/).slice(-1)[0] || '';
  if (given && sur) keys.add((sur + ', ' + given).toLowerCase());
  return Array.from(keys).filter(Boolean);
}
const INV_SOURCES = [
  // table, label, user columns (exact, case-insensitive; comma lists split), row mapper
  { table: 'intune_devices', label: 'Intune', users: ['primary_user_upn', 'primary_user_name'], search: ['device_name', 'serial_number', 'model', 'primary_user_upn', 'primary_user_name', 'imei', 'phone_number'],
    map: r => ({ name: r.device_name, serial: r.serial_number, model: r.model, os: [r.os, r.os_version].filter(Boolean).join(' '), user: r.primary_user_upn || r.primary_user_name, status: r.compliance, lastSeen: r.last_checkin, extra: r.ownership }) },
  { table: 'endpoints', label: 'Endpoints', users: ['logged_on_user', 'first_last'], search: ['computer_name', 'service_tag', 'device_model', 'logged_on_user', 'first_last'],
    // ManageEngine lists servers too; a last-logon there is administration, not ownership.
    notOwned: r => /server/i.test(r.os_name || '') || /^(--|unknown)?$/i.test(String(r.computer_type || '')) && /server/i.test(r.os_name || ''),
    map: r => ({ name: r.computer_name, serial: r.service_tag, model: r.device_model === '--' ? null : r.device_model, os: [r.os_name, r.os_version].filter(x => x && x !== '--').join(' '), user: r.logged_on_user, status: r.computer_type, lastSeen: r.last_asset_scan, extra: r.user_source }) },
  { table: 'macbooks', label: 'Kandji Mac', users: ['user_name'], search: ['device_name', 'serial', 'model', 'user_name', 'local_hostname'],
    map: r => ({ name: r.device_name, serial: r.serial, model: r.model, os: r.os_version ? 'macOS ' + r.os_version : null, user: r.user_name, status: r.filevault_enabled ? 'FileVault on' : null, lastSeen: r.checked_in, extra: r.blueprint }) },
  { table: 'ipad_devices', label: 'Kandji iPad', users: ['user_name'], search: ['device_name', 'serial', 'model', 'user_name'],
    map: r => ({ name: r.device_name, serial: r.serial, model: r.model, os: r.os_version ? 'iPadOS ' + r.os_version : null, user: r.user_name, status: r.is_missing ? 'Missing' : (r.mdm_enabled ? 'MDM' : null), lastSeen: r.checked_in, extra: r.carrier }) },
  { table: 'aws_workspaces', label: 'AWS WorkSpace', users: ['username', 'first_last'], search: ['workspace_id', 'username', 'first_last', 'operating_system'],
    map: r => ({ name: r.workspace_id, serial: null, model: r.compute, os: r.operating_system, user: r.first_last || r.username, status: r.status, lastSeen: r.updated_at, extra: r.running_mode }) },
  { table: 'live_auction_devices', label: 'Live Auction', users: ['assigned_to', 'first_last'], search: ['device_id1', 'phone_number', 'imei', 'assigned_to', 'first_last', 'model'],
    map: r => ({ name: r.device_id1 || r.phone_number, serial: r.imei, model: r.model, os: r.os, user: r.assigned_to || r.first_last, status: r.state || r.active_inactive, lastSeen: r.intune_last_sync || r.updated_at, extra: r.device_type }) },
  { table: 'tmobile_lines', label: 'T-Mobile line', users: ['email_address', 'first_last_name'], search: ['line', 'first_last_name', 'email_address', 'imei', 'device_type'],
    map: r => ({ name: r.line, serial: r.imei, model: r.device_type, os: null, user: r.email_address || r.first_last_name, status: r.line_status, lastSeen: r.updated_at, extra: r.rate_plan }) },
  { table: 'verizon_lines', label: 'Verizon line', users: ['username'], search: ['phone_number', 'username', 'equipment_model', 'imei'],
    map: r => ({ name: r.phone_number, serial: r.imei, model: r.equipment_model, os: null, user: r.username, status: r.service_status, lastSeen: r.updated_at, extra: r.device_type }) },
];
function invUserMatches(value, keys) {
  return String(value || '').split(',').map(x => x.trim().toLowerCase()).some(x => x && keys.includes(x));
}
async function invSource(src, where, params, limit) {
  const [rows] = await invPool.query(`SELECT * FROM \`${src.table}\` ${where} ORDER BY updated_at DESC LIMIT ${limit}`, params);
  return rows;
}
// The Asset Inventory app names its tabs differently from the tables it reads.
const INV_APP_TAB = { intune_devices: 'intune', endpoints: 'endpoints', macbooks: 'macbooks', ipad_devices: 'ipads', aws_workspaces: 'aws', live_auction_devices: 'liveauction', tmobile_lines: 'tmobile', verizon_lines: 'verizon' };
function invRow(src, r) {
  const m = src.map(r);
  return Object.assign(m, { source: src.label, table: src.table, tab: INV_APP_TAB[src.table] || src.table, id: r.id, ref: m.serial || m.name || String(r.id),
    lastSeen: m.lastSeen instanceof Date ? m.lastSeen.toISOString() : (m.lastSeen || null),
    url: '/IT_Inventory_App.html#table=' + encodeURIComponent(INV_APP_TAB[src.table] || src.table) + '&find=' + encodeURIComponent(m.serial || m.name || '') });
}
// ── "My devices" mirrors IT_Inventory_App.js itamDevicesForEmployee() exactly ──────────────
// Employee record = active_employees by business email; u = Username, nm = First/Last.
// xu(): comma list → the @auction.com part's local name, else the first part.
// iPhone (Intune, category iphone, not historical) · Tablet (Intune, category tablet, not
// historical) · MacBook (Kandji: xu(user)==u OR name==nm, "(SCxx)" stripped) · Laptop/Desktop
// (ManageEngine Windows endpoints only: os starts "windows", not server, not WSAMZN-) ·
// AWS Workspace (username==u) · iPad (Kandji, shared accounts excluded). No carrier lines,
// no Intune Windows machines — same as the employee profile in the Asset Inventory.
function xu(val) {
  if (!val || val === '--') return null;
  const parts = String(val).split(',').map(x => x.trim());
  for (const pp of parts) if (pp.toLowerCase().includes('@auction.com')) return pp.toLowerCase().replace('@auction.com', '');
  const first = parts[0];
  return first && first !== '--' ? first.toLowerCase() : null;
}
function isWindowsEndpoint(r) {
  const os = String(r.os_name || '').toLowerCase(), name = String(r.computer_name || '').toUpperCase();
  return os.startsWith('windows') && !os.includes('server') && !name.startsWith('WSAMZN-');
}
const OWN_TABS = { intune: 'intune_devices', tablets: 'intune_devices', macbooks: 'macbooks', endpoints: 'endpoints', aws: 'aws_workspaces', ipads: 'ipad_devices' };
function ownRow(type, page, r, name, detail, query, extra) {
  return Object.assign({ type, source: type, table: OWN_TABS[page], tab: page, id: r.id, name, serial: extra.serial || null, model: extra.model || null, os: extra.os || null, user: extra.user || null, status: extra.status || null,
    lastSeen: extra.lastSeen instanceof Date ? extra.lastSeen.toISOString() : (extra.lastSeen || null), detail, ref: query || name,
    url: '/IT_Inventory_App.html#table=' + encodeURIComponent(page) + '&find=' + encodeURIComponent(query || name || '') });
}
router.get('/devices', async (req, res) => {
  if (!needUser(req, res)) return;
  const email = who(req);
  try {
    const [[emp]] = await invPool.query('SELECT worker_id, status, employee_name, first_last, business_email, username FROM active_employees WHERE LOWER(business_email)=? LIMIT 1', [email]);
    const u = String((emp && emp.username) || email.split('@')[0]).toLowerCase().trim();
    const nm = String((emp && emp.first_last) || req.user.displayName || '').toLowerCase().trim();
    const out = [];
    const q = async (sql, p) => { try { return (await invPool.query(sql, p))[0]; } catch (e) { console.warn('[profile] devices', e.message); return []; } };
    (await q("SELECT * FROM intune_devices WHERE device_category='iphone' AND is_historical=0", [])).forEach(d => {
      if (u && xu(d.primary_user_upn) === u) out.push(ownRow('iPhone', 'intune', d, d.device_name || d.model || 'iPhone', [d.model, d.serial_number].filter(Boolean).join(' · '), d.serial_number || d.device_name,
        { serial: d.serial_number, model: d.model, os: [d.os, d.os_version].filter(Boolean).join(' '), user: d.primary_user_upn, status: d.compliance, lastSeen: d.last_checkin }));
    });
    (await q("SELECT * FROM intune_devices WHERE device_category='tablet' AND is_historical=0", [])).forEach(d => {
      if (u && xu(d.primary_user_upn) === u) out.push(ownRow('Tablet', 'tablets', d, d.device_name || d.model || 'Tablet', [d.model, d.serial_number].filter(Boolean).join(' · '), d.serial_number || d.device_name,
        { serial: d.serial_number, model: d.model, os: [d.os, d.os_version].filter(Boolean).join(' '), user: d.primary_user_upn, status: d.compliance, lastSeen: d.last_checkin }));
    });
    (await q('SELECT * FROM macbooks', [])).forEach(d => {
      const user = String(d.user_name || '').trim(); if (!user || user === '--') return;
      const k = xu(user), nameKey = user.toLowerCase().trim().replace(/\s*\(sc\d*\)\s*$/i, '').trim();
      if ((k && k === u) || (nm && nameKey === nm)) out.push(ownRow('MacBook', 'macbooks', d, d.device_name || d.model || 'MacBook', [d.model, d.serial].filter(Boolean).join(' · '), d.serial || d.device_name,
        { serial: d.serial, model: d.model, os: d.os_version ? 'macOS ' + d.os_version : null, user: d.user_name, status: d.filevault_enabled ? 'FileVault on' : null, lastSeen: d.checked_in }));
    });
    (await q('SELECT * FROM endpoints', [])).forEach(d => {
      if (!isWindowsEndpoint(d)) return;
      if (u && xu(d.first_last) === u) out.push(ownRow('Laptop/Desktop', 'endpoints', d, d.computer_name || 'Windows device', d.os_name || '', d.computer_name,
        { serial: d.service_tag, model: d.device_model === '--' ? null : d.device_model, os: [d.os_name, d.os_version].filter(x => x && x !== '--').join(' '), user: d.logged_on_user, status: d.computer_type && d.computer_type !== 'UNKNOWN' ? d.computer_type : null, lastSeen: d.last_asset_scan }));
    });
    (await q('SELECT * FROM aws_workspaces', [])).forEach(d => {
      const user = String(d.username || '').trim().toLowerCase();
      if (u && user && user !== '--' && user === u) out.push(ownRow('AWS Workspace', 'aws', d, d.username || 'Workspace', d.user_volume ? 'Vol ' + d.user_volume : '', d.username,
        { serial: d.workspace_id, model: d.compute, os: d.operating_system, user: d.first_last || d.username, status: d.status, lastSeen: d.updated_at }));
    });
    const shared = ['zoomo365', 'zoom', '--', ''];
    (await q('SELECT * FROM ipad_devices', [])).forEach(d => {
      const user = String(d.user_name || '').trim(); if (shared.includes(user.toLowerCase())) return;
      const k = xu(user) || user.toLowerCase().trim();
      if (u && k === u) out.push(ownRow('iPad', 'ipads', d, d.device_name || d.model || 'iPad', [d.model, d.serial].filter(Boolean).join(' · '), d.serial || d.device_name,
        { serial: d.serial, model: d.model, os: d.os_version ? 'iPadOS ' + d.os_version : null, user: d.user_name, status: d.is_missing ? 'Missing' : (d.mdm_enabled ? 'MDM' : null), lastSeen: d.checked_in }));
    });
    const freshness = {};
    for (const t of ['intune_devices', 'macbooks', 'endpoints', 'aws_workspaces', 'ipad_devices']) { try { const [[f]] = await invPool.query(`SELECT MAX(updated_at) AS at FROM \`${t}\``); freshness[t] = f.at; } catch (e) {} }
    const stamps = Object.values(freshness).filter(Boolean).map(d => new Date(d).getTime()).filter(t => !isNaN(t));
    res.json({ employee: emp ? { username: emp.username, name: emp.first_last, status: emp.status, workerId: emp.worker_id } : null, keys: [u].concat(nm ? [nm] : []), method: 'asset-inventory-employee-profile',
      devices: out, freshness, snapshot: stamps.length ? new Date(Math.max.apply(null, stamps)).toISOString() : null });
  } catch (e) { console.error('[profile] GET /devices', e.message); res.status(500).json({ error: 'Internal error' }); }
});
router.get('/devices/search', rbac.requirePage('it-inventory', 'read'), async (req, res) => {
  const q = str(req.query.q, 80);
  if (!q || q.length < 2) return res.status(400).json({ error: 'q must be at least 2 characters' });
  const like = '%' + q.toLowerCase().replace(/[%_]/g, '\\$&') + '%';
  try {
    const out = [];
    for (const src of INV_SOURCES) {
      const where = 'WHERE ' + src.search.map(c => `LOWER(\`${c}\`) LIKE ?`).join(' OR ');
      let rows = [];
      try { rows = await invSource(src, where, src.search.map(() => like), 15); } catch (e) { console.warn('[profile] device search', src.table, e.message); continue; }
      rows.forEach(r => out.push(invRow(src, r)));
    }
    logEvent(req, { verb: 'search', object_type: 'asset', object_id: q.toLowerCase(), label: 'Searched devices for "' + q + '"', source: 'my-profile' });
    res.json({ q, total: out.length, devices: out.slice(0, 60) });
  } catch (e) { console.error('[profile] GET /devices/search', e.message); res.status(500).json({ error: 'Internal error' }); }
});

// ───────────────────────── stats + activity ─────────────────────────
const VERB_LABELS = {
  'open:app': 'Opened tools', 'view:asset': 'Viewed assets', 'view:ticket': 'Viewed tickets', 'view:user': 'Viewed user profiles', 'view:change': 'Viewed change controls',
  'search:ticket': 'Searched tickets', 'search:asset': 'Searched assets', 'view:page': 'Viewed profile pages', 'update:prefs': 'Changed preferences', 'save:pins': 'Managed favorites',
  'submit:suggestion': 'Submitted ideas', 'vote:suggestion': 'Voted on ideas', 'save:search': 'Saved searches', 'save:draft': 'Saved drafts', 'refresh:access': 'Refreshed access', 'revoke:session': 'Revoked sessions', 'refresh:photo': 'Refreshed photo',
};
function describeEvent(e) {
  if (e.label) return e.label;
  return (VERB_LABELS[e.verb + ':' + e.object_type] || humanize(e.verb + ' ' + e.object_type)) + (e.object_id ? ' · ' + e.object_id : '');
}
function describeAudit(a, me) {
  const d = (() => { try { return typeof a.details === 'string' ? JSON.parse(a.details) : (a.details || {}); } catch (e) { return {}; } })();
  const actorIsMe = String(a.actor_email || '').toLowerCase() === me;
  const page = a.target_page_key ? ' for ' + a.target_page_key : '';
  switch (a.action) {
    case 'self_refresh_requested': return 'Requested an access refresh from Active Directory';
    case 'view_as_lookup': return actorIsMe ? 'Looked up ' + (a.target_email || 'a user') + ' with View As' : (a.actor_email + ' viewed your access with View As');
    case 'superadmin_access': return 'Used super-admin access: ' + (d.method || '') + ' ' + (d.path || '');
    case 'authorization_denied': return 'Access denied' + page;
    case 'access_granted': return actorIsMe ? 'Granted access' + page + ' to ' + (a.target_email || '') : 'You were granted access' + page + ' by ' + a.actor_email;
    case 'access_changed': case 'page_access_changed': return actorIsMe ? 'Changed access' + page + ' for ' + (a.target_email || '') : 'Your access' + page + ' was changed by ' + a.actor_email;
    case 'access_revoked': return actorIsMe ? 'Revoked access' + page + ' for ' + (a.target_email || '') : 'Your access' + page + ' was revoked by ' + a.actor_email;
    case 'role_applied': return actorIsMe ? 'Applied role ' + (d.role_key || '') + ' to ' + (a.target_email || '') : 'Role ' + (d.role_key || '') + ' applied to you by ' + a.actor_email;
    case 'role_unassigned': return actorIsMe ? 'Removed role ' + (d.role_key || '') + ' from ' + (a.target_email || '') : 'Role ' + (d.role_key || '') + ' removed from you by ' + a.actor_email;
    case 'scope_assigned': return actorIsMe ? 'Assigned reporting scope to ' + (a.target_email || '') : 'Reporting scope assigned to you by ' + a.actor_email;
    case 'view_as_granted': return actorIsMe ? 'Granted View As to ' + (a.target_email || '') : 'View As granted to you by ' + a.actor_email;
    case 'breakglass_login_success': return 'Signed in with the break-glass account';
    case 'user_roles_invalidated': return actorIsMe ? 'Forced an AD re-resolve for ' + (a.target_email || '') : 'Your roles were re-resolved by ' + a.actor_email;
    case 'profile_claude_view_other': return 'Viewed Claude usage for ' + (a.target_email || '');
    case 'suggestion_status_changed': return actorIsMe ? 'Updated suggestion #' + (d.id || '') + ' to ' + (d.status || '') : 'Your suggestion #' + (d.id || '') + ' was marked ' + (d.status || '') + ' by ' + a.actor_email;
    default: return humanize(a.action) + page + (a.target_email && !actorIsMe ? ' (' + a.target_email + ')' : '');
  }
}
const AUDIT_SKIP = new Set(['localdev_login', 'localdev_login_failed', 'qa_token_minted', 'localdev_account_updated']);

router.get('/stats', async (req, res) => {
  if (!needUser(req, res)) return;
  const email = who(req);
  try {
    const q = async (sql, p) => (await pool.query(sql, p))[0];
    const [byKind, tools, weekly, audit30, claude30, totals, firstEv] = await Promise.all([
      q(`SELECT verb, object_type, COUNT(*) AS n FROM profile_events WHERE email=? AND created_at > DATE_SUB(NOW(), INTERVAL 30 DAY) GROUP BY verb, object_type ORDER BY n DESC`, [email]),
      q(`SELECT object_id, MAX(label) AS label, MAX(url) AS url, COUNT(*) AS n, MAX(created_at) AS last_at FROM profile_events WHERE email=? AND verb='open' AND object_type='app' AND created_at > DATE_SUB(NOW(), INTERVAL 30 DAY) GROUP BY object_id ORDER BY n DESC, last_at DESC LIMIT 8`, [email]),
      q(`SELECT DATE_FORMAT(DATE_SUB(created_at, INTERVAL WEEKDAY(created_at) DAY),'%Y-%m-%d') AS week, COUNT(*) AS n FROM profile_events WHERE email=? AND created_at > DATE_SUB(NOW(), INTERVAL 84 DAY) GROUP BY week ORDER BY week`, [email]),
      q(`SELECT action, COUNT(*) AS n FROM rbac_audit_log WHERE actor_email=? AND created_at > DATE_SUB(NOW(), INTERVAL 30 DAY) GROUP BY action ORDER BY n DESC`, [email]),
      q(`SELECT COALESCE(SUM(cc_sessions),0) AS ccSessions, COALESCE(SUM(cc_edits_accepted),0) AS edits, COALESCE(SUM(cowork_sessions),0) AS cowork, COUNT(DISTINCT day) AS activeDays FROM claude_user_activity_daily WHERE LOWER(email)=? AND day > DATE_SUB(CURDATE(), INTERVAL 30 DAY)`, [email]),
      q(`SELECT COUNT(*) AS all30, SUM(created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)) AS all7 FROM profile_events WHERE email=? AND created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)`, [email]),
      q(`SELECT MIN(created_at) AS first_at, COUNT(*) AS total FROM profile_events WHERE email=?`, [email]),
    ]);
    const hit = _sdpCache.get(email);
    res.json({
      window: { days: 30 },
      actions: byKind.map(r => ({ key: r.verb + ':' + r.object_type, label: VERB_LABELS[r.verb + ':' + r.object_type] || humanize(r.verb + ' ' + r.object_type), count: Number(r.n) })),
      tools: tools.map(t => ({ id: t.object_id, label: t.label, url: t.url, count: Number(t.n), lastAt: t.last_at })),
      weekly: weekly.map(w => ({ week: w.week, count: Number(w.n) })),
      security: audit30.filter(a => !AUDIT_SKIP.has(a.action)).map(a => ({ action: a.action, label: humanize(a.action), count: Number(a.n) })),
      claude: claude30[0] ? Object.fromEntries(Object.entries(claude30[0]).map(([k, v]) => [k, Number(v) || 0])) : null,
      totals: { events30: Number(totals[0].all30 || 0), events7: Number(totals[0].all7 || 0), eventsAll: Number(firstEv[0].total || 0), since: firstEv[0].first_at },
      tickets: hit && hit.data && hit.data.tickets && hit.data.tickets.available ? hit.data.tickets.counts : null,
    });
  } catch (e) { console.error('[profile] GET /stats', e.message); res.status(500).json({ error: 'Internal error' }); }
});

router.get('/activity', async (req, res) => {
  if (!needUser(req, res)) return;
  const email = who(req);
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 60, 10), 200);
  const days = Math.min(Math.max(parseInt(req.query.days, 10) || 90, 1), 365);
  const kind = str(req.query.kind, 24);      // product | security | signin | (all)
  try {
    const out = [];
    if (!kind || kind === 'product') {
      const [rows] = await pool.query(`SELECT id, verb, object_type, object_id, label, url, source, created_at FROM profile_events WHERE email=? AND created_at > DATE_SUB(NOW(), INTERVAL ? DAY) ORDER BY created_at DESC LIMIT ?`, [email, days, limit]);
      rows.forEach(e => out.push({ id: 'p' + e.id, kind: 'product', verb: e.verb, objectType: e.object_type, objectId: e.object_id, text: describeEvent(e), url: e.url, source: e.source, at: e.created_at }));
    }
    if (!kind || kind === 'security') {
      const [rows] = await pool.query(`SELECT id, actor_email, action, target_email, target_page_key, details, ip_address, created_at FROM rbac_audit_log WHERE (actor_email=? OR target_email=?) AND created_at > DATE_SUB(NOW(), INTERVAL ? DAY) ORDER BY created_at DESC LIMIT ?`, [email, email, days, limit]);
      rows.filter(a => !AUDIT_SKIP.has(a.action)).filter(a => !(a.action === 'superadmin_access' && (() => { try { return JSON.parse(a.details).write === false; } catch (e) { return false; } })()))
        .forEach(a => out.push({ id: 'a' + a.id, kind: 'security', verb: a.action, objectType: 'access', objectId: a.target_page_key, text: describeAudit(a, email), actor: a.actor_email, ip: a.ip_address, at: a.created_at }));
    }
    if (!kind || kind === 'signin') {
      let liveSec = null;
      try { liveSec = await liveSecurity(email); } catch (e) { liveSec = null; }
      if (liveSec && liveSec.signins) {
        const since = Date.now() - days * 864e5;
        liveSec.signins.filter(x => x.interactive && new Date(x.at).getTime() > since).slice(0, Math.min(limit, 40)).forEach((s, i) => out.push({ id: 'sl' + i + '-' + new Date(s.at).getTime(), kind: 'signin', verb: 'signin', objectType: 'session', objectId: s.app,
          text: (s.ok ? 'Signed in to ' : 'Sign-in failed for ') + (s.app || 'Microsoft') + (s.city ? ' from ' + s.city + (s.state ? ', ' + s.state : '') : '') + (s.browser ? ' · ' + s.browser : ''),
          ip: s.ip, at: s.at, ok: s.ok, source: 'entra-live' }));
      } else {
        const [rows] = await pool.query(`SELECT created_at, outcome, app_display_name, ip_address, location_city, location_state, device_os, device_browser, status_failure_reason FROM entra_signin_logs WHERE LOWER(user_principal_name)=? AND is_interactive=1 AND created_at > DATE_SUB(NOW(), INTERVAL ? DAY) ORDER BY created_at DESC LIMIT ?`, [email, days, Math.min(limit, 40)]);
        rows.forEach((s, i) => out.push({ id: 's' + i + '-' + new Date(s.created_at).getTime(), kind: 'signin', verb: 'signin', objectType: 'session', objectId: s.app_display_name,
          text: (s.outcome === 'SUCCESS' ? 'Signed in to ' : 'Sign-in failed for ') + (s.app_display_name || 'Microsoft') + (s.location_city ? ' from ' + s.location_city + (s.location_state ? ', ' + s.location_state : '') : '') + (s.device_browser ? ' · ' + s.device_browser : ''),
          ip: s.ip_address, at: s.created_at, ok: s.outcome === 'SUCCESS', source: 'entra' }));
      }
    }
    out.sort((a, b) => new Date(b.at) - new Date(a.at));
    res.json({ days, items: out.slice(0, limit) });
  } catch (e) { console.error('[profile] GET /activity', e.message); res.status(500).json({ error: 'Internal error' }); }
});

// ───────────────────────── suggestions ─────────────────────────
const SUGG_STATUS = ['new', 'reviewing', 'planned', 'building', 'shipped', 'declined'];
async function suggestionRows(email, scope, status) {
  const where = [], p = [];
  if (scope !== 'all') { where.push('s.author_email=?'); p.push(email); }
  if (status && SUGG_STATUS.includes(status)) { where.push('s.status=?'); p.push(status); }
  const [rows] = await pool.query(
    `SELECT s.id, s.author_email, s.author_name, s.title, s.details, s.area, s.status, s.admin_note, s.votes, s.status_changed_at, s.status_changed_by, s.created_at, s.updated_at,
            EXISTS(SELECT 1 FROM feature_suggestion_votes v WHERE v.suggestion_id=s.id AND v.email=?) AS voted
       FROM feature_suggestions s ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
      ORDER BY (s.status IN ('shipped','declined')) ASC, s.votes DESC, s.created_at DESC LIMIT 200`, [email].concat(p));
  return rows.map(r => ({ id: r.id, mine: r.author_email === email, authorName: r.author_name || r.author_email.split('@')[0], authorEmail: r.author_email === email ? r.author_email : undefined,
    title: r.title, details: r.details, area: r.area, status: r.status, adminNote: r.admin_note, votes: Number(r.votes), voted: !!r.voted,
    statusChangedAt: r.status_changed_at, statusChangedBy: r.status_changed_by, createdAt: r.created_at, updatedAt: r.updated_at }));
}
router.get('/suggestions', async (req, res) => {
  if (!needUser(req, res)) return;
  try {
    const scope = req.query.scope === 'all' ? 'all' : 'mine';
    const items = await suggestionRows(who(req), scope, str(req.query.status, 16));
    const [[counts]] = await pool.query(`SELECT COUNT(*) AS total, SUM(author_email=?) AS mine, SUM(status IN ('new','reviewing','planned','building')) AS openCount FROM feature_suggestions`, [who(req)]);
    // `mail` says whether this host can send at all, so the page states
    // what it can actually do instead of promising a notice unconditionally.
    // Same shape as bug-reports-routes.js's notify_reporter.
    res.json({ scope, items, counts: { total: Number(counts.total || 0), mine: Number(counts.mine || 0), open: Number(counts.openCount || 0) }, canModerate: !!req.user.isSuperAdmin, statuses: SUGG_STATUS, mail: mailGraph.configured() });
  } catch (e) { console.error('[profile] GET /suggestions', e.message); res.status(500).json({ error: 'Internal error' }); }
});
router.post('/suggestions', express.json({ limit: '16kb' }), async (req, res) => {
  if (!needUser(req, res)) return;
  const title = str(req.body && req.body.title, 160), details = str(req.body && req.body.details, 4000), area = str(req.body && req.body.area, 120);
  if (!title || !details || title.length < 4 || details.length < 10) return res.status(400).json({ error: 'A title (4+ chars) and details (10+ chars) are required' });
  try {
    const [[recent]] = await pool.query(`SELECT COUNT(*) AS n FROM feature_suggestions WHERE author_email=? AND created_at > DATE_SUB(NOW(), INTERVAL 1 DAY)`, [who(req)]);
    if (recent.n >= 20) return res.status(429).json({ error: 'Daily suggestion limit reached' });
    const [r] = await pool.execute('INSERT INTO feature_suggestions (author_email, author_name, title, details, area) VALUES (?,?,?,?,?)', [who(req), str(req.user.displayName, 255), title, details, area]);
    await pool.execute('DELETE FROM profile_drafts WHERE email=? AND draft_key=?', [who(req), 'suggestion:new']);
    await logEvent(req, { verb: 'submit', object_type: 'suggestion', object_id: String(r.insertId), label: 'Submitted idea "' + title + '"', url: '/my-profile.html#suggestions', source: 'my-profile' });
    res.status(201).json({ id: r.insertId, status: 'new' });
  } catch (e) { console.error('[profile] POST /suggestions', e.message); res.status(500).json({ error: 'Internal error' }); }
});
router.post('/suggestions/:id/vote', async (req, res) => {
  if (!needUser(req, res)) return;
  const id = Number(req.params.id) || 0;
  try {
    const [[s]] = await pool.query('SELECT id, title FROM feature_suggestions WHERE id=?', [id]);
    if (!s) return res.status(404).json({ error: 'Not found' });
    const [del] = await pool.execute('DELETE FROM feature_suggestion_votes WHERE suggestion_id=? AND email=?', [id, who(req)]);
    let voted = false;
    if (!del.affectedRows) { await pool.execute('INSERT INTO feature_suggestion_votes (suggestion_id, email) VALUES (?,?)', [id, who(req)]); voted = true; }
    await pool.execute('UPDATE feature_suggestions SET votes=(SELECT COUNT(*) FROM feature_suggestion_votes WHERE suggestion_id=?) WHERE id=?', [id, id]);
    const [[cnt]] = await pool.query('SELECT votes FROM feature_suggestions WHERE id=?', [id]);
    if (voted) logEvent(req, { verb: 'vote', object_type: 'suggestion', object_id: String(id), label: 'Upvoted "' + s.title + '"', source: 'my-profile' });
    res.json({ id, voted, votes: Number(cnt.votes) });
  } catch (e) { console.error('[profile] vote', e.message); res.status(500).json({ error: 'Internal error' }); }
});
router.delete('/suggestions/:id', async (req, res) => {
  if (!needUser(req, res)) return;
  try {
    const [r] = await pool.execute(`DELETE FROM feature_suggestions WHERE id=? AND author_email=? AND status='new'`, [Number(req.params.id) || 0, who(req)]);
    if (!r.affectedRows) return res.status(409).json({ error: 'Only your own suggestions that are still "new" can be withdrawn' });
    await logEvent(req, { verb: 'remove', object_type: 'suggestion', object_id: String(req.params.id), label: 'Withdrew a suggestion', source: 'my-profile' });
    res.status(204).end();
  } catch (e) { res.status(500).json({ error: 'Internal error' }); }
});
// Super-admin moderation — the future Super Admin console calls this same route.
router.patch('/suggestions/:id', rbac.requireSuperAdmin, express.json({ limit: '8kb' }), async (req, res) => {
  const id = Number(req.params.id) || 0;
  const status = str(req.body && req.body.status, 16), note = req.body && 'admin_note' in req.body ? str(req.body.admin_note, 2000) : undefined;
  if (status && !SUGG_STATUS.includes(status)) return res.status(400).json({ error: 'bad status' });
  if (!status && note === undefined) return res.status(400).json({ error: 'Nothing to update' });
  try {
    const [[s]] = await pool.query('SELECT * FROM feature_suggestions WHERE id=?', [id]);
    if (!s) return res.status(404).json({ error: 'Not found' });
    const sets = [], p = [];
    if (status && status !== s.status) { sets.push('status=?', 'status_changed_at=NOW()', 'status_changed_by=?'); p.push(status, who(req)); }
    if (note !== undefined) { sets.push('admin_note=?'); p.push(note); }
    if (sets.length) { p.push(id); await pool.execute('UPDATE feature_suggestions SET ' + sets.join(', ') + ' WHERE id=?', p); }
    await rbac.audit(req, 'suggestion_status_changed', s.author_email, 'my-profile', { id, status: status || s.status, noteChanged: note !== undefined });
    let notified = false;
    if (status && status !== s.status) {
      try {
        const { prefs } = await readPrefs(s.author_email);
        const n = prefs.notifications ? JSON.parse(prefs.notifications) : {};
        if (n.suggestion_status !== false) {
          notified = await sendMailGraph(s.author_email, `[CorpIT] Your idea "${s.title}" is now ${status}`,
            `<p>Hi ${escapeHtml(s.author_name || '')},</p><p>Your suggestion <b>${escapeHtml(s.title)}</b> was marked <b>${escapeHtml(status)}</b> by ${escapeHtml(req.user.displayName || who(req))}.</p>` +
            (note ? `<p>Note: ${escapeHtml(note)}</p>` : '') + `<p><a href="https://corpit.nrpi.local/my-profile.html#suggestions">Open My Profile</a></p>`);
          if (notified) await pool.execute('UPDATE feature_suggestions SET notified_at=NOW() WHERE id=?', [id]);
        }
      } catch (e) { console.warn('[profile] suggestion notify failed:', e.message); }
    }
    res.json({ ok: true, id, status: status || s.status, notified });
  } catch (e) { console.error('[profile] PATCH /suggestions', e.message); res.status(500).json({ error: 'Internal error' }); }
});
function escapeHtml(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
async function sendMailGraph(to, subject, html) {
  const r = await mailGraph.sendMail({ to, subject, html });
  if (!r.ok) console.warn('[profile] suggestion notice not sent: %s %s', r.reason, r.status || '');
  return r.ok;
}

// ───────────────────────── ITAM -> CorpIT changes ─────────────────────────
let _ver = { at: 0, v: null };
async function platformVersion() {
  if (Date.now() - _ver.at < 60e3) return _ver.v;
  try { const v = (await fsp.readFile(VERSION_FILE, 'utf8')).trim(); _ver = { at: Date.now(), v: /^\d+\.\d+\.\d+$/.test(v) ? v : null }; } catch (e) { _ver = { at: Date.now(), v: null }; }
  return _ver.v;
}
router.get('/changes', async (req, res) => {
  if (!needUser(req, res)) return;
  try {
    const hub = await hubLinks();
    const [notes] = await pool.query('SELECT id, kind, title, detail, affects, effective_on, link, itam_state, corpit_state FROM platform_changes WHERE is_active=1 ORDER BY effective_on DESC, id DESC');
    const { prefs } = await readPrefs(who(req));
    const lastSeen = prefs.last_seen_changes || null;
    const STATUS = { corpit: 'On CorpIT', reporting: 'On reporting.nrpi.local', itam: 'Still on ITAM', accessportal: 'Access Portal (ITAM host)', subadmin: 'Admin console', external: 'External', unknown: 'Unknown' };
    const tiles = hub.links.map(l => ({ id: l.id, title: l.title, section: l.section, url: l.url, host: l.host, status: STATUS[l.host] || l.host, newTab: l.newTab }));
    const hosts = {}; tiles.forEach(t => { hosts[t.host] = (hosts[t.host] || 0) + 1; });
    res.json({
      version: await platformVersion(), generated: hub.generated,
      tiles, hosts,
      notes: notes.map(n => ({ id: n.id, kind: n.kind, title: n.title, detail: n.detail, affects: n.affects, effectiveOn: n.effective_on ? ymd(new Date(n.effective_on)) : null, link: n.link, itamState: n.itam_state, corpitState: n.corpit_state,
        unseen: !lastSeen || (n.effective_on && ymd(new Date(n.effective_on)) > lastSeen) })),
      lastSeen,
    });
  } catch (e) { console.error('[profile] GET /changes', e.message); res.status(500).json({ error: 'Internal error' }); }
});
router.post('/changes/seen', async (req, res) => {
  if (!needUser(req, res)) return;
  try { await writePrefs(req, [['last_seen_changes', ymd(new Date())]]); res.status(204).end(); }
  catch (e) { res.status(500).json({ error: 'Internal error' }); }
});

// ───────────────────────── security ─────────────────────────
const MFA_LABELS = { microsoftAuthenticatorMethod: 'Microsoft Authenticator', passwordMethod: 'Password', windowsHelloForBusinessMethod: 'Windows Hello for Business', phoneMethod: 'Phone (SMS/voice)', fido2Method: 'Security key (FIDO2)', softwareOathMethod: 'Authenticator app (TOTP)', emailMethod: 'Email', temporaryAccessPassMethod: 'Temporary Access Pass', passwordlessMicrosoftAuthenticatorMethod: 'Passwordless Authenticator' };
router.get('/security', async (req, res) => {
  if (!needUser(req, res)) return;
  const email = who(req);
  try {
    let liveId = null, liveSec = null;
    try { liveId = await liveIdentity(email); liveSec = await liveSecurity(email); } catch (e) { console.warn('[profile] Graph security fallback:', e.message); }
    const [[u]] = await pool.query('SELECT entra_id, account_enabled, last_login, last_password_change, password_expiry_estimate, is_likely_locked, last_synced_at FROM entra_users WHERE LOWER(user_principal_name)=? LIMIT 1', [email]);
    let methods = [];
    if (liveSec && liveSec.methods) {
      methods = liveSec.methods.map(x => ({ type: x.type, label: MFA_LABELS[x.type] || humanize(x.type.replace(/Method$/, '')), name: x.name, createdAt: x.createdAt, syncedAt: liveSec.fetchedAt }));
    } else if (u && u.entra_id) {
      const [m] = await pool.query('SELECT method_type, display_name, details_json, created_date_time, last_synced_at FROM entra_auth_methods WHERE user_id=? ORDER BY created_date_time', [u.entra_id]);
      methods = m.map(x => { let d = {}; try { d = typeof x.details_json === 'string' ? JSON.parse(x.details_json) : (x.details_json || {}); } catch (e) {}
        return { type: x.method_type, label: MFA_LABELS[x.method_type] || humanize(x.method_type.replace(/Method$/, '')), name: x.display_name || d.displayName || d.deviceTag || null, createdAt: x.created_date_time, syncedAt: x.last_synced_at }; });
    }
    const [signins] = liveSec && liveSec.signins ? [[]] : await pool.query(`SELECT created_at, outcome, app_display_name, ip_address, location_city, location_state, location_country, device_os, device_browser, client_app_used, conditional_access_status, risk_level_during_signin, status_failure_reason
        FROM entra_signin_logs WHERE LOWER(user_principal_name)=? AND is_interactive=1 ORDER BY created_at DESC LIMIT 12`, [email]);
    const [[sync]] = await pool.query(`SELECT MAX(created_at) AS latest FROM entra_signin_logs`);
    const liveRows = liveSec && liveSec.signins ? liveSec.signins.filter(x => x.interactive).slice(0, 12) : null;
    const [revoked] = await pool.query(`SELECT created_at FROM profile_events WHERE email=? AND verb='revoke' AND object_type='session' ORDER BY created_at DESC LIMIT 1`, [email]);
    res.json({
      session: sessionFacts(req),
      source: liveSec ? 'live' : 'sync', fetchedAt: liveSec ? liveSec.fetchedAt : null,
      entra: liveId ? { source: 'live', accountEnabled: liveId.accountEnabled, lastLogin: liveId.lastLogin, lastPasswordChange: liveId.lastPasswordChange, passwordExpiryEstimate: null, likelyLocked: false, syncedAt: liveId.fetchedAt }
           : (u ? { source: 'sync', accountEnabled: u.account_enabled === 1, lastLogin: u.last_login, lastPasswordChange: u.last_password_change, passwordExpiryEstimate: u.password_expiry_estimate, likelyLocked: u.is_likely_locked === 1, syncedAt: u.last_synced_at } : null),
      mfa: { source: liveSec && liveSec.methods ? 'live' : 'sync', methods, strong: methods.some(m => /Authenticator|Hello|fido2|Oath/i.test(m.type)), syncedAt: methods[0] ? methods[0].syncedAt : null },
      signins: liveRows ? liveRows : signins.map(s => ({ at: s.created_at, ok: s.outcome === 'SUCCESS', app: s.app_display_name, ip: s.ip_address, city: s.location_city, state: s.location_state, country: s.location_country, os: s.device_os, browser: s.device_browser, ca: s.conditional_access_status, risk: s.risk_level_during_signin, reason: s.status_failure_reason })),
      signinsSource: liveRows ? 'live' : 'sync',
      signinsAsOf: liveRows ? liveSec.fetchedAt : (sync ? sync.latest : null),
      lastRevokeAll: revoked[0] ? revoked[0].created_at : null,
      links: { securityInfo: 'https://mysignins.microsoft.com/security-info', changePassword: 'https://account.activedirectory.windowsazure.com/ChangePassword.aspx', myAccount: 'https://myaccount.microsoft.com/' },
    });
  } catch (e) { console.error('[profile] GET /security', e.message); res.status(500).json({ error: 'Internal error' }); }
});
router.post('/sessions/revoke-all', async (req, res) => {
  if (!needUser(req, res)) return;
  try {
    if (!sessionAuth.revokeUser(who(req))) {
      res.set('Cache-Control', 'no-store, private');
      return res.status(503).json({ code: 'REVOCATION_NOT_DURABLE',
        error: 'Sign-out could not be confirmed. Retry using Sign Out.',
        retry: '/api/gate/federated-logout' });
    }
    try { sessionCookie.clearSessionCookie(res, req); } catch (e) {}
    await logEvent(req, { verb: 'revoke', object_type: 'session', object_id: 'all', label: 'Signed out everywhere', source: 'my-profile' });
    rbac.audit(req, 'self_sessions_revoked', who(req), null, {});
    res.status(204).end();
  } catch (e) { console.error('[profile] revoke-all', e.message); res.status(500).json({ error: 'Internal error' }); }
});
router.post('/photo/refresh', async (req, res) => {
  if (!needUser(req, res)) return;
  try {
    const f = path.join(PHOTO_CACHE, crypto.createHash('sha256').update(who(req)).digest('hex').slice(0, 16) + '.bin');
    try { await fsp.unlink(f); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    await logEvent(req, { verb: 'refresh', object_type: 'photo', object_id: who(req), label: 'Refreshed profile photo from Microsoft 365', source: 'my-profile' });
    res.status(204).end();
  } catch (e) { console.error('[profile] photo refresh', e.message); res.status(500).json({ error: 'Internal error' }); }
});
router.post('/access/refresh', async (req, res) => {
  if (!needUser(req, res)) return;
  try {
    await pool.execute('UPDATE rbac_users SET roles_invalidated_at = NOW() WHERE email = ?', [who(req)]);
    await rbac.audit(req, 'self_refresh_requested', who(req), null, { via: 'my-profile' });
    await logEvent(req, { verb: 'refresh', object_type: 'access', object_id: who(req), label: 'Refreshed access from Active Directory', source: 'my-profile' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Internal error' }); }
});

// Claude spend limit: self-raise, manager / functional-leader approval, Anthropic apply.
// Registered here, after the View-As write guard, so a borrowed view cannot approve.
require('./claude-limit-approvals').register(router, { pool, rbac, sdp, mailGraph, who, needUser, viewSubject });

router.get('/health', (req, res) => res.json({ ok: true, sdp: sdpReady(), graph: !!(process.env.ENTRA_CLIENT_ID || process.env.AZURE_CLIENT_ID), landing: !!_hub.links.length || fs.existsSync(LANDING_JSON) }));

module.exports = router;
