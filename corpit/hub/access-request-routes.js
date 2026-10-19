// access-request-routes.js — one-press access requests for the CorpIT "you do not have access" pages.
//
// Mount (server.js, after `pool` exists):
//   app.use('/api/access-request', require('./access-request-routes').create({ pool }));
//
//   GET  /api/access-request/context   what was refused, what access would fix it, and whether a ticket is already open
//   POST /api/access-request/file      files ONE Help Desk ticket, pre-filled, from that same context
//
// Why this file looks the way it does
//   * The visitor types nothing. Everything in the ticket is derived on the server: the requester from the
//     HMAC-verified it_session cookie, the site from the Host header nginx forwarded, the group from
//     site-access.json (site denials) or the rbac_* tables (in-app denials). The request body can only NAME
//     which page an in-app denial is about; it can never supply an identity, a group or any ticket text.
//   * Both routes are in server.js API_PUBLIC (they must work for a person the gate just refused, and a
//     directory hiccup must not turn a refusal page into a 401), so they authenticate themselves and do
//     their own same-origin check. A cookie-authenticated POST must POSITIVELY prove same-origin — the
//     platform's cookie is shared across .nrpi.local sibling hosts, so SameSite is no defence here.
//   * One open ticket per person + target + need. A second press shows the existing number instead of
//     filing another. "Open" is decided by asking SDP; if SDP cannot be asked, the earlier ticket is
//     treated as still open (a duplicate ticket is worse than a stale pointer to a real one).
//   * No success is reported until SDP has returned a ticket id. A failed filing says so.
//
// ACCESS_REQ_DRYRUN=1 (dev server only): the route does everything except call SDP and write the ledger, and
// answers `dry_run: true` so the page labels itself "practice run". The dev box blocks outbound non-GETs, so
// this is the only way to see the filed state there. Unset on production.
'use strict';

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const rateLimit = require('express-rate-limit');

const LEVEL_RANK = { none: 0, read: 1, admin: 2 };
const HOST_RE = /^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/;
const PAGE_RE = /^[a-z0-9][a-z0-9_.-]{0,63}$/i;
const CLOSED_RE = /^(closed|resolved|canceled|cancelled|completed|rejected)$/i;
const DEDUPE_DAYS = 45;          // an older ticket is history, not an open request
const MAX_NEW_PER_HOUR = 5;      // new tickets one person can cause in an hour, across every target
const MAX_GROUPS_IN_TICKET = 10;
const SDP_LOOKUP_MS = 4000;
const LOCK_WAIT_S = 5;

const FALLBACK_POLICY = { superadmin_groups: ['SaaS-ITH-SA'], default: { mode: 'superadmin' }, sites: {} };

function loopback(req) {
  const peer = req.socket && req.socket.remoteAddress;
  return peer === '127.0.0.1' || peer === '::1' || peer === '::ffff:127.0.0.1';
}
function clientIp(req) {
  return String((loopback(req) && req.headers['x-real-ip']) || (req.socket && req.socket.remoteAddress) || '')
    .split(',')[0].trim().slice(0, 45) || null;
}
function escHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}
function cleanList(list) {
  const seen = new Set(), out = [];
  (Array.isArray(list) ? list : []).forEach(function (g) {
    const v = String(g == null ? '' : g).trim();
    if (v && v.length <= 256 && !seen.has(v.toLowerCase())) { seen.add(v.toLowerCase()); out.push(v); }
  });
  return out;
}
// "CN=SaaS-ITH-Helpdesk,OU=Groups,DC=..." -> "SaaS-ITH-Helpdesk". Anything else is returned as-is.
function groupNameOf(dnOrName) {
  const m = /^CN=((?:\\.|[^,\\])+)/i.exec(String(dnOrName || '').trim());
  return (m ? m[1].replace(/\\(.)/g, '$1') : String(dnOrName || '').trim());
}
function sha(s, n) { return crypto.createHash('sha256').update(String(s)).digest('hex').slice(0, n); }
function withTimeout(promise, ms) {
  let t;
  return Promise.race([
    promise,
    new Promise(function (_, rej) { t = setTimeout(function () { rej(new Error('timed out')); }, ms); }),
  ]).finally(function () { clearTimeout(t); });
}

// ---- who is asking ---------------------------------------------------------------------------------------------
// Every it_session value is tried (a browser can hold two during a Domain= rollout); the first that verifies wins.
function sessionOf(req, sessionAuth) {
  const raw = req.headers.cookie || '';
  const re = /(?:^|;\s*)it_session=([^;]*)/g;
  let m, expired = false;
  while ((m = re.exec(raw)) !== null) {
    let v = m[1];
    try { v = decodeURIComponent(v); } catch (e) { /* malformed escape: use raw */ }
    if (!v) continue;
    let r = null;
    try { r = sessionAuth.verifySessionToken(v, { host: req.headers.host }); } catch (e) { r = null; }
    if (r && r.ok && r.email) return { ok: true, email: String(r.email).trim().toLowerCase(), name: r.name || null, groups: r.groups };
    if (r && (r.expired || r.revoked)) expired = true;
  }
  return { ok: false, expired };
}

// A cookie-authenticated POST must positively prove it came from this origin (mirrors the server.js CSRF guard).
function sameOrigin(req) {
  const sfs = req.get('sec-fetch-site');
  if (sfs) return sfs === 'same-origin';
  const org = req.get('origin');
  if (!org) return false;
  try {
    const u = new URL(org);
    if (u.protocol !== 'https:') return false;
    return u.host.toLowerCase().replace(/:443$/, '') === String(req.get('host') || '').toLowerCase().replace(/:443$/, '');
  } catch (e) { return false; }
}

// ---- what is needed --------------------------------------------------------------------------------------------
function readPolicy(path) {
  try {
    const p = JSON.parse(fs.readFileSync(path, 'utf8'));
    if (p && typeof p === 'object' && p.sites && typeof p.sites === 'object') return p;
  } catch (e) { /* fall through */ }
  return null;
}

// The AD group(s) a site wants. `mode` and the allow/deny verdict come from site-access.decide(), the one rule the
// gate itself uses; this only reads the NAMES to put on the page and in the ticket.
function siteNeed(policy, host) {
  const p = policy || FALLBACK_POLICY;
  const site = (p.sites && p.sites[host]) || p.default || FALLBACK_POLICY.default;
  const mode = String(site.mode || 'superadmin');
  const sa = cleanList(p.superadmin_groups);
  const groups = mode === 'groups' ? cleanList(site.groups) : (sa.length ? sa : FALLBACK_POLICY.superadmin_groups);
  return { mode, label: String(site.label || host), groups };
}

function describeRefusal(reason) {
  switch (reason) {
    case 'not-in-allowed-group': return 'The signed-in account is not a member of any AD security group this site allows.';
    case 'superadmin-only': return 'This site is limited to platform super-admins.';
    default: return 'The signed-in account is not permitted on this site.';
  }
}

// ---- the router ------------------------------------------------------------------------------------------------
function create(deps) {
  const pool = deps.pool;
  // Production wiring is lazy so the unit tests can inject every collaborator without the hub-api tree present.
  const sessionAuth = deps.sessionAuth || require('./session-auth');
  const siteAccess = deps.siteAccess || require('./site-access');
  const sdp = deps.sdp || (deps.createTicket && deps.getRequestById ? {} : require('./sdp-lookup'));
  const createTicket = deps.createTicket || sdp.createTicket;
  const getRequestById = deps.getRequestById || sdp.getRequestById;
  const policyPath = deps.policyPath || siteAccess.POLICY_PATH;
  const getPolicy = deps.getPolicy || function () { return readPolicy(policyPath); };
  const effectiveLevel = deps.effectiveLevel || (function () {
    const rbac = require('./rbac-middleware')(pool);
    return function (email, roles, pageKey, policy) { return rbac.effectiveLevelForPage(email, roles, pageKey, policy); };
  })();
  const hardExcluded = deps.hardExcluded || new Set(['rbac-admin']);
  const now = deps.now || function () { return new Date(); };
  const dryRun = deps.dryRun || function () { return process.env.ACCESS_REQ_DRYRUN === '1'; };
  const category = deps.category || process.env.ACCESS_REQ_SDP_CATEGORY || 'Identity & Access';
  const subcategory = deps.subcategory || process.env.ACCESS_REQ_SDP_SUBCATEGORY || 'Access Request / Permissions';

  const router = express.Router();
  const keyGenerator = function (req) { return clientIp(req) || req.ip; };
  const readLimiter = rateLimit({ windowMs: 60000, max: 60, standardHeaders: true, keyGenerator,
    message: { ok: false, error: 'RATE_LIMITED' } });
  const fileLimiter = rateLimit({ windowMs: 60000, max: 10, standardHeaders: true, keyGenerator,
    message: { ok: false, error: 'RATE_LIMITED' } });

  router.use(function (req, res, next) { res.set('Cache-Control', 'no-store, private'); next(); });

  async function audit(req, email, action, pageKey, details) {
    try {
      await pool.execute(
        'INSERT INTO rbac_audit_log (actor_email, action, target_email, target_page_key, details, ip_address, user_agent) ' +
        'VALUES (?, ?, ?, ?, ?, ?, ?)',
        [email, action, email, pageKey || null, details ? JSON.stringify(details) : null, clientIp(req),
         String(req.headers['user-agent'] || '').slice(0, 500) || null]);
    } catch (e) { console.error('[access-request] audit insert failed:', e.message); }
  }

  // What was refused and what would fix it. Pure read; never files anything.
  async function resolveTarget(req, sess, src) {
    const kind = String(src.kind || 'site') === 'app' ? 'app' : 'site';
    if (kind === 'site') {
      const host = siteAccess.normHost(req.headers.host);
      if (!HOST_RE.test(host)) return { error: 400, code: 'BAD_HOST' };
      const verdict = siteAccess.decide(host, sess.email, sess.groups === undefined ? null : sess.groups);
      if (verdict.allow) return { kind, state: 'allowed', target: { key: host, label: host, host } };
      if (verdict.reason === 'session-predates-policy') return { kind, state: 'stale-session', target: { key: host, label: host, host } };
      const need = siteNeed(getPolicy(), host);
      const target = { key: host, label: need.label, host };
      if (!need.groups.length) return { kind, state: 'unavailable', target, why: 'no-group-configured' };
      return {
        kind, state: 'ready', target,
        need: { groups: need.groups, any_of: need.groups.length > 1, level: null },
        refusal: describeRefusal(verdict.reason), reason: verdict.reason,
        needKey: sha('site|' + host + '|' + need.groups.map(function (g) { return g.toLowerCase(); }).sort().join('|'), 40),
        needText: need.groups.join(' / '),
      };
    }

    // in-app: which page, at which level
    const page = String(src.page || '').trim();
    const level = String(src.level || 'read').trim().toLowerCase();
    if (!PAGE_RE.test(page)) return { error: 400, code: 'BAD_PAGE' };
    if (level !== 'read' && level !== 'admin') return { error: 400, code: 'BAD_LEVEL' };
    const [pages] = await pool.query('SELECT page_key, display_name, access_policy FROM rbac_pages WHERE page_key = ? LIMIT 1', [page]);
    if (!pages.length) return { error: 404, code: 'UNKNOWN_PAGE' };
    const pg = pages[0];
    const target = { key: pg.page_key, label: String(pg.display_name || pg.page_key), host: siteAccess.normHost(req.headers.host) };
    const [roleRows] = await pool.query('SELECT role_key FROM rbac_user_roles WHERE email = ?', [sess.email]);
    const roleKeys = roleRows.map(function (r) { return r.role_key; });
    if (roleKeys.indexOf('superadmin') !== -1) return { kind, state: 'allowed', target, level };   // super-admins are never refused
    const mine = await effectiveLevel(sess.email, roleKeys, pg.page_key, pg.access_policy);
    if (LEVEL_RANK[mine] >= LEVEL_RANK[level]) return { kind, state: 'allowed', target, level };

    let groups = [];
    if (hardExcluded.has(pg.page_key)) {
      const p = getPolicy() || FALLBACK_POLICY;
      groups = cleanList(p.superadmin_groups).length ? cleanList(p.superadmin_groups) : FALLBACK_POLICY.superadmin_groups;
    } else {
      const [roles] = await pool.query('SELECT role_key, display_name, ad_group_dn, default_access FROM rbac_roles WHERE ad_group_dn IS NOT NULL');
      const [exc] = await pool.query('SELECT role_key, access_level FROM rbac_role_pages WHERE page_key = ?', [pg.page_key]);
      const excBy = {}; exc.forEach(function (e) { excBy[e.role_key] = e.access_level; });
      const fit = [];
      roles.forEach(function (r) {
        const specific = Object.prototype.hasOwnProperty.call(excBy, r.role_key);
        const eff = specific ? excBy[r.role_key] : r.default_access;
        if (LEVEL_RANK[eff] >= LEVEL_RANK[level]) fit.push({ name: groupNameOf(r.ad_group_dn), specific, eff, def: r.default_access, key: r.role_key });
      });
      // closest fit first: a role with an explicit rule for THIS page, then the narrowest grant, then the narrowest role
      fit.sort(function (a, b) {
        return (Number(b.specific) - Number(a.specific)) || (LEVEL_RANK[a.eff] - LEVEL_RANK[b.eff]) ||
               (LEVEL_RANK[a.def] - LEVEL_RANK[b.def]) || a.key.localeCompare(b.key);
      });
      groups = cleanList(fit.map(function (f) { return f.name; }));
    }
    if (!groups.length) return { kind, state: 'unavailable', target, why: 'no-group-grants-it', level };
    return {
      kind, state: 'ready', target, level,
      need: { groups, any_of: groups.length > 1, level },
      refusal: mine === 'none' ? 'The signed-in account has no access to this page.' : 'The signed-in account can open this page but not at the level this action needs.',
      reason: mine === 'none' ? 'NO_ACCESS' : 'INSUFFICIENT_LEVEL',
      needKey: sha('app|' + pg.page_key + '|' + level, 40),
      needText: groups.slice(0, MAX_GROUPS_IN_TICKET).join(' / '),
    };
  }

  // The earlier ticket for this person + target + need, if it is still open.
  async function findOpen(conn, email, kind, targetKey, needKey) {
    const [rows] = await conn.query(
      'SELECT id, created_at, sdp_id, sdp_display_id FROM access_requests ' +
      'WHERE requester_email = ? AND kind = ? AND target = ? AND need_key = ? AND created_at > (NOW() - INTERVAL ? DAY) ' +
      'ORDER BY id DESC LIMIT 1', [email, kind, targetKey, needKey, DEDUPE_DAYS]);
    if (!rows.length) return null;
    const row = rows[0];
    let status = null, verified = false;
    try {
      const r = await withTimeout(Promise.resolve(getRequestById(row.sdp_id)), SDP_LOOKUP_MS);
      if (!r) return null;                                   // SDP no longer has it: deleted, so ask again
      status = r.status ? String(r.status) : null; verified = true;
      if (status && CLOSED_RE.test(status)) return null;     // closed/resolved: a new ask is a new request
    } catch (e) { /* cannot ask SDP: keep pointing at the ticket we know exists */ }
    return { display_id: String(row.sdp_display_id), created_at: row.created_at, status: verified ? status : null, verified };
  }

  function view(t, extra) {
    const out = {
      ok: true, kind: t.kind, state: t.state, target: t.target,
    };
    if (t.need) out.need = t.need;
    if (t.refusal) out.refusal = t.refusal;
    if (t.why) out.why = t.why;
    if (t.reason) out.reason = t.reason;
    if (t.level) out.level = t.level;
    return Object.assign(out, extra || {});
  }

  function gate(req, res) {
    const sess = sessionOf(req, sessionAuth);
    if (!sess.ok) {
      res.status(401).json({ ok: false, error: sess.expired ? 'SESSION_EXPIRED' : 'SIGN_IN_REQUIRED' });
      return null;
    }
    return sess;
  }

  router.get('/context', readLimiter, async function (req, res) {
    const sess = gate(req, res); if (!sess) return;
    try {
      const t = await resolveTarget(req, sess, req.query || {});
      if (t.error) return res.status(t.error).json({ ok: false, error: t.code });
      const base = { user: { name: sess.name, email: sess.email }, dry_run: !!dryRun() };
      if (t.state !== 'ready') return res.json(view(t, base));
      const conn = await pool.getConnection();
      let open = null;
      try { open = await findOpen(conn, sess.email, t.kind, t.target.key, t.needKey); }
      finally { conn.release(); }
      if (open) return res.json(view(Object.assign({}, t, { state: 'already' }), Object.assign(base, { ticket: open })));
      return res.json(view(t, base));
    } catch (e) {
      console.error('[access-request] context failed:', e.message);
      return res.status(500).json({ ok: false, error: 'CONTEXT_FAILED' });
    }
  });

  router.post('/file', fileLimiter, async function (req, res) {
    const sess = gate(req, res); if (!sess) return;
    if (!sameOrigin(req)) return res.status(403).json({ ok: false, error: 'CSRF_ORIGIN_REQUIRED' });
    let conn = null, lockName = null, locked = false;
    try {
      const body = (req.body && typeof req.body === 'object') ? req.body : {};
      const t = await resolveTarget(req, sess, body);
      if (t.error) return res.status(t.error).json({ ok: false, error: t.code });
      const base = { user: { name: sess.name, email: sess.email }, dry_run: !!dryRun() };
      if (t.state !== 'ready') return res.json(view(t, base));     // already allowed / stale session / nothing to ask for

      const path = String(body.path || '').split(/[?#]/)[0].slice(0, 300);
      const stamp = now();

      if (dryRun()) {
        await audit(req, sess.email, 'access_request_dryrun', t.kind === 'app' ? t.target.key : null,
          { host: t.target.host, target: t.target.key, need: t.needText });
        return res.json(view(Object.assign({}, t, { state: 'filed' }), Object.assign(base, {
          ticket: { display_id: 'PRACTICE', created_at: stamp.toISOString(), status: null, verified: false } })));
      }

      conn = await pool.getConnection();
      lockName = 'accreq:' + sha(sess.email + '|' + t.kind + '|' + t.target.key + '|' + t.needKey, 40);
      const [[lk]] = await conn.query('SELECT GET_LOCK(?, ?) AS got', [lockName, LOCK_WAIT_S]);
      locked = Number(lk && lk.got) === 1;
      if (!locked) return res.status(503).json({ ok: false, error: 'BUSY' });

      const open = await findOpen(conn, sess.email, t.kind, t.target.key, t.needKey);
      if (open) {
        await audit(req, sess.email, 'access_request_repeat', t.kind === 'app' ? t.target.key : null,
          { host: t.target.host, target: t.target.key, ticket: open.display_id });
        return res.json(view(Object.assign({}, t, { state: 'already' }), Object.assign(base, { ticket: open })));
      }

      const [[cnt]] = await conn.query(
        'SELECT COUNT(*) AS n FROM access_requests WHERE requester_email = ? AND created_at > (NOW() - INTERVAL 1 HOUR)', [sess.email]);
      if (Number(cnt.n) >= MAX_NEW_PER_HOUR) return res.status(429).json({ ok: false, error: 'TOO_MANY_REQUESTS' });

      const ticketIn = buildTicket(t, sess, path, stamp);
      let made;
      try {
        made = await createTicket({
          subject: ticketIn.subject, description: ticketIn.description,
          requesterEmail: sess.email, requesterName: sess.name || sess.email,
          priority: 'Normal', category, subcategory,
        });
      } catch (e) {
        const why = (typeof sdp.sdpErrorText === 'function') ? sdp.sdpErrorText(e) : (e && e.message);
        console.error('[access-request] SDP createTicket failed for ' + sess.email + ' -> ' + t.target.key + ': ' + why);
        await audit(req, sess.email, 'access_request_failed', t.kind === 'app' ? t.target.key : null,
          { host: t.target.host, target: t.target.key, error: String(why).slice(0, 300) });
        return res.status(502).json({ ok: false, error: 'FILING_FAILED' });
      }
      if (!made || !made.id) {
        console.error('[access-request] SDP answered without a ticket id');
        return res.status(502).json({ ok: false, error: 'FILING_FAILED' });
      }

      const display = String(made.display_id || made.id);
      try {
        await conn.query(
          'INSERT INTO access_requests (requester_email, requester_name, kind, target, need_key, need_text, path, reason, ' +
          'sdp_id, sdp_display_id, sdp_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
          [sess.email, sess.name || null, t.kind, t.target.key, t.needKey, t.needText.slice(0, 500), path || null,
           t.reason || null, String(made.id), display, made.url ? String(made.url).slice(0, 500) : null]);
      } catch (e) {
        // The ticket exists; only the dedupe ledger missed it. Say so loudly, still tell the person the truth.
        console.error('[access-request] TICKET ' + display + ' FILED BUT LEDGER INSERT FAILED (' + sess.email + ' -> ' + t.target.key + '): ' + e.message);
      }
      await audit(req, sess.email, 'access_request_filed', t.kind === 'app' ? t.target.key : null,
        { host: t.target.host, target: t.target.key, need: t.needText, ticket: display });
      return res.json(view(Object.assign({}, t, { state: 'filed' }), Object.assign(base, {
        ticket: { display_id: display, created_at: stamp.toISOString(), status: null, verified: false } })));
    } catch (e) {
      console.error('[access-request] file failed:', e && e.message);
      return res.status(500).json({ ok: false, error: 'FILING_FAILED' });
    } finally {
      if (conn) {
        if (locked) { try { await conn.query('SELECT RELEASE_LOCK(?)', [lockName]); } catch (e) { /* lock dies with the connection */ } }
        conn.release();
      }
    }
  });

  return router;
}

// The ticket text. Every value that came from a person or a config file goes through escHtml: SDP renders the
// description as HTML.
function buildTicket(t, sess, path, stamp) {
  const who = sess.name ? sess.name + ' <' + sess.email + '>' : sess.email;
  const groups = t.need.groups.slice(0, MAX_GROUPS_IN_TICKET);
  const more = t.need.groups.length - groups.length;
  const first = groups[0];
  const subject = (t.kind === 'site'
    ? 'Access request: ' + t.target.label + ' (' + t.target.host + ') - add to ' + first
    : 'Access request: ' + t.target.label + ' (' + t.need.level + ' access) - add to ' + first
  ).slice(0, 250);

  const L = [];
  L.push('<b>Access request filed from the CorpIT access page. The requester typed nothing and does not need a reply to proceed.</b>');
  L.push('');
  L.push('<b>Requester:</b> ' + escHtml(who) + ' (identity verified by CorpIT sign-in)');
  if (t.kind === 'site') {
    L.push('<b>Tried to open:</b> ' + escHtml(t.target.label) + ' - https://' + escHtml(t.target.host) + escHtml(path || '/'));
  } else {
    L.push('<b>Tried to open:</b> ' + escHtml(t.target.label) + ' (page key ' + escHtml(t.target.key) + ') on ' + escHtml(t.target.host) +
           ', needing <b>' + escHtml(t.need.level) + '</b> access');
  }
  L.push('<b>Why it was refused:</b> ' + escHtml(t.refusal));
  L.push('');
  L.push('<b>Access needed:</b> ' + (groups.length > 1
    ? 'add the requester to <b>any one</b> of these Active Directory security groups (closest fit first):'
    : 'add the requester to this Active Directory security group:'));
  groups.forEach(function (g) { L.push('&nbsp;&nbsp;- <b>' + escHtml(g) + '</b>'); });
  if (more > 0) L.push('&nbsp;&nbsp;- and ' + more + ' more that also grant it');
  L.push('');
  L.push('Group membership is read when a person signs in, so after the change the requester needs to sign out and back in.');
  L.push('Filed: ' + escHtml(stamp.toISOString()) + ' (UTC)');
  return { subject, description: L.join('<br>') };
}

module.exports = { create, buildTicket, siteNeed, groupNameOf, sessionOf, sameOrigin, readPolicy, CLOSED_RE };
