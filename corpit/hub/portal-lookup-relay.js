// portal-lookup-relay.js — loopback-only directory lookup for the Access Portal
// (accessportal app.py on :8001). Given a requester's email it returns the
// requester's own profile and their MANAGER (name, email, Entra object id) so the
// public requester form can pre-fill and route approval to a resolved identity.
// One hop up only: it never lists direct reports.
//
// This is NOT a new directory path. It reads the reporting tree the My Profile
// page already maintains (org-tree-lib.js: org_reporting_person, built from the
// Entra `manager_upn` field — the AD Organization tab's Manager — and refreshed on
// read past its 180-min TTL). /api/profile/ai-team walks that same tree DOWN so a
// manager can see their team's Claude usage; this walks it one step UP. Entra
// object ids come from entra_users, the table the tree is built from.
//
// Fallback ladder, reported in `source`:
//   tree  - org_reporting_person + entra_users (the normal case)
//   live  - one Graph call with $expand=manager on the IdentityDiag app, the same
//           call profile-routes.js liveIdentity() makes; used when the tree has no
//           row for the person (new hire ahead of the next entra-sync)
//   sync  - entra_users alone, when Graph is unreachable too
//
// Policy enforced HERE, where the portal cannot override it (mirrors
// portal-mail-relay.js):
//   - caller must be loopback AND present X-Portal-Lookup-Key (PORTAL_LOOKUP_KEY)
//   - PORTAL_LOOKUP_RATE_MAX lookups per rolling hour (default 600)
//   - every lookup (and every refusal) appended to /var/log/corpit/portal-lookup-audit.log
//
// NOT mounted under /api/ on purpose: no nginx location proxies /internal/*, so
// this is unreachable through any vhost even before the key check. The
// browser-facing /api/identity/portal-lookup keeps its RBAC gate untouched.

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const org = require('./org-tree-lib');

const RELAY_KEY = process.env.PORTAL_LOOKUP_KEY || '';
const RATE_MAX = parseInt(process.env.PORTAL_LOOKUP_RATE_MAX || '600', 10);   // per rolling hour
const RATE_WINDOW_MS = 60 * 60 * 1000;
const AUDIT_FILE = process.env.PORTAL_LOOKUP_AUDIT || '/var/log/corpit/portal-lookup-audit.log';
const GRAPH = 'https://graph.microsoft.com/v1.0';
const USER_SELECT = 'id,displayName,userPrincipalName,mail,jobTitle,department,accountEnabled';
const MGR_SELECT = 'id,displayName,userPrincipalName,mail,jobTitle';

const lc = (v) => (v == null ? '' : String(v).trim().toLowerCase());
const s = (v) => (v == null ? '' : String(v));

function audit(entry) {
  const line = JSON.stringify({ ts: new Date().toISOString(), ...entry });
  fs.appendFile(AUDIT_FILE, line + '\n', () => {});
  console.log('[portal-lookup] ' + line);
}

// ── Guards (same shape as portal-mail-relay.js) ─────────────────────────────
const LOOPBACK = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);
function isLoopback(req) {
  // Two addresses, and both must be loopback. The socket peer is the one value
  // a caller cannot forge -- but behind nginx it is ALWAYS loopback, so on its
  // own it proved nothing about a proxied request (CHG-ARCH-05). req.ip follows
  // X-Forwarded-For (trust proxy is on app-wide), which nginx sets on every
  // request it proxies and app.py never sends: a request that came in through
  // a vhost shows the browser's address here and is refused, while a direct
  // loopback caller that forges X-Forwarded-For can only deny itself.
  return LOOPBACK.has(req.socket.remoteAddress) && LOOPBACK.has(req.ip);
}

// F39: compare sha256 digests (always 32 bytes), not the raw strings -- a
// non-ASCII header has the right .length but a different byte length, and
// timingSafeEqual threw inside the async route, exiting the process. Never throws.
function keyOk(req) {
  try {
    if (!RELAY_KEY) return false;
    const got = String(req.get('X-Portal-Lookup-Key') || '');
    const h = (v) => crypto.createHash('sha256').update(v, 'utf8').digest();
    return crypto.timingSafeEqual(h(got), h(RELAY_KEY));
  } catch (e) {
    return false;
  }
}

const _hits = [];
function rateOk() {
  const cut = Date.now() - RATE_WINDOW_MS;
  while (_hits.length && _hits[0] < cut) _hits.shift();
  if (_hits.length >= RATE_MAX) return false;
  _hits.push(Date.now());
  return true;
}

// ── Graph (client credentials, cached) — IdentityDiag app, AZURE_* as fallback ──
let _tok = { value: null, exp: 0 };
async function graphToken() {
  const now = Date.now() / 1000;
  if (_tok.value && now < _tok.exp - 120) return _tok.value;
  const T = process.env.ENTRA_TENANT_ID || process.env.AZURE_TENANT_ID;
  const C = process.env.ENTRA_CLIENT_ID || process.env.AZURE_CLIENT_ID;
  const S = process.env.ENTRA_CLIENT_SECRET || process.env.AZURE_CLIENT_SECRET;
  if (!T || !C || !S) throw new Error('ENTRA_TENANT_ID / ENTRA_CLIENT_ID / ENTRA_CLIENT_SECRET missing');
  const r = await fetch(`https://login.microsoftonline.com/${T}/oauth2/v2.0/token`, {
    method: 'POST',
    body: new URLSearchParams({ client_id: C, client_secret: S, scope: 'https://graph.microsoft.com/.default', grant_type: 'client_credentials' }),
    signal: AbortSignal.timeout(8000),
  });
  if (!r.ok) throw new Error('token HTTP ' + r.status);
  const j = await r.json();
  _tok = { value: j.access_token, exp: now + (j.expires_in || 3600) };
  return _tok.value;
}

// Returns the Graph user with manager expanded, null on 404, throws otherwise.
async function graphUserWithManager(identity) {
  const tok = await graphToken();
  const url = GRAPH + '/users/' + encodeURIComponent(identity)
    + '?$select=' + USER_SELECT + '&$expand=manager($select=' + MGR_SELECT + ')';
  const r = await fetch(url, { headers: { Authorization: 'Bearer ' + tok }, signal: AbortSignal.timeout(8000) });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error('graph HTTP ' + r.status);
  return r.json();
}

// ── Shape ───────────────────────────────────────────────────────────────────
// Flat on purpose: the requester form already reads name/email/department/
// title/manager from the old route, so those keys keep their meaning (manager
// stays the display-name string). Strings are '' when unknown, ids are null.
function shape(source, asOf, me, mgr, hr) {
  return {
    ok: true,
    source,
    asOf: asOf || null,
    name:           s(me.name),
    email:          s(me.email),
    upn:            s(me.upn),
    id:             me.id || null,
    department:     s(me.department),
    title:          s(me.title),
    accountEnabled: me.accountEnabled == null ? null : !!me.accountEnabled,
    manager:        mgr ? s(mgr.name) : '',
    managerEmail:   mgr ? s(mgr.email) : '',
    managerUpn:     mgr ? s(mgr.upn) : '',
    managerId:      mgr && mgr.id ? mgr.id : null,
    managerTitle:   mgr ? s(mgr.title) : '',
    employment:     employmentBlock(hr),
  };
}

// CLA-EMPLOYMENT ────────────────────────────────────────────────────────────
// Employment classification, read from hr_roster (the Dayforce export) because
// Entra carries no usable signal: employeeType is null for every enabled user
// and the extension attributes are sync/routing markers. This relay reports the
// class verbatim and takes NO position on what it means -- app.py owns the
// FTE/PTA decision so the rule lives in one place.
//
// `matched` is deliberately three-valued (see shape callers):
//   true  - hr_roster had a row for this person
//   false - the lookup ran and found nothing (not in the HR export)
//   null  - the lookup itself failed; we could not check
// A caller must not read false and null as the same thing when auditing: one
// says "not in HR", the other says "we do not know".
function employmentBlock(hr) {
  if (hr === undefined) return { matched: null, payClass: '', isContingent: null, workerId: null, asOf: null };
  if (hr === null)      return { matched: false, payClass: '', isContingent: null, workerId: null, asOf: null };
  return {
    matched:      true,
    payClass:     s(hr.pay_class),
    isContingent: hr.is_contingent == null ? null : Number(hr.is_contingent) === 1,
    workerId:     hr.worker_id || null,
    asOf:         hr.loaded_at ? new Date(hr.loaded_at).toISOString() : null,
  };
}

// hr_roster row for the resolved identity. Tries the account email first (the
// same key profile-routes.js uses) and the UPN only if it differs and the first
// missed -- hybrid mailboxes where mail != userPrincipalName would otherwise
// read as "not in HR". Returns null for no row, undefined if the query failed.
async function hrRow(pool, ...candidates) {
  const seen = new Set();
  try {
    for (const c of candidates) {
      const v = lc(c);
      if (!v || !v.includes('@') || seen.has(v)) continue;
      seen.add(v);
      const [rows] = await pool.query(
        `SELECT pay_class, is_contingent, worker_id, loaded_at
           FROM hr_roster WHERE LOWER(email) = ? LIMIT 1`, [v]);
      if (rows[0]) return rows[0];
    }
    return null;
  } catch (e) {
    audit({ ok: false, hrLookupError: e.message });
    return undefined;
  }
}

// entra_users row by UPN or mail (case-insensitive). A bare handle (no @) is
// matched against the UPN local part so the old sAMAccountName-style query
// still resolves; parameterised, so the input never reaches SQL as text.
async function entraRow(pool, q) {
  const v = lc(q);
  const [rows] = v.includes('@')
    ? await pool.query(
        `SELECT entra_id, user_principal_name, mail, display_name, job_title, department,
                manager_upn, account_enabled, user_type, last_synced_at
           FROM entra_users
          WHERE LOWER(user_principal_name) = ? OR LOWER(mail) = ?
          ORDER BY account_enabled DESC, (user_principal_name LIKE '%.onmicrosoft.com') ASC
          LIMIT 1`, [v, v])
    : await pool.query(
        `SELECT entra_id, user_principal_name, mail, display_name, job_title, department,
                manager_upn, account_enabled, user_type, last_synced_at
           FROM entra_users
          WHERE LOWER(SUBSTRING_INDEX(user_principal_name, '@', 1)) = ?
          ORDER BY account_enabled DESC, (user_principal_name LIKE '%.onmicrosoft.com') ASC
          LIMIT 1`, [v]);
  return rows[0] || null;
}

function fromEntraRow(r) {
  return r ? {
    id: r.entra_id || null, name: r.display_name, email: r.mail || r.user_principal_name,
    upn: r.user_principal_name, title: r.job_title, department: r.department,
    accountEnabled: r.account_enabled == null ? null : Number(r.account_enabled) === 1,
  } : null;
}

module.exports = function portalLookupRelay(pool) {
  const router = express.Router();

  // GET /internal/portal-lookup?q=<email | upn | handle>
  router.get('/', async (req, res) => {
    const q = String(req.query.q || '').trim();
    const deny = (code, error) => {
      audit({ ok: false, deny: error, src: req.socket.remoteAddress, client: req.get('X-Real-IP') || null, q });
      return res.status(code).json({ ok: false, error });
    };

    if (!isLoopback(req)) return deny(403, 'loopback only');
    if (!keyOk(req)) return deny(401, 'bad or missing lookup key');
    if (!rateOk()) return deny(429, 'rate limit: ' + RATE_MAX + '/hour');
    if (!q) return deny(400, 'q is required');
    if (q.length > 128 || !/^[a-zA-Z0-9._\-+@]{2,128}$/.test(q)) return deny(400, 'q must be an email, UPN or account name');

    const client = req.get('X-Real-IP') || null;   // requester's address, if app.py forwards it
    try {
      // 1. The reporting tree My Profile keeps warm (refreshes on read past TTL).
      const tree = await org.ensureFresh(pool);
      const me = await entraRow(pool, q);
      const person = me ? await org.person(pool, lc(me.user_principal_name)) : null;

      if (me && person) {
        let mgr = null;
        if (person.manager_email) {
          const [[mp]] = await pool.query(
            'SELECT email, display_name, job_title FROM org_reporting_person WHERE email = ?', [person.manager_email]);
          const mrow = await entraRow(pool, person.manager_email);
          mgr = {
            id: mrow ? mrow.entra_id : null,
            name: (mp && mp.display_name) || (mrow && mrow.display_name) || '',
            email: (mrow && (mrow.mail || mrow.user_principal_name)) || person.manager_email,
            upn: (mrow && mrow.user_principal_name) || person.manager_email,
            title: (mp && mp.job_title) || (mrow && mrow.job_title) || '',
          };
        }
        const hr = await hrRow(pool, me.mail, me.user_principal_name);
        const out = shape('tree', tree.refreshedAt, fromEntraRow(me), mgr, hr);
        audit({ ok: true, source: out.source, q, email: out.email, managerEmail: out.managerEmail, client });
        return res.json(out);
      }

      // 2. Not in the tree yet: one live Graph call, manager expanded.
      let g = null, graphErr = null;
      try { g = await graphUserWithManager(me ? me.user_principal_name : q); }
      catch (e) { graphErr = e.message; }
      if (g) {
        const m = g.manager && g.manager['@odata.type'] === '#microsoft.graph.user' ? g.manager : null;
        const out = shape('live', new Date().toISOString(), {
          id: g.id, name: g.displayName, email: g.mail || g.userPrincipalName, upn: g.userPrincipalName,
          title: g.jobTitle, department: g.department, accountEnabled: g.accountEnabled,
        }, m ? { id: m.id, name: m.displayName, email: m.mail || m.userPrincipalName, upn: m.userPrincipalName, title: m.jobTitle } : null,
           await hrRow(pool, g.mail, g.userPrincipalName));
        audit({ ok: true, source: out.source, q, email: out.email, managerEmail: out.managerEmail, client });
        return res.json(out);
      }
      if (!graphErr) {
        // Graph answered 404 and the tree had nothing: the identity does not exist.
        audit({ ok: false, notFound: true, q, client });
        return res.status(404).json({ ok: false, error: 'User not found', identity: q });
      }

      // 3. Graph unreachable: the last entra-sync copy, if it has the person.
      if (me) {
        const mrow = me.manager_upn ? await entraRow(pool, me.manager_upn) : null;
        const mm = fromEntraRow(mrow);
        const out = shape('sync', me.last_synced_at ? new Date(me.last_synced_at).toISOString() : null, fromEntraRow(me), mm,
                          await hrRow(pool, me.mail, me.user_principal_name));
        audit({ ok: true, source: out.source, q, email: out.email, managerEmail: out.managerEmail, graphErr, client });
        return res.json(out);
      }
      audit({ ok: false, error: 'directory unavailable: ' + graphErr, q, client });
      return res.status(503).json({ ok: false, error: 'Directory unavailable' });
    } catch (e) {
      audit({ ok: false, error: e.message, q, client });
      return res.status(500).json({ ok: false, error: 'Lookup failed' });
    }
  });

  return router;
};
