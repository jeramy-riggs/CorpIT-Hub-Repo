// site-access.js — per-vhost authorization for the CorpIT Hub gate.
//
// The gate answers two different questions and must not confuse them:
//
//   AUTHENTICATION  "is this a valid session?"      pure HMAC, never a network call
//   AUTHORIZATION   "may THIS person open THIS site?"  this file
//
// Authorization is a comparison between two lists that are both already in hand
// by the time a request arrives: the AD groups carried in the signed session
// token (resolved once at sign-in, see ad-groups.js) and the groups the console
// has allowed for the host. So this stays a local, synchronous, in-memory check.
// It performs NO directory lookup. That invariant is deliberate: gating pages on
// a live AD resolution is what locked every non-superadmin user out of the
// platform the last time this gate grew a dependency.
//
// The policy file is written by the admin console (subadmin.nrpi.local) and is
// the single source of truth for who may open which site. It is re-read when its
// mtime changes, so a console edit takes effect without restarting the API.

const fs = require('fs');

// PATH-RELEASE-20260929: /etc/corpit/shared/site-access.json via corpit-paths.js. A missing FILE still
// means FALLBACK below; a missing shared DIR throws at load (the gate does not start).
const POLICY_PATH = require('./corpit-paths').sharedFile('site-access.json', 'SITE_ACCESS_POLICY');

// Fail-safe default used when the policy file is missing or unparseable. Deny
// everyone except the people who build the platform, rather than fall open.
const FALLBACK = {
  version: 1,
  superadmin_groups: ['SaaS-ITH-SA'],
  default: { mode: 'superadmin' },
  sites: {},
};

let cached = null;
let cachedMtime = 0;
let lastError = null;

function loadPolicy() {
  let st;
  try {
    st = fs.statSync(POLICY_PATH);
  } catch (e) {
    // No policy file at all: fall back to superadmin-only rather than open.
    if (!cached) { cached = FALLBACK; lastError = 'policy file missing'; }
    return cached;
  }
  const m = st.mtimeMs;
  if (cached && m === cachedMtime) return cached;
  try {
    const raw = fs.readFileSync(POLICY_PATH, 'utf8');
    const p = JSON.parse(raw);
    if (!p || typeof p !== 'object' || typeof p.sites !== 'object') {
      throw new Error('policy has no sites object');
    }
    cached = p;
    cachedMtime = m;
    lastError = null;
  } catch (e) {
    // A malformed edit must not open the platform. Keep the last good policy if
    // we have one; otherwise deny down to superadmins.
    lastError = 'policy unreadable: ' + e.message;
    if (!cached) cached = FALLBACK;
  }
  return cached;
}

// Hosts arrive from nginx's $host, which may carry a port and any case.
function normHost(h) {
  return String(h || '').trim().toLowerCase().replace(/:\d+$/, '').replace(/\.$/, '');
}

function lower(list) {
  return (Array.isArray(list) ? list : []).map(function (g) {
    return String(g || '').trim().toLowerCase();
  }).filter(Boolean);
}

// The env break-glass floor. These identities are super-admin without any
// directory involvement at all, which is what makes them usable during an AD
// outage or a broken policy file.
function envSuperAdmins() {
  return new Set(lower(String(process.env.RBAC_SUPERADMINS || '').split(',')));
}

// SECPAGELIMIT-20261019 (itam dev, Jeramy 2026-10-19: SaaS-ITH-SEC sees only
// /ai-governance.html and /my-profile.html on dev-corpit). Optional per-group page
// allowlist inside a site entry, set from the admin console:
//   "page_limits": { "<AD group>": ["/a.html", "/b.html"], ... }
// A person is limited only when EVERY group that grants them the site has an entry;
// their pages are then the union of those entries and every other page document on
// the host is refused. Assets and /api/ are not pages and keep the site answer.
// Superadmins are never limited. The first listed page is the person's home there.
const PAGE_ASSET_EXT = /\.(js|mjs|css|map|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|otf|eot)$/i;

// The path nginx will serve for a raw $request_uri, or null when it cannot be read
// safely (null refuses a limited user). One decode, like nginx; repeated slashes and
// dot segments resolved, like nginx.
function pagePath(uri) {
  if (typeof uri !== 'string' || !uri) return null;
  const cut = uri.search(/[?#]/);
  let p = cut === -1 ? uri : uri.slice(0, cut);
  if (p.charAt(0) !== '/') return null;
  try { p = decodeURIComponent(p); } catch (e) { return null; }
  if (/[\x00-\x1f\x7f\\]/.test(p)) return null;
  p = require('path').posix.normalize(p);
  return p.charAt(0) === '/' ? p : null;
}

// A page document, as opposed to an asset or an API call. nginx's '\.html$' regex
// location beats the /api/ and /hub-api/ prefixes, so an .html path is a page there too.
function isPage(p) {
  if (/^\/(api|hub-api)\//.test(p) && !/\.html?$/i.test(p)) return false;
  return !PAGE_ASSET_EXT.test(p);
}

function computeLimit(site, mine) {
  const pl = site && site.page_limits;
  if (!pl || typeof pl !== 'object' || !mine) return null;
  const byGroup = {};
  Object.keys(pl).forEach(function (g) { byGroup[String(g).trim().toLowerCase()] = pl[g]; });
  const granting = lower(site.groups).filter(function (g) { return mine.has(g); });
  if (!granting.length) return null;
  const pages = [];
  for (let i = 0; i < granting.length; i++) {
    const list = byGroup[granting[i]];
    if (!Array.isArray(list)) return null;      // one unlimited granting group lifts the limit
    list.forEach(function (x) {
      x = String(x || '');
      if (x.charAt(0) === '/' && pages.indexOf(x) === -1) pages.push(x);
    });
  }
  return { pages: pages, home: pages[0] || null };
}

/**
 * Decide whether `email` (holding AD groups `groups`) may open `host`.
 *
 * @param {string}        host    the vhost being requested
 * @param {string}        email   HMAC-verified identity from the session token
 * @param {string[]|null} groups  groups from the token; null means the session
 *                                predates group resolution and we know nothing
 * @param {string|null}   [uri]   raw request URI; only the gate's per-request check
 *                                passes it, and only then do page_limits apply
 *                                (SECPAGELIMIT-20261019)
 * @returns {{allow:boolean, reason:string, mode:string}}
 */
function decide(host, email, groups, uri) {
  const policy = loadPolicy();
  const h = normHost(host);
  const who = String(email || '').trim().toLowerCase();
  const mine = groups === null || groups === undefined ? null : new Set(lower(groups));

  // 1. The people who build the platform reach every site on it, including one
  //    created a minute ago that nobody has configured yet.
  if (who && envSuperAdmins().has(who)) {
    return { allow: true, reason: 'superadmin-env', mode: 'superadmin' };
  }
  if (mine) {
    const sa = lower(policy.superadmin_groups || FALLBACK.superadmin_groups);
    for (let i = 0; i < sa.length; i++) {
      if (mine.has(sa[i])) return { allow: true, reason: 'superadmin-group', mode: 'superadmin' };
    }
  }

  // 2. Site policy, or the configured default for a host nobody has set up.
  const site = (policy.sites && policy.sites[h]) || policy.default || FALLBACK.default;
  const mode = String(site.mode || 'superadmin');

  if (mode === 'authenticated') {
    // Any valid session. Note this is not "anyone": Entra assignment-required
    // means only members of the CorpIT Hub groups can obtain a session at all.
    return { allow: true, reason: 'authenticated', mode: mode };
  }

  if (mode === 'groups') {
    if (!mine) {
      // Signed in before this site had a group policy, so the token carries no
      // group list. Not a denial of the person - a denial of the stale token.
      return { allow: false, reason: 'session-predates-policy', mode: mode };
    }
    const allowed = lower(site.groups);
    for (let i = 0; i < allowed.length; i++) {
      if (mine.has(allowed[i])) {
        if (uri !== undefined) {                 // SECPAGELIMIT-20261019
          const lim = computeLimit(site, mine);
          if (lim) {
            const p = pagePath(uri);
            if (p === null || (isPage(p) && lim.pages.indexOf(p) === -1)) {
              return { allow: false, reason: 'page-limited', mode: mode };
            }
          }
        }
        return { allow: true, reason: 'group-match', mode: mode };
      }
    }
    return { allow: false, reason: 'not-in-allowed-group', mode: mode };
  }

  // mode 'superadmin' (and anything unrecognised) - already handled above, so
  // reaching here means the caller is not one.
  return { allow: false, reason: 'superadmin-only', mode: 'superadmin' };
}

// Which groups any site actually references. Sign-in stores only these in the
// session token, so a user in 200 AD groups still gets a small token.
function referencedGroups() {
  const policy = loadPolicy();
  const out = new Set(lower(policy.superadmin_groups || FALLBACK.superadmin_groups));
  const sites = policy.sites || {};
  Object.keys(sites).forEach(function (h) {
    lower(sites[h] && sites[h].groups).forEach(function (g) { out.add(g); });
  });
  lower((policy.default || {}).groups).forEach(function (g) { out.add(g); });
  return Array.from(out);
}

function status() {
  const p = loadPolicy();
  return {
    path: POLICY_PATH,
    error: lastError,
    sites: Object.keys(p.sites || {}).length,
    default_mode: (p.default || {}).mode || 'superadmin',
  };
}

/**
 * Every site this person may open, in policy order.
 *
 * Deliberately reuses decide() rather than reimplementing the rules, so the
 * "somewhere you CAN go" offer can never disagree with the gate about who is
 * allowed where -- a second copy of an authorization rule is a rule that will
 * drift. Returns bare hostnames; the caller chooses the scheme.
 */
function allowedSitesFor(email, groups) {
  const policy = loadPolicy();
  const sites = policy.sites || {};
  return Object.keys(sites)
    .filter(function (h) { return decide(h, email, groups).allow; })
    .map(function (h) {
      return { host: h, label: (sites[h] && sites[h].label) || h };
    });
}

// SECPAGELIMIT-20261019: this person's page limit on `host`, or null when they are
// not limited there (refused outright, superadmin, or a granting group has no limit).
function pageLimitFor(host, email, groups) {
  const d = decide(host, email, groups);
  if (!d.allow || d.reason !== 'group-match') return null;
  const policy = loadPolicy();
  const site = (policy.sites && policy.sites[normHost(host)]) || policy.default || FALLBACK.default;
  return computeLimit(site, new Set(lower(groups)));
}

module.exports = { decide, referencedGroups, status, normHost, POLICY_PATH,
                   allowedSitesFor, pageLimitFor, pagePath, isPage };
