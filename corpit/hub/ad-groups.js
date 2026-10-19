// ad-groups.js — resolve a user's AD security groups, ONCE, at sign-in.
//
// Why here and not in the gate: the gate runs on every request and must never
// depend on the directory being up (see the header of gate-routes.js). Sign-in
// is the one moment where a directory call is both affordable and appropriate,
// so group membership is resolved here and carried in the signed session token.
//
// Only groups that some site policy actually references are returned. A user in
// 200 AD groups therefore still gets a small token, and adding a group to a site
// policy is what makes it start appearing.
//
// Failure is NOT fatal to sign-in. If the directory is unreachable the user still
// gets a session, just without a group list; site-access.js then treats them as
// unresolved rather than as a member of nothing.

const ldap = require('ldapjs');
const siteAccess = require('./site-access');

const LDAP_URL     = process.env.LDAP_URL;
const LDAP_BASE_DN = process.env.LDAP_BASE_DN;
const LDAP_BIND    = process.env.LDAP_BIND_USER;
const LDAP_PASS    = process.env.LDAP_BIND_PASS;

// Sign-in is interactive: a user is watching a spinner. Keep the whole lookup
// inside a few seconds and give up rather than hang the redirect.
const CONNECT_TIMEOUT_MS = 4000;
const SEARCH_TIMEOUT_MS  = 5000;

function configured() {
  return !!(LDAP_URL && LDAP_BASE_DN && LDAP_BIND && LDAP_PASS);
}

function escapeFilterValue(v) {
  return String(v)
    .replace(/\\/g, '\\5c')
    .replace(/\*/g, '\\2a')
    .replace(/\(/g, '\\28')
    .replace(/\)/g, '\\29')
    .replace(/\0/g, '\\00');
}

// "CN=SaaS-ITH-SA,OU=SaaS Okta,OU=Groups,DC=nrpi,DC=local" -> "saas-ith-sa"
function groupCn(dn) {
  const m = /^\s*CN=([^,]+)/i.exec(String(dn || ''));
  if (!m) return '';
  return m[1].replace(/\\([,+"\\<>;=])/g, '$1').trim().toLowerCase();
}

function connectAndBind() {
  return new Promise((resolve, reject) => {
    const client = ldap.createClient({
      url: LDAP_URL,
      connectTimeout: CONNECT_TIMEOUT_MS,
      timeout: SEARCH_TIMEOUT_MS,
    });
    let settled = false;
    const fail = (err) => {
      if (settled) return;
      settled = true;
      try { client.destroy(); } catch (e) { /* ignore */ }
      reject(err);
    };
    client.on('error', fail);
    client.on('connectError', fail);
    client.bind(LDAP_BIND, LDAP_PASS, (err) => {
      if (err) return fail(err);
      if (settled) return;
      settled = true;
      resolve(client);
    });
  });
}

function searchOnce(client, base, filter, attributes) {
  return new Promise((resolve, reject) => {
    const entries = [];
    client.search(base, { scope: 'sub', filter, attributes }, (err, res) => {
      if (err) return reject(err);
      res.on('searchEntry', (entry) => {
        const obj = { dn: entry.dn ? entry.dn.toString() : null };
        for (const a of (entry.attributes || [])) {
          const vals = a.values || a.vals || [];
          obj[a.type] = vals.length === 1 ? vals[0] : vals.slice();
        }
        entries.push(obj);
      });
      res.on('error', reject);
      res.on('end', () => resolve(entries));
    });
  });
}

function closeQuietly(client) {
  try { client.unbind(() => {}); } catch (e) { /* ignore */ }
  try { client.destroy(); } catch (e) { /* ignore */ }
}

/**
 * Groups for a signed-in user, filtered to those any site policy references.
 * Returns null - meaning "unknown", not "none" - when the directory cannot be
 * consulted, so a lookup failure is never mistaken for an empty membership.
 */
async function groupsForSignIn(email) {
  const upn = String(email || '').trim();
  if (!upn || !configured()) return null;

  let client;
  try {
    client = await connectAndBind();
    const u = escapeFilterValue(upn);
    // UPNs in this directory are mixed case and Entra's preferred_username is
    // not always the on-prem UPN, so match mail as well. LDAP matching on both
    // attributes is case-insensitive.
    const filter = '(&(objectCategory=person)(objectClass=user)' +
                   '(|(userPrincipalName=' + u + ')(mail=' + u + ')))';
    const entries = await searchOnce(client, LDAP_BASE_DN, filter,
                                     ['memberOf', 'userAccountControl']);
    // The search SUCCEEDED and matched nobody: this identity authenticated against
    // Entra but has no on-prem account, so it genuinely holds no AD groups. That is
    // [] - a real, empty entitlement - not null. Returning null would tell the user
    // their session was stale and to sign in again, which could never help.
    if (!entries.length) return [];

    const e = entries[0];
    const uac = parseInt(e.userAccountControl, 10) || 0;
    if (uac & 0x2) return [];   // ACCOUNTDISABLE: a real, empty entitlement

    const memberOf = Array.isArray(e.memberOf) ? e.memberOf
                   : (e.memberOf ? [e.memberOf] : []);
    const mine = new Set(memberOf.map(groupCn).filter(Boolean));

    // Keep only what some policy actually uses.
    const referenced = siteAccess.referencedGroups();
    return referenced.filter((g) => mine.has(g));
  } catch (err) {
    console.error('[ad-groups] lookup failed for %s: %s', upn, err && err.message);
    return null;
  } finally {
    if (client) closeQuietly(client);
  }
}

// MP-SIGNIN (2026-10-07): "is this an ACTIVE directory account?" for My Profile's own
// sign-in (mp-signin.js), which admits every active employee and contractor rather
// than an Entra assignment list. Entra alone cannot answer it: a synced account can
// still hold a working Entra session for a while after AD disables it.
//
// Fails CLOSED, the opposite of groupsForSignIn: a sign-in that cannot prove the
// account is active is refused. Statuses:
//   active     exactly one user object, ACCOUNTDISABLE clear, accountExpires not past
//   disabled   ACCOUNTDISABLE (0x2) set
//   expired    accountExpires set and in the past
//   missing    no user object for this UPN/mail (e.g. a guest, or a cloud-only account)
//   ambiguous  more than one user object matched -- refuse rather than pick one
//   unknown    directory unreachable / not configured / unreadable attributes
// `groups` (active only) is the same filtered list groupsForSignIn returns.
const AD_NEVER_EXPIRES = '9223372036854775807';
function accountExpiresMs(v) {
  const s = String(v == null ? '' : v).trim();
  if (!s || s === '0' || s === AD_NEVER_EXPIRES) return null;     // never expires
  if (!/^\d+$/.test(s)) return NaN;
  // FILETIME: 100ns ticks since 1601-01-01 UTC.
  return Number(BigInt(s) / 10000n) - 11644473600000;
}

async function accountForSignIn(email) {
  const upn = String(email || '').trim();
  if (!upn) return { status: 'missing' };
  if (!configured()) return { status: 'unknown' };

  let client;
  try {
    client = await connectAndBind();
    const u = escapeFilterValue(upn);
    const filter = '(&(objectCategory=person)(objectClass=user)' +
                   '(|(userPrincipalName=' + u + ')(mail=' + u + ')))';
    const entries = await searchOnce(client, LDAP_BASE_DN, filter,
                                     ['memberOf', 'userAccountControl', 'accountExpires']);
    if (!entries.length) return { status: 'missing' };
    if (entries.length > 1) return { status: 'ambiguous' };

    const e = entries[0];
    const uac = parseInt(e.userAccountControl, 10);
    if (!isFinite(uac)) return { status: 'unknown' };
    if (uac & 0x2) return { status: 'disabled' };
    const exp = accountExpiresMs(e.accountExpires);
    if (Number.isNaN(exp)) return { status: 'unknown' };
    if (exp !== null && exp <= Date.now()) return { status: 'expired' };

    const memberOf = Array.isArray(e.memberOf) ? e.memberOf
                   : (e.memberOf ? [e.memberOf] : []);
    const mine = new Set(memberOf.map(groupCn).filter(Boolean));
    const referenced = siteAccess.referencedGroups();
    return { status: 'active', groups: referenced.filter((g) => mine.has(g)) };
  } catch (err) {
    console.error('[ad-groups] account check failed for %s: %s', upn, err && err.message);
    return { status: 'unknown' };
  } finally {
    if (client) closeQuietly(client);
  }
}

module.exports = { groupsForSignIn, groupCn, accountForSignIn, _t: { accountExpiresMs } };
