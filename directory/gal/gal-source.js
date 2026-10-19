// =============================================================================
// gal-source.js - shared Microsoft Graph -> GAL roster builder
//
// Used by both directory-sync jobs:
//   gal-mailbox-sync.js    pushes the roster into each user's Exchange contacts
//   gal-carddav-export.js  publishes the roster as a read-only CardDAV book
//
// Auth: client_credentials against the GAL-Sync app registration.
// Graph app permissions required: User.Read.All, GroupMember.Read.All,
// and (mailbox job only) Contacts.ReadWrite scoped by ApplicationAccessPolicy.
//
// Deps: native fetch (Node 18+), crypto (stdlib)
// =============================================================================

const crypto = require('crypto');
const { loadExclusions, applyExclusion, POLICY_REASON } = require('./gal-exclusions');

// -----------------------------------------------------------------------------
// Config (from .env, with safe defaults)
// -----------------------------------------------------------------------------
const TENANT_ID     = process.env.GAL_TENANT_ID || process.env.ENTRA_TENANT_ID;
const CLIENT_ID     = process.env.GAL_CLIENT_ID;
const CLIENT_SECRET = process.env.GAL_CLIENT_SECRET;

// Optional: only users in this group become directory entries. Empty = whole
// tenant, filtered by the rules in shouldPublish() below.
const SOURCE_GROUP = process.env.GAL_SOURCE_GROUP || '';

// Unlicensed accounts are almost always shared mailboxes, rooms, equipment or
// service accounts - none of which belong in a phone address book.
const REQUIRE_LICENSE = (process.env.GAL_REQUIRE_LICENSE || 'true').toLowerCase() === 'true';

// Belt-and-braces exclusion on the primary SMTP address, e.g. "^(svc|test)-"
const EXCLUDE_REGEX = process.env.GAL_EXCLUDE_REGEX
  ? new RegExp(process.env.GAL_EXCLUDE_REGEX, 'i')
  : null;

// Refuse to publish a suspiciously small roster - a Graph filter typo or a
// permissions regression must never be allowed to look like "everyone left".
const MIN_ROSTER = parseInt(process.env.GAL_MIN_ROSTER || '25', 10);

const GRAPH_BASE = 'https://graph.microsoft.com/v1.0';
const TOKEN_URL  = `https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token`;

// Fields we publish. showInAddressList is appended separately - see fetchDirectoryUsers().
const USER_SELECT = [
  'id', 'userPrincipalName', 'mail', 'displayName', 'givenName', 'surname',
  'jobTitle', 'department', 'companyName', 'officeLocation',
  'businessPhones', 'mobilePhone', 'accountEnabled', 'userType',
  'assignedLicenses', 'streetAddress', 'city', 'state', 'postalCode', 'country'
].join(',');

// -----------------------------------------------------------------------------
// Token cache (client_credentials flow)
// -----------------------------------------------------------------------------
let cachedToken = null;
let cachedTokenExpiresAt = 0;
let graphCallCount = 0;

async function getAccessToken() {
  const now = Date.now();
  if (cachedToken && now < cachedTokenExpiresAt - 300_000) {
    return cachedToken;  // 5 min safety buffer
  }
  if (!TENANT_ID || !CLIENT_ID || !CLIENT_SECRET) {
    throw new Error('GAL_TENANT_ID / GAL_CLIENT_ID / GAL_CLIENT_SECRET missing from .env');
  }
  const body = new URLSearchParams({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    scope: 'https://graph.microsoft.com/.default',
    grant_type: 'client_credentials'
  });
  const res = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body
  });
  const data = await res.json();
  if (!data.access_token) {
    throw new Error('Token acquire failed: ' + JSON.stringify(data));
  }
  cachedToken = data.access_token;
  cachedTokenExpiresAt = now + (data.expires_in * 1000);
  return cachedToken;
}

// -----------------------------------------------------------------------------
// Graph HTTP helpers with retry/throttle handling
// -----------------------------------------------------------------------------
class Graph404Error extends Error {
  constructor(url) { super(`Graph 404: ${url}`); this.name = 'Graph404Error'; this.url = url; }
}

async function graphFetch(url, options = {}, retries = 5) {
  const token = await getAccessToken();
  const res = await fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      Authorization: 'Bearer ' + token,
      Accept: 'application/json'
    }
  });
  graphCallCount++;

  if (res.status === 429 || res.status === 503) {
    if (retries <= 0) throw new Error(`Graph ${res.status} after retries: ${url}`);
    const retryAfter = parseInt(res.headers.get('retry-after') || '10', 10);
    await sleep(retryAfter * 1000);
    return graphFetch(url, options, retries - 1);
  }

  if (res.status === 401) {
    cachedToken = null;  // token expired unexpectedly - clear cache and retry once
    if (retries > 0) return graphFetch(url, options, retries - 1);
  }

  if (res.status === 404) throw new Graph404Error(url);

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Graph ${res.status}: ${url} - ${text.slice(0, 300)}`);
  }

  if (res.status === 204) return null;
  return res.json();
}

async function graphFetchAllPages(url) {
  const all = [];
  let nextUrl = url;
  let safetyCap = 200;  // never loop forever - 200 pages x 999 = 199,800 records max
  while (nextUrl && safetyCap-- > 0) {
    const page = await graphFetch(nextUrl);
    if (Array.isArray(page.value)) all.push(...page.value);
    nextUrl = page['@odata.nextLink'] || null;
  }
  return all;
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function callCount() { return graphCallCount; }

// Concurrency-limited parallel processor (same shape as entra-sync.js)
async function parallelLimit(items, limit, worker) {
  const results = [];
  let i = 0;
  const runNext = async () => {
    const idx = i++;
    if (idx >= items.length) return;
    results[idx] = await worker(items[idx], idx);
  };
  const starters = Array(Math.min(limit, items.length)).fill(0).map(async () => {
    while (i < items.length) await runNext();
  });
  await Promise.all(starters);
  return results;
}

// -----------------------------------------------------------------------------
// Group membership (transitive - nested groups count)
// -----------------------------------------------------------------------------
async function getGroupMembers(groupId, select = USER_SELECT) {
  const url = `${GRAPH_BASE}/groups/${groupId}/transitiveMembers/microsoft.graph.user`
            + `?$select=${select}&$top=999`;
  return graphFetchAllPages(url);
}

// -----------------------------------------------------------------------------
// Roster construction
// -----------------------------------------------------------------------------

// A mailbox belongs in the address book if it is a real, enabled, licensed
// person who has not been hidden from the GAL in Exchange. Returns null when
// the person is publishable, otherwise a short reason the console can show -
// "why is X not in the directory?" must have an answer, not a shrug.
function publishReason(u) {
  if (!u.mail) return 'no mailbox';
  if (u.accountEnabled === false) return 'account disabled';
  if (u.userType && u.userType !== 'Member') return 'guest account';
  if (u.showInAddressList === false) return 'hidden from the Exchange address book';
  if (REQUIRE_LICENSE && !(u.assignedLicenses || []).length) return 'no licence (shared mailbox, room or service account)';
  if (EXCLUDE_REGEX && EXCLUDE_REGEX.test(u.mail)) return 'matches the service-account pattern';
  return null;
}
function shouldPublish(u) { return publishReason(u) === null; }

// Only the fields we actually publish feed the hash, so unrelated directory
// churn (licence changes, sign-in activity) never re-pushes to 250 phones.
function entryHash(e) {
  const material = [
    e.displayName, e.givenName, e.surname, e.jobTitle, e.department,
    e.companyName, e.officeLocation, e.mail,
    (e.businessPhones || []).join('|'), e.mobilePhone,
    e.street, e.city, e.state, e.postalCode, e.country
  ].map(v => (v == null ? '' : String(v))).join('');
  return crypto.createHash('sha1').update(material).digest('hex').slice(0, 16);
}

// Entra stores numbers however HR typed them ("347 585 2270"). iOS caller-ID
// matching is most reliable against E.164, so normalize obvious US numbers and
// leave anything else (international, extensions) untouched.
function normPhone(p) {
  if (!p) return p;
  const d = String(p).replace(/[^\d+]/g, '');
  if (d.startsWith('+'))      return d;
  if (/^1\d{10}$/.test(d))    return '+' + d;
  if (/^\d{10}$/.test(d))     return '+1' + d;
  return String(p).trim();
}

function toEntry(u) {
  const e = {
    id:             u.id,
    upn:            u.userPrincipalName,
    mail:           u.mail,
    displayName:    u.displayName || u.mail,
    givenName:      u.givenName || null,
    surname:        u.surname || null,
    jobTitle:       u.jobTitle || null,
    department:     u.department || null,
    companyName:    u.companyName || null,
    officeLocation: u.officeLocation || null,
    businessPhones: Array.isArray(u.businessPhones) ? u.businessPhones.filter(Boolean).map(normPhone) : [],
    mobilePhone:    normPhone(u.mobilePhone) || null,
    street:         u.streetAddress || null,
    city:           u.city || null,
    state:          u.state || null,
    postalCode:     u.postalCode || null,
    country:        u.country || null
  };
  e.hash = entryHash(e);
  return e;
}

// showInAddressList is documented on the v1.0 user resource but is not
// selectable in every tenant shape; a 400 there would kill the whole run, so
// fall back to the select list without it rather than failing closed.
async function fetchDirectoryUsers() {
  if (SOURCE_GROUP) {
    try {
      return await getGroupMembers(SOURCE_GROUP, USER_SELECT + ',showInAddressList');
    } catch (err) {
      if (!/Graph 400/.test(err.message)) throw err;
      console.warn('[gal] showInAddressList not selectable - continuing without it');
      return getGroupMembers(SOURCE_GROUP);
    }
  }

  const base = `${GRAPH_BASE}/users?$top=999&$select=`;
  try {
    return await graphFetchAllPages(base + USER_SELECT + ',showInAddressList');
  } catch (err) {
    if (!/Graph 400/.test(err.message)) throw err;
    console.warn('[gal] showInAddressList not selectable - continuing without it');
    return graphFetchAllPages(base + USER_SELECT);
  }
}

// What the last buildRoster() saw, one row per fetched account - published or
// not, and why not. Never carries a phone number: the console is a control
// plane, not a phone book, and the numbers being hidden must not leak there.
let lastBuild = null;
function lastBuildInfo() { return lastBuild; }

function auditRow(u, published, reason, rule, entry) {
  const row = {
    id: u.id, upn: u.userPrincipalName, mail: u.mail || null,
    name: u.displayName || u.mail || u.userPrincipalName,
    published, reason: reason || null, exclusion: rule ? rule.mode : null
  };
  // Detail columns for anyone we built a card for - published, or held back
  // only by policy - so the console can show what a policy switch affects.
  if (entry) {
    const hadMobile = !!u.mobilePhone;
    const hadDesk   = Array.isArray(u.businessPhones) && u.businessPhones.some(Boolean);
    row.title  = u.jobTitle || null;
    row.dept   = u.department || null;
    row.office = u.officeLocation || null;
    row.mobile = !hadMobile ? 'none' : (entry.mobilePhone ? 'yes' : 'hidden');
    row.desk   = !hadDesk   ? 'none' : (entry.businessPhones.length ? 'yes' : 'hidden');
  }
  return row;
}

async function buildRoster() {
  // Read the exclusions BEFORE the Graph fetch: a malformed file fails the run
  // here, at zero cost, rather than after two minutes of paging.
  const exclusions = loadExclusions();
  const users = await fetchDirectoryUsers();

  const policy = exclusions.policy;
  const roster = [], people = [], heldIds = [];   // heldIds: people the console (rule or policy) kept out
  let applied = 0, heldByPolicy = 0;
  for (const u of users) {
    const why  = publishReason(u);
    const rule = exclusions.match(u);
    if (why) { people.push(auditRow(u, false, why, rule)); continue; }
    if (rule && rule.mode === 'hide') {
      applied++;
      heldIds.push(u.id);
      people.push(auditRow(u, false, 'excluded on the console', rule));
      continue;
    }
    const e = toEntry(u);
    // Directory-wide policy: the phones' address book exists for calling
    // people, so the console can say "only people with a mobile number".
    // Judged on what Entra holds (normalised), before any rule strips it, and
    // only for people without a rule of their own - a rule is a deliberate
    // choice to publish that person in a particular shape.
    if (policy.requireMobile && !rule && !e.mobilePhone) {
      heldByPolicy++;
      heldIds.push(u.id);
      people.push(auditRow(u, false, POLICY_REASON.requireMobile, null, e));
      continue;
    }
    if (rule) {
      applied++;
      applyExclusion(e, rule);
      e.hash = entryHash(e);   // the stripped card must hash differently, or no PATCH ever goes out
    }
    roster.push(e);
    people.push(auditRow(u, true, null, rule, e));
  }
  if (exclusions.size) console.log(`[gal] exclusions: ${exclusions.size} rule(s), ${applied} matched a fetched account`);
  if (policy.requireMobile) console.log(`[gal] policy: only people with a mobile number - ${heldByPolicy} held back`);

  lastBuild = {
    fetchedAt: new Date().toISOString(),
    fetched: users.length, published: roster.length,
    exclusionRules: exclusions.size, exclusionsApplied: applied,
    policy: { ...policy }, heldByPolicy, heldIds,
    people
  };

  // Stable ordering keeps dry-run diffs readable between runs.
  roster.sort((a, b) => a.displayName.localeCompare(b.displayName));

  if (roster.length < MIN_ROSTER) {
    throw new Error(
      `Roster guard tripped: ${roster.length} publishable users, minimum is ${MIN_ROSTER}. ` +
      'Refusing to continue - a run this small would strip contacts off every phone. ' +
      'Raise GAL_MIN_ROSTER only if the org really is this size.'
    );
  }
  return roster;
}

module.exports = {
  GRAPH_BASE,
  getAccessToken, graphFetch, graphFetchAllPages, Graph404Error,
  parallelLimit, sleep, callCount,
  buildRoster, getGroupMembers, entryHash, lastBuildInfo, publishReason
};
