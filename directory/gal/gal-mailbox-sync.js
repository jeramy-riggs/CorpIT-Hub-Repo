// =============================================================================
// gal-mailbox-sync.js - push directory address lists into Exchange mailboxes
// via Microsoft Graph, so iPhones sync them natively and inbound calls get
// caller ID. Multi-list: /var/lib/gal-directory/lists.json defines what gets
// published to whom (see gal-lists.js for the shape and the rules).
//
// Writes to the DEFAULT Contacts folder on purpose: iOS does not sync Exchange
// contact SUBfolders. Every contact this job creates is stamped with a
// single-value extended property carrying the LIST ID; the job only ever
// touches contacts carrying that stamp, so personal contacts are never read
// for content, modified, or deleted. Legacy stamps (pre-lists, 3-part) are
// treated as belonging to the list id "company".
//
// Usage:
//   node gal-mailbox-sync.js                          # dry run, prints the plan
//   node gal-mailbox-sync.js --only=user@x.com --apply
//   node gal-mailbox-sync.js --apply                  # full run
//
// Flags:
//   --apply           actually write. Without it nothing is modified.
//   --only=a,b        limit to these recipient UPNs. Comma separated.
//   --max-deletes=N   abort before writing if the plan deletes more than N
//                     contacts across the whole run (default 500). Removals
//                     of people the console holds back (a rule, or the
//                     "only people with a mobile" policy) do not count: they
//                     are the job doing as asked, not the roster collapsing.
//   --verbose         per-contact detail instead of per-mailbox totals.
//   --purge           rollback: remove every contact this job owns and stop.
//                     Pair with a raised --max-deletes.
//
// Deps: gal-source.js, gal-lists.js, native fetch (Node 18+)
// =============================================================================

// dotenv is a convenience, not a requirement. On a box with no node_modules,
// fall back to parsing ./.env directly - same KEY=value semantics as systemd's
// EnvironmentFile, and unlike shell-sourcing it is safe for values containing
// regex metacharacters. Real environment variables always win.
try { require('dotenv').config(); } catch {
  try {
    for (const line of require('fs').readFileSync('.env', 'utf8').split('\n')) {
      const m = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line.trim());
      if (m && !(m[1] in process.env)) process.env[m[1]] = m[2];
    }
  } catch { /* no .env - env supplied by the caller */ }
}

const {
  GRAPH_BASE, graphFetch, graphFetchAllPages, getGroupMembers,
  parallelLimit, sleep, callCount, buildRoster, Graph404Error, lastBuildInfo
} = require('./gal-source');
const { loadLists } = require('./gal-lists');

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------

// The Exchange access-policy fence group. Every recipient must be a member or
// Graph 403s on their mailbox; its members also form the cleanup universe so
// people removed from every list get their directory cards wiped.
const FENCE_GROUP = process.env.GAL_TARGET_GROUP || '';

const CONCURRENCY = parseInt(process.env.GAL_CONCURRENCY || '4', 10);

// The stamp. v2 (4 parts): NRPI-GAL|<listId>|<source object id>|<content hash>
// Legacy v1 (3 parts):     NRPI-GAL|<source object id>|<content hash>
const TAG        = 'NRPI-GAL';
const LEGACY_LIST = 'company';
const PS_PUBLIC  = '{00020329-0000-0000-C000-000000000046}';   // PS_PUBLIC_STRINGS
const EP_ID      = `String ${PS_PUBLIC} Name nrpiGal`;
const EP_EXPAND  = `singleValueExtendedProperties($filter=id eq '${encodeURIComponent(EP_ID)}')`;

// -----------------------------------------------------------------------------
// Args
// -----------------------------------------------------------------------------
const args       = process.argv.slice(2);
const APPLY      = args.includes('--apply');
const VERBOSE    = args.includes('--verbose');
const PURGE      = args.includes('--purge');
const ONLY       = (args.find(a => a.startsWith('--only=')) || '').slice(7)
                     .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
const MAX_DELETES = parseInt((args.find(a => a.startsWith('--max-deletes=')) || '').slice(14) || '500', 10);

// -----------------------------------------------------------------------------
// Graph $batch - 20 sub-requests per call, with per-sub-request throttle retry
// -----------------------------------------------------------------------------
async function runBatch(requests) {
  const out = [];
  for (let i = 0; i < requests.length; i += 20) {
    let pending = requests.slice(i, i + 20).map((r, ix) => ({ id: String(ix), ...r }));
    let attempt = 0;

    while (pending.length && attempt < 5) {
      const res = await graphFetch(`${GRAPH_BASE}/$batch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ requests: pending })
      });

      const retry = [];
      let waitFor = 5;
      for (const r of res.responses || []) {
        if (r.status === 429 || r.status === 503) {
          const ra = parseInt((r.headers && (r.headers['Retry-After'] || r.headers['retry-after'])) || '5', 10);
          waitFor = Math.max(waitFor, ra);
          retry.push(pending.find(p => p.id === r.id));
        } else {
          out.push(r);
        }
      }
      if (!retry.length) break;
      await sleep(waitFor * 1000);
      pending = retry.filter(Boolean);
      attempt++;
    }

    if (pending.length && attempt >= 5) {
      throw new Error(`$batch still throttled after ${attempt} attempts (${pending.length} sub-requests)`);
    }
  }
  return out;
}

// -----------------------------------------------------------------------------
// Read back only the contacts this job owns. Returns Map key "listId|srcId".
// -----------------------------------------------------------------------------
async function listOwnedContacts(userId) {
  const url = `${GRAPH_BASE}/users/${encodeURIComponent(userId)}/contacts`
            + `?$top=100&$select=id,displayName&$expand=${EP_EXPAND}`;
  const contacts = await graphFetchAllPages(url);

  const owned = new Map();
  for (const c of contacts) {
    const props = c.singleValueExtendedProperties || [];
    const stamp = props.find(p => p.id && p.id.endsWith('Name nrpiGal'));
    if (!stamp || !stamp.value) continue;

    const parts = String(stamp.value).split('|');
    if (parts[0] !== TAG) continue;

    let listId, srcId, hash;
    if (parts.length >= 4)      [, listId, srcId, hash] = parts;   // v2
    else if (parts.length === 3) { listId = LEGACY_LIST; [, srcId, hash] = parts; }  // v1
    else continue;

    if (!srcId) continue;
    owned.set(`${listId}|${srcId}`, { contactId: c.id, listId, srcId, hash: hash || '', displayName: c.displayName });
  }
  return owned;
}

// -----------------------------------------------------------------------------
// Roster entry -> Graph contact body (stamped with the list id)
// -----------------------------------------------------------------------------
function contactBody(e, list) {
  const body = {
    givenName:      e.givenName,
    surname:        e.surname,
    displayName:    e.displayName,
    fileAs:         e.displayName,
    companyName:    e.companyName,
    jobTitle:       e.jobTitle,
    department:     e.department,
    officeLocation: e.officeLocation,
    emailAddresses: e.mail ? [{ address: e.mail, name: e.displayName }] : [],
    businessPhones: e.businessPhones.slice(0, 2),   // Graph caps businessPhones at 2
    mobilePhone:    e.mobilePhone,
    categories:     [list.category],
    singleValueExtendedProperties: [
      { id: EP_ID, value: `${TAG}|${list.id}|${e.id}|${e.hash}` }
    ]
  };

  if (e.street || e.city || e.state || e.postalCode || e.country) {
    body.businessAddress = {
      street:          e.street || '',
      city:            e.city || '',
      state:           e.state || '',
      postalCode:      e.postalCode || '',
      countryOrRegion: e.country || ''
    };
  }
  return body;
}

// -----------------------------------------------------------------------------
// Per-list roster selection out of the full-GAL roster
// -----------------------------------------------------------------------------
async function selectRoster(list, fullRoster, fullById) {
  if (list.source.type === 'all') return fullRoster;

  if (list.source.type === 'upns') {
    const want = new Set(list.source.upns.map(u => u.toLowerCase()));
    return fullRoster.filter(e =>
      want.has((e.upn || '').toLowerCase()) || want.has((e.mail || '').toLowerCase()));
  }

  // group: transitive membership, then keep only publishable people
  const members = await getGroupMembers(list.source.group, 'id');
  const ids = new Set(members.map(m => m.id));
  return fullRoster.filter(e => ids.has(e.id));
}

// -----------------------------------------------------------------------------
// Recipient resolution (recipients live in lists.json as UPNs)
// -----------------------------------------------------------------------------
async function resolveRecipient(upn, cache) {
  const key = upn.toLowerCase();
  if (cache.has(key)) return cache.get(key);
  let rec;
  try {
    const u = await graphFetch(`${GRAPH_BASE}/users/${encodeURIComponent(upn)}`
      + `?$select=id,displayName,mail,userPrincipalName,accountEnabled`);
    rec = (u.accountEnabled === false)
      ? { upn, error: 'account disabled' }
      : { upn: u.userPrincipalName, id: u.id, mail: u.mail, name: u.displayName };
  } catch (err) {
    rec = { upn, error: err instanceof Graph404Error ? 'no such user' : err.message.slice(0, 120) };
  }
  cache.set(key, rec);
  return rec;
}

// -----------------------------------------------------------------------------
// Plan one mailbox across every list that targets it
// -----------------------------------------------------------------------------
function planMailboxLists(target, listsForBox, rosterByList) {
  const desired = new Map();   // "listId|srcId" -> { entry, list }
  const claimed = new Set();   // srcId -> already published to this box by an earlier list

  for (const list of listsForBox) {
    for (const e of rosterByList.get(list.id)) {
      if (e.id === target.id) continue;          // a person's own card is noise
      if (claimed.has(e.id)) continue;           // first list wins, no duplicates
      claimed.add(e.id);
      desired.set(`${list.id}|${e.id}`, { entry: e, list });
    }
  }
  return desired;
}

function diffMailbox(owned, desired) {
  const creates = [], updates = [], deletes = [];
  for (const [key, d] of desired) {
    const have = owned.get(key);
    if (!have)                        creates.push(d);
    else if (have.hash !== d.entry.hash) updates.push({ ...d, contactId: have.contactId });
  }
  for (const [key, rec] of owned) {
    if (!desired.has(key)) deletes.push(rec);
  }
  return { creates, updates, deletes };
}

// -----------------------------------------------------------------------------
// Apply one mailbox plan
// -----------------------------------------------------------------------------
async function applyMailbox(userId, plan) {
  const uid = encodeURIComponent(userId);
  const requests = [];

  for (const d of plan.creates) {
    requests.push({
      method: 'POST',
      url: `/users/${uid}/contacts`,
      headers: { 'Content-Type': 'application/json' },
      body: contactBody(d.entry, d.list)
    });
  }
  for (const u of plan.updates) {
    requests.push({
      method: 'PATCH',
      url: `/users/${uid}/contacts/${u.contactId}`,
      headers: { 'Content-Type': 'application/json' },
      body: contactBody(u.entry, u.list)
    });
  }
  for (const d of plan.deletes) {
    requests.push({ method: 'DELETE', url: `/users/${uid}/contacts/${d.contactId}` });
  }

  if (!requests.length) return { ok: 0, failed: [] };

  const responses = await runBatch(requests);
  const failed = responses.filter(r => r.status >= 400);
  return { ok: responses.length - failed.length, failed };
}

// -----------------------------------------------------------------------------
// Run state for the console page
// -----------------------------------------------------------------------------
// PATH-RELEASE-20260929: state dir via gal-paths.js; the per-file env overrides still win.
const galPaths     = require('./gal-paths');
const STATE_JSON   = galPaths.stateFile('state.json', 'GAL_STATE_JSON');
const HISTORY_JSON = galPaths.stateFile('history.jsonl', 'GAL_HISTORY_JSON');
const ROSTER_JSON  = galPaths.stateFile('roster.json', 'GAL_ROSTER_JSON');

// Who was published, who was not and why, and which lists carry each person.
// This is what the console's "Who is published" view reads. Written on dry
// runs too - the picture is the same, only the mailboxes differ. Carries no
// phone numbers (see gal-source auditRow).
function writeRosterSnapshot(mode, rosterByList) {
  const info = lastBuildInfo();
  if (!info) return;
  const listsFor = new Map();
  for (const [lid, r] of rosterByList) {
    for (const e of r) {
      if (!listsFor.has(e.id)) listsFor.set(e.id, []);
      listsFor.get(e.id).push(lid);
    }
  }
  const people = info.people.map(p => (p.published ? { ...p, lists: listsFor.get(p.id) || [] } : p));
  try {
    const fs = require('fs');
    const tmp = ROSTER_JSON + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify({
      generatedAt: info.fetchedAt, mode,
      fetched: info.fetched, published: info.published,
      exclusionRules: info.exclusionRules, exclusionsApplied: info.exclusionsApplied,
      policy: info.policy || {}, heldByPolicy: info.heldByPolicy || 0,
      lists: [...rosterByList.keys()],
      people
    }));
    fs.renameSync(tmp, ROSTER_JSON);
  } catch (err) {
    console.warn('[gal] could not write roster snapshot: ' + err.message);
  }
}

function writeState(state) {
  try {
    require('fs').writeFileSync(STATE_JSON, JSON.stringify(state, null, 1));
  } catch (err) {
    console.warn('[gal] could not write state file: ' + err.message);
  }
  // One summary line per run, capped, so the console can show sync history.
  try {
    const fs = require('fs');
    const t = state.targets || [];
    const line = JSON.stringify({
      startedAt: state.startedAt, finishedAt: state.finishedAt, mode: state.mode,
      rosterCount: state.rosterCount, opsOk: state.opsOk, opsFailed: state.opsFailed,
      mailboxes: t.length,
      creates: t.reduce((a, x) => a + (x.creates || 0), 0),
      updates: t.reduce((a, x) => a + (x.updates || 0), 0),
      deletes: t.reduce((a, x) => a + (x.deletes || 0), 0),
      errors: t.filter(x => x.error).length,
      lists: (state.lists || []).length,
      exclusionsApplied: state.exclusionsApplied ?? null,
      heldByPolicy: state.heldByPolicy ?? null
    });
    let lines = [];
    try { lines = fs.readFileSync(HISTORY_JSON, 'utf8').split('\n').filter(Boolean); } catch { /* first run */ }
    lines.push(line);
    fs.writeFileSync(HISTORY_JSON, lines.slice(-200).join('\n') + '\n');
  } catch (err) {
    console.warn('[gal] could not append history: ' + err.message);
  }
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------
async function main() {
  const started = Date.now();
  console.log(`[gal] ${new Date().toISOString()} mode=${APPLY ? 'APPLY' : 'DRY-RUN'}${PURGE ? ' PURGE' : ''}`);

  if (!FENCE_GROUP) {
    throw new Error('GAL_TARGET_GROUP (the fence group) is not set. Refusing to run.');
  }

  const lists = PURGE ? [] : loadLists().filter(l => l.enabled);
  const listErrors = [];

  // --purge plans against zero lists: every owned card everywhere is an orphan.
  const fullRoster = PURGE ? [] : await buildRoster();
  const fullById = new Map(fullRoster.map(e => [e.id, e]));
  if (!PURGE) console.log(`[gal] full roster: ${fullRoster.length} publishable people`);

  const rosterByList = new Map();
  for (const list of lists) {
    try {
      const r = await selectRoster(list, fullRoster, fullById);
      if (!r.length) {
        // A list resolving to nobody is a config accident until proven
        // otherwise - skip it rather than delete its cards everywhere.
        listErrors.push({ id: list.id, error: 'source resolves to 0 people - list SKIPPED, nothing deleted' });
        continue;
      }
      rosterByList.set(list.id, r);
      console.log(`[gal] list "${list.id}": ${r.length} people -> ${list.recipients.length} recipients`);
    } catch (err) {
      listErrors.push({ id: list.id, error: err.message.slice(0, 160) });
    }
  }
  const activeLists = lists.filter(l => rosterByList.has(l.id));
  if (!PURGE) writeRosterSnapshot(APPLY ? 'apply' : 'dry-run', rosterByList);

  // ---- Recipient universe: everyone in any list, plus fence members (cleanup)
  const fence = await getGroupMembers(FENCE_GROUP, 'id,userPrincipalName,mail,accountEnabled');
  const fenceByUpn = new Map(fence.map(f => [(f.userPrincipalName || '').toLowerCase(), f]));

  const rcache = new Map();
  const boxes = new Map();   // id -> { target:{id,upn,mail,name}, lists:[], fenceOnly, error }

  for (const list of activeLists) {
    for (const upn of list.recipients) {
      const rec = await resolveRecipient(upn, rcache);
      if (rec.error) {
        listErrors.push({ id: list.id, error: `recipient ${upn}: ${rec.error}` });
        continue;
      }
      if (!boxes.has(rec.id)) {
        const inFence = fenceByUpn.has((rec.upn || '').toLowerCase());
        boxes.set(rec.id, { target: rec, lists: [], fenceOnly: false,
          error: inFence ? null : 'not in GAL-Sync-Targets (fence) - add them there or writes will 403' });
      }
      boxes.get(rec.id).lists.push(list);
    }
  }
  for (const f of fence) {
    if (f.accountEnabled === false || !f.mail) continue;
    if (!boxes.has(f.id)) {
      boxes.set(f.id, {
        target: { id: f.id, upn: f.userPrincipalName, mail: f.mail, name: f.userPrincipalName },
        lists: [], fenceOnly: true, error: null
      });
    }
  }

  let targets = [...boxes.values()];
  if (ONLY.length) {
    targets = targets.filter(b => ONLY.includes((b.target.upn || '').toLowerCase()) ||
                                  ONLY.includes((b.target.mail || '').toLowerCase()));
    if (!targets.length) throw new Error(`--only matched nobody: ${ONLY.join(',')}`);
  }
  console.log(`[gal] mailboxes: ${targets.length} (${targets.filter(b => b.fenceOnly).length} cleanup-only)`);
  for (const le of listErrors) console.warn(`[gal] list "${le.id}": ${le.error}`);

  // ---- Plan every mailbox first, so the delete guard sees the whole picture --
  const plans = [];
  const planErrors = [];
  await parallelLimit(targets, CONCURRENCY, async (box) => {
    try {
      const owned = await listOwnedContacts(box.target.id);
      const desired = planMailboxLists(box.target, box.lists, rosterByList);
      const diff = diffMailbox(owned, desired);
      plans.push({ box, owned: owned.size, ...diff });
    } catch (err) {
      planErrors.push({ upn: box.target.upn, error: err.message.slice(0, 160) });
    }
  });

  const totals = plans.reduce((a, p) => ({
    creates: a.creates + p.creates.length,
    updates: a.updates + p.updates.length,
    deletes: a.deletes + p.deletes.length
  }), { creates: 0, updates: 0, deletes: 0 });

  // The guard exists for one failure: a Graph filter typo or a permissions
  // regression that makes "everyone left" look true. A person held back on
  // the console is a removal somebody asked for, with their name on the page,
  // so those are set aside before the limit is judged. Anyone who never came
  // back from Graph cannot be in the held set - that case still trips it.
  const held = new Set((lastBuildInfo() || {}).heldIds || []);
  const heldDeletes = plans.reduce((a, p) => a + p.deletes.filter(d => held.has(d.srcId)).length, 0);
  const otherDeletes = totals.deletes - heldDeletes;

  console.log(`[gal] plan: +${totals.creates} create  ~${totals.updates} update  ` +
              `-${totals.deletes} delete` + (heldDeletes ? ` (${heldDeletes} held back on the console)` : '') +
              `  across ${plans.length} mailboxes`);

  if (planErrors.length) {
    console.warn(`[gal] ${planErrors.length} mailbox(es) unreadable:`);
    for (const e of planErrors.slice(0, 10)) console.warn(`      ${e.upn}: ${e.error}`);
  }

  if (VERBOSE) {
    for (const p of plans) {
      if (!p.creates.length && !p.updates.length && !p.deletes.length) continue;
      console.log(`  ${p.box.target.upn}: +${p.creates.length} ~${p.updates.length} -${p.deletes.length} (owns ${p.owned})`);
      for (const d of p.deletes) console.log(`      - [${d.listId}] ${d.displayName}`);
    }
  }

  if (otherDeletes > MAX_DELETES) {
    throw new Error(
      `Delete guard tripped: plan removes ${otherDeletes} contacts that nothing on the console ` +
      `accounts for (${heldDeletes} more are people held back there), limit is ${MAX_DELETES}. ` +
      'Nothing was written. Re-run with --verbose to inspect, and only raise ' +
      '--max-deletes once the list looks right.'
    );
  }

  const stateTargets = plans.map(p => ({
    upn: p.box.target.upn,
    mail: p.box.target.mail,
    lists: p.box.lists.map(l => l.id),
    fenceOnly: p.box.fenceOnly,
    owned: p.owned,
    creates: p.creates.length,
    updates: p.updates.length,
    deletes: p.deletes.length,
    error: p.box.error
  })).concat(planErrors.map(e => ({
    upn: e.upn, mail: null, lists: [], fenceOnly: false, owned: null,
    creates: null, updates: null, deletes: null, error: e.error
  })));

  const build = lastBuildInfo() || {};
  const stateBase = {
    startedAt: new Date(started).toISOString(),
    rosterCount: fullRoster.length,
    fetchedCount: build.fetched ?? null,
    exclusionRules: build.exclusionRules ?? null,
    exclusionsApplied: build.exclusionsApplied ?? null,
    policy: build.policy || {},
    heldByPolicy: build.heldByPolicy ?? null,
    lists: lists.map(l => ({
      id: l.id, name: l.name, enabled: l.enabled,
      rosterCount: (rosterByList.get(l.id) || []).length,
      recipients: l.recipients.length,
      error: (listErrors.find(le => le.id === l.id) || {}).error || null
    })),
    targets: stateTargets
  };

  if (!APPLY) {
    console.log('[gal] dry run - nothing written. Re-run with --apply to commit.');
    console.log(`[gal] done in ${Math.round((Date.now() - started) / 1000)}s, ${callCount()} Graph calls`);
    writeState({ ...stateBase, finishedAt: new Date().toISOString(), mode: 'dry-run', opsOk: 0, opsFailed: 0 });
    return;
  }

  // ---- Apply ---------------------------------------------------------------
  let ok = 0;
  const failures = [];
  await parallelLimit(plans, CONCURRENCY, async (p) => {
    try {
      const r = await applyMailbox(p.box.target.id, p);
      ok += r.ok;
      for (const f of r.failed) {
        failures.push({ upn: p.box.target.upn, status: f.status,
                        error: JSON.stringify(f.body && f.body.error || f.body).slice(0, 200) });
      }
    } catch (err) {
      failures.push({ upn: p.box.target.upn, status: 'exception', error: err.message.slice(0, 200) });
    }
  });

  console.log(`[gal] applied: ${ok} operations succeeded, ${failures.length} failed`);
  for (const f of failures.slice(0, 20)) console.error(`      ${f.upn} [${f.status}] ${f.error}`);
  console.log(`[gal] done in ${Math.round((Date.now() - started) / 1000)}s, ${callCount()} Graph calls`);

  for (const f of failures) {
    const t = stateTargets.find(s => s.upn === f.upn);
    if (t && !t.error) t.error = `[${f.status}] ${f.error}`;
  }
  writeState({ ...stateBase, finishedAt: new Date().toISOString(),
               mode: PURGE ? 'purge' : 'apply', opsOk: ok, opsFailed: failures.length });

  if (failures.length) process.exitCode = 1;
}

main().catch(err => {
  console.error('[gal] FATAL:', err.message);
  process.exit(1);
});
