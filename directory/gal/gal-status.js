// =============================================================================
// gal-status.js - one-shot JSON status for the Directory Sync console page.
//
// Merges lists.json (the config), the last run snapshot (state.json), the run
// history (history.jsonl), and live fence membership. Emits per-LIST health
// rollups and full per-MEMBER detail so the dashboard can drill both ways.
// Read-only; no writes anywhere.
// =============================================================================

try { require('dotenv').config(); } catch {
  try {
    for (const line of require('fs').readFileSync('.env', 'utf8').split('\n')) {
      const m = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line.trim());
      if (m && !(m[1] in process.env)) process.env[m[1]] = m[2];
    }
  } catch { /* env supplied by the caller */ }
}

const { getGroupMembers } = require('./gal-source');
const { loadLists } = require('./gal-lists');
const { loadExclusions, POLICY_REASON, EXCLUSIONS_JSON } = require('./gal-exclusions');

const FENCE_GROUP  = process.env.GAL_TARGET_GROUP || '';
// PATH-RELEASE-20260929: state dir via gal-paths.js; the per-file env overrides still win.
const galPaths     = require('./gal-paths');
const STATE_JSON   = galPaths.stateFile('state.json', 'GAL_STATE_JSON');
const HISTORY_JSON = galPaths.stateFile('history.jsonl', 'GAL_HISTORY_JSON');
const ROSTER_JSON  = galPaths.stateFile('roster.json', 'GAL_ROSTER_JSON');

// The exclusion rules, each with what the last sync actually did about it.
// "pending" is normal for the minute after a rule is added; "unmatched" means
// no account with that address came back from Entra - almost always a typo.
function exclusionReport(snapshot) {
  let ex;
  try { ex = loadExclusions(); } catch (err) {
    return { ok: false, error: err.message.slice(0, 300), rules: [], counts: { total: 0, pending: 0, unmatched: 0, applied: 0 },
             policy: null, policyStatus: 'unknown', policyChanged: null };
  }
  // The directory-wide switches: what the file says now, and whether the last
  // run already ran under it. policyChanged is written by the console beside
  // the policy (who flipped it, when) and is what makes "pending" measurable.
  const snapPolicy = (snapshot && snapshot.policy) || {};
  const policyStatus = !snapshot ? 'pending'
    : (Object.keys(ex.policy).every(k => !!snapPolicy[k] === !!ex.policy[k]) ? 'applied' : 'pending');
  let policyChanged = null;
  try {
    const doc = JSON.parse(require('fs').readFileSync(EXCLUSIONS_JSON, 'utf8'));
    if (doc && doc.policyChanged && typeof doc.policyChanged === 'object') policyChanged = { by: doc.policyChanged.by || null, at: doc.policyChanged.at || null };
  } catch { /* missing file = never changed */ }
  const rows = (snapshot && snapshot.people) || [];
  const byId = new Map(), byAddr = new Map();
  for (const r of rows) {
    if (r.id) byId.set(String(r.id).toLowerCase(), r);
    if (r.upn) byAddr.set(String(r.upn).toLowerCase(), r);
    if (r.mail) byAddr.set(String(r.mail).toLowerCase(), r);
  }
  const counts = { total: ex.rules.length, pending: 0, unmatched: 0, applied: 0 };
  const rules = ex.rules.map(rule => {
    const row = (rule.id && byId.get(String(rule.id).toLowerCase())) || byAddr.get(String(rule.upn).toLowerCase()) || null;
    let status;
    if (!snapshot || (rule.at && snapshot.generatedAt && rule.at > snapshot.generatedAt)) status = 'pending';
    else if (!row) status = 'unmatched';
    else if (row.exclusion) status = 'applied';
    else status = 'pending';
    counts[status]++;
    return {
      ...rule, status,
      name: row ? row.name : null,
      effective: row ? row.exclusion : null,
      // "excluded" is moot for someone the policy filters out anyway - say so
      notPublishedAnyway: row && !row.published && row.reason && row.reason !== 'excluded on the console' ? row.reason : null
    };
  });
  return { ok: true, rules, counts, policy: ex.policy, policyStatus, policyChanged };
}

function rosterSummary(snapshot) {
  if (!snapshot) return null;
  const byReason = {};
  // People with a card but no mobile number: published as such today, or held
  // back by the requireMobile policy. Either way it is the group that switch moves.
  let withoutMobile = 0;
  for (const p of snapshot.people || []) {
    if (p.mobile === 'none' && (p.published || p.reason === POLICY_REASON.requireMobile)) withoutMobile++;
    if (p.published) continue;
    byReason[p.reason || 'unknown'] = (byReason[p.reason || 'unknown'] || 0) + 1;
  }
  return {
    generatedAt: snapshot.generatedAt, mode: snapshot.mode,
    fetched: snapshot.fetched, published: snapshot.published,
    notPublished: (snapshot.fetched || 0) - (snapshot.published || 0),
    exclusionsApplied: snapshot.exclusionsApplied, byReason,
    policy: snapshot.policy || {}, heldByPolicy: snapshot.heldByPolicy || 0, withoutMobile
  };
}

(async () => {
  const fs = require('fs');
  let state = null;
  try { state = JSON.parse(fs.readFileSync(STATE_JSON, 'utf8')); } catch { /* no run yet */ }

  let snapshot = null;
  try { snapshot = JSON.parse(fs.readFileSync(ROSTER_JSON, 'utf8')); } catch { /* no snapshot yet */ }

  let history = [];
  try {
    history = fs.readFileSync(HISTORY_JSON, 'utf8').split('\n').filter(Boolean)
      .map(l => { try { return JSON.parse(l); } catch { return null; } })
      .filter(Boolean).slice(-30).reverse();
  } catch { /* no history yet */ }

  const lists = loadLists();
  const fence = FENCE_GROUP
    ? await getGroupMembers(FENCE_GROUP, 'id,displayName,mail,userPrincipalName,accountEnabled')
    : [];
  const fenceUpns = new Set(fence.map(f => (f.userPrincipalName || '').toLowerCase()));
  const nameByUpn = new Map(fence.map(f => [(f.userPrincipalName || '').toLowerCase(), f.displayName]));

  const stateByUpn = new Map((state && state.targets || []).map(t => [String(t.upn || '').toLowerCase(), t]));
  const stateLists = new Map((state && state.lists || []).map(l => [l.id, l]));

  function memberRow(upn, listIds) {
    const key = upn.toLowerCase();
    const t = stateByUpn.get(key) || null;
    let status, detail = '';
    if (!fenceUpns.has(key)) {
      status = 'error';
      detail = 'not in GAL-Sync-Targets (fence) - writes are refused until added';
    } else if (!t) {
      status = 'pending';
      detail = 'added since the last run - fills on the next sync';
    } else if (t.error) {
      status = 'error';
      detail = /403/.test(t.error)
        ? 'access-policy cache has not caught up yet - retries automatically'
        : t.error;
    } else {
      status = 'synced';
      detail = `${t.owned ?? 0} contacts held`;
    }
    return {
      name: nameByUpn.get(key) || upn,
      upn,
      mail: t ? t.mail : null,
      lists: listIds,
      status, detail,
      inFence: fenceUpns.has(key),
      owned: t ? t.owned : null,
      creates: t ? t.creates : null,
      updates: t ? t.updates : null,
      deletes: t ? t.deletes : null,
      fenceOnly: t ? !!t.fenceOnly : false,
      errorRaw: t && t.error ? t.error : null,
      inLastRun: !!t
    };
  }

  // one row per unique recipient, tagged with every list they receive
  const listByUpn = new Map();
  for (const l of lists.filter(l => l.enabled)) {
    for (const upn of l.recipients) {
      const k = upn.toLowerCase();
      if (!listByUpn.has(k)) listByUpn.set(k, { upn, ids: [] });
      listByUpn.get(k).ids.push(l.id);
    }
  }
  for (const f of fence) {
    const k = (f.userPrincipalName || '').toLowerCase();
    if (!listByUpn.has(k)) listByUpn.set(k, { upn: f.userPrincipalName, ids: [] });
  }

  const members = [...listByUpn.values()]
    .map(x => memberRow(x.upn, x.ids))
    .sort((a, b) => a.name.localeCompare(b.name));
  const byUpn = new Map(members.map(m => [m.upn.toLowerCase(), m]));

  // per-list health rollup across that list's recipients
  const listsOut = lists.map(l => {
    const rows = l.recipients.map(u => byUpn.get(u.toLowerCase())).filter(Boolean);
    const health = { synced: 0, pending: 0, error: 0 };
    for (const r of rows) health[r.status] = (health[r.status] || 0) + 1;
    const st = stateLists.get(l.id) || {};
    return {
      id: l.id, name: l.name, category: l.category, enabled: l.enabled,
      sourceType: l.source.type,
      sourceDetail: l.source.type === 'group' ? l.source.group
                  : l.source.type === 'upns' ? `${l.source.upns.length} hand-picked` : 'everyone',
      recipients: l.recipients.length,
      rosterCount: st.rosterCount ?? null,
      error: st.error || null,
      health
    };
  });

  console.log(JSON.stringify({
    ok: true,
    fenceConfigured: !!FENCE_GROUP,
    fenceCount: fence.length,
    lists: listsOut,
    lastRun: state ? {
      mode: state.mode, startedAt: state.startedAt, finishedAt: state.finishedAt,
      rosterCount: state.rosterCount, opsOk: state.opsOk, opsFailed: state.opsFailed
    } : null,
    history,
    members,
    roster: rosterSummary(snapshot),
    exclusions: exclusionReport(snapshot)
  }));
})().catch(e => {
  console.log(JSON.stringify({ ok: false, error: e.message.slice(0, 300) }));
  process.exit(1);
});
