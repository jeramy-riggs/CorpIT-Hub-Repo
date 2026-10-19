// collect-priv-roles.js — Phase 2.1
// Pulls directory role assignments (active + PIM-eligible if licensed) from
// Graph and upserts into priv_role_assignment. role_template_id/role_name
// come directly from Graph on every run — never hardcoded here — so a
// renamed or new Microsoft role is picked up automatically, not silently
// missed. Group-assigned roles are expanded using entra_group_memberships
// (already collected nightly) rather than an extra Graph call per group.
// Pattern matches collect-defender.js (2026-07-20). ENTRA_* creds, mysql2 pool via env.
require('dotenv').config({ path: __dirname + '/.env' });
const mysql = require('mysql2/promise');

async function getToken() {
  const r = await fetch(`https://login.microsoftonline.com/${process.env.ENTRA_TENANT_ID}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: process.env.ENTRA_CLIENT_ID,
      client_secret: process.env.ENTRA_CLIENT_SECRET,
      scope: 'https://graph.microsoft.com/.default',
      grant_type: 'client_credentials',
    }),
  });
  const j = await r.json();
  if (!j.access_token) throw new Error('token fetch failed: ' + JSON.stringify(j));
  return j.access_token;
}

async function graphAll(url, token, cap = 50) {
  const out = [];
  let next = url, pages = 0;
  while (next && pages < cap) {
    // Accept-Language is not optional here. Node's fetch sends 'Accept-Language: *'
    // by default and roleEligibilityScheduleInstances answers 400
    // CultureNotFoundException ("* is an invalid culture identifier"). With
    // en-US the same call returns 200.
    const r = await fetch(next, {
      headers: { Authorization: 'Bearer ' + token, 'Accept-Language': 'en-US' } });
    if (!r.ok) throw new Error(`Graph ${r.status} on ${next}: ${await r.text()}`);
    const j = await r.json();
    out.push(...(j.value || []));
    next = j['@odata.nextLink'];
    pages++;
  }
  return out;
}

async function main() {
  const token = await getToken();
  const pool = mysql.createPool({
    host: process.env.DB_HOST, user: process.env.DB_USER,
    password: process.env.DB_PASSWORD, database: process.env.DB_NAME,
    waitForConnections: true, connectionLimit: 3,
  });

  // 1) Active role assignments, expanded to include principal + roleDefinition
  const assignments = await graphAll(
    'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal&$top=200',
    token
  );
  // roleDefinition isn't expandable in the same call in all tenants — fetch definitions once, map by id
  const defs = await graphAll('https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$top=200', token);
  const defById = Object.fromEntries(defs.map((d) => [d.id, d]));

  // roleDefinitions does not list every role that has assignments. This tenant
  // returns 145 definitions on one page (no nextLink, so not truncation) yet
  // carries live assignments for AdHoc License Administrator, Email Verified
  // User Creator and Modern Commerce User -- all isBuiltIn, all answering 200
  // when fetched by id. Dropping those assignments hid five grants; fetch the
  // definition on a miss and only skip if that fails too.
  const defMisses = new Map();
  const getDef = async (id) => {
    if (defById[id]) return defById[id];
    if (defMisses.has(id)) return defMisses.get(id);
    let d = null;
    try {
      const r = await fetch(
        `https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/${encodeURIComponent(id)}`,
        { headers: { Authorization: 'Bearer ' + token, 'Accept-Language': 'en-US' } });
      if (r.ok) { d = await r.json(); defById[id] = d; }
      else console.log(`  role definition ${id} not listed and fetch-by-id returned ${r.status}`);
    } catch (e) {
      console.log(`  role definition ${id} not listed and fetch-by-id threw: ${e.message}`);
    }
    defMisses.set(id, d);
    return d;
  };

  // 2) PIM-eligible assignments (only returns data if Entra ID P2 is licensed; empty array otherwise — no error)
  let eligible = [];
  let pimError = null;
  try {
    eligible = await graphAll(
      'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$expand=principal&$top=200',
      token
    );
  } catch (e) {
    // Was: 'PIM eligibility fetch skipped (likely no P2 license)'. That named a
    // cause the code never measured, and it was wrong -- the tenant does have
    // PIM. Report what actually happened; do not infer a licensing state from a
    // failed request.
    pimError = e.message;
    console.log('WARNING: PIM eligibility fetch FAILED (this is not evidence the tenant lacks P2):', e.message);
  }

  // 3) Group memberships already collected nightly — build member lookup for group-type principals
  let groupMembers = [];
  try {
    [groupMembers] = await pool.query(`SELECT group_id, member_id FROM entra_group_memberships`);
  } catch (e) {
    console.log('WARNING: entra_group_memberships query failed (' + e.message + ') — group-assigned roles will NOT be expanded to members this run. Verify column names.');
  }
  const membersByGroup = {};
  for (const row of groupMembers) {
    (membersByGroup[row.group_id] = membersByGroup[row.group_id] || []).push(row.member_id);
  }

  // Run marker read from the DB so it shares collected_at's second precision.
  // A JS Date carries milliseconds, and a row written in the same second would
  // compare as older than the marker and be pruned immediately.
  const [[{ runStart }]] = await pool.query('SELECT NOW() AS runStart');

  let upserts = 0;
  const upsertOne = async (roleTemplateId, roleName, memberId, memberType, assignmentType, viaGroupId, eligibility) => {
    await pool.query(
      `INSERT INTO priv_role_assignment
         (role_template_id, role_name, member_entra_id, member_type, assignment_type, via_group_id, eligibility)
       VALUES (?,?,?,?,?,?,?)
       ON DUPLICATE KEY UPDATE role_name=VALUES(role_name), member_type=VALUES(member_type),
         eligibility=VALUES(eligibility), collected_at=CURRENT_TIMESTAMP`,
      // '' not NULL. A MySQL UNIQUE index treats every NULL as distinct, so a
      // direct (non-group) assignment never matched uq_assignment and ON
      // DUPLICATE KEY never fired -- each run inserted a fresh duplicate rather
      // than refreshing collected_at. On ITAM that is 222 rows standing for 74
      // real assignments after three runs.
      [roleTemplateId, roleName, memberId, memberType, assignmentType, viaGroupId || '', eligibility]
    );
    upserts++;
  };

  // Skips were silent: the run reported "79 active assignments" and wrote 74
  // rows with nothing naming the missing five. A privileged-access report that
  // drops assignments without saying so understates privilege.
  const skipped = [];
  for (const a of assignments) {
    const def = await getDef(a.roleDefinitionId);
    if (!def || !a.principal) {
      skipped.push({ id: a.id, roleDefinitionId: a.roleDefinitionId, principalId: a.principalId,
                     why: !def ? 'role definition unresolvable (not listed, and fetch-by-id failed)' : 'principal not expanded' });
      continue;
    }
    const memberType = a.principal['@odata.type']?.replace('#microsoft.graph.', '') || 'unknown';
    if (memberType === 'group') {
      const members = membersByGroup[a.principalId] || [];
      for (const m of members) await upsertOne(def.templateId, def.displayName, m, 'user', 'group', a.principalId, 'permanent');
      if (!members.length) await upsertOne(def.templateId, def.displayName, a.principalId, 'group', 'direct', null, 'permanent');
    } else {
      await upsertOne(def.templateId, def.displayName, a.principalId, memberType, 'direct', null, 'permanent');
    }
  }

  for (const e of eligible) {
    const def = await getDef(e.roleDefinitionId);
    if (!def || !e.principal) {
      skipped.push({ id: e.id, roleDefinitionId: e.roleDefinitionId, principalId: e.principalId,
                     why: 'eligible: ' + (!def ? 'role definition unresolvable (not listed, and fetch-by-id failed)' : 'principal not expanded') });
      continue;
    }
    const memberType = e.principal['@odata.type']?.replace('#microsoft.graph.', '') || 'unknown';
    await upsertOne(def.templateId, def.displayName, e.principalId, memberType, 'direct', null, 'eligible');
  }

  // Prune assignments Graph no longer returns. Every upsert rewrites
  // collected_at, so a row still carrying a pre-run timestamp is a revoked
  // role. The ITAM copy only ever upserted, so a removed Global Admin stayed
  // in the table indefinitely and /priv-access kept reporting them as
  // privileged. Guarded on a non-empty fetch: a Graph outage that returns
  // zero assignments must not empty the table.
  let pruned = 0;
  if (assignments.length) {
    const [r] = await pool.query('DELETE FROM priv_role_assignment WHERE collected_at < ?', [runStart]);
    pruned = r.affectedRows;
  }

  console.log(`priv-roles: ${assignments.length} active assignments, ${eligible.length} PIM-eligible, `
    + `${upserts} rows upserted, ${pruned} stale rows pruned, ${skipped.length} skipped`);
  for (const sk of skipped) console.log(`  SKIPPED ${sk.id} role=${sk.roleDefinitionId} principal=${sk.principalId} - ${sk.why}`);
  if (pimError) console.log(`  PIM eligibility NOT collected this run: ${pimError}`);
  await pool.end();
}

main().then(() => { console.log('collect-priv-roles OK', new Date().toISOString()); process.exit(0); })
  .catch((e) => { console.error('collect-priv-roles FAILED:', e.message); process.exit(1); });
