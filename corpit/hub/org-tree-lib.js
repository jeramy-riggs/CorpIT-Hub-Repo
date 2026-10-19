'use strict';
// org-tree-lib.js  (v1.0.0)
//
// The reporting hierarchy, taken from Active Directory (Entra `manager_upn` — the
// same "Manager" / "Direct reports" fields the AD Users & Computers Organization
// tab shows) and cached so callers do not walk the tree on every request.
//
// Why AD and not the HR roster: on 2026-09-09 the two agreed on 633 of 633 people
// where both had a value, AD carried 89 distinct managers to HR's 85, and AD is
// re-synced continuously (minutes old) while the HR export is loaded by hand.
// HR is kept only as a fallback for the handful of people AD has no row for.
//
// Cached in three tables (see org-schema.sql):
//   org_reporting_person  one row per person: title, dept, manager, report counts
//   org_reporting_edge    transitive closure, manager -> member with depth
//   org_reporting_sync    last refresh, so staleness is reportable, never guessed
//
// The closure is what makes authorization cheap: "may X see Y" is one indexed
// lookup, and a manager's team is one indexed range scan.

const TTL_MINUTES = 180;          // refresh on read if the cache is older than this
const MAX_DEPTH = 30;             // cycle guard; the real tree is ~8 deep
const SYNC_ROW = 1;

const lc = (v) => (v == null ? '' : String(v).trim().toLowerCase());
const nz = (v) => { const s = v == null ? '' : String(v).trim(); return s === '' ? null : s; };

// A tenant-default *.onmicrosoft.com account is a duplicate of the person's real
// UPN (Samuel Park has both), and a disabled account is not a person to report on.
function isRealAccount(r) {
  const upn = lc(r.user_principal_name);
  if (!upn || upn.indexOf('@') < 0) return false;
  if (upn.endsWith('.onmicrosoft.com')) return false;
  if (Number(r.account_enabled) !== 1) return false;
  return true;
}

// dept_code is the leading token of an AD department string, e.g.
// "REA460 - COH Helpdesk" -> "REA460". HR stores it separately; AD does not.
function deptCodeOf(department) {
  const m = /^\s*([A-Z]{2,4}\d{2,4})\b/.exec(String(department || ''));
  return m ? m[1] : null;
}

async function loadSources(pool) {
  const [entra] = await pool.query(
    `SELECT user_principal_name, display_name, job_title, department, manager_upn, account_enabled, user_type
       FROM entra_users`
  );
  const [hr] = await pool.query(
    `SELECT email, employee_name, title, department, dept_code, manager_email
       FROM hr_roster`
  );
  return { entra, hr };
}

// Build the person map: AD first, HR only for people AD has no usable row for.
function buildPeople(entra, hr) {
  const people = new Map();
  for (const r of entra) {
    if (!isRealAccount(r)) continue;
    const email = lc(r.user_principal_name);
    people.set(email, {
      email,
      displayName: nz(r.display_name),
      jobTitle: nz(r.job_title),
      department: nz(r.department),
      deptCode: deptCodeOf(r.department),
      managerEmail: lc(r.manager_upn) || null,
      source: 'entra',
      inHr: 0,
    });
  }
  for (const r of hr) {
    const email = lc(r.email);
    if (!email) continue;
    const have = people.get(email);
    if (have) {
      have.inHr = 1;
      // AD has no dept_code column; HR's is authoritative when AD's parse missed.
      if (!have.deptCode) have.deptCode = nz(r.dept_code);
      if (!have.department) have.department = nz(r.department);
      if (!have.jobTitle) have.jobTitle = nz(r.title);
      if (!have.managerEmail) have.managerEmail = lc(r.manager_email) || null;
      continue;
    }
    people.set(email, {
      email,
      displayName: nz(r.employee_name),
      jobTitle: nz(r.title),
      department: nz(r.department),
      deptCode: nz(r.dept_code),
      managerEmail: lc(r.manager_email) || null,
      source: 'hr',
      inHr: 1,
    });
  }
  // A manager pointer to somebody we do not carry (a disabled or deleted account)
  // would silently orphan a whole branch, so drop the pointer and record the person
  // as a root rather than pretending the edge exists.
  for (const p of people.values()) {
    if (p.managerEmail && !people.has(p.managerEmail)) p.managerEmail = null;
    if (p.managerEmail === p.email) p.managerEmail = null;
  }
  return people;
}

// Walk up from each person, emitting one edge per ancestor. Depth 1 = direct report.
// A cycle (A manages B manages A) would loop forever, so the walk is depth-capped
// and remembers what it has seen on this path.
function buildEdges(people) {
  const edges = [];
  const cycles = [];
  for (const p of people.values()) {
    const seen = new Set([p.email]);
    let cur = p.managerEmail, depth = 1;
    while (cur && depth <= MAX_DEPTH) {
      if (seen.has(cur)) { cycles.push(p.email + ' -> ' + cur); break; }
      seen.add(cur);
      edges.push([cur, p.email, depth, people.get(p.email).source]);
      const up = people.get(cur);
      cur = up ? up.managerEmail : null;
      depth++;
    }
  }
  return { edges, cycles };
}

function summarise(people, edges) {
  const directs = new Map(), totals = new Map();
  for (const [mgr, , depth] of edges) {
    totals.set(mgr, (totals.get(mgr) || 0) + 1);
    if (depth === 1) directs.set(mgr, (directs.get(mgr) || 0) + 1);
  }
  for (const p of people.values()) {
    p.directReports = directs.get(p.email) || 0;
    p.totalReports = totals.get(p.email) || 0;
  }
  // "Manages managers" is what separates a director from a front-line manager
  // without trusting job-title text, which is free-form and inconsistent.
  for (const p of people.values()) {
    p.managesManagers = 0;
    if (!p.directReports) continue;
    for (const q of people.values()) {
      if (q.managerEmail === p.email && q.directReports > 0) { p.managesManagers = 1; break; }
    }
  }
  // Depth from the top of the tree, for display only.
  for (const p of people.values()) {
    let d = 0, cur = p.managerEmail, guard = new Set([p.email]);
    while (cur && d < MAX_DEPTH && !guard.has(cur)) { guard.add(cur); d++; cur = (people.get(cur) || {}).managerEmail; }
    p.depthFromRoot = d;
  }
  return people;
}

async function replaceAll(pool, people, edges, meta) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    await conn.query('DELETE FROM org_reporting_edge');
    await conn.query('DELETE FROM org_reporting_person');
    const now = meta.now;
    const prows = [...people.values()].map((p) => [
      p.email, p.displayName, p.jobTitle, p.department, p.deptCode, p.managerEmail,
      p.directReports, p.totalReports, p.managesManagers, p.depthFromRoot, p.inHr, p.source, now,
    ]);
    for (let i = 0; i < prows.length; i += 500) {
      await conn.query(
        `INSERT INTO org_reporting_person
           (email, display_name, job_title, department, dept_code, manager_email,
            direct_reports, total_reports, manages_managers, depth_from_root, in_hr, source, refreshed_at)
         VALUES ?`, [prows.slice(i, i + 500)]);
    }
    const erows = edges.map((e) => [e[0], e[1], e[2], e[3], now]);
    for (let i = 0; i < erows.length; i += 1000) {
      await conn.query(
        `INSERT INTO org_reporting_edge (manager_email, member_email, depth, source, refreshed_at)
         VALUES ?`, [erows.slice(i, i + 1000)]);
    }
    await conn.query(
      `INSERT INTO org_reporting_sync (id, started_at, finished_at, status, people, edges, managers, source, error)
       VALUES (?,?,?,?,?,?,?,?,NULL)
       ON DUPLICATE KEY UPDATE started_at=VALUES(started_at), finished_at=VALUES(finished_at),
         status=VALUES(status), people=VALUES(people), edges=VALUES(edges), managers=VALUES(managers),
         source=VALUES(source), error=NULL`,
      [SYNC_ROW, meta.startedAt, now, 'ok', people.size, edges.length, meta.managers, meta.source]);
    await conn.commit();
  } catch (e) {
    try { await conn.rollback(); } catch (e2) {}
    throw e;
  } finally {
    conn.release();
  }
}

let refreshing = null;

async function refresh(pool) {
  // One rebuild at a time: a stampede of readers must not each rebuild the closure.
  if (refreshing) return refreshing;
  refreshing = (async () => {
    const startedAt = new Date();
    try {
      const { entra, hr } = await loadSources(pool);
      const people = buildPeople(entra, hr);
      const { edges, cycles } = buildEdges(people);
      summarise(people, edges);
      const managers = [...people.values()].filter((p) => p.directReports > 0).length;
      await replaceAll(pool, people, edges, {
        now: new Date(), startedAt, managers,
        source: 'entra_users+hr_roster',
      });
      if (cycles.length) console.warn('[org-tree] reporting cycles skipped:', cycles.slice(0, 5).join(', '));
      return { ok: true, people: people.size, edges: edges.length, managers, cycles: cycles.length };
    } catch (e) {
      try {
        await pool.query(
          `INSERT INTO org_reporting_sync (id, started_at, finished_at, status, source, error)
           VALUES (?,?,?,?,?,?)
           ON DUPLICATE KEY UPDATE finished_at=VALUES(finished_at), status=VALUES(status), error=VALUES(error)`,
          [SYNC_ROW, startedAt, new Date(), 'error', 'entra_users+hr_roster', String(e.message).slice(0, 2000)]);
      } catch (e2) {}
      throw e;
    } finally {
      refreshing = null;
    }
  })();
  return refreshing;
}

async function syncState(pool) {
  const [[row]] = await pool.query('SELECT * FROM org_reporting_sync WHERE id=?', [SYNC_ROW]);
  if (!row || !row.finished_at || row.status !== 'ok') {
    return { state: 'never', ageMinutes: null, refreshedAt: null, people: 0, managers: 0, error: row ? row.error : null };
  }
  const ageMinutes = Math.round((Date.now() - new Date(row.finished_at).getTime()) / 60000);
  return {
    state: ageMinutes > TTL_MINUTES ? 'stale' : 'ok',
    ageMinutes, refreshedAt: new Date(row.finished_at).toISOString(),
    people: Number(row.people) || 0, managers: Number(row.managers) || 0, error: row.error || null,
  };
}

// Refresh only when the cache is missing or past its TTL. Callers get the cache
// either way; a failed refresh over a warm cache is logged, not fatal.
async function ensureFresh(pool) {
  const before = await syncState(pool);
  if (before.state === 'ok') return before;
  try {
    await refresh(pool);
  } catch (e) {
    console.warn('[org-tree] refresh failed:', e.message);
    return await syncState(pool);
  }
  return await syncState(pool);
}

async function person(pool, email) {
  const [[row]] = await pool.query('SELECT * FROM org_reporting_person WHERE email=?', [lc(email)]);
  return row || null;
}

// Every person at or below `email`, with the depth that separates them.
async function teamMembers(pool, email, opts) {
  const o = opts || {};
  const params = [lc(email)];
  let sql = `SELECT e.member_email AS email, e.depth, p.display_name, p.job_title,
                    p.department, p.dept_code, p.manager_email
               FROM org_reporting_edge e
               JOIN org_reporting_person p ON p.email = e.member_email
              WHERE e.manager_email = ?`;
  if (o.directOnly) sql += ' AND e.depth = 1';
  sql += ' ORDER BY e.depth, p.display_name';
  const [rows] = await pool.query(sql, params);
  return rows;
}

async function isManagerOf(pool, managerEmail, memberEmail) {
  const [[row]] = await pool.query(
    'SELECT depth FROM org_reporting_edge WHERE manager_email=? AND member_email=? LIMIT 1',
    [lc(managerEmail), lc(memberEmail)]
  );
  return row ? Number(row.depth) : 0;
}

module.exports = {
  refresh, ensureFresh, syncState, person, teamMembers, isManagerOf,
  deptCodeOf, isRealAccount, TTL_MINUTES,
};
