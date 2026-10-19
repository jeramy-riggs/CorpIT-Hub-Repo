'use strict';
// =====================================================================
// scope-lib.js — DATA SCOPE resolution.  (2026-09-03)
//
// The platform already answers "may you OPEN this page?" (rbac-middleware,
// rbac_user_page_access). This answers the separate question "how much of the
// data on it may you SEE?" Keeping them apart is deliberate: page access is
// per-page, scope is per-person. Your department is your department on every
// reporting surface, so scope must not be re-answered page by page.
//
// THE LADDER — first match wins, evaluated in this order. An explicit assignment
// is an OVERRIDE and comes first; everything below it is a default.
//
//   1. assigned    An explicit rbac_user_scope row, set in Manage access by a
//                  platform owner and audited. Outranks the AD group so that a
//                  member of it can be narrowed (or anyone widened) without an
//                  AD change. Delete the row to fall back to the default.
//                  This is also where department heads live: HR carries no
//                  head-of-department field, and only 5 of 35 departments have a
//                  single manager, so it cannot be derived.
//   2. org         AD group SaaS-ITH-RPT, via the 'reporting' role.
//                  The only tier that is genuinely a yes/no, so the only one an
//                  AD group can express. Read from rbac_user_roles (written at
//                  sign-in by rbac-ad-resolver) rather than from the session
//                  token: token groups only carry names some SITE policy
//                  references (site-access.js referencedGroups), so a scope-only
//                  group would silently never appear there.
//   3. leader      Appears as somebody's hr_roster.leader_email. 9 people.
//   4. team        Appears as somebody's hr_roster.manager_email. 85 people.
//   5. self        Own activity only. The floor for ~550 of 638 people.
//                  Was 'department' until 2026-09-03; that let any individual
//                  contributor read every colleague's per-person spend just by
//                  holding page access, which is not something anyone had
//                  deliberately granted. Seeing a whole department is now
//                  something you assign, not something you inherit by default.
//   6. unknown     Not in hr_roster. FAILS CLOSED and is reported as its own
//                  state - "we could not determine your scope" must never render
//                  as a department that happens to have spent nothing.
//
// Platform super-admin is deliberately NOT a shortcut to org scope. Administering
// the platform and being entitled to read every employee's spend are different
// claims; if a super-admin needs org-wide data they go in the AD group like
// anyone else.
// =====================================================================

const ORG_ROLE_KEY = 'reporting';

const LABEL = {
  org:        () => 'Org-wide',
  leader:     (v, x) => 'Leader roll-up' + (x && x.leaderName ? ' — ' + x.leaderName : '') + ' (all levels)',
  team:       () => 'Their organisation (all reports, any depth)',
  department: (v, x) => 'Department' + (x && x.departmentName ? ' — ' + x.departmentName : (v ? ' — ' + v : '')),
  self:       () => 'Own activity only',   // the default floor since 2026-09-03
  unknown:    () => 'Undetermined',
};

/**
 * Resolve one person's data scope.
 * @param {object} pool  mysql2/promise pool
 * @param {string} email
 * @returns {Promise<{email,kind,value,source,label,deny,assigned}>}
 */
async function resolveScope(pool, email) {
  const who = String(email || '').trim().toLowerCase();
  if (!who) {
    return { email: who, kind: 'unknown', value: null, source: 'no-identity',
             label: LABEL.unknown(), deny: true, assigned: false };
  }

  // 1. explicit assignment - the OVERRIDE, so it is checked first.
  // This deliberately outranks the AD group. The group answers "should this
  // person see org-wide by default", which is the right question for a group to
  // answer, but it is a yes/no: it cannot say "in the group, but scoped to
  // Finance". Before 2026-09-03 org was checked first, which meant every member
  // of SaaS-CorpITHub-Reporting (now SaaS-ITH-RPT) was unadjustable - the roster in Manage access
  // was the group, so every row rendered read-only and the override existed for
  // nobody. An explicit row is a named, audited decision by a platform owner;
  // deleting it falls straight back to the group.
  const [assignedRows] = await pool.query(
    'SELECT scope_kind, scope_value, granted_by FROM rbac_user_scope WHERE email = ? LIMIT 1',
    [who]
  );
  if (assignedRows.length) {
    const a = assignedRows[0];
    const value = a.scope_kind === 'org' ? null : (a.scope_value || who);
    const extra = await describeValue(pool, a.scope_kind, value);
    return {
      email: who, kind: a.scope_kind, value,
      source: 'assigned', grantedBy: a.granted_by || null,
      label: (LABEL[a.scope_kind] || LABEL.unknown)(value, extra),
      deny: false, assigned: true,
    };
  }

  // 2. org, via AD group membership resolved at sign-in. The default for the
  // group, and what an override reverts to.
  const [roleRows] = await pool.query(
    'SELECT 1 FROM rbac_user_roles WHERE email = ? AND role_key = ? LIMIT 1',
    [who, ORG_ROLE_KEY]
  );
  if (roleRows.length) {
    return { email: who, kind: 'org', value: null, source: 'ad-group',
             label: LABEL.org(), deny: false, assigned: false };
  }

  // 3-5. derived from the roster, in one round trip.
  const [[facts]] = await pool.query(
    `SELECT (SELECT COUNT(*) FROM hr_roster WHERE leader_email  = ?) AS leads,
            (SELECT COUNT(*) FROM hr_roster WHERE manager_email = ?) AS manages,
            (SELECT dept_code  FROM hr_roster WHERE email = ? LIMIT 1) AS dept_code,
            (SELECT department FROM hr_roster WHERE email = ? LIMIT 1) AS department,
            (SELECT leader_name FROM hr_roster WHERE leader_email = ? LIMIT 1) AS leader_name`,
    [who, who, who, who, who]
  );

  if (facts && Number(facts.leads) > 0) {
    return { email: who, kind: 'leader', value: who, source: 'derived-leader',
             label: LABEL.leader(who, { leaderName: facts.leader_name }), deny: false, assigned: false };
  }
  if (facts && Number(facts.manages) > 0) {
    return { email: who, kind: 'team', value: who, source: 'derived-manager',
             label: LABEL.team(), deny: false, assigned: false };
  }
  // On the roster but leading nobody: they see themselves. Department visibility is
  // now granted, never inherited - see the ladder note above.
  if (facts && (facts.dept_code || facts.department)) {
    return { email: who, kind: 'self', value: who, source: 'derived-self',
             label: LABEL.self(), deny: false, assigned: false };
  }

  // 6. not in the roster - fail closed, and say so distinctly.
  return { email: who, kind: 'unknown', value: null, source: 'not-in-roster',
           label: LABEL.unknown(), deny: true, assigned: false };
}

/** Friendly names for an assigned scope, so the UI can render it without a second lookup. */
async function describeValue(pool, kind, value) {
  if (!value) return {};
  if (kind === 'department') {
    const [rows] = await pool.query('SELECT department FROM hr_roster WHERE dept_code = ? LIMIT 1', [value]);
    return { departmentName: rows.length ? rows[0].department : null };
  }
  if (kind === 'leader') {
    const [rows] = await pool.query('SELECT leader_name FROM hr_roster WHERE leader_email = ? LIMIT 1', [value]);
    return { leaderName: rows.length ? rows[0].leader_name : null };
  }
  return {};
}

/**
 * Turn a resolved scope into a SQL predicate against ai_user_org (or any table
 * carrying the same four columns). Returns a fragment plus its params, never an
 * interpolated value - the caller appends it to a parameterised query.
 *
 * 'org' yields an empty fragment (no filter). 'unknown' yields 1=0, so a caller
 * that forgets to check .deny still returns nothing rather than everything.
 */
function scopeWhere(scope, alias = 'o') {
  const a = String(alias).replace(/[^A-Za-z0-9_]/g, '') || 'o';
  switch (scope && scope.kind) {
    case 'org':        return { where: '', params: [] };
    case 'leader':     return { where: `${a}.leader_email = ?`,  params: [scope.value] };
    case 'team':       return { where: `${a}.manager_email = ?`, params: [scope.value] };
    case 'department': return { where: `${a}.dept_code = ?`,     params: [scope.value] };
    case 'self':       return { where: `${a}.email = ?`,         params: [scope.value] };
    default:           return { where: '1=0', params: [] };
  }
}

/* =====================================================================
 * VIEW-AS  (2026-09-03)
 *
 * Borrowing someone else's view, to check what a scope actually renders before
 * handing it to them. Three delegation levels, held in rbac_view_as:
 *
 *   department  may view as anyone in their own department
 *   reports     may view as their own direct or indirect reports
 *   any         may view as anyone
 *
 * THE RULE THAT MAKES THIS SAFE: for 'department' and 'reports', the target's
 * resolved scope must be a SUBSET of the viewer's own. Membership of the allowed
 * set is not sufficient on its own - a department contains its own leader, so
 * "anyone in my department" would otherwise let a self-scoped employee borrow a
 * leader's tree and read the whole division. The subset test is what makes
 * view-as a narrowing operation and never a widening one.
 *
 * 'any' skips the subset test by definition. An org-scoped viewer passes it
 * anyway, since their set contains every other set.
 * ===================================================================== */

async function resolveViewAs(pool, email) {
  const who = String(email || '').trim().toLowerCase();
  if (!who) return null;
  const [rows] = await pool.query('SELECT level, granted_by FROM rbac_view_as WHERE email = ? LIMIT 1', [who]);
  return rows.length ? { level: rows[0].level, grantedBy: rows[0].granted_by } : null;
}

/* TRANSITIVE ROLLUP (fixed 2026-09-03).
 *
 * hr_roster.leader_email and manager_email each name ONE level. Matching them
 * directly - which is what scopeWhere() emits - answers "who reports to you"
 * and not "who is under you", and the difference is not small: Ali Haralson
 * (CEO) has 8 direct leader-reports and 502 people beneath her; 6 direct
 * manager-reports and 496 beneath. An exec looking at a "roll-up of the
 * departments reporting to them" was seeing one slice of one level.
 *
 * So leader and team walk the chain. Depth is capped rather than trusted: a
 * cycle in the roster (A manages B manages A, which a bad HR export can
 * produce) would otherwise spin until MySQL's recursion limit throws, turning
 * a data-quality problem into a 500 on every scoped request.
 */
const CHAIN_MAX_DEPTH = 20;

async function chainEmails(pool, column, rootEmail) {
  const col = column === 'leader_email' ? 'leader_email' : 'manager_email';
  const [rows] = await pool.query(
    `WITH RECURSIVE t (email, depth) AS (
        SELECT LOWER(email), 1 FROM hr_roster WHERE LOWER(${col}) = ?
        UNION
        SELECT LOWER(h.email), t.depth + 1
          FROM hr_roster h JOIN t ON LOWER(h.${col}) = t.email
         WHERE t.depth < ?
     )
     SELECT DISTINCT email FROM t`,
    [String(rootEmail || '').toLowerCase(), CHAIN_MAX_DEPTH]);
  return rows.map((r) => String(r.email || '').toLowerCase());
}

/** The set of member emails a resolved scope can see. null means "everything".
 *  Restricted to people who are actually Claude members (ai_user_org), because
 *  that is the population every consuming query joins against. */
async function scopeEmailSet(pool, scope) {
  if (!scope || scope.kind === 'org') return null;
  if (scope.deny) return new Set();

  if (scope.kind === 'leader' || scope.kind === 'team') {
    const col = scope.kind === 'leader' ? 'leader_email' : 'manager_email';
    const chain = await chainEmails(pool, col, scope.value);
    if (!chain.length) return new Set();
    const [rows] = await pool.query(
      `SELECT o.email FROM ai_user_org o WHERE o.email IN (?)`, [chain]);
    return new Set(rows.map((r) => String(r.email || '').toLowerCase()));
  }

  const sw = scopeWhere(scope, 'o');
  const [rows] = await pool.query(`SELECT o.email FROM ai_user_org o WHERE ${sw.where}`, sw.params);
  return new Set(rows.map((r) => String(r.email || '').toLowerCase()));
}

/* Async predicate for callers that filter in SQL rather than in JS. leader and
 * team resolve to an explicit IN list because their membership needs the chain
 * walk above; everything else keeps the cheap single-column compare.
 * Returns '1=0' when the scope resolves to nobody, never an empty string, so a
 * caller cannot accidentally drop the filter and select the whole table. */
async function scopePredicate(pool, scope, alias = 'o') {
  const a = String(alias).replace(/[^A-Za-z0-9_]/g, '') || 'o';
  if (!scope || scope.kind === 'org') return { where: '', params: [] };
  if (scope.deny) return { where: '1=0', params: [] };
  if (scope.kind === 'leader' || scope.kind === 'team') {
    const col = scope.kind === 'leader' ? 'leader_email' : 'manager_email';
    const chain = await chainEmails(pool, col, scope.value);
    if (!chain.length) return { where: '1=0', params: [] };
    return { where: `${a}.email IN (?)`, params: [chain] };
  }
  return scopeWhere(scope, a);
}

/**
 * May `viewer` borrow `target`'s view?
 * @returns {Promise<{ok:boolean, reason:string, scope?:object, level?:string}>}
 */
async function canViewAs(pool, viewer, target) {
  const v = String(viewer || '').trim().toLowerCase();
  const t = String(target || '').trim().toLowerCase();
  if (!v || !t) return { ok: false, reason: 'missing identity' };
  if (v === t) return { ok: true, reason: 'self', scope: await resolveScope(pool, t), level: 'self' };

  const grant = await resolveViewAs(pool, v);
  if (!grant) return { ok: false, reason: 'view-as is not enabled for you' };

  const targetScope = await resolveScope(pool, t);

  if (grant.level !== 'any') {
    // 1. is the target inside the allowed population?
    let allowedTarget = false;
    if (grant.level === 'department') {
      const [rows] = await pool.query(
        `SELECT 1 FROM hr_roster me JOIN hr_roster them ON them.dept_code = me.dept_code
          WHERE me.email = ? AND them.email = ? LIMIT 1`, [v, t]);
      allowedTarget = rows.length > 0;
      if (!allowedTarget) return { ok: false, reason: 'that person is not in your department' };
    } else if (grant.level === 'reports') {
      const [rows] = await pool.query(
        `SELECT 1 FROM hr_roster WHERE email = ? AND (manager_email = ? OR leader_email = ?) LIMIT 1`,
        [t, v, v]);
      allowedTarget = rows.length > 0;
      if (!allowedTarget) return { ok: false, reason: 'that person does not report to you' };
    }

    // 2. would borrowing their view show you MORE than you already have?
    const mine = await scopeEmailSet(pool, await resolveScope(pool, v));
    const theirs = await scopeEmailSet(pool, targetScope);
    if (mine !== null) {
      if (theirs === null) return { ok: false, reason: 'that view is wider than your own access' };
      for (const e of theirs) {
        if (!mine.has(e)) return { ok: false, reason: 'that view is wider than your own access' };
      }
    }
  }
  return { ok: true, reason: 'granted', scope: targetScope, level: grant.level };
}

/**
 * Scope for one request, honouring ?viewAs= when present and permitted.
 * Returns the scope PLUS a viewingAs marker so a caller can label the screen -
 * an unlabelled borrowed view is how someone reports a bug against data that
 * was never theirs.
 */
async function resolveScopeForRequest(pool, req) {
  const me = (req.user && req.user.email) || '';
  const raw = (req.query && req.query.viewAs) || req.get?.('x-view-as') || '';
  const target = String(raw || '').trim().toLowerCase();
  if (!target || target === String(me).toLowerCase()) {
    return { scope: await resolveScope(pool, me), viewingAs: null };
  }
  const v = await canViewAs(pool, me, target);
  if (!v.ok) return { scope: await resolveScope(pool, me), viewingAs: null, viewAsDenied: v.reason };
  return { scope: v.scope, viewingAs: { email: target, label: v.scope.label, via: v.level } };
}

const SCOPE_KINDS = ['org', 'leader', 'department', 'team', 'self'];

module.exports = { resolveScope, scopeWhere, scopePredicate, chainEmails, SCOPE_KINDS, ORG_ROLE_KEY,
                   resolveViewAs, canViewAs, scopeEmailSet, resolveScopeForRequest };
