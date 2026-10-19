'use strict';
/**
 * spend-alert-lib.js — pure maths for the Claude spend-limit early warning.
 *
 * No DB, no HTTP, no clock of its own. The route, the digest job and the test all
 * require this, so a number shown on the page, mailed to a manager and written into
 * a ticket cannot disagree with each other.
 *
 * Facts this encodes (the API contract lives in claude-limits.js):
 *  - A limit of null is UNLIMITED. There is no such thing as 75% of unlimited, so
 *    those people are never alerted — treating null as 0 would alert everybody.
 *  - A limit of 0 is "included usage only": already at the cap by definition, and
 *    a percentage of it is a division by zero, not 100%.
 *  - The percentage MUST be Anthropic's own period_to_date_spend over Anthropic's
 *    own amount. `claude_user_cost_daily` is a DIFFERENT basis; a percentage mixing
 *    the two is one neither source would stand behind.
 *  - Projection is only meaningful for the CURRENT month. A finished month has no
 *    remainder to run out of, so past periods never raise an alert.
 */

const THRESHOLD_DEFAULT = 70;      // percent of the monthly limit
const HEADROOM = 0.10;             // recommend 10% above the projected close

/** Percent of the limit consumed, or null when the question has no answer. */
function pctOf(ptdSpend, limit) {
  if (limit == null) return null;                    // unlimited
  const l = Number(limit), p = Number(ptdSpend);
  if (!isFinite(l) || !isFinite(p) || l <= 0) return null;   // 0 = included-only
  return Math.round((p / l) * 1000) / 10;
}

/**
 * Which of the five things is true of this person's limit. Kept as one function so
 * the page, the ticket and the digest cannot classify the same row differently.
 *   no-limit       — unlimited, never alerted
 *   included-only  — a hard 0 cap, at the ceiling by definition
 *   over           — spend has passed the limit
 *   near           — at or past the alert threshold, still under the limit
 *   ok             — below the threshold
 */
function stateFor(ptdSpend, limit, threshold) {
  if (limit == null) return 'no-limit';
  const l = Number(limit);
  if (isFinite(l) && l === 0) return 'included-only';
  const pct = pctOf(ptdSpend, limit);
  if (pct == null) return 'no-limit';
  if (pct >= 100) return 'over';
  return pct >= Number(threshold || THRESHOLD_DEFAULT) ? 'near' : 'ok';
}

/** Round up to a sensible money step so a recommendation reads as a decision. */
function roundUpTo(v, step) {
  const s = Number(step) || 1;
  return Math.ceil(Number(v) / s) * s;
}

/** The step to round a recommendation to, scaled to the size of the current limit. */
function stepFor(limit) {
  const l = Number(limit) || 0;
  if (l < 200) return 25;
  if (l < 1000) return 50;
  return 100;
}

/**
 * Spend projected to the end of the month at the rate established so far.
 * Returns null when the month cannot support the arithmetic — day 0, or a period
 * that has already closed, where a "projection" would be a restatement dressed up
 * as a forecast.
 */
function project(ptdSpend, daysElapsed, daysInMonth) {
  const p = Number(ptdSpend), d = Number(daysElapsed), n = Number(daysInMonth);
  if (!isFinite(p) || !isFinite(d) || !isFinite(n) || d <= 0 || n <= 0) return null;
  if (d >= n) return Math.round(p * 100) / 100;      // month complete: the total IS the outcome
  return Math.round((p / d) * n * 100) / 100;
}

/**
 * A limit to ask for, and the reason to give.
 *
 * The honest answer is often "none": somebody at 76% on the 28th finishes inside
 * their cap, and asking IT to raise it would waste a ticket and the requester's
 * credibility. An increase is recommended only when the run rate actually closes
 * the month over the limit.
 */
function recommend(opts) {
  const o = opts || {};
  const limit = o.limit == null ? null : Number(o.limit);
  const ptd = Number(o.ptdSpend) || 0;
  const projected = o.projected == null ? project(ptd, o.daysElapsed, o.daysInMonth) : Number(o.projected);
  if (limit == null || !isFinite(limit) || limit <= 0) {
    return { needed: false, amount: null, projected, reason: 'no-limit' };
  }
  if (projected == null) {
    return { needed: false, amount: null, projected: null, reason: 'no-projection' };
  }
  if (projected <= limit) {
    return {
      needed: false, amount: null, projected, reason: 'on-track',
      note: 'At this rate the month closes at about ' + money(projected) + ', inside the ' + money(limit) + ' limit.',
    };
  }
  const step = stepFor(limit);
  // Never recommend a limit that is not actually an increase: a projection barely
  // over the cap must still round to at least one step above it.
  const amount = Math.max(roundUpTo(projected * (1 + HEADROOM), step), limit + step);
  return {
    needed: true, amount, projected, step, reason: 'projected-over',
    shortfall: Math.round((projected - limit) * 100) / 100,
    note: 'At this rate the month closes at about ' + money(projected) + ', over the ' + money(limit)
      + ' limit by ' + money(projected - limit) + '. ' + money(amount) + ' covers that with about 10% headroom.',
  };
}

function money(v) {
  const n = Number(v);
  if (!isFinite(n)) return '—';
  return '$' + n.toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

/**
 * Assess one team member. `member` is a row from ai-tools-lib's teamReport, which
 * already carries claudeLimit from the same Anthropic pull.
 * Returns null when the person cannot be assessed at all (no seat, no limit row).
 */
function assess(member, period, threshold) {
  const m = member || {};
  const lim = m.claudeLimit || null;
  if (!lim) return null;
  const limit = lim.amount == null ? null : Number(lim.amount);
  const ptd = Number(lim.periodToDateSpend) || 0;
  const th = Number(threshold) || THRESHOLD_DEFAULT;
  const state = stateFor(ptd, limit, th);
  const p = period || {};
  const projected = p.isCurrent ? project(ptd, p.daysElapsed, p.daysInMonth) : null;
  return {
    email: m.email,
    name: m.name || m.email,
    title: m.title || null,
    limit, ptdSpend: ptd,
    pct: pctOf(ptd, limit),
    state,
    basis: lim.basis || null,
    sourceType: lim.sourceType || null,
    asOf: lim.asOf || null,
    projected,
    daysElapsed: p.daysElapsed == null ? null : Number(p.daysElapsed),
    daysInMonth: p.daysInMonth == null ? null : Number(p.daysInMonth),
    recommendation: recommend({ limit, ptdSpend: ptd, projected, daysElapsed: p.daysElapsed, daysInMonth: p.daysInMonth }),
    // Who owns the conversation. depth 1 is the viewer's own report; anything deeper
    // belongs to a manager further down, and naming that manager stops a director
    // opening a conversation the person's own manager is already having.
    direct: m.direct !== false,
    depth: m.depth == null ? 1 : Number(m.depth),
    reportsTo: m.managerName || m.managerEmail || null,
    reportsToEmail: m.managerEmail || null,
  };
}

/**
 * The people a viewer should be told about.
 *
 * A manager sees their DIRECT reports. A DIRECTOR sees their whole subtree — the
 * population they are already accountable for on the same page — but every entry
 * carries `direct` and `reportsTo`, so a skip-level reads as somebody else's report
 * rather than as one of their own. Without that a director cannot tell whose
 * conversation it is, and two people open the same one.
 *
 * `includeIndirect` is the caller's decision, not this module's: ai-tools-lib passes
 * the viewer's own scope kind. Past periods raise nothing — `isCurrent` gates the list.
 */
function alertsFor(members, period, threshold, opts) {
  const p = period || {};
  if (!p.isCurrent) return [];
  const o = opts || {};
  const th = Number(threshold) || THRESHOLD_DEFAULT;
  const out = [];
  for (const m of members || []) {
    if (!m) continue;
    if (!m.direct && !o.includeIndirect) continue;
    const a = assess(m, p, th);
    if (!a) continue;
    if (a.state === 'near' || a.state === 'over' || a.state === 'included-only') out.push(a);
  }
  // Worst first, and the viewer's own reports ahead of the org below them: the
  // people they can act on directly are the ones the card should open with.
  const rank = { over: 0, 'included-only': 1, near: 2 };
  out.sort((x, y) => (Number(y.direct) - Number(x.direct))
    || (rank[x.state] - rank[y.state])
    || ((y.pct || 0) - (x.pct || 0)));
  return out;
}

/**
 * The threshold that applies to one viewer: their own choice if they have made one,
 * otherwise the platform default published by the admin console.
 *
 * "When do you want to be told" is a property of the person being told, so the
 * viewer's number is what the card, the ticket and the digest all use — including
 * for a skip-level, whose own manager may have chosen differently for their own list.
 */
function usableThreshold(v) {
  // Whole numbers only. Both writers upstream already promise an integer — the
  // route validates one and the column is an INT — but this is the function every
  // reader trusts, so it re-checks rather than inheriting somebody else's promise.
  const n = Number(v);
  return Number.isInteger(n) && n >= 1 && n <= 99 ? n : null;
}
function effectiveThreshold(managerThreshold, consoleDefault) {
  const m = usableThreshold(managerThreshold);
  if (m !== null) return { threshold: m, source: 'manager' };
  const c = usableThreshold(consoleDefault);
  if (c !== null) return { threshold: c, source: 'console' };
  return { threshold: THRESHOLD_DEFAULT, source: 'default' };
}

module.exports = {
  THRESHOLD_DEFAULT, HEADROOM,
  pctOf, stateFor, roundUpTo, stepFor, project, recommend, money, assess, alertsFor,
  effectiveThreshold, usableThreshold,
};
