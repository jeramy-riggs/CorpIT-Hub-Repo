'use strict';
// =====================================================================
// claude-limit-approvals.js  (2026-09-25)
//
// My Profile -> Claude spend limit: self-raise, manager approval and
// functional-leader approval, applied in Anthropic, logged on Service Desk
// tickets, mailed from Enterprise Approvals. Registered on the /api/profile
// router, so every route inherits its session auth, CSRF origin guard and the
// View-As read-only guard (a borrowed view cannot approve anything).
//
// Bands, on the SIZE OF THE RAISE over the person's base: the limit they started the
// month with and go back to on the 1st (their admin-set cap, or the inherited default).
// The same for everyone, whatever the base (owner's rules, 2026-09-25):
//   +$100, once a month        the person raises themselves, one click, applied now
//   any other raise, up to +$500 over the base   their manager approves (a second
//                                                request in the month goes to the manager
//                                                however small it is)
//   more than +$500 over the base                their manager, then their functional leader
// The two raise sizes are console settings (selfRaise, managerRaise, Settings -> Claude
// limit approvals, published to /etc/corpit/shared/spend-alerts.json). Until the console
// publishes them the values above are used.
//
// Every approval action files its own SDP ticket. The action that finishes the
// chain sets the cap in Anthropic, writes the result onto that ticket, closes it,
// and mails the person (raised) and their manager (done). A step with nobody to
// approve it (no manager on record, or no functional leader, or the leader is the
// requester) is not guessed at: an OPEN ticket goes to the Service Desk and the
// escalation list is mailed.
//
// Raises made here are undone on the 1st by claude-limit-reset-job.js, back to the
// cap the person had before (their own admin-set cap, or the inherited default).
//
// Interruptions (2026-09-25): a hub restart part-way through a step leaves the row
// in 'applying', 'forwarding', or (no manager on record) 'pending_manager'. Once
// nothing has touched it for STALE_S seconds, the person whose step it was gets
// Try again, which picks up from the row: tickets already recorded are reused, mail
// already recorded is not sent twice, and the cap to go back to is written down
// BEFORE Anthropic is changed, so a write that landed just before the restart is
// recognised as this request's own and still resets on the 1st. Every outside call
// is bounded (SDP, mail, Anthropic) and the row is written between calls, so a live
// step never leaves it untouched for more than a few minutes - far inside STALE_S.
//
// Claude seat owners (stage S, Jeramy's Q2 picks, 2026-09-25): a seat owner may approve
// or deny a request that went to the Service Desk (escalated), and their own requests
// need no other approval (any amount, even with a manager; the manager is still mailed).
// No new column: the seat owner is written into the empty decided_by slot they fill
// (manager_decided_by when there is no manager, leader_decided_by when there is no
// leader), so a slot whose decider is not the person on record is a seat-owner decision
// (standIn). The result mail goes to the people the usual rule names who exist, plus the
// seat owner in place of the missing one. The audit log marks seatOwner.
//
// Withdraw after an interruption (stage T, Jeramy 2026-09-26 "1, yes"): the requester may
// withdraw their own request once it has stopped part-way: a failed Anthropic write
// (apply_failed) at any time, an in-flight step (applying, forwarding) once idle STALE_S,
// claimed the way Try again claims it, so the two cannot both proceed. If a write to
// Anthropic was started for it (apply_method 'writing') and Anthropic reads exactly the
// requested total as a per-user cap, that write landed: the withdraw is refused (Try again
// records it; it then resets on the 1st). Tickets still open on it are noted and closed;
// nobody is mailed, as for any withdraw. A request withdrawn while it was being routed to
// the Service Desk gets its escalation ticket closed the same way.
//
// Wrap-ups finished by the hourly job (stage U, 2026-09-26): a step that stopped after its
// decision was recorded (approved, denied, withdrawn) but before its ticket was closed or its
// mail sent is finished by claude-limit-reset-job.js once the row has been idle STALE_S
// (wrapStopped): the ticket is noted and closed, and whoever has no mail for that event yet
// is mailed. Only rows decided since WRAP_SINCE and in the last WRAP_DAYS days; a close or a
// send that was tried and failed is not tried again; nobody is mailed about a raise that was
// already reset or replaced. In the first LANDED_HOURS of a month, a raise from an earlier
// month that was marked failed or stopped while applying, but whose write DID land
// (apply_method 'writing' and Anthropic reads exactly the requested total as a per-user cap),
// is recorded as approved by the job (recordLanded) so it is reset with the rest; its open
// tickets are closed and only the reset mails the person. Escalated requests, and failed
// ones whose write did not land, are not touched. A denial's ticket is recorded as soon as
// it is filed, so a stop before it is closed leaves it for the job, not a second ticket.
// =====================================================================

const fs = require('fs');
const express = require('express');
const anthropic = require('./anthropic-spend-admin');

// PATH-RELEASE-20260929: /etc/corpit/shared/spend-alerts.json via corpit-paths.js.
const CFG_PATH = require('./corpit-paths').sharedFile('spend-alerts.json', 'SPEND_ALERT_CONFIG_PATH');
const CFG_TTL_MS = 30000;
// Used verbatim until the console publishes an approvals block. `enabled` ships
// OFF: nothing can be raised until the console switch is turned on.
const DEFAULTS = Object.freeze({
  enabled: false, selfRaise: 100, managerRaise: 500,
  escalation: ['rabad@auction.com', 'jriggs@auction.com', 'spark@auction.com'],
  // Claude seat owners: see every request, may retry a failed Anthropic write (picks 11-12), and
  // approve or deny escalated requests and approve their own (stage S).
  seatOwners: ['rabad@auction.com', 'jriggs@auction.com', 'spark@auction.com'],
});
const HISTORY_DAYS = 90;              // how far back the queue tabs go (pick 14); open requests show whatever their age
const MAX_TOTAL = 1000000;            // same sanity guard as /ai-team/limit-request
const STALE_S = 600;                  // an in-flight row untouched this long may be resumed
const SDP_MS = 45000, MAIL_MS = 30000; // per call; the row is written between calls
const RESUMED_NOTE = 'NOTE: filed when this request was resumed after an interruption. If an earlier ticket for this same step exists, it is a duplicate and can be closed.';
// Stage U: what the hourly reset job finishes (wrapStopped) and records on the 1st (recordLanded).
const WRAP_SINCE = '2026-09-26 00:00:00', WRAP_DAYS = 3;   // rows decided before stage U are never touched
const JOB = 'claude-limit-reset-job';                        // applied_by of a landed write the job recorded
const LANDED_HOURS = 6;                                      // the reset job's RETRY_HOURS
const SWEPT = 'Finished by the hourly Claude limit job: the step that made this decision stopped before it closed this ticket.';
// Must match the open_key generated column in the DDL: one open request per person.
const OPEN = ['pending_manager', 'forwarding', 'pending_leader', 'applying', 'apply_failed'];
const PAGE_URL = (process.env.MYPROFILE_ORIGIN || 'https://myprofile.nrpi.local').replace(/\/+$/, '') + '/#claude/limit';
const SENDER = {
  from:     process.env.SPEND_ALERT_FROM      || 'EnterpriseApprovals@auction.com',
  fromName: process.env.SPEND_ALERT_FROM_NAME || 'Enterprise Approvals',
  mailbox:  process.env.SPEND_ALERT_MAILBOX   || 'EnterpriseApprovals@auctiondotcom.onmicrosoft.com',
};
const TICKET_FALLBACK = { email: 'itcommand@auction.com', name: 'IT Command' };
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

// ───────────────────────── config ─────────────────────────
let _cfg = { at: 0, v: null };
/* Re-validated here as well as in the root helper: this process does not own the
 * file. Any problem with the approvals block leaves the feature OFF, never on. */
function readConfig() {
  const out = Object.assign({}, DEFAULTS, { escalation: DEFAULTS.escalation.slice(), seatOwners: DEFAULTS.seatOwners.slice(), source: 'default', error: null });
  let doc;
  try { doc = JSON.parse(fs.readFileSync(CFG_PATH, 'utf8')); }
  catch (e) { if (e.code !== 'ENOENT') { out.source = 'unknown'; out.error = e.message; } return out; }
  const a = doc && doc.approvals;
  if (!a || typeof a !== 'object') return out;
  const int = (v, lo, hi) => (Number.isInteger(v) && v >= lo && v <= hi ? v : null);
  // defaultLimit/selfMax/managerMax (the monthly totals of the first build) can still be
  // in the file until the console publishes the raise sizes. They are not read.
  if (a.selfRaise !== undefined || a.managerRaise !== undefined) {
    const s = int(a.selfRaise, 1, 100000), m = int(a.managerRaise, 1, 1000000);
    if (s == null || m == null || !(s < m)) {
      out.source = 'unknown'; out.error = 'approvals block is out of range or out of order'; out.enabled = false;
      return out;
    }
    out.selfRaise = s; out.managerRaise = m;
  }
  if (Array.isArray(a.escalationEmails)) {
    out.escalation = a.escalationEmails.map(x => String(x).trim().toLowerCase()).filter(x => EMAIL_RE.test(x));
  }
  if (Array.isArray(a.seatOwners)) {
    out.seatOwners = a.seatOwners.map(x => String(x).trim().toLowerCase()).filter(x => EMAIL_RE.test(x));
  }
  out.enabled = a.enabled === true;
  out.source = 'console';
  return out;
}
function config() {
  const now = Date.now();
  if (_cfg.v && now - _cfg.at < CFG_TTL_MS) return _cfg.v;
  _cfg = { at: now, v: readConfig() };
  return _cfg.v;
}

// ───────────────────────── small helpers ─────────────────────────
const lc = (v) => String(v || '').trim().toLowerCase();
const money = (cents) => (cents == null ? 'no cap' : '$' + (Math.round(cents) / 100).toLocaleString('en-US', { minimumFractionDigits: 0, maximumFractionDigits: 2 }));
const monthKey = (d) => (d || new Date()).toISOString().slice(0, 7);
function monthName(key) { return new Date(key + '-01T00:00:00Z').toLocaleString('en-US', { month: 'long', year: 'numeric', timeZone: 'UTC' }); }
function nextFirst() { const n = new Date(); return new Date(Date.UTC(n.getUTCFullYear(), n.getUTCMonth() + 1, 1)); }
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function jsonCol(v) { if (v == null) return null; if (typeof v === 'object') return v; try { return JSON.parse(v); } catch (e) { return null; } }
function sqlNow() { return new Date().toISOString().slice(0, 19).replace('T', ' '); }
function first(name) { return String(name || '').split(/[\s,]+/).filter(Boolean)[0] || ''; }
/* Rejects with code TIMEOUT when `p` has not settled in `ms`. The call itself is not
 * cancelled; the step just stops waiting for it. */
function within(ms, p, what) {
  let t;
  const late = new Promise((_, no) => { t = setTimeout(() => no(Object.assign(new Error(what + ' did not answer within ' + Math.round(ms / 1000) + ' s'), { code: 'TIMEOUT' })), ms); });
  return Promise.race([Promise.resolve(p), late]).finally(() => clearTimeout(t));
}

// ───────────────────────── who approves ─────────────────────────
/* A manager must be a real, enabled Entra account: org nodes such as a board
 * placeholder are in the tree but are not mailboxes, and must not be approvers. */
async function realPerson(pool, email) {
  if (!email) return null;
  const [[e]] = await pool.query(
    `SELECT LOWER(user_principal_name) email, display_name FROM entra_users
      WHERE LOWER(user_principal_name) = ? AND account_enabled = 1 LIMIT 1`, [lc(email)]);
  return e ? { email: e.email, name: e.display_name || e.email } : null;
}

/* Functional leader: the HR roster's functional_leader for this person. Somebody
 * not on the roster (contractor, service account) takes the leader of the nearest
 * manager above them who is. Assigned per person, never per department. The name is
 * resolved to exactly one roster row; an ambiguous or missing name is "no leader". */
async function resolveLeader(pool, email) {
  let cur = lc(email), seen = new Set();
  for (let depth = 0; depth < 12 && cur && !seen.has(cur); depth++) {
    seen.add(cur);
    const [[ae]] = await pool.query(
      'SELECT functional_leader FROM active_employees WHERE LOWER(business_email) = ? LIMIT 1', [cur]);
    if (ae) {
      const name = String(ae.functional_leader || '').trim();
      if (!name) return { leader: null, why: 'no functional leader on the HR roster' };
      const [rows] = await pool.query(
        'SELECT LOWER(business_email) email, first_last FROM active_employees WHERE first_last = ? LIMIT 2', [name]);
      if (rows.length !== 1) return { leader: null, why: 'functional leader "' + name + '" does not match exactly one roster entry' };
      const p = await realPerson(pool, rows[0].email);
      if (!p) return { leader: null, why: 'functional leader ' + rows[0].email + ' has no enabled account' };
      return { leader: { email: p.email, name: p.name || rows[0].first_last }, why: depth ? 'via ' + cur : null };
    }
    const [[p]] = await pool.query('SELECT manager_email FROM org_reporting_person WHERE email = ? LIMIT 1', [cur]);
    cur = p ? lc(p.manager_email) : '';
  }
  return { leader: null, why: 'not on the HR roster and no manager above them is' };
}

async function resolveChain(pool, email) {
  const [[p]] = await pool.query(
    'SELECT email, display_name, manager_email FROM org_reporting_person WHERE email = ? LIMIT 1', [lc(email)]);
  const person = { email: lc(email), name: (p && p.display_name) || lc(email) };
  const manager = p && p.manager_email ? await realPerson(pool, p.manager_email) : null;
  const managerWhy = !p ? 'not in the Active Directory org tree'
    : !p.manager_email ? 'no manager in Active Directory'
      : !manager ? 'manager ' + lc(p.manager_email) + ' is not an enabled account' : null;
  const L = await resolveLeader(pool, email);
  let leader = L.leader, leaderWhy = L.why && !L.leader ? L.why : null;
  if (leader && leader.email === person.email) { leader = null; leaderWhy = 'they are their own functional leader'; }
  return { person, manager, managerWhy, leader, leaderWhy };
}

// ───────────────────────── current limit ─────────────────────────
async function memberRow(pool, email) {
  const [[r]] = await pool.query(
    `SELECT user_id, amount_cents, source_type, spend_limit_id, ptd_spend_cents, fetched_at
       FROM claude_spend_limit WHERE period = 'monthly' AND deleted = 0 AND LOWER(email) = ? LIMIT 1`, [lc(email)]);
  if (!r) return null;
  return {
    userId: r.user_id, amountCents: r.amount_cents == null ? null : Math.round(Number(r.amount_cents)),
    sourceType: r.source_type || '', spendLimitId: r.spend_limit_id || null,
    ptdCents: Math.round(Number(r.ptd_spend_cents) || 0), fetchedAt: r.fetched_at, live: false,
  };
}

/* Live when Anthropic answers, else the hourly feed. Either way the caller is told which. */
async function currentLimit(pool, email) {
  const row = await memberRow(pool, email);
  if (!row) return null;
  const live = await anthropic.effective(row.userId);
  if (live.ok && live.row) {
    return Object.assign({}, row, { amountCents: live.row.amountCents, sourceType: live.row.sourceType,
      spendLimitId: live.row.spendLimitId, ptdCents: live.row.ptdCents, live: true });
  }
  return row;
}

/* 'self' is only ever the one-click raise, which its route has checked is still
 * available this month. Every other request goes by how far the new total is above
 * the base. */
function bandFor(cfg, baseCents, totalCents, self) {
  if (self) return 'self';
  return totalCents - baseCents <= cfg.managerRaise * 100 ? 'manager' : 'leader';
}

/* The base: the cap the person started the month with, which is the cap the reset job
 * puts back on the 1st. Same test as priorFor below, so the two cannot disagree: while
 * the cap is still the latest unreset raise made here, the base is that raise's prior. */
async function baseFor(pool, email, amountCents, sourceType) {
  if (amountCents == null) return null;
  const [[chain]] = await pool.query(
    `SELECT applied_cents, prior_amount_cents FROM claude_limit_approval
      WHERE requester_email = ? AND status = 'approved' AND reset_state IS NULL AND applied_cents IS NOT NULL
      ORDER BY applied_at DESC LIMIT 1`, [email]);
  if (chain && sourceType === 'user' && Number(chain.applied_cents) === amountCents && chain.prior_amount_cents != null) return Number(chain.prior_amount_cents);
  return amountCents;
}

/* The one self-raise a month is used by any self-raise this month except one refused
 * before anything happened ('failed': the log ticket was not filed). With anyBand, a
 * raise of ANY band this month counts: the one-click is the first raise of the month
 * only ("only get one, 100 request a month no matter what"), so a manager or leader
 * raise followed by an outside cap change does not bring it back. The month is the one
 * the request was made in (period). */
async function selfUsed(pool, email, anyBand) {
  const [[r]] = await pool.query(
    `SELECT id FROM claude_limit_approval WHERE requester_email = ?${anyBand ? '' : " AND band = 'self'"} AND period = ?
        AND status IN ('applying', 'apply_failed', 'approved', 'escalated') LIMIT 1`, [email, monthKey()]);
  return !!r;
}

/* A raise from an earlier month that the reset job has not put back yet (it runs at
 * :00; a refused reset is retried hourly). Until it has, "back to $X on the 1st of next
 * month" and "already raised this month" would both be false. */
async function resetDue(pool, email) {
  const [[r]] = await pool.query(
    `SELECT id FROM claude_limit_approval WHERE requester_email = ? AND status = 'approved' AND reset_state IS NULL
        AND applied_cents IS NOT NULL AND DATE_FORMAT(applied_at, '%Y-%m') < ? LIMIT 1`, [email, monthKey()]);
  return !!r;
}

/* The page sends the raise sizes it showed. A size changed in the console since then
 * would apply or route differently from what the card said, so it is refused and the
 * card repaints with the new sizes. A body without them (an older page) is not checked. */
function sizesChanged(body, cfg) {
  const b = body || {};
  return (b.selfRaise !== undefined && b.selfRaise !== cfg.selfRaise) || (b.managerRaise !== undefined && b.managerRaise !== cfg.managerRaise);
}
const SIZES_CHANGED = { error: 'The raise sizes were changed in the admin console since this page loaded, so nothing was sent. The card now shows the new amounts; check them and try again.', code: 'SETTINGS_CHANGED' };

const UNREADABLE = { error: 'Could not check your current limit with Anthropic just now, so nothing was changed. Try again in a minute.', code: 'LIMIT_UNREADABLE' };

// ───────────────────────── rows ─────────────────────────
const ROW_COLS = `id, requester_email, requester_name, manager_email, manager_name, leader_email, leader_name,
  band, period, current_limit_cents, current_source, requested_cents, status,
  manager_decided_by, manager_decided_at, leader_decided_by, leader_decided_at,
  deny_reason, denied_by, denied_at, cancelled_at, applied_at, applied_by, applied_cents, apply_method,
  anthropic_user_id, spend_limit_id, increase_request_id, prior_source, prior_override_cents, prior_amount_cents,
  tickets, notified, fail_reason, reset_state, reset_at, reset_detail, created_at, updated_at,
  TIMESTAMPDIFF(SECOND, updated_at, NOW()) AS idle_s`;

async function getRow(pool, id) {
  const [[r]] = await pool.query(`SELECT ${ROW_COLS} FROM claude_limit_approval WHERE id = ?`, [id]);
  return r || null;
}

function publicRow(r, me) {
  const tickets = (jsonCol(r.tickets) || []).map(t => ({ action: t.action, display: t.display, url: t.url, closed: !!t.closed, closeError: t.closeError || null }));
  return {
    id: r.id, band: r.band, status: r.status, period: r.period,
    requester: { email: r.requester_email, name: r.requester_name },
    manager: r.manager_email ? { email: r.manager_email, name: r.manager_name } : null,
    leader: r.leader_email ? { email: r.leader_email, name: r.leader_name } : null,
    current: r.current_limit_cents == null ? null : Number(r.current_limit_cents) / 100,
    requested: Number(r.requested_cents) / 100,
    applied: r.applied_cents == null ? null : Number(r.applied_cents) / 100,
    appliedAt: r.applied_at, createdAt: r.created_at, updatedAt: r.updated_at,
    managerDecidedAt: r.manager_decided_at, leaderDecidedAt: r.leader_decided_at,
    deniedBy: r.denied_by, denyReason: r.deny_reason, deniedAt: r.denied_at, cancelledAt: r.cancelled_at,
    failReason: r.fail_reason, resetState: r.reset_state, resetAt: r.reset_at,
    interrupted: r.status !== 'apply_failed' && !!resumeKind(r),
    ownerApproval: standIn(r) ? { by: standIn(r), at: standIn(r) === r.manager_decided_by ? r.manager_decided_at : r.leader_decided_at } : null,
    tickets,
    mine: me ? r.requester_email === me : undefined,
  };
}

async function patch(pool, id, fields) {
  const keys = Object.keys(fields);
  if (!keys.length) return;
  await pool.query(`UPDATE claude_limit_approval SET ${keys.map(k => k + ' = ?').join(', ')} WHERE id = ?`,
    keys.map(k => (fields[k] !== null && typeof fields[k] === 'object' && !(fields[k] instanceof Date)) ? JSON.stringify(fields[k]) : fields[k]).concat([id]));
}

/* Compare-and-set on status, so a double click or two approvers at once cannot
 * both proceed: only the caller whose UPDATE matched owns the next step. */
async function claim(pool, id, fromStatuses, fields) {
  const keys = Object.keys(fields);
  const [r] = await pool.query(
    `UPDATE claude_limit_approval SET ${keys.map(k => k + ' = ?').join(', ')}
      WHERE id = ? AND status IN (${fromStatuses.map(() => '?').join(',')})`,
    keys.map(k => fields[k]).concat([id], fromStatuses));
  return r.affectedRows === 1;
}

/* Take an interrupted row for a resume. The status stays as it is; updated_at moves, so
 * a second click (or tab) inside the next STALE_S seconds finds nothing to take. */
async function claimStale(pool, id, status) {
  const [r] = await pool.query(
    `UPDATE claude_limit_approval SET updated_at = NOW()
      WHERE id = ? AND status = ? AND updated_at <= NOW() - INTERVAL ${STALE_S} SECOND`, [id, status]);
  return r.affectedRows === 1;
}

/* Withdraw a stopped row (stage T): the same claim Try again makes, so only one of the two
 * proceeds. apply_failed by its status; an in-flight status only once idle STALE_S. */
async function claimWithdraw(pool, id, status) {
  const idle = status === 'apply_failed' ? '' : ` AND updated_at <= NOW() - INTERVAL ${STALE_S} SECOND`;
  const [r] = await pool.query(
    `UPDATE claude_limit_approval SET status = 'cancelled', cancelled_at = ? WHERE id = ? AND status = ?${idle}`, [sqlNow(), id, status]);
  return r.affectedRows === 1;
}

/* What a stopped request needs to finish, or null. apply_failed may be retried at any
 * time; the in-flight statuses only once idle for STALE_S, so a resume never runs
 * alongside a step that is still going. */
function resumeKind(r) {
  if (r.status === 'apply_failed') return 'apply';
  if (!(Number(r.idle_s) >= STALE_S)) return null;
  if (r.status === 'applying') return r.band === 'self' && !r.manager_email && !standIn(r) ? 'escalate' : 'apply';
  if (r.status === 'forwarding') return 'forward';
  if (r.status === 'pending_manager' && !r.manager_email) return 'escalate';
  return null;
}
// The person whose step it was: the seat owner who approved it, the requester for a
// self-raise or an unrouted request, the manager for a forward, otherwise whoever gave
// the final approval.
function resumerOf(r) {
  const so = standIn(r);
  if (so) return so;
  if (r.band === 'self' || r.status === 'pending_manager') return r.requester_email;
  if (r.status === 'forwarding') return r.manager_decided_by;
  return r.leader_decided_by || r.manager_decided_by;
}
/* A seat-owner decision: a decided_by slot holding somebody other than the person on
 * record for it (nobody else ever writes one; see the stage S note at the top). */
function standIn(r) {
  if (r.manager_decided_by && r.manager_decided_by !== r.manager_email) return r.manager_decided_by;
  if (r.leader_decided_by && r.leader_decided_by !== r.leader_email) return r.leader_decided_by;
  return null;
}
// What a seat owner may approve (stage S): anything with the Service Desk, and their own
// request still waiting on somebody. Deny is the escalated ones only; their own they withdraw.
const isOwner = (cfg, me) => !!(me && cfg.seatOwners.indexOf(me) >= 0);
const ownerDecides = (cfg, r, me) => isOwner(cfg, me) && (r.status === 'escalated'
  || (r.requester_email === me && (r.status === 'pending_manager' || r.status === 'pending_leader')));
const canRetry = (r, me) => !!(me && resumeKind(r) && resumerOf(r) === me);
// The requester may withdraw while it waits on somebody, and once it has stopped part-way
// (stage T): a failed write at any time, an in-flight step once idle STALE_S.
const STOPPED = ['applying', 'forwarding', 'apply_failed'];
function withdrawable(r) {
  if (r.status === 'pending_manager' || r.status === 'pending_leader' || r.status === 'apply_failed') return true;
  return (r.status === 'applying' || r.status === 'forwarding') && Number(r.idle_s) >= STALE_S;
}
// A Claude seat owner may retry any failed Anthropic write (pick 12), never another step.
const ownerRetry = (cfg, r, me) => !!(me && r.status === 'apply_failed' && cfg.seatOwners.indexOf(me) >= 0);
// Waiting on `me` as manager or functional leader: the only rows `me` may approve or deny.
const pendingOn = (r, me) => (r.status === 'pending_manager' && r.manager_email === me) || (r.status === 'pending_leader' && r.leader_email === me);
// Which ticket records the approval that completes the chain.
function finalAction(r) {
  if (r.band === 'self') return 'self';
  return r.leader_decided_by && r.leader_decided_by !== r.manager_decided_by ? 'leader' : 'manager';
}

// ───────────────────────── tickets ─────────────────────────
function ticketText(r, action, extra) {
  const L = [];
  L.push('Logged from CorpIT Hub -> My Profile -> Claude spend limit (request #' + r.id + ').');
  L.push('');
  L.push('PERSON            ' + (r.requester_name || r.requester_email) + ' <' + r.requester_email + '>');
  L.push('MANAGER           ' + (r.manager_email ? (r.manager_name || r.manager_email) + ' <' + r.manager_email + '>' : 'none on record'));
  L.push('FUNCTIONAL LEADER ' + (r.leader_email ? (r.leader_name || r.leader_email) + ' <' + r.leader_email + '>' : 'none on record'));
  L.push('');
  L.push('Current limit     ' + money(r.current_limit_cents == null ? null : Number(r.current_limit_cents)) + ' per month' + (r.current_source ? ' (' + r.current_source + ')' : ''));
  L.push('New monthly total ' + money(Number(r.requested_cents)));
  L.push('Approval band     ' + ({ self: 'self-raise (the one raise a month that needs no approval)', manager: 'manager approval', leader: 'manager, then functional leader' })[r.band]);
  L.push('Month             ' + monthName(r.period) + ' - the raise returns to the prior cap on the 1st.');
  L.push('');
  L.push('ACTION            ' + action);
  (extra || []).forEach(x => L.push(x));
  return L.join('\n');
}

async function fileTicket(D, r, kind, subject, description, requester) {
  if (!D.sdp || !D.sdp.createTicket) throw new Error('The Service Desk integration is not available on this host.');
  let t, fallback = false;
  try {
    t = await within(SDP_MS, D.sdp.createTicket({ subject, description, requesterEmail: requester.email, requesterName: requester.name || requester.email }), 'SDP');
  } catch (e) {
    // SDP may still file a ticket it did not answer for; a second one would be a duplicate.
    if (e && e.code === 'TIMEOUT') throw e;
    // The requester may not exist in SDP. The description names everybody either way.
    t = await within(SDP_MS, D.sdp.createTicket({ subject, description: description + '\n\nNOTE: filed under ' + TICKET_FALLBACK.email + ' because SDP did not accept ' + requester.email + ' as the requester.',
      requesterEmail: TICKET_FALLBACK.email, requesterName: TICKET_FALLBACK.name }), 'SDP');
    fallback = true;
  }
  return { action: kind, id: String(t.id), display: String(t.display_id), url: t.url, closed: false, fallback, at: sqlNow() };
}

// Sets closeError (null when closed) every time it runs; a ticket without that key was never closed out.
async function noteAndClose(D, ticket, note, resolution) {
  try { await within(SDP_MS, D.sdp.addNoteToTicket(ticket.id, note, false), 'SDP'); ticket.noted = true; }
  catch (e) { ticket.noteError = D.sdp.sdpErrorText ? D.sdp.sdpErrorText(e) : e.message; }
  try { if (D.sdp.setResolution) { await within(SDP_MS, D.sdp.setResolution(ticket.id, resolution || note), 'SDP'); ticket.resolution = true; } }
  catch (e) { ticket.resolutionError = D.sdp.sdpErrorText ? D.sdp.sdpErrorText(e) : e.message; }
  let c;
  try { c = D.sdp.closeTicket ? await within(SDP_MS, D.sdp.closeTicket(ticket.id, resolution || note), 'SDP') : { ok: false, error: 'closeTicket unavailable' }; }
  catch (e) { c = { ok: false, error: e.message }; }
  ticket.closed = !!c.ok;
  ticket.closeError = c.ok ? null : String(c.error || 'not closed').slice(0, 300);
  return ticket;
}

async function addTicket(pool, id, ticket) {
  const r = await getRow(pool, id);
  const list = (jsonCol(r && r.tickets) || []).filter(t => t.id !== ticket.id);
  list.push(ticket);
  await patch(pool, id, { tickets: list });
  return list;
}

// ───────────────────────── mail ─────────────────────────
function mailHtml(title, lines, cta) {
  // Same palette as the Enterprise Approvals spend digest, inlined for Outlook.
  const body = lines.map(l => '<p style="margin:0 0 12px;font-size:14px;line-height:1.5;color:#C7D6E8">' + l + '</p>').join('');
  return '<!DOCTYPE html><html><head><meta charset="utf-8"/></head>'
    + '<body style="font-family:-apple-system,\'Segoe UI\',Roboto,sans-serif;background:#0A1628;color:#EEF4FB;margin:0;padding:24px">'
    + '<div style="max-width:620px;margin:0 auto;background:#0F1F35;border:1px solid #1F3A5C;border-radius:10px;overflow:hidden">'
    + '<div style="padding:22px 24px;border-bottom:1px solid #1F3A5C;background:linear-gradient(135deg,#0F1F35,#18304E)">'
    + '<h1 style="margin:0;font-size:19px;color:#EEF4FB">' + esc(title) + '</h1>'
    + '<p style="margin:6px 0 0;font-size:13px;color:#8FA3BE">Claude spend limit</p></div>'
    + '<div style="padding:20px 24px">' + body
    + (cta ? '<a href="' + esc(PAGE_URL) + '" style="display:inline-block;margin-top:6px;padding:9px 16px;background:#0EA5E9;color:#04121F;border-radius:5px;font-size:13px;font-weight:600;text-decoration:none">' + esc(cta) + '</a>' : '')
    + '</div><div style="padding:16px 24px;font-size:11px;color:#5A6F8E;background:#0A1628;text-align:center;line-height:1.6">'
    + 'Sent by Enterprise Approvals from CorpIT Hub. Raises made in My Profile return to the prior limit on the 1st of the month.</div>'
    + '</div></body></html>';
}

/* One message per recipient per event, so a manager who is also the leader is not mailed
 * twice, and a resumed step does not re-mail anybody the interrupted one already did.
 * Each send is recorded as it happens. A send that failed is tried again on a resume
 * (one that timed out may have gone, so that person can get it twice). */
async function mailAll(D, r, event, messages) {
  const cur = await getRow(D.pool, r.id);
  const out = jsonCol(cur && cur.notified) || [];
  const sent = {};
  out.forEach(x => { if (x.event === event && x.ok) sent[x.to] = true; });
  for (const m of messages) {
    const to = lc(m.to);
    if (!to || sent[to]) continue;
    sent[to] = true;
    let res;
    try { res = await within(MAIL_MS, D.mailGraph.sendMail(Object.assign({ to: [to], subject: m.subject, html: m.html, saveToSentItems: true }, SENDER)), 'Mail'); }
    catch (e) { res = { ok: false, reason: e.message }; }
    out.push({ event, to, ok: !!res.ok, reason: res.ok ? null : (res.reason || 'failed'), at: sqlNow() });
    if (!res.ok) console.warn('[limit-approvals] mail to %s not sent (%s): %s', to, event, res.reason);
    await patch(D.pool, r.id, { notified: out.slice(-40) });
  }
  return out;
}

const who2 = (p) => esc(p.name || p.email);

// ───────────────────────── Anthropic apply ─────────────────────────
/* Set the cap, read it back, and say exactly what happened. Never lowers a cap:
 * if somebody already put the person at or above the approved total, nothing is
 * written and that is reported as such. `beforeWrite` runs after the decision to
 * write and before the write; if it throws, nothing is written. */
async function applyInAnthropic(D, r, beforeWrite) {
  const target = Number(r.requested_cents);
  const row = await memberRow(D.pool, r.requester_email);
  if (!row || !row.userId) return { ok: false, error: r.requester_email + ' is not a Claude member on record, so there is no account to change.' };
  const before = await anthropic.effective(row.userId);
  if (!before.ok) return { ok: false, error: 'Could not read the current limit: ' + before.error };
  if (!before.row) return { ok: false, error: 'Anthropic returned no monthly limit for this account.' };
  const b = before.row;
  // An earlier attempt on this request wrote down that it was about to write. Exactly
  // the approved total as a per-user cap means that write landed before the attempt
  // stopped: it is this request's, and is recorded rather than written again.
  if (r.apply_method === 'writing' && !b.unlimited && b.amountCents === target && b.sourceType === 'user') {
    return { ok: true, method: 'recovered', before: null, after: b, userId: row.userId };
  }
  if (b.unlimited) return { ok: true, method: 'none', note: 'The account already has no monthly cap; nothing was changed.', before: b, after: b, userId: row.userId };
  if (b.amountCents != null && b.amountCents >= target) {
    return { ok: true, method: 'none', note: 'The account is already at ' + money(b.amountCents) + ', at or above the approved total; nothing was changed.', before: b, after: b, userId: row.userId };
  }
  if (beforeWrite) {
    try { await beforeWrite({ userId: row.userId, before: b }); }
    catch (e) { return { ok: false, error: 'Could not record the change before making it, so nothing was written: ' + e.message, before: b, userId: row.userId }; }
  }
  let method = 'upsert', reqId = null, w;
  const pend = await anthropic.pendingRequests(row.userId);
  if (pend.ok && pend.rows.length) {
    reqId = pend.rows[0].id;
    w = await anthropic.approveRequest(reqId, target);
    method = 'approve_request';
    if (!w.ok) { method = 'upsert'; w = await anthropic.setUserLimit(row.userId, target); }
  } else {
    w = await anthropic.setUserLimit(row.userId, target);
  }
  if (!w.ok) return { ok: false, error: w.error, before: b, userId: row.userId };
  const after = await anthropic.effective(row.userId);
  if (!after.ok || !after.row) return { ok: false, error: 'The write was accepted but the new limit could not be read back: ' + (after.error || 'no row'), before: b, userId: row.userId, written: true };
  if (after.row.amountCents !== target || after.row.sourceType !== 'user') {
    return { ok: false, error: 'Anthropic reads the limit back as ' + money(after.row.amountCents) + ' (' + (after.row.sourceType || 'unknown') + '), not ' + money(target) + '.', before: b, userId: row.userId, written: true };
  }
  return { ok: true, method, before: b, after: after.row, userId: row.userId, requestId: method === 'approve_request' ? reqId : null };
}

/* The cap to go back to on the 1st. When the cap being replaced was itself set by
 * an earlier My Profile raise that has not been reset yet, the ORIGINAL prior is
 * carried forward and the earlier row is marked superseded, so a self-raise
 * followed by a manager raise still resets to where the person started. */
async function priorFor(pool, r, before) {
  const [[chain]] = await pool.query(
    `SELECT id, applied_cents, prior_source, prior_override_cents, prior_amount_cents FROM claude_limit_approval
      WHERE requester_email = ? AND status = 'approved' AND reset_state IS NULL AND applied_cents IS NOT NULL AND id <> ?
      ORDER BY applied_at DESC LIMIT 1`, [r.requester_email, r.id]);
  if (chain && before.sourceType === 'user' && Number(chain.applied_cents) === before.amountCents) {
    return { source: chain.prior_source, override: chain.prior_override_cents == null ? null : Number(chain.prior_override_cents),
      amount: chain.prior_amount_cents == null ? null : Number(chain.prior_amount_cents), supersedes: chain.id };
  }
  return { source: before.sourceType, override: before.sourceType === 'user' ? before.amountCents : null, amount: before.amountCents, supersedes: null };
}

/* A recovered write: the prior was written down before it, so use that. The earlier
 * raise it carried forward (if any) is the unreset one with the same prior. */
async function recoveredPrior(pool, r) {
  const p = { source: r.prior_source, override: r.prior_override_cents == null ? null : Number(r.prior_override_cents),
    amount: r.prior_amount_cents == null ? null : Number(r.prior_amount_cents), supersedes: null };
  const [[chain]] = await pool.query(
    `SELECT id FROM claude_limit_approval
      WHERE requester_email = ? AND status = 'approved' AND reset_state IS NULL AND applied_cents IS NOT NULL AND id <> ?
        AND prior_source <=> ? AND prior_override_cents <=> ? AND prior_amount_cents <=> ?
      ORDER BY applied_at DESC LIMIT 1`, [r.requester_email, r.id, p.source, p.override, p.amount]);
  if (chain) p.supersedes = chain.id;
  return p;
}

/* Mail that belongs to the approving STEP, not to the outcome: a functional leader
 * approving the final step gets their own confirmation (Jeramy 2026-09-25: a leader
 * approval mails the person, the manager and the leader; a manager approval only the
 * person and the manager). Worked out from the row, so a retry after a failed apply
 * sends exactly what the first attempt would have. */
function stepMail(r, actor, ticket) {
  const out = [], total = money(Number(r.requested_cents)), person = esc(r.requester_name || r.requester_email);
  const byManager = r.manager_decided_by === actor.email, byLeader = r.leader_decided_by === actor.email;
  if (r.band === 'leader' && byLeader && !byManager) {
    out.push({ to: actor.email, subject: 'You approved ' + (r.requester_name || r.requester_email) + '\'s Claude limit of ' + total,
      html: mailHtml('Your approval was applied', [
        'You approved a Claude monthly limit of <b>' + total + '</b> for ' + person + '. It is set in Anthropic.',
        'Service Desk ticket ' + esc(ticket.display) + '.'], null) });
  }
  return out;
}

/* The seat owner's own copy when they approved somebody else's request (stage S, pick b). */
function ownerMail(r, so, actor, ticket, res) {
  if (so === r.requester_email) return [];
  const total = money(Number(r.requested_cents)), person = esc(r.requester_name || r.requester_email);
  return [{ to: so, subject: 'You approved ' + (r.requester_name || r.requester_email) + '\'s Claude limit of ' + total,
    html: mailHtml('Your approval was applied', [
      'You approved a Claude monthly limit of <b>' + total + '</b> for ' + person + ' as a Claude seat owner. '
        + (res.method === 'none' ? esc(res.note) : 'It is set in Anthropic.'),
      (actor.by && actor.by !== actor.email ? 'The write to Anthropic was retried by ' + esc(actor.by) + '. ' : '') + 'Service Desk ticket ' + esc(ticket.display) + '.'], null) }];
}

/* The last step of every successful chain: apply, record, update + close the
 * ticket, mail. `ticket` is the ticket this action already filed. */
async function finish(D, id, actor, ticket) {
  let r = await getRow(D.pool, id);
  let prior = null;
  const res = await applyInAnthropic(D, r, async (w) => {
    prior = await priorFor(D.pool, r, w.before);
    // Written down BEFORE the cap changes. If the hub stops between the write and the
    // 'approved' row below, a resume can tell this write from anybody else's and still
    // knows the cap to go back to. Left in place if the write fails: it may have landed.
    await patch(D.pool, id, { apply_method: 'writing', anthropic_user_id: w.userId,
      prior_source: prior.source, prior_override_cents: prior.override, prior_amount_cents: prior.amount });
  });
  if (!res.ok) {
    const reason = String(res.error || 'unknown').slice(0, 480);
    // apply_failed may be retried at once, so it is set last: a retry cannot start while
    // this attempt is still noting the ticket and would then overwrite what the retry recorded.
    await addTicket(D.pool, id, ticket);
    try { await within(SDP_MS, D.sdp.addNoteToTicket(ticket.id, (res.written ? 'Anthropic limit change NOT confirmed: ' : 'Anthropic limit NOT changed: ') + reason + '\nThe ticket is left open. Retry from My Profile, or set the limit in the Claude admin console and close this ticket.', false), 'SDP'); } catch (e) {}
    await patch(D.pool, id, { status: 'apply_failed', fail_reason: reason });
    return { ok: false, error: reason, written: !!res.written, row: await getRow(D.pool, id) };
  }
  if (res.method === 'none') prior = null;
  else if (res.method === 'recovered') prior = await recoveredPrior(D.pool, r);
  const fields = {
    status: 'approved', applied_at: sqlNow(), applied_by: actor.by || actor.email, apply_method: res.method, fail_reason: null, anthropic_user_id: res.userId || null,
    applied_cents: res.method === 'none' ? null : Number(r.requested_cents),
    spend_limit_id: res.after && res.after.spendLimitId, increase_request_id: res.requestId || null,
    prior_source: prior ? prior.source : null, prior_override_cents: prior ? prior.override : null, prior_amount_cents: prior ? prior.amount : null,
    reset_state: res.method === 'none' ? 'not_applicable' : null,
  };
  await patch(D.pool, id, fields);
  if (prior && prior.supersedes) await patch(D.pool, prior.supersedes, { reset_state: 'superseded', reset_detail: 'replaced by request #' + id, reset_at: sqlNow() });
  r = await getRow(D.pool, id);

  const backOn = nextFirst().toISOString().slice(0, 10);
  const lines = appliedLines(r, res, prior, actor, backOn);
  await noteAndClose(D, ticket, lines.join('\n'), appliedResolution(r, lines));
  await addTicket(D.pool, id, ticket);
  r = await getRow(D.pool, id);
  await mailAll(D, r, 'applied', appliedMail(r, res, prior, actor, ticket, backOn));
  return { ok: true, row: await getRow(D.pool, id), method: res.method };
}

/* What the final ticket says about the result. Without res.before (the hourly job writing it
 * up afterwards, stage U) the row has the result but not what Anthropic read before it. */
function appliedLines(r, res, prior, actor, backOn) {
  const back = 'Returns to ' + (prior && prior.override != null ? money(prior.override) + ' (their prior individual cap)' : 'the inherited default') + ' on ' + backOn + '.';
  const lines = res.method === 'none'
    ? ['Anthropic: ' + res.note]
    : res.method === 'recovered'
      ? ['Anthropic: monthly limit reads ' + money(res.after.amountCents) + ' (user override ' + (res.after.spendLimitId || '?') + ').',
         'Method: written by an earlier attempt on this request that stopped before recording it; read back and verified on resume, not written again.', back]
      : [(res.before ? 'Anthropic: monthly limit changed from ' + money(res.before.amountCents) + ' (' + (res.before.sourceType || '?') + ') to ' : 'Anthropic: monthly limit set to ') + money(res.after.amountCents) + ' (user override ' + (res.after.spendLimitId || '?') + ').',
         'Method: ' + (res.method === 'approve_request' ? 'approved the person\'s pending Claude increase request ' + res.requestId : 'set a per-user limit') + '. Read back and verified.', back];
  const so = standIn(r), own = !!so && so === r.requester_email;
  if (so) lines.unshift('Approved by ' + so + ' (Claude seat owner' + (own ? ', their own request' : '') + ').');
  if (actor.by && actor.by !== actor.email) lines.push('Retried by ' + actor.by + ' (Claude seat owner) after the earlier write to Anthropic failed.');
  return lines;
}
const appliedResolution = (r, lines) => 'Claude monthly limit for ' + r.requester_email + ' set to ' + money(Number(r.requested_cents)) + ' in Anthropic. ' + lines.join(' ');

/* The result mail, worked out from the row and the result, so the hourly job sends exactly
 * what the stopped step would have to anybody it had not reached. */
function appliedMail(r, res, prior, actor, ticket, backOn) {
  const so = standIn(r), own = !!so && so === r.requester_email;
  const person = { email: r.requester_email, name: r.requester_name };
  const newTotal = money(Number(r.requested_cents));
  const msgs = [];
  if (res.method !== 'none') {
    msgs.push({ to: person.email, subject: 'Your Claude monthly limit is now ' + newTotal,
      html: mailHtml('Your Claude limit was increased', [
        'Hi ' + esc(first(person.name)) + ',',
        'Your Claude monthly spend limit is now <b>' + newTotal + '</b>' + (r.current_limit_cents != null ? ' (was ' + money(Number(r.current_limit_cents)) + ')' : '') + '. It is in effect now.',
        own ? 'You approved it yourself as a Claude seat owner.' : actor.email === person.email ? 'You raised it yourself from My Profile.' : 'Approved by ' + who2(actor) + (so ? ' (Claude seat owner)' : '') + '.',
        'It returns to ' + (prior && prior.amount != null ? money(prior.amount) : 'your previous limit') + ' on ' + backOn + '. Service Desk ticket ' + esc(ticket.display) + '.',
      ], 'Open My Profile') });
    if (r.manager_email) {
      msgs.push({ to: r.manager_email, subject: 'Done: ' + (person.name || person.email) + '\'s Claude limit is now ' + newTotal,
        html: mailHtml('Claude limit increase completed', [
          esc(person.name || person.email) + '\'s Claude monthly limit was increased to <b>' + newTotal + '</b> and is in effect now.',
          own ? 'They approved it themselves as a Claude seat owner.' : actor.email === person.email ? 'They used their one self-raise for this month, which does not need approval.' : 'Approved by ' + who2(actor) + (so ? ' (Claude seat owner)' : '') + '.',
          'Logged on Service Desk ticket ' + esc(ticket.display) + '. It returns to the prior limit on the 1st.',
        ], 'Open My Profile') });
    }
  } else {
    msgs.push({ to: person.email, subject: 'Your Claude limit request #' + r.id + ' was approved',
      html: mailHtml('Your Claude limit request was approved', [esc(res.note), 'Service Desk ticket ' + esc(ticket.display) + '.'], 'Open My Profile') });
    // The manager hears about the outcome whether or not Anthropic needed changing.
    if (r.manager_email) {
      msgs.push({ to: r.manager_email, subject: 'Done: ' + (person.name || person.email) + '\'s Claude limit request #' + r.id + ' was approved',
        html: mailHtml('Claude limit request approved', [
          esc(person.name || person.email) + '\'s request for a Claude monthly limit of <b>' + newTotal + '</b> was approved' + (own ? ' (they approved it themselves as a Claude seat owner).' : actor.email === person.email ? ' (their one self-raise for this month).' : ' by ' + who2(actor) + (so ? ' (Claude seat owner).' : '.')),
          esc(res.note),
          'Logged on Service Desk ticket ' + esc(ticket.display) + '.',
        ], 'Open My Profile') });
    }
  }
  // A seat owner stands in for the missing approver and gets the approver's copy; the
  // functional leader is mailed only when they approved (stepMail).
  (so ? ownerMail(r, so, actor, ticket, res) : stepMail(r, actor, ticket)).forEach(m => msgs.push(m));
  return msgs;
}

/* Ticket, then mail, then the status: until the row says 'escalated' it can be resumed,
 * and a resume reuses the recorded ticket and skips anybody already mailed. */
async function escalate(D, id, why, actor, resumed) {
  const cfg = config();
  let r = await getRow(D.pool, id);
  const text = ticketText(r, 'ESCALATED to the Service Desk: ' + why + '. Nothing has been changed in Anthropic.',
    ['', 'Please review and, if approved, set the monthly limit in the Claude admin console. This ticket is left OPEN.'].concat(resumed ? ['', RESUMED_NOTE] : []));
  let ticket = (jsonCol(r.tickets) || []).filter(t => t.action === 'escalation').pop() || null, err = null;
  if (!ticket) {
    try {
      ticket = await fileTicket(D, r, 'escalation', '[Claude spend] Limit request needs routing: ' + (r.requester_name || r.requester_email) + ' to ' + money(Number(r.requested_cents)) + '/mo', text, { email: r.requester_email, name: r.requester_name });
      await addTicket(D.pool, id, ticket);
    } catch (e) { err = D.sdp && D.sdp.sdpErrorText ? D.sdp.sdpErrorText(e) : e.message; }
  }
  const lines = [
    esc(r.requester_name || r.requester_email) + ' &lt;' + esc(r.requester_email) + '&gt; asked for a Claude monthly limit of <b>' + money(Number(r.requested_cents)) + '</b> (currently ' + money(r.current_limit_cents == null ? null : Number(r.current_limit_cents)) + ').',
    'It could not be routed: ' + esc(why) + '.',
    ticket ? 'Open Service Desk ticket: <a href="' + esc(ticket.url) + '">' + esc(ticket.display) + '</a>.' : '<b>The Service Desk ticket could not be filed</b> (' + esc(err) + ').',
    'Nothing has been changed in Anthropic.',
  ];
  await mailAll(D, r, 'escalated', cfg.escalation.map(to => ({ to, subject: '[Claude spend] Needs routing: ' + (r.requester_name || r.requester_email) + ' to ' + money(Number(r.requested_cents)) + '/mo' + (ticket ? ' (' + ticket.display + ')' : ''), html: mailHtml('Claude limit request needs routing', lines, null) })));
  // Only from the in-flight statuses: a request withdrawn meanwhile stays withdrawn.
  const took = await claim(D.pool, id, ['applying', 'pending_manager', 'forwarding'], { status: 'escalated', fail_reason: (why + (err ? ' | ticket not filed: ' + err : '')).slice(0, 480) });
  r = await getRow(D.pool, id);
  // Withdrawn while it was being routed (stage T): nothing is left to route, so its ticket is closed.
  const dropped = !took && r.status === 'cancelled';
  if (dropped && ticket && !ticket.closed) {
    await noteAndClose(D, ticket, 'Withdrawn by ' + r.requester_email + ' in My Profile while this was being routed. Nothing to do: nothing was changed in Anthropic.',
      'Request withdrawn by ' + r.requester_email + ' before it was routed; nothing changed in Anthropic.');
    await addTicket(D.pool, id, ticket);
    r = await getRow(D.pool, id);
  }
  D.rbac.audit(D.req, 'claude_limit_escalated', r.requester_email, 'my-profile', { id, why, ticket: ticket && ticket.display, by: actor && actor.email, resumed: !!resumed, withdrawn: dropped || undefined });
  return r;
}

/* Manager approval on a leader-band request, with the row already 'forwarding': log it
 * on its own ticket (closed), then hand it to the functional leader, or to the Service
 * Desk when there is none. The leader is mailed BEFORE the row moves to pending_leader,
 * so an interruption leaves it resumable rather than parked with nobody told. */
async function forward(D, id, me, resumed) {
  const cfg = config();
  let r = await getRow(D.pool, id);
  let ticket = (jsonCol(r.tickets) || []).filter(t => t.action === 'manager').pop() || null;
  if (!ticket) {
    try {
      ticket = await fileTicket(D, r, 'manager', '[Claude spend] Manager approved, pending functional leader: ' + (r.requester_name || r.requester_email) + ' to ' + money(Number(r.requested_cents)) + '/mo',
        ticketText(r, 'Manager approval by ' + r.manager_decided_by + '. More than +' + money(cfg.managerRaise * 100) + ' over the limit they started the month with, so the functional leader approves next. Nothing is changed in Anthropic at this step.', resumed ? ['', RESUMED_NOTE] : []), me);
    } catch (e) {
      await patch(D.pool, id, { status: 'pending_manager', manager_decided_by: null, manager_decided_at: null });
      return { sdpFailed: true };
    }
    await addTicket(D.pool, id, ticket);
  }
  if (!('closeError' in ticket)) {
    await noteAndClose(D, ticket, 'Manager approval recorded; forwarded to ' + (r.leader_email || 'the Service Desk') + '.', 'Manager approval logged for ' + r.requester_email + '; awaiting functional leader.');
    await addTicket(D.pool, id, ticket);
  }
  if (!r.leader_email) return { escalated: true, ticket, row: await escalate(D, id, 'no functional leader to give the final approval', me, resumed) };
  await mailAll(D, r, 'forwarded', [{ to: r.leader_email,
    subject: 'Approval needed: ' + (r.requester_name || r.requester_email) + ' - Claude limit ' + money(Number(r.requested_cents)),
    html: mailHtml('Claude limit approval needed', [
      who2(me) + ' approved a Claude monthly limit of <b>' + money(Number(r.requested_cents)) + '</b> for ' + esc(r.requester_name || r.requester_email) + ' (currently ' + money(r.current_limit_cents == null ? null : Number(r.current_limit_cents)) + ').',
      'A raise of more than +' + money(cfg.managerRaise * 100) + ' over their limit at the start of the month needs your approval as functional leader. Logged on Service Desk ticket ' + esc(ticket.display) + '.',
    ], 'Review the request') }]);
  await patch(D.pool, id, { status: 'pending_leader' });
  return { forwarded: true, ticket, row: await getRow(D.pool, id) };
}

/* The ticket for the approval that completes the chain, worked out from the row so a
 * resume files what the interrupted step would have. */
function finalTicket(r, by) {
  const who = r.requester_name || r.requester_email, total = money(Number(r.requested_cents));
  const so = standIn(r);
  if (so) {
    // An escalated request is finished on its escalation ticket (noted and closed below).
    const own = so === r.requester_email, onEsc = (jsonCol(r.tickets) || []).some(t => t.action === 'escalation');
    const label = 'Claude seat owner approval' + (own ? ' (their own request)' : '');
    return { kind: onEsc ? 'escalation' : 'seat_owner', subject: '[Claude spend] ' + label + ': ' + who + ' to ' + total + '/mo',
      text: ticketText(r, 'Approved by ' + by + ' (Claude seat owner' + (own ? ': their own request, which needs no other approval' : '') + '). The limit is set in Anthropic now and the result is written below before this ticket closes.') };
  }
  if (r.band === 'self') {
    return { kind: 'self', subject: '[Claude spend] Self-raise: ' + who + ' ' + money(Number(r.current_limit_cents)) + ' to ' + total + '/mo',
      text: ticketText(r, 'Self-raise from ' + money(Number(r.current_limit_cents)) + ' by ' + by + ': the one raise a month the person approves themselves. No approval is required; the manager is notified.') };
  }
  const kind = finalAction(r);
  const label = kind === 'leader' ? 'Functional leader approval' : (r.band === 'leader' ? 'Manager approval (also the functional leader)' : 'Manager approval');
  return { kind, subject: '[Claude spend] ' + label + ': ' + who + ' to ' + total + '/mo',
    text: ticketText(r, label + ' by ' + by + '. The limit is set in Anthropic now and the result is written below before this ticket closes.') };
}

/* A denial's ticket texts and mail, shared by the deny route and the hourly job. `by` is the decider's email. */
function denyTexts(r, by, reason, asOwner) {
  const b = by + (asOwner ? ' (Claude seat owner)' : '');
  return {
    subject: '[Claude spend] Denied: ' + (r.requester_name || r.requester_email) + ' to ' + money(Number(r.requested_cents)) + '/mo',
    text: ticketText(r, 'DENIED by ' + b + '. Reason: ' + reason + '. Nothing was changed in Anthropic.'),
    note: 'Denied by ' + b + ': ' + reason + (asOwner ? '\nNothing was changed in Anthropic.' : ''),
    resolution: 'Claude limit request denied by ' + b + '. Reason: ' + reason,
  };
}
function denyMail(r, me, reason, asOwner, ticket) {
  return { to: r.requester_email, subject: 'Your Claude limit request was not approved',
    html: mailHtml('Your Claude limit request was not approved', [
      'Your request to raise your Claude monthly limit to <b>' + money(Number(r.requested_cents)) + '</b> was not approved by ' + who2(me) + (asOwner ? ' (Claude seat owner)' : '') + '.',
      'Reason: ' + esc(reason),
      'Your limit stays at ' + money(r.current_limit_cents == null ? null : Number(r.current_limit_cents)) + '.' + (ticket ? ' Logged on Service Desk ticket ' + esc(ticket.display) + '.' : ''),
    ], 'Open My Profile') };
}

// ───────────────────────── stage U: finished by the hourly job ─────────────────────────
const lastTicket = (r, action) => (jsonCol(r.tickets) || []).filter(t => t.action === action).pop() || null;
const hasEvent = (r, event, to) => (jsonCol(r.notified) || []).some(x => x.event === event && (!to || x.to === lc(to)));
// The step's own approver denied it (the manager while it waited on them, the leader while it
// waited on them); otherwise a seat owner denied it with the Service Desk (the route's asOwner).
const deniedByStep = (r) => (!!r.manager_email && r.denied_by === r.manager_email && !r.manager_decided_by)
  || (!!r.leader_email && r.denied_by === r.leader_email && !!r.manager_decided_by);
const NONE_NOTE = 'The account was already at or above the approved total, or had no monthly cap; nothing was changed.';
// The result as the row keeps it (what Anthropic read before the write is not kept).
const appliedRes = (r) => ({ method: r.apply_method, before: null, note: NONE_NOTE, requestId: r.increase_request_id,
  after: { amountCents: r.applied_cents == null ? null : Number(r.applied_cents), spendLimitId: r.spend_limit_id } });
const priorOf = (r) => (r.apply_method === 'none' ? null : { source: r.prior_source,
  override: r.prior_override_cents == null ? null : Number(r.prior_override_cents), amount: r.prior_amount_cents == null ? null : Number(r.prior_amount_cents) });
async function personOf(pool, email, r) {
  const p = await realPerson(pool, email).catch(() => null);
  const onRow = email === r.leader_email ? r.leader_name : email === r.manager_email ? r.manager_name : email === r.requester_email ? r.requester_name : null;
  return { email, name: (p && p.name) || onRow || email };
}

/* What a decided row still lacks, from the row alone: null when nothing. A ticket with a
 * closeError key was closed or tried; anybody with any mail event for it was mailed or tried. */
function wrapPlan(r) {
  if (r.status === 'approved') {
    const approver = resumerOf(r);
    const ticket = lastTicket(r, finalTicket(r, approver).kind);
    if (!ticket) return null;
    const close = !('closeError' in ticket) ? [ticket] : [];
    // Nobody is told about a raise that was already reset or replaced.
    const mailOk = r.reset_state == null || r.reset_state === 'not_applicable';
    const actor = { email: approver, name: approver, by: r.applied_by && r.applied_by !== approver ? r.applied_by : undefined };
    const mail = !mailOk ? [] : [...new Set(appliedMail(r, appliedRes(r), priorOf(r), actor, ticket, r.back_on).map(m => lc(m.to)))].filter(to => !hasEvent(r, 'applied', to));
    return close.length || mail.length ? { close, mail, file: false } : null;
  }
  if (r.status === 'denied') {
    const asOwner = !deniedByStep(r);
    const ticket = (asOwner && lastTicket(r, 'escalation')) || lastTicket(r, 'denied');
    // The deny route records a ticket it could not file; that is not tried again.
    const file = !ticket && !/^deny ticket not filed/.test(r.fail_reason || '');
    const close = ticket && !('closeError' in ticket) ? [ticket] : [];
    const mail = hasEvent(r, 'denied') ? [] : [r.requester_email];
    return file || close.length || mail.length ? { close, mail, file, asOwner } : null;
  }
  if (r.status === 'cancelled') {
    const close = (jsonCol(r.tickets) || []).filter(t => t.action !== 'reset' && !t.closed && !('closeError' in t));
    return close.length ? { close, mail: [], file: false } : null;
  }
  return null;
}
const wrapWhat = (p) => [p.file ? 'file the denial ticket' : null, p.close.length ? 'note and close ' + p.close.map(t => t.display).join(', ') : null,
  p.mail.length ? 'mail ' + p.mail.join(', ') : null].filter(Boolean).join('; ');

/* The earlier unreset raise whose prior this one carried (finish marks it superseded right
 * after 'approved'; a stop in between leaves it due): an earlier request of theirs (one open
 * request per person, so ids are in order), same prior. */
async function supersedeEarlier(pool, r) {
  if (r.applied_cents == null || r.reset_state != null) return;
  const [[chain]] = await pool.query(
    `SELECT id FROM claude_limit_approval
      WHERE requester_email = ? AND status = 'approved' AND reset_state IS NULL AND applied_cents IS NOT NULL AND id < ?
        AND prior_source <=> ? AND prior_override_cents <=> ? AND prior_amount_cents <=> ?
      ORDER BY applied_at DESC, id DESC LIMIT 1`, [r.requester_email, r.id, r.prior_source, r.prior_override_cents, r.prior_amount_cents]);
  if (chain) await pool.query("UPDATE claude_limit_approval SET reset_state = 'superseded', reset_detail = ?, reset_at = ? WHERE id = ? AND reset_state IS NULL", ['replaced by request #' + r.id, sqlNow(), chain.id]);
}

async function wrapOne(D, r, p) {
  if (r.status === 'approved') {
    const approver = resumerOf(r), actor = await personOf(D.pool, approver, r);
    if (r.applied_by && r.applied_by !== approver) actor.by = r.applied_by;
    const res = appliedRes(r), prior = priorOf(r);
    const ticket = p.close[0] || lastTicket(r, finalTicket(r, approver).kind);
    if (p.close.length) {
      await supersedeEarlier(D.pool, r);
      const lines = appliedLines(r, res, prior, actor, r.back_on);
      await noteAndClose(D, ticket, lines.concat([SWEPT]).join('\n'), appliedResolution(r, lines));
      await addTicket(D.pool, r.id, ticket);
    }
    const want = new Set(p.mail);
    if (want.size) await mailAll(D, r, 'applied', appliedMail(r, res, prior, actor, ticket, r.back_on).filter(m => want.has(lc(m.to))));
    return;
  }
  if (r.status === 'denied') {
    const me = await personOf(D.pool, r.denied_by, r), reason = r.deny_reason || '';
    const dt = denyTexts(r, r.denied_by, reason, p.asOwner);
    let ticket = p.close[0] || (p.asOwner && lastTicket(r, 'escalation')) || lastTicket(r, 'denied');
    if (p.file) {
      try {
        ticket = await fileTicket(D, r, 'denied', dt.subject, dt.text + '\n\n' + RESUMED_NOTE, me);
        await addTicket(D.pool, r.id, ticket);
      } catch (e) {
        ticket = null;
        await patch(D.pool, r.id, { fail_reason: ('deny ticket not filed: ' + (D.sdp.sdpErrorText ? D.sdp.sdpErrorText(e) : e.message)).slice(0, 480) });
      }
    }
    if (ticket && (p.file || p.close.length)) {
      await noteAndClose(D, ticket, dt.note + '\n' + SWEPT, dt.resolution);
      await addTicket(D.pool, r.id, ticket);
    }
    if (p.mail.length) await mailAll(D, r, 'denied', [denyMail(r, me, reason, p.asOwner, ticket)]);
    return;
  }
  // cancelled: nobody is mailed about a withdraw
  const said = r.apply_method === 'writing'
    ? 'Anthropic was checked when it was withdrawn and did not show the requested limit, so nothing from this request is in effect.'
    : 'Nothing was written to Anthropic for this request.';
  for (const t of p.close) {
    await noteAndClose(D, t, 'Withdrawn by ' + r.requester_email + ' in My Profile. ' + said + '\n' + SWEPT, 'Request withdrawn by ' + r.requester_email + '. ' + said);
    await addTicket(D.pool, r.id, t);
  }
}

/* Run by the hourly reset job: finish the wrap-up of a decision whose step stopped part-way.
 * Only rows decided since WRAP_SINCE and in the last WRAP_DAYS days, idle STALE_S (a live step
 * writes its row far more often), taken with claimStale so two runs cannot both do it. A row
 * with nothing missing is not touched. With `dry`, says what it would do and writes nothing. */
async function wrapStopped(D, opt) {
  const o = opt || {}, log = o.log || (() => {});
  const out = { due: 0, finished: 0 };
  if (!D.sdp || !D.sdp.createTicket) { log('wrap-up check skipped: the Service Desk integration is not available'); return out; }
  const since = new Date(Math.max(Date.parse(WRAP_SINCE.replace(' ', 'T') + 'Z'), Date.now() - WRAP_DAYS * 86400e3)).toISOString().slice(0, 19).replace('T', ' ');
  const [rows] = await D.pool.query(
    `SELECT ${ROW_COLS}, DATE_FORMAT(applied_at + INTERVAL 1 MONTH, '%Y-%m-01') AS back_on FROM claude_limit_approval
      WHERE ((status = 'approved' AND applied_at >= ? AND NOT (applied_by <=> ?)) OR (status = 'denied' AND denied_at >= ?) OR (status = 'cancelled' AND cancelled_at >= ?))
        AND updated_at <= NOW() - INTERVAL ${STALE_S} SECOND
      ORDER BY id LIMIT 500`, [since, JOB, since, since]);
  for (const r0 of rows) {
    if (!wrapPlan(r0)) continue;
    out.due++;
    if (o.dry) { log('would finish #' + r0.id + ' (' + r0.status + '): ' + wrapWhat(wrapPlan(r0))); continue; }
    if (!(await claimStale(D.pool, r0.id, r0.status))) { log('#' + r0.id + ' was taken by somebody else just now; left'); continue; }
    const r = await getRow(D.pool, r0.id);
    if (!r) continue;
    r.back_on = r0.back_on;
    const p = wrapPlan(r);
    if (!p) continue;
    await wrapOne(D, r, p);
    out.finished++;
    log('finished #' + r.id + ' (' + r.status + '): ' + wrapWhat(p));
  }
  return out;
}

/* Run by the hourly reset job in the first LANDED_HOURS of a month: a raise from an earlier
 * month marked failed, or stopped while applying, whose write to Anthropic DID land (the
 * pre-write marker apply_method 'writing', and Anthropic reads exactly the requested total as
 * a per-user cap) is recorded as approved, dated when the row last moved, so the reset that
 * follows puts it back with the rest. Only a row that has not moved since the month began.
 * Its open tickets are noted and closed; nobody is mailed here (the reset mails the person).
 * Anthropic not answering counts as `later` (the next hour tries again). */
async function recordLanded(D, opt) {
  const o = opt || {}, log = o.log || (() => {}), now = o.now || new Date();
  const out = { recorded: 0, left: 0, later: 0 };
  const into = Math.floor((now.getTime() - Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)) / 1000);
  if (into >= LANDED_HOURS * 3600) return out;
  const [rows] = await D.pool.query(
    `SELECT ${ROW_COLS}, DATE_FORMAT(UTC_TIMESTAMP() - INTERVAL TIMESTAMPDIFF(SECOND, updated_at, NOW()) SECOND, '%Y-%m-%d %H:%i:%s') AS touched_utc
       FROM claude_limit_approval
      WHERE apply_method = 'writing' AND reset_state IS NULL
        AND (status = 'apply_failed' OR (status = 'applying' AND updated_at <= NOW() - INTERVAL ${STALE_S} SECOND))
        AND TIMESTAMPDIFF(SECOND, updated_at, NOW()) > ?
      ORDER BY id LIMIT 50`, [into]);
  for (const r of rows) {
    const was = r.status === 'apply_failed' ? 'failed' : 'stopped while applying';
    const uid = r.anthropic_user_id || ((await memberRow(D.pool, r.requester_email)) || {}).userId;
    if (!uid) { out.left++; log('#' + r.id + ' (' + was + ') left: no Claude account on record for ' + r.requester_email); continue; }
    const cur = await anthropic.effective(uid);
    if (!cur.ok || !cur.row) { out.later++; log('#' + r.id + ' (' + was + ') could not be checked with Anthropic (' + (cur.error || 'no limit row') + '); tried again next hour'); continue; }
    const c = cur.row, want = Number(r.requested_cents);
    if (c.unlimited || c.amountCents !== want || c.sourceType !== 'user') {
      out.left++; log('#' + r.id + ' (' + was + ') left: Anthropic reads ' + (c.unlimited ? 'no cap' : money(c.amountCents)) + ' (' + (c.sourceType || '?') + '), not the requested ' + money(want)); continue;
    }
    if (o.dry) { out.recorded++; log('would record #' + r.id + ' (' + was + '): its write landed (' + money(want) + ' per-user cap), and reset it with the rest'); continue; }
    const [u] = await D.pool.query(
      `UPDATE claude_limit_approval SET status = 'approved', apply_method = 'recovered', applied_cents = requested_cents, applied_at = ?, applied_by = ?,
              fail_reason = NULL, anthropic_user_id = ?, spend_limit_id = ?
        WHERE id = ? AND status = ? AND apply_method = 'writing' AND reset_state IS NULL AND TIMESTAMPDIFF(SECOND, updated_at, NOW()) >= ?`,
      [r.touched_utc, JOB, uid, c.spendLimitId || null, r.id, r.status, Number(r.idle_s)]);
    if (u.affectedRows !== 1) { out.left++; log('#' + r.id + ' moved while it was checked; left'); continue; }
    const row = await getRow(D.pool, r.id);
    await supersedeEarlier(D.pool, row);
    const note = 'Anthropic reads the requested ' + money(want) + ' as a per-user cap (checked by the monthly reset on ' + now.toISOString().slice(0, 10) + '): the write for this request went through before it was marked '
      + (r.status === 'apply_failed' ? 'failed' : 'stopped') + '. Recorded as applied by the hourly Claude limit job, so it is put back with the other ' + monthName(r.period) + ' raises.';
    for (const t of (jsonCol(row.tickets) || []).filter(x => x.action !== 'reset' && !x.closed && !('closeError' in x))) {
      await noteAndClose(D, t, note, 'Claude monthly limit for ' + r.requester_email + ' reached ' + money(want) + ' in Anthropic; recorded by the monthly reset and put back on the 1st.');
      await addTicket(D.pool, r.id, t);
    }
    out.recorded++;
    log('#' + r.id + ' recorded (' + was + '): its write landed (' + money(want) + ' per-user cap); reset with the rest');
  }
  return out;
}

// ───────────────────────── routes ─────────────────────────
function register(router, deps) {
  const { pool, rbac, sdp, mailGraph, who, needUser, viewSubject } = deps;
  const json = express.json({ limit: '4kb' });
  const Dfor = (req) => ({ pool, rbac, sdp, mailGraph, req });
  // req.user carries the email only; the name on tickets and mail comes from the directory.
  const actorOf = async (req) => { const e = who(req); const p = await realPerson(pool, e).catch(() => null); return { email: e, name: (p && p.name) || e }; };
  const off = (res) => res.status(409).json({ error: 'Claude limit requests are switched off in the admin console.', code: 'APPROVALS_OFF' });
  const idOf = (req) => { const n = Number(req.params.id); return Number.isInteger(n) && n > 0 ? n : null; };

  // Mine: current limit, what I can do, my open request, my history.
  router.get('/claude-limit', async (req, res) => {
    if (!needUser(req, res)) return;
    try {
      const cfg = config();
      const v = await viewSubject(req);
      const email = v.email;
      if (v.viewingAs) rbac.audit(req, 'profile_claude_limit_view_other', email, 'my-profile', { via: v.viewingAs.via });
      const lim = await memberRow(pool, email);
      const [rows] = await pool.query(`SELECT ${ROW_COLS} FROM claude_limit_approval WHERE requester_email = ? ORDER BY id DESC LIMIT 12`, [email]);
      const open = rows.find(r => OPEN.indexOf(r.status) >= 0) || null;
      const escalatedThisMonth = rows.find(r => r.status === 'escalated' && r.period === monthKey()) || null;
      // The hourly feed can trail a raise made minutes ago, or a reset the job made on the
      // 1st; the rows we wrote cannot. Whichever of the two happened last, after the feed was read.
      let amountCents = lim ? lim.amountCents : null, fresh = false, freshSource = null;
      const at = (d) => (d ? new Date(d).getTime() : 0), feedAt = lim ? at(lim.fetchedAt) : 0;
      const lastApplied = rows.find(r => r.status === 'approved' && r.applied_cents != null && r.reset_state == null);
      const lastReset = rows.filter(r => r.reset_state === 'reset' && r.reset_at && (r.prior_override_cents != null || r.prior_amount_cents != null))
        .sort((x, y) => at(y.reset_at) - at(x.reset_at))[0];
      if (lim && lastApplied && lastApplied.applied_at && at(lastApplied.applied_at) > feedAt && !(lastReset && at(lastReset.reset_at) > at(lastApplied.applied_at))) {
        amountCents = Number(lastApplied.applied_cents); fresh = true; freshSource = 'user';
      } else if (lim && lastReset && at(lastReset.reset_at) > feedAt) {
        // The cap the job put back and read back: their own cap, or the inherited default as it was when raised.
        const own = lastReset.prior_override_cents != null;
        amountCents = Number(own ? lastReset.prior_override_cents : lastReset.prior_amount_cents); fresh = true;
        freshSource = own ? 'user' : (lastReset.prior_source || lim.sourceType);
      }
      const chain = await resolveChain(pool, email);
      const baseCents = await baseFor(pool, email, amountCents, fresh ? freshSource : lim && lim.sourceType);
      const used = await selfUsed(pool, email), raised = await selfUsed(pool, email, true);
      const due = await resetDue(pool, email);
      // The one-click raise: once a month, from the base, while nothing has been raised yet.
      const selfOK = amountCents != null && amountCents === baseCents && !raised;
      res.json({
        enabled: cfg.enabled, configSource: cfg.source,
        settings: { selfRaise: cfg.selfRaise, managerRaise: cfg.managerRaise },
        base: baseCents == null ? null : baseCents / 100, selfUsed: used, resetDue: due,
        selfTo: selfOK ? (baseCents + cfg.selfRaise * 100) / 100 : null,
        member: !!lim,
        limit: lim ? { amount: amountCents == null ? null : amountCents / 100, unlimited: lim && lim.amountCents == null && !fresh, source: fresh ? freshSource : lim.sourceType,
          spent: lim.ptdCents / 100, asOf: lim.fetchedAt, justApplied: fresh } : null,
        canSelfRaise: !!(cfg.enabled && lim && selfOK && !open && !escalatedThisMonth && !v.viewingAs),
        canRequest: !!(cfg.enabled && lim && amountCents != null && !open && !escalatedThisMonth && !v.viewingAs),
        manager: chain.manager, managerWhy: chain.managerWhy, leader: chain.leader, leaderWhy: chain.leaderWhy,
        // A seat owner's own raise applies when they send it (stage S, pick c).
        seatOwner: isOwner(cfg, email),
        open: open ? Object.assign(publicRow(open, email), { canRetry: !!cfg.enabled && !v.viewingAs && canRetry(open, email), canWithdraw: !v.viewingAs && withdrawable(open) }) : null,
        escalated: escalatedThisMonth ? publicRow(escalatedThisMonth, email) : null,
        history: rows.filter(r => r !== open).slice(0, 10).map(r => publicRow(r, email)),
        resetsOn: nextFirst().toISOString().slice(0, 10),
        viewingAs: v.viewingAs, viewAsDenied: v.viewAsDenied,
      });
    } catch (e) { console.error('[limit-approvals] GET /claude-limit', e.message); res.status(500).json({ error: 'Internal error' }); }
  });

  // Approver queue: waiting for me, what I am waiting on, what I decided.
  router.get('/claude-limit/queue', async (req, res) => {
    if (!needUser(req, res)) return;
    try {
      const v = await viewSubject(req);
      const me = v.email;
      if (v.viewingAs) rbac.audit(req, 'profile_claude_limit_queue_view_other', me, 'my-profile', { via: v.viewingAs.via });
      const cfg = config(), enabled = cfg.enabled, owner = cfg.seatOwners.indexOf(me) >= 0;
      const [forMe] = await pool.query(
        `SELECT ${ROW_COLS} FROM claude_limit_approval
          WHERE (status = 'pending_manager' AND manager_email = ?) OR (status = 'pending_leader' AND leader_email = ?)
          ORDER BY created_at ASC LIMIT 100`, [me, me]);
      const [waiting] = await pool.query(
        `SELECT ${ROW_COLS} FROM claude_limit_approval
          WHERE status IN ('pending_manager','forwarding','pending_leader','apply_failed','applying')
            AND (requester_email = ?
                 OR (manager_email = ? AND status <> 'pending_manager')
                 OR (leader_email = ? AND status IN ('applying','apply_failed'))
                 OR ((manager_decided_by = ? OR leader_decided_by = ?) AND status IN ('applying','apply_failed')))
          ORDER BY created_at ASC LIMIT 100`, [me, me, me, me, me]);
      const [decided] = await pool.query(
        `SELECT ${ROW_COLS} FROM claude_limit_approval
          WHERE manager_decided_by = ? OR leader_decided_by = ? OR denied_by = ?
          ORDER BY updated_at DESC LIMIT 20`, [me, me, me]);
      res.json({
        enabled,
        forMe: forMe.map(r => Object.assign(publicRow(r), { step: r.status === 'pending_manager' ? 'manager' : 'leader',
          forwards: r.status === 'pending_manager' && r.band === 'leader' && r.leader_email !== me })),
        waitingOn: waiting.map(r => Object.assign(publicRow(r), { waitingFor: r.status === 'pending_manager' ? r.manager_name || r.manager_email
          : r.status === 'pending_leader' ? r.leader_name || r.leader_email : null, canRetry: !!enabled && !v.viewingAs && (canRetry(r, me) || ownerRetry(cfg, r, me)) })),
        decided: decided.map(r => publicRow(r)),
        board: await board(cfg, me, owner, enabled && !v.viewingAs, forMe, waiting),
        viewingAs: v.viewingAs, viewAsDenied: v.viewAsDenied,
      });
    } catch (e) { console.error('[limit-approvals] GET /claude-limit/queue', e.message); res.status(500).json({ error: 'Internal error' }); }
  });

  /* The queue tabs (picks 12-15). Waiting on me: what I can act on now - my approvals,
   * and a step of mine (or, for a seat owner, any failed Anthropic write) to try again.
   * My team: requests from everybody under me in the reporting tree, view only (a row
   * waiting on me carries its buttons here too). All: every request, seat owners only.
   * History is HISTORY_DAYS; an open request shows however old it is. Every action is
   * the existing approve / deny / retry route, with its own checks and claims.
   * Stage S: a seat owner's Waiting on me also holds the escalated requests of the last
   * HISTORY_DAYS (approve or deny) and their own request still waiting on somebody. */
  async function board(cfg, me, owner, live, forMe, waiting) {
    const recent = `(created_at >= NOW() - INTERVAL ${HISTORY_DAYS} DAY OR status IN (${OPEN.map(x => "'" + x + "'").join(',')}))`;
    const deco = (r) => {
      const od = !(pendingOn(r, me) && r.requester_email !== me) && ownerDecides(cfg, r, me);
      return Object.assign(publicRow(r, me), {
        waitingFor: r.status === 'pending_manager' ? r.manager_name || r.manager_email : r.status === 'pending_leader' ? r.leader_name || r.leader_email : null,
        canDecide: !!live && ((pendingOn(r, me) && r.requester_email !== me) || od),
        // As a seat owner (stage S): Approve applies it now; Deny only on an escalated one.
        seatOwnerStep: !!live && od,
        forwards: !od && r.status === 'pending_manager' && r.band === 'leader' && r.leader_email !== me,
        canRetry: !!live && (canRetry(r, me) || ownerRetry(cfg, r, me)),
      });
    };
    const [team] = await pool.query(
      `WITH RECURSIVE tree (email, depth) AS (
         SELECT email, 1 FROM org_reporting_person WHERE manager_email = ?
         UNION ALL
         SELECT p.email, t.depth + 1 FROM org_reporting_person p JOIN tree t ON p.manager_email = t.email WHERE t.depth < 12)
       SELECT ${ROW_COLS} FROM claude_limit_approval
        WHERE requester_email IN (SELECT email FROM tree) AND requester_email <> ? AND ${recent}
        ORDER BY created_at DESC LIMIT 300`, [me, me]);
    const [all] = owner ? await pool.query(`SELECT ${ROW_COLS} FROM claude_limit_approval WHERE ${recent} ORDER BY created_at DESC LIMIT 500`) : [null];
    const [failed] = owner ? await pool.query(`SELECT ${ROW_COLS} FROM claude_limit_approval WHERE status = 'apply_failed' ORDER BY created_at ASC LIMIT 100`) : [[]];
    const [escd] = owner ? await pool.query(`SELECT ${ROW_COLS} FROM claude_limit_approval WHERE status = 'escalated' AND created_at >= NOW() - INTERVAL ${HISTORY_DAYS} DAY ORDER BY created_at ASC LIMIT 100`) : [[]];
    const seen = new Set(), mine = [];
    forMe.concat(waiting, failed, escd).forEach(r => { const d = deco(r); if ((d.canDecide || d.canRetry) && !seen.has(d.id)) { seen.add(d.id); mine.push(d); } });
    return { seatOwner: owner, historyDays: HISTORY_DAYS, waiting: mine, team: team.map(deco), all: all ? all.map(deco) : null };
  }

  // Self-raise: once a month, one click, the base plus selfRaise. The target is a total,
  // not an increment, so two clicks racing each other set the same cap, not two raises.
  router.post('/claude-limit/self-raise', json, async (req, res) => {
    if (!needUser(req, res)) return;
    const cfg = config(); if (!cfg.enabled) return off(res);
    if (sizesChanged(req.body, cfg)) return res.status(409).json(SIZES_CHANGED);
    try {
      const me = await actorOf(req);
      const lim = await currentLimit(pool, me.email);
      if (!lim) return res.status(409).json({ error: 'You do not have a Claude seat on record, so there is no limit to raise.', code: 'NOT_A_MEMBER' });
      // The amounts are worked out from the live cap only; the hourly feed can be out of date.
      if (!lim.live) return res.status(503).json(UNREADABLE);
      if (lim.amountCents == null) return res.status(409).json({ error: 'Your account has no monthly cap, so there is nothing to raise.', code: 'NO_CAP' });
      if (await selfUsed(pool, me.email)) {
        return res.status(409).json({ error: 'You have already used this month\'s one-click raise. Any other raise this month goes to your manager.', code: 'SELF_USED' });
      }
      const base = await baseFor(pool, me.email, lim.amountCents, lim.sourceType);
      if (lim.amountCents !== base) {
        return res.status(409).json({ error: 'Your limit was already raised this month (from ' + money(base) + ' to ' + money(lim.amountCents) + '). Any other raise this month goes to your manager.', code: 'SELF_USED' });
      }
      if (await selfUsed(pool, me.email, true)) {
        return res.status(409).json({ error: 'Your limit was already raised this month. Any other raise this month goes to your manager.', code: 'SELF_USED' });
      }
      return await create(req, res, me, lim, base + cfg.selfRaise * 100, cfg, base, true);
    } catch (e) { console.error('[limit-approvals] self-raise', e.message); res.status(500).json({ error: 'Internal error' }); }
  });

  // Request: a new monthly total, routed by band.
  router.post('/claude-limit/requests', json, async (req, res) => {
    if (!needUser(req, res)) return;
    const cfg = config(); if (!cfg.enabled) return off(res);
    if (sizesChanged(req.body, cfg)) return res.status(409).json(SIZES_CHANGED);
    const raw = req.body && req.body.newLimit;
    const dollars = Number(raw);
    if (!Number.isFinite(dollars) || dollars <= 0) return res.status(400).json({ error: 'Choose the new monthly total in dollars.', code: 'BAD_AMOUNT' });
    if (dollars > MAX_TOTAL) return res.status(400).json({ error: 'That new total looks too high - enter the monthly cap in dollars.', code: 'AMOUNT_TOO_HIGH' });
    const total = Math.round(dollars * 100);
    try {
      const me = await actorOf(req);
      const lim = await currentLimit(pool, me.email);
      if (!lim) return res.status(409).json({ error: 'You do not have a Claude seat on record, so there is no limit to raise.', code: 'NOT_A_MEMBER' });
      // The amounts are worked out from the live cap only; the hourly feed can be out of date.
      if (!lim.live) return res.status(503).json(UNREADABLE);
      if (lim.amountCents == null) return res.status(409).json({ error: 'Your account has no monthly cap, so there is nothing to raise.', code: 'NO_CAP' });
      if (total <= lim.amountCents) return res.status(400).json({ error: 'Your limit is already ' + money(lim.amountCents) + '. Enter a higher monthly total.', code: 'AMOUNT_NOT_HIGHER' });
      const base = await baseFor(pool, me.email, lim.amountCents, lim.sourceType);
      // Within the automatic raise while it is still unused this month. Exactly the one-click
      // amount IS the self-raise: applied now, no approval, not refused (Jeramy 2026-09-25).
      // Less than that (the page cannot send it) is refused as before.
      if (lim.amountCents === base && total <= base + cfg.selfRaise * 100 && !(await selfUsed(pool, me.email, true))) {
        if (total === base + cfg.selfRaise * 100) return await create(req, res, me, lim, total, cfg, base, true);
        return res.status(400).json({ error: 'Use the one-click button for ' + money(base + cfg.selfRaise * 100) + ' - you approve that one yourself. To ask your manager, choose more than that.', code: 'USE_SELF_RAISE' });
      }
      return await create(req, res, me, lim, total, cfg, base, false);
    } catch (e) { console.error('[limit-approvals] request', e.message); res.status(500).json({ error: 'Internal error' }); }
  });

  async function create(req, res, me, lim, total, cfg, base, self) {
    const [[esc1]] = await pool.query(
      "SELECT id FROM claude_limit_approval WHERE requester_email = ? AND status = 'escalated' AND period = ? LIMIT 1", [me.email, monthKey()]);
    if (esc1) return res.status(409).json({ error: 'A request of yours is already with the Service Desk this month (#' + esc1.id + ').', code: 'ALREADY_ESCALATED' });
    const band = bandFor(cfg, base, total, self);
    const chain = await resolveChain(pool, me.email);
    // A Claude seat owner's own request needs no other approval, whatever the amount and
    // whether or not they have a manager (stage S, pick c). They are written into the slots
    // they fill (pick e). A self-raise with a manager stays an ordinary self-raise.
    const ownerApproves = isOwner(cfg, me.email) && (band !== 'self' || !chain.manager);
    const now = sqlNow(), mSlot = ownerApproves ? me.email : null, lSlot = ownerApproves && band === 'leader' ? me.email : null;
    let id;
    try {
      const [ins] = await pool.query(
        `INSERT INTO claude_limit_approval (requester_email, requester_name, manager_email, manager_name, leader_email, leader_name,
           band, period, current_limit_cents, current_source, requested_cents, status,
           manager_decided_by, manager_decided_at, leader_decided_by, leader_decided_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [me.email, chain.person.name || me.name, chain.manager && chain.manager.email, chain.manager && chain.manager.name,
         chain.leader && chain.leader.email, chain.leader && chain.leader.name, band, monthKey(), lim.amountCents, lim.sourceType || null,
         total, band === 'self' || ownerApproves ? 'applying' : 'pending_manager',
         mSlot, mSlot && now, lSlot, lSlot && now]);
      id = ins.insertId;
    } catch (e) {
      if (e && e.code === 'ER_DUP_ENTRY') {
        const [[o]] = await pool.query(`SELECT ${ROW_COLS} FROM claude_limit_approval WHERE open_key = ?`, [me.email]);
        return res.status(409).json({ error: 'You already have an open limit request.', code: 'ALREADY_OPEN', open: o ? publicRow(o, me.email) : null });
      }
      throw e;
    }
    const D = Dfor(req);
    rbac.audit(req, 'claude_limit_requested', me.email, 'my-profile', { id, band, from: lim.amountCents, to: total, live: lim.live, seatOwner: ownerApproves || undefined });

    // Nobody to tell (self) or to approve (manager step): the Service Desk routes it.
    if (!chain.manager && !ownerApproves) {
      const r = await escalate(D, id, 'no manager to ' + (band === 'self' ? 'notify' : 'approve') + ' (' + chain.managerWhy + ')', me);
      return res.status(202).json({ ok: true, escalated: true, request: publicRow(r, me.email) });
    }

    if (band === 'self' || ownerApproves) {
      let r = await getRow(pool, id), ticket;
      try {
        const t = finalTicket(r, me.email);
        ticket = await fileTicket(D, r, t.kind, t.subject, t.text, me);
      } catch (e) {
        await patch(pool, id, { status: 'failed', fail_reason: ('ticket not filed: ' + (sdp && sdp.sdpErrorText ? sdp.sdpErrorText(e) : e.message)).slice(0, 480) });
        return res.status(502).json({ error: 'The Service Desk did not accept the log ticket, so nothing was changed. Try again in a minute.', code: 'SDP_FAILED' });
      }
      await addTicket(pool, id, ticket);
      if (ownerApproves) rbac.audit(req, 'claude_limit_seat_owner_approved', me.email, 'my-profile', { id, from: 'new', ticket: ticket.display, to: total, own: true, seatOwner: true });
      const out = await finish(D, id, me, ticket);
      if (!out.ok) return res.status(502).json({ error: (out.written ? 'Your new limit could not be confirmed: ' : 'Your limit was NOT changed: ') + out.error, code: 'APPLY_FAILED', request: publicRow(out.row, me.email) });
      return res.json({ ok: true, request: publicRow(out.row, me.email) });
    }

    // Pending the manager: in their queue, and mailed.
    const r = await getRow(pool, id);
    await mailAll(D, r, 'requested', [{ to: chain.manager.email,
      subject: 'Approval needed: ' + (r.requester_name || me.email) + ' asks for a ' + money(total) + ' Claude limit',
      html: mailHtml('Claude limit approval needed', [
        esc(r.requester_name || me.email) + ' asked to raise their Claude monthly limit from ' + money(lim.amountCents) + ' to <b>' + money(total) + '</b>'
          + ' (+' + money(total - base) + ' over the ' + money(base) + ' they started the month with).',
        band !== 'leader' ? 'Your approval applies it straight away.'
          : chain.leader && chain.leader.email === chain.manager.email ? 'That is more than +' + money(cfg.managerRaise * 100) + '. You are also their functional leader, so your approval applies it straight away.'
            : 'That is more than +' + money(cfg.managerRaise * 100) + ', so after you approve it goes to ' + esc(chain.leader ? chain.leader.name || chain.leader.email : 'the Service Desk (' + (chain.leaderWhy || 'no functional leader on record') + ')') + ' for the final approval.',
        'Approve or deny it in My Profile under Claude limit approvals.',
      ], 'Review the request') }]);
    return res.json({ ok: true, request: publicRow(await getRow(pool, id), me.email) });
  }

  /* Stage T: withdraw a request that stopped part-way. A write to Anthropic started for it
   * (apply_method 'writing') must not have landed: exactly the requested total as a per-user
   * cap means it did, and then Try again records it instead. Open tickets are closed. */
  async function withdrawStopped(req, res, r) {
    const id = r.id;
    if (!withdrawable(r)) return res.status(409).json({ code: 'NOT_YET', error: 'This request is still being worked on. If it stays like this, Withdraw appears ' + Math.round(STALE_S / 60) + ' minutes after it last moved.' });
    let reads = null;
    if (r.apply_method === 'writing') {
      const uid = r.anthropic_user_id || ((await memberRow(pool, r.requester_email)) || {}).userId;
      const cur = uid ? await anthropic.effective(uid) : { ok: false };
      if (!cur.ok || !cur.row) return res.status(409).json({ code: 'UNREADABLE', error: 'Could not check your limit with Anthropic just now, so this request was not withdrawn. Try again in a minute.' });
      const c = cur.row;
      if (!c.unlimited && c.amountCents === Number(r.requested_cents) && c.sourceType === 'user') {
        const by = resumerOf(r);
        return res.status(409).json({ code: 'LANDED', error: 'Anthropic already shows your limit at ' + money(c.amountCents) + ': this raise went through, so it cannot be withdrawn. '
          + (by === r.requester_email ? 'Press Try again to record it' : 'Ask ' + by + ' to press Try again to record it') + '; it then returns to your prior limit on the 1st.' });
      }
      reads = c;
    }
    if (!(await claimWithdraw(pool, id, r.status))) return res.status(409).json({ error: 'Somebody already acted on this request.', code: 'RACE' });
    const said = reads ? 'Anthropic reads ' + (reads.unlimited ? 'no cap' : money(reads.amountCents)) + ' (' + (reads.sourceType || '?') + '), not the requested ' + money(Number(r.requested_cents)) + ', so nothing from this request is in effect.'
      : 'Nothing was written to Anthropic for this request.';
    const note = 'Withdrawn by ' + r.requester_email + ' in My Profile after it stopped part-way (' + r.status.replace('_', ' ') + '). ' + said;
    const D = Dfor(req), closed = [];
    for (const t of (jsonCol((await getRow(pool, id)).tickets) || []).filter(x => !x.closed)) {
      await noteAndClose(D, t, note, 'Request withdrawn by ' + r.requester_email + '. ' + said);
      await addTicket(pool, id, t);
      closed.push(t.display + (t.closed ? '' : ' (not closed)'));
    }
    rbac.audit(req, 'claude_limit_cancelled', r.requester_email, 'my-profile', { id, from: r.status, stopped: true, anthropicCents: reads ? reads.amountCents : undefined, tickets: closed.length ? closed : undefined });
    res.json({ ok: true, request: publicRow(await getRow(pool, id), who(req)) });
  }

  router.post('/claude-limit/requests/:id/cancel', json, async (req, res) => {
    if (!needUser(req, res)) return;
    const id = idOf(req); if (!id) return res.status(400).json({ error: 'Bad request id' });
    try {
      const r = await getRow(pool, id);
      if (!r || r.requester_email !== who(req)) return res.status(404).json({ error: 'No such request of yours.' });
      if (STOPPED.indexOf(r.status) >= 0) return await withdrawStopped(req, res, r);
      const ok = await claim(pool, id, ['pending_manager', 'pending_leader'], { status: 'cancelled', cancelled_at: sqlNow() });
      if (!ok) return res.status(409).json({ error: 'This request is ' + r.status.replace('_', ' ') + ' and can no longer be withdrawn.', code: 'NOT_PENDING' });
      rbac.audit(req, 'claude_limit_cancelled', r.requester_email, 'my-profile', { id });
      res.json({ ok: true, request: publicRow(await getRow(pool, id), who(req)) });
    } catch (e) { console.error('[limit-approvals] cancel', e.message); res.status(500).json({ error: 'Internal error' }); }
  });

  router.post('/claude-limit/requests/:id/approve', json, async (req, res) => {
    if (!needUser(req, res)) return;
    const cfg = config(); if (!cfg.enabled) return off(res);
    const id = idOf(req); if (!id) return res.status(400).json({ error: 'Bad request id' });
    try {
      const me = await actorOf(req);
      let r = await getRow(pool, id);
      if (!r) return res.status(404).json({ error: 'No such request.' });
      const D = Dfor(req);
      const now = sqlNow();
      if (ownerDecides(cfg, r, me.email)) return await ownerApprove(req, res, D, r, me, now);
      let step;
      if (r.status === 'pending_manager' && r.manager_email === me.email) step = 'manager';
      else if (r.status === 'pending_leader' && r.leader_email === me.email) step = 'leader';
      else return res.status(403).json({ error: r.status === 'pending_manager' || r.status === 'pending_leader' ? 'This request is waiting on somebody else.' : 'This request is ' + r.status.replace('_', ' ') + '.', code: 'NOT_YOURS' });
      if (r.requester_email === me.email) return res.status(403).json({ error: 'You cannot approve your own request.', code: 'OWN_REQUEST' });

      // Manager step on a leader-band request: log it, then hand it to the leader
      // (or the Service Desk). A manager who is also the leader covers both steps.
      if (step === 'manager' && r.band === 'leader' && r.leader_email !== me.email) {
        if (!(await claim(pool, id, ['pending_manager'], { status: 'forwarding', manager_decided_by: me.email, manager_decided_at: now }))) return res.status(409).json({ error: 'Somebody already acted on this request.', code: 'RACE' });
        const f = await forward(D, id, me, false);
        if (f.sdpFailed) return res.status(502).json({ error: 'The Service Desk did not accept the log ticket, so your approval was not recorded. Try again in a minute.', code: 'SDP_FAILED' });
        rbac.audit(req, 'claude_limit_manager_approved', r.requester_email, 'my-profile', { id, ticket: f.ticket.display, next: r.leader_email || 'escalation' });
        return res.json(f.escalated ? { ok: true, escalated: true, request: publicRow(f.row) } : { ok: true, forwarded: true, request: publicRow(f.row) });
      }

      // The approval that completes the chain.
      const fields = step === 'manager'
        ? { status: 'applying', manager_decided_by: me.email, manager_decided_at: now }
        : { status: 'applying', leader_decided_by: me.email, leader_decided_at: now };
      if (step === 'manager' && r.band === 'leader') Object.assign(fields, { leader_decided_by: me.email, leader_decided_at: now });
      if (!(await claim(pool, id, [r.status], fields))) return res.status(409).json({ error: 'Somebody already acted on this request.', code: 'RACE' });
      r = await getRow(pool, id);
      let ticket;
      try {
        const t = finalTicket(r, me.email);
        ticket = await fileTicket(D, r, t.kind, t.subject, t.text, me);
      } catch (e) {
        const back = step === 'manager' ? { status: 'pending_manager', manager_decided_by: null, manager_decided_at: null, leader_decided_by: null, leader_decided_at: null }
          : { status: 'pending_leader', leader_decided_by: null, leader_decided_at: null };
        await patch(pool, id, back);
        return res.status(502).json({ error: 'The Service Desk did not accept the log ticket, so nothing was changed. Try again in a minute.', code: 'SDP_FAILED' });
      }
      await addTicket(pool, id, ticket);
      rbac.audit(req, 'claude_limit_' + step + '_approved', r.requester_email, 'my-profile', { id, ticket: ticket.display, to: Number(r.requested_cents) });
      const out = await finish(D, id, me, ticket);
      if (!out.ok) return res.status(502).json({ error: (out.written ? 'Approved, but the new limit could not be confirmed in Anthropic: ' : 'Approved, but the limit was NOT changed in Anthropic: ') + out.error + ' The ticket is open; you can retry.', code: 'APPLY_FAILED', request: publicRow(out.row) });
      return res.json({ ok: true, request: publicRow(out.row) });
    } catch (e) { console.error('[limit-approvals] approve', e.message); res.status(500).json({ error: 'Internal error' }); }
  });

  /* A Claude seat owner approves an escalated request, or their own that is waiting on
   * somebody (stage S, picks a and c). They fill the empty decided_by slots (pick e): the
   * manager's when nobody has approved yet, and the leader's on a leader-band request. The
   * escalation ticket, if there is one, is the ticket the result is written on and closed. */
  async function ownerApprove(req, res, D, r, me, now) {
    const id = r.id, from = r.status, own = r.requester_email === me.email;
    const fields = { status: 'applying' };
    if (!r.manager_decided_by) Object.assign(fields, { manager_decided_by: me.email, manager_decided_at: now });
    if (r.band === 'leader' && !r.leader_decided_by) Object.assign(fields, { leader_decided_by: me.email, leader_decided_at: now });
    let took;
    try { took = await claim(pool, id, [from], fields); }
    catch (e) {
      // One open request per person: moving this one back to open collides with a newer one.
      if (e && e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: (own ? 'You have' : (r.requester_name || r.requester_email) + ' has') + ' another open limit request; that one has to finish first.', code: 'ALREADY_OPEN' });
      throw e;
    }
    if (!took) return res.status(409).json({ error: 'Somebody already acted on this request.', code: 'RACE' });
    r = await getRow(pool, id);
    const t = finalTicket(r, me.email);
    let ticket = t.kind === 'escalation' ? (jsonCol(r.tickets) || []).filter(x => x.action === 'escalation').pop() : null;
    if (!ticket) {
      try { ticket = await fileTicket(D, r, t.kind, t.subject, t.text, me); }
      catch (e) {
        const back = { status: from };
        Object.keys(fields).forEach(k => { if (k !== 'status') back[k] = null; });
        await patch(pool, id, back);
        return res.status(502).json({ error: 'The Service Desk did not accept the log ticket, so nothing was changed. Try again in a minute.', code: 'SDP_FAILED' });
      }
      await addTicket(pool, id, ticket);
    }
    rbac.audit(req, 'claude_limit_seat_owner_approved', r.requester_email, 'my-profile', { id, from, ticket: ticket.display, to: Number(r.requested_cents), own, seatOwner: true });
    const out = await finish(D, id, me, ticket);
    if (!out.ok) return res.status(502).json({ error: (out.written ? 'Approved, but the new limit could not be confirmed in Anthropic: ' : 'Approved, but the limit was NOT changed in Anthropic: ') + out.error + ' The ticket is open; you can retry.', code: 'APPLY_FAILED', request: publicRow(out.row) });
    return res.json({ ok: true, seatOwner: true, request: publicRow(out.row) });
  }

  router.post('/claude-limit/requests/:id/deny', json, async (req, res) => {
    if (!needUser(req, res)) return;
    const id = idOf(req); if (!id) return res.status(400).json({ error: 'Bad request id' });
    const reason = String((req.body && req.body.reason) || '').trim().slice(0, 500);
    if (reason.length < 3) return res.status(400).json({ error: 'Give the person a reason.', code: 'NO_REASON' });
    try {
      const me = await actorOf(req);
      let r = await getRow(pool, id);
      if (!r) return res.status(404).json({ error: 'No such request.' });
      const mine = (r.status === 'pending_manager' && r.manager_email === me.email) || (r.status === 'pending_leader' && r.leader_email === me.email);
      // A Claude seat owner denies an escalated request the way a manager denies theirs (stage S, pick d).
      const asOwner = !mine && r.status === 'escalated' && isOwner(config(), me.email);
      if (!mine && !asOwner) return res.status(403).json({ error: 'This request is not waiting on you.', code: 'NOT_YOURS' });
      if (!(await claim(pool, id, [r.status], { status: 'denied', denied_by: me.email, denied_at: sqlNow(), deny_reason: reason }))) return res.status(409).json({ error: 'Somebody already acted on this request.', code: 'RACE' });
      r = await getRow(pool, id);
      const D = Dfor(req), dt = denyTexts(r, me.email, reason, asOwner);
      // An escalated request's own ticket gets the denial and is closed; otherwise a denial ticket is filed and closed.
      let ticket = asOwner ? (jsonCol(r.tickets) || []).filter(x => x.action === 'escalation').pop() || null : null;
      try {
        if (!ticket) {
          ticket = await fileTicket(D, r, 'denied', dt.subject, dt.text, me);
          await addTicket(pool, id, ticket);   // stage U: recorded as soon as it exists
        }
        await noteAndClose(D, ticket, dt.note, dt.resolution);
        await addTicket(pool, id, ticket);
      } catch (e) { await patch(pool, id, { fail_reason: ('deny ticket not filed: ' + (sdp && sdp.sdpErrorText ? sdp.sdpErrorText(e) : e.message)).slice(0, 480) }); }
      rbac.audit(req, 'claude_limit_denied', r.requester_email, 'my-profile', { id, reason, ticket: ticket && ticket.display, seatOwner: asOwner || undefined });
      await mailAll(D, r, 'denied', [denyMail(r, me, reason, asOwner, ticket)]);
      res.json({ ok: true, request: publicRow(await getRow(pool, id)), ticketFiled: !!ticket });
    } catch (e) { console.error('[limit-approvals] deny', e.message); res.status(500).json({ error: 'Internal error' }); }
  });

  // Try again: after Anthropic failed (any time), or after the hub stopped part-way through
  // a step (once the row has been idle STALE_S). Picks up from the row; see resumeKind().
  router.post('/claude-limit/requests/:id/retry', json, async (req, res) => {
    if (!needUser(req, res)) return;
    const cfg = config(); if (!cfg.enabled) return off(res);
    const id = idOf(req); if (!id) return res.status(400).json({ error: 'Bad request id' });
    try {
      const me = await actorOf(req);
      let r = await getRow(pool, id);
      if (!r) return res.status(404).json({ error: 'No such request.' });
      const resumer = resumerOf(r), asOwner = resumer !== me.email && ownerRetry(cfg, r, me.email);
      if (resumer !== me.email && !asOwner) return res.status(403).json({ error: 'Only the person whose step this was, or a Claude seat owner when the Anthropic write failed, can retry it.', code: 'NOT_YOURS' });
      // A seat owner finishes somebody else's approval: the mail and the ticket still name
      // the person who approved; the seat owner is recorded as who applied it, and audited.
      const approver = !asOwner ? me : { email: resumer, by: me.email,
        name: resumer === r.leader_email ? r.leader_name : resumer === r.manager_email ? r.manager_name : resumer === r.requester_email ? r.requester_name : ((await realPerson(pool, resumer).catch(() => null)) || {}).name };
      if (!approver.name) approver.name = approver.email;
      const kind = resumeKind(r), from = r.status;
      if (!kind) {
        const inFlight = r.status === 'applying' || r.status === 'forwarding' || (r.status === 'pending_manager' && !r.manager_email);
        return res.status(409).json({ code: 'NOT_RETRYABLE', error: inFlight
          ? 'This request is still being worked on. If it stays like this, Try again appears ' + Math.round(STALE_S / 60) + ' minutes after it last moved.'
          : 'This request is ' + r.status.replace('_', ' ') + '.' });
      }
      const took = from === 'apply_failed' ? await claim(pool, id, ['apply_failed'], { status: 'applying' }) : await claimStale(pool, id, from);
      if (!took) return res.status(409).json({ error: 'Somebody already acted on this request.', code: 'RACE' });
      rbac.audit(req, 'claude_limit_retry', r.requester_email, 'my-profile', { id, kind, from, seatOwner: asOwner || undefined, approver: asOwner ? resumer : undefined });
      const D = Dfor(req);

      if (kind === 'escalate') {    // no manager on record when it was made (a forward escalates inside forward())
        const why = 'no manager to ' + (r.band === 'self' ? 'notify' : 'approve') + ' (' + ((await resolveChain(pool, r.requester_email)).managerWhy || 'none on record when the request was made') + ')';
        return res.json({ ok: true, resumed: 'escalated', escalated: true, request: publicRow(await escalate(D, id, why, me, true), me.email) });
      }
      if (kind === 'forward') {
        const f = await forward(D, id, me, true);
        if (f.sdpFailed) return res.status(502).json({ error: 'The Service Desk did not accept the log ticket, so your approval was not recorded. It is back in your queue; approve it again in a minute.', code: 'SDP_FAILED' });
        rbac.audit(req, 'claude_limit_manager_approved', r.requester_email, 'my-profile', { id, ticket: f.ticket && f.ticket.display, next: r.leader_email || 'escalation', resumed: true });
        return res.json({ ok: true, resumed: f.escalated ? 'escalated' : 'forwarded', escalated: !!f.escalated, forwarded: !!f.forwarded, request: publicRow(f.row) });
      }

      // kind === 'apply': the ticket for the final approval, recorded or filed now, then finish.
      r = await getRow(pool, id);
      const t = finalTicket(r, approver.email);
      let ticket = (jsonCol(r.tickets) || []).filter(x => x.action === t.kind).pop() || null;
      if (!ticket) {
        try { ticket = await fileTicket(D, r, t.kind, t.subject, t.text + '\n\n' + RESUMED_NOTE + (asOwner ? '\nRetried by ' + me.email + ' (Claude seat owner).' : ''), approver); }
        catch (e) {
          await patch(pool, id, { status: 'apply_failed', fail_reason: ('The Service Desk did not accept the log ticket, so nothing was changed: ' + (sdp && sdp.sdpErrorText ? sdp.sdpErrorText(e) : e.message)).slice(0, 480) });
          return res.status(502).json({ error: 'The Service Desk did not accept the log ticket, so nothing was changed. Try again in a minute.', code: 'SDP_FAILED', request: publicRow(await getRow(pool, id)) });
        }
        await addTicket(pool, id, ticket);
        if (t.kind !== 'self') rbac.audit(req, 'claude_limit_' + t.kind + '_approved', r.requester_email, 'my-profile', { id, ticket: ticket.display, to: Number(r.requested_cents), resumed: true, approver: asOwner ? resumer : undefined,
          own: t.kind === 'seat_owner' ? resumer === r.requester_email : undefined, seatOwner: t.kind === 'seat_owner' || undefined });
      }
      const out = await finish(D, id, approver, ticket);
      if (!out.ok) return res.status(502).json({ error: (out.written ? '' : 'Still not changed in Anthropic: ') + out.error, code: 'APPLY_FAILED', request: publicRow(out.row) });
      res.json({ ok: true, resumed: 'applied', request: publicRow(out.row) });
    } catch (e) { console.error('[limit-approvals] retry', e.message); res.status(500).json({ error: 'Internal error' }); }
  });
}

module.exports = { register, config, readConfig, _clearConfigCache: () => { _cfg = { at: 0, v: null }; }, resolveChain, bandFor, _baseFor: baseFor, _selfUsed: selfUsed, applyInAnthropic, mailHtml, money, monthName, SENDER, PAGE_URL, DEFAULTS, TICKET_FALLBACK, STALE_S, _resumeKind: resumeKind, _resumerOf: resumerOf, _within: within,
  wrapStopped, recordLanded, WRAP_SINCE, JOB };
