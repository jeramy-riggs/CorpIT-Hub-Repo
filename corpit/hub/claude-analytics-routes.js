/**
 * claude-analytics-routes.js — live Claude Enterprise Analytics for the
 * AI Usage & Credits page. Mounted at /api/claude-analytics/.
 * RBAC page key: ai-usage-credits (same audience as the page itself).
 * Read-only: every route is a SELECT against the tables the collector fills.
 *
 * Money is stored in CENTS (DECIMAL(18,6), fractional cents are real). Every
 * route divides by 100 exactly once, here, so the front end only ever sees dollars.
 */
const express = require('express');
const mysql = require('mysql2/promise');
const createRbac = require('./rbac-middleware');

const router = express.Router();
const pool = mysql.createPool({
  host: process.env.DB_HOST, user: process.env.DB_USER,
  password: process.env.DB_PASSWORD, database: process.env.DB_NAME,
  waitForConnections: true, connectionLimit: 5,
});
const rbac = createRbac(pool);
router.use(rbac.loadCurrentUser);

const PAGE_KEY = 'ai-usage-credits';
const read = rbac.requirePage(PAGE_KEY, 'read');
const { resolveScope, scopeWhere, scopePredicate, resolveScopeForRequest, scopeEmailSet } = require('./scope-lib');
/* DATA SCOPE on per-person routes (F28, 2026-10-21). Same idiom as insights-routes.js
 * /shared/*: null = org-wide (no filter, output unchanged), an empty Set when the scope is
 * undetermined (deny - fails closed), else the emails the caller may see. Applied to every
 * route below that returns a person's email or name. */
const scopedEmails = async (req) => scopeEmailSet(pool, (await resolveScopeForRequest(pool, req)).scope);
const inScope = (allow, email) => allow === null || allow.has(String(email || '').toLowerCase());

async function q(sql, params = []) { const [rows] = await pool.query(sql, params); return rows; }
const clampDays = (v, d = 30) => Math.max(1, Math.min(400, parseInt(v, 10) || d));
/* A rolling "last N days" window is the N dates ENDING TODAY, so the lower bound is
 * exclusive: `day > DATE_SUB(CURDATE(), INTERVAL N DAY)`. An inclusive `>=` also matches
 * CURDATE()-N itself and so spans N+1 dates — that is how a total labelled "last 30 days"
 * came to cover 31. Where the bound is interpolated instead of bound as a parameter the
 * same window is written `day >= DATE_SUB(CURDATE(), INTERVAL N-1 DAY)` — see /sessions. */
// The shared month picker is owned by /api/insights, whose option values are full dates
// ('2026-08-01'); these routes work in 'YYYY-MM'. Accept both and normalise — the strict
// 7-char test rejected every picker value, so the param was dropped and each of the five
// month-scoped routes silently answered for the current month instead.
const monthOf = (v) => (/^\d{4}-\d{2}(-\d{2})?$/.test(v || '') ? String(v).slice(0, 7) : null);
const n2 = (v) => Math.round((Number(v) || 0) * 100) / 100;
/* REPORTING PERIOD (2026-09-15). ?from=YYYY-MM-DD&to=YYYY-MM-DD (inclusive) is accepted by
 * /sessions, /rollup, /rollup/coverage, /trend and /tokens. The page's global 30/60/90
 * control sends full-calendar-month bounds (history) or the 1st..today (current month, MTD),
 * so every surface answers for the same period. Callers that send neither keep the old
 * rolling-window / month behaviour untouched. Bounds are validated to a literal date shape
 * before they are ever interpolated. */
const dateOf = (v) => (/^\d{4}-\d{2}-\d{2}$/.test(v || '') ? String(v) : null);
function periodOf(qs) {
  const from = dateOf(qs.from), to = dateOf(qs.to);
  if (!from || !to || from > to) return null;
  const f = new Date(from + 'T00:00:00Z'), t = new Date(to + 'T00:00:00Z');
  const days = Math.round((t - f) / 864e5) + 1;
  const months = (t.getUTCFullYear() - f.getUTCFullYear()) * 12 + (t.getUTCMonth() - f.getUTCMonth()) + 1;
  const axis = [];
  for (let i = 0; i < months; i++) {
    const m = new Date(Date.UTC(f.getUTCFullYear(), f.getUTCMonth() + i, 1));
    axis.push(m.toISOString().slice(0, 7));
  }
  return { from, to, days, months, axis };
}
/** Prompt-cache hit rate over INPUT tokens. The three input counters are disjoint:
 *  cache_read is a hit, uncached_input and cache_creation are both misses (creation
 *  tokens are processed fresh AND written to the cache), so all three belong in the
 *  denominator. Output tokens are not input and stay out of it. Null, not 0, when
 *  there was no input at all — no requests is a gap, not a 0% hit rate. */
const hitRate = (cr, un, cc) => {
  const inTok = (Number(cr) || 0) + (Number(un) || 0) + (Number(cc) || 0);
  return inTok > 0 ? n2(((Number(cr) || 0) / inTok) * 100) : null;
};
const CL = require('./claude-limits');

/** One row per person from the directory.
 *
 *  entra_users is keyed on entra_id, not on the UPN, and the sync keeps rows it has stopped
 *  seeing (46 rows currently carry seen_in_last_sync=0) — so one person can hold two rows, a
 *  current object beside a stale one. Joining the table directly fans that member out: where
 *  the GROUP BY does not separate the two directory rows their figures DOUBLE, and where
 *  there is no GROUP BY at all the member is emitted twice at full value. Every per-member
 *  join below goes through this view instead, so the join is safe whatever the table holds
 *  rather than safe only while it happens to be clean.
 *
 *  The row still seen in the last sync wins — that is what Graph says about the person today,
 *  and it is the row that carries the real account_enabled — then the most recently synced,
 *  with entra_id as a deterministic tiebreak. Only the columns the page reads are carried, so
 *  raw_json is not dragged through the materialisation. */
const ENTRA1 = `(SELECT user_principal_name, entra_id, display_name, department, manager_upn, account_enabled
                   FROM (SELECT eu.user_principal_name, eu.entra_id, eu.display_name, eu.department,
                                eu.manager_upn, eu.account_enabled,
                                ROW_NUMBER() OVER (PARTITION BY eu.user_principal_name
                                     ORDER BY eu.seen_in_last_sync DESC, eu.last_synced_at DESC,
                                              eu.entra_id) AS rn
                           FROM entra_users eu) e1
                  WHERE e1.rn = 1)`;


/** Token counters for one member row. Always the same shape, zeros when the member
 *  has spend but no usage row, so the front end never has to guard for undefined.
 *  costPerMTok is null rather than 0 when there are no tokens — a member with spend
 *  and no tokens is a data gap, not a $0 rate. */
/** Did the member use the allowance we gave them?
 *
 *  The limit is MONTHLY but the window is rolling and caller-chosen, so comparing a
 *  7-day spend against a monthly cap would call almost everyone under-used. The spend
 *  is projected to a monthly run rate first, and THAT is what is judged. Below 14 days
 *  of window the projection is too jumpy to act on, so it is returned but marked
 *  low-confidence rather than dressed up as a recommendation.
 *
 *  'increase' means the cap is being hit — the person is throttled, not overspending.
 *  'reclaim' is reserved for a seat with no activity of ANY kind, which is a different
 *  conversation from a seat that is merely cheap.
 */
function allowanceFor(days) {
  return function allowance(spend, limit, active) {
    const projected = days > 0 ? n2((spend / days) * 30) : 0;
    const confident = days >= 14;
    if (!(limit > 0)) {
      return { projectedMonthlySpend: projected, utilisationPct: null, unusedAllowance: null,
               recommendation: 'no-limit', recommendationReason: 'No spend limit applies to this member.',
               recommendationConfident: confident };
    }
    const util = n2((projected / limit) * 100);
    const unused = n2(Math.max(0, limit - projected));
    let rec, why;
    if (!active) {
      rec = 'reclaim';
      why = 'No sessions, tokens or spend in the window — the seat is idle.';
    } else if (util >= 100) {
      rec = 'increase';
      why = 'At or over the limit — raise it or the work gets throttled.';
    } else if (util >= 80) {
      rec = 'watch';
      why = 'Using most of the allowance; likely to hit the cap.';
    } else if (util >= 40) {
      rec = 'ok';
      why = 'Using a healthy share of the allowance.';
    } else {
      rec = 'decrease';
      why = 'Using a small share of the allowance — $' + unused.toFixed(2) + ' of it goes unused each month.';
    }
    return { projectedMonthlySpend: projected, utilisationPct: util, unusedAllowance: unused,
             recommendation: rec, recommendationReason: why, recommendationConfident: confident };
  };
}

/** Suggested spend limit from the member's own history: the mean of the last 3 complete
 *  months, rounded up to the nearest $5 so the number is one a human would actually set.
 *
 *  Basis is the PEAK month, not the mean: a mean is exceeded in roughly half of months, so
 *  re-basing on it would cap people mid-month and generate a queue of increase requests.
 *  avg3moSpend is still returned for context. suggestedBelowPeak is therefore always false
 *  by construction — kept in the payload so the page contract does not change.
 */
function suggestLimit(byMonth, months, currentLimit) {
  const per = months.map((m) => Number((byMonth || {})[m] || 0));
  const n = months.length || 1;
  const total = per.reduce((a, b) => a + b, 0);
  const avg = Math.round((total / n) * 100) / 100;
  const peak = per.length ? Math.max(...per) : 0;
  const suggested = peak > 0 ? Math.max(5, Math.ceil(peak / 5) * 5) : 0;
  return {
    avg3moSpend: avg,
    max3moSpend: Math.round(peak * 100) / 100,
    months3: months.map((m, i) => ({ month: m, spend: per[i] })),
    monthsWithSpend: per.filter((v) => v > 0).length,
    suggestedLimit: suggested,
    suggestedBasis: 'peak-3mo',
    suggestedBelowPeak: suggested > 0 && suggested < peak,
    // negative = allowance released, positive = allowance to add
    suggestedLimitDelta: currentLimit > 0 ? Math.round((suggested - currentLimit) * 100) / 100 : null,
  };
}

function tokenFields(t) {
  const tokens = Number((t || {}).tokens || 0);
  return {
    tokens,
    tokensUncached: Number((t || {}).uncached_input || 0),
    tokensCacheRead: Number((t || {}).cache_read || 0),
    tokensCacheCreated: Number((t || {}).cache_created || 0),
    tokensOutput: Number((t || {}).output_tokens || 0),
    webSearches: Number((t || {}).web_search_requests || 0),
  };
}

/** Live per-member limits (Spend Limits API) when the key has read:spend_limits and the
 *  pull is fresh; null otherwise, and every caller falls back to the CSV import. */
async function liveLimits() {
  try {
    const rows = await q(
      `SELECT user_id, period, email, amount_cents, source_type, source_ref, ptd_spend_cents, fetched_at
         FROM claude_spend_limit WHERE period='monthly' AND deleted=0`);
    return (rows.length && CL.isFresh(CL.newestFetchedAt(rows))) ? CL.buildLimitMaps(rows) : null;
  } catch (e) {
    if (e.code !== 'ER_NO_SUCH_TABLE') console.error('[claude-analytics] live limits unavailable, using CSV:', e.message);
    return null;
  }
}

/* GET /summary — headline tiles. Month-to-date spend, run rate, projection,
 * engagement, and how stale the data is. */
router.get('/summary', read, async (req, res) => {
  try {
    const month = monthOf(req.query.month) || new Date().toISOString().slice(0, 7);
    const [mtd] = await q(
      `SELECT COALESCE(SUM(amount_cents),0)/100 AS spend, COALESCE(SUM(requests),0) AS requests,
              COUNT(DISTINCT day) AS days_with_data, MAX(day) AS last_day
         FROM claude_cost_daily WHERE DATE_FORMAT(day,'%Y-%m') = ?`, [month]);
    const [prev] = await q(
      `SELECT COALESCE(SUM(amount_cents),0)/100 AS spend FROM claude_cost_daily
        WHERE DATE_FORMAT(day,'%Y-%m') = DATE_FORMAT(DATE_SUB(CONCAT(?,'-01'), INTERVAL 1 MONTH),'%Y-%m')`, [month]);
    // Comparing a month-to-date figure against a FULL previous month reads as a
    // catastrophic drop on the 1st (-99%). Compare the same elapsed span instead.
    const [prevSpan] = await q(
      `SELECT COALESCE(SUM(amount_cents),0)/100 AS spend FROM claude_cost_daily
        WHERE DATE_FORMAT(day,'%Y-%m') = DATE_FORMAT(DATE_SUB(CONCAT(?,'-01'), INTERVAL 1 MONTH),'%Y-%m')
          AND DAYOFMONTH(day) <= ?`, [month, new Date().getUTCDate()]);
    // Engagement has to be read as of the month being displayed. The newest row is only
    // the right answer for the current month; for a historic one it reported today's
    // actives against today's seat count (Jul-2026 showed 60 WAU of 81 seats instead of
    // its own 39 of 52). Same idiom as the seat read in insights-routes: newest snapshot
    // on or before month end, so a month the collector has not filled yet carries the
    // last known one forward instead of blanking the tiles.
    const [eng] = await q(
      `SELECT day, dau, wau, mau, assigned_seats, pending_invites,
              daily_adoption_rate, weekly_adoption_rate, monthly_adoption_rate
         FROM claude_summary_daily
        WHERE day <= LAST_DAY(CONCAT(?,'-01')) ORDER BY day DESC LIMIT 1`, [month]);
    const [sync] = await q(
      `SELECT MAX(ran_at) AS last_run, MAX(data_refreshed_at) AS data_refreshed_at
         FROM claude_sync_log WHERE status='ok'`);
    const [fail] = await q(
      `SELECT COUNT(*) AS n FROM claude_sync_log
        WHERE status='error' AND ran_at > (SELECT COALESCE(MAX(ran_at),'1970-01-01') FROM claude_sync_log WHERE status='ok')`);

    // Projection: mean daily spend so far this month, extended to month end.
    // Only meaningful for the current month, so it is null for historic ones.
    const now = new Date();
    const isCurrent = month === now.toISOString().slice(0, 7);
    const daysInMonth = new Date(Date.UTC(+month.slice(0, 4), +month.slice(5, 7), 0)).getUTCDate();
    const elapsed = isCurrent ? now.getUTCDate() : daysInMonth;
    const spend = Number(mtd.spend) || 0;
    const runRate = elapsed > 0 ? spend / elapsed : 0;

    res.json({
      month,
      spend: n2(spend),
      requests: Number(mtd.requests) || 0,
      daysWithData: mtd.days_with_data,
      lastDay: mtd.last_day,
      prevMonthSpend: n2(prev.spend),
      prevMonthSameSpan: n2(prevSpan.spend),
      // like-for-like while the month is still running; full-month once it has ended
      momPct: (() => {
        const base = isCurrent ? Number(prevSpan.spend) : Number(prev.spend);
        return base > 0 ? n2((spend / base - 1) * 100) : null;
      })(),
      momBasis: isCurrent ? 'same-span' : 'full-month',
      runRatePerDay: n2(runRate),
      projectedMonthEnd: isCurrent ? n2(runRate * daysInMonth) : null,
      daysElapsed: elapsed, daysInMonth,
      engagement: eng || null,
      dataRefreshedAt: sync ? sync.data_refreshed_at : null,
      lastSyncAt: sync ? sync.last_run : null,
      syncErrorsSinceLastOk: fail ? Number(fail.n) : 0,
    });
  } catch (e) { console.error('[claude-analytics/summary]', e.message); res.status(500).json({ error: 'summary failed' }); }
});

/* GET /trend?days=90 or ?month=YYYY-MM — daily spend series, optionally split by
 * product. month, when given, returns that whole calendar month instead of the
 * trailing days window (used by the Live tab's chart, which follows the page's
 * month picker); days-based callers keep their rolling-window behavior. */
router.get('/trend', read, async (req, res) => {
  try {
    const month = monthOf(req.query.month);
    const days = clampDays(req.query.days, 90);
    const period = periodOf(req.query);
    const rows = period
      ? await q(
          `SELECT day, product, SUM(amount_cents)/100 AS spend, SUM(requests) AS requests
             FROM claude_cost_daily WHERE day >= ? AND day <= ?
            GROUP BY day, product ORDER BY day`, [period.from, period.to])
      : month
      ? await q(
          `SELECT day, product, SUM(amount_cents)/100 AS spend, SUM(requests) AS requests
             FROM claude_cost_daily WHERE DATE_FORMAT(day,'%Y-%m') = ?
            GROUP BY day, product ORDER BY day`, [month])
      : await q(
          `SELECT day, product, SUM(amount_cents)/100 AS spend, SUM(requests) AS requests
             FROM claude_cost_daily WHERE day > DATE_SUB(CURDATE(), INTERVAL ? DAY)
            GROUP BY day, product ORDER BY day`, [days]);
    const byDay = {};
    for (const r of rows) {
      const d = r.day instanceof Date ? r.day.toISOString().slice(0, 10) : String(r.day);
      byDay[d] = byDay[d] || { day: d, total: 0, products: {}, requests: 0 };
      byDay[d].products[r.product || 'other'] = n2(r.spend);
      byDay[d].total = n2(byDay[d].total + Number(r.spend));
      byDay[d].requests += Number(r.requests) || 0;
    }
    res.json({ days, month, period, series: Object.values(byDay) });
  } catch (e) { console.error('[claude-analytics/trend]', e.message); res.status(500).json({ error: 'trend failed' }); }
});

/* GET /breakdown?month=YYYY-MM — spend by product and by model. */
router.get('/breakdown', read, async (req, res) => {
  try {
    const month = monthOf(req.query.month) || new Date().toISOString().slice(0, 7);
    const products = await q(
      `SELECT product, SUM(amount_cents)/100 AS spend, SUM(requests) AS requests
         FROM claude_cost_daily WHERE DATE_FORMAT(day,'%Y-%m')=? GROUP BY product
        HAVING spend > 0 OR requests > 0 ORDER BY spend DESC`, [month]);
    const models = await q(
      `SELECT model, SUM(amount_cents)/100 AS spend, SUM(requests) AS requests
         FROM claude_cost_daily WHERE DATE_FORMAT(day,'%Y-%m')=? GROUP BY model
        HAVING spend > 0 OR requests > 0 ORDER BY spend DESC`, [month]);
    const months = await q(
      `SELECT DATE_FORMAT(day,'%Y-%m') AS month, SUM(amount_cents)/100 AS spend
         FROM claude_cost_daily GROUP BY 1 ORDER BY 1 DESC`);
    res.json({
      month,
      products: products.map((r) => ({ ...r, spend: n2(r.spend) })),
      models: models.map((r) => ({ ...r, spend: n2(r.spend) })),
      months: months.map((r) => ({ month: r.month, spend: n2(r.spend) })),
    });
  } catch (e) { console.error('[claude-analytics/breakdown]', e.message); res.status(500).json({ error: 'breakdown failed' }); }
});

/* GET /members?month=YYYY-MM — per-member live spend, joined to the directory.
 * custom_limit still comes from the CSV import: the key carries read:analytics
 * only, so the Spend Limits API is not reachable. Flagged per member so the UI
 * can label it rather than implying it is live. */
router.get('/members', read, async (req, res) => {
  try {
    const month = monthOf(req.query.month) || new Date().toISOString().slice(0, 7);
    const allow = await scopedEmails(req);
    const rows = (await q(
      `SELECT c.email,
              MAX(c.display_name)                              AS api_name,
              SUM(c.amount_cents)/100                          AS spend,
              SUM(c.requests)                                  AS requests,
              COALESCE(o.name, u.display_name, MAX(c.display_name)) AS name,
              COALESCE(o.department, u.department)             AS department,
              COALESCE(o.manager, m.display_name)              AS manager,
              lim.custom_limit                                 AS customLimit,
              lim.group_limit                                  AS groupLimit,
              (u.entra_id IS NOT NULL)                         AS matchedEntra,
              MAX(c.deleted)                                   AS departedFlag
         FROM claude_user_cost_daily c
         LEFT JOIN ${ENTRA1} u ON u.user_principal_name = c.email
         LEFT JOIN ${ENTRA1} m ON m.user_principal_name = u.manager_upn
         LEFT JOIN ai_directory_override o ON o.email = c.email
         LEFT JOIN (SELECT email, custom_limit, group_limit FROM ai_usage_member WHERE platform='claude') lim
                ON lim.email = c.email
        WHERE DATE_FORMAT(c.day,'%Y-%m') = ?
        GROUP BY c.email, o.name, u.display_name, o.department, u.department,
                 o.manager, m.display_name, lim.custom_limit, lim.group_limit, u.entra_id
        ORDER BY spend DESC`, [month])).filter((r) => inScope(allow, r.email));

    // Requests as well as spend: a product that bills at $0 (research) still has real
    // per-member usage, and a spend-only map attributes it to nobody at all.
    const perProduct = await q(
      `SELECT email, product, SUM(amount_cents)/100 AS spend, SUM(requests) AS requests
         FROM claude_user_cost_daily WHERE DATE_FORMAT(day,'%Y-%m')=?
        GROUP BY email, product`, [month]);
    const prodMap = {}, prodReqMap = {};
    for (const p of perProduct) {
      if (!p.email) continue;
      (prodMap[p.email] = prodMap[p.email] || {})[p.product || 'other'] = n2(p.spend);
      (prodReqMap[p.email] = prodReqMap[p.email] || {})[p.product || 'other'] = Number(p.requests) || 0;
    }
    // Tokens come from a different report (user_usage_report) than spend
    // (user_cost_report), so they are joined by email rather than folded into the
    // query above — a member can appear in one and not the other.
    const perTokens = await q(
      `SELECT email,
              SUM(total_tokens)                                    AS tokens,
              SUM(uncached_input)                                  AS uncached_input,
              SUM(cache_read)                                      AS cache_read,
              SUM(cache_creation_5m+cache_creation_1h)             AS cache_created,
              SUM(output_tokens)                                   AS output_tokens,
              SUM(web_search_requests)                             AS web_search_requests
         FROM claude_user_usage_daily WHERE DATE_FORMAT(day,'%Y-%m')=? AND email IS NOT NULL
        GROUP BY email`, [month]);
    const tokMap = {};
    for (const t of perTokens) tokMap[t.email] = t;
    const lim = await liveLimits();
    res.json({
      month,
      limitSource: lim ? 'spend-limits-api' : 'csv-import',
      limitsAsOf: lim ? lim.asOf : null,
      members: rows.map((r) => {
        const L = lim ? (lim.byEmail[r.email] || null) : null;
        const cl = r.customLimit != null ? Number(r.customLimit) : null;        // numeric working copy
        const gl = r.groupLimit != null ? Number(r.groupLimit) : null;          // imported group default
        // The CSV basis: the member's own custom limit, else the imported group default.
        // Same rule as the roster table's rowLimit() and /api/insights (customLimit ||
        // groupLimit) — measuring the two tables against different limits made the same
        // member read "over limit" on one and "no limit" on the other.
        const csvLimit = cl != null ? cl : gl;
        const customLimit = lim ? (L ? L.customLimit : null) : r.customLimit;   // dark: exactly what mysql2 returned
        const effectiveLimit = lim ? (L ? L.effectiveLimit : null) : csvLimit;
        // a "0" cap means included usage only — the docs say to treat it as already at-limit
        const pctOfLimit = lim
          ? (effectiveLimit == null ? null : (effectiveLimit === 0 ? 100 : n2((Number(r.spend) / effectiveLimit) * 100)))
          : (csvLimit ? n2((Number(r.spend) / csvLimit) * 100) : null);
        return {
          ...r, customLimit, effectiveLimit,
          unlimited: lim ? (L ? L.unlimited : false) : false,
          includedOnly: lim ? (L ? !!L.includedOnly : false) : false,
          // 'csv_group' is deliberately NOT one of the Spend Limits API source_type values
          // (user / rbac_group / seat_tier / organization): this limit came from the CSV
          // import, and nothing downstream may mistake it for a fetched per-user limit.
          limitSourceType: lim ? (L ? L.sourceType : null) : (cl != null ? 'user' : (gl != null ? 'csv_group' : null)),
          limitLabel: lim ? (L ? L.label : 'Not in Spend Limits report') : (cl != null ? 'Custom limit' : (gl != null ? 'Group limit (CSV import)' : null)),
          spend: n2(r.spend),
          matched: !!r.matchedEntra,
          departed: !!r.departedFlag,
          products: prodMap[r.email] || {},
          productRequests: prodReqMap[r.email] || {},
          pctOfLimit,
          ...tokenFields(tokMap[r.email]),
        };
      }),
    });
  } catch (e) { console.error('[claude-analytics/members]', e.message); res.status(500).json({ error: 'members failed' }); }
});

/* GET /productivity?days=30 — Claude Code + Cowork output per member. */
router.get('/productivity', read, async (req, res) => {
  try {
    const days = clampDays(req.query.days, 30);
    const allow = await scopedEmails(req);
    // scoped callers: totals cover their own people only (org-wide SQL is untouched)
    const sw = allow === null ? '' : (allow.size ? ' AND email IN (?)' : ' AND 1=0');
    const sp = allow === null || !allow.size ? [] : [[...allow]];
    const [tot] = await q(
      `SELECT SUM(cc_sessions) cc_sessions, SUM(cc_commits) commits, SUM(cc_prs) prs,
              SUM(cc_loc_added) loc_added, SUM(cc_loc_removed) loc_removed,
              SUM(cc_edits_accepted) accepted, SUM(cc_edits_rejected) rejected,
              SUM(cowork_sessions) cowork_sessions, SUM(cowork_actions) cowork_actions,
              SUM(cowork_file_edits) cowork_file_edits, SUM(chat_messages) chat_messages,
              SUM(web_search_count) web_searches
         FROM claude_user_activity_daily WHERE day > DATE_SUB(CURDATE(), INTERVAL ? DAY)${sw}`, [days, ...sp]);
    const people = (await q(
      `SELECT a.email,
              COALESCE(o.name, u.display_name) AS name,
              COALESCE(o.department, u.department) AS department,
              SUM(a.cc_sessions) cc_sessions, SUM(a.cc_commits) commits, SUM(a.cc_prs) prs,
              SUM(a.cc_loc_added) loc_added, SUM(a.cc_loc_removed) loc_removed,
              SUM(a.cc_edits_accepted) accepted, SUM(a.cc_edits_rejected) rejected,
              SUM(a.cowork_sessions) cowork_sessions, SUM(a.cowork_actions) cowork_actions,
              SUM(a.chat_messages) chat_messages, MAX(a.last_activity_date) last_active
         FROM claude_user_activity_daily a
         LEFT JOIN ${ENTRA1} u ON u.user_principal_name = a.email
         LEFT JOIN ai_directory_override o ON o.email = a.email
        WHERE a.day > DATE_SUB(CURDATE(), INTERVAL ? DAY)
        GROUP BY a.email, o.name, u.display_name, o.department, u.department
       HAVING cc_sessions > 0 OR cowork_sessions > 0 OR chat_messages > 0
        -- inside an ORDER BY expression MySQL resolves these as raw columns rather than
        -- the SELECT aliases, which trips only_full_group_by; aggregate explicitly
        ORDER BY (SUM(a.cc_sessions) + SUM(a.cowork_sessions)) DESC, SUM(a.chat_messages) DESC`, [days]))
      .filter((r) => inScope(allow, r.email));
    // cc_edits_rejected has never been populated: the Analytics API does not return
    // tool_actions.*.rejected_count for this org, and the collector's num() folds the
    // missing field to 0, which is indistinguishable from "nothing was rejected". So
    // acc/(acc+rej) is structurally 100% and means nothing. Probe the WHOLE table, not
    // just the window — an empty window must not be mistaken for a dark field — and
    // report no rate at all rather than a fabricated one. It starts reporting on its
    // own the day a single non-zero rejection lands, with no further deploy.
    const [rr] = await q(`SELECT MAX(cc_edits_rejected) maxRejected FROM claude_user_activity_daily`);
    const rejectedReported = Number(rr && rr.maxRejected) > 0;
    const acc = Number(tot.accepted) || 0, rej = Number(tot.rejected) || 0;
    res.json({
      days,
      rejectedReported,
      totals: { ...tot, acceptanceRate: rejectedReported && acc + rej > 0 ? n2((acc / (acc + rej)) * 100) : null },
      people,
    });
  } catch (e) { console.error('[claude-analytics/productivity]', e.message); res.status(500).json({ error: 'productivity failed' }); }
});

/* GET /cache?days=30 — prompt-cache effectiveness. Cached input bills at ~10% of
 * the uncached rate, so the saving is approximated as 90% of what those tokens
 * would otherwise have cost. Labelled an estimate in the response, not a fact. */
router.get('/cache', read, async (req, res) => {
  try {
    const days = clampDays(req.query.days, 30);
    const [t] = await q(
      `SELECT COALESCE(SUM(uncached_input),0) uncached_input,
              COALESCE(SUM(cache_read),0) cache_read,
              COALESCE(SUM(cache_creation_5m+cache_creation_1h),0) cache_created,
              COALESCE(SUM(output_tokens),0) output_tokens,
              COALESCE(SUM(web_search_requests),0) web_search_requests,
              COALESCE(SUM(requests),0) requests
         FROM claude_usage_daily WHERE day > DATE_SUB(CURDATE(), INTERVAL ? DAY)`, [days]);
    const byModel = await q(
      `SELECT model, SUM(uncached_input) uncached_input, SUM(cache_read) cache_read,
              SUM(cache_creation_5m+cache_creation_1h) cache_created,
              SUM(output_tokens) output_tokens, SUM(requests) requests
         FROM claude_usage_daily WHERE day > DATE_SUB(CURDATE(), INTERVAL ? DAY)
        GROUP BY model ORDER BY (SUM(uncached_input)+SUM(cache_read)) DESC`, [days]);
    res.json({
      days,
      totals: t,
      cacheHitRate: hitRate(t.cache_read, t.uncached_input, t.cache_created),
      byModel,
      note: 'cacheHitRate = cache_read / (cache_read + uncached_input + cache_created). Cache-creation tokens are a miss, not a hit, so they count in the denominator. Cached input bills at a fraction of the uncached rate; exact saving depends on per-model pricing.',

    });
  } catch (e) { console.error('[claude-analytics/cache]', e.message); res.status(500).json({ error: 'cache failed' }); }
});

/* GET /tokens?month=YYYY-MM&days=90 — the token side of the same spend.
 * Three independent slices of one number (by model, by product, by member) that the
 * collector reconciles to the same total; each is served here as stored, never
 * re-derived from another, so a divergence stays visible instead of being papered over.
 * Cost is joined per model/product so a token count can be read as a rate ($/Mtok).
 */
router.get('/tokens', read, async (req, res) => {
  try {
    const month = monthOf(req.query.month) || new Date().toISOString().slice(0, 7);
    const days = clampDays(req.query.days, 90);
    const period = periodOf(req.query);
    // one time filter for every slice below: the period when given, else the month
    const tf = (alias) => (period ? `${alias}day >= ? AND ${alias}day <= ?` : `DATE_FORMAT(${alias}day,'%Y-%m')=?`);
    const tp = period ? [period.from, period.to] : [month];
    const TOK = 'uncached_input+cache_read+cache_creation_5m+cache_creation_1h+output_tokens';

    const [tot] = await q(
      `SELECT COALESCE(SUM(uncached_input),0)  uncached_input,
              COALESCE(SUM(cache_read),0)      cache_read,
              COALESCE(SUM(cache_creation_5m+cache_creation_1h),0) cache_created,
              COALESCE(SUM(output_tokens),0)   output_tokens,
              COALESCE(SUM(${TOK}),0)          tokens,
              COALESCE(SUM(web_search_requests),0) web_search_requests,
              COALESCE(SUM(requests),0)        requests
         FROM claude_usage_daily WHERE ${tf('')}`, tp);
    const [spendRow] = await q(
      `SELECT COALESCE(SUM(amount_cents),0)/100 spend FROM claude_cost_daily
        WHERE ${tf('')}`, tp);

    // daily trend, split by token type — the shape of the bill, not just its size
    const byDay = await q(
      `SELECT day, SUM(uncached_input) uncached_input, SUM(cache_read) cache_read,
              SUM(cache_creation_5m+cache_creation_1h) cache_created,
              SUM(output_tokens) output_tokens, SUM(${TOK}) tokens, SUM(requests) requests
         FROM claude_usage_daily WHERE ${period ? 'day >= ? AND day <= ?' : 'day > DATE_SUB(CURDATE(), INTERVAL ? DAY)'}
        GROUP BY day ORDER BY day`, period ? [period.from, period.to] : [days]);

    const byModel = await q(
      `SELECT u.model, SUM(u.${TOK}) tokens, SUM(u.uncached_input) uncached_input,
              SUM(u.cache_read) cache_read, SUM(u.output_tokens) output_tokens,
              SUM(u.requests) requests, COALESCE(c.spend,0) spend
         FROM claude_usage_daily u
         LEFT JOIN (SELECT model, SUM(amount_cents)/100 spend FROM claude_cost_daily
                     WHERE ${tf('')} GROUP BY model) c ON c.model = u.model
        WHERE ${tf('u.')}
        GROUP BY u.model, c.spend ORDER BY tokens DESC`, [...tp, ...tp]);

    const byProduct = await q(
      `SELECT u.product, SUM(u.${TOK}) tokens, SUM(u.output_tokens) output_tokens,
              SUM(u.cache_read) cache_read, SUM(u.requests) requests, COALESCE(c.spend,0) spend
         FROM claude_usage_product_daily u
         LEFT JOIN (SELECT product, SUM(amount_cents)/100 spend FROM claude_cost_daily
                     WHERE ${tf('')} GROUP BY product) c ON c.product = u.product
        WHERE ${tf('u.')}
        GROUP BY u.product, c.spend ORDER BY tokens DESC`, [...tp, ...tp]);

    // top members by tokens, with their spend alongside so the two can disagree visibly.
    // Scoped callers: top 15 of THEIR people (the LIMIT moves after the scope filter).
    const allow = await scopedEmails(req);
    const topUsers = (await q(
      `SELECT t.email, MAX(t.display_name) api_name,
              COALESCE(o.name, e.display_name, MAX(t.display_name)) name,
              COALESCE(o.department, e.department) department,
              SUM(t.total_tokens) tokens, SUM(t.cache_read) cache_read,
              SUM(t.cache_creation_5m+t.cache_creation_1h) cache_created,
              SUM(t.uncached_input) uncached_input, SUM(t.output_tokens) output_tokens,
              SUM(t.requests) requests,
              COALESCE(c.spend,0) spend
         FROM claude_user_usage_daily t
         LEFT JOIN ${ENTRA1} e ON e.user_principal_name = t.email
         LEFT JOIN ai_directory_override o ON o.email = t.email
         LEFT JOIN (SELECT email, SUM(amount_cents)/100 spend FROM claude_user_cost_daily
                     WHERE ${tf('')} GROUP BY email) c ON c.email = t.email
        WHERE ${tf('t.')} AND t.email IS NOT NULL
        GROUP BY t.email, o.name, e.display_name, o.department, e.department, c.spend
        ORDER BY tokens DESC${allow === null ? ' LIMIT 15' : ''}`, [...tp, ...tp]))
      .filter((r) => inScope(allow, r.email)).slice(0, 15);

    // all-history monthly tokens, so this month reads against its own trend
    const byMonth = await q(
      `SELECT DATE_FORMAT(day,'%Y-%m') month, SUM(${TOK}) tokens, SUM(requests) requests
         FROM claude_usage_daily GROUP BY month ORDER BY month`);

    const tokens = Number(tot.tokens);
    const spend = n2(spendRow ? spendRow.spend : 0);
    const perM = (dollars, toks) => (Number(toks) > 0 ? n2((Number(dollars) / Number(toks)) * 1e6) : null);
    res.json({
      month, days, period,
      totals: { ...tot, tokens, spend },
      cacheHitRate: hitRate(tot.cache_read, tot.uncached_input, tot.cache_created),
      costPerMTok: perM(spend, tokens),
      tokensPerRequest: Number(tot.requests) > 0 ? Math.round(tokens / Number(tot.requests)) : null,
      byDay,
      byModel:   byModel.map((m)   => ({ ...m, spend: n2(m.spend), costPerMTok: perM(m.spend, m.tokens) })),
      byProduct: byProduct.map((p) => ({ ...p, spend: n2(p.spend), costPerMTok: perM(p.spend, p.tokens) })),
      topUsers:  topUsers.map((u)  => ({ ...u, spend: n2(u.spend), costPerMTok: perM(u.spend, u.tokens),
        cacheHitRate: hitRate(u.cache_read, u.uncached_input, u.cache_created) })),
      byMonth,
      note: 'Tokens are billable counters from the Analytics API (usage_report / user_usage_report). '
          + 'Cached input bills at a fraction of the uncached rate, so token share and cost share differ by design.',
    });
  } catch (e) { console.error('[claude-analytics/tokens]', e.message); res.status(500).json({ error: 'tokens failed' }); }
});

/* GET /models?month=YYYY-MM  (or ?from=YYYY-MM-DD&to=YYYY-MM-DD) — the MODEL side of the
 * same spend, for the "Model cost & efficiency" section.
 *   models[]       one row per BILLED model (base = claude_cost_daily, the point of the
 *                  section is cost), token-type split LEFT-joined from claude_usage_daily.
 *                  newInput = uncached_input + cache creation (fresh tokens, cached or not).
 *   byMonthModel[] all-history month×model spend, so the trend reads regardless of period.
 *   modelProduct[] period model×product spend (which surface drives which model).
 *   byMember[]     period per-member×model spend from claude_user_model_daily (new
 *                  2026-09-22), folded per person and rounded once. Org-wide, like /tokens.
 * Money is billed cents /100, rounded once (n2). A model with usage but literally zero
 * billed cost is out of models[] by design — this is a cost report; its tokens still
 * appear under /tokens byModel. */
router.get('/models', read, async (req, res) => {
  try {
    const month = monthOf(req.query.month) || new Date().toISOString().slice(0, 7);
    const period = periodOf(req.query);
    const tf = (a) => (period ? `${a}day >= ? AND ${a}day <= ?` : `DATE_FORMAT(${a}day,'%Y-%m')=?`);
    const tp = period ? [period.from, period.to] : [month];
    const TOK = 'uncached_input+cache_read+cache_creation_5m+cache_creation_1h+output_tokens';
    const perM = (d, t) => (Number(t) > 0 ? n2((Number(d) / Number(t)) * 1e6) : null);

    // one row per billed model: spend from cost, token-type split from usage
    const rows = await q(
      `SELECT c.model, c.spend, c.list_spend,
              COALESCE(u.requests,0) requests, COALESCE(u.uncached_input,0) uncached_input,
              COALESCE(u.cache_read,0) cache_read, COALESCE(u.cache_created,0) cache_created,
              COALESCE(u.output_tokens,0) output_tokens, COALESCE(u.tokens,0) tokens
         FROM (SELECT model, SUM(amount_cents)/100 spend, SUM(list_amount_cents)/100 list_spend
                 FROM claude_cost_daily WHERE ${tf('')} GROUP BY model) c
         LEFT JOIN (SELECT model, SUM(requests) requests, SUM(uncached_input) uncached_input,
                           SUM(cache_read) cache_read,
                           SUM(cache_creation_5m+cache_creation_1h) cache_created,
                           SUM(output_tokens) output_tokens, SUM(${TOK}) tokens
                      FROM claude_usage_daily WHERE ${tf('')} GROUP BY model) u ON u.model = c.model
        ORDER BY c.spend DESC`, [...tp, ...tp]);

    // all-history monthly spend per model, so the trend reads against its own past
    const byMonthModel = await q(
      `SELECT DATE_FORMAT(day,'%Y-%m') month, model, SUM(amount_cents)/100 spend, SUM(requests) requests
         FROM claude_cost_daily GROUP BY month, model ORDER BY month`);

    // model × product spend for the selected period
    const modelProduct = await q(
      `SELECT model, product, SUM(amount_cents)/100 spend, SUM(requests) requests
         FROM claude_cost_daily WHERE ${tf('')} GROUP BY model, product`, tp);

    // per-member × model spend for the selected period (org-wide, directory-named)
    const memberRows = await q(
      `SELECT t.email,
              COALESCE(o.name, e.display_name, MAX(t.display_name)) name,
              COALESCE(o.department, e.department) department,
              t.model, SUM(t.amount_cents)/100 spend, SUM(t.requests) requests,
              SUM(t.total_tokens) tokens
         FROM claude_user_model_daily t
         LEFT JOIN ${ENTRA1} e ON e.user_principal_name = t.email
         LEFT JOIN ai_directory_override o ON o.email = t.email
        WHERE ${tf('t.')} AND t.email IS NOT NULL AND t.deleted = 0
        GROUP BY t.email, o.name, e.display_name, o.department, e.department, t.model`, tp);

    // fold members: one object per person, spend summed raw then rounded once per model
    const allow = await scopedEmails(req);
    const mm = new Map();
    for (const r of memberRows) {
      if (!inScope(allow, r.email)) continue;
      let m = mm.get(r.email);
      if (!m) { m = { email: r.email, name: r.name, department: r.department, models: {}, spendRaw: 0, requests: 0, tokens: 0 }; mm.set(r.email, m); }
      m.models[r.model] = (m.models[r.model] || 0) + Number(r.spend);
      m.spendRaw += Number(r.spend); m.requests += Number(r.requests); m.tokens += Number(r.tokens);
    }
    const byMember = [...mm.values()].map((m) => {
      const models = {}; for (const k in m.models) models[k] = n2(m.models[k]);
      return { email: m.email, name: m.name, department: m.department, models,
               spend: n2(m.spendRaw), requests: m.requests, tokens: m.tokens };
    }).sort((a, b) => b.spend - a.spend);

    const totals = rows.reduce((s, m) => ({
      requests: s.requests + Number(m.requests), tokens: s.tokens + Number(m.tokens),
      spendRaw: s.spendRaw + Number(m.spend), listRaw: s.listRaw + Number(m.list_spend),
      uncached_input: s.uncached_input + Number(m.uncached_input), cache_read: s.cache_read + Number(m.cache_read),
      cache_created: s.cache_created + Number(m.cache_created), output_tokens: s.output_tokens + Number(m.output_tokens),
    }), { requests: 0, tokens: 0, spendRaw: 0, listRaw: 0, uncached_input: 0, cache_read: 0, cache_created: 0, output_tokens: 0 });
    totals.spend = n2(totals.spendRaw); totals.list_spend = n2(totals.listRaw);

    res.json({
      month, period,
      totals,
      blendedPerMTok: perM(totals.spend, totals.tokens),
      avgPerRequest: Number(totals.requests) > 0 ? n2(totals.spend / Number(totals.requests)) : null,
      models: rows.map((m) => ({
        model: m.model, requests: Number(m.requests),
        newInput: Number(m.uncached_input) + Number(m.cache_created),
        cache_read: Number(m.cache_read), output_tokens: Number(m.output_tokens),
        tokens: Number(m.tokens), spend: n2(m.spend), list_spend: n2(m.list_spend),
        perRequest: Number(m.requests) > 0 ? n2(Number(m.spend) / Number(m.requests)) : null,
        costPerMTok: perM(m.spend, m.tokens),
        listPerMTok: perM(m.list_spend, m.tokens),
      })),
      byMonthModel: byMonthModel.map((r) => ({ ...r, spend: n2(r.spend) })),
      modelProduct: modelProduct.map((r) => ({ ...r, spend: n2(r.spend) })),
      byMember,
      note: 'Per-model cost is Anthropic billed spend (claude_cost_daily); the token-type split '
          + 'is from usage_report by model. New input = uncached input plus cache-creation (writes). '
          + 'Per-member×model is from the per-user model report and reconciles to the cent on closed days.',
    });
  } catch (e) { console.error('[claude-analytics/models]', e.message); res.status(500).json({ error: 'models failed' }); }
});

/* GET /sessions?days=90&seatCost=20&defaultLimit=100
 * The executive session breakdown: ONE row per Claude member over a ROLLING window,
 * with the session/activity split, token usage, spend and the seat-cost model.
 *
 * Why a rolling window and not the calendar month: /analytics/users publishes a day
 * some hours after it ends, so on the 1st-2nd of a month the month-to-date activity
 * is empty or one day deep — which is exactly how every activity column came to read
 * "—". A rolling window always has data in it.
 *
 * EVERY member is returned, including those with no activity at all (roster UNION
 * observed), zero-filled rather than dropped, so "all members" means all members.
 *
 * seatCost is the CONTRACTED per-seat rate (confirmed 2026-09-02) and defaultLimit the
 * assumed cap for members without one. Neither is readable from any endpoint — Enterprise
 * bills on consumption — so both are echoed under `assumptions` and every surface that
 * spends them says where they came from. Seats are billed to holders only: see `departed`.
 */
router.get('/sessions', read, async (req, res) => {
  try {
    const period = periodOf(req.query);
    const days = period ? period.days : clampDays(req.query.days, 90);
    const seatCost = Math.max(0, Number(req.query.seatCost) || 20);
    const defaultLimit = Math.max(0, Number(req.query.defaultLimit) || 100);
    // "last N days" = the N dates ending today, so the window opens N-1 days back; an
    // inclusive bound at CURDATE()-N spans N+1 dates. All twelve call sites below read
    // `day >= ${since} AND day <= ${until}`, so the bounds are set once, here. With a
    // reporting period (2026-09-15) both bounds are the validated period dates.
    const since = period ? `'${period.from}'` : `DATE_SUB(CURDATE(), INTERVAL ${days - 1} DAY)`;
    const until = period ? `'${period.to}'` : `CURDATE()`;

    // Roster (2026-10-21): the live Members API table when fresh, else the last CSV import.
    // onRoster used to mean "in the CSV import"; that import dates from 2026-08-01, so every
    // seat added since showed as departed or not at all. Same rule /shared/ai-usage follows.
    let rosterRows = [];
    try { rosterRows = await q(`SELECT email, fetched_at FROM claude_member WHERE email IS NOT NULL`); }
    catch (e) { if (e.code !== 'ER_NO_SUCH_TABLE') console.error('[sessions] live roster unavailable, using CSV:', e.message); rosterRows = []; }
    const rosterLive = rosterRows.length > 0 && CL.isFresh(CL.newestFetchedAt(rosterRows));
    const rosterSql = rosterLive
      ? `SELECT email FROM claude_member WHERE email IS NOT NULL`
      : `SELECT email FROM ai_usage_member
               WHERE platform='claude' AND email IS NOT NULL
                 AND month=(SELECT MAX(month) FROM ai_usage_member WHERE platform='claude')`;
    // License assigned (2026-10-30): claude_member.added_at = the date Anthropic granted the
    // seat. Read-only, additive; a member no longer in claude_member reads NULL (never guessed).
    const licSql = rosterRows.length > 0
      ? `SELECT email, MIN(added_at) added_at FROM claude_member WHERE email IS NOT NULL GROUP BY email`
      : `SELECT NULL AS email, NULL AS added_at`;

    const rows = await q(
      `SELECT r.email,
              COALESCE(o.name, u.display_name, c.api_name, t.api_name) AS name,
              COALESCE(o.department, u.department)      AS department,
              COALESCE(o.manager, mg.display_name)      AS manager,
              u.account_enabled                         AS accountEnabled,
              (u.entra_id IS NOT NULL OR o.email IS NOT NULL) AS matched,
              lim.custom_limit                          AS customLimit,
              lim.group_limit                           AS groupLimit,
              (ros.email IS NOT NULL)                   AS onRoster,
              lic.added_at                              AS licenseAddedAt,
              c.departed                                AS departedFlag,
              -- session / activity split
              a.lastActive, a.daysActive, a.chats, a.messages,
              a.projectsCreated, a.projectsUsed, a.artifacts, a.skillsUsed,
              a.codeSessions, a.commits, a.prs, a.locAdded, a.locRemoved,
              a.editsAccepted, a.editsRejected,
              a.coworkSessions, a.coworkMessages, a.coworkActions, a.coworkFileEdits,
              a.officeSessions, a.designSessions, a.scienceSessions, a.webSearches,
              -- tokens
              t.tokens, t.uncached_input, t.cache_read, t.cache_created,
              t.output_tokens, t.tokenRequests,
              -- money
              c.spend, c.requests
         FROM (
              ${rosterSql}
              UNION SELECT DISTINCT email FROM claude_user_cost_daily
               WHERE day >= ${since} AND day <= ${until} AND email IS NOT NULL
              UNION SELECT DISTINCT email FROM claude_user_activity_daily
               WHERE day >= ${since} AND day <= ${until} AND email IS NOT NULL
              UNION SELECT DISTINCT email FROM claude_user_usage_daily
               WHERE day >= ${since} AND day <= ${until} AND email IS NOT NULL
         ) r
         LEFT JOIN (
              SELECT email, MAX(last_activity_date) lastActive,
                     COUNT(DISTINCT CASE WHEN (chat_messages>0 OR cc_sessions>0 OR cowork_sessions>0
                                            OR office_sessions>0 OR design_sessions>0 OR science_sessions>0)
                                         THEN day END) daysActive,
                     SUM(chat_conversations) chats, SUM(chat_messages) messages,
                     SUM(chat_projects_created) projectsCreated, SUM(chat_projects_used) projectsUsed,
                     SUM(chat_artifacts) artifacts, SUM(chat_skills_used) skillsUsed,
                     SUM(cc_sessions) codeSessions, SUM(cc_commits) commits, SUM(cc_prs) prs,
                     SUM(cc_loc_added) locAdded, SUM(cc_loc_removed) locRemoved,
                     SUM(cc_edits_accepted) editsAccepted, SUM(cc_edits_rejected) editsRejected,
                     SUM(cowork_sessions) coworkSessions, SUM(cowork_messages) coworkMessages,
                     SUM(cowork_actions) coworkActions, SUM(cowork_file_edits) coworkFileEdits,
                     SUM(office_sessions) officeSessions, SUM(design_sessions) designSessions,
                     SUM(science_sessions) scienceSessions, SUM(web_search_count) webSearches
                FROM claude_user_activity_daily
               WHERE day >= ${since} AND day <= ${until} AND email IS NOT NULL GROUP BY email
         ) a ON a.email = r.email
         LEFT JOIN (
              SELECT email, MAX(display_name) api_name,
                     SUM(amount_cents)/100 spend, SUM(requests) requests, MAX(deleted) departed
                FROM claude_user_cost_daily
               WHERE day >= ${since} AND day <= ${until} AND email IS NOT NULL GROUP BY email
         ) c ON c.email = r.email
         LEFT JOIN (
              SELECT email, MAX(display_name) api_name,
                     SUM(total_tokens) tokens, SUM(uncached_input) uncached_input,
                     SUM(cache_read) cache_read,
                     SUM(cache_creation_5m+cache_creation_1h) cache_created,
                     SUM(output_tokens) output_tokens, SUM(requests) tokenRequests
                FROM claude_user_usage_daily
               WHERE day >= ${since} AND day <= ${until} AND email IS NOT NULL GROUP BY email
         ) t ON t.email = r.email
         LEFT JOIN ${ENTRA1} u  ON u.user_principal_name = r.email
         LEFT JOIN ${ENTRA1} mg ON mg.user_principal_name = u.manager_upn
         LEFT JOIN ai_directory_override o ON o.email = r.email
         LEFT JOIN (SELECT email, custom_limit, group_limit FROM ai_usage_member
                     WHERE platform='claude'
                       AND month=(SELECT MAX(month) FROM ai_usage_member WHERE platform='claude')
         ) lim ON lim.email = r.email
         LEFT JOIN (${rosterSql}) ros ON ros.email = r.email
         LEFT JOIN (${licSql}) lic ON lic.email = r.email
        ORDER BY c.spend DESC, t.tokens DESC, r.email`);

    /* Suggested limit = the member's average monthly spend over the last 3 COMPLETE
     * months. The current month is excluded deliberately: on the 2nd it is two days
     * deep and would drag every suggestion to near zero. The denominator is the full
     * 3 months (someone who spent in only one of them really did average a third of
     * it), and the per-month figures are returned so the number can be audited and
     * overridden rather than taken on trust. */
    const hist = await q(
      `SELECT email, DATE_FORMAT(day,'%Y-%m') ym, SUM(amount_cents)/100 spend
         FROM claude_user_cost_daily
        WHERE day >= DATE_FORMAT(DATE_SUB(CURDATE(), INTERVAL 3 MONTH),'%Y-%m-01')
          AND day <  DATE_FORMAT(CURDATE(),'%Y-%m-01')
          AND email IS NOT NULL
        GROUP BY email, ym`);
    const histMonths = [...new Set(hist.map((h) => h.ym))].sort();
    const histMap = {};
    for (const h of hist) (histMap[h.email] = histMap[h.email] || {})[h.ym] = n2(h.spend);

    // The org's own seat count, live from the API. Published alongside the billed count
    // so the two can be compared instead of one silently standing in for the other.
    const [seatRow] = await q(
      `SELECT assigned_seats FROM claude_summary_daily ORDER BY day DESC LIMIT 1`);
    const assignedSeats = seatRow ? Number(seatRow.assigned_seats) || null : null;

    // Seat cost ACROSS THE WINDOW. Charging one month of seats against 90 days of usage
    // understated the seat side by ~2 months, and the seat count itself moved during the
    // window — so each day is priced at that day's own seat count, prorated by the length
    // of its month. Returned alongside the monthly run rate; they answer different questions.
    let seatMonths, seatCostWindow;
    if (period) {
      // FULL-CALENDAR-MONTH BILLING (2026-09-15). Each month in the period is charged at that
      // month's assigned-seat count × the contracted rate — no day proration, so a one-seat
      // department reads $20.00, never $19.19. The current month is a whole month's commitment
      // and the page labels it MTD. (Anthropic actually invoices each added seat up front for
      // the rest of the annual term; that cash view lives in the billing ledger.)
      const sm = await q(
        `SELECT DATE_FORMAT(day,'%Y-%m') m, MAX(assigned_seats) seats FROM claude_summary_daily
          WHERE day >= ${since} AND day <= ${until} GROUP BY m`);
      seatMonths = sm.reduce((a, r) => a + (Number(r.seats) || 0), 0);
      seatCostWindow = n2(seatMonths * seatCost);
    } else {
      const [seatWin] = await q(
        `SELECT COALESCE(SUM(assigned_seats / DAY(LAST_DAY(day))), 0) AS seat_months
           FROM claude_summary_daily WHERE day >= ${since} AND day <= ${until}`);
      seatMonths = Number(seatWin ? seatWin.seat_months : 0) || 0;
      seatCostWindow = n2(seatMonths * seatCost);
    }

    const liveLim = await liveLimits();
    const allowance = allowanceFor(days);
    const N = (v) => Number(v) || 0;
    // mysql2 returns DATE columns as Date objects; slicing their toString gives "Tue Sep 01"
    const d10 = (v) => {
      if (!v) return null;
      if (v instanceof Date) {
        return v.getFullYear() + '-' + String(v.getMonth() + 1).padStart(2, '0')
             + '-' + String(v.getDate()).padStart(2, '0');
      }
      return String(v).slice(0, 10);
    };
    const allMembers = rows.map((r) => {
      const L = liveLim ? (liveLim.byEmail[r.email] || null) : null;
      // Departed = the API marked the actor deleted, or they are no longer on the roster.
      // Their spend is real and stays on the books; their SEAT and their LIMIT do not —
      // we stopped paying for the seat, and a cap on someone who left is not a commitment.
      // Declared here because the limit block below reads it.
      const departed = !!r.departedFlag || !r.onRoster;
      const seatCostRow = departed ? 0 : seatCost * (period ? period.months : 1);
      // the limit that actually applies: a live cap, else a per-member custom limit,
      // else the org default the executives asked us to assume
      const custom = r.customLimit != null ? Number(r.customLimit) : null;
      const effective = departed ? null
                      : (liveLim && L ? L.effectiveLimit
                                      : (custom != null ? custom : defaultLimit));
      const limitSource = departed ? 'departed'
                        : (liveLim && L ? (L.sourceType || 'api')
                                        : (custom != null ? 'custom' : 'default'));
      const spendRaw = Number(r.spend) || 0;   // full precision, for totals
      const spend = n2(spendRaw);              // 2dp, for display
      const tokens = N(r.tokens);
      const cr = N(r.cache_read), un = N(r.uncached_input);
      const sessions = N(r.chats) + N(r.codeSessions) + N(r.coworkSessions)
                     + N(r.officeSessions) + N(r.designSessions) + N(r.scienceSessions);
      const active = sessions > 0 || N(r.messages) > 0 || N(r.spend) > 0 || tokens > 0;
      return {
        email: r.email,
        name: r.name || r.email,
        department: r.department || null,
        manager: r.manager || null,
        matched: !!r.matched,
        accountEnabled: r.accountEnabled == null ? null : !!r.accountEnabled,
        lastActive: d10(r.lastActive),
        licenseAssigned: d10(r.licenseAddedAt),
        daysActive: N(r.daysActive),
        // session breakdown
        sessions,
        chats: N(r.chats), messages: N(r.messages),
        projectsCreated: N(r.projectsCreated), projectsUsed: N(r.projectsUsed),
        artifacts: N(r.artifacts), skillsUsed: N(r.skillsUsed),
        codeSessions: N(r.codeSessions), commits: N(r.commits), prs: N(r.prs),
        locAdded: N(r.locAdded), locRemoved: N(r.locRemoved),
        editsAccepted: N(r.editsAccepted), editsRejected: N(r.editsRejected),
        coworkSessions: N(r.coworkSessions), coworkMessages: N(r.coworkMessages),
        coworkActions: N(r.coworkActions), coworkFileEdits: N(r.coworkFileEdits),
        officeSessions: N(r.officeSessions), designSessions: N(r.designSessions),
        scienceSessions: N(r.scienceSessions), webSearches: N(r.webSearches),
        // tokens
        tokens, tokensUncached: un, tokensCacheRead: cr,
        tokensCacheCreated: N(r.cache_created), tokensOutput: N(r.output_tokens),
        cacheHitRate: hitRate(cr, un, N(r.cache_created)),
        // money
        spend, spendRaw, requests: N(r.requests),
        departed, holdsSeat: !departed,
        seatCost: seatCostRow,
        totalCost: n2(seatCostRow + spend),
        effectiveLimit: effective,
        limitSource,
        pctOfLimit: effective > 0 ? n2((spend / effective) * 100) : null,
        overLimit: effective > 0 && spend > effective,
        costPerMTok: tokens > 0 ? n2((spend / tokens) * 1e6) : null,
        active,
        ...(departed
          ? { projectedMonthlySpend: 0, utilisationPct: null, unusedAllowance: null,
              recommendation: 'departed',
              recommendationReason: 'No longer an active member — the seat is already gone.',
              recommendationConfident: true }
          : allowance(spend, effective, active)),
        ...(departed
          ? { avg3moSpend: 0, max3moSpend: 0, months3: [], monthsWithSpend: 0,
              suggestedLimit: 0, suggestedBelowPeak: false, suggestedLimitDelta: null }
          : suggestLimit(histMap[r.email], histMonths, effective)),
      };
    });
    // DATA SCOPE (F28): every total and department below is built from `members`, so it
    // follows the scope. The window seat charge is org-wide; a scoped caller gets their
    // members' share of it (same ratio, so the department seatScale is unchanged), and the
    // org seat count is nulled, as /api/insights/shared/ai-usage does.
    const allow = await scopedEmails(req);
    const members = allow === null ? allMembers : allMembers.filter((m) => inScope(allow, m.email));
    if (allow !== null) {
      const orgSeat = allMembers.reduce((a, m) => a + m.seatCost, 0);
      seatCostWindow = orgSeat > 0 ? n2(seatCostWindow * members.reduce((a, m) => a + m.seatCost, 0) / orgSeat) : 0;
    }

    const activeM = members.filter((m) => m.active);
    const sum = (f) => members.reduce((a, m) => a + (m[f] || 0), 0);

    /* The three sources do not span the same history: cost and tokens go back to the
     * first collected day, activity only as far as the activity collector has run.
     * A 90-day window over 31 days of activity is not wrong, but calling it "90 days"
     * without saying so would be — so the real coverage of each source is reported. */
    const [cov] = await q(
      `SELECT (SELECT MIN(day) FROM claude_user_cost_daily     WHERE day >= ${since} AND day <= ${until}) cost_first,
              (SELECT MAX(day) FROM claude_user_cost_daily     WHERE day >= ${since} AND day <= ${until}) cost_last,
              (SELECT MIN(day) FROM claude_user_activity_daily WHERE day >= ${since} AND day <= ${until}) act_first,
              (SELECT MAX(day) FROM claude_user_activity_daily WHERE day >= ${since} AND day <= ${until}) act_last,
              (SELECT MIN(day) FROM claude_user_usage_daily    WHERE day >= ${since} AND day <= ${until}) tok_first,
              (SELECT MAX(day) FROM claude_user_usage_daily    WHERE day >= ${since} AND day <= ${until}) tok_last`);

    /* Department rollup for the CFO view. Built from the SAME member rows the table
     * renders, so a department total can never disagree with the members inside it.
     * Members with no directory department are kept under "Unassigned" rather than
     * dropped — the rollup has to sum to the invoice. */
    const byDept = {};
    for (const m of members) {
      const d = m.department || 'Unassigned';
      const g = byDept[d] || (byDept[d] = { department: d, members: 0, activeMembers: 0,
        spend: 0, tokens: 0, sessions: 0, messages: 0, seatCostTotal: 0,
        currentLimitTotal: 0, suggestedLimitTotal: 0, unusedAllowance: 0,
        recommendations: {}, topSpender: null });
      g.members++; if (m.active) g.activeMembers++;
      g.spend += m.spendRaw; g.tokens += m.tokens; g.sessions += m.sessions; g.messages += m.messages;
      g.seatCostTotal += m.seatCost;
      g.currentLimitTotal += m.effectiveLimit || 0;
      g.suggestedLimitTotal += m.suggestedLimit || 0;
      g.unusedAllowance += m.unusedAllowance || 0;
      g.recommendations[m.recommendation] = (g.recommendations[m.recommendation] || 0) + 1;
      if (!g.topSpender || m.spend > g.topSpender.spend) g.topSpender = { name: m.name, email: m.email, spend: m.spend };
    }
    const monthlySeatSum = members.reduce((a, m) => a + m.seatCost, 0);
    // With a reporting period the per-member figure is already the full-month charge, so
    // departments are NOT rescaled to the window (that rescale is what produced $19.19).
    const seatScale = period ? 1 : (monthlySeatSum > 0 ? seatCostWindow / monthlySeatSum : 0);
    const departments = Object.values(byDept).map((g) => ({
      ...g,
      spend: n2(g.spend),
      seatCostTotal: n2(g.seatCostTotal * seatScale),
      totalCost: n2(g.seatCostTotal * seatScale + g.spend),
      currentLimitTotal: n2(g.currentLimitTotal),
      suggestedLimitTotal: n2(g.suggestedLimitTotal),
      unusedAllowance: n2(g.unusedAllowance),
      // the CFO's two averages: across everyone holding a seat, and across everyone using it
      avgSpendPerUser: n2(g.spend / (g.members || 1)),
      avgSpendPerActiveUser: g.activeMembers ? n2(g.spend / g.activeMembers) : null,
      avgTotalCostPerUser: n2((g.seatCostTotal * seatScale + g.spend) / (g.members || 1)),
      avgTokensPerUser: Math.round(g.tokens / (g.members || 1)),
      pctOfSpend: null,   // filled once the grand total is known
    })).sort((a, b) => b.totalCost - a.totalCost);
    const grandSpend = departments.reduce((a, d) => a + d.spend, 0) || 1;
    departments.forEach((d) => { d.pctOfSpend = n2((d.spend / grandSpend) * 100); });
    res.json({
      days,
      period: period ? { from: period.from, to: period.to, months: period.months, axis: period.axis } : null,
      windowStart: period ? period.from : new Date(Date.now() - (days - 1) * 864e5).toISOString().slice(0, 10),
      generatedAt: new Date().toISOString().slice(0, 19).replace('T', ' '),
      assumptions: {
        seatCost, defaultLimit,
        note: 'seatCost is the contracted per-seat rate, applied to seats reported as assigned. '
            + 'defaultLimit is the assumed cap for members with no custom limit of their own. '
            + 'Seats are billed to holders only — see the departed flag.',
      },
      totals: {
        members: members.length,
        activeMembers: activeM.length,
        inactiveMembers: members.length - activeM.length,
        sessions: sum('sessions'), messages: sum('messages'),
        chats: sum('chats'), coworkSessions: sum('coworkSessions'),
        codeSessions: sum('codeSessions'),
        tokens: sum('tokens'),
        spend: n2(sum('spendRaw')),
        assignedSeats: allow === null ? assignedSeats : null,
        seatsBilled: members.filter((m) => m.holdsSeat).length,
        // monthly run rate (what we pay this month) vs the window's actual seat charge
        seatCostMonthly: n2(sum('seatCost')),
        seatCostWindow,
        departedMembers: members.filter((m) => m.departed).length,
        // seatCostTotal is the WINDOW charge, so it pairs with window usage in totalCost
        seatCostTotal: seatCostWindow,
        // the number the executives actually asked for: seats + metered usage, same window
        totalCost: n2(seatCostWindow + sum('spendRaw')),
        // sum(displayed rows) - invoice-accurate total; non-zero only from cent rounding
        rowRoundingDelta: n2(sum('spend') - n2(sum('spendRaw'))),
        overLimit: members.filter((m) => m.overLimit).length,
        // what the allowance review is actually worth: the monthly dollars we have
        // handed out to people who are not spending them
        unusedAllowance: n2(members.reduce((a, m) => a + (m.unusedAllowance || 0), 0)),
        recommendations: members.reduce((a, m) => {
          a[m.recommendation] = (a[m.recommendation] || 0) + 1; return a;
        }, {}),
        recommendationsConfident: days >= 14,
        seatBasis: period ? 'full-calendar-month' : 'rolling-window-prorated',
        // what re-basing every limit on 3-month history would do to the committed total
        currentLimitTotal: n2(members.reduce((a, m) => a + (m.effectiveLimit || 0), 0)),
        suggestedLimitTotal: n2(members.reduce((a, m) => a + (m.suggestedLimit || 0), 0)),
        suggestedLimitDelta: n2(members.reduce((a, m) => a + (m.suggestedLimit || 0), 0)
                              - members.reduce((a, m) => a + (m.effectiveLimit || 0), 0)),
        historyMonths: histMonths,
        departments: departments.length,
        avgSpendPerUser: n2(sum('spendRaw') / (members.length || 1)),
        avgSpendPerActiveUser: activeM.length ? n2(sum('spendRaw') / activeM.length) : null,
        avgTotalCostPerUser: n2((seatCostWindow + sum('spendRaw')) / (members.length || 1)),
      },
      coverage: {
        cost:     { first: d10(cov.cost_first), last: d10(cov.cost_last) },
        activity: { first: d10(cov.act_first),  last: d10(cov.act_last) },
        tokens:   { first: d10(cov.tok_first),  last: d10(cov.tok_last) },
      },
      departments,
      members,
    });
  } catch (e) { console.error('[claude-analytics/sessions]', e.message); res.status(500).json({ error: 'sessions failed' }); }
});

/* GET /health — collector freshness, for an honest "data as of" stamp. */
router.get('/health', read, async (req, res) => {
  try {
    const runs = await q(
      `SELECT endpoint, MAX(ran_at) last_ok, MAX(rows_upserted) rows_last,
              MAX(data_refreshed_at) data_refreshed_at
         FROM claude_sync_log WHERE status='ok' GROUP BY endpoint ORDER BY endpoint`);
    const errors = await q(
      `SELECT endpoint, ran_at, LEFT(error,300) error FROM claude_sync_log
        WHERE status='error' ORDER BY ran_at DESC LIMIT 5`);
    const [cov] = await q(
      `SELECT MIN(day) first_day, MAX(day) last_day, COUNT(DISTINCT day) days
         FROM claude_cost_daily`);
    // Admin-scoped endpoints: latest status each ('ok' | 'no-scope' | 'error') and when it was
    // last checked, so the page can say whether spend limits / roster are live.
    const scopes = await q(
      `SELECT s.endpoint, s.status, s.ran_at, LEFT(s.error,200) AS error
         FROM claude_sync_log s
         JOIN (SELECT endpoint, MAX(id) mx FROM claude_sync_log
                WHERE endpoint IN ('spend_limits','limit_requests','members') GROUP BY endpoint) t
           ON t.mx = s.id
        ORDER BY s.endpoint`);
    res.json({ runs, recentErrors: errors, coverage: cov, scopes });
  } catch (e) { console.error('[claude-analytics/health]', e.message); res.status(500).json({ error: 'health failed' }); }
});

/* GET /insights — the three decision-grade views: budget risk, idle seats, and
 * model efficiency. Detection only: this endpoint never sends anything. Wiring
 * Slack/email delivery is a separate, explicitly-approved step.
 *   ?limitPct=80   flag members at/above this share of their limit
 *   ?idleDays=30   a seat is idle with no spend AND no activity in this window
 */
router.get('/insights', read, async (req, res) => {
  try {
    const month = monthOf(req.query.month) || new Date().toISOString().slice(0, 7);
    const limitPct = Math.max(1, Math.min(100, parseInt(req.query.limitPct, 10) || 80));
    const idleDays = clampDays(req.query.idleDays, 30);
    // DATA SCOPE (F28): nearLimit, idle and movers name people; budget and models are org totals.
    const allow = await scopedEmails(req);

    // ---- budget risk -------------------------------------------------------
    const [mtd] = await q(
      `SELECT COALESCE(SUM(amount_cents),0)/100 AS spend FROM claude_cost_daily
        WHERE DATE_FORMAT(day,'%Y-%m')=?`, [month]);
    const [snap] = await q(
      `SELECT org_limit AS orgLimit, month FROM ai_org_snapshot
        WHERE platform='claude' AND month <= CONCAT(?,'-01') ORDER BY month DESC LIMIT 1`, [month]);
    const now = new Date();
    const isCurrent = month === now.toISOString().slice(0, 7);
    const daysInMonth = new Date(Date.UTC(+month.slice(0, 4), +month.slice(5, 7), 0)).getUTCDate();
    const elapsed = isCurrent ? now.getUTCDate() : daysInMonth;
    const spend = Number(mtd.spend) || 0;
    const projected = elapsed > 0 ? (spend / elapsed) * daysInMonth : 0;
    const orgLimit = snap && snap.orgLimit != null ? Number(snap.orgLimit) : null;
    const budget = {
      month, spend: n2(spend), projected: n2(projected),
      orgLimit, orgLimitAsOf: snap ? String(snap.month).slice(0, 10) : null,
      orgLimitSource: 'csv-import',            // no API exposes this on any key
      pctOfLimitNow: orgLimit ? n2((spend / orgLimit) * 100) : null,
      pctOfLimitProjected: orgLimit ? n2((projected / orgLimit) * 100) : null,
      willExceed: orgLimit ? projected > orgLimit : null,
      daysRemaining: Math.max(0, daysInMonth - elapsed),
    };

    // ---- members near their limit ------------------------------------------
    // Limits come from the Spend Limits API when live (any source: override, group, tier,
    // org default), otherwise from the CSV import; both are flagged in nearLimitNote.
    const lim = await liveLimits();
    let nearLimit;
    if (lim) {
      const spendRows = await q(
        `SELECT c.email, COALESCE(o.name,u.display_name,MAX(c.display_name)) AS name,
                COALESCE(o.department,u.department) AS department, SUM(c.amount_cents)/100 AS spend
           FROM claude_user_cost_daily c
           LEFT JOIN entra_users u ON u.user_principal_name=c.email
           LEFT JOIN ai_directory_override o ON o.email=c.email
          WHERE DATE_FORMAT(c.day,'%Y-%m')=? AND c.deleted=0
          GROUP BY c.email,o.name,u.display_name,o.department,u.department`, [month]);
      nearLimit = spendRows.map((r) => {
        const L = lim.byEmail[r.email]; const cap = L ? L.effectiveLimit : null;
        if (cap == null) return null;                                    // unlimited, or not in the report
        const pct = cap > 0 ? (Number(r.spend) / cap) * 100 : 100;       // "0" cap = included usage only = at-limit
        return { row: { ...r, customLimit: cap, limitSourceType: L.sourceType, limitLabel: L.label, includedOnly: !!L.includedOnly }, pct };
      }).filter((x) => x && x.pct >= limitPct).sort((a, b) => b.pct - a.pct).map((x) => x.row);
    } else nearLimit = await q(
      `SELECT c.email, COALESCE(o.name,u.display_name,MAX(c.display_name)) AS name,
              COALESCE(o.department,u.department) AS department,
              SUM(c.amount_cents)/100 AS spend, lim.custom_limit AS customLimit
         FROM claude_user_cost_daily c
         LEFT JOIN entra_users u ON u.user_principal_name=c.email
         LEFT JOIN ai_directory_override o ON o.email=c.email
         JOIN (SELECT a.email, a.custom_limit FROM ai_usage_member a
                 JOIN (SELECT email,MAX(month) mx FROM ai_usage_member
                        WHERE platform='claude' GROUP BY email) t
                   ON t.email=a.email AND t.mx=a.month
                WHERE a.platform='claude' AND a.custom_limit IS NOT NULL) lim
           ON lim.email=c.email
        WHERE DATE_FORMAT(c.day,'%Y-%m')=? AND c.deleted=0
        GROUP BY c.email,o.name,u.display_name,o.department,u.department,lim.custom_limit
       HAVING customLimit > 0 AND (SUM(c.amount_cents)/100)/customLimit*100 >= ?
        ORDER BY (SUM(c.amount_cents)/100)/lim.custom_limit DESC`, [month, limitPct]);
    nearLimit = nearLimit.filter((r) => inScope(allow, r.email));

    // ---- idle seats ---------------------------------------------------------
    // Roster = last import (the only roster we have without read:members), minus
    // anyone with spend or recorded activity inside the window.
    const idle = (await q(
      `SELECT r.email, COALESCE(o.name,u.display_name,r.name_raw) AS name,
              COALESCE(o.department,u.department) AS department,
              u.account_enabled AS accountEnabled,
              (SELECT MAX(a.last_activity_date) FROM claude_user_activity_daily a
                WHERE a.email=r.email) AS lastActivity,
              (SELECT COALESCE(SUM(c.amount_cents),0)/100 FROM claude_user_cost_daily c
                WHERE c.email=r.email) AS lifetimeSpend
         FROM (SELECT a.email, a.name_raw FROM ai_usage_member a
                 JOIN (SELECT email,MAX(month) mx FROM ai_usage_member
                        WHERE platform='claude' GROUP BY email) t
                   ON t.email=a.email AND t.mx=a.month
                WHERE a.platform='claude') r
         LEFT JOIN entra_users u ON u.user_principal_name=r.email
         LEFT JOIN ai_directory_override o ON o.email=r.email
        WHERE r.email NOT IN (
                SELECT DISTINCT email FROM claude_user_cost_daily
                 WHERE day > DATE_SUB(CURDATE(), INTERVAL ? DAY) AND amount_cents > 0)
          AND r.email NOT IN (
                SELECT DISTINCT email FROM claude_user_activity_daily
                 WHERE day > DATE_SUB(CURDATE(), INTERVAL ? DAY)
                   AND (chat_messages>0 OR cc_sessions>0 OR cowork_sessions>0))
        ORDER BY lifetimeSpend ASC, name`, [idleDays, idleDays])).filter((r) => inScope(allow, r.email));

    // ---- model efficiency ---------------------------------------------------
    // Cost per request and per million tokens, so an expensive model doing cheap
    // work is visible next to a cheap model doing lots of it.
    const models = await q(
      `SELECT c.model,
              SUM(c.amount_cents)/100 AS spend, SUM(c.requests) AS requests,
              COALESCE(t.in_tok,0) AS input_tokens, COALESCE(t.out_tok,0) AS output_tokens,
              COALESCE(t.cache_read,0) AS cache_read
         FROM claude_cost_daily c
         LEFT JOIN (SELECT model, SUM(uncached_input) in_tok, SUM(output_tokens) out_tok,
                           SUM(cache_read) cache_read
                      FROM claude_usage_daily
                     WHERE day > DATE_SUB(CURDATE(), INTERVAL ? DAY) GROUP BY model) t
           ON t.model = c.model
        WHERE c.day > DATE_SUB(CURDATE(), INTERVAL ? DAY) AND c.model <> ''
        GROUP BY c.model, t.in_tok, t.out_tok, t.cache_read
       HAVING spend > 0
        ORDER BY spend DESC`, [idleDays, idleDays]);
    const modelRows = models.map((m) => {
      const reqs = Number(m.requests) || 0;
      const tok = Number(m.input_tokens) + Number(m.output_tokens) + Number(m.cache_read);
      return { model: m.model, spend: n2(m.spend), requests: reqs,
        costPerRequest: reqs ? Math.round((Number(m.spend) / reqs) * 10000) / 10000 : null,
        totalTokens: tok,
        costPerMillionTokens: tok ? n2((Number(m.spend) / tok) * 1e6) : null };
    });

    // ---- week-over-week movers ----------------------------------------------
    const movers = (await q(
      `SELECT c.email, COALESCE(o.name,u.display_name,MAX(c.display_name)) AS name,
              SUM(CASE WHEN c.day > DATE_SUB(CURDATE(), INTERVAL 7 DAY)
                       THEN c.amount_cents ELSE 0 END)/100 AS thisWeek,
              SUM(CASE WHEN c.day > DATE_SUB(CURDATE(), INTERVAL 14 DAY)
                        AND c.day <= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
                       THEN c.amount_cents ELSE 0 END)/100 AS lastWeek
         FROM claude_user_cost_daily c
         LEFT JOIN entra_users u ON u.user_principal_name=c.email
         LEFT JOIN ai_directory_override o ON o.email=c.email
        WHERE c.day > DATE_SUB(CURDATE(), INTERVAL 14 DAY) AND c.deleted=0
        GROUP BY c.email,o.name,u.display_name
       HAVING thisWeek > 5 AND thisWeek > lastWeek * 2
        ORDER BY (SUM(CASE WHEN c.day > DATE_SUB(CURDATE(), INTERVAL 7 DAY)
                           THEN c.amount_cents ELSE 0 END)
                  - SUM(CASE WHEN c.day > DATE_SUB(CURDATE(), INTERVAL 14 DAY)
                              AND c.day <= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
                             THEN c.amount_cents ELSE 0 END)) DESC${allow === null ? ' LIMIT 10' : ''}`))
      .filter((r) => inScope(allow, r.email)).slice(0, 10);

    res.json({
      month, limitPct, idleDays,
      limits: { source: lim ? 'spend-limits-api' : 'csv-import', asOf: lim ? lim.asOf : null,
                defaultLimit: lim ? lim.defaultLimit : null, defaultSource: lim ? lim.defaultSource : null },
      budget,
      nearLimit: nearLimit.map((r) => ({ ...r, spend: n2(r.spend),
        customLimit: Number(r.customLimit),
        pct: Number(r.customLimit) > 0 ? n2((Number(r.spend) / Number(r.customLimit)) * 100) : 100 })),
      nearLimitNote: lim
        ? 'Spend and limits are both live (Spend Limits API, as of ' + lim.asOf + '); a member is measured against their effective limit whatever its source.'
        : 'Spend is live; the limit each member is measured against comes from the CSV import.',
      idle: idle.map((r) => ({ ...r, lifetimeSpend: n2(r.lifetimeSpend) })),
      idleNote: `Roster is the last CSV import (a live roster needs read:members). Idle = no spend and no recorded activity in ${idleDays} days.`,
      models: modelRows,
      movers: movers.map((m) => ({ ...m, thisWeek: n2(m.thisWeek), lastWeek: n2(m.lastWeek),
        multiple: Number(m.lastWeek) > 0 ? n2(Number(m.thisWeek) / Number(m.lastWeek)) : null })),
    });
  } catch (e) { console.error('[claude-analytics/insights]', e.message); res.status(500).json({ error: 'insights failed' }); }
});

/* GET /limit-requests — spend-limit increase requests (Spend Limits API, read:spend_limits).
 * Read-only queue view. `available` is false until the collector has a fresh, successful
 * pull, so an EMPTY table (no requests ever) and a key WITHOUT the scope look different. */
router.get('/limit-requests', read, async (req, res) => {
  try {
    const [st] = await q(
      `SELECT status, ran_at FROM claude_sync_log WHERE endpoint='limit_requests' ORDER BY id DESC LIMIT 1`);
    const [ok] = await q(
      `SELECT ran_at FROM claude_sync_log WHERE endpoint='limit_requests' AND status='ok' ORDER BY id DESC LIMIT 1`);
    // Available while the last SUCCESSFUL pull is fresh: one transient error must not hide a
    // queue that is still current. Selection happens in SQL so an old pending row is never
    // cut off by a row limit.
    const available = !!(ok && CL.isFresh(ok.ran_at));
    const cutoffSql = new Date(Date.now() - 30 * 864e5).toISOString().slice(0, 19).replace('T', ' ');
    const allow = await scopedEmails(req);   // DATA SCOPE (F28): each request names a person
    const rows = (available ? await q(
      `SELECT id, user_id, email, display_name, status, period, created_at, resolved_at, resolved_by,
              current_limit_cents, current_source_type, ptd_spend_cents, fetched_at
         FROM claude_limit_request
        WHERE status='pending' OR COALESCE(resolved_at, created_at) >= ?
        ORDER BY created_at DESC`, [cutoffSql]) : []).filter((r) => inScope(allow, r.email));
    const fmt = (r) => ({
      id: r.id, email: r.email, name: r.display_name, status: r.status, period: r.period,
      createdAt: r.created_at ? new Date(CL.parseTs(r.created_at)).toISOString() : null,
      resolvedAt: r.resolved_at ? new Date(CL.parseTs(r.resolved_at)).toISOString() : null,
      resolvedBy: r.resolved_by,
      currentLimit: CL.cents(r.current_limit_cents),
      currentLabel: r.current_source_type != null ? CL.sourceLabel(r.current_source_type, r.current_limit_cents == null) : null,
      ptdSpend: CL.cents(r.ptd_spend_cents),
    });
    const cutoff = Date.now() - 30 * 864e5;
    res.json({
      available,
      scopeStatus: st ? st.status : null,
      checkedAt: st ? new Date(CL.parseTs(st.ran_at)).toISOString() : null,
      asOf: CL.newestFetchedAt(rows),
      pending: rows.filter((r) => r.status === 'pending').map(fmt),
      recent: rows.filter((r) => r.status !== 'pending' && CL.parseTs(r.resolved_at || r.created_at) >= cutoff).slice(0, 20).map(fmt),
    });
  } catch (e) { console.error('[claude-analytics/limit-requests]', e.message); res.status(500).json({ error: 'limit-requests failed' }); }
});


/* ===================== ORG ROLLUP =========================================
 * GET /rollup — AI spend rolled up the org chart, one level at a time.
 *
 *   level = leader | department | manager | user   (default: leader)
 *   leader / department / manager                  parent filters, drill down
 *   months = 1..24                                 how many months back (default 6)
 *
 * Attribution comes from ai_user_org, which is rebuilt from the HR roster
 * (hr_roster) plus an Entra manager climb for anyone HR does not carry.
 * Anything still unattributed is returned as its own row rather than dropped,
 * so the column totals always reconcile to the invoice.
 * ========================================================================= */
const ROLLUP_LEVELS = {
  leader:     { key: 'o.leader_email',  name: 'o.leader_name',  fallback: 'Unassigned' },
  department: { key: 'o.dept_code',     name: 'o.department',   fallback: 'Unassigned' },
  manager:    { key: 'o.manager_email', name: 'o.manager_name', fallback: 'Unassigned' },
  user:       { key: 'o.email',         name: 'o.display_name', fallback: 'Unknown' },
};

router.get('/rollup', read, async (req, res) => {
  try {
    const level = ROLLUP_LEVELS[req.query.level] ? req.query.level : 'leader';
    const L = ROLLUP_LEVELS[level];
    const months = Math.max(1, Math.min(24, parseInt(req.query.months, 10) || 6));
    const period = periodOf(req.query);   // full-month bounds from the page's global control

    // Parent filters. Each is an exact match on a resolved column; '__none__'
    // selects the unattributed bucket so it stays drillable like any other row.
    const where = [], params = [];
    const filt = (col, val) => {
      if (val === undefined || val === null || val === '') return;
      if (val === '__none__') where.push(`(${col} IS NULL OR ${col}='')`);
      else { where.push(`${col} = ?`); params.push(String(val).toLowerCase()); }
    };
    // DATA SCOPE (2026-09-03). The three filters below come from the query string
    // and are a NAVIGATION aid - the caller says which branch to open. This one is
    // not negotiable: it is derived from the signed-in identity and intersects with
    // whatever the caller asked for, so a department-scoped user drilling to
    // level=leader still only sees their own rows. scopeWhere() yields '1=0' for an
    // undetermined scope, so a missed .deny check returns nothing, not everything.
    {
      const sc = (await resolveScopeForRequest(pool, req)).scope;
      // scopePredicate, not scopeWhere: leader and team need the transitive chain,
      // and an IN list is the only way to express it in a single WHERE fragment.
      const sw = await scopePredicate(pool, sc, 'o');
      if (sw.where) { where.push(sw.where); params.push(...sw.params); }
    }
    filt('o.leader_email', req.query.leader);
    if (req.query.department) {
      if (req.query.department === '__none__') where.push(`(o.dept_code IS NULL OR o.dept_code='')`);
      else { where.push('o.dept_code = ?'); params.push(String(req.query.department)); }
    }
    filt('o.manager_email', req.query.manager);

    const sql = `
      SELECT COALESCE(NULLIF(${L.key},''), '__none__')            AS k,
             COALESCE(NULLIF(MAX(${L.name}),''), ?)               AS name,
             DATE_FORMAT(c.day, '%Y-%m')                          AS mo,
             COUNT(DISTINCT c.email)                              AS users,
             SUM(c.amount_cents)                                  AS cents,
             SUM(c.requests)                                      AS requests
        FROM claude_user_cost_daily c
        JOIN ai_user_org o ON o.email = LOWER(c.email)
        -- No deleted filter: this rollup has to reconcile to the invoice, and a member
        -- who has since left was still billed for the month the spend landed in.
       WHERE ${period ? 'c.day >= ? AND c.day <= ?' : "c.day >= DATE_FORMAT(DATE_SUB(CURDATE(), INTERVAL ? MONTH), '%Y-%m-01')"}
         ${where.length ? 'AND ' + where.join(' AND ') : ''}
       GROUP BY k, mo`;
    const rows = await q(sql, [L.fallback, ...(period ? [period.from, period.to] : [months - 1]), ...params]);

    // Month axis: every month in the window, so the table has no ragged columns.
    let axis = [];
    if (period) axis = period.axis;
    else {
      const d = new Date();
      d.setUTCDate(1);
      for (let i = months - 1; i >= 0; i--) {
        const m = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() - i, 1));
        axis.push(`${m.getUTCFullYear()}-${String(m.getUTCMonth() + 1).padStart(2, '0')}`);
      }
    }

    const byKey = new Map();
    for (const r of rows) {
      if (!byKey.has(r.k)) {
        byKey.set(r.k, { key: r.k, name: r.name, months: {}, total: 0, users: 0, requests: 0 });
      }
      const e = byKey.get(r.k);
      e.months[r.mo] = n2(Number(r.cents) / 100);
      e.total += Number(r.cents) / 100;
      e.users = Math.max(e.users, Number(r.users) || 0);
      e.requests += Number(r.requests) || 0;
    }
    // People = DISTINCT spenders across the whole window per row (2026-09-15). The per-month
    // rows above can only give max-month distinct, which undercounted (73 shown vs 78 real).
    {
      const dsql = `
        SELECT COALESCE(NULLIF(${L.key},''), '__none__') AS k, COUNT(DISTINCT c.email) AS users
          FROM claude_user_cost_daily c
          JOIN ai_user_org o ON o.email = LOWER(c.email)
         WHERE ${period ? 'c.day >= ? AND c.day <= ?' : "c.day >= DATE_FORMAT(DATE_SUB(CURDATE(), INTERVAL ? MONTH), '%Y-%m-01')"}
           ${where.length ? 'AND ' + where.join(' AND ') : ''}
         GROUP BY k`;
      const drows = await q(dsql, [...(period ? [period.from, period.to] : [months - 1]), ...params]);
      for (const r of drows) if (byKey.has(r.k)) byKey.get(r.k).users = Number(r.users) || 0;
    }
    const out = [...byKey.values()].map((e) => ({
      ...e,
      total: n2(e.total),
      months: Object.fromEntries(axis.map((m) => [m, e.months[m] || 0])),
    })).sort((a, b) => b.total - a.total);

    // A row is drillable while there is a level below it.
    const nextLevel = { leader: 'department', department: 'manager', manager: 'user', user: null }[level];

    res.json({
      level, nextLevel, months: axis, period,
      filters: {
        leader: req.query.leader || null,
        department: req.query.department || null,
        manager: req.query.manager || null,
      },
      rows: out,
      grand: {
        total: n2(out.reduce((s, r) => s + r.total, 0)),
        users: (await q(`SELECT COUNT(DISTINCT c.email) n FROM claude_user_cost_daily c
                          JOIN ai_user_org o ON o.email = LOWER(c.email)
                         WHERE ${period ? 'c.day >= ? AND c.day <= ?' : "c.day >= DATE_FORMAT(DATE_SUB(CURDATE(), INTERVAL ? MONTH), '%Y-%m-01')"}
                           ${where.length ? 'AND ' + where.join(' AND ') : ''}`,
                        [...(period ? [period.from, period.to] : [months - 1]), ...params]))[0].n,
        byMonth: Object.fromEntries(axis.map((m) => [m, n2(out.reduce((s, r) => s + (r.months[m] || 0), 0))])),
      },
    });
  } catch (e) {
    console.error('[claude-analytics] /rollup', e.message);
    res.status(500).json({ error: 'rollup failed' });
  }
});

/* GET /rollup/coverage — how much spend is attributable, and what is not.
 * Surfaced on the page so an attribution gap can never hide inside a total. */
router.get('/rollup/coverage', read, async (req, res) => {
  try {
    // Scoped to the reporting period when the page sends one (2026-09-15), so the
    // "% attributed" figure describes the same window as the table beside it.
    const period = periodOf(req.query);
    const pw = period ? ' AND c.day >= ? AND c.day <= ?' : '';
    const pp = period ? [period.from, period.to] : [];
    const rows = await q(`
      SELECT o.resolution,
             COUNT(DISTINCT o.email) users,
             SUM(c.amount_cents)     cents
        FROM ai_user_org o
        JOIN claude_user_cost_daily c ON o.email = LOWER(c.email)${pw}
       GROUP BY o.resolution`, pp);
    const allow = await scopedEmails(req);   // DATA SCOPE (F28): the unresolved list names people
    const unresolved = (await q(`
      SELECT o.email, COALESCE(NULLIF(o.display_name,''), o.email) name,
             ROUND(IFNULL(SUM(c.amount_cents),0)/100, 2) usd
        FROM ai_user_org o
        LEFT JOIN claude_user_cost_daily c ON o.email = LOWER(c.email)${pw}
       WHERE o.resolution = 'unresolved'
       GROUP BY o.email, name ORDER BY usd DESC`, pp)).filter((r) => inScope(allow, r.email));
    const [roster] = await q(`SELECT COUNT(*) n, MAX(loaded_at) loaded FROM hr_roster`);
    const total = rows.reduce((s, r) => s + Number(r.cents || 0), 0);
    res.json({
      period,
      roster: { people: Number(roster?.n || 0), loadedAt: roster?.loaded || null },
      byResolution: rows.map((r) => ({
        resolution: r.resolution,
        users: Number(r.users),
        usd: n2(Number(r.cents) / 100),
        pct: total ? Math.round((Number(r.cents) / total) * 1000) / 10 : 0,
      })),
      unresolved,
    });
  } catch (e) {
    console.error('[claude-analytics] /rollup/coverage', e.message);
    res.status(500).json({ error: 'coverage failed' });
  }
});

module.exports = router;
