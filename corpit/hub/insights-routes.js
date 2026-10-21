/**
 * insights-routes.js — Tenant Insights (licensing, usage, applications)
 * Mounted at /api/insights/. RBAC page key: tenant-sentinel (same audience).
 * Read-only. Pattern matches sentinel-routes.js (2026-07-23).
 */
const express = require('express');
const mysql = require('mysql2/promise');
const createRbac = require('./rbac-middleware');
const CL = require('./claude-limits');
const { resolveScope, scopeWhere, resolveScopeForRequest, scopeEmailSet } = require('./scope-lib');

/* ---- DATA SCOPE ENFORCEMENT (2026-09-03) --------------------------------
 * Until now these routes returned the whole organisation and the page filtered
 * it in the browser (ai-usage-credits.html, deptFilter). That is a display
 * convenience, not a boundary: every caller with 'read' received every member's
 * name and spend regardless of what was rendered. The filter now happens here.
 *
 * scopedEmails() returns null for org-wide (no filter at all), an empty Set for
 * a caller whose scope could not be determined (fail closed), or the set of
 * emails the caller may see. Membership is resolved through ai_user_org, which
 * is the same attribution table the rollup reconciles against.
 */
// Delegates to scope-lib so the chain walk for leader/team lives in exactly one
// place. A second copy of this that forgot to be transitive is how the roll-up
// silently showed a CEO eight people.
const scopedEmails = (scope) => scopeEmailSet(pool, scope);
const inScope = (allow, email) => allow === null || allow.has(String(email || '').toLowerCase());
const publicScope = (sc) => ({ kind: sc.kind, label: sc.label, source: sc.source, deny: !!sc.deny });
   // Spend Limits / Members parsing + freshness (shared with the collector)

const router = express.Router();
const pool = mysql.createPool({
  host: process.env.DB_HOST, user: process.env.DB_USER,
  password: process.env.DB_PASSWORD, database: process.env.DB_NAME,
  waitForConnections: true, connectionLimit: 5,
});
const rbac = createRbac(pool);
// settingsfold W6 2026-10-12: the group-limit PUT writes an rbac_audit_log row.
const SA = require('./settings-audit');
router.use(rbac.loadCurrentUser);

const PAGE_KEY = 'tenant-sentinel';

async function q(sql, params = []) {
  const [rows] = await pool.query(sql, params);
  return rows;
}

/** One row per person from the directory — see the same constant in claude-analytics-routes.js.
 *  entra_users is keyed on entra_id, not on the UPN, and stale rows are kept (seen_in_last_sync=0),
 *  so one person can hold two rows and a direct join fans that member out — doubling their figures
 *  where the GROUP BY does not separate the rows, duplicating their row where it does. The row
 *  still seen in the last sync wins, then the most recently synced, entra_id as tiebreak. */
const ENTRA1 = `(SELECT user_principal_name, entra_id, display_name, department, manager_upn, account_enabled
                   FROM (SELECT eu.user_principal_name, eu.entra_id, eu.display_name, eu.department,
                                eu.manager_upn, eu.account_enabled,
                                ROW_NUMBER() OVER (PARTITION BY eu.user_principal_name
                                     ORDER BY eu.seen_in_last_sync DESC, eu.last_synced_at DESC,
                                              eu.entra_id) AS rn
                           FROM entra_users eu) e1
                  WHERE e1.rn = 1)`;

const SKU_FRIENDLY = {
  SPE_E3: 'Microsoft 365 E3', SPE_E5: 'Microsoft 365 E5',
  Microsoft_365_Copilot: 'Microsoft 365 Copilot', POWER_BI_PRO: 'Power BI Pro',
  POWER_BI_PRO_DEPT: 'Power BI Pro (Dept)', EXCHANGEENTERPRISE: 'Exchange Online Plan 2',
  AAD_PREMIUM_P2: 'Microsoft Entra ID P2', SHAREPOINTSTORAGE: 'Office 365 Extra File Storage',
  VISIO_STD: 'Visio Standard', STREAM: 'Microsoft Stream (Trial)',
  FLOW_FREE: 'Power Automate Free', POWER_BI_STANDARD: 'Power BI (Free)',
  POWERAPPS_DEV: 'Power Apps Developer', POWERAPPS_VIRAL: 'Power Apps (Trial)',
  CCIBOTS_PRIVPREV_VIRAL: 'Copilot Studio (Trial)', WINDOWS_STORE: 'Windows Store',
  MICROSOFT_BUSINESS_CENTER: 'Microsoft Business Center', SPZA_IW: 'App Connect (Free)',
  Microsoft_Copilot_for_Finance_trial: 'Copilot for Finance (Preview)',
  Dynamics_365_Sales_Premium_Viral_Trial: 'Dynamics 365 Sales (Trial)',
  Power_Pages_vTrial_for_Makers: 'Power Pages (Trial)',
};
const friendly = (sku) => SKU_FRIENDLY[sku] || sku;

// GET /api/insights/licensing/holders/:sku — who holds a license, with department
router.get('/licensing/holders/:sku', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const skuRow = await q(`SELECT sku_part_number FROM insight_sku WHERE sku_part_number = ?`, [req.params.sku]);
    if (!skuRow.length) return res.status(404).json({ error: 'unknown sku' });
    // Assigned Products in reports use friendly-ish names; match on both raw and friendly forms
    const needle1 = '%' + req.params.sku.replace(/_/g, ' ') + '%';
    const needle2 = '%' + friendly(req.params.sku) + '%';
    // report-style variant: "Exchange Online Plan 2" appears as "EXCHANGE ONLINE (PLAN 2)" in usage reports
    const needle3 = '%' + friendly(req.params.sku).toUpperCase().replace(/ PLAN (\d+)$/, ' (PLAN $1)') + '%';
    const holders = await q(
      `SELECT a.upn, COALESCE(u.department,'(no dept)') AS department, u.display_name AS name,
              GREATEST(COALESCE(a.exchange_last,'2000-01-01'), COALESCE(a.onedrive_last,'2000-01-01'),
                       COALESCE(a.sharepoint_last,'2000-01-01'), COALESCE(a.teams_last,'2000-01-01')) AS lastActive
       FROM insight_user_activity a
       LEFT JOIN entra_users u ON u.user_principal_name = a.upn
       WHERE a.licenses LIKE ? OR a.licenses LIKE ? OR a.licenses LIKE ?
       ORDER BY department, lastActive DESC LIMIT 1000`, [needle1, needle2, needle3]);
    const byDept = {};
    for (const h of holders) byDept[h.department] = (byDept[h.department] || 0) + 1;
    const [skuRec] = await q(`SELECT consumed FROM insight_sku WHERE sku_part_number = ?`, [req.params.sku]);
    res.json({ sku: req.params.sku, name: friendly(req.params.sku), total: holders.length,
               assignedPerMicrosoft: skuRec ? skuRec.consumed : null, byDept, holders });
  } catch (err) {
    console.error('[insights/holders]', err.message);
    res.status(500).json({ error: 'holders query failed' });
  }
});

// GET /api/insights/licensing — SKUs, utilization, unused-license candidates
router.get('/licensing', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const skus = await q(
      `SELECT sku_part_number AS sku, consumed, enabled, suspended, warning
       FROM insight_sku WHERE enabled > 0 ORDER BY consumed DESC`);

    // unused: licensed + enabled account + no activity in any workload for 60d
    const unused = await q(
      `SELECT a.upn, a.licenses,
              GREATEST(COALESCE(a.exchange_last,'2000-01-01'), COALESCE(a.onedrive_last,'2000-01-01'),
                       COALESCE(a.sharepoint_last,'2000-01-01'), COALESCE(a.teams_last,'2000-01-01')) AS lastAny
       FROM insight_user_activity a
       JOIN entra_users u ON u.user_principal_name = a.upn
       WHERE u.account_enabled = 1 AND u.display_name NOT LIKE '.%'
         AND a.licenses IS NOT NULL AND a.licenses <> ''
       HAVING lastAny <= CURDATE() - INTERVAL 60 DAY
       ORDER BY lastAny ASC`);

    // Excludes 'usage'/'server' category costs (e.g. SHAREPOINTSTORAGE,
    // a per-GB capacity add-on, not a per-user seat) from the seat-based
    // "paid" framework -- those get a "0/25000 seats, $X/mo idle" framing
    // that's meaningless for a storage pool (Graph's consumed-seat count
    // is 0 by design for capacity SKUs, not a real utilization signal).
    // They're already shown correctly under Products & Services below.
    const costs0 = await q(`SELECT sku_part_number, unit_monthly, qty FROM insight_cost WHERE sku_part_number IS NOT NULL AND unit_monthly > 0 AND category = 'license'`);
    const paidSet = new Set(costs0.map((c) => c.sku_part_number));
    const paidQty = Object.fromEntries(costs0.map((c) => [c.sku_part_number, +c.qty || null]));
    for (const s of skus) { s.name = friendly(s.sku); s.paid = paidSet.has(s.sku);
      if (s.paid && paidQty[s.sku]) s.purchased = paidQty[s.sku]; }
    const overProvisioned = skus.filter((s) => s.paid && (s.purchased || s.enabled) >= 5
        && s.consumed / (s.purchased || s.enabled) < 0.9)
      .map((s) => ({ ...s, unassigned: (s.purchased || s.enabled) - s.consumed }));

    // cost enrichment
    const costs = await q(`SELECT product, category, qty, unit_monthly, total_monthly, sku_part_number, notes FROM insight_cost`);
    const bySku = {};
    for (const c of costs) if (c.sku_part_number) bySku[c.sku_part_number] = c;
    // Copilot is a special case. R-1 RESOLVED 2026-09-15 (Bich / Karen / Rey review):
    // the licence rate is $28.00 per licence per month and the billed basis is
    // ASSIGNED licences (insight_sku.consumed), not purchased/enabled. insight_cost
    // .unit_monthly is aligned to 28.00 in the same release so DB and page agree.
    // ai-usage-credits.html shows the SAME figure; this panel must never derive its own.
    // Every other SKU keeps the DB-rate calc.
    const COPILOT_UNIT_COST_ALIGNED = 28;
    const skusWithCost = skus.map((s) => {
      const c = bySku[s.sku];
      const category = c ? c.category : null;
      if (/copilot/i.test(s.sku) || /copilot/i.test(s.name || '')) {
        const seats = s.consumed;
        return { ...s, category, unitCost: COPILOT_UNIT_COST_ALIGNED,
                 monthlySpend: +(seats * COPILOT_UNIT_COST_ALIGNED).toFixed(2),
                 unassignedCost: +(Math.max(0, s.enabled - s.consumed) * COPILOT_UNIT_COST_ALIGNED).toFixed(2) };
      }
      if (!c || !c.unit_monthly) return { ...s, category };
      return { ...s, category, unitCost: +c.unit_monthly, monthlySpend: +(s.consumed * c.unit_monthly).toFixed(2),
               unassignedCost: +(Math.max(0, (c.qty ?? s.enabled) - s.consumed) * c.unit_monthly).toFixed(2) };
    });
    const totalMonthly = costs.reduce((a, c) => a + (+c.total_monthly || 0), 0);
    // reclaimable: inactive holders' priciest license (E3 assumed dominant — use E3 unit if licenses mention it)
    const e3 = costs.find((c) => c.sku_part_number === 'SPE_E3');
    const reclaimMonthly = e3 ? +(unused.filter((u) => /E3/i.test(u.licenses || '')).length * e3.unit_monthly).toFixed(2) : null;
    // SHAREPOINTSTORAGE excluded here -- it now has a proper, contextualized
    // home in the SharePoint tile (real TB-in-use alongside this exact cost),
    // so listing it again here bare, with no usage context, would be a
    // duplicate of the same number rather than genuinely new information.
    const productsServices = costs.filter((c) => c.category !== 'license' || !bySku[c.sku_part_number] === false)
      .filter((c) => ['usage', 'server'].includes(c.category))
      .filter((c) => c.sku_part_number !== 'SHAREPOINTSTORAGE')
      .map((c) => ({ product: c.product, category: c.category, monthly: +c.total_monthly || null, notes: c.notes }));

    // Copilot summary card: activeUsers30d/perApp use the SAME "any app
    // activity in a rolling 30-day window" definition as ai-usage-credits.html
    // (the authoritative page, per the consistency review) -- reads the same
    // copilot_app_usage table, same per-app columns. Seats/cost reuse the
    // already-aligned $30 x enabled-seats figure from skusWithCost above.
    let copilot = null;
    const copilotSkuRow = skusWithCost.find((s) => /copilot/i.test(s.sku) || /copilot/i.test(s.name || ''));
    if (copilotSkuRow) {
      const appRows = await q(
        `SELECT chat_last_active, teams_last_active, word_last_active, excel_last_active,
                powerpoint_last_active, outlook_last_active, onenote_last_active, loop_last_active,
                report_refresh_date
           FROM copilot_app_usage`);
      const apps = ['chat', 'teams', 'word', 'excel', 'powerpoint', 'outlook', 'onenote', 'loop'];
      const perApp = Object.fromEntries(apps.map((a) => [a, 0]));
      let activeUsers30d = 0, reportRefreshDate = null;
      const cutoff = new Date(Date.now() - 30 * 86400e3);
      for (const r of appRows) {
        let anyActive = false;
        for (const a of apps) {
          const col = r[a + '_last_active'];
          if (col && new Date(col) >= cutoff) { perApp[a]++; anyActive = true; }
        }
        if (anyActive) activeUsers30d++;
        const rf = r.report_refresh_date;
        if (rf && (!reportRefreshDate || rf > reportRefreshDate)) reportRefreshDate = rf;
      }
      copilot = {
        seats: copilotSkuRow.consumed, monthlySpend: copilotSkuRow.monthlySpend,
        activeUsers30d, perApp,
        reportRefreshDate: reportRefreshDate ? String(reportRefreshDate).slice(0, 10) : null,
      };
    }

    // Real reuse of SharePoint Governance's own live calculation (in-process
    // function call, not a copy) -- per the consistency review, this
    // connects the $4,900/mo storage add-on cost to actual real usage
    // instead of the misleading seat-based framing that was here before.
    // Wrapped defensively: a Graph hiccup on the governance side must not
    // break the whole Licensing & Cost page.
    let sharePoint = null;
    try {
      const spGov = require('./sharepoint-governance');
      if (spGov.fetchAllData) {
        const { summary } = await spGov.fetchAllData();
        const storageCost = costs.find((c) => c.sku_part_number === 'SHAREPOINTSTORAGE');
        sharePoint = {
          totalSites: summary.total_sites, totalStorageGb: summary.total_gb,
          extSharingOnCount: summary.ext_on_count,
          inactiveCritical: summary.inactive_critical, inactiveHigh: summary.inactive_high,
          inactiveMedium: summary.inactive_medium, inactiveWatch: summary.inactive_watch,
          extraStorageMonthlyCost: storageCost ? +storageCost.total_monthly : null,
          extraStorageGb: storageCost ? +storageCost.qty : null,
          seedAsOf: summary.seed_as_of,
        };
      }
    } catch (err) {
      console.error('[insights/licensing] SharePoint Governance reuse failed:', err.message);
    }

    res.json({ skus: skusWithCost, overProvisioned, unusedLicenses: unused.slice(0, 200), unusedCount: unused.length,
               totalMonthly: +totalMonthly.toFixed(2), reclaimMonthly, productsServices, copilot, sharePoint });
  } catch (err) {
    console.error('[insights/licensing]', err.message);
    res.status(500).json({ error: 'licensing query failed' });
  }
});

// GET /api/insights/usage — workload adoption summary
router.get('/usage', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const [tot] = await q(`SELECT COUNT(*) c FROM insight_user_activity`);
    // "716 licensed users" (tot.c) counts ANY row in insight_user_activity --
    // including people whose only license is free/trial (e.g. Power Automate
    // Free). Using it as the denominator for a paid-spend "cost per user"
    // figure dilutes and understates the real cost per paid-license holder.
    // paidLicenseUsers reuses the same E3/E5/Copilot/Power BI Pro filter
    // already validated in the 30/60/90 report (664 users) for an honest
    // "cost per PAID user" figure instead.
    const [paidTot] = await q(
      `SELECT COUNT(*) c FROM insight_user_activity a
         JOIN ${ENTRA1} u ON u.user_principal_name = a.upn
        WHERE u.account_enabled = 1 AND a.licenses IS NOT NULL AND a.licenses != ''
          AND (a.licenses LIKE '%E3%' OR a.licenses LIKE '%E5%' OR a.licenses LIKE '%COPILOT%' OR a.licenses LIKE '%POWER BI PRO%')`);
    const workloads = await q(
      `SELECT
        SUM(exchange_last  > CURDATE() - INTERVAL 30 DAY) exchange30,
        SUM(teams_last     > CURDATE() - INTERVAL 30 DAY) teams30,
        SUM(onedrive_last  > CURDATE() - INTERVAL 30 DAY) onedrive30,
        SUM(sharepoint_last> CURDATE() - INTERVAL 30 DAY) sharepoint30
       FROM insight_user_activity`);
    const copilot = await q(
      `SELECT sku_part_number AS sku, consumed, enabled FROM insight_sku
       WHERE sku_part_number LIKE '%COPILOT%' OR sku_part_number LIKE '%Copilot%'`);
    res.json({ totalUsers: tot.c, paidLicenseUsers: paidTot.c, active30d: workloads[0], copilotSkus: copilot });
  } catch (err) {
    console.error('[insights/usage]', err.message);
    res.status(500).json({ error: 'usage query failed' });
  }
});

// GET /api/insights/apps — enterprise applications incl. third-party
router.get('/apps', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const [counts] = await q(
      `SELECT COUNT(*) total,
              SUM(sp_type='Application') apps,
              SUM(account_enabled=0) disabled,
              SUM(app_owner_org IS NOT NULL AND app_owner_org NOT IN
                  ('f8cdef31-a31e-4b4a-93e4-5f571e91255a', ?)) thirdParty
       FROM insight_service_principal`, [process.env.ENTRA_TENANT_ID || '']);
    const HIGH_SCOPES = ['Mail.Read', 'Mail.ReadWrite', 'Files.Read.All', 'Files.ReadWrite.All',
      'Directory.Read.All', 'Directory.ReadWrite.All', 'Sites.Read.All', 'Sites.ReadWrite.All',
      'User.Read.All', 'Contacts.ReadWrite', 'Calendars.ReadWrite', 'EWS.AccessAsUser.All', 'EAS.AccessAsUser.All'];
    const scopePlain = (s) => {
      const hits = [];
      if (/Mail\./.test(s)) hits.push('email');
      if (/Files\.|Sites\./.test(s)) hits.push('files');
      if (/Calendars\./.test(s)) hits.push('calendars');
      if (/Contacts\./.test(s)) hits.push('contacts');
      if (/Directory\.|User\.Read\.All/.test(s)) hits.push('directory');
      if (/EWS\.|EAS\./.test(s)) hits.push('mailbox protocols');
      return hits.length ? hits.join(', ') : 'basic profile';
    };
    const tpRaw = await q(
      `SELECT sp_id, display_name AS name, publisher, created_dt AS created, account_enabled AS enabled,
              delegated_scopes, consent_type, consented_by, app_role_count, last_signin_dt AS lastSignIn
       FROM insight_service_principal
       WHERE sp_type='Application' AND app_owner_org IS NOT NULL
         AND app_owner_org NOT IN ('f8cdef31-a31e-4b4a-93e4-5f571e91255a', ?)
       ORDER BY last_signin_dt DESC`, [process.env.ENTRA_TENANT_ID || '']);
    // resolve consenting users
    const ids = [...new Set(tpRaw.flatMap((a) => (a.consented_by || '').split(',').filter(Boolean)))];
    let idName = {};
    if (ids.length) {
      const users = await q(
        `SELECT entra_id AS id, display_name FROM entra_users WHERE entra_id IN (${ids.map(() => '?').join(',')})`, ids);
      idName = Object.fromEntries(users.map((u) => [u.id, u.display_name]));
    }
    const now = Date.now();
    const thirdParty = tpRaw.map((a) => {
      const scopes = a.delegated_scopes || '';
      const highPriv = a.app_role_count > 0 || HIGH_SCOPES.some((h) => scopes.includes(h));
      const unverified = !a.publisher;
      const stale = !a.lastSignIn || new Date(a.lastSignIn) < now - 90 * 86400e3;
      let tier = 'healthy', action = 'No action needed.';
      if (stale) { tier = 'abandoned'; action = 'No sign-ins in 90+ days — confirm it is still needed, otherwise disable it.'; }
      if (highPriv && (unverified || stale)) { tier = 'review'; action = stale
        ? 'Broad data access but unused for 90+ days — strong candidate to disable.'
        : 'Broad data access from an unverified publisher — confirm this vendor is approved.'; }
      return {
        name: a.name, publisher: a.publisher || null, verified: !unverified,
        access: scopePlain(scopes) + (a.app_role_count ? ` + ${a.app_role_count} application permission${a.app_role_count === 1 ? '' : 's'}` : ''),
        consent: a.consent_type,
        consentedBy: (a.consented_by || '').split(',').filter(Boolean).map((i) => idName[i] || 'unknown user').join(', ') || null,
        added: a.created, lastSignIn: a.lastSignIn, tier, action,
      };
    });
    const tierOrder = { review: 0, abandoned: 1, healthy: 2 };
    thirdParty.sort((x, y) => tierOrder[x.tier] - tierOrder[y.tier]);

    const flows = await q(
      `SELECT f.display_name AS name, f.state, f.modified_dt AS modified, e.display_name AS env,
              COALESCE(u.display_name, '(owner not found — may have left)') AS owner,
              u.account_enabled AS ownerActive
       FROM insight_flow f
       LEFT JOIN sentinel_pp_environment e ON e.env_id = f.env_id
       LEFT JOIN entra_users u ON u.entra_id = f.owner_id
       ORDER BY f.modified_dt ASC`);
    const inactiveFlows = flows.filter((f) => f.state === 'Started' &&
      f.modified && new Date(f.modified) < now - 180 * 86400e3)
      .map((f) => ({ ...f, action: f.ownerActive === 0 || /not found/.test(f.owner)
        ? 'Owner has left the company — reassign to a service account or disable.'
        : `Ask ${f.owner} to confirm this flow is still needed.` }));
    res.json({ counts, thirdParty, flows, inactiveFlows });
  } catch (err) {
    console.error('[insights/apps]', err.message);
    res.status(500).json({ error: 'apps query failed' });
  }
});

// ---------- AI Usage & Credits (Phase 1, added 2026-08-19) ----------
// Safe DATE formatter — mysql2 returns DATE columns as JS Date objects (not strings),
// so String(dateObj).slice(0,10) produces 'Sat Aug 01' instead of '2026-08-01',
// which MySQL then rejects as an invalid DATE literal on the next query. Handle both.
function fmtDate(v) {
  if (v == null) return null;
  if (v instanceof Date) return v.toISOString().slice(0, 10);
  return String(v).slice(0, 10);
}

/* ---------------------------------------------------------------------------
 * claudeUsagePayload(month) — the shared Claude roster, LIVE-FIRST.
 *
 * Spend and request counts come from claude_user_cost_daily / claude_cost_daily,
 * filled by the Analytics API collector. The per-member spend LIMIT still comes
 * from the CSV import: our key carries read:analytics only, so the Spend Limits
 * API is unreachable. Same for the credit balance, which has no API at all.
 *
 * If the live tables hold nothing for the requested month we fall back to the CSV
 * snapshot, so an API or collector outage degrades to the previous behaviour
 * rather than rendering an empty page. `source` says which one answered.
 *
 * Response shape is byte-compatible with the old CSV-only version so existing
 * front ends need no changes.
 * ------------------------------------------------------------------------- */
async function claudeUsagePayload(reqMonth) {
  // months available from either source, newest first
  const liveMonths = await q(
    `SELECT DISTINCT DATE_FORMAT(day,'%Y-%m-01') AS m FROM claude_cost_daily`);
  const csvMonths = await q(`SELECT DISTINCT month AS m FROM ai_usage_member`);
  const months = [...new Set([...liveMonths, ...csvMonths].map((r) => fmtDate(r.m)))]
    .filter(Boolean).sort().reverse();
  if (!months.length) return { month: null, members: [], org: null, months: [], source: 'none' };

  const useMonth = (/^\d{4}-\d{2}-01$/.test(reqMonth || '') && months.includes(reqMonth))
    ? reqMonth : months[0];
  const ym = useMonth.slice(0, 7);

  // Latest known limit per member. Limits are policy, not a monthly figure, so the
  // most recent import applies to every month rather than only the month it landed in.
  const limitRows = await q(
    `SELECT a.email, a.custom_limit, a.group_limit, a.name_raw
       FROM ai_usage_member a
       JOIN (SELECT email, MAX(month) mx FROM ai_usage_member
              WHERE platform='claude' GROUP BY email) t
         ON t.email = a.email AND t.mx = a.month
      WHERE a.platform='claude'`);
  const limitMap = Object.fromEntries(limitRows.map((r) => [r.email, r.custom_limit]));
  // Group limit is import-sourced as well — Rey's build stores it per member from the
  // CSV (ai_usage_member.group_limit). It stays labelled "not live" until a key with
  // read:spend_limits exists; until then this is the only source the page has.
  const groupMap = Object.fromEntries(limitRows.map((r) => [r.email, r.group_limit]));
  // Month the member limits were last imported — drives the Custom Limits tile label.
  // Distinct from limitAsOf, which stamps the ORG-limit snapshot month.
  const mlRow = await q(`SELECT MAX(month) AS mx FROM ai_usage_member WHERE platform='claude'`);
  const memberLimitsAsOf = (mlRow.length && mlRow[0].mx) ? fmtDate(mlRow[0].mx) : null;

  // ---- LIVE limits + roster (Spend Limits / Members APIs) ---------------------------
  // Dark until the key carries read:spend_limits / read:members: with the analytics-only
  // key the collector logs 'no-scope' and these tables stay empty, so `lim` and `roster`
  // are null and every branch below behaves exactly as it did before.
  let slRows = [], rosterRows = [];
  try {
    slRows = await q(
      `SELECT user_id, period, email, display_name, amount_cents, source_type, source_ref, ptd_spend_cents, fetched_at
         FROM claude_spend_limit WHERE period='monthly' AND deleted=0`);
    rosterRows = await q(
      `SELECT user_id, email, display_name, role, added_at, fetched_at FROM claude_member WHERE email IS NOT NULL`);
  } catch (e) {
    // a missing table (deploy order) or a DB hiccup degrades to the CSV path — never a 500
    if (e.code !== 'ER_NO_SUCH_TABLE') console.error('[insights] live limits unavailable, using CSV:', e.message);
    slRows = []; rosterRows = [];
  }
  const lim = (slRows.length && CL.isFresh(CL.newestFetchedAt(slRows))) ? CL.buildLimitMaps(slRows) : null;
  const rosterAsOf = CL.newestFetchedAt(rosterRows);
  const roster = (rosterRows.length && CL.isFresh(rosterAsOf)) ? rosterRows : null;
  const roleMap = roster ? Object.fromEntries(roster.map((r) => [r.email, r.role])) : {};
  /* One place decides a member's limit fields, whichever source is live. */
  const limitFields = (email) => {
    if (lim) {
      const r = lim.byEmail[email];
      if (!r) return { customLimit: null, groupLimit: null, effectiveLimit: null, unlimited: false, includedOnly: false,
                       limitSourceType: null, limitSourceRef: null, limitLabel: 'Not in Spend Limits report', ptdSpend: null };
      return { customLimit: r.customLimit, groupLimit: r.groupLimit, effectiveLimit: r.effectiveLimit, unlimited: r.unlimited,
               includedOnly: !!r.includedOnly, limitSourceType: r.sourceType, limitSourceRef: r.sourceRef, limitLabel: r.label, ptdSpend: r.ptdSpend };
    }
    // Dark path: nothing here is live. The new keys are added as null/false only; customLimit
    // and groupLimit keep exactly the values they already had (byte-compatible payload).
    return { effectiveLimit: null, unlimited: false, includedOnly: false, limitSourceType: null, limitSourceRef: null, limitLabel: null, ptdSpend: null };
  };

  const live = await q(
    `SELECT c.email,
            SUM(c.amount_cents)/100                               AS mtd,
            SUM(c.requests)                                       AS requests,
            MAX(c.display_name)                                   AS name_raw,
            COALESCE(o.name, u.display_name, MAX(c.display_name)) AS name,
            COALESCE(o.department, u.department)                  AS department,
            COALESCE(o.manager, m.display_name)                   AS manager,
            (u.entra_id IS NOT NULL)                              AS matchedEntra,
            (o.email IS NOT NULL)                                 AS hasOverride,
            u.account_enabled                                     AS accountEnabled,
            MAX(c.deleted)                                        AS departedFlag
       FROM claude_user_cost_daily c
       LEFT JOIN ${ENTRA1} u ON u.user_principal_name = c.email
       LEFT JOIN ${ENTRA1} m ON m.user_principal_name = u.manager_upn
       LEFT JOIN ai_directory_override o ON o.email = c.email
        -- deleted is a property of the PERSON, not of the dollar. A departed member is
        -- NOT filtered out here: their spend was billed in this month and the member
        -- table has to sum to the org total on the same tile. departedFlag above is what
        -- the current-state columns use to say the seat is gone -- same rule as /sessions.
      WHERE DATE_FORMAT(c.day,'%Y-%m') = ?

      GROUP BY c.email, o.name, u.display_name, o.department, u.department,
               o.manager, m.display_name, u.entra_id, o.email, u.account_enabled
      ORDER BY mtd DESC`, [ym]);

  /* Per-member engagement, live. Rey's build feeds these same columns on itam from a
   * richer CSV export (ai_usage_member.chats/messages/code_sessions/...); here they come
   * straight from claude_user_activity_daily so nothing has to be uploaded by hand.
   * groupLimit is the one field with no live source — it needs read:spend_limits. */
  const act = await q(
    `SELECT email,
            MAX(last_activity_date)                                    AS lastActive,
            COUNT(DISTINCT CASE WHEN (chat_messages>0 OR cc_sessions>0 OR cowork_sessions>0
                                      OR office_sessions>0 OR design_sessions>0)
                                THEN day END)                          AS daysActive,
            SUM(chat_conversations)                                    AS chats,
            SUM(chat_messages)                                         AS messages,
            SUM(chat_projects_created)                                 AS projectsCreated,
            SUM(chat_projects_used)                                    AS projectsUsed,
            SUM(cc_sessions)                                           AS codeSessions,
            SUM(cowork_file_edits) + SUM(cc_edits_accepted)            AS fileEdits,
            SUM(cowork_sessions)                                       AS coworkSessions,
            SUM(cowork_messages)                                       AS coworkMessages,
            SUM(chat_artifacts)                                        AS artifactsCreated
       FROM claude_user_activity_daily
      WHERE DATE_FORMAT(day,'%Y-%m') = ?
      GROUP BY email`, [ym]);
  const actMap = Object.fromEntries(act.map((a) => [a.email, a]));
  const withActivity = (m) => {
    const a = actMap[m.email] || {};
    return Object.assign(m, {
      lastActive: a.lastActive ? fmtDate(a.lastActive) : null,
      daysActive: a.daysActive != null ? Number(a.daysActive) : null,
      chats: a.chats != null ? Number(a.chats) : null,
      messages: a.messages != null ? Number(a.messages) : null,
      projectsCreated: a.projectsCreated != null ? Number(a.projectsCreated) : null,
      projectsUsed: a.projectsUsed != null ? Number(a.projectsUsed) : null,
      codeSessions: a.codeSessions != null ? Number(a.codeSessions) : null,
      fileEdits: a.fileEdits != null ? Number(a.fileEdits) : null,
      coworkSessions: a.coworkSessions != null ? Number(a.coworkSessions) : null,
      coworkMessages: a.coworkMessages != null ? Number(a.coworkMessages) : null,
      artifactsCreated: a.artifactsCreated != null ? Number(a.artifactsCreated) : null,
      // our mtd IS the Anthropic analytics figure, so the two reconcile by construction
      estimatedSpend: m.mtd,
      role: roleMap[m.email] || m.role || null,
      // dark: groupLimit from the CSV import exactly as before; live: every limit field from the API
      ...(lim ? {} : { groupLimit: groupMap[m.email] != null ? Number(groupMap[m.email]) : null }),
      ...limitFields(m.email),
    });
  };

  let members, source;
  if (live.length) {
    source = 'analytics-api';
    members = live.map((r) => ({
      platform: 'claude', email: r.email, name_raw: r.name_raw,
      customLimit: limitMap[r.email] != null ? Number(limitMap[r.email]) : null,
      mtd: Math.round(Number(r.mtd) * 100) / 100,
      requests: Number(r.requests) || 0,
      name: r.name || r.name_raw, department: r.department, manager: r.manager,
      accountEnabled: r.accountEnabled,
      matched: !!(r.matchedEntra || r.hasOverride),
      needsReview: !(r.matchedEntra || r.hasOverride),
      departed: !!r.departedFlag,
    }));
    // The cost API returns ONLY members who actually spent, so on its own it turns
    // "Total Members" into "members who spent" — 16 instead of 81 on the 1st of a month.
    // The provisioned roster needs read:members, which this key lacks, so union in the
    // last known import roster and carry non-spenders at $0 rather than dropping them.
    const seen = new Set(members.map((m) => m.email));
    // Roster: the live Members API when fresh (authoritative — CSV-only emails are ex-members),
    // otherwise the last CSV import.
    const extra = roster
      ? roster.filter((r) => !seen.has(r.email)).map((r) => ({ email: r.email, name_raw: r.display_name, custom_limit: null }))
      : limitRows.filter((r) => !seen.has(r.email));
    if (extra.length) {
      const emails = extra.map((r) => r.email);
      const dir = await q(
        `SELECT LOWER(u.user_principal_name)          AS email,
                COALESCE(o.name, u.display_name)     AS name,
                COALESCE(o.department, u.department) AS department,
                COALESCE(o.manager, m.display_name)  AS manager,
                (u.entra_id IS NOT NULL)             AS matchedEntra,
                (o.email IS NOT NULL)                AS hasOverride,
                u.account_enabled                    AS accountEnabled
           FROM entra_users u
           LEFT JOIN entra_users m ON m.user_principal_name = u.manager_upn
           LEFT JOIN ai_directory_override o ON o.email = u.user_principal_name
          WHERE u.user_principal_name IN (?)`, [emails]);
      // entra UPNs are mixed-case; every roster/CSV email is lowercase — key the map on lowercase
      const dirMap = Object.fromEntries(dir.map((d) => [String(d.email).toLowerCase(), d]));
      // overrides for people the directory does not know (override-only rows)
      const ovr = await q(`SELECT LOWER(email) AS email, name, department, manager FROM ai_directory_override WHERE email IN (?)`, [emails]);
      for (const o of ovr) if (!dirMap[o.email]) dirMap[o.email] = { ...o, matchedEntra: 0, hasOverride: 1, accountEnabled: null };
      for (const r of extra) {
        const d = dirMap[r.email] || {};
        members.push({
          platform: 'claude', email: r.email, name_raw: r.name_raw,
          customLimit: r.custom_limit != null ? Number(r.custom_limit) : null,
          mtd: 0, requests: 0,
          name: d.name || r.name_raw, department: d.department ?? null, manager: d.manager ?? null,
          accountEnabled: d.accountEnabled ?? null,
          matched: !!(d.matchedEntra || d.hasOverride),
          needsReview: !(d.matchedEntra || d.hasOverride),
          noSpend: true,
        });
      }
    }
  } else {
    source = 'csv-import';
    const csv = await q(
      `SELECT a.platform, a.email, a.name_raw, a.custom_limit AS customLimit, a.mtd_spend AS mtd,
              COALESCE(o.name, u.display_name)     AS name,
              COALESCE(o.department, u.department) AS department,
              COALESCE(o.manager, m.display_name)  AS manager,
              u.entra_id IS NOT NULL               AS matchedEntra,
              o.email IS NOT NULL                  AS hasOverride,
              u.account_enabled                    AS accountEnabled
         FROM ai_usage_member a
         LEFT JOIN ${ENTRA1} u ON u.user_principal_name = a.email
         LEFT JOIN ${ENTRA1} m ON m.user_principal_name = u.manager_upn
         LEFT JOIN ai_directory_override o ON o.email = a.email
        WHERE a.month = ? AND a.platform='claude'
        ORDER BY a.mtd_spend DESC`, [useMonth]);
    members = csv.map((r) => {
      const matched = !!(r.matchedEntra || r.hasOverride);
      return { platform: r.platform, email: r.email, name_raw: r.name_raw,
        customLimit: r.customLimit, mtd: Number(r.mtd), requests: null,
        name: r.name || r.name_raw, department: r.department, manager: r.manager,
        accountEnabled: r.accountEnabled, matched, needsReview: !matched };
    });
  }

  // Org roll-up: the month total is live; the spend limit and credit balance have no
  // API on any key, so they are carried forward from the most recent CSV snapshot and
  // stamped with the month they were captured. The UI must label them, not imply live.
  const [liveTot] = await q(
    `SELECT COALESCE(SUM(amount_cents),0)/100 AS mtdTotal, COALESCE(SUM(requests),0) AS requests
       FROM claude_cost_daily WHERE DATE_FORMAT(day,'%Y-%m') = ?`, [ym]);
  const [snap] = await q(
    `SELECT month, org_limit AS orgLimit, balance, reset_label AS resetLabel, reset_date AS resetDate,
            mtd_total AS csvMtdTotal
       FROM ai_org_snapshot WHERE platform='claude' AND month <= ?
      ORDER BY month DESC LIMIT 1`, [useMonth]);
  // assigned_seat_count is the authoritative provisioned-member count, straight from the API.
  // It MUST be read for the month being displayed: seats grew 32 -> 42 -> 52 -> 81 between
  // May and August, so using the newest row priced historic months at today's seat count.
  const [seats] = await q(
    `SELECT assigned_seats FROM claude_summary_daily
      WHERE day <= LAST_DAY(?) ORDER BY day DESC LIMIT 1`, [useMonth]);
  const [prevTot] = await q(
    `SELECT COALESCE(SUM(amount_cents),0)/100 AS t FROM claude_cost_daily
      WHERE DATE_FORMAT(day,'%Y-%m') = DATE_FORMAT(DATE_SUB(?, INTERVAL 1 MONTH),'%Y-%m')`, [useMonth]);

  const liveTotal = Number(liveTot ? liveTot.mtdTotal : 0) || 0;
  // reset is the 1st of the next month at 00:00 UTC — derived, no API needed
  const nextMonth = new Date(Date.UTC(+ym.slice(0, 4), +ym.slice(5, 7), 1));
  const org = {
    claude: {
      platform: 'claude',
      orgLimit: snap ? snap.orgLimit : null,
      mtdTotal: liveTotal > 0 ? Math.round(liveTotal * 100) / 100
                              : (snap ? Number(snap.csvMtdTotal) : null),
      // A credit balance is only true for the month it was captured — carrying August's
      // figure into September would be a stale number presented as current. The org
      // LIMIT may carry forward (it is policy, and is stamped with limitAsOf), the
      // balance may not.
      balance: (snap && fmtDate(snap.month) === useMonth) ? snap.balance : null,
      balanceAsOf: (snap && fmtDate(snap.month) === useMonth) ? fmtDate(snap.month) : null,
      resetLabel: nextMonth.toLocaleDateString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' }),
      resetDate: nextMonth.toISOString().slice(0, 10),
      requests: Number(liveTot ? liveTot.requests : 0) || 0,
      source: liveTotal > 0 ? 'analytics-api' : 'csv-import',
      // The ORG-WIDE monthly budget is a billing setting with no API on any key: operator-entered.
      limitSource: 'csv-import',
      limitAsOf: snap ? fmtDate(snap.month) : null,
      // Per-MEMBER limits: live from the Spend Limits API when the key has read:spend_limits
      // and the pull is fresh (< 36h, CL.FRESH_HOURS); otherwise the last CSV import, stamped with its month.
      memberLimitsSource: lim ? 'spend-limits-api' : 'csv-import',
      memberLimitsAsOf: lim ? lim.asOf : memberLimitsAsOf,
      memberDefaultLimit: lim ? lim.defaultLimit : null,     // the org's effective per-member default (inherited)
      memberDefaultSource: lim ? lim.defaultSource : null,
      rosterSource: roster ? 'members-api' : 'csv-import',
      rosterAsOf: roster ? rosterAsOf : memberLimitsAsOf,
      assignedSeats: seats ? Number(seats.assigned_seats) : null,
      prevMonthTotal: prevTot ? Math.round(Number(prevTot.t) * 100) / 100 : null,
    },
  };
  members = members.map(withActivity);
  return { month: useMonth, members, org, months, source };
}

// GET /api/insights/ai/usage?month=YYYY-MM-01 — members joined to entra_users, with match flags
// DATA SCOPE (F36, 2026-10-21): same boundary as /shared/ai-usage below. Org-wide callers
// get the payload unchanged; anyone narrower gets their own rows and no org-wide figures.
router.get('/ai/usage', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const payload = await claudeUsagePayload(req.query.month);
    const allow   = await scopedEmails((await resolveScopeForRequest(pool, req)).scope);
    if (allow === null) return res.json(payload);
    const members = (payload.members || []).filter((m) => inScope(allow, m.email));
    const mtd  = members.reduce((a, m) => a + (Number(m.mtd) || 0), 0);
    const reqs = members.reduce((a, m) => a + (Number(m.requests) || 0), 0);
    const c    = (payload.org && payload.org.claude) || {};
    const org  = { claude: { ...c,
      mtdTotal: Math.round(mtd * 100) / 100,
      requests: reqs,
      assignedSeats: null, prevMonthTotal: null,
      orgLimit: null, balance: null, balanceAsOf: null,
      scoped: true } };
    res.json({ ...payload, members, org });
  } catch (err) {
    console.error('[insights/ai/usage]', err.message);
    res.status(500).json({ error: 'ai usage query failed' });
  }
});

// ---------- Import input hygiene (H-9, 2026-09-02) ----------
// Both CSV import routes below take operator-supplied rows that are stored and later
// rendered on ai-usage-credits.html. Emails must actually look like one (no whitespace,
// quotes or angle brackets; bounded local/domain parts), and free-text fields lose < >
// and are capped, so a hostile or malformed CSV can neither smuggle markup nor overflow
// a varchar column — STRICT_TRANS_TABLES would 500 the whole import on the first one.
const IMPORT_EMAIL_RE = /^[^\s@<>"']{1,64}@[^\s@<>"']{1,255}$/;
const importEmailOk = (e) => IMPORT_EMAIL_RE.test(e) && e.length <= 255;   // ai_usage_member.email is varchar(255)
// email aliasing (2026-09-21): an imported address equal to an Entra account's `mail` is that
// account's UPN — same rule as claude-collector.js, so CSV rows land on the same key as API rows.
async function emailAliasMap() {
  const rows = await q(`SELECT LOWER(mail) m, LOWER(user_principal_name) u FROM entra_users
                         WHERE mail IS NOT NULL AND mail<>'' AND LOWER(mail)<>LOWER(user_principal_name)
                         ORDER BY account_enabled DESC, last_synced_at DESC`);
  const map = new Map(); for (const r of rows) if (!map.has(r.m)) map.set(r.m, r.u); return map;
}
const cleanText = (v, max = 120) => {
  if (v == null) return null;
  const t = String(v).replace(/[<>]/g, '').trim().slice(0, max);
  return t || null;
};

// POST /api/insights/ai/import — body {mode:'preview'|'commit', kind:'usage'|'directory', month?, rows:[...]}
router.post('/ai/import', require('express').json({ limit: '4mb' }), rbac.requirePage(PAGE_KEY, 'admin'), async (req, res) => {
  const { mode, kind, month, rows } = req.body || {};
  if (!['preview', 'commit'].includes(mode) || !['usage', 'directory', 'invoices', 'balance'].includes(kind) || !Array.isArray(rows))
    return res.status(400).json({ error: 'invalid payload' });
  if (kind === 'usage' && !/^\d{4}-\d{2}-01$/.test(month || ''))
    return res.status(400).json({ error: 'usage import requires month YYYY-MM-01' });
  // ---- billing ledger imports (2026-09-15) -------------------------------------------
  // 'invoices': rows {date, due, total, status, description?, type?, seats?, invoice_no?}
  //   pasted from the Billing page table, a CSV, or parsed invoice PDFs. Idempotent: the
  //   dedupe key is the invoice number when present, else date|amount|n-th-occurrence
  //   within the same date+amount — so re-importing the same table updates statuses
  //   (Open → Paid) instead of duplicating rows.
  // 'balance': rows [{as_of, balance}] — the "Current balance" figure from the Billing page.
  if (kind === 'invoices' || kind === 'balance') {
    try {
      const report = { total: rows.length, new: 0, updated: 0, unchanged: 0, duplicates: 0, invalid: 0, items: [], committed: mode === 'commit' };
      if (kind === 'balance') {
        for (const r of rows.slice(0, 50)) {
          const asOf = isoDay(r.as_of || r.date), bal = Number(String(r.balance).replace(/[$,]/g, ''));
          if (!asOf || !isFinite(bal)) { report.invalid++; continue; }
          const ex = await q(`SELECT balance FROM claude_credit_balance WHERE as_of=?`, [asOf]);
          const status = !ex.length ? 'new' : (Number(ex[0].balance) !== bal ? 'updated' : 'unchanged');
          report[status]++; report.items.push({ as_of: asOf, balance: bal, status });
          if (mode === 'commit') await pool.query(
            `INSERT INTO claude_credit_balance (as_of, balance, entered_by) VALUES (?,?,?)
             ON DUPLICATE KEY UPDATE balance=VALUES(balance), entered_by=VALUES(entered_by)`, [asOf, bal, req.user?.email || 'unknown']);
        }
        return res.json(report);
      }
      // term end for the seat-proration rule: latest plan row + 1 year, else the known term
      const [plan] = await q(`SELECT MAX(invoice_date) d FROM claude_invoice WHERE type='plan'`);
      const termEnd = plan && plan.d ? (() => { const x = new Date(fmtDate(plan.d) + 'T00:00:00Z'); x.setUTCFullYear(x.getUTCFullYear() + 1); return x.toISOString().slice(0, 10); })() : '2027-05-01';
      const seen = {};
      for (const raw of rows.slice(0, 2000)) {
        const r = {
          invoice_date: isoDay(raw.date || raw.invoice_date), due_date: isoDay(raw.due || raw.due_date),
          amount: Number(String(raw.total ?? raw.amount ?? '').replace(/[$,]/g, '')),
          status: String(raw.status || 'Open').trim(), description: cleanText(raw.description, 255),
          type: raw.type ? String(raw.type).trim() : null, seats_added: raw.seats != null && raw.seats !== '' ? Number(raw.seats) : (raw.seats_added ?? null),
          invoice_no: cleanText(raw.invoice_no, 64), paid_date: isoDay(raw.paid_date),
        };
        if (/^partially refunded$/i.test(r.status)) r.status = 'Paid';
        if (!r.invoice_date || !isFinite(r.amount) || !BILL_STATUS.includes(r.status)) { report.invalid++; continue; }
        const { type, seats } = classifyInvoice(r, termEnd);
        r.type = type; if (seats != null) r.seats_added = seats;
        const k0 = `${r.invoice_date}|${r.amount.toFixed(2)}`; seen[k0] = (seen[k0] || 0) + 1;
        r.dedupe_key = r.invoice_no ? `inv:${r.invoice_no}` : `${k0}|#${seen[k0]}`;
        const ex = await q(`SELECT status, type, amount FROM claude_invoice WHERE dedupe_key=?`, [r.dedupe_key]);
        const status = !ex.length ? 'new' : (ex[0].status !== r.status || ex[0].type !== r.type ? 'updated' : 'unchanged');
        report[status]++;
        report.items.push({ ...r, importStatus: status });
        if (mode === 'commit') await pool.query(
          `INSERT INTO claude_invoice (invoice_date, due_date, amount, status, type, seats_added, description, invoice_no, paid_date, source, dedupe_key, created_by)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
           ON DUPLICATE KEY UPDATE status=VALUES(status), type=VALUES(type), seats_added=COALESCE(VALUES(seats_added),seats_added),
             description=COALESCE(VALUES(description),description), paid_date=COALESCE(VALUES(paid_date),paid_date), due_date=COALESCE(VALUES(due_date),due_date)`,
          [r.invoice_date, r.due_date, r.amount, r.status, r.type, r.seats_added, r.description, r.invoice_no, r.paid_date, 'import', r.dedupe_key, req.user?.email || 'unknown']);
      }
      return res.json(report);
    } catch (err) {
      console.error('[insights/ai/import billing]', err.message);
      return res.status(500).json({ error: 'billing import failed' });
    }
  }
  try {
    const seen = new Set(); const report = { total: rows.length, new: 0, updated: 0, unchanged: 0, duplicates: 0, unmatchedEntra: 0, invalid: 0, items: [] };
    const clean = []; const alias = await emailAliasMap();
    for (const r of rows.slice(0, 5000)) {
      const raw = String(r.email || '').trim().toLowerCase();
      const email = alias.get(raw) || raw;
      if (!importEmailOk(email)) { report.invalid++; continue; }
      if (seen.has(email)) { report.duplicates++; continue; }
      seen.add(email); clean.push({ ...r, email, name: cleanText(r.name), department: cleanText(r.department), manager: cleanText(r.manager), employeeId: cleanText(r.employeeId, 64) });
    }
    const emails = clean.map((r) => r.email);
    const entra = emails.length ? await q(
      `SELECT user_principal_name upn FROM entra_users WHERE user_principal_name IN (${emails.map(() => '?').join(',')})`, emails) : [];
    const entraSet = new Set(entra.map((e) => e.upn.toLowerCase()));

    if (kind === 'usage') {
      const existing = emails.length ? await q(
        `SELECT email, mtd_spend, custom_limit FROM ai_usage_member WHERE platform='claude' AND month=? AND email IN (${emails.map(() => '?').join(',')})`,
        [month, ...emails]) : [];
      const exMap = Object.fromEntries(existing.map((e) => [e.email, e]));
      for (const r of clean) {
        const spend = parseFloat(r.mtd ?? r.spend ?? 0) || 0;
        const lim = r.customLimit != null && r.customLimit !== '' ? parseFloat(r.customLimit) : null;
        const grp = r.groupLimit != null && r.groupLimit !== '' ? parseFloat(r.groupLimit) : null;
        const ex = exMap[r.email];
        const status = !ex ? 'new' : (Number(ex.mtd_spend) !== spend || Number(ex.custom_limit || 0) !== Number(lim || 0)) ? 'updated' : 'unchanged';
        report[status === 'unchanged' ? 'unchanged' : status]++;
        if (!entraSet.has(r.email)) report.unmatchedEntra++;
        report.items.push({ email: r.email, name: r.name || null, spend, customLimit: lim, status, matchedEntra: entraSet.has(r.email) });
        if (mode === 'commit') {
          await pool.query(
            `INSERT INTO ai_usage_member (platform,email,name_raw,custom_limit,mtd_spend,month,group_limit) VALUES ('claude',?,?,?,?,?,?)
             ON DUPLICATE KEY UPDATE name_raw=VALUES(name_raw), custom_limit=COALESCE(VALUES(custom_limit),custom_limit), mtd_spend=IF(VALUES(mtd_spend)>0,VALUES(mtd_spend),mtd_spend), group_limit=COALESCE(VALUES(group_limit),group_limit)`,
            [r.email, r.name || null, lim, spend, month, grp]);
        }
      }
      if (mode === 'commit' && (req.body.org || null)) {
        const o = req.body.org;
        const resetLabel = cleanText(o.resetLabel, 32);   // ai_org_snapshot.reset_label is varchar(32)
        // Only touch fields actually present & non-null in the payload — never null out good data.
        const sets = []; const vals = [];
        if (o.orgLimit != null) { sets.push('org_limit=?'); vals.push(o.orgLimit); }
        if (o.mtdTotal != null) { sets.push('mtd_total=?'); vals.push(o.mtdTotal); }
        if (o.balance != null) { sets.push('balance=?'); vals.push(o.balance); }
        if (resetLabel != null) { sets.push('reset_label=?'); vals.push(resetLabel); }
        if (o.resetDate != null) { sets.push('reset_date=?'); vals.push(o.resetDate); }
        await pool.query(
          `INSERT INTO ai_org_snapshot (platform,month,org_limit,mtd_total,balance,reset_label,reset_date)
           VALUES ('claude',?,?,?,?,?,?)
           ON DUPLICATE KEY UPDATE ${sets.length ? sets.join(', ') : 'platform=platform'}`,
          [month, o.orgLimit ?? null, o.mtdTotal ?? null, o.balance ?? null, resetLabel, o.resetDate ?? null, ...vals]);
      }
    } else {
      const existing = emails.length ? await q(
        `SELECT email FROM ai_directory_override WHERE email IN (${emails.map(() => '?').join(',')})`, emails) : [];
      const exSet = new Set(existing.map((e) => e.email));
      for (const r of clean) {
        const status = exSet.has(r.email) ? 'updated' : 'new';
        report[status]++;
        if (!entraSet.has(r.email)) report.unmatchedEntra++;
        report.items.push({ email: r.email, name: r.name || null, department: r.department || null, manager: r.manager || null, status, matchedEntra: entraSet.has(r.email) });
        if (mode === 'commit') {
          await pool.query(
            `INSERT INTO ai_directory_override (email,name,department,manager,employee_id,updated_by) VALUES (?,?,?,?,?,?)
             ON DUPLICATE KEY UPDATE name=VALUES(name), department=VALUES(department), manager=VALUES(manager), employee_id=VALUES(employee_id), updated_by=VALUES(updated_by)`,
            [r.email, r.name || null, r.department || null, r.manager || null, r.employeeId || null, req.user?.email || 'unknown']);
        }
      }
    }
    report.committed = mode === 'commit';
    res.json(report);
  } catch (err) {
    console.error('[insights/ai/import]', err.message);
    res.status(500).json({ error: 'import failed' });
  }
});

// ---------- Claude billing ledger (added 2026-09-15) --------------------------------
// Anthropic's invoices and usage-credit balance live only in the claude.ai Billing page
// (no API). They are captured here — pasted table, CSV, or invoice PDFs — into
// claude_invoice / claude_credit_balance, and every page surface reads THIS ledger for
// Invoiced / Paid / Open / Credit balance. Usage stays the Analytics API; the two are
// never blended, only reconciled (credits purchased − usage consumed ≈ balance).
const BILL_TYPES = ['plan', 'plan_refunded', 'seat', 'credit', 'other'];
const BILL_STATUS = ['Open', 'Paid', 'Refunded', 'Void'];
const SEAT_ANNUAL = 240;   // $/seat/yr on the Enterprise term (invoice: 85 × remaining term = $13,385.56)
const isoDay = (v) => { if (!v) return null; const s = String(v).trim(); const m = s.match(/^(\d{4})-(\d{2})-(\d{2})/); if (m) return `${m[1]}-${m[2]}-${m[3]}`;
  const d = new Date(s); return isNaN(d) ? null : d.toISOString().slice(0, 10); };
/** Classify one billing row. An explicit `type` wins; otherwise the same rules the
 *  ledger was reconciled with: no due date → credit purchase (paid on the spot);
 *  a whole number of prorated seats to term end → seat; "Claude Enterprise" with a
 *  seat qty → plan; else 'other' for a human to look at. */
function classifyInvoice(r, termEnd) {
  if (r.type && BILL_TYPES.includes(r.type)) return { type: r.type, seats: r.seats_added != null ? Number(r.seats_added) : null };
  const desc = String(r.description || '').toLowerCase();
  const amt = Number(r.amount) || 0;
  if (/prepaid|recharge|extra usage|credit/.test(desc)) return { type: 'credit', seats: null };
  if (/claude enterprise/.test(desc) && r.seats_added) return { type: 'plan', seats: Number(r.seats_added) };
  if (!r.due_date && amt >= 500) return { type: 'credit', seats: null };
  if (termEnd && r.invoice_date) {
    const daysLeft = Math.round((new Date(termEnd + 'T00:00:00Z') - new Date(r.invoice_date + 'T00:00:00Z')) / 864e5);
    const daysTerm = 365;
    const perSeat = SEAT_ANNUAL * daysLeft / daysTerm;
    if (perSeat > 0) { const n = amt / perSeat; if (Math.abs(n - Math.round(n)) <= 0.03 && Math.round(n) >= 1) return { type: 'seat', seats: Math.round(n) }; }
  }
  return { type: 'other', seats: null };
}

// GET /api/insights/shared/billing?from=YYYY-MM-DD&to=YYYY-MM-DD — ledger + reconciliation.
// Org-wide financial figures: returned only to an org-scope viewer (same rule as the
// Copilot licence block); everyone else gets {scoped:true} and the page hides the card.
router.get('/shared/billing', rbac.requirePage('ai-usage-credits', 'read'), async (req, res) => {
  try {
    const rq = await resolveScopeForRequest(pool, req);
    const allow = await scopedEmails(rq.scope);
    if (allow !== null) return res.json({ scoped: true, rows: [], totals: null });
    const from = isoDay(req.query.from), to = isoDay(req.query.to);
    const rows = await q(
      `SELECT id, invoice_date, due_date, amount, status, type, seats_added, description, invoice_no, paid_date, source
         FROM claude_invoice ORDER BY invoice_date, id`);
    const fmt = (r) => ({ ...r, invoice_date: fmtDate(r.invoice_date), due_date: fmtDate(r.due_date), paid_date: fmtDate(r.paid_date), amount: Number(r.amount) });
    const all = rows.map(fmt);
    const inRange = all.filter((r) => (!from || r.invoice_date >= from) && (!to || r.invoice_date <= to));
    const agg = (list) => {
      const t = { count: list.length, invoicedGross: 0, refunded: 0, invoicedNet: 0, paid: 0, open: 0, byType: {} };
      for (const r of list) {
        t.invoicedGross += r.amount;
        if (r.status === 'Refunded' || r.type === 'plan_refunded') t.refunded += r.amount;
        if (r.status === 'Paid') t.paid += r.amount;
        if (r.status === 'Open') t.open += r.amount;
        const b = t.byType[r.type] || (t.byType[r.type] = { count: 0, amount: 0, seats: 0 });
        b.count++; b.amount += r.amount; b.seats += Number(r.seats_added) || 0;
      }
      t.invoicedNet = t.invoicedGross - t.refunded;
      for (const k of Object.keys(t)) if (typeof t[k] === 'number') t[k] = Math.round(t[k] * 100) / 100;
      for (const b of Object.values(t.byType)) b.amount = Math.round(b.amount * 100) / 100;
      return t;
    };
    // seat timeline: base seats from the plan row, then each seat invoice adds on its date
    let seats = 0; const timeline = [];
    for (const r of all) {
      if (r.type === 'plan') { seats = Number(r.seats_added) || seats; timeline.push({ date: r.invoice_date, added: 0, seats }); }
      else if (r.type === 'seat' && r.seats_added) { seats += Number(r.seats_added); timeline.push({ date: r.invoice_date, added: Number(r.seats_added), seats }); }
    }
    const [bal] = await q(`SELECT as_of, balance FROM claude_credit_balance ORDER BY as_of DESC LIMIT 1`);
    const creditsAll = all.filter((r) => r.type === 'credit' && r.status !== 'Refunded').reduce((a, r) => a + r.amount, 0);
    // usage consumed (Analytics API) to the balance's as-of date, for the identity check
    const asOf = bal ? fmtDate(bal.as_of) : null;
    // Change #15 (2026-09-23): a top-up dated AFTER the balance's as-of date cannot be in that
    // balance, so the implied figure must only count purchases up to and including as-of.
    const creditsToAsOf = all.filter((r) => r.type === 'credit' && r.status !== 'Refunded' && (!asOf || r.invoice_date <= asOf))
      .reduce((a, r) => a + r.amount, 0);
    const [use] = asOf
      ? await q(`SELECT COALESCE(SUM(amount_cents),0)/100 u FROM claude_cost_daily WHERE day <= ?`, [asOf])
      : [{ u: 0 }];
    const [apiSeats] = await q(`SELECT assigned_seats FROM claude_summary_daily ORDER BY day DESC LIMIT 1`);
    const [meta] = await q(`SELECT MAX(updated_at) updated, COUNT(*) n FROM claude_invoice`);
    res.json({
      scoped: false, from, to,
      rows: inRange, totals: agg(inRange), allTime: agg(all),
      seatTimeline: timeline, seatsFromInvoices: seats,
      seatsFromApi: apiSeats ? Number(apiSeats.assigned_seats) : null,
      credits: { purchased: Math.round(creditsAll * 100) / 100, balance: bal ? Number(bal.balance) : null, balanceAsOf: asOf,
                 purchasedToAsOf: Math.round(creditsToAsOf * 100) / 100,
                 usageToAsOf: Math.round(Number(use.u) * 100) / 100,
                 implied: bal ? Math.round((creditsToAsOf - Number(use.u)) * 100) / 100 : null },
      ledgerUpdatedAt: meta && meta.updated ? new Date(meta.updated).toISOString() : null,
      ledgerRows: meta ? Number(meta.n) : 0,
      source: 'claude.ai Billing page (captured)', usageSource: 'Anthropic Analytics API',
    });
  } catch (err) {
    console.error('[insights/shared/billing]', err.message);
    res.status(500).json({ error: 'billing query failed' });
  }
});

// ---------- Model cost & efficiency (added 2026-09-25) ----------
// GET /api/insights/shared/model-cost?from=YYYY-MM-DD&to=YYYY-MM-DD
// Per-model cost for the reporting period, and — new with the collector change of
// 2026-09 — who spent it, per model. Reads ONLY claude_user_model_daily (day × user ×
// product × model, dollars = Anthropic's amount_cents verbatim; nothing is computed from
// tokens). Aggregation happens here, after the RBAC scope filter, so a scoped viewer
// (a manager) gets model totals that add up to the people they are allowed to see.
// Read-only; adds no table and changes no other route.
router.get('/shared/model-cost', rbac.requirePage('ai-usage-credits', 'read'), async (req, res) => {
  try {
    const rq = await resolveScopeForRequest(pool, req);
    const allow = await scopedEmails(rq.scope);
    const from = isoDay(req.query.from), to = isoDay(req.query.to);
    const [cov] = await q(`SELECT MIN(day) f, MAX(day) t, COUNT(*) n FROM claude_user_model_daily`);
    const covFrom = cov && cov.f ? fmtDate(cov.f) : null, covTo = cov && cov.t ? fmtDate(cov.t) : null;
    if (!covFrom) return res.json({ available: false, scoped: allow !== null, coverage: null, byModel: [], byModelProduct: [], byMonth: [], byUser: [] });
    // effective window: the requested period clipped to what the table holds
    const effFrom = from && from > covFrom ? from : covFrom;
    const effTo = to && to < covTo ? to : covTo;
    // one pass at month × person × model × product grain, 13 months back at most
    const rows = await q(
      `SELECT DATE_FORMAT(day,'%Y-%m') ym, LOWER(COALESCE(email,'')) email, MAX(display_name) name, model, product,
              SUM(amount_cents) c, SUM(list_amount_cents) lc, SUM(requests) r,
              SUM(uncached_input) ui, SUM(cache_read) cr, SUM(cache_creation_5m+cache_creation_1h) cw,
              SUM(output_tokens) o, SUM(total_tokens) t
         FROM claude_user_model_daily
        WHERE day >= DATE_SUB(CURDATE(), INTERVAL 13 MONTH)
        GROUP BY ym, email, model, product`);
    const vis = rows.filter((r) => allow === null || allow.has(r.email));
    // month grain is enough for byMonth; for the period itself use day-accurate sums
    const prows = await q(
      `SELECT LOWER(COALESCE(email,'')) email, MAX(display_name) name, model, product,
              SUM(amount_cents) c, SUM(list_amount_cents) lc, SUM(requests) r,
              SUM(uncached_input) ui, SUM(cache_read) cr, SUM(cache_creation_5m+cache_creation_1h) cw,
              SUM(output_tokens) o, SUM(total_tokens) t
         FROM claude_user_model_daily
        WHERE day BETWEEN ? AND ?
        GROUP BY email, model, product`, [effFrom, effTo]);
    const pvis = prows.filter((r) => allow === null || allow.has(r.email));
    const d2 = (v) => Math.round(Number(v) / 100 * 100) / 100;           // cents → dollars, 2dp
    const bump = (o, r) => { o.spend += Number(r.c) || 0; o.list += Number(r.lc) || 0; o.requests += Number(r.r) || 0;
      o.uncached += Number(r.ui) || 0; o.cacheRead += Number(r.cr) || 0; o.cacheWrite += Number(r.cw) || 0; o.output += Number(r.o) || 0; o.tokens += Number(r.t) || 0; };
    const blank = () => ({ spend: 0, list: 0, requests: 0, uncached: 0, cacheRead: 0, cacheWrite: 0, output: 0, tokens: 0 });
    const fin = (o) => ({ ...o, spend: d2(o.spend), list: d2(o.list) });

    const byModel = {}, byMP = {}, byUser = {};
    for (const r of pvis) {
      const m = byModel[r.model] || (byModel[r.model] = { model: r.model, people: new Set(), ...blank() });
      bump(m, r); if (r.email) m.people.add(r.email);
      const k = r.model + '|' + r.product;
      const mp = byMP[k] || (byMP[k] = { model: r.model, product: r.product, ...blank() });
      bump(mp, r);
      if (r.email) {
        const u = byUser[r.email] || (byUser[r.email] = { email: r.email, name: r.name || r.email, models: {}, ...blank() });
        bump(u, r);
        const um = u.models[r.model] || (u.models[r.model] = { model: r.model, ...blank() });
        bump(um, r);
      }
    }
    const byMonth = {};
    for (const r of vis) {
      const k = r.ym + '|' + r.model;
      const o = byMonth[k] || (byMonth[k] = { month: r.ym, model: r.model, ...blank() });
      bump(o, r);
    }
    // org-wide total for the same window from the org-level table, so the page can show
    // what is not attributable to a person (system / API usage with no user) — org-wide only
    let orgTotal = null, unattributed = null;
    if (allow === null) {
      const [ot] = await q(`SELECT COALESCE(SUM(amount_cents),0) c FROM claude_cost_daily WHERE day BETWEEN ? AND ?`, [effFrom, effTo]);
      orgTotal = d2(ot.c);
      const attributed = Object.values(byModel).reduce((a, m) => a + m.spend, 0);
      unattributed = Math.round((Number(ot.c) - attributed) / 100 * 100) / 100;
    }
    const [meta] = await q(`SELECT MAX(updated_at) u FROM claude_user_model_daily`);
    res.json({
      available: true, scoped: allow !== null, scope: publicScope(rq.scope),
      from, to, effectiveFrom: effFrom, effectiveTo: effTo,
      coverage: { from: covFrom, to: covTo, rows: Number(cov.n) },
      byModel: Object.values(byModel).map((m) => ({ ...fin(m), people: m.people.size })).sort((a, b) => b.spend - a.spend),
      byModelProduct: Object.values(byMP).map(fin).sort((a, b) => b.spend - a.spend),
      byMonth: Object.values(byMonth).map(fin).sort((a, b) => a.month.localeCompare(b.month) || b.spend - a.spend),
      byUser: Object.values(byUser).map((u) => ({ ...fin(u), models: Object.values(u.models).map(fin).sort((a, b) => b.spend - a.spend) })).sort((a, b) => b.spend - a.spend),
      orgTotal, unattributed,
      updatedAt: meta && meta.u ? new Date(meta.u).toISOString() : null,
      source: 'Anthropic Analytics API — user_cost_report / user_usage_report grouped by model (claude_user_model_daily)',
    });
  } catch (err) {
    console.error('[insights/shared/model-cost]', err.message);
    res.status(500).json({ error: 'model cost query failed' });
  }
});

// ---------- Copilot per-app usage (added 2026-08-19) ----------
// GET /api/insights/copilot/app-usage — Graph-sourced per-app last-activity, keyed by lowercased email
router.get('/copilot/app-usage', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    // DATA SCOPE (F36, 2026-10-21): same boundary as /shared/copilot-usage.
    const allow = await scopedEmails((await resolveScopeForRequest(pool, req)).scope);
    const rows = (await q(
      `SELECT email, last_activity_date, chat_last_active, teams_last_active, word_last_active,
              excel_last_active, powerpoint_last_active, outlook_last_active, onenote_last_active,
              loop_last_active, report_refresh_date
       FROM copilot_app_usage`)).filter((r) => inScope(allow, r.email));
    const fmt = (v) => (v == null ? null : v instanceof Date ? v.toISOString().slice(0, 10) : String(v).slice(0, 10));
    const users = {};
    let refreshedAt = null;
    for (const r of rows) {
      const rf = fmt(r.report_refresh_date);
      if (rf && (!refreshedAt || rf > refreshedAt)) refreshedAt = rf;
      users[r.email.toLowerCase()] = {
        chat: fmt(r.chat_last_active), teams: fmt(r.teams_last_active), word: fmt(r.word_last_active),
        excel: fmt(r.excel_last_active), powerpoint: fmt(r.powerpoint_last_active), outlook: fmt(r.outlook_last_active),
        onenote: fmt(r.onenote_last_active), loop: fmt(r.loop_last_active),
        lastActivityDate: fmt(r.last_activity_date), reportRefreshDate: rf,
      };
    }
    res.json({ users, refreshedAt, count: rows.length });
  } catch (err) {
    console.error('[insights/copilot/app-usage]', err.message);
    res.status(500).json({ error: 'copilot app-usage query failed' });
  }
});

// ---------- Shared standalone AI Usage & Credits page (added 2026-08-19) ----------
// ACCESS MANAGEMENT NARROWED 2026-09-03: the /access endpoints below moved from
// requirePage('ai-usage-credits','admin') to requireSuperAdmin. Deciding who may open
// a report - and, since the scope layer, how much of it they see - is a platform-owner
// action, not something every page-admin should hold. Hiding the button in the topbar
// would only have changed what is offered; this changes what is permitted.
// Practical effect: asteinhaus keeps admin on the page (import, drawer view) but can no
// longer grant or revoke access. RBAC_SUPERADMINS = jriggs, rabad.
// Gated by a SEPARATE page key ('ai-usage-credits') from the main dashboard ('tenant-sentinel'),
// granted per-user via rbac_user_page_access — deliberately narrower than the main dashboard so
// people sharing this link don't get access to Threat Protection / Devices / Fix Tracking / etc.

// GET /api/insights/shared/ai-usage — same data + join as /api/insights/ai/usage
router.get('/shared/ai-usage', rbac.requirePage('ai-usage-credits', 'read'), async (req, res) => {
  try {
    const rq      = await resolveScopeForRequest(pool, req);
    const scope   = rq.scope;
    const payload = await claudeUsagePayload(req.query.month);
    const allow   = await scopedEmails(scope);
    if (allow === null) return res.json({ ...payload, scope: publicScope(scope),
                                          viewingAs: rq.viewingAs, viewAsDenied: rq.viewAsDenied });

    const members = (payload.members || []).filter((m) => inScope(allow, m.email));
    // The org block carries ORG-WIDE figures. Leaving them intact above a filtered
    // member list would print a total the rows cannot add up to. Recompute what the
    // visible members support and NULL what only makes sense organisation-wide -
    // assignedSeats null makes the page fall back to counting members, which is the
    // same path the old client-side department filter already took.
    const mtd  = members.reduce((a, m) => a + (Number(m.mtd) || 0), 0);
    const reqs = members.reduce((a, m) => a + (Number(m.requests) || 0), 0);
    const c    = (payload.org && payload.org.claude) || {};
    const org  = { claude: { ...c,
      mtdTotal: Math.round(mtd * 100) / 100,
      requests: reqs,
      assignedSeats: null, prevMonthTotal: null,
      orgLimit: null, balance: null, balanceAsOf: null,
      scoped: true } };
    res.json({ ...payload, members, org, scope: publicScope(scope),
               viewingAs: rq.viewingAs, viewAsDenied: rq.viewAsDenied });
  } catch (err) {
    console.error('[insights/shared/ai-usage]', err.message);
    res.status(500).json({ error: 'ai usage query failed' });
  }
});

// GET /api/insights/shared/copilot-usage — Copilot roster sourced directly from
// copilot_app_usage (the Graph-backed table), joined to entra_users. Deliberately does NOT
// depend on the license-holder/SKU lookup the main dashboard uses, so this route has no
// dependency on those endpoints or their gating.
router.get('/shared/copilot-usage', rbac.requirePage('ai-usage-credits', 'read'), async (req, res) => {
  try {
    const rows = await q(
      `SELECT c.email, c.display_name, c.last_activity_date, c.chat_last_active, c.teams_last_active,
              c.word_last_active, c.excel_last_active, c.powerpoint_last_active, c.outlook_last_active,
              c.onenote_last_active, c.loop_last_active, c.report_refresh_date,
              COALESCE(o.name, u.display_name, c.display_name)  AS name,
              COALESCE(o.department, u.department)              AS department,
              COALESCE(o.manager, m.display_name)               AS manager
       FROM copilot_app_usage c
       INNER JOIN insight_user_activity ia ON ia.upn = c.email
         AND ia.licenses LIKE '%MICROSOFT 365 COPILOT%'
       LEFT JOIN ${ENTRA1} u ON u.user_principal_name = c.email
       LEFT JOIN ${ENTRA1} m ON m.user_principal_name = u.manager_upn
       LEFT JOIN ai_directory_override o ON o.email = c.email`);
    let refreshedAt = null;
    const users = rows.map((r) => {
      const rf = fmtDate(r.report_refresh_date);
      if (rf && (!refreshedAt || rf > refreshedAt)) refreshedAt = rf;
      return {
        email: r.email, name: r.name, department: r.department || '—', manager: r.manager || '—',
        lastActive: fmtDate(r.last_activity_date),
        apps: {
          chat: fmtDate(r.chat_last_active), teams: fmtDate(r.teams_last_active), word: fmtDate(r.word_last_active),
          excel: fmtDate(r.excel_last_active), powerpoint: fmtDate(r.powerpoint_last_active),
          outlook: fmtDate(r.outlook_last_active), onenote: fmtDate(r.onenote_last_active), loop: fmtDate(r.loop_last_active),
        },
      };
    });
    const [licRow] = await q(
      `SELECT s.consumed AS assigned, s.enabled AS provisioned, c.unit_monthly AS unitCost
       FROM insight_sku s
       LEFT JOIN insight_cost c ON c.sku_part_number = s.sku_part_number
       WHERE s.sku_part_number = 'Microsoft_365_Copilot'
       LIMIT 1`);
    // R-1 RESOLVED 2026-09-15: $28.00 per ASSIGNED licence. The DB rate is aligned to
    // 28.00 in the same release; the constant guards against a stale row re-appearing.
    const COPILOT_RATE = 28;
    const license = licRow ? {
      purchased: +licRow.provisioned,      // kept in the payload for reference; the page shows Assigned only
      assigned: +licRow.assigned,
      unitCost: COPILOT_RATE,
      totalMonthly: +( +licRow.assigned * COPILOT_RATE ).toFixed(2),
      basis: 'assigned',
    } : null;
    // Same boundary as /shared/ai-usage: this is per-person activity for the whole
    // company unless it is scoped here.
    const cpRq    = await resolveScopeForRequest(pool, req);
    const cpScope = cpRq.scope;
    const cpAllow = await scopedEmails(cpScope);
    const cpUsers = cpAllow === null ? users : users.filter((u) => inScope(cpAllow, u.email));
    // The license block is ORG-WIDE (purchased / assigned / totalMonthly). Same boundary as
    // /shared/ai-usage above: leaving it intact over a filtered member list would print a
    // total the rows cannot add up to, and there is no such thing as a department's share of
    // purchased seats - so NULL it rather than recomputing it. cpAllow === null is this
    // file's idiom for unrestricted, the same test that decides whether to filter `users`.
    // The client already degrades: `licPurchased = lic.purchased || null` then falls back to
    // the visible member count via `licPurchased || totalU` on every consumer.
    res.json({ users: cpUsers, refreshedAt, count: cpUsers.length,
               license: cpAllow === null ? license : null,
               scope: publicScope(cpScope), viewingAs: cpRq.viewingAs, viewAsDenied: cpRq.viewAsDenied });
  } catch (err) {
    console.error('[insights/shared/copilot-usage]', err.message);
    res.status(500).json({ error: 'shared copilot usage query failed' });
  }
});

// ---------- Shared page access admin (added 2026-08-19) ----------
// Lets an ai-usage-credits ADMIN (not just read-access viewers) manage who else can
// view the shared page, directly from the page itself instead of raw SQL each time.
// Deliberately grants only 'read' from this UI — granting 'admin' stays a manual SQL
// action, so ownership can't be silently escalated through the in-page form.
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// GET /api/insights/shared/ai-usage-credits/access — list current grants (admin only)
router.get('/shared/ai-usage-credits/access', rbac.requireSuperAdmin, async (req, res) => {
  try {
    const rows = await q(
      `SELECT email, access_level, granted_by, granted_at
       FROM rbac_user_page_access
       WHERE page_key = 'ai-usage-credits'
       ORDER BY granted_at DESC`);
    const fmt = (v) => (v == null ? null : v instanceof Date ? v.toISOString() : String(v));
    res.json({ grants: rows.map((r) => ({ ...r, granted_at: fmt(r.granted_at) })) });
  } catch (err) {
    console.error('[insights/shared/ai-usage-credits/access GET]', err.message);
    res.status(500).json({ error: 'access list query failed' });
  }
});

// POST /api/insights/shared/ai-usage-credits/access — body {email, accessLevel} — grant read or admin (admin only)
router.post('/shared/ai-usage-credits/access', require('express').json({ limit: '10kb' }), rbac.requireSuperAdmin, async (req, res) => {
  const email = String((req.body || {}).email || '').trim().toLowerCase();
  const accessLevel = String((req.body || {}).accessLevel || 'read').trim().toLowerCase();
  if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'invalid email' });
  if (!['read', 'admin'].includes(accessLevel)) return res.status(400).json({ error: 'invalid access level -- must be read or admin' });
  try {
    await pool.query(`INSERT IGNORE INTO rbac_users (email, display_name, created_by) VALUES (?, ?, ?)`, [email, email, req.user?.email || "system"]);
    const [existing] = await q(`SELECT access_level FROM rbac_user_page_access WHERE email = ? AND page_key = 'ai-usage-credits'`, [email]);
    if (existing && existing.access_level === 'admin' && accessLevel === 'read') {
      return res.status(403).json({
        error: 'cannot_downgrade_admin',
        detail: 'This person is currently an Administrator. Downgrading an admin has to be done via direct SQL, not this panel -- protects against accidental lockouts.',
      });
    }
    await pool.query(
      `INSERT INTO rbac_user_page_access (email, page_key, access_level, granted_by)
       VALUES (?, 'ai-usage-credits', ?, ?)
       ON DUPLICATE KEY UPDATE access_level = VALUES(access_level), granted_by = VALUES(granted_by), granted_at = CURRENT_TIMESTAMP`,
      [email, accessLevel, req.user?.email || 'unknown']
    );
    // Same action vocabulary as rbac-admin (rbac-routes.js PUT /users/:email/access),
    // so a grant made from this page is indistinguishable in rbac_audit_log from one
    // made in the RBAC console. Without this, access to this page could be handed out
    // with no trace at all.
    const before = existing ? existing.access_level : null;
    let action = 'access_changed';
    if (!before) action = 'access_granted';
    if (before !== accessLevel || !before) {
      await rbac.audit(req, action, email, 'ai-usage-credits',
        { before: before || null, after: accessLevel, via: 'ai-usage-credits page' });
    }
    res.json({ ok: true, email, accessLevel });
  } catch (err) {
    console.error('[insights/shared/ai-usage-credits/access POST]', err.message);
    res.status(500).json({ error: 'grant failed' });
  }
});

// DELETE /api/insights/shared/ai-usage-credits/access/:email — revoke (admin only)
router.delete('/shared/ai-usage-credits/access/:email', rbac.requireSuperAdmin, async (req, res) => {
  const email = String(req.params.email || '').trim().toLowerCase();
  if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'invalid email' });
  try {
    const [existing] = await q(`SELECT access_level FROM rbac_user_page_access WHERE email = ? AND page_key = 'ai-usage-credits'`, [email]);
    await pool.query(`DELETE FROM rbac_user_page_access WHERE email = ? AND page_key = 'ai-usage-credits'`, [email]);
    if (existing) {
      await rbac.audit(req, 'access_revoked', email, 'ai-usage-credits',
        { before: existing.access_level, after: null, via: 'ai-usage-credits page' });
    }
    res.json({ ok: true, email });
  } catch (err) {
    console.error('[insights/shared/ai-usage-credits/access DELETE]', err.message);
    res.status(500).json({ error: 'revoke failed' });
  }
});

// GET /api/insights/shared/ai-usage-credits/directory-search?q=... — autocomplete
// against real entra_users (admin only, internal directory only, active accounts only)
router.get('/shared/ai-usage-credits/directory-search', rbac.requireSuperAdmin, async (req, res) => {
  const term = String(req.query.q || '').trim();
  if (term.length < 2) return res.json({ results: [] });
  try {
    const like = `%${term}%`;
    const rows = await q(
      `SELECT user_principal_name AS email, display_name AS name
       FROM entra_users
       WHERE account_enabled = 1
         AND (user_principal_name LIKE ? OR display_name LIKE ? OR mail LIKE ?)
       ORDER BY display_name
       LIMIT 15`,
      [like, like, like]
    );
    res.json({ results: rows });
  } catch (err) {
    console.error('[insights/shared/ai-usage-credits/directory-search]', err.message);
    res.status(500).json({ error: 'directory search failed' });
  }
});

// ── AI usage org group spend limit (settingsfold W3, 2026-10-12) ─────────────
// Was kept only in the browser (localStorage 'ai_group_limit'). Stored in
// corpit_hub.ai_limit_setting, one row per platform. Read = the same guard as
// /shared/ai-usage (the page's data read); write = the same guard as the CSV
// import below (admin on ai-usage-credits), since the value is entered in the
// import drawer. updated_by follows this file's req.user?.email convention.
// The body is parsed by server.js's global 1 MB JSON parser (CHG-ARCH-13).
const GROUP_LIMIT_MAX = 9999999999.99;   // DECIMAL(12,2)
router.get('/shared/ai-usage-credits/group-limit', rbac.requirePage('ai-usage-credits', 'read'), async (req, res) => {
  try {
    const [row] = await q(`SELECT group_limit, updated_by, updated_at FROM ai_limit_setting WHERE platform='claude'`);
    res.json({ platform: 'claude', groupLimit: row && row.group_limit != null ? Number(row.group_limit) : null,
      updatedBy: row ? row.updated_by : null, updatedAt: row ? row.updated_at : null });
  } catch (err) {
    console.error('[insights/shared/ai-usage-credits/group-limit]', err.message);
    res.status(500).json({ error: 'group limit read failed' });
  }
});
router.put('/shared/ai-usage-credits/group-limit', rbac.requirePage('ai-usage-credits', 'admin'), async (req, res) => {
  const raw = (req.body || {}).groupLimit;
  const v = typeof raw === 'number' ? raw : (typeof raw === 'string' && raw.trim() !== '' ? Number(raw) : NaN);
  if (!Number.isFinite(v) || v <= 0 || v > GROUP_LIMIT_MAX)
    return res.status(400).json({ error: 'groupLimit must be a number greater than 0' });
  try {
    const saBefore = await SA.snap(pool, `SELECT group_limit FROM ai_limit_setting WHERE platform='claude'`);
    await pool.query(
      `INSERT INTO ai_limit_setting (platform, group_limit, updated_by) VALUES ('claude', ?, ?)
       ON DUPLICATE KEY UPDATE group_limit=VALUES(group_limit), updated_by=VALUES(updated_by)`,
      [Math.round(v * 100) / 100, req.user?.email || 'unknown']);
    const [row] = await q(`SELECT group_limit, updated_by, updated_at FROM ai_limit_setting WHERE platform='claude'`);
    await SA.record(rbac, req, 'ai-usage-credits', 'settings_saved', SA.entry({ what: 'ai_group_limit', subject: 'claude',
      before: saBefore, after: row || null, keys: ['group_limit'] }));
    res.json({ platform: 'claude', groupLimit: Number(row.group_limit), updatedBy: row.updated_by, updatedAt: row.updated_at });
  } catch (err) {
    console.error('[insights/shared/ai-usage-credits/group-limit PUT]', err.message);
    res.status(500).json({ error: 'group limit save failed' });
  }
});

// POST /api/insights/shared/ai-usage-credits/import — CSV usage import, gated by
// admin level on ai-usage-credits (NOT tenant-sentinel), so standalone-page admins
// can refresh data without needing any access to the main M365 Control Center.
router.post('/shared/ai-usage-credits/import', require('express').json({ limit: '4mb' }), rbac.requirePage('ai-usage-credits', 'admin'), async (req, res) => {
  const { mode, month, rows } = req.body || {};
  if (!['preview', 'commit'].includes(mode) || !Array.isArray(rows))
    return res.status(400).json({ error: 'invalid payload' });
  if (!/^\d{4}-\d{2}-01$/.test(month || ''))
    return res.status(400).json({ error: 'import requires month YYYY-MM-01' });
  try {
    const seen = new Set(); const report = { total: rows.length, new: 0, updated: 0, unchanged: 0, duplicates: 0, unmatchedEntra: 0, invalid: 0, items: [] };
    const clean = []; const alias = await emailAliasMap();
    for (const r of rows.slice(0, 5000)) {
      const raw = String(r.email || '').trim().toLowerCase();
      const email = alias.get(raw) || raw;
      if (!importEmailOk(email)) { report.invalid++; continue; }
      if (seen.has(email)) { report.duplicates++; continue; }
      seen.add(email); clean.push({ ...r, email, name: cleanText(r.name) });
    }
    const emails = clean.map((r) => r.email);
    const entra = emails.length ? await q(
      `SELECT user_principal_name upn FROM entra_users WHERE user_principal_name IN (${emails.map(() => '?').join(',')})`, emails) : [];
    const entraSet = new Set(entra.map((e) => e.upn.toLowerCase()));

    const existing = emails.length ? await q(
      `SELECT email, mtd_spend, custom_limit FROM ai_usage_member WHERE platform='claude' AND month=? AND email IN (${emails.map(() => '?').join(',')})`,
      [month, ...emails]) : [];
    const exMap = Object.fromEntries(existing.map((e) => [e.email, e]));
    for (const r of clean) {
      const spend = parseFloat(r.mtd ?? r.spend ?? 0) || 0;
      const lim = r.customLimit != null && r.customLimit !== '' ? parseFloat(r.customLimit) : null;
      const grp = r.groupLimit != null && r.groupLimit !== '' ? parseFloat(r.groupLimit) : null;
      const ex = exMap[r.email];
      const status = !ex ? 'new' : (Number(ex.mtd_spend) !== spend || Number(ex.custom_limit || 0) !== Number(lim || 0)) ? 'updated' : 'unchanged';
      report[status === 'unchanged' ? 'unchanged' : status]++;
      if (!entraSet.has(r.email)) report.unmatchedEntra++;
      report.items.push({ email: r.email, name: r.name || null, spend, customLimit: lim, status, matchedEntra: entraSet.has(r.email) });
      if (mode === 'commit') {
        await pool.query(
          `INSERT INTO ai_usage_member (platform,email,name_raw,custom_limit,mtd_spend,month,group_limit) VALUES ('claude',?,?,?,?,?,?)
           ON DUPLICATE KEY UPDATE name_raw=VALUES(name_raw), custom_limit=COALESCE(VALUES(custom_limit),custom_limit), mtd_spend=IF(VALUES(mtd_spend)>0,VALUES(mtd_spend),mtd_spend), group_limit=COALESCE(VALUES(group_limit),group_limit)`,
          [r.email, r.name || null, lim, spend, month, grp]);
      }
    }
    if (mode === 'commit' && emails.length) {
      await pool.query(
        `DELETE FROM ai_usage_member WHERE platform='claude' AND month=? AND email NOT IN (${emails.map(()=>'?').join(',')})`,
        [month, ...emails]);
    }
    if (mode === 'commit' && req.body.org) {
      const o = req.body.org;
      await pool.query(
        `INSERT INTO ai_org_snapshot (platform,month,org_limit,mtd_total,balance,reset_label) VALUES ('claude',?,?,?,?,?)
         ON DUPLICATE KEY UPDATE org_limit=VALUES(org_limit), mtd_total=VALUES(mtd_total), balance=VALUES(balance), reset_label=VALUES(reset_label)`,
        [month, o.orgLimit || null, o.mtdTotal || null, o.balance || null, cleanText(o.resetLabel, 32)]);   // reset_label is varchar(32)
    }
    report.committed = mode === 'commit';
    res.json(report);
  } catch (err) {
    console.error('[insights/shared/ai-usage-credits/import]', err.message);
    res.status(500).json({ error: 'import failed' });
  }
});


// ---------- 30/60/90 Day Paid Subscription Usage ----------
// Real data only. "Active" = touched >=3 of 4 workloads (exchange/onedrive/
// sharepoint/teams) within the period; "Low" = 1-2; "Inactive" = 0. This is
// a documented business rule (not a Microsoft-defined metric) built from
// real per-workload last-active dates -- not fabricated. Department Leader
// tier intentionally omitted -- confirmed no leadership signal exists in
// AD or Entra for this tenant.
function classifyUser(row, cutoff) {
  const workloads = ['exchange_last', 'onedrive_last', 'sharepoint_last', 'teams_last'];
  const touched = workloads.filter((w) => row[w] && new Date(row[w]) >= cutoff).length;
  if (touched >= 3) return 'active';
  if (touched >= 1) return 'low';
  return 'inactive';
}

router.get('/paid-usage', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  const days = [30, 60, 90].includes(parseInt(req.query.days, 10)) ? parseInt(req.query.days, 10) : 30;
  const cutoff = new Date(Date.now() - days * 86400e3);
  const rangeEnd = new Date();
  try {
    const paidSkus = await q(
      `SELECT s.sku_part_number, s.consumed, c.total_monthly, c.unit_monthly
         FROM insight_sku s LEFT JOIN insight_cost c ON c.sku_part_number = s.sku_part_number
        WHERE c.category = 'license' OR s.sku_part_number LIKE '%E3%' OR s.sku_part_number LIKE '%E5%'
           OR s.sku_part_number LIKE '%COPILOT%' OR s.sku_part_number LIKE '%POWER_BI_PRO%'`);
    const totalPaidSeats = paidSkus.reduce((a, s) => a + (s.consumed || 0), 0);
    const hasCostData = paidSkus.some((s) => s.total_monthly != null);

    const rows = await q(
      `SELECT a.upn, a.licenses, a.exchange_last, a.onedrive_last, a.sharepoint_last, a.teams_last,
              a.report_date, u.display_name, u.department, u.manager_upn, m.display_name AS managerName
         FROM insight_user_activity a
         JOIN ${ENTRA1} u ON u.user_principal_name = a.upn
         LEFT JOIN ${ENTRA1} m ON m.user_principal_name = u.manager_upn
        WHERE u.account_enabled = 1 AND u.display_name NOT LIKE '.%'
          AND a.licenses IS NOT NULL AND a.licenses != ''
          AND (a.licenses LIKE '%E3%' OR a.licenses LIKE '%E5%' OR a.licenses LIKE '%COPILOT%' OR a.licenses LIKE '%POWER BI PRO%')`);

    const classified = rows.map((r) => ({ ...r, status: classifyUser(r, cutoff) }));
    const active = classified.filter((r) => r.status === 'active').length;
    const low = classified.filter((r) => r.status === 'low').length;
    const inactive = classified.filter((r) => r.status === 'inactive').length;
    const total = classified.length;
    const utilizationRate = total > 0 ? Math.round((active / total) * 100) : 0;

    const byDept = {};
    for (const r of classified) {
      const d = r.department || 'No department on record';
      if (!byDept[d]) byDept[d] = { department: d, total: 0, active: 0, low: 0, inactive: 0 };
      byDept[d].total++;
      byDept[d][r.status]++;
    }
    const departments = Object.values(byDept).map((d) => ({ ...d, utilizationRate: d.total ? Math.round((d.active / d.total) * 100) : 0 }))
      .sort((a, b) => b.total - a.total);

    // Flat employee list + SKU breakdown, for the clickable summary tiles
    // (drawer shows exactly who's behind each number, and how utilization
    // was calculated -- per the spec's SUMMARY -> SUPPORTING DATA -> RECORD
    // -> EVIDENCE principle). Small payload (~600-700 rows), fine to
    // include directly rather than adding a second round-trip endpoint.
    const employees = classified.map((r) => ({
      upn: r.upn, name: r.display_name, department: r.department || 'No department on record',
      manager: r.managerName || r.manager_upn || 'No manager on record', status: r.status,
    }));
    const skuBreakdown = paidSkus.map((s) => ({ sku: s.sku_part_number, seats: s.consumed }));

    res.json({
      days, rangeStart: cutoff.toISOString().slice(0, 10), rangeEnd: rangeEnd.toISOString().slice(0, 10),
      summary: { totalPaidSubscriptionSeats: totalPaidSeats, hasCostData,
                 totalUsersWithPaidLicense: total, active, low, inactive, utilizationRate },
      departments, employees, skuBreakdown,
      note: '"Active/Low/Inactive" is based on each workload\'s last-recorded activity date, not a daily activity log -- Microsoft does not expose per-day usage counts for this data source. Cost figures (where shown) come from a manually-maintained cost table, not live billing.',
    });
  } catch (err) {
    console.error('[insights/paid-usage]', err.message);
    res.status(500).json({ error: 'paid-usage query failed' });
  }
});

router.get('/paid-usage/department', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  const days = [30, 60, 90].includes(parseInt(req.query.days, 10)) ? parseInt(req.query.days, 10) : 30;
  const dept = req.query.dept;
  if (!dept) return res.status(400).json({ error: 'dept query parameter is required' });
  const cutoff = new Date(Date.now() - days * 86400e3);
  try {
    const rows = await q(
      `SELECT a.upn, a.licenses, a.exchange_last, a.onedrive_last, a.sharepoint_last, a.teams_last,
              u.display_name, u.manager_upn, m.display_name AS managerName
         FROM insight_user_activity a
         JOIN ${ENTRA1} u ON u.user_principal_name = a.upn
         LEFT JOIN ${ENTRA1} m ON m.user_principal_name = u.manager_upn
        WHERE u.account_enabled = 1 AND u.department = ?
          AND a.licenses IS NOT NULL AND a.licenses != ''
          AND (a.licenses LIKE '%E3%' OR a.licenses LIKE '%E5%' OR a.licenses LIKE '%COPILOT%' OR a.licenses LIKE '%POWER BI PRO%')`, [dept]);
    const classified = rows.map((r) => ({ ...r, status: classifyUser(r, cutoff) }));
    const byManager = {};
    for (const r of classified) {
      const mgr = r.manager_upn || 'No manager on record';
      if (!byManager[mgr]) byManager[mgr] = { manager_upn: mgr, managerName: r.managerName || mgr, total: 0, active: 0, low: 0, inactive: 0 };
      byManager[mgr].total++;
      byManager[mgr][r.status]++;
    }
    const managers = Object.values(byManager).map((m) => ({ ...m, utilizationRate: m.total ? Math.round((m.active / m.total) * 100) : 0 }))
      .sort((a, b) => b.total - a.total);
    res.json({ department: dept, days, managers });
  } catch (err) {
    console.error('[insights/paid-usage/department]', err.message);
    res.status(500).json({ error: 'department drill-down failed' });
  }
});

router.get('/paid-usage/manager', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  const days = [30, 60, 90].includes(parseInt(req.query.days, 10)) ? parseInt(req.query.days, 10) : 30;
  const mgrUpn = req.query.manager;
  if (!mgrUpn) return res.status(400).json({ error: 'manager query parameter is required' });
  const cutoff = new Date(Date.now() - days * 86400e3);
  try {
    const rows = await q(
      `SELECT a.upn, a.licenses, a.exchange_last, a.onedrive_last, a.sharepoint_last, a.teams_last,
              u.display_name
         FROM insight_user_activity a
         JOIN ${ENTRA1} u ON u.user_principal_name = a.upn
        WHERE u.account_enabled = 1 AND u.manager_upn = ?
          AND a.licenses IS NOT NULL AND a.licenses != ''
          AND (a.licenses LIKE '%E3%' OR a.licenses LIKE '%E5%' OR a.licenses LIKE '%COPILOT%' OR a.licenses LIKE '%POWER BI PRO%')`, [mgrUpn]);
    const employees = rows.map((r) => ({ ...r, status: classifyUser(r, cutoff) }));
    res.json({ manager: mgrUpn, days, employees });
  } catch (err) {
    console.error('[insights/paid-usage/manager]', err.message);
    res.status(500).json({ error: 'manager drill-down failed' });
  }
});

router.get('/paid-usage/employee', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  const upn = req.query.upn;
  if (!upn) return res.status(400).json({ error: 'upn query parameter is required' });
  try {
    const [activity] = await q(
      `SELECT a.*, u.display_name, u.department, u.manager_upn, m.display_name AS managerName
         FROM insight_user_activity a
         JOIN ${ENTRA1} u ON u.user_principal_name = a.upn
         LEFT JOIN ${ENTRA1} m ON m.user_principal_name = u.manager_upn
        WHERE a.upn = ?`, [upn]);
    if (!activity) return res.status(404).json({ error: 'no activity record found for this user' });
    const [mailbox] = await q(`SELECT * FROM sentinel_mailbox_usage WHERE upn = ?`, [upn]);
    const [sharepoint] = await q(`SELECT * FROM sentinel_sp_user_activity WHERE upn = ?`, [upn]);
    const [copilot] = await q(`SELECT * FROM copilot_app_usage WHERE email = ?`, [upn]);
    const now = Date.now();
    const daysSince = (d) => d ? Math.floor((now - new Date(d).getTime()) / 86400e3) : null;
    const periods = [30, 60, 90].map((days) => {
      const cutoff = new Date(now - days * 86400e3);
      return { period: days, status: classifyUser(activity, cutoff) };
    });
    res.json({
      identity: { upn, displayName: activity.display_name, department: activity.department,
                  managerUpn: activity.manager_upn, managerName: activity.managerName },
      licenses: (activity.licenses || '').split('+'),
      workloads: {
        exchange: { lastActive: activity.exchange_last, daysSince: daysSince(activity.exchange_last) },
        onedrive: { lastActive: activity.onedrive_last, daysSince: daysSince(activity.onedrive_last) },
        sharepoint: { lastActive: activity.sharepoint_last, daysSince: daysSince(activity.sharepoint_last) },
        teams: { lastActive: activity.teams_last, daysSince: daysSince(activity.teams_last) },
      },
      mailboxDetail: mailbox ? { itemCount: mailbox.item_count, storageBytes: mailbox.storage_used_b, lastActivity: mailbox.last_activity_date } : null,
      sharepointDetail: sharepoint ? { viewedEditedFiles: sharepoint.viewed_edited_files, sharedInternally: sharepoint.shared_internally, sharedExternally: sharepoint.shared_externally, lastActivity: sharepoint.last_activity_date } : null,
      copilotDetail: copilot ? { chatLastActive: copilot.chat_last_active, teamsLastActive: copilot.teams_last_active, wordLastActive: copilot.word_last_active } : null,
      periodComparison: periods,
      reportDate: activity.report_date,
    });
  } catch (err) {
    console.error('[insights/paid-usage/employee]', err.message);
    res.status(500).json({ error: 'employee detail query failed' });
  }
});


// ---------- Microsoft Renewal Planning (30/60/90) ----------
// Answers: "based on actual usage, how many paid seats should we renew?"
// Purchased/Assigned come from insight_sku (Graph-synced) -- the same source
// Licensing & Cost reads. insight_cost.qty (manually entered contract qty) is
// shown alongside and flagged when it differs; it is never silently swapped in.
// Per SKU and period: Needed = active + low + unknown;
// Recommended = ceil(Needed x (1 + RENEWAL_BUFFER)).
// "Unknown" (a license holder with no usage row) is counted as NEEDED -- a gap
// in the API is never treated as inactivity. Inactive users and disabled
// accounts are reduction candidates, not automatic removals. A SKU with no
// per-user usage source returns status 'insufficient' with the reason instead
// of a number. People are deduplicated through ENTRA1 (see above).
const RENEWAL_BUFFER = 0.05;      // policy assumption, disclosed in the UI
const RENEWAL_COPILOT_RATE = 30;  // confirmed billed rate; matches /licensing and AI Usage & Credits
const RENEWAL_METHODS = {
  SPE_E3: { license: 'MICROSOFT 365 E3', kind: 'workloads',
    definition: 'Active = used 3-4 of Exchange, Teams, SharePoint and OneDrive in the period; Low = 1-2; Inactive = none. Source: Microsoft 365 usage reports (last-activity date per workload). Business rule, not a Microsoft-defined metric.' },
  Microsoft_365_Copilot: { license: 'MICROSOFT 365 COPILOT', kind: 'copilot',
    definition: 'Active = any Copilot app activity in the period -- the same definition AI Usage & Credits uses. Microsoft reports no "low" tier for Copilot. Source: Copilot usage report.' },
  EXCHANGEENTERPRISE: { license: 'EXCHANGE ONLINE (PLAN 2)', kind: 'exchange',
    definition: 'Active = any Exchange activity in the period. Source: Microsoft 365 usage report (Exchange last-activity date).' },
};
const RENEWAL_NO_SOURCE = {
  POWER_BI_PRO: 'This platform collects no Power BI usage data (no Power BI activity table exists), so usage cannot be measured.',
};
const RENEWAL_CP_APPS = ['chat', 'teams', 'word', 'excel', 'powerpoint', 'outlook', 'onenote', 'loop'];
const RENEWAL_WORKLOADS = ['exchange_last', 'onedrive_last', 'sharepoint_last', 'teams_last'];

router.get('/renewal-planning', rbac.requirePage(PAGE_KEY, 'read'), async (req, res) => {
  try {
    const now = Date.now();
    const PERIODS = [30, 60, 90];
    const cutoffs = Object.fromEntries(PERIODS.map((d) => [d, new Date(now - d * 86400e3)]));
    const ymd = (d) => (d ? new Date(d).toISOString().slice(0, 10) : null);

    const skuRows = await q(
      `SELECT s.sku_part_number AS sku, s.consumed, s.enabled, c.qty AS contractQty, c.unit_monthly AS unitMonthly
         FROM insight_sku s
         JOIN insight_cost c ON c.sku_part_number = s.sku_part_number
        WHERE c.category = 'license' AND c.unit_monthly > 0 AND s.enabled > 0
        ORDER BY s.consumed DESC`);
    const users = await q(
      `SELECT a.upn, a.licenses, a.exchange_last, a.onedrive_last, a.sharepoint_last, a.teams_last, a.report_date,
              u.display_name, u.department, u.account_enabled, m.display_name AS managerName
         FROM insight_user_activity a
         LEFT JOIN ${ENTRA1} u ON u.user_principal_name = a.upn
         LEFT JOIN ${ENTRA1} m ON m.user_principal_name = u.manager_upn
        WHERE a.licenses IS NOT NULL AND a.licenses <> ''`);
    const cp = await q(
      `SELECT email, chat_last_active, teams_last_active, word_last_active, excel_last_active,
              powerpoint_last_active, outlook_last_active, onenote_last_active, loop_last_active, report_refresh_date
         FROM copilot_app_usage`);
    const cpByEmail = new Map(cp.map((r) => [String(r.email || '').toLowerCase(), r]));
    const latestOf = (row, cols) => {
      let m = null;
      for (const c of cols) { const v = row[c]; if (v && (!m || new Date(v) > m)) m = new Date(v); }
      return m;
    };
    const cpLatest = (u) => {
      const r = cpByEmail.get(String(u.upn || '').toLowerCase());
      return r ? latestOf(r, RENEWAL_CP_APPS.map((a) => a + '_last_active')) : undefined;
    };
    const classify = (kind, u, cutoff) => {
      if (Number(u.account_enabled) === 0) return 'disabled';
      if (kind === 'workloads') return classifyUser(u, cutoff);
      if (kind === 'exchange') return u.exchange_last && new Date(u.exchange_last) >= cutoff ? 'active' : 'inactive';
      if (kind === 'copilot') {
        const last = cpLatest(u);
        if (last === undefined) return 'unknown';           // no Copilot usage row -> unknown, not inactive
        return last && last >= cutoff ? 'active' : 'inactive';
      }
      return 'unknown';
    };
    const lastActivity = (kind, u) => {
      if (kind === 'copilot') return ymd(cpLatest(u) || null);
      if (kind === 'exchange') return ymd(u.exchange_last);
      return ymd(latestOf(u, RENEWAL_WORKLOADS));
    };
    const holdsLicense = (u, name) => String(u.licenses || '').toUpperCase().split('+').map((x) => x.trim()).includes(name);

    const out = [];
    for (const s of skuRows) {
      const isCopilot = /copilot/i.test(s.sku);
      const base = {
        sku: s.sku, name: friendly(s.sku), purchased: Number(s.enabled), assigned: Number(s.consumed),
        contractQty: s.contractQty != null ? Number(s.contractQty) : null,
        unitMonthly: isCopilot ? RENEWAL_COPILOT_RATE : Number(s.unitMonthly),
        unitSource: isCopilot ? 'confirmed billed rate ($30/seat)' : 'cost table (manually maintained)',
      };
      base.contractQtyDiffers = base.contractQty != null && base.contractQty !== base.purchased;
      const method = RENEWAL_METHODS[s.sku];
      if (!method) {
        out.push({ ...base, status: 'insufficient',
          reason: RENEWAL_NO_SOURCE[s.sku] || 'No per-user usage source is mapped for this subscription.' });
        continue;
      }
      const holders = users.filter((u) => holdsLicense(u, method.license));
      if (!holders.length) {
        out.push({ ...base, status: 'insufficient', method: method.definition,
          reason: `No license holders matched "${method.license}" in the usage report, so usage cannot be measured.` });
        continue;
      }
      const unmatched = Math.max(0, base.assigned - holders.length);
      const periods = {}, candidates = {}, byDept = {};
      for (const d of PERIODS) {
        const c = { active: 0, low: 0, inactive: 0, disabled: 0, unknown: unmatched, holders: holders.length, unmatched };
        const cand = [], dept = {};
        for (const u of holders) {
          const st = classify(method.kind, u, cutoffs[d]);
          c[st]++;
          const dk = u.department || 'No department on record';
          if (!dept[dk]) dept[dk] = { department: dk, holders: 0, needed: 0, reduce: 0 };
          dept[dk].holders++;
          if (st === 'inactive' || st === 'disabled') {
            dept[dk].reduce++;
            cand.push({ upn: u.upn, name: u.display_name || u.upn, department: dk,
              manager: u.managerName || 'No manager on record', status: st, lastActivity: lastActivity(method.kind, u) });
          } else dept[dk].needed++;
        }
        const needed = c.active + c.low + c.unknown;
        const recommended = Math.ceil(needed * (1 + RENEWAL_BUFFER));
        const change = recommended - base.purchased;
        periods[d] = { ...c, needed, recommended, change,
          monthlyImpact: +(change * base.unitMonthly).toFixed(2),
          annualImpact: +(change * base.unitMonthly * 12).toFixed(2),
          utilization: c.holders ? Math.round((c.active / c.holders) * 100) : 0 };
        candidates[d] = cand.sort((a, b) => String(a.lastActivity || '').localeCompare(String(b.lastActivity || '')));
        byDept[d] = Object.values(dept).sort((a, b) => b.reduce - a.reduce || b.holders - a.holders);
      }
      out.push({ ...base, status: 'ok', method: method.definition, periods, candidates, byDept });
    }

    const actDates = users.map((u) => u.report_date).filter(Boolean).map((d) => new Date(d).getTime());
    const cpDates = cp.map((r) => r.report_refresh_date).filter(Boolean).map((d) => new Date(d).getTime());
    res.json({
      generatedAt: new Date(now).toISOString(), bufferPct: RENEWAL_BUFFER * 100, defaultPeriod: 90,
      periods: Object.fromEntries(PERIODS.map((d) => [d, { start: ymd(cutoffs[d]), end: ymd(now) }])),
      freshness: {
        activityReportDate: actDates.length ? ymd(Math.max(...actDates)) : null,
        copilotReportDate: cpDates.length ? ymd(Math.max(...cpDates)) : null,
      },
      skus: out,
    });
  } catch (err) {
    console.error('[insights/renewal-planning]', err.message);
    res.status(500).json({ error: 'renewal planning query failed' });
  }
});

module.exports = router;
