#!/usr/bin/env node
/* claude-collector.js — pulls Claude Enterprise Analytics into corpit_hub.
 *
 * Design notes that are NOT obvious:
 *  - Money arrives as decimal STRINGS in CENTS ("1698.211075"). We hand those strings
 *    straight to MySQL DECIMAL(18,6). Never parseFloat them: at organisation scale a
 *    float silently loses cents, and the value is only divided by 100 for display.
 *  - Enterprise cost figures are revised for up to 30 days as late events land, so
 *    every run re-fetches a rolling window and UPSERTS. A day's row is provisional
 *    until it ages past the window. Never insert-once.
 *  - The org-wide rate limit is 60 requests/minute across ALL endpoints and keys,
 *    so every call is spaced by THROTTLE_MS.
 *  - /analytics/users is queried one day at a time. It accepts a date range, but the
 *    row carries no bucket date, so a range response cannot be attributed per-day
 *    without guessing. One call per day is unambiguous and still cheap.
 *  - /analytics/summaries returns rows under `summaries`, NOT `data`.
 *
 *  - Steps 6-8 (spend limits, increase requests, member roster) need read:spend_limits /
 *    read:members. A key without them answers 403 "Missing required scope"; that is
 *    recorded as status 'no-scope' (a state, not an error) and the page keeps its CSV
 *    fallback. Nothing else has to change when a key with the scopes is installed:
 *    ANTHROPIC_ADMIN_KEY if it is a separate key, or simply replace ANTHROPIC_ANALYTICS_KEY
 *    with a combined one (see /opt/itam-tools/set-claude-key.sh).
 *
 * Usage: sudo node claude-collector.js [--days N] [--end YYYY-MM-DD] [--dry]
 *          [--skip-activity] [--skip-admin] [--admin-only] [--fixture FILE]
 *        --fixture FILE feeds steps 6-8 from a JSON file (documented response shapes)
 *        instead of the API. REQUIRES --dry (refused otherwise): fixture rows never land.
 */
const https = require('https');
const fs = require('fs');
const mysql = require('/var/www/corpit-hub-api/node_modules/mysql2/promise');

const ENV_FILE = '/var/www/corpit-hub-api/.env';
const THROTTLE_MS = 1200;           // ~50 req/min, under the 60/min org cap
const DEFAULT_DAYS = 30;            // matches the revision window
const UA = 'NRPI-ITAM-Collector/1.0 (https://corpit.nrpi.local)';

const argv = process.argv.slice(2);
const DRY = argv.includes('--dry');
const SKIP_ACTIVITY = argv.includes('--skip-activity');   // backfill: activity costs 1 call/day
const SKIP_ADMIN  = argv.includes('--skip-admin');          // steps 6-8 (spend limits / requests / roster)
const ADMIN_ONLY  = argv.includes('--admin-only');          // run ONLY steps 6-8 (e.g. right after a new key lands)
const FIXTURE = (() => { const i = argv.indexOf('--fixture'); return i >= 0 && argv[i + 1] ? JSON.parse(fs.readFileSync(argv[i + 1], 'utf8')) : null; })();
const CL = require('../claude-limits');   // shared, pure: row parsing + freshness (tested by test-claude-limits.js)
// A fixture is for exercising the parse path only. Refuse to let it anywhere near the tables.
if (FIXTURE && !DRY) { console.error('FATAL: --fixture requires --dry (fixture rows must never reach the tables)'); process.exit(2); }
const DAYS = (() => { const i = argv.indexOf('--days'); return i >= 0 ? Math.max(1, Math.min(31, +argv[i + 1] || DEFAULT_DAYS)) : DEFAULT_DAYS; })();
// --end YYYY-MM-DD walks the window backwards for historical backfill (exclusive upper bound)
const END_ARG = (() => { const i = argv.indexOf('--end'); return i >= 0 && /^\d{4}-\d{2}-\d{2}$/.test(argv[i + 1] || '') ? argv[i + 1] : null; })();

function loadEnv(f) {
  const e = {};
  for (const l of fs.readFileSync(f, 'utf8').split(/\r?\n/)) {
    const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*)$/.exec(l);
    if (m) e[m[1]] = m[2].replace(/^["']|["']$/g, '').trim();
  }
  return e;
}
const env = loadEnv(ENV_FILE);
const KEY = env.ANTHROPIC_ANALYTICS_KEY;
if (!KEY) { console.error('FATAL: ANTHROPIC_ANALYTICS_KEY missing from ' + ENV_FILE); process.exit(2); }
// Admin-scoped endpoints: a separate key if one is set, else the analytics key (Enterprise
// keys can combine read:analytics + read:spend_limits + read:members on one key).
const ADMIN_KEY = env.ANTHROPIC_ADMIN_KEY || KEY;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let API_CALLS = 0;

function apiGet(path, key = KEY) {
  API_CALLS++;
  return new Promise((resolve, reject) => {
    const req = https.request(
      { host: 'api.anthropic.com', path, method: 'GET',
        headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01', 'user-agent': UA } },
      (res) => {
        let b = '';
        res.on('data', (c) => (b += c));
        res.on('end', () => {
          if (res.statusCode === 429) return reject(new Error('rate limited (429) — increase THROTTLE_MS'));
          if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode}: ${b.slice(0, 200)}`));
          try { resolve(JSON.parse(b)); } catch (e) { reject(new Error('bad JSON: ' + b.slice(0, 120))); }
        });
      });
    req.on('error', reject);
    req.setTimeout(60000, () => { req.destroy(); reject(new Error('timeout')); });
    req.end();
  });
}

/* ---- email aliasing (2026-09-21) --------------------------------------------------------
 * Anthropic reports a member's primary SMTP address (Entra `mail`, e.g. elan@), while every
 * directory join in the API keys on the Entra UPN (echambers@). Canonicalise at ingestion so
 * one person is one key everywhere: an address equal to an Entra account's mail is stored as
 * that account's UPN. The rule is read from entra_users on every run — nothing per person. */
let ALIAS = new Map();
async function loadAliases(db) {
  ALIAS = new Map();
  if (!db) return;
  const [rows] = await db.execute(
    `SELECT LOWER(mail) m, LOWER(user_principal_name) u FROM entra_users
      WHERE mail IS NOT NULL AND mail<>'' AND LOWER(mail)<>LOWER(user_principal_name)
      ORDER BY account_enabled DESC, last_synced_at DESC`);
  for (const r of rows) if (!ALIAS.has(r.m)) ALIAS.set(r.m, r.u);   // an enabled account wins a shared mail
  console.log(`[claude-collector] email aliases loaded: ${ALIAS.size}`);
}
const canon = (e) => { const x = String(e || '').trim().toLowerCase(); return x ? (ALIAS.get(x) || x) : null; };

const iso = (d) => d.toISOString().replace(/\.\d{3}Z$/, 'Z');
const ymd = (d) => d.toISOString().slice(0, 10);
const num = (v) => (v == null ? 0 : v);
/** keep money as an exact decimal string; '0' when absent */
const money = (v) => (v == null || v === '' ? '0' : String(v));

async function main() {
  const t0 = Date.now();
  const now = new Date();
  const end = END_ARG ? new Date(END_ARG + 'T00:00:00Z')
                      : new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1));
  const start = new Date(end.getTime() - DAYS * 864e5);
  const RANGE = `starting_at=${encodeURIComponent(iso(start))}&ending_at=${encodeURIComponent(iso(end))}`;

  console.log(`[claude-collector] window ${ymd(start)} .. ${ymd(new Date(end - 864e5))} (${DAYS}d)${DRY ? '  [DRY RUN]' : ''}`);

  const db = DRY ? null : await mysql.createConnection({
    host: env.DB_HOST, port: +(env.DB_PORT || 3306), user: env.DB_USER,
    password: env.DB_PASSWORD, database: env.DB_NAME,
  });
  await loadAliases(db);

  const logRun = async (endpoint, ws, we, calls, rows, status, error, ms, refreshed) => {
    if (DRY || !db) return;
    await db.execute(
      `INSERT INTO claude_sync_log (endpoint,window_start,window_end,api_calls,rows_upserted,status,error,duration_ms,data_refreshed_at)
       VALUES (?,?,?,?,?,?,?,?,?)`,
      [endpoint, ws, we, calls, rows, status, error ? String(error).slice(0, 2000) : null, ms,
       refreshed ? refreshed.replace('T', ' ').replace('Z', '') : null]);
  };

  /** A 403 naming a missing scope is a STATE of the key, not a failure of the run. It is
   *  logged as 'no-scope' at most once per 6h per endpoint so the log does not fill up
   *  with the same fact every hour, while /health can still say "checked at HH:MM". */
  const isNoScope = (e) => /HTTP 40[13]/.test(e.message) && (/scope/i.test(e.message) || /permission_error/.test(e.message));
  async function logNoScope(name, msg, ms) {
    if (DRY || !db) return;
    try {
      const [r] = await db.execute(
        `SELECT ran_at FROM claude_sync_log WHERE endpoint=? AND status='no-scope' ORDER BY id DESC LIMIT 1`, [name]);
      if (r.length && (Date.now() - CL.parseTs(r[0].ran_at)) < 6 * 3600e3) return;
      await logRun(name, null, null, 1, 0, 'no-scope', msg, ms, null);
    } catch (e) {
      // e.g. the status ENUM not yet widened (ER 1265). A log write must never abort the run;
      // keep the state visible as an error row instead.
      console.error(`  ${name.padEnd(22)} (could not write no-scope row: ${String(e.message).slice(0, 80)})`);
      try { await logRun(name, null, null, 1, 0, 'error', 'no-scope: ' + msg, ms, null); }
      catch (e2) { console.error('  (log write failed again: ' + String(e2.message).slice(0, 80) + ')'); }
    }
  }

  /** run one collector step with its own timing, error isolation and log row */
  async function step(name, fn) {
    const s = Date.now(); const before = API_CALLS;
    try {
      const { rows, refreshed } = await fn();
      const ms = Date.now() - s;
      console.log(`  ${name.padEnd(22)} OK    ${String(rows).padStart(5)} rows  ${API_CALLS - before} call(s)  ${ms}ms`);
      await logRun(name, ymd(start), ymd(new Date(end - 864e5)), API_CALLS - before, rows, 'ok', null, ms, refreshed);
      return rows;
    } catch (e) {
      const ms = Date.now() - s;
      if (isNoScope(e)) {
        console.log(`  ${name.padEnd(22)} NO-SCOPE (key lacks the scope; CSV fallback stays)  ${e.message.slice(0, 90)}`);
        await logNoScope(name, e.message, ms);
        return 0;
      }
      console.error(`  ${name.padEnd(22)} ERROR ${e.message}`);
      try { await logRun(name, ymd(start), ymd(new Date(end - 864e5)), API_CALLS - before, 0, 'error', e.message, ms, null); }
      catch (e2) { console.error('  (log write failed: ' + String(e2.message).slice(0, 80) + ')'); }
      return 0;
    }
  }

  if (ADMIN_ONLY) console.log('  steps 1-5              SKIPPED (--admin-only)');
  // ---- 1. org cost by day x product x model -------------------------------
  if (!ADMIN_ONLY) await step('cost_daily', async () => {
    let page = null, rows = 0, refreshed = null, guard = 0;
    do {
      const j = await apiGet(`/v1/organizations/analytics/cost_report?${RANGE}&bucket_width=1d`
        + `&group_by[]=product&group_by[]=model&limit=31` + (page ? `&page=${encodeURIComponent(page)}` : ''));
      refreshed = j.data_refreshed_at || refreshed;
      for (const b of j.data || []) {
        const day = b.starting_at.slice(0, 10);
        for (const x of b.results || []) {
          if (!DRY) await db.execute(
            `INSERT INTO claude_cost_daily (day,product,model,amount_cents,list_amount_cents,requests)
             VALUES (?,?,?,?,?,?)
             ON DUPLICATE KEY UPDATE amount_cents=VALUES(amount_cents),
               list_amount_cents=VALUES(list_amount_cents), requests=VALUES(requests)`,
            [day, x.product || '', x.model || '', money(x.amount), money(x.list_amount), num(x.requests)]);
          rows++;
        }
      }
      page = j.has_more ? j.next_page : null;
      if (page) await sleep(THROTTLE_MS);
    } while (page && ++guard < 20);
    return { rows, refreshed };
  });
  await sleep(THROTTLE_MS);

  // ---- 2. token usage by day x model --------------------------------------
  if (!ADMIN_ONLY) await step('usage_daily', async () => {
    let page = null, rows = 0, refreshed = null, guard = 0;
    do {
      const j = await apiGet(`/v1/organizations/analytics/usage_report?${RANGE}&bucket_width=1d`
        + `&group_by[]=model&limit=31` + (page ? `&page=${encodeURIComponent(page)}` : ''));
      refreshed = j.data_refreshed_at || refreshed;
      for (const b of j.data || []) {
        const day = b.starting_at.slice(0, 10);
        for (const x of b.results || []) {
          const cc = x.cache_creation || {};
          if (!DRY) await db.execute(
            `INSERT INTO claude_usage_daily (day,model,uncached_input,cache_read,cache_creation_5m,
               cache_creation_1h,output_tokens,web_search_requests,requests)
             VALUES (?,?,?,?,?,?,?,?,?)
             ON DUPLICATE KEY UPDATE uncached_input=VALUES(uncached_input), cache_read=VALUES(cache_read),
               cache_creation_5m=VALUES(cache_creation_5m), cache_creation_1h=VALUES(cache_creation_1h),
               output_tokens=VALUES(output_tokens), web_search_requests=VALUES(web_search_requests),
               requests=VALUES(requests)`,
            [day, x.model || '', num(x.uncached_input_tokens), num(x.cache_read_input_tokens),
             num(cc.ephemeral_5m_input_tokens), num(cc.ephemeral_1h_input_tokens),
             num(x.output_tokens), num((x.server_tool_use || {}).web_search_requests), num(x.requests)]);
          rows++;
        }
      }
      page = j.has_more ? j.next_page : null;
      if (page) await sleep(THROTTLE_MS);
    } while (page && ++guard < 20);
    return { rows, refreshed };
  });
  await sleep(THROTTLE_MS);

  // ---- 2b. token usage by day x product -----------------------------------
  // Same endpoint as step 2, grouped by product instead of model. It lands in its own
  // table so claude_usage_daily's (day,model) primary key and every query over it are
  // untouched; the two tables are independent slices of the same totals.
  if (!ADMIN_ONLY) await step('usage_product_daily', async () => {
    let page = null, rows = 0, refreshed = null, guard = 0;
    do {
      const j = await apiGet(`/v1/organizations/analytics/usage_report?${RANGE}&bucket_width=1d`
        + `&group_by[]=product&limit=31` + (page ? `&page=${encodeURIComponent(page)}` : ''));
      refreshed = j.data_refreshed_at || refreshed;
      for (const b of j.data || []) {
        const day = b.starting_at.slice(0, 10);
        for (const x of b.results || []) {
          const cc = x.cache_creation || {};
          if (!DRY) await db.execute(
            `INSERT INTO claude_usage_product_daily (day,product,uncached_input,cache_read,
               cache_creation_5m,cache_creation_1h,output_tokens,web_search_requests,requests)
             VALUES (?,?,?,?,?,?,?,?,?)
             ON DUPLICATE KEY UPDATE uncached_input=VALUES(uncached_input), cache_read=VALUES(cache_read),
               cache_creation_5m=VALUES(cache_creation_5m), cache_creation_1h=VALUES(cache_creation_1h),
               output_tokens=VALUES(output_tokens), web_search_requests=VALUES(web_search_requests),
               requests=VALUES(requests)`,
            [day, x.product || '', num(x.uncached_input_tokens), num(x.cache_read_input_tokens),
             num(cc.ephemeral_5m_input_tokens), num(cc.ephemeral_1h_input_tokens),
             num(x.output_tokens), num((x.server_tool_use || {}).web_search_requests), num(x.requests)]);
          rows++;
        }
      }
      page = j.has_more ? j.next_page : null;
      if (page) await sleep(THROTTLE_MS);
    } while (page && ++guard < 20);
    return { rows, refreshed };
  });
  await sleep(THROTTLE_MS);

  // ---- 2c. per-user tokens by day -----------------------------------------
  // user_usage_report is shaped like user_cost_report (flat `data`, actor per row),
  // NOT like usage_report (day buckets with `results`). No group_by: one row per member
  // per day keeps the table small and the join to spend one-to-one.
  // total_tokens comes from the API; stored as given rather than re-derived, because the
  // API's definition of the total is the billable one.
  if (!ADMIN_ONLY) await step('user_usage_daily', async () => {
    let page = null, rows = 0, refreshed = null, guard = 0;
    do {
      const j = await apiGet(`/v1/organizations/analytics/user_usage_report?${RANGE}&bucket_width=1d`
        + `&limit=1000` + (page ? `&page=${encodeURIComponent(page)}` : ''));
      refreshed = j.data_refreshed_at || refreshed;
      for (const x of j.data || []) {
        const a = x.actor || {};
        if (!a.user_id || !x.starting_at) continue;   // playground/API rows carry no user
        const cc = x.cache_creation || {};
        if (!DRY) await db.execute(
          `INSERT INTO claude_user_usage_daily (day,user_id,email,display_name,uncached_input,cache_read,
             cache_creation_5m,cache_creation_1h,output_tokens,total_tokens,web_search_requests,requests,deleted)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON DUPLICATE KEY UPDATE email=VALUES(email), display_name=VALUES(display_name),
             uncached_input=VALUES(uncached_input), cache_read=VALUES(cache_read),
             cache_creation_5m=VALUES(cache_creation_5m), cache_creation_1h=VALUES(cache_creation_1h),
             output_tokens=VALUES(output_tokens), total_tokens=VALUES(total_tokens),
             web_search_requests=VALUES(web_search_requests), requests=VALUES(requests), deleted=VALUES(deleted)`,
          [x.starting_at.slice(0, 10), a.user_id, canon(a.email), a.name || null,
           num(x.uncached_input_tokens), num(x.cache_read_input_tokens),
           num(cc.ephemeral_5m_input_tokens), num(cc.ephemeral_1h_input_tokens),
           num(x.output_tokens), num(x.total_tokens),
           num((x.server_tool_use || {}).web_search_requests), num(x.requests), a.deleted ? 1 : 0]);
        rows++;
      }
      page = j.has_more ? j.next_page : null;
      if (page) await sleep(THROTTLE_MS);
    } while (page && ++guard < 40);
    return { rows, refreshed };
  });
  await sleep(THROTTLE_MS);

  // ---- 3. per-user cost by day x product ----------------------------------
  if (!ADMIN_ONLY) await step('user_cost_daily', async () => {
    let page = null, rows = 0, refreshed = null, guard = 0;
    do {
      const j = await apiGet(`/v1/organizations/analytics/user_cost_report?${RANGE}&bucket_width=1d`
        + `&group_by[]=product&limit=1000` + (page ? `&page=${encodeURIComponent(page)}` : ''));
      refreshed = j.data_refreshed_at || refreshed;
      for (const x of j.data || []) {
        const a = x.actor || {};
        if (!a.user_id || !x.starting_at) continue;   // playground/API rows carry no user
        if (!DRY) await db.execute(
          `INSERT INTO claude_user_cost_daily (day,user_id,product,email,display_name,amount_cents,requests,deleted)
           VALUES (?,?,?,?,?,?,?,?)
           ON DUPLICATE KEY UPDATE email=VALUES(email), display_name=VALUES(display_name),
             amount_cents=VALUES(amount_cents), requests=VALUES(requests), deleted=VALUES(deleted)`,
          [x.starting_at.slice(0, 10), a.user_id, x.product || '',
           canon(a.email), a.name || null,
           money(x.amount), num(x.requests), a.deleted ? 1 : 0]);
        rows++;
      }
      page = j.has_more ? j.next_page : null;
      if (page) await sleep(THROTTLE_MS);
    } while (page && ++guard < 40);
    return { rows, refreshed };
  });
  await sleep(THROTTLE_MS);

  // ---- 3b. per-user cost AND usage by day x product x model ---------------
  // The org-wide tables carry model; the per-user ones did not, so "which model is
  // this person on" was unanswerable. Both user reports accept group_by[]=model, so
  // one table keyed (day,user,product,model) holds cost from one report and tokens
  // from the other. ~40 rows a day org-wide, so the extra two calls are cheap.
  if (!ADMIN_ONLY) await step('user_model_daily', async () => {
    let rows = 0, refreshed = null;

    let page = null, guard = 0;
    do {
      const j = await apiGet(`/v1/organizations/analytics/user_cost_report?${RANGE}&bucket_width=1d`
        + `&group_by[]=product&group_by[]=model&limit=1000` + (page ? `&page=${encodeURIComponent(page)}` : ''));
      refreshed = j.data_refreshed_at || refreshed;
      for (const x of j.data || []) {
        const a = x.actor || {};
        if (!a.user_id || !x.starting_at || !x.model) continue;   // playground/API rows carry no user
        if (!DRY) await db.execute(
          `INSERT INTO claude_user_model_daily (day,user_id,product,model,email,display_name,
             amount_cents,list_amount_cents,requests,deleted)
           VALUES (?,?,?,?,?,?,?,?,?,?)
           ON DUPLICATE KEY UPDATE email=VALUES(email), display_name=VALUES(display_name),
             amount_cents=VALUES(amount_cents), list_amount_cents=VALUES(list_amount_cents),
             requests=VALUES(requests), deleted=VALUES(deleted)`,
          [x.starting_at.slice(0, 10), a.user_id, x.product || '', x.model,
           canon(a.email), a.name || null,
           money(x.amount), money(x.list_amount), num(x.requests), a.deleted ? 1 : 0]);
        rows++;
      }
      page = j.has_more ? j.next_page : null;
      if (page) await sleep(THROTTLE_MS);
    } while (page && ++guard < 40);

    await sleep(THROTTLE_MS);

    // Second report, same key. Token columns only -- a row present here but not in the
    // cost report still deserves to exist, so this is an INSERT too, not an UPDATE.
    page = null; guard = 0;
    do {
      const j = await apiGet(`/v1/organizations/analytics/user_usage_report?${RANGE}&bucket_width=1d`
        + `&group_by[]=product&group_by[]=model&limit=1000` + (page ? `&page=${encodeURIComponent(page)}` : ''));
      refreshed = j.data_refreshed_at || refreshed;
      for (const x of j.data || []) {
        const a = x.actor || {};
        if (!a.user_id || !x.starting_at || !x.model) continue;
        const cc = x.cache_creation || {};
        if (!DRY) await db.execute(
          `INSERT INTO claude_user_model_daily (day,user_id,product,model,email,display_name,
             uncached_input,cache_read,cache_creation_5m,cache_creation_1h,output_tokens,total_tokens,
             web_search_requests,deleted)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON DUPLICATE KEY UPDATE email=VALUES(email), display_name=VALUES(display_name),
             uncached_input=VALUES(uncached_input), cache_read=VALUES(cache_read),
             cache_creation_5m=VALUES(cache_creation_5m), cache_creation_1h=VALUES(cache_creation_1h),
             output_tokens=VALUES(output_tokens), total_tokens=VALUES(total_tokens),
             web_search_requests=VALUES(web_search_requests), deleted=VALUES(deleted)`,
          [x.starting_at.slice(0, 10), a.user_id, x.product || '', x.model,
           canon(a.email), a.name || null,
           num(x.uncached_input_tokens), num(x.cache_read_input_tokens),
           num(cc.ephemeral_5m_input_tokens), num(cc.ephemeral_1h_input_tokens),
           num(x.output_tokens), num(x.total_tokens),
           num((x.server_tool_use || {}).web_search_requests), a.deleted ? 1 : 0]);
        rows++;
      }
      page = j.has_more ? j.next_page : null;
      if (page) await sleep(THROTTLE_MS);
    } while (page && ++guard < 40);

    return { rows, refreshed };
  });
  await sleep(THROTTLE_MS);

  // ---- 4. org engagement summaries (one call, range) -----------------------
  if (!ADMIN_ONLY) await step('summary_daily', async () => {
    const j = await apiGet(`/v1/organizations/analytics/summaries`
      + `?starting_date=${ymd(start)}&ending_date=${ymd(new Date(end - 864e5))}`);
    let rows = 0;
    for (const s of j.summaries || []) {          // NB: `summaries`, not `data`
      if (!DRY) await db.execute(
        `INSERT INTO claude_summary_daily (day,dau,wau,mau,chat_dau,chat_wau,chat_mau,cc_dau,cc_wau,cc_mau,
           cowork_dau,cowork_wau,cowork_mau,design_mau,office_mau,assigned_seats,pending_invites,
           daily_adoption_rate,weekly_adoption_rate,monthly_adoption_rate)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
         ON DUPLICATE KEY UPDATE dau=VALUES(dau),wau=VALUES(wau),mau=VALUES(mau),
           chat_dau=VALUES(chat_dau),chat_wau=VALUES(chat_wau),chat_mau=VALUES(chat_mau),
           cc_dau=VALUES(cc_dau),cc_wau=VALUES(cc_wau),cc_mau=VALUES(cc_mau),
           cowork_dau=VALUES(cowork_dau),cowork_wau=VALUES(cowork_wau),cowork_mau=VALUES(cowork_mau),
           design_mau=VALUES(design_mau),office_mau=VALUES(office_mau),
           assigned_seats=VALUES(assigned_seats),pending_invites=VALUES(pending_invites),
           daily_adoption_rate=VALUES(daily_adoption_rate),weekly_adoption_rate=VALUES(weekly_adoption_rate),
           monthly_adoption_rate=VALUES(monthly_adoption_rate)`,
        [s.starting_at.slice(0, 10), num(s.daily_active_user_count), num(s.weekly_active_user_count), num(s.monthly_active_user_count),
         num(s.chat_daily_active_user_count), num(s.chat_weekly_active_user_count), num(s.chat_monthly_active_user_count),
         num(s.claude_code_daily_active_user_count), num(s.claude_code_weekly_active_user_count), num(s.claude_code_monthly_active_user_count),
         num(s.cowork_daily_active_user_count), num(s.cowork_weekly_active_user_count), num(s.cowork_monthly_active_user_count),
         num(s.claude_design_monthly_active_user_count), num(s.office_agent_monthly_active_user_count),
         num(s.assigned_seat_count), num(s.pending_invite_count),
         s.daily_adoption_rate ?? null, s.weekly_adoption_rate ?? null, s.monthly_adoption_rate ?? null]);
      rows++;
    }
    return { rows, refreshed: null };
  });
  await sleep(THROTTLE_MS);

  // ---- 5. per-user activity, one day per call ------------------------------
  if (ADMIN_ONLY) { /* skipped above */ }
  else if (SKIP_ACTIVITY) console.log('  user_activity_daily    SKIPPED (--skip-activity)');
  else await step('user_activity_daily', async () => {
    let rows = 0;
    for (let i = 0; i < DAYS; i++) {
      const d = ymd(new Date(start.getTime() + i * 864e5));
      let page = null, guard = 0;
      do {
        let j;
        try {
          j = await apiGet(`/v1/organizations/analytics/users?date=${d}&limit=1000`
            + (page ? `&page=${encodeURIComponent(page)}` : ''));
        } catch (e) {
          // a date newer than the pipeline's latest available day returns 400; that is
          // expected at the leading edge, not a failure of the run
          if (/HTTP 400/.test(e.message)) { break; }
          throw e;
        }
        for (const u of j.data || []) {
          const usr = u.user || {}, ch = u.chat_metrics || {}, cc = u.claude_code_metrics || {},
                core = cc.core_metrics || {}, loc = core.lines_of_code || {}, ta = cc.tool_actions || {},
                cw = u.cowork_metrics || {}, om = u.office_metrics || {}, dm = u.design_metrics || {},
                sm = u.science_metrics || {};
          const acc = ['edit_tool','multi_edit_tool','write_tool','notebook_edit_tool']
            .reduce((s, k) => s + num((ta[k] || {}).accepted_count), 0);
          const rej = ['edit_tool','multi_edit_tool','write_tool','notebook_edit_tool']
            .reduce((s, k) => s + num((ta[k] || {}).rejected_count), 0);
          const officeSessions = ['excel','powerpoint','word','outlook']
            .reduce((s, k) => s + num((om[k] || {}).distinct_session_count), 0);
          if (!usr.id) continue;
          if (!DRY) await db.execute(
            `INSERT INTO claude_user_activity_daily (day,user_id,email,chat_conversations,chat_messages,
               chat_projects_used,chat_projects_created,chat_artifacts,chat_skills_used,cc_sessions,cc_commits,cc_prs,
               cc_loc_added,cc_loc_removed,cc_edits_accepted,cc_edits_rejected,cowork_sessions,
               cowork_actions,cowork_file_edits,cowork_messages,office_sessions,design_sessions,
               science_sessions,web_search_count,last_activity_date)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
             ON DUPLICATE KEY UPDATE email=VALUES(email),chat_conversations=VALUES(chat_conversations),
               chat_messages=VALUES(chat_messages),chat_projects_used=VALUES(chat_projects_used),
               chat_projects_created=VALUES(chat_projects_created),
               chat_artifacts=VALUES(chat_artifacts),chat_skills_used=VALUES(chat_skills_used),
               cc_sessions=VALUES(cc_sessions),cc_commits=VALUES(cc_commits),cc_prs=VALUES(cc_prs),
               cc_loc_added=VALUES(cc_loc_added),cc_loc_removed=VALUES(cc_loc_removed),
               cc_edits_accepted=VALUES(cc_edits_accepted),cc_edits_rejected=VALUES(cc_edits_rejected),
               cowork_sessions=VALUES(cowork_sessions),cowork_actions=VALUES(cowork_actions),
               cowork_file_edits=VALUES(cowork_file_edits),cowork_messages=VALUES(cowork_messages),
               office_sessions=VALUES(office_sessions),design_sessions=VALUES(design_sessions),
               science_sessions=VALUES(science_sessions),web_search_count=VALUES(web_search_count),
               last_activity_date=VALUES(last_activity_date)`,
            [d, usr.id, canon(usr.email_address),
             num(ch.distinct_conversation_count), num(ch.message_count), num(ch.distinct_projects_used_count),
             num(ch.distinct_projects_created_count),
             num(ch.distinct_artifacts_created_count), num(ch.distinct_skills_used_count),
             num(core.distinct_session_count), num(core.commit_count), num(core.pull_request_count),
             num(loc.added_count), num(loc.removed_count), acc, rej,
             num(cw.distinct_session_count), num(cw.action_count), num(cw.file_edit_count), num(cw.message_count),
             officeSessions, num(dm.distinct_session_count), num(sm.distinct_session_count),
             num(u.web_search_count), u.last_activity_date || null]);
          rows++;
        }
        page = j.has_more ? j.next_page : null;
        if (page) await sleep(THROTTLE_MS);
      } while (page && ++guard < 10);
      await sleep(THROTTLE_MS);
    }
    return { rows, refreshed: null };
  });

  // ---- 6-8. admin-scoped: spend limits, increase requests, member roster -------
  // Dark until the key carries read:spend_limits / read:members (403 -> 'no-scope').
  if (SKIP_ADMIN) console.log('  admin steps 6-8        SKIPPED (--skip-admin)');
  else {
    const fetchedAt = new Date().toISOString().slice(0, 19).replace('T', ' ');   // UTC, MySQL DATETIME
    const today = ymd(new Date());
    // --fixture: documented response shapes instead of the API (single page each)
    const adminGet = async (path, fixtureKey) => {
      if (FIXTURE) { if (!FIXTURE[fixtureKey]) throw new Error('fixture has no ' + fixtureKey); return FIXTURE[fixtureKey]; }
      return apiGet(path, ADMIN_KEY);
    };
    if (FIXTURE) console.log('  (steps 6-8 reading ' + Object.keys(FIXTURE).filter((k) => k[0] !== '_').join(', ') + ' from --fixture)');

    // ---- 6. effective spend limit per member (all periods; page reads monthly) -----
    await step('spend_limits', async () => {
      let page = null, rows = 0, guard = 0; const parsed = [];
      do {
        const j = await adminGet(`/v1/organizations/spend_limits/effective?limit=1000`
          + (page ? `&page=${encodeURIComponent(page)}` : ''), 'spend_limits');
        for (const x of j.data || []) { const r = CL.parseEffectiveRow(x, fetchedAt); if (r.user_id) parsed.push(r); }
        page = j.next_page || null;
        if (page) await sleep(THROTTLE_MS);
      } while (page && ++guard < 20);
      if (page) throw new Error('spend_limits: pagination guard hit, table left untouched');
      for (const r of parsed) {
        if (DRY) { if (rows < 5) console.log('    would upsert', JSON.stringify(r)); rows++; continue; }
        await db.execute(
          `INSERT INTO claude_spend_limit (user_id,period,email,display_name,deleted,amount_cents,currency,
             source_type,source_ref,spend_limit_id,ptd_spend_cents,fetched_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
           ON DUPLICATE KEY UPDATE email=VALUES(email), display_name=VALUES(display_name), deleted=VALUES(deleted),
             amount_cents=VALUES(amount_cents), currency=VALUES(currency), source_type=VALUES(source_type),
             source_ref=VALUES(source_ref), spend_limit_id=VALUES(spend_limit_id),
             ptd_spend_cents=VALUES(ptd_spend_cents), fetched_at=VALUES(fetched_at)`,
          [r.user_id, r.period, canon(r.email), r.display_name, r.deleted, r.amount_cents, r.currency,
           r.source_type, r.source_ref, r.spend_limit_id, r.ptd_spend_cents, r.fetched_at]);
        await db.execute(
          `INSERT INTO claude_spend_limit_daily (day,user_id,period,email,amount_cents,source_type,ptd_spend_cents)
           VALUES (?,?,?,?,?,?,?)
           ON DUPLICATE KEY UPDATE email=VALUES(email), amount_cents=VALUES(amount_cents),
             source_type=VALUES(source_type), ptd_spend_cents=VALUES(ptd_spend_cents)`,
          [today, r.user_id, r.period, canon(r.email), r.amount_cents, r.source_type, r.ptd_spend_cents]);
        rows++;
      }
      // a complete pull is the whole current state: drop members no longer returned
      if (!DRY && parsed.length) await db.execute(`DELETE FROM claude_spend_limit WHERE fetched_at < ?`, [fetchedAt]);
      return { rows, refreshed: null };
    });
    await sleep(THROTTLE_MS);

    // ---- 7. spend-limit increase requests (all statuses; history kept) --------------
    await step('limit_requests', async () => {
      let page = null, rows = 0, guard = 0;
      do {
        const j = await adminGet(`/v1/organizations/spend_limit_increase_requests?limit=1000`
          + (page ? `&page=${encodeURIComponent(page)}` : ''), 'limit_requests');
        for (const x of j.data || []) {
          const r = CL.parseRequestRow(x, fetchedAt);
          if (!r.id) continue;
          if (DRY) { if (rows < 5) console.log('    would upsert', JSON.stringify(r)); rows++; continue; }
          await db.execute(
            `INSERT INTO claude_limit_request (id,user_id,email,display_name,status,period,created_at,resolved_at,
               resolved_by,current_limit_cents,current_source_type,ptd_spend_cents,fetched_at)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
             ON DUPLICATE KEY UPDATE user_id=VALUES(user_id), email=VALUES(email), display_name=VALUES(display_name),
               status=VALUES(status), period=VALUES(period), created_at=VALUES(created_at), resolved_at=VALUES(resolved_at),
               resolved_by=VALUES(resolved_by), current_limit_cents=VALUES(current_limit_cents),
               current_source_type=VALUES(current_source_type), ptd_spend_cents=VALUES(ptd_spend_cents),
               fetched_at=VALUES(fetched_at)`,
            [r.id, r.user_id, canon(r.email), r.display_name, r.status, r.period, r.created_at, r.resolved_at,
             r.resolved_by, r.current_limit_cents, r.current_source_type, r.ptd_spend_cents, r.fetched_at]);
          rows++;
        }
        page = j.next_page || null;
        if (page) await sleep(THROTTLE_MS);
      } while (page && ++guard < 20);
      if (page) throw new Error('limit_requests: pagination guard hit, table left untouched');
      // The API drops requests whose requester has left the org, so a local 'pending' row not
      // seen in a complete pull is a ghost. Mark it withdrawn — reversible, because a request
      // that reappears is upserted straight back to 'pending'.
      if (!DRY) await db.execute(
        `UPDATE claude_limit_request SET status='withdrawn', resolved_at=COALESCE(resolved_at, ?)
          WHERE status='pending' AND fetched_at < ?`, [fetchedAt, fetchedAt]);
      return { rows, refreshed: null };
    });
    await sleep(THROTTLE_MS);

    // ---- 8. provisioned roster (ID-based pagination: has_more + last_id) ----------
    await step('members', async () => {
      let after = null, rows = 0, guard = 0; const parsed = [];
      do {
        const j = await adminGet(`/v1/organizations/users?limit=1000`
          + (after ? `&after_id=${encodeURIComponent(after)}` : ''), 'members');
        for (const u of j.data || []) { const r = CL.parseMemberRow(u, fetchedAt); if (r.user_id) parsed.push(r); }
        after = j.has_more ? j.last_id : null;
        if (after) await sleep(THROTTLE_MS);
      } while (after && ++guard < 20);
      if (after) throw new Error('members: pagination guard hit, table left untouched');
      for (const r of parsed) {
        if (DRY) { if (rows < 5) console.log('    would upsert', JSON.stringify(r)); rows++; continue; }
        await db.execute(
          `INSERT INTO claude_member (user_id,email,display_name,role,added_at,fetched_at) VALUES (?,?,?,?,?,?)
           ON DUPLICATE KEY UPDATE email=VALUES(email), display_name=VALUES(display_name), role=VALUES(role),
             added_at=VALUES(added_at), fetched_at=VALUES(fetched_at)`,
          [r.user_id, canon(r.email), r.display_name, r.role, r.added_at, r.fetched_at]);
        rows++;
      }
      if (!DRY && parsed.length) await db.execute(`DELETE FROM claude_member WHERE fetched_at < ?`, [fetchedAt]);
      return { rows, refreshed: null };
    });
  }

  if (db) await db.end();
  console.log(`[claude-collector] done in ${((Date.now() - t0) / 1000).toFixed(1)}s, ${API_CALLS} API call(s)`);
}

main().catch((e) => { console.error('[claude-collector] FATAL', e); process.exit(1); });
