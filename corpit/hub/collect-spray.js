// collect-spray.js
// Detects password spray across Entra, Okta, and AD by grouping authentication
// failures by source IP within a sliding window. A source IP is flagged when it
// fails against >= min-users distinct accounts with <= max-per-user attempts
// per account (the spray profile). Upserts sdops_spray.
//
// Dual-window: a "fast" pass runs every invocation (SPRAY_WINDOW_MIN, default
// 60m) and a "slow" pass runs on the first cron hit of each hour
// (SPRAY_SLOW_WINDOW_MIN, default 1440m = 24h) to catch low-and-slow sprays
// that pace under the fast thresholds. Rows are tagged via window_kind.
// Force the slow pass on a manual run with SPRAY_SLOW_FORCE=1.
//
// Manual run: cd /var/www/corpit-hub-api && env $(cat .env | grep -v '^#' | grep -v '^$' | xargs) node collect-spray.js
//
// Reuses the token/pool patterns from collect-lockouts.js.
const mysql = require('mysql2/promise');
const { execFile } = require('child_process');
let sourceErrors = 0;   // a source that threw is a failed pass, not an empty one
const path = require('path');

const WINDOW_MIN    = parseInt(process.env.SPRAY_WINDOW_MIN    || '60', 10);
const MIN_USERS     = parseInt(process.env.SPRAY_MIN_USERS     || '8',  10);
const MAX_PER_USER  = parseInt(process.env.SPRAY_MAX_PER_USER  || '5',  10);
const WINDOW_MS     = WINDOW_MIN * 60 * 1000;

const SLOW_WINDOW_MIN   = parseInt(process.env.SPRAY_SLOW_WINDOW_MIN   || '1440', 10);
const SLOW_MIN_USERS    = parseInt(process.env.SPRAY_SLOW_MIN_USERS    || '8',    10);
const SLOW_MAX_PER_USER = parseInt(process.env.SPRAY_SLOW_MAX_PER_USER || '5',    10);
const SLOW_WINDOW_MS    = SLOW_WINDOW_MIN * 60 * 1000;

async function getPool() {
  return mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '3306', 10),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 5,
  });
}

async function getAllowlist(pool) {
  try {
    const [rows] = await pool.query('SELECT ip FROM sdops_spray_allowlist');
    return new Set(rows.map((r) => String(r.ip).trim()));
  } catch (e) {
    console.error('[spray] allowlist load failed:', e.message);
    return new Set();
  }
}

async function getGraphToken() {
  const res = await fetch(
    `https://login.microsoftonline.com/${process.env.ENTRA_TENANT_ID}/oauth2/v2.0/token`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.ENTRA_CLIENT_ID,
        client_secret: process.env.ENTRA_CLIENT_SECRET,
        scope: 'https://graph.microsoft.com/.default',
        grant_type: 'client_credentials',
      }),
    }
  );
  const data = await res.json();
  if (!data.access_token) throw new Error('Token failure: ' + JSON.stringify(data));
  return data.access_token;
}

// ── Entra: sign-in failures, errorCode 50126 (invalid username or password) ──
async function fetchEntra(sinceIso) {
  const token = await getGraphToken();
  const filter = encodeURIComponent(
    `status/errorCode eq 50126 and createdDateTime ge ${sinceIso}`
  );
  let url = `https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=${filter}&$top=1000`;
  const events = [];
  let pages = 0;
  while (url && pages < 20) {
    const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    if (!res.ok) throw new Error(`Graph ${res.status}: ${await res.text()}`);
    const data = await res.json();
    for (const s of data.value || []) {
      if (!s.ipAddress) continue;
      events.push({
        user: (s.userPrincipalName || '').toLowerCase(),
        ip: s.ipAddress,
        time: s.createdDateTime,
        country: s.location?.countryOrRegion || null,
        city: s.location?.city || null,
      });
    }
    url = data['@odata.nextLink'] || null;
    pages++;
  }
  return events;
}

// ── Okta: user.session.start failures tenant-wide ──
async function fetchOkta(sinceIso) {
  if (!process.env.OKTA_BASE_URL || !process.env.OKTA_API_TOKEN) return [];
  const base = process.env.OKTA_BASE_URL.replace(/\/$/, '');
  const filter = encodeURIComponent('eventType eq "user.session.start" and outcome.result eq "FAILURE"');
  let url = `${base}/api/v1/logs?since=${encodeURIComponent(sinceIso)}&filter=${filter}&limit=1000`;
  const events = [];
  let pages = 0;
  while (url && pages < 20) {
    const res = await fetch(url, {
      headers: {
        Authorization: `SSWS ${process.env.OKTA_API_TOKEN}`,
        Accept: 'application/json',
      },
    });
    if (!res.ok) throw new Error(`Okta ${res.status}: ${await res.text()}`);
    const data = await res.json();
    for (const ev of Array.isArray(data) ? data : []) {
      const ip = ev.client?.ipAddress;
      const user = ev.actor?.alternateId;
      if (!ip || !user) continue;
      events.push({
        user: user.toLowerCase(),
        ip,
        time: ev.published,
        country: ev.client?.geographicalContext?.country || null,
        city: ev.client?.geographicalContext?.city || null,
      });
    }
    // Okta paginates via Link header rel="next"
    const link = res.headers.get('link') || '';
    const m = link.split(',').find((s) => s.includes('rel="next"'));
    url = m ? m.slice(m.indexOf('<') + 1, m.indexOf('>')) : null;
    pages++;
  }
  return events;
}

// ── Entra: successful sign-ins (errorCode 0) for compromise correlation ──
async function fetchEntraSuccess(sinceIso) {
  const token = await getGraphToken();
  const filter = encodeURIComponent(
    `status/errorCode eq 0 and createdDateTime ge ${sinceIso}`
  );
  let url = `https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=${filter}&$top=1000`;
  const events = [];
  let pages = 0;
  while (url && pages < 20) {
    const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    if (!res.ok) throw new Error(`Graph ${res.status}: ${await res.text()}`);
    const data = await res.json();
    for (const s of data.value || []) {
      events.push({
        user: (s.userPrincipalName || '').toLowerCase(),
        ip: s.ipAddress || null,
        time: s.createdDateTime,
        country: s.location?.countryOrRegion || null,
        city: s.location?.city || null,
      });
    }
    url = data['@odata.nextLink'] || null;
    pages++;
  }
  return events;
}

// ── Okta: successful sign-ins for compromise correlation ──
async function fetchOktaSuccess(sinceIso) {
  if (!process.env.OKTA_BASE_URL || !process.env.OKTA_API_TOKEN) return [];
  const base = process.env.OKTA_BASE_URL.replace(/\/$/, '');
  const filter = encodeURIComponent('eventType eq "user.session.start" and outcome.result eq "SUCCESS"');
  let url = `${base}/api/v1/logs?since=${encodeURIComponent(sinceIso)}&filter=${filter}&limit=1000`;
  const events = [];
  let pages = 0;
  while (url && pages < 20) {
    const res = await fetch(url, {
      headers: { Authorization: `SSWS ${process.env.OKTA_API_TOKEN}`, Accept: 'application/json' },
    });
    if (!res.ok) throw new Error(`Okta ${res.status}: ${await res.text()}`);
    const data = await res.json();
    for (const ev of Array.isArray(data) ? data : []) {
      const user = ev.actor?.alternateId;
      if (!user) continue;
      events.push({
        user: user.toLowerCase(),
        ip: ev.client?.ipAddress || null,
        time: ev.published,
        country: ev.client?.geographicalContext?.country || null,
        city: ev.client?.geographicalContext?.city || null,
      });
    }
    const link = res.headers.get('link') || '';
    const m = link.split(',').find((s) => s.includes('rel="next"'));
    url = m ? m.slice(m.indexOf('<') + 1, m.indexOf('>')) : null;
    pages++;
  }
  return events;
}

// ── AD: 4625 failed logons via WinRM python helper ──
function fetchAD(minutes, timeoutMs) {
  return new Promise((resolve) => {
    const script = path.join(__dirname, 'spray-source.py');
    execFile('python3', [script, String(minutes)], {
      timeout: timeoutMs || 90000,
      maxBuffer: 20 * 1024 * 1024,
      env: process.env,
    }, (err, stdout) => {
      if (err) { console.error('[spray] AD fetch error:', err.message); return resolve([]); }
      try {
        const parsed = JSON.parse(stdout.trim() || '[]');
        if (parsed.error) { console.error('[spray] AD:', parsed.error); return resolve([]); }
        const events = [];
        for (const e of parsed) {
          if (!e.ip || e.ip === '-' || !e.user) continue;
          events.push({ user: String(e.user).toLowerCase(), ip: e.ip, time: e.time, country: null, city: null });
        }
        resolve(events);
      } catch (e) {
        console.error('[spray] AD parse error:', e.message);
        resolve([]);
      }
    });
  });
}

// Group a source's events by IP, apply spray thresholds, return flagged rows.
function detect(source, kind, events, windowStart, windowEnd, minUsers, maxPerUserCap, allowlist) {
  const byIp = new Map();
  for (const ev of events) {
    if (allowlist && allowlist.has(ev.ip)) continue;
    if (!byIp.has(ev.ip)) byIp.set(ev.ip, { users: new Map(), country: ev.country, city: ev.city, times: [] });
    const g = byIp.get(ev.ip);
    g.users.set(ev.user, (g.users.get(ev.user) || 0) + 1);
    g.times.push(ev.time);
    if (!g.country && ev.country) g.country = ev.country;
    if (!g.city && ev.city) g.city = ev.city;
  }
  const flagged = [];
  for (const [ip, g] of byIp) {
    const distinctUsers = g.users.size;
    const maxPerUser = Math.max(...g.users.values());
    // Spray profile: many accounts, few tries each.
    if (distinctUsers >= minUsers && maxPerUser <= maxPerUserCap) {
      const totalAttempts = [...g.users.values()].reduce((a, b) => a + b, 0);
      const sorted = g.times.filter(Boolean).sort();
      flagged.push([
        source, kind, ip, distinctUsers, totalAttempts,
        windowStart, windowEnd,
        g.country || null, g.city || null,
        JSON.stringify([...g.users.keys()].slice(0, 25)),
        sorted[0] ? new Date(sorted[0]) : windowStart,
        sorted[sorted.length - 1] ? new Date(sorted[sorted.length - 1]) : windowEnd,
      ]);
    }
  }
  return flagged;
}

async function upsert(pool, rows) {
  if (!rows.length) return 0;
  const sql = `
    INSERT INTO sdops_spray
      (source, window_kind, src_ip, distinct_users, total_attempts, window_start, window_end,
       country, city, sample_users, first_seen, last_seen)
    VALUES ?
    ON DUPLICATE KEY UPDATE
      distinct_users = GREATEST(distinct_users, VALUES(distinct_users)),
      total_attempts = GREATEST(total_attempts, VALUES(total_attempts)),
      window_end     = VALUES(window_end),
      country        = COALESCE(VALUES(country), country),
      city           = COALESCE(VALUES(city), city),
      sample_users   = VALUES(sample_users),
      last_seen      = VALUES(last_seen)`;
  const [r] = await pool.query(sql, [rows]);
  return r.affectedRows;
}

async function upsertCompromise(pool, rows) {
  if (!rows.length) return 0;
  const sql = `
    INSERT INTO sdops_compromise
      (username, success_source, spray_source, spray_ip, spray_window_start, spray_window_kind,
       success_time, success_ip, success_country, success_city, ip_match)
    VALUES ?
    ON DUPLICATE KEY UPDATE
      success_time    = LEAST(success_time, VALUES(success_time)),
      ip_match        = GREATEST(ip_match, VALUES(ip_match)),
      success_ip      = COALESCE(VALUES(success_ip), success_ip),
      success_country = COALESCE(VALUES(success_country), success_country),
      success_city    = COALESCE(VALUES(success_city), success_city),
      last_seen       = NOW()`;
  const [r] = await pool.query(sql, [rows]);
  return r.affectedRows;
}

// Correlate: a user targeted by an active flagged spray who then authenticates
// SUCCESSFULLY within one spray-window of the activity = possible compromise.
// Keys on the USER (survives shared egress); ip_match=1 when the success also
// came from the flagged spray IP (louder sub-tier). Only fetches successes when
// at least one flagged spray row is currently active (no API load on quiet ticks).
async function correlateCompromise(pool, allowlist) {
  const [rows] = await pool.query(
    `SELECT source, window_kind, src_ip, window_start, window_end, sample_users
       FROM sdops_spray
      WHERE last_seen >= (NOW() - INTERVAL ? MINUTE)`,
    [SLOW_WINDOW_MIN]
  );
  if (!rows.length) return { activeFlagged: 0, correlated: 0 };

  // user -> [ targeting spray rows ]
  const targets = new Map();
  let skippedAllowlisted = 0;
  for (const r of rows) {
    // Shared-egress IPs (allowlisted) produce vacuous correlations — every
    // legitimate login through them scores ip_match. Skip them here too.
    if (allowlist && allowlist.has(String(r.src_ip).trim())) { skippedAllowlisted++; continue; }
    let users = [];
    try { users = typeof r.sample_users === 'string' ? JSON.parse(r.sample_users) : (r.sample_users || []); } catch (e) {}
    const wkMs = r.window_kind === 'slow' ? SLOW_WINDOW_MS : WINDOW_MS;
    const start = new Date(r.window_start).getTime();
    const graceEnd = new Date(r.window_end).getTime() + wkMs;
    for (const u of users) {
      const key = String(u).toLowerCase();
      if (!targets.has(key)) targets.set(key, []);
      targets.get(key).push({
        spraySource: r.source, sprayIp: r.src_ip, windowKind: r.window_kind,
        windowStart: r.window_start, start, graceEnd,
      });
    }
  }
  if (!targets.size) return { activeFlagged: rows.length, skippedAllowlisted, correlated: 0 };

  // Pull successes over the widest (slow) window so both fast and slow flagged
  // rows are covered. NOTE (documented limitation): a very busy tenant can hit
  // the 20-page cap here and miss a success → false negative.
  const sinceIso = new Date(Date.now() - SLOW_WINDOW_MS).toISOString().replace(/\.\d{3}Z$/, 'Z');
  let successes = [];
  try { successes = successes.concat((await fetchEntraSuccess(sinceIso)).map((e) => ({ ...e, ssource: 'entra' }))); }
  catch (e) { console.error('[spray] compromise entra-success failed:', e.message); }
  try { successes = successes.concat((await fetchOktaSuccess(sinceIso)).map((e) => ({ ...e, ssource: 'okta' }))); }
  catch (e) { console.error('[spray] compromise okta-success failed:', e.message); }

  const out = [];
  for (const s of successes) {
    const key = (s.user || '').toLowerCase();
    const tgts = targets.get(key);
    if (!tgts) continue;
    const st = new Date(s.time).getTime();
    for (const t of tgts) {
      if (st >= t.start && st <= t.graceEnd) {
        const ipMatch = (s.ip && t.sprayIp && s.ip === t.sprayIp) ? 1 : 0;
        out.push([
          key, s.ssource, t.spraySource, t.sprayIp, t.windowStart, t.windowKind,
          new Date(s.time), s.ip || null, s.country || null, s.city || null, ipMatch,
        ]);
      }
    }
  }
  await upsertCompromise(pool, out);
  // Dedup on the storage unique key (username, spray_source, spray_ip, window_start)
  // so counters match stored rows, not inflated raw success-event matches.
  const seen = new Map();
  for (const r of out) {
    const key = r[0] + '|' + r[2] + '|' + r[3] + '|' + new Date(r[4]).getTime();
    // Louder tier wins if any matching success came from the spray IP.
    seen.set(key, (seen.get(key) ? 1 : 0) | r[10]);
  }
  const correlated = seen.size;
  let ipMatches = 0;
  for (const v of seen.values()) if (v === 1) ipMatches++;
  return { activeFlagged: rows.length, skippedAllowlisted, rawMatches: out.length,
    successes: successes.length, correlated, ipMatches };
}

// One detection pass (fast or slow) across all three sources.
async function runPass(pool, kind, started, windowMin, windowMs, minUsers, maxPerUser, allowlist) {
  // Tumbling bucket key so repeated runs within the same window update one row.
  const bucketStart = new Date(Math.floor(started.getTime() / windowMs) * windowMs);
  const bucketEnd = new Date(bucketStart.getTime() + windowMs);
  // Sliding query window for detection sensitivity.
  const sinceIso = new Date(started.getTime() - windowMs).toISOString().replace(/\.\d{3}Z$/, 'Z');

  // Slow pass pulls up to 24h of 4625s over WinRM — allow more time.
  const adTimeout = kind === 'slow' ? 180000 : 90000;

  const sources = [
    ['entra', () => fetchEntra(sinceIso)],
    ['okta',  () => fetchOkta(sinceIso)],
    ['ad',    () => fetchAD(windowMin, adTimeout)],
  ];

  let flaggedCount = 0;
  const results = {};
  for (const [name, fn] of sources) {
    try {
      const events = await fn();
      const flagged = detect(name, kind, events, bucketStart, bucketEnd, minUsers, maxPerUser, allowlist);
      await upsert(pool, flagged);
      results[name] = { events: events.length, flagged_ips: flagged.length };
      flaggedCount += flagged.length;
    } catch (e) {
      sourceErrors++;
      results[name] = { error: e.message };
      console.error(`[spray] ${kind}/${name} failed:`, e.message);
    }
  }
  return { flaggedCount, results };
}

async function main() {
  const started = new Date();
  const pool = await getPool();
  const allowlist = await getAllowlist(pool);
  if (allowlist.size) console.log(`[spray] allowlist: ${allowlist.size} IP(s) excluded`);

  // Fast pass: every run.
  const fast = await runPass(pool, 'fast', started, WINDOW_MIN, WINDOW_MS, MIN_USERS, MAX_PER_USER, allowlist);
  console.log(`[${started.toISOString()}] spray fast window=${WINDOW_MIN}m ` +
    `minUsers=${MIN_USERS} maxPerUser=${MAX_PER_USER} flagged=${fast.flaggedCount} ` +
    JSON.stringify(fast.results));

  // Slow pass: first cron hit of each hour (cron minutes 5,20,35,50 → the :05 run),
  // or forced via SPRAY_SLOW_FORCE=1.
  const slowDue = started.getMinutes() < 15 || process.env.SPRAY_SLOW_FORCE === '1';
  if (slowDue) {
    const slow = await runPass(pool, 'slow', started, SLOW_WINDOW_MIN, SLOW_WINDOW_MS, SLOW_MIN_USERS, SLOW_MAX_PER_USER, allowlist);
    console.log(`[${started.toISOString()}] spray slow window=${SLOW_WINDOW_MIN}m ` +
      `minUsers=${SLOW_MIN_USERS} maxPerUser=${SLOW_MAX_PER_USER} flagged=${slow.flaggedCount} ` +
      JSON.stringify(slow.results));
  }

  // Compromise layer: sprayed users who subsequently authenticated successfully.
  try {
    const comp = await correlateCompromise(pool, allowlist);
    if (comp.activeFlagged > 0) {
      console.log(`[${started.toISOString()}] compromise activeFlagged=${comp.activeFlagged} ` +
        `skippedAllowlisted=${comp.skippedAllowlisted || 0} successesScanned=${comp.successes || 0} ` +
        `correlated=${comp.correlated} ipMatches=${comp.ipMatches || 0} rawMatches=${comp.rawMatches || 0}`);
    }
  } catch (e) {
    console.error('[spray] compromise correlation failed:', e.message);
  }

  if (sourceErrors) {
    console.error(`[spray] ${sourceErrors} source pass(es) failed - exiting non-zero so the run is recorded as failed, not as 'no spray seen'`);
    process.exitCode = 2;
  }
  await pool.end();
}

main().catch((e) => { console.error('[spray] fatal:', e); process.exit(1); });
