'use strict';
/* ════════════════════════════════════════════════════════════════════
   Schema contract for the tables the hub's request-serving modules used to
   create or alter at load / request time (CHG-ARCH-18, review finding #8).

   The contract is what the CODE needs: every column a module reads or
   writes, the MySQL data type family, and the unique keys its upserts rely
   on. It is checked read-only (information_schema / PRAGMA), so the hub can
   verify it at startup without performing DDL. Changes are made only by
   migrate.js, at deploy time.

   Slices are per module so an incompatible table 503s the routes that use
   it instead of taking down the whole process (the auth gate lives here).
   ════════════════════════════════════════════════════════════════════ */

const path = require('path');

const DEFAULT_NET_DB = '/var/www/corpit-hub-api/data/netfleet.db';

// Resolved the same way the modules resolve them: intune_graph.js pins
// it_inventory, housekeeping.js uses DB_NAME || corpit_hub, netswitch.js uses
// NET_DB || the default path. SCHEMA_INVENTORY_DB exists for the scratch harness.
function names(env = process.env) {
  return {
    inventory: env.SCHEMA_INVENTORY_DB || 'it_inventory',
    hub:       env.DB_NAME || 'corpit_hub',
    netDb:     env.NET_DB || DEFAULT_NET_DB,
  };
}

const TABLES = [
  { slice: 'intune', store: 'mysql', db: 'inventory', table: 'intune_graph_cache',
    columns: {
      device_id: 'varchar', serial_number: 'varchar', imei: 'varchar', computer_name: 'varchar',
      display_name: 'varchar', os_version: 'varchar', compliance: 'varchar', enrolled_date: 'varchar',
      last_sync: 'varchar', user_upn: 'varchar', model: 'varchar', manufacturer: 'varchar',
      phone_number: 'varchar', operating_system: 'varchar', last_synced: 'datetime', is_encrypted: 'tinyint',
    },
    unique: [['device_id']] },                       // /sync upserts ON DUPLICATE KEY device_id
  { slice: 'intune', store: 'mysql', db: 'inventory', table: 'intune_devices',
    columns: {
      id: 'int', device_id: 'varchar', device_name: 'varchar', serial_number: 'varchar', imei: 'varchar',
      phone_number: 'varchar', os: 'varchar', os_version: 'varchar', compliance: 'varchar',
      primary_user_upn: 'varchar', primary_user_name: 'varchar', last_checkin: 'varchar', model: 'varchar',
      device_source: 'varchar', device_category: 'varchar', is_historical: 'tinyint', is_encrypted: 'tinyint',
      la_device_id: 'varchar', la_state: 'varchar', la_regional: 'varchar', la_active: 'varchar',
    },
    unique: [['device_id']] },                       // /sync-to-devices upserts ON DUPLICATE KEY device_id
  { slice: 'housekeeping', store: 'mysql', db: 'hub', table: 'housekeeping_audit',
    columns: {
      id: 'int', created_at: 'datetime', action_type: 'varchar', object_type: 'varchar',
      object_name: 'varchar', object_dn: 'text', original_state: 'json', new_state: 'json',
      performed_by: 'varchar', reverted: 'tinyint', revert_at: 'datetime', notes: 'text',
    },
    unique: [] },
  { slice: 'netfleet', store: 'sqlite', db: 'netDb', table: 'net_watch',
    columns: ['id', 'kind', 'ref', 'label', 'meta', 'created_by', 'created_at', 'active'],
    unique: [['kind', 'ref']] },                     // POST /watch: ON CONFLICT(kind,ref)
  { slice: 'netfleet', store: 'sqlite', db: 'netDb', table: 'net_watch_samples',
    columns: ['watch_id', 'ts', 'data'], unique: [] },
  { slice: 'netfleet', store: 'sqlite', db: 'netDb', table: 'net_watch_events',
    columns: ['id', 'watch_id', 'ts', 'severity', 'kind', 'message'], unique: [] },
  { slice: 'netfleet', store: 'sqlite', db: 'netDb', table: 'net_claims',
    columns: ['id', 'ref', 'title', 'detail', 'claimed_by', 'claimed_at', 'cleared_at'], unique: [] },
  // One-press access requests (access-request-routes.js): the dedupe ledger behind "Already requested #N".
  { slice: 'access-request', store: 'mysql', db: 'hub', table: 'access_requests',
    columns: {
      id: 'bigint', created_at: 'datetime', requester_email: 'varchar', requester_name: 'varchar', kind: 'varchar',
      target: 'varchar', need_key: 'varchar', need_text: 'varchar', path: 'varchar', reason: 'varchar',
      sdp_id: 'varchar', sdp_display_id: 'varchar', sdp_url: 'varchar',
    },
    unique: [] },
  // Shared mailbox housekeeping: the collector's snapshot (upsert ON DUPLICATE KEY mailbox_guid) and the
  // shared settings (upsert ON DUPLICATE KEY setting_key).
  { slice: 'shared-mailbox', store: 'mysql', db: 'hub', table: 'hk_shared_mailbox',
    columns: {
      mailbox_guid: 'varchar', display_name: 'varchar', primary_smtp: 'varchar', upn: 'varchar', alias: 'varchar',
      is_dirsynced: 'tinyint', hidden_gal: 'tinyint', when_created: 'datetime', item_count: 'int', size_bytes: 'bigint',
      last_user_action: 'datetime', last_received: 'datetime', last_sent: 'datetime', graph_last_activity: 'date',
      recv_count: 'int', sent_count: 'int', trace_days: 'smallint', full_access: 'json', send_as: 'json',
      error: 'varchar', run_id: 'varchar', collected_at: 'datetime',
    },
    unique: [['mailbox_guid']] },
  { slice: 'shared-mailbox', store: 'mysql', db: 'hub', table: 'hk_settings',
    columns: { setting_key: 'varchar', setting_value: 'text', updated_by: 'varchar', updated_at: 'datetime' },
    unique: [['setting_key']] },
  // DARKTRACE-EMAIL 2026-10-14 (darktrace-email-lib/-sync/-routes.js).
  { slice: 'darktrace-email', store: 'mysql', db: 'hub', table: 'dt_email_config',
    columns: { id: 'tinyint', enabled: 'tinyint', host: 'varchar', public_token: 'varchar', private_token: 'varchar',
      cadence_min: 'int', updated_by: 'varchar', updated_at: 'datetime' },
    unique: [['id']] },                              // PUT /config upserts id 1
  { slice: 'darktrace-email', store: 'mysql', db: 'hub', table: 'dt_email_run',
    columns: { id: 'bigint', started_at: 'datetime', finished_at: 'datetime', state: 'varchar', held_7d: 'int', junk_7d: 'int',
      critical_7d: 'int', threats_7d: 'int', inbound_7d: 'int', messages: 'int', rcpts: 'int', dlp_rows: 'int',
      anomaly_rows: 'int', audit_new: 'int', pages: 'int', note: 'text' },
    unique: [] },
  { slice: 'darktrace-email', store: 'mysql', db: 'hub', table: 'dt_email_message',
    columns: { uuid: 'varchar', dtime: 'datetime', direction: 'varchar', from_email: 'varchar', from_name: 'varchar',
      subject: 'varchar', model_score: 'int', n_attachments: 'int', n_links: 'int', is_critical: 'tinyint', seen_run_id: 'bigint' },
    unique: [['uuid']] },
  { slice: 'darktrace-email', store: 'mysql', db: 'hub', table: 'dt_email_rcpt',
    columns: { uuid: 'varchar', rcpt_to: 'varchar', rcpt_status: 'varchar', action_status: 'varchar', actions: 'json',
      tags: 'json', is_group: 'tinyint', seen_run_id: 'bigint' },
    unique: [['uuid', 'rcpt_to']] },
  { slice: 'darktrace-email', store: 'mysql', db: 'hub', table: 'dt_email_dlp',
    columns: { sender: 'varchar', n_emails: 'int', n_attachments: 'int', n_rcpts: 'int', total_emails: 'int', run_id: 'bigint' },
    unique: [['sender']] },
  { slice: 'darktrace-email', store: 'mysql', db: 'hub', table: 'dt_email_anomaly',
    columns: { mailbox: 'varchar', n_emails: 'int', n_attachments: 'int', n_links: 'int', n_last_period: 'int',
      n_last_week: 'int', percentage: 'double', total_emails: 'int', run_id: 'bigint' },
    unique: [['mailbox']] },
  { slice: 'darktrace-email', store: 'mysql', db: 'hub', table: 'dt_email_audit',
    columns: { uuid: 'varchar', event_at: 'datetime', event: 'text', account_id: 'varchar', tid: 'varchar',
      provider: 'varchar', run_id: 'bigint' },
    unique: [['uuid']] },
  // AI-GOVERNANCE 2026-10-15 (ai-governance-*.js, ai-risk-*.js).
  { slice: 'ai-governance', store: 'mysql', db: 'hub', table: 'ai_governance_access',
    columns: { id: 'int', catalog_id: 'int', user_identity: 'varchar', access_level: 'varchar', subscription_type: 'varchar', capability_name: 'varchar', business_purpose: 'text', granted_at: 'date', evidence_url: 'varchar', status: 'varchar', recorded_by: 'varchar', recorded_at: 'timestamp' },
    unique: [['id']] },
  { slice: 'ai-governance', store: 'mysql', db: 'hub', table: 'ai_governance_app',
    columns: { catalog_id: 'int', vendor: 'varchar', category: 'varchar', ai_type: 'varchar', owner: 'varchar', business_purpose: 'text', capability_name: 'varchar', enablement: 'varchar', approval_status: 'varchar', evidence_url: 'varchar', review_due: 'date', updated_by: 'varchar', version: 'int', updated_at: 'timestamp' },
    unique: [['catalog_id']] },
  { slice: 'ai-governance', store: 'mysql', db: 'hub', table: 'ai_governance_audit',
    columns: { id: 'bigint', actor: 'varchar', action: 'varchar', catalog_id: 'int', entity_id: 'int', before_json: 'json', after_json: 'json', created_at: 'timestamp' },
    unique: [['id']] },
  { slice: 'ai-governance', store: 'mysql', db: 'hub', table: 'ai_governance_project',
    columns: { id: 'int', catalog_id: 'int', project_id: 'int', ad_group_name: 'varchar', access_level: 'varchar', subscription_type: 'varchar', capability_name: 'varchar', business_purpose: 'text', evidence_url: 'varchar', created_by: 'varchar', created_at: 'timestamp' },
    unique: [['id'], ['catalog_id', 'project_id', 'ad_group_name']] },
  { slice: 'ai-governance', store: 'mysql', db: 'hub', table: 'ai_governance_request',
    columns: { id: 'int', catalog_id: 'int', user_identity: 'varchar', access_level: 'varchar', subscription_type: 'varchar', capability_name: 'varchar', business_purpose: 'text', evidence_url: 'varchar', status: 'varchar', decision_note: 'text', reviewed_by: 'varchar', reviewed_at: 'datetime', requested_by: 'varchar', version: 'int', created_at: 'timestamp', updated_at: 'timestamp' },
    unique: [['id']] },
  { slice: 'ai-governance', store: 'mysql', db: 'hub', table: 'ai_governance_source',
    columns: { source_key: 'varchar', payload: 'json', checked_by: 'varchar', checked_at: 'timestamp' },
    unique: [['source_key']] },
  { slice: 'ai-governance', store: 'mysql', db: 'hub', table: 'ai_governance_category',
    columns: { name: 'varchar', created_by: 'varchar', created_at: 'timestamp' },
    unique: [['name']] },
  { slice: 'ai-governance', store: 'mysql', db: 'hub', table: 'ai_governance_evidence',
    columns: { id: 'bigint', catalog_id: 'int', source_key: 'varchar', source_record_id: 'varchar', evidence_kind: 'varchar', source_url: 'varchar', capability_name: 'varchar', suggested_category: 'varchar', observed_at: 'datetime', attached_by: 'varchar', attached_at: 'timestamp' },
    unique: [['id'], ['catalog_id', 'source_key', 'source_record_id']] },
  { slice: 'ai-governance', store: 'mysql', db: 'hub', table: 'ai_governance_tag',
    columns: { catalog_id: 'int', tag: 'varchar' },
    unique: [['catalog_id', 'tag']] },
  { slice: 'ai-governance', store: 'mysql', db: 'hub', table: 'ai_governance_account',
    columns: { catalog_id: 'int', profile: 'json', revision: 'int', updated_by: 'varchar', updated_at: 'timestamp' },
    unique: [['catalog_id']] },
  { slice: 'ai-governance', store: 'mysql', db: 'hub', table: 'ai_governance_rapid7_observation',
    columns: { fingerprint: 'char', run_id: 'char', candidate_key: 'varchar', catalog_id: 'int', app_name: 'varchar', domain: 'varchar', user_identity: 'varchar', occurred_at: 'datetime', event_time_basis: 'varchar', logset_id: 'varchar', logset_name: 'varchar', log_id: 'varchar', log_name: 'varchar', source_event_id: 'varchar', original_source: 'varchar', evidence_kind: 'varchar', result: 'varchar', blocked: 'tinyint', raw_app_label: 'varchar', raw_category: 'varchar', zscaler_code: 'varchar', zscaler_label: 'varchar', zscaler_category: 'varchar', match_basis: 'varchar', first_collected_at: 'timestamp', last_collected_at: 'timestamp' },
    unique: [['fingerprint']] },
  { slice: 'ai-governance', store: 'mysql', db: 'hub', table: 'ai_governance_refresh_config',
    columns: { source_key: 'varchar', enabled: 'tinyint', interval_minutes: 'int', next_run_at: 'datetime', last_attempt_at: 'datetime', last_success_at: 'datetime', last_status: 'varchar', last_error: 'varchar', last_run_id: 'char', updated_by: 'varchar', updated_at: 'timestamp' },
    unique: [['source_key']] },
  { slice: 'ai-governance', store: 'mysql', db: 'hub', table: 'ai_governance_refresh_run',
    columns: { id: 'char', source_key: 'varchar', trigger_kind: 'varchar', actor: 'varchar', status: 'varchar', phase: 'varchar', started_at: 'datetime', completed_at: 'datetime', error: 'varchar', candidate_count: 'int', observation_count: 'int' },
    unique: [['id']] },
  { slice: 'ai-governance', store: 'mysql', db: 'hub', table: 'ai_governance_refresh_worker',
    columns: { id: 'tinyint', last_seen_at: 'datetime' },
    unique: [['id']] },
  { slice: 'ai-governance', store: 'mysql', db: 'hub', table: 'ai_governance_risk',
    columns: { catalog_id: 'int', profile: 'json', revision: 'int', updated_by: 'varchar', updated_at: 'timestamp' },
    unique: [['catalog_id']] },  // AI-GOVERNANCE PORTAL SYNC 2026-10-15 (ai-governance-portal*.js; hub-0027).
  { slice: 'ai-governance', store: 'mysql', db: 'hub', table: 'ai_governance_portal_sync',
    columns: { id: 'tinyint', enabled: 'tinyint', token: 'varchar', saved_by: 'varchar', saved_at: 'timestamp', next_run_at: 'datetime', last_run_at: 'datetime', last_run_by: 'varchar', last_pull_at: 'datetime', last_pull_status: 'varchar', last_pull_error: 'varchar', last_pull_detail: 'json', last_push_at: 'datetime', last_push_status: 'varchar', last_push_error: 'varchar', last_push_detail: 'json' },
    unique: [['id']] },
];

const SLICES = [...new Set(TABLES.map(t => t.slice))];

const sameCols = (a, b) => a.length === b.length && a.every((c, i) => c.toLowerCase() === String(b[i]).toLowerCase());

// ── MySQL: one information_schema read per kind, filtered in JS ──────────────
async function checkMysql(conn, n) {
  const wanted = TABLES.filter(t => t.store === 'mysql');
  const schemas = [...new Set(wanted.map(t => n[t.db]))];
  const tables  = [...new Set(wanted.map(t => t.table))];
  const [cols] = await conn.query(
    `SELECT TABLE_SCHEMA s, TABLE_NAME t, COLUMN_NAME c, DATA_TYPE d
       FROM information_schema.COLUMNS WHERE TABLE_SCHEMA IN (?) AND TABLE_NAME IN (?)`, [schemas, tables]);
  const [idx] = await conn.query(
    `SELECT TABLE_SCHEMA s, TABLE_NAME t, INDEX_NAME i, NON_UNIQUE nu, SEQ_IN_INDEX q, COLUMN_NAME c
       FROM information_schema.STATISTICS WHERE TABLE_SCHEMA IN (?) AND TABLE_NAME IN (?)
      ORDER BY TABLE_SCHEMA, TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX`, [schemas, tables]);
  const out = [];
  for (const t of wanted) {
    const s = n[t.db], fq = `${s}.${t.table}`;
    const have = new Map(cols.filter(r => r.s === s && r.t === t.table).map(r => [r.c.toLowerCase(), r.d.toLowerCase()]));
    if (!have.size) { out.push({ slice: t.slice, table: fq, problem: 'table missing' }); continue; }
    for (const [c, type] of Object.entries(t.columns)) {
      if (!have.has(c)) out.push({ slice: t.slice, table: fq, problem: `missing column ${c}` });
      else if (have.get(c) !== type) out.push({ slice: t.slice, table: fq, problem: `column ${c} is ${have.get(c)}, expected ${type}` });
    }
    const uniq = new Map();
    for (const r of idx.filter(r => r.s === s && r.t === t.table && Number(r.nu) === 0)) {
      if (!uniq.has(r.i)) uniq.set(r.i, []);
      uniq.get(r.i).push(r.c);
    }
    for (const u of t.unique) {
      if (![...uniq.values()].some(v => sameCols(v, u)))
        out.push({ slice: t.slice, table: fq, problem: `no unique key on (${u.join(', ')})` });
    }
  }
  return out;
}

// ── SQLite: read-only open; a missing file is 'unknown', never created ───────
function checkSqlite(n, Database) {
  const wanted = TABLES.filter(t => t.store === 'sqlite');
  const file = n.netDb, out = [];
  let db;
  try {
    db = new Database(file, { readonly: true, fileMustExist: true });
  } catch (e) {
    return { unreachable: `cannot open ${file} read-only: ${e.code || e.message}`, problems: [] };
  }
  try {
    for (const t of wanted) {
      const fq = `${path.basename(file)}:${t.table}`;
      const cols = db.prepare('SELECT name FROM pragma_table_info(?)').all(t.table).map(r => r.name.toLowerCase());
      if (!cols.length) { out.push({ slice: t.slice, table: fq, problem: 'table missing' }); continue; }
      for (const c of t.columns) if (!cols.includes(c)) out.push({ slice: t.slice, table: fq, problem: `missing column ${c}` });
      const uniq = db.prepare('SELECT name FROM pragma_index_list(?) WHERE "unique" = 1').all(t.table)
        .map(r => db.prepare('SELECT name FROM pragma_index_info(?) ORDER BY seqno').all(r.name).map(x => x.name));
      for (const u of t.unique)
        if (!uniq.some(v => sameCols(v, u))) out.push({ slice: t.slice, table: fq, problem: `no unique key on (${u.join(', ')})` });
    }
  } finally { db.close(); }
  return { unreachable: null, problems: out };
}

/**
 * Read-only contract check. Resolves to
 *   { ok, slices: { <slice>: { state: 'ok'|'incompatible'|'unknown', problems: [...] } } }
 * 'unknown' = the store could not be reached (connection refused, auth, the
 * SQLite file absent), which says nothing about the schema and is kept distinct
 * from 'incompatible'. Callers that must prove the contract treat it as failure.
 */
async function check({ mysqlConn, Database, env } = {}) {
  const n = names(env);
  const slices = Object.fromEntries(SLICES.map(s => [s, { state: 'ok', problems: [] }]));
  const mark = (list) => { for (const p of list) { slices[p.slice].state = 'incompatible'; slices[p.slice].problems.push(`${p.table}: ${p.problem}`); } };
  const mysqlSlices = [...new Set(TABLES.filter(t => t.store === 'mysql').map(t => t.slice))];
  try {
    mark(await checkMysql(mysqlConn, n));
  } catch (e) {
    for (const s of mysqlSlices) { slices[s] = { state: 'unknown', problems: [`mysql unreachable: ${e.code || e.message}`] }; }
  }
  const lite = checkSqlite(n, Database || require('better-sqlite3'));
  if (lite.unreachable) {
    for (const s of new Set(TABLES.filter(t => t.store === 'sqlite').map(t => t.slice))) slices[s] = { state: 'unknown', problems: [lite.unreachable] };
  } else mark(lite.problems);
  const ok = Object.values(slices).every(s => s.state === 'ok');
  return { ok, slices };
}

module.exports = { TABLES, SLICES, names, check, DEFAULT_NET_DB };
