'use strict';
/* ════════════════════════════════════════════════════════════════════
   Versioned schema steps for the hub-owned tables (CHG-ARCH-18). Applied only
   by migrate.js at deploy time, serialized by a MySQL named lock and recorded
   in <hub db>.schema_migrations. Never edit a step that has been recorded —
   migrate.js refuses a checksum change; add a new step instead.

   Each step has a guard: if the database already satisfies it (the tables in
   production predate this file), it is recorded as 'baseline' and nothing is
   executed. So a clean database and the upgraded production one reach the
   same contract (schema/contract.js).

   The CREATE TABLE bodies are the live production definitions as of
   2026-09-24 (SHOW CREATE TABLE / sqlite_master), not the older in-module
   CREATEs, which lacked intune_graph_cache.imei and .is_encrypted.
   ════════════════════════════════════════════════════════════════════ */

module.exports = [
  { id: 'inv-0001-intune-graph-cache', store: 'mysql', db: 'inventory', kind: 'create-table', table: 'intune_graph_cache',
    sql: `CREATE TABLE intune_graph_cache (
  serial_number varchar(128) DEFAULT NULL,
  imei varchar(50) DEFAULT NULL,
  computer_name varchar(255) DEFAULT NULL,
  device_id varchar(128) NOT NULL,
  display_name varchar(255) DEFAULT NULL,
  os_version varchar(128) DEFAULT NULL,
  compliance varchar(64) DEFAULT NULL,
  enrolled_date varchar(64) DEFAULT NULL,
  last_sync varchar(64) DEFAULT NULL,
  user_upn varchar(255) DEFAULT NULL,
  model varchar(255) DEFAULT NULL,
  manufacturer varchar(255) DEFAULT NULL,
  phone_number varchar(64) DEFAULT NULL,
  operating_system varchar(128) DEFAULT NULL,
  last_synced datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_encrypted tinyint(1) DEFAULT NULL,
  PRIMARY KEY (device_id),
  KEY idx_serial (serial_number),
  KEY idx_name (computer_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci` },

  // Tables created by the old in-module CREATE have none of these three.
  { id: 'inv-0002-intune-graph-cache-columns', store: 'mysql', db: 'inventory', kind: 'add-columns', table: 'intune_graph_cache',
    columns: [
      ['imei',         'varchar(50) DEFAULT NULL AFTER serial_number'],
      ['phone_number', 'varchar(64) DEFAULT NULL AFTER manufacturer'],
      ['is_encrypted', 'tinyint(1) DEFAULT NULL'],
    ] },

  // No code in the estate creates intune_devices; the hub writes to it
  // (/api/intune-graph/sync-to-devices), so a clean database gets it here.
  { id: 'inv-0003-intune-devices', store: 'mysql', db: 'inventory', kind: 'create-table', table: 'intune_devices',
    sql: `CREATE TABLE intune_devices (
  id int NOT NULL AUTO_INCREMENT,
  device_id varchar(255) DEFAULT NULL,
  device_name varchar(255) DEFAULT NULL,
  ownership varchar(100) DEFAULT NULL,
  compliance varchar(100) DEFAULT NULL,
  os varchar(100) DEFAULT NULL,
  os_version varchar(100) DEFAULT NULL,
  primary_user_upn varchar(255) DEFAULT NULL,
  last_checkin varchar(100) DEFAULT NULL,
  model varchar(255) DEFAULT NULL,
  serial_number varchar(255) DEFAULT NULL,
  imei varchar(50) DEFAULT NULL,
  phone_number varchar(100) DEFAULT NULL,
  primary_user_name varchar(255) DEFAULT NULL,
  device_source varchar(20) DEFAULT 'xlsx',
  device_category varchar(20) DEFAULT 'mobile',
  is_historical tinyint(1) DEFAULT '0',
  la_device_id varchar(100) DEFAULT NULL,
  la_state varchar(100) DEFAULT NULL,
  la_regional varchar(100) DEFAULT NULL,
  la_active varchar(50) DEFAULT NULL,
  subscriber_carrier varchar(255) DEFAULT NULL,
  created_at timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  carrier varchar(20) DEFAULT NULL,
  is_encrypted tinyint(1) DEFAULT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY idx_device_id (device_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci` },

  // What intune_graph.js used to ALTER in at load (phone_number) and inside
  // /sync-to-devices (the unique key its ON DUPLICATE KEY upsert depends on).
  { id: 'inv-0004-intune-devices-phone-number', store: 'mysql', db: 'inventory', kind: 'add-columns', table: 'intune_devices',
    columns: [['phone_number', 'varchar(100) DEFAULT NULL AFTER imei']] },
  { id: 'inv-0005-intune-devices-unique-device-id', store: 'mysql', db: 'inventory', kind: 'add-unique', table: 'intune_devices',
    index: 'idx_device_id', columns: ['device_id'] },

  { id: 'hub-0001-housekeeping-audit', store: 'mysql', db: 'hub', kind: 'create-table', table: 'housekeeping_audit',
    sql: `CREATE TABLE housekeeping_audit (
  id int NOT NULL AUTO_INCREMENT,
  created_at datetime DEFAULT CURRENT_TIMESTAMP,
  action_type varchar(50) NOT NULL,
  object_type varchar(20) NOT NULL,
  object_name varchar(255) NOT NULL,
  object_dn text,
  original_state json DEFAULT NULL,
  new_state json DEFAULT NULL,
  performed_by varchar(100) DEFAULT 'itam-api',
  reverted tinyint(1) DEFAULT '0',
  revert_at datetime DEFAULT NULL,
  notes text,
  PRIMARY KEY (id),
  KEY idx_created (created_at),
  KEY idx_object (object_name),
  KEY idx_action (action_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci` },

  // netfleet.db itself is created by the netcollect collector; the hub owns
  // only its watch-list and claims tables. watchpoll.py (corpit-netwatch.timer)
  // also creates the first three plus both indexes, with the same shapes.
  { id: 'net-0001-watch-and-claims', store: 'sqlite', db: 'netDb', kind: 'sqlite-tables',
    tables: ['net_watch', 'net_watch_samples', 'net_watch_events', 'net_claims'],
    sql: `CREATE TABLE IF NOT EXISTS net_watch(
      id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, ref TEXT, label TEXT, meta TEXT,
      created_by TEXT, created_at INTEGER, active INTEGER DEFAULT 1, UNIQUE(kind, ref));
CREATE TABLE IF NOT EXISTS net_watch_samples(watch_id INTEGER, ts INTEGER, data TEXT, PRIMARY KEY(watch_id, ts));
CREATE INDEX IF NOT EXISTS ix_ws_ts ON net_watch_samples(watch_id, ts);
CREATE TABLE IF NOT EXISTS net_watch_events(id INTEGER PRIMARY KEY AUTOINCREMENT,
      watch_id INTEGER, ts INTEGER, severity TEXT, kind TEXT, message TEXT);
CREATE INDEX IF NOT EXISTS ix_we ON net_watch_events(watch_id, ts);
CREATE TABLE IF NOT EXISTS net_claims(id INTEGER PRIMARY KEY AUTOINCREMENT,
      ref TEXT, title TEXT, detail TEXT,
      claimed_by TEXT, claimed_at INTEGER, cleared_at INTEGER);` },
  { id: 'hub-0002-access-requests', store: 'mysql', db: 'hub', kind: 'create-table', table: 'access_requests',
    sql: `CREATE TABLE access_requests (
  id bigint NOT NULL AUTO_INCREMENT,
  created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  requester_email varchar(255) NOT NULL,
  requester_name varchar(255) DEFAULT NULL,
  kind varchar(8) NOT NULL,
  target varchar(255) NOT NULL,
  need_key varchar(190) NOT NULL,
  need_text varchar(500) NOT NULL,
  path varchar(500) DEFAULT NULL,
  reason varchar(64) DEFAULT NULL,
  sdp_id varchar(64) NOT NULL,
  sdp_display_id varchar(64) NOT NULL,
  sdp_url varchar(500) DEFAULT NULL,
  PRIMARY KEY (id),
  KEY idx_dedupe (requester_email, kind, target, need_key, created_at),
  KEY idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci` },
];
