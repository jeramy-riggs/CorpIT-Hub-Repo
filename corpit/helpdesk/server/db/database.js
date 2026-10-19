/**
 * SQLite database layer using better-sqlite3.
 * Stores cached Okta data so the dashboard loads instantly
 * without hitting Okta on every page view.
 */
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const logger = require('../utils/logger');

const DB_PATH = path.join(__dirname, '..', '..', 'data', 'helpdesk.db');
let db;

function getDb() {
  if (!db) {
    const dir = path.dirname(DB_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');
    try {
      db.pragma('synchronous = FULL');
      if (db.pragma('synchronous', { simple: true }) !== 2) {
        throw new Error('SQLite writer requires synchronous=FULL');
      }
    } catch (error) {
      db.close();
      db = null; // A later retry must not reuse a rejected/closed singleton.
      throw error;
    }
    db.pragma('foreign_keys = ON');
  }
  return db;
}

function initDatabase() {
  const d = getDb();

  d.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      login TEXT,
      email TEXT,
      first_name TEXT,
      last_name TEXT,
      display_name TEXT,
      status TEXT,
      created TEXT,
      activated TEXT,
      last_login TEXT,
      status_changed TEXT,
      last_password_change TEXT,
      password_expiry_estimate TEXT,
      locked_out INTEGER DEFAULT 0,
      department TEXT,
      title TEXT,
      manager TEXT,
      synced_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS applications (
      id TEXT PRIMARY KEY,
      name TEXT,
      label TEXT,
      status TEXT,
      sign_on_mode TEXT,
      logo_url TEXT,
      created TEXT,
      last_updated TEXT,
      assigned_user_count INTEGER DEFAULT 0,
      assigned_group_count INTEGER DEFAULT 0,
      synced_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS app_assignments (
      id TEXT PRIMARY KEY,
      app_id TEXT,
      user_id TEXT,
      user_login TEXT,
      scope TEXT,
      status TEXT,
      last_sync TEXT,
      synced_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (app_id) REFERENCES applications(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS system_logs (
      uuid TEXT PRIMARY KEY,
      actor_id TEXT,
      actor_login TEXT,
      event_type TEXT,
      display_message TEXT,
      severity TEXT,
      published TEXT,
      target_id TEXT,
      target_type TEXT,
      target_name TEXT,
      client_ip TEXT,
      client_geo TEXT,
      outcome TEXT,
      synced_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS sync_status (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      entity TEXT,
      status TEXT,
      records INTEGER DEFAULT 0,
      started_at TEXT,
      completed_at TEXT,
      error TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
    CREATE INDEX IF NOT EXISTS idx_users_locked ON users(locked_out);
    CREATE INDEX IF NOT EXISTS idx_users_last_login ON users(last_login);
    CREATE INDEX IF NOT EXISTS idx_apps_status ON applications(status);
    CREATE INDEX IF NOT EXISTS idx_app_assign_app ON app_assignments(app_id);
    CREATE INDEX IF NOT EXISTS idx_app_assign_user ON app_assignments(user_id);
    CREATE INDEX IF NOT EXISTS idx_logs_event ON system_logs(event_type);
    CREATE INDEX IF NOT EXISTS idx_logs_published ON system_logs(published);
    CREATE INDEX IF NOT EXISTS idx_logs_actor ON system_logs(actor_id);
  `);

  logger.info('Database schema verified');
}

// ── Helper: upsert many rows ────────────────────────────────
function upsertUsers(users) {
  const d = getDb();
  const stmt = d.prepare(`
    INSERT OR REPLACE INTO users
      (id, login, email, first_name, last_name, display_name, status,
       created, activated, last_login, status_changed, last_password_change,
       password_expiry_estimate, locked_out, department, title, manager, synced_at)
    VALUES
      (@id, @login, @email, @firstName, @lastName, @displayName, @status,
       @created, @activated, @lastLogin, @statusChanged, @lastPasswordChange,
       @passwordExpiryEstimate, @lockedOut, @department, @title, @manager, datetime('now'))
  `);
  const tx = d.transaction((rows) => { for (const r of rows) stmt.run(r); });
  tx(users);
}

function upsertApplications(apps) {
  const d = getDb();
  const stmt = d.prepare(`
    INSERT OR REPLACE INTO applications
      (id, name, label, status, sign_on_mode, logo_url, created, last_updated,
       assigned_user_count, assigned_group_count, synced_at)
    VALUES
      (@id, @name, @label, @status, @signOnMode, @logoUrl, @created, @lastUpdated,
       @assignedUserCount, @assignedGroupCount, datetime('now'))
  `);
  const tx = d.transaction((rows) => { for (const r of rows) stmt.run(r); });
  tx(apps);
}

function upsertAppAssignments(assignments) {
  const d = getDb();
  const stmt = d.prepare(`
    INSERT OR REPLACE INTO app_assignments
      (id, app_id, user_id, user_login, scope, status, last_sync, synced_at)
    VALUES
      (@id, @appId, @userId, @userLogin, @scope, @status, @lastSync, datetime('now'))
  `);
  const tx = d.transaction((rows) => { for (const r of rows) stmt.run(r); });
  tx(assignments);
}

function upsertSystemLogs(logs) {
  const d = getDb();
  const stmt = d.prepare(`
    INSERT OR REPLACE INTO system_logs
      (uuid, actor_id, actor_login, event_type, display_message, severity,
       published, target_id, target_type, target_name, client_ip, client_geo, outcome, synced_at)
    VALUES
      (@uuid, @actorId, @actorLogin, @eventType, @displayMessage, @severity,
       @published, @targetId, @targetType, @targetName, @clientIp, @clientGeo, @outcome, datetime('now'))
  `);
  const tx = d.transaction((rows) => { for (const r of rows) stmt.run(r); });
  tx(logs);
}

function logSync(entity, status, records = 0, error = null) {
  const d = getDb();
  d.prepare(`
    INSERT INTO sync_status (entity, status, records, started_at, completed_at, error)
    VALUES (?, ?, ?, datetime('now'), CASE WHEN ? IN ('completed','failed') THEN datetime('now') ELSE NULL END, ?)
  `).run(entity, status, records, status, error);
}

module.exports = {
  getDb, initDatabase, upsertUsers, upsertApplications,
  upsertAppAssignments, upsertSystemLogs, logSync,
};

// ── Pruning ─────────────────────────────────────────────────
function pruneOldData() {
  const d = getDb();

  // Keep only last 30 days of system logs
  const logsBefore = new Date(Date.now() - 30 * 86_400_000).toISOString();
  const logsDeleted = d.prepare(
    'DELETE FROM system_logs WHERE published < ?'
  ).run(logsBefore).changes;

  // Keep only last 500 sync_status rows (trim oldest)
  const syncDeleted = d.prepare(`
    DELETE FROM sync_status WHERE id NOT IN (
      SELECT id FROM sync_status ORDER BY id DESC LIMIT 500
    )
  `).run().changes;

  return { logsDeleted, syncDeleted };
}

module.exports.pruneOldData = pruneOldData;
