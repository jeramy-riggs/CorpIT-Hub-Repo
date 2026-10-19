/**
 * Sync Service
 * Pulls data from Okta APIs and normalizes it into the local SQLite cache.
 */
const okta = require('./okta-client');
const db = require('../db/database');
const { pruneOldData } = require('../db/database');
const logger = require('../utils/logger');

const PASSWORD_MAX_AGE = parseInt(process.env.PASSWORD_MAX_AGE_DAYS || '90', 10);

// ── Normalize User ──────────────────────────────────────────
function normalizeUser(u) {
  const profile = u.profile || {};
  const creds = u.credentials || {};
  const lastPwChange = creds.password?.value
    ? null // Okta never exposes raw password
    : (u.passwordChanged || null);

  let pwExpiry = null;
  if (lastPwChange) {
    const d = new Date(lastPwChange);
    d.setDate(d.getDate() + PASSWORD_MAX_AGE);
    pwExpiry = d.toISOString();
  }

  return {
    id: u.id,
    login: profile.login || '',
    email: profile.email || '',
    firstName: profile.firstName || '',
    lastName: profile.lastName || '',
    displayName: `${profile.firstName || ''} ${profile.lastName || ''}`.trim(),
    status: u.status || '',
    created: u.created || null,
    activated: u.activated || null,
    lastLogin: u.lastLogin || null,
    statusChanged: u.statusChanged || null,
    lastPasswordChange: lastPwChange,
    passwordExpiryEstimate: pwExpiry,
    lockedOut: u.status === 'LOCKED_OUT' ? 1 : 0,
    department: profile.department || '',
    title: profile.title || '',
    manager: profile.manager || '',
  };
}

// ── Normalize Application ───────────────────────────────────
function normalizeApp(a) {
  const logo = (a._links?.logo || []);
  return {
    id: a.id,
    name: a.name || '',
    label: a.label || '',
    status: a.status || '',
    signOnMode: a.signOnMode || '',
    logoUrl: logo.length > 0 ? logo[0].href : '',
    created: a.created || null,
    lastUpdated: a.lastUpdated || null,
    assignedUserCount: 0,
    assignedGroupCount: 0,
  };
}

// ── Normalize App Assignment ────────────────────────────────
function normalizeAssignment(appId, au) {
  return {
    id: `${appId}_${au.id}`,
    appId,
    userId: au.id,
    userLogin: (au.credentials?.userName || au.profile?.email || ''),
    scope: au.scope || 'USER',
    status: au.status || '',
    lastSync: au.lastSync || null,
  };
}

// ── Normalize System Log ────────────────────────────────────
function normalizeLog(log) {
  const actor = log.actor || {};
  const targets = log.target || [];
  const t = targets[0] || {};
  const client = log.client || {};
  const geo = client.geographicalContext || {};

  return {
    uuid: log.uuid,
    actorId: actor.id || '',
    actorLogin: actor.alternateId || '',
    eventType: log.eventType || '',
    displayMessage: log.displayMessage || '',
    severity: log.severity || '',
    published: log.published || '',
    targetId: t.id || '',
    targetType: t.type || '',
    targetName: t.displayName || '',
    clientIp: client.ipAddress || '',
    clientGeo: geo.city ? `${geo.city}, ${geo.state || ''}` : '',
    outcome: (log.outcome?.result) || '',
  };
}

// ── Sync Users ──────────────────────────────────────────────
async function syncUsers() {
  db.logSync('users', 'running');
  try {
    const raw = await okta.fetchUsers();
    const normalized = raw.map(normalizeUser);
    db.upsertUsers(normalized);
    db.logSync('users', 'completed', normalized.length);
    logger.info(`Synced ${normalized.length} users`);
    return normalized.length;
  } catch (err) {
    db.logSync('users', 'failed', 0, err.message);
    throw err;
  }
}

// ── Sync Applications + Assignments ─────────────────────────
async function syncApps() {
  db.logSync('applications', 'running');
  try {
    const raw = await okta.fetchApplications();
    // Only sync ACTIVE apps to reduce noise
    const active = raw.filter(a => a.status === 'ACTIVE');
    const normalized = active.map(normalizeApp);

    // Fetch per-app user assignments (parallel in batches of 5)
    const allAssignments = [];
    for (let i = 0; i < normalized.length; i += 5) {
      const batch = normalized.slice(i, i + 5);
      const results = await Promise.allSettled(
        batch.map(async (app) => {
          const users = await okta.fetchAppUsers(app.id);
          app.assignedUserCount = users.length;
          return users.map(u => normalizeAssignment(app.id, u));
        })
      );
      for (const r of results) {
        if (r.status === 'fulfilled') allAssignments.push(...r.value);
      }
    }

    db.upsertApplications(normalized);
    if (allAssignments.length > 0) db.upsertAppAssignments(allAssignments);
    db.logSync('applications', 'completed', normalized.length);
    logger.info(`Synced ${normalized.length} apps, ${allAssignments.length} assignments`);
    return normalized.length;
  } catch (err) {
    db.logSync('applications', 'failed', 0, err.message);
    throw err;
  }
}

// ── Sync System Logs (last 7 days) ──────────────────────────
async function syncLogs() {
  db.logSync('logs', 'running');
  try {
    const until = new Date().toISOString();
    const since = new Date(Date.now() - 7 * 86_400_000).toISOString();
    const raw = await okta.fetchSystemLogs(since, until);
    const normalized = raw.map(normalizeLog);
    if (normalized.length > 0) db.upsertSystemLogs(normalized);
    db.logSync('logs', 'completed', normalized.length);
    logger.info(`Synced ${normalized.length} log events`);
    return normalized.length;
  } catch (err) {
    db.logSync('logs', 'failed', 0, err.message);
    throw err;
  }
}

// ── Full Sync ───────────────────────────────────────────────
async function syncAll() {
  logger.info('Starting full Okta sync…');
  const results = { users: 0, apps: 0, logs: 0 };
  const errors = [];

  try { results.users = await syncUsers(); }
  catch (err) { errors.push(`users: ${err.message}`); logger.error(`User sync failed: ${err.message}`); }

  try { results.apps = await syncApps(); }
  catch (err) { errors.push(`apps: ${err.message}`); logger.error(`App sync failed: ${err.message}`); }

  try { results.logs = await syncLogs(); }
  catch (err) { errors.push(`logs: ${err.message}`); logger.error(`Log sync failed: ${err.message}`); }

  if (errors.length > 0) {
    logger.warn(`Sync completed with ${errors.length} error(s): ${errors.join('; ')}`);
  }
  // Prune stale data after EVERY sync attempt. Moved ahead of the total-failure
  // throw 2026-08-24: retention must NOT depend on Okta/sync success, or a dead
  // token lets system_logs grow unbounded (1.93M stale rows / ~1GB by 2026-08-24).
  try {
    const pruned = pruneOldData();
    if (pruned.logsDeleted > 0 || pruned.syncDeleted > 0) {
      logger.info('Pruned old data', pruned);
    }
  } catch (err) { logger.warn('Prune failed: ' + err.message); }

  if (errors.length === 3) {
    // All three failed — propagate so the caller knows the sync was a total failure
    throw new Error(`All sync steps failed: ${errors.join('; ')}`);
  }

  logger.info('Full sync completed', results);
  return results;
}

module.exports = { syncAll, syncUsers, syncApps, syncLogs };
