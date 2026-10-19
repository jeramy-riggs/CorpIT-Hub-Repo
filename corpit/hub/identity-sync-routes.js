'use strict';
/*
 * identity-sync-routes.js — routes for the identity-diag "Add to AD Group" and
 * "Force Replicate & Sync" controls. Registered onto the existing identity
 * router so it shares the same rbac middleware, cache, and /api/identity prefix.
 *
 *   GET  /api/identity/group-search?q=      (read)   type-ahead AD security groups
 *   POST /api/identity/add-to-group         (admin)  add user → group (guarded+audited)
 *   GET  /api/identity/sync-status?...       (read)   per-DC AD + Entra sync state
 *   POST /api/identity/sync/ad              (admin)  force single-object AD replication
 *   POST /api/identity/sync/entra           (admin)  trigger AAD Connect delta (debounced)
 */
const path = require('path');
const { execFile } = require('child_process');

const groupActions = require('./identity-group-actions');
const identitySync = require('./identity-sync');

const SYNC_SCRIPT = path.join(__dirname, 'sync-actions.py');

function runSync(args, timeoutMs) {
  return new Promise((resolve, reject) => {
    execFile('python3', [SYNC_SCRIPT, ...args], { timeout: timeoutMs, env: { ...process.env } }, (err, stdout, stderr) => {
      if (err && !stdout) {
        err.stderr = (stderr || '').slice(0, 300);
        return reject(err);
      }
      try { resolve(JSON.parse((stdout || '').trim())); }
      catch (e) { reject(new Error('Bad response from sync-actions: ' + (stdout || stderr || '').slice(0, 200))); }
    });
  });
}

function register(router, rbac, cache) {
  const clearCache = () => { try { cache && cache.clear && cache.clear(); } catch (e) {} };

  // ── Type-ahead AD security-group search ───────────────────────────────────
  router.get('/group-search', rbac.requirePage('identity-diag', 'read'), async (req, res) => {
    const q = (req.query.q || '').trim();
    if (q.length < 2) return res.json({ groups: [] });
    if (!/^[A-Za-z0-9 ._\-]{2,64}$/.test(q)) return res.status(400).json({ error: 'Invalid query', groups: [] });
    try {
      const groups = await groupActions.searchGroups(q, req.query.limit);
      res.json({ groups });
    } catch (e) {
      console.error('[identity-sync-routes] group-search:', e.message);
      res.status(500).json({ error: 'Group search failed', message: e.message, groups: [] });
    }
  });

  // ── Add user to an AD security group (guarded + audited) ───────────────────
  router.post('/add-to-group', rbac.requirePage('identity-diag', 'admin'), async (req, res) => {
    const identity = (req.body && req.body.identity || '').trim();
    const groupDN = (req.body && req.body.groupDN || '').trim();
    const groupName = (req.body && req.body.groupName || '').trim();
    if (!identity || !groupDN) return res.status(400).json({ success: false, error: 'identity and groupDN are required' });
    try {
      const result = await groupActions.addUserToGroup(identity, groupDN);
      clearCache();
      await rbac.audit(req, 'ad-group-add', identity, 'identity-diag', {
        group: result.group.name, groupDN: result.group.dn, already: result.already,
      });
      res.json(result);
    } catch (e) {
      if (e.code === 'PRIVILEGED') {
        await rbac.audit(req, 'ad-group-add-BLOCKED', identity, 'identity-diag', { groupDN, groupName: groupName || e.group, reason: e.message });
        return res.status(403).json({ success: false, error: e.message, blocked: true });
      }
      if (e.code === 'NOT_GROUP') return res.status(400).json({ success: false, error: e.message });
      console.error('[identity-sync-routes] add-to-group:', e.message);
      await rbac.audit(req, 'ad-group-add-ERROR', identity, 'identity-diag', { groupDN, error: e.message });
      res.status(500).json({ success: false, error: e.message });
    }
  });

  // ── Layered sync status (AD per-DC + Entra) for the modal ─────────────────
  router.get('/sync-status', rbac.requirePage('identity-diag', 'read'), async (req, res) => {
    const identity = (req.query.identity || '').trim();
    const upn = (req.query.upn || '').trim();
    if (!identity) return res.status(400).json({ error: 'identity is required' });
    if (!/^[A-Za-z0-9._\-$]{1,64}$/.test(identity)) return res.status(400).json({ error: 'Invalid identity' });

    const result = { ad: null, entra: null };
    const [adRes, entraRes] = await Promise.allSettled([
      runSync(['ad-status', identity], 60000),
      identitySync.entraUserStatus(upn || identity),
    ]);
    result.ad = adRes.status === 'fulfilled' ? adRes.value : { success: false, error: (adRes.reason && adRes.reason.message) || 'AD status failed' };
    result.entra = entraRes.status === 'fulfilled' ? entraRes.value : { error: (entraRes.reason && entraRes.reason.message) || 'Entra status failed' };
    res.json(result);
  });

  // ── Force single-object AD replication (per user, across DCs) ─────────────
  router.post('/sync/ad', rbac.requirePage('identity-diag', 'admin'), async (req, res) => {
    const identity = (req.body && req.body.identity || '').trim();
    if (!identity) return res.status(400).json({ success: false, error: 'identity is required' });
    if (!/^[A-Za-z0-9._\-$]{1,64}$/.test(identity)) return res.status(400).json({ success: false, error: 'Invalid identity' });
    try {
      const out = await runSync(['replicate', identity], 60000);
      await rbac.audit(req, 'ad-force-replicate', identity, 'identity-diag', { success: out.success, results: out.results });
      res.json(out);
    } catch (e) {
      console.error('[identity-sync-routes] sync/ad:', e.message);
      res.status(e.killed ? 504 : 500).json({ success: false, error: e.killed ? 'Replication timed out' : e.message });
    }
  });

  // ── Trigger AAD Connect delta sync (tenant-wide, debounced) ───────────────
  router.post('/sync/entra', rbac.requirePage('identity-diag', 'admin'), async (req, res) => {
    const gate = identitySync.entraDeltaGate();
    if (!gate.allowed) {
      return res.status(429).json({ success: false, debounced: true, waitSec: gate.waitSec,
        error: 'A delta sync was triggered recently — wait ' + gate.waitSec + 's before triggering again' });
    }
    try {
      const out = await runSync(['entra-delta'], 45000);
      if (out.success) identitySync.markEntraDelta();
      await rbac.audit(req, 'entra-delta-sync', (req.body && req.body.identity) || null, 'identity-diag',
        { success: out.success, alreadyRunning: out.alreadyRunning, result: out.result });
      res.json(out);
    } catch (e) {
      console.error('[identity-sync-routes] sync/entra:', e.message);
      res.status(e.killed ? 504 : 500).json({ success: false, error: e.killed ? 'Delta sync trigger timed out' : e.message });
    }
  });
}

module.exports = { register };
