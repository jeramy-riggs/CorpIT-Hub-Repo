'use strict';

// Existing account preferences, one independent row per guide. No browser or
// caller-supplied identity participates in the key. Replays never reset it.
const GUIDES = Object.freeze(['identity', 'inventory', 'network', 'cert', 'ai', 'migration', 'intune', 'myprofile']);
const PREFIX = 'guide_dismissed_';

function register(router, { pool, who, needUser }) {
  function self(req, res) {
    // devlabelkit 10-20: guides run on prod too (rbac_user_prefs exists on prod).
    if (!['dev-corpit.nrpi.local', 'dev-myprofile.nrpi.local', 'corpit.nrpi.local', 'myprofile.nrpi.local'].includes(req.hostname)) {
      res.status(404).json({ error: 'Not found' }); return false;
    }
    res.set('Cache-Control', 'no-store, private');
    return needUser(req, res);
  }
  router.get('/guides', async (req, res) => {
    if (!self(req, res)) return;
    try {
      const keys = GUIDES.map(id => PREFIX + id);
      const [rows] = await pool.query(
        'SELECT pref_key, pref_value FROM rbac_user_prefs WHERE email = ? AND pref_key IN (?)',
        [who(req), keys]);
      const dismissed = {};
      for (const row of rows) {
        const id = row.pref_key.slice(PREFIX.length);
        if (GUIDES.includes(id) && row.pref_value) dismissed[id] = true;
      }
      res.json({ dismissed });
    } catch (error) {
      console.error('[profile] GET /guides', error.message);
      res.status(503).json({ error: 'Guide status unavailable' });
    }
  });
  // Reset only the authenticated caller's eight onboarding preferences. This
  // inherits the profile router's authentication, CSRF and borrowed-view guards.
  router.post('/guides/reset', async (req, res) => {
    if (!self(req, res)) return;
    try {
      const [result] = await pool.query(
        'DELETE FROM rbac_user_prefs WHERE email = ? AND pref_key IN (?)',
        [who(req), GUIDES.map(id => PREFIX + id)]);
      res.json({ ok: true, removed: result.affectedRows });
    } catch (error) {
      console.error('[profile] POST /guides/reset', error.message);
      res.status(503).json({ error: 'Guides could not be reset. Please try again.' });
    }
  });
  router.put('/guides/:guide', async (req, res) => {
    if (!self(req, res)) return;
    const id = req.params.guide;
    if (!GUIDES.includes(id)) return res.status(400).json({ error: 'Unknown guide' });
    try {
      // Atomic and idempotent: concurrent dismissals from devices cannot lose
      // another guide's state or replace the first dismissal timestamp.
      await pool.query(
        'INSERT INTO rbac_user_prefs (email, pref_key, pref_value) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE pref_value = pref_value',
        [who(req), PREFIX + id, new Date().toISOString()]);
      res.json({ ok: true, guide: id, dismissed: true });
    } catch (error) {
      console.error('[profile] PUT /guides', error.message);
      res.status(503).json({ error: 'Guide dismissal could not be saved' });
    }
  });
}

module.exports = { register, GUIDES };
