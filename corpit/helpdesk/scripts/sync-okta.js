#!/usr/bin/env node
/**
 * Manual Okta data sync.
 * Run: node scripts/sync-okta.js
 */
require('dotenv').config();
const { initDatabase } = require('../server/db/database');
const { syncAll } = require('../server/services/sync-service');

(async () => {
  console.log('Initializing database…');
  initDatabase();
  console.log('Starting full Okta sync…');
  try {
    const results = await syncAll();
    console.log('Sync complete:', results);
  } catch (err) {
    console.error('Sync failed:', err.message);
    process.exit(1);
  }
})();
