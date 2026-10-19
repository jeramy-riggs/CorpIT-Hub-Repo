#!/usr/bin/env node
/**
 * Initializes the SQLite database schema.
 * Run: node scripts/setup-db.js
 */
require('dotenv').config();
const { initDatabase, getDb } = require('../server/db/database');

console.log('Initializing database…');
initDatabase();
const db = getDb();
const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all();
console.log('Tables created:', tables.map(t => t.name).join(', '));
console.log('Database setup complete.');
