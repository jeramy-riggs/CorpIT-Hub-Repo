'use strict';
/* sqlite-offload-worker.js — the thread side of sqlite-offload.js.
   Opens the file readonly, runs the statements it was handed in order on that
   one connection, posts a single reply and exits. Nothing here is reachable
   from a request except through sqlite-offload.query(). */
const { parentPort, workerData } = require('worker_threads');
const Database = require('better-sqlite3');

const t0 = Date.now();
let db = null;
try {
  db = new Database(workerData.dbPath, { readonly: true, fileMustExist: true, timeout: 5000 });
} catch (e) {
  parentPort.postMessage({ ok: false, status: 503, error: 'database not readable at ' + workerData.dbPath + ': ' + e.message });
}
if (db) {
  try {
    const results = (workerData.stmts || []).map((s) => {
      const stmt = db.prepare(s.sql);
      if (!stmt.readonly) throw new Error('offload refuses a statement that writes');
      const params = s.params === undefined ? [] : s.params;
      return s.mode === 'get' ? stmt.get(params) : stmt.all(params);
    });
    parentPort.postMessage({ ok: true, results, tookMs: Date.now() - t0 });
  } catch (e) {
    parentPort.postMessage({ ok: false, status: 500, error: e.message });
  } finally {
    try { db.close(); } catch (_) { /* already closed */ }
  }
}
