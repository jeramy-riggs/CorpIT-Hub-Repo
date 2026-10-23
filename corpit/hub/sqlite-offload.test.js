'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Database = require('better-sqlite3');
const offload = require('./sqlite-offload');

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

test('expired cached reads return a labelled snapshot while refresh runs', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sqlite-offload-'));
  const file = path.join(dir, 'test.db');
  const db = new Database(file);
  const opts = {
    cacheKey: 'stale-' + process.pid,
    cacheTtlMs: 500,
    staleTtlMs: 2000,
    retryDelayMs: 50,
    timeoutMs: 2000,
  };
  const read = () => offload.query(file, [{ sql: 'SELECT v FROM t', mode: 'get' }], opts);
  try {
    db.exec('CREATE TABLE t(v INTEGER); INSERT INTO t VALUES (1)');
    const first = await read();
    assert.equal(first.ok, true);
    assert.equal(first.results[0].v, 1);
    assert.equal(first.stale, undefined);

    db.exec('UPDATE t SET v=2');
    await sleep(550);
    const stale = await read();
    assert.equal(stale.ok, true);
    assert.equal(stale.results[0].v, 1);
    assert.equal(stale.stale, true);

    let fresh;
    for (let i = 0; i < 20; i++) {
      await sleep(25);
      fresh = await read();
      if (fresh.results[0].v === 2 && !fresh.stale) break;
    }
    assert.equal(fresh.results[0].v, 2);
    assert.equal(fresh.stale, undefined);
    assert.ok(fresh.cachedAt >= first.cachedAt);

    db.exec('UPDATE t SET v=3');
    offload.invalidate(opts.cacheKey);
    const afterInvalidate = await read();
    assert.equal(afterInvalidate.results[0].v, 3);
    assert.equal(afterInvalidate.stale, undefined);
  } finally {
    db.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
