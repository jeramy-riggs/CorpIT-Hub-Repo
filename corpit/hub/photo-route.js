// =============================================================================
// photo-route.js — Microsoft Graph user profile photo proxy with disk cache
// Mounted at /api/photo in server.js
//
// Returns a user's Entra/Office 365 profile photo as JPEG bytes.
//
// Cache: 7 days on disk at /var/www/corpit-hub-api/cache/photos/
//        Filename = sha256(upn).slice(0,16) + '.bin'   (hashed for path safety)
//        404s are cached too (negative caching) to avoid hammering Graph for
//        users who have no photo uploaded.
//
// Auth: reuses getAccessToken() from entra-sync.js. No new credentials.
//
// Required Graph permission: User.Read.All (Application) — already granted on
// the IT-Command-IdentityDiag app registration (3836db07).
// =============================================================================

const express = require('express');
const router = express.Router();
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const { getAccessToken } = require('./entra-sync');

const CACHE_DIR     = path.join(__dirname, 'cache', 'photos');
const CACHE_TTL_MS  = 7 * 24 * 60 * 60 * 1000;       // 7 days
const PHOTO_SIZE    = '240x240';                      // Graph offers 48,64,96,120,240,360,432,504,648
const GRAPH_BASE    = 'https://graph.microsoft.com/v1.0';
const NEG_MARKER    = Buffer.from('__NO_PHOTO__');    // sentinel for negative cache

// UPN validation: standard email-like pattern
const UPN_RE = /^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$/;

// Best-effort: ensure cache dir exists at startup. If creation fails the
// route still works (each request also tries to write through), it just
// logs the failure once at boot.
fs.mkdir(CACHE_DIR, { recursive: true }).catch(err => {
  console.error('[photo-route] cache dir init failed:', err.message);
});

function cachePathFor(upn) {
  const hash = crypto.createHash('sha256').update(upn.toLowerCase()).digest('hex').slice(0, 16);
  return path.join(CACHE_DIR, hash + '.bin');
}

async function readCacheIfFresh(file) {
  try {
    const stat = await fs.stat(file);
    if (Date.now() - stat.mtimeMs > CACHE_TTL_MS) return null; // expired
    return await fs.readFile(file);
  } catch {
    return null; // not cached
  }
}

async function writeCache(file, data) {
  try {
    await fs.writeFile(file, data);
  } catch (err) {
    console.error('[photo-route] cache write failed:', err.message);
  }
}

async function fetchFromGraph(upn) {
  const token = await getAccessToken();
  const url = `${GRAPH_BASE}/users/${encodeURIComponent(upn)}/photos/${PHOTO_SIZE}/$value`;
  const res = await fetch(url, {
    headers: { Authorization: 'Bearer ' + token }
  });
  if (res.status === 404) return null;        // user has no photo
  if (res.status === 401) {                   // token went stale unexpectedly
    throw new Error('Graph 401 — token issue');
  }
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Graph ${res.status}: ${text.slice(0, 200)}`);
  }
  return Buffer.from(await res.arrayBuffer());
}

router.get('/', async (req, res) => {
  const upn = String(req.query.upn || '').trim();
  if (!UPN_RE.test(upn)) {
    return res.status(400).json({ ok: false, error: 'invalid upn' });
  }

  const cacheFile = cachePathFor(upn);

  try {
    // Cache hit?
    const cached = await readCacheIfFresh(cacheFile);
    if (cached) {
      if (cached.equals(NEG_MARKER)) {
        return res.status(404).end();
      }
      res.set('Content-Type', 'image/jpeg');
      res.set('Cache-Control', 'private, max-age=86400'); // browser-side cache 1 day
      return res.end(cached);
    }

    // Cache miss — go to Graph
    const photo = await fetchFromGraph(upn);
    if (photo === null) {
      // No photo — record negative result so we don't re-ask for 7 days
      await writeCache(cacheFile, NEG_MARKER);
      return res.status(404).end();
    }
    await writeCache(cacheFile, photo);
    res.set('Content-Type', 'image/jpeg');
    res.set('Cache-Control', 'private, max-age=86400');
    return res.end(photo);
  } catch (err) {
    console.error('[photo-route]', upn, err.message);
    return res.status(502).json({ ok: false, error: 'photo fetch failed' });
  }
});

module.exports = router;
