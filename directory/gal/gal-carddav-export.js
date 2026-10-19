// =============================================================================
// gal-carddav-export.js - Option B: publish the GAL as a read-only CardDAV
// address book that iPhones subscribe to via an Intune-pushed config profile.
//
// Writes vCard 3.0 over HTTP to the local Radicale instance (127.0.0.1:5232)
// rather than poking its storage directory, so Radicale keeps its own etag and
// ctag bookkeeping correct and phones notice changes.
//
// This job is the ONLY writer to the collection, so it reconciles against a
// local state file instead of a PROPFIND. Use --resync after any manual
// tampering to force a full re-upload.
//
// Usage:
//   node gal-carddav-export.js                # dry run, prints the plan
//   node gal-carddav-export.js --apply
//   node gal-carddav-export.js --apply --resync
//
// Deps: gal-source.js, native fetch (Node 18+)
// =============================================================================

// dotenv is a convenience, not a requirement. On a box with no node_modules,
// fall back to parsing ./.env directly - same KEY=value semantics as systemd's
// EnvironmentFile, and unlike shell-sourcing it is safe for values containing
// regex metacharacters. Real environment variables always win.
try { require('dotenv').config(); } catch {
  try {
    for (const line of require('fs').readFileSync('.env', 'utf8').split('\n')) {
      const m = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line.trim());
      if (m && !(m[1] in process.env)) process.env[m[1]] = m[2];
    }
  } catch { /* no .env - env supplied by the caller */ }
}

const fs   = require('fs');
const path = require('path');
const { buildRoster, callCount } = require('./gal-source');

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------
const DAV_BASE  = process.env.GAL_DAV_BASE  || 'http://127.0.0.1:5232';
// The book lives inside the READER's principal home - Radicale only advertises
// address books that are direct children of /<login>/, and the phones log in as
// "directory". See setup-carddav.sh for the full reasoning.
const DAV_PATH  = process.env.GAL_DAV_PATH  || '/directory/company/';
const DAV_USER  = process.env.GAL_DAV_USER  || 'galsync';
const DAV_PASS  = process.env.GAL_DAV_PASS  || '';
// Written by the job's own user (ubuntu), not by the radicale service account,
// so it deliberately lives outside /opt/gal-carddav.
const STATE_FILE = process.env.GAL_DAV_STATE || '/var/lib/gal-carddav/state.json';

const args    = process.argv.slice(2);
const APPLY   = args.includes('--apply');
const RESYNC  = args.includes('--resync');

const AUTH = 'Basic ' + Buffer.from(`${DAV_USER}:${DAV_PASS}`).toString('base64');

// -----------------------------------------------------------------------------
// vCard 3.0 emitter
//
// Escaping and 75-octet line folding are not optional: an unescaped comma in a
// job title or an over-long PHOTO line will make iOS drop the whole card
// silently, and you will spend an afternoon wondering why one person is missing.
// -----------------------------------------------------------------------------
function esc(v) {
  if (v == null) return '';
  return String(v)
    .replace(/\\/g, '\\\\')
    .replace(/;/g, '\\;')
    .replace(/,/g, '\\,')
    .replace(/\r?\n/g, '\\n');
}

function fold(line) {
  const bytes = Buffer.from(line, 'utf8');
  if (bytes.length <= 75) return line;

  const out = [];
  let start = 0;
  let limit = 75;
  while (start < bytes.length) {
    let end = Math.min(start + limit, bytes.length);
    if (end < bytes.length) {
      // Never split a multi-byte UTF-8 sequence across a fold.
      while (end > start + 1 && (bytes[end] & 0xc0) === 0x80) end--;

      // Unfolding removes the CRLF *and* one following space. If a fold lands
      // so that a continuation line would begin with a space that belongs to
      // the value, that space is destroyed on unfold - so back up and let it
      // end the current line instead.
      while (end > start + 1 && bytes[end] === 0x20) {
        end--;
        while (end > start + 1 && (bytes[end] & 0xc0) === 0x80) end--;
      }
    }
    out.push(bytes.slice(start, end).toString('utf8'));
    start = end;
    limit = 74;   // continuation lines carry a leading space
  }
  return out.join('\r\n ');
}

function vcard(e, rev) {
  const lines = [
    'BEGIN:VCARD',
    'VERSION:3.0',
    `UID:${uidFor(e)}`,
    `FN:${esc(e.displayName)}`,
    `N:${esc(e.surname)};${esc(e.givenName)};;;`
  ];

  if (e.companyName || e.department) {
    lines.push(`ORG:${esc(e.companyName)}${e.department ? ';' + esc(e.department) : ''}`);
  }
  if (e.jobTitle) lines.push(`TITLE:${esc(e.jobTitle)}`);
  if (e.mail)     lines.push(`EMAIL;TYPE=INTERNET,WORK,PREF:${esc(e.mail)}`);

  for (const p of e.businessPhones) lines.push(`TEL;TYPE=WORK,VOICE:${esc(p)}`);
  if (e.mobilePhone) lines.push(`TEL;TYPE=CELL,VOICE:${esc(e.mobilePhone)}`);

  if (e.street || e.city || e.state || e.postalCode || e.country) {
    lines.push('ADR;TYPE=WORK:;;' + [e.street, e.city, e.state, e.postalCode, e.country]
      .map(esc).join(';'));
  }
  if (e.officeLocation) lines.push(`NOTE:${esc('Office: ' + e.officeLocation)}`);

  lines.push('CATEGORIES:Company Directory');
  lines.push(`REV:${rev}`);
  lines.push('END:VCARD');

  return lines.map(fold).join('\r\n') + '\r\n';
}

function uidFor(e) { return `nrpi-gal-${e.id}`; }

// -----------------------------------------------------------------------------
// State (uid -> hash) - lets us PUT only what actually changed
// -----------------------------------------------------------------------------
function loadState() {
  try {
    return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
  } catch {
    return {};
  }
}

function saveState(state) {
  fs.mkdirSync(path.dirname(STATE_FILE), { recursive: true });
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}

// -----------------------------------------------------------------------------
// CardDAV writes
// -----------------------------------------------------------------------------
async function davPut(uid, body) {
  const res = await fetch(`${DAV_BASE}${DAV_PATH}${uid}.vcf`, {
    method: 'PUT',
    headers: { Authorization: AUTH, 'Content-Type': 'text/vcard; charset=utf-8' },
    body
  });
  if (!res.ok) throw new Error(`PUT ${uid} -> ${res.status} ${(await res.text()).slice(0, 200)}`);
}

async function davDelete(uid) {
  const res = await fetch(`${DAV_BASE}${DAV_PATH}${uid}.vcf`, {
    method: 'DELETE',
    headers: { Authorization: AUTH }
  });
  // 404 means it is already gone - that is the state we wanted.
  if (!res.ok && res.status !== 404) {
    throw new Error(`DELETE ${uid} -> ${res.status} ${(await res.text()).slice(0, 200)}`);
  }
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------
async function main() {
  const started = Date.now();
  console.log(`[gal-dav] ${new Date().toISOString()} mode=${APPLY ? 'APPLY' : 'DRY-RUN'}${RESYNC ? ' resync' : ''}`);

  if (APPLY && !DAV_PASS) throw new Error('GAL_DAV_PASS is not set');

  const roster = await buildRoster();
  const state  = RESYNC ? {} : loadState();

  // One REV for the whole run keeps cards byte-stable between unchanged runs.
  const rev = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');

  const puts = [];
  const live = new Set();
  for (const e of roster) {
    const uid = uidFor(e);
    live.add(uid);
    if (state[uid] !== e.hash) puts.push({ uid, hash: e.hash, body: vcard(e, rev) });
  }
  const dels = Object.keys(state).filter(uid => !live.has(uid));

  console.log(`[gal-dav] roster ${roster.length} | put ${puts.length} | delete ${dels.length}`);

  if (!APPLY) {
    for (const d of dels) console.log(`  - ${d}`);
    console.log('[gal-dav] dry run - nothing written. Re-run with --apply to commit.');
    return;
  }

  const next = RESYNC ? {} : { ...state };
  let failed = 0;

  for (const p of puts) {
    try { await davPut(p.uid, p.body); next[p.uid] = p.hash; }
    catch (err) { failed++; console.error('  ' + err.message); }
  }
  for (const uid of dels) {
    try { await davDelete(uid); delete next[uid]; }
    catch (err) { failed++; console.error('  ' + err.message); }
  }

  // Carry forward untouched entries on a resync so state stays complete.
  if (RESYNC) for (const e of roster) if (next[uidFor(e)] === undefined) next[uidFor(e)] = e.hash;

  saveState(next);
  console.log(`[gal-dav] done in ${Math.round((Date.now() - started) / 1000)}s, ` +
              `${callCount()} Graph calls, ${failed} failures`);
  if (failed) process.exitCode = 1;
}

main().catch(err => {
  console.error('[gal-dav] FATAL:', err.message);
  process.exit(1);
});
