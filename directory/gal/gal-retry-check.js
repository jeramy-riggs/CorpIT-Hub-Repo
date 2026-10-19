// Exit 0 if a retry sync is warranted (someone errored or is awaiting first
// fill), exit 1 to skip. Used as a systemd ExecCondition so the retry timer is
// silent and free when everything is green. Reads only local files.
//
// PATH-RELEASE-20260929: state lives in the directory gal-paths.js resolves
// (default /var/lib/gal-directory). If that directory is missing, exit 255: for an
// ExecCondition, 1-254 means "skip quietly" and 255 marks the unit FAILED, which is
// what an unreadable state directory must look like.
const fs = require('fs');
let STATE, LISTS, EXCL;
try {
  const galPaths = require('./gal-paths');
  STATE = galPaths.stateFile('state.json', 'GAL_STATE_JSON');
  LISTS = galPaths.stateFile('lists.json', 'GAL_LISTS_JSON');
  EXCL  = galPaths.stateFile('exclusions.json', 'GAL_EXCLUSIONS_JSON');
} catch (err) {
  console.error('retry: ' + err.message);
  process.exit(255);
}

let state = null, lists = [];
try { state = JSON.parse(fs.readFileSync(STATE, 'utf8')); } catch { process.exit(0); } // no run yet -> run
try { lists = JSON.parse(fs.readFileSync(LISTS, 'utf8')); } catch { process.exit(1); }

const targets = state.targets || [];
if (targets.some(t => t.error)) { console.log('retry: targets with errors'); process.exit(0); }

// A rule added on the console after the last run started has not been applied
// yet. The console kicks a sync itself, but if that failed or the console was
// down this is the backstop that still gets the card off the phones.
try {
  const exMtime = fs.statSync(EXCL).mtime.toISOString();
  if (!state.startedAt || exMtime > state.startedAt) { console.log('retry: exclusions changed since the last run'); process.exit(0); }
} catch { /* no exclusions file */ }

const known = new Set(targets.map(t => String(t.upn || '').toLowerCase()));
for (const l of lists.filter(l => l.enabled !== false)) {
  for (const upn of l.recipients || []) {
    if (!known.has(upn.toLowerCase())) { console.log('retry: pending recipient ' + upn); process.exit(0); }
  }
}
console.log('all green - skip');
process.exit(1);
