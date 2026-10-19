'use strict';
// gal-paths.js - PATH-RELEASE-20260929. Where the directory-sync jobs keep their
// run state. Code, .env and the Exchange app certificate stay in /opt/gal-directory;
// everything the jobs or the console WRITE lives in one state directory that the HA
// build later bind-mounts from DRBD as a whole.
//
//   GAL_STATE_DIR   absolute; default /var/lib/gal-directory
//   GAL_STATE_JSON, GAL_HISTORY_JSON, GAL_ROSTER_JSON, GAL_LISTS_JSON,
//   GAL_EXCLUSIONS_JSON   historical per-file overrides, still honoured, but they
//                   must be absolute and may not point back into /opt/gal-directory
//
// Fail closed: a missing state directory throws at require time. A sync that cannot
// see lists.json / exclusions.json must not run on defaults (a missing exclusions
// file means "publish everyone").
const fs = require('fs');
const path = require('path');

const DEFAULT_STATE_DIR = '/var/lib/gal-directory';
const CODE_DIR = '/opt/gal-directory';

function _abs(name, value) {
  if (typeof value !== 'string' || !path.isAbsolute(value)) {
    throw new Error('[gal-paths] ' + name + ' must be an absolute path, got ' + JSON.stringify(value));
  }
  return path.normalize(value);
}

function _checkDir(name, dir) {
  if (dir === CODE_DIR) {
    throw new Error('[gal-paths] ' + name + ' points at the code directory ' + CODE_DIR +
      '; state moved to ' + DEFAULT_STATE_DIR + ' in PATH-RELEASE-20260929');
  }
  let st;
  try { st = fs.statSync(dir); } catch (e) {
    throw new Error('[gal-paths] ' + name + ': state directory ' + dir + ' is not available (' + (e.code || e.message) + ')');
  }
  if (!st.isDirectory()) throw new Error('[gal-paths] ' + name + ': ' + dir + ' is not a directory');
  return dir;
}

function stateDir(env) {
  env = env || process.env;
  const v = env.GAL_STATE_DIR;
  const dir = (v === undefined || v === '') ? DEFAULT_STATE_DIR : _abs('GAL_STATE_DIR', v);
  return _checkDir('GAL_STATE_DIR', dir);
}

function stateFile(basename, overrideEnvName, env) {
  env = env || process.env;
  const v = overrideEnvName ? env[overrideEnvName] : undefined;
  if (v !== undefined && v !== '') {
    const file = _abs(overrideEnvName, v);
    _checkDir(overrideEnvName, path.dirname(file));
    return file;
  }
  return path.join(stateDir(env), basename);
}

// The mutual-exclusion lock the timers (flock ExecStart, unit drop-ins) and the
// console's manual sync share. It lives with the state it protects.
function lockFile(env) { return path.join(stateDir(env), '.sync.lock'); }

module.exports = { stateDir, stateFile, lockFile, DEFAULT_STATE_DIR, CODE_DIR };
