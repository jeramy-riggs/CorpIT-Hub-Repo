'use strict';
// corpit-paths.js - PATH-RELEASE-20260929. The one place the hub, the gate, the
// inventory API (/var/www/api, via symlinked modules that resolve here) and the pm2
// workers learn where replicated state lives. Every path below is a whole directory
// that the HA build later bind-mounts from DRBD, so nothing here may point back into
// a code dir or a node-local home.
//
// Fail closed: a missing state directory throws at require time. A process that
// cannot see its state must not start and quietly run on an empty denylist or on
// defaults.
const fs = require('fs');
const path = require('path');

const DEFAULT_SESSION_DIR = '/var/lib/corpit-session';
const DEFAULT_SHARED_DIR = '/etc/corpit/shared';
// Legacy homes. Refused so a stale env value cannot split readers across two files.
const LEGACY_SESSION_DIRS = ['/var/lib/corpit', '/var/www/corpit-hub-api', '/var/www/api'];
const LEGACY_SHARED_DIRS = ['/etc/corpit'];

function _abs(name, value) {
  if (typeof value !== 'string' || !path.isAbsolute(value)) {
    throw new Error('[corpit-paths] ' + name + ' must be an absolute path, got ' + JSON.stringify(value));
  }
  return path.normalize(value);
}

function _dirMustExist(name, dir) {
  let st;
  try { st = fs.statSync(dir); } catch (e) {
    throw new Error('[corpit-paths] ' + name + ': state directory ' + dir + ' is not available (' + (e.code || e.message) + ')');
  }
  if (!st.isDirectory()) throw new Error('[corpit-paths] ' + name + ': ' + dir + ' is not a directory');
  return dir;
}

function _refuse(name, dir, legacy) {
  if (legacy.indexOf(dir) !== -1) {
    throw new Error('[corpit-paths] ' + name + ' points at legacy directory ' + dir + '; state moved in PATH-RELEASE-20260929');
  }
}

// SESSION_REVOKE_FILE (absolute) overrides; default is the replicated session dir.
// The lock is always REVOKE_FILE + '.lock' (session-auth.js), so it moves with it.
function sessionRevokeFile(env) {
  env = env || process.env;
  const v = env.SESSION_REVOKE_FILE;
  const file = (v === undefined || v === '')
    ? path.join(DEFAULT_SESSION_DIR, 'revoked-sessions.json')
    : _abs('SESSION_REVOKE_FILE', v);
  const dir = path.dirname(file);
  _refuse('SESSION_REVOKE_FILE', dir, LEGACY_SESSION_DIRS);
  _dirMustExist('SESSION_REVOKE_FILE', dir);
  return file;
}

// CORPIT_SHARED_DIR overrides the console-settings directory.
function sharedDir(env) {
  env = env || process.env;
  const v = env.CORPIT_SHARED_DIR;
  const dir = (v === undefined || v === '') ? DEFAULT_SHARED_DIR : _abs('CORPIT_SHARED_DIR', v);
  _refuse('CORPIT_SHARED_DIR', dir, LEGACY_SHARED_DIRS);
  return _dirMustExist('CORPIT_SHARED_DIR', dir);
}

// One console-settings file. The historical per-file override (OBS_CONFIG_PATH,
// SPEND_ALERT_CONFIG_PATH, REPORTING_RETURN_CONFIG_PATH, SITE_ACCESS_POLICY) still
// wins, but it must be absolute, outside /etc/corpit itself, and its dir must exist.
// A missing FILE is fine: every reader already treats ENOENT as "not published".
function sharedFile(basename, overrideEnvName, env) {
  env = env || process.env;
  if (typeof basename !== 'string' || basename.indexOf('/') !== -1 || !basename) {
    throw new Error('[corpit-paths] bad settings file name ' + JSON.stringify(basename));
  }
  const v = overrideEnvName ? env[overrideEnvName] : undefined;
  if (v !== undefined && v !== '') {
    const file = _abs(overrideEnvName, v);
    const dir = path.dirname(file);
    _refuse(overrideEnvName, dir, LEGACY_SHARED_DIRS);
    _dirMustExist(overrideEnvName, dir);
    return file;
  }
  return path.join(sharedDir(env), basename);
}

module.exports = {
  sessionRevokeFile, sharedDir, sharedFile,
  DEFAULT_SESSION_DIR, DEFAULT_SHARED_DIR,
};
