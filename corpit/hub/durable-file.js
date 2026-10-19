'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Linux durable replacement: sync contents/metadata before rename, then sync the
// parent directory. Failure after rename is ambiguous; callers must report it
// and must not restore the old file over a potentially durable new value.
function atomicWriteDurableSync(filename, data, mode = 0o600) {
  const directory = path.dirname(filename);
  const tmp = path.join(directory, '.' + path.basename(filename) + '.' +
    process.pid + '.' + crypto.randomBytes(12).toString('hex') + '.tmp');
  const dirFd = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try {
    const fd = fs.openSync(tmp, 'wx', mode);
    try {
      fs.writeFileSync(fd, data);
      fs.fchmodSync(fd, mode);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, filename);
    fs.fsyncSync(dirFd);
  } finally {
    try { fs.closeSync(dirFd); } finally {
      try { fs.unlinkSync(tmp); } catch (_) { /* absent after rename, or cleanup best effort */ }
    }
  }
}
module.exports = { atomicWriteDurableSync };
