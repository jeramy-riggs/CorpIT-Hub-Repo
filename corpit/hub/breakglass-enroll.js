#!/usr/bin/env node
// =====================================================================
// breakglass-enroll.js  (v1.0.0)
//
// ONE-TIME enrollment for the 'itam' break-glass account. Run over SSH:
//
//     sudo node /var/www/corpit-hub-api/breakglass-enroll.js
//
// What it does, in order:
//   1. Prompts for the password TWICE with echo suppressed (generate it
//      outside this terminal, in your password manager).
//   2. Generates a random 160-bit TOTP secret and renders the enrollment
//      QR directly in the terminal via qrencode (nothing written to disk,
//      nothing served over HTTP).
//   3. Waits for you to scan it and type a live 6-digit code; only a
//      correct code proceeds - so a secret your phone doesn't hold can
//      never be committed.
//   4. Appends ITAM_PASSWORD_HASH, ITAM_TOTP_SECRET and (if absent)
//      RBAC_SESSION_SECRET to /var/www/corpit-hub-api/.env, preserving 0600.
//      A timestamped .env backup is written to /var/backups/itam/ first.
//
// Re-running replaces the previous enrollment (with a confirmation
// prompt). Requires: qrencode (apt install qrencode), root (to write .env).
// =====================================================================

'use strict';

const crypto   = require('crypto');
const fs       = require('fs');
const os       = require('os');
const path     = require('path');
const readline = require('readline');
const { spawnSync } = require('child_process');

const ENV_PATH    = '/var/www/corpit-hub-api/.env';
const BACKUP_DIR  = '/var/backups/itam';
const ISSUER      = 'IT Command';
const ACCOUNT     = 'itam';
const TOTP_STEP_S = 30;
const TOTP_DIGITS = 6;

// ---------- small prompt helpers ---------------------------------------

function promptHidden(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    const stdin = process.stdin;
    process.stdout.write(question);
    const wasRaw = stdin.isRaw;
    stdin.setRawMode(true);
    let buf = '';
    const onData = (ch) => {
      const c = ch.toString('utf8');
      if (c === '\r' || c === '\n') {
        stdin.setRawMode(wasRaw || false);
        stdin.removeListener('data', onData);
        process.stdout.write('\n');
        rl.close();
        resolve(buf);
      } else if (c === '\u0003') {            // Ctrl-C
        process.stdout.write('\n');
        process.exit(130);
      } else if (c === '\u007f' || c === '\b') {
        buf = buf.slice(0, -1);
      } else {
        buf += c;
      }
    };
    stdin.on('data', onData);
  });
}

function promptVisible(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, (answer) => { rl.close(); resolve(answer.trim()); });
  });
}

// ---------- scrypt hashing ---------------------------------------------

const SCRYPT_N = 1 << 15;   // 32768
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEYLEN   = 64;

function hashPassword(plain) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16);
    crypto.scrypt(plain, salt, KEYLEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, maxmem: 256 * 1024 * 1024 }, (err, key) => {
      if (err) return reject(err);
      resolve(`scrypt$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${salt.toString('hex')}$${key.toString('hex')}`);
    });
  });
}

// ---------- TOTP --------------------------------------------------------

function base32Encode(buf) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0, out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}

function totpNow(secretBuf, offset = 0) {
  const step = Math.floor(Date.now() / 1000 / TOTP_STEP_S) + offset;
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const digest = crypto.createHmac('sha1', secretBuf).update(msg).digest();
  const o = digest[digest.length - 1] & 0x0f;
  const bin = ((digest[o] & 0x7f) << 24) | ((digest[o+1] & 0xff) << 16) | ((digest[o+2] & 0xff) << 8) | (digest[o+3] & 0xff);
  return String(bin % (10 ** TOTP_DIGITS)).padStart(TOTP_DIGITS, '0');
}

// ---------- .env editing -------------------------------------------------

function upsertEnvLines(content, updates) {
  const lines = content.split('\n');
  const seen = new Set();
  const out = lines.map((line) => {
    for (const [key, value] of Object.entries(updates)) {
      if (line.startsWith(key + '=')) { seen.add(key); return `${key}=${value}`; }
    }
    return line;
  });
  // trim trailing blank lines, then append missing keys
  while (out.length && out[out.length - 1].trim() === '') out.pop();
  for (const [key, value] of Object.entries(updates)) {
    if (!seen.has(key)) out.push(`${key}=${value}`);
  }
  out.push('');
  return out.join('\n');
}

// ---------- main ---------------------------------------------------------

async function main() {
  if (process.getuid && process.getuid() !== 0) {
    console.error('Run with sudo - writing ' + ENV_PATH + ' requires root.');
    process.exit(1);
  }
  if (!fs.existsSync(ENV_PATH)) {
    console.error('ABORT: ' + ENV_PATH + ' not found.');
    process.exit(1);
  }
  const qr = spawnSync('which', ['qrencode']);
  if (qr.status !== 0) {
    console.error('ABORT: qrencode not installed. Run: sudo apt install qrencode');
    process.exit(1);
  }

  const existing = fs.readFileSync(ENV_PATH, 'utf8');
  if (existing.includes('ITAM_PASSWORD_HASH=')) {
    const ans = await promptVisible('An itam enrollment already exists. Replace it? (type REPLACE to continue): ');
    if (ans !== 'REPLACE') {
      console.log('Aborted. Nothing changed.');
      process.exit(0);
    }
  }

  console.log('');
  console.log('=== itam break-glass enrollment ===');
  console.log('Generate the password OUTSIDE this terminal (password manager,');
  console.log('24+ random characters). It will not be echoed as you type.');
  console.log('');

  const p1 = await promptHidden('Password: ');
  if (p1.length < 16) {
    console.error('ABORT: password shorter than 16 characters. Use 24+.');
    process.exit(1);
  }
  const p2 = await promptHidden('Confirm:  ');
  if (p1 !== p2) {
    console.error('ABORT: passwords do not match. Nothing changed.');
    process.exit(1);
  }

  const passwordHash = await hashPassword(p1);

  // --- TOTP secret + terminal QR ---
  const secretBuf = crypto.randomBytes(20);           // 160-bit
  const secretB32 = base32Encode(secretBuf);
  const otpauth =
    `otpauth://totp/${encodeURIComponent(ISSUER)}:${encodeURIComponent(ACCOUNT)}` +
    `?secret=${secretB32}&issuer=${encodeURIComponent(ISSUER)}&algorithm=SHA1&digits=${TOTP_DIGITS}&period=${TOTP_STEP_S}`;

  console.log('');
  console.log('Scan this QR with your authenticator app:');
  console.log('');
  const render = spawnSync('qrencode', ['-t', 'UTF8', otpauth], { encoding: 'utf8' });
  if (render.status !== 0) {
    console.error('ABORT: qrencode failed: ' + (render.stderr || 'unknown'));
    process.exit(1);
  }
  process.stdout.write(render.stdout);
  console.log('');
  console.log('(If the QR does not scan, manual entry key: ' + secretB32 + ' )');
  console.log('');

  // --- verify a live code before committing anything ---
  let verified = false;
  for (let attempt = 1; attempt <= 3; attempt++) {
    const code = (await promptVisible(`Enter the current 6-digit code (attempt ${attempt}/3): `)).replace(/\s/g, '');
    if ([0, -1, 1].some(off => totpNow(secretBuf, off) === code)) { verified = true; break; }
    console.log('Code did not match. Wait for the next code and try again.');
  }
  if (!verified) {
    console.error('ABORT: could not verify a live code. Nothing was written -');
    console.error('delete the entry from your authenticator and re-run.');
    process.exit(1);
  }

  // --- backup .env, then write ---
  const stamp = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14);
  const backupPath = path.join(BACKUP_DIR, `.env.bak-${stamp}-pre-breakglass`);
  fs.copyFileSync(ENV_PATH, backupPath);
  fs.chmodSync(backupPath, 0o600);

  const updates = {
    ITAM_PASSWORD_HASH: passwordHash,
    ITAM_TOTP_SECRET:   secretB32,
  };
  if (!existing.includes('RBAC_SESSION_SECRET=')) {
    updates.RBAC_SESSION_SECRET = crypto.randomBytes(32).toString('hex');
  }

  const updated = upsertEnvLines(existing, updates);
  const tmp = ENV_PATH + '.tmp-' + process.pid;
  fs.writeFileSync(tmp, updated, { mode: 0o600 });
  fs.renameSync(tmp, ENV_PATH);
  fs.chmodSync(ENV_PATH, 0o600);

  console.log('');
  console.log('Enrollment complete.');
  console.log('  .env backup: ' + backupPath + ' (mode 0600)');
  console.log('  Written: ITAM_PASSWORD_HASH, ITAM_TOTP_SECRET' +
              (updates.RBAC_SESSION_SECRET ? ', RBAC_SESSION_SECRET' : ''));
  console.log('');
  console.log('NOW: store the password AND the manual entry key shown above in');
  console.log('the shared vault so the account survives you being unavailable.');
  console.log('Then: sudo -u ubuntu pm2 restart api-beta --update-env');
  console.log('Then clear this terminal (clear && history -c) - the QR and');
  console.log('manual key were displayed on screen.');
}

main().catch((e) => { console.error('FATAL:', e.message); process.exit(1); });
