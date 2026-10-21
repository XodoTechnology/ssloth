'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = process.env.SSLOTH_DATA_DIR || path.join(__dirname, '..', 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });
try {
  fs.chmodSync(DATA_DIR, 0o700);
} catch {}

// Master key used to encrypt all secrets at rest (credentials, private keys,
// TOTP secrets). Provide SSLOTH_MASTER_KEY (any string, hashed to 32 bytes) in
// production so the key is not stored next to the database. Otherwise a random
// key is generated once and persisted with 0600 permissions.
function loadMasterKey() {
  if (process.env.SSLOTH_MASTER_KEY) {
    if (process.env.SSLOTH_MASTER_KEY.length < 16) {
      console.warn('[ssloth] WARNING: SSLOTH_MASTER_KEY is short; use at least 32 random characters.');
    }
    return crypto.createHash('sha256').update(process.env.SSLOTH_MASTER_KEY, 'utf8').digest();
  }
  const keyPath = path.join(DATA_DIR, 'master.key');
  if (fs.existsSync(keyPath)) {
    const key = fs.readFileSync(keyPath);
    if (key.length !== 32) throw new Error('Corrupt master.key (expected 32 bytes)');
    return key;
  }
  const key = crypto.randomBytes(32);
  fs.writeFileSync(keyPath, key, { mode: 0o600 });
  console.warn('[ssloth] Generated data/master.key. Set SSLOTH_MASTER_KEY in the environment for production use.');
  return key;
}

module.exports = {
  DATA_DIR,
  DB_PATH: path.join(DATA_DIR, 'ssloth.db'),
  MASTER_KEY: loadMasterKey(),
  PORT: parseInt(process.env.PORT || '8080', 10),
  BIND: process.env.BIND || '0.0.0.0',
  // Set to 'true' when terminating TLS in front (nginx/caddy). Marks cookies Secure.
  SECURE_COOKIES: process.env.SSLOTH_SECURE_COOKIES === 'true',
  // Desktop build: loopback-only single-user mode — skips the login wall
  // unless a quick-unlock PIN has been set.
  DESKTOP: process.env.SSLOTH_DESKTOP === '1',
  SESSION_TTL_MS: 7 * 24 * 60 * 60 * 1000, // 7 days, sliding
  WEB_DIST: process.env.SSLOTH_WEB_DIST || path.join(__dirname, '..', '..', 'web', 'dist'),
};
