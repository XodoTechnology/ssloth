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

const MASTER_KEY = loadMasterKey();

// Previous master key, env-only, used solely for key rotation: set
// SSLOTH_MASTER_KEY_OLD=<current key> together with a NEW SSLOTH_MASTER_KEY and
// every stored secret is re-encrypted with the new key at boot. Unset it once
// rotation completes — nothing happens unless both are configured.
const MASTER_KEY_OLD = process.env.SSLOTH_MASTER_KEY_OLD
  ? crypto.createHash('sha256').update(process.env.SSLOTH_MASTER_KEY_OLD, 'utf8').digest()
  : null;
if (MASTER_KEY_OLD && MASTER_KEY_OLD.equals(MASTER_KEY)) {
  console.warn('[ssloth] SSLOTH_MASTER_KEY_OLD equals SSLOTH_MASTER_KEY — rotation is a no-op.');
}

module.exports = {
  DATA_DIR,
  DB_PATH: path.join(DATA_DIR, 'ssloth.db'),
  MASTER_KEY,
  MASTER_KEY_OLD,
  PORT: parseInt(process.env.PORT || '8080', 10),
  BIND: process.env.BIND || '0.0.0.0',
  // Set to 'true' when terminating TLS in front (nginx/caddy). Marks cookies Secure.
  SECURE_COOKIES: process.env.SSLOTH_SECURE_COOKIES === 'true',
  // Desktop build: loopback-only single-user mode — skips the login wall
  // unless a quick-unlock PIN has been set.
  DESKTOP: process.env.SSLOTH_DESKTOP === '1',
  SESSION_TTL_MS: 7 * 24 * 60 * 60 * 1000, // 7 days, sliding
  // Server-side idle timeout: a session with no API/WS activity for this
  // long is deleted outright (the cookie's 7-day sliding TTL alone meant a
  // stolen cookie stayed useful for a week). 0 disables. Default 24h.
  SESSION_IDLE_MS: (() => {
    const h = parseInt(process.env.SSLOTH_SESSION_IDLE_HOURS ?? '24', 10);
    return (Number.isFinite(h) && h >= 0 ? h : 24) * 3600 * 1000;
  })(),
  WEB_DIST: process.env.SSLOTH_WEB_DIST || path.join(__dirname, '..', '..', 'web', 'dist'),
};
