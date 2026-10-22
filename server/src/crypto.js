'use strict';

const crypto = require('crypto');
const { MASTER_KEY } = require('./config');

const { promisify } = require('util');
const scryptAsync = promisify(crypto.scrypt);

const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEYLEN = 64;

// ---- Password hashing (scrypt) ----
// Async so logins/PIN checks don't stall the event loop (terminal I/O) —
// N=16384 takes ~50-100ms per derivation.
async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = await scryptAsync(password, salt, SCRYPT_KEYLEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
  });
  return `scrypt$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

async function verifyPassword(password, stored) {
  try {
    const [scheme, n, r, p, saltB64, hashB64] = String(stored).split('$');
    if (scheme !== 'scrypt') return false;
    const salt = Buffer.from(saltB64, 'base64');
    const expected = Buffer.from(hashB64, 'base64');
    const actual = await scryptAsync(password, salt, expected.length, {
      N: parseInt(n, 10),
      r: parseInt(r, 10),
      p: parseInt(p, 10),
    });
    return crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

// Dummy hash so login timing does not reveal whether a username exists.
// Sync is fine here — it runs once at module load, before the server listens.
const DUMMY_HASH = (() => {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(crypto.randomBytes(16).toString('hex'), salt, SCRYPT_KEYLEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
  });
  return `scrypt$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${salt.toString('base64')}$${hash.toString('base64')}`;
})();

// ---- Secret encryption at rest (AES-256-GCM) ----
// Layout: base64( iv[12] | tag[16] | ciphertext )

function encryptSecret(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', MASTER_KEY, iv);
  const ct = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]).toString('base64');
}

function decryptSecret(encoded) {
  if (encoded == null || encoded === '') return null;
  const buf = Buffer.from(encoded, 'base64');
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const ct = buf.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', MASTER_KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

// ---- Misc helpers ----

function randomToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function sha256(input) {
  return crypto.createHash('sha256').update(input).digest();
}

function sha256B64(input) {
  return crypto.createHash('sha256').update(input).digest('base64');
}

// SSH host key fingerprint in the familiar OpenSSH format: "SHA256:xxxx"
function hostKeyFingerprint(keyBuffer) {
  return 'SHA256:' + crypto.createHash('sha256').update(keyBuffer).digest('base64').replace(/=+$/, '');
}

// ---- TOTP (RFC 6238, HMAC-SHA1) ----

const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buf) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(str) {
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of str.toUpperCase().replace(/=+$/, '').replace(/\s/g, '')) {
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function totpCode(secretB32, timeStepOffset = 0) {
  const key = base32Decode(secretB32);
  const counter = Math.floor(Date.now() / 1000 / 30) + timeStepOffset;
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', key).update(msg).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(code % 1000000).padStart(6, '0');
}

function generateTotpSecret() {
  return base32Encode(crypto.randomBytes(20));
}

// Returns the matched 30s time-step counter on success (for replay
// prevention — store it and reject counters <= it), or false on mismatch.
function verifyTotp(secretB32, code) {
  const clean = String(code || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(clean)) return false;
  const now = Math.floor(Date.now() / 1000 / 30);
  for (const offset of [-1, 0, 1]) {
    const expected = totpCode(secretB32, offset);
    if (crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(clean))) return now + offset;
  }
  return false;
}

module.exports = {
  hashPassword,
  verifyPassword,
  DUMMY_HASH,
  encryptSecret,
  decryptSecret,
  randomToken,
  sha256,
  sha256B64,
  hostKeyFingerprint,
  generateTotpSecret,
  verifyTotp,
};
