'use strict';

const express = require('express');
const ssh2 = require('ssh2');
const { db } = require('../db');
const { encryptSecret } = require('../crypto');
const { auditReq } = require('../auth');

const router = express.Router();

function credView(row) {
  const { secret_enc, ...rest } = row;
  return { ...rest, has_secret: !!secret_enc };
}

// Derive the OpenSSH public key line ("ssh-ed25519 AAAA...") for a private key.
function publicKeyFor(privateKey, passphrase) {
  const parsed = ssh2.utils.parseKey(privateKey, passphrase);
  if (parsed instanceof Error) throw parsed;
  const key = Array.isArray(parsed) ? parsed[0] : parsed;
  if (!key || !key.getPublicSSH) throw new Error('unsupported key format');
  return `${key.type} ${key.getPublicSSH().toString('base64')}`;
}

router.get('/', (req, res) => {
  const rows = db
    .prepare('SELECT * FROM credentials WHERE user_id = ? ORDER BY name COLLATE NOCASE')
    .all(req.user.id);
  res.json({ credentials: rows.map(credView) });
});

router.post('/', (req, res) => {
  const { name, type, username, password, privateKey, passphrase, certificate, comment } = req.body || {};
  if (!name || String(name).trim().length === 0) return res.status(400).json({ error: 'name required' });
  if (!['password', 'key'].includes(type)) return res.status(400).json({ error: 'type must be password or key' });

  let secret, publicKey = null;
  if (type === 'password') {
    if (!password) return res.status(400).json({ error: 'password required' });
    secret = { password: String(password) };
  } else {
    if (!privateKey || !/PRIVATE KEY/.test(privateKey)) {
      return res.status(400).json({ error: 'privateKey (PEM/OpenSSH format) required' });
    }
    try {
      publicKey = publicKeyFor(privateKey, passphrase);
    } catch (e) {
      return res.status(400).json({
        error: 'could not parse private key' + (passphrase ? ' (check passphrase)' : ''),
      });
    }
    // OpenSSH user certificate (id-cert.pub line) — optional; enables
    // CA-signed auth on servers trusting the CA.
    let cert = null;
    if (certificate) {
      const parsed = ssh2.utils.parseKey(String(certificate));
      const c = Array.isArray(parsed) ? parsed[0] : parsed;
      if (!c || c instanceof Error || !/-cert-v0[01]@openssh\.com$/.test(c.type)) {
        return res.status(400).json({ error: 'certificate is not a valid OpenSSH user certificate' });
      }
      cert = String(certificate).trim();
    }
    secret = { privateKey: String(privateKey), passphrase: passphrase ? String(passphrase) : null, certificate: cert };
  }

  const info = db
    .prepare(
      'INSERT INTO credentials (user_id, name, type, username, secret_enc, public_key, comment) VALUES (?, ?, ?, ?, ?, ?, ?)'
    )
    .run(
      req.user.id,
      String(name).slice(0, 128),
      type,
      username ? String(username).slice(0, 64) : null,
      encryptSecret(JSON.stringify(secret)),
      publicKey,
      comment ? String(comment).slice(0, 500) : null
    );
  auditReq(req, 'credential.created', `${type} credential '${name}'`);
  const row = db.prepare('SELECT * FROM credentials WHERE id = ?').get(info.lastInsertRowid);
  res.json({ credential: credView(row), public_key: publicKey });
});

// Generate a fresh key pair (ed25519 or rsa) server-side.
router.post('/generate', (req, res) => {
  const { name, keyType = 'ed25519', bits, passphrase, comment } = req.body || {};
  if (!name || String(name).trim().length === 0) return res.status(400).json({ error: 'name required' });
  if (!['ed25519', 'rsa'].includes(keyType)) return res.status(400).json({ error: 'keyType must be ed25519 or rsa' });

  let privateKey, publicKey;
  try {
    const opts = {};
    if (keyType === 'rsa') opts.bits = Math.min(Math.max(parseInt(bits, 10) || 3072, 2048), 8192);
    if (passphrase) opts.passphrase = String(passphrase);
    const pair = ssh2.utils.generateKeyPairSync(keyType, opts);
    privateKey = pair.private.toString();
    publicKey = pair.public.toString();
  } catch (e) {
    return res.status(500).json({ error: 'key generation failed: ' + e.message });
  }

  const info = db
    .prepare(
      'INSERT INTO credentials (user_id, name, type, username, secret_enc, public_key, comment) VALUES (?, ?, ?, ?, ?, ?, ?)'
    )
    .run(
      req.user.id,
      String(name).slice(0, 128),
      'key',
      req.body.username ? String(req.body.username).slice(0, 64) : null,
      encryptSecret(JSON.stringify({ privateKey, passphrase: passphrase ? String(passphrase) : null })),
      publicKey,
      comment ? String(comment).slice(0, 500) : null
    );
  auditReq(req, 'credential.generated', `${keyType} key '${name}'`);
  const row = db.prepare('SELECT * FROM credentials WHERE id = ?').get(info.lastInsertRowid);
  res.json({ credential: credView(row), public_key: publicKey });
});

router.put('/:id', (req, res) => {
  const cred = db
    .prepare('SELECT * FROM credentials WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.user.id);
  if (!cred) return res.status(404).json({ error: 'not found' });

  const { name, username, comment, password, privateKey, passphrase, certificate } = req.body || {};
  const updates = [];
  const params = [];

  if (name !== undefined) { updates.push('name = ?'); params.push(String(name).slice(0, 128)); }
  if (username !== undefined) { updates.push('username = ?'); params.push(username ? String(username).slice(0, 64) : null); }
  if (comment !== undefined) { updates.push('comment = ?'); params.push(comment ? String(comment).slice(0, 500) : null); }

  if (cred.type === 'password' && password !== undefined && password !== '') {
    updates.push('secret_enc = ?');
    params.push(encryptSecret(JSON.stringify({ password: String(password) })));
  }
  if (cred.type === 'key' && privateKey) {
    try {
      const pub = publicKeyFor(privateKey, passphrase);
      const { decryptSecret } = require('../crypto');
      const prev = JSON.parse(decryptSecret(cred.secret_enc));
      updates.push('secret_enc = ?');
      params.push(encryptSecret(JSON.stringify({ privateKey: String(privateKey), passphrase: passphrase ? String(passphrase) : null, certificate: prev.certificate || null })));
      updates.push('public_key = ?');
      params.push(pub);
    } catch {
      return res.status(400).json({ error: 'could not parse private key' });
    }
  } else if (cred.type === 'key' && (passphrase !== undefined || certificate !== undefined)) {
    // Update passphrase and/or certificate on the existing key.
    const { decryptSecret } = require('../crypto');
    const secret = JSON.parse(decryptSecret(cred.secret_enc));
    if (passphrase !== undefined) secret.passphrase = passphrase ? String(passphrase) : null;
    if (certificate !== undefined) {
      if (!certificate) secret.certificate = null;
      else {
        const parsed = ssh2.utils.parseKey(String(certificate));
        const c = Array.isArray(parsed) ? parsed[0] : parsed;
        if (!c || c instanceof Error || !/-cert-v0[01]@openssh\.com$/.test(c.type)) {
          return res.status(400).json({ error: 'certificate is not a valid OpenSSH user certificate' });
        }
        secret.certificate = String(certificate).trim();
      }
    }
    updates.push('secret_enc = ?');
    params.push(encryptSecret(JSON.stringify(secret)));
  }

  if (!updates.length) return res.json({ credential: credView(cred) });
  db.prepare(`UPDATE credentials SET ${updates.join(', ')} WHERE id = ?`).run(...params, cred.id);
  const row = db.prepare('SELECT * FROM credentials WHERE id = ?').get(cred.id);
  res.json({ credential: credView(row) });
});

router.delete('/:id', (req, res) => {
  const cred = db
    .prepare('SELECT * FROM credentials WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.user.id);
  if (!cred) return res.status(404).json({ error: 'not found' });
  const inUse = db.prepare('SELECT COUNT(*) AS c FROM hosts WHERE credential_id = ?').get(cred.id).c;
  if (inUse > 0 && req.query.force !== '1') {
    return res.status(409).json({ error: `credential is used by ${inUse} host(s)`, in_use: inUse });
  }
  db.prepare('DELETE FROM credentials WHERE id = ?').run(cred.id);
  auditReq(req, 'credential.deleted', `${cred.type} credential '${cred.name}'`);
  res.json({ ok: true });
});

module.exports = router;
