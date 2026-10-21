'use strict';

const express = require('express');
const crypto = require('crypto');
const { db } = require('../db');
const { encryptSecret, decryptSecret } = require('../crypto');
const { auditReq } = require('../auth');

const router = express.Router();

// ---- passphrase-sealed secrets for portable export ----

function sealSecrets(obj, passphrase) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(String(passphrase), salt, 32, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(JSON.stringify(obj), 'utf8'), cipher.final()]);
  return {
    kdf: 'scrypt',
    salt: salt.toString('base64'),
    blob: Buffer.concat([iv, cipher.getAuthTag(), ct]).toString('base64'),
  };
}

function unsealSecrets(sealed, passphrase) {
  if (!sealed || sealed.kdf !== 'scrypt') throw new Error('bad sealed blob');
  const salt = Buffer.from(sealed.salt, 'base64');
  const key = crypto.scryptSync(String(passphrase || ''), salt, 32, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  const buf = Buffer.from(sealed.blob, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, buf.subarray(0, 12));
  decipher.setAuthTag(buf.subarray(12, 28));
  const pt = Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]);
  return JSON.parse(pt.toString('utf8'));
}

// ---- Export ----
// POST /api/export { include_credentials, passphrase }
// Secrets (credential bodies, inline host passwords) are sealed with the
// user-supplied passphrase so the export file is useless without it.
router.post('/export', (req, res) => {
  const { include_credentials, passphrase } = req.body || {};
  const hosts = db.prepare('SELECT * FROM hosts WHERE user_id = ?').all(req.user.id);
  const snippets = db.prepare('SELECT * FROM snippets WHERE user_id = ?').all(req.user.id);
  const creds = db.prepare('SELECT * FROM credentials WHERE user_id = ?').all(req.user.id);

  const secrets = {};
  const credById = new Map(creds.map((c) => [c.id, c]));

  const outHosts = hosts.map((h) => {
    const entry = {
      name: h.name,
      hostname: h.hostname,
      port: h.port,
      username: h.username,
      auth_type: h.auth_type,
      folder: h.folder,
      color: h.color,
      notes: h.notes,
      keepalive: h.keepalive,
      credential_name: h.credential_id ? credById.get(h.credential_id)?.name || null : null,
      jump_host_name: h.jump_host_id
        ? db.prepare('SELECT name FROM hosts WHERE id = ?').get(h.jump_host_id)?.name || null
        : null,
    };
    if (h.password_enc) {
      if (include_credentials) {
        const ref = `h${h.id}`;
        secrets[ref] = decryptSecret(h.password_enc);
        entry.password_ref = ref;
      } else {
        entry.password_ref = null;
      }
    }
    return entry;
  });

  const outCreds = include_credentials
    ? creds.map((c) => {
        const ref = `c${c.id}`;
        secrets[ref] = JSON.parse(decryptSecret(c.secret_enc));
        return {
          name: c.name,
          type: c.type,
          username: c.username,
          comment: c.comment,
          public_key: c.public_key,
          secret_ref: ref,
        };
      })
    : undefined;

  let sealed = null;
  if (Object.keys(secrets).length > 0) {
    if (!passphrase || String(passphrase).length < 8) {
      return res.status(400).json({ error: 'passphrase (min 8 chars) required to export secrets' });
    }
    sealed = sealSecrets(secrets, passphrase);
  }

  auditReq(req, 'vault.exported', `${outHosts.length} hosts, ${outCreds?.length || 0} credentials, ${snippets.length} snippets`);
  res.json({
    ssloth_export: {
      version: 1,
      exported_at: new Date().toISOString(),
      user: req.user.username,
      hosts: outHosts,
      credentials: outCreds,
      snippets: snippets.map((s) => ({
        name: s.name,
        command: s.command,
        description: s.description,
        category: s.category,
      })),
      sealed,
    },
  });
});

// ---- Import ----
// POST /api/import { payload, passphrase }
router.post('/import', (req, res) => {
  const { payload, passphrase } = req.body || {};
  const data = payload?.ssloth_export;
  if (!data || data.version !== 1) return res.status(400).json({ error: 'not a ssloth export file' });

  let secrets = {};
  if (data.sealed) {
    try {
      secrets = unsealSecrets(data.sealed, passphrase);
    } catch {
      return res.status(400).json({ error: 'could not decrypt secrets — wrong passphrase?' });
    }
  }

  const counts = { hosts: 0, credentials: 0, snippets: 0, skipped: 0 };
  const credIdByName = new Map(
    db.prepare('SELECT id, name FROM credentials WHERE user_id = ?').all(req.user.id).map((c) => [c.name, c.id])
  );
  const hostNameToId = new Map(
    db.prepare('SELECT id, name FROM hosts WHERE user_id = ?').all(req.user.id).map((h) => [h.name, h.id])
  );

  const tx = db.transaction(() => {
    // credentials first so hosts can link to them
    for (const c of data.credentials || []) {
      if (credIdByName.has(c.name)) {
        counts.skipped++;
        continue;
      }
      const secret = secrets[c.secret_ref];
      if (!secret) {
        counts.skipped++;
        continue;
      }
      const info = db
        .prepare(
          'INSERT INTO credentials (user_id, name, type, username, secret_enc, public_key, comment) VALUES (?, ?, ?, ?, ?, ?, ?)'
        )
        .run(
          req.user.id,
          String(c.name).slice(0, 128),
          c.type === 'key' ? 'key' : 'password',
          c.username || null,
          encryptSecret(JSON.stringify(secret)),
          c.public_key || null,
          c.comment || null
        );
      credIdByName.set(c.name, info.lastInsertRowid);
      counts.credentials++;
    }

    for (const h of data.hosts || []) {
      if (hostNameToId.has(h.name)) {
        counts.skipped++;
        continue;
      }
      const credential_id = h.credential_name ? credIdByName.get(h.credential_name) || null : null;
      const jump_host_id = h.jump_host_name ? hostNameToId.get(h.jump_host_name) || null : null;
      const info = db
        .prepare(
          `INSERT INTO hosts (user_id, name, hostname, port, username, auth_type, credential_id,
            password_enc, folder, color, notes, keepalive, jump_host_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          req.user.id,
          String(h.name).slice(0, 128),
          String(h.hostname).slice(0, 255),
          Math.min(Math.max(parseInt(h.port, 10) || 22, 1), 65535),
          String(h.username).slice(0, 64),
          ['credential', 'password', 'ask'].includes(h.auth_type) ? h.auth_type : 'ask',
          credential_id,
          h.password_ref && secrets[h.password_ref] ? encryptSecret(secrets[h.password_ref]) : null,
          String(h.folder || '').slice(0, 128),
          String(h.color || '').slice(0, 32),
          String(h.notes || '').slice(0, 4000),
          parseInt(h.keepalive, 10) || 15,
          jump_host_id
        );
      hostNameToId.set(h.name, info.lastInsertRowid);
      counts.hosts++;
    }

    const existingSnippets = new Set(
      db.prepare('SELECT name FROM snippets WHERE user_id = ?').all(req.user.id).map((s) => s.name)
    );
    for (const s of data.snippets || []) {
      if (existingSnippets.has(s.name)) {
        counts.skipped++;
        continue;
      }
      db.prepare('INSERT INTO snippets (user_id, name, command, description, category) VALUES (?, ?, ?, ?, ?)').run(
        req.user.id,
        String(s.name).slice(0, 128),
        String(s.command).slice(0, 8000),
        String(s.description || '').slice(0, 1000),
        String(s.category || '').slice(0, 64)
      );
      counts.snippets++;
    }
  });
  tx();

  auditReq(
    req,
    'vault.imported',
    `${counts.hosts} hosts, ${counts.credentials} credentials, ${counts.snippets} snippets (${counts.skipped} skipped)`
  );
  res.json({ imported: counts });
});

module.exports = router;
