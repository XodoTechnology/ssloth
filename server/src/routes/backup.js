'use strict';

const express = require('express');
const crypto = require('crypto');
const { db } = require('../db');
const { encryptSecret, decryptSecret } = require('../crypto');
const { auditReq } = require('../auth');

const router = express.Router();

// ---- passphrase-sealed secrets for portable export ----
// scrypt via promisify — a sync N=32768 derivation would stall the event
// loop (~200ms) for every connected terminal.

const { promisify } = require('util');
const scryptAsync = promisify(crypto.scrypt);
const KDF_OPTS = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

async function sealSecrets(obj, passphrase) {
  const salt = crypto.randomBytes(16);
  const key = await scryptAsync(String(passphrase), salt, 32, KDF_OPTS);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(JSON.stringify(obj), 'utf8'), cipher.final()]);
  return {
    kdf: 'scrypt',
    salt: salt.toString('base64'),
    blob: Buffer.concat([iv, cipher.getAuthTag(), ct]).toString('base64'),
  };
}

async function unsealSecrets(sealed, passphrase) {
  if (!sealed || sealed.kdf !== 'scrypt') throw new Error('bad sealed blob');
  const salt = Buffer.from(sealed.salt, 'base64');
  const key = await scryptAsync(String(passphrase || ''), salt, 32, KDF_OPTS);
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
router.post('/export', async (req, res) => {
  const { include_credentials, passphrase } = req.body || {};
  const hosts = db.prepare('SELECT * FROM hosts WHERE user_id = ?').all(req.user.id);
  const snippets = db.prepare('SELECT * FROM snippets WHERE user_id = ?').all(req.user.id);
  const creds = db.prepare('SELECT * FROM credentials WHERE user_id = ?').all(req.user.id);
  const playbooks = db.prepare('SELECT * FROM playbooks WHERE user_id = ?').all(req.user.id);
  const tunnels = db.prepare('SELECT * FROM tunnels WHERE user_id = ?').all(req.user.id);

  const secrets = {};
  const credById = new Map(creds.map((c) => [c.id, c]));
  const hostById = new Map(hosts.map((h) => [h.id, h]));

  // A row that fails to decrypt (e.g. master key rotated since it was
  // written) must not kill the export — degrade it to "no secret" instead.
  let undecryptable = 0;

  const outHosts = hosts.map((h) => {
    const entry = {
      name: h.name,
      hostname: h.hostname,
      port: h.port,
      username: h.username,
      auth_type: h.auth_type,
      protocol: h.protocol,
      mac: h.mac,
      agent_forward: h.agent_forward,
      folder: h.folder,
      region: h.region,
      tags: h.tags,
      pinned: h.pinned,
      record: h.record,
      shared: h.shared,
      color: h.color,
      notes: h.notes,
      keepalive: h.keepalive,
      credential_name: h.credential_id ? credById.get(h.credential_id)?.name || null : null,
      jump_host_name: h.jump_host_id ? hostById.get(h.jump_host_id)?.name || null : null,
    };
    if (h.password_enc) {
      if (include_credentials) {
        try {
          const ref = `h${h.id}`;
          secrets[ref] = decryptSecret(h.password_enc);
          entry.password_ref = ref;
        } catch {
          undecryptable++;
          entry.password_ref = null;
        }
      } else {
        entry.password_ref = null;
      }
    }
    return entry;
  });

  const outCreds = include_credentials
    ? creds.map((c) => {
        const out = {
          name: c.name,
          type: c.type,
          username: c.username,
          comment: c.comment,
          public_key: c.public_key,
        };
        try {
          const ref = `c${c.id}`;
          secrets[ref] = JSON.parse(decryptSecret(c.secret_enc));
          out.secret_ref = ref;
        } catch {
          undecryptable++;
          out.undecryptable = true;
        }
        return out;
      })
    : undefined;

  let sealed = null;
  if (Object.keys(secrets).length > 0) {
    if (!passphrase || String(passphrase).length < 8) {
      return res.status(400).json({ error: 'passphrase (min 8 chars) required to export secrets' });
    }
    sealed = await sealSecrets(secrets, passphrase);
  }

  auditReq(req, 'vault.exported', `${outHosts.length} hosts, ${outCreds?.length || 0} credentials, ${snippets.length} snippets${undecryptable ? `, ${undecryptable} undecryptable` : ''}`);
  res.json({
    ssloth_export: {
      version: 2,
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
      playbooks: playbooks.map((p) => ({
        name: p.name,
        description: p.description,
        steps: JSON.parse(p.steps || '[]'),
      })),
      tunnels: tunnels.map((t) => ({
        name: t.name,
        type: t.type,
        host_name: hostById.get(t.host_id)?.name || null,
        bind_address: t.bind_address,
        local_port: t.local_port,
        remote_host: t.remote_host,
        remote_port: t.remote_port,
      })),
      sealed,
    },
  });
});

// ---- Import ----
// POST /api/import { payload, passphrase }
router.post('/import', async (req, res) => {
  const { payload, passphrase } = req.body || {};
  const data = payload?.ssloth_export;
  if (!data || (data.version !== 1 && data.version !== 2)) {
    return res.status(400).json({ error: 'not a ssloth export file' });
  }

  let secrets = {};
  if (data.sealed) {
    try {
      secrets = await unsealSecrets(data.sealed, passphrase);
    } catch {
      return res.status(400).json({ error: 'could not decrypt secrets — wrong passphrase?' });
    }
  }

  const counts = { hosts: 0, credentials: 0, snippets: 0, playbooks: 0, tunnels: 0, skipped: 0 };
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

    // Hosts pass 1: insert everything WITHOUT jump links — a bastion may be
    // defined later in the file than the hosts that reference it.
    const pendingJumps = []; // { hostId, jumpHostName }
    for (const h of data.hosts || []) {
      if (hostNameToId.has(h.name)) {
        counts.skipped++;
        continue;
      }
      const credential_id = h.credential_name ? credIdByName.get(h.credential_name) || null : null;
      const info = db
        .prepare(
          `INSERT INTO hosts (user_id, name, hostname, port, username, auth_type, credential_id,
            password_enc, folder, region, tags, pinned, record, shared, color, notes, keepalive,
            protocol, mac, agent_forward)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
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
          String(h.region || '').slice(0, 128),
          String(h.tags || '').slice(0, 1024),
          h.pinned ? 1 : 0,
          h.record ? 1 : 0,
          // Sharing is an admin-gated flag — importing as a non-admin never
          // widens a host beyond its owner.
          req.user.is_admin && h.shared ? 1 : 0,
          String(h.color || '').slice(0, 32),
          String(h.notes || '').slice(0, 4000),
          parseInt(h.keepalive, 10) || 15,
          h.protocol === 'telnet' ? 'telnet' : 'ssh',
          (h.mac ? String(h.mac).slice(0, 17).toUpperCase() : ''),
          h.agent_forward ? 1 : 0
        );
      hostNameToId.set(h.name, info.lastInsertRowid);
      if (h.jump_host_name) pendingJumps.push({ hostId: info.lastInsertRowid, jumpHostName: h.jump_host_name });
      counts.hosts++;
    }

    // Hosts pass 2: every host exists now — resolve bastion references.
    for (const { hostId, jumpHostName } of pendingJumps) {
      const jumpId = hostNameToId.get(jumpHostName);
      if (jumpId && jumpId !== hostId) {
        db.prepare('UPDATE hosts SET jump_host_id = ? WHERE id = ?').run(jumpId, hostId);
      }
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

    const existingPlaybooks = new Set(
      db.prepare('SELECT name FROM playbooks WHERE user_id = ?').all(req.user.id).map((p) => p.name)
    );
    for (const p of data.playbooks || []) {
      if (!p?.name || existingPlaybooks.has(p.name)) {
        counts.skipped++;
        continue;
      }
      const steps = Array.isArray(p.steps)
        ? p.steps
            .filter((s) => s && typeof s.command === 'string' && s.command.trim())
            .slice(0, 100)
            .map((s) => ({
              command: String(s.command).slice(0, 8000),
              description: String(s.description || '').slice(0, 500),
              timeout_s: Math.min(Math.max(parseInt(s.timeout_s, 10) || 60, 5), 3600),
            }))
        : [];
      db.prepare('INSERT INTO playbooks (user_id, name, description, steps) VALUES (?, ?, ?, ?)').run(
        req.user.id,
        String(p.name).slice(0, 128),
        String(p.description || '').slice(0, 1000),
        JSON.stringify(steps)
      );
      counts.playbooks++;
    }

    // Tunnels reference hosts by name — all hosts exist by now. Imported
    // binds are loopback-only (same rule as the tunnels API).
    for (const t of data.tunnels || []) {
      const hostId = t.host_name ? hostNameToId.get(t.host_name) : null;
      if (!t?.name || !hostId) {
        counts.skipped++;
        continue;
      }
      const bind = String(t.bind_address || '127.0.0.1');
      const bindAddr = ['127.0.0.1', '::1', 'localhost'].includes(bind) ? bind : '127.0.0.1';
      const localPort = Math.min(Math.max(parseInt(t.local_port, 10) || 0, 1024), 65535);
      db.prepare(
        'INSERT INTO tunnels (user_id, name, type, host_id, bind_address, local_port, remote_host, remote_port) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
      ).run(
        req.user.id,
        String(t.name).slice(0, 128),
        t.type === 'dynamic' ? 'dynamic' : 'local',
        hostId,
        bindAddr,
        localPort,
        String(t.remote_host || '-').slice(0, 255),
        Math.min(Math.max(parseInt(t.remote_port, 10) || 0, 0), 65535)
      );
      counts.tunnels++;
    }
  });
  tx();

  auditReq(
    req,
    'vault.imported',
    `${counts.hosts} hosts, ${counts.credentials} credentials, ${counts.snippets} snippets, ${counts.playbooks} playbooks, ${counts.tunnels} tunnels (${counts.skipped} skipped)`
  );
  res.json({ imported: counts });
});

module.exports = router;
