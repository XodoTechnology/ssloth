'use strict';

const express = require('express');
const net = require('net');
const { db } = require('../db');
const { encryptSecret } = require('../crypto');
const { auditReq } = require('../auth');
const { listHostKeys, removeHostKey } = require('../ssh/manager');

const router = express.Router();
const { stopTunnelsForHost } = require('./tunnels');

const AUTH_TYPES = new Set(['credential', 'password', 'ask']);

function cleanHostInput(body, { partial = false } = {}) {
  const out = {};
  const str = (v, max = 255) => String(v ?? '').slice(0, max).trim();

  if (!partial || body.name !== undefined) out.name = str(body.name, 128);
  if (!partial || body.hostname !== undefined) out.hostname = str(body.hostname, 255);
  if (!partial || body.port !== undefined) {
    const p = parseInt(body.port, 10);
    if (!Number.isInteger(p) || p < 1 || p > 65535) throw new Error('invalid port');
    out.port = p;
  }
  if (!partial || body.username !== undefined) out.username = str(body.username, 64);
  if (!partial || body.auth_type !== undefined) {
    if (!AUTH_TYPES.has(body.auth_type)) throw new Error('invalid auth_type');
    out.auth_type = body.auth_type;
  }
  if (!partial || body.credential_id !== undefined) {
    out.credential_id = body.credential_id == null ? null : parseInt(body.credential_id, 10);
  }
  if (!partial || body.jump_host_id !== undefined) {
    out.jump_host_id = body.jump_host_id == null ? null : parseInt(body.jump_host_id, 10);
  }
  if (!partial || body.record !== undefined) {
    out.record = body.record ? 1 : 0;
  }
  if (!partial || body.pinned !== undefined) {
    out.pinned = body.pinned ? 1 : 0;
  }
  if (!partial || body.shared !== undefined) {
    out.shared = body.shared ? 1 : 0;
  }
  if (!partial || body.region !== undefined) out.region = str(body.region, 128);
  if (!partial || body.tags !== undefined) {
    // normalize: "#Routers, core" -> "routers core" (space-separated, deduped)
    const tags = String(body.tags ?? '')
      .split(/[\s,]+/)
      .map((t) => t.replace(/^#+/, '').trim().toLowerCase())
      .filter(Boolean);
    out.tags = [...new Set(tags)].slice(0, 32).join(' ');
  }
  if (!partial || body.folder !== undefined) out.folder = str(body.folder, 128);
  if (!partial || body.color !== undefined) out.color = str(body.color, 32);
  if (!partial || body.notes !== undefined) out.notes = String(body.notes ?? '').slice(0, 4000);
  if (!partial || body.keepalive !== undefined) {
    const k = parseInt(body.keepalive, 10);
    out.keepalive = Number.isInteger(k) && k >= 0 && k <= 300 ? k : 15;
  }
  // Secret fields are only updated when explicitly provided.
  if (body.password !== undefined) {
    out.password_enc = body.password ? encryptSecret(String(body.password)) : null;
  }
  return out;
}

function hostView(row, userId) {
  const { password_enc, ...rest } = row;
  return { ...rest, has_password: !!password_enc, owned: row.user_id === userId };
}

router.get('/', (req, res) => {
  // Own hosts plus shared ones from other users (annotated with the owner's
  // name; `owned` tells the UI what's editable).
  const rows = db
    .prepare(
      `SELECT h.*, u.username AS owner_name FROM hosts h
       LEFT JOIN users u ON u.id = h.user_id
       WHERE h.user_id = ? OR h.shared = 1
       ORDER BY h.folder, h.name COLLATE NOCASE`
    )
    .all(req.user.id);
  res.json({ hosts: rows.map((r) => hostView(r, req.user.id)) });
});

router.post('/', (req, res) => {
  let data;
  try {
    data = cleanHostInput(req.body || {});
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }
  if (!data.name || !data.hostname || !data.username) {
    return res.status(400).json({ error: 'name, hostname and username are required' });
  }
  if (data.shared === 1 && !req.user.is_admin) {
    return res.status(403).json({ error: 'only admins can share hosts' });
  }
  if (data.auth_type === 'credential' && !data.credential_id) {
    return res.status(400).json({ error: 'credential_id required for credential auth' });
  }
  // Don't store secrets that don't match the auth mode.
  if (data.auth_type !== 'password') delete data.password_enc;
  if (data.auth_type === 'password' || data.auth_type === 'ask') data.credential_id = null;
  if (data.credential_id != null) {
    const cred = db
      .prepare('SELECT id FROM credentials WHERE id = ? AND user_id = ?')
      .get(data.credential_id, req.user.id);
    if (!cred) return res.status(400).json({ error: 'credential not found' });
  }
  if (data.jump_host_id != null) {
    const jump = db
      .prepare('SELECT id FROM hosts WHERE id = ? AND (user_id = ? OR shared = 1)')
      .get(data.jump_host_id, req.user.id);
    if (!jump) return res.status(400).json({ error: 'bastion host not found' });
    if (data.jump_host_id === -1) return res.status(400).json({ error: 'invalid bastion' });
  }
  const cols = Object.keys(data);
  const info = db
    .prepare(`INSERT INTO hosts (user_id, ${cols.join(',')}) VALUES (?, ${cols.map(() => '?').join(',')})`)
    .run(req.user.id, ...cols.map((c) => data[c]));
  auditReq(req, 'host.created', `${data.name} (${data.username}@${data.hostname}:${data.port ?? 22})`);
  const row = db.prepare('SELECT * FROM hosts WHERE id = ?').get(info.lastInsertRowid);
  res.json({ host: hostView(row) });
});

router.put('/:id', (req, res) => {
  const existing = db.prepare('SELECT * FROM hosts WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!existing) return res.status(404).json({ error: 'not found' });
  let data;
  try {
    data = cleanHostInput(req.body || {}, { partial: true });
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }
  if (data.shared === 1 && !req.user.is_admin) {
    return res.status(403).json({ error: 'only admins can share hosts' });
  }
  // Auth-mode changes drop the secrets that no longer apply — otherwise a
  // stale password_enc lingers (and still gets exported) after switching
  // to credential/ask auth.
  const nextAuth = data.auth_type ?? existing.auth_type;
  if (nextAuth !== 'password' && req.body.password === undefined) {
    data.password_enc = null;
  }
  if (nextAuth !== 'credential' && req.body.credential_id === undefined) {
    data.credential_id = null;
  }
  if (data.credential_id != null) {
    const cred = db
      .prepare('SELECT id FROM credentials WHERE id = ? AND user_id = ?')
      .get(data.credential_id, req.user.id);
    if (!cred) return res.status(400).json({ error: 'credential not found' });
  }
  if (data.jump_host_id != null) {
    if (data.jump_host_id === existing.id) {
      return res.status(400).json({ error: 'a host cannot be its own bastion' });
    }
    const jump = db
      .prepare('SELECT id FROM hosts WHERE id = ? AND (user_id = ? OR shared = 1)')
      .get(data.jump_host_id, req.user.id);
    if (!jump) return res.status(400).json({ error: 'bastion host not found' });
  }
  const cols = Object.keys(data);
  if (cols.length) {
    db.prepare(
      `UPDATE hosts SET ${cols.map((c) => `${c} = ?`).join(', ')}, updated_at = unixepoch() WHERE id = ?`
    ).run(...cols.map((c) => data[c]), existing.id);
  }
  const row = db.prepare('SELECT * FROM hosts WHERE id = ?').get(existing.id);
  res.json({ host: hostView(row) });
});

router.delete('/:id', (req, res) => {
  const existing = db.prepare('SELECT * FROM hosts WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!existing) return res.status(404).json({ error: 'not found' });
  // CASCADE deletes the tunnel rows — stop the live listeners too.
  stopTunnelsForHost(existing.id);
  db.prepare('DELETE FROM hosts WHERE id = ?').run(existing.id);
  auditReq(req, 'host.deleted', `${existing.name} (${existing.hostname})`);
  res.json({ ok: true });
});

// ---- Reachability probe (parallel TCP connect, 20s cache per user) ----

const statusCache = new Map(); // userId -> { at, result }

function probePort(hostname, port) {
  return new Promise((resolve) => {
    const sock = net.connect({ host: hostname, port, timeout: 3000 });
    const done = (status) => {
      try { sock.destroy(); } catch {}
      resolve(status);
    };
    sock.on('connect', () => done('up'));
    sock.on('timeout', () => done('down'));
    sock.on('error', () => done('down'));
  });
}

router.get('/status', async (req, res) => {
  const cached = statusCache.get(req.user.id);
  if (cached && Date.now() - cached.at < 20000) return res.json({ status: cached.result });

  const hosts = db
    .prepare('SELECT id, hostname, port FROM hosts WHERE user_id = ? OR shared = 1')
    .all(req.user.id);
  // Cap concurrency — hundreds of hosts at once would flood the fd table.
  const result = {};
  const BATCH = 16;
  for (let i = 0; i < hosts.length; i += BATCH) {
    const entries = await Promise.all(
      hosts.slice(i, i + BATCH).map((h) => probePort(h.hostname, h.port).then((s) => [h.id, s]))
    );
    for (const [id, s] of entries) result[id] = s;
  }
  statusCache.set(req.user.id, { at: Date.now(), result });
  res.json({ status: result });
});

// ---- Known host keys (TOFU store) ----

router.get('/hostkeys', (req, res) => {
  res.json({ hostkeys: listHostKeys(req.user.id) });
});

router.delete('/hostkeys/:id', (req, res) => {
  if (!removeHostKey(req.user.id, req.params.id)) return res.status(404).json({ error: 'not found' });
  auditReq(req, 'ssh.hostkey_removed', `hostkey id ${req.params.id}`);
  res.json({ ok: true });
});

module.exports = router;
