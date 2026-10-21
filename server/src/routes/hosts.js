'use strict';

const express = require('express');
const { db } = require('../db');
const { encryptSecret } = require('../crypto');
const { auditReq } = require('../auth');
const { listHostKeys, removeHostKey } = require('../ssh/manager');

const router = express.Router();

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

function hostView(row) {
  const { password_enc, ...rest } = row;
  return { ...rest, has_password: !!password_enc };
}

router.get('/', (req, res) => {
  const rows = db
    .prepare('SELECT * FROM hosts WHERE user_id = ? ORDER BY folder, name COLLATE NOCASE')
    .all(req.user.id);
  res.json({ hosts: rows.map(hostView) });
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
  if (data.auth_type === 'credential' && !data.credential_id) {
    return res.status(400).json({ error: 'credential_id required for credential auth' });
  }
  if (data.credential_id != null) {
    const cred = db
      .prepare('SELECT id FROM credentials WHERE id = ? AND user_id = ?')
      .get(data.credential_id, req.user.id);
    if (!cred) return res.status(400).json({ error: 'credential not found' });
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
  if (data.credential_id != null) {
    const cred = db
      .prepare('SELECT id FROM credentials WHERE id = ? AND user_id = ?')
      .get(data.credential_id, req.user.id);
    if (!cred) return res.status(400).json({ error: 'credential not found' });
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
  db.prepare('DELETE FROM hosts WHERE id = ?').run(existing.id);
  auditReq(req, 'host.deleted', `${existing.name} (${existing.hostname})`);
  res.json({ ok: true });
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
