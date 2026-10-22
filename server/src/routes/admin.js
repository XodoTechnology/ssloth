'use strict';

const express = require('express');
const { db } = require('../db');
const { hashPassword } = require('../crypto');
const { requireAdmin, auditReq } = require('../auth');
const { destroyUserSessions } = require('../ssh/manager');
const { stopTunnelsForUser } = require('./tunnels');

// A password reset or account deletion is a security event — kill the
// user's live SSH sessions and tunnels, not just their cookies.
function killUserRuntime(userId) {
  try { destroyUserSessions(userId); } catch {}
  try { stopTunnelsForUser(userId); } catch {}
}

const router = express.Router();

// ---- Audit log ----
router.get('/audit', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 200, 1000);
  const rows = req.user.is_admin
    ? db.prepare('SELECT * FROM audit ORDER BY id DESC LIMIT ?').all(limit)
    : db.prepare('SELECT * FROM audit WHERE user_id = ? ORDER BY id DESC LIMIT ?').all(req.user.id, limit);
  res.json({ audit: rows });
});

// ---- User management (admin only) ----
const USERNAME_RE = /^[a-zA-Z0-9_.-]{2,32}$/;

router.get('/users', requireAdmin, (req, res) => {
  const rows = db
    .prepare('SELECT id, username, is_admin, totp_enabled, created_at FROM users ORDER BY username COLLATE NOCASE')
    .all();
  res.json({ users: rows });
});

router.post('/users', requireAdmin, async (req, res) => {
  const { username, password, is_admin } = req.body || {};
  if (!USERNAME_RE.test(username || '')) {
    return res.status(400).json({ error: 'username must be 2-32 chars: letters, numbers, _ . -' });
  }
  if (typeof password !== 'string' || password.length < 10) {
    return res.status(400).json({ error: 'password must be at least 10 characters' });
  }
  try {
    const info = db
      .prepare('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)')
      .run(username, await hashPassword(password), is_admin ? 1 : 0);
    auditReq(req, 'user.created', `user '${username}'`);
    res.json({ user: { id: info.lastInsertRowid, username, is_admin: !!is_admin } });
  } catch (e) {
    if (/UNIQUE/i.test(e.message)) return res.status(409).json({ error: 'username taken' });
    throw e;
  }
});

router.post('/users/:id/password', requireAdmin, async (req, res) => {
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!target) return res.status(404).json({ error: 'not found' });
  const { password } = req.body || {};
  if (typeof password !== 'string' || password.length < 10) {
    return res.status(400).json({ error: 'password must be at least 10 characters' });
  }
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(await hashPassword(password), target.id);
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(target.id);
  killUserRuntime(target.id);
  auditReq(req, 'user.password_reset', `user '${target.username}'`);
  res.json({ ok: true });
});

router.delete('/users/:id', requireAdmin, (req, res) => {
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!target) return res.status(404).json({ error: 'not found' });
  if (target.id === req.user.id) return res.status(400).json({ error: 'cannot delete yourself' });
  killUserRuntime(target.id);
  db.prepare('DELETE FROM users WHERE id = ?').run(target.id);
  auditReq(req, 'user.deleted', `user '${target.username}'`);
  res.json({ ok: true });
});

module.exports = router;
