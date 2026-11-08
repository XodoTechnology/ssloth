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

// ---- Metrics (admin only, Prometheus text format) ----
router.get('/metrics', requireAdmin, (req, res) => {
  const now = Date.now();
  const wsCount = typeof globalThis.__ssloth_ws_connections === 'function' ? globalThis.__ssloth_ws_connections() : 0;
  const v = process.version.replace(/^v/, '');
  const lines = [
    '# HELP ssloth_uptime_seconds Server uptime in seconds',
    '# TYPE ssloth_uptime_seconds gauge',
    `ssloth_uptime_seconds ${Math.round(process.uptime())}`,
    '# HELP ssloth_ws_connections Currently open WebSocket connections',
    '# TYPE ssloth_ws_connections gauge',
    `ssloth_ws_connections ${wsCount}`,
    '# HELP ssloth_sessions_active Login sessions not yet expired',
    '# TYPE ssloth_sessions_active gauge',
    `ssloth_sessions_active ${db.prepare('SELECT COUNT(*) c FROM sessions WHERE expires_at > ?').get(now).c}`,
    '# HELP ssloth_users_total User accounts',
    '# TYPE ssloth_users_total gauge',
    `ssloth_users_total ${db.prepare('SELECT COUNT(*) c FROM users').get().c}`,
    '# HELP ssloth_hosts_total Configured hosts',
    '# TYPE ssloth_hosts_total gauge',
    `ssloth_hosts_total ${db.prepare('SELECT COUNT(*) c FROM hosts').get().c}`,
    '# HELP ssloth_shares_active Share links not yet expired',
    '# TYPE ssloth_shares_active gauge',
    `ssloth_shares_active ${db.prepare('SELECT COUNT(*) c FROM shares WHERE expires_at * 1000 > ?').get(now).c}`,
    '# HELP ssloth_audit_events_total Audit log entries',
    '# TYPE ssloth_audit_events_total counter',
    `ssloth_audit_events_total ${db.prepare('SELECT COUNT(*) c FROM audit').get().c}`,
    '# HELP ssloth_desktop_mode 1 when running as the desktop app',
    '# TYPE ssloth_desktop_mode gauge',
    `ssloth_desktop_mode ${require('../config').DESKTOP ? 1 : 0}`,
    '# HELP ssloth_nodejs_version_info Node.js version',
    '# TYPE ssloth_nodejs_version_info gauge',
    `ssloth_nodejs_version_info{version="${v}"} 1`,
    '',
  ];
  res.type('text/plain; version=0.0.4; charset=utf-8').send(lines.join('\n'));
});

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
    .prepare('SELECT id, username, is_admin, role, totp_enabled, lan_allowed, created_at FROM users ORDER BY username COLLATE NOCASE')
    .all();
  res.json({ users: rows });
});

// Per-account network access (desktop LAN mode): lan_allowed=0 keeps the
// account usable from the local app but refuses remote sign-in/API use.
router.post('/users/:id/lan', requireAdmin, (req, res) => {
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!target) return res.status(404).json({ error: 'not found' });
  const allowed = req.body?.allowed !== false;
  db.prepare('UPDATE users SET lan_allowed = ? WHERE id = ?').run(allowed ? 1 : 0, target.id);
  auditReq(req, 'user.lan_changed', `${target.username} -> ${allowed ? 'allowed' : 'denied'}`);
  res.json({ ok: true });
});

const VALID_ROLES = ['admin', 'user', 'viewer'];

router.post('/users', requireAdmin, async (req, res) => {
  const { username, password, is_admin, role } = req.body || {};
  if (!USERNAME_RE.test(username || '')) {
    return res.status(400).json({ error: 'username must be 2-32 chars: letters, numbers, _ . -' });
  }
  if (typeof password !== 'string' || password.length < 10) {
    return res.status(400).json({ error: 'password must be at least 10 characters' });
  }
  const userRole = is_admin ? 'admin' : VALID_ROLES.includes(role) ? role : 'user';
  try {
    const info = db
      .prepare('INSERT INTO users (username, password_hash, is_admin, role) VALUES (?, ?, ?, ?)')
      .run(username, await hashPassword(password), is_admin ? 1 : 0, userRole);
    auditReq(req, 'user.created', `user '${username}'`);
    res.json({ user: { id: info.lastInsertRowid, username, is_admin: !!is_admin, role: userRole } });
  } catch (e) {
    if (/UNIQUE/i.test(e.message)) return res.status(409).json({ error: 'username taken' });
    throw e;
  }
});

router.post('/users/:id/role', requireAdmin, (req, res) => {
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!target) return res.status(404).json({ error: 'not found' });
  const { role } = req.body || {};
  if (!VALID_ROLES.includes(role)) return res.status(400).json({ error: 'role must be admin, user, or viewer' });
  if (target.id === req.user.id) return res.status(400).json({ error: 'cannot change your own role' });
  db.prepare('UPDATE users SET role = ?, is_admin = ? WHERE id = ?')
    .run(role, role === 'admin' ? 1 : 0, target.id);
  auditReq(req, 'user.role_changed', `user '${target.username}' -> ${role}`);
  res.json({ ok: true });
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

// Lockout recovery: clear a user's second factor. Requires admin; kills
// their sessions + runtime so nothing keeps running under the old auth.
router.post('/users/:id/totp-reset', requireAdmin, (req, res) => {
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!target) return res.status(404).json({ error: 'not found' });
  db.prepare(
    'UPDATE users SET totp_enabled = 0, totp_secret = NULL, totp_pending_secret = NULL, totp_last_step = 0 WHERE id = ?'
  ).run(target.id);
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(target.id);
  killUserRuntime(target.id);
  auditReq(req, 'user.totp_reset', `user '${target.username}'`);
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
