'use strict';

const express = require('express');
const { db } = require('../db');
const { randomToken, sha256B64 } = require('../crypto');
const { auditReq } = require('../auth');
const { sessions, closeViewersByShare } = require('../ssh/manager');

const router = express.Router();
const publicRouter = express.Router();

const MIN_TTL = 5;
const MAX_TTL = 24 * 60; // minutes

// Create an ephemeral share link for one of my live sessions.
router.post('/', (req, res) => {
  const { session_id, mode, ttl_minutes } = req.body || {};
  const session = sessions.get(String(session_id || ''));
  if (!session || session.userId !== req.user.id) {
    return res.status(404).json({ error: 'session not found or already closed' });
  }
  if (!['view', 'control'].includes(mode)) return res.status(400).json({ error: 'mode must be view or control' });
  const ttl = Math.min(Math.max(parseInt(ttl_minutes, 10) || 60, MIN_TTL), MAX_TTL);

  const token = randomToken();
  const expiresAt = Date.now() + ttl * 60 * 1000;
  const info = db
    .prepare(
      'INSERT INTO shares (token_hash, user_id, session_id, label, mode, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
    )
    .run(sha256B64(token), req.user.id, session.id, session.label, mode, Math.floor(expiresAt / 1000));
  auditReq(req, 'share.created', `${mode} share of '${session.label}' ttl=${ttl}m`);
  res.json({
    share: {
      id: info.lastInsertRowid,
      url: `/share/${token}`,
      mode,
      label: session.label,
      expires_at: expiresAt,
    },
  });
});

// List my active share links.
router.get('/', (req, res) => {
  const rows = db
    .prepare('SELECT id, session_id, label, mode, expires_at, created_at FROM shares WHERE user_id = ? ORDER BY id DESC')
    .all(req.user.id);
  res.json({ shares: rows.map((r) => ({ ...r, expires_at: r.expires_at * 1000, created_at: r.created_at * 1000, live: sessions.has(r.session_id) })) });
});

// Revoke a share link.
router.delete('/:id', (req, res) => {
  const row = db.prepare('SELECT * FROM shares WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!row) return res.status(404).json({ error: 'not found' });
  db.prepare('DELETE FROM shares WHERE id = ?').run(row.id);
  closeViewersByShare(row.id);
  auditReq(req, 'share.revoked', `share of '${row.label}'`);
  res.json({ ok: true });
});

// Public metadata for a share link (the token itself is the credential).
publicRouter.get('/:token', (req, res) => {
  const row = shareByToken(req.params.token);
  if (!row) return res.status(404).json({ error: 'link expired or revoked' });
  res.json({ label: row.label, mode: row.mode, expires_at: row.expires_at * 1000 });
});

function shareByToken(token) {
  if (!token || typeof token !== 'string' || token.length > 128) return null;
  const row = db.prepare('SELECT * FROM shares WHERE token_hash = ?').get(sha256B64(token));
  if (!row || row.expires_at * 1000 < Date.now()) return null;
  return row;
}

module.exports = { router, publicRouter, shareByToken };
