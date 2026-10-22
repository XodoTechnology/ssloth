'use strict';

// API tokens: scoped bearer tokens for scripts/automation. The token is
// shown ONCE at creation — we store sha256(token). A token request carries
// req.tokenScopes; requireScope(scope) gates routes.
//
// Scopes: 'read' (GET on hosts/snippets/playbooks/tunnels/recordings),
//         'playbooks:run' (POST /api/playbooks/:id/run), 'vault' (export).
const express = require('express');
const { db } = require('../db');
const { randomToken, sha256B64 } = require('../crypto');
const { auditReq } = require('../auth');

const router = express.Router();

const VALID_SCOPES = new Set(['read', 'playbooks:run', 'vault']);

router.get('/', (req, res) => {
  const rows = db
    .prepare('SELECT id, name, scopes, last_used, expires_at, created_at FROM api_tokens WHERE user_id = ? ORDER BY id DESC')
    .all(req.user.id);
  res.json({
    tokens: rows.map((t) => ({
      ...t,
      scopes: t.scopes.split(',').filter(Boolean),
      last_used: t.last_used ? t.last_used * 1000 : null,
      expires_at: t.expires_at ? t.expires_at * 1000 : null,
      created_at: t.created_at * 1000,
    })),
  });
});

router.post('/', (req, res) => {
  const name = String(req.body?.name || '').trim().slice(0, 64);
  if (!name) return res.status(400).json({ error: 'name required' });
  const scopes = (Array.isArray(req.body?.scopes) ? req.body.scopes : ['read'])
    .filter((s) => VALID_SCOPES.has(s));
  if (!scopes.length) return res.status(400).json({ error: 'at least one valid scope required' });
  const days = Math.min(Math.max(parseInt(req.body?.expires_days, 10) || 0, 0), 365);
  const expiresAt = days ? Math.floor(Date.now() / 1000) + days * 86400 : null;

  const count = db.prepare('SELECT COUNT(*) AS n FROM api_tokens WHERE user_id = ?').get(req.user.id).n;
  if (count >= 25) return res.status(400).json({ error: 'token limit reached (25)' });

  const token = `slo_${randomToken()}`;
  const info = db
    .prepare('INSERT INTO api_tokens (user_id, name, token_hash, scopes, expires_at) VALUES (?, ?, ?, ?, ?)')
    .run(req.user.id, name, sha256B64(token), scopes.join(','), expiresAt);
  auditReq(req, 'api_token.created', name);
  res.json({ id: info.lastInsertRowid, token, name, scopes });
});

router.delete('/:id', (req, res) => {
  const r = db.prepare('DELETE FROM api_tokens WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  if (!r.changes) return res.status(404).json({ error: 'not found' });
  auditReq(req, 'api_token.revoked', `id ${req.params.id}`);
  res.json({ ok: true });
});

module.exports = router;
