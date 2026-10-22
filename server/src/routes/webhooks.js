'use strict';

const express = require('express');
const { db } = require('../db');
const { auditReq } = require('../auth');
const { postWebhook } = require('../notify');

const router = express.Router();

function validUrl(v) {
  try {
    const u = new URL(String(v || ''));
    return (u.protocol === 'http:' || u.protocol === 'https:') && u.hostname ? u.toString() : null;
  } catch { return null; }
}

router.get('/', (req, res) => {
  const rows = db.prepare('SELECT id, url, events, enabled, created_at FROM webhooks WHERE user_id = ? ORDER BY id').all(req.user.id);
  res.json({ webhooks: rows.map((r) => ({ ...r, created_at: r.created_at * 1000 })) });
});

router.post('/', (req, res) => {
  const url = validUrl(req.body?.url);
  if (!url) return res.status(400).json({ error: 'valid http(s) URL required' });
  const events = String(req.body?.events || '*').slice(0, 200);
  const count = db.prepare('SELECT COUNT(*) AS n FROM webhooks WHERE user_id = ?').get(req.user.id).n;
  if (count >= 20) return res.status(400).json({ error: 'webhook limit reached (20)' });
  const info = db.prepare('INSERT INTO webhooks (user_id, url, events) VALUES (?, ?, ?)').run(req.user.id, url, events);
  auditReq(req, 'webhook.created', url);
  res.json({ webhook: { id: info.lastInsertRowid, url, events, enabled: 1 } });
});

router.put('/:id', (req, res) => {
  const row = db.prepare('SELECT * FROM webhooks WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!row) return res.status(404).json({ error: 'not found' });
  const url = req.body.url !== undefined ? validUrl(req.body.url) : row.url;
  if (url === null) return res.status(400).json({ error: 'valid http(s) URL required' });
  const events = req.body.events !== undefined ? String(req.body.events).slice(0, 200) : row.events;
  const enabled = req.body.enabled !== undefined ? (req.body.enabled ? 1 : 0) : row.enabled;
  db.prepare('UPDATE webhooks SET url = ?, events = ?, enabled = ? WHERE id = ?').run(url, events, enabled, row.id);
  res.json({ ok: true });
});

router.post('/:id/test', async (req, res) => {
  const row = db.prepare('SELECT * FROM webhooks WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!row) return res.status(404).json({ error: 'not found' });
  const ok = await postWebhook(row.url, 'test', 'ssloth webhook test — it works');
  res.json({ ok });
});

router.delete('/:id', (req, res) => {
  const r = db.prepare('DELETE FROM webhooks WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  if (!r.changes) return res.status(404).json({ error: 'not found' });
  res.json({ ok: true });
});

module.exports = router;
