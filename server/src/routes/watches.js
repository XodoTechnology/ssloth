// Output-watch CRUD: user-scoped regexes matched against session output.
const express = require('express');
const db = require('../db');
const { auditReq } = require('../auth');
const { invalidate } = require('../watch');

const router = express.Router();
const view = (r) => ({ id: r.id, host_id: r.host_id, label: r.label, pattern: r.pattern, enabled: !!r.enabled, created_at: r.created_at });

router.get('/', (req, res) => {
  const rows = db.prepare('SELECT * FROM watches WHERE user_id = ? ORDER BY label').all(req.user.id);
  res.json({ watches: rows.map(view) });
});

router.post('/', (req, res) => {
  const { label, pattern, host_id, enabled } = req.body || {};
  if (!pattern || typeof pattern !== 'string') return res.status(400).json({ error: 'pattern required' });
  try { new RegExp(pattern, 'i'); } catch { return res.status(400).json({ error: 'invalid regex' }); }
  const info = db
    .prepare('INSERT INTO watches (user_id, host_id, label, pattern, enabled) VALUES (?, ?, ?, ?, ?)')
    .run(req.user.id, host_id ? parseInt(host_id, 10) : null,
         String(label || pattern).slice(0, 120), pattern.slice(0, 300), enabled === 0 ? 0 : 1);
  invalidate(req.user.id);
  auditReq(req, 'watch.created', String(label || pattern));
  res.json({ watch: view(db.prepare('SELECT * FROM watches WHERE id = ?').get(info.lastInsertRowid)) });
});

router.put('/:id', (req, res) => {
  const r = db.prepare('SELECT * FROM watches WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!r) return res.status(404).json({ error: 'not found' });
  const enabled = req.body?.enabled !== undefined ? (req.body.enabled ? 1 : 0) : r.enabled;
  db.prepare('UPDATE watches SET enabled = ? WHERE id = ?').run(enabled, r.id);
  invalidate(req.user.id);
  res.json({ watch: view({ ...r, enabled }) });
});

router.delete('/:id', (req, res) => {
  db.prepare('DELETE FROM watches WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  invalidate(req.user.id);
  res.json({ ok: true });
});

module.exports = router;
