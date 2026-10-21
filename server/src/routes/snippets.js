'use strict';

const express = require('express');
const { db } = require('../db');
const { auditReq } = require('../auth');

const router = express.Router();

function cleanSnippet(body, { partial = false } = {}) {
  const out = {};
  if (!partial || body.name !== undefined) out.name = String(body.name ?? '').slice(0, 128).trim();
  if (!partial || body.command !== undefined) out.command = String(body.command ?? '').slice(0, 8000);
  if (!partial || body.description !== undefined) out.description = String(body.description ?? '').slice(0, 1000);
  if (!partial || body.category !== undefined) out.category = String(body.category ?? '').slice(0, 64).trim();
  if (!partial || body.sort !== undefined) out.sort = parseInt(body.sort, 10) || 0;
  return out;
}

router.get('/', (req, res) => {
  const rows = db
    .prepare('SELECT * FROM snippets WHERE user_id = ? ORDER BY category COLLATE NOCASE, sort, name COLLATE NOCASE')
    .all(req.user.id);
  res.json({ snippets: rows });
});

router.post('/', (req, res) => {
  const data = cleanSnippet(req.body || {});
  if (!data.name || !data.command) return res.status(400).json({ error: 'name and command required' });
  const cols = Object.keys(data);
  const info = db
    .prepare(`INSERT INTO snippets (user_id, ${cols.join(',')}) VALUES (?, ${cols.map(() => '?').join(',')})`)
    .run(req.user.id, ...cols.map((c) => data[c]));
  const row = db.prepare('SELECT * FROM snippets WHERE id = ?').get(info.lastInsertRowid);
  res.json({ snippet: row });
});

router.put('/:id', (req, res) => {
  const existing = db.prepare('SELECT * FROM snippets WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!existing) return res.status(404).json({ error: 'not found' });
  const data = cleanSnippet(req.body || {}, { partial: true });
  const cols = Object.keys(data);
  if (cols.length) {
    db.prepare(`UPDATE snippets SET ${cols.map((c) => `${c} = ?`).join(', ')} WHERE id = ?`).run(
      ...cols.map((c) => data[c]),
      existing.id
    );
  }
  const row = db.prepare('SELECT * FROM snippets WHERE id = ?').get(existing.id);
  res.json({ snippet: row });
});

router.delete('/:id', (req, res) => {
  const existing = db.prepare('SELECT * FROM snippets WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!existing) return res.status(404).json({ error: 'not found' });
  db.prepare('DELETE FROM snippets WHERE id = ?').run(existing.id);
  res.json({ ok: true });
});

module.exports = router;
