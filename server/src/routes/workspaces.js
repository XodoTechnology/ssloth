'use strict';

const express = require('express');
const { db } = require('../db');
const { auditReq } = require('../auth');

const router = express.Router();

// A workspace is a named set of host sessions — opening it fans out to a
// multi-tab layout. Layout entries: { host: <host_id> }.
const MAX_LAYOUT = 24;

function cleanLayout(input) {
  if (!Array.isArray(input)) return [];
  return input
    .map((e) => ({ host: parseInt(e?.host, 10) || 0 }))
    .filter((e) => e.host > 0)
    .slice(0, MAX_LAYOUT);
}

router.get('/', (req, res) => {
  const rows = db
    .prepare('SELECT id, name, layout, created_at FROM workspaces WHERE user_id = ? ORDER BY name COLLATE NOCASE')
    .all(req.user.id);
  res.json({
    workspaces: rows.map((w) => ({ ...w, layout: JSON.parse(w.layout || '[]') })),
  });
});

router.post('/', (req, res) => {
  const name = String(req.body?.name ?? '').slice(0, 64).trim();
  const layout = cleanLayout(req.body?.layout);
  if (!name) return res.status(400).json({ error: 'name required' });
  if (!layout.length) return res.status(400).json({ error: 'layout is empty' });
  // every referenced host must be visible to this user (own or shared)
  const ids = layout.map((e) => e.host);
  const found = db
    .prepare(
      `SELECT id FROM hosts WHERE id IN (${ids.map(() => '?').join(',')}) AND (user_id = ? OR shared = 1)`
    )
    .all(...ids, req.user.id);
  const foundSet = new Set(found.map((r) => r.id));
  const clean = layout.filter((e) => foundSet.has(e.host));
  if (!clean.length) return res.status(400).json({ error: 'no usable hosts in layout' });
  const info = db
    .prepare('INSERT INTO workspaces (user_id, name, layout) VALUES (?, ?, ?)')
    .run(req.user.id, name, JSON.stringify(clean));
  auditReq(req, 'workspace.created', `${name} (${clean.length} sessions)`);
  const row = db.prepare('SELECT id, name, layout, created_at FROM workspaces WHERE id = ?').get(info.lastInsertRowid);
  res.json({ workspace: { ...row, layout: JSON.parse(row.layout) } });
});

router.delete('/:id', (req, res) => {
  const info = db
    .prepare('DELETE FROM workspaces WHERE id = ? AND user_id = ?')
    .run(req.params.id, req.user.id);
  if (!info.changes) return res.status(404).json({ error: 'not found' });
  res.json({ ok: true });
});

module.exports = router;
