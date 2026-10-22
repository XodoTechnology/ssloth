'use strict';

const express = require('express');
const { db } = require('../db');
const { auditReq } = require('../auth');

const router = express.Router();

// Playbooks: ordered command lists run step-by-step on a live terminal
// session (see ws/terminal.js — each step's exit code is verified before
// the next runs). steps is JSON [{command, description}].

function cleanPlaybook(body, { partial = false } = {}) {
  const out = {};
  if (!partial || body.name !== undefined) out.name = String(body.name ?? '').slice(0, 128).trim();
  if (!partial || body.description !== undefined) {
    out.description = String(body.description ?? '').slice(0, 2000).trim();
  }
  if (!partial || body.steps !== undefined) {
    if (!Array.isArray(body.steps)) throw new Error('steps must be an array');
    const steps = body.steps
      .slice(0, 100)
      .map((s) => ({
        command: String(s?.command ?? '').slice(0, 4000),
        description: String(s?.description ?? '').slice(0, 200),
        timeout_s: Math.min(Math.max(parseInt(s?.timeout_s, 10) || 60, 5), 3600),
      }))
      .filter((s) => s.command.trim());
    out.steps = JSON.stringify(steps);
  }
  return out;
}

function view(row) {
  let steps = [];
  try {
    steps = JSON.parse(row.steps);
  } catch {}
  return { ...row, steps };
}

router.get('/', (req, res) => {
  const rows = db
    .prepare('SELECT * FROM playbooks WHERE user_id = ? ORDER BY name COLLATE NOCASE')
    .all(req.user.id);
  res.json({ playbooks: rows.map(view) });
});

router.post('/', (req, res) => {
  let data;
  try {
    data = cleanPlaybook(req.body || {});
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }
  if (!data.name) return res.status(400).json({ error: 'name required' });
  const cols = Object.keys(data);
  const info = db
    .prepare(`INSERT INTO playbooks (user_id, ${cols.join(',')}) VALUES (?, ${cols.map(() => '?').join(',')})`)
    .run(req.user.id, ...cols.map((c) => data[c]));
  auditReq(req, 'playbook.created', data.name);
  res.json({ playbook: view(db.prepare('SELECT * FROM playbooks WHERE id = ?').get(info.lastInsertRowid)) });
});

router.put('/:id', (req, res) => {
  const existing = db
    .prepare('SELECT * FROM playbooks WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.user.id);
  if (!existing) return res.status(404).json({ error: 'not found' });
  let data;
  try {
    data = cleanPlaybook(req.body || {}, { partial: true });
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }
  const cols = Object.keys(data);
  if (cols.length) {
    db.prepare(
      `UPDATE playbooks SET ${cols.map((c) => `${c} = ?`).join(', ')}, updated_at = unixepoch() WHERE id = ?`
    ).run(...cols.map((c) => data[c]), existing.id);
  }
  res.json({ playbook: view(db.prepare('SELECT * FROM playbooks WHERE id = ?').get(existing.id)) });
});

router.delete('/:id', (req, res) => {
  const r = db.prepare('DELETE FROM playbooks WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  if (!r.changes) return res.status(404).json({ error: 'not found' });
  auditReq(req, 'playbook.deleted', `id ${req.params.id}`);
  res.json({ ok: true });
});

module.exports = router;
