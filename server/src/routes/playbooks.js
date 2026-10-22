'use strict';

const express = require('express');
const { db } = require('../db');
const { auditReq } = require('../auth');
const { TEMPLATES } = require('../templates');
const { cronMatches, nextCron, runPlaybookDetached, stopRun } = require('../ssh/runner');

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
  // schedule: cron string + target host. next_run_at is derived server-side.
  if (!partial || body.schedule_cron !== undefined) {
    const c = String(body.schedule_cron ?? '').trim();
    if (c && !nextCron(c)) throw new Error('invalid cron expression');
    out.schedule_cron = c || null;
    out.next_run_at = c ? Math.floor(nextCron(c) / 1000) : null;
  }
  if (!partial || body.schedule_host_id !== undefined) {
    out.schedule_host_id = body.schedule_host_id ? parseInt(body.schedule_host_id, 10) : null;
  }
  if (!partial || body.schedule_enabled !== undefined) {
    out.schedule_enabled = body.schedule_enabled ? 1 : 0;
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
  // enabling a schedule with no fresh cron string re-derives next_run_at
  // from the stored expression (or clears it when disabling).
  const effCron = data.schedule_cron !== undefined ? data.schedule_cron : existing.schedule_cron;
  const effEnabled = data.schedule_enabled !== undefined ? data.schedule_enabled : existing.schedule_enabled;
  if (effEnabled && effCron && data.next_run_at === undefined) {
    data.next_run_at = Math.floor(nextCron(effCron) / 1000);
  }
  if (data.schedule_enabled === 0 || (data.schedule_cron === null && effEnabled)) {
    data.next_run_at = null;
  }

  const cols = Object.keys(data);
  if (cols.length) {
    db.prepare(
      `UPDATE playbooks SET ${cols.map((c) => `${c} = ?`).join(', ')}, updated_at = unixepoch() WHERE id = ?`
    ).run(...cols.map((c) => data[c]), existing.id);
  }
  res.json({ playbook: view(db.prepare('SELECT * FROM playbooks WHERE id = ?').get(existing.id)) });
});

// --- template gallery ---
router.get('/templates', (req, res) => {
  res.json({ templates: TEMPLATES.map(({ key, name, description, steps }) => ({ key, name, description, steps })) });
});

router.post('/templates/:key', (req, res) => {
  const t = TEMPLATES.find((x) => x.key === req.params.key);
  if (!t) return res.status(404).json({ error: 'unknown template' });
  const info = db
    .prepare('INSERT INTO playbooks (user_id, name, description, steps) VALUES (?, ?, ?, ?)')
    .run(req.user.id, t.name, t.description, JSON.stringify(t.steps));
  auditReq(req, 'playbook.templated', t.name);
  res.json({ playbook: view(db.prepare('SELECT * FROM playbooks WHERE id = ?').get(info.lastInsertRowid)) });
});

// --- detached runs (REST trigger + history) ---
router.post('/:id/run', (req, res) => {
  const pb = db.prepare('SELECT * FROM playbooks WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!pb) return res.status(404).json({ error: 'not found' });
  const hostId = parseInt(req.body?.host_id, 10);
  const host = db.prepare('SELECT * FROM hosts WHERE id = ? AND (user_id = ? OR shared = 1)').get(hostId, req.user.id);
  if (!host) return res.status(404).json({ error: 'host not found' });
  if (host.protocol && host.protocol !== 'ssh') return res.status(400).json({ error: 'host is not SSH' });
  auditReq(req, 'playbook.run_triggered', `${pb.name} on ${host.name || host.hostname}`);
  const { runId } = runPlaybookDetached(req.user.id, pb, host, 'manual');
  res.json({ run_id: runId });
});

router.get('/runs', (req, res) => {
  const rows = db
    .prepare('SELECT id, playbook_id, host_id, name, host_label, trigger, status, started_at, ended_at, length(output) AS out_len FROM playbook_runs WHERE user_id = ? ORDER BY id DESC LIMIT 100')
    .all(req.user.id);
  res.json({ runs: rows });
});

router.get('/runs/:id', (req, res) => {
  const row = db.prepare('SELECT * FROM playbook_runs WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!row) return res.status(404).json({ error: 'not found' });
  res.json({ run: row });
});

router.post('/runs/:id/stop', (req, res) => {
  const row = db.prepare('SELECT id FROM playbook_runs WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!row) return res.status(404).json({ error: 'not found' });
  stopRun(row.id);
  res.json({ ok: true });
});

router.delete('/:id', (req, res) => {
  const r = db.prepare('DELETE FROM playbooks WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  if (!r.changes) return res.status(404).json({ error: 'not found' });
  auditReq(req, 'playbook.deleted', `id ${req.params.id}`);
  res.json({ ok: true });
});

module.exports = router;
