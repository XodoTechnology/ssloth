'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');
const { db } = require('../db');
const { auditReq } = require('../auth');
const { REC_DIR } = require('../ssh/recorder');

const router = express.Router();

router.get('/', (req, res) => {
  const rows = db
    .prepare('SELECT id, session_id, label, size, started_at, ended_at FROM recordings WHERE user_id = ? ORDER BY id DESC LIMIT 200')
    .all(req.user.id);
  res.json({
    recordings: rows.map((r) => ({
      ...r,
      started_at: r.started_at * 1000,
      ended_at: r.ended_at ? r.ended_at * 1000 : null,
    })),
  });
});

// Raw cast content for the replay player / download.
router.get('/:id/content', (req, res) => {
  const row = db.prepare('SELECT * FROM recordings WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!row) return res.status(404).json({ error: 'not found' });
  const file = path.basename(row.file);
  const full = path.join(REC_DIR, file);
  if (!full.startsWith(REC_DIR) || !fs.existsSync(full)) return res.status(404).json({ error: 'file missing' });
  if (req.query.download === '1') {
    res.setHeader('Content-Disposition', `attachment; filename="ssloth-${row.id}.cast"`);
  }
  res.setHeader('Content-Type', 'application/x-asciicast');
  fs.createReadStream(full).pipe(res);
});

router.delete('/:id', (req, res) => {
  const row = db.prepare('SELECT * FROM recordings WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!row) return res.status(404).json({ error: 'not found' });
  try {
    fs.unlinkSync(row.file);
  } catch {}
  db.prepare('DELETE FROM recordings WHERE id = ?').run(row.id);
  auditReq(req, 'recording.deleted', row.label);
  res.json({ ok: true });
});

module.exports = router;
