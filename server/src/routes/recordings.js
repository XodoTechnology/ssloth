'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');
const readline = require('readline');
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

// Search output text across this user's recordings — "which session ran X".
// Casts are JSONL ([t,'o',data]); we scan the data payloads only. Files are
// streamed line-by-line so a search never blocks the event loop, and a
// deadline bounds total work — partial results beat a stalled server.
const SEARCH_DEADLINE_MS = 20 * 1000;
router.get('/search', async (req, res) => {
  try {
    const q = String(req.query.q || '').slice(0, 200);
    if (!q) return res.status(400).json({ error: 'q required' });
    const rows = db
      .prepare('SELECT id, label, file, started_at, size FROM recordings WHERE user_id = ? ORDER BY id DESC LIMIT 200')
      .all(req.user.id);
    const needle = q.toLowerCase();
    const hits = [];
    const deadline = Date.now() + SEARCH_DEADLINE_MS;
    let truncated = false;
    for (const r of rows) {
      if (Date.now() > deadline) { truncated = true; break; }
      const full = path.join(REC_DIR, path.basename(r.file));
      if (!full.startsWith(REC_DIR) || !fs.existsSync(full)) continue;
      try {
        let count = 0, firstTs = null;
        const rl = readline.createInterface({
          input: fs.createReadStream(full, { encoding: 'utf8' }),
          crlfDelay: Infinity,
        });
        for await (const line of rl) {
          if (!line.startsWith('[')) continue;
          // cheap pre-filter before JSON.parse on every line
          if (!line.toLowerCase().includes(needle)) continue;
          let ev;
          try { ev = JSON.parse(line); } catch { continue; }
          if (ev[1] === 'o' && typeof ev[2] === 'string' && ev[2].toLowerCase().includes(needle)) {
            count++;
            if (firstTs === null) firstTs = ev[0];
          }
        }
        if (count) hits.push({ id: r.id, label: r.label, started_at: r.started_at * 1000, hits: count, first_t: firstTs });
      } catch {}
    }
    res.json({ query: q, results: hits, truncated });
  } catch (e) {
    res.status(500).json({ error: 'search failed' });
  }
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
