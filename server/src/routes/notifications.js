// Sensor-alert rules CRUD + the notifications feed the bell UI reads.
const express = require('express');
const { db } = require('../db');
const { auditReq } = require('../auth');
const notifications = require('../notifications');

const router = express.Router();

// ---- alert rules ----
const ruleView = (r) => ({
  id: r.id, host_id: r.host_id, sensor: r.sensor, min_tier: r.min_tier,
  enabled: !!r.enabled, created_at: r.created_at,
});

router.get('/rules', (req, res) => {
  const rows = db.prepare('SELECT * FROM sensor_alert_rules WHERE user_id = ? ORDER BY id').all(req.user.id);
  res.json({ rules: rows.map(ruleView) });
});

router.post('/rules', (req, res) => {
  const { host_id, sensor, min_tier, enabled } = req.body || {};
  const tier = min_tier === 'warn' ? 'warn' : 'bad';
  if (host_id != null) {
    const h = db.prepare('SELECT id FROM hosts WHERE id = ? AND (user_id = ? OR shared = 1)').get(host_id, req.user.id);
    if (!h) return res.status(400).json({ error: 'host not found' });
  }
  const info = db
    .prepare('INSERT INTO sensor_alert_rules (user_id, host_id, sensor, min_tier, enabled) VALUES (?, ?, ?, ?, ?)')
    .run(req.user.id, host_id ? parseInt(host_id, 10) : null,
         String(sensor || '').slice(0, 120), tier, enabled === 0 ? 0 : 1);
  auditReq(req, 'sensor_rule.created', `${tier} on ${sensor || 'any sensor'}`);
  res.json({ rule: ruleView(db.prepare('SELECT * FROM sensor_alert_rules WHERE id = ?').get(info.lastInsertRowid)) });
});

router.put('/rules/:id', (req, res) => {
  const r = db.prepare('SELECT * FROM sensor_alert_rules WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!r) return res.status(404).json({ error: 'not found' });
  const enabled = req.body?.enabled !== undefined ? (req.body.enabled ? 1 : 0) : r.enabled;
  db.prepare('UPDATE sensor_alert_rules SET enabled = ? WHERE id = ?').run(enabled, r.id);
  res.json({ rule: ruleView({ ...r, enabled }) });
});

router.delete('/rules/:id', (req, res) => {
  db.prepare('DELETE FROM sensor_alert_rules WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  db.prepare('DELETE FROM sensor_alert_state WHERE rule_id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ---- notification feed ----
router.get('/', (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), 200);
  res.json({
    notifications: notifications.list(req.user.id, { unreadOnly: req.query.unread === '1', limit }),
    unread: notifications.unreadCount(req.user.id),
  });
});

router.get('/unread', (req, res) => {
  res.json({ count: notifications.unreadCount(req.user.id) });
});

router.post('/:id/read', (req, res) => {
  notifications.markRead(req.user.id, parseInt(req.params.id, 10));
  res.json({ ok: true });
});

router.post('/read-all', (req, res) => {
  res.json({ ok: true, count: notifications.markAllRead(req.user.id) });
});

router.delete('/:id', (req, res) => {
  notifications.remove(req.user.id, parseInt(req.params.id, 10));
  res.json({ ok: true });
});

module.exports = router;
