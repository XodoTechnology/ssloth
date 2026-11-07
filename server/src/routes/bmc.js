// BMC fleet overview: one call → every BMC host's monitoring state (latest
// sensor sample, host-key status, exclusion flag) for the dashboard page.
const express = require('express');
const { db } = require('../db');
const { auditReq } = require('../auth');
const { resolveConnectSpec } = require('../ssh/manager');
const sensorsPoll = require('../sensors-poll');
const { bmc, applyRoutes } = require('../bmc');

const router = express.Router();

router.get('/overview', (req, res) => {
  const hosts = db
    .prepare("SELECT id, name, hostname, sensor_exclude, hostkey_status, hostkey_checked_at FROM hosts WHERE protocol = 'bmc' AND (user_id = ? OR shared = 1) ORDER BY name COLLATE NOCASE")
    .all(req.user.id);
  res.json({
    bmc_available: !!bmc,
    hosts: hosts.map((h) => ({
      ...h,
      sensor_exclude: !!h.sensor_exclude,
      latest: sensorsPoll.latest(h.id) || null,
      sweep_error: sensorsPoll.lastErr(h.id),
    })),
  });
});

// ---- bulk actions across selected dashboard hosts ----
// {host_ids: [], action: 'power'|'mc-reset'|'sensor-exclude', value, family?}
// Power/MC-reset fan out through the addon at concurrency 4 — each is a
// blocking HTTP/IPMI call, and a 20-host power-on shouldn't serialize for
// minutes. Per-host failures are captured, never abort the batch.
const BULK_ACTIONS = new Set(['power', 'mc-reset', 'sensor-exclude']);
const POWER_ACTIONS = new Set(['on', 'off', 'reset', 'cycle', 'soft']);
const BULK_CONCURRENCY = 4;

router.post('/bulk', async (req, res) => {
  const { host_ids, action, value, family } = req.body || {};
  if (!BULK_ACTIONS.has(action)) return res.status(400).json({ error: 'action must be power|mc-reset|sensor-exclude' });
  const ids = [...new Set((Array.isArray(host_ids) ? host_ids : []).map((x) => parseInt(x, 10)).filter(Number.isInteger))].slice(0, 100);
  if (!ids.length) return res.status(400).json({ error: 'host_ids required' });

  // Ownership/scope check up front — a bulk call must not touch hosts the
  // user can't already see on the dashboard.
  const q = db.prepare(`SELECT id, name, hostname FROM hosts WHERE id = ? AND protocol = 'bmc' AND (user_id = ? OR shared = 1)`);
  const hosts = ids.map((id) => q.get(id, req.user.id)).filter(Boolean);
  if (!hosts.length) return res.status(404).json({ error: 'no matching BMC hosts' });

  if (action === 'sensor-exclude') {
    const exclude = value ? 1 : 0;
    const upd = db.prepare('UPDATE hosts SET sensor_exclude = ? WHERE id = ?');
    const results = hosts.map((h) => {
      upd.run(exclude, h.id);
      return { id: h.id, ok: true, message: exclude ? 'monitoring excluded' : 'monitoring included' };
    });
    auditReq(req, 'bmc.bulk', `sensor_exclude=${exclude} ×${results.length}`);
    return res.json({ ok: true, results });
  }

  if (!bmc) return res.status(503).json({ error: `bmc addon unavailable` });
  if (action === 'power' && !POWER_ACTIONS.has(value)) {
    return res.status(400).json({ error: 'power value must be on|off|reset|cycle|soft' });
  }

  const specFor = (hostId) => {
    const spec = resolveConnectSpec(req.user.id, { hostId });
    applyRoutes(resolveConnectSpec, req.user.id, spec);
    return { host: spec.hostname, user: spec.username || '', pass: spec.password || '' };
  };

  const results = new Array(hosts.length);
  let next = 0;
  const worker = async () => {
    while (next < hosts.length) {
      const i = next++;
      const h = hosts[i];
      try {
        const spec = specFor(h.id);
        const message =
          action === 'mc-reset'
            ? await bmc.bmcReset(spec)
            : value === 'cycle'
              ? await bmc.ipmiPower(spec, value)
              : await bmc.powerCmd(spec, value, family || null);
        // The addon reports failures inside the message ("power on failed:
        // …") rather than throwing — surface them as per-host errors.
        results[i] = /\bfailed\b/i.test(message) ? { id: h.id, ok: false, message } : { id: h.id, ok: true, message };
      } catch (e) {
        results[i] = { id: h.id, ok: false, message: e.message };
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(BULK_CONCURRENCY, hosts.length) }, worker));
  auditReq(req, 'bmc.bulk', `${action} ${value || ''} ×${results.filter((r) => r.ok).length}/${results.length}`);
  res.json({ ok: results.every((r) => r.ok), results });
});

// ---- host groups: named BMC-host sets for bulk selection ----
const groupView = (g) => ({
  id: g.id,
  name: g.name,
  host_ids: db.prepare('SELECT host_id FROM host_group_members WHERE group_id = ?').all(g.id).map((r) => r.host_id),
});

const ownGroup = (req, id) =>
  db.prepare('SELECT * FROM host_groups WHERE id = ? AND user_id = ?').get(id, req.user.id);

router.get('/groups', (req, res) => {
  const rows = db.prepare('SELECT * FROM host_groups WHERE user_id = ? ORDER BY name COLLATE NOCASE').all(req.user.id);
  res.json({ groups: rows.map(groupView) });
});

router.post('/groups', (req, res) => {
  const name = String(req.body?.name || '').trim().slice(0, 80);
  if (!name) return res.status(400).json({ error: 'name required' });
  const hostIds = (Array.isArray(req.body?.host_ids) ? req.body.host_ids : [])
    .map((x) => parseInt(x, 10)).filter(Number.isInteger).slice(0, 200);
  const own = db.prepare(`SELECT id FROM hosts WHERE id = ? AND protocol = 'bmc' AND (user_id = ? OR shared = 1)`);
  const valid = hostIds.filter((id) => own.get(id, req.user.id));
  const info = db.prepare('INSERT INTO host_groups (user_id, name) VALUES (?, ?)').run(req.user.id, name);
  const ins = db.prepare('INSERT OR IGNORE INTO host_group_members (group_id, host_id) VALUES (?, ?)');
  for (const id of valid) ins.run(info.lastInsertRowid, id);
  auditReq(req, 'bmc.group', `created "${name}" (${valid.length} hosts)`);
  res.json({ group: groupView(ownGroup(req, info.lastInsertRowid)) });
});

router.put('/groups/:id', (req, res) => {
  const g = ownGroup(req, req.params.id);
  if (!g) return res.status(404).json({ error: 'not found' });
  if (req.body?.name !== undefined) {
    const name = String(req.body.name).trim().slice(0, 80);
    if (!name) return res.status(400).json({ error: 'name required' });
    db.prepare('UPDATE host_groups SET name = ? WHERE id = ?').run(name, g.id);
  }
  if (Array.isArray(req.body?.host_ids)) {
    const own = db.prepare(`SELECT id FROM hosts WHERE id = ? AND protocol = 'bmc' AND (user_id = ? OR shared = 1)`);
    const valid = [...new Set(req.body.host_ids.map((x) => parseInt(x, 10)).filter(Number.isInteger))]
      .filter((id) => own.get(id, req.user.id)).slice(0, 200);
    db.prepare('DELETE FROM host_group_members WHERE group_id = ?').run(g.id);
    const ins = db.prepare('INSERT INTO host_group_members (group_id, host_id) VALUES (?, ?)');
    for (const id of valid) ins.run(g.id, id);
  }
  res.json({ group: groupView(ownGroup(req, g.id)) });
});

router.delete('/groups/:id', (req, res) => {
  const g = ownGroup(req, req.params.id);
  if (!g) return res.status(404).json({ error: 'not found' });
  db.prepare('DELETE FROM host_groups WHERE id = ?').run(g.id);
  auditReq(req, 'bmc.group', `deleted "${g.name}"`);
  res.json({ ok: true });
});

module.exports = router;
