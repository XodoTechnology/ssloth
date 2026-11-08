// BMC sensor history + alerting: a ring of recent readings per host, filled
// by the live sensors endpoint whenever someone views it and by a slow
// background sweep so charts have continuity. Samples also persist to
// sensor_history (throttled), and sensor_alert_rules turn status-tier
// crossings into notifications + webhooks + audit rows.

const { bmc, applyRoutes, releaseRoute } = require('./bmc');
const { db, audit } = require('./db');
const { resolveConnectSpec } = require('./ssh/manager');
const { sensorTier, tierAtLeast } = require('./sensor-tier');
const notifications = require('./notifications');

const SAMPLES_PER_HOST = 200; // ~16h at the 5-min sweep
const SWEEP_EVERY_MS = 5 * 60 * 1000;
const HISTORY_MIN_INTERVAL_MS = 60 * 1000; // live views shouldn't flood the table
const history = new Map(); // hostId -> [{t, entries, source}]
const lastErr = new Map(); // hostId -> error string from the last failed sweep
const lastPersist = new Map(); // hostId -> ms of last sensor_history write

const stmtHost = db.prepare('SELECT id, user_id, name, hostname FROM hosts WHERE id = ?');
const stmtRules = db.prepare(
  'SELECT id, host_id, sensor, min_tier FROM sensor_alert_rules WHERE user_id = ? AND enabled = 1 AND (host_id = ? OR host_id IS NULL)'
);
const stmtState = db.prepare(
  'SELECT tier FROM sensor_alert_state WHERE rule_id = ? AND host_id = ? AND sensor = ?'
);
const stmtStateUpsert = db.prepare(
  `INSERT INTO sensor_alert_state (rule_id, host_id, sensor, tier, updated_at) VALUES (?, ?, ?, ?, unixepoch())
   ON CONFLICT(rule_id, host_id, sensor) DO UPDATE SET tier = excluded.tier, updated_at = unixepoch()`
);
const stmtHistInsert = db.prepare(
  'INSERT INTO sensor_history (host_id, t, name, reading, units, status) VALUES (?, ?, ?, ?, ?, ?)'
);

function record(hostId, sensors) {
  if (!sensors || !Array.isArray(sensors.entries) || !sensors.entries.length) return;
  const t = Date.now();
  const arr = history.get(hostId) || [];
  arr.push({ t, source: sensors.source || '', entries: sensors.entries });
  if (arr.length > SAMPLES_PER_HOST) arr.splice(0, arr.length - SAMPLES_PER_HOST);
  history.set(hostId, arr);
  maybePersist(hostId, t, sensors.entries);
  evalAlerts(hostId, sensors.entries);
}

/// One row per entry per sample — but at most once a minute per host, so
/// someone leaving the sensors page open doesn't write a row per repaint.
function maybePersist(hostId, t, entries) {
  const last = lastPersist.get(hostId) || 0;
  if (t - last < HISTORY_MIN_INTERVAL_MS) return;
  lastPersist.set(hostId, t);
  const rows = [];
  for (const e of entries) {
    rows.push(hostId, Math.floor(t / 1000), String(e.name || ''),
      String(e.reading ?? ''), String(e.units || ''), String(e.status || ''));
  }
  try {
    db.transaction(() => {
      for (let i = 0; i < rows.length; i += 6) stmtHistInsert.run(...rows.slice(i, i + 6));
    })();
  } catch {}
}

/// Transition detection: compare each entry's tier with what the state table
/// last saw for this rule+sensor. Only crossings notify; a sensor that stays
/// bad for a week alerts once, not 288 times a day.
function evalAlerts(hostId, entries) {
  const host = stmtHost.get(hostId);
  if (!host) return;
  const rules = stmtRules.all(host.user_id, hostId);
  if (!rules.length) return;
  const hostLabel = host.name || host.hostname || `host ${hostId}`;
  for (const rule of rules) {
    const pat = String(rule.sensor || '').toLowerCase();
    for (const e of entries) {
      const name = String(e.name || '');
      if (pat && !name.toLowerCase().includes(pat)) continue;
      const tier = sensorTier(e.status);
      const prev = stmtState.get(rule.id, hostId, name);
      const wasAlerting = prev ? tierAtLeast(prev.tier, rule.min_tier) : false;
      const alerting = tierAtLeast(tier, rule.min_tier);
      if (prev && prev.tier === tier) continue; // nothing moved
      stmtStateUpsert.run(rule.id, hostId, name, tier);
      if (alerting === wasAlerting) continue;
      const detail = `${e.reading ?? ''} ${e.units ?? ''}`.trim();
      const body = `${e.status}${detail ? ` — ${detail}` : ''}`;
      if (alerting) {
        notifications.push(host.user_id, 'sensor.alert',
          `${name} on ${hostLabel}`, body, '/bmc');
        audit({ id: host.user_id, username: 'sensors' }, 'sensor.alert',
          `${hostLabel}: ${name} ${body}`);
      } else {
        notifications.push(host.user_id, 'sensor.recovered',
          `${name} on ${hostLabel} recovered`, body, '/bmc');
      }
    }
  }
}

function getHistory(hostId) {
  return history.get(hostId) || [];
}

function latest(hostId) {
  const arr = history.get(hostId);
  return arr && arr.length ? arr[arr.length - 1] : null;
}

let sweepSeq = 0;
function specFor(hostRow, holderId) {
  const spec = resolveConnectSpec(hostRow.user_id, { hostId: hostRow.id });
  applyRoutes(resolveConnectSpec, hostRow.user_id, spec, { id: holderId });
  return { host: spec.hostname, user: spec.username || '', pass: spec.password || '' };
}

async function sweep() {
  if (!bmc) return;
  let hosts;
  try {
    hosts = db.prepare("SELECT id, user_id FROM hosts WHERE protocol = 'bmc' AND COALESCE(sensor_exclude,0) = 0").all();
  } catch { return; }
  for (const h of hosts) {
    const hid = `sensors-${h.id}-${++sweepSeq}`;
    let spec = null;
    try {
      spec = specFor(h, hid);
      const s = JSON.parse(await bmc.readSensors(spec));
      record(h.id, s);
      lastErr.delete(h.id);
    } catch (e) {
      lastErr.set(h.id, String(e && e.message || e).slice(0, 140));
    } finally {
      if (spec) {
        try { releaseRoute(spec.host, hid); } catch {}
      }
    }
  }
}

/// Trim sensor_history beyond the retention window — runs on the sweep so a
/// quiet server doesn't carry the table forever.
const RETENTION_DAYS = 30;
function pruneHistory() {
  try {
    db.prepare('DELETE FROM sensor_history WHERE t < unixepoch() - ?')
      .run(RETENTION_DAYS * 86400);
  } catch {}
}

let timer = null;
function start() {
  if (timer) return;
  setTimeout(sweep, 45 * 1000); // let the server settle first
  timer = setInterval(() => { sweep(); pruneHistory(); }, SWEEP_EVERY_MS);
  timer.unref?.();
}

module.exports = { record, getHistory, latest, start, lastErr: (id) => lastErr.get(id) || null };
