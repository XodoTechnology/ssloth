// BMC sensor history: a ring of recent readings per host, filled by the
// live sensors endpoint whenever someone views it and by a slow background
// sweep so charts have continuity. Memory-only — restarts lose history, and
// nothing extra hits the BMC's session pool when nobody is looking.

const { bmc, applyRoutes } = require('./bmc');
const db = require('./db');
const { resolveConnectSpec } = require('./ssh/manager');

const SAMPLES_PER_HOST = 200; // ~16h at the 5-min sweep
const SWEEP_EVERY_MS = 5 * 60 * 1000;
const history = new Map(); // hostId -> [{t, entries, source}]

function record(hostId, sensors) {
  if (!sensors || !Array.isArray(sensors.entries) || !sensors.entries.length) return;
  const arr = history.get(hostId) || [];
  arr.push({ t: Date.now(), source: sensors.source || '', entries: sensors.entries });
  if (arr.length > SAMPLES_PER_HOST) arr.splice(0, arr.length - SAMPLES_PER_HOST);
  history.set(hostId, arr);
}

function getHistory(hostId) {
  return history.get(hostId) || [];
}

function latest(hostId) {
  const arr = history.get(hostId);
  return arr && arr.length ? arr[arr.length - 1] : null;
}

function specFor(hostRow) {
  const spec = resolveConnectSpec(hostRow.user_id, { hostId: hostRow.id });
  applyRoutes(resolveConnectSpec, hostRow.user_id, spec);
  return { host: spec.hostname, user: spec.username || '', pass: spec.password || '' };
}

async function sweep() {
  if (!bmc) return;
  let hosts;
  try {
    hosts = db.prepare("SELECT id, user_id FROM hosts WHERE protocol = 'bmc' AND COALESCE(sensor_exclude,0) = 0").all();
  } catch { return; }
  for (const h of hosts) {
    try {
      const spec = specFor(h);
      const s = JSON.parse(await bmc.readSensors(spec));
      record(h.id, s);
    } catch {
      // unreachable hosts are routine; the next sweep retries quietly
    }
  }
}

let timer = null;
function start() {
  if (timer) return;
  setTimeout(sweep, 45 * 1000); // let the server settle first
  timer = setInterval(sweep, SWEEP_EVERY_MS);
  timer.unref?.();
}

module.exports = { record, getHistory, latest, start };
