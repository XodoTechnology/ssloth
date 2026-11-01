// Fleet host-key monitoring: every 30 min, re-scan each SSH host's key and
// compare it with the fingerprint the user already trusted. A drift (changed
// key outside of a legitimate reinstall) is the classic MITM signature, so it
// surfaces on the host card and in the audit log rather than failing silently.

const { db } = require('./db');
const { scanHostKey } = require('./ssh/keyscan');
const { audit } = require('./db');

const SWEEP_EVERY_MS = 30 * 60 * 1000;

async function checkHost(host) {
  const trusted = db
    .prepare('SELECT fingerprint FROM hostkeys WHERE user_id = ? AND hostname = ? AND port = ?')
    .get(host.user_id, host.hostname, host.port || 22);
  if (!trusted) {
    db.prepare('UPDATE hosts SET hostkey_status = ?, hostkey_checked_at = unixepoch() WHERE id = ?')
      .run('untrusted', host.id);
    return;
  }
  let status = 'ok';
  try {
    const r = await scanHostKey(host.hostname, host.port || 22);
    if (r.fingerprint !== trusted.fingerprint) {
      status = 'changed';
      audit({ id: host.user_id, username: 'monitor' }, 'hostkey.changed',
        `${host.hostname}:${host.port || 22} expected ${trusted.fingerprint.slice(0, 24)}…, got ${r.fingerprint.slice(0, 24)}…`, null);
    }
  } catch {
    status = 'unreachable';
  }
  db.prepare('UPDATE hosts SET hostkey_status = ?, hostkey_checked_at = unixepoch() WHERE id = ?')
    .run(status, host.id);
}

async function sweep() {
  let hosts;
  try {
    hosts = db.prepare("SELECT id, user_id, hostname, port FROM hosts WHERE protocol IS NULL OR protocol = 'ssh'").all();
  } catch { return; }
  for (const h of hosts) {
    try { await checkHost(h); } catch {}
  }
}

let timer = null;
function start() {
  if (timer) return;
  setTimeout(sweep, 2 * 60 * 1000); // first pass 2 min after boot
  timer = setInterval(sweep, SWEEP_EVERY_MS);
  timer.unref?.();
}

module.exports = { start };
