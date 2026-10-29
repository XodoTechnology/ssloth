'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');
const net = require('net');
const dgram = require('dgram');
const { db } = require('../db');
const { encryptSecret } = require('../crypto');
const { auditReq } = require('../auth');
const { listHostKeys, removeHostKey, trustHostKey, getStoredHostKey, resolveConnectSpec } = require('../ssh/manager');
const { bmc, bmcError, applyRoutes } = require('../bmc');
const { scanHostKey } = require('../ssh/keyscan');
const { getHealthHistory, latestHealth } = require('../health');

const router = express.Router();
const { stopTunnelsForHost } = require('./tunnels');

const AUTH_TYPES = new Set(['credential', 'password', 'ask']);
const PROTOCOLS = new Set(['ssh', 'telnet', 'bmc']);

function cleanHostInput(body, { partial = false } = {}) {
  const out = {};
  const str = (v, max = 255) => String(v ?? '').slice(0, max).trim();

  if (!partial || body.name !== undefined) out.name = str(body.name, 128);
  if (!partial || body.hostname !== undefined) out.hostname = str(body.hostname, 255);
  if (!partial || body.port !== undefined) {
    const p = parseInt(body.port, 10);
    if (!Number.isInteger(p) || p < 1 || p > 65535) throw new Error('invalid port');
    out.port = p;
  }
  if (!partial || body.username !== undefined) out.username = str(body.username, 64);
  if (!partial || body.auth_type !== undefined) {
    if (!AUTH_TYPES.has(body.auth_type)) throw new Error('invalid auth_type');
    out.auth_type = body.auth_type;
  }
  if (!partial || body.credential_id !== undefined) {
    out.credential_id = body.credential_id == null ? null : parseInt(body.credential_id, 10);
  }
  if (!partial || body.jump_host_id !== undefined) {
    out.jump_host_id = body.jump_host_id == null ? null : parseInt(body.jump_host_id, 10);
  }
  if (!partial || body.record !== undefined) {
    out.record = body.record ? 1 : 0;
  }
  if (!partial || body.pinned !== undefined) {
    out.pinned = body.pinned ? 1 : 0;
  }
  if (!partial || body.shared !== undefined) {
    out.shared = body.shared ? 1 : 0;
  }
  if (!partial || body.region !== undefined) out.region = str(body.region, 128);
  if (!partial || body.tags !== undefined) {
    // normalize: "#Routers, core" -> "routers core" (space-separated, deduped)
    const tags = String(body.tags ?? '')
      .split(/[\s,]+/)
      .map((t) => t.replace(/^#+/, '').trim().toLowerCase())
      .filter(Boolean);
    out.tags = [...new Set(tags)].slice(0, 32).join(' ');
  }
  if (!partial || body.folder !== undefined) out.folder = str(body.folder, 128);
  if (!partial || body.color !== undefined) out.color = str(body.color, 32);
  if (!partial || body.notes !== undefined) out.notes = String(body.notes ?? '').slice(0, 4000);
  if (!partial || body.keepalive !== undefined) {
    const k = parseInt(body.keepalive, 10);
    out.keepalive = Number.isInteger(k) && k >= 0 && k <= 300 ? k : 15;
  }
  if (!partial || body.protocol !== undefined) {
    const p = String(body.protocol ?? 'ssh').toLowerCase();
    if (!PROTOCOLS.has(p)) throw new Error('invalid protocol');
    out.protocol = p;
  }
  if (!partial || body.mac !== undefined) {
    const mac = str(body.mac, 17).toUpperCase();
    if (mac && !/^([0-9A-F]{2}[:-]){5}[0-9A-F]{2}$/.test(mac)) throw new Error('invalid MAC address');
    out.mac = mac;
  }
  if (!partial || body.agent_forward !== undefined) {
    out.agent_forward = body.agent_forward ? 1 : 0;
  }
  // Secret fields are only updated when explicitly provided.
  if (body.password !== undefined) {
    out.password_enc = body.password ? encryptSecret(String(body.password)) : null;
  }
  return out;
}

function hostView(row, userId) {
  const { password_enc, ...rest } = row;
  return { ...rest, has_password: !!password_enc, owned: row.user_id === userId };
}

router.get('/', (req, res) => {
  // Own hosts plus shared ones from other users (annotated with the owner's
  // name; `owned` tells the UI what's editable).
  const rows = db
    .prepare(
      `SELECT h.*, u.username AS owner_name FROM hosts h
       LEFT JOIN users u ON u.id = h.user_id
       WHERE h.user_id = ? OR h.shared = 1
       ORDER BY h.folder, h.name COLLATE NOCASE`
    )
    .all(req.user.id);
  res.json({ hosts: rows.map((r) => hostView(r, req.user.id)) });
});

router.post('/', (req, res) => {
  let data;
  try {
    data = cleanHostInput(req.body || {});
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }
  if (!data.name || !data.hostname || !data.username) {
    return res.status(400).json({ error: 'name, hostname and username are required' });
  }
  if (data.shared === 1 && !req.user.is_admin) {
    return res.status(403).json({ error: 'only admins can share hosts' });
  }
  if (data.auth_type === 'credential' && !data.credential_id) {
    return res.status(400).json({ error: 'credential_id required for credential auth' });
  }
  // Don't store secrets that don't match the auth mode.
  if (data.auth_type !== 'password') delete data.password_enc;
  if (data.auth_type === 'password' || data.auth_type === 'ask') data.credential_id = null;
  if (data.credential_id != null) {
    const cred = db
      .prepare('SELECT id FROM credentials WHERE id = ? AND user_id = ?')
      .get(data.credential_id, req.user.id);
    if (!cred) return res.status(400).json({ error: 'credential not found' });
  }
  if (data.jump_host_id != null) {
    const jump = db
      .prepare('SELECT id FROM hosts WHERE id = ? AND (user_id = ? OR shared = 1)')
      .get(data.jump_host_id, req.user.id);
    if (!jump) return res.status(400).json({ error: 'bastion host not found' });
    if (data.jump_host_id === -1) return res.status(400).json({ error: 'invalid bastion' });
  }
  const cols = Object.keys(data);
  const info = db
    .prepare(`INSERT INTO hosts (user_id, ${cols.join(',')}) VALUES (?, ${cols.map(() => '?').join(',')})`)
    .run(req.user.id, ...cols.map((c) => data[c]));
  auditReq(req, 'host.created', `${data.name} (${data.username}@${data.hostname}:${data.port ?? 22})`);
  const row = db.prepare('SELECT * FROM hosts WHERE id = ?').get(info.lastInsertRowid);
  res.json({ host: hostView(row) });
});

router.put('/:id', (req, res) => {
  const existing = db.prepare('SELECT * FROM hosts WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!existing) return res.status(404).json({ error: 'not found' });
  let data;
  try {
    data = cleanHostInput(req.body || {}, { partial: true });
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }
  if (data.shared === 1 && !req.user.is_admin) {
    return res.status(403).json({ error: 'only admins can share hosts' });
  }
  // Auth-mode changes drop the secrets that no longer apply — otherwise a
  // stale password_enc lingers (and still gets exported) after switching
  // to credential/ask auth.
  const nextAuth = data.auth_type ?? existing.auth_type;
  if (nextAuth !== 'password' && req.body.password === undefined) {
    data.password_enc = null;
  }
  if (nextAuth !== 'credential' && req.body.credential_id === undefined) {
    data.credential_id = null;
  }
  if (data.credential_id != null) {
    const cred = db
      .prepare('SELECT id FROM credentials WHERE id = ? AND user_id = ?')
      .get(data.credential_id, req.user.id);
    if (!cred) return res.status(400).json({ error: 'credential not found' });
  }
  if (data.jump_host_id != null) {
    if (data.jump_host_id === existing.id) {
      return res.status(400).json({ error: 'a host cannot be its own bastion' });
    }
    const jump = db
      .prepare('SELECT id FROM hosts WHERE id = ? AND (user_id = ? OR shared = 1)')
      .get(data.jump_host_id, req.user.id);
    if (!jump) return res.status(400).json({ error: 'bastion host not found' });
  }
  const cols = Object.keys(data);
  if (cols.length) {
    db.prepare(
      `UPDATE hosts SET ${cols.map((c) => `${c} = ?`).join(', ')}, updated_at = unixepoch() WHERE id = ?`
    ).run(...cols.map((c) => data[c]), existing.id);
  }
  const row = db.prepare('SELECT * FROM hosts WHERE id = ?').get(existing.id);
  res.json({ host: hostView(row) });
});

router.delete('/:id', (req, res) => {
  const existing = db.prepare('SELECT * FROM hosts WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!existing) return res.status(404).json({ error: 'not found' });
  // CASCADE deletes the tunnel rows — stop the live listeners too.
  stopTunnelsForHost(existing.id);
  db.prepare('DELETE FROM hosts WHERE id = ?').run(existing.id);
  auditReq(req, 'host.deleted', `${existing.name} (${existing.hostname})`);
  res.json({ ok: true });
});

// ---- Reachability probe (parallel TCP connect, 20s cache per user) ----

const statusCache = new Map(); // userId -> { at, result }

function probePort(hostname, port) {
  return new Promise((resolve) => {
    const sock = net.connect({ host: hostname, port, timeout: 3000 });
    const done = (status) => {
      try { sock.destroy(); } catch {}
      resolve(status);
    };
    sock.on('connect', () => done('up'));
    sock.on('timeout', () => done('down'));
    sock.on('error', () => done('down'));
  });
}

// ---- quick-connect history ----
// Logs user@host[:port] quick connects so they can be re-opened or promoted
// into saved hosts later. One row per tuple — reconnecting bumps its ts.

router.get('/quicklog', (req, res) => {
  const rows = db
    .prepare('SELECT id, hostname, port, username, ts FROM quick_history WHERE user_id = ? ORDER BY ts DESC, id DESC LIMIT 25')
    .all(req.user.id);
  res.json({ entries: rows });
});

router.post('/quicklog', (req, res) => {
  const hostname = String(req.body?.hostname ?? '').slice(0, 255).trim();
  const username = String(req.body?.username ?? '').slice(0, 64).trim();
  const port = Math.min(Math.max(parseInt(req.body?.port, 10) || 22, 1), 65535);
  if (!hostname) return res.status(400).json({ error: 'hostname required' });
  // delete+reinsert so repeats get a fresh id AND ts — a same-second bump
  // stays correctly ordered
  db.prepare('DELETE FROM quick_history WHERE user_id = ? AND hostname = ? AND port = ? AND username = ?')
    .run(req.user.id, hostname, port, username);
  const id = db
    .prepare('INSERT INTO quick_history (user_id, hostname, port, username) VALUES (?, ?, ?, ?)')
    .run(req.user.id, hostname, port, username).lastInsertRowid;
  // keep the log bounded
  db.prepare(
    'DELETE FROM quick_history WHERE user_id = ? AND id NOT IN (SELECT id FROM quick_history WHERE user_id = ? ORDER BY ts DESC, id DESC LIMIT 50)'
  ).run(req.user.id, req.user.id);
  res.json({ entry: { id, hostname, port, username } });
});

router.delete('/quicklog/:id', (req, res) => {
  db.prepare('DELETE FROM quick_history WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  res.json({ ok: true });
});

router.get('/status', async (req, res) => {
  const cached = statusCache.get(req.user.id);
  if (cached && Date.now() - cached.at < 20000) return res.json({ status: cached.result });

  const hosts = db
    .prepare('SELECT id, hostname, port FROM hosts WHERE user_id = ? OR shared = 1')
    .all(req.user.id);
  // Cap concurrency — hundreds of hosts at once would flood the fd table.
  const result = {};
  const BATCH = 16;
  for (let i = 0; i < hosts.length; i += BATCH) {
    const entries = await Promise.all(
      hosts.slice(i, i + BATCH).map((h) => probePort(h.hostname, h.port).then((s) => [h.id, s]))
    );
    for (const [id, s] of entries) result[id] = s;
  }
  statusCache.set(req.user.id, { at: Date.now(), result });
  res.json({ status: result });
});

// ---- Known host keys (TOFU store) ----

router.get('/hostkeys', (req, res) => {
  res.json({ hostkeys: listHostKeys(req.user.id) });
});

router.delete('/hostkeys/:id', (req, res) => {
  if (!removeHostKey(req.user.id, req.params.id)) return res.status(404).json({ error: 'not found' });
  auditReq(req, 'ssh.hostkey_removed', `hostkey id ${req.params.id}`);
  res.json({ ok: true });
});

// ---- ssh-keyscan: fetch a host's public key without trusting it yet.
// POST /hostkeys/scan { hosts: [{hostname,port}] | host_ids: [..], trust }
// Returns per-host { fingerprint, algorithm, trusted } so the UI can show
// what will be pinned before the user commits to it.
const scanLimiter = new Map(); // crude per-user rate cap
router.post('/hostkeys/scan', async (req, res) => {
  const last = scanLimiter.get(req.user.id) || 0;
  if (Date.now() - last < 3000) return res.status(429).json({ error: 'slow down' });
  scanLimiter.set(req.user.id, Date.now());

  const targets = [];
  for (const h of req.body?.hosts || []) {
    const hostname = String(h.hostname || '').trim();
    const port = Math.min(Math.max(parseInt(h.port, 10) || 22, 1), 65535);
    if (hostname && hostname.length <= 255) targets.push({ hostname, port });
  }
  for (const id of req.body?.host_ids || []) {
    const row = db.prepare('SELECT hostname, port FROM hosts WHERE id = ? AND (user_id = ? OR shared = 1)').get(id, req.user.id);
    if (row) targets.push({ hostname: row.hostname, port: row.port });
  }
  if (!targets.length || targets.length > 50) {
    return res.status(400).json({ error: '1–50 scan targets required' });
  }

  const results = [];
  const trust = !!req.body.trust;
  const BATCH = 8;
  for (let i = 0; i < targets.length; i += BATCH) {
    const batch = await Promise.all(
      targets.slice(i, i + BATCH).map(async (t) => {
        const r = await scanHostKey(t.hostname, t.port);
        if (!r.ok) return { ...t, ok: false, error: r.error };
        const stored = getStoredHostKey(req.user.id, t.hostname, t.port);
        const entry = {
          ...t, ok: true,
          fingerprint: r.fingerprint, algorithm: r.algorithm, key_b64: r.keyB64,
          already_trusted: !!stored,
          changed: stored ? stored.key_b64 !== r.keyB64 : false,
        };
        if (trust) {
          trustHostKey(req.user.id, t.hostname, t.port, r.keyB64, r.algorithm);
          entry.trusted = true;
        }
        return entry;
      })
    );
    results.push(...batch);
  }
  auditReq(req, 'ssh.hostkey_scan', `${targets.length} targets${trust ? ' (trusted)' : ''}`);
  res.json({ results });
});

// ---- Wake-on-LAN ----
router.post('/:id/wol', (req, res) => {
  const host = db.prepare('SELECT mac, name FROM hosts WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!host) return res.status(404).json({ error: 'not found' });
  const mac = (host.mac || '').replace(/[:-]/g, '');
  if (!/^[0-9a-fA-F]{12}$/.test(mac)) return res.status(400).json({ error: 'no MAC address on this host' });
  const macBuf = Buffer.from(mac, 'hex');
  const packet = Buffer.concat([Buffer.alloc(6, 0xff), ...Array(16).fill(macBuf)]);
  const sock = dgram.createSocket('udp4');
  sock.once('error', () => { try { sock.close(); } catch {} });
  sock.bind(() => {
    sock.setBroadcast(true);
    sock.send(packet, 0, packet.length, 9, '255.255.255.255', (err) => {
      try { sock.close(); } catch {}
      if (err) return res.status(500).json({ error: 'broadcast failed' });
      auditReq(req, 'host.wol', `${host.name} (${host.mac})`);
      res.json({ ok: true });
    });
  });
});

// ---- health history (written by the background sweeper) ----
router.get('/:id/health', (req, res) => {
  const own = db.prepare('SELECT id FROM hosts WHERE id = ? AND (user_id = ? OR shared = 1)').get(req.params.id, req.user.id);
  if (!own) return res.status(404).json({ error: 'not found' });
  res.json({ history: getHealthHistory(own.id), current: latestHealth(own.id) });
});

// ---- BMC host commands (power / MC reset / SEL / sensors / detect) ----
// Resolved through the vault like a connect; bastion chains install into the
// addon's route table before the call. These are blocking IPMI/HTTP calls
// inside the addon — napi runs them off the event loop, we await them here.

function bmcSpec(req) {
  const spec = resolveConnectSpec(req.user.id, { hostId: parseInt(req.params.id, 10) });
  applyRoutes(resolveConnectSpec, req.user.id, spec);
  return { host: spec.hostname, user: spec.username || '', pass: spec.password || '' };
}

const BMC_ACTIONS = new Set(['on', 'off', 'reset', 'cycle', 'soft']);

router.post('/:id/power', async (req, res) => {
  if (!bmc) return res.status(503).json({ error: `bmc addon unavailable: ${bmcError}` });
  const { action, family } = req.body || {};
  if (!BMC_ACTIONS.has(action)) return res.status(400).json({ error: 'action must be on|off|reset|cycle|soft' });
  try {
    const spec = bmcSpec(req);
    const message =
      action === 'cycle'
        ? await bmc.ipmiPower(spec, action)
        : await bmc.powerCmd(spec, action, family || null);
    auditReq(req, 'bmc.power', `${spec.host} ${action}`);
    res.json({ ok: true, message });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

router.post('/:id/mc-reset', async (req, res) => {
  if (!bmc) return res.status(503).json({ error: `bmc addon unavailable: ${bmcError}` });
  try {
    const spec = bmcSpec(req);
    const message = await bmc.bmcReset(spec);
    auditReq(req, 'bmc.mc_reset', spec.host);
    res.json({ ok: true, message });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

router.get('/:id/sel', async (req, res) => {
  if (!bmc) return res.status(503).json({ error: `bmc addon unavailable: ${bmcError}` });
  try {
    res.json(JSON.parse(await bmc.readSel(bmcSpec(req))));
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

router.get('/:id/sensors', async (req, res) => {
  if (!bmc) return res.status(503).json({ error: `bmc addon unavailable: ${bmcError}` });
  try {
    res.json(JSON.parse(await bmc.readSensors(bmcSpec(req))));
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

router.get('/:id/bmc-detect', async (req, res) => {
  if (!bmc) return res.status(503).json({ error: `bmc addon unavailable: ${bmcError}` });
  try {
    const spec = resolveConnectSpec(req.user.id, { hostId: parseInt(req.params.id, 10) });
    const [family, vendor] = String(await bmc.detectFamily(spec.hostname)).split(':');
    res.json({ family, vendor });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// ISO upload for virtual media: raw body to data/media/, then mounted via
// the console's mount call with the returned server-side path.
router.put('/:id/media-upload', express.raw({ type: () => true, limit: '8gb' }), (req, res) => {
  const own = db.prepare('SELECT id FROM hosts WHERE id = ? AND (user_id = ? OR shared = 1)').get(req.params.id, req.user.id);
  if (!own) return res.status(404).json({ error: 'not found' });
  const name = path.basename(String(req.query.name || 'image.iso')).replace(/[^\w.\- ]/g, '_');
  const dir = path.join(__dirname, '..', '..', 'data', 'media');
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `${own.id}-${Date.now()}-${name}`);
  fs.writeFileSync(file, req.body || Buffer.alloc(0));
  auditReq(req, 'bmc.media_upload', name);
  res.json({ path: file });
});

module.exports = router;
