'use strict';

const express = require('express');
const net = require('net');
const { db } = require('../db');
const { auditReq } = require('../auth');
const { resolveConnectSpec, tryConnect, establishConn, getStoredHostKey } = require('../ssh/manager');

const router = express.Router();

// Active forwards: tunnelId -> { server, conn, spec }
const active = new Map();

function tunnelView(row) {
  return { ...row, active: active.has(row.id) };
}

function cleanTunnel(body, { partial = false } = {}) {
  const out = {};
  if (!partial || body.name !== undefined) out.name = String(body.name ?? '').slice(0, 128).trim();
  if (!partial || body.type !== undefined) {
    out.type = body.type === 'dynamic' ? 'dynamic' : 'local';
  }
  if (!partial || body.host_id !== undefined) out.host_id = parseInt(body.host_id, 10);
  if (!partial || body.bind_address !== undefined) {
    out.bind_address = String(body.bind_address || '127.0.0.1').slice(0, 64).trim();
  }
  if (!partial || body.local_port !== undefined) {
    const p = parseInt(body.local_port, 10);
    if (!Number.isInteger(p) || p < 1 || p > 65535) throw new Error('invalid local_port');
    out.local_port = p;
  }
  if (!partial || body.remote_host !== undefined) out.remote_host = String(body.remote_host ?? '').slice(0, 255).trim();
  if (body.remote_port !== undefined) {
    const p = parseInt(body.remote_port, 10);
    if (!Number.isInteger(p) || p < 0 || p > 65535) throw new Error('invalid remote_port');
    out.remote_port = p;
  } else if (!partial) {
    out.remote_port = 0; // dynamic tunnels have no fixed remote
  }
  return out;
}

router.get('/', (req, res) => {
  const rows = db.prepare('SELECT * FROM tunnels WHERE user_id = ? ORDER BY name COLLATE NOCASE').all(req.user.id);
  res.json({ tunnels: rows.map(tunnelView) });
});

router.post('/', (req, res) => {
  let data;
  try {
    data = cleanTunnel(req.body || {});
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }
  if (!data.name || !data.host_id || !data.local_port) {
    return res.status(400).json({ error: 'name, host_id and local_port are required' });
  }
  if (data.type === 'dynamic') {
    data.remote_host = data.remote_host || '-';
    data.remote_port = data.remote_port || 0;
  } else if (!data.remote_host || !data.remote_port) {
    return res.status(400).json({ error: 'local forwards need remote_host and remote_port' });
  }
  const host = db.prepare('SELECT id FROM hosts WHERE id = ? AND (user_id = ? OR shared = 1)').get(data.host_id, req.user.id);
  if (!host) return res.status(400).json({ error: 'host not found' });
  const cols = Object.keys(data);
  const info = db
    .prepare(`INSERT INTO tunnels (user_id, ${cols.join(',')}) VALUES (?, ${cols.map(() => '?').join(',')})`)
    .run(req.user.id, ...cols.map((c) => data[c]));
  const row = db.prepare('SELECT * FROM tunnels WHERE id = ?').get(info.lastInsertRowid);
  res.json({ tunnel: tunnelView(row) });
});

router.delete('/:id', (req, res) => {
  const t = db.prepare('SELECT * FROM tunnels WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!t) return res.status(404).json({ error: 'not found' });
  stopTunnel(t.id);
  db.prepare('DELETE FROM tunnels WHERE id = ?').run(t.id);
  res.json({ ok: true });
});

router.post('/:id/start', async (req, res) => {
  const t = db.prepare('SELECT * FROM tunnels WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!t) return res.status(404).json({ error: 'not found' });
  if (active.has(t.id)) return res.json({ tunnel: tunnelView(t) });

  let spec;
  try {
    spec = resolveConnectSpec(req.user.id, { hostId: t.host_id });
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }
  if (spec.authType === 'ask' && !spec.password) {
    return res.status(400).json({ error: 'host uses prompt-at-connect auth; tunnels need a stored credential' });
  }
  if (!getStoredHostKey(req.user.id, spec.hostname, spec.port)) {
    return res.status(400).json({
      error: 'host key not trusted yet - open a terminal session to this host first to verify and trust its key',
    });
  }

  try {
    const conn = await establishConn(req.user.id, spec);
    const server = net.createServer((socket) => {
      if (t.type === 'dynamic') return handleSocks5(conn, socket);
      conn.forwardOut(socket.remoteAddress, socket.remotePort, t.remote_host, t.remote_port, (err, stream) => {
        if (err) {
          socket.destroy();
          return;
        }
        socket.pipe(stream).pipe(socket);
        stream.on('error', () => socket.destroy());
        socket.on('error', () => stream.destroy());
      });
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(t.local_port, t.bind_address, resolve);
    });
    conn.on('close', () => stopTunnel(t.id));
    active.set(t.id, { server, conn });
    const via =
      t.type === 'dynamic'
        ? `${t.bind_address}:${t.local_port} (SOCKS5)`
        : `${t.bind_address}:${t.local_port} -> ${t.remote_host}:${t.remote_port}`;
    auditReq(req, 'tunnel.started', `${t.name}: ${via} via ${spec.label}`);
    res.json({ tunnel: tunnelView(t) });
  } catch (e) {
    res.status(502).json({ error: 'tunnel failed: ' + (e.message || e.code || 'unknown') });
  }
});

// Minimal SOCKS5 server (no-auth, CONNECT only) — every accepted connection
// is dialled onward through the SSH channel via forwardOut.
function handleSocks5(conn, socket) {
  let buf = Buffer.alloc(0);
  let stage = 0; // 0 = greeting, 1 = request, 2 = piping

  const fail = () => socket.destroy();
  const onData = (data) => {
    buf = Buffer.concat([buf, data]);
    try {
      parse();
    } catch {
      fail();
    }
  };

  const parse = () => {
    if (stage === 0) {
      if (buf.length < 2) return;
      const ver = buf[0];
      const nmethods = buf[1];
      if (ver !== 5) throw new Error('not socks5');
      if (buf.length < 2 + nmethods) return;
      buf = buf.subarray(2 + nmethods);
      socket.write(Buffer.from([5, 0])); // no-auth accepted
      stage = 1;
      parse();
    } else if (stage === 1) {
      if (buf.length < 5) return;
      const ver = buf[0];
      const cmd = buf[1];
      const atyp = buf[3];
      if (ver !== 5 || cmd !== 1) throw new Error('unsupported socks request');
      let off;
      let host;
      if (atyp === 1) {
        if (buf.length < 10) return;
        host = Array.from(buf.subarray(4, 8)).join('.');
        off = 8;
      } else if (atyp === 3) {
        const len = buf[4];
        if (buf.length < 5 + len + 2) return;
        host = buf.subarray(5, 5 + len).toString('utf8');
        off = 5 + len;
      } else if (atyp === 4) {
        if (buf.length < 22) return;
        const a = buf.subarray(4, 20);
        host = Array.from({ length: 8 }, (_, i) => a.readUInt16BE(i * 2).toString(16)).join(':');
        off = 20;
      } else {
        throw new Error('bad atyp');
      }
      const port = buf.readUInt16BE(off);
      buf = buf.subarray(off + 2);
      stage = 2;
      conn.forwardOut(socket.remoteAddress, socket.remotePort, host, port, (err, stream) => {
        if (err) {
          // general failure reply then drop
          try { socket.write(Buffer.from([5, 1, 0, 1, 0, 0, 0, 0, 0, 0])); } catch {}
          socket.destroy();
          return;
        }
        try { socket.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0])); } catch { stream.destroy(); return; }
        socket.removeListener('data', onData);
        if (buf.length) stream.write(buf);
        socket.pipe(stream).pipe(socket);
        stream.on('error', () => socket.destroy());
        socket.on('error', () => stream.destroy());
      });
    }
  };

  socket.on('data', onData);
  socket.on('error', () => {});
}

router.post('/:id/stop', (req, res) => {
  const t = db.prepare('SELECT * FROM tunnels WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!t) return res.status(404).json({ error: 'not found' });
  stopTunnel(t.id);
  auditReq(req, 'tunnel.stopped', t.name);
  res.json({ tunnel: tunnelView(t) });
});

function stopTunnel(id) {
  const a = active.get(id);
  if (!a) return;
  active.delete(id);
  try { a.server.close(); } catch {}
  try { a.conn.end(); } catch {}
}

module.exports = router;
