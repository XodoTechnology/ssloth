'use strict';

// /ws/kvm — KVM-over-IP console bridge. One BmcSession (bmc-node, the vendored
// bmc-core napi addon) per console; frames flow as binary wire packets to the
// browser's canvas painter, input flows back as input::Events.
//
// Client → server messages:
//   {type:'connect', hostId?, inline?}     — saved host or {hostname,port,username,password}
//   {type:'reattach', sessionId}
//   {type:'key', usage, down, repeat?}
//   {type:'pointer', x, y, fw, fh, buttons, wheel}
//   {type:'char', c}   {type:'releaseAll'}   {type:'cad'}
//   {type:'close'}
//
// Server → client:
//   binary frames (KVMF wire format — see web/src/lib/kvm/frames.js)
//   {type:'status', state:'connecting'|'ready'|'error'|'closed', message}
//   {type:'ready', sessionId, title, family}

const path = require('path');
const { audit } = require('../db');
const { resolveConnectSpec } = require('../ssh/manager');

// The vendored bmc-core napi addon. Built per-platform by the Rust build
// (vendor/bmc); a missing or wrong-arch binary degrades this endpoint to a
// clear error instead of taking the whole server down at require time.
let bmc = null;
let bmcError = null;
try {
  bmc = require(path.join(__dirname, '..', '..', 'native', 'bmc.node'));
} catch (e) {
  bmcError = e.message;
  console.warn('[ssloth] bmc addon unavailable:', e.message);
}

// Persistent sessions, same model as ssh: detach keeps the console alive.
const sessions = new Map(); // id -> {id, bmc, ws, label, createdAt}
let seq = 0;

function send(ws, obj) {
  if (ws.readyState === 1) ws.send(JSON.stringify(obj));
}

// Map a resolved ssloth bastion chain onto bmc RouteSpec hops (dial order:
// outermost first — buildChain already returns that order).
function chainToRoutes(hops) {
  return hops.map((h) => ({
    name: h.label || `${h.hostname}:${h.port}`,
    kind: 'ssh',
    host: h.hostname,
    port: h.port || 22,
    user: h.username || '',
    auth: h.privateKey ? 'key' : h.password ? 'password' : 'agent',
    keyFile: h.__keyFile || null,
    secret: h.password || h.passphrase || null,
    hostKey: null,
    via: null,
  }));
}

function handleKvmWs(ws, req, user) {
  if (!bmc) {
    send(ws, { type: 'status', state: 'error', message: `KVM backend unavailable on this install (${bmcError})` });
    ws.close();
    return;
  }
  let session = null;

  ws.on('message', (data, isBinary) => {
    if (isBinary) return; // browser sends no binary; input is JSON
    let msg;
    try {
      msg = JSON.parse(data.toString());
    } catch {
      return;
    }
    try {
      switch (msg.type) {
        case 'connect':
          connect(msg);
          break;
        case 'reattach': {
          const s = sessions.get(msg.sessionId);
          if (!s || !user.admin && false) break; // sessions are per-user below
          if (s.userId !== user.id) break;
          session = s;
          s.ws = ws;
          send(ws, { type: 'ready', sessionId: s.id, title: s.label, family: s.family, reattached: true });
          audit(user, 'kvm.reattach', s.label, req);
          break;
        }
        case 'key':
          session?.bmc.sendKey(msg.usage | 0, !!msg.down, !!msg.repeat);
          break;
        case 'pointer':
          session?.bmc.sendPointer(+msg.x, +msg.y, msg.fw | 0, msg.fh | 0, msg.buttons | 0, msg.wheel | 0);
          break;
        case 'char':
          session?.bmc.sendChar(String(msg.c || '').slice(0, 1));
          break;
        case 'releaseAll':
          session?.bmc.releaseAll();
          break;
        case 'cad':
          session?.bmc.sendCad();
          break;
        case 'close': {
          const s = session;
          session = null;
          if (s) kill(s);
          break;
        }
      }
    } catch (e) {
      send(ws, { type: 'status', state: 'error', message: e.message });
    }
  });

  ws.on('close', () => {
    // detach — the console keeps running for reattach
    if (session && session.ws === ws) session.ws = null;
    session = null;
  });

  function connect(msg) {
    let spec;
    try {
      spec = resolveConnectSpec(user.id, msg);
    } catch (e) {
      send(ws, { type: 'status', state: 'error', message: e.message });
      return;
    }
    if (spec.protocol && spec.protocol !== 'bmc') {
      // tolerated — but the client should only send bmc hosts here
    }

    const pass = spec.password || msg.password || '';
    send(ws, { type: 'status', state: 'connecting', message: `connecting to ${spec.label} …` });

    // Bastion chain → bmc route table (installed globally by addr).
    try {
      const hops = buildHops(spec);
      bmc.clearRoute(spec.hostname);
      if (hops.length) bmc.setRoute(spec.hostname, chainToRoutes(hops));
    } catch (e) {
      send(ws, { type: 'status', state: 'error', message: 'route setup failed: ' + e.message });
      return;
    }

    const id = `kvm${++seq}-${Date.now().toString(36)}`;
    const b = new bmc.BmcSession(
      { host: spec.hostname, user: spec.username || '', pass, seize: !!msg.seize },
      (e) => onEvent(String(e)),
      (frame) => {
        const s = sessions.get(id);
        if (s?.ws && s.ws.readyState === 1) s.ws.send(Buffer.from(frame));
      }
    );

    const rec = {
      id,
      bmc: b,
      ws,
      userId: user.id,
      label: spec.label,
      family: null,
      createdAt: Date.now(),
    };
    sessions.set(id, rec);
    session = rec;

    function onEvent(line) {
      const s = sessions.get(id);
      const out = s?.ws || ws;
      const [kind, ...rest] = line.split(':');
      const body = rest.join(':');
      if (kind === 'ready') {
        const [title, family] = body.split(':');
        s.family = family;
        send(out, { type: 'ready', sessionId: id, title, family });
        audit(user, 'kvm.connect', spec.label, req);
      } else if (kind === 'progress') {
        send(out, { type: 'status', state: 'connecting', message: body });
      } else if (kind === 'error') {
        send(out, { type: 'status', state: 'error', message: body });
      } else if (kind === 'ended') {
        send(out, { type: 'status', state: 'closed', message: 'console ended' });
        kill(s);
      } else if (kind === 'problem' || kind === 'notice') {
        send(out, { type: 'status', state: 'notice', message: body });
      }
    }
  }

  // Walk the saved bastion chain (same rule as ssh: host.jumpHostId → hops,
  // outermost first).
  function buildHops(spec) {
    const hops = [];
    const seen = new Set(spec.hostId ? [spec.hostId] : []);
    let cursor = spec;
    while (cursor.jumpHostId) {
      if (hops.length >= 8) throw new Error('bastion chain too long');
      const hop = resolveConnectSpec(user.id, { hostId: cursor.jumpHostId });
      if (seen.has(hop.hostId)) throw new Error('bastion chain contains a cycle');
      seen.add(hop.hostId);
      hops.push(hop);
      cursor = hop;
    }
    return hops.reverse();
  }

  function kill(s) {
    if (!s) return;
    sessions.delete(s.id);
    try {
      s.bmc.close();
    } catch {}
    if (s.ws && s.ws.readyState === 1) send(s.ws, { type: 'status', state: 'closed' });
  }
}

module.exports = { handleKvmWs };
