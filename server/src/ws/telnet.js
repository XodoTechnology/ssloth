'use strict';

// Telnet terminal: raw TCP + a minimal IAC filter. We refuse every option
// negotiation (DONT/WONT) so the remote falls back to raw mode, strip
// subnegotiation blocks, and pass 0xFF escapes through. Everything else is
// a byte pipe to xterm — no auth, no SFTP, no health.
const net = require('net');
const { db, audit } = require('../db');

const IAC = 0xff, DONT = 0xfe, DO = 0xfd, WONT = 0xfc, WILL = 0xfb, SB = 0xfa, SE = 0xf0;

// Strip telnet IAC sequences from a chunk; writes refusal replies to sock.
// Returns the payload bytes for the terminal. Handles sequences split
// across chunks via a tiny carry-over buffer stored on `st`.
function filterIac(st, chunk, sock) {
  const replies = [];
  const out = [];
  const b = st.carry ? Buffer.concat([st.carry, chunk]) : chunk;
  st.carry = null;
  let i = 0;
  for (; i < b.length; i++) {
    if (b[i] !== IAC) { out.push(b[i]); continue; }
    if (i + 1 >= b.length) { st.carry = b.subarray(i); break; }
    const cmd = b[i + 1];
    if (cmd === IAC) { out.push(IAC); i++; continue; }
    if (cmd === WILL || cmd === WONT || cmd === DO || cmd === DONT) {
      if (i + 2 >= b.length) { st.carry = b.subarray(i); break; }
      const opt = b[i + 2];
      // refuse everything: WILL -> DONT, DO -> WONT (once per remote ask)
      if (cmd === WILL) replies.push(IAC, DONT, opt);
      else if (cmd === DO) replies.push(IAC, WONT, opt);
      i += 2;
      continue;
    }
    if (cmd === SB) {
      // subnegotiation: consume until IAC SE
      let j = i + 2;
      while (j + 1 < b.length && !(b[j] === IAC && b[j + 1] === SE)) j++;
      if (j + 1 >= b.length) { st.carry = b.subarray(i); break; }
      i = j + 1;
      continue;
    }
    i++; // IAC + other command byte (GA/NOP/etc) — drop both
  }
  if (replies.length && !sock.destroyed) {
    try { sock.write(Buffer.from(replies)); } catch {}
  }
  return Buffer.from(out);
}

function handleTelnetWs(ws, req, user) {
  const send = (obj) => { if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(obj)); };
  let sock = null;

  ws.on('message', (data, isBinary) => {
    if (isBinary) {
      if (sock && !sock.destroyed) {
        try { sock.write(data); } catch {}
      }
      return;
    }
    let msg;
    try { msg = JSON.parse(data.toString()); } catch { return; }
    if (msg.type === 'connect' && !sock) {
      const host = db
        .prepare('SELECT * FROM hosts WHERE id = ? AND (user_id = ? OR shared = 1)')
        .get(msg.hostId, user.id);
      if (!host) { send({ type: 'status', state: 'error', message: 'host not found' }); return ws.close(); }
      if (host.protocol !== 'telnet') { send({ type: 'status', state: 'error', message: 'host protocol is not telnet' }); return ws.close(); }
      audit(user, 'telnet.connect', `${host.name || host.hostname}:${host.port}`, req);

      const st = { carry: null };
      sock = net.connect({ host: host.hostname, port: host.port, timeout: 10000 });
      sock.on('connect', () => {
        send({ type: 'ready', sessionId: `telnet-${host.id}-${Date.now()}`, label: `${host.name} [telnet]` });
      });
      sock.on('data', (chunk) => {
        const clean = filterIac(st, chunk, sock);
        if (clean.length && ws.readyState === ws.OPEN) ws.send(clean, { binary: true });
      });
      const bye = (reason) => {
        send({ type: 'status', state: 'closed', message: reason });
        try { ws.close(); } catch {}
      };
      sock.on('close', () => bye('connection closed'));
      sock.on('timeout', () => bye('connection timed out'));
      sock.on('error', (e) => bye(e.message));
      return;
    }
    if (msg.type === 'close' || msg.type === 'resize') {
      // resize has no meaning for a raw pipe; 'close' just ends the socket.
      if (msg.type === 'close') { try { sock?.end(); } catch {} }
    }
  });

  ws.on('close', () => { try { sock?.destroy(); } catch {} });
}

module.exports = { handleTelnetWs };
