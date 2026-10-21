'use strict';

const { audit } = require('../db');
const {
  resolveConnectSpec,
  tryConnect,
  createSession,
  destroySession,
  trustHostKey,
  broadcastOutput,
} = require('../ssh/manager');

const MAX_AUTH_ATTEMPTS = 3;
const MAX_PAYLOAD = 256 * 1024;

// JSON control protocol + binary frames for terminal I/O.
// client->server JSON:
//   {type:'connect', hostId|inline:{hostname,port,username,password?}, cols, rows}
//   {type:'trust', accept:boolean}
//   {type:'auth', password:string}
//   {type:'resize', cols, rows}
// server->client JSON:
//   {type:'status', state, message}
//   {type:'hostkey', fingerprint, algorithm, hostname, port}
//   {type:'auth_request', reason}
//   {type:'ready', sessionId, label}
function handleTerminalWs(ws, req, user) {
  const send = (obj) => {
    if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(obj));
  };

  let spec = null;
  let session = null;
  let stream = null;
  let awaiting = null; // 'trust' | 'auth' | null
  let pendingKey = null;
  let authAttempts = 0;
  let pendingResize = { cols: 80, rows: 24 };
  let connected = false;

  ws.on('message', (data, isBinary) => {
    if (isBinary) {
      if (stream) stream.write(data);
      return;
    }
    let msg;
    try {
      msg = JSON.parse(data.toString());
    } catch {
      return;
    }
    switch (msg.type) {
      case 'connect':
        if (spec || session) return;
        pendingResize = { cols: clampDim(msg.cols, 80), rows: clampDim(msg.rows, 24) };
        try {
          spec = resolveConnectSpec(user.id, msg);
        } catch (e) {
          send({ type: 'status', state: 'error', message: e.message });
          return ws.close();
        }
        connect();
        break;

      case 'trust':
        if (awaiting !== 'trust' || !pendingKey) return;
        if (msg.accept === 'always') {
          trustHostKey(user.id, pendingKey.hostname, pendingKey.port, pendingKey.keyB64, pendingKey.algorithm);
          audit(user, 'ssh.hostkey_trusted', `${pendingKey.hostname}:${pendingKey.port} ${pendingKey.fingerprint}`, req);
        }
        if (msg.accept === 'always' || msg.accept === 'once') {
          const keyB64 = pendingKey.keyB64;
          pendingKey = null;
          awaiting = null;
          connect({ acceptedKeyB64: keyB64 });
        } else {
          send({ type: 'status', state: 'error', message: 'host key rejected' });
          ws.close();
        }
        break;

      case 'auth':
        if (awaiting !== 'auth') return;
        if (authAttempts++ >= MAX_AUTH_ATTEMPTS) {
          send({ type: 'status', state: 'error', message: 'too many authentication attempts' });
          return ws.close();
        }
        awaiting = null;
        spec = { ...spec, password: String(msg.password || ''), authType: 'password' };
        connect();
        break;

      case 'resize':
        pendingResize = { cols: clampDim(msg.cols, 80), rows: clampDim(msg.rows, 24) };
        if (stream) stream.setWindow(pendingResize.rows, pendingResize.cols, 0, 0);
        break;

      case 'close':
        ws.close();
        break;
    }
  });

  ws.on('close', () => {
    if (session) {
      audit(user, 'ssh.disconnect', session.label, req);
      destroySession(session.id);
      session = null;
    }
    stream = null;
  });

  function connect(opts = {}) {
    send({ type: 'status', state: 'connecting', message: `connecting to ${spec.label} ...` });
    tryConnect(user.id, spec, opts)
      .then((conn) => onConnected(conn))
      .catch((err) => {
        switch (err.code) {
          case 'unknown_hostkey':
            pendingKey = {
              hostname: spec.hostname,
              port: spec.port,
              fingerprint: err.fingerprint,
              keyB64: err.keyB64,
              algorithm: err.algorithm,
            };
            awaiting = 'trust';
            send({
              type: 'hostkey',
              hostname: spec.hostname,
              port: spec.port,
              fingerprint: err.fingerprint,
              algorithm: err.algorithm,
            });
            break;
          case 'hostkey_mismatch':
            audit(user, 'ssh.hostkey_mismatch', `${spec.hostname}:${spec.port} saw ${err.fingerprint}, expected ${err.expected}`, req);
            send({
              type: 'status',
              state: 'error',
              message:
                `HOST KEY CHANGED for ${spec.hostname}:${spec.port}! ` +
                `Expected ${err.expected}, got ${err.fingerprint}. ` +
                'This could indicate a man-in-the-middle attack. Delete the stored key in Settings if the change is expected.',
            });
            ws.close();
            break;
          case 'auth_failed':
            awaiting = 'auth';
            send({
              type: 'auth_request',
              reason:
                authAttempts === 0 && spec.authType === 'ask'
                  ? `password required for ${spec.username}@${spec.hostname}`
                  : 'authentication failed - enter password to retry',
            });
            break;
          default:
            send({ type: 'status', state: 'error', message: err.message || 'connection failed' });
            ws.close();
        }
      });
  }

  function onConnected(conn) {
    session = createSession(user.id, conn, spec);
    session.ws = ws;
    connected = true;
    audit(user, 'ssh.connect', spec.label, req);
    conn.shell(
      { term: 'xterm-256color', cols: pendingResize.cols, rows: pendingResize.rows },
      (err, s) => {
        if (err) {
          send({ type: 'status', state: 'error', message: 'shell request failed: ' + err.message });
          return destroySession(session.id);
        }
        stream = s;
        session.stream = s;
        send({ type: 'ready', sessionId: session.id, label: spec.label });
        stream.on('data', (chunk) => {
          if (ws.readyState === ws.OPEN) ws.send(chunk, { binary: true });
          broadcastOutput(session, chunk);
        });
        stream.stderr?.on('data', (chunk) => {
          if (ws.readyState === ws.OPEN) ws.send(chunk, { binary: true });
          broadcastOutput(session, chunk);
        });
        stream.on('close', () => {
          send({ type: 'status', state: 'closed', message: 'session ended' });
          ws.close();
        });
      }
    );
  }

  // Nothing happens until the client sends 'connect'. For 'ask' auth the
  // first attempt still verifies the host key before we prompt for a password,
  // so the fingerprint is shown before credentials are typed.
  send({ type: 'hello' });
}

function clampDim(v, fallback) {
  const n = parseInt(v, 10);
  return Number.isFinite(n) && n >= 1 && n <= 1000 ? n : fallback;
}

module.exports = { handleTerminalWs };
