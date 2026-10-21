'use strict';

const crypto = require('crypto');
const { Client } = require('ssh2');
const { db } = require('../db');
const { decryptSecret, hostKeyFingerprint } = require('../crypto');

// Live SSH sessions. A session owns one ssh2 Client; the terminal WebSocket
// pipes a shell channel, the SFTP REST endpoints reuse the same connection,
// and tunnels open dedicated connections of their own.
const sessions = new Map(); // sessionId -> session

const IDLE_TTL_MS = 60 * 60 * 1000;
setInterval(() => {
  const now = Date.now();
  for (const [id, s] of sessions) {
    if (now - s.lastUsed > IDLE_TTL_MS) destroySession(id);
  }
}, 5 * 60 * 1000).unref();

function getStoredHostKey(userId, hostname, port) {
  return db
    .prepare('SELECT * FROM hostkeys WHERE user_id = ? AND hostname = ? AND port = ?')
    .get(userId, hostname, port);
}

function trustHostKey(userId, hostname, port, keyB64, algorithm) {
  const fingerprint = hostKeyFingerprint(Buffer.from(keyB64, 'base64'));
  db.prepare(
    `INSERT INTO hostkeys (user_id, hostname, port, fingerprint, key_b64, algorithm)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT (user_id, hostname, port)
     DO UPDATE SET fingerprint = excluded.fingerprint, key_b64 = excluded.key_b64,
                   algorithm = excluded.algorithm, trusted_at = unixepoch()`
  ).run(userId, hostname, port, fingerprint, keyB64, algorithm);
  return fingerprint;
}

function listHostKeys(userId) {
  return db
    .prepare('SELECT id, hostname, port, fingerprint, algorithm, trusted_at FROM hostkeys WHERE user_id = ? ORDER BY hostname')
    .all(userId);
}

function removeHostKey(userId, id) {
  return db.prepare('DELETE FROM hostkeys WHERE id = ? AND user_id = ?').run(id, userId).changes;
}

// Build a connect spec from a saved host (decrypting its credential) or an
// ad-hoc quick-connect definition. Spec: { hostname, port, username, authType,
// password, privateKey, passphrase, label, hostId }
function resolveConnectSpec(userId, input) {
  if (input && input.inline) {
    const { hostname, port, username, password } = input.inline;
    return {
      hostname: String(hostname || ''),
      port: parseInt(port, 10) || 22,
      username: String(username || ''),
      authType: password ? 'password' : 'ask',
      password: password || null,
      label: `${username}@${hostname}:${port || 22}`,
      hostId: null,
    };
  }

  const host = db.prepare('SELECT * FROM hosts WHERE id = ? AND user_id = ?').get(input.hostId, userId);
  if (!host) throw Object.assign(new Error('host not found'), { code: 'host_not_found' });

  const spec = {
    hostname: host.hostname,
    port: host.port,
    username: host.username,
    authType: host.auth_type,
    keepalive: host.keepalive,
    label: host.name || `${host.username}@${host.hostname}`,
    hostId: host.id,
    jumpHostId: host.jump_host_id || null,
    record: !!host.record,
  };

  if (host.auth_type === 'credential' && host.credential_id) {
    const cred = db
      .prepare('SELECT * FROM credentials WHERE id = ? AND user_id = ?')
      .get(host.credential_id, userId);
    if (!cred) throw Object.assign(new Error('credential not found'), { code: 'credential_not_found' });
    const secret = JSON.parse(decryptSecret(cred.secret_enc));
    if (cred.type === 'key') {
      spec.privateKey = secret.privateKey;
      spec.passphrase = secret.passphrase || undefined;
      if (!spec.username && cred.username) spec.username = cred.username;
    } else {
      spec.password = secret.password;
      if (cred.username && (!host.username || host.username === '')) spec.username = cred.username;
    }
  } else if (host.auth_type === 'password' && host.password_enc) {
    spec.password = decryptSecret(host.password_enc);
  }
  // authType 'ask' (or missing credential) -> no secret; caller prompts.
  if (!spec.password && !spec.privateKey) spec.authType = 'ask';
  return spec;
}

// Attempt one ssh2 connection. Resolves with a connected Client.
// Rejects with err.code:
// Parse the algorithm name ("ssh-ed25519", "ssh-rsa", ...) out of a raw
// SSH wire-format public key blob.
function keyAlgorithm(buf) {
  try {
    const len = buf.readUInt32BE(0);
    if (len > 0 && len < 64 && buf.length >= 4 + len) {
      return buf.toString('ascii', 4, 4 + len);
    }
  } catch {}
  return '';
}

// Attempt one ssh2 connection. Resolves with a connected Client.
// Rejects with err.code:
//   'unknown_hostkey'   - first time seeing this host (err.fingerprint/keyB64 set)
//   'hostkey_mismatch'  - key changed vs stored trust (possible MITM)
//   'auth_failed'       - credentials rejected
//   'error'             - anything else
function tryConnect(userId, spec, opts = {}) {
  const password = opts.password !== undefined ? opts.password : spec.password;
  return new Promise((resolve, reject) => {
    let presented = null;
    const conn = new Client();
    let settled = false;

    const fail = (code, message, extra = {}) => {
      if (settled) return;
      settled = true;
      try { conn.end(); } catch {}
      reject(Object.assign(new Error(message), { code, ...extra }));
    };

    conn
      .on('ready', () => {
        if (settled) return;
        settled = true;
        resolve(conn);
      })
      .on('error', (err) => {
        if (settled) return;
        if (presented) {
          const keyB64 = presented.key.toString('base64');
          const fingerprint = hostKeyFingerprint(presented.key);
          const stored = getStoredHostKey(userId, spec.hostname, spec.port);
          if (stored && stored.key_b64 !== keyB64) {
            return fail('hostkey_mismatch', 'Host key changed', {
              fingerprint,
              keyB64,
              algorithm: presented.algo,
              expected: stored.fingerprint,
            });
          }
          if (opts.acceptedKeyB64 !== keyB64) {
            return fail('unknown_hostkey', 'Unknown host key', {
              fingerprint,
              keyB64,
              algorithm: presented.algo,
            });
          }
        }
        if (err.level === 'client-authentication' || /authentication/i.test(err.message)) {
          return fail('auth_failed', 'Authentication failed');
        }
        fail('error', err.message || 'connection failed');
      })
      .on('keyboard-interactive', (name, instructions, lang, prompts, finish) => {
        finish(prompts.map(() => password || ''));
      })
      .connect({
        host: spec.hostname,
        port: spec.port,
        username: spec.username,
        password: password || undefined,
        privateKey: spec.privateKey || undefined,
        passphrase: spec.passphrase || undefined,
        sock: opts.sock || undefined,
        tryKeyboard: true,
        readyTimeout: 20000,
        keepaliveInterval: (spec.keepalive ?? 15) * 1000,
        keepaliveCountMax: 3,
        hostVerifier(key) {
          // ssh2 may pass the key as a Buffer or a base64 string.
          const buf = Buffer.isBuffer(key) ? key : Buffer.from(key, 'base64');
          const keyB64 = buf.toString('base64');
          presented = { key: buf, algo: keyAlgorithm(buf) };
          if (opts.acceptedKeyB64 && opts.acceptedKeyB64 === keyB64) return true;
          const stored = getStoredHostKey(userId, spec.hostname, spec.port);
          return !!stored && stored.key_b64 === keyB64;
        },
      });
  });
}

// Connect to spec, optionally hopping through a saved bastion host
// (ProxyJump). Host-key verification applies per hop: the bastion is
// verified under its own hostname:port, the target under its own.
// Errors from the bastion hop carry hopSpec so the caller can display the
// right fingerprint in the trust prompt.
async function establishConn(userId, spec, opts = {}) {
  if (!spec.jumpHostId) return tryConnect(userId, spec, opts);

  const jumpSpec = resolveConnectSpec(userId, { hostId: spec.jumpHostId });
  if (jumpSpec.jumpHostId) {
    throw Object.assign(new Error('nested bastion hops are not supported (max 1 jump)'), { code: 'error' });
  }
  if (!jumpSpec.password && !jumpSpec.privateKey) {
    throw Object.assign(
      new Error(`bastion '${jumpSpec.label}' has no stored credential — it can't prompt interactively`),
      { code: 'error' }
    );
  }

  let jumpConn;
  try {
    jumpConn = await tryConnect(userId, jumpSpec, opts.jump || {});
  } catch (e) {
    if (e.code === 'unknown_hostkey' || e.code === 'hostkey_mismatch') e.hopSpec = jumpSpec;
    throw e;
  }

  try {
    const sock = await new Promise((resolve, reject) => {
      jumpConn.forwardOut('127.0.0.1', 0, spec.hostname, spec.port, (err, stream) =>
        err ? reject(err) : resolve(stream)
      );
    });
    const conn = await tryConnect(userId, spec, { ...opts, sock });
    conn.on('close', () => {
      try { jumpConn.end(); } catch {}
    });
    return conn;
  } catch (e) {
    try { jumpConn.end(); } catch {}
    throw e;
  }
}

// Create a registered session around an established connection.
function createSession(userId, conn, spec) {
  const id = crypto.randomBytes(16).toString('hex');
  const session = {
    id,
    userId,
    conn,
    spec,
    label: spec.label,
    sftp: null,
    sftpPromise: null,
    ws: null,
    stream: null,
    viewers: new Map(), // ws -> { mode }
    replay: Buffer.alloc(0),
    createdAt: Date.now(),
    lastUsed: Date.now(),
  };
  sessions.set(id, session);
  conn.on('close', () => {
    const s = sessions.get(id);
    if (s) {
      sessions.delete(id);
      if (s.recorder) finalizeRecorder(s);
      try { s.ws?.send(JSON.stringify({ type: 'status', state: 'closed', message: 'connection closed' })); } catch {}
      try { s.ws?.close(); } catch {}
      for (const viewerWs of s.viewers.keys()) {
        try { viewerWs.send(JSON.stringify({ type: 'status', state: 'closed', message: 'session ended by owner' })); } catch {}
        try { viewerWs.close(); } catch {}
      }
      s.viewers.clear();
      // Shares bound to a dead session can never resolve again.
      try { db.prepare('DELETE FROM shares WHERE session_id = ?').run(id); } catch {}
    }
  });
  return session;
}

const REPLAY_CAP = 256 * 1024;

// Send terminal output to all attached share viewers and keep a capped
// replay buffer so viewers joining late see recent output.
function broadcastOutput(session, chunk) {
  session.replay =
    session.replay.length + chunk.length > REPLAY_CAP
      ? Buffer.concat([session.replay.subarray(-REPLAY_CAP / 2), chunk])
      : Buffer.concat([session.replay, chunk]);
  for (const ws of session.viewers.keys()) {
    try {
      if (ws.readyState === ws.OPEN) ws.send(chunk, { binary: true });
    } catch {}
  }
}

function attachViewer(session, ws, mode) {
  session.viewers.set(ws, { mode });
  session.lastUsed = Date.now();
  if (session.replay.length) {
    try {
      ws.send(session.replay, { binary: true });
    } catch {}
  }
}

function detachViewer(session, ws) {
  session.viewers.delete(ws);
}

function getSession(userId, sessionId) {
  const s = sessions.get(sessionId);
  if (!s || s.userId !== userId) return null;
  s.lastUsed = Date.now();
  return s;
}

function getSftp(session) {
  if (session.sftp) return Promise.resolve(session.sftp);
  if (!session.sftpPromise) {
    session.sftpPromise = new Promise((resolve, reject) => {
      session.conn.sftp((err, sftp) => {
        if (err) {
          session.sftpPromise = null;
          return reject(err);
        }
        session.sftp = sftp;
        resolve(sftp);
      });
    });
  }
  return session.sftpPromise;
}

function destroySession(sessionId) {
  const s = sessions.get(sessionId);
  if (!s) return;
  sessions.delete(sessionId);
  if (s.recorder) finalizeRecorder(s);
  try { s.ws?.close(); } catch {}
  try { s.conn.end(); } catch {}
}

// Flush a session's cast recorder and mark the recordings row complete.
function finalizeRecorder(session) {
  try {
    const { size } = session.recorder.close();
    db.prepare('UPDATE recordings SET ended_at = unixepoch(), size = ? WHERE id = ?').run(
      size,
      session.recorder.recId
    );
  } catch {}
  session.recorder = null;
}

module.exports = {
  sessions,
  resolveConnectSpec,
  tryConnect,
  establishConn,
  createSession,
  getSession,
  getSftp,
  destroySession,
  broadcastOutput,
  attachViewer,
  detachViewer,
  finalizeRecorder,
  trustHostKey,
  listHostKeys,
  removeHostKey,
  getStoredHostKey,
};
