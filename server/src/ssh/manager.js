'use strict';

const crypto = require('crypto');
const { Client, utils } = require('ssh2');
const { makeCertKey, enableCertAuth } = require('./certauth');
const { db } = require('../db');
const { decryptSecret, hostKeyFingerprint } = require('../crypto');
const { agentForSpec } = require('./agent');

// Live SSH sessions. A session owns one ssh2 Client; the terminal WebSocket
// pipes a shell channel, the SFTP REST endpoints reuse the same connection,
// and tunnels open dedicated connections of their own.
const sessions = new Map(); // sessionId -> session

const IDLE_TTL_MS = 60 * 60 * 1000;
const DETACHED_TTL_MS = 60 * 60 * 1000; // detached sessions die even if output is noisy
const MAX_SESSIONS_PER_USER = 25;
setInterval(() => {
  const now = Date.now();
  for (const [id, s] of sessions) {
    const abandoned =
      !s.ws && s.viewers.size === 0 && s.detachedAt && now - s.detachedAt > DETACHED_TTL_MS;
    if (abandoned || now - s.lastUsed > IDLE_TTL_MS) destroySession(id);
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

  // Saved hosts: visible if owned, or flagged shared by another user.
  // Shared hosts can be *used* (secrets stay server-side, never sent to the
  // connecting user) but are read-only — mutations still require ownership.
  const host = db
    .prepare('SELECT * FROM hosts WHERE id = ? AND (user_id = ? OR shared = 1)')
    .get(input.hostId, userId);
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
    protocol: host.protocol || 'ssh',
    agentForward: !!host.agent_forward,
  };

  if (host.auth_type === 'credential' && host.credential_id) {
    // On a shared host the credential belongs to the owner — the secret is
    // decrypted only inside this process and never leaves the server.
    const cred = host.shared
      ? db.prepare('SELECT * FROM credentials WHERE id = ?').get(host.credential_id)
      : db.prepare('SELECT * FROM credentials WHERE id = ? AND user_id = ?').get(host.credential_id, userId);
    if (!cred) throw Object.assign(new Error('credential not found'), { code: 'credential_not_found' });
    const secret = JSON.parse(decryptSecret(cred.secret_enc));
    if (cred.type === 'key') {
      spec.privateKey = secret.privateKey;
      spec.passphrase = secret.passphrase || undefined;
      if (secret.certificate) spec.certificate = secret.certificate;
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

// Certificate auth: ssh2 has no `certificate` connect option — cfg.privateKey
// only accepts strings/Buffers and authPK cannot express the split
// pkalg(cert type)/sigalg(plain type) wire format. makeCertKey wraps the
// parsed private key so it presents the cert blob, and enableCertAuth patches
// the connection's protocol so the signature field uses the right algorithm.
function certAuth(spec) {
  let key;
  try {
    key = utils.parseKey(spec.privateKey, spec.passphrase);
    if (Array.isArray(key)) key = key[0];
    if (!key || key instanceof Error) return {};
    key = makeCertKey(key, spec.certificate);
  } catch {
    return {};
  }
  let triedCert = false, triedPassword = false;
  return {
    authHandler: (authsLeft, partial, next) => {
      if (!triedCert) {
        triedCert = true;
        return next({ type: 'publickey', username: spec.username, key });
      }
      if (spec.password && !triedPassword) {
        triedPassword = true;
        return next({ type: 'password', username: spec.username, password: spec.password });
      }
      next(false);
    },
  };
}

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
          const accepted =
            opts.acceptedKeyB64 === keyB64 ||
            opts.acceptedKeys?.[`${spec.hostname}:${spec.port}`] === keyB64;
          if (!accepted) {
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
        // Agent forwarding: a VaultAgent serving this host's stored keys so
        // remote processes (git, nested ssh) can sign without seeing keys.
        ...(spec.agentForward && spec.privateKey
          ? { agent: agentForSpec(spec) || undefined, agentForward: !!agentForSpec(spec) }
          : {}),
        // Certificate auth: ssh2 has no cert option — wrap the parsed key so
        // the cert blob is offered instead of the raw public key while the
        // real private key still signs. Needs the authHandler to inject the
        // mutated key object (cfg.privateKey only accepts strings).
        ...(spec.certificate ? certAuth(spec) : {}),
        hostVerifier(key) {
          // ssh2 may pass the key as a Buffer or a base64 string.
          const buf = Buffer.isBuffer(key) ? key : Buffer.from(key, 'base64');
          const keyB64 = buf.toString('base64');
          presented = { key: buf, algo: keyAlgorithm(buf) };
          if (opts.acceptedKeyB64 && opts.acceptedKeyB64 === keyB64) return true;
          if (opts.acceptedKeys?.[`${spec.hostname}:${spec.port}`] === keyB64) return true;
          const stored = getStoredHostKey(userId, spec.hostname, spec.port);
          return !!stored && stored.key_b64 === keyB64;
        },
      });
    // conn.connect() creates conn._protocol synchronously; patch authPK so a
    // certificate credential is offered with the correct wire format.
    if (spec.certificate) enableCertAuth(conn);
  });
}

// Connect to spec, hopping through bastion hosts (ProxyJump). Chains are
// recursive: a bastion may itself sit behind another bastion, giving
// A -> B -> target hop chains. Host-key verification applies per hop and
// per-hop one-shot accepts live in opts.acceptedKeys['host:port'].
// Errors from a bastion hop carry hopSpec so the caller can display the
// right fingerprint in the trust prompt.
const MAX_HOPS = 8;

function buildChain(userId, spec) {
  const hops = [];
  const seen = new Set(spec.hostId ? [spec.hostId] : []);
  let cursor = spec;
  while (cursor.jumpHostId) {
    if (hops.length >= MAX_HOPS) {
      throw Object.assign(new Error(`bastion chain too long (max ${MAX_HOPS} hops)`), { code: 'error' });
    }
    const hop = resolveConnectSpec(userId, { hostId: cursor.jumpHostId });
    if (seen.has(hop.hostId)) {
      throw Object.assign(new Error('bastion chain contains a cycle'), { code: 'error' });
    }
    seen.add(hop.hostId);
    if (!hop.password && !hop.privateKey) {
      throw Object.assign(
        new Error(`bastion '${hop.label}' has no stored credential — it can't prompt interactively`),
        { code: 'error' }
      );
    }
    hops.push(hop);
    cursor = hop;
  }
  return hops.reverse(); // outermost bastion first
}

async function establishConn(userId, spec, opts = {}) {
  const hops = buildChain(userId, spec);
  if (!hops.length) return tryConnect(userId, spec, opts);

  // Connect outermost bastion first, then tunnel inward hop by hop.
  const conns = [];
  const cleanup = () => conns.forEach((c) => { try { c.end(); } catch {} });
  try {
    let prev = null;
    for (const hop of hops) {
      const hopOpts = { acceptedKeys: opts.acceptedKeys };
      if (prev) {
        hopOpts.sock = await new Promise((resolve, reject) => {
          prev.forwardOut('127.0.0.1', 0, hop.hostname, hop.port, (err, stream) =>
            err ? reject(err) : resolve(stream)
          );
        });
      }
      try {
        prev = await tryConnect(userId, hop, hopOpts);
      } catch (e) {
        if (e.code === 'unknown_hostkey' || e.code === 'hostkey_mismatch') e.hopSpec = hop;
        throw e;
      }
      conns.push(prev);
    }
    const sock = await new Promise((resolve, reject) => {
      prev.forwardOut('127.0.0.1', 0, spec.hostname, spec.port, (err, stream) =>
        err ? reject(err) : resolve(stream)
      );
    });
    const conn = await tryConnect(userId, spec, { ...opts, sock });
    conn.on('close', cleanup);
    return conn;
  } catch (e) {
    cleanup();
    throw e;
  }
}

// Create a registered session around an established connection.
// Sessions are persistent: the owner's WebSocket is attached/detached via
// session.ws, so closing a tab detaches rather than kills — output keeps
// buffering in `replay` for reattach. Only an explicit close (or the idle
// sweep, conn death) destroys the session.
function createSession(userId, conn, spec) {
  let mine = 0;
  for (const s of sessions.values()) if (s.userId === userId) mine++;
  if (mine >= MAX_SESSIONS_PER_USER) {
    try { conn.end(); } catch {}
    throw Object.assign(new Error(`session limit reached (${MAX_SESSIONS_PER_USER} per user)`), { code: 'error' });
  }
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
    healthTimer: null,
    playbook: null, // { steps, idx, buf, marker, send }
    createdAt: Date.now(),
    lastUsed: Date.now(),
    detachedAt: null, // set while no owner ws is attached
  };
  sessions.set(id, session);
  conn.on('error', () => {}); // 'close' follows; prevents unhandled-error crash
  conn.on('close', () => {
    const s = sessions.get(id);
    if (s) {
      sessions.delete(id);
      if (s.healthTimer) clearInterval(s.healthTimer);
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

const REPLAY_CAP = 1024 * 1024;

// Fan a shell chunk to every consumer: the owner's ws (if attached), share
// viewers, the asciinema recorder, and the capped replay buffer that powers
// late-joining viewers *and* reattach scrollback.
function sessionOutput(session, chunk) {
  // Only consumers count as activity — a detached `top` session must still
  // hit the detached-session TTL rather than churning forever.
  if (session.ws || session.viewers.size > 0) session.lastUsed = Date.now();
  session.replay =
    session.replay.length + chunk.length > REPLAY_CAP
      ? Buffer.concat([session.replay.subarray(-REPLAY_CAP / 2), chunk])
      : Buffer.concat([session.replay, chunk]);
  const ws = session.ws;
  if (ws && ws.readyState === ws.OPEN) {
    try { ws.send(chunk, { binary: true }); } catch {}
  }
  for (const vws of session.viewers.keys()) {
    try {
      if (vws.readyState === vws.OPEN) vws.send(chunk, { binary: true });
    } catch {}
  }
  if (session.recorder) session.recorder.out(chunk);
}

// Owner ws lifecycle — detach keeps the session (and its processes) alive.
function attachWs(session, ws) {
  session.ws = ws;
  session.lastUsed = Date.now();
  session.detachedAt = null;
}

function detachWs(session) {
  if (session) {
    session.ws = null;
    if (!session.detachedAt) session.detachedAt = Date.now();
  }
}

function attachViewer(session, ws, mode, shareId) {
  session.viewers.set(ws, { mode, shareId });
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

// Revoking a share link must kill any viewers that got in through it —
// they were admitted on the token's say-so, which no longer exists.
function closeViewersByShare(shareId) {
  for (const s of sessions.values()) {
    for (const [vws, meta] of s.viewers) {
      if (meta.shareId === shareId) {
        try { vws.send(JSON.stringify({ type: 'status', state: 'closed', message: 'share link revoked' })); } catch {}
        try { vws.close(); } catch {}
        s.viewers.delete(vws);
      }
    }
  }
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

// Lightweight host health: one exec channel per tick over the existing
// connection (multiplexed — doesn't disturb the shell). Linux-only metrics;
// failures are silent (we just don't emit).
function probeHealth(session) {
  const ws = session.ws;
  if (!ws || ws.readyState !== ws.OPEN || !session.conn) return;
  try {
    session.conn.exec(
      'cat /proc/loadavg 2>/dev/null; grep -E "MemTotal|MemAvailable" /proc/meminfo 2>/dev/null; df -P / 2>/dev/null | tail -1',
      (err, ch) => {
        if (err) return;
        let text = '';
        ch.on('data', (d) => (text += d));
        ch.on('close', () => {
          const loadM = text.match(/^([\d.]+) ([\d.]+) ([\d.]+)/m);
          const memT = text.match(/MemTotal:\s+(\d+) kB/);
          const memA = text.match(/MemAvailable:\s+(\d+) kB/);
          const diskM = text.match(/(\d+)%\s+\/\s*$/m);
          if (!loadM && !memT) return;
          const msg = { type: 'health' };
          if (loadM) msg.load = [+loadM[1], +loadM[2], +loadM[3]];
          if (memT && memA) msg.memPct = Math.round((1 - +memA[1] / +memT[1]) * 100);
          if (diskM) msg.diskPct = +diskM[1];
          try { ws.send(JSON.stringify(msg)); } catch {}
        });
      }
    );
  } catch {}
}

function destroySession(sessionId) {
  const s = sessions.get(sessionId);
  if (!s) return;
  sessions.delete(sessionId);
  if (s.healthTimer) clearInterval(s.healthTimer);
  if (s.recorder) finalizeRecorder(s);
  try { s.ws?.send(JSON.stringify({ type: 'status', state: 'closed', message: 'session closed' })); } catch {}
  try { s.ws?.close(); } catch {}
  // Kill share viewers + their tokens too — a destroyed session's share links
  // must never resolve again (they'd hang waiting on a dead session_id).
  for (const viewerWs of s.viewers.keys()) {
    try { viewerWs.send(JSON.stringify({ type: 'status', state: 'closed', message: 'session ended by owner' })); } catch {}
    try { viewerWs.close(); } catch {}
  }
  s.viewers.clear();
  try { db.prepare('DELETE FROM shares WHERE session_id = ?').run(sessionId); } catch {}
  try { s.conn.end(); } catch {}
}

// Tear down every live session a user owns — used on logout, password
// change/reset and account deletion so no channel outlives its auth.
function destroyUserSessions(userId) {
  for (const s of [...sessions.values()]) {
    if (s.userId === userId) destroySession(s.id);
  }
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
  destroyUserSessions,
  sessionOutput,
  attachWs,
  detachWs,
  probeHealth,
  attachViewer,
  detachViewer,
  closeViewersByShare,
  finalizeRecorder,
  trustHostKey,
  listHostKeys,
  removeHostKey,
  getStoredHostKey,
};
