'use strict';

const crypto = require('crypto');
const { db, audit } = require('../db');
const { CastRecorder } = require('../ssh/recorder');
const {
  resolveConnectSpec,
  establishConn,
  createSession,
  getSession,
  destroySession,
  trustHostKey,
  sessionOutput,
  attachWs,
  detachWs,
  probeHealth,
} = require('../ssh/manager');

const MAX_AUTH_ATTEMPTS = 3;

// JSON control protocol + binary frames for terminal I/O.
// client->server JSON:
//   {type:'connect', hostId|inline:{hostname,port,username,password?}, cols, rows}
//   {type:'reattach', sessionId, cols, rows}
//   {type:'trust', accept:'always'|'once'|'reject'}
//   {type:'auth', password:string}
//   {type:'resize', cols, rows}
//   {type:'playbook', playbookId} / {type:'playbook_stop'}
//   {type:'close'}                — explicit kill (vs ws close = detach)
// server->client JSON:
//   {type:'status', state, message}   state 'gone' = session doesn't exist
//   {type:'hostkey', fingerprint, algorithm, hostname, port, hop}
//   {type:'auth_request', reason}
//   {type:'ready', sessionId, label, reattached}
//   {type:'playbook_step', index, total, status, exitCode, command}
//   {type:'playbook_done', ok, aborted}
//   {type:'health', load, memPct, diskPct}
function handleTerminalWs(ws, req, user) {
  const send = (obj) => {
    if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(obj));
  };
  // Session-scoped send: output handlers outlive any one WebSocket (detach →
  // reattach swaps session.ws), so events like playbook progress must go to
  // the *currently attached* socket, not the one that ran 'connect'.
  const sendToSession = (sess, obj) => {
    const w = sess?.ws;
    if (w && w.readyState === w.OPEN) {
      try { w.send(JSON.stringify(obj)); } catch {}
    }
  };

  let spec = null;
  let session = null;
  let stream = null;
  let awaiting = null; // 'trust' | 'auth' | null
  let pendingKey = null;
  let authAttempts = 0;
  let pendingResize = { cols: 80, rows: 24 };
  let acceptedKeys = {}; // 'hostname:port' -> keyB64, one-shot trusts this connect
  let intentionalClose = false;

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

      case 'reattach': {
        if (session || spec) return;
        const s = getSession(user.id, String(msg.sessionId || ''));
        if (!s || !s.stream) {
          send({ type: 'status', state: 'gone' });
          return;
        }
        session = s;
        stream = s.stream;
        spec = s.spec;
        attachWs(s, ws);
        stream.setWindow(clampDim(msg.rows, 24), clampDim(msg.cols, 80), 0, 0);
        // scrollback replay first, then ready — restores the whole terminal
        if (s.replay.length) ws.send(s.replay, { binary: true });
        send({ type: 'ready', sessionId: s.id, label: s.label, reattached: true });
        if (s.recorder) send({ type: 'recording', on: true });
        audit(user, 'ssh.reattach', s.label, req);
        break;
      }

      case 'trust':
        if (awaiting !== 'trust' || !pendingKey) return;
        if (msg.accept === 'always') {
          trustHostKey(user.id, pendingKey.hostname, pendingKey.port, pendingKey.keyB64, pendingKey.algorithm);
          audit(user, 'ssh.hostkey_trusted', `${pendingKey.hostname}:${pendingKey.port} ${pendingKey.fingerprint}`, req);
        }
        if (msg.accept === 'always' || msg.accept === 'once') {
          acceptedKeys[`${pendingKey.hostname}:${pendingKey.port}`] = pendingKey.keyB64;
          pendingKey = null;
          awaiting = null;
          connect();
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

      case 'ping':
        send({ type: 'pong', t: msg.t });
        break;

      case 'resize':
        pendingResize = { cols: clampDim(msg.cols, 80), rows: clampDim(msg.rows, 24) };
        if (stream) stream.setWindow(pendingResize.rows, pendingResize.cols, 0, 0);
        break;

      case 'record':
        if (!session) return;
        if (msg.on && !session.recorder) startRecording();
        if (!msg.on && session.recorder) stopRecording();
        break;

      case 'playbook':
        if (!session || !stream || session.playbook) return;
        startPlaybook(msg.playbookId);
        break;

      case 'playbook_stop':
        if (session?.playbook) {
          session.playbook = null;
          send({ type: 'playbook_done', ok: false, aborted: true });
        }
        break;

      case 'close':
        intentionalClose = true;
        if (session) destroySession(session.id);
        ws.close();
        break;
    }
  });

  ws.on('close', () => {
    // Explicit 'close' already destroyed; anything else is a detach — the
    // session, its shell and its processes keep running for reattach.
    // Guard: only detach if we're still the attached ws — a new socket may
    // already have reattached before this close event lands.
    if (session && !intentionalClose) {
      audit(user, 'ssh.detach', session.label, req);
      if (session.ws === ws) detachWs(session);
    }
    session = null;
    stream = null;
  });

  function connect() {
    send({ type: 'status', state: 'connecting', message: `connecting to ${spec.label} ...` });
    establishConn(user.id, spec, { acceptedKeys })
      .then((conn) => onConnected(conn))
      .catch((err) => {
        switch (err.code) {
          case 'unknown_hostkey': {
            // hopSpec is the bastion when the failing hop is a jump host.
            const hop = err.hopSpec || spec;
            pendingKey = {
              hostname: hop.hostname,
              port: hop.port,
              fingerprint: err.fingerprint,
              keyB64: err.keyB64,
              algorithm: err.algorithm,
              hop: err.hopSpec ? 'jump' : 'target',
            };
            awaiting = 'trust';
            send({
              type: 'hostkey',
              hostname: hop.hostname,
              port: hop.port,
              fingerprint: err.fingerprint,
              algorithm: err.algorithm,
              hop: pendingKey.hop,
            });
            break;
          }
          case 'hostkey_mismatch': {
            const hop = err.hopSpec || spec;
            audit(user, 'ssh.hostkey_mismatch', `${hop.hostname}:${hop.port} saw ${err.fingerprint}, expected ${err.expected}`, req);
            send({
              type: 'status',
              state: 'error',
              message:
                `HOST KEY CHANGED for ${hop.hostname}:${hop.port}! ` +
                `Expected ${err.expected}, got ${err.fingerprint}. ` +
                'This could indicate a man-in-the-middle attack. Delete the stored key in Settings if the change is expected.',
            });
            ws.close();
            break;
          }
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
    const sess = createSession(user.id, conn, spec);
    session = sess;
    attachWs(sess, ws);
    audit(user, 'ssh.connect', spec.label, req);
    if (spec.hostId) {
      try {
        db.prepare('UPDATE hosts SET last_used_at = unixepoch() WHERE id = ?').run(spec.hostId);
      } catch {}
    }
    conn.shell(
      { term: 'xterm-256color', cols: pendingResize.cols, rows: pendingResize.rows },
      (err, s) => {
        if (err) {
          send({ type: 'status', state: 'error', message: 'shell request failed: ' + err.message });
          return destroySession(sess.id);
        }
        stream = s;
        sess.stream = s;
        if (!sess.healthTimer) {
          sess.healthTimer = setInterval(() => probeHealth(sess), 10000);
          setTimeout(() => probeHealth(sess), 1500);
        }
        send({ type: 'ready', sessionId: sess.id, label: spec.label });
        if (spec.record) startRecording();
        const onOut = (chunk) => {
          scanPlaybook(sess, chunk);
          sessionOutput(sess, chunk);
        };
        s.on('data', onOut);
        s.stderr?.on('data', onOut);
        s.on('close', () => {
          sendToSession(sess, { type: 'status', state: 'closed', message: 'session ended' });
          destroySession(sess.id);
        });
      }
    );
  }

  // ---- Playbooks: run steps sequentially, detect each step's exit code via
  // a unique marker echo. Output (including the marker line) still streams
  // to the terminal so progress is visible.
  function startPlaybook(playbookId) {
    const pb = db
      .prepare('SELECT * FROM playbooks WHERE id = ? AND user_id = ?')
      .get(playbookId, user.id);
    if (!pb) return send({ type: 'status', state: 'error', message: 'playbook not found' });
    let steps;
    try {
      steps = JSON.parse(pb.steps);
    } catch {
      steps = [];
    }
    steps = (steps || []).filter((s) => s && typeof s.command === 'string' && s.command.trim());
    if (!steps.length) return send({ type: 'status', state: 'error', message: 'playbook has no steps' });
    session.playbook = {
      steps,
      idx: 0,
      buf: '',
      rand: crypto.randomBytes(4).toString('hex'),
      name: pb.name,
    };
    audit(user, 'playbook.run', `${pb.name} on ${session.label}`, req);
    runPlaybookStep(session);
  }

  // NOTE: takes the session object, not the ws-scoped `session` — this runs
  // from the stream data handler which outlives whichever socket attached.
  function runPlaybookStep(sess) {
    const pb = sess.playbook;
    const step = pb.steps[pb.idx];
    sendToSession(sess, {
      type: 'playbook_step',
      index: pb.idx,
      total: pb.steps.length,
      status: 'running',
      command: step.command,
      name: pb.name,
    });
    sess.stream.write(`${step.command}\necho "__SSLPB_${pb.idx}_${pb.rand}_$?__"\n`);
  }

  function scanPlaybook(sess, chunk) {
    const pb = sess.playbook;
    if (!pb) return;
    pb.buf = (pb.buf + chunk.toString('utf8')).slice(-8192);
    const m = pb.buf.match(new RegExp(`__SSLPB_${pb.idx}_${pb.rand}_(\\d+)__`));
    if (!m) return;
    const exitCode = parseInt(m[1], 10);
    sendToSession(sess, {
      type: 'playbook_step',
      index: pb.idx,
      total: pb.steps.length,
      status: exitCode === 0 ? 'ok' : 'fail',
      exitCode,
      command: pb.steps[pb.idx].command,
    });
    pb.idx++;
    pb.buf = '';
    if (pb.idx >= pb.steps.length) {
      sess.playbook = null;
      sendToSession(sess, { type: 'playbook_done', ok: exitCode === 0 });
      return;
    }
    // A failed step aborts the run — later steps assume earlier state.
    if (exitCode !== 0) {
      sess.playbook = null;
      sendToSession(sess, { type: 'playbook_done', ok: false });
      return;
    }
    runPlaybookStep(sess);
  }

  function startRecording() {
    const rec = new CastRecorder(session.id, pendingResize.cols, pendingResize.rows, session.label);
    session.recorder = rec;
    const info = db
      .prepare('INSERT INTO recordings (user_id, session_id, label, file) VALUES (?, ?, ?, ?)')
      .run(user.id, session.id, session.label, rec.file);
    rec.recId = info.lastInsertRowid;
    send({ type: 'recording', on: true });
    audit(user, 'recording.started', session.label, req);
  }

  function stopRecording() {
    const { size } = session.recorder.close();
    db.prepare('UPDATE recordings SET ended_at = unixepoch(), size = ? WHERE id = ?').run(
      size,
      session.recorder.recId
    );
    session.recorder = null;
    send({ type: 'recording', on: false });
  }

  // Nothing happens until the client sends 'connect' or 'reattach'. For 'ask'
  // auth the first attempt still verifies the host key before we prompt for a
  // password, so the fingerprint is shown before credentials are typed.
  send({ type: 'hello' });
}

function clampDim(v, fallback) {
  const n = parseInt(v, 10);
  return Number.isFinite(n) && n >= 1 && n <= 1000 ? n : fallback;
}

module.exports = { handleTerminalWs };
