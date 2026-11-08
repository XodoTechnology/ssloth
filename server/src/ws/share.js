'use strict';

const { db, audit } = require('../db');
const { sessions, attachViewer, detachViewer } = require('../ssh/manager');
const { shareByToken } = require('../routes/shares');
const { kvmSession, attachKvmViewer } = require('./kvm');
const { verifyPassword } = require('../crypto');

const SHARE_AUTH_TIMEOUT_MS = 60_000;
const SHARE_AUTH_MAX_ATTEMPTS = 5;

// Share events belong to the link's owner — attribute them so they show in
// the owner's audit log and forward to their webhooks.
function shareOwner(share) {
  if (!share) return null;
  return db.prepare('SELECT id, username FROM users WHERE id = ?').get(share.user_id) || { id: share.user_id };
}

// Public viewer WebSocket: /ws/share/<token>
// Streams the owner's live terminal. 'control' shares can also send input.
// Links created with a password must answer a share_auth challenge first.
function handleShareWs(ws, req, token) {
  const send = (obj) => {
    if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(obj));
  };

  const share = shareByToken(token);
  if (!share) {
    // Probing dead/guessed share links is worth a trail — the public GET
    // metadata route stays silent to avoid crawler noise, but an actual
    // view attempt is a real signal.
    audit(null, 'share.token_rejected', 'invalid, expired or revoked share token', req);
    send({ type: 'status', state: 'error', message: 'link expired or revoked' });
    return ws.close();
  }

  const proceed = () => {
    attachShare(ws, req, share, send);
  };

  if (share.password_hash) {
    let attempts = 0;
    const authTimer = setTimeout(() => {
      send({ type: 'status', state: 'error', message: 'authentication timed out' });
      ws.close();
    }, SHARE_AUTH_TIMEOUT_MS);
    authTimer.unref();
    ws.on('close', () => clearTimeout(authTimer));
    send({ type: 'share_auth_required' });
    ws.on('message', function onAuth(data, isBinary) {
      if (isBinary) return;
      let m;
      try {
        m = JSON.parse(data);
      } catch {
        return;
      }
      if (m?.type !== 'share_auth') return;
      attempts++;
      verifyPassword(String(m.password || ''), share.password_hash)
        .then((ok) => {
          if (!ok) {
            if (attempts >= SHARE_AUTH_MAX_ATTEMPTS) {
              send({ type: 'status', state: 'error', message: 'too many failed attempts' });
              return ws.close();
            }
            return send({ type: 'share_auth_required', error: 'incorrect password' });
          }
          clearTimeout(authTimer);
          ws.off('message', onAuth);
          audit(shareOwner(share), 'share.password_ok', `'${share.label}'`, req);
          proceed();
        })
        .catch(() => send({ type: 'share_auth_required', error: 'verification failed' }));
    });
    return;
  }

  proceed();
}

function attachShare(ws, req, share, send) {

  // KVM console shares: the token attaches a view-only watcher to the live
  // BmcSession — same framebuffer fan-out the owner sees, no input path.
  if (share.kind === 'kvm') {
    const ks = kvmSession(share.session_id);
    if (!ks) {
      send({ type: 'status', state: 'error', message: 'console has ended' });
      return ws.close();
    }
    attachKvmViewer(ks, ws, share.id);
    audit(shareOwner(share), 'share.kvm_viewer_joined', `'${share.label}'`, req);
    const msLeft = share.expires_at * 1000 - Date.now();
    const timer = setTimeout(() => {
      send({ type: 'status', state: 'closed', message: 'share link expired' });
      ws.close();
    }, msLeft);
    timer.unref();
    ws.on('close', () => clearTimeout(timer));
    return;
  }

  const session = sessions.get(share.session_id);
  if (!session || !session.stream) {
    send({ type: 'status', state: 'error', message: 'session has ended' });
    return ws.close();
  }

  const canWrite = share.mode === 'control';
  attachViewer(session, ws, share.mode, share.id);
  send({ type: 'ready', label: share.label, mode: share.mode, expires_at: share.expires_at * 1000 });
  audit(shareOwner(share), 'share.viewer_joined', `'${share.label}' (${share.mode})`, req);

  ws.on('message', (data, isBinary) => {
    if (!isBinary || !canWrite) return;
    try {
      session.stream.write(data);
      session.lastUsed = Date.now();
    } catch {}
  });

  ws.on('close', () => detachViewer(session, ws));

  // Expire the socket itself when the share TTL runs out.
  const msLeft = share.expires_at * 1000 - Date.now();
  const timer = setTimeout(() => {
    send({ type: 'status', state: 'closed', message: 'share link expired' });
    ws.close();
  }, msLeft);
  timer.unref();
  ws.on('close', () => clearTimeout(timer));
}

module.exports = { handleShareWs };
