'use strict';

const { db, audit } = require('../db');
const { sessions, attachViewer, detachViewer } = require('../ssh/manager');
const { shareByToken } = require('../routes/shares');
const { kvmSession, attachKvmViewer } = require('./kvm');

// Public viewer WebSocket: /ws/share/<token>
// Streams the owner's live terminal. 'control' shares can also send input.
function handleShareWs(ws, req, token) {
  const send = (obj) => {
    if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(obj));
  };

  const share = shareByToken(token);
  if (!share) {
    send({ type: 'status', state: 'error', message: 'link expired or revoked' });
    return ws.close();
  }

  // KVM console shares: the token attaches a view-only watcher to the live
  // BmcSession — same framebuffer fan-out the owner sees, no input path.
  if (share.kind === 'kvm') {
    const ks = kvmSession(share.session_id);
    if (!ks) {
      send({ type: 'status', state: 'error', message: 'console has ended' });
      return ws.close();
    }
    attachKvmViewer(ks, ws, share.id);
    audit(null, 'share.kvm_viewer_joined', `'${share.label}'`, req);
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
  audit(null, 'share.viewer_joined', `'${share.label}' (${share.mode})`, req);

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
