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
//   {type:'takeoverAnswer', answer}          — 'full'|'view'|'deny' to a share prompt
//   {type:'close'}
//
// Server → client:
//   binary frames (KVMF wire format — see web/src/lib/kvm/frames.js)
//   {type:'status', state:'connecting'|'ready'|'error'|'closed', message}
//   {type:'ready', sessionId, title, family}
//   {type:'takeover', pending}               — someone wants this console; answer it
//   {type:'takeover_clear'}                  — the request ended (answered/lapsed)
//   {type:'takeover_lapsed', user, answered} — it timed out before an answer

const fs = require('fs');
const path = require('path');
const { audit } = require('../db');
const { resolveConnectSpec } = require('../ssh/manager');

// The vendored bmc-core napi addon, shared with the BMC host-command routes.
const { bmc, bmcError, applyRoutes, chainToRoutes } = require('../bmc');

// Persistent sessions, same model as ssh: detach keeps the console alive —
// but a *detached* console dies on the same TTL ssh uses, and each user is
// capped, so a wedged BMC can't leak bastion tunnels forever.
const sessions = new Map(); // id -> {id, bmc, ws, label, createdAt}
const MEDIA_DIR = path.join(__dirname, '..', '..', 'data', 'media');
const MAX_KVM_PER_USER = 8;
const KVM_DETACHED_TTL_MS = 60 * 60 * 1000;
let seq = 0;

setInterval(() => {
  const now = Date.now();
  for (const s of [...sessions.values()]) {
    if (s.detachedAt && now - s.detachedAt > KVM_DETACHED_TTL_MS) killSession(s);
  }
}, 5 * 60 * 1000).unref();

// End a console: release the BMC handles and unlink any staged media files
// this session mounted (uploads live under data/media and are per-session).
function killSession(s) {
  if (!s) return;
  sessions.delete(s.id);
  if (s.takeoverPoll) clearInterval(s.takeoverPoll);
  try {
    s.bmc.close();
  } catch {}
  for (const f of s.mediaFiles || []) {
    if (f.startsWith(MEDIA_DIR + path.sep)) fs.unlink(f, () => {});
  }
  if (s.ws && s.ws.readyState === 1) send(s.ws, { type: 'status', state: 'closed' });
}

function send(ws, obj) {
  if (ws.readyState === 1) ws.send(JSON.stringify(obj));
}

// Push the console-sharing state to whichever socket is watching: a pending
// request goes out once per distinct prompt, its end as takeover_clear, and a
// request that timed out unanswered as takeover_lapsed (the core reports each
// lapsed request exactly once).
function pushTakeover(s) {
  const ws = s.ws;
  if (!ws || ws.readyState !== 1) return;
  let st;
  try {
    st = s.bmc.takeoverState();
  } catch {
    return; // console not adopted yet
  }
  if (!st) return;
  if (st.pending) {
    const key = `${st.pending.user}${st.pending.question}`;
    if (s.takeoverKey !== key) {
      s.takeoverKey = key;
      send(ws, { type: 'takeover', pending: st.pending });
    }
  } else if (s.takeoverKey) {
    s.takeoverKey = null;
    send(ws, { type: 'takeover_clear' });
  }
  if (st.lapsed) {
    send(ws, { type: 'takeover_lapsed', user: st.lapsed.user, answered: st.lapsed.answered });
  }
}

// An in-flight BMC operation's stage, for the client's progress list:
// {type:'op', op:'mount'|'power', phase:'start'|'stage'|'done'|'error', message}
function op(ws, name, phase, message) {
  send(ws, { type: 'op', op: name, phase, message });
}

function handleKvmWs(ws, req, user) {
  if (!bmc) {
    send(ws, { type: 'status', state: 'error', message: `KVM backend unavailable on this install (${bmcError})` });
    ws.close();
    return;
  }
  let session = null;

  // Any inbound message means a live socket is driving this console.
  ws.on('message', (data, isBinary) => {
    if (session) session.detachedAt = null;
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
          s.detachedAt = null;
          send(ws, { type: 'ready', sessionId: s.id, title: s.label, family: s.family, reattached: true });
          pushTakeover(s); // a prompt may already be pending
          audit(user, 'kvm.reattach', s.label, req);
          break;
        }
        case 'key':
          sendInput(() => session.bmc.sendKey(msg.usage | 0, !!msg.down, !!msg.repeat));
          break;
        case 'pointer':
          sendInput(() => session.bmc.sendPointer(+msg.x, +msg.y, msg.fw | 0, msg.fh | 0, msg.buttons | 0, msg.wheel | 0));
          break;
        case 'char':
          sendInput(() => session.bmc.sendChar(String(msg.c || '').slice(0, 1)));
          break;
        case 'releaseAll':
          sendInput(() => session.bmc.releaseAll());
          break;
        case 'cad':
          sendInput(() => session.bmc.sendCad());
          break;
        case 'takeoverAnswer': {
          const ans = String(msg.answer || '');
          if (session) {
            try {
              const ok = session.bmc.takeoverAnswer(ans);
              audit(user, 'kvm.takeover', `${session.label} → ${ans}${ok ? '' : ' (request had ended)'}`, req);
            } catch (e) {
              send(ws, { type: 'status', state: 'notice', message: e.message });
            }
          }
          break;
        }
        case 'mount': {
          // spec: server-side path or http(s) URL — async; stages land as
          // {type:'op'} + notices from the core's own sink
          const spec = String(msg.spec || '');
          if (session && spec) {
            // A staged file under data/media is ours to clean up on kill.
            if (spec.startsWith(MEDIA_DIR + path.sep)) session.mediaFiles.add(spec);
            op(ws, 'mount', 'start', 'attaching media…');
            session.bmc
              .mountMedia(spec)
              .then((m) => {
                op(ws, 'mount', 'done', String(m));
                send(ws, { type: 'status', state: 'notice', message: String(m) });
                audit(user, 'bmc.mount', `${session.label} ${spec}`, req);
              })
              .catch((e) => {
                op(ws, 'mount', 'error', `mount failed: ${e.message}`);
                send(ws, { type: 'status', state: 'notice', message: `mount failed: ${e.message}` });
              });
          }
          break;
        }
        case 'unmount':
          op(ws, 'mount', 'start', 'ejecting media…');
          sendInput(() => session.bmc.unmountMedia());
          op(ws, 'mount', 'done', 'media ejected');
          send(ws, { type: 'status', state: 'notice', message: 'media ejected' });
          break;
        case 'power': {
          // Chassis power through the console's own creds + detected family —
          // no re-detect, so the wait is the BMC's own API/IPMI round trip.
          const action = String(msg.action || '');
          if (!session || !session.spec) break;
          if (!['on', 'off', 'reset', 'cycle', 'soft', 'mcreset'].includes(action)) break;
          const label = action === 'mcreset' ? 'BMC reset' : `power ${action}`;
          op(ws, 'power', 'start', `${label} → ${session.label}`);
          op(ws, 'power', 'stage', 'sending to the BMC…');
          const task =
            action === 'mcreset'
              ? bmc.bmcReset(session.spec)
              : action === 'cycle'
                ? bmc.ipmiPower(session.spec, action)
                : bmc.powerCmd(session.spec, action, session.family || null);
          task
            .then((m) => {
              op(ws, 'power', 'done', String(m));
              send(ws, { type: 'status', state: 'notice', message: String(m) });
              audit(user, 'bmc.power', `${session.label} ${action}`, req);
            })
            .catch((e) => {
              op(ws, 'power', 'error', `power failed: ${e.message}`);
              send(ws, { type: 'status', state: 'notice', message: `power failed: ${e.message}` });
            });
          break;
        }
        case 'close': {
          const s = session;
          session = null;
          if (s) killSession(s);
          break;
        }
      }
    } catch (e) {
      send(ws, { type: 'status', state: 'error', message: e.message });
    }
  });

  ws.on('close', () => {
    // detach — the console keeps running for reattach, but only for the TTL
    if (session && session.ws === ws) {
      session.ws = null;
      if (!session.detachedAt) session.detachedAt = Date.now();
    }
    session = null;
  });

  // Input is best-effort: a pre-ready key or a dead channel is a notice,
  // never the fatal 'error' status that ends the session client-side.
  function sendInput(fn) {
    try {
      if (session) fn();
    } catch (e) {
      send(ws, { type: 'status', state: 'notice', message: e.message });
    }
  }

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
    let mine = 0;
    for (const s of sessions.values()) if (s.userId === user.id) mine++;
    if (mine >= MAX_KVM_PER_USER) {
      send(ws, { type: 'status', state: 'error', message: `KVM session limit reached (${MAX_KVM_PER_USER})` });
      return;
    }
    send(ws, { type: 'status', state: 'connecting', message: `connecting to ${spec.label} …` });

    // Bastion chain → bmc route table (installed globally by addr).
    try {
      applyRoutes(resolveConnectSpec, user.id, spec);
    } catch (e) {
      send(ws, { type: 'status', state: 'error', message: 'route setup failed: ' + e.message });
      return;
    }

    const id = `kvm${++seq}-${Date.now().toString(36)}`;
    // napi ThreadsafeFunction callbacks fire as (err, value) — the payload
    // is the second arg, not the first.
    const b = new bmc.BmcSession(
      { host: spec.hostname, user: spec.username || '', pass, seize: !!msg.seize },
      (_err, line) => onEvent(String(line ?? '')),
      (_err, frame) => {
        const s = sessions.get(id);
        if (frame && s?.ws && s.ws.readyState === 1) s.ws.send(Buffer.from(frame));
      }
    );

    const rec = {
      id,
      bmc: b,
      ws,
      userId: user.id,
      label: spec.label,
      family: null,
      spec: { host: spec.hostname, user: spec.username || '', pass },
      mediaFiles: new Set(),
      detachedAt: null,
      createdAt: Date.now(),
    };
    sessions.set(id, rec);
    session = rec;
    // Console-sharing prompts ("X wants this console") ride this poll — the
    // core's slot only lives in Rust, so JS asks for its state.
    rec.takeoverPoll = setInterval(() => pushTakeover(rec), 800);
    rec.takeoverPoll.unref();

    function onEvent(line) {
      const s = sessions.get(id);
      const out = s?.ws || ws;
      const [kind, ...rest] = line.split(':');
      const body = rest.join(':');
      if (kind === 'ready') {
        const [title, family] = body.split(':');
        s.family = family;
        send(out, { type: 'ready', sessionId: id, title, family });
        pushTakeover(s);
        audit(user, 'kvm.connect', spec.label, req);
      } else if (kind === 'progress') {
        send(out, { type: 'status', state: 'connecting', message: body });
      } else if (kind === 'error') {
        send(out, { type: 'status', state: 'error', message: body });
      } else if (kind === 'ended') {
        send(out, { type: 'status', state: 'closed', message: 'console ended' });
        killSession(s);
      } else if (kind === 'problem' || kind === 'notice') {
        // The core's own mount stages ("mount: attaching …") land here —
        // mirror them into the op stream so the client's progress list ticks.
        if (body.startsWith('mount:')) op(out, 'mount', 'stage', body.slice(6).trim());
        send(out, { type: 'status', state: 'notice', message: body });
      }
    }
  }


}

module.exports = { handleKvmWs };
