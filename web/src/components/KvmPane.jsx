import React, { useEffect, useRef, useState } from 'react';
import { decodeFrame, paintFrame, hidFor, usKey } from '../lib/kvm';
import { api } from '../api';
import { useStore } from '../store';
import Modal from './Modal';

// One pane = one BMC console: a canvas painted from KVMF wire frames over
// /ws/kvm, with HID input forwarded as input::Events. Same lifecycle as
// TerminalPane — detach keeps the console server-side, reattach resumes it.
export default function KvmPane({ tab, pane, active, focused, onFocus, onPaneState }) {
  const canvasRef = useRef(null);
  const wrapRef = useRef(null);
  const wsRef = useRef(null);
  const sessionRef = useRef(null);
  const heldRef = useRef(new Set());
  const mountedRef = useRef(true);
  const retryRef = useRef({ attempt: 0, timer: null });
  const intentionalRef = useRef(false);
  const stateRef = useRef({ status: 'idle' });
  const [pasteOpen, setPasteOpen] = useState(false);
  const [pasteText, setPasteText] = useState('');
  const [mountOpen, setMountOpen] = useState(false);
  const [mountUrl, setMountUrl] = useState('');
  const [op, setOp] = useState(null); // {name, stages:[{msg,done}], done, err}
  const [stages, setStages] = useState([]); // connect-time stage lines
  const [takeover, setTakeover] = useState(null); // {user, question, answers:[{answer,label}]}
  const fileRef = useRef(null);
  const opTimerRef = useRef(null);
  const toast = useStore((s) => s.toast);
  const setPaneStateRef = useRef(setPaneState);
  setPaneStateRef.current = setPaneState;

  function setPaneState(patch) {
    stateRef.current = { ...stateRef.current, ...(typeof patch === 'function' ? patch(stateRef.current) : patch) };
    onPaneState(tab.id, pane.id, stateRef.current);
  }

  useEffect(() => {
    mountedRef.current = true;
    const prior = useStore.getState().paneStates[`${tab.id}:${pane.id}`];
    if (prior?.sessionId) sessionRef.current = prior.sessionId;
    open();
    // The toolbar drives this pane through the registered sender — mount
    // modal, power, reconnect all reach the live ws through sendJson.
    useStore.getState().registerPane(tab.id, pane.id, {
      sendJson: (obj) => wsRef.current?.readyState === 1 && wsRef.current.send(JSON.stringify(obj)),
      reconnect: () => { intentionalRef.current = false; open(); },
      openMount: () => setMountOpen(true),
      closeSession: () => sendJson({ type: 'close' }),
    });
    const onBlur = () => {
      heldRef.current.clear();
      if (wsRef.current?.readyState === 1) wsRef.current.send(JSON.stringify({ type: 'releaseAll' }));
    };
    window.addEventListener('blur', onBlur);
    return () => {
      mountedRef.current = false;
      window.removeEventListener('blur', onBlur);
      clearTimeout(retryRef.current.timer);
      clearTimeout(opTimerRef.current);
      useStore.getState().unregisterPane(tab.id, pane.id);
      try { wsRef.current?.close(); } catch {}
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab.id, pane.id]);

  function scheduleRetry() {
    const r = retryRef.current;
    r.attempt = Math.min(r.attempt + 1, 12);
    const delay = Math.min(1000 * r.attempt, 15000);
    setPaneState({ status: 'connecting', statusMsg: `connection lost — reconnecting in ${Math.ceil(delay / 1000)}s` });
    r.timer = setTimeout(() => mountedRef.current && open(), delay);
  }

  function open() {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${proto}://${location.host}/ws/kvm`);
    ws.binaryType = 'arraybuffer';
    wsRef.current = ws;
    intentionalRef.current = false;
    setPaneState({ status: 'connecting', statusMsg: sessionRef.current ? 'reattaching…' : 'connecting…' });

    ws.onopen = () => {
      if (sessionRef.current) {
        ws.send(JSON.stringify({ type: 'reattach', sessionId: sessionRef.current }));
      } else {
        ws.send(JSON.stringify({ type: 'connect', ...pane.target }));
      }
    };
    ws.onmessage = (ev) => {
      if (ev.data instanceof ArrayBuffer) {
        try {
          const frame = decodeFrame(ev.data);
          const canvas = canvasRef.current;
          if (!canvas) return;
          if (canvas.width !== frame.width || canvas.height !== frame.height) {
            canvas.width = frame.width;
            canvas.height = frame.height;
          }
          paintFrame(canvas.getContext('2d'), frame);
        } catch (e) {
          console.warn('kvm frame:', e.message);
        }
        return;
      }
      let msg;
      try { msg = JSON.parse(ev.data); } catch { return; }
      switch (msg.type) {
        case 'ready':
          sessionRef.current = msg.sessionId;
          retryRef.current.attempt = 0;
          setStages([]);
          setPaneState({ status: 'ready', sessionId: msg.sessionId, statusMsg: msg.reattached ? 'session restored' : `${msg.title} (${msg.family})` });
          break;
        case 'op':
          // A BMC operation's progress report — mount/power stage lines.
          setOp((cur) => {
            if (msg.phase === 'start' || !cur || cur.name !== msg.op || cur.done) {
              return { name: msg.op, stages: [{ msg: msg.message, done: false }], done: false, err: false };
            }
            const stages = [...cur.stages];
            if (msg.phase === 'stage') {
              if (stages.length) stages[stages.length - 1] = { ...stages[stages.length - 1], done: true };
              stages.push({ msg: msg.message, done: false });
              return { ...cur, stages };
            }
            if (stages.length) stages[stages.length - 1] = { ...stages[stages.length - 1], done: true };
            stages.push({ msg: msg.message, done: true });
            return { ...cur, stages, done: msg.phase === 'done', err: msg.phase === 'error' };
          });
          if (msg.phase === 'done' || msg.phase === 'error') {
            clearTimeout(opTimerRef.current);
            opTimerRef.current = setTimeout(() => mountedRef.current && setOp(null), msg.phase === 'done' ? 5000 : 9000);
          }
          break;
        case 'status':
          setPaneState({ statusMsg: msg.message || '' });
          if (msg.state === 'connecting') {
            setPaneState({ status: 'connecting' });
            if (msg.message) setStages((s) => (s[s.length - 1] === msg.message ? s : [...s.slice(-7), msg.message]));
          } else if (msg.state === 'error') {
            sessionRef.current = null;
            setPaneState({ status: 'error', sessionId: null });
            setTakeover(null);
            clearCanvas();
          } else if (msg.state === 'closed') {
            setPaneState({ status: 'closed' });
            setTakeover(null);
            clearCanvas();
          }
          break;
        case 'takeover':
          setTakeover(msg.pending || null);
          break;
        case 'takeover_clear':
          setTakeover(null);
          break;
        case 'takeover_lapsed':
          setTakeover(null);
          toast(`${msg.user || 'Another user'}'s console request ${msg.answered ? `was answered (${msg.answered})` : 'timed out'}`, 'info');
          break;
      }
    };
    ws.onclose = () => {
      if (!mountedRef.current || intentionalRef.current) return;
      if (sessionRef.current) scheduleRetry();
      else setPaneState((s) => ({ status: s.status === 'error' ? 'error' : 'closed' }));
    };
  }

  const sendJson = (o) => wsRef.current?.readyState === 1 && wsRef.current.send(JSON.stringify(o));

  // View-only share link for this console — anyone with the URL watches the
  // same framebuffer; the token is the credential and expires on its own.
  async function shareConsole() {
    try {
      const r = await api('/api/shares', {
        method: 'POST',
        body: { session_id: sessionRef.current, kind: 'kvm', mode: 'view', ttl_minutes: 60 },
      });
      const url = `${location.origin}${r.share.url}`;
      try { await navigator.clipboard.writeText(url); } catch {}
      toast('view-only console link copied (expires in 1h)', 'success');
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  // Wipe the framebuffer — a closed/error console shouldn't keep showing the
  // last frame it received behind the overlay.
  const clearCanvas = () => {
    const c = canvasRef.current;
    if (!c) return;
    const ctx = c.getContext('2d');
    ctx.fillStyle = '#000';
    ctx.fillRect(0, 0, c.width, c.height);
  };

  const onKey = (e, down) => {
    if (stateRef.current.status !== 'ready') return;
    const u = hidFor(e.code);
    if (u === null) return;
    if (down && e.repeat && heldRef.current.has(u)) { sendJson({ type: 'key', usage: u, down: true, repeat: true }); e.preventDefault(); return; }
    if (down) { if (heldRef.current.has(u)) return; heldRef.current.add(u); }
    else if (!heldRef.current.delete(u)) return;
    sendJson({ type: 'key', usage: u, down, repeat: e.repeat });
    e.preventDefault();
  };

  const pointer = (e, buttons, wheel = 0) => {
    if (stateRef.current.status !== 'ready') return;
    const c = canvasRef.current;
    if (!c || !c.width) return;
    const r = c.getBoundingClientRect();
    sendJson({ type: 'pointer', x: (e.clientX - r.left) / r.width, y: (e.clientY - r.top) / r.height, fw: c.width, fh: c.height, buttons, wheel });
  };

  const pasteKeys = () => {
    let i = 0;
    const step = () => {
      if (i >= pasteText.length) { setPasteOpen(false); setPasteText(''); return; }
      const k = usKey(pasteText[i++]);
      if (k) {
        if (k.shift) sendJson({ type: 'key', usage: 0xe1, down: true });
        sendJson({ type: 'key', usage: k.usage, down: true });
        sendJson({ type: 'key', usage: k.usage, down: false });
        if (k.shift) sendJson({ type: 'key', usage: 0xe1, down: false });
      }
      setTimeout(step, 40);
    };
    step();
  };

  const st = stateRef.current;

  return (
    <div
      ref={wrapRef}
      className="absolute inset-0 flex items-center justify-center bg-black overflow-hidden"
      onMouseDown={onFocus}
      tabIndex={0}
      onKeyDown={(e) => onKey(e, true)}
      onKeyUp={(e) => onKey(e, false)}
      style={{ outline: 'none' }}
    >
      <canvas
        ref={canvasRef}
        className="max-w-full max-h-full"
        style={{ visibility: st.status === 'ready' ? 'visible' : 'hidden' }}
        onMouseMove={(e) => pointer(e, e.buttons)}
        onMouseDown={(e) => pointer(e, e.buttons | (1 << e.button === 1 ? 0 : e.button))}
        onMouseUp={(e) => pointer(e, e.buttons)}
        onWheel={(e) => pointer(e, e.buttons, e.deltaY < 0 ? 1 : -1)}
        onContextMenu={(e) => e.preventDefault()}
      />
      {st.status !== 'ready' && (
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 bg-ink-950 text-zinc-400">
          <p className="text-sm">{st.status === 'error' ? 'connection failed' : st.status === 'closed' ? 'console closed' : 'connecting…'}</p>
          {stages.length > 0 ? (
            <div className="flex flex-col gap-0.5 text-left">
              {stages.map((s, i) => (
                <p key={i} className={`text-xs font-mono ${i === stages.length - 1 ? 'text-zinc-400' : 'text-zinc-600'}`}>
                  {i === stages.length - 1 && st.status === 'connecting' ? '▸ ' : '  '}{s}
                </p>
              ))}
            </div>
          ) : (
            st.statusMsg && <p className="text-xs text-zinc-600 max-w-md text-center">{st.statusMsg}</p>
          )}
          {(st.status === 'error' || st.status === 'closed') && (
            <button className="btn-primary mt-2" onClick={() => { intentionalRef.current = false; open(); }}>Reconnect</button>
          )}
        </div>
      )}
      {op && (
        <div className="absolute bottom-3 right-3 z-20 w-64 rounded-md border border-ink-700 bg-ink-900/95 shadow-lg p-2.5">
          <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-zinc-300">
            {!op.done && !op.err && <span className="h-2 w-2 rounded-full bg-amber-400 animate-pulse" />}
            {op.done && <span className="h-2 w-2 rounded-full bg-emerald-500" />}
            {op.err && <span className="h-2 w-2 rounded-full bg-red-500" />}
            {op.name}
          </div>
          <div className="mt-1.5 flex flex-col gap-0.5">
            {op.stages.map((s, i) => (
              <p key={i} className={`text-[11px] font-mono leading-tight ${s.done ? 'text-zinc-500' : op.err && i === op.stages.length - 1 ? 'text-red-400' : 'text-zinc-300'}`}>
                <span className="mr-1">{s.done ? '✓' : '▸'}</span>{s.msg}
              </p>
            ))}
          </div>
        </div>
      )}
      {focused && st.status === 'ready' && (
        <div className="absolute top-2 right-2 flex gap-1 opacity-70 hover:opacity-100">
          <button className="btn-ghost text-xs px-2 py-1" onClick={shareConsole}>Share</button>
          <button className="btn-ghost text-xs px-2 py-1" onClick={() => setPasteOpen(true)}>Paste</button>
          <button className="btn-ghost text-xs px-2 py-1" onClick={() => setMountOpen(true)}>Mount ISO</button>
          <button className="btn-ghost text-xs px-2 py-1" onClick={() => sendJson({ type: 'cad' })}>Ctrl+Alt+Del</button>
        </div>
      )}
      {mountOpen && (
        <Modal title="Mount virtual media" onClose={() => setMountOpen(false)}>
          <div className="space-y-3">
            <div>
              <label className="label">Image URL (http/https)</label>
              <input className="input w-full font-mono text-xs" value={mountUrl} onChange={(e) => setMountUrl(e.target.value)} placeholder="http://host/win11.iso — the BMC fetches it where it can" />
            </div>
            <div className="flex items-center gap-2">
              <input ref={fileRef} type="file" accept=".iso,.img" className="text-xs text-zinc-400" />
            </div>
            <div className="flex justify-end gap-2">
              <button className="btn-ghost" onClick={() => { sendJson({ type: 'unmount' }); setMountOpen(false); }}>Unmount</button>
              <button
                className="btn-ghost"
                disabled={!fileRef.current?.files?.[0]}
                onClick={async () => {
                  const f = fileRef.current.files[0];
                  const hostId = pane.target?.hostId;
                  const r = await fetch(`/api/hosts/${hostId}/media-upload?name=${encodeURIComponent(f.name)}`, { method: 'PUT', body: f, credentials: 'same-origin' });
                  const j = await r.json();
                  if (j.path) { sendJson({ type: 'mount', spec: j.path }); setMountOpen(false); }
                }}
              >
                Upload + mount
              </button>
              <button
                className="btn-primary"
                disabled={!mountUrl}
                onClick={() => { sendJson({ type: 'mount', spec: mountUrl }); setMountOpen(false); }}
              >
                Mount URL
              </button>
            </div>
          </div>
        </Modal>
      )}

      {pasteOpen && (
        <Modal title="Paste as keystrokes" onClose={() => setPasteOpen(false)}>
          <div className="space-y-3">
            <textarea className="input w-full h-28 font-mono text-xs" autoFocus value={pasteText} onChange={(e) => setPasteText(e.target.value)} placeholder="typed on the remote at ~25 cps" />
            <div className="flex justify-end gap-2">
              <button className="btn-ghost" onClick={() => setPasteOpen(false)}>Cancel</button>
              <button className="btn-primary" disabled={!pasteText} onClick={pasteKeys}>Type it</button>
            </div>
          </div>
        </Modal>
      )}

      {takeover && (
        <Modal title="Console access request" onClose={() => {}}>
          <div className="space-y-3">
            <p className="text-sm text-zinc-300">{takeover.question}</p>
            {takeover.addr && <p className="text-xs text-zinc-500 font-mono">from {takeover.addr}</p>}
            <p className="text-xs text-zinc-500">The BMC withdraws unanswered requests after ~30 seconds.</p>
            <div className="flex flex-wrap justify-end gap-2">
              {(takeover.answers || []).map((a) => (
                <button
                  key={a.answer}
                  className={a.answer === 'deny' ? 'btn-ghost' : 'btn-primary'}
                  onClick={() => { sendJson({ type: 'takeoverAnswer', answer: a.answer }); setTakeover(null); }}
                >
                  {a.label}
                </button>
              ))}
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
