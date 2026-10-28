import React, { useEffect, useRef, useState } from 'react';
import { decodeFrame, paintFrame, hidFor, usKey } from '../lib/kvm';
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
    const onBlur = () => {
      heldRef.current.clear();
      if (wsRef.current?.readyState === 1) wsRef.current.send(JSON.stringify({ type: 'releaseAll' }));
    };
    window.addEventListener('blur', onBlur);
    return () => {
      mountedRef.current = false;
      window.removeEventListener('blur', onBlur);
      clearTimeout(retryRef.current.timer);
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
          setPaneState({ status: 'ready', sessionId: msg.sessionId, statusMsg: msg.reattached ? 'session restored' : `${msg.title} (${msg.family})` });
          break;
        case 'status':
          setPaneState({ statusMsg: msg.message || '' });
          if (msg.state === 'error') { sessionRef.current = null; setPaneState({ status: 'error', sessionId: null }); }
          else if (msg.state === 'closed') setPaneState({ status: 'closed' });
          else if (msg.state === 'connecting') setPaneState({ status: 'connecting' });
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

  const onKey = (e, down) => {
    const u = hidFor(e.code);
    if (u === null) return;
    if (down && e.repeat && heldRef.current.has(u)) { sendJson({ type: 'key', usage: u, down: true, repeat: true }); e.preventDefault(); return; }
    if (down) { if (heldRef.current.has(u)) return; heldRef.current.add(u); }
    else if (!heldRef.current.delete(u)) return;
    sendJson({ type: 'key', usage: u, down, repeat: e.repeat });
    e.preventDefault();
  };

  const pointer = (e, buttons, wheel = 0) => {
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
        onMouseMove={(e) => pointer(e, e.buttons)}
        onMouseDown={(e) => pointer(e, e.buttons | (1 << e.button === 1 ? 0 : e.button))}
        onMouseUp={(e) => pointer(e, e.buttons)}
        onWheel={(e) => pointer(e, e.buttons, e.deltaY < 0 ? 1 : -1)}
        onContextMenu={(e) => e.preventDefault()}
      />
      {st.status !== 'ready' && (
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 bg-ink-950/90 text-zinc-400">
          <p className="text-sm">{st.status === 'error' ? 'connection failed' : st.status === 'closed' ? 'console closed' : 'connecting…'}</p>
          {st.statusMsg && <p className="text-xs text-zinc-600 max-w-md text-center">{st.statusMsg}</p>}
          {(st.status === 'error' || st.status === 'closed') && (
            <button className="btn-primary mt-2" onClick={() => { intentionalRef.current = false; open(); }}>Reconnect</button>
          )}
        </div>
      )}
      {focused && st.status === 'ready' && (
        <div className="absolute top-2 right-2 flex gap-1 opacity-70 hover:opacity-100">
          <button className="btn-ghost text-xs px-2 py-1" onClick={() => setPasteOpen(true)}>Paste</button>
          <button className="btn-ghost text-xs px-2 py-1" onClick={() => sendJson({ type: 'cad' })}>Ctrl+Alt+Del</button>
        </div>
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
    </div>
  );
}
