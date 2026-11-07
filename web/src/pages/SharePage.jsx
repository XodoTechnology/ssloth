import React, { useEffect, useRef, useState } from 'react';
import { useParams } from 'react-router-dom';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import { WebglAddon } from '@xterm/addon-webgl';
import { CanvasAddon } from '@xterm/addon-canvas';
import '@xterm/xterm/css/xterm.css';
import { Terminal as TermIcon, Eye, MousePointer2, Clock, MonitorPlay } from 'lucide-react';
import { api } from '../api';
import { decodeFrame, paintFrame } from '../lib/kvm';

const encoder = new TextEncoder();

// Public, unauthenticated shared-session viewer. The URL token is the
// credential; the server enforces expiry, mode, and liveness.
export default function SharePage() {
  const { token } = useParams();
  const containerRef = useRef(null);
  const [meta, setMeta] = useState(null); // {label, mode, expires_at}
  const [error, setError] = useState('');
  const [closed, setClosed] = useState('');

  useEffect(() => {
    let term, ws, ro;
    api(`/api/public/share/${token}`)
      .then((m) => {
        setMeta(m);
        if (m.kind === 'kvm') return; // the canvas viewer owns its own socket
        term = new Terminal({
          cursorBlink: false,
          fontSize: 13,
          fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
          scrollback: 10000,
          disableStdin: m.mode !== 'control',
          theme: { background: '#0a0d10', foreground: '#d6dde5', cursor: '#34d399', selectionBackground: '#33455c' },
        });
        const fit = new FitAddon();
        term.loadAddon(fit);
        term.loadAddon(new WebLinksAddon());
        term.open(containerRef.current);
        try {
          const gl = new WebglAddon();
          gl.onContextLoss(() => {
            try { gl.dispose(); } catch {}
            try { term.loadAddon(new CanvasAddon()); } catch {}
          });
          term.loadAddon(gl);
        } catch {
          try { term.loadAddon(new CanvasAddon()); } catch {}
        }
        fit.fit();
        ro = new ResizeObserver(() => {
          try {
            fit.fit();
          } catch {}
        });
        ro.observe(containerRef.current);

        const proto = location.protocol === 'https:' ? 'wss' : 'ws';
        ws = new WebSocket(`${proto}://${location.host}/ws/share/${token}`);
        ws.binaryType = 'arraybuffer';
        ws.onmessage = (ev) => {
          if (typeof ev.data !== 'string') {
            term.write(new Uint8Array(ev.data));
            return;
          }
          let msg;
          try {
            msg = JSON.parse(ev.data);
          } catch {
            return;
          }
          if (msg.type === 'status' && (msg.state === 'closed' || msg.state === 'error')) {
            setClosed(msg.message || 'session closed');
          }
        };
        ws.onclose = () => setClosed((c) => c || 'session closed');

        if (m.mode === 'control') {
          term.onData((d) => {
            if (ws.readyState === WebSocket.OPEN) ws.send(encoder.encode(d));
          });
        }
        // highlight-to-copy for viewers too
        term.onSelectionChange(() => {
          const sel = term.getSelection();
          if (sel) navigator.clipboard?.writeText(sel).catch(() => {});
        });
      })
      .catch((e) => setError(e.message));

    return () => {
      try {
        ws?.close();
      } catch {}
      ro?.disconnect();
      term?.dispose();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  return (
    <div className="h-full flex flex-col bg-ink-950">
      <div className="flex items-center gap-3 px-4 h-12 border-b border-ink-700 bg-ink-900 shrink-0">
        <span className="text-emerald-400">
          {meta?.kind === 'kvm' ? <MonitorPlay size={18} /> : <TermIcon size={18} />}
        </span>
        <span className="font-bold text-zinc-100">ssloth</span>
        <span className="text-zinc-600 text-xs">{meta?.kind === 'kvm' ? 'shared console' : 'shared session'}</span>
        {meta && (
          <>
            <span className="text-sm text-zinc-300 font-mono truncate">{meta.label}</span>
            <span
              className={`text-[10px] font-semibold uppercase px-1.5 py-0.5 rounded ${
                meta.mode === 'control' ? 'bg-amber-950 text-amber-300' : 'bg-emerald-950 text-emerald-300'
              }`}
            >
              {meta.mode === 'control' ? (
                <>
                  <MousePointer2 size={10} className="inline -mt-0.5" /> interactive
                </>
              ) : (
                <>
                  <Eye size={10} className="inline -mt-0.5" /> view only
                </>
              )}
            </span>
            <span className="ml-auto text-[11px] text-zinc-500 flex items-center gap-1">
              <Clock size={11} /> expires {new Date(meta.expires_at).toLocaleTimeString()}
            </span>
          </>
        )}
      </div>

      {error ? (
        <div className="flex-1 flex items-center justify-center">
          <div className="card px-6 py-5 text-center">
            <p className="text-sm text-zinc-300">{error}</p>
            <p className="text-xs text-zinc-600 mt-1">ask the owner for a fresh link</p>
          </div>
        </div>
      ) : meta?.kind === 'kvm' ? (
        <KvmShareView token={token} />
      ) : (
        <div className="flex-1 relative min-h-0">
          <div ref={containerRef} className="absolute inset-0" />
          {closed && (
            <div className="absolute inset-0 bg-ink-950/80 flex items-center justify-center">
              <div className="card px-6 py-4 text-sm text-zinc-300">{closed}</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// Read-only BMC console for a kvm share link: same KVMF wire frames the
// owner's KvmPane decodes, painted to a canvas. No input path exists.
function KvmShareView({ token }) {
  const canvasRef = useRef(null);
  const wrapRef = useRef(null);
  const [state, setState] = useState({ status: 'connecting', msg: '' });

  useEffect(() => {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${proto}://${location.host}/ws/share/${token}`);
    ws.binaryType = 'arraybuffer';
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
          setState((s) => (s.status === 'ready' ? s : { status: 'ready', msg: '' }));
        } catch {}
        return;
      }
      let msg;
      try { msg = JSON.parse(ev.data); } catch { return; }
      if (msg.type === 'ready') setState({ status: 'ready', msg: '' });
      else if (msg.type === 'status') {
        setState({ status: msg.state === 'closed' || msg.state === 'error' ? msg.state : 'connecting', msg: msg.message || '' });
      }
    };
    ws.onclose = () => setState({ status: 'closed', msg: 'share ended' });
    return () => { try { ws.close(); } catch {} };
  }, [token]);

  // Keep the canvas centered at native res, scaled to fit — same letterbox
  // approach the owner pane uses via CSS.
  return (
    <div ref={wrapRef} className="flex-1 relative min-h-0 bg-black flex items-center justify-center overflow-hidden">
      <canvas ref={canvasRef} className="max-w-full max-h-full object-contain" style={{ imageRendering: 'pixelated' }} />
      {state.status !== 'ready' && (
        <div className="absolute inset-0 bg-ink-950/85 flex items-center justify-center">
          <div className="card px-6 py-4 text-sm text-zinc-300 flex items-center gap-2">
            {state.status === 'connecting' ? <MonitorPlay size={16} className="animate-pulse text-emerald-400" /> : null}
            {state.msg || (state.status === 'connecting' ? 'connecting to console…' : state.status)}
          </div>
        </div>
      )}
    </div>
  );
}
