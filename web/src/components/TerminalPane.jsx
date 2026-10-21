import React, { useEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import { SearchAddon } from '@xterm/addon-search';
import '@xterm/xterm/css/xterm.css';
import { ShieldAlert, KeyRound, CloudUpload } from 'lucide-react';
import { useStore } from '../store';
import { uploadToSession } from '../transfers';
import { termOptions } from '../termThemes';
import Modal from './Modal';

const encoder = new TextEncoder();

// One pane = one xterm + one SSH session. Reports its state upward via
// onPaneState(tabId, paneId, {status, sessionId, label, recording}).
export default function TerminalPane({ tab, pane, active, focused, onFocus, onPaneState }) {
  const containerRef = useRef(null);
  const termRef = useRef(null);
  const fitRef = useRef(null);
  const searchRef = useRef(null);
  const wsRef = useRef(null);
  const sessionRef = useRef(null);
  const reconnectSeq = useRef(0);

  const [hostkey, setHostkey] = useState(null);
  const [authPrompt, setAuthPrompt] = useState(null);
  const [password, setPassword] = useState('');
  const [fileDrag, setFileDrag] = useState(false);
  const stateRef = useRef({ status: 'idle' });
  const activeRef = useRef(active);

  const toast = useStore((s) => s.toast);
  const registerPane = useStore((s) => s.registerPane);
  const broadcastText = useStore((s) => s.broadcastText);
  const setTabBell = useStore((s) => s.setTabBell);

  useEffect(() => {
    activeRef.current = active;
  }, [active]);

  function setPaneState(patch) {
    stateRef.current = { ...stateRef.current, ...(typeof patch === 'function' ? patch(stateRef.current) : patch) };
    onPaneState(tab.id, pane.id, stateRef.current);
  }

  useEffect(() => {
    const term = new Terminal({
      cursorBlink: true,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
      scrollback: 10000,
      ...termOptions(),
      allowProposedApi: true,
    });
    const fit = new FitAddon();
    const links = new WebLinksAddon();
    const search = new SearchAddon();
    term.loadAddon(fit);
    term.loadAddon(links);
    term.loadAddon(search);
    term.open(containerRef.current);
    fit.fit();
    term.focus();

    termRef.current = term;
    fitRef.current = fit;
    searchRef.current = search;

    term.onData((d) => {
      const ws = wsRef.current;
      if (ws && ws.readyState === WebSocket.OPEN) ws.send(encoder.encode(d));
      broadcastText(`${tab.id}:${pane.id}`, d);
    });

    let selTimer = null;
    term.onSelectionChange(() => {
      // fires continuously during a drag-select — debounce the clipboard write
      clearTimeout(selTimer);
      selTimer = setTimeout(() => {
        const sel = term.getSelection();
        if (sel) navigator.clipboard?.writeText(sel).catch(() => {});
      }, 120);
    });

    term.onBell(() => {
      if (!activeRef.current || document.hidden) {
        setTabBell(tab.id);
        toast(`Terminal bell — ${tab.title}`, 'info');
      }
    });

    const onContextMenu = (e) => {
      e.preventDefault();
      navigator.clipboard
        ?.readText()
        .then((text) => {
          if (text) term.paste(text);
        })
        .catch(() => toast('clipboard read blocked — use Ctrl+V', 'info'));
    };
    containerRef.current.addEventListener('contextmenu', onContextMenu);

    registerPane(tab.id, pane.id, {
      send: (text) => {
        const ws = wsRef.current;
        if (ws && ws.readyState === WebSocket.OPEN) ws.send(encoder.encode(text));
      },
      sendJson: (obj) => {
        const ws = wsRef.current;
        if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
      },
      reconnect: () => connect(),
      search: (q, dir) => (dir === 'prev' ? search.findPrevious(q) : search.findNext(q)),
      getTerm: () => term,
    });

    const ro = new ResizeObserver(() => {
      try {
        fit.fit();
        const ws = wsRef.current;
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
        }
      } catch {}
    });
    ro.observe(containerRef.current);

    connect();

    return () => {
      ro.disconnect();
      containerRef.current?.removeEventListener('contextmenu', onContextMenu);
      try {
        wsRef.current?.close();
      } catch {}
      term.dispose();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab.id, pane.id]);

  // fit when this pane becomes visible/active or layout changes
  useEffect(() => {
    if (active) {
      try {
        fitRef.current?.fit();
      } catch {}
    }
  }, [active]);

  function connect() {
    const term = termRef.current;
    setPaneState({ status: 'connecting', sessionId: null });
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${proto}://${location.host}/ws/terminal`);
    ws.binaryType = 'arraybuffer';
    wsRef.current = ws;
    const seq = ++reconnectSeq.current;
    let pingTimer = null;

    ws.onopen = () => {
      const { cols, rows } = term || { cols: 80, rows: 24 };
      ws.send(JSON.stringify({ type: 'connect', ...pane.target, cols, rows }));
    };

    ws.onmessage = (ev) => {
      if (typeof ev.data !== 'string') {
        term?.write(new Uint8Array(ev.data));
        return;
      }
      let msg;
      try {
        msg = JSON.parse(ev.data);
      } catch {
        return;
      }
      switch (msg.type) {
        case 'status':
          setPaneState({ statusMsg: msg.message || '' });
          if (msg.state === 'error') setPaneState({ status: 'error' });
          else if (msg.state === 'closed') setPaneState({ status: 'closed' });
          else setPaneState({ status: msg.state });
          break;
        case 'hostkey':
          setPaneState({ statusMsg: `verifying host key for ${msg.hostname}` });
          setHostkey(msg);
          break;
        case 'auth_request':
          setPassword('');
          setAuthPrompt({ reason: msg.reason });
          break;
        case 'ready':
          sessionRef.current = msg.sessionId;
          setPaneState({ status: 'ready', sessionId: msg.sessionId, label: msg.label, statusMsg: '' });
          term?.focus();
          pingTimer = setInterval(() => {
            if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'ping', t: Date.now() }));
          }, 4000);
          break;
        case 'pong':
          setPaneState({ rtt: Date.now() - msg.t });
          break;
        case 'recording':
          setPaneState({ recording: msg.on });
          break;
      }
    };

    ws.onclose = () => {
      clearInterval(pingTimer);
      if (reconnectSeq.current !== seq) return;
      setPaneState({
        status: stateRef.current.status === 'error' ? 'error' : 'closed',
        sessionId: null,
        recording: false,
      });
      sessionRef.current = null;
    };
    ws.onerror = () => setPaneState({ statusMsg: 'websocket error' });
  }

  const sendJson = (obj) => {
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
  };

  return (
    <div
      className="relative flex-1 min-w-0 min-h-0 w-full h-full"
      onMouseDown={onFocus}
      style={focused ? { boxShadow: 'inset 0 0 0 1px rgba(52,211,153,0.35)' } : undefined}
      onDragOver={(e) => {
        if (e.dataTransfer?.types?.includes('Files')) {
          e.preventDefault();
          setFileDrag(true);
        }
      }}
      onDragLeave={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget)) setFileDrag(false);
      }}
      onDrop={(e) => {
        e.preventDefault();
        setFileDrag(false);
        const files = e.dataTransfer?.files;
        const sid = sessionRef.current;
        if (files?.length && sid) {
          const st = useStore.getState();
          const dir = st.sftpPaths[sid] || '.';
          uploadToSession(sid, dir, [...files], tab.title);
        } else if (files?.length) {
          toast('no session yet — connect first', 'info');
        }
      }}
    >
      <div ref={containerRef} className="absolute inset-0" />

      {fileDrag && (
        <div className="pointer-events-none absolute inset-0 z-20 flex flex-col items-center justify-center gap-2 border-2 border-dashed border-emerald-500 bg-emerald-950/70">
          <CloudUpload size={28} className="text-emerald-400" />
          <span className="text-sm text-emerald-300">drop to upload via SFTP</span>
        </div>
      )}

      {hostkey && (
        <Modal
          title={`Verify host key${hostkey.hop === 'jump' ? ' (bastion hop)' : ''}`}
          onClose={() => {
            sendJson({ type: 'trust', accept: 'reject' });
            setHostkey(null);
          }}
        >
          <div className="space-y-3">
            <div className="flex items-start gap-2 text-amber-300 text-sm">
              <ShieldAlert size={18} className="shrink-0 mt-0.5" />
              <p>
                First time connecting to{' '}
                <span className="font-mono">
                  {hostkey.hostname}:{hostkey.port}
                </span>
                {hostkey.hop === 'jump' && ' (bastion)'}. Verify this fingerprint before trusting.
              </p>
            </div>
            <div className="rounded-md bg-ink-900 border border-ink-700 p-3 font-mono text-xs space-y-1">
              <div className="text-zinc-500">{hostkey.algorithm || 'ssh key'}</div>
              <div className="text-emerald-300 break-all">{hostkey.fingerprint}</div>
            </div>
            <div className="flex justify-end gap-2">
              <button
                className="btn-ghost"
                onClick={() => {
                  sendJson({ type: 'trust', accept: 'reject' });
                  setHostkey(null);
                }}
              >
                Reject
              </button>
              <button
                className="btn-ghost border border-ink-600"
                onClick={() => {
                  sendJson({ type: 'trust', accept: 'once' });
                  setHostkey(null);
                }}
              >
                Trust once
              </button>
              <button
                className="btn-primary"
                onClick={() => {
                  sendJson({ type: 'trust', accept: 'always' });
                  setHostkey(null);
                }}
              >
                Trust always
              </button>
            </div>
          </div>
        </Modal>
      )}

      {authPrompt && (
        <Modal
          title="Authentication"
          onClose={() => {
            setAuthPrompt(null);
            wsRef.current?.close();
          }}
        >
          <form
            onSubmit={(e) => {
              e.preventDefault();
              sendJson({ type: 'auth', password });
              setAuthPrompt(null);
              setPassword('');
            }}
            className="space-y-3"
          >
            <div className="flex items-start gap-2 text-sm text-zinc-300">
              <KeyRound size={16} className="shrink-0 mt-0.5 text-emerald-400" />
              <p>{authPrompt.reason}</p>
            </div>
            <input
              className="input"
              type="password"
              autoFocus
              autoComplete="off"
              placeholder="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <p className="text-[11px] text-zinc-500">sent over this encrypted session — never stored</p>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                className="btn-ghost"
                onClick={() => {
                  setAuthPrompt(null);
                  wsRef.current?.close();
                }}
              >
                Cancel
              </button>
              <button className="btn-primary" disabled={!password}>
                Authenticate
              </button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
}
