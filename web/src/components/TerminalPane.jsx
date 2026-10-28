import React, { useEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import { SearchAddon } from '@xterm/addon-search';
import { WebglAddon } from '@xterm/addon-webgl';
import { CanvasAddon } from '@xterm/addon-canvas';
import '@xterm/xterm/css/xterm.css';
import { ShieldAlert, KeyRound, CloudUpload, ClipboardPaste } from 'lucide-react';
import { useStore } from '../store';
import { uploadToSession } from '../transfers';
import { termOptions } from '../termThemes';
import Modal from './Modal';

const encoder = new TextEncoder();
const PASTE_GUARD_LINES = 4; // pastes with more lines than this get a confirm

// One pane = one xterm + one SSH session. Sessions are persistent server-
// side: unmounting detaches (processes keep running), remounting reattaches
// via the stored sessionId + scrollback replay. Unexpected socket drops
// auto-reconnect with backoff.
export default function TerminalPane({ tab, pane, active, focused, onFocus, onPaneState }) {
  const containerRef = useRef(null);
  const termRef = useRef(null);
  const fitRef = useRef(null);
  const searchRef = useRef(null);
  const wsRef = useRef(null);
  const sessionRef = useRef(null);
  const reconnectSeq = useRef(0);
  const mountedRef = useRef(true);
  const intentionalRef = useRef(false);
  const fatalRef = useRef(false); // user-action-required failure — don't auto-retry
  const retryRef = useRef({ attempt: 0, timer: null });
  const reattachRef = useRef(false);

  const [hostkey, setHostkey] = useState(null);
  const [authPrompt, setAuthPrompt] = useState(null);
  const [password, setPassword] = useState('');
  const [authCred, setAuthCred] = useState('');
  const [fileDrag, setFileDrag] = useState(false);
  const [pasteConfirm, setPasteConfirm] = useState(null); // {text, lines, preview}
  const stateRef = useRef({ status: 'idle' });
  const activeRef = useRef(active);

  const toast = useStore((s) => s.toast);
  const registerPane = useStore((s) => s.registerPane);
  const broadcastText = useStore((s) => s.broadcastText);
  const setTabBell = useStore((s) => s.setTabBell);
  const credentials = useStore((s) => s.credentials);
  const keyCreds = credentials.filter((c) => c.type === 'key' || c.type === 'password');

  useEffect(() => {
    activeRef.current = active;
  }, [active]);

  function setPaneState(patch) {
    stateRef.current = { ...stateRef.current, ...(typeof patch === 'function' ? patch(stateRef.current) : patch) };
    onPaneState(tab.id, pane.id, stateRef.current);
  }

  // Multi-line pastes get a confirmation — protects against clipboard-hijack
  // payloads and accidental dumps of shell scripts into prod.
  function guardedPaste(text) {
    if (!text) return;
    const lines = text.split('\n').length;
    if (lines <= PASTE_GUARD_LINES) {
      termRef.current?.paste(text);
      return;
    }
    setPasteConfirm({
      text,
      lines,
      preview: text.split('\n').slice(0, 6).join('\n'),
    });
  }

  useEffect(() => {
    mountedRef.current = true;
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
    // The DOM renderer tears badly under heavy-redraw TUIs (btop, htop,
    // lazygit). WebGL fixes it; canvas is the fallback for no-GPU webviews.
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
        .then((text) => guardedPaste(text))
        .catch(() => toast('clipboard read blocked — use Ctrl+V', 'info'));
    };
    // Route ALL pastes (Ctrl+V, browser menu) through the guard. Capture phase
    // runs before xterm's own paste handler on its hidden textarea.
    const onPasteCapture = (e) => {
      e.preventDefault();
      e.stopPropagation();
      const text = e.clipboardData?.getData('text/plain') || e.clipboardData?.getData('text');
      guardedPaste(text);
    };
    containerRef.current.addEventListener('contextmenu', onContextMenu);
    containerRef.current.addEventListener('paste', onPasteCapture, true);

    registerPane(tab.id, pane.id, {
      send: (text) => {
        const ws = wsRef.current;
        if (ws && ws.readyState === WebSocket.OPEN) ws.send(encoder.encode(text));
      },
      sendJson: (obj) => {
        const ws = wsRef.current;
        if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
      },
      reconnect: () => {
        intentionalRef.current = false;
        fatalRef.current = false;
        sessionRef.current = null; // fresh dial — old session may be dead
        clearTimeout(retryRef.current.timer);
        try { wsRef.current?.close(); } catch {}
        open();
      },
      closeSession: () => {
        // explicit kill — session dies server-side, no reattach
        intentionalRef.current = true;
        clearTimeout(retryRef.current.timer);
        const ws = wsRef.current;
        if (ws && ws.readyState === WebSocket.OPEN) {
          try { ws.send(JSON.stringify({ type: 'close' })); } catch {}
        }
        try { ws?.close(); } catch {}
      },
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

    // Restore a detached session if this pane had one before unmount.
    const prior = useStore.getState().paneStates[`${tab.id}:${pane.id}`];
    if (prior?.sessionId) {
      sessionRef.current = prior.sessionId;
      reattachRef.current = true;
    }
    open();

    return () => {
      mountedRef.current = false;
      clearTimeout(retryRef.current.timer);
      ro.disconnect();
      containerRef.current?.removeEventListener('contextmenu', onContextMenu);
      containerRef.current?.removeEventListener('paste', onPasteCapture, true);
      try {
        wsRef.current?.close(); // detaches the session — it keeps running
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

  function scheduleRetry() {
    const r = retryRef.current;
    r.attempt = Math.min(r.attempt + 1, 12);
    const delay = Math.min(1000 * r.attempt, 15000);
    setPaneState({
      status: 'connecting',
      statusMsg: `connection lost — reconnecting in ${Math.ceil(delay / 1000)}s`,
      sessionId: sessionRef.current,
    });
    r.timer = setTimeout(() => {
      if (mountedRef.current) open();
    }, delay);
  }

  function open() {
    const term = termRef.current;
    setPaneState({ status: 'connecting', statusMsg: sessionRef.current ? 'reattaching…' : 'connecting…' });
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    // Telnet hosts get the raw-TCP bridge — different backend, same terminal.
    const targetHost = pane.target?.hostId
      ? useStore.getState().hosts.find((h) => h.id === pane.target.hostId)
      : null;
    const wsPath = targetHost?.protocol === 'telnet' ? '/ws/telnet' : '/ws/terminal';
    const ws = new WebSocket(`${proto}://${location.host}${wsPath}`);
    ws.binaryType = 'arraybuffer';
    wsRef.current = ws;
    const seq = ++reconnectSeq.current;
    let pingTimer = null;
    intentionalRef.current = false;

    ws.onopen = () => {
      const { cols, rows } = term || { cols: 80, rows: 24 };
      if (sessionRef.current) {
        ws.send(JSON.stringify({ type: 'reattach', sessionId: sessionRef.current, cols, rows }));
      } else {
        ws.send(JSON.stringify({ type: 'connect', ...pane.target, cols, rows }));
      }
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
          if (msg.state === 'error') {
            sessionRef.current = null;
            setPaneState({ status: 'error', sessionId: null });
          } else if (msg.state === 'closed') {
            setPaneState({ status: 'closed' });
          } else if (msg.state === 'gone') {
            // reattach missed — session died server-side; fall back to a
            // fresh connect on the same socket.
            sessionRef.current = null;
            reattachRef.current = false;
            const { cols, rows } = term || { cols: 80, rows: 24 };
            ws.send(JSON.stringify({ type: 'connect', ...pane.target, cols, rows }));
          } else setPaneState({ status: msg.state });
          break;
        case 'hostkey':
          setPaneState({ statusMsg: `verifying host key for ${msg.hostname}` });
          setHostkey(msg);
          break;
        case 'hostkey_mismatch':
          // changed server key — surface as a hard stop, never auto-retry
          fatalRef.current = true;
          sessionRef.current = null;
          reattachRef.current = false;
          setPaneState({ status: 'error', statusMsg: msg.message || 'HOST KEY CHANGED', sessionId: null, mismatch: msg });
          break;
        case 'auth_request':
          setPassword('');
          setAuthPrompt({ reason: msg.reason });
          break;
        case 'ready':
          sessionRef.current = msg.sessionId;
          retryRef.current.attempt = 0;
          setPaneState({
            status: 'ready',
            sessionId: msg.sessionId,
            label: msg.label,
            statusMsg: msg.reattached ? 'session restored' : '',
          });
          term?.focus();
          clearInterval(pingTimer);
          pingTimer = setInterval(() => {
            if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'ping', t: Date.now() }));
          }, 4000);
          // a playbook queued from the Playbooks page fires once we're ready
          {
            const st = useStore.getState();
            const pbId = st.pendingPlaybooks[tab.id];
            if (pbId) {
              st.clearPendingPlaybook(tab.id);
              ws.send(JSON.stringify({ type: 'playbook', playbookId: pbId }));
            }
          }
          break;
        case 'pong':
          setPaneState({ rtt: Date.now() - msg.t });
          break;
        case 'recording':
          setPaneState({ recording: msg.on });
          break;
        case 'health':
          setPaneState({ health: { load: msg.load, memPct: msg.memPct, diskPct: msg.diskPct } });
          break;
        case 'playbook_step':
          setPaneState({ playbook: { index: msg.index, total: msg.total, status: msg.status, command: msg.command } });
          break;
        case 'playbook_done':
          setPaneState({ playbook: null });
          toast(msg.aborted ? 'playbook stopped' : msg.ok ? 'playbook finished' : 'playbook failed', msg.ok ? 'success' : 'error');
          break;
      }
    };

    ws.onclose = () => {
      clearInterval(pingTimer);
      if (reconnectSeq.current !== seq) return;
      if (fatalRef.current) {
        // mismatch/fatal — stay on the error, don't loop connect attempts
        setPaneState({ status: 'error', sessionId: null, recording: false });
        return;
      }
      if (!mountedRef.current || intentionalRef.current) {
        setPaneState({
          status: stateRef.current.status === 'error' ? 'error' : 'closed',
          sessionId: sessionRef.current,
          recording: false,
        });
        return;
      }
      // unexpected drop — the session likely still lives server-side
      scheduleRetry();
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
            {keyCreds.length > 0 && (
              <div className="border-t border-ink-700 pt-3 space-y-2">
                <label className="label">or use a saved credential</label>
                <div className="flex gap-2">
                  <select
                    className="input flex-1"
                    value={authCred}
                    onChange={(e) => setAuthCred(e.target.value)}
                  >
                    <option value="">choose a key or password credential…</option>
                    {keyCreds.map((c) => (
                      <option key={c.id} value={c.id}>
                        {c.type === 'key' ? '🔑' : '🔒'} {c.name}
                        {c.username ? ` (${c.username})` : ''}
                      </option>
                    ))}
                  </select>
                  <button
                    type="button"
                    className="btn-ghost border border-emerald-800 text-emerald-300 whitespace-nowrap"
                    disabled={!authCred}
                    onClick={() => {
                      sendJson({ type: 'auth', credentialId: parseInt(authCred, 10) });
                      setAuthPrompt(null);
                      setAuthCred('');
                    }}
                  >
                    Use this
                  </button>
                </div>
              </div>
            )}
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

      {pasteConfirm && (
        <Modal title="Confirm paste" onClose={() => setPasteConfirm(null)}>
          <div className="space-y-3">
            <div className="flex items-start gap-2 text-amber-300 text-sm">
              <ClipboardPaste size={18} className="shrink-0 mt-0.5" />
              <p>
                You're about to paste <span className="font-semibold">{pasteConfirm.lines} lines</span> into the
                terminal — they'll execute as typed.
              </p>
            </div>
            <pre className="rounded-md bg-ink-900 border border-ink-700 p-3 font-mono text-xs text-zinc-400 max-h-40 overflow-auto whitespace-pre-wrap">
              {pasteConfirm.preview}
              {pasteConfirm.lines > 6 ? '\n…' : ''}
            </pre>
            <div className="flex justify-end gap-2">
              <button className="btn-ghost" onClick={() => setPasteConfirm(null)}>
                Cancel
              </button>
              <button
                className="btn-primary"
                onClick={() => {
                  termRef.current?.paste(pasteConfirm.text);
                  setPasteConfirm(null);
                }}
              >
                Paste {pasteConfirm.lines} lines
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
