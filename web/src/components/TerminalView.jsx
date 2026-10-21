import React, { useEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import { SearchAddon } from '@xterm/addon-search';
import '@xterm/xterm/css/xterm.css';
import {
  FolderOpen,
  RefreshCw,
  X,
  Zap,
  ShieldAlert,
  KeyRound,
  Search,
  Share2,
  Copy,
  Trash2,
} from 'lucide-react';
import { api } from '../api';
import { useStore } from '../store';
import Modal from './Modal';
import SftpPanel from './SftpPanel';

const encoder = new TextEncoder();

function ShareModal({ sessionId, label, onClose }) {
  const [mode, setMode] = useState('view');
  const [ttl, setTtl] = useState(60);
  const [shares, setShares] = useState([]);
  const [freshUrl, setFreshUrl] = useState('');
  const [busy, setBusy] = useState(false);
  const { toast } = useStore();

  const load = () =>
    api('/api/shares')
      .then((r) => setShares(r.shares.filter((s) => s.session_id === sessionId && s.expires_at > Date.now())))
      .catch((e) => toast(e.message, 'error'));

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const create = async () => {
    setBusy(true);
    try {
      const r = await api('/api/shares', {
        method: 'POST',
        body: { session_id: sessionId, mode, ttl_minutes: ttl },
      });
      const full = `${location.origin}${r.share.url}`;
      setFreshUrl(full);
      try {
        await navigator.clipboard.writeText(full);
        toast('share link copied to clipboard', 'success');
      } catch {
        toast('link created', 'success');
      }
      await load();
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (id) => {
    await api(`/api/shares/${id}`, { method: 'DELETE' });
    load();
  };

  return (
    <Modal title={`Share session — ${label}`} onClose={onClose}>
      <div className="space-y-4">
        <p className="text-xs text-zinc-400">
          Generates a one-off link anyone can open — no login. <span className="text-emerald-300">View only</span> lets
          them watch; <span className="text-amber-300">interactive</span> lets them type into your session. Links expire
          automatically and die when you close the tab.
        </p>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="label">Access</label>
            <select className="input" value={mode} onChange={(e) => setMode(e.target.value)}>
              <option value="view">View only (read)</option>
              <option value="control">Interactive (can type)</option>
            </select>
          </div>
          <div>
            <label className="label">Expires in</label>
            <select className="input" value={ttl} onChange={(e) => setTtl(parseInt(e.target.value, 10))}>
              <option value={15}>15 minutes</option>
              <option value={60}>1 hour</option>
              <option value={480}>8 hours</option>
              <option value={1440}>24 hours</option>
            </select>
          </div>
        </div>
        <button className="btn-primary w-full justify-center" onClick={create} disabled={busy}>
          {busy ? '…' : 'Generate ephemeral link'}
        </button>

        {freshUrl && (
          <div className="rounded-md border border-emerald-800 bg-emerald-950/40 p-2.5 space-y-1.5">
            <div className="text-[11px] text-emerald-300 font-medium">link created — shown once, copy it now</div>
            <div className="flex gap-2">
              <input className="input font-mono !text-[11px] flex-1" readOnly value={freshUrl} onFocus={(e) => e.target.select()} />
              <button
                className="btn-ghost border border-ink-600 !px-2"
                onClick={async () => {
                  try {
                    await navigator.clipboard.writeText(freshUrl);
                    toast('copied', 'success');
                  } catch {}
                }}
              >
                <Copy size={13} />
              </button>
            </div>
          </div>
        )}

        {shares.length > 0 && (
          <div className="space-y-1.5">
            <div className="label !mb-0">Active links for this session</div>
            {shares.map((s) => (
              <div key={s.id} className="flex items-center gap-2 rounded-md border border-ink-700 bg-ink-900 px-2.5 py-1.5">
                <span
                  className={`text-[10px] font-semibold uppercase px-1.5 py-0.5 rounded ${
                    s.mode === 'control' ? 'bg-amber-950 text-amber-300' : 'bg-emerald-950 text-emerald-300'
                  }`}
                >
                  {s.mode === 'control' ? 'interactive' : 'view'}
                </span>
                <span className="text-[11px] text-zinc-500">
                  expires {new Date(s.expires_at).toLocaleTimeString()}
                </span>
                <span className="flex-1" />
                <button className="p-1 text-zinc-500 hover:text-red-400" title="Revoke" onClick={() => revoke(s.id)}>
                  <Trash2 size={13} />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </Modal>
  );
}

export default function TerminalView({ tab, active }) {
  const containerRef = useRef(null);
  const termRef = useRef(null);
  const fitRef = useRef(null);
  const searchRef = useRef(null);
  const wsRef = useRef(null);
  const sessionRef = useRef(null);

  const [status, setStatus] = useState('idle'); // idle|connecting|ready|closed|error
  const [statusMsg, setStatusMsg] = useState('');
  const [hostkey, setHostkey] = useState(null);
  const [authPrompt, setAuthPrompt] = useState(null);
  const [password, setPassword] = useState('');
  const [showSftp, setShowSftp] = useState(false);
  const [showSnippets, setShowSnippets] = useState(false);
  const [showSearch, setShowSearch] = useState(false);
  const [searchQ, setSearchQ] = useState('');
  const [varPrompt, setVarPrompt] = useState(null); // {snippet, vars:[names]}
  const [varValues, setVarValues] = useState({});
  const [showShare, setShowShare] = useState(false);

  const { snippets, closeTab, setTabStatus, setTabSession, registerTerminal, toast } = useStore();

  // ---- xterm init (once per tab) ----
  useEffect(() => {
    const term = new Terminal({
      cursorBlink: true,
      fontSize: 13,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
      scrollback: 10000,
      theme: {
        background: '#0a0d10',
        foreground: '#d6dde5',
        cursor: '#34d399',
        cursorAccent: '#0a0d10',
        selectionBackground: '#33455c',
        black: '#0a0d10',
        brightBlack: '#33455c',
      },
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
    });

    // Highlight-to-copy, like a desktop SSH client.
    term.onSelectionChange(() => {
      const sel = term.getSelection();
      if (sel) navigator.clipboard?.writeText(sel).catch(() => {});
    });

    // Right-click pastes into the shell (xterm applies bracketed-paste so a
    // pasted multi-line blob can't auto-execute without your Enter).
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

    registerTerminal(tab.id, {
      send: (text) => {
        const ws = wsRef.current;
        if (ws && ws.readyState === WebSocket.OPEN) ws.send(encoder.encode(text));
      },
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
      try { wsRef.current?.close(); } catch {}
      term.dispose();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab.id]);

  useEffect(() => {
    if (active) {
      try {
        fitRef.current?.fit();
        termRef.current?.focus();
      } catch {}
    }
  }, [active]);

  // ---- ws lifecycle ----
  function connect() {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${proto}://${location.host}/ws/terminal`);
    ws.binaryType = 'arraybuffer';
    wsRef.current = ws;
    setStatus('connecting');
    setStatusMsg('connecting…');
    setTabStatus(tab.id, 'connecting');

    ws.onopen = () => {
      const { cols, rows } = termRef.current || { cols: 80, rows: 24 };
      ws.send(JSON.stringify({ type: 'connect', ...tab.target, cols, rows }));
    };

    ws.onmessage = (ev) => {
      if (typeof ev.data !== 'string') {
        termRef.current?.write(new Uint8Array(ev.data));
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
          setStatusMsg(msg.message || '');
          if (msg.state === 'error') {
            setStatus('error');
            setTabStatus(tab.id, 'error');
          } else if (msg.state === 'closed') {
            setStatus('closed');
            setTabStatus(tab.id, 'closed');
          } else {
            setStatus(msg.state);
          }
          break;
        case 'hostkey':
          setStatusMsg(`verifying host key for ${msg.hostname}`);
          setHostkey(msg);
          break;
        case 'auth_request':
          setPassword('');
          setAuthPrompt({ reason: msg.reason });
          break;
        case 'ready':
          setStatus('ready');
          setStatusMsg(msg.label);
          setTabStatus(tab.id, 'ready');
          setTabSession(tab.id, msg.sessionId);
          sessionRef.current = msg.sessionId;
          termRef.current?.focus();
          break;
        case 'hello':
          break;
      }
    };

    ws.onclose = () => {
      setStatus((s) => (s === 'error' ? s : 'closed'));
      setTabStatus(tab.id, 'closed');
      sessionRef.current = null;
    };

    ws.onerror = () => {
      setStatusMsg('websocket error');
    };
  }

  const sendJson = (obj) => wsRef.current?.readyState === WebSocket.OPEN && wsRef.current.send(JSON.stringify(obj));

  const trust = (accept) => {
    sendJson({ type: 'trust', accept });
    setHostkey(null);
  };

  const submitPassword = (e) => {
    e.preventDefault();
    sendJson({ type: 'auth', password });
    setAuthPrompt(null);
    setPassword('');
  };

  const runSnippet = (snip, execute) => {
    setShowSnippets(false);
    const vars = [...snip.command.matchAll(/\{\{\s*([\w.-]+)\s*\}\}/g)].map((m) => m[1]);
    const unique = [...new Set(vars)];
    if (unique.length) {
      setVarValues({});
      setVarPrompt({ snippet: snip, vars: unique, execute });
      return;
    }
    sendSnippet(snip.command, execute);
  };

  const sendSnippet = (command, execute) => {
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) return toast('session not connected', 'error');
    ws.send(encoder.encode(command + (execute ? '\n' : '')));
    termRef.current?.focus();
  };

  const submitVars = (e) => {
    e.preventDefault();
    let cmd = varPrompt.snippet.command;
    for (const [k, v] of Object.entries(varValues)) {
      cmd = cmd.replaceAll(new RegExp(`\\{\\{\\s*${k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*\\}\\}`, 'g'), v);
    }
    sendSnippet(cmd, varPrompt.execute);
    setVarPrompt(null);
  };

  const sessionId = tab.sessionId;

  return (
    <div className={`absolute inset-0 flex flex-col ${active ? '' : 'invisible pointer-events-none'}`}>
      {/* toolbar */}
      <div className="flex items-center gap-1 px-2 h-9 border-b border-ink-800 bg-ink-900/40 shrink-0">
        <span
          className={`h-1.5 w-1.5 rounded-full ml-1 ${
            status === 'ready' ? 'bg-emerald-500' : status === 'error' ? 'bg-red-500' : status === 'connecting' ? 'bg-amber-500 animate-pulse' : 'bg-zinc-600'
          }`}
        />
        <span className="text-xs text-zinc-400 truncate max-w-[40%]">{statusMsg || tab.title}</span>
        <div className="flex-1" />
        <div className="relative">
          <button
            className="btn-ghost !py-1 !px-2 text-xs"
            onClick={() => setShowSnippets((v) => !v)}
            disabled={status !== 'ready'}
            title="Snippets"
          >
            <Zap size={14} /> <span className="hidden sm:inline">Snippets</span>
          </button>
          {showSnippets && (
            <div className="absolute right-0 top-8 z-30 w-80 card shadow-xl max-h-80 overflow-y-auto">
              {snippets.length === 0 && (
                <div className="p-3 text-xs text-zinc-500">no snippets yet — add them in the Snippets page</div>
              )}
              {snippets.map((s) => (
                <div key={s.id} className="flex items-center gap-1 px-2 py-1.5 hover:bg-ink-800 group">
                  <div className="min-w-0 flex-1">
                    <div className="text-xs text-zinc-200 truncate">{s.name}</div>
                    <div className="text-[10px] font-mono text-zinc-500 truncate">{s.command}</div>
                  </div>
                  <button className="btn-ghost !px-1.5 !py-0.5 text-[11px]" onClick={() => runSnippet(s, false)} title="Insert">
                    insert
                  </button>
                  <button className="btn-primary !px-1.5 !py-0.5 text-[11px]" onClick={() => runSnippet(s, true)} title="Run">
                    run
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
        <button
          className="btn-ghost !py-1 !px-2 text-xs"
          onClick={() => setShowSearch((v) => !v)}
          title="Search scrollback"
        >
          <Search size={14} />
        </button>
        <button
          className={`btn-ghost !py-1 !px-2 text-xs ${showSftp ? 'text-emerald-400' : ''}`}
          onClick={() => setShowSftp((v) => !v)}
          disabled={status !== 'ready'}
          title="Files (SFTP)"
        >
          <FolderOpen size={14} /> <span className="hidden sm:inline">Files</span>
        </button>
        <button
          className="btn-ghost !py-1 !px-2 text-xs"
          onClick={() => setShowShare(true)}
          disabled={status !== 'ready'}
          title="Share session"
        >
          <Share2 size={14} /> <span className="hidden sm:inline">Share</span>
        </button>
        <button className="btn-ghost !py-1 !px-2 text-xs" onClick={connect} title="Reconnect">
          <RefreshCw size={14} />
        </button>
        <button className="btn-ghost !py-1 !px-2 text-xs hover:text-red-400" onClick={() => closeTab(tab.id)} title="Close">
          <X size={14} />
        </button>
      </div>

      {showSearch && (
        <div className="flex items-center gap-1 px-2 py-1 border-b border-ink-800 bg-ink-900/40 shrink-0">
          <input
            className="input !py-0.5 !w-64 text-xs font-mono"
            placeholder="search scrollback…"
            value={searchQ}
            autoFocus
            onChange={(e) => {
              setSearchQ(e.target.value);
              searchRef.current?.findNext(e.target.value, { incremental: true });
            }}
            onKeyDown={(e) => {
              if (e.key === 'Enter') searchRef.current?.findNext(searchQ);
              if (e.key === 'Escape') setShowSearch(false);
            }}
          />
          <button className="btn-ghost !px-2 !py-0.5 text-xs" onClick={() => searchRef.current?.findNext(searchQ)}>
            next
          </button>
          <button className="btn-ghost !px-2 !py-0.5 text-xs" onClick={() => searchRef.current?.findPrevious(searchQ)}>
            prev
          </button>
        </div>
      )}

      {/* terminal + sftp */}
      <div className="flex-1 flex min-h-0">
        <div ref={containerRef} className="flex-1 min-w-0" onClick={() => setShowSnippets(false)} />
        {showSftp && status === 'ready' && sessionId && (
          <SftpPanel sessionId={sessionId} label={statusMsg} />
        )}
      </div>

      {/* status bar */}
      <div className="flex items-center gap-3 px-3 h-6 border-t border-ink-800 bg-ink-900/40 text-[11px] text-zinc-500 shrink-0">
        <span className="truncate">{tab.title}</span>
        <span className="ml-auto">{status === 'ready' ? 'ssh channel open' : status}</span>
      </div>

      {/* host key trust modal */}
      {hostkey && (
        <Modal title="Verify host key" onClose={() => trust('reject')}>
          <div className="space-y-3">
            <div className="flex items-start gap-2 text-amber-300 text-sm">
              <ShieldAlert size={18} className="shrink-0 mt-0.5" />
              <p>
                First time connecting to <span className="font-mono">{hostkey.hostname}:{hostkey.port}</span>. Verify
                this fingerprint against the server's{' '}
                <span className="font-mono">ssh-keygen -lf</span> output before trusting.
              </p>
            </div>
            <div className="rounded-md bg-ink-900 border border-ink-700 p-3 font-mono text-xs space-y-1">
              <div className="text-zinc-500">{hostkey.algorithm || 'ssh key'}</div>
              <div className="text-emerald-300 break-all">{hostkey.fingerprint}</div>
            </div>
            <div className="flex justify-end gap-2">
              <button className="btn-ghost" onClick={() => trust('reject')}>
                Reject
              </button>
              <button className="btn-ghost border border-ink-600" onClick={() => trust('once')}>
                Trust once
              </button>
              <button className="btn-primary" onClick={() => trust('always')}>
                Trust always
              </button>
            </div>
          </div>
        </Modal>
      )}

      {/* password prompt modal */}
      {authPrompt && (
        <Modal title="Authentication" onClose={() => { setAuthPrompt(null); wsRef.current?.close(); }}>
          <form onSubmit={submitPassword} className="space-y-3">
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

      {/* share link modal */}
      {showShare && sessionId && (
        <ShareModal sessionId={sessionId} label={statusMsg || tab.title} onClose={() => setShowShare(false)} />
      )}

      {/* snippet variable fill */}
      {varPrompt && (
        <Modal title={`Fill: ${varPrompt.snippet.name}`} onClose={() => setVarPrompt(null)}>
          <form onSubmit={submitVars} className="space-y-3">
            {varPrompt.vars.map((v) => (
              <div key={v}>
                <label className="label font-mono">{`{{${v}}}`}</label>
                <input
                  className="input font-mono"
                  autoFocus={v === varPrompt.vars[0]}
                  value={varValues[v] || ''}
                  onChange={(e) => setVarValues((s) => ({ ...s, [v]: e.target.value }))}
                />
              </div>
            ))}
            <div className="flex justify-end gap-2">
              <button type="button" className="btn-ghost" onClick={() => setVarPrompt(null)}>
                Cancel
              </button>
              <button className="btn-primary">{varPrompt.execute ? 'Run' : 'Insert'}</button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
}
