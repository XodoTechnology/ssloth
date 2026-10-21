import React, { useEffect, useState } from 'react';
import {
  FolderOpen,
  RefreshCw,
  X,
  Zap,
  Search,
  Share2,
  Copy,
  Trash2,
  Disc3,
  Radio,
  Columns2,
  Square,
  FileDown,
  Play,
} from 'lucide-react';
import { api } from '../api';
import { useStore } from '../store';
import Modal from './Modal';
import SftpPanel from './SftpPanel';
import TerminalPane from './TerminalPane';

export default function TerminalView({ tab, active }) {
  const [panes, setPanes] = useState([{ id: 'p1', target: tab.target }]);
  const [showSftp, setShowSftp] = useState(false);
  const [showSnippets, setShowSnippets] = useState(false);
  const [showSearch, setShowSearch] = useState(false);
  const [searchQ, setSearchQ] = useState('');
  const [showShare, setShowShare] = useState(false);
  const [showPlaybooks, setShowPlaybooks] = useState(false);
  const [splitPicker, setSplitPicker] = useState(false);
  const [varPrompt, setVarPrompt] = useState(null); // {snippet, vars, execute}
  const [varValues, setVarValues] = useState({});

  const snippets = useStore((s) => s.snippets);
  const playbooks = useStore((s) => s.playbooks);
  const hosts = useStore((s) => s.hosts);
  const closeTab = useStore((s) => s.closeTab);
  const setPaneState = useStore((s) => s.setPaneState);
  const setActivePane = useStore((s) => s.setActivePane);
  const toggleBroadcast = useStore((s) => s.toggleBroadcast);
  const broadcastTabId = useStore((s) => s.broadcastTabId);
  const sendToTab = useStore((s) => s.sendToTab);
  const activeSender = useStore((s) => s.activeSender);
  const toast = useStore((s) => s.toast);
  const paneStates = useStore((s) => s.paneStates);
  const activePaneId = useStore((s) => s.activePane[tab.id]) || panes[0].id;
  const pstate = paneStates[`${tab.id}:${activePaneId}`] || { status: 'idle' };
  const status = pstate.status || 'idle';
  const statusMsg = pstate.statusMsg || pstate.label || tab.title;
  const sessionId = pstate.sessionId;
  const recording = !!pstate.recording;
  const broadcasting = broadcastTabId === tab.id;

  const sender = () => activeSender(tab.id);

  // Ctrl+F opens the scrollback search for this tab while it's visible.
  useEffect(() => {
    if (!active) return;
    const onKey = (e) => {
      if (e.ctrlKey && !e.shiftKey && !e.altKey && (e.key === 'f' || e.key === 'F')) {
        e.preventDefault();
        setShowSearch(true);
      }
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [active]);

  const runSnippet = (snip, execute) => {
    setShowSnippets(false);
    const vars = [...new Set([...snip.command.matchAll(/\{\{\s*([\w.-]+)\s*\}\}/g)].map((m) => m[1]))];
    if (vars.length) {
      setVarValues({});
      setVarPrompt({ snippet: snip, vars, execute });
      return;
    }
    sendCommand(snip.command, execute);
  };

  const sendCommand = (command, execute) => {
    if (status !== 'ready') return toast('session not connected', 'error');
    sendToTab(tab.id, command + (execute ? '\n' : ''));
  };

  const submitVars = (e) => {
    e.preventDefault();
    let cmd = varPrompt.snippet.command;
    for (const [k, v] of Object.entries(varValues)) {
      cmd = cmd.replaceAll(new RegExp(`\\{\\{\\s*${k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*\\}\\}`, 'g'), v);
    }
    sendCommand(cmd, varPrompt.execute);
    setVarPrompt(null);
  };

  const addPane = (target) => {
    setSplitPicker(false);
    setPanes((p) => (p.length >= 2 ? p : [...p, { id: `p${Date.now().toString(36)}`, target }]));
  };

  const removePane = (paneId) => {
    setPanes((p) => p.filter((x) => x.id !== paneId));
  };

  const toggleRecord = () => {
    const s = sender();
    if (!s?.sendJson) return;
    s.sendJson({ type: 'record', on: !recording });
  };

  const downloadLog = () => {
    const term = sender()?.getTerm?.();
    if (!term) return toast('no terminal', 'error');
    const buf = term.buffer.active;
    const lines = [];
    for (let i = 0; i < buf.length; i++) {
      const line = buf.getLine(i);
      if (line) lines.push(line.translateToString(true));
    }
    const blob = new Blob([lines.join('\n').replace(/\n+$/, '\n')], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${tab.title.replace(/[^\w.-]+/g, '_')}-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.log`;
    a.click();
    URL.revokeObjectURL(a.href);
    toast('session log downloaded', 'success');
  };

  return (
    <div className={`absolute inset-0 flex flex-col ${active ? '' : 'invisible pointer-events-none'}`}>
      {/* toolbar */}
      <div className="flex items-center gap-1 px-2 h-9 border-b border-ink-800 bg-ink-900/40 shrink-0">
        <span
          className={`h-1.5 w-1.5 rounded-full ml-1 ${
            status === 'ready'
              ? 'bg-emerald-500'
              : status === 'error'
                ? 'bg-red-500'
                : status === 'connecting'
                  ? 'bg-amber-500 animate-pulse'
                  : 'bg-zinc-600'
          }`}
        />
        <span className="text-xs text-zinc-400 truncate max-w-[30%]">{statusMsg}</span>
        {broadcasting && (
          <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded bg-amber-950 text-amber-300 animate-pulse">
            broadcasting
          </span>
        )}
        {recording && (
          <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded bg-red-950 text-red-300 flex items-center gap-1">
            <Disc3 size={10} className="animate-spin" /> rec
          </span>
        )}
        {pstate.playbook && (
          <span
            className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded ${
              pstate.playbook.status === 'fail' ? 'bg-red-950 text-red-300' : 'bg-sky-950 text-sky-300'
            }`}
            title={pstate.playbook.command}
          >
            playbook {pstate.playbook.index + 1}/{pstate.playbook.total}
          </span>
        )}
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
                <div key={s.id} className="flex items-center gap-1 px-2 py-1.5 hover:bg-ink-800">
                  <div className="min-w-0 flex-1">
                    <div className="text-xs text-zinc-200 truncate">{s.name}</div>
                    <div className="text-[10px] font-mono text-zinc-500 truncate">{s.command}</div>
                  </div>
                  <button className="btn-ghost !px-1.5 !py-0.5 text-[11px]" onClick={() => runSnippet(s, false)}>
                    insert
                  </button>
                  <button className="btn-primary !px-1.5 !py-0.5 text-[11px]" onClick={() => runSnippet(s, true)}>
                    run
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="relative">
          <button
            className="btn-ghost !py-1 !px-2 text-xs"
            onClick={() => setShowPlaybooks((v) => !v)}
            disabled={status !== 'ready'}
            title="Run playbook"
          >
            <Play size={14} />
          </button>
          {showPlaybooks && (
            <div className="absolute right-0 top-8 z-30 w-72 card shadow-xl max-h-80 overflow-y-auto">
              {playbooks.length === 0 && (
                <div className="p-3 text-xs text-zinc-500">
                  no playbooks yet — build them in the Playbooks page
                </div>
              )}
              {playbooks.map((p) => (
                <button
                  key={p.id}
                  className="w-full text-left px-3 py-2 hover:bg-ink-800"
                  onClick={() => {
                    setShowPlaybooks(false);
                    sender()?.sendJson?.({ type: 'playbook', playbookId: p.id });
                  }}
                >
                  <div className="text-xs text-zinc-200 truncate">{p.name}</div>
                  <div className="text-[10px] text-zinc-500">{p.steps?.length || 0} steps</div>
                </button>
              ))}
            </div>
          )}
        </div>
        <button
          className="btn-ghost !py-1 !px-2 text-xs"
          onClick={() => setShowSearch((v) => !v)}
          title="Search scrollback (Ctrl+F)"
        >
          <Search size={14} />
        </button>
        <button
          className={`btn-ghost !py-1 !px-2 text-xs ${recording ? 'text-red-400' : ''}`}
          onClick={toggleRecord}
          disabled={status !== 'ready'}
          title={recording ? 'Stop recording' : 'Record session (asciinema)'}
        >
          <Disc3 size={14} />
        </button>
        <button
          className={`btn-ghost !py-1 !px-2 text-xs ${broadcasting ? 'text-amber-400' : ''}`}
          onClick={() => toggleBroadcast(tab.id)}
          title="Broadcast input to all open sessions"
        >
          <Radio size={14} />
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
          onClick={downloadLog}
          title="Download scrollback as .log"
        >
          <FileDown size={14} />
        </button>
        <button
          className="btn-ghost !py-1 !px-2 text-xs"
          onClick={() => setSplitPicker(true)}
          disabled={panes.length >= 2}
          title="Split pane"
        >
          <Columns2 size={14} />
        </button>
        <button
          className="btn-ghost !py-1 !px-2 text-xs"
          onClick={() => setShowShare(true)}
          disabled={status !== 'ready'}
          title="Share session"
        >
          <Share2 size={14} />
        </button>
        <button
          className="btn-ghost !py-1 !px-2 text-xs"
          onClick={() => sender()?.reconnect?.()}
          title="Reconnect"
        >
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
              sender()?.search?.(e.target.value);
            }}
            onKeyDown={(e) => {
              if (e.key === 'Enter') sender()?.search?.(searchQ);
              if (e.key === 'Escape') setShowSearch(false);
            }}
          />
          <button className="btn-ghost !px-2 !py-0.5 text-xs" onClick={() => sender()?.search?.(searchQ)}>
            next
          </button>
          <button
            className="btn-ghost !px-2 !py-0.5 text-xs"
            onClick={() => sender()?.search?.(searchQ, 'prev')}
          >
            prev
          </button>
        </div>
      )}

      {/* panes + sftp */}
      <div className="flex-1 flex min-h-0">
        <div className={`flex-1 flex min-w-0 min-h-0 ${panes.length > 1 ? 'gap-px bg-ink-700' : ''}`}>
          {panes.map((p) => (
            <div key={p.id} className="flex-1 min-w-0 relative bg-ink-950">
              <TerminalPane
                tab={tab}
                pane={p}
                active={active}
                focused={p.id === activePaneId}
                onFocus={() => setActivePane(tab.id, p.id)}
                onPaneState={setPaneState}
              />
              {panes.length > 1 && (
                <button
                  className="absolute top-1.5 right-1.5 z-10 p-1 rounded bg-ink-800/80 text-zinc-500 hover:text-red-400"
                  title="Close pane"
                  onClick={() => removePane(p.id)}
                >
                  <Square size={10} />
                </button>
              )}
            </div>
          ))}
        </div>
        {showSftp && status === 'ready' && sessionId && <SftpPanel sessionId={sessionId} label={statusMsg} />}
      </div>

      {/* status bar */}
      <div className="flex items-center gap-3 px-3 h-6 border-t border-ink-800 bg-ink-900/40 text-[11px] text-zinc-500 shrink-0">
        <span className="truncate">{tab.title}</span>
        {panes.length > 1 && <span>{panes.length} panes</span>}
        {pstate.health && status === 'ready' && (
          <span className="font-mono text-[10px] text-zinc-500" title="remote load · memory · root disk">
            {pstate.health.load ? `load ${pstate.health.load.map((l) => l.toFixed(2)).join(' ')}` : ''}
            {pstate.health.memPct != null ? ` · mem ${pstate.health.memPct}%` : ''}
            {pstate.health.diskPct != null ? ` · disk ${pstate.health.diskPct}%` : ''}
          </span>
        )}
        <span className="ml-auto">
          {status === 'ready' ? 'ssh channel open' : status}
          {pstate.rtt != null && status === 'ready' ? ` · ${pstate.rtt}ms` : ''}
          {broadcasting ? ' · broadcast on' : ''}
        </span>
      </div>

      {showShare && sessionId && (
        <ShareModal sessionId={sessionId} label={statusMsg || tab.title} onClose={() => setShowShare(false)} />
      )}

      {splitPicker && (
        <Modal title="Split pane — connect to" onClose={() => setSplitPicker(false)}>
          <div className="space-y-1 max-h-72 overflow-y-auto">
            <button
              className="w-full text-left rounded-md px-3 py-2 text-sm hover:bg-ink-800 text-zinc-200"
              onClick={() => addPane(tab.target)}
            >
              Same host <span className="text-zinc-500">({tab.title})</span>
            </button>
            {hosts.map((h) => (
              <button
                key={h.id}
                className="w-full text-left rounded-md px-3 py-2 text-sm hover:bg-ink-800"
                onClick={() => addPane({ hostId: h.id })}
              >
                <span className="text-zinc-200">{h.name}</span>
                <span className="ml-2 text-[11px] font-mono text-zinc-500">
                  {h.username}@{h.hostname}:{h.port}
                </span>
              </button>
            ))}
          </div>
        </Modal>
      )}

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
              <input
                className="input font-mono !text-[11px] flex-1"
                readOnly
                value={freshUrl}
                onFocus={(e) => e.target.select()}
              />
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
              <div
                key={s.id}
                className="flex items-center gap-2 rounded-md border border-ink-700 bg-ink-900 px-2.5 py-1.5"
              >
                <span
                  className={`text-[10px] font-semibold uppercase px-1.5 py-0.5 rounded ${
                    s.mode === 'control' ? 'bg-amber-950 text-amber-300' : 'bg-emerald-950 text-emerald-300'
                  }`}
                >
                  {s.mode === 'control' ? 'interactive' : 'view'}
                </span>
                <span className="text-[11px] text-zinc-500">expires {new Date(s.expires_at).toLocaleTimeString()}</span>
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
