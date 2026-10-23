import React, { useEffect, useMemo, useState } from 'react';
import {
  Plus,
  Search,
  Server,
  FolderClosed,
  X,
  Pencil,
  Trash2,
  Zap,
  PanelLeftClose,
  PanelLeftOpen,
  FileUp,
  Star,
  Copy,
  Clock,
  Play,
  Power,
  Activity,
  Layers,
} from 'lucide-react';
import { api } from '../api';
import { useStore } from '../store';
import HostForm from '../components/HostForm';
import TerminalView from '../components/TerminalView';
import SshConfigImport from '../components/SshConfigImport';

const DOT_COLORS = {
  emerald: 'bg-emerald-500',
  sky: 'bg-sky-500',
  amber: 'bg-amber-500',
  rose: 'bg-rose-500',
  violet: 'bg-violet-500',
  zinc: 'bg-zinc-500',
};

export default function Sessions() {
  const { hosts, tabs, activeTabId, openTab, closeTab, setActiveTab, refreshAll, toast, hostStatus, setHostStatus, user } =
    useStore();
  const readOnly = user?.role === 'viewer';
  const [sidebar, setSidebar] = useState(true);
  const [query, setQuery] = useState('');
  const [quick, setQuick] = useState('');
  const [editing, setEditing] = useState(null); // host object | 'new' | null
  const [importing, setImporting] = useState(false);
  const [collapsed, setCollapsed] = useState({});
  const [healthFor, setHealthFor] = useState(null); // hostId -> popover sparkline
  const [healthData, setHealthData] = useState({});
  const [sideView, setSideView] = useState('groups'); // groups|recent|frequent|workspaces
  const [workspaces, setWorkspaces] = useState(null);

  useEffect(() => {
    refreshAll(api).catch((e) => toast(e.message, 'error'));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Live reachability dots (server-side TCP probe, cached ~20s server-side).
  useEffect(() => {
    let alive = true;
    const poll = () =>
      api('/api/hosts/status')
        .then((r) => alive && setHostStatus(r.status))
        .catch(() => {});
    poll();
    const t = setInterval(poll, 30000);
    return () => {
      alive = false;
      clearInterval(t);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hosts.length]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (q.startsWith('#')) {
      const tag = q.slice(1);
      return hosts.filter((h) => (h.tags || '').split(' ').includes(tag));
    }
    return hosts.filter(
      (h) =>
        !q ||
        h.name.toLowerCase().includes(q) ||
        h.hostname.toLowerCase().includes(q) ||
        h.username.toLowerCase().includes(q) ||
        (h.folder || '').toLowerCase().includes(q) ||
        (h.region || '').toLowerCase().includes(q) ||
        (h.tags || '').includes(q)
    );
  }, [hosts, query]);

  const groups = useMemo(() => {
    const m = new Map();
    for (const h of filtered) {
      if (h.pinned) continue; // pinned hosts live in their own group
      const f = h.folder || 'Ungrouped';
      if (!m.has(f)) m.set(f, []);
      m.get(f).push(h);
    }
    return [...m.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [filtered]);

  const pinned = useMemo(() => filtered.filter((h) => h.pinned), [filtered]);
  const recent = useMemo(
    () =>
      filtered
        .filter((h) => h.last_used_at)
        .sort((a, b) => b.last_used_at - a.last_used_at)
        .slice(0, 15),
    [filtered]
  );
  const frequent = useMemo(
    () =>
      filtered
        .filter((h) => h.use_count > 0)
        .sort((a, b) => b.use_count - a.use_count || b.last_used_at - a.last_used_at)
        .slice(0, 15),
    [filtered]
  );

  // Single click focuses an already-open session instead of stacking dupes;
  // double-click on a live host offers to open a duplicate.
  const connectHost = (h, { forceNew = false } = {}) => {
    const existing = tabs.find((t) => t.target?.hostId === h.id);
    if (existing && !forceNew) return setActiveTab(existing.id);
    openTab({ hostId: h.id }, h.name, h.color);
  };

  const maybeDuplicate = (h) => {
    // live check — the first click of this double-click may have just opened it
    const existing = useStore.getState().tabs.find((t) => t.target?.hostId === h.id);
    if (!existing) return;
    if (Date.now() - (existing.openedAt || 0) < 1500) return; // it just opened via these clicks
    if (confirm(`"${h.name}" already has an open session — open a duplicate?`)) {
      connectHost(h, { forceNew: true });
    }
  };

  const connectAll = (list, label) => {
    if (!list.length) return;
    if (list.length > 8 && !confirm(`Open ${list.length} sessions to ${label}?`)) return;
    for (const h of list) connectHost(h, { forceNew: true });
    toast(`opened ${list.length} session${list.length > 1 ? 's' : ''} → ${label}`, 'success');
  };

  // ---- quick connect + history ----
  const [quickLog, setQuickLog] = useState(null); // null = panel closed
  const logQuick = (entry) => {
    api('/api/hosts/quicklog', { method: 'POST', body: entry })
      .then((r) => setQuickLog((q) => (q ? { entries: [r.entry, ...q.entries.filter((e) => e.id !== r.entry.id)] } : q)))
      .catch(() => {});
  };

  const openQuick = (entry) => {
    openTab({ inline: { hostname: entry.hostname, port: entry.port, username: entry.username } },
      `${entry.username}@${entry.hostname}`);
    logQuick(entry);
  };

  const toggleQuickLog = async () => {
    if (quickLog) return setQuickLog(null);
    try {
      setQuickLog(await api('/api/hosts/quicklog'));
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  const dropQuickEntry = async (e2, id) => {
    e2.stopPropagation();
    try {
      await api(`/api/hosts/quicklog/${id}`, { method: 'DELETE' });
      setQuickLog((q) => ({ entries: q.entries.filter((x) => x.id !== id) }));
    } catch {}
  };

  const quickConnect = (e) => {
    e.preventDefault();
    const m = quick.trim().match(/^(?:(?<user>[^@\s]+)@)?(?<host>[^:\s]+)(?::(?<port>\d+))?$/);
    if (!m) return toast('use user@host[:port]', 'error');
    const { user, host, port } = m.groups;
    openQuick({ hostname: host, port: parseInt(port, 10) || 22, username: user || 'root' });
    setQuick('');
  };

  const wake = async (h, e) => {
    e.stopPropagation();
    try {
      await api(`/api/hosts/${h.id}/wol`, { method: 'POST' });
      toast(`magic packet sent to ${h.name}`, 'success');
    } catch (e2) {
      toast(e2.message, 'error');
    }
  };

  const toggleHealth = async (h, e) => {
    e.stopPropagation();
    if (healthFor === h.id) return setHealthFor(null);
    setHealthFor(h.id);
    try {
      const r = await api(`/api/hosts/${h.id}/health`);
      setHealthData((d) => ({ ...d, [h.id]: r }));
    } catch {}
  };

  const moveToFolder = async (e, folder) => {
    e.preventDefault();
    e.stopPropagation();
    const id = parseInt(e.dataTransfer.getData('text/ssloth-host'), 10);
    const h = hosts.find((x) => x.id === id);
    if (!h || h.owned === false) return;
    const target = folder === 'Ungrouped' ? '' : folder;
    if ((h.folder || '') === target) return;
    try {
      await api(`/api/hosts/${h.id}`, { method: 'PUT', body: { folder: target } });
      toast(`moved ${h.name} → ${target || 'Ungrouped'}`, 'success');
      refreshAll(api);
    } catch (e2) {
      toast(e2.message, 'error');
    }
  };

  // ---- workspaces ----
  const loadWorkspaces = async () => {
    try {
      setWorkspaces(await api('/api/workspaces'));
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  const saveWorkspace = async () => {
    const layout = tabs
      .map((t) => t.target?.hostId)
      .filter(Boolean)
      .map((host) => ({ host }));
    if (!layout.length) return toast('no saved-host sessions open — quick connects can\'t go in a workspace', 'error');
    const name = prompt('Workspace name:', 'morning rounds');
    if (!name?.trim()) return;
    try {
      await api('/api/workspaces', { method: 'POST', body: { name: name.trim(), layout } });
      toast(`workspace "${name.trim()}" saved (${layout.length} sessions)`, 'success');
      loadWorkspaces();
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  const openWorkspace = (w) => {
    let opened = 0;
    for (const entry of w.layout) {
      const h = hosts.find((x) => x.id === entry.host);
      if (h) {
        connectHost(h);
        opened++;
      }
    }
    toast(`workspace "${w.name}" — ${opened}/${w.layout.length} sessions up`, opened ? 'success' : 'error');
  };

  const dropWorkspace = async (e, w) => {
    e.stopPropagation();
    if (!confirm(`Delete workspace "${w.name}"?`)) return;
    try {
      await api(`/api/workspaces/${w.id}`, { method: 'DELETE' });
      loadWorkspaces();
    } catch (e2) {
      toast(e2.message, 'error');
    }
  };

  const togglePin = async (h) => {
    try {
      await api(`/api/hosts/${h.id}`, { method: 'PUT', body: { pinned: !h.pinned } });
      refreshAll(api);
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  const duplicateHost = async (h) => {
    try {
      const { id, last_used_at, pinned, ...rest } = h;
      await api('/api/hosts', { method: 'POST', body: { ...rest, name: `${h.name} copy` } });
      toast('host duplicated', 'success');
      refreshAll(api);
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  const deleteHost = async (h) => {
    if (!confirm(`Delete host "${h.name}"?`)) return;
    try {
      await api(`/api/hosts/${h.id}`, { method: 'DELETE' });
      toast('host deleted', 'success');
      refreshAll(api);
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  const renderHost = (h) => (
    <React.Fragment key={h.id}>
    <div
      className="group flex items-center gap-2 rounded-md px-2 py-1.5 cursor-pointer hover:bg-ink-800"
      onClick={() => connectHost(h)}
      onDoubleClick={() => maybeDuplicate(h)}
      draggable
      onDragStart={(e) => {
        e.dataTransfer.setData('text/ssloth-host', String(h.id));
        e.dataTransfer.effectAllowed = 'move';
      }}
      title={`${h.username}@${h.hostname}:${h.port}`}
    >
      <button
        className={`h-2 w-2 rounded-full shrink-0 ${DOT_COLORS[h.color] || 'bg-zinc-600'} ${
          hostStatus[h.id] === 'up'
            ? 'ring-2 ring-emerald-500/60'
            : hostStatus[h.id] === 'down'
              ? 'ring-2 ring-red-500/60'
              : ''
        }`}
        title={
          hostStatus[h.id] === 'up'
            ? 'reachable — click for history'
            : hostStatus[h.id] === 'down'
              ? 'unreachable — click for history'
              : 'status unknown — click for history'
        }
        onClick={(e) => toggleHealth(h, e)}
      />
      <div className="min-w-0 flex-1">
        <div className="text-sm text-zinc-200 truncate flex items-center gap-1.5">
          {h.name}
          {h.protocol === 'telnet' && (
            <span className="shrink-0 rounded bg-amber-950 px-1 py-px text-[9px] font-medium text-amber-300 uppercase">
              telnet
            </span>
          )}
          {h.shared === 1 && (
            <span
              className="shrink-0 rounded bg-violet-950 px-1 py-px text-[9px] font-medium text-violet-300 uppercase"
              title={h.owned ? 'shared with the team' : `shared by ${h.owner_name || 'a teammate'}`}
            >
              {h.owned ? 'shared' : `from ${h.owner_name || 'team'}`}
            </span>
          )}
          {h.region && (
            <span className="shrink-0 rounded bg-ink-800 px-1 py-px text-[9px] font-medium text-sky-400 uppercase">
              {h.region}
            </span>
          )}
        </div>
        <div className="text-[11px] text-zinc-500 truncate font-mono">
          {h.username}@{h.hostname}
          {h.port !== 22 ? `:${h.port}` : ''}
        </div>
        {h.tags && (
          <div className="flex flex-wrap gap-1 mt-0.5">
            {h.tags.split(' ').map((t) => (
              <button
                key={t}
                className="rounded bg-ink-800 px-1 text-[9px] text-violet-400 hover:bg-violet-950"
                title={`filter #${t}`}
                onClick={(e) => {
                  e.stopPropagation();
                  setQuery(`#${t}`);
                }}
              >
                #{t}
              </button>
            ))}
          </div>
        )}
      </div>
      <div className="hidden group-hover:flex items-center gap-0.5 shrink-0">
        {h.mac && !readOnly && (
          <button
            className="p-1 text-zinc-500 hover:text-amber-400"
            title={`Wake-on-LAN — send magic packet to ${h.mac}`}
            onClick={(e) => wake(h, e)}
          >
            <Power size={13} />
          </button>
        )}
        {h.owned !== false && !readOnly && (
          <>
            <button
              className={`p-1 ${h.pinned ? 'text-amber-400' : 'text-zinc-500 hover:text-amber-400'}`}
              title={h.pinned ? 'Unpin' : 'Pin to top'}
              onClick={(e) => {
                e.stopPropagation();
                togglePin(h);
              }}
            >
              <Star size={13} className={h.pinned ? 'fill-amber-400' : ''} />
            </button>
            <button
              className="p-1 text-zinc-500 hover:text-zinc-200"
              title="Duplicate"
              onClick={(e) => {
                e.stopPropagation();
                duplicateHost(h);
              }}
            >
              <Copy size={13} />
            </button>
            <button
              className="p-1 text-zinc-500 hover:text-zinc-200"
              title="Edit"
              onClick={(e) => {
                e.stopPropagation();
                setEditing(h);
              }}
            >
              <Pencil size={13} />
            </button>
            <button
              className="p-1 text-zinc-500 hover:text-red-400"
              title="Delete"
              onClick={(e) => {
                e.stopPropagation();
                deleteHost(h);
              }}
            >
              <Trash2 size={13} />
            </button>
          </>
        )}
      </div>
    </div>
    {healthFor === h.id && (
      <div className="mx-2 mb-1 rounded-md border border-ink-700 bg-ink-900 px-3 py-2" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-2 text-[11px] text-zinc-400">
          <Activity size={11} className="text-emerald-400" />
          <span>reachability — last 48h</span>
          <span className="ml-auto font-mono text-zinc-500">
            {healthData[h.id]?.current
              ? `${healthData[h.id].current.latencyMs}ms`
              : '…'}
          </span>
        </div>
        <HealthSpark rows={healthData[h.id]?.history || []} />
      </div>
    )}
    </React.Fragment>
  );

  return (
    <div className="flex-1 flex min-h-0">
      {sidebar && (
        <aside className="w-72 shrink-0 border-r border-ink-700 bg-ink-900/60 flex flex-col min-h-0">
          <div className="p-2.5 space-y-2 border-b border-ink-700">
            <form onSubmit={quickConnect} className="flex gap-1.5">
              <input
                className="input !py-1 font-mono text-xs"
                placeholder="user@host[:port]"
                value={quick}
                onChange={(e) => setQuick(e.target.value)}
              />
              <button className="btn-primary !px-2.5" title="Quick connect" disabled={!quick.trim()}>
                <Zap size={14} />
              </button>
              <button
                type="button"
                className={`btn-ghost !px-2 border ${quickLog ? 'border-emerald-700 text-emerald-400' : 'border-ink-700'}`}
                title="Quick-connect history — reconnect or save as host"
                onClick={toggleQuickLog}
              >
                <Clock size={14} />
              </button>
            </form>
            {quickLog && (
              <div className="rounded-md border border-ink-700 bg-ink-900 max-h-44 overflow-y-auto">
                {quickLog.entries.length === 0 && (
                  <div className="px-3 py-2.5 text-[11px] text-zinc-600">no quick connects yet</div>
                )}
                {quickLog.entries.map((e2) => (
                  <div
                    key={e2.id}
                    className="group/q flex items-center gap-2 px-2.5 py-1.5 cursor-pointer hover:bg-ink-800"
                    onClick={() => openQuick(e2)}
                    title="connect again"
                  >
                    <span className="flex-1 font-mono text-[11px] text-zinc-300 truncate">
                      {e2.username}@{e2.hostname}{e2.port !== 22 ? `:${e2.port}` : ''}
                    </span>
                    <span className="text-[9px] text-zinc-600 shrink-0">
                      {new Date(e2.ts * 1000).toLocaleDateString()}
                    </span>
                    {!readOnly && (
                      <span
                        className="opacity-0 group-hover/q:opacity-100 text-zinc-500 hover:text-emerald-400"
                        title="Save as host"
                        onClick={(ev) => {
                          ev.stopPropagation();
                          setEditing({
                            name: `${e2.username}@${e2.hostname}`,
                            hostname: e2.hostname,
                            port: e2.port,
                            username: e2.username,
                          });
                        }}
                      >
                        <Star size={11} />
                      </span>
                    )}
                    <span
                      className="opacity-0 group-hover/q:opacity-100 text-zinc-600 hover:text-red-400"
                      title="Remove from history"
                      onClick={(ev) => dropQuickEntry(ev, e2.id)}
                    >
                      <X size={11} />
                    </span>
                  </div>
                ))}
              </div>
            )}
            <div className="flex gap-1.5">
              <div className="relative flex-1">
                <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-500" />
                <input
                  className="input !py-1 !pl-7 text-xs"
                  placeholder="filter hosts"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                />
              </div>
              {!readOnly && (
                <button className="btn-ghost !px-2 border border-ink-700" title="New host" onClick={() => setEditing('new')}>
                  <Plus size={14} />
                </button>
              )}
              <button
                className="btn-ghost !px-2 border border-ink-700"
                title="Import ~/.ssh/config"
                onClick={() => setImporting(true)}
              >
                <FileUp size={14} />
              </button>
            </div>
            <div className="flex rounded-md border border-ink-700 overflow-hidden text-[10px] font-medium">
              {[['groups', 'Groups'], ['recent', 'Recent'], ['frequent', 'Frequent'], ['workspaces', 'Workspaces']].map(
                ([v, label]) => (
                  <button
                    key={v}
                    className={`flex-1 py-1 ${
                      sideView === v ? 'bg-emerald-950/60 text-emerald-300' : 'bg-ink-900 text-zinc-500 hover:text-zinc-300'
                    }`}
                    onClick={() => {
                      setSideView(v);
                      if (v === 'workspaces' && workspaces === null) loadWorkspaces();
                    }}
                  >
                    {label}
                  </button>
                )
              )}
            </div>
          </div>

          <div className="flex-1 overflow-y-auto p-2 space-y-3">
            {query.trim().startsWith('#') && filtered.length > 0 && (
              <button
                className="w-full flex items-center justify-center gap-2 rounded-md border border-violet-800 bg-violet-950/40 px-2 py-1.5 text-xs text-violet-300 hover:bg-violet-950/70"
                onClick={() => connectAll(filtered, query.trim())}
              >
                <Play size={11} />
                open all {filtered.length} {query.trim()} sessions
              </button>
            )}
            {sideView === 'recent' && (
              <div>
                <div className="px-1.5 py-1 text-[11px] font-semibold uppercase tracking-wider text-zinc-500">Recent</div>
                {recent.map(renderHost)}
                {recent.length === 0 && <div className="px-3 py-4 text-xs text-zinc-600">nothing connected yet</div>}
              </div>
            )}
            {sideView === 'frequent' && (
              <div>
                <div className="px-1.5 py-1 text-[11px] font-semibold uppercase tracking-wider text-zinc-500">Frequent</div>
                {frequent.map(renderHost)}
                {frequent.length === 0 && <div className="px-3 py-4 text-xs text-zinc-600">usage counts build up as you connect</div>}
              </div>
            )}
            {sideView === 'workspaces' && (
              <div className="space-y-1">
                <button
                  className="w-full flex items-center justify-center gap-2 rounded-md border border-dashed border-ink-600 px-2 py-2 text-xs text-zinc-400 hover:text-emerald-300 hover:border-emerald-800"
                  onClick={saveWorkspace}
                >
                  <Layers size={12} /> save current tabs as a workspace
                </button>
                {(workspaces?.workspaces || []).map((w) => (
                  <div
                    key={w.id}
                    className="group/w flex items-center gap-2 rounded-md px-2 py-2 cursor-pointer border border-ink-700 hover:border-emerald-800 hover:bg-ink-800"
                    onClick={() => openWorkspace(w)}
                    title={`open ${w.layout.length} sessions`}
                  >
                    <Layers size={13} className="text-emerald-500 shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="text-sm text-zinc-200 truncate">{w.name}</div>
                      <div className="text-[10px] text-zinc-500">{w.layout.length} session{w.layout.length === 1 ? '' : 's'}</div>
                    </div>
                    <span
                      className="opacity-0 group-hover/w:opacity-100 text-zinc-600 hover:text-red-400 p-1"
                      title="Delete workspace"
                      onClick={(e) => dropWorkspace(e, w)}
                    >
                      <Trash2 size={12} />
                    </span>
                  </div>
                ))}
                {workspaces && workspaces.workspaces.length === 0 && (
                  <div className="px-3 py-4 text-xs text-zinc-600 text-center">
                    no workspaces yet — open the tabs you want together, then save them above
                  </div>
                )}
              </div>
            )}
            {sideView === 'groups' && pinned.length > 0 && (
              <div>
                <div className="flex items-center gap-1.5 px-1.5 py-1 text-[11px] font-semibold uppercase tracking-wider text-amber-500">
                  <Star size={11} className="fill-amber-500" /> Pinned
                </div>
                {pinned.map(renderHost)}
              </div>
            )}
            {sideView === 'groups' && groups.map(([folder, list]) => (
              <div key={folder}>
                <button
                  className="group/hdr flex items-center gap-1.5 w-full px-1.5 py-1 text-[11px] font-semibold uppercase tracking-wider text-zinc-500 hover:text-zinc-300"
                  onClick={() => setCollapsed((c) => ({ ...c, [folder]: !c[folder] }))}
                  onDragOver={(e) => e.preventDefault()}
                  onDrop={(e) => moveToFolder(e, folder)}
                >
                  <FolderClosed size={12} />
                  <span className="truncate">{folder}</span>
                  <span
                    className="ml-auto opacity-0 group-hover/hdr:opacity-100 text-zinc-500 hover:text-emerald-400"
                    title={`Connect to all ${list.length} hosts in ${folder}`}
                    onClick={(e) => {
                      e.stopPropagation();
                      connectAll(list, folder);
                    }}
                  >
                    <Play size={11} />
                  </span>
                  {!readOnly && (
                    <span
                      className="opacity-0 group-hover/hdr:opacity-100 text-zinc-500 hover:text-emerald-400"
                      title={`New host in ${folder}`}
                      onClick={(e) => {
                        e.stopPropagation();
                        setEditing({ folder: folder === 'Ungrouped' ? '' : folder });
                      }}
                    >
                      <Plus size={11} />
                    </span>
                  )}
                  <span className="text-zinc-600">{list.length}</span>
                </button>
                {!collapsed[folder] && list.map(renderHost)}
              </div>
            ))}
            {hosts.length === 0 && (
              <div className="px-3 py-8 text-center text-xs text-zinc-600">
                no hosts yet — add one or quick connect above
              </div>
            )}
          </div>
        </aside>
      )}

      <div className="flex-1 flex flex-col min-w-0 min-h-0">
        <div className="flex items-center gap-1 border-b border-ink-700 bg-ink-900/60 px-1.5 h-10 overflow-x-auto">
          <button
            className="btn-ghost !px-2 shrink-0"
            onClick={() => setSidebar((v) => !v)}
            title={sidebar ? 'Hide hosts' : 'Show hosts'}
          >
            {sidebar ? <PanelLeftClose size={15} /> : <PanelLeftOpen size={15} />}
          </button>
          {tabs.map((t) => (
            <div
              key={t.id}
              onClick={() => setActiveTab(t.id)}
              className={`group flex items-center gap-2 rounded-t-md px-3 h-8 mt-2 cursor-pointer text-sm whitespace-nowrap border border-b-0 ${
                t.id === activeTabId
                  ? 'bg-ink-950 border-ink-700 text-zinc-100'
                  : 'border-transparent text-zinc-500 hover:text-zinc-300 hover:bg-ink-800/60'
              }`}
            >
              <span
                className={`h-1.5 w-1.5 rounded-full ${
                  t.bell
                    ? 'bg-amber-400 animate-ping'
                    : t.status === 'ready'
                      ? 'bg-emerald-500'
                      : t.status === 'connecting'
                        ? 'bg-amber-500 animate-pulse'
                        : 'bg-zinc-600'
                }`}
                title={t.bell ? 'terminal bell' : ''}
              />
              {t.title}
              {t.target?.inline && !readOnly && (
                <button
                  className="text-zinc-600 hover:text-emerald-400 opacity-0 group-hover:opacity-100"
                  title="Save as host"
                  onClick={(e) => {
                    e.stopPropagation();
                    setEditing({
                      name: t.title,
                      hostname: t.target.inline.hostname,
                      port: t.target.inline.port,
                      username: t.target.inline.username,
                    });
                  }}
                >
                  <Star size={11} />
                </button>
              )}
              <button
                className="text-zinc-600 hover:text-zinc-200 opacity-0 group-hover:opacity-100"
                onClick={(e) => {
                  e.stopPropagation();
                  closeTab(t.id);
                }}
              >
                <X size={13} />
              </button>
            </div>
          ))}
          {tabs.length === 0 && (
            <span className="px-3 text-xs text-zinc-600">select a host or quick-connect to open a session</span>
          )}
        </div>

        <div className="flex-1 relative min-h-0 bg-ink-950">
          {tabs.map((t) => (
            <TerminalView key={t.id} tab={t} active={t.id === activeTabId} />
          ))}
          {tabs.length === 0 && (
            <div className="h-full flex flex-col items-center justify-center text-zinc-600 gap-3">
              <Server size={40} strokeWidth={1.2} />
              <p className="text-sm">no open sessions</p>
            </div>
          )}
        </div>
      </div>

      {editing && (
        <HostForm
          host={editing === 'new' ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            refreshAll(api);
          }}
        />
      )}
      {importing && <SshConfigImport onClose={() => setImporting(false)} />}
    </div>
  );
}

// Tiny uptime/latency sparkline: one column per probe, green when up,
// red when down, height ~ latency (log-scaled, capped).
function HealthSpark({ rows }) {
  if (!rows.length) {
    return <div className="py-3 text-center text-[10px] text-zinc-600">no probes yet — the sweeper runs every minute</div>;
  }
  const pts = [...rows].reverse().slice(-96);
  const maxMs = Math.max(...pts.map((r) => r.latency_ms || 0), 1);
  return (
    <div className="flex items-end gap-px h-8 mt-1">
      {pts.map((r, i) => (
        <div
          key={i}
          title={`${new Date(r.ts).toLocaleTimeString()} — ${r.ok ? `${r.latency_ms}ms` : 'down'}`}
          className={`flex-1 rounded-sm ${r.ok ? 'bg-emerald-600' : 'bg-red-600'}`}
          style={{ height: r.ok ? `${Math.max(18, Math.round((Math.log2(1 + r.latency_ms) / Math.log2(1 + maxMs)) * 100))}%` : '100%' }}
        />
      ))}
    </div>
  );
}
