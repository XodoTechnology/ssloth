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
  const { hosts, tabs, activeTabId, openTab, closeTab, setActiveTab, refreshAll, toast, hostStatus, setHostStatus } =
    useStore();
  const [sidebar, setSidebar] = useState(true);
  const [query, setQuery] = useState('');
  const [quick, setQuick] = useState('');
  const [editing, setEditing] = useState(null); // host object | 'new' | null
  const [importing, setImporting] = useState(false);
  const [collapsed, setCollapsed] = useState({});

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
        .slice(0, 5),
    [filtered]
  );

  const connectHost = (h) => {
    openTab({ hostId: h.id }, h.name, h.color);
  };

  const connectAll = (list, label) => {
    if (!list.length) return;
    if (list.length > 8 && !confirm(`Open ${list.length} sessions to ${label}?`)) return;
    for (const h of list) openTab({ hostId: h.id }, h.name, h.color);
    toast(`opened ${list.length} session${list.length > 1 ? 's' : ''} → ${label}`, 'success');
  };

  const quickConnect = (e) => {
    e.preventDefault();
    const m = quick.trim().match(/^(?:(?<user>[^@\s]+)@)?(?<host>[^:\s]+)(?::(?<port>\d+))?$/);
    if (!m) return toast('use user@host[:port]', 'error');
    const { user, host, port } = m.groups;
    openTab(
      { inline: { hostname: host, port: parseInt(port, 10) || 22, username: user || 'root' } },
      `${user || 'root'}@${host}`
    );
    setQuick('');
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
    <div
      key={h.id}
      className="group flex items-center gap-2 rounded-md px-2 py-1.5 cursor-pointer hover:bg-ink-800"
      onClick={() => connectHost(h)}
      title={`${h.username}@${h.hostname}:${h.port}`}
    >
      <span
        className={`h-2 w-2 rounded-full shrink-0 ${DOT_COLORS[h.color] || 'bg-zinc-600'} ${
          hostStatus[h.id] === 'up'
            ? 'ring-2 ring-emerald-500/60'
            : hostStatus[h.id] === 'down'
              ? 'ring-2 ring-red-500/60'
              : ''
        }`}
        title={
          hostStatus[h.id] === 'up'
            ? 'reachable'
            : hostStatus[h.id] === 'down'
              ? 'unreachable'
              : 'status unknown'
        }
      />
      <div className="min-w-0 flex-1">
        <div className="text-sm text-zinc-200 truncate flex items-center gap-1.5">
          {h.name}
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
        {h.owned !== false && (
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
            </form>
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
              <button className="btn-ghost !px-2 border border-ink-700" title="New host" onClick={() => setEditing('new')}>
                <Plus size={14} />
              </button>
              <button
                className="btn-ghost !px-2 border border-ink-700"
                title="Import ~/.ssh/config"
                onClick={() => setImporting(true)}
              >
                <FileUp size={14} />
              </button>
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
            {pinned.length > 0 && (
              <div>
                <div className="flex items-center gap-1.5 px-1.5 py-1 text-[11px] font-semibold uppercase tracking-wider text-amber-500">
                  <Star size={11} className="fill-amber-500" /> Pinned
                </div>
                {pinned.map(renderHost)}
              </div>
            )}
            {recent.length > 0 && (
              <div>
                <div className="flex items-center gap-1.5 px-1.5 py-1 text-[11px] font-semibold uppercase tracking-wider text-zinc-500">
                  <Clock size={11} /> Recent
                </div>
                {recent.map(renderHost)}
              </div>
            )}
            {groups.map(([folder, list]) => (
              <div key={folder}>
                <button
                  className="group/hdr flex items-center gap-1.5 w-full px-1.5 py-1 text-[11px] font-semibold uppercase tracking-wider text-zinc-500 hover:text-zinc-300"
                  onClick={() => setCollapsed((c) => ({ ...c, [folder]: !c[folder] }))}
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
