import React, { useEffect, useMemo, useState } from 'react';
import { Zap, Plus, Pencil, Trash2, Search } from 'lucide-react';
import { api } from '../api';
import { useStore } from '../store';
import Modal from '../components/Modal';

export default function Snippets() {
  const { snippets, refreshAll, toast, tabs, activeTabId, sendToTab } = useStore();
  const [editing, setEditing] = useState(null); // 'new' | snippet | null
  const [query, setQuery] = useState('');

  useEffect(() => {
    refreshAll(api).catch((e) => toast(e.message, 'error'));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return snippets.filter(
      (s) =>
        !q ||
        s.name.toLowerCase().includes(q) ||
        s.command.toLowerCase().includes(q) ||
        s.category.toLowerCase().includes(q)
    );
  }, [snippets, query]);

  const categories = useMemo(() => {
    const m = new Map();
    for (const s of filtered) {
      const c = s.category || 'General';
      if (!m.has(c)) m.set(c, []);
      m.get(c).push(s);
    }
    return [...m.entries()];
  }, [filtered]);

  const del = async (s) => {
    if (!confirm(`Delete snippet "${s.name}"?`)) return;
    await api(`/api/snippets/${s.id}`, { method: 'DELETE' });
    refreshAll(api);
  };

  const runHere = (s, execute) => {
    if (!activeTabId) return toast('open a session tab first', 'error');
    sendToTab(activeTabId, s.command + (execute ? '\n' : ''));
    toast(execute ? `ran "${s.name}"` : `inserted "${s.name}"`, 'success');
  };

  return (
    <div className="flex-1 overflow-y-auto p-6">
      <div className="max-w-4xl mx-auto space-y-4">
        <div className="flex items-center justify-between gap-3">
          <h1 className="text-lg font-semibold flex items-center gap-2">
            <Zap size={18} className="text-emerald-400" /> Snippets
          </h1>
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-500" />
              <input
                className="input !py-1.5 !pl-8 w-56"
                placeholder="search commands"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
            </div>
            <button className="btn-primary" onClick={() => setEditing('new')}>
              <Plus size={14} /> New snippet
            </button>
          </div>
        </div>
        <p className="text-xs text-zinc-500">
          One-click commands for your sessions. Use <span className="font-mono">{'{{name}}'}</span> placeholders —
          you'll be prompted to fill them when running from a terminal.
        </p>

        {categories.map(([cat, list]) => (
          <div key={cat}>
            <div className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 px-1 pb-1.5">{cat}</div>
            <div className="card divide-y divide-ink-700/60">
              {list.map((s) => (
                <div key={s.id} className="flex items-center gap-3 px-4 py-2.5 group">
                  <div className="min-w-0 flex-1">
                    <div className="text-sm text-zinc-100">{s.name}</div>
                    <div className="font-mono text-[11px] text-zinc-500 truncate">{s.command}</div>
                    {s.description && <div className="text-[11px] text-zinc-600 truncate">{s.description}</div>}
                  </div>
                  <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <button className="btn-ghost !py-1 text-xs" onClick={() => runHere(s, false)}>
                      insert
                    </button>
                    <button className="btn-primary !py-1 text-xs" onClick={() => runHere(s, true)}>
                      run
                    </button>
                    <button className="btn-ghost !py-1 !px-1.5" onClick={() => setEditing(s)}>
                      <Pencil size={13} />
                    </button>
                    <button className="btn-ghost !py-1 !px-1.5 hover:text-red-400" onClick={() => del(s)}>
                      <Trash2 size={13} />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
        {snippets.length === 0 && (
          <div className="card px-4 py-10 text-center text-sm text-zinc-600">
            no snippets yet — save commands you run often
          </div>
        )}
      </div>

      {editing && <SnippetModal snippet={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
    </div>
  );
}

function SnippetModal({ snippet, onClose }) {
  const { refreshAll, toast } = useStore();
  const [form, setForm] = useState({
    name: snippet?.name || '',
    command: snippet?.command || '',
    description: snippet?.description || '',
    category: snippet?.category || '',
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));

  const save = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      if (snippet) {
        await api(`/api/snippets/${snippet.id}`, { method: 'PUT', body: form });
      } else {
        await api('/api/snippets', { method: 'POST', body: form });
      }
      toast('snippet saved', 'success');
      refreshAll(api);
      onClose();
    } catch (e2) {
      setError(e2.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal title={snippet ? 'Edit snippet' : 'New snippet'} onClose={onClose} wide>
      <form onSubmit={save} className="space-y-3">
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="label">Name</label>
            <input className="input" value={form.name} onChange={set('name')} placeholder="update & restart nginx" autoFocus />
          </div>
          <div>
            <label className="label">Category</label>
            <input className="input" value={form.category} onChange={set('category')} placeholder="maintenance" />
          </div>
        </div>
        <div>
          <label className="label">Command</label>
          <textarea
            className="input font-mono !text-xs"
            rows="4"
            spellCheck="false"
            placeholder={'apt update && apt upgrade -y\n# {{var}} placeholders are supported'}
            value={form.command}
            onChange={set('command')}
          />
        </div>
        <div>
          <label className="label">Description</label>
          <input className="input" value={form.description} onChange={set('description')} />
        </div>
        {error && (
          <div className="rounded-md border border-red-800 bg-red-950/60 px-3 py-2 text-xs text-red-300">{error}</div>
        )}
        <div className="flex justify-end gap-2">
          <button type="button" className="btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button className="btn-primary" disabled={busy || !form.name || !form.command}>
            {busy ? '…' : 'Save'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
