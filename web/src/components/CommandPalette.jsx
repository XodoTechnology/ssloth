import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Server, Zap, Terminal, KeyRound, ArrowRightLeft, ScrollText, Settings, Search } from 'lucide-react';
import { useStore } from '../store';

const ICONS = { host: Server, snippet: Zap, nav: Terminal };

export default function CommandPalette() {
  const open = useStore((s) => s.paletteOpen);
  const setOpen = useStore((s) => s.setPaletteOpen);
  const { hosts, snippets, openTab, activeTabId, toast } = useStore();
  const [q, setQ] = useState('');
  const [idx, setIdx] = useState(0);
  const inputRef = useRef(null);
  const navigate = useNavigate();

  useEffect(() => {
    const onKey = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setOpen(!useStore.getState().paletteOpen);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [setOpen]);

  useEffect(() => {
    if (open) {
      setQ('');
      setIdx(0);
      setTimeout(() => inputRef.current?.focus(), 0);
    }
  }, [open]);

  const items = useMemo(() => {
    const list = [];
    for (const h of hosts) {
      list.push({
        kind: 'host',
        icon: ICONS.host,
        label: `Connect: ${h.name}`,
        hint: `${h.username}@${h.hostname}:${h.port}`,
        hay: `${h.name} ${h.hostname} ${h.username} ${h.folder}`,
        run: () => openTab({ hostId: h.id }, h.name, h.color),
      });
    }
    for (const s of snippets) {
      list.push({
        kind: 'snippet',
        icon: ICONS.snippet,
        label: `Run: ${s.name}`,
        hint: s.command.slice(0, 60),
        hay: `${s.name} ${s.command} ${s.category}`,
        run: () => {
          // shared runner — prompts for {{vars}} via the global modal
          useStore.getState().runSnippet(s, { tabId: activeTabId, execute: true });
        },
      });
    }
    for (const [label, path] of [
      ['Go to Sessions', '/'],
      ['Go to Vault', '/vault'],
      ['Go to Snippets', '/snippets'],
      ['Go to Tunnels', '/tunnels'],
      ['Go to Recordings', '/recordings'],
      ['Go to Audit Log', '/audit'],
      ['Go to Settings', '/settings'],
    ]) {
      list.push({ kind: 'nav', icon: ICONS.nav, label, hint: path, hay: label, run: () => navigate(path) });
    }
    return list;
  }, [hosts, snippets, openTab, activeTabId, navigate, toast]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return items.slice(0, 20);
    return items
      .filter((i) => i.hay.toLowerCase().includes(needle))
      .sort((a, b) => {
        // prefix matches on the label win
        const ap = a.label.toLowerCase().indexOf(needle);
        const bp = b.label.toLowerCase().indexOf(needle);
        return ap - bp;
      })
      .slice(0, 20);
  }, [items, q]);

  if (!open) return null;

  const pick = (i) => {
    const item = filtered[i];
    if (!item) return;
    setOpen(false);
    item.run();
  };

  return (
    <div
      className="fixed inset-0 z-[90] flex items-start justify-center pt-[15vh] bg-black/50 backdrop-blur-sm"
      onMouseDown={(e) => e.target === e.currentTarget && setOpen(false)}
    >
      <div className="w-full max-w-xl card shadow-2xl overflow-hidden">
        <div className="flex items-center gap-2 px-3 border-b border-ink-700">
          <Search size={15} className="text-zinc-500" />
          <input
            ref={inputRef}
            className="flex-1 bg-transparent py-3 text-sm outline-none placeholder:text-zinc-600"
            placeholder="connect to a host, run a snippet, jump to a page…"
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setIdx(0);
            }}
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') {
                e.preventDefault();
                setIdx((i) => Math.min(i + 1, filtered.length - 1));
              } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                setIdx((i) => Math.max(i - 1, 0));
              } else if (e.key === 'Enter') {
                pick(idx);
              } else if (e.key === 'Escape') {
                setOpen(false);
              }
            }}
          />
          <kbd className="text-[10px] text-zinc-600 border border-ink-700 rounded px-1">esc</kbd>
        </div>
        <div className="max-h-80 overflow-y-auto py-1">
          {filtered.map((item, i) => (
            <button
              key={`${item.kind}-${item.label}-${i}`}
              className={`w-full flex items-center gap-2.5 px-3 py-2 text-left text-sm ${
                i === idx ? 'bg-ink-700/70 text-zinc-100' : 'text-zinc-400 hover:bg-ink-800'
              }`}
              onMouseEnter={() => setIdx(i)}
              onClick={() => pick(i)}
            >
              <item.icon size={14} className={item.kind === 'host' ? 'text-emerald-400' : item.kind === 'snippet' ? 'text-amber-400' : 'text-zinc-500'} />
              <span className="flex-1 truncate">{item.label}</span>
              <span className="text-[10px] font-mono text-zinc-600 truncate max-w-[45%]">{item.hint}</span>
            </button>
          ))}
          {filtered.length === 0 && <div className="px-4 py-6 text-center text-xs text-zinc-600">nothing matches</div>}
        </div>
        <div className="border-t border-ink-700 px-3 py-1.5 text-[10px] text-zinc-600 flex gap-3">
          <span>↑↓ navigate</span>
          <span>↵ select</span>
          <span className="ml-auto">ctrl+k</span>
        </div>
      </div>
    </div>
  );
}
