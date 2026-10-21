import React, { useEffect } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import {
  Terminal,
  KeyRound,
  Zap,
  ArrowRightLeft,
  ScrollText,
  Settings as SettingsIcon,
  LogOut,
  Disc3,
} from 'lucide-react';
import { api } from '../api';
import { useStore } from '../store';
import CommandPalette from './CommandPalette';
import TransfersTray from './TransfersTray';

const NAV = [
  { to: '/', label: 'Sessions', icon: Terminal, end: true },
  { to: '/vault', label: 'Vault', icon: KeyRound },
  { to: '/snippets', label: 'Snippets', icon: Zap },
  { to: '/tunnels', label: 'Tunnels', icon: ArrowRightLeft },
  { to: '/recordings', label: 'Recordings', icon: Disc3 },
  { to: '/audit', label: 'Audit Log', icon: ScrollText },
  { to: '/settings', label: 'Settings', icon: SettingsIcon },
];

export default function Layout() {
  const user = useStore((s) => s.user);
  const setUser = useStore((s) => s.setUser);
  const navigate = useNavigate();

  // Global tab shortcuts: Ctrl+Shift+[ / ] cycle, Ctrl+Shift+X closes.
  // (Ctrl+W / Ctrl+Tab are browser-reserved and can't be intercepted.)
  useEffect(() => {
    const onKey = (e) => {
      if (!e.ctrlKey || !e.shiftKey) return;
      const s = useStore.getState();
      if (!s.tabs.length) return;
      const idx = s.tabs.findIndex((t) => t.id === s.activeTabId);
      if (e.key === '}') {
        e.preventDefault();
        s.setActiveTab(s.tabs[(idx + 1) % s.tabs.length].id);
      } else if (e.key === '{') {
        e.preventDefault();
        s.setActiveTab(s.tabs[(idx - 1 + s.tabs.length) % s.tabs.length].id);
      } else if (e.key === 'X' && s.activeTabId) {
        e.preventDefault();
        s.closeTab(s.activeTabId);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const logout = async () => {
    try {
      await api('/api/auth/logout', { method: 'POST' });
    } catch {}
    setUser(null);
    navigate('/');
  };

  return (
    <div className="h-full flex">
      <aside className="w-52 shrink-0 border-r border-ink-700 bg-ink-900 flex flex-col">
        <div className="flex items-center gap-2 px-4 h-14 border-b border-ink-700">
          <span className="text-emerald-400">
            <Terminal size={20} />
          </span>
          <span className="font-bold text-zinc-100 tracking-tight">ssloth</span>
        </div>
        <nav className="flex-1 p-2 space-y-0.5">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                `flex items-center gap-2.5 rounded-md px-3 py-2 text-sm transition-colors ${
                  isActive
                    ? 'bg-ink-700/70 text-emerald-300 font-medium'
                    : 'text-zinc-400 hover:bg-ink-800 hover:text-zinc-200'
                }`
              }
            >
              <Icon size={16} />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="border-t border-ink-700 p-3 flex items-center justify-between">
          <div className="min-w-0">
            <div className="text-sm text-zinc-200 truncate">{user?.username}</div>
            <div className="text-[11px] text-zinc-500">{user?.is_admin ? 'administrator' : 'user'}</div>
          </div>
          <button className="btn-ghost !px-2" title="Sign out" onClick={logout}>
            <LogOut size={15} />
          </button>
        </div>
      </aside>
      <main className="flex-1 min-w-0 flex flex-col bg-ink-950">
        <Outlet />
      </main>
      <CommandPalette />
      <TransfersTray />
    </div>
  );
}
