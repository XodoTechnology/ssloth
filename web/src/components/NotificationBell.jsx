import React, { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Bell, CheckCheck, X, BellRing } from 'lucide-react';
import { api } from '../api';
import { useStore } from '../store';

const canNotify = () => typeof Notification !== 'undefined';

// Browser Notification for a freshly-arrived feed item. Clicking it focuses
// the tab and follows the item's link.
function fireBrowserNotification(n, navigate) {
  if (!canNotify() || Notification.permission !== 'granted') return;
  try {
    const note = new Notification(n.title, {
      body: n.body || '',
      icon: '/sloth.svg',
      tag: `ssloth-${n.id}`, // same id => replaces, never stacks duplicates
    });
    note.onclick = () => {
      window.focus();
      if (n.link) navigate(n.link);
      note.close();
    };
  } catch {}
}

// The bell: unread badge + dropdown of the latest notifications. Polls the
// feed on an interval and on window focus — sensor sweeps are minutes
// apart, so 30s latency is invisible next to them. Newly-seen unread items
// also raise an OS notification when the user has granted permission.
export default function NotificationBell() {
  const [open, setOpen] = useState(false);
  const [count, setCount] = useState(0);
  const [items, setItems] = useState([]);
  const [perm, setPerm] = useState(canNotify() ? Notification.permission : 'unsupported');
  const ref = useRef(null);
  const seenRef = useRef(null); // ids already surfaced as browser notifications
  const navigate = useNavigate();

  const refresh = () =>
    api('/api/notifications?limit=20')
      .then((d) => {
        const list = d.notifications || [];
        setCount(typeof d.unread === 'number' ? d.unread : list.filter((n) => !n.read).length);
        // First poll seeds the seen-set silently; later polls notify on new ids.
        if (seenRef.current === null) {
          seenRef.current = new Set(list.map((n) => n.id));
        } else {
          for (const n of list) {
            if (!n.read && !seenRef.current.has(n.id)) fireBrowserNotification(n, navigate);
            seenRef.current.add(n.id);
          }
        }
        setItems(list);
      })
      .catch(() => {});

  const loadItems = () => api('/api/notifications').then((d) => setItems(d.notifications || [])).catch(() => {});

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 30000);
    const onFocus = () => refresh();
    window.addEventListener('focus', onFocus);
    return () => { clearInterval(t); window.removeEventListener('focus', onFocus); };
  }, []);

  useEffect(() => {
    if (open) loadItems();
  }, [open]);

  useEffect(() => {
    const onDown = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', onDown);
    return () => document.removeEventListener('mousedown', onDown);
  }, []);

  const enableBrowser = async () => {
    if (!canNotify()) return;
    const p = await Notification.requestPermission();
    setPerm(p);
  };

  const open_item = async (n) => {
    if (!n.read) {
      api(`/api/notifications/${n.id}/read`, { method: 'POST' }).catch(() => {});
      setItems((xs) => xs.map((x) => (x.id === n.id ? { ...x, read: 1 } : x)));
      setCount((c) => Math.max(0, c - 1));
    }
    if (n.link) { setOpen(false); navigate(n.link); }
  };

  const markAll = async () => {
    await api('/api/notifications/read-all', { method: 'POST' }).catch(() => {});
    setItems((xs) => xs.map((x) => ({ ...x, read: 1 })));
    setCount(0);
  };

  const remove = async (n, e) => {
    e.stopPropagation();
    await api(`/api/notifications/${n.id}`, { method: 'DELETE' }).catch(() => {});
    setItems((xs) => xs.filter((x) => x.id !== n.id));
    if (!n.read) setCount((c) => Math.max(0, c - 1));
  };

  const KIND_ICON = { 'sensor.alert': '▲', 'sensor.recovered': '▼', 'watch.hit': '◎' };
  const KIND_COLOR = { 'sensor.alert': 'text-rose-400', 'sensor.recovered': 'text-emerald-400', 'watch.hit': 'text-amber-300' };

  return (
    <div className="relative" ref={ref}>
      <button className="btn-ghost !px-2 relative" title="Notifications" onClick={() => setOpen((o) => !o)}>
        <Bell size={15} />
        {count > 0 && (
          <span className="absolute -top-0.5 -right-0.5 min-w-[14px] h-3.5 px-0.5 rounded-full bg-rose-500 text-[9px] font-bold text-white flex items-center justify-center">
            {count > 99 ? '99+' : count}
          </span>
        )}
      </button>
      {open && (
        <div className="absolute bottom-9 right-0 z-50 w-80 rounded-lg border border-ink-700 bg-ink-900 shadow-2xl">
          <div className="flex items-center justify-between border-b border-ink-700 px-3 py-2">
            <span className="text-xs font-semibold text-zinc-200">Notifications</span>
            <div className="flex items-center gap-2">
              {perm === 'default' && (
                <button className="text-[11px] text-emerald-400 hover:text-emerald-300 flex items-center gap-1" onClick={enableBrowser} title="Show OS notifications for new alerts">
                  <BellRing size={12} /> enable alerts
                </button>
              )}
              {perm === 'granted' && <BellRing size={12} className="text-emerald-400" title="browser notifications on" />}
              {count > 0 && (
                <button className="text-[11px] text-zinc-400 hover:text-zinc-200 flex items-center gap-1" onClick={markAll}>
                  <CheckCheck size={12} /> mark all read
                </button>
              )}
            </div>
          </div>
          <div className="max-h-80 overflow-y-auto">
            {items.length === 0 && <p className="px-3 py-4 text-xs text-zinc-500 text-center">nothing yet</p>}
            {items.map((n) => (
              <button
                key={n.id}
                className={`w-full text-left px-3 py-2 border-b border-ink-800/60 hover:bg-ink-800/60 ${n.read ? 'opacity-60' : ''}`}
                onClick={() => open_item(n)}
              >
                <div className="flex items-start gap-2">
                  <span className={`mt-0.5 text-[10px] ${KIND_COLOR[n.kind] || 'text-zinc-400'}`}>{KIND_ICON[n.kind] || '•'}</span>
                  <div className="min-w-0 flex-1">
                    <div className="text-xs text-zinc-200 truncate">{n.title}</div>
                    {n.body && <div className="text-[11px] text-zinc-500 truncate">{n.body}</div>}
                    <div className="text-[10px] text-zinc-600">{new Date(n.created_at * 1000).toLocaleString()}</div>
                  </div>
                  <span role="button" className="text-zinc-600 hover:text-zinc-300 shrink-0" onClick={(e) => remove(n, e)}>
                    <X size={12} />
                  </span>
                </div>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
