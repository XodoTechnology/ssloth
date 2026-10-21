import { create } from 'zustand';

let tabSeq = 1;

export const useStore = create((set, get) => ({
  // auth
  user: null,
  setupRequired: false,
  booted: false,

  // data
  hosts: [],
  credentials: [],
  snippets: [],
  tunnels: [],

  // terminal tabs: [{id, title, target, color}] target={hostId} | {inline:{...}}
  tabs: [],
  activeTabId: null,

  // registry of live terminal senders: tabId -> { send(text), status }
  termSenders: {},

  // toasts: [{id, kind, text}]
  toasts: [],

  toast(text, kind = 'info') {
    const id = Date.now() + Math.random();
    set((s) => ({ toasts: [...s.toasts, { id, kind, text }] }));
    setTimeout(() => {
      set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }));
    }, 4500);
  },

  setUser(user) {
    set({ user });
  },

  async refreshAll(api) {
    const [h, c, s, t] = await Promise.all([
      api('/api/hosts'),
      api('/api/credentials'),
      api('/api/snippets'),
      api('/api/tunnels'),
    ]);
    set({ hosts: h.hosts, credentials: c.credentials, snippets: s.snippets, tunnels: t.tunnels });
  },

  openTab(target, title, color = '') {
    const id = `t${tabSeq++}-${Date.now().toString(36)}`;
    set((s) => ({
      tabs: [...s.tabs, { id, title, target, color }],
      activeTabId: id,
    }));
    return id;
  },

  closeTab(id) {
    set((s) => {
      const tabs = s.tabs.filter((t) => t.id !== id);
      const senders = { ...s.termSenders };
      delete senders[id];
      let activeTabId = s.activeTabId;
      if (activeTabId === id) activeTabId = tabs.length ? tabs[tabs.length - 1].id : null;
      return { tabs, termSenders: senders, activeTabId };
    });
  },

  setActiveTab(id) {
    set({ activeTabId: id });
  },

  registerTerminal(id, sender) {
    set((s) => ({ termSenders: { ...s.termSenders, [id]: sender } }));
  },

  setTabStatus(id, status) {
    set((s) => ({
      tabs: s.tabs.map((t) => (t.id === id ? { ...t, status } : t)),
    }));
  },

  setTabSession(id, sessionId) {
    set((s) => ({
      tabs: s.tabs.map((t) => (t.id === id ? { ...t, sessionId } : t)),
    }));
  },

  sendToTab(id, text) {
    const s = get().termSenders[id];
    if (s && s.send) s.send(text);
  },
}));
