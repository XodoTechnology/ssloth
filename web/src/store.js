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
  hostStatus: {}, // hostId -> 'up' | 'down'

  // terminal tabs: [{id, title, target, color}] target={hostId} | {inline:{...}}
  tabs: [],
  activeTabId: null,

  // pane registry: 'tabId:paneId' -> { send, sendJson, reconnect, search, getTerm }
  paneSenders: {},
  paneStates: {}, // 'tabId:paneId' -> { status, sessionId, label, recording, statusMsg }
  activePane: {}, // tabId -> paneId
  broadcastTabId: null,

  // command palette
  paletteOpen: false,

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

  setPaletteOpen(v) {
    set({ paletteOpen: v });
  },

  setHostStatus(status) {
    set({ hostStatus: status });
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
      const paneSenders = { ...s.paneSenders };
      const paneStates = { ...s.paneStates };
      const activePane = { ...s.activePane };
      for (const k of Object.keys(paneSenders)) if (k.startsWith(id + ':')) delete paneSenders[k];
      for (const k of Object.keys(paneStates)) if (k.startsWith(id + ':')) delete paneStates[k];
      delete activePane[id];
      let activeTabId = s.activeTabId;
      if (activeTabId === id) activeTabId = tabs.length ? tabs[tabs.length - 1].id : null;
      const broadcastTabId = s.broadcastTabId === id ? null : s.broadcastTabId;
      return { tabs, paneSenders, paneStates, activePane, broadcastTabId, activeTabId };
    });
  },

  setActiveTab(id) {
    set({ activeTabId: id });
  },

  registerPane(tabId, paneId, sender) {
    set((s) => ({
      paneSenders: { ...s.paneSenders, [`${tabId}:${paneId}`]: sender },
      activePane: s.activePane[tabId] ? s.activePane : { ...s.activePane, [tabId]: paneId },
    }));
  },

  unregisterPane(tabId, paneId) {
    set((s) => {
      const paneSenders = { ...s.paneSenders };
      const paneStates = { ...s.paneStates };
      delete paneSenders[`${tabId}:${paneId}`];
      delete paneStates[`${tabId}:${paneId}`];
      return { paneSenders, paneStates };
    });
  },

  setActivePane(tabId, paneId) {
    set((s) => ({ activePane: { ...s.activePane, [tabId]: paneId } }));
  },

  setPaneState(tabId, paneId, state) {
    set((s) => ({ paneStates: { ...s.paneStates, [`${tabId}:${paneId}`]: state } }));
    // roll up: tab status = ready if any pane ready, else worst of states
    const st = get().paneStates;
    const keys = Object.keys(st).filter((k) => k.startsWith(tabId + ':'));
    if (!keys.length) return;
    const order = { ready: 3, connecting: 2, closed: 1, error: 1, idle: 0 };
    let best = 'idle';
    for (const k of keys) {
      const v = st[k]?.status;
      if ((order[v] || 0) > (order[best] || 0)) best = v;
    }
    set((s) => ({ tabs: s.tabs.map((t) => (t.id === tabId ? { ...t, status: best } : t)) }));
  },

  toggleBroadcast(tabId) {
    set((s) => ({ broadcastTabId: s.broadcastTabId === tabId ? null : tabId }));
  },

  // Input from the broadcasting pane goes to every other ready pane.
  broadcastText(fromKey, text) {
    const s = get();
    const fromTab = fromKey.split(':')[0];
    if (s.broadcastTabId !== fromTab) return;
    for (const [key, sender] of Object.entries(s.paneSenders)) {
      if (key === fromKey) continue;
      if (s.paneStates[key]?.status === 'ready' && sender.send) sender.send(text);
    }
  },

  sendToTab(tabId, text) {
    const s = get();
    const paneId = s.activePane[tabId];
    const sender = s.paneSenders[`${tabId}:${paneId}`];
    if (sender?.send) sender.send(text);
  },

  activeSender(tabId) {
    const s = get();
    const paneId = s.activePane[tabId];
    return s.paneSenders[`${tabId}:${paneId}`] || null;
  },
}));
