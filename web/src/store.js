import { create } from 'zustand';

let tabSeq = 1;

// {{var}} placeholders in snippet commands — collected and prompted for
// (via the store's varPrompt) from every run path: terminal dropdown,
// Snippets page, command palette.
export function snippetVars(command) {
  return [...new Set([...command.matchAll(/\{\{\s*([\w.-]+)\s*\}\}/g)].map((m) => m[1]))];
}
export function expandSnippet(command, values) {
  let cmd = command;
  for (const [k, v] of Object.entries(values)) {
    cmd = cmd.replaceAll(new RegExp(`\\{\\{\\s*${k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*\\}\\}`, 'g'), v);
  }
  return cmd;
}

export const useStore = create((set, get) => ({
  // auth
  user: null,
  setupRequired: false,
  booted: false,
  desktop: false,
  pinSet: false,

  // data
  hosts: [],
  credentials: [],
  snippets: [],
  tunnels: [],
  playbooks: [],
  hostStatus: {}, // hostId -> 'up' | 'down'
  pendingPlaybooks: {}, // tabId -> playbookId to fire once ready
  // Persisted so a page reload can't bypass an engaged idle-lock. It's a UX
  // guard, not a security boundary — the vault itself stays server-side.
  locked: localStorage.getItem('ssloth_locked') === '1',

  // terminal tabs: [{id, title, target, color}] target={hostId} | {inline:{...}}
  tabs: [],
  activeTabId: null,

  // pane registry: 'tabId:paneId' -> { send, sendJson, reconnect, search, getTerm }
  paneSenders: {},
  paneStates: {}, // 'tabId:paneId' -> { status, sessionId, label, recording, statusMsg }
  activePane: {}, // tabId -> paneId
  broadcastTabId: null,

  // transfer queue: [{id, sessionId, label, name, dir, kind, pct, state}] kind=up|down, state=active|done|error
  transfers: [],
  sftpPaths: {}, // sessionId -> last browsed remote dir

  // command palette
  paletteOpen: false,

  // snippet {{var}} fill prompt: {snippet, vars, tabId, execute}
  varPrompt: null,

  // toasts: [{id, kind, text}]
  toasts: [],

  addTransfer(t) {
    set((s) => ({ transfers: [...s.transfers, t] }));
  },
  updateTransfer(id, patch) {
    set((s) => ({
      transfers: s.transfers.map((t) => (t.id === id ? { ...t, ...patch } : t)),
    }));
  },
  removeTransfer(id) {
    set((s) => ({ transfers: s.transfers.filter((t) => t.id !== id) }));
  },
  setSftpPath(sessionId, path) {
    set((s) => ({ sftpPaths: { ...s.sftpPaths, [sessionId]: path } }));
  },

  toast(text, kind = 'info') {
    const id = Date.now() + Math.random();
    set((s) => ({ toasts: [...s.toasts, { id, kind, text }] }));
    setTimeout(() => {
      set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }));
    }, 4500);
  },

  setUser(user) {
    if (!user) localStorage.removeItem('ssloth_locked'); // logout clears the lock too
    set({ user, locked: user ? get().locked : false });
  },

  setPaletteOpen(v) {
    set({ paletteOpen: v });
  },

  setHostStatus(status) {
    set({ hostStatus: status });
  },

  async refreshAll(api) {
    const [h, c, s, t, p] = await Promise.all([
      api('/api/hosts'),
      api('/api/credentials'),
      api('/api/snippets'),
      api('/api/tunnels'),
      api('/api/playbooks'),
    ]);
    set({
      hosts: h.hosts,
      credentials: c.credentials,
      snippets: s.snippets,
      tunnels: t.tunnels,
      playbooks: p.playbooks,
    });
  },

  setPendingPlaybook(tabId, playbookId) {
    set((s) => ({ pendingPlaybooks: { ...s.pendingPlaybooks, [tabId]: playbookId } }));
  },
  clearPendingPlaybook(tabId) {
    set((s) => {
      const p = { ...s.pendingPlaybooks };
      delete p[tabId];
      return { pendingPlaybooks: p };
    });
  },
  setLocked(v) {
    if (v) localStorage.setItem('ssloth_locked', '1');
    else localStorage.removeItem('ssloth_locked');
    set({ locked: v });
  },

  openTab(target, title, color = '') {
    const id = `t${tabSeq++}-${Date.now().toString(36)}`;
    set((s) => ({
      tabs: [...s.tabs, { id, title, target, color, openedAt: Date.now() }],
      activeTabId: id,
    }));
    return id;
  },

  closeTab(id) {
    // Explicit close kills server-side sessions (vs navigation, which detaches)
    const st = get();
    for (const [key, sender] of Object.entries(st.paneSenders)) {
      if (key.startsWith(id + ':')) {
        try { sender.closeSession?.(); } catch {}
      }
    }
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
    set((s) => ({
      activeTabId: id,
      tabs: s.tabs.map((t) => (t.id === id && t.bell ? { ...t, bell: false } : t)),
    }));
  },

  setTabBell(id) {
    set((s) => ({
      tabs: s.tabs.map((t) => (t.id === id ? { ...t, bell: true } : t)),
    }));
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

  // Run a snippet into a tab — prompts for {{vars}} first when present.
  runSnippet(snippet, { tabId, execute = true } = {}) {
    const s = get();
    if (!tabId) return s.toast('open a session first', 'error');
    const vars = snippetVars(snippet.command);
    if (vars.length) {
      set({ varPrompt: { snippet, vars, tabId, execute } });
      return;
    }
    s.sendSnippetTo(tabId, snippet.command, execute);
  },

  sendSnippetTo(tabId, command, execute) {
    const s = get();
    const paneId = s.activePane[tabId];
    if (s.paneStates[`${tabId}:${paneId}`]?.status !== 'ready') {
      return s.toast('session not connected', 'error');
    }
    s.sendToTab(tabId, command + (execute ? '\n' : ''));
  },

  submitVarPrompt(values) {
    const vp = get().varPrompt;
    if (!vp) return;
    set({ varPrompt: null });
    get().sendSnippetTo(vp.tabId, expandSnippet(vp.snippet.command, values), vp.execute);
  },

  closeVarPrompt() {
    set({ varPrompt: null });
  },

  activeSender(tabId) {
    const s = get();
    const paneId = s.activePane[tabId];
    return s.paneSenders[`${tabId}:${paneId}`] || null;
  },
}));
