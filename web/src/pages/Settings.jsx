import React, { useEffect, useState } from 'react';
import {
  Settings as SettingsIcon,
  ShieldCheck,
  Fingerprint,
  Users,
  Trash2,
  Plus,
  Download,
  Upload,
  Palette,
  Keyboard,
} from 'lucide-react';
import { useRef } from 'react';
import { api } from '../api';
import { useStore } from '../store';
import { TERM_THEMES } from '../termThemes';
import Modal from '../components/Modal';

export default function Settings() {
  const { user, setUser, toast } = useStore();
  const [hostkeys, setHostkeys] = useState([]);
  const [users, setUsers] = useState([]);
  const [totpSetup, setTotpSetup] = useState(null); // {qr, secret}
  const [totpCode, setTotpCode] = useState('');
  const [pwForm, setPwForm] = useState({ current: '', next: '', confirm: '' });
  const [newUser, setNewUser] = useState(null); // bool
  const [nuForm, setNuForm] = useState({ username: '', password: '', is_admin: false });
  const [expForm, setExpForm] = useState({ include: false, passphrase: '' });
  const [impPass, setImpPass] = useState('');
  const [fontSize, setFontSize] = useState(localStorage.getItem('ssloth.termFontSize') || '13');
  const [termTheme, setTermTheme] = useState(localStorage.getItem('ssloth.termTheme') || 'dark');
  const impFile = useRef(null);

  const loadHostkeys = () => api('/api/hosts/hostkeys').then((r) => setHostkeys(r.hostkeys)).catch(() => {});
  const loadUsers = () =>
    user?.is_admin && api('/api/admin/users').then((r) => setUsers(r.users)).catch(() => {});

  useEffect(() => {
    loadHostkeys();
    loadUsers();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.is_admin]);

  const changePw = async (e) => {
    e.preventDefault();
    if (pwForm.next !== pwForm.confirm) return toast('passwords do not match', 'error');
    try {
      await api('/api/auth/password', {
        method: 'POST',
        body: { current_password: pwForm.current, new_password: pwForm.next },
      });
      setPwForm({ current: '', next: '', confirm: '' });
      toast('password changed — other sessions signed out', 'success');
    } catch (e2) {
      toast(e2.message, 'error');
    }
  };

  const startTotp = async () => {
    const r = await api('/api/auth/totp/setup', { method: 'POST' });
    setTotpSetup(r);
    setTotpCode('');
  };

  const enableTotp = async () => {
    try {
      await api('/api/auth/totp/enable', { method: 'POST', body: { code: totpCode } });
      setTotpSetup(null);
      setUser({ ...user, totp_enabled: true });
      toast('two-factor enabled', 'success');
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  const disableTotp = async () => {
    const pw = prompt('confirm with your password');
    if (!pw) return;
    try {
      await api('/api/auth/totp/disable', { method: 'POST', body: { password: pw } });
      setUser({ ...user, totp_enabled: false });
      toast('two-factor disabled', 'success');
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  const removeHostkey = async (k) => {
    if (!confirm(`Forget trusted key for ${k.hostname}:${k.port}?`)) return;
    await api(`/api/hosts/hostkeys/${k.id}`, { method: 'DELETE' });
    loadHostkeys();
  };

  const createUser = async (e) => {
    e.preventDefault();
    try {
      await api('/api/admin/users', { method: 'POST', body: nuForm });
      setNewUser(false);
      setNuForm({ username: '', password: '', is_admin: false });
      loadUsers();
      toast('user created', 'success');
    } catch (e2) {
      toast(e2.message, 'error');
    }
  };

  const deleteUser = async (u) => {
    if (!confirm(`Delete user "${u.username}"? Their hosts, credentials and snippets are removed.`)) return;
    try {
      await api(`/api/admin/users/${u.id}`, { method: 'DELETE' });
      loadUsers();
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  const resetPw = async (u) => {
    const pw = prompt(`new password for ${u.username} (min 10 chars)`);
    if (!pw) return;
    try {
      await api(`/api/admin/users/${u.id}/password`, { method: 'POST', body: { password: pw } });
      toast('password reset', 'success');
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  const doExport = async () => {
    try {
      const r = await api('/api/vault/export', {
        method: 'POST',
        body: { include_credentials: expForm.include, passphrase: expForm.passphrase || undefined },
      });
      const blob = new Blob([JSON.stringify(r, null, 2)], { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `ssloth-export-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(a.href);
      toast('vault exported', 'success');
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  const doImport = async (e) => {
    const f = e.target.files?.[0];
    e.target.value = '';
    if (!f) return;
    try {
      const payload = JSON.parse(await f.text());
      const r = await api('/api/vault/import', {
        method: 'POST',
        body: { payload, passphrase: impPass || undefined },
      });
      const c = r.imported;
      toast(`imported ${c.hosts} hosts, ${c.credentials} credentials, ${c.snippets} snippets (${c.skipped} skipped)`, 'success');
    } catch (e2) {
      toast(e2.message, 'error');
    }
  };

  return (
    <div className="flex-1 overflow-y-auto p-6">
      <div className="max-w-3xl mx-auto space-y-6">
        <h1 className="text-lg font-semibold flex items-center gap-2">
          <SettingsIcon size={18} className="text-emerald-400" /> Settings
        </h1>

        {/* password */}
        <section className="card p-4">
          <h2 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <ShieldCheck size={15} className="text-emerald-400" /> Change password
          </h2>
          <form onSubmit={changePw} className="grid grid-cols-3 gap-3 items-end">
            <div>
              <label className="label">Current</label>
              <input className="input" type="password" autoComplete="current-password" value={pwForm.current} onChange={(e) => setPwForm((f) => ({ ...f, current: e.target.value }))} />
            </div>
            <div>
              <label className="label">New (min 10)</label>
              <input className="input" type="password" autoComplete="new-password" value={pwForm.next} onChange={(e) => setPwForm((f) => ({ ...f, next: e.target.value }))} />
            </div>
            <div>
              <label className="label">Confirm</label>
              <input className="input" type="password" autoComplete="new-password" value={pwForm.confirm} onChange={(e) => setPwForm((f) => ({ ...f, confirm: e.target.value }))} />
            </div>
            <div className="col-span-3 flex justify-end">
              <button className="btn-primary" disabled={!pwForm.current || pwForm.next.length < 10}>
                Update password
              </button>
            </div>
          </form>
        </section>

        {/* TOTP */}
        <section className="card p-4">
          <h2 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <Fingerprint size={15} className="text-emerald-400" /> Two-factor authentication
          </h2>
          {user?.totp_enabled ? (
            <div className="flex items-center justify-between">
              <p className="text-sm text-emerald-300">enabled — an authenticator code is required at login</p>
              <button className="btn-danger !py-1 text-xs" onClick={disableTotp}>
                disable
              </button>
            </div>
          ) : totpSetup ? (
            <div className="flex items-center gap-4">
              <img src={totpSetup.qr} alt="TOTP QR" className="rounded-md bg-white p-1" width="140" height="140" />
              <div className="flex-1 space-y-2">
                <p className="text-xs text-zinc-400">
                  scan with your authenticator app, or enter the secret manually:
                </p>
                <code className="block font-mono text-[11px] text-emerald-300 break-all bg-ink-900 rounded p-2 border border-ink-700">
                  {totpSetup.secret}
                </code>
                <div className="flex gap-2">
                  <input
                    className="input !w-32 font-mono tracking-widest"
                    placeholder="123456"
                    inputMode="numeric"
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value)}
                  />
                  <button className="btn-primary" onClick={enableTotp} disabled={totpCode.length !== 6}>
                    Verify & enable
                  </button>
                  <button className="btn-ghost" onClick={() => setTotpSetup(null)}>
                    Cancel
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex items-center justify-between">
              <p className="text-sm text-zinc-400">protect your account with a TOTP authenticator</p>
              <button className="btn-primary !py-1 text-xs" onClick={startTotp}>
                set up
              </button>
            </div>
          )}
        </section>

        {/* appearance */}
        <section className="card p-4">
          <h2 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <Palette size={15} className="text-emerald-400" /> Terminal appearance
          </h2>
          <div className="flex flex-wrap items-end gap-4">
            <div>
              <label className="label">Theme</label>
              <select
                className="input !w-48"
                value={termTheme}
                onChange={(e) => {
                  setTermTheme(e.target.value);
                  localStorage.setItem('ssloth.termTheme', e.target.value);
                }}
              >
                {Object.entries(TERM_THEMES).map(([k, v]) => (
                  <option key={k} value={k}>
                    {v.label}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="label">Font size</label>
              <select
                className="input !w-28"
                value={fontSize}
                onChange={(e) => {
                  setFontSize(e.target.value);
                  localStorage.setItem('ssloth.termFontSize', e.target.value);
                }}
              >
                {[11, 12, 13, 14, 15, 16, 18, 20].map((n) => (
                  <option key={n} value={n}>
                    {n}px
                  </option>
                ))}
              </select>
            </div>
            <p className="text-[11px] text-zinc-500 pb-1">applies to new sessions — reconnect open tabs to pick it up</p>
          </div>
        </section>

        {/* keyboard shortcuts */}
        <section className="card p-4">
          <h2 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <Keyboard size={15} className="text-emerald-400" /> Keyboard shortcuts
          </h2>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-1.5 text-xs text-zinc-400">
            <span><kbd className="kbd">Ctrl K</kbd> command palette</span>
            <span><kbd className="kbd">Ctrl Shift ]</kbd> next tab</span>
            <span><kbd className="kbd">Ctrl Shift [</kbd> prev tab</span>
            <span><kbd className="kbd">Ctrl Shift X</kbd> close tab</span>
            <span>select text = copy</span>
            <span>right-click = paste</span>
          </div>
        </section>

        {/* host keys */}
        <section className="card p-4">
          <h2 className="text-sm font-semibold mb-1 flex items-center gap-2">
            <Fingerprint size={15} className="text-emerald-400" /> Trusted host keys
          </h2>
          <p className="text-[11px] text-zinc-500 mb-3">
            ssloth pins the SSH host key on first connect (TOFU) and blocks the session if it ever changes.
          </p>
          <div className="divide-y divide-ink-700/50">
            {hostkeys.map((k) => (
              <div key={k.id} className="flex items-center gap-3 py-2">
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-mono text-zinc-200">
                    {k.hostname}:{k.port}
                  </div>
                  <div className="text-[11px] font-mono text-zinc-500 truncate">
                    {k.algorithm} {k.fingerprint}
                  </div>
                </div>
                <button className="btn-ghost !p-1.5 hover:text-red-400" onClick={() => removeHostkey(k)}>
                  <Trash2 size={13} />
                </button>
              </div>
            ))}
            {hostkeys.length === 0 && (
              <div className="py-4 text-center text-xs text-zinc-600">no trusted host keys yet</div>
            )}
          </div>
        </section>

        {/* vault backup */}
        <section className="card p-4">
          <h2 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <Download size={15} className="text-emerald-400" /> Vault export / import
          </h2>
          <div className="flex flex-wrap items-center gap-3">
            <label className="flex items-center gap-2 text-sm text-zinc-300">
              <input
                type="checkbox"
                className="accent-emerald-600"
                checked={expForm.include}
                onChange={(e) => setExpForm((f) => ({ ...f, include: e.target.checked }))}
              />
              include credentials &amp; keys
            </label>
            {expForm.include && (
              <input
                className="input !w-56"
                type="password"
                placeholder="export passphrase (min 8)"
                value={expForm.passphrase}
                onChange={(e) => setExpForm((f) => ({ ...f, passphrase: e.target.value }))}
              />
            )}
            <button className="btn-primary !py-1.5 text-xs" onClick={doExport}>
              <Download size={13} /> Export
            </button>
            <span className="text-zinc-600">|</span>
            <input
              className="input !w-56"
              type="password"
              placeholder="import passphrase (if sealed)"
              value={impPass}
              onChange={(e) => setImpPass(e.target.value)}
            />
            <button className="btn-ghost border border-ink-700 !py-1.5 text-xs" onClick={() => impFile.current?.click()}>
              <Upload size={13} /> Import file
            </button>
            <input ref={impFile} type="file" accept=".json" className="hidden" onChange={doImport} />
          </div>
          <p className="text-[11px] text-zinc-500 mt-2">
            secrets are sealed with your export passphrase (scrypt + AES-256-GCM) — the file alone can't be opened
            without it. imports skip duplicates by name.
          </p>
        </section>

        {/* users admin */}
        {user?.is_admin && (
          <section className="card p-4">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold flex items-center gap-2">
                <Users size={15} className="text-emerald-400" /> Users
              </h2>
              <button className="btn-ghost border border-ink-700 !py-1 text-xs" onClick={() => setNewUser(true)}>
                <Plus size={13} /> Add user
              </button>
            </div>
            <div className="divide-y divide-ink-700/50">
              {users.map((u) => (
                <div key={u.id} className="flex items-center gap-3 py-2">
                  <div className="flex-1">
                    <span className="text-sm text-zinc-200">{u.username}</span>
                    <span className="ml-2 text-[10px] text-zinc-500">
                      {u.is_admin ? 'admin' : 'user'}
                      {u.totp_enabled ? ' · 2fa' : ''}
                    </span>
                  </div>
                  <button className="btn-ghost !py-1 text-xs" onClick={() => resetPw(u)}>
                    reset pw
                  </button>
                  {u.id !== user.id && (
                    <button className="btn-ghost !p-1.5 hover:text-red-400" onClick={() => deleteUser(u)}>
                      <Trash2 size={13} />
                    </button>
                  )}
                </div>
              ))}
            </div>
          </section>
        )}
      </div>

      {newUser && (
        <Modal title="New user" onClose={() => setNewUser(false)}>
          <form onSubmit={createUser} className="space-y-3">
            <div>
              <label className="label">Username</label>
              <input className="input" value={nuForm.username} onChange={(e) => setNuForm((f) => ({ ...f, username: e.target.value }))} autoFocus />
            </div>
            <div>
              <label className="label">Password (min 10)</label>
              <input className="input" type="password" value={nuForm.password} onChange={(e) => setNuForm((f) => ({ ...f, password: e.target.value }))} />
            </div>
            <label className="flex items-center gap-2 text-sm text-zinc-300">
              <input
                type="checkbox"
                checked={nuForm.is_admin}
                onChange={(e) => setNuForm((f) => ({ ...f, is_admin: e.target.checked }))}
                className="accent-emerald-600"
              />
              administrator
            </label>
            <div className="flex justify-end gap-2">
              <button type="button" className="btn-ghost" onClick={() => setNewUser(false)}>
                Cancel
              </button>
              <button className="btn-primary" disabled={!nuForm.username || nuForm.password.length < 10}>
                Create
              </button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
}
