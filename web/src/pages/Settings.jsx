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
  Lock,
  Webhook,
  KeySquare,
  Zap,
  Radar,
} from 'lucide-react';
import { useRef } from 'react';
import { api } from '../api';
import { useStore } from '../store';
import { TERM_THEMES } from '../termThemes';
import Modal from '../components/Modal';

export default function Settings() {
  const { user, setUser, toast } = useStore();
  const desktop = useStore((s) => s.desktop);
  const pinSet = useStore((s) => s.pinSet);
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
  const [pinForm, setPinForm] = useState({ pin: '', password: '' });
  const [idleMin, setIdleMin] = useState(localStorage.getItem('ssloth_idle_min') || '0');
  const [webhooks, setWebhooks] = useState([]);
  const [whForm, setWhForm] = useState({ url: '', events: '*' });
  const [tokens, setTokens] = useState([]);
  const [tokForm, setTokForm] = useState({ name: '', scopes: ['read'], expires_days: 90 });
  const [freshToken, setFreshToken] = useState(null);
  const [scanForm, setScanForm] = useState('');
  const [scanResults, setScanResults] = useState(null);
  const [scanning, setScanning] = useState(false);
  const impFile = useRef(null);

  const loadHostkeys = () => api('/api/hosts/hostkeys').then((r) => setHostkeys(r.hostkeys)).catch(() => {});
  const loadUsers = () =>
    user?.is_admin && api('/api/admin/users').then((r) => setUsers(r.users)).catch(() => {});
  const loadWebhooks = () => api('/api/webhooks').then((r) => setWebhooks(r.webhooks)).catch(() => {});
  const loadTokens = () => api('/api/tokens').then((r) => setTokens(r.tokens)).catch(() => {});

  useEffect(() => {
    loadHostkeys();
    loadUsers();
    loadWebhooks();
    loadTokens();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.is_admin]);

  const addWebhook = async (e) => {
    e.preventDefault();
    try {
      await api('/api/webhooks', { method: 'POST', body: whForm });
      setWhForm({ url: '', events: '*' });
      loadWebhooks();
      toast('webhook added', 'success');
    } catch (e2) {
      toast(e2.message, 'error');
    }
  };

  const toggleWebhook = async (w) => {
    await api(`/api/webhooks/${w.id}`, { method: 'PUT', body: { enabled: !w.enabled } });
    loadWebhooks();
  };

  const testWebhook = async (w) => {
    const r = await api(`/api/webhooks/${w.id}/test`, { method: 'POST' });
    toast(r.ok ? 'test delivered' : 'delivery failed — check the URL', r.ok ? 'success' : 'error');
  };

  const delWebhook = async (w) => {
    await api(`/api/webhooks/${w.id}`, { method: 'DELETE' });
    loadWebhooks();
  };

  const createToken = async (e) => {
    e.preventDefault();
    try {
      const r = await api('/api/tokens', { method: 'POST', body: tokForm });
      setFreshToken(r.token);
      setTokForm({ name: '', scopes: ['read'], expires_days: 90 });
      loadTokens();
    } catch (e2) {
      toast(e2.message, 'error');
    }
  };

  const revokeToken = async (t) => {
    if (!confirm(`Revoke token "${t.name}"? Requests using it will fail immediately.`)) return;
    await api(`/api/tokens/${t.id}`, { method: 'DELETE' });
    loadTokens();
  };

  // ssh-keyscan: paste "host[:port]" lines, scan, then trust.
  const runScan = async (trust) => {
    const targets = scanForm
      .split(/[\n,;]+/)
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => {
        const m = l.match(/^(.+?)(?::(\d+))?$/);
        return { hostname: m[1], port: m[2] ? parseInt(m[2], 10) : 22 };
      });
    if (!targets.length) return toast('enter host[:port] lines first', 'error');
    setScanning(true);
    try {
      const r = await api('/api/hosts/hostkeys/scan', { method: 'POST', body: { hosts: targets, trust } });
      setScanResults(r.results);
      if (trust) loadHostkeys();
    } catch (e2) {
      toast(e2.message, 'error');
    } finally {
      setScanning(false);
    }
  };

  const setRole = async (u, role) => {
    try {
      await api(`/api/admin/users/${u.id}/role`, { method: 'POST', body: { role } });
      loadUsers();
      toast(`${u.username} → ${role}`, 'success');
    } catch (e) {
      toast(e.message, 'error');
    }
  };

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

        {/* desktop quick PIN */}
        {desktop && (
          <section className="card p-4">
            <h2 className="text-sm font-semibold mb-1 flex items-center gap-2">
              <Lock size={15} className="text-emerald-400" /> Quick unlock PIN
            </h2>
            <p className="text-[11px] text-zinc-500 mb-3">
              {pinSet
                ? 'PIN required on app launch. Without it the app opens straight in.'
                : 'No PIN — the app opens straight into your sessions. Set one to lock it on launch.'}
            </p>
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                try {
                  await api(pinSet ? '/api/auth/pin/disable' : '/api/auth/pin/setup', {
                    method: 'POST',
                    body: pinForm,
                  });
                  useStore.setState({ pinSet: !pinSet });
                  setPinForm({ pin: '', password: '' });
                  toast(pinSet ? 'PIN removed' : 'PIN set — required on next launch', 'success');
                } catch (e2) {
                  toast(e2.message, 'error');
                }
              }}
              className="flex flex-wrap items-end gap-3"
            >
              {!pinSet && (
                <div>
                  <label className="label">New PIN (4-8 digits)</label>
                  <input
                    className="input !w-36 font-mono tracking-widest"
                    type="password"
                    inputMode="numeric"
                    maxLength={8}
                    value={pinForm.pin}
                    onChange={(e) => setPinForm((f) => ({ ...f, pin: e.target.value.replace(/\D/g, '') }))}
                  />
                </div>
              )}
              <div>
                <label className="label">Confirm with password</label>
                <input
                  className="input !w-48"
                  type="password"
                  autoComplete="current-password"
                  value={pinForm.password}
                  onChange={(e) => setPinForm((f) => ({ ...f, password: e.target.value }))}
                />
              </div>
              <button
                className={pinSet ? 'btn-danger !py-1.5 text-xs' : 'btn-primary !py-1.5 text-xs'}
                disabled={(!pinSet && !/^\d{4,8}$/.test(pinForm.pin)) || !pinForm.password}
              >
                {pinSet ? 'Remove PIN' : 'Set PIN'}
              </button>
            </form>
          </section>
        )}

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

          {/* ssh-keyscan: pre-seed trust before first connect */}
          <div className="mt-3 border-t border-ink-700/60 pt-3">
            <div className="flex items-center gap-2 text-xs text-zinc-400 mb-2">
              <Radar size={12} className="text-sky-400" /> ssh-keyscan — pre-seed trusted keys
            </div>
            <textarea
              className="input font-mono !text-[11px]"
              rows="2"
              placeholder={'one per line: host[:port]\n10.0.0.5\nprod-web-01:2222'}
              value={scanForm}
              onChange={(e) => setScanForm(e.target.value)}
            />
            <div className="flex gap-2 mt-2">
              <button className="btn-ghost border border-ink-700 !py-1 text-xs" onClick={() => runScan(false)} disabled={scanning || !scanForm.trim()}>
                {scanning ? '…' : 'scan (preview)'}
              </button>
              <button className="btn-primary !py-1 text-xs" onClick={() => runScan(true)} disabled={scanning || !scanForm.trim()}>
                scan & trust
              </button>
            </div>
            {scanResults && (
              <div className="mt-2 space-y-1">
                {scanResults.map((r, i) => (
                  <div key={i} className="flex items-center gap-2 text-[11px] font-mono rounded bg-ink-900 border border-ink-700 px-2 py-1.5">
                    <span className={`h-1.5 w-1.5 rounded-full shrink-0 ${r.ok ? (r.changed ? 'bg-red-500' : 'bg-emerald-500') : 'bg-zinc-600'}`} />
                    <span className="text-zinc-300">{r.hostname}:{r.port}</span>
                    {r.ok ? (
                      <>
                        <span className="text-zinc-500 truncate">{r.algorithm} {r.fingerprint}</span>
                        {r.changed && <span className="text-red-400 font-semibold shrink-0">KEY CHANGED — was {r.already_trusted ? 'trusted' : 'unknown'}</span>}
                        {!r.changed && r.already_trusted && <span className="text-zinc-600 shrink-0">already trusted</span>}
                        {r.trusted && <span className="text-emerald-400 shrink-0">trusted</span>}
                      </>
                    ) : (
                      <span className="text-zinc-600">{r.error}</span>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>

        {/* idle auto-lock */}
        <section className="card p-4">
          <h2 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <Lock size={15} className="text-emerald-400" /> Idle auto-lock
          </h2>
          <div className="flex items-center gap-3">
            <select
              className="input !w-48"
              value={idleMin}
              onChange={(e) => {
                setIdleMin(e.target.value);
                localStorage.setItem('ssloth_idle_min', e.target.value);
                toast(e.target.value === '0' ? 'auto-lock off' : `locks after ${e.target.value} min idle`, 'success');
              }}
            >
              <option value="0">Off</option>
              <option value="5">5 minutes</option>
              <option value="15">15 minutes</option>
              <option value="30">30 minutes</option>
              <option value="60">1 hour</option>
            </select>
            <span className="text-[11px] text-zinc-500">
              locks the screen after inactivity — SSH sessions keep running; unlock with
              {desktop && pinSet ? ' your PIN or ' : ' '}account password
            </span>
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

        {/* webhooks */}
        <section className="card p-4">
          <h2 className="text-sm font-semibold mb-1 flex items-center gap-2">
            <Webhook size={15} className="text-emerald-400" /> Webhook notifications
          </h2>
          <p className="text-[11px] text-zinc-500 mb-3">
            POSTed on host down/up, playbook runs finishing, etc. Slack, Discord and ntfy.sh payloads are detected
            automatically; anything else gets <code className="font-mono">{'{event, message, ts}'}</code>.
          </p>
          <form onSubmit={addWebhook} className="flex flex-wrap items-end gap-3 mb-3">
            <div className="flex-1 min-w-48">
              <label className="label">URL</label>
              <input
                className="input font-mono !text-xs"
                placeholder="https://ntfy.sh/my-topic or a slack/discord webhook"
                value={whForm.url}
                onChange={(e) => setWhForm((f) => ({ ...f, url: e.target.value }))}
              />
            </div>
            <div className="w-44">
              <label className="label">Events</label>
              <input
                className="input font-mono !text-xs"
                placeholder="* or host.down,playbook.done"
                value={whForm.events}
                onChange={(e) => setWhForm((f) => ({ ...f, events: e.target.value }))}
              />
            </div>
            <button className="btn-primary !py-1.5 text-xs" disabled={!whForm.url.trim()}>
              <Plus size={13} /> Add
            </button>
          </form>
          <div className="divide-y divide-ink-700/50">
            {webhooks.map((w) => (
              <div key={w.id} className="flex items-center gap-3 py-2">
                <button
                  className={`h-2 w-2 rounded-full shrink-0 ${w.enabled ? 'bg-emerald-500' : 'bg-zinc-600'}`}
                  title={w.enabled ? 'enabled — click to disable' : 'disabled — click to enable'}
                  onClick={() => toggleWebhook(w)}
                />
                <div className="min-w-0 flex-1">
                  <div className="text-[12px] font-mono text-zinc-200 truncate">{w.url}</div>
                  <div className="text-[10px] font-mono text-zinc-500">{w.events}</div>
                </div>
                <button className="btn-ghost !p-1.5" title="send a test" onClick={() => testWebhook(w)}>
                  <Zap size={13} />
                </button>
                <button className="btn-ghost !p-1.5 hover:text-red-400" onClick={() => delWebhook(w)}>
                  <Trash2 size={13} />
                </button>
              </div>
            ))}
            {webhooks.length === 0 && (
              <div className="py-3 text-center text-xs text-zinc-600">no webhooks configured</div>
            )}
          </div>
        </section>

        {/* API tokens */}
        <section className="card p-4">
          <h2 className="text-sm font-semibold mb-1 flex items-center gap-2">
            <KeySquare size={15} className="text-emerald-400" /> API tokens
          </h2>
          <p className="text-[11px] text-zinc-500 mb-3">
            Scoped bearer tokens for scripts: <code className="font-mono">Authorization: Bearer slo_…</code>. Shown
            once at creation.
          </p>
          <form onSubmit={createToken} className="flex flex-wrap items-end gap-3 mb-3">
            <div>
              <label className="label">Name</label>
              <input
                className="input !w-44"
                placeholder="ci-nightly"
                value={tokForm.name}
                onChange={(e) => setTokForm((f) => ({ ...f, name: e.target.value }))}
              />
            </div>
            <div>
              <label className="label">Scopes</label>
              <div className="flex gap-3 text-xs text-zinc-300 items-center h-9">
                {[['read', 'read'], ['playbooks:run', 'run playbooks'], ['vault', 'vault export']].map(([v, l]) => (
                  <label key={v} className="flex items-center gap-1.5 cursor-pointer">
                    <input
                      type="checkbox"
                      className="accent-emerald-600"
                      checked={tokForm.scopes.includes(v)}
                      onChange={(e) =>
                        setTokForm((f) => ({
                          ...f,
                          scopes: e.target.checked ? [...f.scopes, v] : f.scopes.filter((s) => s !== v),
                        }))
                      }
                    />
                    {l}
                  </label>
                ))}
              </div>
            </div>
            <div>
              <label className="label">Expires</label>
              <select
                className="input !w-28"
                value={tokForm.expires_days}
                onChange={(e) => setTokForm((f) => ({ ...f, expires_days: parseInt(e.target.value, 10) }))}
              >
                <option value={30}>30 days</option>
                <option value={90}>90 days</option>
                <option value={365}>1 year</option>
                <option value={0}>never</option>
              </select>
            </div>
            <button className="btn-primary !py-1.5 text-xs" disabled={!tokForm.name.trim() || !tokForm.scopes.length}>
              <Plus size={13} /> Create
            </button>
          </form>
          {freshToken && (
            <div className="mb-3 rounded-md border border-emerald-800 bg-emerald-950/40 p-2.5 space-y-1">
              <div className="text-[11px] text-emerald-300 font-medium">token created — copy it now, it won't be shown again</div>
              <code className="block font-mono text-[11px] text-emerald-200 break-all">{freshToken}</code>
            </div>
          )}
          <div className="divide-y divide-ink-700/50">
            {tokens.map((t) => (
              <div key={t.id} className="flex items-center gap-3 py-2">
                <div className="min-w-0 flex-1">
                  <div className="text-sm text-zinc-200">{t.name}</div>
                  <div className="text-[10px] font-mono text-zinc-500">
                    {t.scopes.join(' ')}
                    {t.last_used ? ` · last used ${new Date(t.last_used).toLocaleDateString()}` : ' · never used'}
                    {t.expires_at ? ` · expires ${new Date(t.expires_at).toLocaleDateString()}` : ' · no expiry'}
                  </div>
                </div>
                <button className="btn-ghost !p-1.5 hover:text-red-400" onClick={() => revokeToken(t)}>
                  <Trash2 size={13} />
                </button>
              </div>
            ))}
            {tokens.length === 0 && (
              <div className="py-3 text-center text-xs text-zinc-600">no API tokens</div>
            )}
          </div>
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
                      {u.totp_enabled ? '2fa' : ''}
                    </span>
                  </div>
                  {u.id !== user.id ? (
                    <select
                      className="input !w-24 !py-1 !text-[11px]"
                      value={u.role || (u.is_admin ? 'admin' : 'user')}
                      onChange={(e) => setRole(u, e.target.value)}
                      title="admin: full access · user: normal · viewer: read-only"
                    >
                      <option value="admin">admin</option>
                      <option value="user">user</option>
                      <option value="viewer">viewer</option>
                    </select>
                  ) : (
                    <span className="text-[10px] uppercase font-semibold text-emerald-400 px-1">{u.role || 'admin'}</span>
                  )}
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
            <div>
              <label className="label">Role</label>
              <select
                className="input"
                value={nuForm.is_admin ? 'admin' : nuForm.role || 'user'}
                onChange={(e) =>
                  setNuForm((f) => ({ ...f, is_admin: e.target.value === 'admin', role: e.target.value }))
                }
              >
                <option value="user">user — normal access</option>
                <option value="viewer">viewer — read-only</option>
                <option value="admin">admin — full access</option>
              </select>
            </div>
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
