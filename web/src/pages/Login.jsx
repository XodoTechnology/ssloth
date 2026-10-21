import React, { useState } from 'react';
import { Terminal, ShieldCheck } from 'lucide-react';
import { api } from '../api';
import { useStore } from '../store';

export default function Login({ setupMode }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [totp, setTotp] = useState('');
  const [needTotp, setNeedTotp] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const { setUser, toast } = useStore();

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      const path = setupMode ? '/api/auth/setup' : '/api/auth/login';
      const body = setupMode ? { username, password } : { username, password, totp: totp || undefined };
      const r = await api(path, { method: 'POST', body });
      useStore.setState({ setupRequired: false });
      setUser(r.user);
      toast(setupMode ? 'admin account created' : `welcome back, ${r.user.username}`, 'success');
    } catch (e) {
      if (e.totp_required) setNeedTotp(true);
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="h-full flex items-center justify-center bg-ink-950 p-4">
      <div className="w-full max-w-sm">
        <div className="flex items-center justify-center gap-2.5 mb-8">
          <span className="text-emerald-400">
            <Terminal size={30} />
          </span>
          <span className="text-3xl font-bold tracking-tight text-zinc-100">ssloth</span>
        </div>

        <form onSubmit={submit} className="card p-6 space-y-4 shadow-xl">
          <h1 className="text-center text-sm font-medium text-zinc-300">
            {setupMode ? 'create the first admin account' : 'sign in'}
          </h1>
          <div>
            <label className="label">Username</label>
            <input
              className="input"
              autoFocus
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </div>
          <div>
            <label className="label">Password {setupMode && <span className="text-zinc-600">(min 10 chars)</span>}</label>
            <input
              className="input"
              type="password"
              autoComplete={setupMode ? 'new-password' : 'current-password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          {needTotp && !setupMode && (
            <div>
              <label className="label">Authenticator code</label>
              <input
                className="input font-mono tracking-widest"
                inputMode="numeric"
                placeholder="123456"
                autoFocus
                value={totp}
                onChange={(e) => setTotp(e.target.value)}
              />
            </div>
          )}
          {error && (
            <div className="rounded-md border border-red-800 bg-red-950/60 px-3 py-2 text-xs text-red-300">
              {error}
            </div>
          )}
          <button className="btn-primary w-full justify-center" disabled={busy || !username || !password}>
            {busy ? '…' : setupMode ? 'Create account' : 'Sign in'}
          </button>
          <div className="flex items-center justify-center gap-1.5 text-[11px] text-zinc-600">
            <ShieldCheck size={12} /> credentials stay encrypted on this server
          </div>
        </form>
      </div>
    </div>
  );
}
