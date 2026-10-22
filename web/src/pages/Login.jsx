import React, { useState } from 'react';
import { ShieldCheck, Delete } from 'lucide-react';
import { api } from '../api';
import { useStore } from '../store';

function PinPad({ onUnlock }) {
  const [pin, setPin] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const { setUser } = useStore();

  const unlock = async (value) => {
    if (busy || value.length < 4) return;
    setBusy(true);
    setError('');
    try {
      const r = await api('/api/auth/pin', { method: 'POST', body: { pin: value } });
      setUser(r.user);
      onUnlock?.();
    } catch (e) {
      setError(e.message);
      setPin('');
    } finally {
      setBusy(false);
    }
  };

  const tap = (d) => {
    if (busy || pin.length >= 8) return;
    const next = pin + d;
    setPin(next);
    // Auto-submit only at the max length — firing at 4 would make longer
    // PINs impossible to type (the 4-digit prefix gets rejected first).
    if (next.length === 8) unlock(next);
  };

  return (
    <div className="card p-6 shadow-xl space-y-4">
      <h1 className="text-center text-sm font-medium text-zinc-300">enter PIN to unlock</h1>
      <div className="flex justify-center gap-2">
        {Array.from({ length: 8 }).map((_, i) => (
          <span
            key={i}
            className={`h-2.5 w-2.5 rounded-full transition-colors ${
              i < pin.length ? 'bg-emerald-400' : i < 4 ? 'bg-ink-700' : 'bg-ink-800/50'
            }`}
          />
        ))}
      </div>
      {error && (
        <div className="rounded-md border border-red-800 bg-red-950/60 px-3 py-2 text-xs text-red-300 text-center">
          {error}
        </div>
      )}
      <div className="grid grid-cols-3 gap-2 max-w-[220px] mx-auto">
        {[1, 2, 3, 4, 5, 6, 7, 8, 9].map((d) => (
          <button
            key={d}
            type="button"
            onClick={() => tap(d)}
            className="h-12 rounded-md bg-ink-800 text-zinc-200 text-lg font-medium hover:bg-ink-700 active:bg-ink-600 transition-colors"
          >
            {d}
          </button>
        ))}
        <button
          type="button"
          onClick={() => unlock(pin)}
          disabled={pin.length < 4 || busy}
          className="h-12 rounded-md bg-emerald-900/60 text-emerald-300 hover:bg-emerald-800/60 disabled:opacity-40 flex items-center justify-center"
        >
          ✓
        </button>
        <button
          type="button"
          onClick={() => tap(0)}
          className="h-12 rounded-md bg-ink-800 text-zinc-200 text-lg font-medium hover:bg-ink-700 active:bg-ink-600 transition-colors"
        >
          0
        </button>
        <button
          type="button"
          onClick={() => setPin((p) => p.slice(0, -1))}
          className="h-12 rounded-md bg-ink-800 text-zinc-400 hover:bg-ink-700 flex items-center justify-center"
        >
          <Delete size={18} />
        </button>
      </div>
      <p className="text-center text-[11px] text-zinc-600">4–8 digits — press ✓ (or it submits at 8)</p>
    </div>
  );
}

export default function Login({ setupMode }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [totp, setTotp] = useState('');
  const [needTotp, setNeedTotp] = useState(false);
  const [usePassword, setUsePassword] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const { setUser, toast } = useStore();
  const pinMode = useStore((s) => s.desktop && s.pinSet && !setupMode);

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
          <img src="/sloth.svg" alt="ssloth" className="w-11 h-11" />
          <span className="text-3xl font-bold tracking-tight text-zinc-100">ssloth</span>
        </div>

        {pinMode && !usePassword ? (
          <PinPad onUnlock={() => {}} />
        ) : (
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
        )}
        {pinMode && (
          <button
            className="mt-4 w-full text-center text-xs text-zinc-500 hover:text-zinc-300"
            onClick={() => setUsePassword((v) => !v)}
          >
            {usePassword ? 'use PIN instead' : 'use password instead'}
          </button>
        )}
      </div>
    </div>
  );
}
