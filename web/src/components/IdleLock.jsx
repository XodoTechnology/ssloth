import React, { useEffect, useRef, useState } from 'react';
import { Lock } from 'lucide-react';
import { api } from '../api';
import { useStore } from '../store';

// Idle auto-lock: after N minutes without input (setting lives in
// localStorage 'ssloth_idle_min', 0 = off), the UI covers with a lock
// screen. SSH sessions keep running server-side underneath — this only
// shields the screen. Unlock = account password, or PIN on desktop builds.
export default function IdleLock() {
  const locked = useStore((s) => s.locked);
  const setLocked = useStore((s) => s.setLocked);
  const desktop = useStore((s) => s.desktop);
  const pinSet = useStore((s) => s.pinSet);
  const user = useStore((s) => s.user);
  const setUser = useStore((s) => s.setUser);
  const [mode, setMode] = useState('auto'); // 'pin' | 'password'
  const [pin, setPin] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const pinRef = useRef(null);

  // activity tracker runs regardless of lock state
  useEffect(() => {
    let timer = null;
    const arm = () => {
      clearTimeout(timer);
      const mins = parseInt(localStorage.getItem('ssloth_idle_min') || '0', 10);
      if (!mins || useStore.getState().locked) return;
      timer = setTimeout(() => useStore.getState().setLocked(true), mins * 60000);
    };
    const events = ['mousemove', 'mousedown', 'keydown', 'wheel', 'touchstart', 'scroll'];
    events.forEach((e) => window.addEventListener(e, arm, { passive: true }));
    arm();
    // re-arm when settings change or lock engages/disengages
    const iv = setInterval(arm, 15000);
    return () => {
      clearTimeout(timer);
      clearInterval(iv);
      events.forEach((e) => window.removeEventListener(e, arm));
    };
  }, []);

  const usePin = desktop && pinSet && mode === 'pin';

  useEffect(() => {
    setMode(desktop && pinSet ? 'pin' : 'password');
    setError('');
    setPin('');
    setPassword('');
  }, [locked, desktop, pinSet]);

  const unlockPassword = async (e) => {
    e?.preventDefault();
    setBusy(true);
    setError('');
    try {
      await api('/api/auth/verify', { method: 'POST', body: { password } });
      setLocked(false);
    } catch (e2) {
      if (/401|unauthorized/i.test(e2.message)) {
        setUser(null); // session expired — back to full login
      } else {
        setError(e2.message);
      }
    } finally {
      setBusy(false);
      setPassword('');
    }
  };

  const unlockPin = async (digits) => {
    setBusy(true);
    setError('');
    try {
      await api('/api/auth/pin', { method: 'POST', body: { pin: digits } });
      setLocked(false);
    } catch (e2) {
      setError(e2.message);
      setPin('');
    } finally {
      setBusy(false);
    }
  };

  const onPinKey = (k) => {
    if (busy) return;
    if (k === 'back') return setPin((p) => p.slice(0, -1));
    if (k === 'ok') return pin.length >= 4 && unlockPin(pin);
    if (pin.length >= 8) return;
    const next = pin + k;
    setPin(next);
    // Auto-submit only at the max length — firing at 4 would make longer
    // PINs impossible to type.
    if (next.length === 8) unlockPin(next);
  };

  if (!locked) return null;

  return (
    <div className="fixed inset-0 z-[90] flex items-center justify-center bg-ink-950/95 backdrop-blur">
      <div className="w-80 card p-6 space-y-4 text-center">
        <div className="flex flex-col items-center gap-2">
          <img src="/sloth.svg" alt="" className="w-9 h-9" />
          <div className="font-bold text-zinc-100">ssloth</div>
          <div className="flex items-center gap-1.5 text-xs text-zinc-500">
            <Lock size={12} /> locked — sessions keep running
          </div>
        </div>

        {usePin ? (
          <div className="space-y-3">
            <div className="flex justify-center gap-2">
              {Array.from({ length: 8 }, (_, i) => (
                <span
                  key={i}
                  className={`h-2.5 w-2.5 rounded-full ${i < pin.length ? 'bg-emerald-400' : 'bg-ink-700'}`}
                />
              ))}
            </div>
            <div className="grid grid-cols-3 gap-2">
              {['1', '2', '3', '4', '5', '6', '7', '8', '9', 'back', '0', 'ok'].map((k) => (
                <button
                  key={k}
                  type="button"
                  className={`!py-2 text-sm font-mono ${
                    k === 'ok'
                      ? 'bg-emerald-900/60 text-emerald-300 hover:bg-emerald-800/60 rounded-md disabled:opacity-40'
                      : 'btn-ghost border border-ink-700'
                  }`}
                  disabled={k === 'ok' && pin.length < 4}
                  onClick={() => onPinKey(k)}
                >
                  {k === 'back' ? '⌫' : k === 'ok' ? '✓' : k}
                </button>
              ))}
            </div>
            <div className="text-[10px] text-zinc-600">4–8 digits — press ✓ (submits at 8)</div>
            <button className="text-[11px] text-zinc-500 hover:text-zinc-300" onClick={() => setMode('password')}>
              use password instead
            </button>
          </div>
        ) : (
          <form onSubmit={unlockPassword} className="space-y-3">
            <input
              className="input text-center"
              type="password"
              autoFocus
              autoComplete="off"
              placeholder={`${user?.username || 'account'} password`}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <button className="btn-primary w-full justify-center" disabled={busy || !password}>
              {busy ? '…' : 'Unlock'}
            </button>
            {desktop && pinSet && (
              <button type="button" className="text-[11px] text-zinc-500 hover:text-zinc-300" onClick={() => setMode('pin')}>
                use PIN instead
              </button>
            )}
          </form>
        )}

        {error && <div className="text-xs text-red-400">{error}</div>}
        <div className="text-[10px] text-zinc-600">signed in as {user?.username}</div>
      </div>
    </div>
  );
}
