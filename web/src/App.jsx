import React, { useEffect, useState } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { api } from './api';
import { useStore } from './store';
import Layout from './components/Layout';
import Toasts from './components/Toasts';
import Login from './pages/Login';
import Sessions from './pages/Sessions';
import Vault from './pages/Vault';
import Snippets from './pages/Snippets';
import Tunnels from './pages/Tunnels';
import Settings from './pages/Settings';
import Audit from './pages/Audit';

export default function App() {
  const { booted, setupRequired, user, setUser } = useStore();
  const [error, setError] = useState(null);

  useEffect(() => {
    api('/api/auth/state')
      .then((s) => {
        useStore.setState({ setupRequired: s.setup_required, booted: true });
        setUser(s.authenticated ? s.user : null);
      })
      .catch((e) => setError(e.message));
  }, []);

  if (error) {
    return (
      <div className="h-full flex items-center justify-center text-zinc-400">
        failed to reach server: {error}
      </div>
    );
  }
  if (!booted) {
    return (
      <div className="h-full flex items-center justify-center text-zinc-500">
        <span className="animate-pulse">loading ssloth…</span>
      </div>
    );
  }
  if (setupRequired || !user) {
    return (
      <>
        <Login setupMode={setupRequired} />
        <Toasts />
      </>
    );
  }

  return (
    <>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Sessions />} />
          <Route path="/vault" element={<Vault />} />
          <Route path="/snippets" element={<Snippets />} />
          <Route path="/tunnels" element={<Tunnels />} />
          <Route path="/audit" element={<Audit />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
      <Toasts />
    </>
  );
}
