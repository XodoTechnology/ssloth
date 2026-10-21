import React, { useEffect, useState } from 'react';
import { ArrowRightLeft, Plus, Play, Square, Trash2 } from 'lucide-react';
import { api } from '../api';
import { useStore } from '../store';
import Modal from '../components/Modal';

export default function Tunnels() {
  const { tunnels, hosts, refreshAll, toast } = useStore();
  const [modal, setModal] = useState(false);
  const [busyId, setBusyId] = useState(null);

  useEffect(() => {
    refreshAll(api).catch((e) => toast(e.message, 'error'));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const toggle = async (t) => {
    setBusyId(t.id);
    try {
      await api(`/api/tunnels/${t.id}/${t.active ? 'stop' : 'start'}`, { method: 'POST' });
      await refreshAll(api);
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      setBusyId(null);
    }
  };

  const del = async (t) => {
    if (!confirm(`Delete tunnel "${t.name}"?`)) return;
    await api(`/api/tunnels/${t.id}`, { method: 'DELETE' });
    refreshAll(api);
  };

  const hostName = (id) => hosts.find((h) => h.id === id)?.name || `#${id}`;

  return (
    <div className="flex-1 overflow-y-auto p-6">
      <div className="max-w-4xl mx-auto space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-lg font-semibold flex items-center gap-2">
            <ArrowRightLeft size={18} className="text-emerald-400" /> Tunnels
          </h1>
          <button className="btn-primary" onClick={() => setModal(true)} disabled={hosts.length === 0}>
            <Plus size={14} /> New tunnel
          </button>
        </div>
        <p className="text-xs text-zinc-500">
          Local port forwards through your SSH hosts. The listening port is opened on the ssloth server — browse to it
          from wherever you run ssloth.
        </p>

        <div className="card divide-y divide-ink-700/60">
          {tunnels.map((t) => (
            <div key={t.id} className="flex items-center gap-3 px-4 py-3">
              <span className={`h-2 w-2 rounded-full ${t.active ? 'bg-emerald-500' : 'bg-zinc-600'}`} />
              <div className="min-w-0 flex-1">
                <div className="text-sm text-zinc-100">
                  {t.name}
                  {t.type === 'dynamic' && (
                    <span className="ml-2 text-[9px] font-bold uppercase px-1.5 py-0.5 rounded bg-sky-950 text-sky-300">
                      socks5
                    </span>
                  )}
                </div>
                <div className="font-mono text-[11px] text-zinc-500">
                  {t.type === 'dynamic'
                    ? `${t.bind_address}:${t.local_port} → dynamic via ${hostName(t.host_id)}`
                    : `${t.bind_address}:${t.local_port} → ${t.remote_host}:${t.remote_port} via ${hostName(t.host_id)}`}
                </div>
              </div>
              <button
                className={t.active ? 'btn-danger !py-1 text-xs' : 'btn-primary !py-1 text-xs'}
                disabled={busyId === t.id}
                onClick={() => toggle(t)}
              >
                {t.active ? <Square size={12} /> : <Play size={12} />}
                {busyId === t.id ? '…' : t.active ? 'stop' : 'start'}
              </button>
              <button className="btn-ghost !p-1.5 hover:text-red-400" onClick={() => del(t)}>
                <Trash2 size={14} />
              </button>
            </div>
          ))}
          {tunnels.length === 0 && (
            <div className="px-4 py-10 text-center text-sm text-zinc-600">
              no tunnels — {hosts.length === 0 ? 'add a host first' : 'create a local forward'}
            </div>
          )}
        </div>
      </div>

      {modal && <TunnelModal onClose={() => setModal(false)} />}
    </div>
  );
}

function TunnelModal({ onClose }) {
  const { hosts, refreshAll, toast } = useStore();
  const [form, setForm] = useState({
    name: '',
    type: 'local',
    host_id: hosts[0]?.id || '',
    bind_address: '127.0.0.1',
    local_port: '',
    remote_host: '127.0.0.1',
    remote_port: '',
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));

  const save = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      await api('/api/tunnels', {
        method: 'POST',
        body: {
          name: form.name,
          type: form.type,
          host_id: parseInt(form.host_id, 10),
          bind_address: form.bind_address,
          local_port: parseInt(form.local_port, 10),
          remote_host: form.remote_host,
          remote_port: parseInt(form.remote_port, 10) || 0,
        },
      });
      toast('tunnel created', 'success');
      refreshAll(api);
      onClose();
    } catch (e2) {
      setError(e2.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal title="New tunnel" onClose={onClose}>
      <form onSubmit={save} className="space-y-3">
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="label">Name</label>
            <input className="input" value={form.name} onChange={set('name')} placeholder="grafana on prod" autoFocus />
          </div>
          <div>
            <label className="label">Type</label>
            <select className="input" value={form.type} onChange={set('type')}>
              <option value="local">Local forward</option>
              <option value="dynamic">SOCKS5 proxy (dynamic)</option>
            </select>
          </div>
        </div>
        <div>
          <label className="label">Through host</label>
          <select className="input" value={form.host_id} onChange={set('host_id')}>
            {hosts.map((h) => (
              <option key={h.id} value={h.id}>
                {h.name}
              </option>
            ))}
          </select>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="label">Bind address</label>
            <input className="input font-mono" value={form.bind_address} onChange={set('bind_address')} />
          </div>
          <div>
            <label className="label">Local port</label>
            <input className="input font-mono" type="number" value={form.local_port} onChange={set('local_port')} placeholder="3000" />
          </div>
        </div>
        {form.type === 'local' ? (
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="label">Remote host</label>
              <input className="input font-mono" value={form.remote_host} onChange={set('remote_host')} placeholder="127.0.0.1" />
            </div>
            <div>
              <label className="label">Remote port</label>
              <input className="input font-mono" type="number" value={form.remote_port} onChange={set('remote_port')} placeholder="3000" />
            </div>
          </div>
        ) : (
          <p className="text-[11px] text-zinc-400 rounded-md border border-sky-900 bg-sky-950/40 px-3 py-2">
            SOCKS5: point your browser/app's proxy at {form.bind_address || '127.0.0.1'}:{form.local_port || 'PORT'} —
            all requests dial out through {hosts.find((h) => h.id === +form.host_id)?.name || 'the host'}.
          </p>
        )}
        <p className="text-[11px] text-zinc-500">
          keep the bind address on 127.0.0.1 unless you intentionally want the tunnel reachable by other machines.
        </p>
        {error && (
          <div className="rounded-md border border-red-800 bg-red-950/60 px-3 py-2 text-xs text-red-300">{error}</div>
        )}
        <div className="flex justify-end gap-2">
          <button type="button" className="btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn-primary"
            disabled={
              busy ||
              !form.name ||
              !form.host_id ||
              !form.local_port ||
              (form.type === 'local' && (!form.remote_port || !form.remote_host))
            }
          >
            {busy ? '…' : 'Create'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
