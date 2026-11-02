import React, { useEffect, useState } from 'react';
import { api } from '../api';
import { useStore } from '../store';
import { Activity, EyeOff, Eye } from 'lucide-react';

const KEY_CHIP = {
  ok: 'text-emerald-400',
  changed: 'text-rose-400',
  untrusted: 'text-amber-400',
  unreachable: 'text-zinc-500',
};

export default function BmcDashboard() {
  const { toast } = useStore();
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  const load = () =>
    api('/api/bmc/overview').then(setData).catch((e) => setError(e.message));

  useEffect(() => {
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, []);

  const toggle = async (h) => {
    try {
      await api(`/api/hosts/${h.id}`, {
        method: 'PUT',
        body: { sensor_exclude: h.sensor_exclude ? 0 : 1 },
      });
      setData((d) => ({
        ...d,
        hosts: d.hosts.map((x) => (x.id === h.id ? { ...x, sensor_exclude: !x.sensor_exclude } : x)),
      }));
      toast(`${h.sensor_exclude ? 'Included' : 'Excluded'} ${h.name || h.hostname}`, 'success');
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  if (error) return <div className="p-6 text-rose-400">{error}</div>;
  if (!data) return <div className="p-6 text-zinc-500">loading BMC overview…</div>;
  if (!data.hosts.length)
    return <div className="p-6 text-zinc-500">No BMC hosts yet — add one with protocol “BMC”.</div>;

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center gap-2">
        <Activity size={18} className="text-emerald-400" />
        <h1 className="text-lg font-semibold text-zinc-100">BMC dashboard</h1>
        <span className="text-xs text-zinc-500">{data.hosts.length} host{data.hosts.length === 1 ? '' : 's'}</span>
      </div>
      {data.bmc_available === false && (
        <p className="text-sm text-rose-400">native bmc addon not loaded — sensor sweeps can't run</p>
      )}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
        {data.hosts.map((h) => {
          const power = h.latest?.entries?.find((e) => /^Power/i.test(e.name));
          const bad = h.latest?.entries?.filter((e) => !/^(ok|on|completed|operable)$/i.test(e.status || ''));
          return (
            <div key={h.id} className="rounded-lg border border-ink-700 bg-ink-900 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-medium text-zinc-100">{h.name || h.hostname}</div>
                  <div className="text-xs text-zinc-500 font-mono">{h.hostname}</div>
                </div>
                <button
                  className="text-zinc-500 hover:text-zinc-300"
                  title={h.sensor_exclude ? 'include in sensor sweep' : 'exclude from sensor sweep'}
                  onClick={() => toggle(h)}
                >
                  {h.sensor_exclude ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
              <div className="flex flex-wrap gap-2 text-[11px]">
                {h.hostkey_status && h.hostkey_status !== 'ok' && (
                  <span className={KEY_CHIP[h.hostkey_status] || 'text-zinc-500'}>
                    key {h.hostkey_status}
                  </span>
                )}
                {h.sensor_exclude && <span className="text-zinc-500">monitoring off</span>}
                {!h.latest && !h.sensor_exclude && !h.sweep_error && (
                  <span className="text-zinc-600">no samples yet</span>
                )}
                {!h.latest && h.sweep_error && (
                  <span className="text-rose-400" title={h.sweep_error}>
                    sweep: {h.sweep_error}
                  </span>
                )}
                {h.latest && (
                  <span className="text-zinc-500">
                    {new Date(h.latest.t).toLocaleTimeString()} · {h.latest.entries.length} sensors
                    {h.latest.warnings?.length ? ' · warnings' : ''}
                  </span>
                )}
              </div>
              {power && (
                <div className="text-2xl font-semibold text-emerald-400">
                  {power.reading}
                  <span className="text-xs text-zinc-500 font-normal ml-1">{power.units}</span>
                </div>
              )}
              {bad?.length > 0 && (
                <p className="text-[11px] text-amber-400">
                  {bad.length} sensor{bad.length === 1 ? '' : 's'} outside normal
                </p>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
