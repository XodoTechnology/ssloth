import React, { useEffect, useState } from 'react';
import { api } from '../api';
import { useStore } from '../store';
import { Activity, EyeOff, Eye, BellRing, Plus, Trash2 } from 'lucide-react';
import Modal from '../components/Modal';
import { sensorTier } from '../lib/sensor-tier';

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
  const [detail, setDetail] = useState(null); // host object

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
          const bad = h.latest?.entries?.filter((e) => sensorTier(e.status) === 'bad');
          return (
            <div
              key={h.id}
              className="rounded-lg border border-ink-700 bg-ink-900 p-4 space-y-2 cursor-pointer hover:border-ink-500"
              onClick={() => h.latest && setDetail(h)}
            >
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-medium text-zinc-100">{h.name || h.hostname}</div>
                  <div className="text-xs text-zinc-500 font-mono">{h.hostname}</div>
                </div>
                <button
                  className="text-zinc-500 hover:text-zinc-300"
                  title={h.sensor_exclude ? 'include in sensor sweep' : 'exclude from sensor sweep'}
                  onClick={(e) => { e.stopPropagation(); toggle(h); }}
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
      {detail && <SensorDetail host={detail} onClose={() => setDetail(null)} />}
      <AlertRules hosts={data.hosts} />
    </div>
  );
}

// Sensor alert rules: notify (bell + webhook + audit) when a sensor's status
// tier crosses the floor — on the transition, not every poll.
function AlertRules({ hosts }) {
  const { toast } = useStore();
  const [rules, setRules] = useState([]);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ host_id: '', sensor: '', min_tier: 'bad' });

  const load = () => api('/api/notifications/rules').then((d) => setRules(d.rules || [])).catch(() => {});
  useEffect(load, []);

  const add = async () => {
    try {
      await api('/api/notifications/rules', {
        method: 'POST',
        body: { host_id: form.host_id || null, sensor: form.sensor, min_tier: form.min_tier },
      });
      setForm({ host_id: '', sensor: '', min_tier: 'bad' });
      setOpen(false);
      load();
      toast('alert rule added', 'success');
    } catch (e) { toast(e.message, 'error'); }
  };

  const toggle = async (r) => {
    await api(`/api/notifications/rules/${r.id}`, { method: 'PUT', body: { enabled: !r.enabled } }).catch(() => {});
    load();
  };
  const del = async (r) => {
    await api(`/api/notifications/rules/${r.id}`, { method: 'DELETE' }).catch(() => {});
    load();
  };

  const hostName = (id) => (id == null ? 'all BMC hosts' : (hosts.find((h) => h.id === id)?.name || hosts.find((h) => h.id === id)?.hostname || `#${id}`));

  return (
    <div className="rounded-lg border border-ink-700 bg-ink-900">
      <button className="flex w-full items-center gap-2 px-4 py-3 text-left" onClick={() => setOpen((o) => !o)}>
        <BellRing size={14} className="text-amber-300" />
        <span className="text-sm font-medium text-zinc-200">Sensor alerts</span>
        <span className="text-xs text-zinc-500">{rules.filter((r) => r.enabled).length} active</span>
        <span className="ml-auto text-zinc-500">{open ? '▾' : '▸'}</span>
      </button>
      {open && (
        <div className="border-t border-ink-800 px-4 py-3 space-y-3">
          {rules.length === 0 && <p className="text-xs text-zinc-500">no rules — alerts fire on status-tier crossings (warn/bad) into the bell, webhooks and audit log</p>}
          {rules.map((r) => (
            <div key={r.id} className="flex items-center gap-2 text-xs">
              <button
                className={`h-2 w-2 rounded-full ${r.enabled ? 'bg-emerald-400' : 'bg-zinc-600'}`}
                title={r.enabled ? 'enabled — click to pause' : 'paused — click to enable'}
                onClick={() => toggle(r)}
              />
              <span className="text-zinc-300">{r.min_tier === 'warn' ? 'warn+' : 'bad only'}</span>
              <span className="text-zinc-500">on</span>
              <span className="text-zinc-200 font-mono">{r.sensor || '*'}</span>
              <span className="text-zinc-500">@ {hostName(r.host_id)}</span>
              <button className="ml-auto text-zinc-600 hover:text-rose-400" onClick={() => del(r)}><Trash2 size={12} /></button>
            </div>
          ))}
          <div className="flex flex-wrap items-center gap-2 pt-1">
            <select className="input !w-auto text-xs" value={form.host_id} onChange={(e) => setForm({ ...form, host_id: e.target.value })}>
              <option value="">all hosts</option>
              {hosts.map((h) => <option key={h.id} value={h.id}>{h.name || h.hostname}</option>)}
            </select>
            <input className="input !w-40 text-xs font-mono" placeholder="sensor name contains…" value={form.sensor} onChange={(e) => setForm({ ...form, sensor: e.target.value })} />
            <select className="input !w-auto text-xs" value={form.min_tier} onChange={(e) => setForm({ ...form, min_tier: e.target.value })}>
              <option value="bad">bad only</option>
              <option value="warn">warn or worse</option>
            </select>
            <button className="btn-primary !px-2 !py-1 text-xs flex items-center gap-1" onClick={add} disabled={!form.sensor && !form.host_id}>
              <Plus size={12} /> add rule
            </button>
            <span className="text-[10px] text-zinc-600">empty sensor = every sensor; needs a name or a host</span>
          </div>
        </div>
      )}
    </div>
  );
}



function SensorDetail({ host, onClose }) {
  const entries = host.latest?.entries || [];
  const bad = entries.filter((e) => sensorTier(e.status) === 'bad');
  const warn = entries.filter((e) => sensorTier(e.status) === 'warn');
  const good = entries.filter((e) => ['ok', 'info'].includes(sensorTier(e.status)));
  return (
    <Modal title={`${host.name || host.hostname} — sensors`} onClose={onClose} wide>
      <div className="text-[11px] text-zinc-500 mb-2">
        {entries.length} sensors · {bad.length} outside normal ·
        sampled {host.latest ? new Date(host.latest.t).toLocaleTimeString() : '—'}
      </div>
      <div className="max-h-[60vh] overflow-auto rounded border border-ink-800">
        <table className="w-full text-[11px] font-mono">
          <tbody>
            {[...bad, ...warn, ...good].map((e, i) => {
              const t = sensorTier(e.status);
              return (
                <tr key={i} className="border-b border-ink-800/60">
                  {[e.name, e.reading, e.units, e.status, e.thresholds].map((c, j) => (
                    <td key={j}
                      className={`px-2 py-1 ${t === 'bad' ? 'text-rose-400' : t === 'warn' ? 'text-amber-300' : 'text-zinc-300'}`}>
                      {c}
                    </td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Modal>
  );
}
