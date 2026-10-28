import React, { useState } from 'react';
import Modal from './Modal';
import { api } from '../api';
import { useStore } from '../store';

const COLORS = ['', 'emerald', 'sky', 'amber', 'rose', 'violet'];
const COLOR_DOT = {
  '': 'bg-zinc-600',
  emerald: 'bg-emerald-500',
  sky: 'bg-sky-500',
  amber: 'bg-amber-500',
  rose: 'bg-rose-500',
  violet: 'bg-violet-500',
};

export default function HostForm({ host, onClose, onSaved }) {
  const { credentials, toast, hosts } = useStore();
  const [form, setForm] = useState({
    name: host?.name || '',
    hostname: host?.hostname || '',
    port: host?.port || 22,
    username: host?.username || '',
    protocol: host?.protocol || 'ssh',
    mac: host?.mac || '',
    agent_forward: !!host?.agent_forward,
    auth_type: host?.auth_type || 'credential',
    credential_id: host?.credential_id || '',
    jump_host_id: host?.jump_host_id || '',
    record: !!host?.record,
    shared: !!host?.shared,
    password: '',
    folder: host?.folder || '',
    region: host?.region || '',
    tags: host?.tags || '',
    color: host?.color || '',
    notes: host?.notes || '',
    keepalive: host?.keepalive ?? 15,
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target?.value ?? e }));

  const save = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      const body = {
        name: form.name,
        hostname: form.hostname,
        port: parseInt(form.port, 10) || (form.protocol === 'telnet' ? 23 : 22),
        username: form.username,
        protocol: form.protocol,
        mac: form.mac,
        agent_forward: form.protocol === 'ssh' && !!form.agent_forward,
        auth_type: form.auth_type,
        credential_id: form.auth_type === 'credential' ? parseInt(form.credential_id, 10) || null : null,
        jump_host_id: form.jump_host_id ? parseInt(form.jump_host_id, 10) : null,
        record: !!form.record,
        shared: !!form.shared,
        folder: form.folder,
        region: form.region,
        tags: form.tags,
        color: form.color,
        notes: form.notes,
        keepalive: parseInt(form.keepalive, 10) || 0,
      };
      if (form.auth_type === 'password' && form.password) body.password = form.password;
      if (host?.id) {
        await api(`/api/hosts/${host.id}`, { method: 'PUT', body });
        toast('host updated', 'success');
      } else {
        if (form.auth_type === 'password' && !form.password) {
          throw new Error('password required for password auth (or pick "ask")');
        }
        await api('/api/hosts', { method: 'POST', body });
        toast('host created', 'success');
      }
      onSaved();
    } catch (e2) {
      setError(e2.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal title={host?.id ? `Edit ${host.name}` : 'New host'} onClose={onClose} wide>
      <form onSubmit={save} className="grid grid-cols-2 gap-3">
        <div className="col-span-2">
          <label className="label">Display name</label>
          <input className="input" value={form.name} onChange={set('name')} placeholder="prod-web-01" autoFocus />
        </div>
        <div>
          <label className="label">Hostname / IP</label>
          <input className="input font-mono" value={form.hostname} onChange={set('hostname')} placeholder="10.0.0.5" />
        </div>
        <div className="grid grid-cols-3 gap-3">
          <div>
            <label className="label">Protocol</label>
            <select
              className="input"
              value={form.protocol}
              onChange={(e) => {
                const p = e.target.value;
                setForm((f) => ({
                  ...f,
                  protocol: p,
                  port: !host && f.port === 22 && p === 'telnet' ? 23 : !host && f.port === 23 && p === 'ssh' ? 22 : f.port,
                  auth_type: p === 'bmc' && f.auth_type === 'ask' ? 'credential' : f.auth_type,
                }));
              }}
            >
              <option value="ssh">SSH</option>
              <option value="telnet">Telnet</option>
              <option value="bmc">BMC / KVM</option>
            </select>
          </div>
          <div>
            <label className="label">Port</label>
            <input className="input font-mono" type="number" min="1" max="65535" value={form.port} onChange={set('port')} />
          </div>
          <div>
            <label className="label">Username</label>
            <input className="input font-mono" value={form.username} onChange={set('username')} placeholder="root" />
          </div>
        </div>

        {form.protocol === 'bmc' && (
          <div className="col-span-2 rounded-md border border-sky-800/60 bg-sky-950/30 px-3 py-2 text-[11px] text-sky-300">
            BMC family, console and management ports are auto-detected — the port field is unused.
            Pick a password credential (key credentials don't apply to BMC login).
          </div>
        )}

        {form.protocol === 'telnet' && (
          <div className="col-span-2 rounded-md border border-amber-800/60 bg-amber-950/30 px-3 py-2 text-[11px] text-amber-300">
            telnet is unencrypted — credentials and traffic cross the wire in cleartext. use only for
            legacy gear (switches, UPSs, serial consoles) on trusted networks.
          </div>
        )}

        <div>
          <label className="label">MAC address <span className="text-zinc-600">(Wake-on-LAN)</span></label>
          <input
            className="input font-mono"
            value={form.mac}
            onChange={set('mac')}
            placeholder="AA:BB:CC:DD:EE:FF"
            maxLength={17}
          />
        </div>

        {(form.protocol === 'ssh' || form.protocol === 'bmc') && (
        <>
        <div>
          <label className="label">Authentication</label>
          <select className="input" value={form.auth_type} onChange={set('auth_type')}>
            <option value="credential">Saved credential / key</option>
            <option value="password">Inline password</option>
            {form.protocol === 'ssh' && <option value="ask">Ask at connect (never stored)</option>}
          </select>
        </div>
        <div>
          {form.auth_type === 'credential' && (
            <>
              <label className="label">Credential</label>
              <select className="input" value={form.credential_id} onChange={set('credential_id')}>
                <option value="">— select —</option>
                {credentials.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name} ({c.type})
                  </option>
                ))}
              </select>
            </>
          )}
          {form.auth_type === 'password' && (
            <>
              <label className="label">Password {host && <span className="text-zinc-600">(blank = keep)</span>}</label>
              <input className="input" type="password" value={form.password} onChange={set('password')} autoComplete="new-password" />
            </>
          )}
          {form.auth_type === 'ask' && (
            <p className="text-[11px] text-zinc-500 mt-6">password is prompted in the terminal and never stored</p>
          )}
        </div>
        </>
        )}

        <div>
          <label className="label">Folder / group</label>
          <input
            className="input"
            list="ssloth-folders"
            value={form.folder}
            onChange={set('folder')}
            placeholder="production — pick or type a new group"
          />
          <datalist id="ssloth-folders">
            {[...new Set(hosts.map((x) => x.folder).filter(Boolean))].map((f) => (
              <option key={f} value={f} />
            ))}
          </datalist>
        </div>
        <div>
          <label className="label">Region</label>
          <input className="input" value={form.region} onChange={set('region')} placeholder="us-east-1" />
        </div>
        <div className="col-span-2">
          <label className="label">Tags — filter with #tag, open all at once</label>
          <input
            className="input font-mono"
            value={form.tags}
            onChange={set('tags')}
            placeholder="routers core eu-west"
          />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="label">Color</label>
            <div className="flex gap-1.5 mt-1.5">
              {COLORS.map((c) => (
                <button
                  key={c || 'none'}
                  type="button"
                  onClick={() => set('color')(c)}
                  className={`h-5 w-5 rounded-full ${COLOR_DOT[c]} ${form.color === c ? 'ring-2 ring-zinc-300 ring-offset-2 ring-offset-ink-850' : 'opacity-60 hover:opacity-100'}`}
                />
              ))}
            </div>
          </div>
          <div>
            <label className="label">Keepalive (s)</label>
            <input className="input font-mono" type="number" min="0" max="300" value={form.keepalive} onChange={set('keepalive')} />
          </div>
        </div>

        {form.protocol === 'ssh' && (
        <div>
          <label className="label">Bastion / jump host (optional)</label>
          <select className="input" value={form.jump_host_id} onChange={set('jump_host_id')}>
            <option value="">— direct connection —</option>
            {hosts
              .filter((h) => h.id !== host?.id)
              .map((h) => (
                <option key={h.id} value={h.id}>
                  via {h.name}
                </option>
              ))}
          </select>
        </div>
        )}
        <div className="flex items-end pb-1 gap-5">
          <label className="flex items-center gap-2 text-sm text-zinc-300 cursor-pointer">
            <input
              type="checkbox"
              className="accent-emerald-600"
              checked={form.record}
              onChange={(e) => setForm((f) => ({ ...f, record: e.target.checked }))}
            />
            auto-record sessions
          </label>
          {form.protocol === 'ssh' && (
          <label
            className="flex items-center gap-2 text-sm text-zinc-300 cursor-pointer"
            title="Remote commands can use this host's stored key to authenticate onward (like ssh -A) — keys never leave this server"
          >
            <input
              type="checkbox"
              className="accent-emerald-600"
              checked={form.agent_forward}
              onChange={(e) => setForm((f) => ({ ...f, agent_forward: e.target.checked }))}
            />
            agent forwarding
          </label>
          )}
          <label
            className="flex items-center gap-2 text-sm text-zinc-300 cursor-pointer"
            title="Other users on this ssloth instance can see and connect to this host — they can use its saved credential but never read it"
          >
            <input
              type="checkbox"
              className="accent-emerald-600"
              checked={form.shared}
              onChange={(e) => setForm((f) => ({ ...f, shared: e.target.checked }))}
            />
            shared with team
          </label>
        </div>

        <div className="col-span-2">
          <label className="label">Notes</label>
          <textarea className="input" rows="2" value={form.notes} onChange={set('notes')} />
        </div>

        {error && (
          <div className="col-span-2 rounded-md border border-red-800 bg-red-950/60 px-3 py-2 text-xs text-red-300">
            {error}
          </div>
        )}

        <div className="col-span-2 flex justify-end gap-2 pt-1">
          <button type="button" className="btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button className="btn-primary" disabled={busy || !form.name || !form.hostname || !form.username}>
            {busy ? '…' : host ? 'Save' : 'Create'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
