import React, { useEffect, useState } from 'react';
import { ListChecks, Plus, Pencil, Trash2, Play, ChevronUp, ChevronDown, X } from 'lucide-react';
import { api } from '../api';
import { useStore } from '../store';
import Modal from '../components/Modal';

// Playbooks: ordered command lists executed step-by-step on a session —
// each step's exit code is verified server-side before the next runs.
export default function Playbooks() {
  const { playbooks, refreshAll, toast, hosts, openTab, setPendingPlaybook, setActiveTab } = useStore();
  const [editing, setEditing] = useState(null); // 'new' | playbook | null
  const [runTarget, setRunTarget] = useState(null); // playbook to pick a host for

  useEffect(() => {
    refreshAll(api).catch((e) => toast(e.message, 'error'));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const del = async (p) => {
    if (!confirm(`Delete playbook "${p.name}"?`)) return;
    await api(`/api/playbooks/${p.id}`, { method: 'DELETE' });
    refreshAll(api);
  };

  const runOn = (pb, host) => {
    const tabId = openTab({ hostId: host.id }, host.name);
    setPendingPlaybook(tabId, pb.id);
    setRunTarget(null);
    setActiveTab(tabId);
  };

  return (
    <div className="flex-1 overflow-y-auto p-6">
      <div className="max-w-4xl mx-auto space-y-4">
        <div className="flex items-center justify-between gap-3">
          <h1 className="text-lg font-semibold flex items-center gap-2">
            <ListChecks size={18} className="text-emerald-400" /> Playbooks
          </h1>
          <button className="btn-primary" onClick={() => setEditing('new')}>
            <Plus size={14} /> New playbook
          </button>
        </div>
        <p className="text-xs text-zinc-500">
          Ordered setup/maintenance scripts. Each step runs only after the previous one exits cleanly — the run
          streams live in the terminal with per-step status.
        </p>

        <div className="space-y-3">
          {playbooks.map((p) => (
            <div key={p.id} className="card px-4 py-3">
              <div className="flex items-center gap-3">
                <div className="min-w-0 flex-1">
                  <div className="text-sm text-zinc-100">{p.name}</div>
                  {p.description && <div className="text-[11px] text-zinc-500 truncate">{p.description}</div>}
                </div>
                <span className="text-[10px] text-zinc-500">{p.steps?.length || 0} steps</span>
                <div className="flex items-center gap-1">
                  <button className="btn-primary !py-1 text-xs" onClick={() => setRunTarget(p)}>
                    <Play size={12} /> Run on…
                  </button>
                  <button className="btn-ghost !py-1 !px-1.5" onClick={() => setEditing(p)}>
                    <Pencil size={13} />
                  </button>
                  <button className="btn-ghost !py-1 !px-1.5 hover:text-red-400" onClick={() => del(p)}>
                    <Trash2 size={13} />
                  </button>
                </div>
              </div>
              <ol className="mt-2 space-y-0.5">
                {p.steps?.map((s, i) => (
                  <li key={i} className="flex gap-2 text-[11px] font-mono text-zinc-500">
                    <span className="text-zinc-700 w-4 shrink-0 text-right">{i + 1}.</span>
                    <span className="truncate">{s.command}</span>
                  </li>
                ))}
              </ol>
            </div>
          ))}
          {playbooks.length === 0 && (
            <div className="card px-4 py-10 text-center text-sm text-zinc-600">
              no playbooks yet — turn your repeated setup commands into one-click runs
            </div>
          )}
        </div>
      </div>

      {editing && (
        <PlaybookModal playbook={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />
      )}

      {runTarget && (
        <Modal title={`Run "${runTarget.name}" on`} onClose={() => setRunTarget(null)}>
          <div className="space-y-1 max-h-80 overflow-y-auto">
            {hosts.map((h) => (
              <button
                key={h.id}
                className="w-full text-left rounded-md px-3 py-2 text-sm hover:bg-ink-800"
                onClick={() => runOn(runTarget, h)}
              >
                <span className="text-zinc-200">{h.name}</span>
                <span className="ml-2 text-[11px] font-mono text-zinc-500">
                  {h.username}@{h.hostname}:{h.port}
                </span>
              </button>
            ))}
            {!hosts.length && <div className="p-3 text-xs text-zinc-500">no saved hosts</div>}
          </div>
        </Modal>
      )}
    </div>
  );
}

function PlaybookModal({ playbook, onClose }) {
  const { refreshAll, toast } = useStore();
  const [name, setName] = useState(playbook?.name || '');
  const [description, setDescription] = useState(playbook?.description || '');
  const [steps, setSteps] = useState(
    playbook?.steps?.length ? playbook.steps.map((s) => ({ ...s })) : [{ command: '', description: '' }]
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const setStep = (i, k, v) => setSteps((s) => s.map((x, j) => (j === i ? { ...x, [k]: v } : x)));
  const move = (i, d) =>
    setSteps((s) => {
      const j = i + d;
      if (j < 0 || j >= s.length) return s;
      const n = [...s];
      [n[i], n[j]] = [n[j], n[i]];
      return n;
    });

  const save = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      const body = { name, description, steps: steps.filter((s) => s.command.trim()) };
      if (playbook) await api(`/api/playbooks/${playbook.id}`, { method: 'PUT', body });
      else await api('/api/playbooks', { method: 'POST', body });
      toast('playbook saved', 'success');
      refreshAll(api);
      onClose();
    } catch (e2) {
      setError(e2.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal title={playbook ? 'Edit playbook' : 'New playbook'} onClose={onClose} wide>
      <form onSubmit={save} className="space-y-3">
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="label">Name</label>
            <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="harden new box" autoFocus />
          </div>
          <div>
            <label className="label">Description</label>
            <input className="input" value={description} onChange={(e) => setDescription(e.target.value)} />
          </div>
        </div>
        <div>
          <label className="label">Steps — run in order, aborts on failure</label>
          <div className="space-y-1.5">
            {steps.map((s, i) => (
              <div key={i} className="flex items-center gap-1">
                <span className="text-[10px] text-zinc-600 w-4 text-right shrink-0">{i + 1}</span>
                <input
                  className="input font-mono !text-xs flex-1"
                  placeholder="apt update && apt install -y htop"
                  value={s.command}
                  spellCheck={false}
                  onChange={(e) => setStep(i, 'command', e.target.value)}
                />
                <input
                  className="input !text-xs w-36"
                  placeholder="note (optional)"
                  value={s.description}
                  onChange={(e) => setStep(i, 'description', e.target.value)}
                />
                <button type="button" className="btn-ghost !px-1" onClick={() => move(i, -1)} disabled={i === 0}>
                  <ChevronUp size={13} />
                </button>
                <button type="button" className="btn-ghost !px-1" onClick={() => move(i, 1)} disabled={i === steps.length - 1}>
                  <ChevronDown size={13} />
                </button>
                <button
                  type="button"
                  className="btn-ghost !px-1 hover:text-red-400"
                  onClick={() => setSteps((x) => (x.length > 1 ? x.filter((_, j) => j !== i) : x))}
                >
                  <X size={13} />
                </button>
              </div>
            ))}
          </div>
          <button
            type="button"
            className="btn-ghost !text-xs mt-2"
            onClick={() => setSteps((s) => [...s, { command: '', description: '' }])}
          >
            <Plus size={12} /> add step
          </button>
        </div>
        {error && (
          <div className="rounded-md border border-red-800 bg-red-950/60 px-3 py-2 text-xs text-red-300">{error}</div>
        )}
        <div className="flex justify-end gap-2">
          <button type="button" className="btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button className="btn-primary" disabled={busy || !name || !steps.some((s) => s.command.trim())}>
            {busy ? '…' : 'Save'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
