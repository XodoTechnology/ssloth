import React, { useEffect, useState } from 'react';
import {
  ListChecks,
  Plus,
  Pencil,
  Trash2,
  Play,
  ChevronUp,
  ChevronDown,
  X,
  Library,
  History,
  CloudDownload,
  Clock,
} from 'lucide-react';
import { api } from '../api';
import { useStore } from '../store';
import Modal from '../components/Modal';

// Playbooks: ordered command lists executed step-by-step on a session —
// each step's exit code is verified server-side before the next runs.
export default function Playbooks() {
  const { playbooks, refreshAll, toast, hosts, openTab, setPendingPlaybook, setActiveTab, user } = useStore();
  const readOnly = user?.role === 'viewer';
  const [editing, setEditing] = useState(null); // 'new' | playbook | null
  const [runTarget, setRunTarget] = useState(null); // playbook to pick a host for
  const [gallery, setGallery] = useState(false);
  const [runsOpen, setRunsOpen] = useState(false);

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

  // Detached run — no terminal needed; output lands in run history.
  const runDetached = async (pb, host) => {
    try {
      await api(`/api/playbooks/${pb.id}/run`, { method: 'POST', body: { host_id: host.id } });
      toast(`"${pb.name}" started on ${host.name} — see run history`, 'success');
      setRunTarget(null);
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  return (
    <div className="flex-1 overflow-y-auto p-6">
      <div className="max-w-4xl mx-auto space-y-4">
        <div className="flex items-center justify-between gap-3">
          <h1 className="text-lg font-semibold flex items-center gap-2">
            <ListChecks size={18} className="text-emerald-400" /> Playbooks
          </h1>
          <div className="flex gap-2">
            <button className="btn-ghost border border-ink-700" onClick={() => setRunsOpen(true)}>
              <History size={14} /> Runs
            </button>
            {!readOnly && (
              <>
                <button className="btn-ghost border border-ink-700" onClick={() => setGallery(true)}>
                  <Library size={14} /> Templates
                </button>
                <button className="btn-primary" onClick={() => setEditing('new')}>
                  <Plus size={14} /> New playbook
                </button>
              </>
            )}
          </div>
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
                {p.schedule_enabled && p.schedule_cron && (
                  <span
                    className="shrink-0 rounded bg-sky-950 px-1.5 py-px text-[9px] font-medium text-sky-300 flex items-center gap-1"
                    title={`scheduled: ${p.schedule_cron}${p.next_run_at ? ` — next ${new Date(p.next_run_at * 1000).toLocaleString()}` : ''}`}
                  >
                    <Clock size={9} /> {p.schedule_cron}
                  </span>
                )}
                <div className="flex items-center gap-1">
                  {!readOnly && (
                    <>
                      <button className="btn-primary !py-1 text-xs" onClick={() => setRunTarget(p)}>
                        <Play size={12} /> Run on…
                      </button>
                      <button className="btn-ghost !py-1 !px-1.5" onClick={() => setEditing(p)}>
                        <Pencil size={13} />
                      </button>
                      <button className="btn-ghost !py-1 !px-1.5 hover:text-red-400" onClick={() => del(p)}>
                        <Trash2 size={13} />
                      </button>
                    </>
                  )}
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
              <div key={h.id} className="flex items-center rounded-md hover:bg-ink-800">
                <button
                  className="flex-1 text-left px-3 py-2 text-sm"
                  title="open a terminal and run interactively"
                  onClick={() => runOn(runTarget, h)}
                >
                  <span className="text-zinc-200">{h.name}</span>
                  <span className="ml-2 text-[11px] font-mono text-zinc-500">
                    {h.username}@{h.hostname}:{h.port}
                  </span>
                </button>
                <button
                  className="btn-ghost !py-1 !px-2 text-[11px] mr-1"
                  title="run in the background — no terminal; result lands in run history"
                  onClick={() => runDetached(runTarget, h)}
                >
                  <CloudDownload size={12} /> bg
                </button>
              </div>
            ))}
            {!hosts.length && <div className="p-3 text-xs text-zinc-500">no saved hosts</div>}
          </div>
        </Modal>
      )}

      {gallery && <TemplateGallery onClose={() => setGallery(false)} />}
      {runsOpen && <RunsModal onClose={() => setRunsOpen(false)} />}
    </div>
  );
}

const RUN_BADGE = {
  ok: 'bg-emerald-950 text-emerald-300',
  fail: 'bg-red-950 text-red-300',
  error: 'bg-red-950 text-red-300',
  timeout: 'bg-amber-950 text-amber-300',
  aborted: 'bg-zinc-800 text-zinc-300',
  running: 'bg-sky-950 text-sky-300',
};

function TemplateGallery({ onClose }) {
  const { toast, refreshAll } = useStore();
  const [templates, setTemplates] = useState([]);
  const [busy, setBusy] = useState('');

  useEffect(() => {
    api('/api/playbooks/templates').then((r) => setTemplates(r.templates)).catch((e) => toast(e.message, 'error'));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const install = async (t) => {
    setBusy(t.key);
    try {
      await api(`/api/playbooks/templates/${t.key}`, { method: 'POST' });
      toast(`added "${t.name}" to your playbooks`, 'success');
      refreshAll(api);
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      setBusy('');
    }
  };

  return (
    <Modal title="Playbook templates" onClose={onClose} wide>
      <div className="space-y-2 max-h-[60vh] overflow-y-auto">
        {templates.map((t) => (
          <div key={t.key} className="rounded-md border border-ink-700 bg-ink-900 px-3 py-2.5">
            <div className="flex items-center gap-3">
              <div className="min-w-0 flex-1">
                <div className="text-sm text-zinc-100">{t.name}</div>
                <div className="text-[11px] text-zinc-500">{t.description}</div>
              </div>
              <button className="btn-primary !py-1 text-xs" onClick={() => install(t)} disabled={!!busy}>
                {busy === t.key ? '…' : 'Add'}
              </button>
            </div>
            <ol className="mt-1.5 space-y-0.5">
              {t.steps.map((s, i) => (
                <li key={i} className="text-[10px] font-mono text-zinc-600 truncate">
                  <span className="text-zinc-700">{i + 1}.</span> {s.command}
                </li>
              ))}
            </ol>
          </div>
        ))}
        {!templates.length && <div className="py-6 text-center text-xs text-zinc-600">loading…</div>}
      </div>
    </Modal>
  );
}

function RunsModal({ onClose }) {
  const [runs, setRuns] = useState([]);
  const [detail, setDetail] = useState(null);
  const { toast } = useStore();

  const load = () => api('/api/playbooks/runs').then((r) => setRuns(r.runs)).catch((e) => toast(e.message, 'error'));
  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const stop = async (r) => {
    await api(`/api/playbooks/runs/${r.id}/stop`, { method: 'POST' });
    load();
  };

  return (
    <Modal title="Playbook run history" onClose={onClose} wide>
      <div className="space-y-1 max-h-[60vh] overflow-y-auto">
        {runs.map((r) => (
          <div key={r.id} className="flex items-center gap-2 rounded-md border border-ink-700 bg-ink-900 px-3 py-2">
            <span className={`rounded px-1.5 py-px text-[10px] font-semibold uppercase ${RUN_BADGE[r.status] || RUN_BADGE.running}`}>
              {r.status}
            </span>
            <div className="min-w-0 flex-1">
              <div className="text-sm text-zinc-200 truncate">
                {r.name} <span className="text-zinc-500">→ {r.host_label}</span>
              </div>
              <div className="text-[10px] font-mono text-zinc-500">
                {new Date(r.started_at * 1000).toLocaleString()} · {r.trigger}
                {r.ended_at ? ` · ${Math.round(r.ended_at - r.started_at)}s` : ' · running…'}
              </div>
            </div>
            {!r.ended_at && (
              <button className="btn-ghost !py-1 !px-2 text-[10px] text-red-400" onClick={() => stop(r)}>
                stop
              </button>
            )}
            <button className="btn-ghost !py-1 !px-2 text-[11px]" onClick={async () => {
              const d = await api(`/api/playbooks/runs/${r.id}`).catch(() => null);
              if (d) setDetail(d.run);
            }}>
              output
            </button>
          </div>
        ))}
        {!runs.length && (
          <div className="py-8 text-center text-xs text-zinc-600">
            no runs yet — scheduled and background runs land here
          </div>
        )}
      </div>
      {detail && (
        <Modal title={`run #${detail.id} — ${detail.name} on ${detail.host_label}`} onClose={() => setDetail(null)} wide>
          <pre className="rounded-md bg-ink-950 border border-ink-700 p-3 font-mono text-[11px] text-zinc-300 whitespace-pre-wrap max-h-[50vh] overflow-y-auto">
            {detail.output || '(no output)'}
          </pre>
        </Modal>
      )}
    </Modal>
  );
}

function PlaybookModal({ playbook, onClose }) {
  const { refreshAll, toast, hosts } = useStore();
  const [name, setName] = useState(playbook?.name || '');
  const [description, setDescription] = useState(playbook?.description || '');
  const [steps, setSteps] = useState(
    playbook?.steps?.length ? playbook.steps.map((s) => ({ ...s })) : [{ command: '', description: '' }]
  );
  const [sched, setSched] = useState({
    enabled: !!playbook?.schedule_enabled,
    cron: playbook?.schedule_cron || '0 3 * * 0',
    host_id: playbook?.schedule_host_id || '',
  });
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
      const body = {
        name,
        description,
        steps: steps.filter((s) => s.command.trim()),
        schedule_enabled: sched.enabled,
        schedule_cron: sched.enabled ? sched.cron : playbook?.schedule_cron || null,
        schedule_host_id: sched.enabled && sched.host_id ? parseInt(sched.host_id, 10) : null,
      };
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

        <div className="rounded-md border border-ink-700 bg-ink-900/60 px-3 py-2.5 space-y-2">
          <label className="flex items-center gap-2 text-sm text-zinc-300 cursor-pointer">
            <input
              type="checkbox"
              className="accent-emerald-600"
              checked={sched.enabled}
              onChange={(e) => setSched((s) => ({ ...s, enabled: e.target.checked }))}
            />
            <Clock size={13} className="text-sky-400" /> run on a schedule
          </label>
          {sched.enabled && (
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="label">Cron (min hour dom mon dow)</label>
                <input
                  className="input font-mono !text-xs"
                  value={sched.cron}
                  onChange={(e) => setSched((s) => ({ ...s, cron: e.target.value }))}
                  placeholder="0 3 * * 0"
                />
              </div>
              <div>
                <label className="label">Target host (needs stored creds)</label>
                <select
                  className="input !text-xs"
                  value={sched.host_id}
                  onChange={(e) => setSched((s) => ({ ...s, host_id: e.target.value }))}
                >
                  <option value="">— select —</option>
                  {hosts.map((h) => (
                    <option key={h.id} value={h.id}>
                      {h.name}
                    </option>
                  ))}
                </select>
              </div>
              <p className="col-span-2 text-[10px] text-zinc-600">
                scheduled runs are non-interactive — the host must use a stored credential and an already-trusted
                host key. Results land in run history.
              </p>
            </div>
          )}
        </div>
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
              !name ||
              !steps.some((s) => s.command.trim()) ||
              (sched.enabled && (!sched.cron.trim() || !sched.host_id))
            }
          >
            {busy ? '…' : 'Save'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
