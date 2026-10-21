import React, { useEffect, useRef, useState } from 'react';
import { Disc3, Play, Download, Trash2, Pause } from 'lucide-react';
import { api } from '../api';
import { useStore } from '../store';
import Modal from '../components/Modal';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';

export default function Recordings() {
  const [rows, setRows] = useState([]);
  const [playing, setPlaying] = useState(null);
  const { toast } = useStore();

  const load = () => api('/api/recordings').then((r) => setRows(r.recordings)).catch((e) => toast(e.message, 'error'));

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const del = async (r) => {
    if (!confirm(`Delete recording of "${r.label}"?`)) return;
    await api(`/api/recordings/${r.id}`, { method: 'DELETE' });
    load();
  };

  const fmtDur = (r) => {
    if (!r.ended_at) return 'recording…';
    const s = Math.round((r.ended_at - r.started_at) / 1000);
    return `${Math.floor(s / 60)}m ${s % 60}s`;
  };

  return (
    <div className="flex-1 overflow-y-auto p-6">
      <div className="max-w-4xl mx-auto space-y-4">
        <h1 className="text-lg font-semibold flex items-center gap-2">
          <Disc3 size={18} className="text-emerald-400" /> Session recordings
        </h1>
        <p className="text-xs text-zinc-500">
          Terminal output captured as asciinema casts (keystrokes are never recorded). Toggle recording from the
          terminal toolbar or per-host with "auto-record".
        </p>
        <div className="card divide-y divide-ink-700/60">
          {rows.map((r) => (
            <div key={r.id} className="flex items-center gap-3 px-4 py-2.5">
              <Disc3 size={15} className={r.ended_at ? 'text-zinc-500' : 'text-red-400 animate-pulse'} />
              <div className="min-w-0 flex-1">
                <div className="text-sm text-zinc-200 truncate">{r.label}</div>
                <div className="text-[11px] text-zinc-500 font-mono">
                  {new Date(r.started_at).toLocaleString()} · {fmtDur(r)} · {(r.size / 1024).toFixed(1)}K
                </div>
              </div>
              <button className="btn-ghost !py-1 text-xs" onClick={() => setPlaying(r)}>
                <Play size={13} /> replay
              </button>
              <a className="btn-ghost !py-1 text-xs" href={`/api/recordings/${r.id}/content?download=1`} download>
                <Download size={13} />
              </a>
              <button className="btn-ghost !py-1 !px-1.5 hover:text-red-400" onClick={() => del(r)}>
                <Trash2 size={13} />
              </button>
            </div>
          ))}
          {rows.length === 0 && (
            <div className="px-4 py-10 text-center text-sm text-zinc-600">
              no recordings yet — hit the record button in a terminal
            </div>
          )}
        </div>
      </div>
      {playing && <CastPlayer rec={playing} onClose={() => setPlaying(null)} />}
    </div>
  );
}

function CastPlayer({ rec, onClose }) {
  const ref = useRef(null);
  const termRef = useRef(null);
  const timerRef = useRef(null);
  const [state, setState] = useState('loading'); // loading|ready|playing|paused|done|error
  const [speed, setSpeed] = useState(1);
  const eventsRef = useRef([]);
  const posRef = useRef(0);

  useEffect(() => {
    const term = new Terminal({
      fontSize: 13,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
      disableStdin: true,
      theme: { background: '#0a0d10', foreground: '#d6dde5', selectionBackground: '#33455c' },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(ref.current);
    fit.fit();
    termRef.current = term;

    fetch(`/api/recordings/${rec.id}/content`, { credentials: 'same-origin' })
      .then((r) => r.text())
      .then((text) => {
        const lines = text.trim().split('\n');
        // line 0 = header; rest = [t, 'o', data]
        eventsRef.current = lines
          .slice(1)
          .map((l) => {
            try {
              return JSON.parse(l);
            } catch {
              return null;
            }
          })
          .filter((e) => e && e[1] === 'o');
        setState('ready');
      })
      .catch(() => setState('error'));

    return () => {
      clearTimeout(timerRef.current);
      term.dispose();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rec.id]);

  const pump = () => {
    const events = eventsRef.current;
    const step = () => {
      if (posRef.current >= events.length) return setState('done');
      const [t, , data] = events[posRef.current];
      termRef.current?.write(data);
      posRef.current++;
      const nextT = posRef.current < events.length ? events[posRef.current][0] : t;
      timerRef.current = setTimeout(step, Math.min(Math.max((nextT - t) * 1000 / speed, 0), 3000));
    };
    step();
  };

  const play = () => {
    if (state === 'done') {
      termRef.current?.reset();
      posRef.current = 0;
    }
    setState('playing');
    pump();
  };

  const pause = () => {
    clearTimeout(timerRef.current);
    setState('paused');
  };

  const restart = () => {
    clearTimeout(timerRef.current);
    termRef.current?.reset();
    posRef.current = 0;
    setState('playing');
    pump();
  };

  return (
    <Modal title={`Replay — ${rec.label}`} onClose={onClose} wide>
      <div className="space-y-2">
        <div className="flex items-center gap-2">
          {state === 'playing' ? (
            <button className="btn-ghost border border-ink-600 !py-1 text-xs" onClick={pause}>
              <Pause size={13} /> pause
            </button>
          ) : (
            <button className="btn-primary !py-1 text-xs" onClick={play} disabled={state === 'loading' || state === 'error'}>
              <Play size={13} /> {state === 'done' ? 'replay again' : state === 'paused' ? 'resume' : 'play'}
            </button>
          )}
          <button className="btn-ghost !py-1 text-xs" onClick={restart} disabled={state !== 'playing' && state !== 'paused' && state !== 'done'}>
            restart
          </button>
          <select className="input !w-24 !py-1 text-xs" value={speed} onChange={(e) => setSpeed(parseFloat(e.target.value))}>
            <option value={0.5}>0.5×</option>
            <option value={1}>1×</option>
            <option value={2}>2×</option>
            <option value={4}>4×</option>
            <option value={16}>16×</option>
          </select>
          <span className="text-[11px] text-zinc-500 ml-auto">{state}</span>
        </div>
        <div className="rounded-md overflow-hidden border border-ink-700" style={{ height: 360 }}>
          <div ref={ref} className="h-full" />
        </div>
      </div>
    </Modal>
  );
}
