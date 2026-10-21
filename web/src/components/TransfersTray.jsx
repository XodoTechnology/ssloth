import { useState } from 'react';
import { useStore } from '../store';
import { ArrowUp, ArrowDown, CheckCircle2, AlertTriangle, X, Loader2 } from 'lucide-react';

function fmtDir(dir) {
  return dir === '.' ? '~' : dir;
}

export default function TransfersTray() {
  const transfers = useStore((s) => s.transfers);
  const removeTransfer = useStore((s) => s.removeTransfer);
  const [open, setOpen] = useState(true);

  if (!transfers.length) return null;
  const active = transfers.filter((t) => t.state === 'active').length;

  return (
    <div className="fixed bottom-4 right-4 z-50 w-80 rounded-xl border border-slate-700/60 bg-slate-900/95 shadow-2xl shadow-black/50 backdrop-blur">
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center justify-between px-3 py-2 text-xs font-medium text-slate-300"
      >
        <span className="flex items-center gap-2">
          {active ? <Loader2 className="h-3.5 w-3.5 animate-spin text-indigo-400" /> : <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />}
          {active ? `${active} transfer${active > 1 ? 's' : ''} in progress` : 'Transfers complete'}
        </span>
        <span className="text-slate-500">{open ? '▾' : '▴'}</span>
      </button>
      {open && (
        <div className="max-h-64 overflow-y-auto border-t border-slate-800">
          {transfers.map((t) => (
            <div key={t.id} className="flex items-center gap-2 border-b border-slate-800/60 px-3 py-2 last:border-0">
              {t.kind === 'up' ? (
                <ArrowUp className="h-3.5 w-3.5 shrink-0 text-indigo-400" />
              ) : (
                <ArrowDown className="h-3.5 w-3.5 shrink-0 text-emerald-400" />
              )}
              <div className="min-w-0 flex-1">
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate text-xs text-slate-200" title={t.name}>{t.name}</span>
                  <span className="shrink-0 text-[10px] text-slate-500">
                    {t.state === 'active' ? `${t.pct}%` : t.state === 'done' ? 'done' : 'failed'}
                  </span>
                </div>
                <div className="mt-1 h-1 overflow-hidden rounded-full bg-slate-800">
                  <div
                    className={`h-full rounded-full transition-all ${
                      t.state === 'error' ? 'bg-red-500' : t.state === 'done' ? 'bg-emerald-500' : 'bg-indigo-500'
                    }`}
                    style={{ width: `${t.pct}%` }}
                  />
                </div>
                <div className="mt-0.5 flex items-center gap-1 truncate text-[10px] text-slate-500">
                  {t.state === 'error' && <AlertTriangle className="h-2.5 w-2.5 text-red-400" />}
                  <span className="truncate">{t.label}:{fmtDir(t.dir)}</span>
                </div>
              </div>
              {t.state !== 'active' && (
                <button onClick={() => removeTransfer(t.id)} className="shrink-0 text-slate-600 hover:text-slate-400">
                  <X className="h-3 w-3" />
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
