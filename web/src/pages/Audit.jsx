import React, { useEffect, useState } from 'react';
import { ScrollText } from 'lucide-react';
import { api } from '../api';
import { useStore } from '../store';

export default function Audit() {
  const [rows, setRows] = useState([]);
  const [error, setError] = useState('');
  const { toast } = useStore();

  useEffect(() => {
    api('/api/admin/audit')
      .then((r) => setRows(r.audit))
      .catch((e) => setError(e.message));
  }, []);

  const fmt = (ts) => new Date(ts * 1000).toLocaleString();

  return (
    <div className="flex-1 overflow-y-auto p-6">
      <div className="max-w-4xl mx-auto space-y-4">
        <h1 className="text-lg font-semibold flex items-center gap-2">
          <ScrollText size={18} className="text-emerald-400" /> Audit log
        </h1>
        {error && <div className="card px-4 py-3 text-sm text-red-300">{error}</div>}
        <div className="card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-[11px] uppercase tracking-wider text-zinc-500 border-b border-ink-700">
                <th className="px-4 py-2 font-medium">Time</th>
                <th className="px-4 py-2 font-medium">User</th>
                <th className="px-4 py-2 font-medium">Action</th>
                <th className="px-4 py-2 font-medium">Detail</th>
                <th className="px-4 py-2 font-medium">IP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ink-700/50">
              {rows.map((r) => (
                <tr key={r.id} className="text-zinc-300">
                  <td className="px-4 py-1.5 text-xs font-mono text-zinc-500 whitespace-nowrap">{fmt(r.created_at)}</td>
                  <td className="px-4 py-1.5 text-xs">{r.username || '—'}</td>
                  <td className="px-4 py-1.5 text-xs font-mono text-emerald-300/90">{r.action}</td>
                  <td className="px-4 py-1.5 text-xs text-zinc-400 max-w-[320px] truncate" title={r.detail}>
                    {r.detail}
                  </td>
                  <td className="px-4 py-1.5 text-xs font-mono text-zinc-500">{r.ip}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length === 0 && !error && (
            <div className="px-4 py-10 text-center text-sm text-zinc-600">no audit events yet</div>
          )}
        </div>
      </div>
    </div>
  );
}
