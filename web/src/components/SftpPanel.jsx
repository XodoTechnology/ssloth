import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  Folder,
  File,
  ArrowUp,
  Home,
  RefreshCw,
  FolderPlus,
  Upload,
  Download,
  Pencil,
  Trash2,
  CloudUpload,
} from 'lucide-react';
import { api, uploadFile } from '../api';
import { useStore } from '../store';

function fmtSize(n) {
  if (n == null) return '';
  const u = ['B', 'K', 'M', 'G', 'T'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) {
    n /= 1024;
    i++;
  }
  return i === 0 ? `${n}${u[i]}` : `${n.toFixed(1)}${u[i]}`;
}

export default function SftpPanel({ sessionId, label }) {
  const [path, setPath] = useState('.');
  const [realPath, setRealPath] = useState('');
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [dragOver, setDragOver] = useState(false);
  const [uploads, setUploads] = useState([]); // [{name, pct, error}]
  const fileInput = useRef(null);
  const { toast } = useStore();

  const load = useCallback(
    async (p) => {
      setLoading(true);
      setError('');
      try {
        const r = await api(`/api/sftp/${sessionId}/list?path=${encodeURIComponent(p)}`);
        setEntries(r.entries);
        setRealPath(r.path);
        setPath(r.path);
      } catch (e) {
        setError(e.message);
      } finally {
        setLoading(false);
      }
    },
    [sessionId]
  );

  useEffect(() => {
    load('.');
  }, [load]);

  const nav = (name) => load(joinPath(realPath || path, name));
  const goUp = () => {
    const p = realPath || path;
    const up = p === '/' ? '/' : p.replace(/\/+$/, '').replace(/\/[^/]*$/, '') || '/';
    load(up);
  };

  const doUpload = async (files) => {
    const dir = realPath || path;
    for (const f of files) {
      const id = Date.now() + Math.random();
      setUploads((u) => [...u, { id, name: f.name, pct: 0 }]);
      try {
        await uploadFile(
          `/api/sftp/${sessionId}/upload?path=${encodeURIComponent(dir)}&name=${encodeURIComponent(f.name)}`,
          f,
          (pct) => setUploads((u) => u.map((x) => (x.id === id ? { ...x, pct } : x)))
        );
        setUploads((u) => u.filter((x) => x.id !== id));
      } catch (e) {
        setUploads((u) => u.map((x) => (x.id === id ? { ...x, error: e.message } : x)));
        setTimeout(() => setUploads((u) => u.filter((x) => x.id !== id)), 4000);
      }
    }
    load(dir);
  };

  const onDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer?.files?.length) doUpload([...e.dataTransfer.files]);
  };

  const download = (name) => {
    const p = joinPath(realPath || path, name);
    const a = document.createElement('a');
    a.href = `/api/sftp/${sessionId}/download?path=${encodeURIComponent(p)}`;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
  };

  const mkdir = async () => {
    const name = prompt('new directory name');
    if (!name) return;
    try {
      await api(`/api/sftp/${sessionId}/mkdir`, {
        method: 'POST',
        body: { path: joinPath(realPath || path, name) },
      });
      load(realPath || path);
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  const rename = async (entry) => {
    const name = prompt('rename to', entry.name);
    if (!name || name === entry.name) return;
    const dir = realPath || path;
    try {
      await api(`/api/sftp/${sessionId}/rename`, {
        method: 'POST',
        body: { from: joinPath(dir, entry.name), to: joinPath(dir, name) },
      });
      load(dir);
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  const remove = async (entry) => {
    const recursive = entry.is_dir;
    if (!confirm(`Delete ${entry.is_dir ? 'directory (recursive)' : 'file'} "${entry.name}"?`)) return;
    try {
      await api(`/api/sftp/${sessionId}/delete`, {
        method: 'POST',
        body: { path: joinPath(realPath || path, entry.name), recursive },
      });
      load(realPath || path);
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  return (
    <div
      className="w-80 shrink-0 border-l border-ink-700 bg-ink-900/50 flex flex-col min-h-0 relative"
      onDragOver={(e) => {
        e.preventDefault();
        setDragOver(true);
      }}
      onDragLeave={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget)) setDragOver(false);
      }}
      onDrop={onDrop}
    >
      {/* path bar */}
      <div className="flex items-center gap-1 px-2 py-1.5 border-b border-ink-700">
        <button className="btn-ghost !p-1" title="Home" onClick={() => load('.')}>
          <Home size={14} />
        </button>
        <button className="btn-ghost !p-1" title="Up" onClick={goUp}>
          <ArrowUp size={14} />
        </button>
        <button className="btn-ghost !p-1" title="Refresh" onClick={() => load(realPath || path)}>
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
        </button>
        <span className="flex-1 font-mono text-[11px] text-zinc-400 truncate px-1" title={realPath}>
          {realPath || path}
        </span>
        <button className="btn-ghost !p-1" title="New folder" onClick={mkdir}>
          <FolderPlus size={14} />
        </button>
        <button className="btn-ghost !p-1" title="Upload" onClick={() => fileInput.current?.click()}>
          <Upload size={14} />
        </button>
        <input
          ref={fileInput}
          type="file"
          multiple
          className="hidden"
          onChange={(e) => {
            doUpload([...e.target.files]);
            e.target.value = '';
          }}
        />
      </div>

      {error && <div className="px-3 py-2 text-xs text-red-400 border-b border-ink-700">{error}</div>}

      {/* uploads progress */}
      {uploads.length > 0 && (
        <div className="border-b border-ink-700 px-3 py-2 space-y-1.5">
          {uploads.map((u) => (
            <div key={u.id}>
              <div className="flex justify-between text-[11px]">
                <span className="truncate text-zinc-300">{u.name}</span>
                <span className={u.error ? 'text-red-400' : 'text-zinc-500'}>
                  {u.error ? u.error : `${Math.round(u.pct * 100)}%`}
                </span>
              </div>
              <div className="h-1 rounded bg-ink-700 overflow-hidden">
                <div
                  className={`h-full ${u.error ? 'bg-red-500' : 'bg-emerald-500'}`}
                  style={{ width: `${Math.round(u.pct * 100)}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      )}

      {/* file list */}
      <div className="flex-1 overflow-y-auto">
        {entries.map((e) => (
          <div
            key={e.name}
            className={`group flex items-center gap-2 px-3 py-1 text-sm hover:bg-ink-800 ${
              e.is_dir ? 'cursor-pointer' : ''
            }`}
            onClick={() => e.is_dir && nav(e.name)}
          >
            {e.is_dir ? (
              <Folder size={14} className="text-sky-400 shrink-0" />
            ) : (
              <File size={14} className="text-zinc-500 shrink-0" />
            )}
            <span className="flex-1 truncate text-zinc-200" title={e.name}>
              {e.name}
            </span>
            <span className="text-[10px] font-mono text-zinc-600 w-14 text-right shrink-0">
              {e.is_dir ? '' : fmtSize(e.size)}
            </span>
            <div className="hidden group-hover:flex items-center shrink-0" onClick={(ev) => ev.stopPropagation()}>
              {!e.is_dir && (
                <button className="p-0.5 text-zinc-500 hover:text-emerald-400" title="Download" onClick={() => download(e.name)}>
                  <Download size={13} />
                </button>
              )}
              <button className="p-0.5 text-zinc-500 hover:text-zinc-200" title="Rename" onClick={() => rename(e)}>
                <Pencil size={13} />
              </button>
              <button className="p-0.5 text-zinc-500 hover:text-red-400" title="Delete" onClick={() => remove(e)}>
                <Trash2 size={13} />
              </button>
            </div>
          </div>
        ))}
        {!loading && entries.length === 0 && !error && (
          <div className="px-3 py-6 text-center text-xs text-zinc-600">empty directory</div>
        )}
      </div>

      <div className="border-t border-ink-700 px-3 py-1.5 text-[10px] text-zinc-600 truncate">
        {label} · drop files to upload
      </div>

      {dragOver && (
        <div className="absolute inset-0 z-10 bg-emerald-950/80 border-2 border-dashed border-emerald-500 flex flex-col items-center justify-center gap-2 pointer-events-none">
          <CloudUpload size={32} className="text-emerald-400" />
          <span className="text-sm text-emerald-300">drop to upload to {realPath || path}</span>
        </div>
      )}
    </div>
  );
}

function joinPath(dir, name) {
  if (!dir || dir === '.') return name;
  return dir.endsWith('/') ? dir + name : `${dir}/${name}`;
}
