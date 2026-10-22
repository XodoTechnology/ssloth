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
  Eye,
  FileEdit,
  FolderSync,
} from 'lucide-react';
import { api } from '../api';
import { startUpload, uploadToSession } from '../transfers';
import { useStore } from '../store';
import FileEditor from './FileEditor';
import Modal from './Modal';

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
  const [editPath, setEditPath] = useState(null);
  const [syncOpen, setSyncOpen] = useState(false);
  const [preview, setPreview] = useState(null); // {name, kind, content|url, size}
  const fileInput = useRef(null);
  const toast = useStore((s) => s.toast);
  const setSftpPath = useStore((s) => s.setSftpPath);

  const load = useCallback(
    async (p) => {
      setLoading(true);
      setError('');
      try {
        const r = await api(`/api/sftp/${sessionId}/list?path=${encodeURIComponent(p)}`);
        setEntries(r.entries);
        setRealPath(r.path);
        setPath(r.path);
        setSftpPath(sessionId, r.path);
      } catch (e) {
        setError(e.message);
      } finally {
        setLoading(false);
      }
    },
    [sessionId, setSftpPath]
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

  const doUpload = (files) => {
    const dir = realPath || path;
    uploadToSession(sessionId, dir, files, label);
    // refresh listing after a moment so finished files appear
    setTimeout(() => load(dir), 1500);
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

  const openPreview = async (name) => {
    const p = joinPath(realPath || path, name);
    const imgExt = /\.(png|jpe?g|gif|webp|bmp|avif)$/i.test(name);
    try {
      const r = await api(`/api/sftp/${sessionId}/read?path=${encodeURIComponent(p)}`);
      if (r.too_large) {
        setPreview({ name, kind: 'toolarge', size: r.size });
      } else if (r.binary && imgExt) {
        // image — stream it through the download endpoint as a blob
        const resp = await fetch(`/api/sftp/${sessionId}/download?path=${encodeURIComponent(p)}`);
        const blob = await resp.blob();
        setPreview({ name, kind: 'image', url: URL.createObjectURL(blob) });
      } else if (r.binary) {
        setPreview({ name, kind: 'binary', size: r.size });
      } else {
        setPreview({ name, kind: 'text', content: r.content, size: r.size });
      }
    } catch (e) {
      toast(e.message, 'error');
    }
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
        <button className="btn-ghost !p-1" title="Sync a folder (push local dir / pull remote as tar.gz)" onClick={() => setSyncOpen(true)}>
          <FolderSync size={14} />
        </button>
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

      {/* file list */}
      <div className="flex-1 overflow-y-auto">
        {entries.map((e) => (
          <div
            key={e.name}
            className={`group flex items-center gap-2 px-3 py-1 text-sm hover:bg-ink-800 ${
              e.is_dir ? 'cursor-pointer' : 'cursor-pointer'
            }`}
            onClick={() => (e.is_dir ? nav(e.name) : openPreview(e.name))}
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
                <>
                  <button className="p-0.5 text-zinc-500 hover:text-emerald-400" title="Preview" onClick={() => openPreview(e.name)}>
                    <Eye size={13} />
                  </button>
                  <button
                    className="p-0.5 text-zinc-500 hover:text-sky-400"
                    title="Edit in place"
                    onClick={() => setEditPath(joinPath(realPath || path, e.name))}
                  >
                    <FileEdit size={13} />
                  </button>
                </>
              )}
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

      {editPath && (
        <FileEditor
          sessionId={sessionId}
          path={editPath}
          onClose={() => {
            setEditPath(null);
            load(realPath || path);
          }}
        />
      )}

      {syncOpen && (
        <SyncModal
          sessionId={sessionId}
          remoteDir={realPath || path}
          label={label}
          onClose={() => setSyncOpen(false)}
          onDone={() => load(realPath || path)}
        />
      )}

      {preview && (
        <Modal
          title={preview.name}
          wide
          onClose={() => {
            if (preview.url) URL.revokeObjectURL(preview.url);
            setPreview(null);
          }}
        >
          {preview.kind === 'text' && (
            <pre className="font-mono text-[11px] leading-5 text-zinc-300 whitespace-pre-wrap break-all max-h-[60vh] overflow-auto">
              {preview.content}
            </pre>
          )}
          {preview.kind === 'image' && (
            <div className="flex items-center justify-center max-h-[60vh] overflow-auto">
              <img src={preview.url} alt={preview.name} className="max-w-full max-h-[56vh] object-contain" />
            </div>
          )}
          {preview.kind === 'binary' && (
            <div className="text-sm text-zinc-400 space-y-2">
              <p>
                Binary file ({fmtSize(preview.size)}) — no inline preview.
              </p>
              <button className="btn-primary" onClick={() => download(preview.name)}>
                <Download size={14} /> Download
              </button>
            </div>
          )}
          {preview.kind === 'toolarge' && (
            <div className="text-sm text-zinc-400 space-y-2">
              <p>
                File is {fmtSize(preview.size)} — too large to preview inline.
              </p>
              <button className="btn-primary" onClick={() => download(preview.name)}>
                <Download size={14} /> Download
              </button>
            </div>
          )}
        </Modal>
      )}
    </div>
  );
}

function joinPath(dir, name) {
  if (!dir || dir === '.') return name;
  return dir.endsWith('/') ? dir + name : `${dir}/${name}`;
}

// Folder sync — push: pick a local directory, diff it against the remote
// (missing files or different size => upload). pull: remote dir comes back
// as a streamed tar.gz the browser downloads.
function SyncModal({ sessionId, remoteDir, label, onClose, onDone }) {
  const { toast } = useStore();
  const [mode, setMode] = useState('push');
  const [localFiles, setLocalFiles] = useState(null); // FileList -> [{file, rel}]
  const [remoteFiles, setRemoteFiles] = useState(null);
  const [diff, setDiff] = useState(null); // {upload:[{file,rel}], skip:n}
  const [busy, setBusy] = useState(false);
  const dirInput = useRef(null);

  const analyze = async (files) => {
    setBusy(true);
    try {
      const r = await api(`/api/sftp/${sessionId}/rlist?path=${encodeURIComponent(remoteDir)}`);
      const remote = new Map(r.files.map((f) => [f.path, f]));
      setRemoteFiles(r.files);
      // strip the picked dir's own name so 'site/index.html' -> 'index.html'
      const items = files.map((f) => {
        const rel = (f.webkitRelativePath || f.name).split('/').slice(1).join('/') || f.name;
        return { file: f, rel };
      });
      const upload = [];
      let skip = 0;
      for (const it of items) {
        const rem = remote.get(it.rel);
        if (rem && rem.size === it.file.size) skip++;
        else upload.push(it);
      }
      setLocalFiles(items);
      setDiff({ upload, skip, truncated: r.truncated });
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      setBusy(false);
    }
  };

  const push = async () => {
    if (!diff?.upload.length) return;
    // create parent dirs level-by-level (mkdir fails harmlessly when it exists)
    const dirs = new Set();
    for (const it of diff.upload) {
      const parts = it.rel.split('/').slice(0, -1);
      for (let i = 1; i <= parts.length; i++) dirs.add(parts.slice(0, i).join('/'));
    }
    for (const d of [...dirs].sort()) {
      try {
        await api(`/api/sftp/${sessionId}/mkdir`, {
          method: 'POST',
          body: { path: joinPath(remoteDir, d) },
        });
      } catch {}
    }
    for (const it of diff.upload) {
      const dirPart = it.rel.split('/').slice(0, -1).join('/');
      startUpload(sessionId, joinPath(remoteDir, dirPart), it.file, `${label} (sync)`);
    }
    toast(`syncing ${diff.upload.length} file(s) — see the transfer tray`, 'success');
    onClose();
    setTimeout(onDone, 1500);
  };

  const pull = () => {
    const a = document.createElement('a');
    a.href = `/api/sftp/${sessionId}/tar?path=${encodeURIComponent(remoteDir)}`;
    a.download = '';
    document.body.appendChild(a);
    a.click();
    a.remove();
    toast(`downloading ${remoteDir} as tar.gz`, 'success');
    onClose();
  };

  return (
    <Modal title={`Sync folder — ${remoteDir}`} onClose={onClose}>
      <div className="space-y-3">
        <div className="flex gap-2">
          <button
            className={`flex-1 rounded-md border px-3 py-2 text-sm ${
              mode === 'push' ? 'border-emerald-700 bg-emerald-950/40 text-emerald-200' : 'border-ink-700 text-zinc-400'
            }`}
            onClick={() => setMode('push')}
          >
            Push — local → remote
          </button>
          <button
            className={`flex-1 rounded-md border px-3 py-2 text-sm ${
              mode === 'pull' ? 'border-emerald-700 bg-emerald-950/40 text-emerald-200' : 'border-ink-700 text-zinc-400'
            }`}
            onClick={() => setMode('pull')}
          >
            Pull — remote → tar.gz
          </button>
        </div>

        {mode === 'push' && (
          <div className="space-y-3">
            <button className="btn-ghost border border-ink-700 w-full justify-center" onClick={() => dirInput.current?.click()}>
              <Upload size={14} /> pick local folder
            </button>
            <input
              ref={dirInput}
              type="file"
              className="hidden"
              // nonstandard but supported by every modern browser
              {...{ webkitdirectory: '', directory: '' }}
              onChange={(e) => {
                const files = [...e.target.files];
                e.target.value = '';
                if (files.length) analyze(files);
              }}
            />
            {busy && <div className="text-xs text-zinc-500">scanning remote…</div>}
            {diff && (
              <>
                <div className="rounded-md bg-ink-900 border border-ink-700 p-2.5 text-xs space-y-1">
                  <div className="text-zinc-300">
                    {diff.upload.length} file{diff.upload.length === 1 ? '' : 's'} to upload, {diff.skip} unchanged
                    {diff.truncated && <span className="text-amber-400"> (remote listing truncated at 50k entries)</span>}
                  </div>
                  <div className="max-h-40 overflow-y-auto space-y-0.5">
                    {diff.upload.slice(0, 100).map((it) => (
                      <div key={it.rel} className="font-mono text-[10px] text-zinc-500 truncate">
                        {remoteFiles?.some((r) => r.path === it.rel) ? '~' : '+'} {it.rel}
                        <span className="text-zinc-700"> {fmtSize(it.file.size)}</span>
                      </div>
                    ))}
                    {diff.upload.length > 100 && (
                      <div className="text-[10px] text-zinc-600">…and {diff.upload.length - 100} more</div>
                    )}
                  </div>
                </div>
                <button className="btn-primary w-full justify-center" onClick={push} disabled={!diff.upload.length}>
                  push {diff.upload.length} file{diff.upload.length === 1 ? '' : 's'}
                </button>
              </>
            )}
          </div>
        )}

        {mode === 'pull' && (
          <div className="space-y-3">
            <p className="text-xs text-zinc-400">
              Streams <code className="font-mono">tar czf</code> on the remote — one download for the whole directory.
            </p>
            <button className="btn-primary w-full justify-center" onClick={pull}>
              <Download size={14} /> download {remoteDir} as .tar.gz
            </button>
          </div>
        )}
      </div>
    </Modal>
  );
}
