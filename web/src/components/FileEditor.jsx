import React, { useEffect, useRef, useState } from 'react';
import { Save, X, Loader2 } from 'lucide-react';
import { api } from '../api';
import { useStore } from '../store';
import Modal from './Modal';

// In-place remote text editor over SFTP — read/write endpoints on the
// session's existing connection. Caps at 1MB server-side.
export default function FileEditor({ sessionId, path, onClose }) {
  const [content, setContent] = useState(null);
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const gutterRef = useRef(null);
  const taRef = useRef(null);
  const toast = useStore((s) => s.toast);

  useEffect(() => {
    api(`/api/sftp/${sessionId}/read?path=${encodeURIComponent(path)}`)
      .then((r) => {
        if (r.binary) setError(r.too_large ? 'file too large to edit (>1MB)' : 'binary file — cannot edit');
        else setContent(r.content ?? '');
      })
      .catch((e) => setError(e.message));
  }, [sessionId, path]);

  const save = async () => {
    setSaving(true);
    try {
      await api(`/api/sftp/${sessionId}/write`, {
        method: 'POST',
        body: { path, content },
      });
      setDirty(false);
      toast(`saved ${path}`, 'success');
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      setSaving(false);
    }
  };

  const lines = content == null ? 0 : content.split('\n').length;
  const name = path.split('/').pop();

  return (
    <Modal title={name} onClose={onClose} wide>
      <div className="flex flex-col gap-2 h-[70vh]">
        <div className="flex items-center gap-2 text-[11px] text-zinc-500">
          <span className="font-mono truncate flex-1">{path}</span>
          {dirty && <span className="text-amber-400">modified</span>}
        </div>
        {error ? (
          <div className="flex-1 flex items-center justify-center text-sm text-zinc-500">{error}</div>
        ) : content == null ? (
          <div className="flex-1 flex items-center justify-center text-zinc-500">
            <Loader2 size={18} className="animate-spin" />
          </div>
        ) : (
          <div className="flex-1 flex min-h-0 rounded-md border border-ink-700 bg-ink-950 overflow-hidden">
            <div
              ref={gutterRef}
              className="w-12 shrink-0 overflow-hidden text-right pr-2 py-2 font-mono text-[11px] leading-5 text-zinc-600 select-none bg-ink-900/60 border-r border-ink-800"
            >
              {Array.from({ length: lines }, (_, i) => (
                <div key={i}>{i + 1}</div>
              ))}
            </div>
            <textarea
              ref={taRef}
              className="flex-1 resize-none bg-transparent p-2 font-mono text-[11px] leading-5 text-zinc-200 outline-none whitespace-pre overflow-auto"
              value={content}
              spellCheck={false}
              onChange={(e) => {
                setContent(e.target.value);
                setDirty(true);
              }}
              onScroll={(e) => {
                if (gutterRef.current) gutterRef.current.scrollTop = e.target.scrollTop;
              }}
              onKeyDown={(e) => {
                if (e.key === 'Tab') {
                  e.preventDefault();
                  const el = e.target;
                  const { selectionStart: s, selectionEnd: en } = el;
                  setContent(content.slice(0, s) + '\t' + content.slice(en));
                  requestAnimationFrame(() => el.setSelectionRange(s + 1, s + 1));
                }
                if ((e.ctrlKey || e.metaKey) && e.key === 's') {
                  e.preventDefault();
                  if (dirty) save();
                }
              }}
            />
          </div>
        )}
        <div className="flex justify-end gap-2">
          <button className="btn-ghost" onClick={onClose}>
            <X size={14} /> Close
          </button>
          <button className="btn-primary" onClick={save} disabled={!dirty || saving || content == null}>
            <Save size={14} /> {saving ? 'saving…' : 'Save (Ctrl+S)'}
          </button>
        </div>
      </div>
    </Modal>
  );
}
