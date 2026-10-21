import React, { useEffect, useState } from 'react';
import { KeyRound, Plus, Trash2, Pencil, Copy, Sparkles, Eye } from 'lucide-react';
import { api } from '../api';
import { useStore } from '../store';
import Modal from '../components/Modal';

export default function Vault() {
  const { credentials, refreshAll, toast } = useStore();
  const [modal, setModal] = useState(null); // 'password' | 'key' | 'generate' | cred object
  const [viewKey, setViewKey] = useState(null); // credential with public key shown

  useEffect(() => {
    refreshAll(api).catch((e) => toast(e.message, 'error'));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const del = async (c) => {
    if (!confirm(`Delete credential "${c.name}"?`)) return;
    try {
      await api(`/api/credentials/${c.id}`, { method: 'DELETE' });
      toast('credential deleted', 'success');
      refreshAll(api);
    } catch (e) {
      if (e.status === 409 && confirm(`${e.message}. Delete anyway? Hosts will fall back to prompt-at-connect.`)) {
        await api(`/api/credentials/${c.id}?force=1`, { method: 'DELETE' });
        refreshAll(api);
      } else if (e.status !== 409) {
        toast(e.message, 'error');
      }
    }
  };

  const copy = async (text, what) => {
    try {
      await navigator.clipboard.writeText(text);
      toast(`${what} copied`, 'success');
    } catch {
      toast('clipboard unavailable', 'error');
    }
  };

  return (
    <div className="flex-1 overflow-y-auto p-6">
      <div className="max-w-4xl mx-auto space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-lg font-semibold flex items-center gap-2">
            <KeyRound size={18} className="text-emerald-400" /> Credential vault
          </h1>
          <div className="flex gap-2">
            <button className="btn-ghost border border-ink-700" onClick={() => setModal('generate')}>
              <Sparkles size={14} /> Generate key
            </button>
            <button className="btn-ghost border border-ink-700" onClick={() => setModal('key')}>
              <KeyRound size={14} /> Import key
            </button>
            <button className="btn-primary" onClick={() => setModal('password')}>
              <Plus size={14} /> Password
            </button>
          </div>
        </div>
        <p className="text-xs text-zinc-500">
          Secrets are stored AES-256-GCM encrypted on this server and are never returned to the browser after saving.
        </p>

        <div className="grid gap-2">
          {credentials.map((c) => (
            <div key={c.id} className="card flex items-center gap-3 px-4 py-3">
              <span className={c.type === 'key' ? 'text-violet-400' : 'text-amber-400'}>
                <KeyRound size={16} />
              </span>
              <div className="min-w-0 flex-1">
                <div className="text-sm text-zinc-100">{c.name}</div>
                <div className="text-[11px] text-zinc-500 font-mono truncate">
                  {c.type === 'key' ? 'private key' : 'password'}
                  {c.username ? ` · ${c.username}` : ''}
                  {c.comment ? ` · ${c.comment}` : ''}
                </div>
              </div>
              {c.public_key && (
                <button className="btn-ghost !py-1 text-xs" onClick={() => setViewKey(c)} title="View public key">
                  <Eye size={13} /> pubkey
                </button>
              )}
              <button className="btn-ghost !py-1 text-xs" onClick={() => setModal(c)}>
                <Pencil size={13} />
              </button>
              <button className="btn-ghost !py-1 text-xs hover:text-red-400" onClick={() => del(c)}>
                <Trash2 size={13} />
              </button>
            </div>
          ))}
          {credentials.length === 0 && (
            <div className="card px-4 py-10 text-center text-sm text-zinc-600">
              vault is empty — add a password or SSH key to get started
            </div>
          )}
        </div>
      </div>

      {modal && <CredentialModal mode={modal} onClose={() => setModal(null)} />}
      {viewKey && (
        <Modal title={`Public key — ${viewKey.name}`} onClose={() => setViewKey(null)}>
          <div className="space-y-3">
            <pre className="rounded-md bg-ink-900 border border-ink-700 p-3 font-mono text-[11px] text-emerald-300 break-all whitespace-pre-wrap">
              {viewKey.public_key}
            </pre>
            <p className="text-[11px] text-zinc-500">
              append this to <span className="font-mono">~/.ssh/authorized_keys</span> on your servers
            </p>
            <div className="flex justify-end">
              <button className="btn-primary" onClick={() => copy(viewKey.public_key, 'public key')}>
                <Copy size={14} /> Copy
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}

function CredentialModal({ mode, onClose }) {
  const editing = typeof mode === 'object' ? mode : null;
  const initial = editing ? editing.type : mode;
  const [type, setType] = useState(initial === 'generate' ? 'key' : initial);
  const [form, setForm] = useState({
    name: editing?.name || '',
    username: editing?.username || '',
    comment: editing?.comment || '',
    password: '',
    privateKey: '',
    passphrase: '',
    keyType: 'ed25519',
    bits: 3072,
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const { refreshAll, toast } = useStore();

  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target?.value ?? e }));

  const save = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      if (editing) {
        const body = { name: form.name, username: form.username || null, comment: form.comment };
        if (editing.type === 'password' && form.password) body.password = form.password;
        if (editing.type === 'key') {
          if (form.privateKey) body.privateKey = form.privateKey;
          if (form.passphrase !== '') body.passphrase = form.passphrase;
        }
        await api(`/api/credentials/${editing.id}`, { method: 'PUT', body });
        toast('credential updated', 'success');
      } else if (mode === 'generate') {
        const r = await api('/api/credentials/generate', {
          method: 'POST',
          body: {
            name: form.name,
            username: form.username || undefined,
            keyType: form.keyType,
            bits: form.keyType === 'rsa' ? form.bits : undefined,
            passphrase: form.passphrase || undefined,
            comment: form.comment,
          },
        });
        toast(`key generated — public key copied`, 'success');
        try {
          await navigator.clipboard.writeText(r.public_key);
        } catch {}
      } else {
        await api('/api/credentials', {
          method: 'POST',
          body:
            type === 'password'
              ? { name: form.name, type, username: form.username || undefined, password: form.password, comment: form.comment }
              : {
                  name: form.name,
                  type,
                  username: form.username || undefined,
                  privateKey: form.privateKey,
                  passphrase: form.passphrase || undefined,
                  comment: form.comment,
                },
        });
        toast('credential saved', 'success');
      }
      refreshAll(api);
      onClose();
    } catch (e2) {
      setError(e2.message);
    } finally {
      setBusy(false);
    }
  };

  const isGenerate = mode === 'generate' && !editing;

  return (
    <Modal
      title={editing ? `Edit ${editing.name}` : isGenerate ? 'Generate SSH key' : type === 'key' ? 'Import private key' : 'New password credential'}
      onClose={onClose}
      wide
    >
      <form onSubmit={save} className="grid grid-cols-2 gap-3">
        <div>
          <label className="label">Name</label>
          <input className="input" value={form.name} onChange={set('name')} placeholder="prod deploy key" autoFocus />
        </div>
        <div>
          <label className="label">Default username (optional)</label>
          <input className="input font-mono" value={form.username} onChange={set('username')} placeholder="ubuntu" />
        </div>

        {isGenerate && (
          <>
            <div>
              <label className="label">Key type</label>
              <select className="input" value={form.keyType} onChange={set('keyType')}>
                <option value="ed25519">ed25519 (recommended)</option>
                <option value="rsa">RSA</option>
              </select>
            </div>
            {form.keyType === 'rsa' && (
              <div>
                <label className="label">Bits</label>
                <select className="input" value={form.bits} onChange={set('bits')}>
                  <option value={2048}>2048</option>
                  <option value={3072}>3072</option>
                  <option value={4096}>4096</option>
                </select>
              </div>
            )}
          </>
        )}

        {(type === 'key' || isGenerate) && (
          <div className="col-span-2">
            <label className="label">Passphrase (optional)</label>
            <input className="input" type="password" value={form.passphrase} onChange={set('passphrase')} autoComplete="new-password" />
          </div>
        )}

        {!editing && type === 'password' && !isGenerate && (
          <div className="col-span-2">
            <label className="label">Password</label>
            <input className="input" type="password" value={form.password} onChange={set('password')} autoComplete="new-password" />
          </div>
        )}

        {type === 'key' && !isGenerate && (
          <div className="col-span-2">
            <label className="label">
              Private key (PEM/OpenSSH){' '}
              {editing && <span className="text-zinc-600">— blank keeps existing key</span>}
            </label>
            <textarea
              className="input font-mono !text-[11px]"
              rows="7"
              spellCheck="false"
              placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
              value={form.privateKey}
              onChange={set('privateKey')}
            />
          </div>
        )}

        {editing?.type === 'password' && (
          <div className="col-span-2">
            <label className="label">
              New password <span className="text-zinc-600">— blank keeps existing</span>
            </label>
            <input className="input" type="password" value={form.password} onChange={set('password')} autoComplete="new-password" />
          </div>
        )}

        <div className="col-span-2">
          <label className="label">Comment</label>
          <input className="input" value={form.comment} onChange={set('comment')} />
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
          <button
            className="btn-primary"
            disabled={
              busy ||
              !form.name ||
              (!editing && !isGenerate && type === 'password' && !form.password) ||
              (!editing && !isGenerate && type === 'key' && !form.privateKey)
            }
          >
            {busy ? '…' : isGenerate ? 'Generate' : 'Save'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
