import React, { useMemo, useRef, useState } from 'react';
import { FileUp } from 'lucide-react';
import { api } from '../api';
import { useStore } from '../store';
import Modal from './Modal';

// Parse OpenSSH client config into host entries. Pattern/wildcard Host blocks
// are skipped. IdentityFile entries get matched against uploaded key files by
// basename; ProxyJump resolves to an existing/imported host by name.
function parseSshConfig(text) {
  const entries = [];
  let cur = null;
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const m = line.match(/^([A-Za-z][A-Za-z-]*)[\s=]+(.+)$/);
    if (!m) continue;
    const key = m[1].toLowerCase();
    const val = m[2].trim();
    if (key === 'host') {
      for (const pat of val.split(/\s+/)) {
        if (/[*?]/.test(pat)) continue;
        cur = { name: pat, hostname: pat, port: 22, username: '', identityfile: '', proxyjump: '' };
        entries.push(cur);
      }
      continue;
    }
    if (!cur) continue;
    if (key === 'hostname') cur.hostname = val;
    else if (key === 'user') cur.username = val;
    else if (key === 'port') cur.port = parseInt(val, 10) || 22;
    else if (key === 'identityfile') cur.identityfile = val.replace(/^~/, '').split('/').pop();
    else if (key === 'proxyjump') cur.proxyjump = val.split('@').pop().split(':')[0];
  }
  return entries;
}

export default function SshConfigImport({ onClose }) {
  const [text, setText] = useState('');
  const [keyFiles, setKeyFiles] = useState({}); // basename -> {name, content}
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState('');
  const fileRef = useRef(null);
  const { refreshAll, toast, hosts } = useStore();

  const parsed = useMemo(() => parseSshConfig(text), [text]);

  const pickFiles = async (e) => {
    const map = { ...keyFiles };
    for (const f of e.target.files) {
      if (f.name.endsWith('.pub') || f.size > 64 * 1024) continue;
      const content = await f.text();
      if (/PRIVATE KEY/.test(content)) map[f.name] = { name: f.name, content };
    }
    setKeyFiles(map);
    e.target.value = '';
  };

  const doImport = async () => {
    setBusy(true);
    setResult('');
    let created = 0,
      creds = 0,
      errs = 0;
    try {
      const credIds = {};
      for (const [basename, f] of Object.entries(keyFiles)) {
        try {
          const r = await api('/api/credentials', {
            method: 'POST',
            body: { name: basename, type: 'key', privateKey: f.content, comment: 'imported from ~/.ssh' },
          });
          credIds[basename] = r.credential.id;
          creds++;
        } catch {
          errs++;
        }
      }
      // jump resolution: existing host names + names created this run
      const nameToId = new Map(hosts.map((h) => [h.name, h.id]));
      for (const e2 of parsed) {
        try {
          const credId = e2.identityfile && credIds[e2.identityfile] ? credIds[e2.identityfile] : null;
          const r = await api('/api/hosts', {
            method: 'POST',
            body: {
              name: e2.name,
              hostname: e2.hostname,
              port: e2.port,
              username: e2.username || 'root',
              auth_type: credId ? 'credential' : 'ask',
              credential_id: credId,
              jump_host_id: e2.proxyjump ? nameToId.get(e2.proxyjump) || null : null,
            },
          });
          nameToId.set(e2.name, r.host.id);
          created++;
        } catch {
          errs++;
        }
      }
      setResult(`imported ${created} hosts${creds ? ` + ${creds} keys` : ''}${errs ? ` (${errs} errors)` : ''}`);
      refreshAll(api);
      toast('ssh config imported', 'success');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal title="Import ~/.ssh/config" onClose={onClose} wide>
      <div className="space-y-3">
        <div>
          <label className="label">Paste your ssh config</label>
          <textarea
            className="input font-mono !text-[11px]"
            rows="8"
            spellCheck="false"
            placeholder={'Host prod\n  HostName 10.0.0.5\n  User ubuntu\n  IdentityFile ~/.ssh/id_ed25519'}
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
        </div>
        <div className="flex items-center gap-2">
          <button type="button" className="btn-ghost border border-ink-700 text-xs" onClick={() => fileRef.current?.click()}>
            <FileUp size={13} /> attach key files
          </button>
          <input ref={fileRef} type="file" multiple className="hidden" onChange={pickFiles} />
          <span className="text-[11px] text-zinc-500">
            {Object.keys(keyFiles).length
              ? Object.keys(keyFiles).join(', ')
              : 'select your private keys (matched by IdentityFile name)'}
          </span>
        </div>

        {parsed.length > 0 && (
          <div className="rounded-md border border-ink-700 max-h-44 overflow-y-auto">
            {parsed.map((h, i) => (
              <div key={i} className="flex items-center gap-2 px-3 py-1.5 text-xs border-b border-ink-800 last:border-0">
                <span className="text-zinc-200 w-28 truncate">{h.name}</span>
                <span className="font-mono text-zinc-500 flex-1 truncate">
                  {h.username || 'root'}@{h.hostname}:{h.port}
                </span>
                {h.identityfile && (
                  <span className={`text-[10px] ${keyFiles[h.identityfile] ? 'text-emerald-400' : 'text-amber-400'}`}>
                    {h.identityfile}
                    {keyFiles[h.identityfile] ? ' ✓' : ' (key not attached)'}
                  </span>
                )}
                {h.proxyjump && <span className="text-[10px] text-sky-400">via {h.proxyjump}</span>}
              </div>
            ))}
          </div>
        )}

        {result && <div className="text-sm text-emerald-300">{result}</div>}

        <div className="flex justify-end gap-2">
          <button className="btn-ghost" onClick={onClose}>
            Close
          </button>
          <button className="btn-primary" disabled={busy || parsed.length === 0} onClick={doImport}>
            {busy ? 'importing…' : `Import ${parsed.length} host${parsed.length === 1 ? '' : 's'}`}
          </button>
        </div>
      </div>
    </Modal>
  );
}
