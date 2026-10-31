import { useStore } from './store';

let seq = 0;

// Uploads run in this module (not inside a component) so they survive tab
// switches and the SFTP panel being closed. Progress lands in the store's
// transfer tray; completion fires a toast.
export function startUpload(sessionId, dir, file, label) {
  const id = `tr${++seq}-${Date.now().toString(36)}`;
  const store = useStore.getState();
  store.addTransfer({
    id,
    sessionId,
    label: label || sessionId,
    name: file.name,
    dir,
    kind: 'up',
    pct: 0,
    state: 'active',
  });

  const done = (state, pct, error) => {
    const s = useStore.getState();
    s.updateTransfer(id, { state, pct, error });
    if (state === 'done') s.toast(`Uploaded ${file.name} → ${label}`, 'success');
    else s.toast(`Upload failed: ${file.name} → ${label}${error ? ` (${error})` : ''}`, 'error');
    setTimeout(() => useStore.getState().removeTransfer(id), 30000);
  };

  const xhr = new XMLHttpRequest();
  xhr.open(
    'POST',
    `/api/sftp/${sessionId}/upload?path=${encodeURIComponent(dir)}&name=${encodeURIComponent(file.name)}`
  );
  xhr.withCredentials = true;
  let lastPct = -1;
  xhr.upload.onprogress = (ev) => {
    if (!ev.lengthComputable) return;
    const pct = Math.round((ev.loaded / ev.total) * 100);
    if (pct - lastPct >= 2 || pct === 100) {
      lastPct = pct;
      useStore.getState().updateTransfer(id, { pct });
    }
  };
  xhr.onload = () => {
    if (xhr.status >= 200 && xhr.status < 300) {
      done('done', 100);
    } else {
      let msg = '';
      try {
        msg = JSON.parse(xhr.responseText).error;
      } catch {}
      done('error', undefined, msg);
    }
  };
  xhr.onerror = () => done('error');
  xhr.send(file);
  return id;
}

async function mkdirp(sessionId, dir) {
  // best-effort mkdir of each segment; failures (exists) are ignored
  let cur = '';
  for (const seg of dir.split('/').filter(Boolean)) {
    cur += '/' + seg;
    try {
      await fetch(`/api/sftp/${sessionId}/mkdir`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ path: cur }),
      });
    } catch {}
  }
}

// items: File[] or {file, rel}[] — rel is a dir path under `dir`
// (e.g. 'myfolder/sub'), so dropped folders keep their structure.
export function uploadToSession(sessionId, dir, items, label) {
  const ensured = new Set();
  for (const it of items) {
    const file = it instanceof File ? it : it.file;
    const rel =
      it instanceof File
        ? (it.webkitRelativePath || '').replace(/\/[^/]*$/, '').replace(/^\/+/, '')
        : (it.rel || '').replace(/^\/+|\/+$/g, '');
    const target = rel ? `${dir}/${rel}` : dir;
    if (rel && !ensured.has(target)) {
      ensured.add(target);
      mkdirp(sessionId, target);
    }
    startUpload(sessionId, target, file, label);
  }
}
