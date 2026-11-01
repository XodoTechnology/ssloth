import { useStore } from './store';

let seq = 0;

// Uploads run in this module (not inside a component) so they survive tab
// switches and the SFTP panel being closed. Progress lands in the store's
// transfer tray; completion fires a toast.
async function remoteSize(sessionId, p) {
  try {
    const r = await fetch(`/api/sftp/${sessionId}/stat?path=${encodeURIComponent(p)}`,
      { credentials: 'same-origin' });
    if (!r.ok) return 0;
    const j = await r.json();
    return j.size || 0;
  } catch { return 0; }
}

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
  const job = runUpload(id, sessionId, dir, file, label);
  job.then((ok) => ok).catch(() => {});
  return id;
}

/// The upload proper — resumes part-sent files: stat the remote, slice the
/// local File at that offset, and open the stream in append mode.
export async function runUpload(id, sessionId, dir, file, label) {
  const target = `${dir}/${file.name}`;
  const have = await remoteSize(sessionId, target);
  let body = file;
  let append = false;
  if (have > 0 && have < file.size) {
    body = file.slice(have);
    append = true;
    useStore.getState().updateTransfer(id, { pct: Math.round((have / file.size) * 100), state: 'active' });
  } else if (have >= file.size && have > 0) {
    useStore.getState().updateTransfer(id, { state: 'done', pct: 100 });
    useStore.getState().toast(`${file.name} already uploaded → ${label}`, 'success');
    setTimeout(() => useStore.getState().removeTransfer(id), 15000);
    return true;
  }

  const done = (state, pct, error) => {
    const s = useStore.getState();
    s.updateTransfer(id, { state, pct, error });
    if (state === 'done') s.toast(`Uploaded ${file.name} → ${label}`, 'success');
    else s.toast(`Upload failed: ${file.name} → ${label}${error ? ` (${error})` : ''}`, 'error');
    setTimeout(() => useStore.getState().removeTransfer(id), 30000);
  };

  const basePct = append ? Math.round((have / file.size) * 100) : 0;
  const spanPct = append ? 100 - basePct : 100;
  const xhr = new XMLHttpRequest();
  xhr.open(
    'POST',
    `/api/sftp/${sessionId}/upload?path=${encodeURIComponent(dir)}&name=${encodeURIComponent(file.name)}${append ? '&append=1' : ''}`
  );
  xhr.withCredentials = true;
  let lastPct = -1;
  xhr.upload.onprogress = (ev) => {
    if (!ev.lengthComputable) return;
    const pct = basePct + Math.round((ev.loaded / ev.total) * spanPct);
    if (pct - lastPct >= 2 || pct === 100) {
      lastPct = pct;
      useStore.getState().updateTransfer(id, { pct });
    }
  };
  return new Promise((resolve) => {
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        done('done', 100);
        resolve(true);
      } else {
        let msg = '';
        try {
          msg = JSON.parse(xhr.responseText).error;
        } catch {}
        done('error', undefined, msg);
        resolve(false);
      }
    };
    xhr.onerror = () => { done('error'); resolve(false); };
    xhr.send(body);
  });
}

/// FIFO queue — uploads run one at a time so a busy link isn't fighting
/// itself and retries stay in order.
let queue = Promise.resolve();
export function queueUpload(sessionId, dir, file, label) {
  const id = `tr${++seq}-${Date.now().toString(36)}`;
  useStore.getState().addTransfer({
    id, sessionId, label: label || sessionId, name: file.name, dir,
    kind: 'up', pct: 0, state: 'active',
  });
  queue = queue.then(() => runUpload(id, sessionId, dir, file, label).catch(() => {}));
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
    queueUpload(sessionId, target, file, label);
  }
}
