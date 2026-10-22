'use strict';

const express = require('express');
const path = require('path');
const { getSession, getSftp } = require('../ssh/manager');
const { auditReq } = require('../auth');

const router = express.Router();
const json = express.json({ limit: '1500kb' });

const S_IFMT = 0o170000;
const S_IFDIR = 0o040000;

function sftpError(res, e, fallback = 'sftp error') {
  const msg = e?.message || String(e);
  if (/no such file/i.test(msg)) return res.status(404).json({ error: 'path not found' });
  if (/permission denied/i.test(msg)) return res.status(403).json({ error: 'permission denied' });
  return res.status(400).json({ error: `${fallback}: ${msg}` });
}

async function requireSftp(req, res) {
  const session = getSession(req.user.id, req.params.sid);
  if (!session) {
    res.status(404).json({ error: 'session not found or expired' });
    return null;
  }
  try {
    const sftp = await getSftp(session);
    return { session, sftp };
  } catch (e) {
    sftpError(res, e, 'could not open sftp channel');
    return null;
  }
}

const pReaddir = (sftp, p) => new Promise((res, rej) => sftp.readdir(p, (e, l) => (e ? rej(e) : res(l))));
const pRealpath = (sftp, p) => new Promise((res, rej) => sftp.realpath(p, (e, r) => (e ? rej(e) : res(r))));
const pStat = (sftp, p) => new Promise((res, rej) => sftp.stat(p, (e, s) => (e ? rej(e) : res(s))));
const pLstat = (sftp, p) => new Promise((res, rej) => sftp.lstat(p, (e, s) => (e ? rej(e) : res(s))));
const pMkdir = (sftp, p) => new Promise((res, rej) => sftp.mkdir(p, (e) => (e ? rej(e) : res())));
const pRename = (sftp, a, b) => new Promise((res, rej) => sftp.rename(a, b, (e) => (e ? rej(e) : res())));
const pUnlink = (sftp, p) => new Promise((res, rej) => sftp.unlink(p, (e) => (e ? rej(e) : res())));
const pRmdir = (sftp, p) => new Promise((res, rej) => sftp.rmdir(p, (e) => (e ? rej(e) : res())));

function cleanPathParam(v) {
  const s = String(v ?? '.');
  if (s.length > 4096 || s.includes('\0')) return null;
  return s;
}

function entryView(e) {
  const mode = e.attrs?.mode;
  const isDir =
    mode != null ? (mode & S_IFMT) === S_IFDIR : typeof e.longname === 'string' && e.longname.startsWith('d');
  return {
    name: e.filename,
    is_dir: isDir,
    size: e.attrs?.size ?? 0,
    mtime: (e.attrs?.mtime ?? 0) * 1000,
    mode: mode != null ? (mode & 0o7777).toString(8).padStart(4, '0') : '',
  };
}

// List a directory. `path` defaults to the user's home on the remote.
router.get('/:sid/list', async (req, res) => {
  const ctx = await requireSftp(req, res);
  if (!ctx) return;
  const p = cleanPathParam(req.query.path);
  if (p === null) return res.status(400).json({ error: 'bad path' });
  try {
    const real = await pRealpath(ctx.sftp, p || '.');
    const list = await pReaddir(ctx.sftp, real);
    const entries = list
      .map(entryView)
      .filter((e) => e.name !== '.' && e.name !== '..')
      .sort((a, b) => Number(b.is_dir) - Number(a.is_dir) || a.name.localeCompare(b.name));
    res.json({ path: real, entries });
  } catch (e) {
    sftpError(res, e, 'list failed');
  }
});

const READ_CAP = 1024 * 1024; // editor/preview cap

function looksBinary(buf) {
  const n = Math.min(buf.length, 8192);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
  return false;
}

// Read a small file into memory — powers the in-app editor and previews.
// Returns {path, size, binary, content?} — content is utf8 text when not binary.
router.get('/:sid/read', async (req, res) => {
  const ctx = await requireSftp(req, res);
  if (!ctx) return;
  const p = cleanPathParam(req.query.path);
  if (p === null || p === '.') return res.status(400).json({ error: 'bad path' });
  try {
    const st = await pStat(ctx.sftp, p);
    if ((st.mode & S_IFMT) === S_IFDIR) return res.status(400).json({ error: 'cannot read a directory' });
    if (st.size > READ_CAP) {
      return res.json({ path: p, size: st.size, binary: true, too_large: true });
    }
    const buf = await new Promise((resolve, reject) => {
      const chunks = [];
      const rs = ctx.sftp.createReadStream(p);
      rs.on('data', (c) => chunks.push(c));
      rs.on('error', reject);
      rs.on('end', () => resolve(Buffer.concat(chunks)));
    });
    if (looksBinary(buf)) return res.json({ path: p, size: buf.length, binary: true });
    auditReq(req, 'sftp.read', `${ctx.session.label}:${p}`);
    res.json({ path: p, size: buf.length, binary: false, content: buf.toString('utf8') });
  } catch (e) {
    sftpError(res, e, 'read failed');
  }
});

// Write text content back — the editor's save.
router.post('/:sid/write', json, async (req, res) => {
  const ctx = await requireSftp(req, res);
  if (!ctx) return;
  const p = cleanPathParam(req.body?.path);
  const content = req.body?.content;
  if (p === null || p === '.' || typeof content !== 'string') {
    return res.status(400).json({ error: 'path and content required' });
  }
  if (Buffer.byteLength(content) > READ_CAP) {
    return res.status(400).json({ error: 'content too large' });
  }
  try {
    const ws = ctx.sftp.createWriteStream(p);
    await new Promise((resolve, reject) => {
      ws.on('error', reject);
      ws.on('close', resolve);
      ws.end(content, 'utf8');
    });
    auditReq(req, 'sftp.write', `${ctx.session.label}:${p}`);
    res.json({ ok: true });
  } catch (e) {
    sftpError(res, e, 'write failed');
  }
});

// Stream a file download.
router.get('/:sid/download', async (req, res) => {
  const ctx = await requireSftp(req, res);
  if (!ctx) return;
  const p = cleanPathParam(req.query.path);
  if (p === null || p === '.') return res.status(400).json({ error: 'bad path' });
  try {
    const st = await pStat(ctx.sftp, p);
    if ((st.mode & S_IFMT) === S_IFDIR) return res.status(400).json({ error: 'cannot download a directory' });
    const filename = path.posix.basename(p);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`);
    if (st.size != null) res.setHeader('Content-Length', String(st.size));
    const rs = ctx.sftp.createReadStream(p);
    rs.on('error', (e) => {
      if (!res.headersSent) sftpError(res, e, 'download failed');
      else res.destroy(e);
    });
    // Client aborting mid-download must kill the sftp read stream — otherwise
    // the channel (and its window/buffers) leaks until the connection dies.
    res.on('close', () => {
      if (!res.writableEnded) rs.destroy();
    });
    rs.pipe(res);
    auditReq(req, 'sftp.download', `${ctx.session.label}:${p}`);
  } catch (e) {
    sftpError(res, e, 'download failed');
  }
});

// Stream a file upload: raw request body -> remote file.
const UPLOAD_CAP = 2 * 1024 * 1024 * 1024; // 2GB per file
router.post('/:sid/upload', async (req, res) => {
  const ctx = await requireSftp(req, res);
  if (!ctx) return;
  const dir = cleanPathParam(req.query.path);
  const name = cleanPathParam(req.query.name);
  if (dir === null || !name || name === '.') return res.status(400).json({ error: 'bad path/name' });
  const safeName = path.posix.basename(name);
  const full = path.posix.join(dir, safeName);
  try {
    const ws = ctx.sftp.createWriteStream(full);
    await new Promise((resolve, reject) => {
      let received = 0;
      ws.on('error', reject);
      req.on('error', reject);
      ws.on('close', resolve);
      req.on('data', (chunk) => {
        received += chunk.length;
        if (received > UPLOAD_CAP) {
          req.unpipe(ws);
          ws.destroy();
          reject(Object.assign(new Error('file too large'), { code: 'too_large' }));
          req.resume(); // drain the rest so the socket stays clean
        }
      });
      req.pipe(ws);
    });
    auditReq(req, 'sftp.upload', `${ctx.session.label}:${full}`);
    res.json({ ok: true, path: full });
  } catch (e) {
    if (e?.code === 'too_large') return res.status(413).json({ error: 'file exceeds 2GB upload limit' });
    sftpError(res, e, 'upload failed');
  }
});

router.post('/:sid/mkdir', json, async (req, res) => {
  const ctx = await requireSftp(req, res);
  if (!ctx) return;
  const p = cleanPathParam(req.body?.path);
  if (p === null) return res.status(400).json({ error: 'bad path' });
  try {
    await pMkdir(ctx.sftp, p);
    res.json({ ok: true });
  } catch (e) {
    sftpError(res, e, 'mkdir failed');
  }
});

router.post('/:sid/rename', json, async (req, res) => {
  const ctx = await requireSftp(req, res);
  if (!ctx) return;
  const from = cleanPathParam(req.body?.from);
  const to = cleanPathParam(req.body?.to);
  if (from === null || to === null) return res.status(400).json({ error: 'bad path' });
  try {
    await pRename(ctx.sftp, from, to);
    res.json({ ok: true });
  } catch (e) {
    sftpError(res, e, 'rename failed');
  }
});

router.post('/:sid/delete', json, async (req, res) => {
  const ctx = await requireSftp(req, res);
  if (!ctx) return;
  const p = cleanPathParam(req.body?.path);
  if (p === null || p === '/' || p === '.') return res.status(400).json({ error: 'refusing to delete that path' });
  try {
    if (req.body?.recursive) {
      await rmrf(ctx.sftp, p, 0);
    } else {
      const st = await pLstat(ctx.sftp, p);
      if ((st.mode & S_IFMT) === S_IFDIR) await pRmdir(ctx.sftp, p);
      else await pUnlink(ctx.sftp, p);
    }
    res.json({ ok: true });
  } catch (e) {
    sftpError(res, e, 'delete failed');
  }
});

// Recursive file listing for folder sync — files only (dirs implied),
// bounded so a pathological tree can't run away.
const RLIST_DEPTH = 12;
const RLIST_MAX = 50000;
router.get('/:sid/rlist', async (req, res) => {
  const ctx = await requireSftp(req, res);
  if (!ctx) return;
  const p = cleanPathParam(req.query.path);
  if (p === null) return res.status(400).json({ error: 'bad path' });
  try {
    const real = await pRealpath(ctx.sftp, p || '.');
    const files = [];
    const walk = async (dir, depth) => {
      if (depth > RLIST_DEPTH || files.length >= RLIST_MAX) return;
      const list = await pReaddir(ctx.sftp, dir);
      for (const e of list) {
        if (e.filename === '.' || e.filename === '..') continue;
        const full = path.posix.join(dir, e.filename);
        const v = entryView(e);
        if (v.is_dir) await walk(full, depth + 1);
        else files.push({ path: full.slice(real.length + 1) || e.filename, size: v.size, mtime: v.mtime });
        if (files.length >= RLIST_MAX) return;
      }
    };
    const st = await pStat(ctx.sftp, real);
    if ((st.mode & S_IFMT) === S_IFDIR) await walk(real, 0);
    else files.push({ path: path.posix.basename(real), size: st.size, mtime: st.mtime * 1000 });
    res.json({ path: real, files, truncated: files.length >= RLIST_MAX });
  } catch (e) {
    sftpError(res, e, 'recursive list failed');
  }
});

// Pull a remote directory as a tar.gz streamed off `tar` on the remote.
router.get('/:sid/tar', async (req, res) => {
  const session = getSession(req.user.id, req.params.sid);
  if (!session) return res.status(404).json({ error: 'session not found or expired' });
  const p = cleanPathParam(req.query.path);
  if (p === null || p === '/' || p === '.') return res.status(400).json({ error: 'bad path' });
  const name = path.posix.basename(p) || 'dir';
  const cmd = `tar czf - -C ${shellQuote(path.posix.dirname(p))} ${shellQuote(path.posix.basename(p))}`;
  try {
    session.conn.exec(cmd, (err, ch) => {
      if (err) return res.status(500).json({ error: 'exec failed: ' + err.message });
      res.setHeader('Content-Type', 'application/gzip');
      res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(name)}.tar.gz`);
      let errText = '';
      ch.stderr?.on('data', (d) => { errText += d.toString(); });
      ch.on('close', (code) => {
        if (!res.headersSent && code !== 0) {
          return res.status(400).json({ error: `tar failed: ${errText.slice(0, 200)}` });
        }
      });
      res.on('close', () => { if (!res.writableEnded) try { ch.close(); } catch {} });
      ch.pipe(res);
      auditReq(req, 'sftp.tardl', `${session.label}:${p}`);
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

function shellQuote(s) {
  return `'${String(s).replace(/'/g, "'\\''")}'`;
}

// lstat (not stat): a symlink inside the tree must be unlinked as a link —
// stat() would follow it into the target directory and delete its contents.
async function rmrf(sftp, p, depth) {
  if (depth > 32) throw new Error('directory too deep to delete recursively');
  const st = await pLstat(sftp, p);
  if ((st.mode & S_IFMT) !== S_IFDIR) return pUnlink(sftp, p);
  const list = await pReaddir(sftp, p);
  for (const e of list) {
    if (e.filename === '.' || e.filename === '..') continue;
    await rmrf(sftp, path.posix.join(p, e.filename), depth + 1);
  }
  return pRmdir(sftp, p);
}

module.exports = router;
