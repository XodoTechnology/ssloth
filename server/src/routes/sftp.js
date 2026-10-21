'use strict';

const express = require('express');
const path = require('path');
const { getSession, getSftp } = require('../ssh/manager');
const { auditReq } = require('../auth');

const router = express.Router();
const json = express.json({ limit: '64kb' });

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
    rs.pipe(res);
    auditReq(req, 'sftp.download', `${ctx.session.label}:${p}`);
  } catch (e) {
    sftpError(res, e, 'download failed');
  }
});

// Stream a file upload: raw request body -> remote file.
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
      ws.on('error', reject);
      req.on('error', reject);
      ws.on('close', resolve);
      req.pipe(ws);
    });
    auditReq(req, 'sftp.upload', `${ctx.session.label}:${full}`);
    res.json({ ok: true, path: full });
  } catch (e) {
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
      const st = await pStat(ctx.sftp, p);
      if ((st.mode & S_IFMT) === S_IFDIR) await pRmdir(ctx.sftp, p);
      else await pUnlink(ctx.sftp, p);
    }
    res.json({ ok: true });
  } catch (e) {
    sftpError(res, e, 'delete failed');
  }
});

async function rmrf(sftp, p, depth) {
  if (depth > 32) throw new Error('directory too deep to delete recursively');
  const st = await pStat(sftp, p);
  if ((st.mode & S_IFMT) !== S_IFDIR) return pUnlink(sftp, p);
  const list = await pReaddir(sftp, p);
  for (const e of list) {
    if (e.filename === '.' || e.filename === '..') continue;
    await rmrf(sftp, path.posix.join(p, e.filename), depth + 1);
  }
  return pRmdir(sftp, p);
}

module.exports = router;
