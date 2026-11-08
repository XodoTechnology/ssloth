'use strict';

const express = require('express');
const rateLimit = require('express-rate-limit');
const QRCode = require('qrcode');
const { db, audit } = require('../db');
const buildInfo = require('../buildinfo');
const {
  hashPassword,
  verifyPassword,
  DUMMY_HASH,
  encryptSecret,
  decryptSecret,
  generateTotpSecret,
  verifyTotp,
  sha256,
} = require('../crypto');
const {
  COOKIE_NAME,
  createSession,
  destroySession,
  resolveCookie,
  requireAuth,
} = require('../auth');
const { DESKTOP } = require('../config');
const { lanActive, isLoopbackClient } = require('../netcfg');
const oidc = require('../oidc');
const { destroyUserSessions } = require('../ssh/manager');
const { stopTunnelsForUser } = require('./tunnels');

const router = express.Router();

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too many attempts, try again later' },
});

// Per-username cap on top of the per-IP one: credential stuffing that
// rotates source IPs still hits a wall after a handful of tries against
// the same account. Falls back to IP when no username is supplied.
const loginUserLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 8,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const u = String(req.body?.username || '').trim().toLowerCase();
    return u ? `u:${u}` : `ip:${req.ip}`;
  },
  message: { error: 'too many attempts for this account, try again later' },
});

// PINs are only 4-8 digits — far weaker than passwords, so they get a much
// tighter per-IP budget than the general auth limiter on top of it.
const pinLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too many pin attempts, try again later' },
});

const USERNAME_RE = /^[a-zA-Z0-9_.-]{2,32}$/;

function publicUser(u) {
  return {
    id: u.id,
    username: u.username,
    is_admin: !!u.is_admin,
    role: u.role || (u.is_admin ? 'admin' : 'user'),
    totp_enabled: !!u.totp_enabled,
  };
}

// ---- OIDC single-sign-on (env-configured; disabled unless issuer+client id set) ----
router.get('/oidc/login', authLimiter, async (req, res) => {
  if (!oidc.enabled()) return res.status(404).json({ error: 'oidc not configured' });
  try {
    await oidc.startLogin(req, res);
  } catch (e) {
    res.redirect(`/login?oidc_error=${encodeURIComponent(e.message)}`);
  }
});

router.get('/oidc/callback', authLimiter, (req, res) => {
  if (!oidc.enabled()) return res.status(404).json({ error: 'oidc not configured' });
  oidc
    .finishLogin(req, res, { db, createSession, audit, hashPassword, DUMMY_HASH, isLoopbackClient, lanActive })
    .catch((e) => res.redirect(`/login?oidc_error=${encodeURIComponent(e.message)}`));
});

// ---- State / setup / login ----

router.get('/state', (req, res) => {
  const userCount = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
  const user = resolveCookie(req);
  res.json({
    setup_required: userCount === 0,
    authenticated: !!user,
    user: user ? publicUser(user) : null,
    desktop: DESKTOP,
    oidc: oidc.enabled(),
    pin_set: DESKTOP && !!db.prepare('SELECT COUNT(*) AS c FROM users WHERE pin_hash IS NOT NULL').get().c,
    version: buildInfo.version,
    commit: buildInfo.commit,
    build_date: buildInfo.buildDate,
  });
});

router.post('/setup', authLimiter, async (req, res) => {
  const userCount = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
  if (userCount > 0) return res.status(403).json({ error: 'already initialized' });

  const { username, password } = req.body || {};
  if (!USERNAME_RE.test(username || '')) {
    return res.status(400).json({ error: 'username must be 2-32 chars: letters, numbers, _ . -' });
  }
  if (typeof password !== 'string' || password.length < 10) {
    return res.status(400).json({ error: 'password must be at least 10 characters' });
  }
  const info = db
    .prepare('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)')
    .run(username, await hashPassword(password));
  audit(null, 'auth.setup', `admin user '${username}' created`, req);
  createSession(info.lastInsertRowid, req, res);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
  res.json({ user: publicUser(user) });
});

router.post('/login', authLimiter, loginUserLimiter, async (req, res) => {
  const { username, password, totp } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username || '');
  const ok = await verifyPassword(String(password || ''), user ? user.password_hash : DUMMY_HASH);
  if (!ok) {
    audit(user, 'auth.login_failed', `bad password for '${username}'`, req);
    return res.status(401).json({ error: 'invalid credentials' });
  }
  // Per-account network restriction (desktop LAN mode): checked after the
  // password so the response doesn't reveal which accounts are restricted.
  if (lanActive() && !isLoopbackClient(req) && user.lan_allowed === 0) {
    audit(user, 'auth.login_denied', 'account not allowed from this network', req);
    return res.status(403).json({ error: 'this account cannot sign in from the network' });
  }
  if (user.totp_enabled) {
    if (!totp) {
      return res.status(401).json({ error: 'totp required', totp_required: true });
    }
    const secret = decryptSecret(user.totp_secret);
    const step = verifyTotp(secret, totp);
    // Replay protection: each 30s step may only be consumed once.
    if (step === false || step <= user.totp_last_step) {
      audit(user, 'auth.login_failed', step === false ? 'bad TOTP code' : 'replayed TOTP code', req);
      return res.status(401).json({ error: 'invalid authenticator code', totp_required: true });
    }
    db.prepare('UPDATE users SET totp_last_step = ? WHERE id = ?').run(step, user.id);
  }
  createSession(user.id, req, res);
  audit(user, 'auth.login', 'login success', req);
  res.json({ user: publicUser(user) });
});

router.post('/logout', (req, res) => {
  const user = resolveCookie(req);
  destroySession(req, res);
  if (user) {
    // Logging out means disconnecting — tear down live SSH sessions and
    // tunnels so nothing keeps running under a dead login.
    destroyUserSessions(user.id);
    stopTunnelsForUser(user.id);
    audit(user, 'auth.logout', '', req);
  }
  res.json({ ok: true });
});

// ---- Session management ----
// List this account's live login sessions. Note the column units: created_at
// is unixepoch() seconds (DB default) while expires_at/last_seen_at are ms
// (written by resolveToken/touchSession).
router.get('/sessions', requireAuth, (req, res) => {
  const rows = db
    .prepare(
      `SELECT id, ip, ua, created_at, expires_at, last_seen_at FROM sessions
       WHERE user_id = ? AND expires_at > ? ORDER BY COALESCE(last_seen_at, created_at * 1000) DESC`
    )
    .all(req.user.id, Date.now());
  res.json({
    sessions: rows.map((s) => ({
      id: s.id,
      ip: s.ip,
      ua: s.ua,
      created_at: s.created_at * 1000,
      expires_at: s.expires_at,
      last_seen_at: s.last_seen_at,
      current: s.id === req.user.session_id,
    })),
  });
});

router.delete('/sessions/:id', authLimiter, requireAuth, (req, res) => {
  const r = db.prepare('DELETE FROM sessions WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  if (!r.changes) return res.status(404).json({ error: 'not found' });
  audit(req.user, 'auth.session_revoked', `session ${req.params.id}`, req);
  res.json({ ok: true });
});

// "Sign out everywhere else" — keeps the current session, kills the rest.
router.delete('/sessions', authLimiter, requireAuth, (req, res) => {
  const token = req.cookies?.[COOKIE_NAME];
  const args = [req.user.id];
  let sql = 'DELETE FROM sessions WHERE user_id = ?';
  if (token) {
    sql += ' AND token_hash != ?';
    args.push(sha256(token));
  }
  const r = db.prepare(sql).run(...args);
  audit(req.user, 'auth.sessions_revoked', `${r.changes} other session(s)`, req);
  res.json({ ok: true, revoked: r.changes });
});

// ---- Account self-service ----

router.post('/password', authLimiter, requireAuth, async (req, res) => {
  const { current_password, new_password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!(await verifyPassword(String(current_password || ''), user.password_hash))) {
    return res.status(403).json({ error: 'current password incorrect' });
  }
  if (typeof new_password !== 'string' || new_password.length < 10) {
    return res.status(400).json({ error: 'new password must be at least 10 characters' });
  }
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(await hashPassword(new_password), user.id);
  // Invalidate all other sessions for this account, keeping this one, and
  // kill the user's live SSH sessions/tunnels — a password change is a
  // security event, nothing should keep running under the old credential.
  const token = req.cookies?.[COOKIE_NAME];
  if (token) {
    db.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?').run(
      user.id,
      sha256(token)
    );
  }
  destroyUserSessions(user.id);
  stopTunnelsForUser(user.id);
  audit(req.user, 'auth.password_changed', '', req);
  res.json({ ok: true });
});

// Lock-screen verification — checks the current user's password without
// touching the session (unlike /login: no cookie, no TOTP). For the idle
// lock overlay, not for authentication.
router.post('/verify', authLimiter, requireAuth, async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!(await verifyPassword(String(req.body?.password || ''), user.password_hash))) {
    return res.status(403).json({ error: 'wrong password' });
  }
  res.json({ ok: true });
});

// ---- Desktop quick-unlock PIN ----

const PIN_RE = /^\d{4,8}$/;

// PIN unlock — desktop mode only. Tries each configured PIN hash so a shared
// desktop DB with multiple accounts still resolves to the right user.
router.post('/pin', pinLimiter, authLimiter, async (req, res) => {
  // PIN is a local quick-unlock convenience — never a network credential.
  if (!DESKTOP || !isLoopbackClient(req)) {
    return res.status(403).json({ error: 'pin login is local only' });
  }
  const pin = String(req.body?.pin || '');
  if (!PIN_RE.test(pin)) return res.status(400).json({ error: 'pin must be 4-8 digits' });
  const rows = db.prepare('SELECT * FROM users WHERE pin_hash IS NOT NULL').all();
  let user = null;
  for (const u of rows) {
    if (await verifyPassword(pin, u.pin_hash)) {
      user = u;
      break;
    }
  }
  if (!user) {
    audit(null, 'auth.pin_failed', 'bad pin', req);
    return res.status(401).json({ error: 'wrong pin' });
  }
  // A PIN never bypasses the second factor — same TOTP check as /login.
  if (user.totp_enabled) {
    if (!req.body?.totp) {
      return res.status(401).json({ error: 'authenticator code required', totp_required: true });
    }
    const step = verifyTotp(decryptSecret(user.totp_secret), req.body.totp);
    if (step === false || step <= user.totp_last_step) {
      audit(user, 'auth.pin_failed', 'bad totp', req);
      return res.status(401).json({ error: 'invalid authenticator code', totp_required: true });
    }
    db.prepare('UPDATE users SET totp_last_step = ? WHERE id = ?').run(step, user.id);
  }
  createSession(user.id, req, res);
  audit(user, 'auth.pin_login', 'pin unlock', req);
  res.json({ user: publicUser(user) });
});

router.post('/pin/setup', authLimiter, requireAuth, async (req, res) => {
  if (!DESKTOP) return res.status(403).json({ error: 'pin is desktop only' });
  const pin = String(req.body?.pin || '');
  if (!PIN_RE.test(pin)) return res.status(400).json({ error: 'pin must be 4-8 digits' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!(await verifyPassword(String(req.body?.password || ''), user.password_hash))) {
    return res.status(403).json({ error: 'password incorrect' });
  }
  db.prepare('UPDATE users SET pin_hash = ? WHERE id = ?').run(await hashPassword(pin), user.id);
  audit(req.user, 'auth.pin_set', '', req);
  res.json({ ok: true });
});

router.post('/pin/disable', authLimiter, requireAuth, async (req, res) => {
  if (!DESKTOP) return res.status(403).json({ error: 'pin is desktop only' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!(await verifyPassword(String(req.body?.password || ''), user.password_hash))) {
    return res.status(403).json({ error: 'password incorrect' });
  }
  db.prepare('UPDATE users SET pin_hash = NULL WHERE id = ?').run(req.user.id);
  audit(req.user, 'auth.pin_disabled', '', req);
  res.json({ ok: true });
});

// ---- TOTP enrollment ----

// Generates a *pending* secret — never touches the live totp_secret, so a
// stolen session can't silently strip or replace 2FA. The pending secret
// only activates via /totp/enable with a valid code, or via /totp/disable
// (password + current code) to re-enroll.
router.post('/totp/setup', authLimiter, requireAuth, async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  // Sudo-mode: a stolen session alone must not enroll an authenticator —
  // the pending secret would hand 2FA to whoever holds the session.
  if (!(await verifyPassword(String(req.body?.password || ''), user.password_hash))) {
    return res.status(403).json({ error: 'password required' });
  }
  if (user.totp_enabled) {
    return res.status(400).json({ error: '2FA already enabled — disable it first to re-enroll' });
  }
  const secret = generateTotpSecret();
  db.prepare('UPDATE users SET totp_pending_secret = ? WHERE id = ?').run(
    encryptSecret(secret),
    req.user.id
  );
  const issuer = 'ssloth';
  const url = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(req.user.username)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}`;
  const qr = await QRCode.toDataURL(url, { margin: 1, width: 220 });
  res.json({ secret, otpauth_url: url, qr });
});

router.post('/totp/enable', authLimiter, requireAuth, async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!(await verifyPassword(String(req.body?.password || ''), user.password_hash))) {
    return res.status(403).json({ error: 'password required' });
  }
  if (!user.totp_pending_secret) return res.status(400).json({ error: 'run setup first' });
  const secret = decryptSecret(user.totp_pending_secret);
  const step = verifyTotp(secret, req.body?.code);
  if (step === false) {
    return res.status(400).json({ error: 'code did not match, try again' });
  }
  db.prepare(
    'UPDATE users SET totp_enabled = 1, totp_secret = totp_pending_secret, totp_pending_secret = NULL, totp_last_step = ? WHERE id = ?'
  ).run(step, req.user.id);
  audit(req.user, 'auth.totp_enabled', '', req);
  res.json({ ok: true });
});

// Disabling 2FA requires BOTH the password and a current authenticator code —
// a stolen session alone can't strip the second factor.
router.post('/totp/disable', authLimiter, requireAuth, async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!(await verifyPassword(String(req.body?.password || ''), user.password_hash))) {
    return res.status(403).json({ error: 'password incorrect' });
  }
  if (user.totp_enabled) {
    const step = verifyTotp(decryptSecret(user.totp_secret), req.body?.code);
    if (step === false || step <= user.totp_last_step) {
      return res.status(403).json({ error: 'valid authenticator code required to disable 2FA' });
    }
    db.prepare('UPDATE users SET totp_last_step = ? WHERE id = ?').run(step, user.id);
  }
  db.prepare(
    'UPDATE users SET totp_enabled = 0, totp_secret = NULL, totp_pending_secret = NULL, totp_last_step = 0 WHERE id = ?'
  ).run(req.user.id);
  audit(req.user, 'auth.totp_disabled', '', req);
  res.json({ ok: true });
});

module.exports = router;
