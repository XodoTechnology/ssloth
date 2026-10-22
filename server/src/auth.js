'use strict';

const crypto = require('crypto');
const { db, audit } = require('./db');
const { sha256, randomToken } = require('./crypto');
const { SESSION_TTL_MS, SECURE_COOKIES, DESKTOP } = require('./config');

const COOKIE_NAME = 'ssloth_session';

const stmtFindSession = db.prepare(`
  SELECT s.id AS session_id, s.expires_at, u.id, u.username, u.is_admin, u.totp_enabled
  FROM sessions s JOIN users u ON u.id = s.user_id
  WHERE s.token_hash = ?
`);
const stmtTouchSession = db.prepare('UPDATE sessions SET expires_at = ? WHERE id = ?');
const stmtDeleteSession = db.prepare('DELETE FROM sessions WHERE token_hash = ?');
const stmtInsertSession = db.prepare(
  'INSERT INTO sessions (token_hash, user_id, ip, ua, expires_at) VALUES (?, ?, ?, ?, ?)'
);

// Periodic purge of expired sessions.
setInterval(() => {
  try {
    db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(Date.now());
  } catch {}
}, 60 * 60 * 1000).unref();

function createSession(userId, req, res) {
  const token = randomToken();
  const expires = Date.now() + SESSION_TTL_MS;
  stmtInsertSession.run(sha256(token), userId, req.ip || '', String(req.headers['user-agent'] || '').slice(0, 300), expires);
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: SECURE_COOKIES,
    maxAge: SESSION_TTL_MS,
    path: '/',
  });
}

function destroySession(req, res) {
  const token = req.cookies?.[COOKIE_NAME];
  if (token) stmtDeleteSession.run(sha256(token));
  res.clearCookie(COOKIE_NAME, { path: '/' });
}

// Resolve a session token (from cookie or raw token) to a user row.
function resolveToken(token) {
  if (!token || typeof token !== 'string') return null;
  const row = stmtFindSession.get(sha256(token));
  if (!row) return null;
  if (row.expires_at < Date.now()) {
    stmtDeleteSession.run(sha256(token));
    return null;
  }
  // Sliding renewal: extend when less than half the TTL remains.
  if (row.expires_at - Date.now() < SESSION_TTL_MS / 2) {
    stmtTouchSession.run(Date.now() + SESSION_TTL_MS, row.session_id);
  }
  return { id: row.id, username: row.username, is_admin: !!row.is_admin, totp_enabled: !!row.totp_enabled };
}

// Desktop mode: single-user loopback app — auto-resolve the account when no
// unlock PIN is configured. With a PIN, returns null so the unlock screen shows.
function desktopUser() {
  if (!DESKTOP) return null;
  const users = db.prepare('SELECT id, username, is_admin, totp_enabled, pin_hash FROM users ORDER BY id').all();
  if (users.length !== 1) return null;
  if (users[0].pin_hash) return null;
  const u = users[0];
  return { id: u.id, username: u.username, is_admin: !!u.is_admin, totp_enabled: !!u.totp_enabled };
}

function resolveCookie(req) {
  return resolveToken(req.cookies?.[COOKIE_NAME]) || desktopUser();
}

function requireAuth(req, res, next) {
  const user = resolveCookie(req);
  if (!user) return res.status(401).json({ error: 'authentication required' });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user?.is_admin) return res.status(403).json({ error: 'admin required' });
  next();
}

// CSRF defense: the API is only consumed by our SPA, so for state-changing
// requests require a *positive* same-origin signal — a matching Origin
// header or Sec-Fetch-Site: same-origin. Same-site is NOT sufficient
// (sibling subdomains stay within SameSite=Lax scope), and absent headers
// are no longer a free pass (a plain cross-site <form> POST omits them).
// Non-browser API clients must send an Origin header matching the Host.
function checkOrigin(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const fetchSite = req.headers['sec-fetch-site'];
  if (fetchSite === 'same-origin') return next();
  if (fetchSite && fetchSite !== 'none') {
    return res.status(403).json({ error: 'cross-site request blocked' });
  }
  const origin = req.headers.origin;
  if (!origin) return res.status(403).json({ error: 'origin required' });
  try {
    if (new URL(origin).host === req.headers.host) return next();
    return res.status(403).json({ error: 'origin mismatch' });
  } catch {
    return res.status(403).json({ error: 'invalid origin' });
  }
}

// Loopback-only deployments (desktop mode, BIND=127.0.0.1) must also verify
// the Host header — otherwise a DNS-rebinding domain (attacker.com -> 127.0.0.1)
// satisfies the Origin==Host check while the browser treats it as a different
// site entirely. Require the Host to be an actual loopback name.
const LOOPBACK_HOSTNAMES = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);
function isLoopbackHostHeader(hostHeader) {
  try {
    const hostname = new URL(`http://${hostHeader}`).hostname.toLowerCase();
    return LOOPBACK_HOSTNAMES.has(hostname);
  } catch {
    return false;
  }
}
function checkLoopbackHost(req, res, next) {
  if (!DESKTOP) return next();
  if (!isLoopbackHostHeader(req.headers.host)) {
    return res.status(403).json({ error: 'invalid host header' });
  }
  next();
}

// Same check for the WebSocket upgrade, which always sends Origin.
// In desktop mode the Host must also be loopback (DNS-rebinding guard).
function checkWsOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return false;
  if (DESKTOP && !isLoopbackHostHeader(req.headers.host)) return false;
  try {
    return new URL(origin).host === req.headers.host;
  } catch {
    return false;
  }
}

function auditReq(req, action, detail) {
  audit(req.user || null, action, detail, req);
}

module.exports = {
  COOKIE_NAME,
  createSession,
  destroySession,
  resolveToken,
  resolveCookie,
  desktopUser,
  requireAuth,
  requireAdmin,
  checkOrigin,
  checkWsOrigin,
  checkLoopbackHost,
  isLoopbackHostHeader,
  auditReq,
};
