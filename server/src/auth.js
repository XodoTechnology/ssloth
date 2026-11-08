'use strict';

const crypto = require('crypto');
const { db, audit } = require('./db');
const { sha256, sha256B64, randomToken } = require('./crypto');
const { SESSION_TTL_MS, SESSION_IDLE_MS, SECURE_COOKIES, DESKTOP } = require('./config');
const { lanActive, isLoopbackClient, hostHeaderAllowed } = require('./netcfg');

const COOKIE_NAME = 'ssloth_session';

const stmtFindSession = db.prepare(`
  SELECT s.id AS session_id, s.expires_at, s.last_seen_at, u.id, u.username, u.is_admin, u.totp_enabled, u.role, u.lan_allowed
  FROM sessions s JOIN users u ON u.id = s.user_id
  WHERE s.token_hash = ?
`);
// One write covers both clocks: expires_at slides on activity (the old
// half-TTL check was just a write throttle) and last_seen_at feeds the
// idle timeout. Throttled to one write per minute per session.
const stmtTouchSession = db.prepare('UPDATE sessions SET expires_at = ?, last_seen_at = ? WHERE id = ?');
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
  const now = Date.now();
  if (row.expires_at < now) {
    stmtDeleteSession.run(sha256(token));
    return null;
  }
  // Idle timeout: rows predating last_seen_at get stamped on first use
  // (a grace window), then must see activity within SESSION_IDLE_MS.
  if (SESSION_IDLE_MS > 0 && row.last_seen_at != null && now - row.last_seen_at > SESSION_IDLE_MS) {
    stmtDeleteSession.run(sha256(token));
    audit(null, 'session.idle_expired', `session ${row.session_id} idle > ${Math.round(SESSION_IDLE_MS / 3600000)}h`, null);
    return null;
  }
  if (row.last_seen_at == null || now - row.last_seen_at > 60_000 || row.expires_at - now < SESSION_TTL_MS / 2) {
    stmtTouchSession.run(now + SESSION_TTL_MS, now, row.session_id);
  }
  return { id: row.id, username: row.username, is_admin: !!row.is_admin || row.role === 'admin', role: row.role || (row.is_admin ? 'admin' : 'user'), totp_enabled: !!row.totp_enabled, session_id: row.session_id, lan_allowed: row.lan_allowed !== 0 };
}

// Keepalive for long-lived WebSockets: an open console counts as activity,
// otherwise a user watching a running job would be logged out mid-session.
function touchSession(sessionId) {
  try {
    const now = Date.now();
    stmtTouchSession.run(now + SESSION_TTL_MS, now, sessionId);
  } catch {}
}

// Bearer API tokens: 'Authorization: Bearer slo_...'. Token requests are
// scope-limited to an allowlist of routes — a token can never do anything
// the scope doesn't name.
const TOKEN_SCOPE_ROUTES = {
  read: [/^GET \/api\/(hosts|snippets|playbooks|tunnels|recordings|credentials)(\/|$)/],
  'playbooks:run': [/^POST \/api\/playbooks\/\d+\/run$/],
  vault: [/^POST \/api\/vault\/export$/],
};

function resolveApiToken(req) {
  const h = req.headers.authorization || '';
  const m = h.match(/^Bearer\s+(slo_[A-Za-z0-9_-]{20,128})$/);
  if (!m) return null;
  const row = db
    .prepare('SELECT t.id AS tok, t.scopes, t.expires_at, u.id, u.username, u.is_admin, u.role, u.totp_enabled, u.lan_allowed FROM api_tokens t JOIN users u ON u.id = t.user_id WHERE t.token_hash = ?')
    .get(sha256B64(m[1]));
  if (!row) return null;
  if (row.expires_at && row.expires_at * 1000 < Date.now()) return null;
  db.prepare('UPDATE api_tokens SET last_used = unixepoch() WHERE id = ?').run(row.tok);
  const scopes = new Set(row.scopes.split(',').filter(Boolean));
  const user = { id: row.id, username: row.username, is_admin: !!row.is_admin || row.role === 'admin', role: row.role || 'user', totp_enabled: !!row.totp_enabled, lan_allowed: row.lan_allowed !== 0 };
  return { user, scopes };
}

// Full route+method the request targets, e.g. 'GET /api/hosts/12'.
function routeKey(req) {
  return `${req.method} ${req.baseUrl}${req.path}`;
}

// Desktop mode: single-user loopback app — auto-resolve the account when no
// unlock PIN is configured. With a PIN, returns null so the unlock screen shows.
// Loopback clients only: on a LAN-exposed desktop server a remote client must
// always go through real authentication.
function desktopUser(req) {
  if (!DESKTOP) return null;
  if (req && !isLoopbackClient(req)) return null;
  const users = db.prepare('SELECT id, username, is_admin, role, totp_enabled, pin_hash, lan_allowed FROM users ORDER BY id').all();
  if (users.length !== 1) return null;
  if (users[0].pin_hash) return null;
  const u = users[0];
  return { id: u.id, username: u.username, is_admin: !!u.is_admin || u.role === 'admin', role: u.role || (u.is_admin ? 'admin' : 'user'), totp_enabled: !!u.totp_enabled, lan_allowed: u.lan_allowed !== 0 };
}

function resolveCookie(req) {
  return resolveToken(req.cookies?.[COOKIE_NAME]) || desktopUser(req);
}

// Accounts flagged lan_allowed=0 can't be used from non-loopback clients
// while desktop LAN mode is on (loopback — the local app — is unaffected).
function lanDenied(req, user) {
  return user.lan_allowed === false && lanActive() && !isLoopbackClient(req);
}

function requireAuth(req, res, next) {
  // Bearer API token path — scope-gated.
  if (req.headers.authorization?.startsWith('Bearer ')) {
    const t = resolveApiToken(req);
    if (!t) return res.status(401).json({ error: 'invalid or expired token' });
    const key = routeKey(req);
    const allowed = [...t.scopes].some((s) =>
      (TOKEN_SCOPE_ROUTES[s] || []).some((re) => re.test(key))
    );
    if (!allowed) return res.status(403).json({ error: 'token scope does not allow this route' });
    if (lanDenied(req, t.user)) return res.status(403).json({ error: 'this account cannot be used from the network' });
    req.user = t.user;
    req.tokenScopes = t.scopes;
    return next();
  }
  const user = resolveCookie(req);
  if (!user) return res.status(401).json({ error: 'authentication required' });
  if (lanDenied(req, user)) return res.status(403).json({ error: 'this account cannot be used from the network' });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user?.is_admin) return res.status(403).json({ error: 'admin required' });
  next();
}

// 'viewer' role: read-only access — every mutation is refused (except the
// account self-service routes under /api/auth, e.g. logout).
function requireWrite(req, res, next) {
  if (req.user?.role === 'viewer' && !['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return res.status(403).json({ error: 'read-only account' });
  }
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
  // Bearer-token requests aren't ambient (no cookie) so CSRF doesn't apply.
  if (req.headers.authorization?.startsWith('Bearer ')) return next();
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
  // hostHeaderAllowed additionally permits IP-literal hosts when desktop
  // LAN mode is on — DNS names stay rejected either way (rebinding guard).
  if (!hostHeaderAllowed(req.headers.host)) {
    return res.status(403).json({ error: 'invalid host header' });
  }
  next();
}

// Same check for the WebSocket upgrade, which always sends Origin.
// In desktop mode the Host must also be loopback (DNS-rebinding guard).
function checkWsOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return false;
  if (DESKTOP && !hostHeaderAllowed(req.headers.host)) return false;
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
  touchSession,
  resolveCookie,
  desktopUser,
  requireAuth,
  requireAdmin,
  requireWrite,
  checkOrigin,
  checkWsOrigin,
  checkLoopbackHost,
  isLoopbackHostHeader,
  lanDenied,
  auditReq,
};
