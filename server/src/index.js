'use strict';

const http = require('http');
const path = require('path');
const fs = require('fs');
const express = require('express');
const compression = require('compression');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const { WebSocketServer } = require('ws');
const cookie = require('cookie');

const { PORT, BIND, WEB_DIST, SECURE_COOKIES, DESKTOP, MASTER_KEY_OLD } = require('./config');
const { db } = require('./db');
const { rotateSecrets } = require('./crypto');
const {
  COOKIE_NAME,
  resolveToken,
  desktopUser,
  requireAuth,
  checkOrigin,
  checkWsOrigin,
  checkLoopbackHost,
  touchSession,
  lanDenied,
} = require('./auth');
const { lanAccessGuard, getNetConfig, lanActive, isLoopbackClient, clientIpAllowed, setLanStatus } = require('./netcfg');
const netcfgRoutes = require('./routes/netcfg');
const { handleTerminalWs } = require('./ws/terminal');
const { handleShareWs } = require('./ws/share');

const authRoutes = require('./routes/auth');
const hostRoutes = require('./routes/hosts');
const credentialRoutes = require('./routes/credentials');
const snippetRoutes = require('./routes/snippets');
const tunnelRoutes = require('./routes/tunnels');
const sftpRoutes = require('./routes/sftp');
const adminRoutes = require('./routes/admin');
const watchRoutes = require('./routes/watches');
const recordingRoutes = require('./routes/recordings');
const playbookRoutes = require('./routes/playbooks');
const backupRoutes = require('./routes/backup');
const webhookRoutes = require('./routes/webhooks');
const tokenRoutes = require('./routes/tokens');
const notificationRoutes = require('./routes/notifications');
const { router: shareRoutes, publicRouter: sharePublicRoutes } = require('./routes/shares');
const { handleTelnetWs } = require('./ws/telnet');
const { handleKvmWs } = require('./ws/kvm');
const { startScheduler } = require('./ssh/runner');
const { startSweeper } = require('./health');
const { requireWrite } = require('./auth');

const app = express();
app.disable('x-powered-by');

// Last line of defense: Express 4 does not forward errors thrown inside
// async route handlers, and ws message callbacks bypass the error middleware
// entirely — without these, any stray rejection/exception kills the process
// (Node >=15 default) and every session with it.
process.on('unhandledRejection', (e) => {
  console.error('[ssloth] unhandled rejection:', e);
});
process.on('uncaughtException', (e) => {
  console.error('[ssloth] uncaught exception:', e);
  process.exit(1);
});
const trustProxy = process.env.TRUST_PROXY;
if (trustProxy && trustProxy !== 'false' && trustProxy !== '0') {
  app.set('trust proxy', trustProxy === 'true' ? true : trustProxy);
}

// gzip/deflate responses — the SPA bundle is ~600KB raw; over a WAN link
// this is the difference between a snappy load and a multi-second stall.
// SFTP file streams already transfer raw bytes, so skip compressing those.
app.use(
  compression({
    filter: (req, res) => {
      if (/\/api\/sftp\/[^/]+\/(download|upload)$/.test(req.path)) return false;
      return compression.filter(req, res);
    },
  })
);

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        connectSrc: ["'self'", 'ws:', 'wss:'],
        imgSrc: ["'self'", 'data:', 'blob:'],
        fontSrc: ["'self'", 'data:'],
        workerSrc: ["'self'", 'blob:'],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'none'"],
        formAction: ["'self'"],
        // Only rewrite http->https subresource requests when actually serving TLS;
        // on a plain-http LAN deploy this directive makes the JS bundle unloadable.
        upgradeInsecureRequests: SECURE_COOKIES ? [] : null,
      },
    },
    crossOriginEmbedderPolicy: false,
    referrerPolicy: { policy: 'no-referrer' },
  })
);

app.use(cookieParser());

// Desktop mode is loopback-only — reject foreign Host headers early so a
// DNS-rebinding domain can't reach the API or WS at all.
app.use(checkLoopbackHost);
// Desktop LAN mode: remote clients outside the IP allowlist get a flat 403
// before any route runs (including the login page itself).
app.use(lanAccessGuard);

// SFTP streams raw bodies on upload, so it mounts before the JSON parser.
app.use('/api/sftp', checkOrigin, requireAuth, requireWrite, sftpRoutes);

// Vault export/import payloads (sealed secrets + hundreds of hosts) can
// legitimately exceed the general 2MB cap.
app.use('/api/vault', checkOrigin, express.json({ limit: '16mb' }));
// Per-IP ceiling on the whole API — generous for normal UI polling, but caps
// scraping/abuse. Stricter per-route limiters (auth, PIN, KVM input) still win.
const apiLimiter = rateLimit({
  windowMs: 60_000,
  limit: 600,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'rate limit exceeded' },
});

app.use('/api', apiLimiter, checkOrigin, express.json({ limit: '2mb' }));
app.use('/api/auth', authRoutes);
// 'viewer' role: read-only — requireWrite refuses their mutations (except
// the auth self-service routes above: logout/password change stay allowed).
app.use('/api/hosts', requireAuth, requireWrite, hostRoutes);
app.use('/api/credentials', requireAuth, requireWrite, credentialRoutes);
app.use('/api/snippets', requireAuth, requireWrite, snippetRoutes);
app.use('/api/tunnels', requireAuth, requireWrite, tunnelRoutes);
app.use('/api/shares', requireAuth, requireWrite, shareRoutes);
app.use('/api/recordings', requireAuth, requireWrite, recordingRoutes);
app.use('/api/watches', requireAuth, requireWrite, watchRoutes);
app.use('/api/bmc', requireAuth, requireWrite, require('./routes/bmc'));
app.use('/api/playbooks', requireAuth, requireWrite, playbookRoutes);
app.use('/api/vault', requireAuth, requireWrite, backupRoutes);
app.use('/api/webhooks', requireAuth, requireWrite, webhookRoutes);
app.use('/api/tokens', requireAuth, requireWrite, tokenRoutes);
app.use('/api/notifications', requireAuth, requireWrite, notificationRoutes);
app.use('/api/workspaces', requireAuth, requireWrite, require('./routes/workspaces'));
app.use('/api/admin', requireAuth, requireWrite, adminRoutes);
app.use('/api/netcfg', requireAuth, requireWrite, netcfgRoutes.router);
// Public read-only metadata for share links (token in path is the credential).
app.use('/api/public/share', sharePublicRoutes);

app.use('/api', (req, res) => res.status(404).json({ error: 'not found' }));

// Static SPA
if (fs.existsSync(WEB_DIST)) {
  app.use(
    express.static(WEB_DIST, {
      index: false,
      maxAge: '1h',
      setHeaders(res, filePath) {
        if (filePath.includes(`${path.sep}assets${path.sep}`)) {
          res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        }
      },
    })
  );
  app.get('*', (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.sendFile(path.join(WEB_DIST, 'index.html'));
  });
} else {
  app.get('/', (req, res) =>
    res.status(503).send('web build not found - run `npm run build` or use the Vite dev server')
  );
}

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err?.type === 'entity.too.large') return res.status(413).json({ error: 'payload too large' });
  if (err?.type === 'entity.parse.failed') return res.status(400).json({ error: 'invalid json' });
  console.error('[ssloth] error:', err);
  res.status(500).json({ error: 'internal error' });
});

const server = http.createServer(app);

// ---- WebSocket upgrade (terminal bridge) ----
const wss = new WebSocketServer({ noServer: true, maxPayload: 256 * 1024 });

// Global socket ceiling — per-user session caps exist, but share viewers and
// pre-auth sockets aren't covered by them.
const MAX_WS_CONNECTIONS = 512;
let wsConnections = 0;
globalThis.__ssloth_ws_connections = () => wsConnections;
wss.on('connection', (ws) => {
  wsConnections++;
  ws.on('close', () => wsConnections--);
});

function onUpgrade(req, socket, head) {
  const url = new URL(req.url, 'http://localhost');
  const shareMatch = url.pathname.match(/^\/ws\/share\/([A-Za-z0-9_-]{20,128})$/);
  if (url.pathname !== '/ws/terminal' && url.pathname !== '/ws/telnet' && url.pathname !== '/ws/kvm' && !shareMatch) {
    socket.destroy();
    return;
  }
  if (!checkWsOrigin(req)) {
    socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
    socket.destroy();
    return;
  }
  // Raw upgrade reqs aren't Express requests — give audit() a real client IP.
  req.ip = req.socket.remoteAddress;
  // Desktop LAN mode: the same IP allowlist that guards HTTP applies to
  // every WebSocket, share viewers included.
  if (lanActive() && !isLoopbackClient(req) && !clientIpAllowed(req)) {
    socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
    socket.destroy();
    return;
  }
  if (wsConnections >= MAX_WS_CONNECTIONS) {
    socket.write('HTTP/1.1 503 Service Unavailable\r\n\r\n');
    socket.destroy();
    return;
  }
  if (shareMatch) {
    // Public share viewer - the URL token is the credential, no session cookie.
    wss.handleUpgrade(req, socket, head, (ws) => {
      handleShareWs(ws, req, shareMatch[1]);
    });
    return;
  }
  let cookies = {};
  try {
    cookies = cookie.parse(req.headers.cookie || '');
  } catch {}
  const user = resolveToken(cookies[COOKIE_NAME]) || desktopUser(req);
  if (!user) {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    socket.destroy();
    return;
  }
  if (lanDenied(req, user)) {
    socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    // An attached console is session activity — keep last_seen_at fresh so
    // the idle timeout doesn't log out a user watching a running job.
    if (user.session_id) {
      const keepalive = setInterval(() => touchSession(user.session_id), 60_000);
      keepalive.unref();
      ws.on('close', () => clearInterval(keepalive));
    }
    if (url.pathname === '/ws/telnet') handleTelnetWs(ws, req, user);
    else if (url.pathname === '/ws/kvm') handleKvmWs(ws, req, user);
    else handleTerminalWs(ws, req, user);
  });
}
server.on('upgrade', onUpgrade);

// ---- Optional LAN listener (desktop mode only) ----
// A second http server sharing `app` and the WS upgrade path, bound per the
// netcfg settings. The primary loopback server — and the Electron window on
// it — is untouched, so enabling/disabling LAN access never drops sessions.
let lanServer = null;
let lanServerKey = null;

function syncLanServer() {
  const cfg = getNetConfig();
  const want = DESKTOP && cfg.enabled && cfg.port ? `${cfg.bind}:${cfg.port}` : null;
  if (want === lanServerKey) return;
  if (lanServer) {
    try { lanServer.close(); } catch {}
    lanServer = null;
    lanServerKey = null;
  }
  setLanStatus({ listening: false, error: null, address: null });
  if (!want) return;
  const srv = http.createServer(app);
  srv.on('upgrade', onUpgrade);
  srv.on('error', (e) => {
    setLanStatus({ listening: false, error: e.message, address: null });
    lanServer = null;
    lanServerKey = null;
    console.error(`[ssloth] LAN listener failed on ${want}: ${e.message}`);
  });
  srv.listen(cfg.port, cfg.bind, () => {
    lanServer = srv;
    lanServerKey = want;
    setLanStatus({ listening: true, error: null, address: `http://${cfg.bind}:${cfg.port}` });
    console.log(`[ssloth] LAN listening on http://${cfg.bind}:${cfg.port}`);
  });
}
netcfgRoutes.setOnChange(syncLanServer);
server.on('close', () => {
  try { lanServer?.close(); } catch {}
});

startScheduler();
startSweeper();
require('./sensors-poll').start();
require('./hostkey-monitor').start();

// Opt-in master-key rotation: only runs when SSLOTH_MASTER_KEY_OLD is set.
// Every encrypted column is re-sealed under the current key; unset the OLD
// env var once this reports zero failures.
if (MASTER_KEY_OLD) {
  try {
    const r = rotateSecrets(db);
    console.log(`[ssloth] master-key rotation: ${r.migrated} secret(s) re-encrypted, ${r.failed} undecryptable`);
    if (r.failed) {
      console.error('[ssloth] rotation incomplete — some secrets could not be decrypted with either key.');
      console.error('[ssloth] fix via vault export/import, then unset SSLOTH_MASTER_KEY_OLD.');
    } else {
      console.log('[ssloth] rotation complete — unset SSLOTH_MASTER_KEY_OLD and restart.');
    }
  } catch (e) {
    console.error('[ssloth] master-key rotation failed:', e.message);
  }
}

server.listen(PORT, BIND, () => {
  const addr = server.address();
  console.log(`[ssloth] listening on http://${addr.address}:${addr.port}`);
  syncLanServer(); // pick up persisted LAN settings, if any
});
