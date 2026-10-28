'use strict';

const http = require('http');
const path = require('path');
const fs = require('fs');
const express = require('express');
const compression = require('compression');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const { WebSocketServer } = require('ws');
const cookie = require('cookie');

const { PORT, BIND, WEB_DIST, SECURE_COOKIES } = require('./config');
const {
  COOKIE_NAME,
  resolveToken,
  desktopUser,
  requireAuth,
  checkOrigin,
  checkWsOrigin,
  checkLoopbackHost,
} = require('./auth');
const { handleTerminalWs } = require('./ws/terminal');
const { handleShareWs } = require('./ws/share');

const authRoutes = require('./routes/auth');
const hostRoutes = require('./routes/hosts');
const credentialRoutes = require('./routes/credentials');
const snippetRoutes = require('./routes/snippets');
const tunnelRoutes = require('./routes/tunnels');
const sftpRoutes = require('./routes/sftp');
const adminRoutes = require('./routes/admin');
const recordingRoutes = require('./routes/recordings');
const playbookRoutes = require('./routes/playbooks');
const backupRoutes = require('./routes/backup');
const webhookRoutes = require('./routes/webhooks');
const tokenRoutes = require('./routes/tokens');
const { router: shareRoutes, publicRouter: sharePublicRoutes } = require('./routes/shares');
const { handleTelnetWs } = require('./ws/telnet');
const { handleKvmWs } = require('./ws/kvm');
const { startScheduler } = require('./ssh/runner');
const { startSweeper } = require('./health');
const { requireWrite } = require('./auth');

const app = express();
app.disable('x-powered-by');
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

// SFTP streams raw bodies on upload, so it mounts before the JSON parser.
app.use('/api/sftp', checkOrigin, requireAuth, requireWrite, sftpRoutes);

// Vault export/import payloads (sealed secrets + hundreds of hosts) can
// legitimately exceed the general 2MB cap.
app.use('/api/vault', checkOrigin, express.json({ limit: '16mb' }));
app.use('/api', checkOrigin, express.json({ limit: '2mb' }));
app.use('/api/auth', authRoutes);
// 'viewer' role: read-only — requireWrite refuses their mutations (except
// the auth self-service routes above: logout/password change stay allowed).
app.use('/api/hosts', requireAuth, requireWrite, hostRoutes);
app.use('/api/credentials', requireAuth, requireWrite, credentialRoutes);
app.use('/api/snippets', requireAuth, requireWrite, snippetRoutes);
app.use('/api/tunnels', requireAuth, requireWrite, tunnelRoutes);
app.use('/api/shares', requireAuth, requireWrite, shareRoutes);
app.use('/api/recordings', requireAuth, requireWrite, recordingRoutes);
app.use('/api/playbooks', requireAuth, requireWrite, playbookRoutes);
app.use('/api/vault', requireAuth, requireWrite, backupRoutes);
app.use('/api/webhooks', requireAuth, requireWrite, webhookRoutes);
app.use('/api/tokens', requireAuth, requireWrite, tokenRoutes);
app.use('/api/workspaces', requireAuth, requireWrite, require('./routes/workspaces'));
app.use('/api/admin', requireAuth, requireWrite, adminRoutes);
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

server.on('upgrade', (req, socket, head) => {
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
  const user = resolveToken(cookies[COOKIE_NAME]) || desktopUser();
  if (!user) {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    if (url.pathname === '/ws/telnet') handleTelnetWs(ws, req, user);
    else if (url.pathname === '/ws/kvm') handleKvmWs(ws, req, user);
    else handleTerminalWs(ws, req, user);
  });
});

startScheduler();
startSweeper();

server.listen(PORT, BIND, () => {
  const addr = server.address();
  console.log(`[ssloth] listening on http://${addr.address}:${addr.port}`);
});
