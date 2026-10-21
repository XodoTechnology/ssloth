'use strict';

const http = require('http');
const path = require('path');
const fs = require('fs');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const { WebSocketServer } = require('ws');
const cookie = require('cookie');

const { PORT, BIND, WEB_DIST } = require('./config');
const {
  COOKIE_NAME,
  resolveToken,
  requireAuth,
  checkOrigin,
  checkWsOrigin,
} = require('./auth');
const { handleTerminalWs } = require('./ws/terminal');

const authRoutes = require('./routes/auth');
const hostRoutes = require('./routes/hosts');
const credentialRoutes = require('./routes/credentials');
const snippetRoutes = require('./routes/snippets');
const tunnelRoutes = require('./routes/tunnels');
const sftpRoutes = require('./routes/sftp');
const adminRoutes = require('./routes/admin');

const app = express();
app.disable('x-powered-by');
if (process.env.TRUST_PROXY) app.set('trust proxy', process.env.TRUST_PROXY === 'true' ? true : process.env.TRUST_PROXY);

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
      },
    },
    crossOriginEmbedderPolicy: false,
    referrerPolicy: { policy: 'no-referrer' },
  })
);

app.use(cookieParser());

// SFTP streams raw bodies on upload, so it mounts before the JSON parser.
app.use('/api/sftp', checkOrigin, requireAuth, sftpRoutes);

app.use('/api', checkOrigin, express.json({ limit: '2mb' }));
app.use('/api/auth', authRoutes);
app.use('/api/hosts', requireAuth, hostRoutes);
app.use('/api/credentials', requireAuth, credentialRoutes);
app.use('/api/snippets', requireAuth, snippetRoutes);
app.use('/api/tunnels', requireAuth, tunnelRoutes);
app.use('/api/admin', requireAuth, adminRoutes);

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
  if (url.pathname !== '/ws/terminal') {
    socket.destroy();
    return;
  }
  if (!checkWsOrigin(req)) {
    socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
    socket.destroy();
    return;
  }
  let cookies = {};
  try {
    cookies = cookie.parse(req.headers.cookie || '');
  } catch {}
  const user = resolveToken(cookies[COOKIE_NAME]);
  if (!user) {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    handleTerminalWs(ws, req, user);
  });
});

server.listen(PORT, BIND, () => {
  console.log(`[ssloth] listening on http://${BIND}:${PORT}`);
});
