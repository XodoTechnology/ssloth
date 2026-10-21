'use strict';

// ssloth desktop — spawns the bundled Express/WS server inside Electron's
// Node runtime and loads it in a BrowserWindow. Data lives in
// %APPDATA%/ssloth (or the platform equivalent); the server only binds
// loopback, so nothing is exposed to the network.

const { app, BrowserWindow, dialog } = require('electron');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const net = require('net');

let serverProc = null;
let mainWindow = null;
let serverUrl = null;

function serverPaths() {
  // Packaged: resources/server + resources/web/dist (mirrors repo layout so
  // config.js's relative WEB_DIST resolution keeps working).
  if (app.isPackaged) {
    return {
      entry: path.join(process.resourcesPath, 'server', 'src', 'index.js'),
      cwd: path.join(process.resourcesPath, 'server'),
    };
  }
  return {
    entry: path.join(__dirname, '..', 'server', 'src', 'index.js'),
    cwd: path.join(__dirname, '..', 'server'),
  };
}

function startServer() {
  return new Promise((resolve, reject) => {
    const { entry, cwd } = serverPaths();
    const logFile = path.join(app.getPath('userData'), 'server.log');
    const log = fs.createWriteStream(logFile, { flags: 'a' });

    serverProc = spawn(process.execPath, [entry], {
      cwd,
      env: {
        ...process.env,
        ELECTRON_RUN_AS_NODE: '1',
        SSLOTH_DATA_DIR: app.getPath('userData'),
        BIND: '127.0.0.1',
        PORT: '0',
        // not TLS-terminating here; loopback is already a secure context
        SSLOTH_SECURE_COOKIES: 'false',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const onData = (buf) => {
      const line = buf.toString();
      log.write(line);
      const m = line.match(/\[ssloth\] listening on (http:\/\/\S+)/);
      if (m && !serverUrl) {
        serverUrl = m[1];
        resolve(serverUrl);
      }
    };
    serverProc.stdout.on('data', onData);
    serverProc.stderr.on('data', (d) => log.write(d));

    serverProc.on('exit', (code) => {
      if (!serverUrl) {
        reject(new Error(`server exited before startup (code ${code}) — see ${logFile}`));
      }
    });

    setTimeout(() => {
      if (!serverUrl) reject(new Error(`server startup timed out — see ${logFile}`));
    }, 20000);
  });
}

function createWindow(url) {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 900,
    minHeight: 600,
    autoHideMenuBar: true,
    backgroundColor: '#0a0d10',
    title: 'ssloth',
    webPreferences: {
      // remote content is our own localhost server; keep the renderer locked down
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: false,
    },
  });
  mainWindow.loadURL(url);
}

const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });

  app.whenReady().then(async () => {
    try {
      const url = await startServer();
      createWindow(url);
    } catch (e) {
      dialog.showErrorBox('ssloth failed to start', String(e.message || e));
      app.quit();
    }
  });

  app.on('window-all-closed', () => app.quit());
  app.on('quit', () => {
    try {
      serverProc?.kill();
    } catch {}
  });
}
