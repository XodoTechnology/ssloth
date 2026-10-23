'use strict';

// ssloth desktop — spawns the bundled Express/WS server with a real Node
// binary and loads it in a BrowserWindow. Data lives in %APPDATA%\ssloth
// (or the platform equivalent); the server only binds loopback, so nothing
// is exposed to the network.
//
// Packaged builds ship resources/node/node(.exe) plus the server and
// web/dist as raw resources, so native modules (better-sqlite3) keep their
// standard Node prebuilds — no Electron ABI rebuild needed. In dev (`npm
// run dev`) it just uses the `node` on PATH.

const { app, BrowserWindow, Menu, dialog, shell } = require('electron');
const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

let serverProc = null;
let mainWindow = null;
let serverUrl = null;
let checkForUpdates = () => {};

// Update events get appended here so failures are diagnosable after the fact.
const updateLog = () =>
  fs.createWriteStream(path.join(app.getPath('userData'), 'update.log'), { flags: 'a' });

function initUpdater() {
  // Only packaged builds self-update; dev mode has no feed to check.
  if (!app.isPackaged) return;
  let autoUpdater;
  try {
    ({ autoUpdater } = require('electron-updater'));
  } catch {
    return; // dep absent (dev checkout / hand-copied resources)
  }
  const log = updateLog();
  const write = (m) => log.write(`${new Date().toISOString()} ${m}\n`);
  autoUpdater.logger = { info: write, warn: write, error: write, debug: () => {} };
  autoUpdater.autoInstallOnAppQuit = true;

  autoUpdater.on('update-downloaded', (info) => {
    write(`update ${info.version} downloaded`);
    dialog
      .showMessageBox(mainWindow, {
        type: 'info',
        title: 'Update ready',
        message: `ssloth ${info.version} has been downloaded.`,
        detail: 'Restart now to install it, or it will be applied next time you quit.',
        buttons: ['Restart now', 'Later'],
        defaultId: 0,
      })
      .then(({ response }) => {
        if (response === 0) autoUpdater.quitAndInstall();
      });
  });
  autoUpdater.on('error', (e) => write(`update error: ${e.message}`));

  // Silent background check on launch; failures (offline, private repo) are logged only.
  autoUpdater.checkForUpdates().catch((e) => write(`check failed: ${e.message}`));

  checkForUpdates = () =>
    autoUpdater
      .checkForUpdates()
      .then((r) => {
        if (!r?.updateInfo || r.updateInfo.version === app.getVersion()) {
          dialog.showMessageBox(mainWindow, {
            type: 'info',
            message: `ssloth ${app.getVersion()} is up to date.`,
          });
        }
      })
      .catch((e) =>
        dialog.showErrorBox('Update check failed', `${e.message}\n\nSee update.log in the data folder.`)
      );
}

function installMenu() {
  Menu.setApplicationMenu(
    Menu.buildFromTemplate([
      {
        label: 'ssloth',
        submenu: [
          {
            label: 'Check for Updates…',
            click: () => checkForUpdates(),
          },
          { type: 'separator' },
          { role: 'quit' },
        ],
      },
      {
        label: 'Edit',
        role: 'editMenu',
      },
      {
        label: 'View',
        submenu: [
          { role: 'reload' },
          { role: 'toggleDevTools' },
          { type: 'separator' },
          { role: 'resetZoom' },
          { role: 'zoomIn' },
          { role: 'zoomOut' },
        ],
      },
    ])
  );
}

function serverPaths() {
  const res = app.isPackaged ? process.resourcesPath : path.join(__dirname, '..');
  return {
    entry: path.join(res, 'server', 'src', 'index.js'),
    cwd: path.join(res, 'server'),
    node: app.isPackaged
      ? path.join(res, 'node', process.platform === 'win32' ? 'node.exe' : 'node')
      : null,
  };
}

function startServer() {
  return new Promise((resolve, reject) => {
    const { entry, cwd, node } = serverPaths();
    const logFile = path.join(app.getPath('userData'), 'server.log');
    const log = fs.createWriteStream(logFile, { flags: 'a' });

    if (node && !fs.existsSync(node)) {
      return reject(new Error(`bundled runtime missing at ${node} — the install is incomplete; please reinstall or use the portable zip`));
    }

    let bin = node || 'node';
    const args = [entry];
    const extraEnv = {};
    if (!app.isPackaged) {
      // dev convenience: no node on PATH -> fall back to Electron-as-Node
      const probe = spawnSync(bin, ['--version'], { encoding: 'utf8' });
      if (probe.error) {
        bin = process.execPath;
        extraEnv.ELECTRON_RUN_AS_NODE = '1';
      }
    }

    serverProc = spawn(bin, args, {
      cwd,
      env: {
        ...process.env,
        ...extraEnv,
        SSLOTH_DATA_DIR: app.getPath('userData'),
        BIND: '127.0.0.1',
        PORT: '0',
        // single-user loopback app: auto-unlocks unless a PIN is set
        SSLOTH_DESKTOP: '1',
        // not TLS-terminating here; loopback is already a secure context
        SSLOTH_SECURE_COOKIES: 'false',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    serverProc.on('error', (e) => reject(new Error(`could not spawn server: ${e.message}`)));

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
    icon: path.join(__dirname, 'icon.png'),
    webPreferences: {
      // remote content is our own localhost server; keep the renderer locked down
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: false,
    },
  });
  mainWindow.loadURL(url);

  // Navigation hardening: the only legitimate content is our own loopback
  // server (plus its /share/ links). Block in-window navigation anywhere
  // else, and never open a second BrowserWindow — external http(s) links
  // go to the system browser instead, so untrusted pages never inherit our
  // (admittedly minimal) renderer privileges.
  const allowed = (target) => {
    try {
      const u = new URL(target);
      const srv = new URL(serverUrl);
      return u.origin === srv.origin;
    } catch {
      return false;
    }
  };

  mainWindow.webContents.setWindowOpenHandler(({ url: target }) => {
    try {
      const u = new URL(target);
      if (u.protocol === 'http:' || u.protocol === 'https:') {
        shell.openExternal(target);
      }
    } catch {}
    return { action: 'deny' };
  });

  mainWindow.webContents.on('will-navigate', (e, target) => {
    if (!allowed(target)) {
      e.preventDefault();
      try {
        const u = new URL(target);
        if (u.protocol === 'http:' || u.protocol === 'https:') shell.openExternal(target);
      } catch {}
    }
  });
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
    installMenu();
    initUpdater();
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
