'use strict';

// Rebuilds the server's native module (better-sqlite3) against Electron's
// Node ABI, since main.js runs the server via ELECTRON_RUN_AS_NODE.
// Tries the published Electron prebuild first (no toolchain needed); falls
// back to a source build, which requires Visual Studio Build Tools.

const { spawnSync } = require('child_process');
const path = require('path');

const electronVersion = require('electron/package.json').version;
const serverDir = path.join(__dirname, '..', 'server');

const env = {
  ...process.env,
  npm_config_runtime: 'electron',
  npm_config_target: electronVersion,
  npm_config_dist_url: 'https://electronjs.org/headers',
};

const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const r = spawnSync(npm, ['rebuild', 'better-sqlite3'], {
  cwd: serverDir,
  env,
  stdio: 'inherit',
});

if (r.status !== 0) {
  console.error('\nNative rebuild failed. Install Visual Studio Build Tools');
  console.error('(Desktop development with C++) and retry — or use a Node');
  console.error('version whose better-sqlite3 prebuild matches Electron ' + electronVersion + '.\n');
  process.exit(r.status || 1);
}
console.log(`better-sqlite3 rebuilt for Electron ${electronVersion}`);
