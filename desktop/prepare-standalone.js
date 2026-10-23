'use strict';

// Stages everything the packaged app needs under desktop/stage/:
//   stage/server         — server source + production deps for the TARGET platform
//   stage/web/dist       — built frontend
//   stage/node/node.exe  — Node runtime for the target platform
//
// Usage: node prepare-standalone.js [--platform win32] [--arch x64]
// Run before electron-builder. Requires: npm, unzip (win zip), tar (native .tgz).

const { spawnSync, execFileSync } = require('child_process');
const fs = require('fs');
const https = require('https');
const path = require('path');

const args = process.argv.slice(2);
const opt = (name, dflt) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : dflt;
};
const PLATFORM = opt('platform', 'win32');
const ARCH = opt('arch', 'x64');
const NODE_VERSION = process.version; // match this Node's ABI for the bundled runtime

const ROOT = path.join(__dirname, '..');
const STAGE = path.join(__dirname, 'stage');

const run = (cmd, a, opts = {}) =>
  spawnSync(cmd, a, { stdio: 'inherit', shell: process.platform === 'win32', ...opts });

const dl = (url, dest) =>
  new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    https
      .get(url, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          file.close();
          fs.unlinkSync(dest);
          return dl(res.headers.location, dest).then(resolve, reject);
        }
        if (res.statusCode !== 200) return reject(new Error(`${url} -> ${res.statusCode}`));
        res.pipe(file).on('finish', () => file.close(resolve));
      })
      .on('error', reject);
  });

function copy(src, dst, filter) {
  fs.cpSync(src, dst, {
    recursive: true,
    filter: (s) => {
      const rel = path.relative(src, s);
      return !filter || !filter(rel);
    },
  });
}

async function main() {
  console.log(`staging for ${PLATFORM}/${ARCH} (node ${NODE_VERSION})`);
  fs.rmSync(STAGE, { recursive: true, force: true });

  // 1. server source (no node_modules/data — platform deps reinstalled below)
  copy(
    path.join(ROOT, 'server'),
    path.join(STAGE, 'server'),
    (rel) => rel.startsWith('node_modules') || rel.startsWith('data')
  );

  // 2. production deps without scripts — native builds happen per-target below
  let r = run('npm', ['ci', '--omit=dev', '--ignore-scripts'], { cwd: path.join(STAGE, 'server') });
  if (r.status !== 0) process.exit(r.status);

  // 3. target-platform prebuilt better-sqlite3 binary
  const bsVer = require(path.join(STAGE, 'server', 'node_modules', 'better-sqlite3', 'package.json')).version;
  const abi = process.versions.modules;
  const bsDir = path.join(STAGE, 'server', 'node_modules', 'better-sqlite3');
  const tgz = path.join(STAGE, `bs3-${PLATFORM}-${ARCH}.tar.gz`);
  const url = `https://github.com/WiseLibs/better-sqlite3/releases/download/v${bsVer}/better-sqlite3-v${bsVer}-node-v${abi}-${PLATFORM}-${ARCH}.tar.gz`;
  console.log('fetching', url);
  let ok = false;
  try {
    await dl(url, tgz);
    fs.rmSync(path.join(bsDir, 'build'), { recursive: true, force: true });
    ok = run('tar', ['-xzf', tgz, '-C', bsDir]).status === 0;
    fs.rmSync(tgz, { force: true });
  } catch {}
  if (!ok) {
    // no published prebuild for this target (e.g. darwin-arm64) — compile it
    console.warn('no better-sqlite3 prebuild — building from source (needs toolchain)');
    r = run('npm', ['rebuild', 'better-sqlite3', '--build-from-source'], {
      cwd: path.join(STAGE, 'server'),
    });
    if (r.status !== 0) process.exit(r.status);
  }

  // 4. web build
  if (!fs.existsSync(path.join(ROOT, 'web', 'dist', 'index.html'))) {
    console.error('web/dist missing — run `npm run build` first');
    process.exit(1);
  }
  copy(path.join(ROOT, 'web', 'dist'), path.join(STAGE, 'web', 'dist'));

  // 5. Node runtime for the target platform
  const nodeDir = path.join(STAGE, 'node');
  fs.mkdirSync(nodeDir, { recursive: true });
  const tag = NODE_VERSION.replace(/^v/, 'v');
  const name = `node-${tag}-${PLATFORM === 'win32' ? 'win' : PLATFORM === 'darwin' ? 'darwin' : 'linux'}-${ARCH}`;
  if (PLATFORM === 'win32') {
    const zip = path.join(STAGE, 'node.zip');
    await dl(`https://nodejs.org/dist/${tag}/${name}.zip`, zip);
    // Windows runners guarantee bsdtar (system32\tar.exe); unix hosts have unzip
    if (process.platform === 'win32') {
      run('tar', ['-xf', zip, '-C', nodeDir, '--strip-components=1', `${name}/node.exe`]);
    } else {
      run('unzip', ['-o', '-j', zip, `${name}/node.exe`, '-d', nodeDir]);
    }
    fs.unlinkSync(zip);
  } else {
    const tgzN = path.join(STAGE, 'node.tar.gz');
    await dl(`https://nodejs.org/dist/${tag}/${name}.tar.gz`, tgzN);
    run('tar', ['-xzf', tgzN, '-C', nodeDir, '--strip-components=2', `${name}/bin/node`]);
    fs.unlinkSync(tgzN);
  }

  // 6. build provenance — shown in-app (About dialog + footer)
  const info = {
    version: require(path.join(__dirname, 'package.json')).version,
    commit: execFileSync('git', ['rev-parse', '--short', 'HEAD'], { cwd: ROOT, encoding: 'utf8' }).trim(),
    buildDate: new Date().toISOString().slice(0, 10),
    platform: PLATFORM,
    arch: ARCH,
  };
  fs.writeFileSync(path.join(STAGE, 'server', 'build-info.json'), JSON.stringify(info, null, 2));

  console.log(`\nstaged under desktop/stage (${PLATFORM}/${ARCH})`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
