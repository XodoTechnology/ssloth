'use strict';

// Build provenance: packaged builds ship server/build-info.json (written by
// desktop/prepare-standalone.js). Dev checkouts fall back to the package
// version + live git HEAD.

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

function buildInfo() {
  try {
    const j = JSON.parse(
      fs.readFileSync(path.join(__dirname, '..', 'build-info.json'), 'utf8')
    );
    if (j.version) return j;
  } catch {}

  let commit = 'dev';
  try {
    commit = execFileSync('git', ['rev-parse', '--short', 'HEAD'], {
      cwd: path.join(__dirname, '..', '..'),
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  } catch {}

  return {
    version: require('../package.json').version,
    commit,
    buildDate: null,
  };
}

module.exports = buildInfo();
