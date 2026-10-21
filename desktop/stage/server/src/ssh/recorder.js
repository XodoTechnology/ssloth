'use strict';

const fs = require('fs');
const path = require('path');
const { DATA_DIR } = require('../config');

const REC_DIR = path.join(DATA_DIR, 'recordings');
fs.mkdirSync(REC_DIR, { recursive: true });
try {
  fs.chmodSync(REC_DIR, 0o700);
} catch {}

// asciinema cast v2 recorder. Output events only — input (keystrokes,
// including typed passwords) is deliberately NOT captured.
class CastRecorder {
  constructor(sessionId, cols, rows, label) {
    this.file = path.join(REC_DIR, `${sessionId}-${Date.now()}.cast`);
    this.start = Date.now();
    this.size = 0;
    const header = JSON.stringify({
      version: 2,
      width: cols,
      height: rows,
      timestamp: Math.floor(this.start / 1000),
      env: { TERM: 'xterm-256color' },
      title: label,
    });
    this._write(header + '\n');
  }

  _write(line) {
    try {
      fs.appendFileSync(this.file, line);
      this.size += line.length;
    } catch {}
  }

  out(chunk) {
    const t = (Date.now() - this.start) / 1000;
    this._write(JSON.stringify([t, 'o', chunk.toString('utf8')]) + '\n');
  }

  close() {
    return { file: this.file, size: this.size };
  }
}

module.exports = { CastRecorder, REC_DIR };
