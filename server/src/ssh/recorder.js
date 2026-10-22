'use strict';

const fs = require('fs');
const path = require('path');
const { DATA_DIR } = require('../config');

const REC_DIR = path.join(DATA_DIR, 'recordings');
fs.mkdirSync(REC_DIR, { recursive: true });
try {
  fs.chmodSync(REC_DIR, 0o700);
} catch {}

const MAX_REC_BYTES = 50 * 1024 * 1024; // 50MB per recording

// asciinema cast v2 recorder. Output events only — input (keystrokes,
// including typed passwords) is deliberately NOT captured.
// Writes go through an async stream (appendFileSync per chunk stalls the
// event loop under high-throughput output) and self-cap at MAX_REC_BYTES
// so `yes > /dev/stdout` can't fill the disk.
class CastRecorder {
  constructor(sessionId, cols, rows, label) {
    this.file = path.join(REC_DIR, `${sessionId}-${Date.now()}.cast`);
    this.start = Date.now();
    this.size = 0;
    this.capped = false;
    this.stream = fs.createWriteStream(this.file, { flags: 'w' });
    this.stream.on('error', () => {});
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
    if (this.capped) return;
    this.size += line.length;
    if (this.size > MAX_REC_BYTES) {
      this.capped = true;
      try { this.stream.end(); } catch {}
      return;
    }
    try {
      this.stream.write(line);
    } catch {}
  }

  out(chunk) {
    const t = (Date.now() - this.start) / 1000;
    this._write(JSON.stringify([t, 'o', chunk.toString('utf8')]) + '\n');
  }

  close() {
    try { this.stream.end(); } catch {}
    return { file: this.file, size: this.size, capped: this.capped };
  }
}

module.exports = { CastRecorder, REC_DIR };
