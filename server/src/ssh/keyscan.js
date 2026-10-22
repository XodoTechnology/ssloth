'use strict';

// ssh-keyscan equivalent: run the SSH handshake far enough to learn the
// server's host key, then bail before auth. Used to pre-seed TOFU pins.
const { Client } = require('ssh2');
const { hostKeyFingerprint } = require('../crypto');

function scanHostKey(hostname, port, timeoutMs = 8000) {
  return new Promise((resolve) => {
    const conn = new Client();
    let presented = null;
    let done = false;
    const finish = (r) => {
      if (done) return;
      done = true;
      try { conn.end(); } catch {}
      resolve(r);
    };
    const timer = setTimeout(() => finish({ ok: false, error: 'timed out' }), timeoutMs);
    timer.unref?.();

    conn
      .on('ready', () => finish({ ok: false, error: 'unexpected auth success' }))
      .on('error', () => {
        // hostVerifier rejects -> error; auth failure also -> error. Either
        // way if we captured a key the scan succeeded.
        clearTimeout(timer);
        if (presented) {
          finish({
            ok: true,
            keyB64: presented.key.toString('base64'),
            fingerprint: hostKeyFingerprint(presented.key),
            algorithm: presented.algo,
          });
        } else {
          finish({ ok: false, error: 'no key received (SSH service up?)' });
        }
      })
      .connect({
        host: hostname,
        port,
        username: 'ssloth-keyscan',
        password: 'x',
        readyTimeout: timeoutMs,
        tryKeyboard: false,
        hostVerifier(key) {
          const buf = Buffer.isBuffer(key) ? key : Buffer.from(key, 'base64');
          let len = 0, algo = '';
          try {
            len = buf.readUInt32BE(0);
            if (len > 0 && len < 64) algo = buf.toString('ascii', 4, 4 + len);
          } catch {}
          presented = { key: buf, algo };
          clearTimeout(timer);
          finish({
            ok: true,
            keyB64: buf.toString('base64'),
            fingerprint: hostKeyFingerprint(buf),
            algorithm: algo,
          });
          return false; // always reject — we only wanted the key
        },
      });
  });
}

module.exports = { scanHostKey };
