'use strict';

// VaultAgent — an in-process ssh-agent serving the stored private keys of a
// connect spec. Passed as ssh2's `agent` option with `agentForward: true`,
// so processes on the remote (git pull, nested ssh) can sign with vault
// keys without the keys ever leaving this server.
const { BaseAgent, utils } = require('ssh2');

class VaultAgent extends BaseAgent {
  // keys: array of parsed private keys (utils.parseKey results)
  constructor(keys) {
    super();
    this.keys = keys;
  }

  getIdentities(cb) {
    cb(null, this.keys.map((k) => k.getPublicSSH()));
  }

  sign(pubKey, data, options, cb) {
    if (typeof options === 'function') cb = options;
    const want = pubKey?.getPublicSSH ? pubKey.getPublicSSH() : pubKey;
    const key = this.keys.find((k) => {
      try { return k.getPublicSSH().equals(want); } catch { return false; }
    });
    if (!key) return cb(new Error('key not in vault agent'));
    const sig = key.sign(data, options?.hash);
    if (sig instanceof Error) return cb(sig);
    cb(null, sig);
  }
}

// Build a VaultAgent from a spec's privateKey (PEM/OpenSSH string).
// Returns null when there's no usable key.
function agentForSpec(spec) {
  if (!spec.privateKey) return null;
  try {
    const parsed = utils.parseKey(spec.privateKey, spec.passphrase);
    const keys = (Array.isArray(parsed) ? parsed : [parsed]).filter((k) => !(k instanceof Error) && k.isPrivateKey?.());
    return keys.length ? new VaultAgent(keys) : null;
  } catch {
    return null;
  }
}

module.exports = { VaultAgent, agentForSpec };
