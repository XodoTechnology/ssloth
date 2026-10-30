'use strict';

// Shared loader + helpers for the vendored bmc-core napi addon
// (vendor/bmc/bmc-node). Used by /ws/kvm and the BMC host-command routes.
// A missing or wrong-arch binary degrades callers to a clear 503 instead of
// killing the server at require time.

const path = require('path');

let bmc = null;
let bmcError = null;
// Per-platform addon first (bmc.linux-x64.node, bmc.win32-x64.node,
// bmc.darwin-arm64.node…), then a lipo'd bmc.<platform>-universal.node
// (what build-bmc-node.sh emits on macOS), then the generic bmc.node.
const nativeDir = path.join(__dirname, '..', 'native');
const candidates = [
  `bmc.${process.platform}-${process.arch}.node`,
  `bmc.${process.platform}-universal.node`,
  'bmc.node',
];
for (const name of candidates) {
  const p = path.join(nativeDir, name);
  if (!require('fs').existsSync(p)) continue;
  try {
    bmc = require(p);
    break;
  } catch (e) {
    bmcError = `${name}: ${e.message}`;
    console.warn('[ssloth] bmc addon failed:', bmcError);
  }
}
if (!bmc) console.warn('[ssloth] bmc addon unavailable:', bmcError || 'no binary for this platform');

// Map a resolved ssloth bastion chain onto bmc RouteSpec hops (dial order:
// outermost first).
function chainToRoutes(hops) {
  return hops.map((h) => ({
    name: h.label || `${h.hostname}:${h.port}`,
    kind: 'ssh',
    host: h.hostname,
    port: h.port || 22,
    user: h.username || '',
    auth: h.privateKey ? 'key' : h.password ? 'password' : 'agent',
    keyFile: h.__keyFile || null,
    secret: h.password || h.passphrase || null,
    hostKey: null,
    via: null,
  }));
}

// Resolve + install the bastion chain for a spec into the addon's route
// table (which is global, keyed by address). `resolveConnectSpec` is injected
// by the caller to avoid a circular dep with ssh/manager.
function applyRoutes(resolveConnectSpec, userId, spec) {
  const hops = [];
  const seen = new Set(spec.hostId ? [spec.hostId] : []);
  let cursor = spec;
  while (cursor.jumpHostId) {
    if (hops.length >= 8) throw new Error('bastion chain too long');
    const hop = resolveConnectSpec(userId, { hostId: cursor.jumpHostId });
    if (seen.has(hop.hostId)) throw new Error('bastion chain contains a cycle');
    seen.add(hop.hostId);
    hops.push(hop);
    cursor = hop;
  }
  hops.reverse();
  bmc.clearRoute(spec.hostname);
  if (hops.length) bmc.setRoute(spec.hostname, chainToRoutes(hops));
}

module.exports = { bmc, bmcError, applyRoutes, chainToRoutes };
