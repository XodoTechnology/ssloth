'use strict';

// Shared loader + helpers for the vendored bmc-core napi addon
// (vendor/bmc/bmc-node). Used by /ws/kvm and the BMC host-command routes.
// A missing or wrong-arch binary degrades callers to a clear 503 instead of
// killing the server at require time.

const path = require('path');

let bmc = null;
let bmcError = null;
try {
  bmc = require(path.join(__dirname, '..', 'native', 'bmc.node'));
} catch (e) {
  bmcError = e.message;
  console.warn('[ssloth] bmc addon unavailable:', e.message);
}

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
