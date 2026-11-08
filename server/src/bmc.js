'use strict';

// Shared loader + helpers for the vendored bmc-core napi addon
// (vendor/bmc/bmc-node). Used by /ws/kvm and the BMC host-command routes.
// A missing or wrong-arch binary degrades callers to a clear 503 instead of
// killing the server at require time.

const path = require('path');
const crypto = require('crypto');

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

// The addon's route table is global, keyed by BMC address alone — two users
// whose hosts share an address (common behind NAT) but need *different*
// bastion chains would silently overwrite each other, and the loser's BMC
// traffic (credentials included) could transit the winner's bastion. Track
// route holders here: a conflicting chain for an address already in use is
// refused instead of silently misrouting. Same-chain holders share fine.
const routeHolders = new Map(); // addrKey -> { addr, sig, holders: Map<holderId, userId> }

// Mirror of the addon's addr_key: trim, strip [v6] brackets, lowercase.
// (It also canonicalizes IP literals; spellings that differ only there are
// a rare enough edge that the JS-side check is a best-effort guard — the
// Rust table still does the real lookup.)
function addrKey(addr) {
  let a = String(addr || '').trim();
  if (a.startsWith('[') && a.endsWith(']')) a = a.slice(1, -1);
  return a.toLowerCase();
}

// Fingerprint of the hop chain actually installed — host, port, user, auth
// kind, key file and secrets. Two specs resolving to the same chain share
// the route; anything else is a conflict.
function chainSig(routes) {
  return crypto
    .createHash('sha256')
    .update(
      JSON.stringify(
        routes.map((r) => [
          r.host, r.port, r.user, r.auth, r.keyFile || '', r.secret || '', r.via || '',
        ])
      )
    )
    .digest('hex');
}

// Map a resolved ssloth bastion chain onto bmc RouteSpec hops (dial order:
// outermost first). Optional fields must be undefined, not null — napi
// rejects Null where the Rust side declares Option<String>.
function chainToRoutes(hops) {
  return hops.map((h) => ({
    name: h.label || `${h.hostname}:${h.port}`,
    kind: 'ssh',
    host: h.hostname,
    port: h.port || 22,
    user: h.username || '',
    auth: h.privateKey ? 'key' : h.password ? 'password' : 'agent',
    keyFile: h.__keyFile || undefined,
    secret: h.password || h.passphrase || undefined,
    hostKey: undefined,
    via: undefined,
  }));
}

// Resolve + install the bastion chain for a spec into the addon's route
// table (which is global, keyed by address). `resolveConnectSpec` is injected
// by the caller to avoid a circular dep with ssh/manager. `holder` ({id})
// registers this user of the route so it can be released later; pass a
// stable id for long-lived sessions, a unique one for one-shot calls.
function applyRoutes(resolveConnectSpec, userId, spec, holder) {
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
  const routes = chainToRoutes(hops);
  const key = addrKey(spec.hostname);
  const sig = chainSig(routes);
  const holderId = holder && holder.id != null ? String(holder.id) : null;
  const entry = routeHolders.get(key);
  // A holder re-applying (e.g. the sensors sweep refreshing after a host's
  // jump config changed) may update its own chain; a *different* holder with
  // a different chain is refused — the global table can't serve both.
  const mine = holderId != null && entry != null && entry.holders.has(holderId);
  if (entry && entry.sig !== sig && !mine) {
    throw new Error(
      `BMC address ${spec.hostname} already has a different bastion route in use`
    );
  }
  // One atomic table write — an empty hop list *is* the direct route, so
  // clear+set never leaves a window where the address dials direct.
  bmc.setRoute(spec.hostname, routes);
  if (holderId != null) {
    if (entry) {
      entry.holders.set(holderId, userId);
      entry.sig = sig;
      entry.addr = spec.hostname;
    } else {
      routeHolders.set(key, { addr: spec.hostname, sig, holders: new Map([[holderId, userId]]) });
    }
  }
}

// Drop a holder's claim on an address's route; the last holder out clears
// the route so the address goes back to direct.
function releaseRoute(addr, holderId) {
  const key = addrKey(addr);
  const entry = routeHolders.get(key);
  if (!entry) return;
  entry.holders.delete(String(holderId));
  if (entry.holders.size === 0) {
    routeHolders.delete(key);
    try {
      bmc.clearRoute(entry.addr);
    } catch {}
  }
}

// The addon's media fetcher (vendor/bmc media_source.rs) refuses private and
// reserved addresses unless this is set — ssloth maps its own
// SSLOTH_ALLOW_PRIVATE_MEDIA_URLS knob onto it so LAN ISO servers still work
// for deployments that want them.
if (process.env.SSLOTH_ALLOW_PRIVATE_MEDIA_URLS === 'true' && !process.env.BMC_MEDIA_ALLOW_PRIVATE) {
  process.env.BMC_MEDIA_ALLOW_PRIVATE = '1';
}

module.exports = { bmc, bmcError, applyRoutes, releaseRoute, chainToRoutes };
