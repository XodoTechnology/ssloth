'use strict';

// Desktop "serve on LAN" configuration. Only meaningful when DESKTOP=1 —
// on a regular server the bind address is ops-controlled via BIND/PORT env
// and every check in this module no-ops.
//
// Model: the primary server stays bound to loopback (the Electron window
// keeps working exactly as before). Enabling LAN access spins up a SECOND
// http server on the configured bind/port sharing the same Express app and
// WebSocket upgrade handler — so remote clients get the real login page and
// full auth, while the local app is never disrupted by a rebind.
//
// Remote (non-loopback) clients must authenticate with username+password —
// the desktopUser() auto-auth is loopback-only — and may additionally be
// restricted by an IP allowlist (CIDRs) and per-account lan_allowed flags.

const net = require('net');
const { db } = require('./db');
const { DESKTOP } = require('./config');

const DEFAULT_LAN_PORT = 8080;

// ---- settings persistence (server_settings kv) ----

function getSetting(key) {
  return db.prepare('SELECT value FROM server_settings WHERE key = ?').get(key)?.value;
}
function setSetting(key, value) {
  db.prepare(
    'INSERT INTO server_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
  ).run(key, value);
}

// Short cache: these helpers run per-request (every API call + WS upgrade),
// and the config changes only via the settings PUT which busts the cache.
let cache = { at: 0, cfg: null };

function getNetConfig() {
  if (cache.cfg && Date.now() - cache.at < 5000) return cache.cfg;
  let cidrs = [];
  try {
    const parsed = JSON.parse(getSetting('net.allow_cidrs') || '[]');
    if (Array.isArray(parsed)) cidrs = parsed.filter((c) => typeof c === 'string');
  } catch {}
  const port = parseInt(getSetting('net.lan_port'), 10);
  const bind = String(getSetting('net.lan_bind') || '').trim();
  cache = {
    at: Date.now(),
    cfg: {
      enabled: getSetting('net.lan_enabled') === '1',
      port: Number.isInteger(port) && port > 0 && port <= 65535 ? port : null,
      bind: net.isIP(bind) ? bind : '0.0.0.0',
      allowCidrs: cidrs,
    },
  };
  return cache.cfg;
}

function validateNetConfig(body) {
  const b = body || {};
  const enabled = !!b.enabled;
  let port = null;
  if (enabled) {
    port = parseInt(b.port, 10);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return { error: 'a fixed port (1-65535) is required for LAN access' };
    }
  }
  const bind = String(b.bind || '0.0.0.0').trim() || '0.0.0.0';
  if (bind !== '0.0.0.0' && bind !== '::' && net.isIP(bind) === 0) {
    return { error: 'bind must be an IP address, :: or 0.0.0.0' };
  }
  const allowCidrs = [];
  for (const raw of String(b.allowCidrs ?? '').split(/[\s,;]+/)) {
    const c = raw.trim();
    if (!c) continue;
    if (!parseCidr(c)) return { error: `invalid IP or CIDR: ${c}` };
    allowCidrs.push(c);
  }
  return { config: { enabled, port, bind, allowCidrs } };
}

function saveNetConfig(body) {
  const { config, error } = validateNetConfig(body);
  if (error) return { error };
  setSetting('net.lan_enabled', config.enabled ? '1' : '0');
  setSetting('net.lan_port', config.port ? String(config.port) : '');
  setSetting('net.lan_bind', config.bind);
  setSetting('net.allow_cidrs', JSON.stringify(config.allowCidrs));
  cache = { at: 0, cfg: null };
  return { config: getNetConfig() };
}

// ---- IP helpers ----

function normalizeIp(ip) {
  ip = String(ip || '').trim();
  // IPv4-mapped IPv6 (::ffff:1.2.3.4) is how dual-stack sockets report v4 peers.
  if (ip.toLowerCase().startsWith('::ffff:')) {
    const v4 = ip.slice(7);
    if (net.isIP(v4) === 4) return v4;
  }
  return ip;
}

function ipv4ToInt(ip) {
  const p = ip.split('.').map(Number);
  return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
}

function ipv6ToBig(ip) {
  const s = ip.toLowerCase().split('%')[0];
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 ? (halves[1] ? halves[1].split(':') : []) : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 && head.length !== 8) return null;
  if (missing < 0) return null;
  const parts = [...head, ...Array(missing).fill('0'), ...tail].map((h) => parseInt(h || '0', 16));
  if (parts.length !== 8 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 0xffff)) return null;
  let v = 0n;
  for (const p of parts) v = (v << 16n) | BigInt(p);
  return v;
}

function ipToBig(ip) {
  ip = normalizeIp(ip);
  if (net.isIP(ip) === 4) return BigInt(ipv4ToInt(ip));
  if (net.isIP(ip) === 6) return ipv6ToBig(ip);
  return null;
}

// 'a.b.c.d', 'a.b.c.d/24', '::1', 'fd00::/64' → {base, shift} or null.
function parseCidr(c) {
  const s = String(c || '').trim();
  const m = s.match(/^(.+)\/(\d{1,3})$/);
  const addr = m ? m[1] : s;
  const bits = m ? parseInt(m[2], 10) : null;
  const v = ipToBig(addr);
  if (v === null) return null;
  const isV6 = addr.includes(':');
  const maxBits = isV6 ? 128 : 32;
  const b = bits === null ? maxBits : bits;
  if (b < 0 || b > maxBits) return null;
  const shift = BigInt(maxBits - b);
  return { base: v >> shift, shift, isV6 };
}

function ipMatchesCidr(ip, cidrs) {
  const n = normalizeIp(ip);
  const v = ipToBig(n);
  if (v === null) return false;
  const ipIsV6 = n.includes(':');
  for (const c of cidrs) {
    const p = parseCidr(c);
    if (!p || p.isV6 !== ipIsV6) continue;
    if ((v >> p.shift) === p.base) return true;
  }
  return false;
}

function isLoopbackIp(ip) {
  const n = normalizeIp(ip);
  if (n === '::1') return true;
  if (net.isIP(n) === 4) return (ipv4ToInt(n) >>> 24) === 127;
  return false;
}

// ---- request-level checks (all no-op unless DESKTOP + LAN enabled) ----

function lanActive() {
  return DESKTOP && getNetConfig().enabled;
}

function clientIp(req) {
  return req.ip || req.socket?.remoteAddress || '';
}

function isLoopbackClient(req) {
  return isLoopbackIp(clientIp(req));
}

// IP allowlist for remote clients. Loopback is always allowed (the local
// app must keep working); an empty list means "any address may reach the
// login page" — still gated by real authentication.
function clientIpAllowed(req) {
  const cfg = getNetConfig();
  if (!cfg.allowCidrs.length) return true;
  return ipMatchesCidr(clientIp(req), cfg.allowCidrs);
}

// Express middleware: 403 remote clients outside the allowlist. Mount
// before all routes — it also gates the login page itself.
function lanAccessGuard(req, res, next) {
  if (!lanActive() || isLoopbackClient(req) || clientIpAllowed(req)) return next();
  return res.status(403).json({ error: 'client address not allowed' });
}

// Host-header check shared by the HTTP middleware and the WS upgrade:
// loopback names always pass; with LAN enabled, IP literals pass too (the
// UI is reached by address, not name). DNS names stay rejected — that's the
// DNS-rebinding guard.
function hostHeaderAllowed(hostHeader) {
  if (isLoopbackHostHeader(hostHeader)) return true;
  if (!lanActive()) return false;
  try {
    let h = new URL(`http://${hostHeader}`).hostname;
    if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
    return net.isIP(h) !== 0;
  } catch {
    return false;
  }
}

const LOOPBACK_HOSTNAMES = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);
function isLoopbackHostHeader(hostHeader) {
  try {
    const hostname = new URL(`http://${hostHeader}`).hostname.toLowerCase();
    return LOOPBACK_HOSTNAMES.has(hostname);
  } catch {
    return false;
  }
}

// Live status of the optional LAN listener, reported by index.js so the
// settings UI can show whether the configured bind actually came up.
let lanStatus = { listening: false, error: null, address: null };
function setLanStatus(s) {
  lanStatus = s;
}
function getLanStatus() {
  return lanStatus;
}

module.exports = {
  DEFAULT_LAN_PORT,
  getNetConfig,
  saveNetConfig,
  lanActive,
  isLoopbackClient,
  isLoopbackIp,
  clientIpAllowed,
  lanAccessGuard,
  hostHeaderAllowed,
  isLoopbackHostHeader,
  setLanStatus,
  getLanStatus,
};
