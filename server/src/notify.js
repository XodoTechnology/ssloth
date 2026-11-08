'use strict';

// Outbound webhook notifications: fire-and-forget POSTs to user-configured
// URLs. Payload adapts to the receiver: ntfy.sh wants a raw body + X-Title,
// Slack/Discord want {text}/{content}, anything else gets a generic JSON.
const { db } = require('./db');
const { URL } = require('url');
const dns = require('dns').promises;
const net = require('net');
const http = require('http');
const https = require('https');

const TIMEOUT_MS = 8000;

// Webhook URLs are user-supplied — without a guard they are an SSRF channel
// into loopback, the LAN, or cloud metadata (169.254.169.254). Resolve at
// send time (not just registration) so DNS rebinding can't sneak past.
// SSLOTH_ALLOW_PRIVATE_WEBHOOKS=true opts out for self-hosted LAN setups.
const ALLOW_PRIVATE = process.env.SSLOTH_ALLOW_PRIVATE_WEBHOOKS === 'true';

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return (
      a === 0 || a === 10 || a === 127 || // this-net, private, loopback
      (a === 169 && b === 254) || // link-local / cloud metadata
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) || // CGNAT
      a >= 224 // multicast + reserved
    );
  }
  if (net.isIPv6(ip)) {
    const s = ip.toLowerCase();
    if (s === '::1' || s === '::') return true;
    if (s.startsWith('fe80') || s.startsWith('fc') || s.startsWith('fd')) return true;
    // IPv4-mapped IPv6 (::ffff:a.b.c.d)
    const m = s.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (m) return isPrivateIp(m[1]);
    return false;
  }
  return true; // not an IP literal we understand — treat as unsafe
}

async function assertPublicHost(url) {
  if (ALLOW_PRIVATE) return true;
  const host = new URL(url).hostname;
  if (net.isIP(host)) return !isPrivateIp(host);
  let addrs;
  try {
    addrs = await dns.lookup(host, { all: true });
  } catch {
    return false;
  }
  if (!addrs.length) return false;
  return addrs.every((a) => !isPrivateIp(a.address));
}

function payloadFor(url, event, message) {
  const u = new URL(url);
  if (/(^|\.)ntfy\.sh$/.test(u.hostname)) {
    return { body: message, headers: { 'X-Title': `ssloth — ${event}` } };
  }
  if (/hooks\.slack\.com$/.test(u.hostname)) {
    return { body: JSON.stringify({ text: `*${event}* — ${message}` }) };
  }
  if (/discord(app)?\.com$/.test(u.hostname) && u.pathname.includes('/webhooks/')) {
    return { body: JSON.stringify({ content: `**${event}** — ${message}` }) };
  }
  return { body: JSON.stringify({ event, message, ts: Date.now() }) };
}

// Resolve a webhook host once and return the validated addresses — the TCP
// connect is then pinned to exactly these IPs via a custom lookup, closing
// the DNS-rebinding TOCTOU where assertPublicHost's resolution and fetch's
// own resolution could disagree.
async function resolvePublicAddrs(host) {
  if (net.isIP(host)) {
    return isPrivateIp(host) ? null : [{ address: host, family: net.isIP(host) }];
  }
  let addrs;
  try {
    addrs = await dns.lookup(host, { all: true });
  } catch {
    return null;
  }
  if (!addrs.length || !addrs.every((a) => !isPrivateIp(a.address))) return null;
  return addrs;
}

function postWebhook(url, event, message) {
  return new Promise((resolve) => {
    let u;
    try {
      u = new URL(url);
    } catch {
      return resolve(false);
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return resolve(false);
    const { body, headers = {} } = payloadFor(url, event, message);
    const mod = u.protocol === 'https:' ? https : http;

    (ALLOW_PRIVATE ? Promise.resolve(null) : resolvePublicAddrs(u.hostname))
      .then((addrs) => {
        if (!ALLOW_PRIVATE && !addrs) {
          console.error(`[ssloth] webhook delivery refused — non-public address (${url})`);
          return resolve(false);
        }
        // Pin the connection to the addresses we just validated. Node calls
        // lookup per connect attempt; rotate through the validated set.
        let i = 0;
        const lookup = addrs
          ? (hostname, options, cb) => {
              const a = addrs[i++ % addrs.length];
              cb(null, a.address, a.family);
            }
          : undefined;
        const req = mod.request(u, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...headers },
          lookup,
          servername: u.protocol === 'https:' ? u.hostname : undefined,
          timeout: TIMEOUT_MS,
        }, (res) => {
          res.resume();
          resolve(true);
        });
        req.on('timeout', () => req.destroy());
        req.on('error', () => resolve(false));
        req.end(body);
      })
      .catch(() => resolve(false));
  });
}

// events: '*' or comma list ('host.down','playbook.done',...)
function matchEvents(events, event) {
  if (!events || events === '*') return true;
  return events.split(',').map((s) => s.trim()).includes(event);
}

// Per-user send budget: audit forwarding means one busy account (bulk SFTP,
// sensor storms) could otherwise fire hundreds of POSTs at its webhook.
const SEND_BUDGET = 60; // per user per minute
const sendWindows = new Map(); // userId -> { count, resetAt }

function allowSend(userId) {
  const now = Date.now();
  let w = sendWindows.get(userId);
  if (!w || now > w.resetAt) {
    w = { count: 0, resetAt: now + 60_000 };
    sendWindows.set(userId, w);
  }
  if (++w.count > SEND_BUDGET) return false;
  if (sendWindows.size > 10000) sendWindows.clear(); // bound the map
  return true;
}

// Fire matching webhooks for a user. Never throws; never blocks callers.
function notify(userId, event, message) {
  if (!allowSend(userId)) return;
  let rows;
  try {
    rows = db.prepare('SELECT * FROM webhooks WHERE user_id = ? AND enabled = 1').all(userId);
  } catch {
    return;
  }
  for (const w of rows) {
    if (!matchEvents(w.events, event)) continue;
    postWebhook(w.url, event, message).then((ok) => {
      if (!ok) console.error(`[ssloth] webhook ${w.id} delivery failed (${event})`);
    });
  }
}

module.exports = { notify, postWebhook, assertPublicHost };
