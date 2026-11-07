'use strict';

// Outbound webhook notifications: fire-and-forget POSTs to user-configured
// URLs. Payload adapts to the receiver: ntfy.sh wants a raw body + X-Title,
// Slack/Discord want {text}/{content}, anything else gets a generic JSON.
const { db } = require('./db');
const { URL } = require('url');
const dns = require('dns').promises;
const net = require('net');

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

async function postWebhook(url, event, message) {
  if (!(await assertPublicHost(url))) {
    console.error(`[ssloth] webhook delivery refused — non-public address (${url})`);
    return false;
  }
  const { body, headers = {} } = payloadFor(url, event, message);
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...headers },
      body,
      signal: ctrl.signal,
      redirect: 'error',
    });
    return true;
  } catch {
    return false;
  } finally {
    clearTimeout(t);
  }
}

// events: '*' or comma list ('host.down','playbook.done',...)
function matchEvents(events, event) {
  if (!events || events === '*') return true;
  return events.split(',').map((s) => s.trim()).includes(event);
}

// Fire matching webhooks for a user. Never throws; never blocks callers.
function notify(userId, event, message) {
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
