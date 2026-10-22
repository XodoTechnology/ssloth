'use strict';

// Outbound webhook notifications: fire-and-forget POSTs to user-configured
// URLs. Payload adapts to the receiver: ntfy.sh wants a raw body + X-Title,
// Slack/Discord want {text}/{content}, anything else gets a generic JSON.
const { db } = require('./db');
const { URL } = require('url');

const TIMEOUT_MS = 8000;

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

module.exports = { notify, postWebhook };
