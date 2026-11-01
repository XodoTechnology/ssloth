// Output watches: user-defined regexes tested against live session output.
// A hit rides the session ws as {type:'watch_hit'} so every attached client
// (and recording) sees it; the matcher is cheap — compiled regexes cached
// per user, refreshed whenever the table changes.

const db = require('./db');

const cache = new Map(); // userId -> {at, list:[{id,host_id,label,re}]}
const TTL_MS = 30 * 1000;

function watchesFor(userId) {
  const c = cache.get(userId);
  if (c && Date.now() - c.at < TTL_MS) return c.list;
  const rows = db
    .prepare('SELECT id, host_id, label, pattern FROM watches WHERE user_id = ? AND enabled = 1')
    .all(userId);
  const list = [];
  for (const r of rows) {
    try {
      list.push({ id: r.id, host_id: r.host_id, label: r.label || r.pattern, re: new RegExp(r.pattern, 'i') });
    } catch {}
  }
  cache.set(userId, { at: Date.now(), list });
  return list;
}

function invalidate(userId) {
  cache.delete(userId);
}

/// Strip ANSI so patterns match what the user reads, not escape codes.
const ANSI = /[\x1b\x9b][[\]()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-ntqry=><~]/g;

/// Called from sessionOutput — returns matching watch ids/labels.
function check(userId, hostId, text) {
  const list = watchesFor(userId);
  if (!list.length) return [];
  const clean = text.replace(ANSI, ' ');
  return list.filter((w) => (w.host_id == null || w.host_id === hostId) && w.re.test(clean));
}

module.exports = { check, invalidate };
