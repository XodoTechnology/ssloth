'use strict';

// In-app notifications: one row per event, fanned out to the bell UI, the
// webhook dispatcher, and (Phase 2c) browser push. Everything here is
// fire-and-forget — a notification must never break the thing it reports.
const { db } = require('./db');
const { notify: notifyWebhooks } = require('./notify');

/// kind examples: 'sensor.alert', 'sensor.recovered', 'watch.hit'.
/// link is an in-app route the bell click follows ('/bmc', '/sessions'…).
/// With dedupeMs > 0, an identical (kind,title) within the window is dropped —
/// for events that can repeat every poll.
function push(userId, kind, title, body = '', link = null, dedupeMs = 0) {
  try {
    if (dedupeMs > 0) {
      const since = Math.floor(Date.now() / 1000) - Math.ceil(dedupeMs / 1000);
      const dup = db
        .prepare('SELECT 1 FROM notifications WHERE user_id = ? AND kind = ? AND title = ? AND created_at > ? LIMIT 1')
        .get(userId, kind, title, since);
      if (dup) return null;
    }
    const info = db
      .prepare('INSERT INTO notifications (user_id, kind, title, body, link) VALUES (?, ?, ?, ?, ?)')
      .run(userId, kind, String(title).slice(0, 200), String(body).slice(0, 1000), link);
    // Webhooks see the same event under a dotted name ('sensor.alert').
    notifyWebhooks(userId, kind, `${title}${body ? ` — ${body}` : ''}`);
    return info.lastInsertRowid;
  } catch (e) {
    console.error('[ssloth] notification push failed:', e.message);
    return null;
  }
}

function list(userId, { unreadOnly = false, limit = 100 } = {}) {
  return db
    .prepare(
      `SELECT id, kind, title, body, link, read, created_at FROM notifications
       WHERE user_id = ? ${unreadOnly ? 'AND read = 0' : ''}
       ORDER BY created_at DESC, id DESC LIMIT ?`
    )
    .all(userId, Math.min(limit, 500));
}

function unreadCount(userId) {
  return db.prepare('SELECT COUNT(*) AS n FROM notifications WHERE user_id = ? AND read = 0').get(userId).n;
}

function markRead(userId, id) {
  return db.prepare('UPDATE notifications SET read = 1 WHERE id = ? AND user_id = ?').run(id, userId).changes;
}

function markAllRead(userId) {
  return db.prepare('UPDATE notifications SET read = 1 WHERE user_id = ? AND read = 0').run(userId).changes;
}

function remove(userId, id) {
  return db.prepare('DELETE FROM notifications WHERE id = ? AND user_id = ?').run(id, userId).changes;
}

// Watch hits repeat every output chunk — cap them at one notification per
// (user, watch label) per window so a chatty match can't flood the bell.
const HIT_COOLDOWN_MS = 5 * 60 * 1000;
const hitCache = new Map(); // `${userId}:${label}` -> last sent ms
function watchHit(userId, hostLabel, label) {
  const key = `${userId}:${label}`;
  const now = Date.now();
  if (now - (hitCache.get(key) || 0) < HIT_COOLDOWN_MS) return;
  hitCache.set(key, now);
  push(userId, 'watch.hit', `Watch hit on ${hostLabel}`, `pattern "${label}" matched session output`, '/sessions');
}

module.exports = { push, list, unreadCount, markRead, markAllRead, remove, watchHit };
