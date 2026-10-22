'use strict';

// Background health sweeper: TCP-probes every saved host on an interval,
// records transitions into host_health, and fires 'host.down'/'host.up'
// webhooks. The host-card status dots read the sweeper's in-memory cache,
// so the dots stay warm even between /status polls.

const net = require('net');
const { db } = require('./db');
const { notify } = require('./notify');

const SWEEP_MS = 60 * 1000;          // probe all hosts every minute
const ROW_EVERY = 10;                // persist every 10th probe (10 min)
const HISTORY_HOURS = 48;            // prune older rows
const BATCH = 16;

// hostId -> { ok, latencyMs, checkedAt, sinceChange, probes }
const state = new Map();

function probe(hostname, port, timeoutMs = 3000) {
  return new Promise((resolve) => {
    const started = Date.now();
    const sock = net.connect({ host: hostname, port, timeout: timeoutMs });
    const done = (ok) => {
      try { sock.destroy(); } catch {}
      resolve({ ok, latencyMs: Date.now() - started });
    };
    sock.on('connect', () => done(true));
    sock.on('timeout', () => done(false));
    sock.on('error', () => done(false));
  });
}

function latestHealth(hostId) {
  return state.get(hostId) || null;
}

function getHealthHistory(hostId) {
  return db
    .prepare('SELECT ts, ok, latency_ms FROM host_health WHERE host_id = ? ORDER BY ts DESC LIMIT 288')
    .all(hostId)
    .map((r) => ({ ...r, ts: r.ts * 1000 }));
}

async function sweep() {
  let hosts;
  try {
    hosts = db.prepare('SELECT id, user_id, hostname, port, name FROM hosts').all();
  } catch { return; }

  for (let i = 0; i < hosts.length; i += BATCH) {
    await Promise.all(
      hosts.slice(i, i + BATCH).map(async (h) => {
        const r = await probe(h.hostname, h.port);
        const prev = state.get(h.id);
        const changed = prev && prev.ok !== r.ok;
        const probes = (prev?.probes || 0) + 1;
        state.set(h.id, {
          ok: r.ok,
          latencyMs: r.latencyMs,
          checkedAt: Date.now(),
          sinceChange: changed ? Date.now() : prev?.sinceChange || Date.now(),
          probes,
        });

        if (changed) {
          db.prepare('INSERT INTO host_health (host_id, user_id, ok, latency_ms) VALUES (?, ?, ?, ?)')
            .run(h.id, h.user_id, r.ok ? 1 : 0, r.latencyMs);
          notify(h.user_id, r.ok ? 'host.up' : 'host.down', `${h.name || h.hostname} is now ${r.ok ? 'reachable' : 'unreachable'}`);
        } else if (probes % ROW_EVERY === 1 || !prev) {
          // heartbeat row so latency history exists between transitions
          db.prepare('INSERT INTO host_health (host_id, user_id, ok, latency_ms) VALUES (?, ?, ?, ?)')
            .run(h.id, h.user_id, r.ok ? 1 : 0, r.latencyMs);
        }
      })
    );
  }
}

function startSweeper() {
  setInterval(sweep, SWEEP_MS).unref();
  setTimeout(sweep, 15 * 1000).unref(); // first pass shortly after boot
  // prune old history hourly
  setInterval(() => {
    try {
      db.prepare('DELETE FROM host_health WHERE ts < unixepoch() - ?').run(HISTORY_HOURS * 3600);
    } catch {}
  }, 3600 * 1000).unref();
}

module.exports = { startSweeper, latestHealth, getHealthHistory, probe };
