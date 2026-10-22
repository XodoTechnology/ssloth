'use strict';

// Standalone playbook runner — runs a playbook's steps on exec channels over
// a dedicated SSH connection (no interactive shell, no attached terminal).
// Powers the cron scheduler and the REST "run now" trigger. Results land in
// playbook_runs and fire a webhook.
//
// Caveat: non-interactive runs can't prompt — hosts must have stored
// credentials (auth_type 'credential'/'password'), and host keys must already
// be trusted (no TOFU prompt exists off-terminal). A run on an untrusted key
// fails closed, which is the correct posture.

const { db, audit } = require('../db');
const { resolveConnectSpec, establishConn } = require('./manager');
const { notify } = require('../notify');

const MAX_RUN_OUTPUT = 256 * 1024;
const running = new Map(); // runId -> { stop() }

// cron: '* * * * *' — supports '*', lists '1,3', ranges '1-5', steps '*/5'
// and 'a-b/n'. Fields: minute hour day-of-month month day-of-week.
// Does a single cron field pattern match `val` within [lo,hi]?
function fieldMatch(p, val, lo, hi, isDow) {
  return p.split(',').some((piece) => {
    const m = piece.match(/^(\*|\d+)(?:-(\d+))?(?:\/(\d+))?$/);
    if (!m) return false;
    const a = m[1] === '*' ? lo : +m[1];
    const b = m[2] !== undefined ? +m[2] : m[1] === '*' ? hi : +m[1];
    const step = +m[3] || 1;
    if (a < lo || b > hi || a > b) return false;
    // sunday normalization: both 0 and 7 are valid
    const vv = isDow && val === 0 ? 7 : val;
    const inRange = (val >= a && val <= b) || (isDow && vv >= a && vv <= b);
    return inRange && (val - a) % step === 0;
  });
}

// cron: '* * * * *' — supports '*', lists '1,3', ranges '1-5', steps '*/5'
// and 'a-b/n'. Fields: minute hour day-of-month month day-of-week.
function cronMatches(expr, d = new Date()) {
  const parts = String(expr || '').trim().split(/\s+/);
  if (parts.length !== 5) return false;
  const fields = [
    [d.getMinutes(), 0, 59, false],
    [d.getHours(), 0, 23, false],
    [d.getDate(), 1, 31, false],
    [d.getMonth() + 1, 1, 12, false],
    [d.getDay(), 0, 7, true],
  ];
  return parts.every((p, i) => fieldMatch(p, ...fields[i]));
}

function nextCron(expr, from = Date.now()) {
  // Day-wise scan (≤4 years of days): check the date fields per-day, then
  // find the earliest matching hour:minute within a matching day. A pure
  // minute-by-minute scan would take ~500k iterations to find a monthly run.
  const parts = String(expr || '').trim().split(/\s+/);
  if (parts.length !== 5) return null;
  const day0 = new Date(from);
  for (let d = 0; d < 4 * 366; d++) {
    // new Date(y,m,dom+d) handles month rollover AND DST-odd days correctly.
    const date = new Date(day0.getFullYear(), day0.getMonth(), day0.getDate() + d);
    if (!fieldMatch(parts[2], date.getDate(), 1, 31, false)) continue;
    if (!fieldMatch(parts[3], date.getMonth() + 1, 1, 12, false)) continue;
    if (!fieldMatch(parts[4], date.getDay(), 0, 7, true)) continue;
    const midnight = date.getTime();
    for (let m = 0; m < 24 * 60; m++) {
      const t = midnight + m * 60000;
      if (t <= from) continue;
      const dt = new Date(t);
      if (fieldMatch(parts[0], dt.getMinutes(), 0, 59, false) &&
          fieldMatch(parts[1], dt.getHours(), 0, 23, false)) {
        return t;
      }
    }
  }
  return null;
}

// Kick off a detached run: inserts the playbook_runs row synchronously and
// returns { runId, done } — `done` resolves with {runId, status, output}.
// onStep(i, status, code) is optional progress reporting.
function runPlaybookDetached(userId, pbRow, hostRow, trigger, onStep) {
  const steps = (JSON.parse(pbRow.steps || '[]') || [])
    .filter((s) => s && typeof s.command === 'string' && s.command.trim())
    .slice(0, 100);

  const runInfo = db
    .prepare(
      'INSERT INTO playbook_runs (user_id, playbook_id, host_id, name, host_label, trigger) VALUES (?, ?, ?, ?, ?, ?)'
    )
    .run(userId, pbRow.id, hostRow.id, pbRow.name, hostRow.name || hostRow.hostname, trigger);
  const runId = runInfo.lastInsertRowid;

  const done = runSteps(userId, pbRow, hostRow, runId, steps, onStep).catch((e) => {
    db.prepare("UPDATE playbook_runs SET status = 'error', output = output || ?, ended_at = unixepoch() WHERE id = ?")
      .run(`\ninternal error: ${e.message}\n`, runId);
    running.delete(runId);
    return { runId, status: 'error' };
  });
  return { runId, done };
}

async function runSteps(userId, pbRow, hostRow, runId, steps, onStep) {
  let output = '';
  const append = (s) => {
    output += s;
    if (output.length > MAX_RUN_OUTPUT) output = output.slice(-MAX_RUN_OUTPUT);
  };

  const finish = (status) => {
    db.prepare('UPDATE playbook_runs SET status = ?, output = ?, ended_at = unixepoch() WHERE id = ?')
      .run(status, output, runId);
    db.prepare('UPDATE playbooks SET last_run_at = unixepoch() WHERE id = ?').run(pbRow.id);
    running.delete(runId);
    audit({ id: userId, username: '' }, 'playbook.run_finished', `${pbRow.name} -> ${hostRow.name}: ${status}`);
    notify(userId, 'playbook.done', `'${pbRow.name}' on ${hostRow.name || hostRow.hostname}: ${status}`);
    return { runId, status, output };
  };

  let conn = null;
  const abort = { flag: false };
  running.set(runId, { stop: () => { abort.flag = true; try { conn?.end(); } catch {} } });

  try {
    const spec = resolveConnectSpec(userId, { hostId: hostRow.id });
    if (spec.authType === 'ask') throw Object.assign(new Error('host has no stored credential — scheduled runs cannot prompt'), { code: 'error' });
    conn = await establishConn(userId, spec, {});
  } catch (e) {
    append(`connect failed: ${e.message}\n`);
    return finish(e.code === 'hostkey_mismatch' || e.code === 'unknown_hostkey' ? 'error' : 'fail');
  }

  let status = 'ok';
  for (let i = 0; i < steps.length && !abort.flag; i++) {
    const step = steps[i];
    const timeoutMs = Math.min(Math.max(parseInt(step.timeout_s, 10) || 60, 5), 3600) * 1000;
    append(`\n$ ${step.command}\n`);
    onStep?.(i, 'running');
    // eslint-disable-next-line no-await-in-loop
    const r = await new Promise((resolve) => {
      let timer;
      conn.exec(step.command, (err, ch) => {
        if (err) return resolve({ status: 'fail', code: null });
        ch.on('data', (d) => append(d.toString()));
        ch.stderr?.on('data', (d) => append(d.toString()));
        timer = setTimeout(() => {
          try { ch.close(); } catch {}
          resolve({ status: 'timeout', code: null });
        }, timeoutMs);
        timer.unref?.();
        ch.on('close', (code) => {
          clearTimeout(timer);
          resolve({ status: code === 0 ? 'ok' : 'fail', code });
        });
      });
    });
    append(`[exit ${r.code ?? r.status}]\n`);
    onStep?.(i, r.status, r.code);
    if (r.status !== 'ok') { status = r.status; break; }
  }
  if (abort.flag) status = 'aborted';
  try { conn.end(); } catch {}
  return finish(status);
}

function stopRun(runId) {
  running.get(runId)?.stop();
}

// ---- scheduler: tick every 30s, fire due playbooks ----
const tick = () => {
  let due;
  try {
    due = db
      .prepare(
        `SELECT p.*, h.user_id AS owner, h.name AS hname, h.hostname AS hhost
         FROM playbooks p JOIN hosts h ON h.id = p.schedule_host_id
         WHERE p.schedule_enabled = 1 AND p.next_run_at IS NOT NULL AND p.next_run_at <= unixepoch()`
      )
      .all();
  } catch { return; }
  for (const pb of due) {
    const next = nextCron(pb.schedule_cron);
    db.prepare('UPDATE playbooks SET next_run_at = ? WHERE id = ?')
      .run(next ? Math.floor(next / 1000) : null, pb.id);
    const hostRow = db.prepare('SELECT * FROM hosts WHERE id = ?').get(pb.schedule_host_id);
    if (!hostRow) continue;
    runPlaybookDetached(pb.user_id, pb, hostRow, 'schedule').catch(() => {});
  }
};

function startScheduler() {
  // compute next_run_at for enabled schedules missing it (first boot)
  try {
    const rows = db.prepare('SELECT id, schedule_cron FROM playbooks WHERE schedule_enabled = 1 AND next_run_at IS NULL').all();
    for (const r of rows) {
      const next = nextCron(r.schedule_cron);
      if (next) db.prepare('UPDATE playbooks SET next_run_at = ? WHERE id = ?').run(Math.floor(next / 1000), r.id);
    }
  } catch {}
  setInterval(tick, 30 * 1000).unref();
}

module.exports = { cronMatches, nextCron, runPlaybookDetached, startScheduler, stopRun };
