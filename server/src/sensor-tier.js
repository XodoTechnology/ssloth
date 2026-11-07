'use strict';

// Server-side port of web/src/lib/sensor-tier.js — same classification, so
// alert rules and the dashboard badge agree on what "bad" means. Keep the
// two files in sync.
const BAD = /critical|fatal|non.?recoverable|fail|degraded|offline|fault|unhealthy|urgent|emerg/i;
const WARN = /warn|non.?crit|elevated|high|low|throttl|not.?redundant|predictive/i;
const INFO = /absent|missing|unknown|na|n\/a|disabled|inactive|offline/i;
const OK = /^(ok|on|operable|completed|normal|good|enabled|present|equipped|redundant|healthy|fine|online|up|idle|standby)$/i;

const RANK = { ok: 0, info: 1, warn: 2, bad: 3 };

function sensorTier(status) {
  const s = String(status || '');
  if (BAD.test(s)) return 'bad';
  if (WARN.test(s)) return 'warn';
  if (INFO.test(s)) return 'info';
  if (OK.test(s)) return 'ok';
  return 'info'; // unknown strings don't alarm
}

/// Numeric rank for threshold comparisons: does `tier` meet `floor`?
function tierAtLeast(tier, floor) {
  return (RANK[tier] ?? 1) >= (RANK[floor] ?? 3);
}

module.exports = { sensorTier, tierAtLeast };
