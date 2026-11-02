// Classify a sensor status string into a severity tier so the dashboard
// only flags things that actually matter. Words like 'redundant',
// 'present' or 'enabled' are fine; 'absent' is informational (a slot
// being empty is normal in single-PSU builds, not an alert); only
// genuine fault states light the badge red.
const BAD = /critical|fatal|non.?recoverable|fail|degraded|offline|fault|unhealthy|urgent|emerg/i;
const WARN = /warn|non.?crit|elevated|high|low|throttl|not.?redundant|predictive/i;
const INFO = /absent|missing|unknown|na|n\/a|disabled|inactive|offline/i;
const OK = /^(ok|on|operable|completed|normal|good|enabled|present|equipped|redundant|healthy|fine|online|up|idle|standby)$/i;

export function sensorTier(status) {
  const s = String(status || '');
  if (BAD.test(s)) return 'bad';
  if (WARN.test(s)) return 'warn';
  if (INFO.test(s)) return 'info';
  if (OK.test(s)) return 'ok';
  return 'info'; // unknown strings don't alarm
}
