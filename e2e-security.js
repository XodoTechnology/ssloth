// E2E security round: TOTP lifecycle (pending-secret enroll, replay,
// disable requirements), CSRF/origin enforcement, tunnel bind rules,
// admin-only sharing, stale-secret cleanup, exec playbooks (exit codes +
// timeout), vault v2 export/import (bastion ordering, playbooks, tunnels),
// logout teardown.
const crypto = require('crypto');
const BASE = 'http://localhost:8089';
const WebSocket = require('/root/vscode/ssloth/server/node_modules/ws');
const net = require('net');

// ---- helpers ----
function ctx() {
  let cookie = '';
  return {
    api: async (path, opts = {}) => {
      const r = await fetch(BASE + path, {
        method: opts.method || 'GET',
        headers: {
          ...(opts.body ? { 'Content-Type': 'application/json' } : {}),
          cookie,
          origin: opts.origin === undefined ? BASE : opts.origin,
          ...(opts.headers || {}),
        },
        body: opts.body ? JSON.stringify(opts.body) : undefined,
      });
      const sc = r.headers.get('set-cookie');
      if (sc) cookie = sc.split(';')[0];
      const j = await r.json().catch(() => ({}));
      if (!r.ok) j._status = r.status;
      return j;
    },
    get cookie() { return cookie; },
    set cookie(v) { cookie = v; },
  };
}

const results = [];
const check = (name, ok, extra = '') => {
  results.push([name, ok]);
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${extra ? ' — ' + extra : ''}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// RFC6238 client for the test — mirrors server/src/crypto.js.
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32dec(str) {
  let bits = 0, value = 0;
  const out = [];
  for (const ch of str.toUpperCase()) {
    const i = B32.indexOf(ch);
    if (i === -1) continue;
    value = (value << 5) | i; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(out);
}
function totp(secret, offset = 0) {
  const key = b32dec(secret);
  const counter = Math.floor(Date.now() / 1000 / 30) + offset;
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', key).update(msg).digest();
  const o = h[h.length - 1] & 0x0f;
  const code = ((h[o] & 0x7f) << 24) | ((h[o + 1] & 0xff) << 16) | ((h[o + 2] & 0xff) << 8) | (h[o + 3] & 0xff);
  return String(code % 1000000).padStart(6, '0');
}
const nowStep = () => Math.floor(Date.now() / 1000 / 30);
async function waitStepBeyond(step) {
  while (nowStep() <= step) await sleep(700);
}

function wsCollect(cookie, firstMsg, { until, timeoutMs = 20000, autoTrust = false, autoPassword = null }) {
  return new Promise((resolve) => {
    const ws = new WebSocket('ws://localhost:8089/ws/terminal', {
      headers: { cookie, origin: BASE },
    });
    const out = [];
    let done = false;
    const finish = () => { if (!done) { done = true; try { ws.close(); } catch {} resolve(out); } };
    ws.on('open', () => ws.send(JSON.stringify(firstMsg)));
    ws.on('message', (d, isBinary) => {
      if (isBinary) { out.push({ type: 'binary' }); return; }
      let m;
      try { m = JSON.parse(d.toString()); } catch { return; }
      out.push(m);
      if (m.type === 'hostkey' && autoTrust) ws.send(JSON.stringify({ type: 'trust', accept: 'once' }));
      if (m.type === 'auth_request' && autoPassword) ws.send(JSON.stringify({ type: 'auth', password: autoPassword }));
      if (until(out)) finish();
    });
    ws.on('close', finish);
    setTimeout(finish, timeoutMs);
  });
}

(async () => {
  const admin = ctx();
  await admin.api('/api/auth/login', { method: 'POST', body: { username: 'admin', password: 'supersecretpw1' } });

  // ---------- CSRF / origin ----------
  const noOrigin = await admin.api('/api/hosts', { method: 'POST', origin: null, body: { name: 'x', hostname: 'x', username: 'x', auth_type: 'ask' } });
  check('mutation without Origin rejected', noOrigin._status === 403, JSON.stringify(noOrigin));
  const evilOrigin = await admin.api('/api/hosts', { method: 'POST', origin: 'https://evil.example', body: { name: 'x', hostname: 'x', username: 'x', auth_type: 'ask' } });
  check('mutation with foreign Origin rejected', evilOrigin._status === 403);
  const fetchSite = await admin.api('/api/hosts', { method: 'GET', headers: { 'sec-fetch-site': 'cross-site' } });
  check('GET unaffected by origin rules', fetchSite._status === undefined && Array.isArray(fetchSite.hosts));

  // ---------- TOTP lifecycle on the admin account ----------
  // Each 30s step's code may only be consumed once (replay protection), so
  // the test tracks the last consumed counter and uses the +1 window when
  // it needs a fresh code inside the same step.
  let totpSecret = null;
  let lastStep = 0;
  const freshCode = async () => {
    if (nowStep() <= lastStep) await waitStepBeyond(lastStep);
    // nowStep() > lastStep — current-step code has an unused counter
    lastStep = nowStep();
    return totp(totpSecret);
  };
  try {
    const setup = await admin.api('/api/auth/totp/setup', { method: 'POST', body: {} });
    totpSecret = setup.secret;
    check('totp setup returns pending secret', !!totpSecret && !!setup.qr);

    const st = await admin.api('/api/auth/state');
    check('totp not enabled before confirm', st.user && st.user.totp_enabled === false);

    const badEnable = await admin.api('/api/auth/totp/enable', { method: 'POST', body: { code: '000000' } });
    check('enable rejects wrong code', badEnable._status === 400);

    const code0 = totp(totpSecret);
    lastStep = nowStep(); // enabling consumes the current step
    const enable = await admin.api('/api/auth/totp/enable', { method: 'POST', body: { code: code0 } });
    check('totp enable with valid code', enable.ok === true);

    // logout, login without code -> totp_required
    await admin.api('/api/auth/logout', { method: 'POST' });
    const need = await admin.api('/api/auth/login', { method: 'POST', body: { username: 'admin', password: 'supersecretpw1' } });
    check('login requires TOTP', need.totp_required === true && need._status === 401);

    const code1 = await freshCode();
    const login = await admin.api('/api/auth/login', { method: 'POST', body: { username: 'admin', password: 'supersecretpw1', totp: code1 } });
    check('TOTP login succeeds', !!login.user, JSON.stringify(login));

    // replay the same code — must be rejected
    await admin.api('/api/auth/logout', { method: 'POST' });
    const replay = await admin.api('/api/auth/login', { method: 'POST', body: { username: 'admin', password: 'supersecretpw1', totp: code1 } });
    check('TOTP replay rejected', replay._status === 401 && replay.totp_required === true);

    // back in with a fresh code for the disable checks
    const code2 = await freshCode();
    const login2 = await admin.api('/api/auth/login', { method: 'POST', body: { username: 'admin', password: 'supersecretpw1', totp: code2 } });
    check('login with fresh code', !!login2.user);

    const noPw = await admin.api('/api/auth/totp/disable', { method: 'POST', body: {} });
    check('disable without password rejected', noPw._status === 403);
    const noCode = await admin.api('/api/auth/totp/disable', { method: 'POST', body: { password: 'supersecretpw1' } });
    check('disable without code rejected', noCode._status === 403);
    const replayedDisable = await admin.api('/api/auth/totp/disable', { method: 'POST', body: { password: 'supersecretpw1', code: code2 } });
    check('disable rejects replayed code', replayedDisable._status === 403);
  } finally {
    // restore: admin must end up with 2FA off, whatever happened above
    if (totpSecret) {
      const code = await freshCode();
      await admin.api('/api/auth/login', { method: 'POST', body: { username: 'admin', password: 'supersecretpw1', totp: code } });
      const dcode = await freshCode();
      await admin.api('/api/auth/totp/disable', { method: 'POST', body: { password: 'supersecretpw1', code: dcode } });
    }
    await admin.api('/api/auth/login', { method: 'POST', body: { username: 'admin', password: 'supersecretpw1' } });
    const after = await admin.api('/api/auth/state');
    check('TOTP disabled cleanly at end', after.user && after.user.totp_enabled === false);
  }

  // ---------- tunnel bind rules ----------
  const hosts = (await admin.api('/api/hosts')).hosts;
  const testHost = hosts.find((h) => h.name === 'test-sshd');
  const badBind = await admin.api('/api/tunnels', {
    method: 'POST',
    body: { name: 'pub-bind', host_id: testHost.id, bind_address: '0.0.0.0', local_port: 18777, remote_host: '127.0.0.1', remote_port: 2222 },
  });
  check('public bind rejected without env+admin opt-in', badBind._status === 400, JSON.stringify(badBind));
  const lowPort = await admin.api('/api/tunnels', {
    method: 'POST',
    body: { name: 'low-port', host_id: testHost.id, bind_address: '127.0.0.1', local_port: 80, remote_host: '127.0.0.1', remote_port: 2222 },
  });
  check('privileged local_port rejected', lowPort._status === 400);

  // ---------- stale secret cleared on auth_type switch ----------
  const tmpHost = await admin.api('/api/hosts', {
    method: 'POST',
    body: { name: 'stale-secret-test', hostname: '127.0.0.1', port: 2222, username: 'tester', auth_type: 'password', password: 'testpass123' },
  });
  check('password host created', !!tmpHost.host?.id);
  const withSecret = (await admin.api('/api/hosts')).hosts.find((h) => h.id === tmpHost.host.id);
  await admin.api(`/api/hosts/${tmpHost.host.id}`, { method: 'PUT', body: { auth_type: 'ask' } });
  const afterSwitch = (await admin.api('/api/hosts')).hosts.find((h) => h.id === tmpHost.host.id);
  check('password_enc cleared on auth_type -> ask', withSecret?.has_password === true && afterSwitch?.has_password === false, `before=${withSecret?.has_password} after=${afterSwitch?.has_password}`);
  await admin.api(`/api/hosts/${tmpHost.host.id}`, { method: 'DELETE' });

  // ---------- shared flag is admin-only ----------
  const mate = ctx();
  let mk = await admin.api('/api/admin/users', { method: 'POST', body: { username: 'secmate', password: 'matepass1234' } });
  if (!mk.user?.id) {
    // leftover from a previous run — delete and recreate so the password is known
    const all = await admin.api('/api/admin/users');
    const existing = (all.users || []).find((u) => u.username === 'secmate');
    if (existing) {
      await admin.api(`/api/admin/users/${existing.id}`, { method: 'DELETE' });
      mk = await admin.api('/api/admin/users', { method: 'POST', body: { username: 'secmate', password: 'matepass1234' } });
    }
  }
  check('second user created', !!mk.user?.id);
  await mate.api('/api/auth/login', { method: 'POST', body: { username: 'secmate', password: 'matepass1234' } });
  const shareTry = await mate.api('/api/hosts', {
    method: 'POST',
    body: { name: 'mate-share-try', hostname: '127.0.0.1', port: 2222, username: 'tester', auth_type: 'ask', shared: true },
  });
  check('non-admin cannot create shared host', shareTry._status === 403, JSON.stringify(shareTry));
  const mateHost = await mate.api('/api/hosts', {
    method: 'POST',
    body: { name: 'mate-own', hostname: '127.0.0.1', port: 2222, username: 'tester', auth_type: 'ask' },
  });
  const mateShare = await mate.api(`/api/hosts/${mateHost.host.id}`, { method: 'PUT', body: { shared: true } });
  check('non-admin cannot flag own host shared', mateShare._status === 403);

  // ---------- exec playbooks: real exit codes, abort on fail, timeout ----------
  const pb = await admin.api('/api/playbooks', {
    method: 'POST',
    body: {
      name: 'sec-playbook',
      steps: [
        { command: 'echo step-one && exit 0' },
        { command: 'exit 3' },
        { command: 'echo SHOULD_NOT_RUN' },
      ],
    },
  });
  check('playbook created', !!pb.playbook?.id);

  // fresh session for the playbook run
  let sid = null;
  const con = await wsCollect(admin.cookie, { type: 'connect', hostId: testHost.id, cols: 80, rows: 24 }, {
    until: (o) => o.some((m) => m.type === 'ready'),
    timeoutMs: 15000,
  });
  sid = con.find((m) => m.type === 'ready')?.sessionId;
  check('session for playbook', !!sid);

  // run the playbook over a fresh reattached socket
  const pbRun = await new Promise((resolve) => {
    const ws = new WebSocket('ws://localhost:8089/ws/terminal', { headers: { cookie: admin.cookie, origin: BASE } });
    const out = [];
    const finish = () => { try { ws.close(); } catch {} resolve(out); };
    ws.on('open', () => ws.send(JSON.stringify({ type: 'reattach', sessionId: sid, cols: 80, rows: 24 })));
    ws.on('message', (d, isBinary) => {
      if (isBinary) return;
      let m;
      try { m = JSON.parse(d.toString()); } catch { return; }
      out.push(m);
      if (m.type === 'ready') ws.send(JSON.stringify({ type: 'playbook', playbookId: pb.playbook.id }));
      if (m.type === 'playbook_done') finish();
    });
    setTimeout(finish, 30000);
  });
  const steps = pbRun.filter((m) => m.type === 'playbook_step' && m.status !== 'running');
  const done = pbRun.find((m) => m.type === 'playbook_done');
  check('step 1 ok exit 0', steps[0]?.status === 'ok' && steps[0]?.exitCode === 0, JSON.stringify(steps[0]));
  check('step 2 fails with real code 3', steps[1]?.status === 'fail' && steps[1]?.exitCode === 3, JSON.stringify(steps[1]));
  check('step 3 aborted after failure', steps.length === 2 && done?.ok === false, `steps=${steps.length} done=${JSON.stringify(done)}`);

  // timeout step
  const pbT = await admin.api('/api/playbooks', {
    method: 'POST',
    body: { name: 'timeout-playbook', steps: [{ command: 'sleep 30', timeout_s: 2 }] },
  });
  const toRun = await new Promise((resolve) => {
    const ws = new WebSocket('ws://localhost:8089/ws/terminal', { headers: { cookie: admin.cookie, origin: BASE } });
    const out = [];
    const finish = () => { try { ws.close(); } catch {} resolve(out); };
    ws.on('open', () => ws.send(JSON.stringify({ type: 'reattach', sessionId: sid, cols: 80, rows: 24 })));
    ws.on('message', (d, isBinary) => {
      if (isBinary) return;
      let m;
      try { m = JSON.parse(d.toString()); } catch { return; }
      out.push(m);
      if (m.type === 'ready') ws.send(JSON.stringify({ type: 'playbook', playbookId: pbT.playbook.id }));
      if (m.type === 'playbook_done') finish();
    });
    setTimeout(finish, 15000);
  });
  const toStep = toRun.find((m) => m.type === 'playbook_step' && m.status === 'timeout');
  check('step times out (2s on sleep 30)', !!toStep && toStep.timedOut === true, JSON.stringify(toStep));
  await admin.api(`/api/playbooks/${pb.playbook.id}`, { method: 'DELETE' });
  await admin.api(`/api/playbooks/${pbT.playbook.id}`, { method: 'DELETE' });

  // ---------- vault export/import v2: bastion ordering + playbooks + tunnels ----------
  const bastion = await admin.api('/api/hosts', {
    method: 'POST', body: { name: 'exp-bastion', hostname: '127.0.0.1', port: 2222, username: 'tester', auth_type: 'password', password: 'testpass123' },
  });
  const behind = await admin.api('/api/hosts', {
    method: 'POST', body: { name: 'exp-behind', hostname: '10.255.0.9', port: 22, username: 'ops', auth_type: 'ask', jump_host_id: bastion.host.id },
  });
  const tun = await admin.api('/api/tunnels', {
    method: 'POST', body: { name: 'exp-tunnel', host_id: testHost.id, bind_address: '127.0.0.1', local_port: 18778, remote_host: '127.0.0.1', remote_port: 80 },
  });
  const expPb = await admin.api('/api/playbooks', {
    method: 'POST', body: { name: 'exp-playbook', steps: [{ command: 'uptime' }] },
  });
  const vault = await admin.api('/api/vault/export', {
    method: 'POST', body: { include_credentials: true, passphrase: 'vault-pass-1234' },
  });
  const exp = vault.ssloth_export;
  check('vault export v2', exp?.version === 2 && Array.isArray(exp.playbooks) && Array.isArray(exp.tunnels));
  check('export carries shared flag', exp?.hosts?.every((h) => 'shared' in h));

  // bastion ordering bug: put the dependent host BEFORE its bastion in the payload
  const bi = exp.hosts.findIndex((h) => h.name === 'exp-behind');
  const bj = exp.hosts.findIndex((h) => h.name === 'exp-bastion');
  if (bi > bj) [exp.hosts[bi], exp.hosts[bj]] = [exp.hosts[bj], exp.hosts[bi]];
  const imp = await mate.api('/api/vault/import', { method: 'POST', body: { payload: vault, passphrase: 'vault-pass-1234' } });
  check('vault import into second user', imp.imported?.hosts >= 2 && imp.imported?.playbooks >= 1 && imp.imported?.tunnels >= 1, JSON.stringify(imp.imported));

  const mateHosts = (await mate.api('/api/hosts')).hosts;
  const mateBehind = mateHosts.find((h) => h.name === 'exp-behind');
  const mateBastion = mateHosts.find((h) => h.name === 'exp-bastion');
  check('bastion link survives out-of-order import', mateBehind?.jump_host_id === mateBastion?.id && mateBastion?.id != null, `jump=${mateBehind?.jump_host_id} bastion=${mateBastion?.id}`);
  const mateTun = (await mate.api('/api/tunnels')).tunnels.find((t) => t.name === 'exp-tunnel');
  check('tunnel imported loopback-bound', mateTun?.bind_address === '127.0.0.1');
  const matePb = (await mate.api('/api/playbooks')).playbooks.find((p) => p.name === 'exp-playbook');
  check('playbook imported with steps', Array.isArray(matePb?.steps) && matePb.steps.length === 1);
  check('non-admin import does not widen shared', mateHosts.every((h) => h.shared === 0));

  // ---------- logout tears down live session ----------
  const l = ctx();
  await l.api('/api/auth/login', { method: 'POST', body: { username: 'secmate', password: 'matepass1234' } });
  let mateSid = null;
  await wsCollect(l.cookie, { type: 'connect', hostId: mateBastion.id, cols: 80, rows: 24 }, {
    until: (o) => o.some((m) => m.type === 'ready' || (m.type === 'status' && m.state === 'error')),
    timeoutMs: 20000,
    autoTrust: true,
    autoPassword: 'testpass123',
  }).then((msgs) => {
    mateSid = msgs.find((m) => m.type === 'ready')?.sessionId;
  });
  check('mate session connects (imported pw host)', !!mateSid);
  if (mateSid) {
    await l.api('/api/auth/logout', { method: 'POST' });
    await l.api('/api/auth/login', { method: 'POST', body: { username: 'secmate', password: 'matepass1234' } });
    const re = await wsCollect(l.cookie, { type: 'reattach', sessionId: mateSid, cols: 80, rows: 24 }, {
      until: (o) => o.some((m) => m.type === 'ready' || (m.type === 'status' && m.state === 'gone')),
      timeoutMs: 10000,
    });
    check('logout killed the live session', re.some((m) => m.type === 'status' && m.state === 'gone'));
  }

  // ---------- host delete stops live tunnel ----------
  const t2 = await admin.api('/api/tunnels', {
    method: 'POST', body: { name: 'orphan-check', host_id: testHost.id, bind_address: '127.0.0.1', local_port: 18779, remote_host: '127.0.0.1', remote_port: 2222 },
  });
  const started = await admin.api(`/api/tunnels/${t2.tunnel.id}/start`, { method: 'POST' });
  check('tunnel started for orphan test', started.tunnel?.active === true);
  const portOpen = await new Promise((res) => {
    const s = net.connect(18779, '127.0.0.1');
    s.on('connect', () => { s.destroy(); res(true); });
    s.on('error', () => res(false));
    setTimeout(() => res(false), 3000);
  });
  check('tunnel port listening', portOpen === true);
  // delete via host id — tunnels cascade; listener must stop
  await admin.api(`/api/hosts/${testHost.id}`, { method: 'DELETE' });
  const portClosed = await new Promise((res) => {
    const s = net.connect(18779, '127.0.0.1');
    s.on('connect', () => { s.destroy(); res(false); });
    s.on('error', () => res(true));
    setTimeout(() => res(true), 3000);
  });
  check('host delete stops orphaned tunnel listener', portClosed === true);

  // recreate test-sshd for future runs (the delete was real)
  const back = await admin.api('/api/hosts', {
    method: 'POST', body: { name: 'test-sshd', hostname: '127.0.0.1', port: 2222, username: 'tester', auth_type: 'password', password: 'testpass123' },
  });
  check('test-sshd restored', !!back.host?.id);

  // ---------- cleanup ----------
  for (const name of ['exp-bastion', 'exp-behind']) {
    const h = (await admin.api('/api/hosts')).hosts.find((x) => x.name === name);
    if (h) await admin.api(`/api/hosts/${h.id}`, { method: 'DELETE' });
  }
  const leftover = (await admin.api('/api/tunnels')).tunnels.find((t) => t.name === 'exp-tunnel');
  if (leftover) await admin.api(`/api/tunnels/${leftover.id}`, { method: 'DELETE' });
  const lpb = (await admin.api('/api/playbooks')).playbooks.find((p) => p.name === 'exp-playbook');
  if (lpb) await admin.api(`/api/playbooks/${lpb.id}`, { method: 'DELETE' });
  await admin.api(`/api/admin/users/${mk.user.id}`, { method: 'DELETE' });

  // ---------- summary ----------
  const failed = results.filter(([, ok]) => !ok);
  console.log(`\n${results.length - failed.length}/${results.length} passed`);
  process.exit(failed.length ? 1 : 0);
})().catch((e) => {
  console.log('E2E crashed:', e);
  process.exit(1);
});
