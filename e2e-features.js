// E2E features round: API tokens (scopes), viewer role, webhooks CRUD+test,
// playbook detached runs + schedule validation + run history, ssh-keyscan
// pre-seeding, Wake-on-LAN, telnet sessions, agent forwarding, SSH
// certificate auth, recordings search, SFTP rlist/tar, health endpoint.
// Requires: server on :8089 (admin/supersecretpw1), docker sshd on :2222.
const crypto = require('crypto');
const net = require('net');
const fs = require('fs');
const { execSync } = require('child_process');
const BASE = 'http://localhost:8089';
const WebSocket = require('./server/node_modules/ws');

function ctx() {
  let cookie = '';
  return {
    api: async (path, opts = {}) => {
      const r = await fetch(BASE + path, {
        method: opts.method || 'GET',
        headers: {
          ...(opts.body ? { 'Content-Type': 'application/json' } : {}),
          cookie,
          origin: BASE,
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
  };
}

const results = [];
const check = (name, ok, extra = '') => {
  results.push([name, ok]);
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${extra ? ' — ' + extra : ''}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ws helper that ALSO collects decoded binary output text.
function wsTerm(cookie, firstMsg, opts, path = '/ws/terminal') {
  return new Promise((resolve) => {
    const ws = new WebSocket(`ws://localhost:8089${path}`, { headers: { cookie, origin: BASE } });
    const out = { msgs: [], text: '' };
    let done = false;
    const finish = () => { if (!done) { done = true; try { ws.close(); } catch {} resolve(out); } };
    ws.on('open', () => ws.send(JSON.stringify(firstMsg)));
    ws.on('message', (d, isBinary) => {
      if (isBinary) {
        out.text += Buffer.from(d).toString('utf8');
        if (opts.until && opts.until(out)) finish();
        return;
      }
      let m;
      try { m = JSON.parse(d.toString()); } catch { return; }
      out.msgs.push(m);
      if (m.type === 'hostkey') ws.send(JSON.stringify({ type: 'trust', accept: 'always' }));
      if (m.type === 'auth_request' && opts.password) ws.send(JSON.stringify({ type: 'auth', password: opts.password }));
      if (opts.onmsg && opts.onmsg(ws, m, out)) finish();
    });
    ws.on('close', finish);
    setTimeout(finish, opts.timeoutMs || 20000);
  });
}

(async () => {
  const admin = ctx();
  await admin.api('/api/auth/login', { method: 'POST', body: { username: 'admin', password: 'supersecretpw1' } });
  const hosts = (await admin.api('/api/hosts')).hosts;
  let testHost = hosts.find((h) => h.name === 'test-sshd');
  if (!testHost) {
    testHost = (await admin.api('/api/hosts', {
      method: 'POST',
      body: { name: 'test-sshd', hostname: '127.0.0.1', port: 2222, username: 'tester', auth_type: 'password', password: 'testpass123' },
    })).host;
  } else {
    // re-encrypt the stored password under the current master key (DBs may
    // outlive the env key between test runs)
    await admin.api(`/api/hosts/${testHost.id}`, { method: 'PUT', body: { password: 'testpass123', auth_type: 'password' } });
  }

  // ================= API tokens =================
  const tok = await admin.api('/api/tokens', { method: 'POST', body: { name: 'e2e-read', scopes: ['read'], expires_days: 1 } });
  check('api token created once-shown', /^slo_/.test(tok.token) && tok.scopes.includes('read'));
  const bearer = { authorization: `Bearer ${tok.token}` };
  const r1 = await admin.api('/api/hosts', { headers: bearer });
  check('read token lists hosts', Array.isArray(r1.hosts));
  const r2 = await admin.api('/api/hosts', { method: 'POST', headers: bearer, body: { name: 'x', hostname: 'x', username: 'x', auth_type: 'ask' } });
  check('read token cannot mutate', r2._status === 403);
  const r3 = await admin.api('/api/snippets', { headers: bearer });
  check('read token lists snippets', Array.isArray(r3.snippets));
  const r4 = await admin.api('/api/hosts', { headers: { authorization: `Bearer ${tok.token}x` } });
  check('bad token rejected', r4._status === 401);

  // playbook scope
  const pbtok = await admin.api('/api/tokens', { method: 'POST', body: { name: 'e2e-run', scopes: ['playbooks:run'] } });
  const pbBearer = { authorization: `Bearer ${pbtok.token}` };
  const pr1 = await admin.api('/api/hosts', { headers: pbBearer });
  check('playbooks:run token cannot read hosts', pr1._status === 403);

  // ================= playbooks: detached run + schedule =================
  const pb = await admin.api('/api/playbooks', {
    method: 'POST',
    body: {
      name: 'e2e-detached',
      steps: [
        { command: 'echo DETACHED-$((6*7))', description: 'marker', timeout_s: 10 },
        { command: 'hostname', timeout_s: 10 },
      ],
    },
  });
  const pbId = pb.playbook.id;
  const runRes = await admin.api(`/api/playbooks/${pbId}/run`, { method: 'POST', body: { host_id: testHost.id } });
  check('detached run returns run_id', Number.isInteger(runRes.run_id), JSON.stringify(runRes));

  // playbooks:run token can trigger
  const runRes2 = await admin.api(`/api/playbooks/${pbId}/run`, { method: 'POST', headers: pbBearer, body: { host_id: testHost.id } });
  check('playbooks:run token triggers run', Number.isInteger(runRes2.run_id), JSON.stringify(runRes2));

  let run = null;
  for (let i = 0; i < 30; i++) {
    const d = await admin.api(`/api/playbooks/runs/${runRes.run_id}`);
    if (d.run && d.run.status !== 'running') { run = d.run; break; }
    await sleep(500);
  }
  check('detached run finishes ok', run && run.status === 'ok', run && run.status + ' ' + (run.output || '').slice(0, 120));
  check('run output captured', run && run.output.includes('DETACHED-42'));
  const runs = await admin.api('/api/playbooks/runs');
  check('runs listed', Array.isArray(runs.runs) && runs.runs.some((r) => r.id === runRes.run_id));

  // schedule validation + fields
  const badCron = await admin.api(`/api/playbooks/${pbId}`, { method: 'PUT', body: { schedule_cron: 'not a cron', schedule_enabled: true } });
  check('invalid cron rejected', badCron._status === 400);
  const sched = await admin.api(`/api/playbooks/${pbId}`, {
    method: 'PUT',
    body: { schedule_cron: '0 3 * * 0', schedule_host_id: testHost.id, schedule_enabled: true },
  });
  check('schedule stored + next_run_at computed', sched.playbook.schedule_enabled === 1 && sched.playbook.next_run_at > 0,
    JSON.stringify({ next: sched.playbook.next_run_at }));
  const unsched = await admin.api(`/api/playbooks/${pbId}`, { method: 'PUT', body: { schedule_enabled: false } });
  check('schedule disable clears next_run_at', unsched.playbook.next_run_at === null);

  // templates
  const tpl = await admin.api('/api/playbooks/templates');
  check('templates listed', Array.isArray(tpl.templates) && tpl.templates.length >= 6, `${tpl.templates?.length} templates`);
  const inst = await admin.api('/api/playbooks/templates/sysreport', { method: 'POST', body: {} });
  check('template install creates playbook', inst.playbook?.steps?.length > 0);

  // ================= ssh-keyscan =================
  const scan = await admin.api('/api/hosts/hostkeys/scan', {
    method: 'POST',
    body: { hosts: [{ hostname: '127.0.0.1', port: 2222 }, { hostname: '127.0.0.1', port: 9 }] },
  });
  const ok0 = scan.results?.[0];
  check('keyscan returns fingerprint', ok0?.ok && /^SHA256:/.test(ok0.fingerprint), JSON.stringify(ok0));
  check('keyscan reports dead ports', scan.results?.[1]?.ok === false);
  await sleep(3200); // per-user scan rate cap is 3s
  const scanTrust = await admin.api('/api/hosts/hostkeys/scan', {
    method: 'POST',
    body: { hosts: [{ hostname: '127.0.0.1', port: 2222 }], trust: true },
  });
  check('scan+trust pins key', scanTrust.results?.[0]?.trusted === true);
  const hk = await admin.api('/api/hosts/hostkeys');
  check('pinned key in store', hk.hostkeys.some((k) => k.hostname === '127.0.0.1' && k.port === 2222));

  // ================= Wake-on-LAN =================
  const wolHost = await admin.api('/api/hosts', {
    method: 'POST',
    body: { name: 'e2e-wol', hostname: '192.0.2.1', port: 22, username: 'x', auth_type: 'ask', mac: 'aa:bb:cc:dd:ee:ff' },
  });
  check('host with mac created', !!wolHost.host?.id, JSON.stringify(wolHost).slice(0, 120));
  const wol = await admin.api(`/api/hosts/${wolHost.host.id}/wol`, { method: 'POST' });
  check('wol magic packet sent', wol.ok === true, JSON.stringify(wol));
  const badMac = await admin.api('/api/hosts', {
    method: 'POST',
    body: { name: 'badmac', hostname: '192.0.2.2', port: 22, username: 'x', auth_type: 'ask', mac: 'not-a-mac' },
  });
  check('invalid MAC rejected', badMac._status === 400);

  // ================= webhooks (local receiver) =================
  const got = [];
  const recv = net.createServer((s) => {
    s.on('data', () => { got.push(true); s.end('HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'); });
  });
  await new Promise((r) => recv.listen(18923, '127.0.0.1', r));
  const wh = await admin.api('/api/webhooks', {
    method: 'POST',
    body: { url: 'http://127.0.0.1:18923/hook', events: 'test,host.down' },
  });
  check('webhook created', !!wh.webhook?.id);
  const whTest = await admin.api(`/api/webhooks/${wh.webhook.id}/test`, { method: 'POST' });
  check('webhook test delivered', whTest.ok === true && got.length > 0);
  const whList = await admin.api('/api/webhooks');
  check('webhook listed', whList.webhooks.length > 0);
  const badWh = await admin.api('/api/webhooks', { method: 'POST', body: { url: 'javascript:alert(1)' } });
  check('non-http webhook rejected', badWh._status === 400);
  recv.close();

  // ================= telnet =================
  // Fake "telnet" peer: banner + echo.
  const tnl = net.createServer((s) => {
    s.write('FakeSwitch login: ');
    s.on('data', (d) => s.write(`\r\necho:${d.toString().trim()}\r\n> `));
  });
  await new Promise((r) => tnl.listen(12323, '127.0.0.1', r));
  const telHost = await admin.api('/api/hosts', {
    method: 'POST',
    body: { name: 'e2e-telnet', hostname: '127.0.0.1', port: 12323, username: 'admin', auth_type: 'ask', protocol: 'telnet' },
  });
  check('telnet host created', !!telHost.host?.id && telHost.host.protocol === 'telnet');
  const t = await wsTerm(admin.cookie, { type: 'connect', hostId: telHost.host.id, cols: 80, rows: 24 }, {
    timeoutMs: 8000,
    until: (o) => o.text.includes('FakeSwitch login'),
  }, '/ws/telnet');
  check('telnet session gets banner', t.text.includes('FakeSwitch login'), t.text.slice(0, 60));
  // wrong-protocol guard
  const tw = await wsTerm(admin.cookie, { type: 'connect', hostId: testHost.id, cols: 80, rows: 24 }, { timeoutMs: 5000 }, '/ws/telnet');
  check('telnet ws refuses ssh host', tw.msgs.some((m) => m.state === 'error'));
  tnl.close();

  // ================= key auth + agent forwarding =================
  // generate a keypair via ssh2 (returns OpenSSH-format .public/.private),
  // install pubkey into the container, save credential
  const ssh2 = require('./server/node_modules/ssh2');
  const kp = ssh2.utils.generateKeyPairSync('ed25519');
  const pubLine = `${kp.public.toString().trim()} e2e-agent`;
  const privPem = kp.private.toString();
  execSync(`docker exec ssloth-test-sshd sh -c "mkdir -p /config/.ssh && echo '${pubLine}' >> /config/.ssh/authorized_keys && chmod 700 /config/.ssh && chmod 600 /config/.ssh/authorized_keys && chown -R tester:users /config/.ssh"`);

  const cred = await admin.api('/api/credentials', {
    method: 'POST',
    body: { name: 'e2e-key', type: 'key', privateKey: privPem },
  });
  check('key credential created', !!cred.credential?.id && /^ssh-ed25519/.test(cred.public_key || ''));

  const fwdHost = await admin.api('/api/hosts', {
    method: 'POST',
    body: { name: 'e2e-fwd', hostname: '127.0.0.1', port: 2222, username: 'tester', auth_type: 'credential', credential_id: cred.credential.id, agent_forward: true },
  });
  check('agent_forward host created', fwdHost.host?.agent_forward === 1);

  const fwd = await wsTerm(admin.cookie, { type: 'connect', hostId: fwdHost.host.id, cols: 80, rows: 24 }, {
    timeoutMs: 25000,
    onmsg: (ws, m) => {
      if (m.type === 'ready') {
        ws.send(require('buffer').Buffer.from('test -S "$SSH_AUTH_SOCK" && echo AGENT-FWD-OK || echo NO-SOCK\n'));
      }
      return false;
    },
    until: (o) => o.text.includes('AGENT-FWD-OK') || o.text.includes('NO-SOCK'),
  });
  check('key auth connected', fwd.msgs.some((m) => m.type === 'ready'), fwd.msgs.map((m) => m.type + ':' + (m.message || '')).join(','));
  check('SSH_AUTH_SOCK forwarded', fwd.text.includes('AGENT-FWD-OK'), fwd.text.slice(-200));

  // ================= SSH certificate auth =================
  try {
    execSync('docker exec ssloth-test-sshd sh -c "command -v ssh-keygen"');
    const ca = ssh2.utils.generateKeyPairSync('ed25519');
    const caLine = `${ca.public.toString().trim()} e2e-ca`;
    // sign the user pubkey with ssh-keygen inside the container
    fs.writeFileSync('/tmp/e2e-user.pub', pubLine);
    execSync(`docker cp /tmp/e2e-user.pub ssloth-test-sshd:/tmp/e2e-user.pub`);
    fs.writeFileSync('/tmp/e2e-ca.pem', ca.private.toString());
    execSync(`docker cp /tmp/e2e-ca.pem ssloth-test-sshd:/tmp/e2e-ca.pem && docker exec ssloth-test-sshd chmod 600 /tmp/e2e-ca.pem`);
    execSync(`docker exec ssloth-test-sshd ssh-keygen -s /tmp/e2e-ca.pem -I e2e -n tester -V +1h /tmp/e2e-user.pub`);
    const certLine = execSync(`docker exec ssloth-test-sshd cat /tmp/e2e-user-cert.pub`).toString().trim();
    // trust the CA
    execSync(`docker exec ssloth-test-sshd sh -c "echo '${caLine}' > /config/ca.pub && echo 'TrustedUserCAKeys /config/ca.pub' >> /config/sshd/sshd_config"`);
    execSync('docker restart ssloth-test-sshd'); // reload sshd so TrustedUserCAKeys takes effect
    await sleep(3000);

    const certCred = await admin.api('/api/credentials', {
      method: 'POST',
      body: { name: 'e2e-cert', type: 'key', privateKey: privPem, certificate: certLine },
    });
    check('cert credential accepted', !!certCred.credential?.id, JSON.stringify(certCred).slice(0, 120));
    const certHost = await admin.api('/api/hosts', {
      method: 'POST',
      body: { name: 'e2e-cert-host', hostname: '127.0.0.1', port: 2222, username: 'tester', auth_type: 'credential', credential_id: certCred.credential.id },
    });
    const cc = await wsTerm(admin.cookie, { type: 'connect', hostId: certHost.host.id, cols: 80, rows: 24 }, { timeoutMs: 25000 });
    check('certificate auth connects', cc.msgs.some((m) => m.type === 'ready'), cc.msgs.map((m) => m.type + ':' + (m.message || '')).join(','));
  } catch (e) {
    check('certificate auth connects', false, 'setup failed: ' + e.message.slice(0, 120));
  }

  // ================= recordings: search =================
  const recHost = await admin.api('/api/hosts', {
    method: 'POST',
    body: { name: 'e2e-rec', hostname: '127.0.0.1', port: 2222, username: 'tester', auth_type: 'password', password: 'testpass123', record: true },
  });
  const rs = await wsTerm(admin.cookie, { type: 'connect', hostId: recHost.host.id, cols: 80, rows: 24 }, {
    timeoutMs: 20000,
    password: 'testpass123',
    onmsg: (ws, m, o) => {
      if (m.type === 'ready') ws.send(Buffer.from('echo REC-MARKER-99\n'));
      if (o.text.includes('REC-MARKER-99')) { ws.send(JSON.stringify({ type: 'close' })); return true; }
      return false;
    },
    until: (o) => o.text.includes('REC-MARKER-99'),
  });
  await sleep(1200); // let the recorder finalize
  const srh = await admin.api('/api/recordings/search?q=REC-MARKER-99');
  check('recording search finds marker', Array.isArray(srh.results) && srh.results.length > 0, JSON.stringify(srh.results?.length));
  const srhMiss = await admin.api('/api/recordings/search?q=NEVERPRESENT');
  check('search miss returns empty', Array.isArray(srhMiss.results) && srhMiss.results.length === 0);

  // ================= SFTP rlist + tar =================
  // reuse a live session: open one
  let sid = null;
  await wsTerm(admin.cookie, { type: 'connect', hostId: testHost.id, cols: 80, rows: 24 }, {
    timeoutMs: 20000,
    password: 'testpass123',
    onmsg: (ws, m) => { if (m.type === 'ready') { sid = m.sessionId; return true; } return false; },
  });
  if (sid) {
    const rl = await admin.api(`/api/sftp/${sid}/rlist?path=/config`);
    check('rlist returns files', Array.isArray(rl.files) && rl.files.length > 0, `${rl.files?.length} files`);
    const tarRes = await fetch(`${BASE}/api/sftp/${sid}/tar?path=/config/sshd`, { headers: { cookie: admin.cookie, origin: BASE } });
    const tarBuf = Buffer.from(await tarRes.arrayBuffer());
    check('tar download is gzip', tarRes.status === 200 && tarBuf[0] === 0x1f && tarBuf[1] === 0x8b, `status ${tarRes.status} size ${tarBuf.length}`);
  } else {
    check('rlist returns files', false, 'no session');
    check('tar download is gzip', false, 'no session');
  }

  // ================= health =================
  const hl = await admin.api(`/api/hosts/${testHost.id}/health`);
  check('health endpoint responds', Array.isArray(hl.history) && 'current' in hl);

  // ================= viewer role =================
  const uname = `viewer_${Date.now().toString(36)}`;
  await admin.api('/api/admin/users', { method: 'POST', body: { username: uname, password: 'viewerpass123', role: 'viewer' } });
  const vw = ctx();
  await vw.api('/api/auth/login', { method: 'POST', body: { username: uname, password: 'viewerpass123' } });
  const vwState = await vw.api('/api/auth/state');
  check('viewer role in state', vwState.user?.role === 'viewer', JSON.stringify(vwState.user));
  const vwGet = await vw.api('/api/hosts');
  check('viewer can list hosts', Array.isArray(vwGet.hosts));
  const vwPost = await vw.api('/api/hosts', { method: 'POST', body: { name: 'x', hostname: 'x', username: 'x', auth_type: 'ask' } });
  check('viewer mutation blocked', vwPost._status === 403);
  const vwSnippet = await vw.api('/api/snippets', { method: 'POST', body: { name: 'x', command: 'x' } });
  check('viewer snippet create blocked', vwSnippet._status === 403);
  const vwCred = await vw.api('/api/credentials', { method: 'POST', body: { name: 'x', type: 'password', password: 'y' } });
  check('viewer credential create blocked', vwCred._status === 403);
  const vwWh = await vw.api('/api/webhooks', { method: 'POST', body: { url: 'http://127.0.0.1:1/x' } });
  check('viewer webhook create blocked', vwWh._status === 403);
  const vwToken = await vw.api('/api/tokens', { method: 'POST', body: { name: 'x', scopes: ['read'] } });
  check('viewer token create blocked', vwToken._status === 403);
  const vwRuns = await vw.api('/api/playbooks/runs');
  check('viewer can read runs', Array.isArray(vwRuns.runs));

  // cleanup viewer
  const users = await admin.api('/api/admin/users');
  const vu = users.users.find((u) => u.username === uname);
  if (vu) await admin.api(`/api/admin/users/${vu.id}`, { method: 'DELETE' });

  // role change route
  const u2 = `roleuser_${Date.now().toString(36)}`;
  const nu = await admin.api('/api/admin/users', { method: 'POST', body: { username: u2, password: 'userpass1234', role: 'user' } });
  const roleCh = await admin.api(`/api/admin/users/${nu.user.id}/role`, { method: 'POST', body: { role: 'viewer' } });
  check('role change works', roleCh.ok === true);
  await admin.api(`/api/admin/users/${nu.user.id}`, { method: 'DELETE' });

  const passed = results.filter(([, ok]) => ok).length;
  console.log(`\n${passed}/${results.length} checks passed`);
  process.exit(results.every(([, ok]) => ok) ? 0 : 1);
})().catch((e) => {
  console.error('fatal', e);
  process.exit(1);
});
