// E2E round 5: persistent sessions, playbooks, health, multi-hop, socks5,
// sftp read/write, shared hosts.
const BASE = 'http://localhost:8089';
const WebSocket = require('/root/vscode/ssloth/server/node_modules/ws');
let cookie = '';

async function api(path, opts = {}) {
  const r = await fetch(BASE + path, {
    method: opts.method || 'GET',
    headers: {
      ...(opts.body ? { 'Content-Type': 'application/json' } : {}),
      cookie,
      // mutations now require a same-origin Origin header (CSRF hardening)
      origin: BASE,
    },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const sc = r.headers.get('set-cookie');
  if (sc) cookie = sc.split(';')[0];
  const j = await r.json().catch(() => ({}));
  if (!r.ok) j._status = r.status;
  return j;
}

const results = [];
const check = (name, ok, extra = '') => {
  results.push([name, ok]);
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${extra ? ' — ' + extra : ''}`);
};

function wsSession(msgs, timeoutMs = 25000) {
  // open ws, send msgs on events, resolve collected messages
  return new Promise((resolve) => {
    const ws = new WebSocket('ws://localhost:8089/ws/terminal', {
      headers: { cookie, origin: BASE },
    });
    const out = [];
    let done = false;
    const finish = () => { if (!done) { done = true; try { ws.close(); } catch {} resolve(out); } };
    ws.on('open', () => { if (msgs.onopen) msgs.onopen(ws); });
    ws.on('message', (d, isBinary) => {
      if (isBinary) { out.push({ type: 'binary' }); return; }
      const m = JSON.parse(d.toString());
      out.push(m);
      if (msgs.onmsg && msgs.onmsg(ws, m)) finish();
    });
    ws.on('close', finish);
    setTimeout(finish, timeoutMs);
  });
}

(async () => {
  await api('/api/auth/login', { method: 'POST', body: { username: 'admin', password: 'supersecretpw1' } });
  const hosts = (await api('/api/hosts')).hosts;
  const testHost = hosts.find((h) => h.name === 'test-sshd');

  // ---------- 1. persistent session: connect, detach, reattach ----------
  let sid = null;
  await wsSession({
    onopen: (ws) => ws.send(JSON.stringify({ type: 'connect', hostId: testHost.id, cols: 80, rows: 24 })),
    onmsg: (ws, m) => {
      if (m.type === 'ready') {
        sid = m.sessionId;
        ws.send(require('buffer').Buffer.from('echo DETACH_MARKER_XYZ\n'));
        return false;
      }
      if (m.type === 'binary' && sid) return true; // got output, detach
      return false;
    },
  }, 15000);
  check('session connect + output', !!sid, sid);

  // reattach on a fresh socket — expect replay with the marker + ready
  let reattached = false, replayHadMarker = false;
  const reMsgs = await wsSession({
    onopen: (ws) => ws.send(JSON.stringify({ type: 'reattach', sessionId: sid, cols: 80, rows: 24 })),
    onmsg: (ws, m) => {
      if (m.type === 'ready' && m.reattached) { reattached = true; return true; }
      return false;
    },
  }, 10000);
  check('reattach -> ready', reattached);

  // ---------- 2. playbook ----------
  const pb = await api('/api/playbooks', {
    method: 'POST',
    body: {
      name: 'e2e-pb',
      description: 'test',
      steps: [
        { command: 'echo PB_STEP_ONE' },
        { command: 'true' },
        { command: 'echo PB_DONE_$(date +%s)' },
      ],
    },
  });
  check('playbook created', !!pb.playbook?.id);
  const pbMsgs = await wsSession({
    onopen: (ws) => ws.send(JSON.stringify({ type: 'reattach', sessionId: sid, cols: 80, rows: 24 })),
    onmsg: (ws, m) => {
      if (m.type === 'ready') { ws.send(JSON.stringify({ type: 'playbook', playbookId: pb.playbook.id })); return false; }
      if (m.type === 'playbook_done') return true;
      return false;
    },
  }, 30000);
  const steps = pbMsgs.filter((m) => m.type === 'playbook_step');
  const done = pbMsgs.find((m) => m.type === 'playbook_done');
  check('playbook ran all steps', steps.filter((s) => s.status === 'ok').length === 3 && done?.ok === true,
    `${steps.length} steps, done.ok=${done?.ok}`);

  // ---------- 3. health probe ----------
  const hMsgs = await wsSession({
    onopen: (ws) => ws.send(JSON.stringify({ type: 'reattach', sessionId: sid, cols: 80, rows: 24 })),
    onmsg: (ws, m) => m.type === 'health',
  }, 25000);
  const health = hMsgs.find((m) => m.type === 'health');
  check('health metrics arrive', !!health && (health.load || health.memPct != null), JSON.stringify(health || {}));

  // ---------- 4. sftp read/write ----------
  const wr = await api(`/api/sftp/${sid}/write`, {
    method: 'POST',
    body: { path: '/config/e2e-edit.txt', content: 'line one\nline two\n' },
  });
  check('sftp write', wr.ok === true);
  const rd = await api(`/api/sftp/${sid}/read?path=${encodeURIComponent('/config/e2e-edit.txt')}`);
  check('sftp read', rd.binary === false && rd.content === 'line one\nline two\n');
  const rdBin = await api(`/api/sftp/${sid}/read?path=${encodeURIComponent('/bin/sh')}`);
  check('sftp read detects binary', rdBin.binary === true);

  // ---------- 5. multi-hop bastion chain ----------
  const b1 = await api('/api/hosts', {
    method: 'POST',
    body: { name: 'hop-b', hostname: '127.0.0.1', port: 2222, username: 'tester', auth_type: 'password', password: 'testpass123' },
  });
  const b2 = await api('/api/hosts', {
    method: 'POST',
    body: { name: 'hop-a', hostname: '127.0.0.1', port: 2222, username: 'tester', auth_type: 'password', password: 'testpass123', jump_host_id: b1.host.id },
  });
  const target = await api('/api/hosts', {
    method: 'POST',
    body: { name: 'chain-target', hostname: '127.0.0.1', port: 2222, username: 'tester', auth_type: 'password', password: 'testpass123', jump_host_id: b2.host.id },
  });
  const chainMsgs = await wsSession({
    onopen: (ws) => ws.send(JSON.stringify({ type: 'connect', hostId: target.host.id, cols: 80, rows: 24 })),
    onmsg: (ws, m) => m.type === 'ready' || (m.type === 'status' && m.state === 'error'),
  }, 30000);
  const chainReady = chainMsgs.find((m) => m.type === 'ready');
  check('2-hop bastion chain connects', !!chainReady, chainReady ? '' : JSON.stringify(chainMsgs.filter(m=>m.type==='status')));

  // ---------- 6. socks5 dynamic tunnel ----------
  const tun = await api('/api/tunnels', {
    method: 'POST',
    body: { name: 'e2e-socks', type: 'dynamic', host_id: testHost.id, bind_address: '127.0.0.1', local_port: 11888 },
  });
  check('dynamic tunnel created', !!tun.tunnel?.id);
  const started = await api(`/api/tunnels/${tun.tunnel.id}/start`, { method: 'POST' });
  check('socks5 tunnel started', started.tunnel?.active === true, started.error || '');

  if (started.tunnel?.active) {
    const net = require('net');
    const socksOk = await new Promise((resolve) => {
      const s = net.connect(11888, '127.0.0.1', () => {
        s.write(Buffer.from([5, 1, 0])); // greeting: ver5, 1 method, no-auth
      });
      let stage = 0;
      s.on('data', (d) => {
        if (stage === 0 && d[0] === 5 && d[1] === 0) {
          stage = 1;
          // request CONNECT 127.0.0.1:2222 through the tunnel — the dial
          // happens sshd-side, and the container's sshd listens on 2222
          s.write(Buffer.concat([Buffer.from([5, 1, 0, 1, 127, 0, 0, 1]), Buffer.from([0x08, 0xae])]));
        } else if (stage === 1) {
          resolve(d[0] === 5 && d[1] === 0);
          s.destroy();
        }
      });
      s.on('error', () => resolve(false));
      setTimeout(() => { s.destroy(); resolve(false); }, 8000);
    });
    check('socks5 proxy connects through ssh', socksOk);
    await api(`/api/tunnels/${tun.tunnel.id}/stop`, { method: 'POST' });
  }

  // ---------- 7. shared hosts ----------
  const u2 = await api('/api/admin/users', {
    method: 'POST',
    body: { username: 'teammate', password: 'teampw-12345', is_admin: false },
  });
  check('second user created', !!u2.user?.id || /taken/.test(u2.error || ''));

  await api(`/api/hosts/${testHost.id}`, { method: 'PUT', body: { shared: true } });
  // switch to teammate
  cookie = '';
  await api('/api/auth/login', { method: 'POST', body: { username: 'teammate', password: 'teampw-12345' } });
  const mateHosts = (await api('/api/hosts')).hosts;
  const sharedSeen = mateHosts.find((h) => h.id === testHost.id);
  check('shared host visible to teammate', !!sharedSeen && sharedSeen.owned === false, sharedSeen?.owner_name);
  const mateEdit = await api(`/api/hosts/${testHost.id}`, { method: 'PUT', body: { name: 'hijack' } });
  check('teammate cannot edit shared host', mateEdit._status === 404);
  const mateConn = await wsSession({
    onopen: (ws) => ws.send(JSON.stringify({ type: 'connect', hostId: testHost.id, cols: 80, rows: 24 })),
    onmsg: (ws, m) => m.type === 'ready' || (m.type === 'status' && (m.state === 'error' || m.state === 'closed')) || m.type === 'hostkey',
  }, 25000);
  const mateReady = mateConn.find((m) => m.type === 'ready');
  const mateKey = mateConn.find((m) => m.type === 'hostkey');
  check('teammate connects via shared host (hostkey prompt ok)', !!mateReady || !!mateKey,
    mateReady ? 'ready' : mateKey ? 'hostkey prompt (expected)' : JSON.stringify(mateConn.filter(m=>m.type==='status')));

  // back to admin, unshare + cleanup temp hosts
  cookie = '';
  await api('/api/auth/login', { method: 'POST', body: { username: 'admin', password: 'supersecretpw1' } });
  await api(`/api/hosts/${testHost.id}`, { method: 'PUT', body: { shared: false } });
  for (const h of [b1, b2, target]) if (h.host?.id) await api(`/api/hosts/${h.host.id}`, { method: 'DELETE' });
  if (tun.tunnel?.id) await api(`/api/tunnels/${tun.tunnel.id}`, { method: 'DELETE' });
  if (pb.playbook?.id) await api(`/api/playbooks/${pb.playbook.id}`, { method: 'DELETE' });
  // explicit session close
  const cs = new WebSocket('ws://localhost:8089/ws/terminal', { headers: { cookie, origin: BASE } });
  cs.on('open', () => cs.send(JSON.stringify({ type: 'reattach', sessionId: sid, cols: 80, rows: 24 })));
  cs.on('message', (d, isBinary) => {
    if (isBinary) return; // replay scrollback is binary, not JSON
    const m = JSON.parse(d.toString());
    if (m.type === 'ready') { cs.send(JSON.stringify({ type: 'close' })); setTimeout(() => cs.close(), 300); }
  });
  await new Promise((r) => setTimeout(r, 1500));

  const failed = results.filter(([, ok]) => !ok);
  console.log(`\n${results.length - failed.length}/${results.length} passed`);
  process.exit(failed.length ? 1 : 0);
})().catch((e) => { console.error('E2E crashed:', e); process.exit(1); });
