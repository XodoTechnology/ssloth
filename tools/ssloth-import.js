#!/usr/bin/env node
'use strict';

// ssloth-import — converts host/session exports from other SSH clients into
// a ssloth vault file you import via Settings -> Vault -> Import.
// Standalone: zero deps, never touches the running app or its database.
//
//   node tools/ssloth-import.js --mremoteng confCons.xml -o ssloth-import.json
//   node tools/ssloth-import.js --putty-export putty.reg
//   node tools/ssloth-import.js --putty-live                    (Windows)
//   node tools/ssloth-import.js --openssh ~/.ssh/config
//   node tools/ssloth-import.js --securecrt "Sessions dir"
//   node tools/ssloth-import.js --winscp WinSCP.ini
//   node tools/ssloth-import.js --csv hosts.csv | --json hosts.json
//
// Options:
//   -o FILE            output vault JSON (default: stdout)
//   --seal             prompt for a passphrase and encrypt recovered secrets
//   --mremoteng-password P  custom mRemoteNG encryption password
//                        (default tries the built-in "mR3m")
//   --dry-run          print a summary, write nothing

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { execFileSync } = require('child_process');
const readline = require('readline');

const args = process.argv.slice(2);
const opt = {};
const positional = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === '-o') opt.out = args[++i];
  else if (args[i] === '--mremoteng-password') opt.mrngPass = args[++i];
  else if (args[i] === '--seal-passphrase') opt.sealPassphrase = args[++i];
  else if (args[i].startsWith('--')) opt[args[i].slice(2).replace(/-(.)/g, (_, c) => c.toUpperCase())] = true;
  else positional.push(args[i]);
}
const SRCS = ['puttyLive', 'puttyExport', 'mremoteng', 'openssh', 'securecrt', 'winscp', 'csv', 'json'];
const src = SRCS.find((s) => opt[s]);
if (!src) {
  console.error('usage: ssloth-import <source flag> [file] [-o out.json] [--seal] [--dry-run]');
  console.error('  sources: --putty-live --putty-export FILE --mremoteng FILE --openssh [FILE]');
  console.error('           --securecrt DIR --winscp FILE --csv FILE --json FILE');
  process.exit(2);
}

// ---------------------------------------------------------------------------
// vault builder
// ---------------------------------------------------------------------------

const vault = {
  ssloth_export: {
    version: 2,
    exported_at: new Date().toISOString(),
    user: 'ssloth-import',
    hosts: [],
    credentials: [],
    sealed: null,
  },
};
const secrets = {}; // ref -> plaintext password string | {privateKey, passphrase}
const seenNames = new Set();
const seenCredNames = new Set();
const warnings = [];
let skipped = 0;

function uniqName(base) {
  const n = String(base || 'host').trim() || 'host';
  if (!seenNames.has(n)) { seenNames.add(n); return n; }
  for (let i = 2; ; i++) {
    const c = `${n} (${i})`;
    if (!seenNames.has(c)) { seenNames.add(c); return c; }
  }
}

// addHost({name, hostname, port, username, auth_type, folder, jump_host_name,
//          password, credential_name, notes, tags})
function addHost(h) {
  if (!h.hostname) { skipped++; return; }
  const entry = {
    name: uniqName(h.name || h.hostname),
    hostname: String(h.hostname).trim(),
    port: Math.min(Math.max(parseInt(h.port, 10) || 22, 1), 65535),
    username: String(h.username || '').slice(0, 64),
    auth_type: 'ask',
    folder: String(h.folder || '').slice(0, 128),
    region: '', tags: String(h.tags || ''),
    pinned: 0, record: 0, shared: 0, color: '',
    notes: String(h.notes || '').slice(0, 4000),
    keepalive: 15,
    credential_name: h.credential_name || null,
    jump_host_name: h.jump_host_name || null,
    password_ref: null,
  };
  if (h.password) {
    const ref = `imp${vault.ssloth_export.hosts.length}`;
    secrets[ref] = String(h.password);
    entry.password_ref = ref;
    entry.auth_type = 'password';
  } else if (h.credential_name) {
    entry.auth_type = 'credential';
  }
  vault.ssloth_export.hosts.push(entry);
}

function addCredential(name, type, username, secret, comment) {
  let n = String(name).trim() || `${type}-imported`;
  if (seenCredNames.has(n)) {
    for (let i = 2; seenCredNames.has(`${n} (${i})`); i++) n = `${name} (${i + 1})`;
  }
  seenCredNames.add(n);
  const ref = `ic${vault.ssloth_export.credentials.length}`;
  secrets[ref] = secret;
  vault.ssloth_export.credentials.push({
    name: n, type, username: username || null, comment: comment || null,
    public_key: null, secret_ref: ref,
  });
  return n;
}

const note = (w) => warnings.push(w);

// ---------------------------------------------------------------------------
// source: PuTTY — exported .reg file or live registry
// ---------------------------------------------------------------------------

function decodePuttyName(raw) {
  try { return decodeURIComponent(raw); } catch { return raw; }
}

function parsePuttyEntries(text) {
  // accepts both `regedit /e` export and `reg query /s` output — we normalize
  // both into [{ name, values: {k: v} }]
  const entries = [];
  let cur = null;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    const m = line.match(/Sessions\\(.+?)\]?$/i) || line.match(/^\\?\[(.+Sessions\\[^\]]+)\]$/i);
    if (/^\[|^HKEY/i.test(line) && /Sessions\\/i.test(line)) {
      const name = line.match(/Sessions\\([^\]"]+)/i)[1].replace(/\\+$/, '');
      cur = { name, values: {} };
      entries.push(cur);
      continue;
    }
    if (/^\[|^HKEY/i.test(line)) { cur = null; continue; }
    if (!cur || !line) continue;

    // .reg form: "HostName"="10.0.0.5"  or  "PortNumber"=dword:00000016
    let mv = line.match(/^"([^"]+)"=(.+)$/);
    if (mv) {
      let v = mv[2];
      if (v.startsWith('"')) v = v.slice(1, -1).replace(/\\(.)/g, '$1');
      else if (v.startsWith('dword:')) v = String(parseInt(v.slice(6), 16));
      else if (v.startsWith('hex')) { /* skip binary blobs */ continue; }
      cur.values[mv[1]] = v;
      continue;
    }
    // reg query form:    HostName    REG_SZ    10.0.0.5
    mv = line.match(/^(\w+)\s+REG_\w+\s+(.*)$/);
    if (mv) cur.values[mv[1]] = mv[2].trim();
  }
  return entries;
}

function importPutty(text) {
  for (const e of parsePuttyEntries(text)) {
    const v = e.values;
    const proto = (v.Protocol || 'ssh').toLowerCase();
    if (proto !== 'ssh') {
      skipped++;
      note(`PuTTY: skipped '${e.name}' — protocol '${proto}' isn't SSH`);
      continue;
    }
    const decoded = decodePuttyName(e.name);
    const slash = decoded.lastIndexOf('/');
    const notes = [];
    if (v.PublicKeyFile) notes.push(`PuTTY key file: ${v.PublicKeyFile} (convert to OpenSSH: puttygen x.ppk -O private-openssh -o key)`);
    if (parseInt(v.ProxyMethod, 10) > 0 && v.ProxyHost) notes.push(`PuTTY proxy: method ${v.ProxyMethod} host ${v.ProxyHost} — recreate as a tunnel/jump host if needed`);
    addHost({
      name: slash >= 0 ? decoded.slice(slash + 1) : decoded,
      folder: slash >= 0 ? decoded.slice(0, slash) : '',
      hostname: v.HostName,
      port: v.PortNumber,
      username: v.UserName,
      notes: notes.join('\n'),
    });
  }
}

// ---------------------------------------------------------------------------
// source: mRemoteNG — confCons.xml
// ---------------------------------------------------------------------------

function mrngDecrypt(b64, pass) {
  // LegacyRijndaelCryptographyProvider: AES-128-CBC, IV = first block,
  // key = SHA1(utf8(password))[0..16]. Returns null on failure.
  try {
    const raw = Buffer.from(b64, 'base64');
    if (raw.length < 32) return null;
    const key = crypto.createHash('sha1').update(pass, 'utf8').digest().subarray(0, 16);
    const d = crypto.createDecipheriv('aes-128-cbc', key, raw.subarray(0, 16));
    d.setAutoPadding(true);
    const pt = Buffer.concat([d.update(raw.subarray(16)), d.final()]).toString('utf8');
    // decrypted garbage usually isn't printable — sanity-check it
    return /^[\x09\x0a\x0d\x20-\x7e -￿]*$/.test(pt) ? pt : null;
  } catch { return null; }
}

function importMremoteng(file) {
  const xml = fs.readFileSync(file, 'utf8');
  if (/FullFileEncryption="true"/i.test(xml)) {
    throw new Error('confCons.xml is fully encrypted — export without full-file encryption, or decrypt it in mRemoteNG first');
  }
  const gcm = /BlockCipherMode="GCM"/i.test(xml);
  if (gcm) note('mRemoteNG: AES-GCM + Argon2 crypto — stored passwords marked for re-entry');
  const enginePass = opt.mrngPass || 'mR3m';

  const tagRe = /<(\/?)Node\b([^>]*?)(\/?)>/gs;
  const attrRe = /(\w+)="([^"]*)"/g;
  const stack = [];
  let m;
  while ((m = tagRe.exec(xml))) {
    const [, close, attrBody, selfClose] = m;
    if (close === '/') { stack.pop(); continue; }
    const attrs = {};
    let am;
    while ((am = attrRe.exec(attrBody))) {
      attrs[am[1]] = am[2].replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&apos;/g, "'");
    }
    if (attrs.Type === 'Container') {
      if (selfClose === '/') stack.push(attrs.Name), stack.pop(); // empty container
      else stack.push(attrs.Name);
      continue;
    }
    if (attrs.Type === 'Connection') {
      if (!/^(SSH[12])$/i.test(attrs.Protocol || 'SSH2')) {
        skipped++;
        note(`mRemoteNG: skipped '${attrs.Name}' — protocol '${attrs.Protocol}' isn't SSH`);
        continue;
      }
      let password = null;
      if (attrs.Password && !gcm) {
        password = mrngDecrypt(attrs.Password, enginePass);
        if (password === null) note(`mRemoteNG: '${attrs.Name}' — password didn't decrypt; set it on first connect`);
      } else if (attrs.Password) {
        note(`mRemoteNG: '${attrs.Name}' has a stored (GCM) password — re-enter it in ssloth`);
      }
      addHost({
        name: attrs.Name,
        folder: stack.join('/'),
        hostname: attrs.Hostname,
        port: attrs.Port,
        username: attrs.Username,
        password,
        notes: attrs.Descr || '',
      });
    }
  }
}

// ---------------------------------------------------------------------------
// source: OpenSSH config — ProxyJump chains become bastion links, IdentityFile
// keys become 'key' credentials (file contents embedded).
// ---------------------------------------------------------------------------

function importOpenssh(file) {
  const cfg = fs.readFileSync(file, 'utf8');
  const stanzas = [];
  let cur = null;
  for (const raw of cfg.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const m = line.match(/^(\S+)\s+(.*)$/);
    if (!m) continue;
    const k = m[1].toLowerCase(), v = m[2];
    if (k === 'host') {
      cur = { patterns: v.split(/\s+/), opts: {} };
      stanzas.push(cur);
    } else if (cur) {
      (cur.opts[k] = cur.opts[k] || []).push(v);
    }
  }
  const createdJumps = new Map(); // jumpName -> host entry name
  for (const s of stanzas) {
    const name = s.patterns.find((p) => !/[*?]/.test(p));
    if (!name) continue;
    const o = s.opts;
    const hostname = o.hostname?.[0] || name;
    const port = o.port?.[0] || 22;
    const username = o.user?.[0] || '';
    const notes = [];
    let credential_name = null;

    if (o.identityfile?.length) {
      const keyPath = o.identityfile[0].replace(/^~/, os.homedir());
      try {
        const pem = fs.readFileSync(keyPath, 'utf8');
        const encrypted = /ENCRYPTED/.test(pem);
        if (encrypted) notes.push(`key ${keyPath} is passphrase-protected — set the passphrase on credential '${name}-key'`);
        credential_name = addCredential(`${name}-key`, 'key', username || null,
          { privateKey: pem, passphrase: null }, `imported from ${keyPath}`);
      } catch {
        notes.push(`key file ${keyPath} unreadable — attach the key manually`);
      }
    }

    let jump_host_name = null;
    if (o.proxyjump?.length) {
      const hops = o.proxyjump[0].split(',').map((h) => h.trim()).filter(Boolean);
      // hops run client->out: ProxyJump a,b means dial a first, then b.
      let parent = null;
      hops.forEach((hop, i) => {
        const hm = hop.match(/^(?:([^@]+)@)?([^:]+)(?::(\d+))?$/);
        const jname = `jump-${hm?.[2] || hop}-${i}`;
        if (!createdJumps.has(jname) && !seenNames.has(hm?.[2])) {
          const jh = {
            name: hm?.[2] || jname,
            hostname: hm?.[2] || hop,
            port: hm?.[3] || 22,
            username: hm?.[1] || username,
            jump_host_name: parent,
          };
          addHost(jh);
          createdJumps.set(jname, jh.name);
        }
        parent = createdJumps.get(jname) || hm?.[2] || jname;
      });
      jump_host_name = parent;
      notes.push(`imported ProxyJump chain: ${o.proxyjump[0]}`);
    }
    if (o.proxycommand) notes.push(`ProxyCommand not migrated: ${o.proxycommand[0]}`);

    addHost({ name, hostname, port, username, credential_name, jump_host_name, notes: notes.join('\n') });
  }
}

// ---------------------------------------------------------------------------
// source: SecureCRT — a folder of .ini session files (subdirs -> folders)
// ---------------------------------------------------------------------------

function importSecurecrt(dir) {
  const walk = (d, rel) => {
    for (const f of fs.readdirSync(d, { withFileTypes: true })) {
      if (f.isDirectory()) { walk(path.join(d, f.name), rel ? `${rel}/${f.name}` : f.name); continue; }
      if (!/\.ini$/i.test(f.name)) continue;
      const ini = fs.readFileSync(path.join(d, f.name), 'utf8');
      const get = (k) => ini.match(new RegExp(`^S:"${k}"=(.*)$`, 'm'))?.[1]?.trim();
      const proto = get('Protocol Name') || 'SSH2';
      if (!/^SSH[12]$/i.test(proto)) { skipped++; note(`SecureCRT: skipped '${f.name}' — ${proto}`); continue; }
      const portHex = ini.match(/^D:"\[SSH2\] Port"=([0-9a-f]+)/im)?.[1];
      addHost({
        name: f.name.replace(/\.ini$/i, ''),
        folder: rel || '',
        hostname: get('Hostname'),
        port: portHex ? parseInt(portHex, 16) : 22,
        username: get('Username') || '',
        notes: get('Description') || '',
      });
    }
  };
  walk(dir, '');
}

// ---------------------------------------------------------------------------
// source: WinSCP.ini
// ---------------------------------------------------------------------------

function importWinscp(file) {
  const ini = fs.readFileSync(file, 'utf8');
  let section = null, vals = {};
  const flush = () => {
    if (!section || !/^Sessions\\/i.test(section)) { vals = {}; return; }
    const sess = section.slice(9);
    const slash = sess.lastIndexOf('/');
    addHost({
      name: slash >= 0 ? sess.slice(slash + 1) : sess,
      folder: slash >= 0 ? sess.slice(0, slash) : '',
      hostname: vals.HostName,
      port: vals.PortNumber,
      username: vals.UserName,
      notes: vals.Password ? 'stored WinSCP password not recovered — set on first connect' : '',
    });
    vals = {};
  };
  for (const raw of ini.split(/\r?\n/)) {
    const line = raw.trim();
    const ms = line.match(/^\[(.+)\]$/);
    if (ms) { flush(); section = ms[1]; continue; }
    const mk = line.match(/^(\w+)=(.*)$/);
    if (mk && /^Sessions\\/i.test(section || '')) vals[mk[1]] = mk[2];
  }
  flush();
}

// ---------------------------------------------------------------------------
// sources: generic CSV / JSON
// header: name,hostname,port,username,password,key_file,folder,jump,tags
// ---------------------------------------------------------------------------

function csvSplit(line) {
  const out = [];
  let cur = '', q = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) {
      if (c === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (c === '"') q = false;
      else cur += c;
    } else if (c === '"') q = true;
    else if (c === ',') { out.push(cur); cur = ''; }
    else cur += c;
  }
  out.push(cur);
  return out;
}

function importCsv(file) {
  const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/).filter((l) => l.trim());
  const header = csvSplit(lines.shift()).map((h) => h.trim().toLowerCase());
  for (const line of lines) {
    const row = {};
    csvSplit(line).forEach((v, i) => { row[header[i]] = v.trim(); });
    let credential_name = null;
    const notes = [];
    if (row.key_file) {
      try {
        const pem = fs.readFileSync(row.key_file.replace(/^~/, os.homedir()), 'utf8');
        if (/ENCRYPTED/.test(pem)) notes.push(`key ${row.key_file} is passphrase-protected`);
        credential_name = addCredential(`${row.name || row.hostname}-key`, 'key', row.username, { privateKey: pem, passphrase: null }, `from ${row.key_file}`);
      } catch { notes.push(`key file ${row.key_file} unreadable`); }
    }
    addHost({
      name: row.name, hostname: row.hostname || row.host || row.address,
      port: row.port, username: row.username || row.user,
      password: row.password, folder: row.folder,
      jump_host_name: row.jump || row.jump_host || null,
      tags: row.tags, credential_name, notes: notes.join('\n'),
    });
  }
}

const pick = (o, keys) => { for (const k of keys) if (o[k] != null && o[k] !== '') return o[k]; };

function importJson(file) {
  const arr = JSON.parse(fs.readFileSync(file, 'utf8'));
  const list = Array.isArray(arr) ? arr : arr.hosts || arr.connections || [];
  for (const o of list) {
    let credential_name = null;
    const notes = [];
    const keyFile = pick(o, ['key_file', 'privateKeyFile', 'identityFile', 'keyFile']);
    if (keyFile) {
      try {
        const pem = fs.readFileSync(String(keyFile).replace(/^~/, os.homedir()), 'utf8');
        if (/ENCRYPTED/.test(pem)) notes.push(`key ${keyFile} is passphrase-protected`);
        credential_name = addCredential(`${pick(o, ['name', 'label']) || 'host'}-key`, 'key', pick(o, ['username', 'user']), { privateKey: pem, passphrase: null }, `from ${keyFile}`);
      } catch { notes.push(`key file ${keyFile} unreadable`); }
    } else if (o.privateKey || o.key) {
      credential_name = addCredential(`${pick(o, ['name', 'label']) || 'host'}-key`, 'key', pick(o, ['username', 'user']), { privateKey: String(o.privateKey || o.key), passphrase: pick(o, ['key_passphrase', 'keyPassphrase']) || null }, 'imported key');
    }
    addHost({
      name: pick(o, ['name', 'label', 'alias']),
      hostname: pick(o, ['hostname', 'host', 'address', 'ip']),
      port: pick(o, ['port']), username: pick(o, ['username', 'user']),
      password: pick(o, ['password']),
      folder: pick(o, ['folder', 'group']),
      jump_host_name: pick(o, ['jump', 'jump_host', 'bastion', 'proxyJump']) || null,
      tags: pick(o, ['tags', 'tag']), credential_name, notes: notes.join('\n'),
    });
  }
}

// ---------------------------------------------------------------------------
// sealing + output — must match server/src/routes/backup.js exactly:
// scrypt N=32768 r=8 p=1 -> AES-256-GCM, blob = iv(12)||tag(16)||ct, base64.
// ---------------------------------------------------------------------------

const KDF_OPTS = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

let rl = null, rlPending = null, pipedLines = null;
function promptPass(question) {
  return new Promise((resolve) => {
    process.stderr.write(question);
    if (!process.stdin.isTTY) {
      // piped stdin: consume buffered lines — no readline race
      if (!pipedLines) pipedLines = fs.readFileSync(0, 'utf8').split('\n');
      const line = (pipedLines.shift() || '').trim();
      process.stderr.write('\n');
      return resolve(line);
    }
    if (!rl) {
      rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
      rl._writeToOutput = () => {};
      rl.on('close', () => { if (rlPending) { const r = rlPending; rlPending = null; r(''); } });
    }
    rlPending = resolve;
    rl.question('', (ans) => { rlPending = null; process.stderr.write('\n'); resolve(ans); });
  });
}

async function seal(passphrase) {
  const salt = crypto.randomBytes(16);
  const key = await new Promise((res, rej) =>
    crypto.scrypt(String(passphrase), salt, 32, KDF_OPTS, (e, k) => (e ? rej(e) : res(k))));
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(JSON.stringify(secrets), 'utf8'), c.final()]);
  return { kdf: 'scrypt', salt: salt.toString('base64'), blob: Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64') };
}

async function main() {
  switch (src) {
    case 'puttyExport': importPutty(fs.readFileSync(positional[0], 'utf8')); break;
    case 'puttyLive': {
      if (process.platform !== 'win32') { console.error('--putty-live only works on Windows; export a .reg instead'); process.exit(2); }
      const out = execFileSync('reg.exe', ['query', 'HKCU\\Software\\SimonTatham\\PuTTY\\Sessions', '/s'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
      importPutty(out);
      break;
    }
    case 'mremoteng': importMremoteng(positional[0]); break;
    case 'openssh': importOpenssh(positional[0] || path.join(os.homedir(), '.ssh', 'config')); break;
    case 'securecrt': importSecurecrt(positional[0]); break;
    case 'winscp': importWinscp(positional[0]); break;
    case 'csv': importCsv(positional[0]); break;
    case 'json': importJson(positional[0]); break;
  }

  const nSecrets = Object.keys(secrets).length;
  console.error(`imported ${vault.ssloth_export.hosts.length} hosts` +
    `, ${vault.ssloth_export.credentials.length} credentials` +
    (skipped ? `, ${skipped} skipped` : '') +
    (nSecrets ? `, ${nSecrets} secrets` : ''));
  warnings.forEach((w) => console.error(`  warn: ${w}`));

  if (opt.dryRun) return;

  if (nSecrets > 0) {
    const given = opt.sealPassphrase || process.env.SSLOTH_SEAL_PASS;
    if (given) {
      if (given.length >= 8) vault.ssloth_export.sealed = await seal(given);
      else console.error('given passphrase too short — secrets dropped');
    } else if (opt.seal) {
      const p1 = await promptPass('passphrase to seal secrets (min 8): ');
      if (p1.length < 8) { console.error('passphrase too short — secrets dropped'); }
      else {
        const p2 = await promptPass('confirm: ');
        if (p1 !== p2) { console.error('mismatch — secrets dropped'); }
        else vault.ssloth_export.sealed = await seal(p1);
      }
    } else {
      console.error('NOTE: secrets dropped (run again with --seal to carry them)');
      for (const h of vault.ssloth_export.hosts) { if (h.password_ref) { h.password_ref = null; h.auth_type = 'ask'; } }
      vault.ssloth_export.credentials = [];
    }
  }
  if (!vault.ssloth_export.sealed) {
    for (const h of vault.ssloth_export.hosts) h.password_ref = null;
    // credentials without secrets are useless — drop them
    vault.ssloth_export.credentials = [];
    for (const h of vault.ssloth_export.hosts) if (h.auth_type === 'credential') h.auth_type = 'ask';
  }

  const out = JSON.stringify(vault, null, 2) + '\n';
  if (opt.out) {
    fs.writeFileSync(opt.out, out, { mode: 0o600 });
    console.error(`wrote ${opt.out} — import via ssloth -> Vault -> Import`);
  } else process.stdout.write(out);
}

main().catch((e) => { console.error('error:', e.message); process.exit(1); });
