'use strict';

const Database = require('better-sqlite3');
const { DB_PATH } = require('./config');

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  is_admin      INTEGER NOT NULL DEFAULT 0,
  totp_secret   TEXT,
  totp_enabled  INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS sessions (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash TEXT NOT NULL UNIQUE,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ip         TEXT,
  ua         TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS credentials (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name       TEXT NOT NULL,
  type       TEXT NOT NULL CHECK (type IN ('password','key')),
  username   TEXT,
  secret_enc TEXT NOT NULL,          -- JSON: {password} or {privateKey, passphrase}
  public_key TEXT,
  comment    TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_credentials_user ON credentials(user_id);

CREATE TABLE IF NOT EXISTS hosts (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name          TEXT NOT NULL,
  hostname      TEXT NOT NULL,
  port          INTEGER NOT NULL DEFAULT 22,
  username      TEXT NOT NULL,
  auth_type     TEXT NOT NULL DEFAULT 'credential'
                CHECK (auth_type IN ('credential','password','ask')),
  credential_id INTEGER REFERENCES credentials(id) ON DELETE SET NULL,
  password_enc  TEXT,
  folder        TEXT NOT NULL DEFAULT '',
  color         TEXT NOT NULL DEFAULT '',
  notes         TEXT NOT NULL DEFAULT '',
  keepalive     INTEGER NOT NULL DEFAULT 15,
  created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at    INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_hosts_user ON hosts(user_id);

CREATE TABLE IF NOT EXISTS hostkeys (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  hostname    TEXT NOT NULL,
  port        INTEGER NOT NULL,
  fingerprint TEXT NOT NULL,
  key_b64     TEXT NOT NULL,
  algorithm   TEXT NOT NULL DEFAULT '',
  trusted_at  INTEGER NOT NULL DEFAULT (unixepoch()),
  UNIQUE (user_id, hostname, port)
);

CREATE TABLE IF NOT EXISTS snippets (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  command     TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  category    TEXT NOT NULL DEFAULT '',
  sort        INTEGER NOT NULL DEFAULT 0,
  created_at  INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_snippets_user ON snippets(user_id);

CREATE TABLE IF NOT EXISTS tunnels (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  host_id      INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  bind_address TEXT NOT NULL DEFAULT '127.0.0.1',
  local_port   INTEGER NOT NULL,
  remote_host  TEXT NOT NULL,
  remote_port  INTEGER NOT NULL,
  created_at   INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_tunnels_user ON tunnels(user_id);

CREATE TABLE IF NOT EXISTS shares (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash TEXT NOT NULL UNIQUE,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_id TEXT NOT NULL,
  label      TEXT NOT NULL DEFAULT '',
  mode       TEXT NOT NULL DEFAULT 'view' CHECK (mode IN ('view','control')),
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_shares_session ON shares(session_id);

CREATE TABLE IF NOT EXISTS recordings (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_id TEXT NOT NULL,
  label      TEXT NOT NULL DEFAULT '',
  file       TEXT NOT NULL,
  size       INTEGER NOT NULL DEFAULT 0,
  started_at INTEGER NOT NULL DEFAULT (unixepoch()),
  ended_at   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_recordings_user ON recordings(user_id);

CREATE TABLE IF NOT EXISTS playbooks (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  steps       TEXT NOT NULL DEFAULT '[]',   -- JSON: [{command, description}]
  created_at  INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at  INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_playbooks_user ON playbooks(user_id);

CREATE TABLE IF NOT EXISTS audit (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER,
  username   TEXT,
  action     TEXT NOT NULL,
  detail     TEXT NOT NULL DEFAULT '',
  ip         TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit(created_at);
`);

// Lightweight column migrations for existing databases.
function ensureColumn(table, column, ddl) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!cols.some((c) => c.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${ddl}`);
  }
}
ensureColumn('hosts', 'jump_host_id', 'jump_host_id INTEGER REFERENCES hosts(id) ON DELETE SET NULL');
ensureColumn('hosts', 'record', 'record INTEGER NOT NULL DEFAULT 0');
ensureColumn('hosts', 'pinned', 'pinned INTEGER NOT NULL DEFAULT 0');
ensureColumn('hosts', 'last_used_at', 'last_used_at INTEGER');
ensureColumn('hosts', 'region', "region TEXT NOT NULL DEFAULT ''");
ensureColumn('hosts', 'tags', "tags TEXT NOT NULL DEFAULT ''");
ensureColumn('users', 'pin_hash', 'pin_hash TEXT');
ensureColumn('users', 'totp_pending_secret', 'totp_pending_secret TEXT');
ensureColumn('users', 'totp_last_step', 'totp_last_step INTEGER NOT NULL DEFAULT 0');
ensureColumn('hosts', 'shared', 'shared INTEGER NOT NULL DEFAULT 0');
ensureColumn('tunnels', 'type', "type TEXT NOT NULL DEFAULT 'local' CHECK (type IN ('local','dynamic'))");
// --- round: importer/portal feature set ---
ensureColumn('hosts', 'protocol', "protocol TEXT NOT NULL DEFAULT 'ssh' CHECK (protocol IN ('ssh','telnet','bmc'))");
ensureColumn('hosts', 'mac', "mac TEXT NOT NULL DEFAULT ''");
ensureColumn('hosts', 'agent_forward', 'agent_forward INTEGER NOT NULL DEFAULT 0');
ensureColumn('users', 'role', "role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin','user','viewer'))");
db.exec("UPDATE users SET role = 'admin' WHERE is_admin = 1 AND role = 'user'");
ensureColumn('playbooks', 'schedule_cron', 'schedule_cron TEXT');
ensureColumn('playbooks', 'schedule_host_id', 'schedule_host_id INTEGER REFERENCES hosts(id) ON DELETE SET NULL');
ensureColumn('playbooks', 'schedule_enabled', 'schedule_enabled INTEGER NOT NULL DEFAULT 0');
ensureColumn('playbooks', 'next_run_at', 'next_run_at INTEGER');
ensureColumn('playbooks', 'last_run_at', 'last_run_at INTEGER');
ensureColumn('hosts', 'use_count', 'use_count INTEGER NOT NULL DEFAULT 0');

// DBs created before 'bmc' was a protocol carry a CHECK that rejects it, and
// SQLite can't alter a CHECK in place — rebuild the table once if stale.
{
  const ddl = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='hosts'").get()?.sql || '';
  if (ddl && !ddl.includes("'bmc'")) {
    const cols = db.prepare('PRAGMA table_info(hosts)').all().map((c) => c.name);
    db.pragma('foreign_keys = OFF');
    db.transaction(() => {
      db.exec(`CREATE TABLE hosts_new (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name          TEXT NOT NULL,
        hostname      TEXT NOT NULL,
        port          INTEGER NOT NULL DEFAULT 22,
        username      TEXT NOT NULL,
        auth_type     TEXT NOT NULL DEFAULT 'credential'
                      CHECK (auth_type IN ('credential','password','ask')),
        credential_id INTEGER REFERENCES credentials(id) ON DELETE SET NULL,
        password_enc  TEXT,
        folder        TEXT NOT NULL DEFAULT '',
        color         TEXT NOT NULL DEFAULT '',
        notes         TEXT NOT NULL DEFAULT '',
        keepalive     INTEGER NOT NULL DEFAULT 15,
        created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
        updated_at    INTEGER NOT NULL DEFAULT (unixepoch()),
        jump_host_id  INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
        record        INTEGER NOT NULL DEFAULT 0,
        pinned        INTEGER NOT NULL DEFAULT 0,
        last_used_at  INTEGER,
        region        TEXT NOT NULL DEFAULT '',
        tags          TEXT NOT NULL DEFAULT '',
        shared        INTEGER NOT NULL DEFAULT 0,
        protocol      TEXT NOT NULL DEFAULT 'ssh'
                      CHECK (protocol IN ('ssh','telnet','bmc')),
        mac           TEXT NOT NULL DEFAULT '',
        agent_forward INTEGER NOT NULL DEFAULT 0,
        use_count     INTEGER NOT NULL DEFAULT 0
      )`);
      const inNew = new Set(db.prepare('PRAGMA table_info(hosts_new)').all().map((c) => c.name));
      const common = cols.filter((c) => inNew.has(c));
      db.exec(`INSERT INTO hosts_new (${common.join(',')}) SELECT ${common.join(',')} FROM hosts`);
      db.exec('DROP TABLE hosts');
      db.exec('ALTER TABLE hosts_new RENAME TO hosts');
      db.exec('CREATE INDEX IF NOT EXISTS idx_hosts_user ON hosts(user_id)');
    })();
    db.pragma('foreign_keys = ON');
  }
}

db.exec(`
CREATE TABLE IF NOT EXISTS playbook_runs (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  playbook_id INTEGER,
  host_id     INTEGER,
  name        TEXT NOT NULL DEFAULT '',
  host_label  TEXT NOT NULL DEFAULT '',
  trigger     TEXT NOT NULL DEFAULT 'manual',
  status      TEXT NOT NULL DEFAULT 'running'
              CHECK (status IN ('running','ok','fail','timeout','aborted','error')),
  output      TEXT NOT NULL DEFAULT '',
  started_at  INTEGER NOT NULL DEFAULT (unixepoch()),
  ended_at    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_pruns_user ON playbook_runs(user_id, started_at);

CREATE TABLE IF NOT EXISTS api_tokens (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name       TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  scopes     TEXT NOT NULL DEFAULT '',
  last_used  INTEGER,
  expires_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_tokens_user ON api_tokens(user_id);

CREATE TABLE IF NOT EXISTS host_health (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ts         INTEGER NOT NULL DEFAULT (unixepoch()),
  ok         INTEGER NOT NULL DEFAULT 0,
  latency_ms INTEGER
);
CREATE INDEX IF NOT EXISTS idx_health_host ON host_health(host_id, ts);

CREATE TABLE IF NOT EXISTS webhooks (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  url        TEXT NOT NULL,
  events     TEXT NOT NULL DEFAULT '*',
  enabled    INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_webhooks_user ON webhooks(user_id);

CREATE TABLE IF NOT EXISTS quick_history (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  hostname TEXT NOT NULL,
  port     INTEGER NOT NULL DEFAULT 22,
  username TEXT NOT NULL DEFAULT '',
  ts       INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_quick_user ON quick_history(user_id, ts);

CREATE TABLE IF NOT EXISTS workspaces (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name       TEXT NOT NULL,
  layout     TEXT NOT NULL DEFAULT '[]',
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_workspaces_user ON workspaces(user_id);
`);

function audit(user, action, detail, req) {
  try {
    db.prepare(
      'INSERT INTO audit (user_id, username, action, detail, ip) VALUES (?, ?, ?, ?, ?)'
    ).run(
      user ? user.id : null,
      user ? user.username : null,
      action,
      String(detail || '').slice(0, 500),
      req ? (req.ip || '') : ''
    );
  } catch (e) {
    console.error('[ssloth] audit write failed:', e.message);
  }
}

module.exports = { db, audit };
