# ssloth

A self-hosted, security-first SSH client and connection manager in the browser —
think Termius or mRemoteNG as a web portal. Multi-tab terminals, an encrypted
credential vault, SFTP drag-and-drop file transfer, command snippets, and local
port forwards.

## Features

- **Web terminal** — full xterm.js terminal over a WebSocket → SSH bridge.
  Multiple tabs, reconnect, scrollback search, clickable links,
  highlight-to-copy and right-click paste (with bracketed-paste safety).
- **Ephemeral share links** — share a live session to anyone with a one-off
  link: view-only or interactive, 15 min–24 h TTL, revocable, stored hashed,
  and dead the moment you close the tab.
- **Host manager** — saved hosts with folders, colors, notes, and keepalive;
  quick-connect with `user@host[:port]`.
- **Credential vault** — reusable password credentials and SSH keys
  (ed25519/RSA generation or OpenSSH/PEM import, optional passphrases).
  All secrets encrypted at rest with AES-256-GCM.
- **Auth modes** — saved credential, inline password, or *ask at connect*
  (password typed into the terminal, never stored).
- **Split panes** — two terminals side-by-side in one tab, each its own
  session (same or different hosts).
- **Broadcast input** — toggle the radio button and your keystrokes go to
  every open session at once (multi-exec).
- **Command palette** — Ctrl+K fuzzy search across hosts, snippets, and
  navigation.
- **Session recording** — record terminal output to asciinema `.cast` files
  (keystrokes never captured), per-session toggle or auto-record per host,
  replay in-app or download.
- **Bastion / ProxyJump** — hop through a saved jump host to reach private
  targets; host keys are verified per hop.
- **Host status** — live reachable/unreachable rings on host dots (server-side
  TCP probe, cached).
- **Import `~/.ssh/config`** — bulk-create hosts (and keys, if you attach the
  private key files) including ProxyJump links.
- **Encrypted vault export** — passphrase-sealed JSON export of hosts,
  snippets, and optionally credentials; re-import skips duplicates.
- **SFTP browser** — per-session file panel: browse, upload (button or
  drag-and-drop), download, mkdir, rename, recursive delete, upload progress.
- **Snippets** — saved one-click commands runnable in the active terminal,
  with `{{variable}}` placeholders filled in at run time.
- **Tunnels** — local port forwards through any saved host (bastions work).
- **TOFU host-key pinning** — the server's host key fingerprint is shown and
  pinned on first connect; a changed key hard-blocks the session (MITM guard).
- **Portal security** — scrypt-hashed accounts, httpOnly SameSite session
  cookies, optional TOTP 2FA, rate-limited login, same-origin/CSRF checks on
  every mutation and the WebSocket upgrade, strict CSP, and an audit log of
  logins, connections, transfers, and host-key trust decisions.
- **Multi-user** — every user gets their own vault, hosts, snippets, and
  pinned keys; admins manage users and see the full audit log.

## Quick start (Docker)

```bash
cp .env.example .env
# edit .env — set SSLOTH_MASTER_KEY (openssl rand -base64 48)
docker compose up -d --build
```

Open `http://localhost:8080`, create the first admin account, add a host, and
connect.

## Development

```bash
npm run install:all        # install server + web deps
PORT=8080 npm start        # terminal: run API+WS server (after one web build)
npm run dev:web            # Vite dev server on :5173 with /api + /ws proxies
# or for backend watch-mode:
npm --prefix server run dev
npm run build              # produce web/dist (served by the server in prod)
```

## Configuration

| Variable | Purpose |
| --- | --- |
| `SSLOTH_MASTER_KEY` | Secret that encrypts all stored credentials/keys (recommended in production). If unset, a random key is generated at `data/master.key` (mode 0600). |
| `SSLOTH_DATA_DIR` | Where the SQLite DB and master key live (default `server/data`, `/data` in Docker). |
| `SSLOTH_SECURE_COOKIES` | `true` when behind HTTPS — marks session cookies `Secure`. |
| `TRUST_PROXY` | `true` or a CIDR when behind a reverse proxy (fixes client IPs + rate limiting). |
| `PORT`, `BIND` | Listen address (default `0.0.0.0:8080`). |

## Production notes

- Always run behind TLS (nginx/caddy/traefik) and set `SSLOTH_SECURE_COOKIES=true`.
- Set `SSLOTH_MASTER_KEY` so the encryption key isn't stored beside the database.
  Rotating it requires re-entering stored credentials.
- Back up `/data` — it contains the DB, the encrypted vault, and `master.key`.
- The audit log lives in the DB (`audit` table); visible under Audit Log in the UI.

## Architecture

```text
browser ──HTTPS──> express (static SPA + JSON API + cookie auth)
browser ──WSS───> /ws/terminal ──ssh2──> your servers
viewer  ──WSS───> /ws/share/<token> (ephemeral, no login)
browser ──HTTPS─> /api/sftp/* ────ssh2 SFTP──> same servers
```

- `server/` — Node/Express backend, `ssh2` for SSH+SFTP, `better-sqlite3` for
  storage, AES-256-GCM for secrets, scrypt for passwords.
- `web/` — React + Vite + Tailwind + xterm.js SPA.
