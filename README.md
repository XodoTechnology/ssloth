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
- **Persistent sessions** — close or reload the tab and the SSH session
  keeps running server-side; reopening reattaches with full scrollback.
- **Playbooks** — ordered command sequences run step-by-step on a session
  with real exit codes, per-step timeouts, and abort-on-failure.
- **Session recording** — record terminal output to asciinema `.cast` files
  (keystrokes never captured), per-session toggle or auto-record per host,
  replay in-app or download.
- **Bastion / ProxyJump** — hop through saved jump hosts to reach private
  targets; chains recurse (A → B → C) and host keys are verified per hop.
- **Host health** — connected sessions poll load/memory/disk into the
  status bar.
- **Remote file editor** — open remote files from the SFTP panel in a code
  editor, preview logs/images, save back over SFTP.
- **Host status** — live reachable/unreachable rings on host dots (server-side
  TCP probe, cached).
- **Import `~/.ssh/config`** — bulk-create hosts (and keys, if you attach the
  private key files) including ProxyJump links.
- **Encrypted vault export** — passphrase-sealed JSON export of hosts,
  snippets, and optionally credentials; re-import skips duplicates.
- **Background transfers** — SFTP uploads keep running across tab switches;
  a bottom-right tray tracks progress and alerts on completion.
- **Drop-to-upload** — drag files straight onto a terminal pane to SFTP them
  to the remote (uses the SFTP panel's current directory).
- **Session log export** — dump the full scrollback buffer to a `.log` file.
- **Terminal bell alerts** — a `BEL` on a background tab flashes its dot and
  toasts you (`sleep 5 && printf '\a'` — job-done pings).
- **Pinned & recent hosts** — star favorites to the top; last-used group
  updates on every connect.
- **Tags, groups & regions** — folder groups, region badges, and `#tag`
  hashtags on hosts; filter with `#routers` and open every matching
  session at once (or hit the play button on any group header).
- **Desktop app** — `desktop/` wraps the whole thing in Electron: bundled
  Node runtime, loopback-only server, vault in `%APPDATA%`. Clipboard
  features work without HTTPS.
- **Latency meter** — live connection RTT in the status bar.
- **Appearance presets** — font size + terminal themes in Settings.
- **Keyboard shortcuts** — Ctrl+K palette, Ctrl+Shift+`[`/`]` cycle tabs,
  Ctrl+Shift+X closes a tab.
- **SFTP browser** — per-session file panel: browse, upload (button or
  drag-and-drop), download, mkdir, rename, recursive delete, upload progress.
- **Snippets** — saved one-click commands runnable in the active terminal,
  with `{{variable}}` placeholders filled in at run time.
- **Tunnels** — local port forwards through any saved host (bastions work),
  plus dynamic SOCKS5 proxies. Loopback-bound by default.
- **Shared hosts** — admins can flag a host as shared: teammates connect
  through it without ever seeing its credentials.
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

### Disposable test sshd

A throwaway sshd ships under the `test` compose profile for exercising
terminals, SFTP, tunnels, and ProxyJump without touching a real box:

```bash
docker compose --profile test up -d
# add a host: tester@<server-ip>:2222, password testpass123
```

TCP forwarding is enabled so tunnels and bastion jumps work. It's a test
fixture, not production material — omit the profile on real deployments.

## Build from source

Two distributables come out of this repo: the **web portal** (a Node server
serving an SPA — runs on any OS Node runs on) and the **desktop app**
(per-platform Electron packages). Prerequisites: **Node.js ≥ 20** and npm;
no other build tooling is needed for the portal itself.

### Web portal (Linux / macOS / Windows)

```bash
git clone <repo> && cd ssloth
npm run install:all      # installs server/ and web/ dependencies
npm run build            # builds the SPA into web/dist
PORT=8080 npm start      # serves UI + API + WS on one port
```

`better-sqlite3` ships prebuilt binaries for linux/darwin/win32 x64+arm64,
so `npm ci` normally needs no compiler. On a platform without a published
prebuild it falls back to a source build — install a C++ toolchain
(`build-essential` / Xcode CLT / MSVC Build Tools) in that case.

Copy `.env.example` to `.env` and set `SSLOTH_MASTER_KEY` for production
(see Configuration below), then open `http://localhost:8080`.

### Desktop packages

```bash
cd desktop
npm install

# build the frontend first, from the repo root:
npm --prefix ../web run build

npm run dist        # Windows → release/"ssloth Setup x.y.z.exe" (NSIS)
npm run dist:linux  # Linux   → release/*.AppImage + *.deb
npm run dist:mac    # macOS   → release/*.dmg + *.zip
```

Per-platform notes:

- **Windows** — build on Windows for the cleanest result. Cross-building on
  Linux works too if `wine` + `wine32` are installed (electron-builder runs
  `rcedit` and the NSIS packager under wine).
- **Linux** — AppImage and `.deb` build natively on any Linux host.
- **macOS** — unsigned `.zip` bundles (Intel: `--mac zip --x64`, Apple
  Silicon: `--mac zip --arm64`) can be built on Linux. `.dmg` and code
  signing need `hdiutil`/Apple tooling — use a Mac or the
  `desktop-release.yml` CI workflow, which builds all targets on native
  runners on a `v*` tag push.

`prepare-standalone.js` (invoked by each `dist:*` script) stages the server
with production deps, downloads the target's `better-sqlite3` prebuild and
a matching Node runtime, and bundles `web/dist` — the packaged app needs
nothing installed on the user's machine.

### Verify a build

```bash
# with the server running on :8089 (and the test sshd container up for
# SSH-dependent checks):
PORT=8089 npm start
node e2e-round5.js     # feature suite: sessions, SFTP, bastions, SOCKS5
node e2e-security.js   # security suite: TOTP, CSRF, tunnel binds, teardown
```

## Desktop app (Electron)

`desktop/` wraps the same server + web build in Electron. Packaged builds
ship a real Node binary plus the server and `web/dist` as raw resources, so
`better-sqlite3` uses its standard Node prebuilds — no Electron ABI rebuild
needed. The server binds only `127.0.0.1` on a random port and stores the
vault under the OS data dir (`%APPDATA%\ssloth`, `~/.config/ssloth`,
`~/Library/Application Support/ssloth`). Loopback counts as a secure
context, so clipboard features work without HTTPS.

```bash
cd desktop
npm install
npm run dev         # launch against the repo's server + web/dist
npm run dist        # Windows: NSIS installer
npm run dist:linux  # Linux: AppImage + .deb
npm run dist:mac    # macOS: dmg + zip (dmg needs a Mac or CI)
```

`prepare-standalone.js` stages the server with production deps, fetches the
target platform's `better-sqlite3` prebuild (falls back to a source build
when none is published), bundles the matching Node runtime, and copies
`web/dist`. `electron-builder` then packages per-platform installers.

Unsigned macOS **zip** builds (Intel + Apple Silicon) can be produced on
Linux — `npx electron-builder --mac zip [--arm64]` — but `.dmg` and code
signing require `hdiutil`/Apple tooling, i.e. a real Mac or CI.
`.github/workflows/desktop-release.yml` builds Windows/Linux/macOS-Intel/
macOS-ARM artifacts on a `v*` tag push. Unsigned mac builds trip Gatekeeper
once: right-click → Open, or `xattr -d com.apple.quarantine ssloth.app`.
Proper signing/notarization requires an Apple Developer account.

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
| `SSLOTH_ALLOW_PUBLIC_TUNNELS` | `true` lets **admins** bind tunnels to non-loopback addresses. Default `false` — tunnels always bind `127.0.0.1`/`::1`. |

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
