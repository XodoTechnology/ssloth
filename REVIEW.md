# ssloth Code Review & Mitigation Plan

**Review Date:** 2026-10-21  
**Scope:** Full security and functionality audit of the `ssloth` codebase (`server/src/`, `web/src/`, `desktop/main.js`, `desktop/prepare-standalone.js`, `Dockerfile`, and `docker-compose.yml`), excluding generated/rendered build artifacts.

---

## Executive Summary

The review identified **15 findings** across the `ssloth` codebase:

- **6 Critical / High Severity Security Vulnerabilities**
- **5 Functional & Logic Bugs**
- **4 Medium / Low Severity Hardening Issues**

| # | Severity | Category | Issue | Status | Target Files |
| --- | --- | --- | --- | --- | --- |
| 1.1 | Critical | Authentication / 2FA | `POST /api/auth/totp/setup` overwrites `totp_secret` and sets `totp_enabled = 0` without verifying password or TOTP; `/totp/disable` does not require TOTP or rate-limiting; TOTP codes lack replay protection | **Pending** | `server/src/routes/auth.js`, `server/src/crypto.js` |
| 1.2 | Critical | Network / Access Control | `tunnels.js` allows any user to bind unauthenticated SOCKS5 proxies and TCP forwards to `0.0.0.0` (all interfaces) on arbitrary ports, and deleting a user or host orphans live tunnel listeners and SSH sessions | **Pending** | `server/src/routes/tunnels.js`, `server/src/routes/admin.js`, `server/src/routes/hosts.js` |
| 1.3 | High | Desktop Auth / DNS Rebinding | Desktop mode (`SSLOTH_DESKTOP=1`) auto-authenticates requests without validating the `Host` header on `GET` requests, and the 4–8 digit PIN UI (`Login.jsx`, `IdleLock.jsx`) auto-submits and wipes the PIN on the 4th digit, breaking all 5–8 digit PINs | **Pending** | `server/src/auth.js`, `web/src/pages/Login.jsx`, `web/src/components/IdleLock.jsx` |
| 1.4 | High | CSRF / Origin Check | `checkOrigin()` allows requests when `Origin` is absent and permits `Sec-Fetch-Site: same-site`, exposing raw-body endpoints like `POST /api/sftp/:sid/upload` | **Pending** | `server/src/auth.js` |
| 1.5 | High | Multi-User / Phishing | Any non-admin user can publish `shared = 1` hosts with `auth_type = 'ask'` to all users' sidebars to harvest credentials, and editing a host's `auth_type` or `hostname` retains stale `password_enc` secrets | **Pending** | `server/src/routes/hosts.js`, `server/src/ssh/manager.js` |
| 1.6 | High | DoS / Resource Exhaustion | `CastRecorder` writes synchronously (`fs.appendFileSync`) with no size cap; `/api/hosts/status` opens unbounded parallel TCP sockets; detached SSH sessions never idle-expire while remote output continues | **Pending** | `server/src/ssh/recorder.js`, `server/src/routes/hosts.js`, `server/src/ssh/manager.js`, `server/src/routes/sftp.js` |
| 2.1 | High | Functional / SFTP | Recursive directory delete (`rmrf`) uses `sftp.stat` instead of `sftp.lstat`, following symlinks into external target directories and deleting their contents | **Pending** | `server/src/routes/sftp.js` |
| 2.2 | Medium | Functional / Snippets | Running a snippet from `Snippets.jsx` or `CommandPalette.jsx` bypasses `{{variable}}` placeholder prompting and executes literal `{{var}}` text in the active terminal | **Pending** | `web/src/pages/Snippets.jsx`, `web/src/components/CommandPalette.jsx` |
| 2.3 | Medium | Functional / Split Panes | Closing a split pane (`removePane`) only unmounts the component without sending `{type:'close'}` or calling `unregisterPane()`, leaking the server-side SSH session and stale store state | **Pending** | `web/src/components/TerminalView.jsx`, `web/src/components/TerminalPane.jsx` |
| 2.4 | Medium | Functional / Backup & Import | Vault import (`backup.js`) and `~/.ssh/config` import (`SshConfigImport.jsx`) resolve `jump_host_name` / `ProxyJump` in a single pass, dropping bastion links when a host precedes its bastion; `playbooks` and `tunnels` are not exported | **Pending** | `server/src/routes/backup.js`, `web/src/components/SshConfigImport.jsx` |
| 2.5 | Medium | Functional / Playbooks | Playbook runner (`ws/terminal.js`) relies on POSIX `$?` expansion and has no step timeout, hanging indefinitely on non-POSIX shells (`fish`, `csh`, router CLIs) or interactive prompts | **Pending** | `server/src/ws/terminal.js` |
| 3.1 | Medium | Session Lifecycle | Logging out, changing a password, or admin password reset/user deletion deletes DB cookie rows but leaves active `/ws/terminal` WebSockets, detached SSH sessions, and active tunnels running | **Pending** | `server/src/routes/auth.js`, `server/src/routes/admin.js`, `server/src/ssh/manager.js`, `server/src/routes/tunnels.js` |
| 3.2 | Medium | Security / Lock Screen | `IdleLock.jsx` stores lock state only in volatile React/Zustand memory (`useStore.getState().locked`), so pressing F5 / Reload bypasses the lock screen completely | **Pending** | `web/src/components/IdleLock.jsx`, `web/src/store.js` |
| 3.3 | Low | Electron Hardening | `desktop/main.js` does not set `setWindowOpenHandler` or `will-navigate` guards, so clicking terminal links (`WebLinksAddon`) opens untrusted external sites inside an Electron `BrowserWindow` instead of the OS browser | **Pending** | `desktop/main.js` |
| 3.4 | Low | Event-Loop Blocking | `crypto.scryptSync` is used synchronously for login, PIN, and vault export/import (`N=32768`), stalling active SSH terminal streams during key derivation | **Pending** | `server/src/crypto.js`, `server/src/routes/backup.js` |

---

## 1. Critical & High Severity Security Vulnerabilities

### 1.1. 2FA Bypass via `/api/auth/totp/setup`, Unthrottled `/totp/disable` & `/verify`, and TOTP Replay

- **Status:** **Pending**
- **File:** `server/src/routes/auth.js` (lines 28–34, 81–102, 113–144, 193–225), `server/src/crypto.js` (lines 140–148)
- **Issue:**
  1. **`POST /api/auth/totp/setup` silently disables 2FA without password or TOTP verification:**
     In `server/src/routes/auth.js` (lines 193–198):

     ```js
     router.post('/totp/setup', requireAuth, async (req, res) => {
       const secret = generateTotpSecret();
       db.prepare('UPDATE users SET totp_secret = ?, totp_enabled = 0 WHERE id = ?').run(
         encryptSecret(secret),
         req.user.id
       );
     ```

     If an account already has `totp_enabled = 1`, calling `POST /api/auth/totp/setup` immediately sets `totp_enabled = 0` and overwrites `totp_secret` without checking the user's current password or current TOTP code. An attacker with a stolen session or CSRF primitive can strip 2FA from the account in one request, bypassing `/api/auth/totp/disable`.
  2. **`POST /api/auth/totp/disable` does not require a TOTP code and is not rate-limited:**
     `/totp/disable` only verifies `req.body.password` (not a current TOTP code), and `/password`, `/verify`, `/pin/setup`, `/pin/disable`, `/totp/enable`, and `/totp/disable` do not apply `authLimiter`.
  3. **TOTP codes can be replayed within the 90-second window:**
     `verifyTotp()` in `server/src/crypto.js` accepts offsets `[-1, 0, 1]` without recording the last accepted time-step counter, allowing a captured 6-digit code to be reused multiple times within 90 seconds.

- **Proposed Mitigation:**
  1. In `POST /api/auth/totp/setup`, reject the request with `400` if `user.totp_enabled` is already `1` (require disabling 2FA first), and store pending enrollment secrets in a separate column (`totp_pending_secret`) until `/totp/enable` succeeds.
  2. In `POST /api/auth/totp/disable`, require both the user's password **and** a valid TOTP code (or admin override), and apply `authLimiter` to `/password`, `/verify`, `/pin/*`, and `/totp/*`.
  3. Track `totp_last_step` on `users` so each 30-second TOTP time-step can only be used once.

---

### 1.2. Unauthenticated SOCKS5 / Port-Forward Binding on `0.0.0.0` & Orphaned Tunnels on User/Host Deletion

- **Status:** **Pending**
- **File:** `server/src/routes/tunnels.js` (lines 18–42, 75–136, 218–224), `server/src/routes/admin.js` (lines 62–69), `server/src/routes/hosts.js` (lines 156–162)
- **Issue:**
  1. **Unrestricted `bind_address` exposes unauthenticated SOCKS5 proxy to the network:**
     In `server/src/routes/tunnels.js` (lines 25–27), `cleanTunnel()` accepts any `bind_address` string (such as `0.0.0.0` or `::`). When a user starts a `dynamic` tunnel bound to `0.0.0.0`, `handleSocks5()` (lines 136–208) opens a **zero-authentication SOCKS5 proxy** (`socket.write(Buffer.from([5, 0]))`) on all interfaces of the `ssloth` server, allowing anyone on the network to pivot through the user's SSH host into internal networks.
  2. **Orphaned active tunnels when a host or user is deleted:**
     When a host is deleted (`DELETE /api/hosts/:id`) or a user is deleted (`DELETE /api/admin/users/:id`), SQLite `ON DELETE CASCADE` deletes the corresponding rows in `tunnels`, **without calling `stopTunnel(id)`**. The `net.Server` listener and SSH connection in the in-memory `active` Map remain open indefinitely, and can no longer even be stopped via `POST /api/tunnels/:id/stop` because the database row no longer exists (`404 not found`).

- **Proposed Mitigation:**
  1. Restrict `bind_address` in `cleanTunnel()` to loopback addresses (`127.0.0.1`, `::1`, `localhost`) unless an explicit environment variable (e.g., `SSLOTH_ALLOW_PUBLIC_TUNNELS=true`) is enabled and the user is an administrator; restrict `local_port` to unprivileged ports (`1024–65535`).
  2. Export a helper `stopTunnelsForHost(hostId)` and `stopTunnelsForUser(userId)` from `server/src/routes/tunnels.js` (tracking `userId` and `hostId` on `active` entries) and call them in `DELETE /api/hosts/:id`, `DELETE /api/admin/users/:id`, and `POST /api/auth/logout`.

---

### 1.3. Desktop Mode (`SSLOTH_DESKTOP=1`) Broken 5–8 Digit PIN Unlock & Missing `Host` Header Validation

- **Status:** **Pending**
- **File:** `web/src/pages/Login.jsx` (lines 12–32), `web/src/components/IdleLock.jsx` (lines 73–94), `server/src/auth.js` (lines 65–76, 93–111)
- **Issue:**
  1. **5–8 digit PINs are completely unusable in `Login.jsx` and `IdleLock.jsx`:**
     In `Settings.jsx` (line 281) and `routes/auth.js` (line 148), PINs are defined as 4–8 digits (`/^\d{4,8}$/`). However, in `Login.jsx` (lines 28–32):

     ```js
     const tap = (d) => {
       const next = (pin + d).slice(0, 8);
       setPin(next);
       if (next.length >= 4) unlock(next);
     };
     ```

     and in `IdleLock.jsx` (lines 91–93):

     ```js
     const next = pin + k;
     setPin(next);
     if (next.length >= 4) unlockPin(next);
     ```

     When a user with a 6-digit PIN (e.g., `123456`) enters the 4th digit (`1234`), `unlock("1234")` fires immediately, receives `401 wrong pin` from `POST /api/auth/pin`, and the `catch` block executes `setPin('')`—wiping the input before the user can type the 5th digit. Users who set a 5–8 digit PIN are permanently locked out of PIN unlock.
  2. **DNS rebinding against Desktop mode (`SSLOTH_DESKTOP=1`):**
     In Desktop mode without a PIN, `desktopUser()` automatically authenticates every request as the local admin user. Because `checkOrigin()` skips `GET` requests and only compares `new URL(origin).host === req.headers.host` on `POST` / WebSocket upgrades, a DNS-rebinding attack (`rebind.attacker.com` resolving to `127.0.0.1`) satisfies `new URL(origin).host === req.headers.host` and can read all API endpoints and open `/ws/terminal`.

- **Proposed Mitigation:**
  1. Add an explicit submit button (or Enter key handler) to the PIN pad in `Login.jsx` and `IdleLock.jsx` instead of auto-submitting on every keystroke at `length >= 4` (or store the PIN length on setup so auto-submit only fires at the exact configured length).
  2. When `DESKTOP` is enabled (or `BIND === '127.0.0.1'`), reject any HTTP request or WebSocket upgrade whose `Host` header hostname is not `127.0.0.1`, `localhost`, or `[::1]`.

---

### 1.4. CSRF `checkOrigin` Bypass When `Origin` Is Omitted or `Sec-Fetch-Site` Is `same-site`

- **Status:** **Pending**
- **File:** `server/src/auth.js` (lines 93–111)
- **Issue:**
  In `server/src/auth.js`:

  ```js
  function checkOrigin(req, res, next) {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    const fetchSite = req.headers['sec-fetch-site'];
    if (fetchSite && !['same-origin', 'same-site', 'none'].includes(fetchSite)) {
      return res.status(403).json({ error: 'cross-site request blocked' });
    }
    const origin = req.headers.origin;
    if (origin) {
      ...
    }
    next();
  }
  ```

  1. `'same-site'` is permitted in `sec-fetch-site`, meaning a compromised sibling subdomain (e.g. `app2.example.com` vs `ssh.example.com`) passes the Fetch Metadata check while `SameSite=Lax` cookies are still sent by the browser across subdomains.
  2. If a request omits both `Origin` and `Sec-Fetch-Site` (or sends `Sec-Fetch-Site: same-site` without `Origin`), `checkOrigin()` falls through to `next()`. Notably, `POST /api/sftp/:sid/upload` (`server/src/index.js` line 81) streams raw request bodies without requiring `Content-Type: application/json`, making it triggerable via a plain HTML `<form method="POST">`.

- **Proposed Mitigation:**
  1. Remove `'same-site'` from the allowed `sec-fetch-site` list in `checkOrigin()` (`!['same-origin', 'none'].includes(fetchSite)`).
  2. Require state-changing `/api` requests to include either a matching `Origin` header **or** `Sec-Fetch-Site: same-origin` (matching the strictness of `checkWsOrigin()`).

---

### 1.5. Multi-User Shared Host Phishing (`shared = 1`) & Stale `password_enc` Retention

- **Status:** **Pending**
- **File:** `server/src/routes/hosts.js` (lines 42–44, 61–64, 73–154), `server/src/routes/backup.js` (lines 70–78)
- **Issue:**
  1. **Unprivileged users can inject `shared = 1` hosts into all users' sidebars:**
     Any non-admin user can create or edit a host with `shared: true` and `auth_type: 'ask'` (or `credential`) pointing to an attacker-controlled SSH server and spoofing the name/folder of an administrative host. When another user (such as an admin) clicks that shared host in their sidebar, `ssloth` connects to the attacker's server and prompts the victim for their password (`auth_request`), sending the victim's password directly to the attacker's SSH server.
  2. **Stale `password_enc` is retained when `auth_type` or `hostname` changes:**
     In `cleanHostInput()` (`server/src/routes/hosts.js` lines 62–64), `password_enc` is only updated when `body.password !== undefined`. If a user changes a host's `auth_type` from `'password'` to `'credential'` or `'ask'`, the old `password_enc` remains stored on the row and is still exported by `/api/vault/export` (`server/src/routes/backup.js` line 70).

- **Proposed Mitigation:**
  1. Restrict setting `shared = 1` on hosts to administrators (`req.user.is_admin`), or require admin approval before a shared host appears to other users.
  2. In `cleanHostInput()` / `PUT /api/hosts/:id`, clear `password_enc = null` whenever `auth_type` is changed to `'credential'` or `'ask'`, and clear `credential_id = null` when `auth_type` is changed to `'password'` or `'ask'`.

---

### 1.6. DoS via Synchronous Recording Writes, Unbounded Parallel Port Probes, and Immortal Detached Sessions

- **Status:** **Pending**
- **File:** `server/src/ssh/recorder.js` (lines 31–41), `server/src/routes/hosts.js` (lines 168–194), `server/src/ssh/manager.js` (lines 13–19, 333–349), `server/src/routes/sftp.js` (lines 157–163, 179–185)
- **Issue:**
  1. **Synchronous disk writes (`fs.appendFileSync`) without size cap in `CastRecorder`:**
     `CastRecorder._write()` calls `fs.appendFileSync(this.file, line)` on every terminal output chunk with no file-size cap. High-throughput terminal output (e.g., `yes` or `find /`) blocks the entire Node.js event loop and can fill the server's disk.
  2. **Detached SSH sessions never expire while any output is produced:**
     In `server/src/ssh/manager.js` (line 334), `sessionOutput()` sets `session.lastUsed = Date.now()` on every output chunk even when `session.ws === null` (detached). A detached session running `top`, `vmstat`, or `tail -f` resets `lastUsed` forever and is never reaped by the `IDLE_TTL_MS` sweep. There is also no per-user limit on concurrent sessions.
  3. **Unbounded parallel TCP sockets in `GET /api/hosts/status`:**
     `Promise.all(hosts.map((h) => probePort(h.hostname, h.port)))` dials every saved and shared host simultaneously with no concurrency cap.
  4. **Leaked SFTP read stream on client disconnect:**
     In `GET /api/sftp/:sid/download` (`server/src/routes/sftp.js` line 157), if the HTTP client aborts the download mid-stream, `rs` (`sftp.createReadStream`) is not destroyed on `res.on('close')`.

- **Proposed Mitigation:**
  1. Replace `fs.appendFileSync` in `CastRecorder` with an async `fs.WriteStream` and enforce a maximum recording size (e.g., 50 MB), stopping the recorder automatically when reached.
  2. Only update `session.lastUsed` on client input/attach/SFTP activity (or enforce a separate `detachedAt` TTL so detached sessions with `session.ws === null` close after `IDLE_TTL_MS` regardless of remote stdout), and cap concurrent sessions per user (e.g., 25).
  3. Limit concurrency in `/api/hosts/status` (e.g., batches of 16 sockets) and attach `res.on('close', () => rs.destroy())` in `GET /api/sftp/:sid/download` and upload size limits on `POST /api/sftp/:sid/upload`.

---

## 2. Functional & Logic Bugs

### 2.1. SFTP Recursive Delete (`rmrf`) Uses `stat` Instead of `lstat`, Following Symlinks Into Target Directories

- **Status:** **Pending**
- **File:** `server/src/routes/sftp.js` (lines 38, 229, 239–249)
- **Issue:**
  In `server/src/routes/sftp.js` (lines 239–249):

  ```js
  async function rmrf(sftp, p, depth) {
    if (depth > 32) throw new Error('directory too deep to delete recursively');
    const st = await pStat(sftp, p);
    if ((st.mode & S_IFMT) !== S_IFDIR) return pUnlink(sftp, p);
    const list = await pReaddir(sftp, p);
    for (const e of list) {
      if (e.filename === '.' || e.filename === '..') continue;
      await rmrf(sftp, path.posix.join(p, e.filename), depth + 1);
    }
    return pRmdir(sftp, p);
  }
  ```

  Because `pStat` calls `sftp.stat()` (which follows symlinks) rather than `sftp.lstat()`:
  1. If a directory being deleted contains a symlink pointing to another directory (e.g., `/var/www` or `~`), `sftp.stat()` reports `S_IFDIR`, causing `rmrf()` to recurse into the symlinked target directory and **delete all files inside the target directory** instead of simply unlinking the symlink.
  2. If a directory contains a broken symlink, `sftp.stat()` fails with `No such file`, aborting the deletion.

- **Proposed Mitigation:**
  Use `sftp.lstat` (`const pLstat = (sftp, p) => new Promise((res, rej) => sftp.lstat(p, (e, s) => (e ? rej(e) : res(s))));`) in `delete` and `rmrf()` so symlinks (and broken symlinks) are unlinked directly with `pUnlink` and never traversed.

---

### 2.2. Snippets Run from `Snippets.jsx` and `CommandPalette.jsx` Skip `{{variable}}` Substitution

- **Status:** **Pending**
- **File:** `web/src/pages/Snippets.jsx` (lines 44–48), `web/src/components/CommandPalette.jsx` (lines 55–59)
- **Issue:**
  `Snippets.jsx` states: *"Use `{{name}}` placeholders — you'll be prompted to fill them when running from a terminal."*
  While `TerminalView.jsx` (lines 71–80) parses `/\{\{\s*([\w.-]+)\s*\}\}/g` and prompts the user for values before executing, `Snippets.jsx` (`runHere`) and `CommandPalette.jsx` send `s.command + '\n'` directly via `sendToTab(activeTabId, ...)` without checking for `{{...}}` placeholders. Clicking **Run** on the Snippets page or in the Command Palette executes the raw un-substituted `{{var}}` string in the remote shell.

- **Proposed Mitigation:**
  Prompt for `{{variable}}` values in `Snippets.jsx` and `CommandPalette.jsx` (or centralize snippet execution in `store.js` / `TerminalView.jsx`) before sending the command to the terminal.

---

### 2.3. Closing a Split Pane (`removePane`) Leaks the Server-Side SSH Session & Store State

- **Status:** **Pending**
- **File:** `web/src/components/TerminalView.jsx` (lines 102–104), `web/src/components/TerminalPane.jsx` (lines 183–193)
- **Issue:**
  When a user closes a split pane via the pane's close button (`removePane(p.id)` in `TerminalView.jsx` line 102), `removePane` only removes the pane from local component state (`setPanes((p) => p.filter((x) => x.id !== paneId))`):
  1. It never calls `paneSenders[`${tab.id}:${paneId}`]?.closeSession?.()`, so the `<TerminalPane>` unmount handler simply closes the WebSocket (which the server treats as a **detach**, keeping the SSH session and shell running in memory for up to an hour or forever if producing output).
  2. It never calls `useStore.getState().unregisterPane(tab.id, paneId)`, leaving stale entries in `paneSenders` and `paneStates` (and if `activePane[tab.id]` was the closed pane, snippet/log/record toolbar actions on that tab stop working because `activePane[tab.id]` still points to the removed pane ID!).

- **Proposed Mitigation:**
  In `TerminalView.jsx::removePane(paneId)`:
  1. Call `useStore.getState().paneSenders[`${tab.id}:${paneId}`]?.closeSession?.()`.
  2. Call `useStore.getState().unregisterPane(tab.id, paneId)`.
  3. Update `activePane` to the remaining pane's ID (`setActivePane(tab.id, remaining[0].id)`).

---

### 2.4. Single-Pass Bastion (`jump_host_id`) Resolution Drops ProxyJump Links During Vault & SSH Config Imports

- **Status:** **Pending**
- **File:** `server/src/routes/backup.js` (lines 177–211), `web/src/components/SshConfigImport.jsx` (lines 80–101)
- **Issue:**
  In both `POST /api/vault/import` (`server/src/routes/backup.js` line 183) and `SshConfigImport.jsx` (line 93), hosts are inserted in a single pass while looking up `jump_host_name` / `proxyjump` in `hostNameToId`. Whenever a host appears before its bastion host in the export file or `~/.ssh/config` (for example, `app-01` jumping through `zed-bastion`), `hostNameToId.get(jumpName)` returns `undefined` at insert time and `jump_host_id` is silently set to `null`.
  Additionally, `/api/vault/export` and `/api/vault/import` do not include `playbooks`, `tunnels`, or the `shared` flag on hosts.

- **Proposed Mitigation:**
  1. Perform a second pass after inserting all hosts in both `server/src/routes/backup.js` and `web/src/components/SshConfigImport.jsx` to link `jump_host_id` once all host names are in `hostNameToId`.
  2. Include `playbooks` and `tunnels` in `/api/vault/export` and `/api/vault/import`.

---

### 2.5. Playbook Runner Assumes POSIX `$?` and Lacks a Step Timeout

- **Status:** **Pending**
- **File:** `server/src/ws/terminal.js` (lines 309–352)
- **Issue:**
  `runPlaybookStep()` writes `${step.command}\necho "__SSLPB_${pb.idx}_${pb.rand}_$?__"\n` to the interactive shell and `scanPlaybook()` waits for `__SSLPB_<idx>_<rand>_(\d+)__`.
  - On `fish` (`$status`), `csh`/`tcsh` (`$status`), Nushell, PowerShell, or network appliance CLIs, `$?` does not expand to an integer, so the regex never matches and `session.playbook` stays stuck in `running` forever.
  - If a command prompts interactively or hangs, there is no step timeout.

- **Proposed Mitigation:**
  Use `sh`-compatible status reporting or execute playbook steps via dedicated `session.conn.exec(step.command)` channels (streaming stdout/stderr to `sessionOutput(sess, chunk)` and reading the real SSH channel exit status code from the `'close'` event `(code, signal)`), which works reliably regardless of the user's interactive login shell and avoids polluting shell history with `__SSLPB_...` marker echoes.

---

## 3. Medium & Low Severity Issues

### 3.1. Logout, Password Change & User Deletion Leave Active WebSockets, SSH Sessions & Shares Open

- **Status:** **Pending**
- **File:** `server/src/routes/auth.js` (lines 104–133), `server/src/routes/admin.js` (lines 49–69), `server/src/ssh/manager.js` (lines 429–437)
- **Issue:**
  `destroySession()` in `server/src/auth.js` (logout), `POST /api/auth/password`, `POST /api/admin/users/:id/password`, and `DELETE /api/admin/users/:id` delete rows from the SQLite `sessions` table, but never close the user's live `/ws/terminal` WebSockets, in-memory SSH `sessions` (`server/src/ssh/manager.js`), or active `tunnels` (`server/src/routes/tunnels.js`). Additionally, `ssh/manager.js::destroySession()` (line 429) does not close attached share viewers (`s.viewers`) or delete `shares` rows from SQLite (unlike the `conn.on('close')` handler at lines 316–322).

- **Proposed Mitigation:**
  1. In `ssh/manager.js::destroySession(sessionId)`, notify and close all `s.viewers` sockets and delete `shares` rows for `sessionId`.
  2. Export `destroyUserSessions(userId)` from `ssh/manager.js` and `stopTunnelsForUser(userId)` from `routes/tunnels.js`, and invoke them on user deletion (`DELETE /api/admin/users/:id`) and admin password reset (`POST /api/admin/users/:id/password`).

---

### 3.2. Client-Side Idle Lock (`IdleLock.jsx`) Resets on Page Reload

- **Status:** **Pending**
- **File:** `web/src/components/IdleLock.jsx` (lines 10–43), `web/src/store.js` (line 21)
- **Issue:**
  `locked` in `useStore` is initialized to `false` in memory and is not persisted in `sessionStorage` or `localStorage`. If `IdleLock` engages after inactivity, anyone with physical access to the browser can press **F5 / Ctrl+R** to reload the page and immediately access all open sessions and the vault without entering the password or PIN.

- **Proposed Mitigation:**
  Persist the locked flag in `localStorage` (`ssloth_locked = '1'`) when `setLocked(true)` is called (and clear it only after `/api/auth/verify` or `/api/auth/pin` succeeds or on logout), initializing `locked: localStorage.getItem('ssloth_locked') === '1'` in `store.js`.

---

### 3.3. Electron `desktop/main.js` Missing `setWindowOpenHandler` and `will-navigate` Guards

- **Status:** **Pending**
- **File:** `desktop/main.js` (lines 93–111)
- **Issue:**
  `TerminalPane.jsx` and `SharePage.jsx` load `@xterm/addon-web-links`, which opens clicked terminal URLs via `window.open(uri, '_blank')`. In Electron (`desktop/main.js`), `createWindow()` does not configure `mainWindow.webContents.setWindowOpenHandler()` or `will-navigate`, so clicking an HTTP/HTTPS URL in terminal output opens an untrusted external website inside a new Electron `BrowserWindow` instead of the user's system browser.

- **Proposed Mitigation:**
  In `desktop/main.js::createWindow(url)`, intercept `setWindowOpenHandler` and `will-navigate` to open external `http:`/`https:` URLs via `shell.openExternal()` and deny in-app navigation away from `serverUrl`.

---

### 3.4. Synchronous `crypto.scryptSync` Blocks the Event Loop During Auth & Vault Operations

- **Status:** **Pending**
- **File:** `server/src/crypto.js` (lines 13–38), `server/src/routes/backup.js` (lines 13–35)
- **Issue:**
  `hashPassword()`, `verifyPassword()`, `sealSecrets()`, and `unsealSecrets()` use `crypto.scryptSync()` (`N=16384` and `N=32768`) on the main Node.js thread, stalling terminal WebSocket I/O for all connected users during login, PIN attempts, and vault export/import.

- **Proposed Mitigation:**
  Convert `hashPassword`, `verifyPassword`, `sealSecrets`, and `unsealSecrets` to use asynchronous `util.promisify(crypto.scrypt)` (or apply `authLimiter` to `/api/vault/export` and `/api/vault/import`).
