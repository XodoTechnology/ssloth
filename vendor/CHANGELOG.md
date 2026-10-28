# Changelog

<!--
Compiled into the binary and shown on the GUI's "What's new" page
(crates/bmc-core/src/changelog.rs), which reads only "## <version> — <date>"
headings, "### <section>" headings and "- " bullets, with `code` spans. Changes since
the last release go under "## Unreleased". The build fails if the version in
Cargo.toml has no "## " heading here, so a release commit renames Unreleased
to its version in the same change as the version bump.
-->

## 0.7.1 — 2026-10-18

### Added

- `bmc-kvm console <host> [secs] [out.ppm]` opens any family's console the
  way the GUI does, watches it, and closes it, printing each stage, the
  frames decoded and what the close released. It sends no input. It also
  rebuilds the screen from only the parts the decoder reported changed, and
  its `damage:` line counts the pixels that disagree, which must be none.

### Fixed

- On Windows, two inventory saves at once (hosts, groups, routes or
  settings) could fail one with "The file exists" and lose the other.
- `bmc-kvm --help` lists every command it accepts again, including `qkvm`,
  `idrac8kvm` and `--ui-shot`, with each console test's real options, and
  says which families `mount-url`, `unmount` and `hotplug` cover.
- Credentials resolve the same way on the command line and in the GUI:
  `--user`/`--password`, then `hosts.json`, then `IKVM_USER`/`IKVM_PASSWORD`,
  then `hosts.ini`. A host given as a hostname, an IP or in brackets matches
  its inventory entry as the GUI matches it, and a `hosts.json` that does not
  parse is reported rather than read as empty.
- A console the BMC ends is now closed, and its BMC sessions released, even
  while the window is not redrawing.
- Closing an SP-X, Avocent or iDRAC 8 console now waits for its web
  session's logout, so a reconnect to the same BMC no longer races it.
- HP iLO 4 hosts show their BIOS version and hardware health in the
  overview again, without spending a web session: the BIOS version comes
  over IPMI and the health from iLO's public identification page, which
  already gave the model and serial number.

### Changed

- iLO 4, iDRAC 9 and iDRAC 8 consoles now redraw only the parts of the
  screen that changed, as the ATEN, AMI and Gigabyte consoles already did,
  instead of the whole picture for every frame.
- The container image carries the command line alone, without `ipmitool`,
  which nothing has needed since IPMI became built in.
- A power, reset or Ctrl+Alt+Del confirmation now expires after two
  minutes: answering one left open longer does nothing but say so, and the
  action has to be asked for again.

## 0.7.0 — 2026-10-17

### Added

- Hosts behind a SOCKS5 proxy or an SSH jump host, or a chain of them, can
  be reached. Define a route once with `bmc-kvm route add`, then set it on a
  group with `bmc-kvm route group` for every host inside, and override it or
  opt out per host with `bmc-kvm route host`. A group key is the full
  "Datacenter / Group" path, and subgroups inherit. `route show` says which
  route each host gets and why, and `route test` checks one stage by stage.
  The routes are kept in `routes.json` and `groups.json` beside the inventory
  and can be edited by hand. A file that does not parse stops the hosts it
  concerns rather than letting them connect directly.
- Consoles, virtual media, power, the event log and sensors all go through
  a host's route. IPMI rides a relay that the jump host runs with `socat`
  (`UDP-SENDTO`) or `nc`. `mount-url` is refused behind a route, because the
  BMC would have to connect back to this machine.
- Every headless command takes `--via <route>` or `--direct` to override the
  saved route for that one command. In the GUI they apply to the host named
  on the command line only.
- The GUI uses routes, and the connect page shows their stages, but it does
  not ask questions yet. A jump host key that nothing vouches for, or a
  password the route does not store, is settled once with
  `bmc-kvm route test <name>` on a terminal.

### Changed

- Adding or editing a host offers the groups and racks already in the
  inventory as you type, with a count of hosts in each, so a new host joins
  its neighbours instead of starting a near-duplicate group. Racks at the
  group's location come first. "Move selected hosts" and the import page's
  default group offer the same list. A new name is still accepted as typed.
- The Windows installer updates an existing install in place: it skips the
  folder page, says which version it replaced, and asks for bmc-kvm to be
  closed if it is still running instead of failing to write the file.
  `setup.exe /S` updates silently and leaves a running copy alone.
- A Supermicro X9 console now presents the client certificate the BMC's own
  Java viewer carries, read from the BMC and cached, rather than only the copy
  built in; the connect screen says which one it used. Firmware that ships a
  renewed certificate is picked up without an update here.
- The BMC clock is moved for an X9 console only when the certificate is not
  valid at the BMC's own time, and then to a month before the certificate
  expires instead of a fixed date in January 2026.
- `bmc-kvm aten-cert <host>` shows that certificate, the date a console would
  set the clock to, and whether the console port accepts it, without moving
  the clock. With `--try` it rolls the clock back, tries the console and media
  ports, and puts the clock (and NTP) back.
- A BMC whose NTP undoes the clock roll-back has NTP paused for the session
  and turned back on, with its own servers, before the clock is restored. NTP
  that was off is left alone.
- A console and a virtual-media mount on one X9 share a single clock
  roll-back, and it is restored only when the last of them closes. One that
  could not be restored, after a crash or a lost reply, is put right the next
  time the app starts.

### Fixed

- Virtual media on Supermicro boards whose media port wants the same client
  certificate as the console now mounts, where it failed with "vmedia port not
  responding to the control handshake"; a refused certificate is said as such.

- Typing in a console no longer falls behind while the mouse pointer rests on
  the picture. The pointer was sent sixty times a second even when it had not
  moved, and Dell iDRAC 8 queued key presses behind it.
- Holding a key in a Dell iDRAC 8 console repeats it, as a local keyboard
  would, instead of typing it once.
- Updating a Windows install made in a folder other than the default no
  longer leaves a second copy in `Program Files`.

## 0.6.0 — 2026-10-17

### Changed

- A new app icon: a console's open edge and a mouse pointer, in teal on a
  dark tile. It replaces the generic monitor in the window, the task bar and
  the installers, sits inside Apple's icon grid on macOS, and now heads the
  README.

### Fixed

- iDRAC 9: if the BMC's session list could not be read when a console or
  mount started, closing it no longer deletes every session on the BMC,
  other people's consoles and virtual media included. Ours are left to time
  out instead, and the app says so, with the reason: in the console while
  it is open, and in the status bar, until dismissed, once it closes.
- Supermicro X9: a console that fails to connect after the BMC's clock was
  set back for its expired certificate now puts the clock back, as does
  closing one whose set-back went unanswered. A clock that cannot be put
  back is reported in the status bar until dismissed, instead of being left
  in January 2026 without a word. The new `bmc-kvm ipmi <host> sel-time now`
  sets it by hand.
- Reconnecting to a host whose previous session is still closing waits for
  the close to finish, and the connecting screen says so, instead of racing
  it: on iDRAC 9 the old close could delete the new console's sessions, and
  on Supermicro X9 set the clock forward again under the new connect. Cancel
  stops the wait, and nothing logs in after it.
- HP iLO 4: the host list's background check no longer reads the server
  over Redfish, which cost one of iLO's few web sessions per request for 30
  minutes and could lock out logins as though the password were wrong. The
  model and serial number now come from iLO's public identification page
  and the power state over IPMI; health and BIOS version are not shown. For
  the same reason the Logs and Sensors tabs' Auto setting reads an iLO over
  IPMI first, and Redfish only if IPMI fails, and neither tab reads a host
  on its own until its BMC type is known.
- Dell iDRAC 8 hosts now show their model, serial number, BIOS version,
  power state and health in the overview. The probe asked for the generic
  Redfish system path, which iDRAC 8 answers with a 404, rather than Dell's.
- Switching between console tabs gives the new console the keyboard at once,
  instead of ignoring key presses until the picture was clicked.

## 0.5.6 — 2026-10-17

### Fixed

- Older Supermicro firmware (seen on an X7SB3, IPMI 3.52) no longer fails
  with "no KVM token": it serves the console launch file only to requests
  that name its console page as the referrer, as a browser does.

## 0.5.5 — 2026-10-17

### Fixed

- Supermicro X10 boards whose firmware has the HTML5 console but still
  requires the Java client's certificate on the console port connect again,
  instead of failing with "handshake failure". Whether the certificate is
  needed is now asked of the port rather than assumed from the generation.

## 0.5.4 — 2026-10-17

### Fixed

- Supermicro X9 boards whose console has no TLS — it answers in plain RFB on
  port 5900 — now connect, instead of failing with "wrong version number". The
  console port is checked before connecting, and the BMC clock is only rolled
  back when the bundled client certificate is actually used.

## 0.5.3 — 2026-10-17

### Fixed

- Supermicro X9 and X10 boards are told apart reliably on every platform. The
  check used the operating system's TLS, which on Windows refuses an X9 for
  reasons of its own, so an X9's console could be opened without the client
  certificate it requires and fail with "handshake failure".

## 0.5.2 — 2026-10-16

### Fixed

- Supermicro X9 boards connect again where the platform's TLS refused them:
  on Windows with "the client and server cannot communicate, because they do
  not possess a common algorithm", and wherever OpenSSL 3 refuses their
  missing renegotiation support. ATEN's login, console and virtual media now
  use OpenSSL configured for old firmware.

## 0.5.1 — 2026-10-16

### Fixed

- Mounting virtual media on an iDRAC 8 no longer fails with "no CD slot to
  map" when it follows an unmount: the mount waits the two seconds the BMC
  takes to present its virtual CD to the host.
- The iDRAC 8 video decoder can no longer be made to hang or crash by a
  malformed stream: runs that never end are refused, and a frame of two-colour
  blocks decodes in linear time.

## 0.5.0 — 2026-10-16

### Added

- Dell iDRAC 8 (PowerEdge 13G): console, keyboard and mouse, virtual media,
  console preview, power and BMC reset. It used to be mistaken for a
  Supermicro board and fail with "login rejected".
- `bmc-kvm idrac8kvm <host>` tests the iDRAC 8 console from the command line,
  and it and `avokvm` take `--mount ISO`.

## 0.4.0 — 2026-10-16

### Added

- A "What's new" page with these notes, opened from the version at the foot
  of the sidebar, from Settings or from the command palette.
- A dot beside "What's new" after an upgrade, until the page is opened.
- `bmc-kvm --version` (or `-V`) prints the version, and `--help` shows it.
- On Linux, a touchpad flick keeps scrolling after the fingers lift, as it
  does in GTK and Qt applications.

### Changed

- A mouse wheel notch scrolls 100 points instead of 40.
- Scroll bars stay faintly visible wherever there is more to scroll to, and
  long pages fade out at the edge instead of cutting a card in half.

### Fixed

- ASRock Rack and other AMI SP-X consoles no longer lose what is typed in
  their first seconds. On a BMC in USB power-save mode the host only gets the
  keyboard a few seconds after the console opens; keys typed before then are
  now held and sent once it has it, with a notice saying so.

## 0.3.0 — 2026-10-16

### Added

- ASRock Rack / AMI SP-X consoles work. The handshake now sends the bare
  connection-complete header both vendor viewers send first, and older
  firmware gets its token from `/api/kvm/token`.
- SP-X virtual media, over the Java viewer's tunnel on :443. Lenovo TSM, whose
  web server refuses that tunnel, falls back to the web viewer's WebSocket.
- Native IPMI (RMCP+, cipher suite 17 falling back to 3) for power, BMC reset,
  the X9 clock, the event log and sensors, so `ipmitool` is no longer needed.
  `bmc-kvm ipmi <host> …` runs it headless.
- Paste as keystrokes (Keyboard menu, Ctrl+Shift+V): the text is shown before
  it is typed, then typed with progress and Stop.
- One dialog answers another user's request for a console you hold: iLO seize
  requests, and AMI requests for full access, view-only or deny. Connecting to
  a busy iLO offers "Take over" instead of seizing it.
- The brand is named apart from the firmware: ASUS, Lenovo, Intel and others
  running AMI firmware, and Dell running Avocent, get their own labels and
  marks.
- Dell PowerEdge C boards, as the Avocent family.
- A console that ends on screen says why, how long it ran and what the BMC
  last reported, with Reconnect, instead of dropping back to the list.

### Changed

- The console uploads only the part of the screen that changed, and only when
  a frame arrives, instead of the whole framebuffer on every repaint.
- Tab, Escape, the arrow keys and Ctrl+K/P/N go to the console while it has
  focus.

### Fixed

- AST2300 video (AMI and Avocent): quantisation tables, refinement blocks and
  blocks at the right edge now decode as the vendor viewers do.
- SP-X waits up to 45 s for another console's holder to answer the BMC's
  access prompt, instead of giving up at 15 s.
- Ctrl+X, Ctrl+C and Ctrl+V reach the console as key presses.
- IPMI tries cipher suite 3 even when suite 17 reports a wrong password, as
  the Lenovo TSM does with the right one.
- Intel's build of the ATEN firmware logs in.
- A failed iLO channel open logs the web session out instead of holding one of
  its few slots.

## 0.2.0 — 2026-09-29

### Added

- A new workspace: a host table with groups, a host page with the Redfish
  event log and sensors, saved credentials, discovery and bulk import, a
  command palette (Ctrl+K), and several consoles open at once.
- Virtual media from a URL. iLO and iDRAC fetch the image themselves; every
  other family has it fetched here and served down the usual channel.
- iLO virtual media mounts `.img` files as a USB drive, and answers more of
  the CD commands a host asks for.
- Opening a console shows each stage as it happens, with Cancel, and Retry if
  it fails.
- Installers: a `.deb`, a `.dmg` and a Windows `setup.exe`, alongside the bare
  binaries.

### Changed

- Every action that touches the network runs in the background and shows that
  it is running: power, BMC reset, mount, eject, probes and disconnect. A
  second click no longer sends a second command.

### Fixed

- The Windows binary starts on machines without a desktop, such as Server
  Core, so the headless subcommands run there.
- The confirmation dialog is sized to its contents.

## 0.1.0 — 2026-09-28

### Added

- A native KVM console (video, keyboard and mouse) for Supermicro / ATEN
  (X9, X10, X11/X12), Quanta / AMI MegaRAC, HP iLO 4, Dell iDRAC 9 and
  Gigabyte / Avocent MergePoint, detected automatically. ASRock Rack / AMI
  SP-X is detected and has power control.
- Virtual media from a local ISO, served from this machine, so it works when
  the BMC cannot connect back.
- Power control and BMC reset.
- Console previews from the BMC's own snapshot (ATEN, iDRAC), and on request
  for iLO 4.
- A host inventory with live reachability, power and model, marked with the
  vendor's logo.
- Live stats: resolution, frame rate, bitrate, virtual-media counters, and
  network, console and frame latency.
- Headless subcommands for power, virtual media and per-family console tests.
- `bmc-kvm install` adds a desktop entry and icon.
- Builds for Linux, Windows and macOS.
