# ssloth roadmap

Remaining feature work, in dependency order. Each step lists what it touches
and what "done" looks like. Check items off as they land.

## Phase 1 — close the verification gaps (no new code, just hardware time)

- [ ] **SP-X/Gooxi**: preview snapshot, BMC reset, unmount, seize/takeover
      negotiation — console/power/sensors/SEL/media all proven; these four
      paths exist but are unverified on live hardware.
- [ ] **CIMC (UCS C220)**: power + reset — wired but deliberately untested.
- [ ] **iLO5**: seize/takeover negotiation on a contended console.
- [ ] **SFTP resume**: interrupt a real transfer mid-flight (kill server,
      flap the link) and confirm `append=1` picks up where it left off.
- [ ] **BMC dashboard**: live-verify exclusion toggle + sweep error surfacing
      on the deployed build.

## Phase 2 — alerting (builds on sensors-poll data that already exists)

- [ ] **Sensor alert rules**: per-host or fleet rules
      (`sensor matches X`, `status != ok`, `reading > threshold`) →
      webhook + toast + audit on state *transitions* only (no spam on every
      poll). Store rules in a `sensor_rules` table; evaluate inside
      `sensors-poll.js` sweep; notify via `notify.js` + `watch_hit`-style
      ws push.
- [ ] **Persist sensor history**: roll samples into SQLite
      (`sensor_samples` table or hourly rollup) so trends survive restarts;
      feed the existing sparklines + add a fleet-wide "worst offenders"
      sort on `/api/bmc/overview`.
- [ ] **Browser push for watch hits + sensor alerts**: Notification API
      permission in Settings; fire on `watch_hit` and alert transitions
      even when the tab is backgrounded.

## Phase 3 — fleet ops (needs groups)

- [ ] **Host groups/tags entity**: promote `folder`+`tags` into a first-class
      `groups` table (name, members, shared flag); bulk-select UI on the
      Sessions page; keep folders as the visual grouping, groups as the
      action target.
- [ ] **Bulk ops**: power on/off/reset, connect, run playbook, WoL across a
      group selection — sequential with per-host result reporting (reuse
      the playbook-run history table for the audit trail).
- [ ] **Bulk BMC dashboard actions**: fleet power, mount/unmount, exclude —
      the overview endpoint already returns everything needed.

## Phase 4 — sharing + polish

- [ ] **KVM console share links**: read-only (maybe control) share for BMC
      consoles — `shares` table + ws plumbing exist for ssh sessions; kvm
      sessions need the same viewer path (`session.ws` fan-out is
      ssh-specific today). Decide deliberately whether BMC consoles should
      be shareable at all — they're the most sensitive surface.
- [ ] **API token scope docs**: tokens can't touch websockets — document in
      Settings/API page; optionally add a `kvm` scope if a use case appears.
- [ ] **Login rate limit**: also key on username (shared-NAT lockout).
- [ ] **In-app notification center**: persist watch hits / alerts / scheduled
      playbook results into a `notifications` table with an unread badge —
      today they only exist as transient toasts.

## Deferred / maybe

- OIDC/SSO for multi-user deployments.
- Mobile-optimized KVM view.
- BMC credential vault integration (some orgs keep BMC creds in a separate
  PAM — an import adapter could map them onto `credentials`).
