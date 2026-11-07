# ssloth roadmap

Remaining feature work, in dependency order. Each step lists what it touches
and what "done" looks like. Check items off as they land.

## Phase 1 — close the verification gaps (no new code, just hardware time)

- [x] **SP-X/Gooxi**: preview snapshot, BMC reset, unmount, seize/takeover —
      preview/reset/unmount/same-user takeover verified on the Datto SP-X
      (10.51.0.10); different-user takeover prompt still needs a second
      BMC account to prove.
- [ ] **CIMC (UCS C220)**: power + reset — wired but deliberately untested.
      Blocked: no working credentials (cloudie/? and Administrator/? both
      rejected).
- [ ] **iLO5**: seize/takeover negotiation on a contended console. Blocked:
      Administrator credentials rejected.
- [x] **SFTP resume**: auto-resume shipped (`f96f042`) — verified end-to-end
      with exact size + SHA-256 match after interruption.
- [ ] **BMC dashboard**: live-verify exclusion toggle + sweep error surfacing
      on the deployed build.

## Phase 2 — alerting ✅ landed

- [x] **Sensor alert rules** (`8fe3ffa`): `sensor_alert_rules` table, per-host /
      per-sensor / warn-or-bad floors, evaluated on status-tier *transitions*
      in `sensors-poll.js`; recovery notices too. Delivery: in-app bell,
      registered webhooks (SSRF-guarded), audit records. UI: collapsible
      "Sensor alerts" editor on the BMC dashboard.
- [x] **Persist sensor history** (`8fe3ffa`): `sensor_history` SQLite table,
      throttled writes alongside the in-memory ring; `/api/hosts/:id/sensors/history`
      serves it. Hourly/daily rollups still open.
- [x] **Browser notifications** (`953378d`): Notification API alerts for new
      feed items (sensor alerts + watch hits), opt-in via the bell dropdown,
      click focuses tab + follows link. True Web Push (closed tab) deferred —
      needs VAPID + a push service.

## Phase 3 — fleet ops ✅ landed

- [x] **Host groups** (`480792a`): `host_groups` + `host_group_members`,
      CRUD under `/api/bmc/groups`, BMC-scoped. Dashboard group picker fills
      the bulk selection; "save as group" from any selection.
- [x] **Bulk BMC dashboard actions** (`480792a`): `POST /api/bmc/bulk` —
      power on/off/cycle/reset, BMC reset, exclude/include monitoring across
      selected hosts at concurrency 4 with per-host results. Checkbox
      selection + action bar on the dashboard.
- [ ] **Bulk ops beyond BMC**: power/connect/playbook/WoL across SSH host
      groups — needs the groups entity generalized off `protocol='bmc'`
      and a sessions-page group selector.

## Phase 4 — sharing + polish

- [x] **KVM console share links** (`f88eb7a`): view-only shares for live BMC
      consoles — `shares.kind`, ws/kvm framebuffer fan-out to viewers,
      canvas viewer on SharePage, Share button in KvmPane. Verified
      end-to-end on the Datto SP-X (59 frames fanned out, close propagated).
      Control-mode shares deliberately unsupported — revisit only if a real
      use case appears.
- [x] **Worst-offenders sort**: `/api/bmc/overview?sort=worst` orders by bad
      then warn sensor counts; dashboard "worst first" toggle.
- [x] **API token scope docs**: README "API tokens" section — scopes, the
      route allowlist, WS exclusion, expiry. (`slo_` tokens were already
      enforced via `TOKEN_SCOPE_ROUTES`; they were just undocumented.)
- [x] **Login rate limit**: `/login` now also keys on username (8/15min)
      behind the per-IP 30/15min — credential stuffing across rotating IPs
      stalls per-account.
- [x] **In-app notification center** (`8fe3ffa`): `notifications` table +
      bell dropdown — unread badge, mark read/all, delete, deep links.
      Watch hits feed it too (5-min per-label cooldown).

## Deferred / maybe

- OIDC/SSO for multi-user deployments.
- Mobile-optimized KVM view.
- BMC credential vault integration (some orgs keep BMC creds in a separate
  PAM — an import adapter could map them onto `credentials`).
- Web Push (VAPID) for notifications when the browser is closed.
- Sensor history rollups (hourly/daily) + fleet "worst offenders" sort.
