//! Temporary BMC clock control for X9 (expired KVM cert). Rolls the RTC back
//! into the client certificate's validity before a TLS handshake and restores
//! real time when the last console or mount on that BMC closes, over IPMI.
//!
//! A console and a mount on one BMC share one roll-back through `Hold`: the
//! first that needs it rolls the clock (pausing the BMC's NTP if it runs, or
//! it pulls the clock forward again within seconds), each re-checks the clock
//! before its own handshake, and only the last to let go restores NTP and the
//! clock. What is owed is journalled before it is done, so a crash or a
//! failed restore is put right on the next run.
//!
//! Set SEL Time takes seconds since the epoch, so this goes through the native
//! client rather than `ipmitool`, whose `sel time set` wanted a date string in
//! a locale-dependent format that had to be guessed at.

use crate::families::aten::ntp;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Why a roll-back failed, and whether it could have moved the clock anyway.
#[derive(Debug)]
pub enum RollBackError {
    /// No IPMI session, so Set SEL Time was never sent: the clock is as it was.
    NotSent(String),
    /// Sent, without a good answer: the BMC may have acted on it regardless.
    Sent(String),
}

/// Set the RTC to `t` (seconds since the epoch) so the client certificate
/// validates.
pub fn roll_back_to(host: &str, user: &str, pass: &str, t: i64) -> Result<(), RollBackError> {
    // Set SEL Time by hand rather than through `ipmi::set_sel_time`, to tell a
    // session that never opened from a request that went unanswered.
    let mut s = crate::ipmi::Session::open(host, user, pass)
        .map_err(|e| RollBackError::NotSent(e.to_string()))?;
    s.call(crate::ipmi::NETFN_STORAGE, 0x49, &(t as u32).to_le_bytes())
        .map(|_| ())
        .map_err(|e| RollBackError::Sent(e.to_string()))
}

/// How far inside the certificate's validity a rolled-back clock is set.
const MARGIN: i64 = 30 * 86400;

/// Where to set a BMC clock reading `bmc_now` so that a client certificate
/// valid `not_before..not_after` is accepted, or None to leave it alone.
///
/// Left alone when the certificate is valid at the BMC's time and stays so for
/// a day, which covers a session and its reconnects (X9 checks only at the
/// handshake) — but only if it is valid at ours too. A BMC whose clock reads
/// inside an expired certificate's validity was most likely left rolled back
/// by a restore that never ran; rolling it again is what makes this session
/// owe, and run, the restore that puts it right. Otherwise set it a month before expiry: as late as possible, so the event
/// log the BMC keeps stamping during the session is as near the truth as it
/// can be, yet far enough inside that RTC drift, a session left open for
/// weeks or a restore that never ran do not carry it past `not_after`. A
/// window too short for that margin gets its midpoint. The same arithmetic
/// moves a BMC whose RTC reset to 1970 *forward* into the window.
pub fn roll_back_target(not_before: i64, not_after: i64, bmc_now: i64, our_now: i64)
    -> Option<i64>
{
    let w = (not_before, not_after);
    (!(inside(w, bmc_now) && inside(w, our_now))).then(|| target(w))
}

/// `t` is inside the validity window `w` with a day to spare.
fn inside(w: (i64, i64), t: i64) -> bool {
    w.0 <= t && t + 86400 < w.1
}

/// Where a roll-back into `w` sets the clock (see `roll_back_target`).
fn target((not_before, not_after): (i64, i64)) -> i64 {
    if not_after - not_before > 2 * MARGIN {
        not_after - MARGIN
    } else {
        not_before + (not_after - not_before) / 2
    }
}

/// The BMC's own clock, or ours where it cannot be read: a BMC is usually set
/// from NTP or the host, and a roll-back that turns out unnecessary only
/// costs a restore.
pub fn bmc_now(host: &str, user: &str, pass: &str) -> i64 {
    crate::ipmi::sel_time(host, user, pass).map(i64::from).unwrap_or_else(|_| our_now())
}

/// This machine's clock, in seconds since the epoch.
pub fn our_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

/// `t` as a UTC time, YYYY-MM-DD HH:MM:SS.
pub fn stamp(t: i64) -> String {
    let s = t.rem_euclid(86400);
    format!("{} {:02}:{:02}:{:02}", date(t), s / 3600, s / 60 % 60, s % 60)
}

/// `t` as a UTC date, YYYY-MM-DD, for the status line.
pub fn date(t: i64) -> String {
    let (y, m, d) = civil(t.div_euclid(86400));
    format!("{y:04}-{m:02}-{d:02}")
}

/// Restore the BMC clock to the current time.
///
/// A failure has to reach the user: nothing else will notice the BMC still
/// running months in the past and stamping its event log with that date.
pub fn restore(host: &str, user: &str, pass: &str) -> Result<(), String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    crate::ipmi::set_sel_time(host, user, pass, now as u32).map_err(|e| e.to_string())
}

/// What to tell the user when `restore` fails, and how they can do it instead.
pub fn not_restored(host: &str, e: &str) -> String {
    format!("{host}: could not restore the BMC clock: {e}; set it with \
`bmc-kvm ipmi {host} sel-time now`")
}


/// The BMC, as far as the roll-back needs it. A trait so the bookkeeping can
/// be tested without one.
pub trait Bmc {
    fn now(&mut self) -> Result<i64, String>;
    fn set(&mut self, t: i64) -> Result<(), RollBackError>;
    fn restore(&mut self) -> Result<(), String>;
    fn ntp_read(&mut self) -> Result<ntp::Settings, String>;
    fn ntp_write(&mut self, s: &ntp::Settings, on: bool, wall: &ntp::Wall) -> Result<(), String>;
}

/// The real one: IPMI for the clock, the web UI for NTP.
pub struct Live<'a> {
    pub host: &'a str,
    pub user: &'a str,
    pub pass: &'a str,
}

impl Bmc for Live<'_> {
    fn now(&mut self) -> Result<i64, String> {
        crate::ipmi::sel_time(self.host, self.user, self.pass).map(i64::from).map_err(|e| e.to_string())
    }
    fn set(&mut self, t: i64) -> Result<(), RollBackError> {
        roll_back_to(self.host, self.user, self.pass, t)
    }
    fn restore(&mut self) -> Result<(), String> {
        restore(self.host, self.user, self.pass)
    }
    fn ntp_read(&mut self) -> Result<ntp::Settings, String> {
        ntp::read(self.host, self.user, self.pass)
    }
    fn ntp_write(&mut self, s: &ntp::Settings, on: bool, wall: &ntp::Wall) -> Result<(), String> {
        ntp::write(self.host, self.user, self.pass, s, on, wall)
    }
}

/// What a BMC is owed: its clock restored, and its NTP settings written back.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Owed {
    pub host: String,
    pub clock: bool,
    pub ntp: Option<ntp::Settings>,
}

impl Owed {
    fn nothing(&self) -> bool {
        !self.clock && self.ntp.is_none()
    }
}

/// What is owed, on disk, so that it outlives a crash. Written *before* the
/// change it records, so the worst a crash leaves is a restore that was not
/// needed.
pub struct Journal(pub PathBuf);

impl Journal {
    pub fn standard() -> Journal {
        Journal(crate::hosts::config_dir().join("clock-journal.json"))
    }

    pub fn load(&self) -> Vec<Owed> {
        std::fs::read(&self.0).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    fn get(&self, host: &str) -> Option<Owed> {
        self.load().into_iter().find(|o| o.host == host)
    }

    /// Record `o` as the host's entry; an entry owing nothing is removed.
    fn put(&self, o: &Owed) {
        let mut all: Vec<Owed> = self.load().into_iter().filter(|e| e.host != o.host).collect();
        if !o.nothing() {
            all.push(o.clone());
        }
        let r = if all.is_empty() {
            match std::fs::remove_file(&self.0) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            }
        } else {
            std::fs::create_dir_all(self.0.parent().unwrap_or(std::path::Path::new(".")))
                .and_then(|_| std::fs::write(&self.0, serde_json::to_vec_pretty(&all).unwrap()))
        };
        if let Err(e) = r {
            eprintln!("clock: could not update {}: {e}", self.0.display());
        }
    }
}

struct Entry {
    holders: usize,
    owed: Owed,
    /// NTP has been looked at, so it is not read again on every re-check.
    ntp_checked: bool,
}

/// Every BMC whose clock this process holds, and what it owes.
#[derive(Default)]
pub struct Holds(Vec<Entry>);

static HOLDS: Mutex<Holds> = Mutex::new(Holds(Vec::new()));

/// Whether a roll-back may pause a running NTP (`--no-ntp` says not).
static NTP_ALLOWED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Leave the BMC's NTP alone even where it would undo a roll-back.
pub fn leave_ntp_alone() {
    NTP_ALLOWED.store(false, std::sync::atomic::Ordering::SeqCst);
}

impl Holds {
    fn entry(&mut self, host: &str) -> &mut Entry {
        let i = self.0.iter().position(|e| e.owed.host == host).expect("taken before use");
        &mut self.0[i]
    }

    /// One more holder for `host`. The first adopts whatever the journal
    /// says an earlier run left owing, so this session puts it right.
    pub fn take(&mut self, host: &str, journal: &Journal) {
        if let Some(e) = self.0.iter_mut().find(|e| e.owed.host == host) {
            e.holders += 1;
            return;
        }
        let owed = journal.get(host).unwrap_or(Owed { host: host.into(), ..Default::default() });
        self.0.push(Entry { holders: 1, ntp_checked: owed.ntp.is_some(), owed });
    }

    /// Make sure the BMC clock is inside the certificate's validity `w` for
    /// a handshake about to happen, rolling it (again) if it is not.
    pub fn ensure(&mut self, host: &str, journal: &Journal, bmc: &mut dyn Bmc, w: (i64, i64),
                  our_now: i64, say: &dyn Fn(&str)) -> Result<(), String>
    {
        const TRIES: usize = 3;
        let mut last_read = None;
        for attempt in 0..=TRIES {
            let e = self.entry(host);
            let bmc_now = match bmc.now() {
                Ok(t) => t,
                // Set and unreadable: trust the set rather than spin on it.
                Err(_) if attempt > 0 => return Ok(()),
                // Unreadable before a handshake: assume it needs setting,
                // which costs a Set SEL Time and nothing else.
                Err(err) => {
                    say(&format!("could not read the BMC clock ({err})"));
                    our_now
                }
            };
            // Once rolled, only the BMC's clock matters; until then, a clock
            // valid at the BMC's time but not ours was left rolled back by an
            // earlier run and is rolled again so this session owes the restore.
            let fine = inside(w, bmc_now) && (e.owed.clock || inside(w, our_now));
            if fine {
                return Ok(());
            }
            if attempt == TRIES {
                last_read = Some(bmc_now);
                break;
            }
            if (attempt > 0 || e.owed.clock) && bmc_now != our_now {
                // Rolled already, and moved since: by its NTP, or by
                // whatever else sets the clock on that BMC.
                say(&format!("the BMC clock has moved to {} since it was set; setting it again…",
                             stamp(bmc_now)));
            }
            // Only now that a roll-back is needed is NTP looked at, and only
            // a running one is touched: what was off stays off.
            if !e.ntp_checked && NTP_ALLOWED.load(std::sync::atomic::Ordering::SeqCst) {
                e.ntp_checked = true;
                match bmc.ntp_read() {
                    Ok(s) if s.ntp => {
                        say("pausing the BMC's NTP for the session…");
                        e.owed.ntp = Some(s.clone());
                        journal.put(&e.owed);
                        // The save carries the wall clock too: send back the
                        // one just read, so turning NTP off moves nothing.
                        let wall = s.wall.clone().unwrap_or_else(|| ntp::Wall::at(bmc_now, &s));
                        if let Err(err) = bmc.ntp_write(&s, false, &wall) {
                            // Owed regardless: a failed save may have half
                            // applied, and turning NTP on is what it was.
                            say(&format!("could not pause the BMC's NTP ({err})"));
                        }
                    }
                    Ok(_) => {}
                    Err(err) => say(&format!("could not read the BMC's NTP setting ({err})")),
                }
            }
            let t = target(w);
            say(&format!("rolling BMC clock back to {} (client certificate expired {})…",
                         date(t), date(w.1)));
            let was = e.owed.clock;
            e.owed.clock = true;
            journal.put(&e.owed);
            match bmc.set(t) {
                // A lost reply may still have moved the clock: owed either way.
                Ok(()) => {}
                Err(RollBackError::Sent(err)) => say(&format!("no answer to Set SEL Time ({err}); \
checking the clock…")),
                Err(RollBackError::NotSent(err)) => {
                    e.owed.clock = was;
                    journal.put(&e.owed);
                    return Err(format!("the BMC clock could not be rolled back: {err}"));
                }
            }
        }
        let paused = self.entry(host).owed.ntp.is_some();
        Err(format!("the BMC clock will not stay inside the client certificate's validity: set to {}, it read {} again. Something keeps resetting it, most likely the BMC's NTP{}; turn NTP off on the BMC for the session", date(target(w)), date(last_read.unwrap_or(our_now)),
            if paused { ", although it was paused" } else { "" }))
    }

    /// One holder fewer for `host`. The last puts back NTP, then the clock,
    /// and says what it could not.
    pub fn release(&mut self, host: &str, journal: &Journal, bmc: &mut dyn Bmc, our_now: i64)
        -> Option<String>
    {
        let i = self.0.iter().position(|e| e.owed.host == host)?;
        self.0[i].holders -= 1;
        if self.0[i].holders > 0 {
            return None;
        }
        let mut owed = self.0.remove(i).owed;
        let mut problems = Vec::new();
        // NTP first: turning it back on carries a wall clock of its own, and
        // the restore below then sets the exact time over IPMI.
        if let Some(s) = owed.ntp.clone() {
            match bmc.ntp_write(&s, true, &ntp::Wall::at(our_now, &s)) {
                Ok(()) => owed.ntp = None,
                Err(e) => problems.push(format!("could not turn the BMC's NTP back on: {e}; turn it on in the BMC's web UI (Configuration, Date and Time)")),
            }
        }
        if owed.clock {
            match bmc.restore() {
                Ok(()) => owed.clock = false,
                Err(e) => problems.push(not_restored(host, &e)),
            }
        }
        journal.put(&owed);
        (!problems.is_empty()).then(|| {
            let joined = problems.join("; ");
            if joined.starts_with(host) { joined } else { format!("{host}: {joined}") }
        })
    }
}

/// A console's or a mount's claim on a BMC clock rolled back for the client
/// certificate valid over `window`. Released explicitly where the caller can
/// show a problem, else on drop.
pub struct Hold {
    host: String,
    user: String,
    pass: String,
    window: (i64, i64),
    released: bool,
}

impl Hold {
    /// Claim `host`'s clock. Nothing reaches the BMC until `ensure`.
    pub fn take(host: &str, user: &str, pass: &str, window: (i64, i64)) -> Hold {
        HOLDS.lock().unwrap().take(host, &Journal::standard());
        Hold { host: host.into(), user: user.into(), pass: pass.into(), window, released: false }
    }

    /// See `Holds::ensure`; call it just before every TLS handshake, since a
    /// BMC's NTP may have moved the clock since the last one.
    pub fn ensure(&self, say: &dyn Fn(&str)) -> Result<(), String> {
        let mut bmc = Live { host: &self.host, user: &self.user, pass: &self.pass };
        HOLDS.lock().unwrap().ensure(&self.host, &Journal::standard(), &mut bmc, self.window,
                                     our_now(), say)
    }

    /// Whether NTP is paused on this BMC for the session.
    pub fn ntp_paused(&self) -> bool {
        HOLDS.lock().unwrap().0.iter().any(|e| e.owed.host == self.host && e.owed.ntp.is_some())
    }

    /// Let go; the last holder restores. What could not be restored comes back.
    pub fn release(mut self) -> Option<String> {
        self.released = true;
        self.give_back()
    }

    fn give_back(&self) -> Option<String> {
        let mut bmc = Live { host: &self.host, user: &self.user, pass: &self.pass };
        HOLDS.lock().unwrap().release(&self.host, &Journal::standard(), &mut bmc, our_now())
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        if !self.released {
            if let Some(p) = self.give_back() {
                eprintln!("{p}");
            }
        }
    }
}

/// Whether this process holds `host`'s clock (a console on it is up).
pub fn held(host: &str) -> bool {
    HOLDS.lock().unwrap().0.iter().any(|e| e.owed.host == host)
}

/// Put right what an earlier run left owing — a clock not restored, NTP not
/// turned back on — on every BMC in the journal that `creds` knows. Returns
/// what still could not be.
pub fn recover(creds: impl Fn(&str) -> Option<(String, String)>) -> Vec<String> {
    let mut problems = Vec::new();
    for owed in Journal::standard().load() {
        // A BMC this process already holds is put right when it lets go.
        if held(&owed.host) {
            continue;
        }
        match creds(&owed.host) {
            Some((user, pass)) => {
                let hold = Hold::take(&owed.host, &user, &pass, (0, 0));
                problems.extend(hold.release());
            }
            None => problems.push(format!("{}: an earlier session left its clock or NTP to put back, and there are no saved credentials to do it with; run `bmc-kvm ipmi {} sel-time now`",
                                          owed.host, owed.host)),
        }
    }
    problems
}

/// The proleptic Gregorian date `z` days after 1970-01-01 (Hinnant's algorithm).
pub fn civil(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + (m <= 2) as i64, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    // The X9 viewer's certificate: 2016-05-19 09:46:36 .. 2026-05-17 09:46:36.
    const NB: i64 = 1_463_651_196;
    const NA: i64 = 1_779_011_196;
    const DAY: i64 = 86400;
    const TODAY: i64 = 1_792_195_200; // 2026-10-17, after the certificate expired

    #[test]
    fn dates_print_as_utc_days() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(NB), "2016-05-19");
        assert_eq!(date(NA), "2026-05-17");
        assert_eq!(date(951_782_400), "2000-02-29");
    }

    #[test]
    fn an_expired_certificate_rolls_the_clock_to_a_month_before_expiry() {
        // Today (2026-10-17) is past its notAfter.
        let t = roll_back_target(NB, NA, TODAY, TODAY).unwrap();
        assert_eq!(t, NA - 30 * DAY);
        assert_eq!(date(t), "2026-04-17");
        assert!(NB < t && t < NA);
    }

    #[test]
    fn a_certificate_valid_now_leaves_the_clock_alone() {
        assert_eq!(roll_back_target(NB, NA, NB, NB), None);
        assert_eq!(roll_back_target(NB, NA, NA - 2 * DAY, NA - 2 * DAY), None);
    }

    #[test]
    fn a_bmc_left_rolled_back_is_rolled_again_so_the_session_restores_it() {
        // Valid at the BMC's time, not at ours: a restore that never ran.
        assert_eq!(roll_back_target(NB, NA, NA - 30 * DAY, TODAY), Some(NA - 30 * DAY));
    }

    #[test]
    fn a_certificate_expiring_within_a_day_still_rolls_back() {
        assert_eq!(roll_back_target(NB, NA, NA - DAY / 2, NA - DAY / 2), Some(NA - 30 * DAY));
    }

    #[test]
    fn a_clock_before_the_certificate_is_moved_forward_into_it() {
        // An RTC that reset to the epoch.
        assert_eq!(roll_back_target(NB, NA, 0, NB + DAY), Some(NA - 30 * DAY));
    }

    #[test]
    fn a_short_certificate_gets_its_midpoint() {
        let (nb, na) = (NB, NB + 40 * DAY);
        assert_eq!(roll_back_target(nb, na, na + DAY, na + DAY), Some(nb + 20 * DAY));
    }

    /// A BMC in memory. With `ntp_fights`, its NTP puts the clock back to
    /// `real` on every read for as long as NTP is on.
    struct Fake {
        clock: i64,
        real: i64,
        ntp: ntp::Settings,
        ntp_fights: bool,
        unreachable: bool,
        restore_fails: bool,
        log: RefCell<Vec<String>>,
    }

    impl Fake {
        fn new(ntp_on: bool) -> Fake {
            Fake {
                clock: TODAY,
                real: TODAY,
                ntp: ntp::Settings {
                    ntp: ntp_on, server_pri: "ntp.example.com".into(), server_2nd: String::new(),
                    timezone: "0".into(), dst_en: "0".into(), wall: None,
                },
                ntp_fights: false,
                unreachable: false,
                restore_fails: false,
                log: RefCell::new(Vec::new()),
            }
        }
        fn log(&self) -> Vec<String> { self.log.borrow().clone() }
    }

    impl Bmc for Fake {
        fn now(&mut self) -> Result<i64, String> {
            if self.ntp.ntp && self.ntp_fights {
                self.clock = self.real;
            }
            Ok(self.clock)
        }
        fn set(&mut self, t: i64) -> Result<(), RollBackError> {
            if self.unreachable {
                return Err(RollBackError::NotSent("no answer on UDP 623".into()));
            }
            self.log.borrow_mut().push(format!("set {}", date(t)));
            self.clock = t;
            Ok(())
        }
        fn restore(&mut self) -> Result<(), String> {
            self.log.borrow_mut().push("restore".into());
            if self.restore_fails {
                return Err("no reply".into());
            }
            self.clock = self.real;
            Ok(())
        }
        fn ntp_read(&mut self) -> Result<ntp::Settings, String> {
            self.log.borrow_mut().push("ntp read".into());
            Ok(self.ntp.clone())
        }
        fn ntp_write(&mut self, s: &ntp::Settings, on: bool, _: &ntp::Wall) -> Result<(), String> {
            self.log.borrow_mut().push(format!("ntp {}", if on { "on" } else { "off" }));
            self.ntp = ntp::Settings { ntp: on, ..s.clone() };
            Ok(())
        }
    }

    fn journal(name: &str) -> Journal {
        let j = Journal(std::env::temp_dir().join(format!("bmc-kvm-clock-{name}-{}.json",
                                                          std::process::id())));
        let _ = std::fs::remove_file(&j.0);
        j
    }

    const W: (i64, i64) = (NB, NA);
    const H: &str = "192.0.2.20";
    fn quiet(_: &str) {}

    #[test]
    fn a_console_and_a_mount_share_one_roll_back_and_one_restore() {
        let (j, mut b, mut h) = (journal("share"), Fake::new(false), Holds::default());
        h.take(H, &j);
        h.ensure(H, &j, &mut b, W, TODAY, &quiet).unwrap();
        h.take(H, &j);
        h.ensure(H, &j, &mut b, W, TODAY, &quiet).unwrap();
        assert_eq!(b.log(), ["ntp read", "set 2026-04-17"]);
        assert_eq!(j.get(H).map(|o| o.clock), Some(true));
        assert_eq!(h.release(H, &j, &mut b, TODAY), None);
        assert_eq!(b.log().last().unwrap(), "set 2026-04-17");
        assert_eq!(h.release(H, &j, &mut b, TODAY), None);
        assert_eq!(b.log().last().unwrap(), "restore");
        assert_eq!(j.get(H), None);
    }

    #[test]
    fn a_certificate_valid_now_touches_neither_clock_nor_ntp() {
        let (j, mut b, mut h) = (journal("valid"), Fake::new(true), Holds::default());
        h.take(H, &j);
        h.ensure(H, &j, &mut b, (NB, TODAY + 365 * DAY), TODAY, &quiet).unwrap();
        assert_eq!(h.release(H, &j, &mut b, TODAY), None);
        assert!(b.log().is_empty());
    }

    #[test]
    fn running_ntp_is_paused_before_the_roll_back_and_back_on_before_the_restore() {
        let (j, mut b, mut h) = (journal("ntp"), Fake::new(true), Holds::default());
        b.ntp_fights = true;
        h.take(H, &j);
        h.ensure(H, &j, &mut b, W, TODAY, &quiet).unwrap();
        let saved = j.get(H).unwrap();
        assert_eq!(saved.ntp.as_ref().map(|s| s.server_pri.as_str()), Some("ntp.example.com"));
        assert_eq!(h.release(H, &j, &mut b, TODAY), None);
        assert_eq!(b.log(), ["ntp read", "ntp off", "set 2026-04-17", "ntp on", "restore"]);
        assert!(b.ntp.ntp);
        assert_eq!(j.get(H), None);
    }

    #[test]
    fn ntp_that_was_off_is_left_off() {
        let (j, mut b, mut h) = (journal("off"), Fake::new(false), Holds::default());
        h.take(H, &j);
        h.ensure(H, &j, &mut b, W, TODAY, &quiet).unwrap();
        h.release(H, &j, &mut b, TODAY);
        assert!(!b.log().iter().any(|l| l.starts_with("ntp o")));
    }

    #[test]
    fn a_clock_that_keeps_being_reset_is_tried_a_few_times_then_blamed_on_ntp() {
        let (j, mut b, mut h) = (journal("fight"), Fake::new(true), Holds::default());
        b.ntp_fights = true;
        // NTP that ignores being paused: the write is logged but it stays on.
        struct Stubborn(Fake);
        impl Bmc for Stubborn {
            fn now(&mut self) -> Result<i64, String> { self.0.now() }
            fn set(&mut self, t: i64) -> Result<(), RollBackError> { self.0.set(t) }
            fn restore(&mut self) -> Result<(), String> { self.0.restore() }
            fn ntp_read(&mut self) -> Result<ntp::Settings, String> { self.0.ntp_read() }
            fn ntp_write(&mut self, _: &ntp::Settings, _: bool, _: &ntp::Wall) -> Result<(), String> {
                Err("HTTP/1.1 500".into())
            }
        }
        let mut b2 = Stubborn(std::mem::replace(&mut b, Fake::new(true)));
        b2.0.ntp_fights = true;
        h.take(H, &j);
        let e = h.ensure(H, &j, &mut b2, W, TODAY, &quiet).unwrap_err();
        assert!(e.contains("NTP"), "{e}");
        assert!(e.contains("although it was paused"), "{e}");
        assert_eq!(b2.0.log().iter().filter(|l| l.starts_with("set")).count(), 3);
        // Still owed: the clock was set, and NTP may have been half saved.
        assert!(j.get(H).unwrap().clock);
        h.release(H, &j, &mut b2, TODAY);
    }

    #[test]
    fn a_roll_back_that_never_reached_the_bmc_owes_nothing() {
        let (j, mut b, mut h) = (journal("unreach"), Fake::new(false), Holds::default());
        b.unreachable = true;
        h.take(H, &j);
        assert!(h.ensure(H, &j, &mut b, W, TODAY, &quiet).unwrap_err().contains("UDP 623"));
        assert_eq!(j.get(H), None);
        assert_eq!(h.release(H, &j, &mut b, TODAY), None);
        assert!(!b.log().contains(&"restore".to_string()));
    }

    #[test]
    fn a_failed_restore_stays_journalled_and_the_next_run_puts_it_right() {
        let (j, mut b, mut h) = (journal("recover"), Fake::new(true), Holds::default());
        h.take(H, &j);
        h.ensure(H, &j, &mut b, W, TODAY, &quiet).unwrap();
        b.restore_fails = true;
        let problem = h.release(H, &j, &mut b, TODAY).unwrap();
        assert!(problem.starts_with("192.0.2.20: could not restore the BMC clock: no reply"), "{problem}");
        // NTP went back on; only the clock is still owed.
        assert_eq!(j.get(H).map(|o| (o.clock, o.ntp.is_some())), Some((true, false)));
        // The next run adopts it, and its last release restores it.
        b.restore_fails = false;
        let mut next = Holds::default();
        next.take(H, &j);
        assert_eq!(next.release(H, &j, &mut b, TODAY), None);
        assert_eq!(b.log().last().unwrap(), "restore");
        assert_eq!(j.get(H), None);
    }

    #[test]
    fn a_bmc_left_inside_the_window_by_an_earlier_run_is_rolled_and_restored() {
        let (j, mut b, mut h) = (journal("left"), Fake::new(false), Holds::default());
        b.clock = NA - 30 * DAY;
        h.take(H, &j);
        h.ensure(H, &j, &mut b, W, TODAY, &quiet).unwrap();
        h.release(H, &j, &mut b, TODAY);
        assert_eq!(b.log(), ["ntp read", "set 2026-04-17", "restore"]);
    }

    #[test]
    fn not_restored_names_the_way_out() {
        let line = not_restored("192.0.2.20", "no reply");
        assert!(line.starts_with("192.0.2.20: could not restore the BMC clock: no reply"));
        assert!(line.contains("bmc-kvm ipmi 192.0.2.20 sel-time now"));
    }
}
