//! The open consoles, by id, and the one place each is closed.
//!
//! A console ends in one of three ways: the user closes it, the app exits,
//! or its threads clear their liveness flag because the BMC or the network
//! ended it. The last used to be noticed by the GUI's frame loop, so a
//! console that died while the window was not drawing held its BMC sessions
//! until the next repaint. Here a watcher thread notices it instead, closes
//! the console once and raises `SessionEnded`, whether or not anything is
//! drawing. Whichever way comes first takes the console out of the table,
//! so it is closed exactly once.

use crate::console::{self, Closing, ConnectOk, Console};
use crate::events::{Event, Sink};
use crate::jobs::{JobKey, Jobs};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

/// How often the watcher looks at the liveness flags. A console's end shows
/// within this; it is far below the seconds a close itself takes.
const WATCH_EVERY: Duration = Duration::from_millis(100);

struct Inner {
    open: Mutex<HashMap<u64, Closing>>,
    next: AtomicU64,
    jobs: Jobs,
    sink: Sink,
}

/// Shared by cloning; the watcher stops once the last clone is dropped.
#[derive(Clone)]
pub struct SessionManager(Arc<Inner>);

impl SessionManager {
    /// Closes run as `close:<addr>` jobs in `jobs`, so a connect to the same
    /// host waits for them; what they report goes to `sink`.
    pub fn new(jobs: Jobs, sink: Sink) -> Self {
        Self::watching_every(jobs, sink, WATCH_EVERY)
    }

    fn watching_every(jobs: Jobs, sink: Sink, every: Duration) -> Self {
        let inner = Arc::new(Inner { open: Default::default(), next: AtomicU64::new(1), jobs, sink });
        let weak = Arc::downgrade(&inner);
        std::thread::spawn(move || watch(weak, every));
        SessionManager(inner)
    }

    /// Take a finished connect into the table: the console a front end
    /// holds, and its id here.
    pub fn adopt(&self, ok: ConnectOk, host: &str, user: String, pass: String) -> (u64, Console) {
        let (console, closing) = console::adopt(ok, host, user, pass);
        let id = self.0.next.fetch_add(1, Ordering::Relaxed);
        self.0.open.lock().unwrap().insert(id, closing);
        (id, console)
    }

    /// Close `id` off the calling thread. False if it is not open, because
    /// it has already ended or been closed.
    pub fn close(&self, id: u64) -> bool {
        let Some(c) = self.0.open.lock().unwrap().remove(&id) else { return false };
        close_in_background(&self.0, c);
        true
    }

    /// Close every console now, blocking, and return what could not be put
    /// back. For exit, when there is no thread left to wait for.
    pub fn close_all(&self) -> Vec<String> {
        let all: Vec<Closing> = self.0.open.lock().unwrap().drain().map(|(_, c)| c).collect();
        all.into_iter().flat_map(console::close).collect()
    }

    /// How many consoles are open.
    pub fn len(&self) -> usize {
        self.0.open.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Closing is network work — media detach, logout, iDRAC's session release,
/// X9's clock restore — and takes seconds. It runs as the host's close job,
/// begun here, before anyone hears of it, so a reconnect waits for it.
fn close_in_background(inner: &Inner, c: Closing) {
    let host = c.host.clone();
    let guard = inner.jobs.begin(JobKey::Close(host.clone()),
                                 format!("Closing the session on {host}"));
    let sink = inner.sink.clone();
    std::thread::spawn(move || {
        let _guard = guard;
        let problems = crate::net::deliberately(|| console::close(c));
        for p in problems {
            sink.emit(Event::Problem(p));
        }
        sink.emit(Event::Notice(format!("disconnected from {host}")));
    });
}

fn watch(weak: Weak<Inner>, every: Duration) {
    loop {
        std::thread::sleep(every);
        let Some(inner) = weak.upgrade() else { return };
        let ended: Vec<(u64, Closing)> = {
            let mut open = inner.open.lock().unwrap();
            let ids: Vec<u64> = open.iter()
                .filter(|(_, c)| !c.alive.load(Ordering::SeqCst))
                .map(|(id, _)| *id)
                .collect();
            ids.into_iter().filter_map(|id| open.remove(&id).map(|c| (id, c))).collect()
        };
        for (id, c) in ended {
            let host = c.host.clone();
            close_in_background(&inner, c);
            inner.sink.emit(Event::SessionEnded { id, host });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::console::{trackers, FamilyLink};
    use crate::events::Recorder;
    use crate::families::Family;
    use std::sync::atomic::AtomicBool;
    use std::time::Instant;

    /// A console with no BMC behind it whose teardown counts its runs.
    fn fake(closes: &Arc<AtomicU64>) -> (ConnectOk, Arc<AtomicBool>) {
        let (tx, _rx) = std::sync::mpsc::channel();
        let alive = Arc::new(AtomicBool::new(true));
        let mut link = FamilyLink::new(tx, alive.clone());
        let n = closes.clone();
        link.teardown.push(move || { n.fetch_add(1, Ordering::SeqCst); Vec::new() });
        let (net, rtt, frame) = trackers();
        let ok = ConnectOk {
            decoder: Arc::new(Mutex::new(crate::ast2100::Decoder::new(8, 8))),
            link, title: "fake".into(), family: Family::Aten, kvm_token: String::new(),
            notice: Default::default(), takeover: Default::default(), ended: Default::default(),
            idrac: None, avocent: None, spx: None, net, rtt, frame,
        };
        (ok, alive)
    }

    fn until(what: &str, f: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !f() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn a_console_that_dies_is_closed_once_and_reported_once() {
        let rec = Recorder::default();
        let jobs = Jobs::default();
        let m = SessionManager::watching_every(jobs.clone(), Arc::new(rec.clone()), Duration::from_millis(5));
        let closes = Arc::new(AtomicU64::new(0));
        let (ok, alive) = fake(&closes);
        let (id, _console) = m.adopt(ok, "192.0.2.7", "admin".into(), "secret".into());
        alive.store(false, Ordering::SeqCst);
        until("the close", || closes.load(Ordering::SeqCst) == 1 && !jobs.any_closing());
        // Several more watches find nothing left to close.
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(closes.load(Ordering::SeqCst), 1);
        assert!(m.is_empty());
        until("the notice", || rec.events().contains(&Event::Notice("disconnected from 192.0.2.7".into())));
        let ended: Vec<Event> = rec.events().into_iter()
            .filter(|e| matches!(e, Event::SessionEnded { .. })).collect();
        assert_eq!(ended, [Event::SessionEnded { id, host: "192.0.2.7".into() }]);
        assert!(!m.close(id), "an ended console is not closed again");
    }

    #[test]
    fn a_console_the_user_closes_is_not_closed_again_when_its_threads_stop() {
        let rec = Recorder::default();
        let m = SessionManager::watching_every(Jobs::default(), Arc::new(rec.clone()), Duration::from_millis(5));
        let closes = Arc::new(AtomicU64::new(0));
        let (ok, alive) = fake(&closes);
        let (id, _console) = m.adopt(ok, "192.0.2.8", "admin".into(), "secret".into());
        assert!(m.close(id));
        until("the close", || closes.load(Ordering::SeqCst) == 1);
        assert!(!alive.load(Ordering::SeqCst), "the close stops the console's threads");
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(closes.load(Ordering::SeqCst), 1);
        assert!(!rec.events().iter().any(|e| matches!(e, Event::SessionEnded { .. })),
                "a close the user asked for is not an ended console");
    }

    #[test]
    fn exit_closes_everything_still_open_before_returning() {
        let m = SessionManager::new(Jobs::default(), Arc::new(crate::events::Discard));
        let closes = Arc::new(AtomicU64::new(0));
        for host in ["192.0.2.9", "192.0.2.10"] {
            let (ok, _alive) = fake(&closes);
            m.adopt(ok, host, "admin".into(), "secret".into());
        }
        assert!(m.close_all().is_empty());
        assert_eq!(closes.load(Ordering::SeqCst), 2);
        assert!(m.is_empty());
    }
}
