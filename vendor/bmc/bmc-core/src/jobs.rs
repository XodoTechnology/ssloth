//! Actions in flight off the UI thread, by key, each with the line a GUI
//! shows while it runs. A key present means "running": its controls are
//! disabled and a second request is refused rather than starting the same
//! thing twice. A connect also waits here for a close of its host, which
//! would otherwise race it (see `Jobs::wait_until_done`).

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// What a job is, and on which BMC.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum JobKey {
    /// A chassis power command.
    Power(String),
    /// A BMC (management controller) reset.
    Reset(String),
    /// A console session closing: media detach, logout, iDRAC's session
    /// release, X9's clock restore.
    Close(String),
    /// Virtual media being attached.
    Mount(String),
}

impl JobKey {
    /// The address the job acts on.
    pub fn addr(&self) -> &str {
        match self {
            JobKey::Power(a) | JobKey::Reset(a) | JobKey::Close(a) | JobKey::Mount(a) => a,
        }
    }
    fn kind(&self) -> &'static str {
        match self {
            JobKey::Power(_) => "power",
            JobKey::Reset(_) => "reset",
            JobKey::Close(_) => "close",
            JobKey::Mount(_) => "mount",
        }
    }
}

/// `power:<addr>`, `reset:<addr>`, `close:<addr>`, `mount:<addr>`.
impl fmt::Display for JobKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind(), self.addr())
    }
}

/// The registry, shared by cloning. Newest job last.
#[derive(Clone, Default)]
pub struct Jobs(Arc<Mutex<Vec<(JobKey, String)>>>);

/// Registers a job and removes it when dropped — at the end of the thread
/// that owns it, however that thread ends.
pub struct JobGuard {
    jobs: Jobs,
    key: JobKey,
}

impl Drop for JobGuard {
    fn drop(&mut self) {
        self.jobs.0.lock().unwrap().retain(|(k, _)| *k != self.key);
    }
}

/// How a wait on a job ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Waited {
    Done,
    TimedOut,
    Cancelled,
}

impl Jobs {
    /// Start `key`, shown as `what`. None when it is already running.
    pub fn begin(&self, key: JobKey, what: impl Into<String>) -> Option<JobGuard> {
        let mut jobs = self.0.lock().unwrap();
        if jobs.iter().any(|(k, _)| *k == key) {
            return None;
        }
        jobs.push((key.clone(), what.into()));
        Some(JobGuard { jobs: self.clone(), key })
    }

    /// Whether `key` is running.
    pub fn running(&self, key: &JobKey) -> bool {
        self.0.lock().unwrap().iter().any(|(k, _)| k == key)
    }

    pub fn is_empty(&self) -> bool {
        self.0.lock().unwrap().is_empty()
    }

    /// Whether any session is still closing, on any host.
    pub fn any_closing(&self) -> bool {
        self.0.lock().unwrap().iter().any(|(k, _)| matches!(k, JobKey::Close(_)))
    }

    /// What each running job shows, oldest first.
    pub fn lines(&self) -> Vec<String> {
        self.0.lock().unwrap().iter().map(|(_, what)| what.clone()).collect()
    }

    /// Wait for `key` to finish, for at most `limit`, or until `cancel` is set.
    pub fn wait_until_done(&self, key: &JobKey, limit: Duration, cancel: &AtomicBool) -> Waited {
        let deadline = Instant::now() + limit;
        loop {
            if cancel.load(Ordering::SeqCst) {
                return Waited::Cancelled;
            }
            if !self.running(key) {
                return Waited::Done;
            }
            if Instant::now() >= deadline {
                return Waited::TimedOut;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{JobKey, Jobs, Waited};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn no_cancel() -> AtomicBool {
        AtomicBool::new(false)
    }
    fn close(a: &str) -> JobKey {
        JobKey::Close(a.into())
    }

    #[test]
    fn keys_read_as_kind_and_address() {
        assert_eq!(JobKey::Power("192.0.2.1".into()).to_string(), "power:192.0.2.1");
        assert_eq!(JobKey::Reset("192.0.2.1".into()).to_string(), "reset:192.0.2.1");
        assert_eq!(close("192.0.2.1").to_string(), "close:192.0.2.1");
        assert_eq!(JobKey::Mount("192.0.2.1".into()).to_string(), "mount:192.0.2.1");
    }

    #[test]
    fn a_running_key_is_refused_until_its_guard_drops() {
        let jobs = Jobs::default();
        let guard = jobs.begin(close("10.0.0.1"), "Closing").unwrap();
        assert!(jobs.begin(close("10.0.0.1"), "again").is_none());
        assert!(jobs.running(&close("10.0.0.1")) && jobs.any_closing());
        drop(guard);
        assert!(jobs.is_empty() && !jobs.any_closing());
        assert!(jobs.begin(close("10.0.0.1"), "Closing").is_some());
    }

    #[test]
    fn nothing_running_is_no_wait() {
        let jobs = Jobs::default();
        let t = Instant::now();
        assert_eq!(jobs.wait_until_done(&close("10.0.0.1"), Duration::from_secs(5), &no_cancel()),
                   Waited::Done);
        assert!(t.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn other_actions_do_not_hold_a_connect_up() {
        let jobs = Jobs::default();
        let _a = jobs.begin(close("10.0.0.2"), String::new()).unwrap();
        let _b = jobs.begin(JobKey::Power("10.0.0.1".into()), String::new()).unwrap();
        let t = Instant::now();
        assert_eq!(jobs.wait_until_done(&close("10.0.0.1"), Duration::from_secs(5), &no_cancel()),
                   Waited::Done);
        assert!(t.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_close_still_running_is_waited_for() {
        let jobs = Jobs::default();
        let guard = jobs.begin(close("10.0.0.1"), String::new()).unwrap();
        let t = Instant::now();
        let closer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            drop(guard);
        });
        assert_eq!(jobs.wait_until_done(&close("10.0.0.1"), Duration::from_secs(5), &no_cancel()),
                   Waited::Done);
        assert!(t.elapsed() >= Duration::from_millis(200));
        closer.join().unwrap();
    }

    #[test]
    fn a_close_that_outlasts_the_limit_is_not_raced() {
        let jobs = Jobs::default();
        let _guard = jobs.begin(close("10.0.0.1"), String::new()).unwrap();
        let t = Instant::now();
        assert_eq!(jobs.wait_until_done(&close("10.0.0.1"), Duration::from_millis(200), &no_cancel()),
                   Waited::TimedOut);
        assert!(t.elapsed() >= Duration::from_millis(200));
    }

    #[test]
    fn cancel_ends_the_wait() {
        let jobs = Jobs::default();
        let _guard = jobs.begin(close("10.0.0.1"), String::new()).unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let canceller = {
            let cancel = cancel.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(150));
                cancel.store(true, Ordering::SeqCst);
            })
        };
        let t = Instant::now();
        assert_eq!(jobs.wait_until_done(&close("10.0.0.1"), Duration::from_secs(10), &cancel),
                   Waited::Cancelled);
        assert!(t.elapsed() < Duration::from_secs(2));
        canceller.join().unwrap();
        // Already cancelled: no wait at all, even with nothing running.
        assert_eq!(Jobs::default().wait_until_done(&close("10.0.0.1"), Duration::from_secs(5), &cancel),
                   Waited::Cancelled);
    }
}
