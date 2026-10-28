//! Latency measurement for a live console session.
//!
//! Three different things get called "latency" on a KVM, and they answer
//! different questions, so they are tracked separately rather than averaged
//! into one misleading number:
//!
//! * **net** — TCP handshake round trip to the BMC. Pure network, no BMC work.
//!   Sampled periodically on a throwaway connection to the web port.
//! * **rtt** — console round trip: how long the BMC takes to answer a request.
//!   Network plus encode time, which is what the console actually feels like.
//!   Only meaningful where the protocol is request/response (see `vnc`).
//! * **frame** — interval between decoded updates. Not latency at all; it is
//!   smoothness, and its spread is the jitter.
//!
//! Samples are kept in a small rolling window so a single stall does not haunt
//! the average for the rest of the session.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const WINDOW: usize = 64;

#[derive(Clone, Copy, Debug)]
pub struct Stats {
    pub last_ms: f32,
    pub min_ms: f32,
    pub avg_ms: f32,
    /// 95th percentile — the number that reflects how bad it feels, since the
    /// occasional slow frame is what people notice.
    pub p95_ms: f32,
    pub max_ms: f32,
    pub count: u64,
}

#[derive(Default)]
struct Window {
    samples: VecDeque<f32>,
    last: f32,
    count: u64,
}

#[derive(Default)]
pub struct Tracker {
    w: Mutex<Window>,
}

impl Tracker {
    pub fn new() -> Arc<Tracker> {
        Arc::new(Tracker::default())
    }

    pub fn record(&self, d: Duration) {
        let ms = d.as_secs_f32() * 1000.0;
        let mut w = self.w.lock().unwrap();
        w.last = ms;
        w.count += 1;
        w.samples.push_back(ms);
        while w.samples.len() > WINDOW {
            w.samples.pop_front();
        }
    }

    /// None until at least one sample has been taken.
    pub fn stats(&self) -> Option<Stats> {
        let w = self.w.lock().unwrap();
        if w.samples.is_empty() {
            return None;
        }
        let mut v: Vec<f32> = w.samples.iter().copied().collect();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let sum: f32 = v.iter().sum();
        // Nearest-rank p95, which for a 64-sample window is the 61st value.
        let idx = (((v.len() as f32) * 0.95).ceil() as usize).saturating_sub(1);
        Some(Stats {
            last_ms: w.last,
            min_ms: v[0],
            avg_ms: sum / v.len() as f32,
            p95_ms: v[idx.min(v.len() - 1)],
            max_ms: v[v.len() - 1],
            count: w.count,
        })
    }
}

/// Time a TCP handshake to `host:port`. This is the network alone: the kernel
/// answers the SYN, so no BMC work is included and a slow result means the path.
/// Name lookup is excluded for a direct host. Through a route, this is the
/// handshake to the BMC as the last hop sees it, plus the hops; the GUI labels
/// it so.
pub fn probe_tcp(host: &str, port: u16, timeout: Duration) -> Option<Duration> {
    let (sock, d) = if crate::net::is_routed(host) == Ok(false) {
        let addrs = crate::net::resolve_addrs(host, port).ok()?;
        let t0 = Instant::now();
        let sock = crate::net::direct_addrs(&addrs, Some(timeout)).ok()?;
        (sock, t0.elapsed())
    } else {
        let t0 = Instant::now();
        let sock = crate::net::connect(host, port, Some(timeout)).ok()?;
        (sock, t0.elapsed())
    };
    // Close immediately; BMC web servers are not generous with connections.
    drop(sock);
    Some(d)
}

/// Sample the network round trip every `interval` until `alive` clears.
///
/// Deliberately infrequent: these are management controllers, and probing them
/// hard is how you end up exhausting their connection or session pools.
pub fn spawn_net_probe(
    host: String,
    port: u16,
    alive: Arc<AtomicBool>,
    tracker: Arc<Tracker>,
    interval: Duration,
) {
    std::thread::spawn(move || {
        while alive.load(Ordering::SeqCst) {
            if let Some(d) = probe_tcp(&host, port, Duration::from_secs(3)) {
                tracker.record(d);
            }
            // Wake often enough to notice the session ending.
            let step = Duration::from_millis(250);
            let mut left = interval;
            while left > Duration::ZERO && alive.load(Ordering::SeqCst) {
                let d = step.min(left);
                std::thread::sleep(d);
                left -= d;
            }
        }
    });
}

/// Records the gap between successive events, for frame intervals.
pub struct Intervals {
    last: Mutex<Option<Instant>>,
    pub tracker: Arc<Tracker>,
}

impl Intervals {
    pub fn new(tracker: Arc<Tracker>) -> Intervals {
        Intervals { last: Mutex::new(None), tracker }
    }

    pub fn tick(&self) {
        let mut l = self.last.lock().unwrap();
        let now = Instant::now();
        if let Some(prev) = *l {
            self.tracker.record(now - prev);
        }
        *l = Some(now);
    }
}

/// One-line summary for a status bar, e.g. `12/18ms`.
pub fn brief(s: &Stats) -> String {
    if s.avg_ms >= 100.0 {
        format!("{:.0}/{:.0}ms", s.avg_ms, s.p95_ms)
    } else {
        format!("{:.1}/{:.1}ms", s.avg_ms, s.p95_ms)
    }
}

/// Full summary for the headless commands.
pub fn detail(name: &str, s: &Stats) -> String {
    format!(
        "{name}: last {:.1}ms  min {:.1}  avg {:.1}  p95 {:.1}  max {:.1}  (n={})",
        s.last_ms, s.min_ms, s.avg_ms, s.p95_ms, s.max_ms, s.count
    )
}
