//! SSH jump hosts: one authenticated connection per route, with a
//! `direct-tcpip` channel on it for every connection to every BMC behind it.
//! Every family's code wants a real `TcpStream` (concrete TLS types,
//! `try_clone`, `peek`, socket timeouts), and a channel is not one, so each
//! channel is handed over through the loopback front end (`front.rs`). tokio
//! lives here, in `front.rs` and in the server half of `socks.rs` it uses.

use super::{front, is_refusal, is_unasked, refused, say, socks, unasked, via, Context};
use crate::routes::{Auth, Kind, Route};
use russh::client;
use russh::keys::{self, HashAlg, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use russh::MethodKind;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;

/// How long opening a tunnel may take in all, and how long a caller who can
/// be asked waits for it: every hop's network phases, but not the time the
/// user spends answering a prompt (`Asked`). A backstop; each network phase
/// has its own, shorter limit.
const TUNNEL_TIMEOUT: Duration = Duration::from_secs(120);
/// How long one network phase may take: reaching a hop, the SSH handshake,
/// one authentication exchange, opening a channel. A port that accepts TCP
/// but never speaks SSH fails here instead of holding its chain's slot.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const IDLE_CLOSE: Duration = Duration::from_secs(60);
const KEEPALIVE: Duration = Duration::from_secs(15);
/// How long a chain's failed open answers for it, so that the next round of
/// probes is told at once rather than each dialling the jump host again.
const FAILURE_KEPT: Duration = Duration::from_secs(15);
/// How long past its caller's deadline the wait for a tunnel still takes
/// the open's own outcome. A caller that named no timeout gets one phase's
/// limit, and the open's phase under the same limit began a moment later:
/// it fails just after the caller stops, and "no SSH server answered" says
/// more than "timed out waiting". Every phase run for the caller stops at
/// the deadline itself, with its own account of what was slow; twice this
/// past it, a connect is abandoned outright, which catches only what has
/// no account, such as a prompt left open.
const BACKSTOP_AFTER: Duration = Duration::from_millis(250);

pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub(crate) type BoxIo = Box<dyn Io>;
type Opening<'a> = Pin<Box<dyn Future<Output = io::Result<(BoxIo, Vec<Lease>)>> + Send + 'a>>;

fn other(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg.into())
}
fn timed_out(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, msg.into())
}

#[cfg(any(test, feature = "testing"))]
thread_local! {
    static HANDSHAKE_LIMIT: std::cell::Cell<Duration> = const { std::cell::Cell::new(HANDSHAKE_TIMEOUT) };
}

/// What a test set on the thread that started an open, carried into the
/// task that runs it.
#[cfg(any(test, feature = "testing"))]
#[derive(Clone)]
struct TestLocal {
    phase: Duration,
    known_hosts: Option<Option<PathBuf>>,
    #[cfg(unix)]
    agent: Option<PathBuf>,
}

#[cfg(any(test, feature = "testing"))]
tokio::task_local! {
    static TEST_LOCAL: TestLocal;
}

#[cfg(all(any(test, feature = "testing"), unix))]
thread_local! {
    static TEST_AGENT: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

/// The agent socket a test points this thread at, instead of SSH_AUTH_SOCK.
#[cfg(all(any(test, feature = "testing"), unix))]
fn test_agent() -> Option<PathBuf> {
    TEST_LOCAL.try_with(|l| l.agent.clone()).ok().flatten().or_else(|| TEST_AGENT.with(|a| a.borrow().clone()))
}

#[cfg(all(test, unix))]
pub(crate) fn with_agent<R>(path: Option<PathBuf>, f: impl FnOnce() -> R) -> R {
    let old = TEST_AGENT.with(|a| a.replace(path));
    let out = f();
    TEST_AGENT.with(|a| *a.borrow_mut() = old);
    out
}

/// `HANDSHAKE_TIMEOUT`, except where a test has shortened it for its own
/// thread, so that a silent hop fails in a moment rather than in twenty
/// seconds. Read where a connect is polled, which `block_on` does on the
/// caller's thread; an open started from there carries it along.
fn handshake_timeout() -> Duration {
    #[cfg(any(test, feature = "testing"))]
    return TEST_LOCAL.try_with(|l| l.phase).unwrap_or_else(|_| HANDSHAKE_LIMIT.with(|l| l.get()));
    #[cfg(not(any(test, feature = "testing")))]
    HANDSHAKE_TIMEOUT
}

#[cfg(test)]
pub(crate) fn with_handshake_timeout<R>(limit: Duration, f: impl FnOnce() -> R) -> R {
    let old = HANDSHAKE_LIMIT.with(|l| l.replace(limit));
    let out = f();
    HANDSHAKE_LIMIT.with(|l| l.set(old));
    out
}

/// Time the user has spent answering one context's questions. No network
/// limit counts it: a fingerprint is checked, or a passphrase found, at the
/// user's pace, and a limit that ran on meanwhile would end the open, or
/// the wait for it, with the prompt still on the screen. Kept per context,
/// which an open shares with the caller that started it, so that a dialog
/// left open stops no other work's clock.
#[derive(Default)]
pub struct Asked(Mutex<AskedSoFar>);

#[derive(Default)]
struct AskedSoFar {
    done: Duration,
    /// When the questions now open began, and how many there are.
    since: Option<Instant>,
    open: usize,
}

impl Asked {
    /// How long in all, a question still open included.
    fn total(&self) -> Duration {
        let g = self.0.lock().unwrap();
        g.done + g.since.map_or(Duration::ZERO, |s| s.elapsed())
    }

    /// Count the time from now until the guard is dropped: the answer, or
    /// the open being given up.
    fn asking(self: &Arc<Self>) -> Asking {
        let mut g = self.0.lock().unwrap();
        if g.open == 0 {
            g.since = Some(Instant::now());
        }
        g.open += 1;
        Asking(self.clone())
    }
}

struct Asking(Arc<Asked>);

impl Drop for Asking {
    fn drop(&mut self) {
        let mut g = self.0 .0.lock().unwrap();
        g.open -= 1;
        if g.open == 0 {
            if let Some(since) = g.since.take() {
                g.done += since.elapsed();
            }
        }
    }
}

/// A moment that moves later by whatever time the user spends answering
/// questions after it was set.
#[derive(Clone)]
struct Deadline {
    at: Instant,
    asked: Arc<Asked>,
    asked_then: Duration,
}

impl Deadline {
    fn after(limit: Duration, asked: &Arc<Asked>) -> Deadline {
        Deadline { at: Instant::now() + limit, asked: asked.clone(), asked_then: asked.total() }
    }

    fn get(&self) -> Instant {
        self.at + self.asked.total().saturating_sub(self.asked_then)
    }
}

/// How often a wait looks again at an end that a question keeps moving.
const RECHECK: Duration = Duration::from_millis(100);

/// `f`, or None if `end` passes first. `end` is read again when it is
/// reached, since a question asked meanwhile moves it. While one stays open
/// the end moves on by however long was left when it was asked, which can be
/// a millisecond, so it is looked at no more often than every `RECHECK`: a
/// prompt left on screen must not keep a runtime worker spinning.
async fn before<T>(end: impl Fn() -> Instant, f: impl Future<Output = T>) -> Option<T> {
    tokio::pin!(f);
    let mut at = end();
    loop {
        tokio::select! {
            biased;
            out = &mut f => return Some(out),
            _ = tokio::time::sleep_until(at.into()) => {
                let now = Instant::now();
                let moved = end();
                if moved <= now {
                    return None;
                }
                at = moved.max(now + RECHECK);
            }
        }
    }
}

/// Who a connect in progress is for.
#[derive(Clone, Default)]
struct Caller {
    /// When it stops waiting: the phases run on its behalf stop there, and
    /// its wait for a tunnel's outcome a moment later (`BACKSTOP_AFTER`). A
    /// tunnel it is waiting for does not stop.
    until: Option<Deadline>,
    /// When the deliberate action it belongs to began; None for background
    /// work. Carried into an open it starts, and so to the hops under it.
    since: Option<Instant>,
}

tokio::task_local! {
    static CALLER: Caller;
}

fn caller() -> Caller {
    CALLER.try_with(Caller::clone).unwrap_or_default()
}

fn deadline() -> Option<Instant> {
    caller().until.map(|d| d.get())
}

/// When a phase that may take `limit` must end: then, or at the caller's
/// deadline if one is waiting on it and that comes first. A tunnel's own
/// open has no caller's deadline.
fn phase_end(limit: Duration) -> tokio::time::Instant {
    let end = Instant::now() + limit;
    deadline().map_or(end, |d| d.min(end)).into()
}

/// Run one network phase under `handshake_timeout()`; `phase` names it in
/// the error.
async fn bounded<T>(phase: &str, f: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    bounded_by(handshake_timeout(), phase, f).await
}

async fn bounded_by<T>(limit: Duration, phase: &str, f: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    tokio::time::timeout_at(phase_end(limit), f)
        .await
        .unwrap_or_else(|_| Err(timed_out(format!("{phase} timed out"))))
}

/// Run a connect for a caller of `ctx` that will wait `timeout`, the wait for
/// a tunnel included. Where nobody can be asked, that is all it gets (one
/// phase's limit, if it named none): a probe is not held for twenty seconds
/// by a jump host that has gone quiet. Where somebody can, the backstop as
/// well, and the time they spend answering is not counted. A tunnel the
/// caller stops waiting for goes on opening for whoever comes next.
async fn within<T>(
    ctx: &Context,
    timeout: Option<Duration>,
    late: impl FnOnce() -> io::Error,
    open: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    let reach = timeout.unwrap_or_else(handshake_timeout);
    let patience = if ctx.prompter.is_some() { TUNNEL_TIMEOUT + reach } else { reach };
    let until = Deadline::after(patience, &ctx.asked);
    let since = (ctx.deliberate || ctx.prompter.is_some()).then(|| super::action_began().unwrap_or_else(Instant::now));
    CALLER
        .scope(Caller { until: Some(until.clone()), since }, async {
            before(|| until.get() + 2 * BACKSTOP_AFTER, open).await.unwrap_or_else(|| Err(late()))
        })
        .await
}

/// The runtime every tunnel runs on. Multi-threaded, so that a blocking
/// caller on any ordinary thread can `block_on` into it.
pub(crate) fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("bmc-kvm-net")
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.spawn(async {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                reap(IDLE_CLOSE).await;
            }
        });
        rt
    })
}

pub(crate) struct Tunnel {
    handle: client::Handle<Client>,
    leases: AtomicUsize,
    idle_since: Mutex<Option<Instant>>,
    /// The outer tunnel this one runs through, held for as long as it lives.
    _transport: Vec<Lease>,
}

/// A use of a tunnel. The tunnel may close once it has none left.
pub(crate) struct Lease(Arc<Tunnel>);

impl Lease {
    fn new(t: Arc<Tunnel>) -> Lease {
        t.leases.fetch_add(1, Ordering::SeqCst);
        *t.idle_since.lock().unwrap() = None;
        Lease(t)
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if self.0.leases.fetch_sub(1, Ordering::SeqCst) == 1 {
            *self.0.idle_since.lock().unwrap() = Some(Instant::now());
        }
    }
}

/// A chain's tunnel, the open in progress, or why the last open failed.
#[derive(Default)]
struct SlotState {
    tunnel: Option<Arc<Tunnel>>,
    /// The open every caller for the chain waits on. It runs as a task of
    /// its own, so that a caller that stops waiting (a probe's 1.5 s) cancels
    /// nothing: the tunnel opens for the next caller, and a refusal that
    /// comes late is remembered all the same.
    opening: Option<Underway>,
    failed: Option<Failure>,
}

/// An open under way: the chain as it was started for, and its outcome.
struct Underway {
    chain: Vec<Route>,
    outcome: watch::Receiver<Option<Outcome>>,
}

type Slot = Arc<Mutex<SlotState>>;

/// What an open came to, for every caller waiting on it.
type Outcome = Result<Arc<Tunnel>, Fail>;

/// An error that can be given to each of several callers.
#[derive(Clone)]
struct Fail {
    kind: io::ErrorKind,
    message: String,
    cause: Cause,
}

/// Whether another try could go differently.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Cause {
    /// Our credentials or the jump host's key, refused: not until the route
    /// changes.
    Refused,
    /// Refused only because the open could ask nobody (a key nothing vouches
    /// for, a secret not saved): not for background work, which cannot ask
    /// either, but a caller who can be asked tries it.
    Unasked,
    /// Anything else: an unreachable host, a timeout, a local error.
    Other,
}

impl Fail {
    fn of(e: &io::Error) -> Fail {
        let cause = if is_unasked(e) {
            Cause::Unasked
        } else if is_refusal(e) {
            Cause::Refused
        } else {
            Cause::Other
        };
        Fail { kind: e.kind(), message: e.to_string(), cause }
    }
    fn error(&self) -> io::Error {
        self.with_message(self.message.clone())
    }
    /// The same error, said differently; a refusal stays one.
    fn with_message(&self, message: String) -> io::Error {
        match self.cause {
            Cause::Refused => refused(message),
            Cause::Unasked => unasked(message),
            Cause::Other => io::Error::new(self.kind, message),
        }
    }
}

/// Why a chain's tunnel last failed to open.
struct Failure {
    /// The chain as configured then, secrets and pins included, which the
    /// slot's key leaves out: once any of its hops is edited (a password, a
    /// pin, a host), it is tried afresh. Nothing else forgets it: an edit to
    /// another route cannot mend this one, a host regrouped elsewhere
    /// resolves to another chain, and what is mended outside routes.json
    /// (`ssh-add`, an unbanned address) is retried by the user's own action.
    chain: Vec<Route>,
    fail: Fail,
    at: Instant,
}

impl Failure {
    /// What to remember of `e`, if anything: not a cancelled prompt, which
    /// is the user's answer rather than the jump host's.
    fn of(chain: &[Route], e: &io::Error) -> Option<Failure> {
        (e.kind() != io::ErrorKind::Interrupted).then(|| Failure {
            chain: chain.to_vec(),
            fail: Fail::of(e),
            at: Instant::now(),
        })
    }

    /// A refused login or host key, or a key or secret nobody could be
    /// asked about. Another try costs an authentication failure against
    /// MaxAuthTries and fail2ban, or a handshake with a server already
    /// distrusted, and cannot go differently until the route does, or
    /// someone who can be asked tries it.
    fn lasting(&self) -> bool {
        matches!(self.fail.cause, Cause::Refused | Cause::Unasked)
    }

    /// The answer, instead of dialling again, for a caller whose deliberate
    /// action began at `since` (None for background work). Background work
    /// is answered while the failure is fresh, or for good if it is lasting.
    /// The user's own action tries once: it is answered only with what has
    /// failed since it began, and a passing failure only while it is fresh,
    /// as background work is. An action can run for hours (a CLI mount), and
    /// its last connection, a logout, must not be refused untried over a
    /// timeout near its start. A caller who `can_ask` is never answered with
    /// what failed only because nobody could be asked: it asks.
    fn answer(&self, chain: &[Route], since: Option<Instant>, can_ask: bool) -> Option<io::Error> {
        if self.chain != chain || (can_ask && self.fail.cause == Cause::Unasked) {
            return None;
        }
        let fresh = self.at.elapsed() < FAILURE_KEPT;
        match since {
            Some(began) => (self.at >= began && (self.lasting() || fresh)).then(|| self.fail.error()),
            // A refused login is tried again by the user's next connect. A
            // key or secret nobody was asked about is not: no GUI connect
            // can ask yet, and the refusal already names the command that
            // can.
            None if self.fail.cause == Cause::Unasked => {
                Some(self.fail.with_message(format!("{} (not retried in the background)", self.fail.message)))
            }
            None if self.lasting() => {
                let name = chain.last().map_or("", |r| r.name.as_str());
                Some(self.fail.with_message(format!(
                    "{} (not retried in the background: connect again, or run `bmc-kvm route test {name}`)",
                    self.fail.message
                )))
            }
            None => fresh.then(|| self.fail.error()),
        }
    }
}

/// One slot per chain, so that every caller for it shares its tunnel, the
/// one open under way and how the last one failed. Its lock is held only to
/// read or settle those, never across an open, which runs as a task of its
/// own (`start_open`); the hops a chain runs through open under theirs.
fn slots() -> &'static Mutex<HashMap<String, Slot>> {
    static S: OnceLock<Mutex<HashMap<String, Slot>>> = OnceLock::new();
    S.get_or_init(Default::default)
}

/// How many live tunnels serve `chain`: 0 or 1.
#[cfg(test)]
pub(crate) fn open_tunnels(chain: &[Route]) -> usize {
    let slot = slots().lock().unwrap().get(&super::chain_key(chain)).cloned();
    slot.map(|s| s.lock().unwrap().tunnel.as_ref().is_some_and(|t| !t.handle.is_closed()) as usize).unwrap_or(0)
}

/// Close tunnels that have been unused for `after`; returns how many.
pub(crate) async fn reap(after: Duration) -> usize {
    let slots: Vec<Slot> = slots().lock().unwrap().values().cloned().collect();
    reap_slots(slots, after).await
}

/// `reap` for `chain`'s tunnel and the ones it runs through only: a test
/// that reaped every chain would close another test's tunnel under it.
#[cfg(test)]
pub(crate) async fn reap_chain(chain: &[Route], after: Duration) -> usize {
    let keys: Vec<String> = (1..=chain.len()).map(|n| super::chain_key(&chain[..n])).collect();
    let slots: Vec<Slot> = {
        let all = slots().lock().unwrap();
        keys.iter().filter_map(|k| all.get(k).cloned()).collect()
    };
    reap_slots(slots, after).await
}

async fn reap_slots(slots: Vec<Slot>, after: Duration) -> usize {
    let mut idle = Vec::new();
    for slot in slots {
        // Taken under the slot's lock, which a caller also holds while it
        // takes a lease, so a tunnel is never closed under a new lease.
        let mut g = slot.lock().unwrap();
        let unused = g.tunnel.as_ref().is_some_and(|t| {
            t.leases.load(Ordering::SeqCst) == 0
                && t.idle_since.lock().unwrap().is_some_and(|i| i.elapsed() >= after)
        });
        if unused {
            idle.extend(g.tunnel.take());
        }
    }
    for t in &idle {
        let _ = t.handle.disconnect(russh::Disconnect::ByApplication, "idle", "en").await;
    }
    idle.len()
}

/// What the user settled earlier in this run, by route: secrets typed at a
/// prompt, and host keys trusted. Background work, which cannot ask, uses
/// them; and a CLI session or a forced `--via` chain, whose copy of the route
/// is never reloaded, still holds a jump host to the key it showed first.
#[derive(Default)]
struct Settled {
    secrets: HashMap<String, String>,
    pins: HashMap<String, String>,
}

fn settled() -> &'static Mutex<Settled> {
    static S: OnceLock<Mutex<Settled>> = OnceLock::new();
    S.get_or_init(Default::default)
}

/// A route's identity for what has been settled about it. Its host, user,
/// auth and key file are part of it, so editing those asks again rather than
/// reusing an answer given about something else.
fn run_key(r: &Route) -> String {
    super::chain_key(std::slice::from_ref(r))
}

/// Trust `fp` for `route` for the rest of this run.
fn trust_for_run(route: &Route, fp: &str) {
    settled().lock().unwrap().pins.insert(run_key(route), fp.to_owned());
}

/// `route forget`: stop trusting the key trusted for `route` earlier in this
/// run, as well as the one routes.json pins, which the caller clears. A
/// key kept for the run would otherwise go on vouching for the server.
pub fn forget_host_key(route: &Route) {
    settled().lock().unwrap().pins.remove(&run_key(route));
}

/// What a key file holds, as far as can be told without a jump host.
pub enum KeyFile {
    Opens,
    /// Encrypted, and no passphrase was given.
    Encrypted,
    /// Missing, not a key, or not opened by the passphrase given.
    Fails(String),
}

/// Whether `passphrase` (or none) opens the private key in `path`: for
/// `route add`, which can say so before anything is dialled.
pub fn key_file(path: &str, passphrase: Option<&str>) -> KeyFile {
    match keys::load_secret_key(path, passphrase) {
        Ok(_) => KeyFile::Opens,
        Err(keys::Error::KeyIsEncrypted) => KeyFile::Encrypted,
        Err(e) => KeyFile::Fails(e.to_string()),
    }
}

/// Trust `fp` for `route`: for the rest of this run, and in routes.json if
/// the route is saved there. Only once a login through it has worked:
/// rewriting routes.json reads as an edited route, so a pin written before a
/// refused login would buy the next caller another try. A pin that cannot
/// be saved still holds for this run, and says so.
fn pin(route: &Route, fp: &str, ctx: &Context) {
    trust_for_run(route, fp);
    if let Err(e) = crate::routes::pin_host_key(&route.name, fp) {
        say(ctx, &format!("Could not save {}'s host key ({e}); it is trusted for this run only", route.name));
    }
}

#[cfg(any(test, feature = "testing"))]
thread_local! {
    static KNOWN_HOSTS: std::cell::RefCell<Option<Option<PathBuf>>> = const { std::cell::RefCell::new(None) };
}

/// The known_hosts a test pointed this thread, or the open it started, at.
#[cfg(any(test, feature = "testing"))]
fn test_known_hosts() -> Option<Option<PathBuf>> {
    TEST_LOCAL.try_with(|l| l.known_hosts.clone()).ok().flatten().or_else(|| KNOWN_HOSTS.with(|k| k.borrow().clone()))
}

/// Which known_hosts file vouches for a jump host's key. The tests swap it
/// out per thread, and an open carries the swap into its task, where the
/// hops under it open; so they neither read nor depend on the developer's own.
fn known_hosts() -> Option<PathBuf> {
    #[cfg(any(test, feature = "testing"))]
    if let Some(path) = test_known_hosts() {
        return path;
    }
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })?;
    Some(PathBuf::from(home).join(".ssh").join("known_hosts"))
}

#[cfg(any(test, feature = "testing"))]
pub fn with_known_hosts<R>(path: Option<PathBuf>, f: impl FnOnce() -> R) -> R {
    let old = KNOWN_HOSTS.with(|k| k.replace(Some(path)));
    let out = f();
    KNOWN_HOSTS.with(|k| *k.borrow_mut() = old);
    out
}

/// What the key check concluded, where the key did not simply match a pin.
enum Judgement {
    /// known_hosts vouches for it: pin it once a login through it works.
    Listed(String),
    /// Nothing vouches for this fingerprint: the user's call.
    Unknown(String),
    /// Refused outright, and why.
    Refused(String),
}

pub(crate) struct Client {
    route: Route,
    known_hosts: Option<PathBuf>,
    /// The check's conclusion, for `handshake` to act on; russh reports only
    /// whether the key was accepted.
    judged: Arc<Mutex<Option<Judgement>>>,
    hung_up: HungUp,
}

/// What the jump host said when it ended the session itself, if it did.
type HungUp = Arc<Mutex<Option<String>>>;

impl client::Handler for Client {
    type Error = russh::Error;

    /// Never asks: this runs inside the handshake, under its timeout. A key
    /// nobody vouches for is refused here and asked about in `dial`.
    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let judgement = match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => judge(&self.route, key, self.known_hosts.as_deref()),
            _ => Some(Judgement::Refused("SSH host certificates are not supported".into())),
        };
        let accept = matches!(judgement, None | Some(Judgement::Listed(_)));
        *self.judged.lock().unwrap() = judgement;
        Ok(accept)
    }

    async fn disconnected(&mut self, reason: client::DisconnectReason<Self::Error>) -> Result<(), Self::Error> {
        match reason {
            client::DisconnectReason::ReceivedDisconnect(info) => {
                *self.hung_up.lock().unwrap() = Some(info.message);
                Ok(())
            }
            client::DisconnectReason::Error(e) => Err(e),
        }
    }
}

/// Trust on first use, pinned per route; None when the key matches the
/// route's pin or the one trusted earlier this run. A pin must match exactly;
/// with no pin, an entry in known_hosts is pinned silently and anything else
/// is the user's call, or refused where nobody can be asked.
fn judge(route: &Route, key: &PublicKey, known_hosts: Option<&Path>) -> Option<Judgement> {
    let fp = key.fingerprint(HashAlg::Sha256).to_string();
    if !route.host_key.is_empty() {
        return (route.host_key != fp).then(|| {
            Judgement::Refused(format!(
                "its host key has changed: pinned {}, presented {fp}. If the server was really \
                 rebuilt, run `bmc-kvm route forget {}`.",
                route.host_key, route.name
            ))
        });
    }
    if let Some(trusted) = settled().lock().unwrap().pins.get(&run_key(route)) {
        return (*trusted != fp).then(|| {
            Judgement::Refused(format!(
                "its host key has changed since it was trusted earlier in this run: trusted {trusted}, \
                 presented {fp}"
            ))
        });
    }
    if let Some(path) = known_hosts {
        match keys::check_known_hosts_path(&route.host, route.port, key, path) {
            Ok(true) => return Some(Judgement::Listed(fp)),
            Err(keys::Error::KeyChanged { line }) => {
                return Some(Judgement::Refused(format!(
                    "it presents {fp}, which does not match line {line} of {}",
                    path.display()
                )))
            }
            _ => {}
        }
    }
    Some(Judgement::Unknown(fp))
}

/// Ask whether to trust a key nothing vouches for. Outside every network
/// timeout: the user may take their time over a fingerprint. A yes holds for
/// this run at once, so that the next handshake passes; `dial` pins it once
/// the login has worked.
async fn ask_trust(hop: &Route, fp: &str, ctx: &Context) -> io::Result<()> {
    let Some(prompter) = ctx.prompter.clone() else {
        return Err(unasked(format!(
            "its host key {fp} is not trusted yet: run `bmc-kvm route test {name}` to trust it, \
             or check it and run `bmc-kvm route pin {name} {fp}`",
            name = hop.name
        )));
    };
    let (r, f) = (hop.clone(), fp.to_owned());
    let asking = ctx.asked.asking();
    let trusted = tokio::task::spawn_blocking(move || prompter.trust_host_key(&r, &f)).await.unwrap_or(false);
    drop(asking);
    if !trusted {
        return Err(refused("its host key was not trusted"));
    }
    trust_for_run(hop, fp);
    Ok(())
}

/// Where a secret came from, which decides what happens once it is tried.
enum Origin {
    Route,
    Run,
    Typed { save: bool },
}

struct Secret {
    value: String,
    origin: Origin,
}

fn remembered(route: &Route) -> Option<String> {
    settled().lock().unwrap().secrets.get(&run_key(route)).cloned()
}

/// Nothing can ask for a secret but `route test` in a terminal, until the
/// GUI can; `route edit --password` saves one, a password or, on a route
/// that logs in with a key, its passphrase.
fn missing(route: &Route, what: &str) -> io::Error {
    let name = &route.name;
    unasked(format!(
        "route {name} needs its {what}: save it with `bmc-kvm route edit {name} --password`, \
         or run `bmc-kvm route test {name}` to enter it"
    ))
}

/// The route's stored secret, one typed earlier this run, or one asked for.
/// Background work has no prompter and fails with what to fix instead.
async fn secret(route: &Route, ctx: &Context, what: &str) -> io::Result<Secret> {
    if !route.secret.is_empty() {
        return Ok(Secret { value: route.secret.clone(), origin: Origin::Route });
    }
    if let Some(value) = remembered(route) {
        return Ok(Secret { value, origin: Origin::Run });
    }
    let Some(prompter) = ctx.prompter.clone() else {
        return Err(missing(route, what));
    };
    let (r, w) = (route.clone(), what.to_owned());
    let asking = ctx.asked.asking();
    let answer = tokio::task::spawn_blocking(move || prompter.secret(&r, &w)).await.map_err(|e| other(e.to_string()));
    drop(asking);
    let answer = answer?;
    let (value, save) = answer.ok_or_else(|| io::Error::new(io::ErrorKind::Interrupted, "cancelled"))?;
    Ok(Secret { value, origin: Origin::Typed { save } })
}

/// Settle a secret once it has been tried. One the user typed is kept for
/// the run (and saved, if they asked) only once it has worked, so a typo is
/// asked for again rather than remembered; one kept from earlier that no
/// longer works is dropped, so the next connect asks.
fn settle(route: &Route, s: &Secret, worked: bool, what: &str, ctx: &Context) {
    match (&s.origin, worked) {
        (Origin::Typed { save }, true) => {
            settled().lock().unwrap().secrets.insert(run_key(route), s.value.clone());
            if *save {
                if let Err(e) = crate::routes::save_secret(&route.name, &s.value) {
                    say(ctx, &format!("Could not save {}'s {what} ({e}); it is kept for this run only", route.name));
                }
            }
        }
        (Origin::Run, false) => {
            settled().lock().unwrap().secrets.remove(&run_key(route));
        }
        _ => {}
    }
}

/// The secret `hop` would have to ask for before it could authenticate: a
/// password, or an encrypted key's passphrase, that neither the route nor
/// this run knows.
fn unasked_secret(hop: &Route) -> Option<&'static str> {
    if !hop.secret.is_empty() || remembered(hop).is_some() {
        return None;
    }
    match hop.auth {
        Auth::Password => Some("password"),
        Auth::Key if matches!(keys::load_secret_key(&hop.key_file, None), Err(keys::Error::KeyIsEncrypted)) => {
            Some("key passphrase")
        }
        _ => None,
    }
}

fn ssh_err(e: russh::Error) -> io::Error {
    other(format!("SSH: {e}"))
}

/// What can be found wrong without dialling: no agent to ask, an agent with
/// no keys to offer, a key file that cannot be read, a saved passphrase that
/// does not open it. Each would otherwise fail only after a full handshake,
/// which sshd logs and an aggressive fail2ban counts. Returns the key, if it
/// opened, for `authenticate`.
async fn check_locally(hop: &Route) -> io::Result<Option<keys::PrivateKey>> {
    match hop.auth {
        // A locked agent lists no keys either. Not a refusal: `ssh-add`, or
        // unlocking it, mends it without touching the route.
        Auth::Agent => match agent().await?.request_identities().await {
            Ok(ids) if ids.is_empty() => {
                Err(other("the SSH agent holds no keys (ssh-add one, or unlock the agent with ssh-add -X)"))
            }
            Ok(_) => Ok(None),
            Err(e) => Err(other(format!("SSH agent: {e}"))),
        },
        Auth::Password => Ok(None),
        Auth::Key => {
            let saved = (!hop.secret.is_empty()).then_some(hop.secret.as_str());
            let unreadable = |e: &dyn std::fmt::Display| other(format!("cannot read key file {}: {e}", hop.key_file));
            match keys::load_secret_key(&hop.key_file, saved) {
                Ok(key) => Ok(Some(key)),
                // Nothing saved: a passphrase typed earlier this run, or one
                // asked for, opens it.
                Err(keys::Error::KeyIsEncrypted) => Ok(None),
                Err(keys::Error::IO(e)) => Err(unreadable(&e)),
                Err(e) if saved.is_some() => Err(refused(format!(
                    "the passphrase saved in route {} does not open key file {}: {e}",
                    hop.name, hop.key_file
                ))),
                Err(e) => Err(unreadable(&e)),
            }
        }
    }
}

async fn authenticate(
    h: &mut client::Handle<Client>,
    hung_up: &HungUp,
    r: &Route,
    ctx: &Context,
    opened: Option<keys::PrivateKey>,
) -> io::Result<()> {
    say(ctx, &format!("Authenticating to {}…", r.name));
    let ok = match r.auth {
        Auth::Agent => by_agent(h, hung_up, &r.user).await?,
        Auth::Key => {
            let saved = (!r.secret.is_empty()).then_some(r.secret.as_str());
            let key = match opened.map_or_else(|| keys::load_secret_key(&r.key_file, saved), Ok) {
                Ok(k) => k,
                Err(keys::Error::KeyIsEncrypted) => {
                    let pass = secret(r, ctx, "key passphrase").await?;
                    let loaded = keys::load_secret_key(&r.key_file, Some(&pass.value));
                    settle(r, &pass, loaded.is_ok(), "key passphrase", ctx);
                    loaded.map_err(|e| refused(format!("wrong passphrase for key file {} ({e})", r.key_file)))?
                }
                Err(e) => return Err(other(format!("cannot read key file {}: {e}", r.key_file))),
            };
            let hash = bounded("authentication", async { h.best_supported_rsa_hash().await.map_err(ssh_err) })
                .await?
                .flatten();
            let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash);
            bounded("authentication", async { h.authenticate_publickey(&r.user, key).await.map_err(ssh_err) })
                .await?
                .success()
        }
        Auth::Password => {
            let pass = secret(r, ctx, "password").await?;
            let tried =
                bounded("authentication", async { h.authenticate_password(&r.user, &pass.value).await.map_err(ssh_err) })
                    .await?;
            let ok = match tried {
                client::AuthResult::Success => true,
                // Keyboard-interactive only where the server takes no
                // password at all: after a refused one it would be a second
                // failure against MaxAuthTries, and against fail2ban.
                client::AuthResult::Failure { remaining_methods, .. } => {
                    !remaining_methods.contains(&MethodKind::Password)
                        && remaining_methods.contains(&MethodKind::KeyboardInteractive)
                        && keyboard_interactive(h, &r.user, &pass.value).await?
                }
            };
            settle(r, &pass, ok, "password", ctx);
            ok
        }
    };
    if ok {
        Ok(())
    } else {
        let tried = match r.auth {
            Auth::Agent => "the agent's keys",
            Auth::Key => "the key file",
            Auth::Password => "the password",
        };
        Err(refused(format!("authentication failed (tried {tried})")))
    }
}

/// Servers that offer only keyboard-interactive get the password once, for
/// a round that asks one hidden question that names a password or
/// passphrase. Anything else (a prompt that echoes, an OTP asked first, a
/// second question in the round or after it) is MFA or something like it,
/// and answering it with the password would hand the password to an OTP
/// check, and to whatever service verifies it. sshd runs PAM in the C
/// locale, so a prompt in another language is refused with the rest. Rounds
/// that ask nothing, as PAM sends after the password, are answered with
/// nothing.
async fn keyboard_interactive(h: &mut client::Handle<Client>, user: &str, pass: &str) -> io::Result<bool> {
    use client::KeyboardInteractiveAuthResponse as R;
    let mut r = bounded("authentication", async {
        h.authenticate_keyboard_interactive_start(user, None).await.map_err(ssh_err)
    })
    .await?;
    let mut answered = false;
    for _ in 0..4 {
        let answers = match r {
            R::Success => return Ok(true),
            R::Failure { .. } => return Ok(false),
            R::InfoRequest { ref prompts, .. } if prompts.is_empty() => Vec::new(),
            R::InfoRequest { ref prompts, .. } if !answered && prompts.len() == 1 && asks_for_password(&prompts[0]) => {
                answered = true;
                vec![pass.to_owned()]
            }
            R::InfoRequest { .. } => {
                return Err(refused("the jump host asks for more than a password (MFA?); use an agent or key"))
            }
        };
        r = bounded("authentication", async {
            h.authenticate_keyboard_interactive_respond(answers).await.map_err(ssh_err)
        })
        .await?;
    }
    Ok(false)
}

/// Some OTP modules name their code a password ("One-time password (OATH)"
/// from pam_oath), so a prompt that also names one of these is not ours.
const NOT_A_PASSWORD: [&str; 6] = ["one time", "otp", "oath", "verification", "code", "token"];

/// Whole words only, and only in the question: what is asked comes before
/// whom it is for ("Password for jdoe@REALM: "), and a realm, a host or a
/// user name can hold any word ("hotpoint" holds "otp").
fn asks_for_password(p: &client::Prompt) -> bool {
    let text = p.prompt.to_ascii_lowercase();
    let question = text.split(" for ").next().unwrap_or_default();
    let words: Vec<&str> = question.split(|c: char| !c.is_ascii_alphanumeric()).filter(|w| !w.is_empty()).collect();
    // Spaced at both ends, so that each test is for whole words.
    let words = format!(" {} ", words.join(" "));
    let says = |w: &str| words.contains(&format!(" {w} "));
    !p.echo && (says("password") || says("passphrase")) && !NOT_A_PASSWORD.iter().any(|w| says(w))
}

type Agent = keys::agent::client::AgentClient<Box<dyn keys::agent::client::AgentStream + Send + Unpin>>;

/// This user's SSH agent.
async fn agent() -> io::Result<Agent> {
    use keys::agent::client::AgentClient;
    let none = |e: keys::Error| other(format!("no SSH agent: {e}"));
    #[cfg(all(any(test, feature = "testing"), unix))]
    if let Some(path) = test_agent() {
        return AgentClient::connect_uds(path).await.map(AgentClient::dynamic).map_err(none);
    }
    #[cfg(unix)]
    return AgentClient::connect_env().await.map(AgentClient::dynamic).map_err(none);
    // The Windows OpenSSH agent first, Pageant if it is not running.
    #[cfg(windows)]
    return match AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await {
        Ok(a) => Ok(a.dynamic()),
        Err(_) => AgentClient::connect_pageant().await.map(AgentClient::dynamic).map_err(none),
    };
}

/// Offer the agent's keys in turn. sshd hangs up after MaxAuthTries refusals
/// (six by default), so an agent holding more keys has had its answer once
/// the jump host ends the session: that is a refusal like any other, not a
/// network failure to be tried again.
async fn by_agent(h: &mut client::Handle<Client>, hung_up: &HungUp, user: &str) -> io::Result<bool> {
    let mut agent = agent().await?;
    let ids = agent.request_identities().await.map_err(|e| other(format!("SSH agent: {e}")))?;
    for id in ids {
        let keys::agent::AgentIdentity::PublicKey { key, .. } = id else { continue };
        let signed = async {
            let hash = bounded("authentication", async { h.best_supported_rsa_hash().await.map_err(ssh_err) })
                .await?
                .flatten();
            bounded("authentication", async {
                h.authenticate_publickey_with(user, key, hash, &mut agent)
                    .await
                    .map_err(|e| other(format!("SSH agent: {e:?}")))
            })
            .await
        }
        .await;
        if signed.as_ref().is_ok_and(|r| r.success()) {
            return Ok(true);
        }
        if h.is_closed() {
            if let Some(said) = hung_up.lock().unwrap().clone() {
                return Err(refused(format!(
                    "authentication failed (tried the agent's keys until the jump host hung up: {said})"
                )));
            }
        }
        signed?;
    }
    Ok(false)
}

/// Why a handshake did not complete.
enum Unmet {
    /// Nothing vouches for the key with this fingerprint.
    Unknown(String),
    Failed(io::Error),
}

/// Reach `hop` through `rest` and run the SSH handshake, judging the key
/// without asking anyone.
async fn handshake(
    hop: &Route,
    rest: &[Route],
    ctx: &Context,
    known_hosts: Option<PathBuf>,
) -> Result<(client::Handle<Client>, Vec<Lease>, HungUp, Option<String>), Unmet> {
    let (transport, outer) = open_stream(rest, &hop.host, hop.port, ctx, None).await.map_err(Unmet::Failed)?;
    let config = Arc::new(client::Config {
        keepalive_interval: Some(KEEPALIVE),
        keepalive_max: 3,
        nodelay: true,
        ..Default::default()
    });
    let (judged, hung_up) = (Arc::new(Mutex::new(None)), HungUp::default());
    let client = Client { route: hop.clone(), known_hosts, judged: judged.clone(), hung_up: hung_up.clone() };
    let connected =
        tokio::time::timeout_at(phase_end(handshake_timeout()), client::connect_stream(config, transport, client)).await;
    let judgement = judged.lock().unwrap().take();
    match (connected, judgement) {
        (Err(_), _) => Err(Unmet::Failed(timed_out(format!(
            "no SSH server answered at {}:{} (the SSH handshake timed out)",
            hop.host, hop.port
        )))),
        // known_hosts vouched for a key no pin named: `dial` pins it once
        // the login has worked.
        (Ok(Ok(handle)), judgement) => {
            let listed = match judgement {
                Some(Judgement::Listed(fp)) => Some(fp),
                _ => None,
            };
            Ok((handle, outer, hung_up, listed))
        }
        (Ok(Err(_)), Some(Judgement::Unknown(fp))) => Err(Unmet::Unknown(fp)),
        (Ok(Err(_)), Some(Judgement::Refused(why))) => Err(Unmet::Failed(refused(why))),
        (Ok(Err(e)), _) => Err(Unmet::Failed(other(format!("SSH handshake failed: {e}")))),
    }
}

/// The SSH connection for `chain`'s last hop, opened if need be.
pub(crate) fn tunnel<'a>(
    chain: &'a [Route],
    ctx: &'a Context,
) -> Pin<Box<dyn Future<Output = io::Result<Lease>> + Send + 'a>> {
    Box::pin(open_tunnel(chain, ctx))
}

/// A lease on `chain`'s tunnel: the live one, or the open in progress once
/// it finishes, or a new open. Waits no longer than the caller's deadline,
/// and a moment past it for the open's own account; the open itself goes on.
///
/// An open that is asking the user something holds the chain's slot until
/// it is answered, so every other caller on that chain waits on it and,
/// past its own deadline, gives up saying another connection is opening the
/// tunnel. Only `route test` asks today, in a process of its own, so nothing
/// else in that process is held; a GUI that asks would want the question
/// answered off the slot.
async fn open_tunnel(chain: &[Route], ctx: &Context) -> io::Result<Lease> {
    let hop = chain.last().expect("a tunnel needs a hop");
    let slot = slots().lock().unwrap().entry(super::chain_key(chain)).or_default().clone();
    let can_ask = ctx.prompter.is_some();
    // Round again once an open finishes: to take the lease under the slot's
    // lock, or to try for ourselves where the open's answer is not ours. A
    // tunnel reaped in between is opened again, but not for ever.
    // Whether the last round ended on another open's answer, rather than
    // on a tunnel that was gone again by the time it was looked for.
    let mut others_answered = false;
    for _ in 0..4 {
        let (mut waiting, ours) = {
            let mut g = slot.lock().unwrap();
            if let Some(t) = g.tunnel.as_ref().filter(|t| !t.handle.is_closed()) {
                return Ok(Lease::new(t.clone()));
            }
            // An open whose task has gone without saying how it went is
            // forgotten, not waited on for ever.
            match g.opening.as_ref().filter(|o| o.outcome.has_changed().is_ok()) {
                // One started for the chain as it was before an edit (a
                // password put right, a pin saved) is waited out, not taken
                // at its word: its refusal was of what has since changed.
                Some(o) => (o.outcome.clone(), o.chain == chain),
                None => {
                    // Background work cannot be asked for a secret, so it
                    // fails here rather than after a full handshake: probes
                    // must not hammer the jump host.
                    if !can_ask {
                        if let Some(what) = unasked_secret(hop) {
                            return Err(via(hop, missing(hop, what)));
                        }
                    }
                    if let Some(e) = g.failed.as_ref().and_then(|f| f.answer(chain, caller().since, can_ask)) {
                        return Err(e);
                    }
                    let (tx, rx) = watch::channel(None);
                    g.opening = Some(Underway { chain: chain.to_vec(), outcome: rx.clone() });
                    start_open(&slot, chain, ctx, tx);
                    (rx, true)
                }
            }
        };
        let finished = waiting.wait_for(Option::is_some);
        let outcome = match caller().until {
            Some(until) => before(|| until.get() + BACKSTOP_AFTER, finished).await.ok_or_else(|| {
                via(
                    hop,
                    timed_out(if ours {
                        "timed out waiting for the SSH tunnel to open"
                    } else {
                        "timed out waiting for the SSH tunnel, which another connection is opening"
                    }),
                )
            })?,
            None => finished.await,
        }
        .map_err(|_| via(hop, other("opening the SSH tunnel was abandoned")))?
        .clone()
        .expect("waited for an outcome");
        match outcome {
            Err(f) if ours && !(can_ask && f.cause == Cause::Unasked) => return Err(f.error()),
            // A tunnel to take a lease on; the answer about another version
            // of the chain; or a key or secret the open could ask nobody
            // about, which this caller can: round again, through `answer`.
            outcome => others_answered = outcome.is_err(),
        }
    }
    Err(via(
        hop,
        other(if others_answered {
            "other connections through this route kept it busy; try again"
        } else {
            "the SSH tunnel closed as soon as it opened"
        }),
    ))
}

/// Open `chain`'s tunnel as a task of its own, which settles the slot and
/// then tells every caller waiting on `tx`. It asks only if the caller that
/// started it could: an open background work started never prompts.
fn start_open(slot: &Slot, chain: &[Route], ctx: &Context, tx: watch::Sender<Option<Outcome>>) {
    let (slot, chain, ctx) = (slot.clone(), chain.to_vec(), ctx.clone());
    // Read here: the task runs on the runtime, not on the caller's thread.
    let known_hosts = known_hosts();
    let open = async move {
        let (hop, rest) = chain.split_last().expect("a tunnel needs a hop");
        let limit = Deadline::after(TUNNEL_TIMEOUT, &ctx.asked);
        let dialled = before(|| limit.get(), dial(hop, rest, &ctx, known_hosts))
            .await
            .unwrap_or_else(|| Err(via(hop, timed_out("opening the SSH tunnel timed out"))));
        let outcome = {
            let mut g = slot.lock().unwrap();
            g.opening = None;
            match dialled {
                Ok(t) => {
                    g.failed = None;
                    g.tunnel = Some(t.clone());
                    Ok(t)
                }
                Err(e) => {
                    if let Some(f) = Failure::of(&chain, &e) {
                        g.failed = Some(f);
                    }
                    Err(Fail::of(&e))
                }
            }
        };
        let _ = tx.send(Some(outcome));
    };
    // Not the caller's deadline: the open is not cut short with it.
    let open = CALLER.scope(Caller { until: None, since: caller().since }, open);
    #[cfg(any(test, feature = "testing"))]
    let open = TEST_LOCAL.scope(
        TestLocal {
            phase: handshake_timeout(),
            known_hosts: test_known_hosts(),
            #[cfg(unix)]
            agent: test_agent(),
        },
        open,
    );
    runtime().spawn(open);
}

/// Reach `hop`, check its key and log in.
async fn dial(hop: &Route, rest: &[Route], ctx: &Context, known_hosts: Option<PathBuf>) -> io::Result<Arc<Tunnel>> {
    let opened = check_locally(hop).await.map_err(|e| via(hop, e))?;
    say(ctx, &format!("Opening SSH tunnel via {}…", hop.name));
    let mut trusted = None;
    let shaken = match handshake(hop, rest, ctx, known_hosts.clone()).await {
        // Asked between handshakes, so no network timeout runs while the user
        // reads the fingerprint. The refused connection is gone; once the key
        // is trusted, a second one finds it trusted for the run.
        Err(Unmet::Unknown(fp)) => {
            ask_trust(hop, &fp, ctx).await.map_err(|e| via(hop, e))?;
            trusted = Some(fp);
            handshake(hop, rest, ctx, known_hosts).await
        }
        r => r,
    };
    let (mut handle, outer, hung_up, listed) = shaken.map_err(|u| {
        via(
            hop,
            match u {
                Unmet::Failed(e) => e,
                Unmet::Unknown(fp) => refused(format!("its host key {fp} is still not trusted")),
            },
        )
    })?;
    authenticate(&mut handle, &hung_up, hop, ctx, opened).await.map_err(|e| via(hop, e))?;
    if let Some(fp) = listed.or(trusted) {
        pin(hop, &fp, ctx);
    }
    Ok(Arc::new(Tunnel {
        handle,
        leases: AtomicUsize::new(0),
        idle_since: Mutex::new(Some(Instant::now())),
        _transport: outer,
    }))
}

/// A stream to `host:port` through `chain`, outermost hop first: TCP when the
/// chain is empty, a SOCKS5 CONNECT for a proxy hop, a channel for an SSH hop.
/// `reach`, when shorter than a phase's own limit, bounds the step that
/// reaches `host:port` itself: the caller's patience with its BMC.
pub(crate) fn open_stream<'a>(
    chain: &'a [Route],
    host: &'a str,
    port: u16,
    ctx: &'a Context,
    reach: Option<Duration>,
) -> Opening<'a> {
    Box::pin(async move {
        let limit = reach.map_or_else(handshake_timeout, |r| r.min(handshake_timeout()));
        let Some((hop, rest)) = chain.split_last() else {
            let tcp = bounded_by(limit, &format!("connecting to {host}:{port}"), async {
                tokio::net::TcpStream::connect((host, port)).await
            })
            .await?;
            tcp.set_nodelay(true).ok();
            return Ok((Box::new(tcp) as BoxIo, Vec::new()));
        };
        match hop.kind {
            Kind::Socks5 => {
                let (mut s, leases) = open_stream(rest, &hop.host, hop.port, ctx, None).await.map_err(|e| via(hop, e))?;
                bounded_by(limit, "the SOCKS5 handshake", socks::connect_async(&mut s, host, port, socks::auth_of(hop)))
                    .await
                    .map_err(|e| via(hop, e))?;
                Ok((s, leases))
            }
            Kind::Ssh => {
                let lease = tunnel(chain, ctx).await?;
                let channel = bounded_by(limit, &format!("opening a channel to {host}:{port}"), async {
                    lease
                        .0
                        .handle
                        .channel_open_direct_tcpip(host, port as u32, "127.0.0.1", 0)
                        .await
                        .map_err(|e| other(format!("could not reach {host}:{port}: {e}")))
                })
                .await
                .map_err(|e| via(hop, e))?;
                Ok((Box::new(channel.into_stream()) as BoxIo, vec![lease]))
            }
        }
    })
}

/// `open_stream` for a caller of `ctx` that will wait `timeout`: for that
/// long in all, as `within` decides.
pub(crate) async fn reach(
    chain: &[Route],
    host: &str,
    port: u16,
    ctx: &Context,
    timeout: Option<Duration>,
) -> io::Result<(BoxIo, Vec<Lease>)> {
    let late = || {
        let e = timed_out(format!("timed out reaching {host}:{port}"));
        match chain.last() {
            Some(hop) => via(hop, e),
            None => e,
        }
    };
    within(ctx, timeout, late, open_stream(chain, host, port, ctx, timeout)).await
}

/// `net::connect` for a chain with an SSH hop: open the channel here, then
/// collect it from the front end as a real socket.
pub fn connect(chain: &[Route], host: &str, port: u16, timeout: Option<Duration>) -> io::Result<TcpStream> {
    let ctx = super::context();
    let (io, leases) = runtime().block_on(reach(chain, host, port, &ctx, timeout))?;
    front::hand_over(io, leases)
}

/// Open (or reuse) `chain`'s tunnel and nothing more: `route test`'s first stage.
pub(crate) fn check(chain: &[Route]) -> io::Result<()> {
    let ctx = super::context();
    let hop = chain.last().expect("a tunnel needs a hop");
    let late = || via(hop, timed_out("opening the SSH tunnel timed out"));
    runtime().block_on(within(&ctx, None, late, tunnel(chain, &ctx))).map(drop)
}

/// What the jump host runs to carry IPMI: socat if it has it, else nc. The
/// BMC's address and port are positional arguments, never part of the
/// script, and are checked first.
///
/// socat sends with `UDP-SENDTO`, an unconnected socket: on a connected one a
/// BMC answering ICMP port-unreachable (IPMI over LAN off, or rebooting) fails
/// socat's next read, and the relay exits as if the jump host could not run it.
pub(crate) fn relay_command(host: &str, port: u16) -> io::Result<String> {
    // IPv6 is refused: socat would need UDP6:[…] and nc a flag, per flavour.
    // A leading '-' would reach nc as an option, so the first character must
    // be alphanumeric; `--` before the address is the second line of defence.
    let first_ok = host.starts_with(|c: char| c.is_ascii_alphanumeric());
    if !first_ok || !host.chars().all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the IPMI relay takes IPv4 addresses and host names only",
        ));
    }
    Ok(format!(
        "sh -c 'if command -v socat >/dev/null 2>&1; then exec socat -T 60 - \"UDP-SENDTO:$0:$1\"; \
         elif command -v nc >/dev/null 2>&1; then exec nc -u -w 60 -- \"$0\" \"$1\"; \
         else echo \"no socat or nc on the jump host\" >&2; exit 127; fi' {host} {port}"
    ))
}

#[derive(Default)]
struct Ending {
    status: Option<u32>,
    /// The start of what the command wrote to stderr: socat's own account of
    /// a failure, such as a BMC name the jump host cannot resolve.
    stderr: Vec<u8>,
}

/// What the jump host reported when the relay's command ended. Only its exit
/// status tells a jump host without socat or nc, which no BMC behind it can
/// use, from a relay that stopped over one BMC.
#[derive(Clone, Default)]
pub struct RelayEnd(Arc<Mutex<Ending>>);

impl RelayEnd {
    /// The shell's "command not found": neither socat nor nc.
    pub fn lacks_tools(&self) -> bool {
        self.0.lock().unwrap().status == Some(127)
    }

    /// Why the relay stopped, as far as the jump host said.
    pub fn describe(&self) -> String {
        let e = self.0.lock().unwrap();
        let stderr = String::from_utf8_lossy(&e.stderr);
        let said = stderr.lines().map(str::trim).filter(|l| !l.is_empty()).last();
        match (e.status, said) {
            (Some(127), _) => "the jump host has neither socat nor nc, which the IPMI relay needs".into(),
            (Some(s), Some(said)) => format!("the IPMI relay on the jump host exited with status {s}: {said}"),
            (Some(s), None) => format!("the IPMI relay on the jump host exited with status {s}"),
            (None, _) => "the IPMI relay on the jump host closed".into(),
        }
    }
}

const STDERR_KEPT: usize = 512;

/// Carry the relay's channel through a pipe, keeping the exit status and
/// stderr that a channel stream drops. The pipe ends when the channel closes,
/// which RFC 4254 §6.10 has come after the exit status, so whoever reads the
/// end of the stream finds the status already recorded.
fn pump(channel: russh::Channel<client::Msg>, end: RelayEnd) -> BoxIo {
    use tokio::io::AsyncWriteExt;
    let (ours, theirs) = tokio::io::duplex(64 * 1024);
    let (mut from_us, mut to_us) = tokio::io::split(theirs);
    let (mut rx, tx) = channel.split();
    tokio::spawn(async move {
        let down = async {
            while let Some(msg) = rx.wait().await {
                match msg {
                    russh::ChannelMsg::Data { data } => {
                        if to_us.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    russh::ChannelMsg::ExtendedData { data, ext: 1 } => {
                        let mut e = end.0.lock().unwrap();
                        let room = STDERR_KEPT.saturating_sub(e.stderr.len());
                        e.stderr.extend_from_slice(&data[..data.len().min(room)]);
                    }
                    russh::ChannelMsg::ExitStatus { exit_status } => end.0.lock().unwrap().status = Some(exit_status),
                    russh::ChannelMsg::Close => break,
                    _ => {}
                }
            }
            let _ = to_us.shutdown().await;
        };
        tokio::pin!(down);
        let up = async {
            let _ = tokio::io::copy(&mut from_us, &mut tx.make_writer()).await;
            let _ = tx.eof().await;
        };
        tokio::select! {
            _ = &mut down => {}
            // Our side is done; give the relay a moment to exit on its EOF.
            _ = up => {
                let _ = tokio::time::timeout(Duration::from_secs(5), &mut down).await;
            }
        }
        let _ = tx.close().await;
    });
    Box::new(ours)
}

/// IPMI through an SSH jump host: an exec channel running `relay_command`,
/// handed over as a socket that carries the datagrams as a byte stream, with
/// what the jump host reports once the command ends.
pub(crate) fn relay(chain: &[Route], host: &str, port: u16) -> io::Result<(TcpStream, RelayEnd)> {
    let command = relay_command(host, port)?;
    let hop = chain.last().expect("a relay needs a hop");
    let ctx = super::context();
    let end = RelayEnd::default();
    let late = || via(hop, timed_out("opening the IPMI relay timed out"));
    let (io, leases) = runtime().block_on(within(&ctx, None, late, async {
        let lease = tunnel(chain, &ctx).await?;
        say(&ctx, "Opening IPMI relay…");
        let channel = bounded("opening the IPMI relay's channel", async {
            lease.0.handle.channel_open_session().await.map_err(ssh_err)
        })
        .await
        .map_err(|e| via(hop, e))?;
        bounded("starting the IPMI relay", async { channel.exec(true, command).await.map_err(ssh_err) })
            .await
            .map_err(|e| via(hop, e))?;
        Ok::<_, io::Error>((pump(channel, end.clone()), vec![lease]))
    }))?;
    Ok((front::hand_over(io, leases)?, end))
}

#[cfg(any(test, feature = "testing"))]
pub mod testing {
    //! An in-process SSH server for the tests. It takes password or key
    //! auth, opens `direct-tcpip` to anything on loopback, and answers `exec`
    //! by relaying datagrams to a UDP target, standing in for socat.

    use russh::keys::PublicKey;
    use russh::server::{self, Auth as SAuth, Msg, Session};
    use russh::{Channel, ChannelId, MethodKind, MethodSet};
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    use std::sync::{Arc, Mutex, Once};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub const HOST_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDHrWqM2hWriuvckvEcNlqjYrFjuI0GpWm6RRI3wsTodAAAAJjSlBxw0pQc
cAAAAAtzc2gtZWQyNTUxOQAAACDHrWqM2hWriuvckvEcNlqjYrFjuI0GpWm6RRI3wsTodA
AAAEA0fGO/mTIxcT52kZi/4CGqZsTnzDYA0/FDxrdsrCyxgcetaozaFauK69yS8Rw2WqNi
sWO4jQalabpFEjfCxOh0AAAAFWJtYy1rdm0gdGVzdCBob3N0IGtleQ==
-----END OPENSSH PRIVATE KEY-----
";
    pub const HOST_FP: &str = "SHA256:mpqLvnyKWXVAxgjB1CgmafTUVxSGmZUUGCP4LPDz38M";
    pub const CLIENT_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDALbl2EIjvH3J0B9pITHnWcfp2pzigScWztPMUlEDINAAAAKBYr3CJWK9w
iQAAAAtzc2gtZWQyNTUxOQAAACDALbl2EIjvH3J0B9pITHnWcfp2pzigScWztPMUlEDINA
AAAEASTFgJXWVWKxllhWbV0OcP0V1468FSLFSoW3HD69NjysAtuXYQiO8fcnQH2khMedZx
+nanOKBJxbO08xSUQMg0AAAAF2JtYy1rdm0gdGVzdCBjbGllbnQga2V5AQIDBAUG
-----END OPENSSH PRIVATE KEY-----
";
    pub const PASSWORD: &str = "correct horse";
    /// An ed25519 key under the passphrase "right passphrase", made for
    /// these tests; no server takes it. One KDF round (`ssh-keygen -a 1`):
    /// each round is a full bcrypt, which a debug build runs slowly, and two
    /// of CI's three legs run the tests in one.
    pub const ENCRYPTED_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAdqYme0z
FmbE31nmfkF/IJAAAAAQAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAINJucRo1yV38vjqd
etiA4boWadk1yjwEYOM8i649Oe8oAAAAkK6PwP9CvRvRDiH6ilwlJJlagTcLG/JRizv626
iaojlg0W0mekPCUu5BKBFqX/icOm9Fcudgm+xu6Oewaka3AbHV/WjlUOfqwy+yDczXZt1y
CbqQH5f6wwHeHHUdCIdxXd63gZj1gk85Kz/0J+GO0SFEmeE1md+ySgmJg6N+SfX6I8qA5a
fQE+N6rAS9jK+lDg==
-----END OPENSSH PRIVATE KEY-----
";

    /// Point config_dir() at a scratch directory for the whole test process,
    /// so pins and saved secrets never touch the real inventory.
    pub fn isolate_config() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let dir = std::env::temp_dir().join(format!("bmc-kvm-net-tests-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            std::env::set_var("BMCKVM_CONFIG_DIR", dir);
        });
    }

    /// `[127.0.0.1]:port ssh-ed25519 …`, a known_hosts line for the test server.
    pub fn host_public_line(addr: SocketAddr) -> String {
        let key = russh::keys::decode_secret_key(HOST_KEY, None).unwrap();
        format!("[{}]:{} {}\n", addr.ip(), addr.port(), key.public_key().to_openssh().unwrap())
    }

    /// A keyboard-interactive round: each prompt, and whether it echoes.
    pub type Round = Vec<(&'static str, bool)>;

    /// How a test server behaves beyond taking a password or a key.
    #[derive(Clone, Default)]
    pub struct Options {
        pub udp_target: Option<SocketAddr>,
        /// How long refusing a login takes, so that other callers can queue
        /// behind it meanwhile.
        pub refuse_after: Option<Duration>,
        /// How long accepting the right password takes.
        pub login_after: Option<Duration>,
        /// Refused logins after which the server hangs up, as sshd's
        /// MaxAuthTries does.
        pub max_auth: Option<usize>,
        /// Offer keyboard-interactive only, in these rounds; the password,
        /// given once in all, logs in.
        pub rounds: Vec<Round>,
    }

    /// What a test server has been asked.
    #[derive(Default)]
    pub struct Seen {
        /// TCP connections accepted: one per tunnel opened or attempted.
        pub dials: AtomicUsize,
        /// Password logins tried.
        pub passwords: AtomicUsize,
        /// Each keyboard-interactive response, in order.
        pub answers: Mutex<Vec<Vec<String>>>,
    }

    impl Seen {
        pub fn dials(&self) -> usize {
            self.dials.load(SeqCst)
        }
        pub fn passwords(&self) -> usize {
            self.passwords.load(SeqCst)
        }
    }

    /// The direct-tcpip target whose channel the server never answers, like
    /// a jump host waiting on a BMC that drops its SYNs.
    pub const SILENT: &str = "silent.invalid";

    #[derive(Clone)]
    struct Handler {
        client_key: PublicKey,
        udp_target: Option<SocketAddr>,
        login_after: Option<Duration>,
        rounds: Arc<Vec<Round>>,
        seen: Arc<Seen>,
        sessions: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
        /// This session's keyboard-interactive round, and what it was told.
        round: usize,
        given: Vec<String>,
    }

    impl server::Handler for Handler {
        type Error = russh::Error;

        async fn auth_password(&mut self, _user: &str, password: &str) -> Result<SAuth, Self::Error> {
            self.seen.passwords.fetch_add(1, SeqCst);
            if password != PASSWORD || !self.rounds.is_empty() {
                return Ok(SAuth::reject());
            }
            if let Some(d) = self.login_after {
                tokio::time::sleep(d).await;
            }
            Ok(SAuth::Accept)
        }

        async fn auth_keyboard_interactive<'a>(
            &'a mut self,
            _user: &str,
            _submethods: &str,
            response: Option<server::Response<'a>>,
        ) -> Result<SAuth, Self::Error> {
            if self.rounds.is_empty() {
                return Ok(SAuth::reject());
            }
            match response {
                None => (self.round, self.given) = (0, Vec::new()),
                Some(r) => {
                    let answers: Vec<String> = r.map(|b| String::from_utf8_lossy(&b).into_owned()).collect();
                    self.given.extend(answers.iter().cloned());
                    self.seen.answers.lock().unwrap().push(answers);
                    self.round += 1;
                }
            }
            if let Some(prompts) = self.rounds.get(self.round) {
                let prompts: Vec<_> = prompts.iter().map(|&(p, echo)| (Cow::Borrowed(p), echo)).collect();
                return Ok(SAuth::Partial { name: "".into(), instructions: "".into(), prompts: Cow::Owned(prompts) });
            }
            Ok(if self.given == [PASSWORD] { SAuth::Accept } else { SAuth::reject() })
        }

        async fn auth_publickey(&mut self, _user: &str, key: &PublicKey) -> Result<SAuth, Self::Error> {
            Ok(if key.key_data() == self.client_key.key_data() { SAuth::Accept } else { SAuth::reject() })
        }

        async fn channel_open_direct_tcpip(
            &mut self,
            channel: Channel<Msg>,
            host: &str,
            port: u32,
            _originator_address: &str,
            _originator_port: u32,
            reply: server::ChannelOpenHandle,
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            if host == SILENT {
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    drop(reply);
                });
                return Ok(());
            }
            match tokio::net::TcpStream::connect(format!("{host}:{port}")).await {
                Ok(mut tcp) => {
                    reply.accept().await;
                    tokio::spawn(async move {
                        let mut ch = channel.into_stream();
                        let _ = tokio::io::copy_bidirectional(&mut ch, &mut tcp).await;
                    });
                }
                Err(_) => reply.reject(russh::ChannelOpenFailure::ConnectFailed).await,
            }
            Ok(())
        }

        async fn channel_open_session(
            &mut self,
            channel: Channel<Msg>,
            reply: server::ChannelOpenHandle,
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            self.sessions.lock().unwrap().insert(channel.id(), channel);
            reply.accept().await;
            Ok(())
        }

        /// Relays to the UDP target; without one, stands in for a relay that
        /// cannot start: a line on stderr, then the port it was given as its
        /// exit status.
        async fn exec_request(&mut self, id: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
            let command = String::from_utf8_lossy(data).into_owned();
            assert!(command.contains("socat"), "the relay command is sent");
            let channel = self.sessions.lock().unwrap().remove(&id).expect("session channel");
            session.channel_success(id)?;
            let Some(target) = self.udp_target else {
                let status: u32 = command.rsplit(' ').next().and_then(|p| p.parse().ok()).expect("a port");
                session.extended_data(id, 1, &b"relay: cannot start\n"[..])?;
                session.exit_status_request(id, status)?;
                session.eof(id)?;
                session.close(id)?;
                drop(channel);
                return Ok(());
            };
            tokio::spawn(async move {
                let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                udp.connect(target).await.unwrap();
                let mut ch = channel.into_stream();
                let (mut a, mut b) = ([0u8; 2048], [0u8; 2048]);
                loop {
                    tokio::select! {
                        n = ch.read(&mut a) => match n { Ok(0) | Err(_) => break, Ok(n) => { let _ = udp.send(&a[..n]).await; } },
                        n = udp.recv(&mut b) => match n { Ok(n) => { if ch.write_all(&b[..n]).await.is_err() { break } } Err(_) => break },
                    }
                }
            });
            Ok(())
        }
    }

    /// Start a server on the shared runtime; returns its address.
    pub fn start(udp_target: Option<SocketAddr>) -> SocketAddr {
        start_with(Options { udp_target, ..Default::default() }).0
    }

    /// Start a server that behaves as `opts` says; returns its address and
    /// what it is asked.
    pub fn start_with(opts: Options) -> (SocketAddr, Arc<Seen>) {
        isolate_config();
        let seen = Arc::new(Seen::default());
        let counted = seen.clone();
        let addr = super::runtime().block_on(async move {
            let mut methods = MethodSet::server_supported();
            if !opts.rounds.is_empty() {
                methods = MethodSet::empty();
                methods.push(MethodKind::KeyboardInteractive);
            }
            let config = Arc::new(server::Config {
                keys: vec![russh::keys::decode_secret_key(HOST_KEY, None).unwrap()],
                methods,
                max_auth_attempts: opts.max_auth.unwrap_or(10),
                auth_rejection_time: opts.refuse_after.unwrap_or(Duration::from_millis(10)),
                auth_rejection_time_initial: Some(Duration::ZERO),
                ..Default::default()
            });
            let client_key = russh::keys::decode_secret_key(CLIENT_KEY, None).unwrap().public_key().clone();
            let handler = Handler {
                client_key,
                udp_target: opts.udp_target,
                login_after: opts.login_after,
                rounds: Arc::new(opts.rounds),
                seen: counted,
                sessions: Default::default(),
                round: 0,
                given: Vec::new(),
            };
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                while let Ok((sock, _)) = listener.accept().await {
                    handler.seen.dials.fetch_add(1, SeqCst);
                    let (config, handler) = (config.clone(), handler.clone());
                    tokio::spawn(async move {
                        if let Ok(session) = server::run_stream(config, sock, handler).await {
                            let _ = session.await;
                        }
                    });
                }
            });
            addr
        });
        (addr, seen)
    }

    /// An SSH agent on a Unix socket holding `keys` ed25519 keys, none of
    /// which the test server takes. It signs with a signature that does not
    /// verify, which a server refuses like any other. Returns its socket and
    /// how many times it was asked to sign.
    #[cfg(unix)]
    pub fn fake_agent(keys: u8) -> (std::path::PathBuf, Arc<AtomicUsize>) {
        use std::io::{Read, Write};
        let path = std::env::temp_dir().join(format!("bmc-kvm-test-agent-{}-{}", std::process::id(), crate::rand::hex(4)));
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let blobs: Arc<Vec<Vec<u8>>> = Arc::new(
            (1..=keys)
                .map(|i| {
                    let pair = russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[i; 32]);
                    russh::keys::PrivateKey::from(pair).public_key().to_bytes().unwrap()
                })
                .collect(),
        );
        let signs = Arc::new(AtomicUsize::new(0));
        let counted = signs.clone();
        let string = |out: &mut Vec<u8>, b: &[u8]| {
            out.extend((b.len() as u32).to_be_bytes());
            out.extend(b);
        };
        std::thread::spawn(move || {
            for mut s in listener.incoming().flatten() {
                let (blobs, counted) = (blobs.clone(), counted.clone());
                std::thread::spawn(move || loop {
                    let mut len = [0u8; 4];
                    if s.read_exact(&mut len).is_err() {
                        return;
                    }
                    let mut msg = vec![0u8; u32::from_be_bytes(len) as usize];
                    if s.read_exact(&mut msg).is_err() {
                        return;
                    }
                    let reply = match msg.first() {
                        // REQUEST_IDENTITIES: IDENTITIES_ANSWER.
                        Some(11) => {
                            let mut r = vec![12];
                            r.extend((blobs.len() as u32).to_be_bytes());
                            for b in blobs.iter() {
                                string(&mut r, b);
                                string(&mut r, b"test key");
                            }
                            r
                        }
                        // SIGN_REQUEST: SIGN_RESPONSE.
                        Some(13) => {
                            counted.fetch_add(1, SeqCst);
                            let mut sig = Vec::new();
                            string(&mut sig, b"ssh-ed25519");
                            string(&mut sig, &[0u8; 64]);
                            let mut r = vec![14];
                            string(&mut r, &sig);
                            r
                        }
                        _ => vec![5],
                    };
                    let mut frame = (reply.len() as u32).to_be_bytes().to_vec();
                    frame.extend(reply);
                    if s.write_all(&frame).is_err() {
                        return;
                    }
                });
            }
        });
        (path, signs)
    }

    /// A TCP echo server on a plain thread.
    pub fn echo_tcp() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                std::thread::spawn(move || {
                    let mut r = s.try_clone().unwrap();
                    let mut w = s;
                    let _ = std::io::copy(&mut r, &mut w);
                });
            }
        });
        port
    }

    /// A UDP echo server on a plain thread.
    pub fn echo_udp() -> SocketAddr {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = s.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut b = [0u8; 2048];
            while let Ok((n, from)) = s.recv_from(&mut b) {
                let _ = s.send_to(&b[..n], from);
            }
        });
        addr
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use crate::routes::{Auth, Kind, Route};
    use std::io::{Read, Write};

    fn ssh_route(name: &str, addr: std::net::SocketAddr) -> Route {
        Route {
            name: name.into(),
            kind: Kind::Ssh,
            host: addr.ip().to_string(),
            port: addr.port(),
            user: "ops".into(),
            auth: Auth::Password,
            secret: PASSWORD.into(),
            host_key: HOST_FP.into(),
            ..Default::default()
        }
    }

    fn echo_through(s: &mut std::net::TcpStream) {
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(b"ping").unwrap();
        let mut b = [0u8; 4];
        s.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"ping");
    }

    #[test]
    fn tunnels_carry_connections_as_real_loopback_sockets() {
        let server = start(None);
        let echo = echo_tcp();
        let chain = [ssh_route("t1", server)];
        let mut s = connect(&chain, "127.0.0.1", echo, None).unwrap();
        assert!(s.peer_addr().unwrap().ip().is_loopback(), "handed over by the front end");
        echo_through(&mut s);
        // A second connection shares the tunnel.
        let mut s2 = connect(&chain, "127.0.0.1", echo, None).unwrap();
        echo_through(&mut s2);
        assert_eq!(open_tunnels(&chain), 1);
    }

    #[test]
    fn key_files_authenticate() {
        let server = start(None);
        let key = std::env::temp_dir().join(format!("bmc-kvm-test-key-{}", std::process::id()));
        std::fs::write(&key, CLIENT_KEY).unwrap();
        let mut r = ssh_route("t2", server);
        r.auth = Auth::Key;
        r.secret.clear();
        r.key_file = key.to_string_lossy().into();
        let mut s = connect(&[r], "127.0.0.1", echo_tcp(), None).unwrap();
        echo_through(&mut s);
    }

    #[test]
    fn host_keys_are_pinned_checked_and_found_in_known_hosts() {
        let server = start(None);
        let mut wrong = ssh_route("t3", server);
        wrong.host_key = "SHA256:not-the-key".into();
        let e = connect(&[wrong], "127.0.0.1", echo_tcp(), None).unwrap_err().to_string();
        assert!(e.contains("SHA256:not-the-key") && e.contains(HOST_FP), "{e}");
        assert!(e.contains("run `bmc-kvm route forget t3`"), "{e}");
        // `via` names the hop; the refusal itself does not again.
        assert_eq!(e.matches("t3 (ssh").count(), 1, "{e}");

        let mut unknown = ssh_route("t4", server);
        unknown.host_key.clear();
        let e = with_known_hosts(None, || connect(&[unknown.clone()], "127.0.0.1", echo_tcp(), None))
            .unwrap_err()
            .to_string();
        assert!(e.contains("bmc-kvm route pin t4"), "{e}");
        // The GUI cannot ask yet: the CLI is where a key is first trusted.
        assert!(e.contains("run `bmc-kvm route test t4` to trust it") && !e.contains("GUI"), "{e}");
        assert_eq!(e.matches("t4 (ssh").count(), 1, "{e}");

        let kh = std::env::temp_dir().join(format!("bmc-kvm-test-known-hosts-{}", std::process::id()));
        std::fs::write(&kh, host_public_line(server)).unwrap();
        unknown.name = "t5".into();
        let mut s = with_known_hosts(Some(kh), || connect(&[unknown], "127.0.0.1", echo_tcp(), None)).unwrap();
        echo_through(&mut s);
    }

    struct Yes(std::sync::atomic::AtomicUsize);
    impl crate::net::Prompter for Yes {
        fn trust_host_key(&self, _: &Route, _: &str) -> bool {
            true
        }
        fn secret(&self, _: &Route, _: &str) -> Option<(String, bool)> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Some((PASSWORD.into(), false))
        }
    }

    #[test]
    fn missing_secrets_prompt_only_where_a_prompter_is_set() {
        let server = start(None);
        let mut r = ssh_route("t6", server);
        r.secret.clear();
        let e = connect(&[r.clone()], "127.0.0.1", echo_tcp(), None).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert!(e.to_string().contains("needs its password"), "{e}");
        let said = e.to_string();
        assert!(
            said.contains("save it with `bmc-kvm route edit t6 --password`, or run `bmc-kvm route test t6` to enter it"),
            "{said}"
        );

        let yes = Arc::new(Yes(Default::default()));
        let ctx = crate::net::Context { prompter: Some(yes.clone()), ..Default::default() };
        r.name = "t7".into();
        let mut s = crate::net::with_context(ctx, || connect(&[r], "127.0.0.1", echo_tcp(), None)).unwrap();
        echo_through(&mut s);
        assert_eq!(yes.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn ssh_hops_chain_through_each_other() {
        let (outer, inner) = (start(None), start(None));
        let mut second = ssh_route("t8-inner", inner);
        second.via = "t8-outer".into();
        let chain = [ssh_route("t8-outer", outer), second];
        let mut s = connect(&chain, "127.0.0.1", echo_tcp(), None).unwrap();
        echo_through(&mut s);
    }

    #[test]
    fn an_outer_hop_is_checked_against_the_same_known_hosts() {
        // The outer hop's tunnel opens from inside the inner hop's open, on
        // a runtime thread: the test's known_hosts must reach it there too.
        let (outer, inner) = (start(None), start(None));
        let kh = std::env::temp_dir().join(format!("bmc-kvm-test-nested-hosts-{}", std::process::id()));
        std::fs::write(&kh, host_public_line(outer)).unwrap();
        let mut first = ssh_route("n7-outer", outer);
        first.host_key.clear();
        let mut second = ssh_route("n7-inner", inner);
        second.via = "n7-outer".into();
        let chain = [first, second];
        let s = with_known_hosts(Some(kh.clone()), || connect(&chain, "127.0.0.1", echo_tcp(), None));
        let _ = std::fs::remove_file(&kh);
        echo_through(&mut s.unwrap());
    }

    #[test]
    fn idle_tunnels_close() {
        let server = start(None);
        let chain = [ssh_route("t9", server)];
        let s = connect(&chain, "127.0.0.1", echo_tcp(), None).unwrap();
        drop(s);
        close_idle(&chain);
    }

    /// Wait for `chain`'s tunnel to close once nothing uses it. The copy
    /// ends, and drops its lease, once the closed socket is noticed.
    fn close_idle(chain: &[Route]) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            runtime().block_on(reap_chain(chain, Duration::ZERO));
            if open_tunnels(chain) == 0 {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "tunnel still open");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn the_front_end_refuses_strangers() {
        let (url, _) = crate::net::front::proxy().unwrap();
        let port: u16 = url.rsplit(':').next().unwrap().parse().unwrap();
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let e = crate::net::socks::connect(
            &mut s,
            "127.0.0.1",
            80,
            Some(crate::net::socks::Auth { user: "x", pass: "y" }),
        )
        .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
    }

    use std::sync::atomic::Ordering::SeqCst;

    /// Answers the trust question one way, and counts how often it is asked.
    struct Trust {
        yes: bool,
        asked: std::sync::atomic::AtomicUsize,
    }
    impl crate::net::Prompter for Trust {
        fn trust_host_key(&self, _: &Route, fingerprint: &str) -> bool {
            assert_eq!(fingerprint, HOST_FP, "the user is shown the key presented");
            self.asked.fetch_add(1, SeqCst);
            self.yes
        }
        fn secret(&self, _: &Route, _: &str) -> Option<(String, bool)> {
            None
        }
    }

    fn trusting(yes: bool) -> Arc<Trust> {
        Arc::new(Trust { yes, asked: Default::default() })
    }

    /// Types `.0` whenever asked for a secret, without saving it.
    struct Typed(&'static str, std::sync::atomic::AtomicUsize);
    impl crate::net::Prompter for Typed {
        fn trust_host_key(&self, _: &Route, _: &str) -> bool {
            false
        }
        fn secret(&self, _: &Route, _: &str) -> Option<(String, bool)> {
            self.1.fetch_add(1, SeqCst);
            Some((self.0.into(), false))
        }
    }

    fn asking(prompter: Arc<dyn crate::net::Prompter>) -> crate::net::Context {
        crate::net::Context { prompter: Some(prompter), ..Default::default() }
    }

    #[test]
    fn unknown_host_keys_are_the_users_call_and_stay_trusted_for_the_run() {
        let server = start(None);
        let mut r = ssh_route("t10", server);
        r.host_key.clear();
        let no = trusting(false);
        let e = with_known_hosts(None, || {
            crate::net::with_context(asking(no.clone()), || connect(&[r.clone()], "127.0.0.1", echo_tcp(), None))
        })
        .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert!(e.to_string().contains("was not trusted"), "{e}");
        assert_eq!(no.asked.load(SeqCst), 1);

        r.name = "t11".into();
        let chain = [r];
        let yes = trusting(true);
        let mut s = with_known_hosts(None, || {
            crate::net::with_context(asking(yes.clone()), || connect(&chain, "127.0.0.1", echo_tcp(), None))
        })
        .unwrap();
        echo_through(&mut s);
        assert_eq!(yes.asked.load(SeqCst), 1);

        // Background work on a fresh tunnel: the key trusted above still
        // holds, though the route could not be saved and nobody can be asked.
        drop(s);
        close_idle(&chain);
        let mut s = with_known_hosts(None, || connect(&chain, "127.0.0.1", echo_tcp(), None)).unwrap();
        echo_through(&mut s);
        assert_eq!(yes.asked.load(SeqCst), 1);
    }

    #[test]
    fn a_forgotten_key_is_not_trusted_for_the_rest_of_the_run() {
        let server = start(None);
        let mut r = ssh_route("f1", server);
        r.host_key.clear();
        let chain = [r.clone()];
        with_known_hosts(None, || {
            let s = crate::net::with_context(asking(trusting(true)), || connect(&chain, "127.0.0.1", echo_tcp(), None));
            drop(s.unwrap());
            close_idle(&chain);
            forget_host_key(&r);
            let e = connect(&chain, "127.0.0.1", echo_tcp(), None).unwrap_err();
            assert!(e.to_string().contains("is not trusted yet"), "{e}");
        });
    }

    #[test]
    fn time_spent_answering_moves_a_deadline() {
        let asked = Arc::new(Asked::default());
        let limit = Deadline::after(Duration::from_millis(200), &asked);
        let answering = asked.asking();
        std::thread::sleep(Duration::from_millis(300));
        assert!(limit.get() > std::time::Instant::now(), "it does not pass while the user answers");
        drop(answering);
        let left = limit.get().saturating_duration_since(std::time::Instant::now());
        assert!(left > Duration::from_millis(100) && left <= Duration::from_millis(200), "{left:?} left");
        // And once it has, a wait for it ends.
        let waited = runtime().block_on(before(|| limit.get(), std::future::pending::<()>()));
        assert!(waited.is_none());
        assert!(std::time::Instant::now() >= limit.get());
    }

    #[test]
    fn a_wait_does_not_spin_while_a_question_stays_open() {
        let asked = Arc::new(Asked::default());
        // Asked with a millisecond left: without a floor, the end moves on by
        // a millisecond each time it is reached, for as long as the question
        // stays open.
        let limit = Deadline::after(Duration::from_millis(1), &asked);
        let answering = asked.asking();
        let looks = AtomicUsize::new(0);
        let answered = async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            drop(answering);
        };
        let out = runtime().block_on(before(
            || {
                looks.fetch_add(1, SeqCst);
                limit.get()
            },
            answered,
        ));
        assert!(out.is_some(), "the answer came while the wait was held open");
        assert!(looks.load(SeqCst) <= 10, "looked {} times in half a second", looks.load(SeqCst));
    }

    /// Trusts every key, after reading the fingerprint for a while.
    struct Slow;
    impl crate::net::Prompter for Slow {
        fn trust_host_key(&self, _: &Route, _: &str) -> bool {
            std::thread::sleep(Duration::from_millis(300));
            true
        }
        fn secret(&self, _: &Route, _: &str) -> Option<(String, bool)> {
            None
        }
    }

    #[test]
    fn a_question_counts_as_time_spent_answering() {
        let server = start(None);
        let mut r = ssh_route("q1", server);
        r.host_key.clear();
        let ctx = asking(Arc::new(Slow));
        let asked = ctx.asked.clone();
        let s = with_known_hosts(None, || crate::net::with_context(ctx, || connect(&[r], "127.0.0.1", echo_tcp(), None)));
        echo_through(&mut s.unwrap());
        assert!(asked.total() >= Duration::from_millis(300), "{:?}", asked.total());
    }

    #[test]
    fn a_pin_that_does_not_match_is_refused_without_asking() {
        let server = start(None);
        let yes = trusting(true);
        let mut saved = ssh_route("t12", server);
        saved.host_key = "SHA256:not-the-key".into();
        let e = crate::net::with_context(asking(yes.clone()), || connect(&[saved], "127.0.0.1", echo_tcp(), None))
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert!(e.to_string().contains("has changed"), "{e}");

        // Likewise a key trusted earlier in the run, which a forced chain's
        // copy of the route does not carry.
        let mut unsaved = ssh_route("t13", server);
        unsaved.host_key.clear();
        settled().lock().unwrap().pins.insert(run_key(&unsaved), "SHA256:not-the-key".into());
        let e = with_known_hosts(None, || {
            crate::net::with_context(asking(yes.clone()), || connect(&[unsaved], "127.0.0.1", echo_tcp(), None))
        })
        .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert!(e.to_string().contains("trusted earlier in this run"), "{e}");
        assert_eq!(yes.asked.load(SeqCst), 0);
    }

    #[test]
    fn a_changed_key_in_known_hosts_is_refused_without_asking() {
        let server = start(None);
        // Another ed25519 key for the same host and port: the server is not
        // the one known_hosts saw.
        let other = russh::keys::decode_secret_key(CLIENT_KEY, None).unwrap();
        let line = format!("[{}]:{} {}\n", server.ip(), server.port(), other.public_key().to_openssh().unwrap());
        let kh = std::env::temp_dir().join(format!("bmc-kvm-test-changed-hosts-{}", std::process::id()));
        std::fs::write(&kh, line).unwrap();
        let mut r = ssh_route("t14", server);
        r.host_key.clear();
        let yes = trusting(true);
        let e = with_known_hosts(Some(kh.clone()), || {
            crate::net::with_context(asking(yes.clone()), || connect(&[r], "127.0.0.1", echo_tcp(), None))
        })
        .unwrap_err();
        let _ = std::fs::remove_file(&kh);
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert!(e.to_string().contains(&format!("does not match line 1 of {}", kh.display())), "{e}");
        assert_eq!(yes.asked.load(SeqCst), 0);
    }

    #[test]
    fn typed_secrets_are_kept_for_the_run_once_they_work() {
        let server = start(None);
        let mut r = ssh_route("t15", server);
        r.secret.clear();
        let chain = [r];

        // A typo is not remembered, so background work still has nothing.
        let typo = Arc::new(Typed("wrong horse", Default::default()));
        let e = crate::net::with_context(asking(typo), || connect(&chain, "127.0.0.1", echo_tcp(), None)).unwrap_err();
        assert!(e.to_string().contains("authentication failed"), "{e}");
        let e = connect(&chain, "127.0.0.1", echo_tcp(), None).unwrap_err();
        assert!(e.to_string().contains("needs its password"), "{e}");

        let right = Arc::new(Typed(PASSWORD, Default::default()));
        let mut s =
            crate::net::with_context(asking(right.clone()), || connect(&chain, "127.0.0.1", echo_tcp(), None)).unwrap();
        echo_through(&mut s);
        drop(s);
        close_idle(&chain);
        // Background work on a fresh tunnel uses what was typed.
        let mut s = connect(&chain, "127.0.0.1", echo_tcp(), None).unwrap();
        echo_through(&mut s);
        assert_eq!(right.1.load(SeqCst), 1);
    }

    #[test]
    fn a_hop_that_never_speaks_ssh_fails_within_the_handshake_timeout() {
        // Accepts TCP (the kernel completes it into the backlog) and then
        // says nothing, like a web server on the wrong port.
        let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let chain = [ssh_route("t16", silent.local_addr().unwrap())];
        let begun = std::time::Instant::now();
        let (connected, checked) = with_handshake_timeout(Duration::from_millis(300), || {
            (connect(&chain, "127.0.0.1", 9, None), check(&chain))
        });
        assert!(begun.elapsed() < Duration::from_secs(5), "took {:?}", begun.elapsed());
        // The caller who started the open, whose patience was the phase's,
        // hears how it failed, not just that it gave up waiting.
        for e in [connected.unwrap_err(), checked.unwrap_err()] {
            assert_eq!(e.kind(), io::ErrorKind::TimedOut, "{e}");
            let said = e.to_string();
            let why = said.contains("no SSH server answered at") || said.contains("connecting to 127.0.0.1");
            assert!(said.contains("via t16") && why, "{e}");
        }
        drop(silent);
    }

    #[test]
    fn the_front_end_explains_a_routed_failure_once() {
        let host = "broken-route.test";
        crate::net::set_route(host, Err("route nowhere is not defined".into()));
        let since = std::time::Instant::now();
        let e = through_front_end(host).unwrap_err();
        assert!(e.to_string().contains("connection not allowed by ruleset"), "{e}");
        let why = crate::net::front::last_error(host, since).expect("the failure is recorded");
        assert!(why.contains("route nowhere is not defined"), "{why}");
        assert!(crate::net::front::last_error(host, since).is_some(), "readers do not take it");
        assert_eq!(crate::net::front::last_error(host, std::time::Instant::now()), None, "an older cause never explains a later request");
    }

    fn through_front_end(host: &str) -> io::Result<()> {
        let (url, cred) = crate::net::front::proxy().unwrap();
        let port: u16 = url.rsplit(':').next().unwrap().parse().unwrap();
        let (user, pass) = cred.split_once(':').unwrap();
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        crate::net::socks::connect(&mut s, host, 443, Some(crate::net::socks::Auth { user, pass })).map(|_| ())
    }

    #[test]
    fn the_front_end_refuses_a_host_with_no_route_rather_than_dial_it() {
        let host = "unrouted-host.test";
        let since = std::time::Instant::now();
        let e = through_front_end(host).unwrap_err();
        assert!(e.to_string().contains("connection not allowed by ruleset"), "{e}");
        let why = crate::net::front::last_error(host, since).expect("recorded");
        assert!(why.contains("no route for unrouted-host.test in the table"), "{why}");
    }

    #[test]
    fn the_relay_carries_datagrams_over_exec() {
        let target = echo_udp();
        let server = start(Some(target));
        let chain = [ssh_route("t17", server)];
        let (mut s, _) = relay(&chain, "127.0.0.1", target.port()).unwrap();
        echo_through(&mut s);
    }

    #[test]
    fn a_relay_that_ends_says_whether_the_jump_host_lacks_its_tools() {
        let server = start(None);
        let chain = [ssh_route("t18", server)];
        // The test server's relay exits with the port it is given.
        for (status, missing, says) in [(127, true, "neither socat nor nc"), (1, false, "status 1: relay: cannot start")] {
            let (mut s, end) = relay(&chain, "127.0.0.1", status).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            assert_eq!(s.read(&mut [0u8; 16]).unwrap(), 0, "the stream ends with the relay");
            assert_eq!(end.lacks_tools(), missing);
            assert!(end.describe().contains(says), "{}", end.describe());
        }
    }

    /// Run `f` on `n` threads at once, and collect what each returns; fails
    /// rather than hangs if any takes longer than `limit`.
    fn at_once<T: Send + 'static>(n: usize, limit: Duration, f: impl Fn() -> T + Send + Sync + 'static) -> Vec<T> {
        let f = Arc::new(f);
        let (tx, rx) = std::sync::mpsc::channel();
        let start = Arc::new(std::sync::Barrier::new(n));
        for _ in 0..n {
            let (f, tx, start) = (f.clone(), tx.clone(), start.clone());
            std::thread::spawn(move || {
                start.wait();
                let _ = tx.send(f());
            });
        }
        let deadline = std::time::Instant::now() + limit;
        let left = || deadline.saturating_duration_since(std::time::Instant::now());
        (0..n).map(|_| rx.recv_timeout(left()).expect("every caller answers in time")).collect()
    }

    #[test]
    fn callers_queued_behind_a_refused_login_share_its_answer() {
        let (server, seen) = start_with(Options { refuse_after: Some(Duration::from_millis(300)), ..Default::default() });
        let mut r = ssh_route("m1", server);
        r.secret = "wrong horse".into();
        let chain = [r];
        let echo = echo_tcp();
        let errors = at_once(6, Duration::from_secs(10), move || connect(&chain, "127.0.0.1", echo, None).unwrap_err());
        for e in &errors {
            assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
            assert!(e.to_string().contains("authentication failed"), "{e}");
        }
        assert_eq!(seen.dials(), 1, "one connection to the jump host");
        assert_eq!(seen.passwords(), 1, "one password tried");
    }

    #[test]
    fn background_work_never_retries_a_refused_login() {
        let (server, seen) = start_with(Options::default());
        let mut r = ssh_route("m2", server);
        r.secret = "wrong horse".into();
        let echo = echo_tcp();
        for _ in 0..3 {
            let e = connect(&[r.clone()], "127.0.0.1", echo, None).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
            assert!(e.to_string().contains("authentication failed"), "{e}");
        }
        assert_eq!((seen.dials(), seen.passwords()), (1, 1), "tried once, not once per caller");
        // Not even once the failure is old.
        age_failure(&[r.clone()]);
        let e = connect(&[r.clone()], "127.0.0.1", echo, None).unwrap_err().to_string();
        assert!(e.contains("authentication failed") && e.contains("not retried in the background"), "{e}");
        assert_eq!(seen.dials(), 1);

        // Someone who could be asked is acting on purpose: that is tried.
        let yes = Arc::new(Yes(Default::default()));
        let e = crate::net::with_context(asking(yes), || connect(&[r.clone()], "127.0.0.1", echo, None)).unwrap_err();
        assert!(e.to_string().contains("authentication failed"), "{e}");
        assert_eq!(seen.passwords(), 2);

        // So is the route once it has been changed.
        r.secret = PASSWORD.into();
        let mut s = connect(&[r], "127.0.0.1", echo, None).unwrap();
        echo_through(&mut s);
        assert_eq!(seen.passwords(), 3);
    }

    /// A jump host that takes each connection, then drops it before saying
    /// anything; returns its address and how often it has been dialled.
    fn hangs_up() -> (std::net::SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = dials.clone();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                counted.fetch_add(1, SeqCst);
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(200));
                    drop(s);
                });
            }
        });
        (addr, dials)
    }

    #[test]
    fn a_jump_host_that_fails_is_not_dialled_again_for_a_while() {
        let (addr, dials) = hangs_up();
        let chain = [ssh_route("m3", addr)];
        let queued = chain.clone();
        let errors =
            at_once(6, Duration::from_secs(10), move || connect(&queued, "127.0.0.1", 9, None).unwrap_err().to_string());
        assert!(errors.iter().all(|e| *e == errors[0] && e.contains("via m3")), "{errors:?}");
        assert_eq!(dials.load(SeqCst), 1, "the callers queued behind it were told");
        let e = connect(&chain, "127.0.0.1", 9, None).unwrap_err().to_string();
        assert_eq!(e, errors[0], "and so is the next caller, for a while");
        assert_eq!(dials.load(SeqCst), 1);
        age_failure(&chain);
        assert!(connect(&chain, "127.0.0.1", 9, None).is_err());
        assert_eq!(dials.load(SeqCst), 2, "then it is tried again");
    }

    #[test]
    fn background_work_never_retries_a_refused_host_key() {
        let (server, seen) = start_with(Options::default());
        let mut r = ssh_route("m6", server);
        r.host_key = "SHA256:not-the-key".into();
        for _ in 0..2 {
            let e = connect(&[r.clone()], "127.0.0.1", echo_tcp(), None).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
            assert!(e.to_string().contains("has changed"), "{e}");
        }
        assert_eq!(seen.dials(), 1, "one handshake with a server already distrusted");
        r.host_key = HOST_FP.into();
        let mut s = connect(&[r], "127.0.0.1", echo_tcp(), None).unwrap();
        echo_through(&mut s);
        assert_eq!(seen.dials(), 2, "a corrected pin is tried");
    }

    /// Make `chain`'s remembered failure older than `FAILURE_KEPT`.
    fn age_failure(chain: &[Route]) {
        let slot = slots().lock().unwrap().get(&crate::net::chain_key(chain)).cloned().expect("a slot");
        let mut g = slot.lock().unwrap();
        let f = g.failed.as_mut().expect("a failure is remembered");
        f.at = f.at.checked_sub(FAILURE_KEPT).expect("the clock is old enough");
    }

    #[test]
    fn a_probe_gives_up_on_a_silent_jump_host_at_its_own_timeout() {
        // Completes TCP in the kernel's backlog, then never speaks.
        let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let chain = [ssh_route("m4", silent.local_addr().unwrap())];
        let probe = Duration::from_millis(300);
        let begun = std::time::Instant::now();
        let errors = at_once(4, Duration::from_secs(5), move || connect(&chain, "127.0.0.1", 9, Some(probe)).unwrap_err());
        assert!(begun.elapsed() < Duration::from_secs(2), "took {:?}", begun.elapsed());
        for e in errors {
            assert_eq!(e.kind(), io::ErrorKind::TimedOut, "{e}");
            assert!(e.to_string().contains("via m4"), "{e}");
        }
        drop(silent);
    }

    #[test]
    fn opening_the_channel_waits_no_longer_than_the_caller() {
        let server = start(None);
        let chain = [ssh_route("m5", server)];
        // The tunnel is up already: what is timed is the channel alone.
        let held = connect(&chain, "127.0.0.1", echo_tcp(), None).unwrap();
        let begun = std::time::Instant::now();
        let errors = at_once(1, Duration::from_secs(5), move || {
            let background = connect(&chain, SILENT, 443, Some(Duration::from_millis(300))).unwrap_err();
            let yes = Arc::new(Yes(Default::default()));
            let asking = crate::net::with_context(asking(yes), || {
                connect(&chain, SILENT, 443, Some(Duration::from_millis(300))).unwrap_err()
            });
            [background, asking]
        });
        assert!(begun.elapsed() < Duration::from_secs(2), "took {:?}", begun.elapsed());
        for e in errors.into_iter().flatten() {
            assert_eq!(e.kind(), io::ErrorKind::TimedOut, "{e}");
            assert!(e.to_string().contains(&format!("opening a channel to {SILENT}:443 timed out")), "{e}");
        }
        drop(held);
    }

    /// A server that offers only keyboard-interactive, in `rounds`; a route
    /// to it that holds the password.
    fn interactive(name: &str, rounds: Vec<Round>) -> (Route, Arc<Seen>) {
        let (server, seen) = start_with(Options { rounds, ..Default::default() });
        (ssh_route(name, server), seen)
    }

    #[test]
    fn keyboard_interactive_answers_a_password_prompt() {
        // One hidden prompt; then, as PAM does, a round that asks nothing.
        let password = || vec![("Password: ", false)];
        // Whom a password is for can hold any word: a realm with "code" in
        // it, a host named "hotpoint" (with "otp" in it), a user called
        // token-auth.
        let cases = [
            ("k1", vec![password()]),
            ("k2", vec![password(), vec![]]),
            ("k8", vec![vec![("Password for jdoe@CODE.EXAMPLE.ORG: ", false)]]),
            ("k9", vec![vec![("Password for ops@hotpoint: ", false)]]),
            ("k10", vec![vec![("Password for token-auth user: ", false)]]),
        ];
        for (name, rounds) in cases {
            let (r, seen) = interactive(name, rounds);
            let mut s = connect(&[r], "127.0.0.1", echo_tcp(), None).unwrap();
            echo_through(&mut s);
            assert_eq!(seen.answers.lock().unwrap()[0], [PASSWORD], "{name}");
        }
    }

    #[test]
    fn keyboard_interactive_never_gives_the_password_to_anything_else() {
        let cases: [(&str, Vec<Round>, &[&[&str]]); 6] = [
            // An echoed prompt is not a password prompt.
            ("k3", vec![vec![("Username: ", true)]], &[]),
            // Nor is a hidden one that asks for something else: an OTP first.
            ("k6", vec![vec![("Verification code: ", false)]], &[]),
            // Nor one that calls an OTP a password, as pam_oath does.
            ("k7", vec![vec![("One-time password (OATH) for `ops': ", false)]], &[]),
            ("k11", vec![vec![("Enter your one time password: ", false)]], &[]),
            // Two questions in one round: the password would fill both.
            ("k4", vec![vec![("Password: ", false), ("Verification code: ", false)]], &[]),
            // A second question after the password: an OTP, or Duo.
            ("k5", vec![vec![("Password: ", false)], vec![("Verification code: ", false)]], &[&[PASSWORD]]),
        ];
        for (name, rounds, sent) in cases {
            let (r, seen) = interactive(name, rounds);
            let e = connect(&[r], "127.0.0.1", echo_tcp(), None).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{name}: {e}");
            assert!(e.to_string().contains("asks for more than a password (MFA?); use an agent or key"), "{name}: {e}");
            assert_eq!(*seen.answers.lock().unwrap(), sent, "{name}");
        }
    }

    /// How many leases `chain`'s tunnel has out.
    fn leases(chain: &[Route]) -> usize {
        let slot = slots().lock().unwrap().get(&crate::net::chain_key(chain)).cloned().expect("a slot");
        let g = slot.lock().unwrap();
        g.tunnel.as_ref().map_or(0, |t| t.leases.load(SeqCst))
    }

    /// A BMC that reads to the end of what it is sent, then does `then`.
    fn bmc(then: impl Fn(std::net::TcpStream) + Send + Sync + 'static) -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let then = Arc::new(then);
        std::thread::spawn(move || {
            for mut s in l.incoming().flatten() {
                let then = then.clone();
                std::thread::spawn(move || {
                    let _ = std::io::copy(&mut s, &mut std::io::sink());
                    then(s);
                });
            }
        });
        port
    }

    #[test]
    fn a_bmc_may_answer_after_we_have_finished_sending() {
        let chain = [ssh_route("b1", start(None))];
        let port = bmc(|mut s| {
            let _ = s.write_all(b"bye");
        });
        let mut s = connect(&chain, "127.0.0.1", port, None).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(b"hello").unwrap();
        s.shutdown(std::net::Shutdown::Write).unwrap();
        let mut answer = Vec::new();
        s.read_to_end(&mut answer).unwrap();
        assert_eq!(answer, b"bye");
    }

    #[test]
    fn a_bmc_that_ignores_our_close_does_not_hold_the_tunnel() {
        let chain = [ssh_route("b2", start(None))];
        let (saw_close, closed) = std::sync::mpsc::channel();
        let saw_close = Mutex::new(saw_close);
        // Neither answers nor closes.
        let port = bmc(move |s| {
            let _ = saw_close.lock().unwrap().send(());
            std::thread::sleep(Duration::from_secs(60));
            drop(s);
        });
        let s = connect(&chain, "127.0.0.1", port, None).unwrap();
        assert_eq!(leases(&chain), 1);
        drop(s);
        closed.recv_timeout(Duration::from_secs(5)).expect("the BMC is told we are done");
        let begun = std::time::Instant::now();
        while leases(&chain) > 0 {
            assert!(begun.elapsed() < Duration::from_secs(10), "the tunnel is still held");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Wait up to five seconds for `done`.
    fn wait_until(what: &str, done: impl Fn() -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !done() {
            assert!(std::time::Instant::now() < deadline, "{what}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn remembers_a_failure(chain: &[Route]) -> bool {
        let slot = slots().lock().unwrap().get(&crate::net::chain_key(chain)).cloned();
        slot.is_some_and(|s| s.lock().unwrap().failed.is_some())
    }

    fn is_opening(chain: &[Route]) -> bool {
        let slot = slots().lock().unwrap().get(&crate::net::chain_key(chain)).cloned();
        slot.is_some_and(|s| s.lock().unwrap().opening.is_some())
    }

    /// A front for `to` that holds the first connection `delay` before
    /// passing it on, as a jump host far away would: an open through it is
    /// still under way when the next caller arrives. Later ones pass at once.
    fn slow_at_first(to: std::net::SocketAddr, delay: Duration) -> std::net::SocketAddr {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            for (i, near) in l.incoming().flatten().enumerate() {
                std::thread::spawn(move || {
                    if i == 0 {
                        std::thread::sleep(delay);
                    }
                    let Ok(far) = std::net::TcpStream::connect(to) else { return };
                    let (mut a, mut b) = (near.try_clone().unwrap(), far.try_clone().unwrap());
                    std::thread::spawn(move || std::io::copy(&mut a, &mut b));
                    let (mut near, mut far) = (near, far);
                    let _ = std::io::copy(&mut far, &mut near);
                });
            }
        });
        addr
    }

    #[test]
    fn a_caller_with_an_edited_route_does_not_take_the_old_routes_answer() {
        let (server, seen) = start_with(Options { refuse_after: Some(Duration::from_secs(1)), ..Default::default() });
        let mut old = ssh_route("o1", server);
        old.secret = "wrong horse".into();
        let echo = echo_tcp();
        // A probe with the old password starts the open and stops waiting.
        let e = connect(&[old], "127.0.0.1", echo, Some(Duration::from_millis(100))).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut, "{e}");
        // The password is put right while that open is still refusing.
        let fixed = [ssh_route("o1", server)];
        assert!(is_opening(&fixed), "the old open is under way");
        let mut s = connect(&fixed, "127.0.0.1", echo, None).unwrap();
        echo_through(&mut s);
        assert_eq!((seen.dials(), seen.passwords()), (2, 2), "the old password, then the new");
    }

    #[test]
    fn a_caller_who_can_be_asked_is_not_given_what_nobody_was_asked() {
        let mut r = ssh_route("o2", slow_at_first(start(None), Duration::from_secs(2)));
        r.host_key.clear();
        let chain = [r];
        with_known_hosts(None, || {
            // Background work starts the open, which can only refuse the
            // key nobody vouches for, and stops waiting.
            let e = connect(&chain, "127.0.0.1", 9, Some(Duration::from_millis(100))).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::TimedOut, "{e}");
            assert!(is_opening(&chain), "the background open is under way");
            let yes = trusting(true);
            let mut s =
                crate::net::with_context(asking(yes.clone()), || connect(&chain, "127.0.0.1", echo_tcp(), None)).unwrap();
            echo_through(&mut s);
            assert_eq!(yes.asked.load(SeqCst), 1, "the user is asked");
        });
    }

    #[test]
    fn a_caller_kept_waiting_by_other_opens_says_so() {
        // Opens for other versions of the chain (its password edited
        // meanwhile), one after another: each answer is not this caller's.
        let chain = [ssh_route("w1", "127.0.0.1:9".parse().unwrap())];
        let mut theirs = chain[0].clone();
        theirs.secret = "an older password".into();
        let slot = slots().lock().unwrap().entry(crate::net::chain_key(&chain)).or_default().clone();
        let (tx, rx) = watch::channel(None);
        slot.lock().unwrap().opening = Some(Underway { chain: vec![theirs.clone()], outcome: rx });
        let busy = std::thread::spawn({
            let slot = slot.clone();
            move || {
                let mut answering = tx;
                for _ in 0..4 {
                    // The slot's receiver and the caller's: it is waiting.
                    wait_until("the caller waits on the open", || answering.receiver_count() == 2);
                    // The next open is under way before this one answers, so
                    // the caller finds it when it looks again.
                    let (next, rx) = watch::channel(None);
                    let mut g = slot.lock().unwrap();
                    g.opening = Some(Underway { chain: vec![theirs.clone()], outcome: rx });
                    let fail = Fail { kind: io::ErrorKind::Other, message: "refused".into(), cause: Cause::Refused };
                    answering.send(Some(Err(fail))).unwrap();
                    drop(g);
                    answering = next;
                }
                wait_until("the caller gives up", || answering.receiver_count() == 1);
                slot.lock().unwrap().opening = None;
            }
        });
        let e = runtime().block_on(open_tunnel(&chain, &crate::net::Context::default())).err().expect("no tunnel");
        busy.join().unwrap();
        assert!(e.to_string().contains("other connections through this route kept it busy; try again"), "{e}");
    }

    #[test]
    fn a_tunnel_a_caller_gave_up_on_opens_for_the_next() {
        let (server, seen) = start_with(Options { login_after: Some(Duration::from_millis(600)), ..Default::default() });
        let chain = [ssh_route("s1", server)];
        let (echo, probe) = (echo_tcp(), Some(Duration::from_millis(300)));
        let e = connect(&chain, "127.0.0.1", echo, probe).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut, "{e}");
        wait_until("the tunnel opens without its first caller", || open_tunnels(&chain) == 1);
        let mut s = connect(&chain, "127.0.0.1", echo, None).unwrap();
        echo_through(&mut s);
        assert_eq!(seen.dials(), 1);
    }

    #[test]
    fn a_refusal_that_comes_after_the_caller_gave_up_is_remembered() {
        let (server, seen) = start_with(Options { refuse_after: Some(Duration::from_millis(600)), ..Default::default() });
        let mut r = ssh_route("s2", server);
        r.secret = "wrong horse".into();
        let chain = [r];
        let probe = Some(Duration::from_millis(300));
        let e = connect(&chain, "127.0.0.1", 9, probe).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut, "{e}");
        wait_until("the refusal is remembered", || remembers_a_failure(&chain));
        let e = connect(&chain, "127.0.0.1", 9, probe).unwrap_err();
        assert!(e.to_string().contains("authentication failed"), "{e}");
        assert_eq!((seen.dials(), seen.passwords()), (1, 1), "one login tried across both rounds");
    }

    #[test]
    fn only_our_own_refusals_are_remembered_for_good() {
        let chain = [ssh_route("c1", "127.0.0.1:22".parse().unwrap())];
        // EPERM from connect(): a firewall rule or a VPN kill-switch, which
        // can clear at any moment.
        let local = io::Error::new(io::ErrorKind::PermissionDenied, "Operation not permitted (os error 1)");
        let f = Failure::of(&chain, &via(&chain[0], local)).unwrap();
        assert!(!f.lasting(), "a refusal by this machine's own policy is not the jump host's");

        // Ours stays a refusal through every hop that wraps it, and through
        // the outcome each waiting caller is given.
        let ours = via(&chain[0], via(&chain[0], refused("authentication failed (tried the password)")));
        assert_eq!(ours.kind(), io::ErrorKind::PermissionDenied);
        let f = Failure::of(&chain, &ours).unwrap();
        assert!(f.lasting());
        assert!(is_refusal(&f.fail.error()));

        // So does one nobody could be asked about, as that sort.
        let nobody = via(&chain[0], unasked("its host key is not trusted yet"));
        let f = Failure::of(&chain, &nobody).unwrap();
        assert!(f.lasting() && is_unasked(&f.fail.error()));
        let e = f.answer(&chain, None, false).expect("background work cannot ask either").to_string();
        // Nor can a GUI connect yet, so it is not offered as the remedy.
        assert!(e.ends_with("(not retried in the background)") && !e.contains("connect again"), "{e}");
        assert!(f.answer(&chain, None, true).is_none(), "whoever can be asked tries it");
    }

    #[cfg(unix)]
    #[test]
    fn an_agent_with_more_keys_than_the_jump_host_allows_is_refused_for_good() {
        let (server, seen) = start_with(Options { max_auth: Some(2), ..Default::default() });
        let mut r = ssh_route("a1", server);
        (r.auth, r.secret) = (Auth::Agent, String::new());
        let chain = [r];
        let (agent, signs) = fake_agent(6);
        let e = with_agent(Some(agent.clone()), || connect(&chain, "127.0.0.1", 9, None)).unwrap_err();
        assert!(e.to_string().contains("authentication failed (tried the agent's keys until the jump host hung up"), "{e}");
        assert!(signs.load(SeqCst) < 6, "the agent's keys stop once the jump host has hung up");
        age_failure(&chain);
        let e = with_agent(Some(agent), || connect(&chain, "127.0.0.1", 9, None)).unwrap_err();
        assert!(e.to_string().contains("authentication failed"), "{e}");
        assert_eq!(seen.dials(), 1, "not tried again, even once the failure is old");
    }

    #[test]
    fn a_users_own_action_tries_once_what_background_work_will_not() {
        let (server, seen) = start_with(Options::default());
        let mut r = ssh_route("d1", server);
        r.secret = "wrong horse".into();
        let chain = [r];
        let background = || connect(&chain, "127.0.0.1", 9, None).unwrap_err().to_string();
        background();
        background();
        assert_eq!(seen.passwords(), 1);
        // One action (a Connect, a CLI command) may open several connections
        // (detection alone does): it tries the route once, not once each.
        // Whether or not anyone can be asked: a GUI connect has nobody.
        let actions: [fn() -> crate::net::Context; 2] = [
            || crate::net::Context { deliberate: true, ..Default::default() },
            || asking(Arc::new(Yes(Default::default()))),
        ];
        for (i, action) in actions.into_iter().enumerate() {
            crate::net::with_context(action(), || {
                for _ in 0..3 {
                    connect(&chain, "127.0.0.1", 9, None).unwrap_err();
                }
            });
            assert_eq!(seen.passwords(), 2 + 2 * i);
            crate::net::with_context(action(), || connect(&chain, "127.0.0.1", 9, None).unwrap_err());
            assert_eq!(seen.passwords(), 3 + 2 * i, "the next action tries again");
        }
        let e = background();
        assert!(e.contains("not retried in the background: connect again, or run `bmc-kvm route test d1`"), "{e}");
        assert_eq!(seen.passwords(), 5);
    }

    #[test]
    fn a_long_action_tries_again_what_failed_in_passing_long_ago() {
        let action = || crate::net::Context { deliberate: true, ..Default::default() };
        let (addr, dials) = hangs_up();
        let chain = [ssh_route("d2", addr)];
        crate::net::with_context(action(), || {
            // Begun long ago: the failure below, aged, still comes after it.
            crate::net::backdate_action(FAILURE_KEPT * 2);
            for _ in 0..2 {
                connect(&chain, "127.0.0.1", 9, None).unwrap_err();
            }
            assert_eq!(dials.load(SeqCst), 1, "a fresh failure answers the rest of the action");
            age_failure(&chain);
            connect(&chain, "127.0.0.1", 9, None).unwrap_err();
            assert_eq!(dials.load(SeqCst), 2, "an old one does not");
        });

        // A refusal answers the rest of the action, however long it runs.
        let (server, seen) = start_with(Options::default());
        let mut r = ssh_route("d3", server);
        r.secret = "wrong horse".into();
        crate::net::with_context(action(), || {
            crate::net::backdate_action(FAILURE_KEPT * 2);
            connect(&[r.clone()], "127.0.0.1", 9, None).unwrap_err();
            age_failure(&[r.clone()]);
            let e = connect(&[r.clone()], "127.0.0.1", 9, None).unwrap_err();
            assert!(e.to_string().contains("authentication failed"), "{e}");
        });
        assert_eq!(seen.passwords(), 1);
    }

    #[test]
    fn background_work_tries_a_refused_route_again_once_it_is_edited() {
        let (server, seen) = start_with(Options::default());
        let (moved, moved_seen) = start_with(Options::default());
        let mut r = ssh_route("e1", server);
        r.secret = "wrong horse".into();
        // Each edit is tried once, and its own refusal remembered.
        let refused_twice = |r: &Route, says: &str| {
            for _ in 0..2 {
                let e = connect(&[r.clone()], "127.0.0.1", 9, None).unwrap_err().to_string();
                assert!(e.contains(says), "{e}");
            }
        };
        refused_twice(&r, "authentication failed");
        assert_eq!(seen.dials(), 1);
        r.secret = "wrong pony".into();
        refused_twice(&r, "authentication failed");
        assert_eq!(seen.dials(), 2, "its password edited");
        r.host_key = "SHA256:not-the-key".into();
        refused_twice(&r, "has changed");
        assert_eq!(seen.dials(), 3, "its pinned key edited");
        (r.host, r.port, r.host_key) = (moved.ip().to_string(), moved.port(), HOST_FP.into());
        refused_twice(&r, "authentication failed");
        assert_eq!((seen.dials(), moved_seen.dials()), (3, 1), "its host edited");
    }

    #[test]
    fn a_refusal_stands_while_another_route_changes() {
        let (server, seen) = start_with(Options::default());
        let mut a = ssh_route("e2-a", server);
        a.secret = "wrong horse".into();
        let refused = || connect(&[a.clone()], "127.0.0.1", 9, None).unwrap_err().to_string();
        refused();
        // Another route, saved in routes.json, has its key pinned there by
        // a login that works: the GUI rebuilds its route table on that save.
        let (other, _) = start_with(Options::default());
        let mut b = ssh_route("e2-b", other);
        b.host_key.clear();
        // Beside the routes other tests have saved in the shared config
        // directory, not over them.
        crate::routes::edit_routes(|routes| {
            routes.retain(|r| r.name != b.name);
            routes.push(b.clone());
            Ok(())
        })
        .unwrap();
        let kh = std::env::temp_dir().join(format!("bmc-kvm-test-other-hosts-{}", std::process::id()));
        std::fs::write(&kh, host_public_line(other)).unwrap();
        let s = with_known_hosts(Some(kh.clone()), || connect(&[b], "127.0.0.1", echo_tcp(), None));
        let _ = std::fs::remove_file(&kh);
        echo_through(&mut s.unwrap());
        let saved = crate::routes::try_load_routes().unwrap().into_iter().find(|r| r.name == "e2-b").map(|r| r.host_key);
        assert_eq!(saved.as_deref(), Some(HOST_FP), "the pin is saved");
        let e = refused();
        assert!(e.contains("authentication failed") && e.contains("not retried in the background"), "{e}");
        assert_eq!(seen.dials(), 1, "nothing about another route mends this one");
    }

    #[test]
    fn a_key_is_pinned_only_once_the_login_works() {
        let (server, _) = start_with(Options::default());
        let kh = std::env::temp_dir().join(format!("bmc-kvm-test-pin-hosts-{}", std::process::id()));
        std::fs::write(&kh, host_public_line(server)).unwrap();
        let mut r = ssh_route("p1", server);
        (r.host_key, r.secret) = (String::new(), "wrong horse".into());
        let pinned = |r: &Route| settled().lock().unwrap().pins.get(&run_key(r)).cloned();
        let e = with_known_hosts(Some(kh.clone()), || connect(&[r.clone()], "127.0.0.1", echo_tcp(), None)).unwrap_err();
        assert!(e.to_string().contains("authentication failed"), "{e}");
        // Pinning would rewrite routes.json, which reads as an edited route,
        // and buys the next caller another failed login.
        assert_eq!(pinned(&r), None);
        r.secret = PASSWORD.into();
        let mut s = with_known_hosts(Some(kh.clone()), || connect(&[r.clone()], "127.0.0.1", echo_tcp(), None)).unwrap();
        echo_through(&mut s);
        let _ = std::fs::remove_file(&kh);
        assert_eq!(pinned(&r).as_deref(), Some(HOST_FP));
    }

    #[test]
    fn local_credentials_are_checked_before_the_jump_host_is_dialled() {
        let (server, seen) = start_with(Options::default());
        let key_route = |name: &str, file: &std::path::Path, secret: &str| {
            let mut r = ssh_route(name, server);
            (r.auth, r.key_file, r.secret) = (Auth::Key, file.to_string_lossy().into(), secret.into());
            r
        };
        let missing = std::env::temp_dir().join(format!("bmc-kvm-test-no-such-key-{}", std::process::id()));
        let e = connect(&[key_route("l1", &missing, "")], "127.0.0.1", 9, None).unwrap_err();
        assert!(e.to_string().contains("cannot read key file"), "{e}");

        let file = std::env::temp_dir().join(format!("bmc-kvm-test-encrypted-key-{}", std::process::id()));
        std::fs::write(&file, ENCRYPTED_KEY).unwrap();
        let wrong = [key_route("l2", &file, "wrong passphrase")];
        let e = connect(&wrong, "127.0.0.1", 9, None).unwrap_err();
        assert!(e.to_string().contains("does not open"), "{e}");
        // It cannot start working without the route changing.
        let e = connect(&wrong, "127.0.0.1", 9, None).unwrap_err();
        assert!(e.to_string().contains("not retried in the background"), "{e}");
        // No passphrase at all: on a key route, --password saves one.
        let e = connect(&[key_route("l5", &file, "")], "127.0.0.1", 9, None).unwrap_err().to_string();
        let save = "save it with `bmc-kvm route edit l5 --password`, or run `bmc-kvm route test l5`";
        assert!(e.contains("needs its key passphrase") && e.contains(save), "{e}");
        let _ = std::fs::remove_file(&file);

        #[cfg(unix)]
        {
            let mut r = ssh_route("l3", server);
            (r.auth, r.secret) = (Auth::Agent, String::new());
            let e = with_agent(Some(missing.clone()), || connect(&[r.clone()], "127.0.0.1", 9, None)).unwrap_err();
            assert!(e.to_string().contains("no SSH agent"), "{e}");
            // An agent with nothing in it, or locked, which lists no keys.
            r.name = "l4".into();
            let (empty, _) = fake_agent(0);
            let e = with_agent(Some(empty), || connect(&[r], "127.0.0.1", 9, None)).unwrap_err();
            assert!(
                e.to_string().contains("the SSH agent holds no keys (ssh-add one, or unlock the agent with ssh-add -X)"),
                "{e}"
            );
            assert!(!is_refusal(&e), "it may hold one by the next try: {e}");
        }
        assert_eq!(seen.dials(), 0, "none of it needed the jump host");
    }

    /// Gives every secret asked for as `0`.
    struct Says(&'static str);
    impl crate::net::Prompter for Says {
        fn trust_host_key(&self, _: &Route, _: &str) -> bool {
            true
        }
        fn secret(&self, _: &Route, _: &str) -> Option<(String, bool)> {
            Some((self.0.into(), false))
        }
    }

    #[test]
    fn a_mistyped_passphrase_is_called_that_and_names_its_key() {
        let server = start(None);
        let file = std::env::temp_dir().join(format!("bmc-kvm-test-typed-key-{}", std::process::id()));
        std::fs::write(&file, ENCRYPTED_KEY).unwrap();
        let mut r = ssh_route("l6", server);
        (r.auth, r.key_file, r.secret) = (Auth::Key, file.to_string_lossy().into(), String::new());
        let ctx = asking(Arc::new(Says("not the passphrase")));
        let e = crate::net::with_context(ctx, || connect(&[r], "127.0.0.1", echo_tcp(), None));
        let _ = std::fs::remove_file(&file);
        let e = e.unwrap_err().to_string();
        assert!(e.contains(&format!("wrong passphrase for key file {}", file.display())), "{e}");
        assert_eq!(e.matches("l6 (ssh").count(), 1, "{e}");
    }

    #[test]
    fn relay_commands_pass_the_bmc_as_arguments_and_refuse_odd_names() {
        let c = relay_command("10.20.1.11", 623).unwrap();
        assert!(c.ends_with("' 10.20.1.11 623"), "{c}");
        assert!(c.contains("socat -T 60 - \"UDP-SENDTO:$0:$1\""), "{c}");
        assert!(c.contains("nc -u -w 60 -- \"$0\" \"$1\""), "{c}");
        for odd in ["a;reboot", "fe80::1", "-e", "-oProxyCommand=x", ".lab", "_bmc", ""] {
            assert!(relay_command(odd, 623).is_err(), "{odd:?}");
        }
        assert!(relay_command("bmc-01.lab_a", 623).is_ok());
    }
}
