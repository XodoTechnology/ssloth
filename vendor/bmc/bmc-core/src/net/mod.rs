//! Every connection to a BMC goes through here, so that a host behind a
//! SOCKS5 proxy or an SSH jump host is reached the same way as one on the
//! local network. Call sites keep passing the BMC's own address: it also goes
//! into Host headers, SNI and SP-X's CONNECT line, so routing happens under
//! the socket rather than by rewriting the address.

mod front;
pub(crate) use front::last_error as front_error;
pub(crate) use front::proxy as front_proxy;
pub mod socks;
pub mod ssh;

use crate::routes::Route;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex, OnceLock, RwLock};

/// A host's hops, or why it has none it can use. The error is kept rather
/// than falling back to a direct connection: a misnamed route must not quietly
/// send a BMC's traffic somewhere the user said it should not go.
pub type Chain = Result<Vec<Route>, String>;

#[derive(Clone, Default)]
pub struct Table {
    forced: Option<Chain>,
    by_addr: HashMap<String, Chain>,
    /// What an address the table does not list gets, if not direct.
    unlisted: Option<Chain>,
}

/// IP literals are keyed canonically: curl hands the front end an address
/// re-rendered from its bytes (`[FD00:0:0::5]` arrives as `fd00::5`), and a
/// lookup that missed would send the connection direct.
pub(crate) fn addr_key(addr: &str) -> String {
    let a = addr.trim();
    let bare = a.strip_prefix('[').and_then(|r| r.strip_suffix(']')).unwrap_or(a);
    match bare.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.to_string(),
        Err(_) => a.to_ascii_lowercase(),
    }
}

/// Whether two spellings name the same BMC, as the table would look them up.
pub fn same_address(a: &str, b: &str) -> bool {
    addr_key(a) == addr_key(b)
}

impl Table {
    pub fn set(&mut self, addr: &str, chain: Chain) {
        self.by_addr.insert(addr_key(addr), chain);
    }
    /// Route every address one way: the CLI's `--via` and `--direct`.
    pub fn force(&mut self, chain: Chain) {
        self.forced = Some(chain);
    }
    /// Route every address not `set` one way, rather than direct: the GUI's
    /// answer to a hosts.json that does not parse, which may be where an
    /// address's route is.
    pub fn unlisted(&mut self, chain: Chain) {
        self.unlisted = Some(chain);
    }
    pub fn chain_for(&self, addr: &str) -> Chain {
        if let Some(f) = &self.forced {
            return f.clone();
        }
        match self.by_addr.get(&addr_key(addr)) {
            Some(c) => c.clone(),
            None => self.unlisted.clone().unwrap_or(Ok(Vec::new())),
        }
    }
}

fn table() -> &'static RwLock<Table> {
    static T: OnceLock<RwLock<Table>> = OnceLock::new();
    T.get_or_init(Default::default)
}

/// Install a rebuilt table. Failures remembered under the old one stand
/// for exactly the chains they failed on: a host whose route was edited
/// resolves to a different chain, which is tried afresh (`ssh::Failure`).
pub fn install(t: Table) {
    *table().write().unwrap() = t;
}

/// Route one address before it is saved: the host editor's Probe BMC and
/// the import page's Discover hosts. Until the next `install`, which must
/// carry it too (the GUI keeps it in `App::provisional`).
pub fn set_route(addr: &str, chain: Chain) {
    table().write().unwrap().set(addr, chain);
}

pub fn chain_for(addr: &str) -> Chain {
    table().read().unwrap().chain_for(addr)
}

/// Whether `addr` goes through a route; Err if its route is broken.
pub fn is_routed(addr: &str) -> Result<bool, String> {
    chain_for(addr).map(|c| !c.is_empty())
}

/// The questions a route can need answered: whether to trust a jump host's
/// key, and a password or passphrase the route does not store.
pub trait Prompter: Send + Sync {
    fn trust_host_key(&self, route: &Route, fingerprint: &str) -> bool;
    /// `(secret, save it)`, or None if the user cancelled.
    fn secret(&self, route: &Route, what: &str) -> Option<(String, bool)>;
}

/// What a blocking connect may do besides connect: report its stages, and
/// ask the user. Set per thread by whoever owns that thread's UI. A thread
/// without one (probes, previews, sensors) never prompts.
#[derive(Clone, Default)]
pub struct Context {
    pub progress: Option<Arc<Mutex<String>>>,
    pub prompter: Option<Arc<dyn Prompter>>,
    /// Print stages to stderr, for the CLI.
    pub echo: bool,
    /// The user's own action (a Connect, a CLI command), not background
    /// work: it tries once more what background work has stopped trying,
    /// such as a jump host that refused the login. A context with a
    /// prompter is one too.
    pub deliberate: bool,
    /// Time spent answering this context's prompter, which no network limit
    /// counts. Shared by its clones, and so with an open it starts.
    pub asked: Arc<ssh::Asked>,
}

thread_local! {
    static CONTEXT: RefCell<Context> = RefCell::new(Context::default());
    /// When this thread's deliberate action began.
    static BEGAN: Cell<Option<Instant>> = const { Cell::new(None) };
}

/// When an action under `ctx` begins now, if it is a deliberate one. An
/// action can open several connections (detection alone does), and should
/// try a refused route once in all, not once each: what has failed since it
/// began is not tried again within it.
fn began(ctx: &Context) -> Option<Instant> {
    (ctx.deliberate || ctx.prompter.is_some()).then(Instant::now)
}

/// Run `f` with `ctx` as this thread's context, then put the old one back.
pub fn with_context<R>(ctx: Context, f: impl FnOnce() -> R) -> R {
    let old_began = BEGAN.with(|b| b.replace(began(&ctx)));
    let old = CONTEXT.with(|c| c.replace(ctx));
    let out = f();
    CONTEXT.with(|c| *c.borrow_mut() = old);
    BEGAN.with(|b| b.set(old_began));
    out
}

/// Run `f` as an action the user took just now (a close, an eject, a power
/// command), on a thread that has no context of its own: what a route
/// refused earlier in the run is tried once more rather than answered from
/// memory, since what is not done here (a logout, X9's clock put back, an
/// iDRAC session released) stays undone. Nothing is asked.
pub fn deliberately<R>(f: impl FnOnce() -> R) -> R {
    with_context(Context { deliberate: true, ..Default::default() }, f)
}

/// Make the rest of this thread's work the user's own action, begun now, as
/// `deliberately` does for one closure: for a worker thread started by a
/// click, which ends when its work does.
pub fn begin_action() {
    set_context(Context { deliberate: true, ..Default::default() });
}

/// Set this thread's context for good: the CLI's main thread.
pub fn set_context(ctx: Context) {
    BEGAN.with(|b| b.set(began(&ctx)));
    CONTEXT.with(|c| *c.borrow_mut() = ctx);
}

/// When this thread's deliberate action began, if it is in one.
pub(crate) fn action_began() -> Option<Instant> {
    BEGAN.with(Cell::get)
}

/// Make this thread's action have begun `by` earlier: one that has run as
/// long as a CLI mount can.
#[cfg(test)]
pub(crate) fn backdate_action(by: Duration) {
    let began = action_began().expect("in an action").checked_sub(by).expect("the clock is old enough");
    BEGAN.with(|b| b.set(Some(began)));
}

pub fn context() -> Context {
    CONTEXT.with(|c| c.borrow().clone())
}

pub(crate) fn say(ctx: &Context, msg: &str) {
    if let Some(p) = &ctx.progress {
        *p.lock().unwrap() = msg.to_owned();
    }
    if ctx.echo {
        eprintln!("{msg}");
    }
}

/// A jump host or proxy refusing our credentials, or a jump host's key
/// refused: trying again cannot go differently until the route does. Made
/// where the refusal happens and carried inside the `io::Error`, so that
/// what a failed open is remembered as never rests on an error kind the OS
/// can produce too (EPERM from a firewall rule is PermissionDenied as well).
#[derive(Debug)]
pub(crate) struct Refusal {
    message: String,
    /// Refused only because nobody could be asked: a jump host's key that
    /// nothing vouches for, a secret the route does not hold. Whoever can
    /// be asked may settle it.
    unasked: bool,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Refusal {}

fn refusal(message: String, unasked: bool) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, Refusal { message, unasked })
}

pub(crate) fn refused(msg: impl Into<String>) -> io::Error {
    refusal(msg.into(), false)
}

/// A refusal that only an answer from the user can settle.
pub(crate) fn unasked(msg: impl Into<String>) -> io::Error {
    refusal(msg.into(), true)
}

fn as_refusal(e: &io::Error) -> Option<&Refusal> {
    e.get_ref().and_then(|inner| inner.downcast_ref::<Refusal>())
}

pub(crate) fn is_refusal(e: &io::Error) -> bool {
    as_refusal(e).is_some()
}

pub fn is_unasked(e: &io::Error) -> bool {
    as_refusal(e).is_some_and(|r| r.unasked)
}

/// Prefix an error with the hop it happened at. A refusal stays one, of
/// the same sort.
pub(crate) fn via(hop: &Route, e: io::Error) -> io::Error {
    let message = format!("via {}: {e}", hop.describe());
    match as_refusal(&e) {
        Some(r) => refusal(message, r.unasked),
        None => io::Error::new(e.kind(), message),
    }
}

/// Identifies a chain: its tunnel is shared, and its UDP results remembered,
/// under this key; for a single route, it is also what `net::ssh` keeps a
/// typed secret and a trusted host key under for the run. A route's secret
/// and pinned key are not part of it: they are how a hop is authenticated
/// and checked, not which hop it is. So saving a secret or pinning a key
/// leaves the open tunnel in use, and any caller whose chain names the same
/// hops shares that tunnel without authenticating again.
pub(crate) fn chain_key(chain: &[Route]) -> String {
    chain
        .iter()
        .map(|r| format!("{}|{:?}|{}|{}|{}|{:?}|{}", r.name, r.kind, r.host, r.port, r.user, r.auth, r.key_file))
        .collect::<Vec<_>>()
        .join(">")
}

use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// How long a proxy hop may take to connect and answer the handshake.
pub const HOP_TIMEOUT: Duration = Duration::from_secs(15);

/// The addresses `host` resolves to.
pub(crate) fn resolve_addrs(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    Ok((host, port).to_socket_addrs()?.collect())
}

/// A plain TCP connection, trying each resolved address in turn. `timeout`
/// is one deadline for the whole attempt, not per address, so a host with
/// dead A and AAAA records waits no longer than asked.
pub(crate) fn direct(host: &str, port: u16, timeout: Option<Duration>) -> io::Result<TcpStream> {
    direct_addrs(&resolve_addrs(host, port)?, timeout)
}

/// `direct` for addresses already resolved, so a caller can time the
/// handshake without the name lookup.
pub(crate) fn direct_addrs(addrs: &[SocketAddr], timeout: Option<Duration>) -> io::Result<TcpStream> {
    let deadline = timeout.map(|t| std::time::Instant::now() + t);
    let mut last = None;
    for addr in addrs {
        let r = match deadline {
            Some(d) => {
                let left = d.saturating_duration_since(std::time::Instant::now());
                if left.is_zero() {
                    break;
                }
                TcpStream::connect_timeout(addr, left)
            }
            None => TcpStream::connect(addr),
        };
        match r {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "cannot resolve host or timed out")))
}

/// A connection to the BMC at `host:port`, through its route if it has one.
/// Direct, `timeout` bounds the whole connect. Through SOCKS5 it bounds the
/// first hop's connect and the last hop's reply (intermediate replies get
/// `HOP_TIMEOUT`). Through SSH it bounds the caller's wait, for the tunnel
/// (longer where this thread can prompt, since the user may be answering)
/// and then for the channel; the tunnel's open goes on without the caller,
/// for up to `ssh::TUNNEL_TIMEOUT`, and is there for the next one.
pub fn connect(host: &str, port: u16, timeout: Option<Duration>) -> io::Result<TcpStream> {
    let chain = chain_for(host).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    connect_chain(&chain, host, port, timeout)
}

pub fn connect_chain(chain: &[Route], host: &str, port: u16, timeout: Option<Duration>) -> io::Result<TcpStream> {
    if chain.is_empty() {
        return direct(host, port, timeout);
    }
    if chain.iter().any(|r| r.kind == crate::routes::Kind::Ssh) {
        return ssh::connect(chain, host, port, timeout);
    }
    // SOCKS5 all the way: each hop is asked for the next over the same socket,
    // which is then the caller's, with no copying in between.
    let first = &chain[0];
    let mut s = direct(&first.host, first.port, Some(first_hop_limit(timeout))).map_err(|e| via(first, e))?;
    for (i, hop) in chain.iter().enumerate() {
        let last = i + 1 == chain.len();
        let (h, p) = chain.get(i + 1).map_or((host, port), |n| (n.host.as_str(), n.port));
        // The caller's patience applies to the answer that matters to it.
        let wait = match timeout {
            Some(t) if last => t.max(Duration::from_millis(1)),
            _ => HOP_TIMEOUT,
        };
        s.set_read_timeout(Some(wait))?;
        socks::connect(&mut s, h, p, socks::auth_of(hop)).map_err(|e| {
            let e = match e.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                    io::Error::new(io::ErrorKind::TimedOut, format!("timed out waiting for {h}:{p}"))
                }
                _ => e,
            };
            via(hop, e)
        })?;
    }
    s.set_read_timeout(None)?;
    Ok(s)
}

/// How long the first SOCKS hop may take to accept: the caller's own limit,
/// so that a probe of a host behind a dead proxy gives up when it said it
/// would.
fn first_hop_limit(timeout: Option<Duration>) -> Duration {
    timeout.unwrap_or(HOP_TIMEOUT)
}

/// Where IPMI's datagrams go.
pub enum Datagram {
    Udp(std::net::UdpSocket),
    Socks(socks::UdpAssociate),
    /// Through an SSH jump host's relay: datagrams as one byte stream, which
    /// `ipmi.rs` splits again, and how the relay ended once it has.
    Stream(TcpStream, ssh::RelayEnd),
}

/// Whether IPMI can reach a host through its route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Udp {
    Unknown,
    Available,
    Unavailable(String),
}

fn udp_states() -> &'static Mutex<HashMap<String, Udp>> {
    static S: OnceLock<Mutex<HashMap<String, Udp>>> = OnceLock::new();
    S.get_or_init(Default::default)
}

/// UDP cannot cross a SOCKS5 proxy that is itself behind another hop: the
/// datagrams would have to reach its relay port directly.
fn udp_impossible(chain: &[Route]) -> Option<String> {
    let last = chain.last()?;
    (last.kind == crate::routes::Kind::Socks5 && chain.len() > 1).then(|| {
        format!("IPMI cannot reach this BMC: {} is reached through another hop, so it cannot relay UDP", last.name)
    })
}

pub fn udp_capability(addr: &str) -> Udp {
    match chain_for(addr) {
        Err(e) => Udp::Unavailable(e),
        Ok(c) if c.is_empty() => Udp::Available,
        Ok(c) => match udp_impossible(&c) {
            Some(why) => Udp::Unavailable(why),
            None => udp_states().lock().unwrap().get(&chain_key(&c)).cloned().unwrap_or(Udp::Unknown),
        },
    }
}

/// Record what an IPMI attempt learned about the route `chain`: the chain it
/// went over, which for `route test` need not be any host's route. A direct
/// path has nothing to record.
pub fn mark_udp(chain: &[Route], state: Udp) {
    if !chain.is_empty() {
        udp_states().lock().unwrap().insert(chain_key(chain), state);
    }
}

pub fn udp(host: &str, port: u16) -> io::Result<Datagram> {
    let chain = chain_for(host).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    udp_via(&chain, host, port)
}

/// Only `Unsupported` failures are remembered as the route's: a proxy that
/// refuses UDP, or a chain that cannot carry it. A timeout, or a BMC address
/// the relay will not take, says nothing about the other hosts behind it.
pub fn udp_via(chain: &[Route], host: &str, port: u16) -> io::Result<Datagram> {
    let r = open_udp(chain, host, port);
    if let Err(e) = &r {
        if e.kind() == io::ErrorKind::Unsupported {
            mark_udp(chain, Udp::Unavailable(e.to_string()));
        }
    }
    r
}

fn open_udp(chain: &[Route], host: &str, port: u16) -> io::Result<Datagram> {
    let Some(last) = chain.last() else {
        let s = std::net::UdpSocket::bind(("0.0.0.0", 0))?;
        s.connect((host, port))?;
        return Ok(Datagram::Udp(s));
    };
    if let Some(why) = udp_impossible(chain) {
        return Err(io::Error::new(io::ErrorKind::Unsupported, why));
    }
    match last.kind {
        crate::routes::Kind::Ssh => ssh::relay(chain, host, port).map(|(s, end)| Datagram::Stream(s, end)),
        crate::routes::Kind::Socks5 => {
            socks::UdpAssociate::open(last, host, port).map(Datagram::Socks).map_err(|e| via(last, e))
        }
    }
}

/// `route test`: dial the route's last hop and say how it went. The BMC
/// stages run only once the route itself answers; then both always run, since
/// 443 can be closed while 623 is open. Failures stay `io::Error`s, so the
/// caller can tell one nobody could be asked about (`is_unasked`).
pub fn test_route(chain: &[Route], bmc: Option<&str>) -> Vec<(String, io::Result<String>)> {
    let mut out = Vec::new();
    let Some(last) = chain.last() else { return out };
    let t0 = std::time::Instant::now();
    let ms = |t: std::time::Instant| format!("{} ms", t.elapsed().as_millis());
    let reached = match last.kind {
        crate::routes::Kind::Ssh => ssh::check(chain).map(|_| format!("authenticated, {}", ms(t0))),
        crate::routes::Kind::Socks5 => (|| {
            let rest = &chain[..chain.len() - 1];
            let mut s = connect_chain(rest, &last.host, last.port, Some(HOP_TIMEOUT))?;
            s.set_read_timeout(Some(HOP_TIMEOUT))?;
            socks::negotiate(&mut s, socks::auth_of(last))?;
            Ok::<_, io::Error>(format!("accepted, {}", ms(t0)))
        })(),
    };
    let ok = reached.is_ok();
    out.push((format!("reach {}", last.describe()), reached));
    let Some(bmc) = bmc.filter(|_| ok) else { return out };
    let t0 = std::time::Instant::now();
    let tcp = connect_chain(chain, bmc, 443, Some(Duration::from_secs(10))).map(|_| ms(t0));
    out.push((format!("TCP to {bmc}:443"), tcp));
    let t0 = std::time::Instant::now();
    let ipmi = crate::ipmi::probe_via(chain, bmc).map(|_| ms(t0)).map_err(|e| match e {
        crate::ipmi::Error::Io(e) | crate::ipmi::Error::Route(e) => e,
        e => io::Error::other(e.to_string()),
    });
    out.push((format!("IPMI to {bmc}:623"), ipmi));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::Kind;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn a_close_thread_is_an_action_begun_when_it_closes() {
        assert!(!context().deliberate && action_began().is_none(), "a new thread is background work");
        let began = deliberately(|| {
            assert!(context().deliberate && context().prompter.is_none());
            action_began().expect("an action has begun")
        });
        assert!(began.elapsed() < Duration::from_secs(5));
        assert!(!context().deliberate && action_began().is_none(), "and is again afterwards");
    }

    #[test]
    fn ip_literals_share_one_key_however_they_are_written() {
        let mut t = Table::default();
        t.set("FD00:0:0::5", Err("x".into()));
        for spelled in ["fd00::5", "[fd00::5]", "[FD00:0:0::5]", " fd00:0:0:0:0:0:0:5 "] {
            assert_eq!(t.chain_for(spelled), Err("x".into()), "{spelled}");
        }
        t.set("BMC.Example", Err("y".into()));
        assert_eq!(t.chain_for("bmc.example"), Err("y".into()));
    }

    /// A no-auth SOCKS5 proxy that really connects and then pipes bytes.
    fn forwarding_proxy() -> (u16, std::sync::Arc<Mutex<Vec<(String, u16)>>>) {
        let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for mut s in l.incoming().flatten() {
                let log = log.clone();
                std::thread::spawn(move || {
                    let mut g = [0u8; 3];
                    s.read_exact(&mut g).unwrap();
                    s.write_all(&[5, 0]).unwrap();
                    let mut req = [0u8; 5];
                    s.read_exact(&mut req).unwrap();
                    let mut name = vec![0u8; req[4] as usize];
                    s.read_exact(&mut name).unwrap();
                    let mut p = [0u8; 2];
                    s.read_exact(&mut p).unwrap();
                    let name = String::from_utf8(name).unwrap();
                    log.lock().unwrap().push((name.clone(), u16::from_be_bytes(p)));
                    let target = TcpStream::connect((name.as_str(), u16::from_be_bytes(p))).unwrap();
                    s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
                    let (mut a, mut b) = (s.try_clone().unwrap(), target.try_clone().unwrap());
                    let (mut c, mut d) = (s, target);
                    std::thread::spawn(move || std::io::copy(&mut a, &mut d));
                    let _ = std::io::copy(&mut b, &mut c);
                });
            }
        });
        (port, seen)
    }

    fn proxy_route(name: &str, port: u16, via: &str) -> Route {
        Route { name: name.into(), kind: Kind::Socks5, host: "127.0.0.1".into(), port, via: via.into(), ..Default::default() }
    }

    #[test]
    fn route_test_reports_the_route_then_the_bmc_stages() {
        let (port, _) = forwarding_proxy();
        let chain = [proxy_route("p", port, "")];
        let r = test_route(&chain, None);
        assert_eq!(r.len(), 1);
        assert!(r[0].1.as_ref().is_ok_and(|m| m.starts_with("accepted")), "{r:?}");

        // A port nothing listens on: one failure, and no BMC stage after it.
        let dead = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let r = test_route(&[proxy_route("d", dead, "")], Some("127.0.0.1"));
        assert_eq!(r.len(), 1);
        assert!(r[0].1.is_err(), "{r:?}");

        // A local listener standing in for the BMC: the TCP stage dials it
        // through the proxy (443 is not ours to bind, so it is the stage that
        // may fail, but it must run, followed by IPMI).
        let r = test_route(&chain, Some("127.0.0.1"));
        assert_eq!(r.len(), 3, "{r:?}");
        assert!(r[1].0.starts_with("TCP to") && r[2].0.starts_with("IPMI to"));
    }

    #[test]
    fn socks_chains_dial_each_hop_in_turn() {
        let echo = ssh::testing::echo_tcp();
        let (p1, seen1) = forwarding_proxy();
        let (p2, seen2) = forwarding_proxy();
        let chain = [proxy_route("p1", p1, ""), proxy_route("p2", p2, "p1")];
        let mut s = connect_chain(&chain, "127.0.0.1", echo, Some(std::time::Duration::from_secs(5))).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        s.write_all(b"hop").unwrap();
        let mut b = [0u8; 3];
        s.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"hop");
        assert_eq!(*seen1.lock().unwrap(), vec![("127.0.0.1".to_string(), p2)], "p1 was asked for p2");
        assert_eq!(*seen2.lock().unwrap(), vec![("127.0.0.1".to_string(), echo)], "p2 was asked for the target");
    }

    #[test]
    fn connect_refuses_a_broken_route_instead_of_dialling() {
        set_route("broken.test.invalid", Err("no route named gone".into()));
        let e = connect("broken.test.invalid", 1, None).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        assert!(e.to_string().contains("no route named gone"));
    }

    #[test]
    fn the_first_proxy_is_given_the_callers_patience() {
        let probe = std::time::Duration::from_millis(1_500);
        assert_eq!(first_hop_limit(Some(probe)), probe);
        assert_eq!(first_hop_limit(None), HOP_TIMEOUT);
    }

    #[test]
    fn a_silent_last_hop_times_out_at_the_callers_timeout() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for mut s in l.incoming().flatten() {
                let mut g = [0u8; 3];
                let _ = s.read_exact(&mut g);
                let _ = s.write_all(&[5, 0]);
                std::thread::sleep(std::time::Duration::from_secs(20));
            }
        });
        let t = std::time::Instant::now();
        let e = connect_chain(&[proxy_route("mute", port, "")], "127.0.0.1", 1, Some(std::time::Duration::from_millis(400))).unwrap_err();
        assert!(t.elapsed() < std::time::Duration::from_secs(5), "took {:?}", t.elapsed());
        assert_eq!(e.kind(), io::ErrorKind::TimedOut, "{e}");
    }

    #[test]
    fn only_route_failures_are_remembered_as_the_routes() {
        // A proxy that answers UDP ASSOCIATE with "command not supported".
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut g = [0u8; 3];
            s.read_exact(&mut g).unwrap();
            s.write_all(&[5, 0]).unwrap();
            let mut req = [0u8; 10];
            s.read_exact(&mut req).unwrap();
            s.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
        });
        let socks = vec![proxy_route("no-udp", port, "")];
        set_route("udp-refused.test", Ok(socks.clone()));
        let e = udp_via(&socks, "10.0.0.1", 623).err().expect("refused");
        assert_eq!(e.kind(), io::ErrorKind::Unsupported, "{e}");
        assert!(
            matches!(udp_capability("udp-refused.test"), Udp::Unavailable(w) if w.contains("command not supported")),
            "a refusal is the proxy's"
        );

        // An address the SSH relay will not take is that host's problem alone.
        let ssh = vec![Route { name: "jump".into(), kind: Kind::Ssh, host: "127.0.0.1".into(), port: 9, ..Default::default() }];
        set_route("fe80::1", Ok(ssh));
        let e = udp("fe80::1", 623).err().expect("refused");
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "{e}");
        assert_eq!(udp_capability("fe80::1"), Udp::Unknown);
        assert_eq!(udp_capability("192.0.2.1"), Udp::Available, "a direct host needs no record");
    }

    #[test]
    fn broken_routes_fail_instead_of_going_direct() {
        let mut t = Table::default();
        t.set("10.0.0.1", Err("no route named gone".into()));
        assert_eq!(t.chain_for("10.0.0.1").unwrap_err(), "no route named gone");
        assert_eq!(t.chain_for(" 10.0.0.2 ").unwrap(), Vec::<Route>::new(), "unknown addresses go direct");
        t.force(Ok(vec![proxy_route("p", 1080, "")]));
        assert_eq!(t.chain_for("10.0.0.1").unwrap().len(), 1, "--via overrides every host");
    }
}
