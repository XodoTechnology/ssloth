//! The loopback SOCKS5 server that turns SSH channels into real sockets. A
//! caller that opened a channel parks it under a random id and connects here
//! asking for `<id>.bridge.invalid`. `curl` asks for its BMC by name, and is
//! routed by the table like anything else. It listens on 127.0.0.1 only, and
//! demands a per-run user name and password, so another local user cannot
//! borrow it to reach the BMC network.

use super::socks;
use super::ssh::{runtime, BoxIo, Lease};
use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex, OnceLock};
#[cfg(test)]
use std::sync::atomic::Ordering::SeqCst;
use std::time::{Duration, Instant};

const BRIDGE: &str = ".bridge.invalid";
/// How long a client may take to authenticate and name its target. Ours
/// do it at once; anything slower must not hold a task.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// How long curl's BMC may take to reach. curl gives up on the proxy at 20 s
/// (event_log's `--connect-timeout`); finishing first means the cause is
/// recorded by the time its caller asks for it.
const CURL_REACH: Duration = Duration::from_secs(15);

/// Why the last routed connection to each BMC failed, and when. curl reports
/// only a SOCKS reply code, so its caller asks here for the reason behind it.
fn failures() -> &'static Mutex<HashMap<String, (Instant, String)>> {
    static F: OnceLock<Mutex<HashMap<String, (Instant, String)>>> = OnceLock::new();
    F.get_or_init(Default::default)
}

/// How long a recorded cause is kept for a late reader.
const CAUSE_KEPT: Duration = Duration::from_secs(300);

/// Why the front end failed to reach `host` for curl at or after `since` (the
/// start of the caller's request). Not taken: concurrent readers of one BMC
/// (sensors, event log) each see it, and the timestamp stops an old failure
/// explaining a later request.
pub(crate) fn last_error(host: &str, since: Instant) -> Option<String> {
    let recorded = failures().lock().unwrap();
    recorded.get(&super::addr_key(host)).filter(|(at, _)| *at >= since).map(|(_, why)| why.clone())
}

/// The hops for a BMC curl asked for. Only routed hosts are ever pointed at
/// the front end, so an empty chain means the lookup missed: refuse rather
/// than dial the BMC directly.
fn curl_chain(host: &str) -> io::Result<Vec<crate::routes::Route>> {
    match super::chain_for(host) {
        Ok(chain) if chain.is_empty() => {
            Err(io::Error::new(io::ErrorKind::InvalidInput, format!("no route for {host} in the table")))
        }
        Ok(chain) => Ok(chain),
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidInput, e)),
    }
}

/// The nearest SOCKS5 reply, so that curl's own message points the right way.
fn reply_code(e: &io::Error) -> u8 {
    match e.kind() {
        // A broken route is the route table refusing, as much as a jump host
        // turning us away is.
        io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidInput => 2,
        io::ErrorKind::TimedOut => 4,
        io::ErrorKind::ConnectionRefused => 5,
        _ => 1,
    }
}

struct Front {
    addr: SocketAddr,
    user: String,
    pass: String,
    parked: Mutex<HashMap<String, (BoxIo, Vec<Lease>)>>,
    /// Accepts the tests turn into failures, standing in for EMFILE or a
    /// peer that reset before it was accepted.
    #[cfg(test)]
    fail_accepts: std::sync::atomic::AtomicUsize,
}

/// The front end being served, and the task serving it.
struct Serving {
    front: Arc<Front>,
    task: tokio::task::JoinHandle<()>,
}

/// Started on first use, and again whenever its task has ended (a panic, or
/// a runtime that dropped it): an address nobody serves would refuse every
/// routed connection for the rest of the run.
struct Frontend(Mutex<Option<Serving>>);

static FRONTEND: Frontend = Frontend(Mutex::new(None));

/// How long the accept loop pauses after a failed accept, so that EMFILE
/// cannot spin it.
const ACCEPT_RETRY: Duration = Duration::from_millis(50);

impl Frontend {
    fn get(&self) -> io::Result<Arc<Front>> {
        let mut serving = self.0.lock().unwrap();
        if let Some(s) = serving.as_ref().filter(|s| !s.task.is_finished()) {
            return Ok(s.front.clone());
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let f = Arc::new(Front {
            addr: listener.local_addr()?,
            user: crate::rand::hex(8),
            pass: crate::rand::hex(16),
            parked: Mutex::new(HashMap::new()),
            #[cfg(test)]
            fail_accepts: Default::default(),
        });
        // Registered here, not in the task, so that a failure reaches this
        // caller and nothing is kept.
        let listener = {
            let _rt = runtime().enter();
            tokio::net::TcpListener::from_std(listener)?
        };
        let task = runtime().spawn(accept_loop(listener, f.clone()));
        *serving = Some(Serving { front: f.clone(), task });
        Ok(f)
    }
}

async fn accept_loop(listener: tokio::net::TcpListener, front: Arc<Front>) {
    let mut failing = false;
    loop {
        let accepted = listener.accept().await;
        #[cfg(test)]
        let accepted = accepted.and_then(|a| {
            if front.fail_accepts.load(SeqCst) == 0 {
                return Ok(a);
            }
            front.fail_accepts.fetch_sub(1, SeqCst);
            Err(io::Error::from(io::ErrorKind::ConnectionAborted))
        });
        match accepted {
            Ok((sock, peer)) => {
                failing = false;
                if !peer.ip().is_loopback() {
                    continue;
                }
                let f = front.clone();
                tokio::spawn(async move {
                    let _ = serve(&f, sock).await;
                });
            }
            // EMFILE, or a client that reset before it was accepted (macOS,
            // Windows): that connection is lost, the listener is not. Leaving
            // the loop would refuse every routed connection from here on.
            Err(e) => {
                if !failing {
                    eprintln!("route front end: accept failed ({e}); retrying");
                    failing = true;
                }
                tokio::time::sleep(ACCEPT_RETRY).await;
            }
        }
    }
}

async fn serve(f: &Front, mut sock: tokio::net::TcpStream) -> io::Result<()> {
    let (host, port) = tokio::time::timeout(HELLO_TIMEOUT, socks::accept(&mut sock, &f.user, &f.pass))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "front-end handshake timed out"))??;
    let opened = match host.strip_suffix(BRIDGE) {
        Some(id) => f.parked.lock().unwrap().remove(id).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such bridge")),
        // curl: route the BMC by the table. Background work, so no prompts.
        None => {
            let opened = match curl_chain(&host) {
                Ok(chain) => super::ssh::reach(&chain, &host, port, &super::Context::default(), Some(CURL_REACH)).await,
                Err(e) => Err(e),
            };
            if let Err(e) = &opened {
                let mut recorded = failures().lock().unwrap();
                recorded.retain(|_, (at, _)| at.elapsed() < CAUSE_KEPT);
                recorded.insert(super::addr_key(&host), (Instant::now(), e.to_string()));
            }
            opened
        }
    };
    let (io, leases) = match opened {
        Ok(o) => o,
        Err(e) => {
            let _ = socks::answer(&mut sock, reply_code(&e)).await;
            return Err(e);
        }
    };
    socks::answer(&mut sock, 0).await?;
    sock.set_nodelay(true).ok();
    bridge(sock, io).await;
    drop(leases);
    Ok(())
}

/// How long the BMC may go on sending once the client has finished, as
/// `pump` gives the IPMI relay. A BMC that ignores the half-close and stays
/// silent would otherwise hold the channel, and its tunnel, for good.
const CLOSE_GRACE: Duration = Duration::from_secs(5);

/// Copy both ways until the client has finished, and the BMC has too or has
/// had `CLOSE_GRACE` to.
async fn bridge(mut sock: tokio::net::TcpStream, io: BoxIo) {
    use tokio::io::AsyncWriteExt;
    let (mut from_client, mut to_client) = sock.split();
    let (mut from_bmc, mut to_bmc) = tokio::io::split(io);
    let up = async {
        let _ = tokio::io::copy(&mut from_client, &mut to_bmc).await;
        let _ = to_bmc.shutdown().await;
    };
    let down = async {
        let _ = tokio::io::copy(&mut from_bmc, &mut to_client).await;
        let _ = to_client.shutdown().await;
    };
    tokio::pin!(up, down);
    tokio::select! {
        // The BMC has finished; the client finishes when it closes its socket.
        _ = &mut down => up.await,
        _ = &mut up => {
            let _ = tokio::time::timeout(CLOSE_GRACE, down).await;
        }
    }
}

/// Collect `io` as a real socket. `leases` keep its tunnels open until the
/// socket is closed.
pub(crate) fn hand_over(io: BoxIo, leases: Vec<Lease>) -> io::Result<TcpStream> {
    hand_over_to(&FRONTEND, io, leases)
}

fn hand_over_to(frontend: &Frontend, io: BoxIo, leases: Vec<Lease>) -> io::Result<TcpStream> {
    let f = frontend.get()?;
    let id = crate::rand::hex(16);
    f.parked.lock().unwrap().insert(id.clone(), (io, leases));
    let collect = || -> io::Result<TcpStream> {
        let mut s = TcpStream::connect(f.addr)?;
        s.set_read_timeout(Some(Duration::from_secs(10)))?;
        socks::connect(&mut s, &format!("{id}{BRIDGE}"), 0, Some(socks::Auth { user: &f.user, pass: &f.pass }))?;
        s.set_read_timeout(None)?;
        s.set_nodelay(true).ok();
        Ok(s)
    };
    let r = collect();
    if r.is_err() {
        f.parked.lock().unwrap().remove(&id);
    }
    r
}

/// Where `curl` sends a routed BMC's requests, and the credentials it needs.
pub(crate) fn proxy() -> io::Result<(String, String)> {
    let f = FRONTEND.get()?;
    Ok((format!("socks5h://127.0.0.1:{}", f.addr.port()), format!("{}:{}", f.user, f.pass)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tokio::io::AsyncReadExt;

    impl Frontend {
        fn new() -> Frontend {
            Frontend(Mutex::new(None))
        }

        /// End the serving task, as a panic in it would.
        fn stop(&self) {
            let serving = self.0.lock().unwrap();
            let task = &serving.as_ref().expect("serving").task;
            task.abort();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !task.is_finished() {
                assert!(Instant::now() < deadline, "the task did not end");
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }

    /// Hand one end of a pipe over, and check that bytes written to the
    /// socket come out of the other end.
    fn bridged(frontend: &Frontend) -> io::Result<()> {
        let (ours, mut theirs) = tokio::io::duplex(64);
        let mut s = hand_over_to(frontend, Box::new(ours), Vec::new())?;
        s.write_all(b"ping")?;
        let mut b = [0u8; 4];
        runtime().block_on(async { tokio::time::timeout(Duration::from_secs(5), theirs.read_exact(&mut b)).await })??;
        assert_eq!(&b, b"ping");
        Ok(())
    }

    #[test]
    fn a_failed_accept_does_not_stop_the_front_end() {
        let frontend = Frontend::new();
        let first = frontend.get().unwrap();
        first.fail_accepts.store(1, SeqCst);
        assert!(bridged(&frontend).is_err(), "the client whose accept failed is dropped");
        bridged(&frontend).expect("the next one is served");
        assert_eq!(frontend.get().unwrap().addr, first.addr, "by the same listener");
    }

    #[test]
    fn a_front_end_whose_task_ended_is_started_again() {
        let frontend = Frontend::new();
        let first = frontend.get().unwrap().addr;
        frontend.stop();
        bridged(&frontend).expect("served by a new listener");
        assert_ne!(frontend.get().unwrap().addr, first);
    }
}
