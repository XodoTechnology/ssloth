//! A SOCKS5 client (RFC 1928, with RFC 1929 username/password), and the
//! server half the loopback front end needs. Small enough to own rather than
//! depend on, like the other protocol code here. Targets always go as domain
//! names, so they resolve on the proxy's side, as `socks5h` does.

use std::io::{self, Read, Write};
use std::net::IpAddr;

const VERSION: u8 = 5;
pub const CONNECT: u8 = 1;
pub const UDP_ASSOCIATE: u8 = 3;
const NO_AUTH: u8 = 0;
const USER_PASS: u8 = 2;

#[derive(Clone, Copy)]
pub struct Auth<'a> {
    pub user: &'a str,
    pub pass: &'a str,
}

/// The address a proxy names in its reply: where it connected from, for
/// CONNECT; where to send datagrams, for UDP ASSOCIATE.
#[derive(Debug, PartialEq, Eq)]
pub struct Bound {
    pub host: String,
    pub port: u16,
}

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}
fn denied(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, msg.to_owned())
}

pub fn greeting(auth: Option<Auth>) -> Vec<u8> {
    match auth {
        Some(_) => vec![VERSION, 2, NO_AUTH, USER_PASS],
        None => vec![VERSION, 1, NO_AUTH],
    }
}

/// RFC 1929's sub-negotiation: both fields are length-prefixed bytes.
pub fn auth_request(a: Auth) -> io::Result<Vec<u8>> {
    if a.user.len() > 255 || a.pass.len() > 255 {
        return Err(bad("SOCKS5 user names and passwords are at most 255 bytes"));
    }
    let mut m = vec![1, a.user.len() as u8];
    m.extend_from_slice(a.user.as_bytes());
    m.push(a.pass.len() as u8);
    m.extend_from_slice(a.pass.as_bytes());
    Ok(m)
}

/// A request naming `host` as a domain (ATYP 3), even when it is an IP
/// literal: the proxy parses it either way, and a name resolves over there.
pub fn request(cmd: u8, host: &str, port: u16) -> io::Result<Vec<u8>> {
    if host.is_empty() || host.len() > 255 {
        return Err(bad("SOCKS5 host names are 1 to 255 bytes"));
    }
    let mut m = vec![VERSION, cmd, 0, 3, host.len() as u8];
    m.extend_from_slice(host.as_bytes());
    m.extend_from_slice(&port.to_be_bytes());
    Ok(m)
}

pub fn reply_text(code: u8) -> &'static str {
    match code {
        1 => "general SOCKS server failure",
        2 => "connection not allowed by ruleset",
        3 => "network unreachable",
        4 => "host unreachable",
        5 => "connection refused",
        6 => "TTL expired",
        7 => "command not supported",
        8 => "address type not supported",
        _ => "unknown SOCKS5 error",
    }
}

/// Whether the method the proxy chose works for us; true when it wants a
/// user name and password next.
fn method_ok(m: [u8; 2], auth: Option<Auth>) -> io::Result<bool> {
    if m[0] != VERSION {
        return Err(bad("not a SOCKS5 proxy"));
    }
    match (m[1], auth) {
        (NO_AUTH, _) => Ok(false),
        (USER_PASS, Some(_)) => Ok(true),
        (USER_PASS, None) => Err(super::refused("the proxy wants a user name and password")),
        _ => Err(super::refused("the proxy accepts none of the authentication methods offered")),
    }
}

fn auth_ok(r: [u8; 2]) -> io::Result<()> {
    if r[1] == 0 { Ok(()) } else { Err(super::refused("the proxy refused the user name or password")) }
}

fn reply_ok(head: [u8; 4]) -> io::Result<()> {
    if head[0] != VERSION {
        return Err(bad("the proxy did not answer as SOCKS5"));
    }
    if head[1] != 0 {
        return Err(io::Error::new(io::ErrorKind::ConnectionRefused, reply_text(head[1])));
    }
    Ok(())
}

fn read_addr<R: Read>(r: &mut R, atyp: u8) -> io::Result<String> {
    match atyp {
        1 => {
            let mut a = [0u8; 4];
            r.read_exact(&mut a)?;
            Ok(IpAddr::from(a).to_string())
        }
        4 => {
            let mut a = [0u8; 16];
            r.read_exact(&mut a)?;
            Ok(IpAddr::from(a).to_string())
        }
        3 => {
            let mut n = [0u8; 1];
            r.read_exact(&mut n)?;
            let mut a = vec![0u8; n[0] as usize];
            r.read_exact(&mut a)?;
            String::from_utf8(a).map_err(|_| bad("bad name in SOCKS5 reply"))
        }
        _ => Err(bad("unknown address type in SOCKS5 reply")),
    }
}

/// A reply: `[VER, REP, RSV, ATYP, address, port]`.
pub fn read_reply<R: Read>(r: &mut R) -> io::Result<Bound> {
    let mut head = [0u8; 4];
    r.read_exact(&mut head)?;
    reply_ok(head)?;
    let host = read_addr(r, head[3])?;
    let mut port = [0u8; 2];
    r.read_exact(&mut port)?;
    Ok(Bound { host, port: u16::from_be_bytes(port) })
}

/// Agree a method, authenticating if the proxy asks for it.
pub fn negotiate<S: Read + Write>(s: &mut S, auth: Option<Auth>) -> io::Result<()> {
    s.write_all(&greeting(auth))?;
    let mut m = [0u8; 2];
    s.read_exact(&mut m)?;
    if method_ok(m, auth)? {
        s.write_all(&auth_request(auth.expect("method_ok checked"))?)?;
        let mut r = [0u8; 2];
        s.read_exact(&mut r)?;
        auth_ok(r)?;
    }
    Ok(())
}

/// Ask the proxy at the far end of `s` for a connection to `host:port`. On
/// success `s` carries that connection.
pub fn connect<S: Read + Write>(s: &mut S, host: &str, port: u16, auth: Option<Auth>) -> io::Result<()> {
    negotiate(s, auth)?;
    s.write_all(&request(CONNECT, host, port)?)?;
    read_reply(s)
        .map(drop)
        .map_err(|e| io::Error::new(e.kind(), format!("proxy refused CONNECT to {host}:{port}: {e}")))
}

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The credentials a SOCKS5 route sends, if it has a user.
pub fn auth_of(route: &crate::routes::Route) -> Option<Auth<'_>> {
    (!route.user.is_empty()).then_some(Auth { user: &route.user, pass: &route.secret })
}

async fn read_addr_async<R: AsyncRead + Unpin>(r: &mut R, atyp: u8) -> io::Result<String> {
    match atyp {
        1 => {
            let mut a = [0u8; 4];
            r.read_exact(&mut a).await?;
            Ok(IpAddr::from(a).to_string())
        }
        4 => {
            let mut a = [0u8; 16];
            r.read_exact(&mut a).await?;
            Ok(IpAddr::from(a).to_string())
        }
        3 => {
            let n = r.read_u8().await? as usize;
            let mut a = vec![0u8; n];
            r.read_exact(&mut a).await?;
            String::from_utf8(a).map_err(|_| bad("bad name in SOCKS5 message"))
        }
        _ => Err(bad("unknown SOCKS5 address type")),
    }
}

/// `connect`, over a channel or any other async stream: a SOCKS5 proxy
/// reached through an SSH jump host.
pub async fn connect_async<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    host: &str,
    port: u16,
    auth: Option<Auth<'_>>,
) -> io::Result<()> {
    s.write_all(&greeting(auth)).await?;
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await?;
    if method_ok(m, auth)? {
        s.write_all(&auth_request(auth.expect("method_ok checked"))?).await?;
        let mut r = [0u8; 2];
        s.read_exact(&mut r).await?;
        auth_ok(r)?;
    }
    s.write_all(&request(CONNECT, host, port)?).await?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    reply_ok(head)
        .map_err(|e| io::Error::new(e.kind(), format!("proxy refused CONNECT to {host}:{port}: {e}")))?;
    read_addr_async(s, head[3]).await?;
    s.read_u16().await?;
    Ok(())
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The front end's side: require `user`/`pass`, read one CONNECT, and return
/// its target. Answering is left to the caller, once it knows the outcome.
pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, user: &str, pass: &str) -> io::Result<(String, u16)> {
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(bad("not SOCKS5"));
    }
    let mut methods = vec![0u8; head[1] as usize];
    s.read_exact(&mut methods).await?;
    if !methods.contains(&USER_PASS) {
        s.write_all(&[VERSION, 0xFF]).await?;
        return Err(denied("the front end requires its user name and password"));
    }
    s.write_all(&[VERSION, USER_PASS]).await?;
    let _sub_version = s.read_u8().await?;
    let mut u = vec![0u8; s.read_u8().await? as usize];
    s.read_exact(&mut u).await?;
    let mut p = vec![0u8; s.read_u8().await? as usize];
    s.read_exact(&mut p).await?;
    let ok = constant_eq(&u, user.as_bytes()) & constant_eq(&p, pass.as_bytes());
    s.write_all(&[1, if ok { 0 } else { 1 }]).await?;
    if !ok {
        return Err(denied("wrong front-end credentials"));
    }
    let mut req = [0u8; 4];
    s.read_exact(&mut req).await?;
    if req[1] != CONNECT {
        answer(s, 7).await?;
        return Err(bad("the front end only connects"));
    }
    let host = read_addr_async(s, req[3]).await?;
    let port = s.read_u16().await?;
    Ok((host, port))
}

/// Answer a CONNECT the front end accepted: 0 for success, else a reply code.
pub async fn answer<S: AsyncWrite + Unpin>(s: &mut S, code: u8) -> io::Result<()> {
    s.write_all(&[VERSION, code, 0, 1, 0, 0, 0, 0, 0, 0]).await
}

/// RFC 1928 §7's datagram header. The target goes as a literal where it is
/// one, which every relay accepts, and by name otherwise.
pub fn udp_wrap(host: &str, port: u16, data: &[u8]) -> Vec<u8> {
    let mut m = vec![0, 0, 0];
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => {
            m.push(1);
            m.extend_from_slice(&a.octets());
        }
        Ok(IpAddr::V6(a)) => {
            m.push(4);
            m.extend_from_slice(&a.octets());
        }
        Err(_) => {
            m.push(3);
            m.push(host.len().min(255) as u8);
            m.extend_from_slice(&host.as_bytes()[..host.len().min(255)]);
        }
    }
    m.extend_from_slice(&port.to_be_bytes());
    m.extend_from_slice(data);
    m
}

/// The payload of a relayed datagram, or None for a fragment or a malformed one.
pub fn udp_unwrap(pkt: &[u8]) -> Option<&[u8]> {
    if pkt.len() < 4 || pkt[0] != 0 || pkt[1] != 0 || pkt[2] != 0 {
        return None;
    }
    let addr = match pkt[3] {
        1 => 4,
        4 => 16,
        3 => 1 + *pkt.get(4)? as usize,
        _ => return None,
    };
    pkt.get(4 + addr + 2..)
}

/// IPMI's datagrams through a SOCKS5 proxy that relays UDP. The control
/// connection must stay open for as long as the association is used.
pub struct UdpAssociate {
    _control: std::net::TcpStream,
    sock: std::net::UdpSocket,
    host: String,
    port: u16,
}

/// What a failed UDP ASSOCIATE reply means. Only a refusal, or an answer
/// that is not SOCKS5, says the proxy will not relay UDP (`Unsupported`, which
/// `net::udp_via` remembers for the route); a slow or dropped connection is
/// just that, and is reported as it is.
fn associate_error(e: io::Error) -> io::Error {
    match e.kind() {
        io::ErrorKind::ConnectionRefused | io::ErrorKind::InvalidData => {
            io::Error::new(io::ErrorKind::Unsupported, format!("the proxy does not relay UDP: {e}"))
        }
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
            io::Error::new(io::ErrorKind::TimedOut, "timed out waiting for the UDP ASSOCIATE reply")
        }
        _ => e,
    }
}

/// Where to send datagrams: BND.ADDR, which may be a name (RFC 1928 allows
/// it), except that 0.0.0.0 or :: means "the address you reached me on".
fn relay_addr(bound: &Bound, peer: IpAddr) -> io::Result<std::net::SocketAddr> {
    use std::net::{SocketAddr, ToSocketAddrs};
    match bound.host.parse::<IpAddr>() {
        Ok(ip) if ip.is_unspecified() => Ok(SocketAddr::new(peer, bound.port)),
        Ok(ip) => Ok(SocketAddr::new(ip, bound.port)),
        Err(_) => (bound.host.as_str(), bound.port).to_socket_addrs()?.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("cannot resolve the proxy's UDP relay {}", bound.host))
        }),
    }
}

impl UdpAssociate {
    pub fn open(proxy: &crate::routes::Route, host: &str, port: u16) -> io::Result<UdpAssociate> {
        let mut control = super::direct(&proxy.host, proxy.port, Some(super::HOP_TIMEOUT))?;
        control.set_read_timeout(Some(super::HOP_TIMEOUT))?;
        negotiate(&mut control, auth_of(proxy))?;
        // DST.ADDR is where our datagrams will come from; all zeros says "not
        // known yet", which a client behind NAT cannot do better than.
        control.write_all(&[VERSION, UDP_ASSOCIATE, 0, 1, 0, 0, 0, 0, 0, 0])?;
        let bound = read_reply(&mut control).map_err(associate_error)?;
        let relay = relay_addr(&bound, control.peer_addr()?.ip())?;
        let sock = std::net::UdpSocket::bind(if relay.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" })?;
        sock.connect(relay)?;
        Ok(UdpAssociate { _control: control, sock, host: host.into(), port })
    }

    pub fn send(&self, data: &[u8]) -> io::Result<()> {
        self.sock.send(&udp_wrap(&self.host, self.port, data)).map(drop)
    }

    /// The next datagram's payload. `wait` bounds the whole call, however many
    /// fragments or malformed datagrams are skipped on the way.
    pub fn recv(&self, wait: std::time::Duration) -> io::Result<Vec<u8>> {
        let deadline = std::time::Instant::now() + wait;
        let mut b = [0u8; 2048];
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            self.sock.set_read_timeout(Some(left.max(std::time::Duration::from_millis(1))))?;
            let n = self.sock.recv(&mut b)?;
            if let Some(p) = udp_unwrap(&b[..n]) {
                return Ok(p.to_vec());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    /// A proxy that checks what the client sends and answers `rep`. Returns
    /// the target it was asked for.
    fn proxy(expect: Option<(&'static str, &'static str)>, rep: u8) -> (u16, thread::JoinHandle<(String, u16)>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut head = [0u8; 2];
            s.read_exact(&mut head).unwrap();
            let mut methods = vec![0u8; head[1] as usize];
            s.read_exact(&mut methods).unwrap();
            if let Some((u, p)) = expect {
                assert!(methods.contains(&2));
                s.write_all(&[5, 2]).unwrap();
                let mut v = [0u8; 2];
                s.read_exact(&mut v).unwrap();
                let mut user = vec![0u8; v[1] as usize];
                s.read_exact(&mut user).unwrap();
                let mut n = [0u8; 1];
                s.read_exact(&mut n).unwrap();
                let mut pass = vec![0u8; n[0] as usize];
                s.read_exact(&mut pass).unwrap();
                let ok = user == u.as_bytes() && pass == p.as_bytes();
                s.write_all(&[1, if ok { 0 } else { 1 }]).unwrap();
                if !ok {
                    return (String::new(), 0);
                }
            } else {
                s.write_all(&[5, 0]).unwrap();
            }
            let mut req = [0u8; 4];
            s.read_exact(&mut req).unwrap();
            assert_eq!(&req[..3], &[5, 1, 0]);
            assert_eq!(req[3], 3, "targets go by name, so they resolve at the proxy");
            let host = read_addr(&mut s, 3).unwrap();
            let mut port = [0u8; 2];
            s.read_exact(&mut port).unwrap();
            s.write_all(&[5, rep, 0, 1, 10, 0, 0, 9, 0x1F, 0x90]).unwrap();
            (host, u16::from_be_bytes(port))
        });
        (port, h)
    }

    #[test]
    fn connects_by_name_without_auth() {
        let (port, h) = proxy(None, 0);
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        connect(&mut s, "10.20.1.11", 443, None).unwrap();
        assert_eq!(h.join().unwrap(), ("10.20.1.11".to_owned(), 443));
    }

    #[test]
    fn authenticates_and_reports_refusals() {
        let (port, h) = proxy(Some(("ops", "pw")), 0);
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        connect(&mut s, "bmc.lab", 623, Some(Auth { user: "ops", pass: "pw" })).unwrap();
        assert_eq!(h.join().unwrap(), ("bmc.lab".to_owned(), 623));

        let (port, _h) = proxy(Some(("ops", "pw")), 0);
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let e = connect(&mut s, "bmc.lab", 623, Some(Auth { user: "ops", pass: "nope" })).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);

        let (port, _h) = proxy(None, 2);
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let e = connect(&mut s, "10.20.1.11", 443, None).unwrap_err();
        assert_eq!(e.to_string(), "proxy refused CONNECT to 10.20.1.11:443: connection not allowed by ruleset");
    }

    #[test]
    fn every_reply_code_has_its_own_text() {
        let texts: std::collections::HashSet<_> = (1..=8).map(reply_text).collect();
        assert_eq!(texts.len(), 8);
        assert_eq!(reply_text(0x42), "unknown SOCKS5 error");
    }

    #[test]
    fn reads_every_address_type() {
        for (bytes, want) in [
            (vec![5, 0, 0, 1, 192, 0, 2, 1, 0, 80], "192.0.2.1"),
            (vec![5, 0, 0, 3, 3, b'b', b'm', b'c', 0, 80], "bmc"),
            (vec![5, 0, 0, 4, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 80], "2001:db8::1"),
        ] {
            assert_eq!(read_reply(&mut &bytes[..]).unwrap(), Bound { host: want.into(), port: 80 });
        }
    }

    #[test]
    fn udp_associate_wraps_and_unwraps() {
        use std::net::UdpSocket;
        use std::time::Duration;
        let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
        let echo_addr = echo.local_addr().unwrap();
        thread::spawn(move || {
            let mut b = [0u8; 512];
            while let Ok((n, from)) = echo.recv_from(&mut b) {
                echo.send_to(&b[..n], from).unwrap();
            }
        });
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
        let relay_port = relay.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut g = [0u8; 3];
            s.read_exact(&mut g).unwrap();
            s.write_all(&[5, 0]).unwrap();
            let mut req = [0u8; 10];
            s.read_exact(&mut req).unwrap();
            assert_eq!(req[1], UDP_ASSOCIATE);
            s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1]).unwrap();
            s.write_all(&relay_port.to_be_bytes()).unwrap();
            let mut b = [0u8; 1024];
            let (n, client) = relay.recv_from(&mut b).unwrap();
            let payload = udp_unwrap(&b[..n]).unwrap().to_vec();
            let out = UdpSocket::bind("127.0.0.1:0").unwrap();
            out.send_to(&payload, echo_addr).unwrap();
            let m = out.recv(&mut b).unwrap();
            relay.send_to(&udp_wrap(&echo_addr.ip().to_string(), echo_addr.port(), &b[..m]), client).unwrap();
            thread::sleep(Duration::from_secs(2));
            drop(s);
        });
        let proxy = crate::routes::Route { name: "p".into(), host: "127.0.0.1".into(), port, ..Default::default() };
        let u = UdpAssociate::open(&proxy, &echo_addr.ip().to_string(), echo_addr.port()).unwrap();
        u.send(b"ipmi").unwrap();
        assert_eq!(u.recv(Duration::from_secs(2)).unwrap(), b"ipmi");
    }

    #[test]
    fn only_a_refusal_says_the_proxy_does_not_relay_udp() {
        use io::ErrorKind::*;
        for (kind, becomes) in [
            (ConnectionRefused, Unsupported),
            (InvalidData, Unsupported),
            (WouldBlock, TimedOut),
            (TimedOut, TimedOut),
            (UnexpectedEof, UnexpectedEof),
            (ConnectionReset, ConnectionReset),
        ] {
            assert_eq!(associate_error(io::Error::new(kind, "x")).kind(), becomes, "{kind:?}");
        }
    }

    #[test]
    fn the_udp_relay_is_where_the_proxy_says() {
        let peer: IpAddr = "192.0.2.9".parse().unwrap();
        let at = |host: &str| relay_addr(&Bound { host: host.into(), port: 1080 }, peer).unwrap();
        assert_eq!(at("0.0.0.0"), "192.0.2.9:1080".parse().unwrap(), "unspecified: where we reached it");
        assert_eq!(at("::").ip(), peer);
        assert_eq!(at("198.51.100.7"), "198.51.100.7:1080".parse().unwrap());
        assert!(at("localhost").ip().is_loopback(), "a name is resolved, not replaced by the peer");
    }
}
