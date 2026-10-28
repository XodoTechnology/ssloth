//! A native IPMI v2.0 client — RMCP+ over UDP :623 — so power, BMC reset, the
//! X9 clock roll-back, the SEL and sensors work without `ipmitool` on `PATH`.
//!
//! Session establishment is RAKP, as IPMI v2.0 §13.17-13.31 lays it out:
//!
//!   Get Channel Authentication Capabilities   (IPMI 1.5 framing, no session)
//!   Open Session Request / Response            payload 0x10 / 0x11
//!   RAKP 1 -> RAKP 2                           we send Rm, BMC answers Rc, GUIDc
//!   RAKP 3 -> RAKP 4                           each side proves the password
//!   Set Session Privilege Level, then commands, then Close Session
//!
//! Two cipher suites, the pair the crate already asked `ipmitool` for:
//! 17 (RAKP-HMAC-SHA256, HMAC-SHA256-128, AES-CBC-128) and 3 (RAKP-HMAC-SHA1,
//! HMAC-SHA1-96, AES-CBC-128), which is all the older AMI firmware speaks.
//! `Session::open` tries 17 first and falls back to 3.
//!
//! Crypto comes from the `openssl` crate the Avocent family already needs, so
//! this adds no dependency.

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::symm::{Cipher, Crypter, Mode};
use std::io::{Read, Write};
use std::time::{Duration, Instant};

const PORT: u16 = 623;
const RMCP: [u8; 4] = [0x06, 0x00, 0xFF, 0x07];
const BMC_ADDR: u8 = 0x20;
const CONSOLE_ADDR: u8 = 0x81;

// Payload types.
const PT_IPMI: u8 = 0x00;
const PT_OPEN_REQ: u8 = 0x10;
const PT_OPEN_RSP: u8 = 0x11;
const PT_RAKP1: u8 = 0x12;
const PT_RAKP2: u8 = 0x13;
const PT_RAKP3: u8 = 0x14;
const PT_RAKP4: u8 = 0x15;
const ENCRYPTED: u8 = 0x80;
const AUTHENTICATED: u8 = 0x40;

// Network functions.
pub const NETFN_CHASSIS: u8 = 0x00;
pub const NETFN_SENSOR: u8 = 0x04;
pub const NETFN_APP: u8 = 0x06;
pub const NETFN_STORAGE: u8 = 0x0A;

/// Privilege levels, as RAKP 1 and Set Session Privilege Level name them.
const PRIV_ADMIN: u8 = 4;
const PRIV_OPERATOR: u8 = 3;
/// RAKP 1 role bit: look the user up by name only, as `ipmitool` does.
const NAME_ONLY_LOOKUP: u8 = 0x10;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Suite {
    /// Cipher suite 17: SHA-256 throughout.
    Sha256,
    /// Cipher suite 3: SHA-1, for firmware that predates suite 17.
    Sha1,
}

impl Suite {
    fn digest(self) -> MessageDigest {
        match self {
            Suite::Sha256 => MessageDigest::sha256(),
            Suite::Sha1 => MessageDigest::sha1(),
        }
    }
    /// Authentication, integrity and confidentiality algorithm numbers.
    fn algorithms(self) -> (u8, u8, u8) {
        match self {
            Suite::Sha256 => (3, 4, 1),
            Suite::Sha1 => (1, 1, 1),
        }
    }
    /// Bytes of HMAC kept as the RAKP 4 check value and the packet trailer.
    fn icv_len(self) -> usize {
        match self {
            Suite::Sha256 => 16,
            Suite::Sha1 => 12,
        }
    }
    pub fn number(self) -> u8 {
        match self {
            Suite::Sha256 => 17,
            Suite::Sha1 => 3,
        }
    }
}

/// An established RMCP+ session.
pub struct Session {
    link: Link,
    suite: Suite,
    /// The BMC's session id, which every packet we send carries.
    bmc_sid: u32,
    seq: u32,
    rq_seq: u8,
    k1: Vec<u8>,
    k2: Vec<u8>,
}

/// Where IPMI's datagrams go. Direct and through SOCKS5 they stay datagrams;
/// through an SSH jump host the relay hands them back as one byte stream,
/// which is split here because only the session knows the AuthCode length
/// that ends an authenticated packet.
struct Link {
    /// The hops the datagrams go over, empty when direct: what this link
    /// learns about UDP is recorded against them, and its errors name the last.
    chain: Vec<crate::routes::Route>,
    dg: crate::net::Datagram,
    buf: Vec<u8>,
    /// Whether anything has come back yet: the first reply is what shows
    /// that the route carries IPMI.
    heard: bool,
}

/// The largest packet the direct path can take in, its receive buffer. A
/// relayed "packet" longer than this is bytes that only look like a header.
const MAX_PACKET: usize = 2048;

/// Whether `b` could start an RMCP header for IPMI, as far as it goes:
/// version 6, a reserved zero, class 7. Byte 2 is a sequence number.
fn rmcp_start(b: &[u8]) -> bool {
    [(0, RMCP[0]), (1, RMCP[1]), (3, RMCP[3])].iter().all(|&(i, v)| b.get(i).is_none_or(|&x| x == v))
}

/// Length of the first packet in `b`: None until enough has arrived to tell,
/// `Err` if `b` does not start with an IPMI packet at all. Only class 7 (IPMI)
/// is framed: an ASF ping (class 6) is reported as garbage, as nothing here
/// sends one.
pub(crate) fn frame_len(b: &[u8], icv: usize) -> Option<std::result::Result<usize, ()>> {
    if !rmcp_start(b) {
        return Some(Err(()));
    }
    if b.len() < 5 {
        return None;
    }
    let n = match b[4] {
        // RMCP+ (§13.6): 16-byte header with a 2-byte payload length. An
        // authenticated packet adds the pad that brings auth type through
        // next header to a multiple of 4, the pad length, next header, AuthCode.
        0x06 => {
            if b.len() < 16 {
                return None;
            }
            let len = u16::from_le_bytes([b[14], b[15]]) as usize;
            let auth = if b[5] & AUTHENTICATED != 0 { (4 - (len + 14) % 4) % 4 + 2 + icv } else { 0 };
            16 + len + auth
        }
        // IPMI 1.5 (§13.6): one-byte length, after a 16-byte AuthCode unless
        // the auth type is none.
        0x00 => {
            if b.len() < 14 {
                return None;
            }
            14 + b[13] as usize
        }
        0x01 | 0x02 | 0x04 | 0x05 => {
            if b.len() < 30 {
                return None;
            }
            30 + b[29] as usize
        }
        _ => return Some(Err(())),
    };
    // A false header must not leave the link waiting for kilobytes that will
    // never come, timing out every exchange after it.
    Some(if n > MAX_PACKET { Err(()) } else { Ok(n) })
}

impl Link {
    fn open(chain: &[crate::routes::Route], dg: crate::net::Datagram) -> Link {
        Link { chain: chain.to_vec(), dg, buf: Vec::new(), heard: false }
    }

    /// `e`, naming the hop it came through when there is one.
    fn routed(&self, e: std::io::Error) -> std::io::Error {
        match self.chain.last() {
            Some(hop) => crate::net::via(hop, e),
            None => e,
        }
    }

    fn send(&mut self, pkt: &[u8]) -> std::io::Result<()> {
        use crate::net::Datagram::*;
        match &mut self.dg {
            Udp(s) => s.send(pkt).map(drop),
            Socks(s) => s.send(pkt),
            Stream(s, _) => s.write_all(pkt),
        }
    }

    /// The next packet, or an `Io` WouldBlock/TimedOut once `until` has
    /// passed. A relay that has ended is `Error::Route`.
    fn recv(&mut self, until: Instant, icv: usize) -> Result<Vec<u8>> {
        use crate::net::Datagram::*;
        let left = || until.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
        let mut b = [0u8; MAX_PACKET];
        let pkt = match &mut self.dg {
            Udp(s) => {
                s.set_read_timeout(Some(left()))?;
                let n = s.recv(&mut b)?;
                b[..n].to_vec()
            }
            Socks(s) => s.recv(left())?,
            Stream(s, end) => loop {
                match frame_len(&self.buf, icv) {
                    Some(Ok(n)) if self.buf.len() >= n => break self.buf.drain(..n).collect(),
                    // Lost sync: drop bytes up to the next that could start a
                    // packet, keeping any whole one buffered behind the garbage.
                    Some(Err(())) => {
                        let skip = (1..self.buf.len()).find(|&i| rmcp_start(&self.buf[i..])).unwrap_or(self.buf.len());
                        self.buf.drain(..skip);
                        continue;
                    }
                    _ => {}
                }
                s.set_read_timeout(Some(left()))?;
                match s.read(&mut b)? {
                    0 => {
                        let why = end.describe();
                        // Only missing tools are the route's; anything else
                        // may be this one BMC, such as a name the jump host
                        // cannot resolve.
                        let missing = end.lacks_tools();
                        let e = self.routed(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, why));
                        if missing {
                            crate::net::mark_udp(&self.chain, crate::net::Udp::Unavailable(e.to_string()));
                        }
                        return Err(Error::Route(e));
                    }
                    n => self.buf.extend_from_slice(&b[..n]),
                }
            },
        };
        if !self.heard {
            self.heard = true;
            crate::net::mark_udp(&self.chain, crate::net::Udp::Available);
        }
        Ok(pkt)
    }
}

/// Send a datagram and wait for one that `accept` recognises, resending on
/// silence: UDP loses packets, and BMCs drop requests while busy.
fn exchange(link: &mut Link, icv: usize, pkt: &[u8], accept: impl Fn(&[u8]) -> bool) -> Result<Vec<u8>> {
    for _ in 0..4 {
        link.send(pkt)?;
        let deadline = Instant::now() + Duration::from_millis(1500);
        while Instant::now() < deadline {
            match link.recv(deadline, icv) {
                Ok(r) if accept(&r) => return Ok(r),
                Ok(_) => continue,
                Err(Error::Io(e)) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                    break
                }
                Err(e) => return Err(e),
            }
        }
    }
    Err(Error::Io(link.routed(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "no answer from the BMC on UDP 623 (is IPMI over LAN enabled?)",
    ))))
}

/// Get Channel Authentication Capabilities, which needs no session or
/// credentials: whether anything answers IPMI at `host` through `chain`.
/// `route test`'s IPMI stage, so what it learns is recorded against `chain`.
pub fn probe_via(chain: &[crate::routes::Route], host: &str) -> Result<()> {
    let mut link = Link::open(chain, crate::net::udp_via(chain, host, PORT).map_err(Error::Route)?);
    let caps = ipmi_msg(NETFN_APP, 0, 0x38, 0, &[0x8E, PRIV_ADMIN]);
    let mut pkt = RMCP.to_vec();
    pkt.extend_from_slice(&[0x00, 0, 0, 0, 0, 0, 0, 0, 0, caps.len() as u8]);
    pkt.extend_from_slice(&caps);
    exchange(&mut link, 16, &pkt, |r| r.len() > 4 && r[..4] == RMCP).map(drop)
}

/// An IPMI error: either the transport or a completion code.
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// The route failed rather than the BMC: it could not be set up, or its
    /// relay ended. Another cipher suite would only fail the same way.
    Route(std::io::Error),
    /// A completion code other than 0x00, with the command it answered.
    Completion { cmd: u8, code: u8 },
    Protocol(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Io(e) | Error::Route(e) => write!(f, "{e}"),
            Error::Completion { cmd, code } => {
                write!(f, "command {cmd:#04x} failed: {} ({code:#04x})", completion_text(*code))
            }
            Error::Protocol(m) => f.write_str(m),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::Io(e) | Error::Route(e) => e,
            other => std::io::Error::new(std::io::ErrorKind::Other, other.to_string()),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

fn proto<T>(m: impl Into<String>) -> Result<T> {
    Err(Error::Protocol(m.into()))
}

fn completion_text(code: u8) -> &'static str {
    match code {
        0xC0 => "node busy",
        0xC1 => "invalid command",
        0xC2 => "invalid for this LUN",
        0xC3 => "timeout",
        0xC4 => "out of space",
        0xC5 => "reservation cancelled",
        0xC6 => "request data truncated",
        0xC7 => "request data length invalid",
        0xC8 => "request data field length limit exceeded",
        0xC9 => "parameter out of range",
        0xCA => "cannot return the requested number of bytes",
        0xCB => "requested sensor, data or record not present",
        0xCC => "invalid data field in request",
        0xCD => "command illegal for this sensor or record type",
        0xCE => "response could not be provided",
        0xCF => "duplicated request",
        0xD0 => "SDR repository in update mode",
        0xD1 => "device in firmware update mode",
        0xD2 => "BMC initialisation in progress",
        0xD3 => "destination unavailable",
        0xD4 => "insufficient privilege",
        0xD5 => "not supported in present state",
        0xD6 => "parameter is illegal",
        _ => "unspecified error",
    }
}

/// RAKP status codes, for a refusal that says why.
fn rakp_status(code: u8) -> &'static str {
    match code {
        0x01 => "insufficient resources to create a session",
        0x02 => "invalid session id",
        0x03 => "invalid payload type",
        0x04 => "invalid authentication algorithm",
        0x05 => "invalid integrity algorithm",
        0x06 => "no matching authentication payload",
        0x07 => "no matching integrity payload",
        0x08 => "inactive session id",
        0x09 => "invalid role",
        0x0A => "unauthorised role or privilege level requested",
        0x0B => "insufficient resources to create a session at the requested role",
        0x0C => "invalid name length",
        0x0D => "unauthorised name (unknown user)",
        0x0E => "unauthorised GUID",
        0x0F => "invalid integrity check value (wrong password)",
        0x10 => "invalid confidentiality algorithm",
        0x11 => "no cipher suite match",
        0x12 => "illegal or unrecognised parameter",
        _ => "refused",
    }
}

fn hmac(md: MessageDigest, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let k = PKey::hmac(key).expect("HMAC key");
    let mut s = Signer::new(md, &k).expect("HMAC signer");
    for p in parts {
        s.update(p).expect("HMAC update");
    }
    s.sign_to_vec().expect("HMAC sign")
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    openssl::rand::rand_bytes(&mut b).expect("OS randomness");
    b
}

fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |a, b| a.wrapping_add(*b)).wrapping_neg()
}

/// An IPMI request message: the addressing, two checksums, and the data.
fn ipmi_msg(netfn: u8, lun: u8, cmd: u8, rq_seq: u8, data: &[u8]) -> Vec<u8> {
    let mut m = vec![BMC_ADDR, netfn << 2 | (lun & 3), 0];
    m[2] = checksum(&m[..2]);
    m.extend_from_slice(&[CONSOLE_ADDR, rq_seq << 2, cmd]);
    m.extend_from_slice(data);
    let c = checksum(&m[3..]);
    m.push(c);
    m
}

impl Session {
    /// Log in, trying cipher suite 17 and then 3, at administrator privilege
    /// and then operator — the level an operator account can actually have.
    pub fn open(host: &str, user: &str, pass: &str) -> Result<Session> {
        let mut last = None;
        for suite in [Suite::Sha256, Suite::Sha1] {
            let r = Session::open_with(host, user, pass, suite);
            if let (Err(e), true) = (&r, std::env::var("BMCKVM_DEBUG").is_ok()) {
                eprintln!("[ipmi] cipher suite {}: {e}", suite.number());
            }
            match r {
                Ok(s) => return Ok(s),
                // The route failed, not the suite: trying the next would only
                // open it again, and ask again for anything it prompts for.
                Err(e @ Error::Route(_)) => return Err(e),
                // Even "wrong password" is worth one more suite: a Lenovo TSM
                // (AMI SP-X) fails RAKP 2 verification under suite 17 with the
                // right password and succeeds under 3, as ipmitool finds too.
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| Error::Protocol("no session".into())))
    }

    pub fn open_with(host: &str, user: &str, pass: &str, suite: Suite) -> Result<Session> {
        if user.len() > 16 {
            return proto("IPMI user names are at most 16 characters");
        }
        // The chain net::udp resolves too: the link records against it.
        let chain = crate::net::chain_for(host);
        let dg = match crate::net::udp(host, PORT) {
            Ok(dg) => dg,
            // A direct socket that would not open is tried again under the
            // next suite, as it always was.
            Err(e) if matches!(&chain, Ok(c) if c.is_empty()) => return Err(Error::Io(e)),
            Err(e) => return Err(Error::Route(e)),
        };
        let link = Link::open(&chain.unwrap_or_default(), dg);
        let mut s = Session {
            link,
            suite,
            bmc_sid: 0,
            seq: 0,
            rq_seq: 1,
            k1: Vec::new(),
            k2: Vec::new(),
        };

        // Channel authentication capabilities: harmless, and some BMCs will not
        // open a session for a client that has not asked first.
        let caps = ipmi_msg(NETFN_APP, 0, 0x38, 0, &[0x8E, PRIV_ADMIN]);
        let mut pkt = RMCP.to_vec();
        pkt.extend_from_slice(&[0x00, 0, 0, 0, 0, 0, 0, 0, 0, caps.len() as u8]);
        pkt.extend_from_slice(&caps);
        let reply = s.exchange_raw(&pkt, |r| r.len() > 4 && r[..4] == RMCP)?;
        if reply.len() < 22 || reply.get(20) != Some(&0) {
            return proto("the BMC did not answer the IPMI capabilities request");
        }
        // Byte 2 of the capabilities data, bit 7: IPMI v2.0 extended data.
        if reply.get(22).is_some_and(|b| b & 0x80 == 0) {
            return proto("the BMC does not support IPMI v2.0 (RMCP+)");
        }

        let mut last = None;
        for priv_level in [PRIV_ADMIN, PRIV_OPERATOR] {
            match s.handshake(user, pass, priv_level) {
                Ok(()) => {
                    // Set Session Privilege Level. A name-only lookup lets RAKP
                    // succeed at a level the account does not hold, and the BMC
                    // then refuses this (0x81, on the X570D4U's operator
                    // account); step down as ipmitool does rather than fail.
                    let mut level = priv_level;
                    loop {
                        match s.call(NETFN_APP, 0x3B, &[level]) {
                            Ok(_) => return Ok(s),
                            Err(Error::Completion { code: 0x80 | 0x81, .. }) if level > 2 => level -= 1,
                            Err(e) => return Err(e),
                        }
                    }
                }
                // Only a refused role is worth retrying at a lower level.
                Err(Error::Protocol(m)) if m.contains("role") => last = Some(Error::Protocol(m)),
                Err(e) => return Err(e),
            }
        }
        Err(last.unwrap())
    }

    fn handshake(&mut self, user: &str, pass: &str, priv_level: u8) -> Result<()> {
        let md = self.suite.digest();
        let (auth, integ, conf) = self.suite.algorithms();
        let console_sid = u32::from_le_bytes(random::<4>()) | 1;
        let tag = random::<1>()[0];

        // Open Session.
        let mut p = vec![tag, 0, 0, 0];
        p.extend_from_slice(&console_sid.to_le_bytes());
        p.extend_from_slice(&[0, 0, 0, 8, auth, 0, 0, 0]);
        p.extend_from_slice(&[1, 0, 0, 8, integ, 0, 0, 0]);
        p.extend_from_slice(&[2, 0, 0, 8, conf, 0, 0, 0]);
        let r = self.exchange_setup(PT_OPEN_REQ, PT_OPEN_RSP, &p)?;
        if r.len() < 12 || r[1] != 0 {
            return proto(format!("open session refused: {}", rakp_status(r.get(1).copied().unwrap_or(0xFF))));
        }
        let bmc_sid = u32::from_le_bytes([r[8], r[9], r[10], r[11]]);

        // RAKP 1: our random, the role, the user name.
        let rm = random::<16>();
        let role = priv_level | NAME_ONLY_LOOKUP;
        let uname = user.as_bytes();
        let mut p = vec![tag, 0, 0, 0];
        p.extend_from_slice(&bmc_sid.to_le_bytes());
        p.extend_from_slice(&rm);
        p.extend_from_slice(&[role, 0, 0, uname.len() as u8]);
        p.extend_from_slice(uname);
        let r = self.exchange_setup(PT_RAKP1, PT_RAKP2, &p)?;
        if r.len() < 2 || r[1] != 0 {
            return proto(format!("RAKP 2: {}", rakp_status(r.get(1).copied().unwrap_or(0xFF))));
        }
        let digest_len = md.size();
        if r.len() < 40 + digest_len {
            return proto("RAKP 2 is too short");
        }
        let rc = &r[8..24];
        let guid = &r[24..40];
        let their = &r[40..40 + digest_len];

        // The password key is the password zero-padded to 20 bytes, for either
        // digest — the IPMI 1.5 password field width, which `ipmitool` keeps.
        let mut kuid = [0u8; 20];
        let pw = pass.as_bytes();
        kuid[..pw.len().min(20)].copy_from_slice(&pw[..pw.len().min(20)]);
        let ulen = [uname.len() as u8];
        let expect = hmac(md, &kuid, &[
            &console_sid.to_le_bytes(), &bmc_sid.to_le_bytes(), &rm, rc, guid, &[role], &ulen, uname,
        ]);
        if expect != their {
            return proto("RAKP 2 did not verify (wrong password)");
        }

        let sik = hmac(md, &kuid, &[&rm, rc, &[role], &ulen, uname]);
        // The constants are 20 bytes for either digest. IPMI 2.0 defined them for
        // SHA-1 and suite 17 never widened them; `ipmitool` and the BMCs agree.
        self.k1 = hmac(md, &sik, &[&[1u8; 20]]);
        self.k2 = hmac(md, &sik, &[&[2u8; 20]]);

        // RAKP 3: prove we know the password too.
        let code = hmac(md, &kuid, &[rc, &console_sid.to_le_bytes(), &[role], &ulen, uname]);
        let mut p = vec![tag, 0, 0, 0];
        p.extend_from_slice(&bmc_sid.to_le_bytes());
        p.extend_from_slice(&code);
        let r = self.exchange_setup(PT_RAKP3, PT_RAKP4, &p)?;
        if r.len() < 2 || r[1] != 0 {
            return proto(format!("RAKP 4: {}", rakp_status(r.get(1).copied().unwrap_or(0xFF))));
        }
        let icv = hmac(md, &sik, &[&rm, &bmc_sid.to_le_bytes(), guid]);
        if r.len() < 8 + self.suite.icv_len() || r[8..8 + self.suite.icv_len()] != icv[..self.suite.icv_len()] {
            return proto("RAKP 4 did not verify");
        }
        self.bmc_sid = bmc_sid;
        self.seq = 1;
        Ok(())
    }

    /// Send a session-setup payload (unauthenticated, session id 0) and wait
    /// for the matching response type.
    fn exchange_setup(&mut self, ty: u8, want: u8, payload: &[u8]) -> Result<Vec<u8>> {
        let mut pkt = RMCP.to_vec();
        pkt.extend_from_slice(&[0x06, ty, 0, 0, 0, 0, 0, 0, 0, 0]);
        pkt.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        pkt.extend_from_slice(payload);
        let r = self.exchange_raw(&pkt, |r| r.len() >= 16 && r[5] & 0x3F == want)?;
        let len = u16::from_le_bytes([r[14], r[15]]) as usize;
        Ok(r.get(16..16 + len).unwrap_or(&r[16..]).to_vec())
    }

    /// `exchange` over this session's link, split by its suite's AuthCode length.
    fn exchange_raw(&mut self, pkt: &[u8], accept: impl Fn(&[u8]) -> bool) -> Result<Vec<u8>> {
        let icv = self.suite.icv_len();
        exchange(&mut self.link, icv, pkt, accept)
    }

    /// Run one command; returns its response data after the completion code.
    pub fn call(&mut self, netfn: u8, cmd: u8, data: &[u8]) -> Result<Vec<u8>> {
        self.call_lun(netfn, 0, cmd, data)
    }

    /// `call` addressed to one of the BMC's other LUNs, where some sensors live.
    pub fn call_lun(&mut self, netfn: u8, lun: u8, cmd: u8, data: &[u8]) -> Result<Vec<u8>> {
        let r = self.send_ipmi(netfn, lun, cmd, data, true)?;
        match r {
            Some(r) => Ok(r),
            None => Err(Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "no answer"))),
        }
    }

    /// Run a command the BMC may not answer — Cold Reset restarts it before it
    /// replies. Returns Ok(None) on silence.
    pub fn call_no_reply(&mut self, netfn: u8, cmd: u8, data: &[u8]) -> Result<Option<Vec<u8>>> {
        self.send_ipmi(netfn, 0, cmd, data, false)
    }

    fn send_ipmi(&mut self, netfn: u8, lun: u8, cmd: u8, data: &[u8], need_reply: bool)
        -> Result<Option<Vec<u8>>>
    {
        let rq_seq = self.rq_seq;
        self.rq_seq = (self.rq_seq + 1) & 0x3F;
        let msg = ipmi_msg(netfn, lun, cmd, rq_seq, data);
        let pkt = self.seal(&msg);
        let want_netfn = netfn + 1;
        // The keys, not `self`: the link is borrowed mutably alongside them.
        let (suite, k1, k2) = (self.suite, &self.k1, &self.k2);
        let accept = |r: &[u8]| {
            match Self::open_packet(suite, k1, k2, r) {
                Some(m) => m.len() >= 7 && m[1] >> 2 == want_netfn && m[4] >> 2 == rq_seq && m[5] == cmd,
                None => false,
            }
        };
        let raw = match exchange(&mut self.link, suite.icv_len(), &pkt, accept) {
            Ok(r) => r,
            Err(Error::Io(e)) if !need_reply && e.kind() == std::io::ErrorKind::TimedOut => {
                return Ok(None)
            }
            Err(e) => return Err(e),
        };
        let m = Self::open_packet(self.suite, &self.k1, &self.k2, &raw).unwrap();
        let code = m[6];
        if code != 0 {
            return Err(Error::Completion { cmd, code });
        }
        // Strip the trailing checksum.
        Ok(Some(m[7..m.len() - 1].to_vec()))
    }

    /// Encrypt and authenticate an IPMI message into an RMCP+ packet.
    fn seal(&mut self, msg: &[u8]) -> Vec<u8> {
        // AES-CBC-128 with the vendor-neutral padding: 1, 2, 3 ... then the count.
        let mut plain = msg.to_vec();
        let pad = (16 - (plain.len() + 1) % 16) % 16;
        plain.extend((1..=pad as u8).collect::<Vec<_>>());
        plain.push(pad as u8);
        let iv = random::<16>();
        let mut c = Crypter::new(Cipher::aes_128_cbc(), Mode::Encrypt, &self.k2[..16], Some(&iv))
            .expect("AES");
        c.pad(false);
        let mut enc = vec![0u8; plain.len() + 16];
        let mut n = c.update(&plain, &mut enc).expect("AES update");
        n += c.finalize(&mut enc[n..]).expect("AES final");
        enc.truncate(n);

        let mut payload = iv.to_vec();
        payload.extend_from_slice(&enc);

        let mut p = RMCP.to_vec();
        p.push(0x06);
        p.push(PT_IPMI | ENCRYPTED | AUTHENTICATED);
        p.extend_from_slice(&self.bmc_sid.to_le_bytes());
        p.extend_from_slice(&self.seq.to_le_bytes());
        self.seq = self.seq.wrapping_add(1).max(1);
        p.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        p.extend_from_slice(&payload);
        // Integrity pad: 0xFF until the authenticated span (from the auth type
        // byte through the next-header byte) is a multiple of four.
        let span = p.len() - 4 + 2;
        let ipad = (4 - span % 4) % 4;
        p.extend(std::iter::repeat(0xFF).take(ipad));
        p.push(ipad as u8);
        p.push(0x07);
        let code = hmac(self.suite.digest(), &self.k1, &[&p[4..]]);
        p.extend_from_slice(&code[..self.suite.icv_len()]);
        p
    }

    /// Verify and decrypt an RMCP+ packet from the BMC; None if it is not one
    /// of ours or does not verify.
    fn open_packet(suite: Suite, k1: &[u8], k2: &[u8], r: &[u8]) -> Option<Vec<u8>> {
        if r.len() < 16 || r[..4] != RMCP || r[4] != 0x06 || r[5] & 0x3F != PT_IPMI {
            return None;
        }
        let len = u16::from_le_bytes([r[14], r[15]]) as usize;
        let body = r.get(16..16 + len)?;
        if r[5] & AUTHENTICATED != 0 {
            let icv = suite.icv_len();
            if r.len() < 16 + len + 2 + icv {
                return None;
            }
            let end = r.len() - icv;
            let code = hmac(suite.digest(), k1, &[&r[4..end]]);
            if code[..icv] != r[end..] {
                return None;
            }
        }
        if r[5] & ENCRYPTED == 0 {
            return Some(body.to_vec());
        }
        if body.len() < 32 || (body.len() - 16) % 16 != 0 {
            return None;
        }
        let (iv, data) = body.split_at(16);
        let mut c = Crypter::new(Cipher::aes_128_cbc(), Mode::Decrypt, &k2[..16], Some(iv)).ok()?;
        c.pad(false);
        let mut out = vec![0u8; data.len() + 16];
        let mut n = c.update(data, &mut out).ok()?;
        n += c.finalize(&mut out[n..]).ok()?;
        out.truncate(n);
        let pad = *out.last()? as usize;
        if pad + 1 > out.len() {
            return None;
        }
        out.truncate(out.len() - pad - 1);
        Some(out)
    }

    pub fn suite(&self) -> Suite {
        self.suite
    }
}

impl Drop for Session {
    /// Close the session: BMCs keep only a handful, and an abandoned one holds
    /// its slot until the idle timeout.
    fn drop(&mut self) {
        if self.bmc_sid != 0 {
            let sid = self.bmc_sid.to_le_bytes();
            let _ = self.call_no_reply(NETFN_APP, 0x3C, &sid);
        }
    }
}

// ---------- commands ----------

/// Chassis Control. `cmd` is the GUI/`ipmitool` vocabulary:
/// on | off | reset | soft | cycle.
pub fn power(host: &str, user: &str, pass: &str, cmd: &str) -> std::io::Result<String> {
    let action = match cmd {
        "off" => 0x00,
        "on" => 0x01,
        "cycle" => 0x02,
        "reset" => 0x03,
        "soft" => 0x05,
        other => return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput,
            format!("unknown power command {other}"))),
    };
    let mut s = Session::open(host, user, pass)?;
    s.call(NETFN_CHASSIS, 0x02, &[action])?;
    Ok(format!("Chassis Power Control: {}", match action {
        0 => "Down/Off", 1 => "Up/On", 2 => "Cycle", 3 => "Reset", _ => "Soft",
    }))
}

/// Cold-reset the BMC. It usually restarts before it can answer, so silence
/// counts as sent.
pub fn mc_reset_cold(host: &str, user: &str, pass: &str) -> std::io::Result<String> {
    let mut s = Session::open(host, user, pass)?;
    s.call_no_reply(NETFN_APP, 0x02, &[])?;
    // The session died with the BMC; do not wait on a Close Session reply.
    s.bmc_sid = 0;
    Ok("Sent cold reset command to MC".into())
}

/// Read the SEL clock, seconds since the epoch in the BMC's own time base.
pub fn sel_time(host: &str, user: &str, pass: &str) -> std::io::Result<u32> {
    let mut s = Session::open(host, user, pass)?;
    let r = s.call(NETFN_STORAGE, 0x48, &[])?;
    if r.len() < 4 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "short SEL time"));
    }
    Ok(u32::from_le_bytes([r[0], r[1], r[2], r[3]]))
}

/// Set the SEL clock. A raw timestamp, so none of `ipmitool`'s locale-dependent
/// date parsing is involved.
pub fn set_sel_time(host: &str, user: &str, pass: &str, epoch: u32) -> std::io::Result<()> {
    let mut s = Session::open(host, user, pass)?;
    s.call(NETFN_STORAGE, 0x49, &epoch.to_le_bytes())?;
    Ok(())
}

/// Whether the host is powered on, from Get Chassis Status.
pub fn chassis_power_on(host: &str, user: &str, pass: &str) -> std::io::Result<bool> {
    let mut s = Session::open(host, user, pass)?;
    let r = s.call(NETFN_CHASSIS, 0x01, &[])?;
    power_is_on(&r).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "short Get Chassis Status")
    })
}

/// Bit 0 of Get Chassis Status's current power state is "power is on"; the
/// bits above it are faults and the restore policy.
fn power_is_on(status: &[u8]) -> Option<bool> {
    status.first().map(|b| b & 1 != 0)
}

/// The manufacturer's IANA enterprise number, from Get Device ID — the one
/// brand signal every BMC answers, Redfish or not.
pub fn manufacturer_id(host: &str, user: &str, pass: &str) -> std::io::Result<u32> {
    let mut s = Session::open(host, user, pass)?;
    let r = s.call(NETFN_APP, 0x01, &[])?;
    if r.len() < 9 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "short Get Device ID"));
    }
    // Bytes 6..9, little-endian, 20 bits used.
    Ok(u32::from_le_bytes([r[6], r[7], r[8], 0]) & 0x0F_FFFF)
}

/// The system firmware (BIOS) version, from Get System Info Parameters'
/// parameter 1 (IPMI v2.0, 22.14a). iLO 4 answers it with the system ROM,
/// "P89 08/29/2024"; a BMC that does not implement it is an error.
pub fn system_firmware_version(host: &str, user: &str, pass: &str) -> std::io::Result<String> {
    let mut s = Session::open(host, user, pass)?;
    let mut blocks = vec![s.call(NETFN_APP, 0x59, &[0x00, 0x01, 0x00, 0x00])?];
    for set in 1..=more_info_blocks(&blocks[0]) as u8 {
        blocks.push(s.call(NETFN_APP, 0x59, &[0x00, 0x01, set, 0x00])?);
    }
    system_info_text(&blocks).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "no system firmware version")
    })
}

/// How many set selectors a System Info string takes after the first, which
/// carries its length and 14 bytes of it; each later one carries 16.
fn more_info_blocks(first: &[u8]) -> usize {
    first.get(3).map_or(0, |&len| (len as usize).saturating_sub(14).div_ceil(16))
}

/// The string a System Info parameter's set selectors spell. Each block
/// starts with the parameter revision and the set selector; the first one
/// then has the encoding and the string's length.
fn system_info_text(blocks: &[Vec<u8>]) -> Option<String> {
    let first = blocks.first()?;
    let (encoding, len) = (first.get(2)? & 0x0F, *first.get(3)? as usize);
    let mut text = first.get(4..)?.to_vec();
    for b in &blocks[1..] {
        text.extend_from_slice(b.get(2..)?);
    }
    text.truncate(len);
    // 0 is ASCII with Latin-1, 1 UTF-8; 2, UCS-2, is not worth a decoder here.
    let text: String = match encoding {
        0 => text.iter().map(|&c| c as char).collect(),
        1 => String::from_utf8_lossy(&text).into_owned(),
        _ => return None,
    };
    let text = text.trim_matches(|c: char| c == '\0' || c.is_whitespace());
    (!text.is_empty()).then(|| text.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chassis_status_reads_the_power_bit() {
        // Get Chassis Status (IPMI v2.0, 28.2), after the completion code:
        // current power state, last power event, misc chassis state.
        assert_eq!(power_is_on(&[0x01, 0x00, 0x00]), Some(true));
        // Power restore policy "always on" (bits 6:5) with the power off.
        assert_eq!(power_is_on(&[0x40, 0x10, 0x00]), Some(false));
        assert_eq!(power_is_on(&[0x61, 0x00, 0x00, 0x00]), Some(true));
        assert_eq!(power_is_on(&[]), None);
    }

    #[test]
    fn system_firmware_version_fits_the_first_block() {
        // Get System Info Parameters, parameter 1, set selector 0, after the
        // completion code: revision, set selector, encoding, length, text.
        let mut block = vec![0x11, 0x00, 0x00, 14];
        block.extend_from_slice(b"P89 08/29/2024");
        assert_eq!(more_info_blocks(&block), 0);
        assert_eq!(system_info_text(&[block]).as_deref(), Some("P89 08/29/2024"));
    }

    #[test]
    fn system_firmware_version_spans_set_selectors() {
        let version = b"1.2.3 built 2024-08-29 rev 4"; // 28 bytes: 14 + 14 of 16
        let mut first = vec![0x11, 0x00, 0x01, version.len() as u8];
        first.extend_from_slice(&version[..14]);
        assert_eq!(more_info_blocks(&first), 1);
        let mut second = vec![0x11, 0x01];
        second.extend_from_slice(&version[14..]);
        second.extend_from_slice(&[0, 0]);
        assert_eq!(
            system_info_text(&[first, second]).as_deref(),
            Some("1.2.3 built 2024-08-29 rev 4")
        );
    }

    #[test]
    fn system_firmware_version_blank_or_ucs2_is_none() {
        assert_eq!(system_info_text(&[vec![0x11, 0x00, 0x00, 0x00, 0, 0, 0]]), None);
        let mut ucs2 = vec![0x11, 0x00, 0x02, 4];
        ucs2.extend_from_slice(&[b'P', 0, b'8', 0]);
        assert_eq!(system_info_text(&[ucs2]), None);
        assert_eq!(system_info_text(&[]), None);
    }

    fn v15(len: u8) -> Vec<u8> {
        let mut p = RMCP.to_vec();
        p.extend_from_slice(&[0x00, 0, 0, 0, 0, 0, 0, 0, 0, len]);
        p.extend(std::iter::repeat(0xAB).take(len as usize));
        p
    }

    /// An RMCP+ packet laid out as IPMI v2.0 §13.6 has it: header, payload,
    /// then for an authenticated one the integrity pad (to a multiple of 4
    /// from the auth type through the next-header byte), pad length, next
    /// header and AuthCode.
    fn v20(len: u16, authed: bool, icv: usize) -> Vec<u8> {
        let mut p = RMCP.to_vec();
        p.push(0x06);
        p.push(PT_IPMI | if authed { AUTHENTICATED } else { 0 });
        p.extend_from_slice(&7u32.to_le_bytes());
        p.extend_from_slice(&1u32.to_le_bytes());
        p.extend_from_slice(&len.to_le_bytes());
        p.extend(std::iter::repeat(0xCD).take(len as usize));
        if authed {
            let pad = (4 - (p.len() - 4 + 2) % 4) % 4;
            p.extend(std::iter::repeat(0xFF).take(pad));
            p.push(pad as u8);
            p.push(0x07);
            p.extend(std::iter::repeat(0xEE).take(icv));
        }
        p
    }

    #[test]
    fn relayed_streams_split_back_into_packets() {
        for icv in [12, 16] {
            // Payload lengths 2, 3, 1 and 32 give integrity pads of 0, 3, 1 and 2.
            let packets = vec![
                v15(7),
                v20(20, false, icv),
                v20(2, true, icv),
                v20(3, true, icv),
                v20(32, true, icv),
                v20(33, true, icv),
                v20(1, true, icv),
            ];
            let stream = packets.concat();
            for chunk in [1, 3, 7, 64, stream.len()] {
                let (mut buf, mut out) = (Vec::new(), Vec::new());
                for piece in stream.chunks(chunk) {
                    buf.extend_from_slice(piece);
                    while let Some(Ok(n)) = frame_len(&buf, icv) {
                        if buf.len() < n {
                            break;
                        }
                        out.push(buf.drain(..n).collect::<Vec<u8>>());
                    }
                }
                assert_eq!(out, packets, "icv {icv}, chunks of {chunk}");
            }
        }
    }

    #[test]
    fn the_splitter_agrees_with_our_own_sealed_packets() {
        for suite in [Suite::Sha256, Suite::Sha1] {
            let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let mut s = Session {
                link: Link::open(&[], crate::net::Datagram::Udp(sock)),
                suite,
                bmc_sid: 0x1234,
                seq: 1,
                rq_seq: 1,
                k1: vec![1; 32],
                k2: vec![2; 32],
            };
            for len in [0usize, 1, 5, 17, 40] {
                let pkt = s.seal(&vec![0x5A; len]);
                assert_eq!(frame_len(&pkt, suite.icv_len()), Some(Ok(pkt.len())));
            }
        }
    }

    /// A header claiming a 64 KiB payload, as bytes after a desync can.
    fn false_header() -> Vec<u8> {
        let mut h = RMCP.to_vec();
        h.extend_from_slice(&[0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF]);
        h
    }

    #[test]
    fn a_relay_stream_is_read_back_packet_by_packet_past_garbage() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut w = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let relay = crate::net::Datagram::Stream(l.accept().unwrap().0, Default::default());
        let mut link = Link::open(&[], relay);
        let packets = [v15(3), v20(9, true, 16), v20(2, true, 16)];
        // A login shell's chatter first, then garbage between the packets.
        let stream = [
            b"Last login: never\n".to_vec(),
            packets[0].clone(),
            b"\x06junk".to_vec(),
            packets[1].clone(),
            false_header(),
            packets[2].clone(),
        ]
        .concat();
        // In pieces that cut every packet, then closed, as a relay exiting would.
        std::thread::spawn(move || {
            for piece in stream.chunks(5) {
                w.write_all(piece).unwrap();
                std::thread::sleep(Duration::from_millis(2));
            }
        });
        let until = Instant::now() + Duration::from_secs(5);
        for p in &packets {
            assert_eq!(&link.recv(until, 16).unwrap(), p);
        }
        match link.recv(until, 16) {
            Err(Error::Route(e)) => assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof, "{e}"),
            other => panic!("{:?}", other.map(|p| p.len())),
        }
    }

    #[test]
    fn garbage_is_reported_so_the_reader_can_resync() {
        assert_eq!(frame_len(b"HTTP/1.1 200 OK", 16), Some(Err(())));
        assert_eq!(frame_len(&RMCP[..3], 16), None);
        assert_eq!(frame_len(&[0x06, 0x01], 16), Some(Err(())), "the same bytes are checked however few");
        assert_eq!(frame_len(&false_header(), 16), Some(Err(())), "no IPMI packet is that long");
    }

    /// An SSH hop on the test server, whose relay exits without a UDP target.
    fn jump(name: &str) -> crate::routes::Route {
        use crate::net::ssh::testing::{start, HOST_FP, PASSWORD};
        let server = start(None);
        crate::routes::Route {
            name: name.into(),
            kind: crate::routes::Kind::Ssh,
            host: server.ip().to_string(),
            port: server.port(),
            user: "ops".into(),
            auth: crate::routes::Auth::Password,
            secret: PASSWORD.into(),
            host_key: HOST_FP.into(),
            ..Default::default()
        }
    }

    #[test]
    fn a_route_that_fails_is_not_opened_again_for_the_next_suite() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        struct Cancel(AtomicUsize);
        impl crate::net::Prompter for Cancel {
            fn trust_host_key(&self, _: &crate::routes::Route, _: &str) -> bool {
                false
            }
            fn secret(&self, _: &crate::routes::Route, _: &str) -> Option<(String, bool)> {
                self.0.fetch_add(1, SeqCst);
                None
            }
        }
        let mut hop = jump("ipmi-cancel");
        hop.secret.clear();
        crate::net::set_route("cancelled-bmc.test", Ok(vec![hop]));
        let asked = std::sync::Arc::new(Cancel(AtomicUsize::new(0)));
        let ctx = crate::net::Context { prompter: Some(asked.clone()), ..Default::default() };
        let r = crate::net::with_context(ctx, || Session::open("cancelled-bmc.test", "admin", "pw"));
        assert!(matches!(r, Err(Error::Route(_))), "{:?}", r.err());
        assert_eq!(asked.0.load(SeqCst), 1, "asked once, not once per cipher suite");
    }

    #[test]
    fn only_a_relay_missing_its_tools_marks_the_route() {
        use crate::net::Udp;
        let chain = vec![jump("ipmi-relay")];
        crate::net::set_route("relayed-bmc.test", Ok(chain.clone()));
        // The test server's relay exits with the port it is given as its status.
        let ended = |status| {
            let mut link = Link::open(&chain, crate::net::udp_via(&chain, "127.0.0.1", status).unwrap());
            match link.recv(Instant::now() + Duration::from_secs(5), 16) {
                Err(Error::Route(e)) => e.to_string(),
                other => panic!("{:?}", other.map(|p| p.len())),
            }
        };
        let e = ended(1);
        assert!(e.starts_with("via ipmi-relay") && e.contains("exited with status 1"), "{e}");
        assert_eq!(crate::net::udp_capability("relayed-bmc.test"), Udp::Unknown, "one BMC's failure is not the route's");
        let e = ended(127);
        assert!(e.starts_with("via ipmi-relay") && e.contains("neither socat nor nc"), "{e}");
        assert_eq!(crate::net::udp_capability("relayed-bmc.test"), Udp::Unavailable(e));
    }
}
