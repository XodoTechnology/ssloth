//! AMI SP-X virtual CD — the Java JViewer's path, not the H5Viewer's.
//!
//! Both vendor clients speak AMI IUSB (the protocol `quanta::vmedia` speaks on
//! :5120), but they carry it differently. The HTML5 viewer wraps it in a
//! WebSocket to `/cd-server`; the Java client — which was always the faster of
//! the two — opens a TLS connection to the web port and turns it into a raw
//! byte tunnel with two lines of text, then streams IUSB with no framing on
//! top. This is the Java path, ported from `JViewer.jar`
//! (`SinglePortKVM`, `CDROMRedir`, `imageredir.cd.CDImage`), which the BMC
//! serves under `/Java/release/` and which decompiles cleanly.
//!
//!   TLS to <host>:443
//!   client -> "CONNECT <host>:443 HTTPS/1.1\r\n cookie <QSESSIONID>\r\n\r\n"
//!   client -> "JVIEWER CDMEDIA cookie <QSESSIONID>\r\n\r\n"
//!   server -> a short text reply ("ERROR..." on refusal)
//!   client -> IUSB auth: 160 bytes, opcode 0xF2 at 41, the KVM token at 63
//!   server -> IUSB 0xF1 (DEVICE_REDIRECTION_ACK), connection status at 62
//!   server -> IUSB SCSI requests; client -> responses
//!
//! IUSB packet: a 32-byte header (`"IUSB    "`, version, length, checksum,
//! direction...) and a payload whose SCSI CDB starts at packet offset 41. A
//! response is the first 61 bytes of the request echoed back with status at
//! 53..57 and the data length at 57, then the data at 61. The checksum at 11
//! is the negated byte sum of the *whole packet*, not just the header — both
//! vendor clients compute it that way.
//!
//! Single port: every service is reached through 443 here, and the tunnel is
//! how. The dedicated media port (5120/5124) is not routed on the test network
//! anyway.

use crate::media_source::Source;
use crate::vmedia::{Mount, Stats};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const HEADER_LEN: usize = 32;
/// Request/response prefix: IUSB header + the SCSI packet fields up to data.
const RESP_PREFIX: usize = 61;
const SECTOR: u64 = 2048;

const OP_AUTH: u8 = 0xF2;
const OP_REDIRECTION_ACK: u8 = 0xF1;
const OP_KEEP_ALIVE: u8 = 0xF3;
const OP_KILL_REDIR: u8 = 0xF6;
const OP_SESSION_DISCONNECT: u8 = 0xF7;

// SCSI opcodes the Java CDImage answers. Everything else is refused with
// "invalid command", as it does; the BMC answers INQUIRY and the rest itself.
const TEST_UNIT_READY: u8 = 0x00;
const START_STOP_UNIT: u8 = 0x1B;
const READ_CAPACITY: u8 = 0x25;
const READ_10: u8 = 0x28;
const READ_TOC: u8 = 0x43;
const READ_12: u8 = 0xA8;

/// `connectionStatus` in the redirection ack.
fn ack_reason(status: u8) -> &'static str {
    match status {
        3 => "the BMC rejected the login",
        4 => "the virtual CD is already in use",
        5 => "this account lacks the virtual media privilege",
        8 => "the maximum number of media sessions is in use",
        13 => "virtual media is disabled on this BMC",
        _ => "the BMC refused the redirection",
    }
}

/// Where the IUSB stream runs: the Java client's raw tunnel through :443, or
/// the web viewer's WebSocket to `/cd-server` on firmware that has dropped the
/// tunnel (a Lenovo TSM answers the CONNECT line with `400 Bad Request`).
enum Link {
    Tunnel(native_tls::TlsStream<TcpStream>),
    /// WebSocket message boundaries are not packet boundaries, so the stream
    /// is reassembled in `buf`, as for the console.
    Ws { sock: crate::ws::WebSocket, buf: Vec<u8> },
}

impl Link {
    /// The next packet; Ok(None) when a WebSocket poll found nothing yet, so
    /// the caller can look at its stop flag.
    fn next(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        match self {
            Link::Tunnel(t) => read_packet(t).map(Some),
            Link::Ws { sock, buf } => loop {
                if buf.len() >= HEADER_LEN {
                    if &buf[0..8] != b"IUSB    " {
                        return Err(ioerr("bad IUSB signature"));
                    }
                    let len = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]) as usize;
                    if buf.len() >= HEADER_LEN + len {
                        let rest = buf.split_off(HEADER_LEN + len);
                        return Ok(Some(std::mem::replace(buf, rest)));
                    }
                }
                match sock.poll()? {
                    Some(m) => buf.extend_from_slice(&m),
                    None => return Ok(None),
                }
            },
        }
    }

    fn send(&mut self, p: &[u8]) -> std::io::Result<()> {
        match self {
            Link::Tunnel(t) => { t.write_all(p)?; t.flush() }
            Link::Ws { sock, .. } => sock.send_binary(p),
        }
    }

    fn close(&mut self) {
        match self {
            Link::Tunnel(t) => { let _ = t.shutdown(); }
            Link::Ws { sock, .. } => sock.close(),
        }
    }
}

/// Attach `path` (a file or a URL, see `media_source`) as the BMC's virtual CD
/// and serve it until the mount is dropped.
///
/// `cookie` is the web session (`QSESSIONID=...` or the bare value) and
/// `kvm_token` the per-launch token from `spx::kvm_launch` — both vendor
/// clients authenticate media with the same token as the console. No console
/// needs to be open: the vendor's standalone media app runs without one.
pub fn mount(host: &str, cookie: &str, kvm_token: &str, path: &str) -> std::io::Result<Mount> {
    let mut image = Source::open(path)?;
    let size = image.len()?;
    if size < SECTOR {
        return Err(ioerr("image is too small to be a CD-ROM"));
    }
    let bare = cookie.trim().strip_prefix("QSESSIONID=").unwrap_or(cookie.trim()).to_string();
    if bare.is_empty() {
        return Err(ioerr("no web session for virtual media"));
    }

    // The Java path first — no framing on top of IUSB, and the faster of the
    // two vendor clients. A refusal there is clean (an HTTP error, nothing
    // wedged), so the WebSocket is only tried when the tunnel does not exist.
    let (mut link, raw, auth_payload) = match tunnel(host, &bare) {
        Ok((tls, raw)) => (Link::Tunnel(tls), Some(raw), 128),
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
            if std::env::var("BMCKVM_DEBUG").is_ok() {
                eprintln!("[cdmedia] {e}; using the WebSocket");
            }
            let mut sock = crate::ws::connect_with(host, 443, "/cd-server",
                Some(&format!("QSESSIONID={bare}")), Some("binary"))?;
            sock.set_poll_timeout(Duration::from_millis(200)).ok();
            // The web viewer's auth packet is sized for its longer session
            // record: 62 + 32 + 98 bytes, plus the one it slices on.
            (Link::Ws { sock, buf: Vec::new() }, None, 62 + 98 + 1)
        }
        Err(e) => return Err(e),
    };

    let mut auth = vec![0u8; HEADER_LEN + auth_payload];
    write_header(&mut auth, 0);
    auth[41] = OP_AUTH;
    let t = kvm_token.as_bytes();
    let n = t.len().min(auth.len() - 63);
    auth[63..63 + n].copy_from_slice(&t[..n]);
    seal(&mut auth);
    link.send(&auth)?;

    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let ack = loop {
        if let Some(p) = link.next()? {
            break p;
        }
        if std::time::Instant::now() > deadline {
            link.close();
            return Err(ioerr("the BMC did not answer the media login"));
        }
    };
    if ack.get(41) != Some(&OP_REDIRECTION_ACK) {
        link.close();
        return Err(ioerr(format!("unexpected IUSB reply opcode {:#x}", ack.get(41).copied().unwrap_or(0))));
    }
    let status = ack.get(62).copied().unwrap_or(0);
    if status != 1 {
        let other = ack.get(63..).map(|b| {
            let e = b.iter().position(|c| *c == 0).unwrap_or(b.len());
            String::from_utf8_lossy(&b[..e]).trim().to_string()
        }).unwrap_or_default();
        let who = if status == 4 && !other.is_empty() { format!(" (by {other})") } else { String::new() };
        link.close();
        return Err(ioerr(format!("virtual media: {}{who}", ack_reason(status))));
    }

    let stop = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(Stats::default());

    // The tunnel's serve thread blocks in a read with no timeout — a short
    // SO_RCVTIMEO can expire inside a TLS record, which OpenSSL treats as
    // fatal — so stopping shuts its socket down from outside, which is also all
    // the Java client does (`VmediaSockclose`). The WebSocket polls instead.
    if let Some(raw) = raw {
        let s = stop.clone();
        std::thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(100));
            }
            let _ = raw.shutdown(std::net::Shutdown::Both);
        });
    }

    let (s, st) = (stop.clone(), stats.clone());
    let handle = std::thread::spawn(move || {
        let mut target = CdImage { image: &mut image, sectors: size / SECTOR, first: true };
        while !s.load(Ordering::SeqCst) {
            let req = match link.next() {
                Ok(Some(p)) => p,
                Ok(None) => continue,
                Err(_) => break,
            };
            let op = req.get(41).copied().unwrap_or(0);
            match op {
                OP_KEEP_ALIVE => {
                    let mut p = vec![0u8; HEADER_LEN + 30];
                    write_header(&mut p, 0);
                    p[41] = OP_KEEP_ALIVE;
                    seal(&mut p);
                    if link.send(&p).is_err() { break; }
                    continue;
                }
                OP_KILL_REDIR | OP_SESSION_DISCONNECT => break,
                _ => {}
            }
            st.commands.fetch_add(1, Ordering::Relaxed);
            let (resp, ejected) = target.execute(&req, &st);
            if link.send(&resp).is_err() { break; }
            if ejected { break; }
        }
        s.store(true, Ordering::SeqCst);
        link.close();
    });

    Ok(Mount::from_parts(stop, handle, path.to_string(), size, stats))
}

/// Open the TLS connection and turn it into a tunnel to the CD service.
/// Returns the TLS stream and the raw socket underneath (for shutdown). A BMC
/// without the tunnel answers with an HTTP error, reported as `Unsupported`.
fn tunnel(host: &str, cookie: &str)
    -> std::io::Result<(native_tls::TlsStream<TcpStream>, TcpStream)>
{
    let c = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .map_err(|e| ioerr(e.to_string()))?;
    let tcp = crate::net::connect(host, 443, Some(Duration::from_secs(12)))?;
    tcp.set_nodelay(true).ok();
    let raw = tcp.try_clone()?;
    // A timeout only for the text exchange; cleared before IUSB starts.
    tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut tls = c.connect(host, tcp).map_err(|e| ioerr(format!("TLS: {e}")))?;

    // Both lines exactly as `SinglePortKVM.doTunnelHandshake` writes them,
    // including the leading space before "cookie".
    tls.write_all(format!("CONNECT {host}:443 HTTPS/1.1\r\n cookie {cookie}\r\n\r\n").as_bytes())?;
    tls.write_all(format!("JVIEWER CDMEDIA cookie {cookie}\r\n\r\n").as_bytes())?;
    tls.flush()?;

    // The reply is free text, read by the vendor until the socket goes idle:
    // "HTTP/1.0 200 OK" where the tunnel exists, an HTTP error where the web
    // server has no idea what CONNECT means, "ERROR..." on a refusal.
    let mut reply = vec![0u8; 200];
    let n = tls.read(&mut reply)?;
    let text = String::from_utf8_lossy(&reply[..n]).into_owned();
    if std::env::var("BMCKVM_DEBUG").is_ok() {
        eprintln!("[cdmedia] tunnel reply {:?}", text);
    }
    if n == 0 {
        return Err(ioerr("the BMC closed the media tunnel"));
    }
    let status = text.strip_prefix("HTTP/").and_then(|r| r.split_whitespace().nth(1));
    if status.is_some_and(|c| c != "200") {
        return Err(std::io::Error::new(std::io::ErrorKind::Unsupported,
            format!("no Java media tunnel ({})", text.lines().next().unwrap_or("").trim())));
    }
    if text.contains("ERROR") {
        return Err(ioerr(format!("the BMC refused the media tunnel: {}", text.trim())));
    }
    raw.set_read_timeout(None)?;
    Ok((tls, raw))
}

/// Read one IUSB packet: the header, then its payload.
fn read_packet<R: Read>(s: &mut R) -> std::io::Result<Vec<u8>> {
    let mut p = vec![0u8; HEADER_LEN];
    s.read_exact(&mut p)?;
    if &p[0..8] != b"IUSB    " {
        return Err(ioerr("bad IUSB signature"));
    }
    let len = u32::from_le_bytes([p[12], p[13], p[14], p[15]]) as usize;
    if len > 16 * 1024 * 1024 {
        return Err(ioerr("implausible IUSB packet length"));
    }
    p.resize(HEADER_LEN + len, 0);
    s.read_exact(&mut p[HEADER_LEN..])?;
    Ok(p)
}

/// A fresh header, as `new IUSBHeader(n)` builds it: CD-ROM, protocol 1.
fn write_header(p: &mut [u8], instance: u8) {
    p[0..8].copy_from_slice(b"IUSB    ");
    p[8] = 1; // major
    p[9] = 0; // minor
    p[10] = HEADER_LEN as u8;
    p[17] = 5; // device type: CD-ROM
    p[18] = 1; // protocol
    p[23] = instance;
}

/// Finish a packet for sending: length, direction, checksum.
///
/// The checksum is the vendor's: every byte of the packet summed — the old
/// checksum byte included, since a response starts as a copy of the request —
/// and the negation written at 11.
fn seal(p: &mut [u8]) {
    let len = (p.len() - HEADER_LEN) as u32;
    p[12..16].copy_from_slice(&len.to_le_bytes());
    p[19] = 0x80; // direction: from the client
    let sum = p.iter().fold(0u8, |a, b| a.wrapping_add(*b));
    p[11] = sum.wrapping_neg();
}

/// The Java client's `CDImage`, which answers only what the BMC does not.
struct CdImage<'a> {
    image: &'a mut Source,
    sectors: u64,
    /// The first TEST UNIT READY or READ CAPACITY reports "medium changed",
    /// which the host needs before it trusts the capacity.
    first: bool,
}

/// `setErrorStatus` codes: overall status, sense key, ASC, ASCQ.
const OK: [u8; 4] = [0, 0, 0, 0];
const MEDIUM_CHANGED: [u8; 4] = [1, 6, 0x28, 0];
const OUT_OF_RANGE: [u8; 4] = [1, 5, 0x21, 0];
const READ_ERROR: [u8; 4] = [1, 3, 0x11, 0];
const INVALID_COMMAND: [u8; 4] = [1, 5, 0x20, 0];

impl CdImage<'_> {
    /// Build the response to one request. Returns it and whether the host
    /// ejected the disc.
    fn execute(&mut self, req: &[u8], stats: &Stats) -> (Vec<u8>, bool) {
        let cdb: Vec<u8> = req.get(41..).unwrap_or(&[]).iter().copied().chain(std::iter::repeat(0)).take(16).collect();
        let (status, data, ejected) = match cdb[0] {
            TEST_UNIT_READY | READ_CAPACITY if std::mem::take(&mut self.first) => {
                (MEDIUM_CHANGED, Vec::new(), false)
            }
            TEST_UNIT_READY => (OK, Vec::new(), false),
            READ_CAPACITY => {
                let mut d = Vec::with_capacity(8);
                d.extend_from_slice(&(self.sectors.saturating_sub(1) as u32).to_be_bytes());
                d.extend_from_slice(&(SECTOR as u32).to_be_bytes());
                (OK, d, false)
            }
            READ_10 | READ_12 => {
                stats.reads.fetch_add(1, Ordering::Relaxed);
                let lba = u32::from_be_bytes([cdb[2], cdb[3], cdb[4], cdb[5]]) as u64;
                // The Java client reads READ(12)'s length from READ(10)'s
                // offset, which is wrong for it; this reads the real field.
                let count = if cdb[0] == READ_12 {
                    u32::from_be_bytes([cdb[6], cdb[7], cdb[8], cdb[9]]) as u64
                } else {
                    u16::from_be_bytes([cdb[7], cdb[8]]) as u64
                };
                match self.read(lba, count) {
                    Ok(d) => {
                        stats.bytes.fetch_add(d.len() as u64, Ordering::Relaxed);
                        (OK, d, false)
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => (OUT_OF_RANGE, Vec::new(), false),
                    Err(_) => (READ_ERROR, Vec::new(), false),
                }
            }
            READ_TOC => (OK, self.read_toc(&cdb), false),
            // LoEj with start clear: the host ejected the disc.
            START_STOP_UNIT => (OK, Vec::new(), cdb[4] & 3 == 2),
            _ => (INVALID_COMMAND, Vec::new(), false),
        };

        let mut p: Vec<u8> = req.iter().copied().chain(std::iter::repeat(0)).take(RESP_PREFIX).collect();
        p[53..57].copy_from_slice(&status);
        p[57..61].copy_from_slice(&(data.len() as u32).to_le_bytes());
        p.extend_from_slice(&data);
        seal(&mut p);
        (p, ejected)
    }

    fn read(&mut self, lba: u64, count: u64) -> std::io::Result<Vec<u8>> {
        if lba.saturating_add(count) > self.sectors {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "past the end"));
        }
        let mut d = vec![0u8; (count * SECTOR) as usize];
        self.image.seek(SeekFrom::Start(lba * SECTOR))?;
        self.image.read_exact(&mut d)?;
        Ok(d)
    }

    /// `CDImage.readTOC`, quirks and all: one data track and the lead-out, the
    /// track always at LBA 0 (the vendor's MSF test, `(lun & 2) == 1`, can never
    /// be true) and the lead-out always in MSF.
    fn read_toc(&self, cdb: &[u8]) -> Vec<u8> {
        let track = cdb[6];
        let alloc = u16::from_be_bytes([cdb[7], cdb[8]]) as usize;
        if track > 1 && track != 0xAA {
            return Vec::new();
        }
        let mut d = vec![0u8; 20];
        d[2] = 1;
        d[3] = 1;
        let mut n = 4;
        if track <= 1 {
            d[n..n + 8].copy_from_slice(&[0, 0x14, 1, 0, 0, 0, 0, 0]);
            n += 8;
        }
        let f = self.sectors + 150;
        d[n..n + 8].copy_from_slice(&[
            0, 0x16, 0xAA, 0, 0, (f / 75 / 60) as u8, (f / 75 % 60) as u8, (f % 75) as u8,
        ]);
        n += 8;
        let n = n.min(alloc);
        d[0] = ((n.saturating_sub(2)) >> 8) as u8;
        d[1] = n.saturating_sub(2) as u8;
        d.truncate(n);
        d
    }
}

fn ioerr<S: AsRef<str>>(m: S) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, m.as_ref().to_string())
}
