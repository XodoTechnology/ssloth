//! iDRAC 9 direct (push) virtual media — the client serves the image.
//!
//! iDRAC's Redfish `InsertMedia` hands the BMC a URL and the BMC fetches it,
//! which needs an inbound route back to the client. This is the path the vendor
//! console uses instead: a WebSocket to `wss://<host>:<port>/vnc/vmedia?vmk=…`
//! that *we* open, over which the BMC asks for blocks and we answer. Being
//! outbound it works through NAT, VPNs and one-way routes, so it is the default.
//!
//! Ported from the console bundle's `VMedia` class
//! (`/restgui/vconsole/main-es5.*.js`, saved in `~/.config/smc-ikvm/idrac9-ref/`).
//!
//! Unlike the ATEN, AMI and iLO channels this is **not** SCSI: it is a block
//! protocol of little-endian `u32` words. Every message starts with the same
//! four-word header — `msgType, imageType, msgLen, vmToken` — and `msgLen` is
//! the literal 28 the reference sends, not a computed length.

use crate::vmedia::{Mount, Stats};
use crate::ws::{self, WebSocket};
use std::io::{Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Server -> client.
const MSG_READ_REQUEST: u32 = 1;
const MSG_UNMAP: u32 = 8;
const MSG_CONNECTED: u32 = 16;
const MSG_STATUS: u32 = 256;
const MSG_KEY2_REQUEST: u32 = 8192;

/// Client -> server.
const MSG_INQUIRY: u32 = 32;
const MSG_HEARTBEAT: u32 = 2048;

/// Device class. 1 CD/DVD, 2 removable disk, 3 USB.
const IMAGE_CD: u32 = 1;

const CD_BLOCK: u64 = 2048;
/// The reference sends this literal in every header rather than a real length.
const MSG_LEN: u32 = 28;
/// Blocks handed over unprompted with the inquiry, priming the BMC's reader.
const PRIME_BLOCKS: u64 = 32;
/// Cap on a single read so a hostile or confused request cannot exhaust memory.
const MAX_BLOCKS: u64 = 4096;

const HEARTBEAT: Duration = Duration::from_secs(10);

/// Attach `iso_path` as a virtual CD and serve it until the mount is dropped.
///
/// `vmk` is the console ticket (`Launch::vcsid`) and `key2` its companion
/// (`Launch::vcsid2`); the BMC may replace the latter mid-session.
pub fn mount(
    host: &str,
    port: u16,
    cookie: &str,
    vmk: &str,
    key2: &str,
    iso_path: &str,
) -> std::io::Result<Mount> {
    let mut file = crate::media_source::Source::open(iso_path)?;
    let size = file.len()?;
    if size < CD_BLOCK {
        return Err(ioerr("image is too small to be a CD-ROM"));
    }
    // The protocol addresses whole blocks; a trailing partial block is not
    // representable, and real ISO images are always a multiple of 2048.
    let total_blocks = size / CD_BLOCK;

    let path = format!("/vnc/vmedia?vmk={vmk}");
    let cookie = format!("-http-session-={cookie}");
    let mut sock = ws::connect_with(host, port, &path, Some(&cookie), Some("binary"))?;
    // Long timeout for the handshake: a short SO_RCVTIMEO makes reads expire
    // inside a TLS record, which OpenSSL treats as fatal rather than "retry".
    sock.set_poll_timeout(Duration::from_secs(5))?;

    if std::env::var("BMCKVM_DEBUG").is_ok() {
        eprintln!("[idrac-vm] vmk={vmk} key2={key2}");
    }
    let mut s = Session {
        sock, vm_token: 0, key2: key2.to_string(), connected: false, status: None,
    };
    s.wait_connected(Duration::from_secs(20))?;
    dbg_stage("connected");

    // Announce the medium, then push the opening blocks without being asked —
    // the reference primes the BMC's reader this way and it expects it.
    s.send_words(&[
        MSG_INQUIRY,
        IMAGE_CD,
        MSG_LEN,
        s.vm_token,
        total_blocks as u32,
        CD_BLOCK as u32,
        0, // cylinders
        0, // heads
        0, // sectors
        1, // flags: read-only
        20, // TOC length the BMC synthesises; the reference sends no TOC bytes
    ])?;
    dbg_stage("inquiry sent");
    let prime = total_blocks.min(PRIME_BLOCKS);
    let stats = Arc::new(Stats::default());
    s.send_blocks(&mut file, 0, prime, &stats)?;

    // Give the BMC a moment to accept the medium and say so. A session that
    // connects but never maps the device serves reads to the BMC's own probe
    // and looks fine from here, while the host sees no drive at all.
    let deadline = Instant::now() + Duration::from_secs(5);
    while s.status.is_none() && Instant::now() < deadline {
        match s.sock.poll() {
            Ok(Some(msg)) => {
                // A read request this early is fine: the BMC is probing the
                // medium, which means it accepted it.
                if !s.control(&msg)? {
                    break;
                }
            }
            Ok(None) => {}
            Err(e) => return Err(e),
        }
    }
    // 0 success, 38 mapped, 70 partition mounted: all mean the medium was taken.
    match s.status {
        Some(0) | Some(38) | Some(70) | None => {}
        Some(code) => {
            return Err(ioerr(&format!(
                "iDRAC refused the medium: {} (status {code})",
                status_name(code)
            )))
        }
    }

    dbg_stage("primed");
    sock_short_timeout(&mut s)?;
    let stop = Arc::new(AtomicBool::new(false));
    let (st, sp) = (stats.clone(), stop.clone());
    let handle = std::thread::spawn(move || {
        serve(&mut s, &mut file, total_blocks, &sp, &st);
    });
    Ok(Mount::from_parts(stop, handle, iso_path.to_string(), size, stats))
}

fn dbg_stage(m: &str) {
    if std::env::var("BMCKVM_DEBUG").is_ok() {
        eprintln!("[idrac-vm] stage: {m}");
    }
}

fn sock_short_timeout(s: &mut Session) -> std::io::Result<()> {
    // Streaming wants a short poll so the stop flag and heartbeat stay responsive.
    s.sock.set_poll_timeout(Duration::from_millis(200))
}

struct Session {
    sock: WebSocket,
    vm_token: u32,
    key2: String,
    connected: bool,
    /// Last status the BMC reported, if any.
    status: Option<u32>,
}

/// Status codes from the vendor client's `VMEDIA_STATUS` table. Only the ones
/// worth telling a user about are named.
fn status_name(code: u32) -> &'static str {
    match code {
        0 => "success",
        1 => "failed",
        3 => "driver open failed",
        4 => "unsupported image type",
        7 => "set LUN types failed",
        8 => "set inquiry data failed",
        11 => "read data write failed",
        12 => "data read error",
        14 => "unsupported message type",
        15 => "LUN not found",
        16 => "invalid header message",
        19 => "read data header mismatch",
        20 => "inquiry data read failed",
        23 => "virtual media is disabled",
        25 => "eject request succeeded",
        31 => "mass storage open failed",
        38 => "media mapped",
        39 => "licence error",
        40 => "virtual media mode is Detached",
        41 => "max sessions is zero",
        42 => "no free virtual-media session",
        // The vendor client treats this one as success: its handler sets
        // isMappedCD on exactly this code, not on 38.
        70 => "partition mounted",
        84 => "licence disabled",
        89 => "login denied",
        _ => "unknown",
    }
}

impl Session {
    /// Read messages until the BMC says the device is attached.
    fn wait_connected(&mut self, timeout: Duration) -> std::io::Result<()> {
        let deadline = Instant::now() + timeout;
        while !self.connected {
            if Instant::now() >= deadline {
                return Err(ioerr(
                    "iDRAC virtual media: the BMC never acknowledged the connection",
                ));
            }
            let Some(msg) = self.sock.poll()? else { continue };
            if std::env::var("BMCKVM_DEBUG").is_ok() {
                eprintln!("[idrac-vm] recv {}B {:?}", msg.len(), &words(&msg)[..words(&msg).len().min(6)]);
            }
            self.control(&msg)?;
        }
        Ok(())
    }

    /// Handle a non-read message. Returns true if it was consumed.
    fn control(&mut self, msg: &[u8]) -> std::io::Result<bool> {
        let w = words(msg);
        let Some(&ty) = w.first() else { return Ok(true) };
        match ty {
            MSG_CONNECTED => {
                self.vm_token = w.get(3).copied().unwrap_or(0);
                // Words 4.. carry a fresh 24-character key as packed characters.
                if w.len() > 4 {
                    let k = unpack_key(&w[4..]);
                    if !k.is_empty() {
                        self.key2 = k;
                    }
                }
                self.connected = true;
                Ok(true)
            }
            MSG_KEY2_REQUEST => {
                // The reference answers only the bare form of this request.
                if w.get(1) == Some(&0) && w.get(2) == Some(&0) {
                    let k = pack_key(&self.key2);
                    let mut m = vec![MSG_KEY2_REQUEST, 0, 32, self.vm_token];
                    m.extend_from_slice(&k);
                    m.extend_from_slice(&[0, 0]);
                    self.send_words(&m)?;
                }
                Ok(true)
            }
            MSG_STATUS => {
                // The BMC reports what it made of our inquiry here. Anything
                // other than success means the device was not presented to the
                // host, which otherwise looks exactly like a working mount.
                let code = w.get(4).copied().unwrap_or(0);
                self.status = Some(code);
                if std::env::var("BMCKVM_DEBUG").is_ok() {
                    eprintln!("[idrac-vm] status {code} ({})", status_name(code));
                }
                Ok(true)
            }
            MSG_UNMAP => Ok(true),
            MSG_READ_REQUEST => Ok(false),
            _ => Ok(true),
        }
    }

    fn send_words(&mut self, w: &[u32]) -> std::io::Result<()> {
        let mut b = Vec::with_capacity(w.len() * 4);
        for v in w {
            b.extend_from_slice(&v.to_le_bytes());
        }
        self.sock.send_binary(&b)
    }

    /// Answer a read: the data header, then the raw blocks in one message.
    fn send_blocks(
        &mut self,
        file: &mut crate::media_source::Source,
        start: u64,
        count: u64,
        stats: &Arc<Stats>,
    ) -> std::io::Result<()> {
        let len = (count * CD_BLOCK) as u32;
        self.send_words(&[
            MSG_READ_REQUEST,
            IMAGE_CD,
            MSG_LEN,
            self.vm_token,
            start as u32,
            count as u32,
            (start + count) as u32,
            CD_BLOCK as u32,
            len,
        ])?;
        file.seek(SeekFrom::Start(start * CD_BLOCK))?;
        let mut buf = vec![0u8; len as usize];
        // A short read means a truncated image; pad so the BMC still gets the
        // byte count its header promised rather than desynchronising.
        let mut filled = 0usize;
        while filled < buf.len() {
            match file.read(&mut buf[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) => return Err(e),
            }
        }
        self.sock.send_binary(&buf)?;
        stats.commands.fetch_add(1, Ordering::Relaxed);
        stats.reads.fetch_add(1, Ordering::Relaxed);
        stats.bytes.fetch_add(filled as u64, Ordering::Relaxed);
        Ok(())
    }
}

fn serve(
    s: &mut Session,
    file: &mut crate::media_source::Source,
    total_blocks: u64,
    stop: &Arc<AtomicBool>,
    stats: &Arc<Stats>,
) {
    let mut last_beat = Instant::now();
    loop {
        if stop.load(Ordering::SeqCst) {
            // Detach cleanly: unmap the device, then close the channel so iDRAC
            // frees the session. It only has one.
            let t = s.vm_token;
            let _ = s.send_words(&[MSG_UNMAP, IMAGE_CD, 0, t]);
            std::thread::sleep(Duration::from_millis(150));
            s.sock.close();
            return;
        }
        match s.sock.poll() {
            Ok(Some(msg)) => {
                let consumed = match s.control(&msg) {
                    Ok(c) => c,
                    Err(_) => return,
                };
                if consumed {
                    continue;
                }
                let w = words(&msg);
                // Read request: msgType, imageType, msgLen, vmToken, startBlock,
                // reqNumBlocks, blockSize.
                let (Some(&start), Some(&count)) = (w.get(4), w.get(5)) else { continue };
                let (start, mut count) = (start as u64, count as u64);
                if start >= total_blocks || count == 0 {
                    continue;
                }
                count = count.min(total_blocks - start).min(MAX_BLOCKS);
                if s.send_blocks(file, start, count, stats).is_err() {
                    return;
                }
            }
            Ok(None) => {
                if last_beat.elapsed() >= HEARTBEAT {
                    let t = s.vm_token;
                    if s.send_words(&[MSG_HEARTBEAT, 0, 0, t]).is_err() {
                        return;
                    }
                    last_beat = Instant::now();
                }
            }
            Err(_) => return,
        }
    }
}

/// Reinterpret a message as little-endian `u32` words.
fn words(msg: &[u8]) -> Vec<u32> {
    msg.chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

/// Pack a 24-character key into six words, four characters each, low byte first.
fn pack_key(key: &str) -> [u32; 6] {
    let b = key.as_bytes();
    let mut out = [0u32; 6];
    for (i, w) in out.iter_mut().enumerate() {
        let mut v = 0u32;
        for j in 0..4 {
            v |= (*b.get(i * 4 + j).unwrap_or(&0) as u32) << (j * 8);
        }
        *w = v;
    }
    out
}

/// The inverse, for the key the BMC hands back.
fn unpack_key(w: &[u32]) -> String {
    let mut s = String::new();
    for v in w.iter().take(6) {
        for j in 0..4 {
            let c = ((v >> (j * 8)) & 0xFF) as u8;
            if c == 0 {
                return s;
            }
            s.push(c as char);
        }
    }
    s
}

fn ioerr(m: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, m.to_string())
}
