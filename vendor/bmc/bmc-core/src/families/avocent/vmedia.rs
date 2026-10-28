//! Avocent virtual media (AVMP) — a CD image served to the BMC over TCP 2068.
//!
//! Ported from the BMC's own `avctVM.jar`, which unlike the console jar keeps
//! its class names (`ApplianceSession`, `PacketAVMP`, `VDiskInfo`), so this is a
//! close transcription rather than a reconstruction.
//!
//! Same port and the same APCP negotiation as the console, but a third channel
//! type (2, against the console's 3 and 4) and a different protocol inside.
//! This firmware answers channel 2 with capability 1 — cleartext — where it
//! insists on TLS for the console's channels, so the media login and the image
//! bytes go over the wire in the clear. The hello offers both; that is the
//! BMC's choice, and the vendor client accepts the same answer.
//!
//! After APCP:
//!
//! ```text
//!   ->  "AVMP" u32=153 u16=0x0100 u16=0  login
//!       u8 len + 96 bytes username, 32 bytes password, 8 zero bytes,
//!       u8 0, u8 0, u8 0, u8 preempt
//!   <-  "AVMP" u32 len u16=0x8100 u16  u8 status (0 = in)  ...
//! ```
//!
//! then a request/response protocol whose frames are
//! `"AVMP" u32 total-length u16 message-type`, big-endian, header 10 bytes:
//!
//! ```text
//!   ->  0x0200 GET_VDISK_INFO   (disk id 0xFFFF = "all")
//!   <-  0x8200 VDISK_INFO       u16 count, then 4 bytes per slot
//!                               (type, status, u16 capabilities)
//!   ->  0x0210 VDISK_REQUEST    map a CD into a slot: block size, block count,
//!                               read-only flag, name
//!   <-  0x8410 DEVICE_STATUS    the slot is attached to the host
//!   <-  0x8300 VDISK_READ       start block, block count, blocking factor
//!   ->  0x0300 VDISK_READ_DATA  start block, block count, the bytes
//!   ->  0x0410 CLIENT_STATUS    0 for served, 2 for a read error
//!   ->  0x0400 HEARTBEAT        every 10 seconds
//!   ->  0x0220 VDISK_RELEASE    on unmount
//! ```
//!
//! This is a pull protocol in shape — the BMC asks for blocks — but the
//! connection is ours, outbound, which is what the "virtual media is mounted
//! directly" rule in CLAUDE.md requires: nothing here depends on the BMC being
//! able to reach back to us.
//!
//! Writes are refused. The BMC can ask (`0x8310 VDISK_WRITE`) because the media
//! was offered as a CD, and a CD is read-only; the reference maps that to a
//! client-status error and so does this. See docs/GIGABYTE-AVOCENT.md.

use super::Stream;
use crate::vmedia::{Mount, Stats};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A CD sector. The BMC is told this as the block size and asks in these units.
const BLOCK: u64 = 2048;

/// APCP channel type for virtual media.
const CH_VMEDIA: u8 = 2;

/// AVMP message types, named as the vendor client names them.
#[allow(dead_code)]
mod msg {
    // client -> BMC
    pub const PREEMPT_RESPONSE: u16 = 0x0120;
    pub const GET_VDISK_INFO: u16 = 0x0200;
    pub const VDISK_REQUEST: u16 = 0x0210;
    pub const VDISK_REQUEST2: u16 = 0x0211;
    pub const VDISK_RELEASE: u16 = 0x0220;
    pub const VDISK_SET_ENABLE: u16 = 0x0230;
    pub const VDISK_READ_DATA: u16 = 0x0300;
    pub const HEARTBEAT: u16 = 0x0400;
    pub const CLIENT_STATUS: u16 = 0x0410;
    pub const USB_RESET: u16 = 0x0420;

    // BMC -> client
    pub const DISCONNECT: u16 = 0x8110;
    pub const DISCONNECT_CANCEL: u16 = 0x8120;
    pub const VDISK_INFO: u16 = 0x8200;
    pub const VDISK_REQUEST_RELEASE: u16 = 0x8240;
    pub const VDISK_READ: u16 = 0x8300;
    pub const VDISK_WRITE: u16 = 0x8310;
    pub const DEVICE_STATUS: u16 = 0x8410;
    pub const DEVICE_CONFIGURATION_OPTION: u16 = 0x8430;
}

/// `DriveInfo` type bits from the vendor client.
const DRIVE_CD: u8 = 2;

/// iDRAC 8's table of contents for every CD image, from its viewer's
/// `getTableOfContents`.
const IDRAC8_TOC: [u8; 20] = [
    0x00, 0x12, 0x01, 0x01, 0x00, 0x14, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x14, 0xAA, 0x00, 0x00, 0x11, 0x76, 0xE0,
];

/// `DEVICE_STATUS` codes, from the iDRAC 8 viewer's `vDiskDevice_STATUS`.
fn device_reason(code: u32) -> &'static str {
    match code {
        1 => "unsupported",
        2 => "read failed",
        3 => "write failed",
        4 => "not connected",
        5 => "a device is already attached",
        6 => "virtual media is disabled",
        7 => "unknown option",
        8 => "request failed",
        _ => "unknown error",
    }
}

/// `CLIENT_STATUS` values: the read was served, or it failed.
const CLIENT_OK: u32 = 0;
const CLIENT_ERROR: u32 = 2;

/// The reference's heartbeat period.
const HEARTBEAT_EVERY: Duration = Duration::from_secs(10);

fn ioerr<S: AsRef<str>>(m: S) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, m.as_ref().to_string())
}

fn would_block(e: &std::io::Error) -> bool {
    matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
}

/// One AVMP message: the 10-byte header plus its payload, as one buffer, so the
/// field offsets below match the reference's byte indices exactly.
struct Frame(Vec<u8>);

impl Frame {
    fn ty(&self) -> u16 {
        u16::from_be_bytes([self.0[8], self.0[9]])
    }
    fn u16at(&self, o: usize) -> u16 {
        if self.0.len() < o + 2 { return 0 }
        u16::from_be_bytes([self.0[o], self.0[o + 1]])
    }
    fn u32at(&self, o: usize) -> u32 {
        if self.0.len() < o + 4 { return 0 }
        u32::from_be_bytes([self.0[o], self.0[o + 1], self.0[o + 2], self.0[o + 3]])
    }
    fn disk_id(&self) -> u16 { self.u16at(10) }
    fn start_block(&self) -> u32 { self.u32at(12) }
    fn block_count(&self) -> u32 { self.u32at(16) }
    fn blocking_factor(&self) -> u32 { self.u32at(20) }
}

/// Build an AVMP message: magic, total length, type, then `payload` from
/// offset 10.
fn avmp(ty: u16, payload: &[u8]) -> Vec<u8> {
    let total = (10 + payload.len()) as u32;
    let mut v = Vec::with_capacity(total as usize);
    v.extend_from_slice(b"AVMP");
    v.extend_from_slice(&total.to_be_bytes());
    v.extend_from_slice(&ty.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// The AVMP channel: the negotiated stream plus a reassembly buffer, for the
/// same reason the console has one — reads use a short timeout so the serve
/// loop can also send heartbeats and notice the stop flag.
struct Chan {
    s: Stream,
    buf: Vec<u8>,
    pos: usize,
}

impl Chan {
    fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.s.write_all(data)?;
        self.s.flush()
    }

    fn poll(&mut self) -> std::io::Result<Option<Frame>> {
        loop {
            if let Some(f) = self.take()? {
                return Ok(Some(f));
            }
            let mut tmp = [0u8; 32768];
            match self.s.read(&mut tmp) {
                Ok(0) => return Err(ioerr("the BMC closed the media channel")),
                Ok(n) => self.buf.extend_from_slice(&tmp[..n]),
                Err(ref e) if would_block(e) => return Ok(None),
                Err(e) => return Err(e),
            }
        }
    }

    fn recv(&mut self, timeout: Duration) -> std::io::Result<Frame> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(f) = self.poll()? {
                return Ok(f);
            }
            if Instant::now() >= deadline {
                return Err(ioerr("the BMC did not answer the media channel in time"));
            }
        }
    }

    fn take(&mut self) -> std::io::Result<Option<Frame>> {
        if self.buf.len() - self.pos < 10 {
            self.compact();
            return Ok(None);
        }
        let h = &self.buf[self.pos..self.pos + 10];
        if &h[..4] != b"AVMP" {
            return Err(ioerr("AVMP stream desynchronised"));
        }
        let total = u32::from_be_bytes([h[4], h[5], h[6], h[7]]) as usize;
        if !(10..=1 << 22).contains(&total) {
            return Err(ioerr(format!("AVMP frame claims {total} bytes")));
        }
        if self.buf.len() - self.pos < total {
            self.compact();
            return Ok(None);
        }
        let f = Frame(self.buf[self.pos..self.pos + total].to_vec());
        self.pos += total;
        Ok(Some(f))
    }

    fn compact(&mut self) {
        if self.pos > 1 << 20 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }
}

/// Open the media channel and log in.
///
/// The channel comes back in the clear on this firmware — APCP offers
/// capability 1 for channel type 2, where it insists on TLS for the console's
/// 3 and 4 — so the login credentials and the image bytes cross the wire
/// unencrypted. That is the BMC's choice, not ours: the hello offers to do
/// either, and the vendor client takes the same answer.
fn connect(host: &str, port: u16, user: &str, pass: &str) -> std::io::Result<Chan> {
    // 0.0, not the console's 2.34: the media client announces a different
    // protocol version and the BMC answers channel type 2 on that basis.
    let s = super::apcp_channel(host, port, CH_VMEDIA, (0, 0))?;
    let mut c = Chan { s, buf: Vec::new(), pos: 0 };

    // Login. Fixed 153 bytes; the trailing four are three reserved zeros and a
    // preempt flag, which we leave clear so an existing session is never stolen.
    let ub = user.as_bytes();
    let pb = pass.as_bytes();
    if ub.len() > 96 || pb.len() > 32 {
        return Err(ioerr("media credentials are longer than the protocol allows"));
    }
    let mut login = Vec::with_capacity(153);
    login.extend_from_slice(b"AVMP");
    login.extend_from_slice(&153u32.to_be_bytes());
    login.extend_from_slice(&0x0100u16.to_be_bytes());
    login.extend_from_slice(&0u16.to_be_bytes());
    login.push(ub.len() as u8);
    login.extend_from_slice(ub);
    login.resize(login.len() + 96 - ub.len(), 0);
    login.extend_from_slice(pb);
    login.resize(login.len() + 32 - pb.len(), 0);
    login.extend_from_slice(&[0u8; 8]);
    login.extend_from_slice(&[0, 0, 0, 0]);
    debug_assert_eq!(login.len(), 153);
    c.send(&login)?;

    // The login reply reuses the APCP reply shape rather than the AVMP one:
    // magic, length, 0x8100, a short, then the status byte.
    let mut r = [0u8; 13];
    c.s.read_exact(&mut r)?;
    if &r[..4] != b"AVMP" || u16::from_be_bytes([r[8], r[9]]) != 0x8100 {
        return Err(ioerr("unexpected reply to the media login"));
    }
    if r[12] != 0 {
        return Err(ioerr(format!(
            "the BMC refused the media login (status {}) — the web session that \
minted these credentials must still be open", r[12])));
    }
    // Drain the rest of the login reply (flags, then a 96-byte padded username)
    // so the frame parser starts on a header.
    let total = u32::from_be_bytes([r[4], r[5], r[6], r[7]]) as usize;
    if total > 13 {
        let mut rest = vec![0u8; total - 13];
        c.s.read_exact(&mut rest)?;
    }
    Ok(c)
}

/// Attach `iso_path` to the BMC as a CD and serve its blocks until unmounted.
///
/// `launch` must come from `avocent::vm_launch` on a web session that stays
/// logged in for the life of the mount, the same rule the console follows.
pub fn mount(host: &str, launch: &super::Launch, iso_path: &str)
    -> std::io::Result<Mount>
{
    let mut file = crate::media_source::Source::open(iso_path)?;
    let size = file.len()?;
    if size == 0 {
        return Err(ioerr("the image is empty"));
    }
    // Round up: a trailing partial sector is padded with zeros rather than
    // truncated, or the last few kilobytes of the image become unreadable.
    let blocks = size.div_ceil(BLOCK);
    if blocks > u32::MAX as u64 {
        return Err(ioerr("the image is larger than the protocol's 2 TiB block count"));
    }

    let mut c = connect(host, launch.km_port, &launch.user, &launch.pass)?;

    // Ask what slots exist. 0xFFFF means "all of them".
    //
    // iDRAC 8 (AutoAttach) plugs its virtual CD into the host only once a
    // media session logs in, and its slots read "disabled" until the host has
    // enumerated it — about two seconds. The vendor client keeps the session
    // and watches the list; asking once and giving up looked like a cooldown
    // after every unmount. So re-ask until a CD slot appears, or time runs out.
    let deadline = Instant::now() + Duration::from_secs(20);
    let info = loop {
        c.send(&avmp(msg::GET_VDISK_INFO, &0xFFFFu16.to_be_bytes()))?;
        let f = loop {
            let f = c.recv(Duration::from_secs(15))?;
            if f.ty() == msg::VDISK_INFO {
                break f;
            }
        };
        let n = f.u16at(12) as usize;
        let ready = (0..n).any(|i| f.0.get(14 + 4 * i).copied().unwrap_or(0) & DRIVE_CD != 0);
        if ready || Instant::now() > deadline {
            break f;
        }
        std::thread::sleep(Duration::from_secs(1));
    };
    let count = info.u16at(12) as usize;
    let slot = (0..count)
        .find(|i| info.0.get(14 + 4 * i).copied().unwrap_or(0) & DRIVE_CD != 0)
        .ok_or_else(|| ioerr(format!(
            "this BMC offers no CD slot to map ({count} media slots, none of them optical: \
             type/status/capabilities {:02x?})",
            info.0.get(14..14 + 4 * count).unwrap_or(&[]))))?
        as u16;

    // Map it. Both generations send block size, block count and a flags byte;
    // they part company after that.
    let mut req = Vec::with_capacity(32);
    req.extend_from_slice(&slot.to_be_bytes());
    req.extend_from_slice(&(BLOCK as u32).to_be_bytes());
    req.extend_from_slice(&(blocks as u32).to_be_bytes());
    // Read-only. The reference hardcodes it for CDs, and so does this: the host
    // must not be able to write into somebody's installer image.
    req.push(1);
    if launch.platform == super::IDRAC8 {
        // iDRAC 8's client sends a write ceiling of zero and a canned 20-byte
        // table of contents — the same bytes whatever the image — where the
        // MergePoint client sends a block count and a name. Sent the MergePoint
        // way, the map is acknowledged and the host never sees a disc.
        req.push(0);
        req.extend_from_slice(&(IDRAC8_TOC.len() as u16).to_be_bytes());
        req.extend_from_slice(&IDRAC8_TOC);
    } else {
        // A legacy one-byte block count, saturating at 255. Meaningless for
        // any real image, but the BMC reads the field, so it is sent as the
        // reference sends it. The name is what the BMC shows in its media list.
        req.push(if blocks > 255 { 0xFF } else { blocks as u8 });
        let name = std::path::Path::new(iso_path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "image.iso".into());
        let nb = name.as_bytes();
        let nb = &nb[..nb.len().min(256)];
        req.extend_from_slice(&(nb.len() as u16).to_be_bytes());
        req.extend_from_slice(nb);
    }
    c.send(&avmp(msg::VDISK_REQUEST, &req))?;

    // DEVICE_STATUS says the slot is attached on the host side.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if Instant::now() > deadline {
            return Err(ioerr("the BMC never reported the CD as attached"));
        }
        let f = c.recv(Duration::from_secs(20))?;
        match f.ty() {
            msg::DEVICE_STATUS => match f.0.get(12..16).map(|b| u32::from_be_bytes(b.try_into().unwrap())) {
                Some(0) | None => break,
                Some(code) => return Err(ioerr(format!(
                    "the BMC refused to attach the CD: {} (status {code})", device_reason(code)))),
            },
            msg::DISCONNECT => return Err(ioerr("the BMC disconnected the media session")),
            _ => continue,
        }
    }

    let stop = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(Stats::default());
    let (tstop, tstats) = (stop.clone(), stats.clone());
    let image = iso_path.to_string();
    let handle = std::thread::spawn(move || {
        // Short timeout so the loop notices `stop` and the heartbeat clock.
        let _ = c.s.set_read_timeout(Some(Duration::from_millis(200)));
        let mut next_beat = Instant::now() + HEARTBEAT_EVERY;
        let mut buf = vec![0u8; 64 * 1024];
        while !tstop.load(Ordering::SeqCst) {
            if Instant::now() >= next_beat {
                if c.send(&avmp(msg::HEARTBEAT, &[])).is_err() {
                    break;
                }
                next_beat = Instant::now() + HEARTBEAT_EVERY;
            }
            let f = match c.poll() {
                Ok(Some(f)) => f,
                Ok(None) => continue,
                Err(_) => break,
            };
            match f.ty() {
                msg::VDISK_READ => {
                    tstats.commands.fetch_add(1, Ordering::Relaxed);
                    tstats.reads.fetch_add(1, Ordering::Relaxed);
                    let ok = serve_read(&mut c, &mut file, size, &f, &mut buf, &tstats).is_ok();
                    let mut st = f.disk_id().to_be_bytes().to_vec();
                    st.extend_from_slice(
                        &(if ok { CLIENT_OK } else { CLIENT_ERROR }).to_be_bytes());
                    if c.send(&avmp(msg::CLIENT_STATUS, &st)).is_err() {
                        break;
                    }
                }
                // The media is a CD and was offered read-only, so a write is a
                // host-side mistake, not ours: refuse it and keep serving.
                msg::VDISK_WRITE => {
                    tstats.commands.fetch_add(1, Ordering::Relaxed);
                    let mut st = f.disk_id().to_be_bytes().to_vec();
                    st.extend_from_slice(&CLIENT_ERROR.to_be_bytes());
                    if c.send(&avmp(msg::CLIENT_STATUS, &st)).is_err() {
                        break;
                    }
                }
                msg::DISCONNECT | msg::VDISK_REQUEST_RELEASE => break,
                _ => {}
            }
        }
        // Release the slot. Dropping the socket leaves the BMC showing a mapped
        // drive the host can no longer read from.
        let _ = c.send(&avmp(msg::VDISK_RELEASE, &slot.to_be_bytes()));
        // And wait for the BMC to say it is free before closing, as the
        // vendor client does: it asks for the slot list straight after the
        // release rather than dropping the socket on a request still in flight.
        let _ = c.send(&avmp(msg::GET_VDISK_INFO, &0xFFFFu16.to_be_bytes()));
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            match c.poll() {
                Ok(Some(f)) if f.ty() == msg::VDISK_INFO
                    && f.0.get(15 + 4 * slot as usize) != Some(&1) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }
        c.s.shutdown();
    });

    Ok(Mount::from_parts(stop, handle, image, size, stats))
}

/// Answer one `VDISK_READ`, in chunks of at most `blocking_factor` blocks —
/// the BMC's own limit on how much it will take in a single message.
fn serve_read(
    c: &mut Chan,
    file: &mut crate::media_source::Source,
    size: u64,
    req: &Frame,
    buf: &mut Vec<u8>,
    stats: &Stats,
) -> std::io::Result<()> {
    let disk = req.disk_id();
    let start = req.start_block() as u64;
    let want = req.block_count() as u64;
    // A zero blocking factor would mean "no blocks per message", which would
    // spin forever; the reference never sees one, so treat it as "all at once".
    let per = match req.blocking_factor() as u64 {
        0 => want.max(1),
        n => n,
    };

    let mut block = start;
    let mut left = want;
    while left > 0 {
        let n = left.min(per);
        let bytes = (n * BLOCK) as usize;
        if buf.len() < bytes {
            buf.resize(bytes, 0);
        }
        // Past the end of the image reads as zeros rather than an error: the
        // last sector of an image whose length is not a multiple of 2048 is
        // partial, and refusing it would make the tail unreadable.
        let off = block * BLOCK;
        let avail = size.saturating_sub(off).min(bytes as u64) as usize;
        buf[..bytes].fill(0);
        if avail > 0 {
            file.seek(SeekFrom::Start(off))?;
            file.read_exact(&mut buf[..avail])?;
        }

        let mut p = Vec::with_capacity(10 + bytes);
        p.extend_from_slice(&disk.to_be_bytes());
        p.extend_from_slice(&(block as u32).to_be_bytes());
        p.extend_from_slice(&(n as u32).to_be_bytes());
        p.extend_from_slice(&buf[..bytes]);
        c.send(&avmp(msg::VDISK_READ_DATA, &p))?;

        stats.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        block += n;
        left -= n;
    }
    Ok(())
}
