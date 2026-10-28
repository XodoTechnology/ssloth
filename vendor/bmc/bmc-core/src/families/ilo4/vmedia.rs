//! iLO 4 push-mode virtual media — the client is the SCSI target.
//!
//! iLO offers two ways to attach an image. The scripted path (`ilo4::insert_media`)
//! hands the BMC a URL and it fetches the image itself, which needs the BMC to be
//! able to reach *us*. This path is the one the vendor's own HTML5 console uses:
//! a WebSocket to `wss://<host>/wss/vmport` that *we* open, over which the BMC
//! sends SCSI commands and we answer with data. Because the connection is
//! outbound it works through NAT, VPNs and one-way routes, so it is the default.
//!
//! Ported from the console's `js/VMconnection.js`, with the CD commands that
//! file leaves unanswered (READ TOC, GET EVENT STATUS NOTIFICATION, MODE
//! SENSE(10)) filled in from the Windows client, which synthesises them.
//!
//! **Prerequisite:** iLO refuses this connection unless an Integrated Remote
//! Console session is already established on the same web session — *both* the
//! KVM and command channels, not just the video one. Without it every hello is
//! answered "invalid key" regardless of the key. The GUI always has a console up
//! by the time it can mount; headless callers use `ilo4_kvm::hold_session`.
//!
//!   client -> [16][devType][32-byte session key]          (34-byte hello)
//!   server -> [32][0][..][..]                             (4 bytes: attached)
//!   server -> 12-byte SCSI CDB (+ data-out payload for a WRITE)
//!   client -> 16-byte response header (+ payload in <=32K chunks)
//!
//! Response header: u32 magic 0x0BADC0DE, u32 flags, media, sense key, ASC,
//! ASCQ, u32 payload length — all little-endian.

use crate::vmedia::{Mount, Stats};
use crate::ws::{self, WebSocket};
use crate::media_source::Source;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAGIC: u32 = 0x0BAD_C0DE;
const HELLO_CONNECT: u8 = 16;

const FLAG_WRITE_PROTECT: u32 = 1;
const FLAG_KEEPALIVE: u32 = 2;
const FLAG_DISCONNECT: u32 = 4;

const MAX_CHUNK: usize = 32768;

// SCSI opcodes the BMC issues.
const TEST_UNIT_READY: u8 = 0x00;
const START_STOP_UNIT: u8 = 0x1B;
const PA_MEDIA_REMOVAL: u8 = 0x1E;
const READ_FORMAT_CAPACITIES: u8 = 0x23;
const READ_CAPACITY: u8 = 0x25;
const READ_10: u8 = 0x28;
const WRITE_10: u8 = 0x2A;
const READ_TOC: u8 = 0x43;
const GET_EVENT_STATUS: u8 = 0x4A;
const MODE_SENSE_10: u8 = 0x5A;
const READ_12: u8 = 0xA8;
const WRITE_12: u8 = 0xAA;

// Medium presence, as the reference tracks it: the BMC must see one
// "medium changed" unit attention before it will trust the capacity.
const MEDIA_NOT_PRESENT: u8 = 0;
const MEDIA_CHANGED: u8 = 1;
const MEDIA_READY: u8 = 2;

/// Which drive the image is presented as. The vendor console decides by file
/// extension alone: `.iso` is a CD-ROM, `.img` a floppy — whatever its size,
/// since the BMC's "floppy" is a USB mass-storage device underneath and serves
/// a multi-gigabyte USB-stick image just as well.
#[derive(Clone, Copy, PartialEq)]
enum Drive {
    Cdrom,
    Floppy,
}

impl Drive {
    fn for_path(path: &str) -> Drive {
        let name = crate::media_source::file_name(path);
        let img = std::path::Path::new(&name)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("img"));
        if img { Drive::Floppy } else { Drive::Cdrom }
    }
    /// The hello's device byte (`vmConnType`: 1 floppy, 2 CD-ROM, 3 USB).
    fn hello(self) -> u8 {
        match self {
            Drive::Cdrom => 2,
            Drive::Floppy => 1,
        }
    }
    fn sector(self) -> u64 {
        match self {
            Drive::Cdrom => 2048,
            Drive::Floppy => 512,
        }
    }
    /// The header's medium-type byte when an image is loaded. These are the
    /// reference's constants; 0x24 is not a type any SCSI table assigns, but
    /// it is what the BMC is used to seeing from a floppy.
    fn media(self) -> u8 {
        match self {
            Drive::Cdrom => 1,
            Drive::Floppy => 0x24,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Drive::Cdrom => "CD-ROM",
            Drive::Floppy => "floppy/USB key",
        }
    }
}

/// Which drive `path` will be attached as, for callers that report it.
pub fn drive_label(path: &str) -> &'static str {
    Drive::for_path(path).label()
}

/// Attach `path` and serve it until the mount is dropped: an `.iso` as a
/// virtual CD-ROM, an `.img` as a floppy/USB key. `session_key` is the iLO web
/// session key from `ilo4::login`.
///
/// `path` may also be an http(s) URL, fetched here and proxied (see
/// `media_source`). A disk image is opened read-write when it is a local file
/// that allows it, so what the host writes lands in the image as it would on a
/// real USB stick; a read-only file or a URL is presented write-protected.
pub fn mount(host: &str, session_key: &str, path: &str) -> std::io::Result<Mount> {
    let drive = Drive::for_path(path);
    let (file, writable) = match drive {
        Drive::Floppy => Source::open_rw(path)?,
        Drive::Cdrom => (Source::open(path)?, false),
    };
    let size = file.len()?;
    if session_key.len() != 32 {
        return Err(ioerr("iLO session key is not 32 characters"));
    }

    let mut sock = ws::connect(host, 443, "/wss/vmport", Some(session_key))?;
    let mut hello = [0u8; 34];
    hello[0] = HELLO_CONNECT;
    hello[1] = drive.hello();
    hello[2..34].copy_from_slice(session_key.as_bytes());
    sock.send_binary(&hello)?;

    // The BMC answers with a 4-byte attach status before any SCSI traffic.
    let reply = sock.recv(Duration::from_secs(15))?;
    if std::env::var("BMCKVM_DEBUG").is_ok() {
        eprintln!("[vmport] reply {reply:?}");
    }
    if reply.len() != 4 || reply[0] != 32 || reply[1] != 0 {
        return Err(ioerr(attach_error(reply.first().copied().unwrap_or(0))));
    }

    sock.set_poll_timeout(Duration::from_millis(200)).ok();
    let stop = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(Stats::default());
    let (s, st) = (stop.clone(), stats.clone());
    let mut target = Target {
        drive,
        file,
        size,
        writable,
        state: MEDIA_NOT_PRESENT,
        new_media: true,
        write: None,
    };
    let handle = std::thread::spawn(move || {
        target.serve(&mut sock, &s, &st);
    });
    Ok(Mount::from_parts(stop, handle, path.to_string(), size, stats))
}

/// A WRITE whose data-out payload is still arriving: the BMC sends the CDB,
/// then the sectors as separate messages, and expects the status only once
/// all of them are in.
struct PendingWrite {
    left: u64,
    ok: bool,
}

struct Target {
    drive: Drive,
    file: Source,
    size: u64,
    writable: bool,
    state: u8,
    /// GET EVENT STATUS reports "new media" once, then "no change".
    new_media: bool,
    write: Option<PendingWrite>,
}

impl Target {
    fn media(&self) -> u8 {
        if self.size == 0 { 0 } else { self.drive.media() }
    }

    fn flags(&self) -> u32 {
        if self.drive == Drive::Floppy && !self.writable { FLAG_WRITE_PROTECT } else { 0 }
    }

    fn serve(&mut self, sock: &mut WebSocket, stop: &Arc<AtomicBool>, stats: &Arc<Stats>) {
        let mut last = Instant::now();
        loop {
            if stop.load(Ordering::SeqCst) {
                // Tell the BMC the drive is going away, then close the channel so it
                // frees the session rather than waiting for a timeout.
                let _ = sock.send_binary(&header(FLAG_DISCONNECT, 0, 0, 0, 0, 0));
                std::thread::sleep(Duration::from_millis(150));
                sock.close();
                return;
            }
            let msg = match sock.poll() {
                Ok(Some(m)) => m,
                Ok(None) => {
                    // The BMC drops an idle drive; the reference pings every 2s.
                    if last.elapsed() >= Duration::from_secs(2) {
                        let h = header(self.flags() | FLAG_KEEPALIVE, self.media(), 0, 0, 0, 0);
                        if sock.send_binary(&h).is_err() {
                            return;
                        }
                        last = Instant::now();
                    }
                    continue;
                }
                Err(_) => return,
            };
            last = Instant::now();

            if self.write.is_some() {
                if !self.write_data(sock, &msg, stats) {
                    return;
                }
                continue;
            }
            if msg.len() != 12 {
                continue; // status frames; a CDB is always exactly 12 bytes
            }
            stats.commands.fetch_add(1, Ordering::Relaxed);
            if std::env::var("BMCKVM_DEBUG").is_ok() {
                eprintln!("[vmport] cdb {:02x?}", &msg);
            }
            if !self.command(sock, &msg, stop, stats) {
                return;
            }
        }
    }

    fn command(&mut self, sock: &mut WebSocket, cmd: &[u8], stop: &Arc<AtomicBool>, stats: &Arc<Stats>) -> bool {
        // Medium state advances on every command until it settles on READY.
        if self.size == 0 {
            self.state = MEDIA_NOT_PRESENT;
        } else if self.state < MEDIA_READY {
            self.state += 1;
        }

        match cmd[0] {
            TEST_UNIT_READY => match self.state {
                MEDIA_NOT_PRESENT => self.send(sock, 2, 0x3A, 0, 0),
                MEDIA_CHANGED => {
                    self.state = MEDIA_READY;
                    self.send(sock, 6, 0x28, 0, 0)
                }
                _ => self.send(sock, 0, 0, 0, 0),
            },
            START_STOP_UNIT => {
                let r = self.send(sock, 0, 0, 0, 0);
                // LOEJ: the host ejected the medium, so tear the drive down.
                if cmd[4] & 3 == 2 {
                    let _ = sock.send_binary(&header(FLAG_DISCONNECT, 0, 0, 0, 0, 0));
                    stop.store(true, Ordering::SeqCst);
                }
                r
            }
            // The floppy refuses to be locked in; the CD accepts. The reference
            // tests bit 1 rather than PREVENT's bit 0 — kept, since it is what
            // the BMC has only ever been answered with.
            PA_MEDIA_REMOVAL if self.drive == Drive::Floppy && cmd[4] & 2 != 0 => {
                self.send(sock, 5, 0x24, 0, 0)
            }
            PA_MEDIA_REMOVAL => self.send(sock, 0, 0, 0, 0),
            READ_CAPACITY => match self.state {
                MEDIA_NOT_PRESENT => self.send(sock, 2, 0x3A, 0, 0),
                MEDIA_CHANGED => self.send(sock, 6, 0x28, 0, 0),
                _ => {
                    let sector = self.drive.sector();
                    let last_lba = (self.size / sector).saturating_sub(1) as u32;
                    let mut d = [0u8; 8];
                    d[0..4].copy_from_slice(&last_lba.to_be_bytes());
                    d[4..8].copy_from_slice(&(sector as u32).to_be_bytes());
                    self.reply(sock, 0, 0, 0, &d)
                }
            },
            READ_FORMAT_CAPACITIES if self.drive == Drive::Floppy => {
                // The current capacity, then the one format the reference offers
                // (2880 x 512, a 1.44 MB floppy). Byte 8 = 2: formatted media.
                let mut d = [0, 0, 0, 16, 0, 0, 0, 0, 2, 0, 2, 0, 0, 0, 0x0B, 0x40, 0, 0, 2, 0];
                let blocks = (self.size / 512) as u32;
                d[4..8].copy_from_slice(&blocks.to_be_bytes());
                // Unlike every other command, this one carries its data even
                // while reporting the unit attention.
                if self.state == MEDIA_CHANGED {
                    self.state = MEDIA_READY;
                    self.reply(sock, 6, 0x28, 0, &d)
                } else {
                    self.reply(sock, 0, 0, 0, &d)
                }
            }
            READ_10 | READ_12 => {
                stats.reads.fetch_add(1, Ordering::Relaxed);
                self.read(sock, cmd, stats)
            }
            WRITE_10 | WRITE_12 if self.drive == Drive::Floppy => self.begin_write(sock, cmd),
            READ_TOC if self.drive == Drive::Cdrom => {
                let d = self.read_toc(cmd);
                self.reply(sock, 0, 0, 0, &cap(d, be16(cmd, 7)))
            }
            GET_EVENT_STATUS if self.drive == Drive::Cdrom => match self.event_status(cmd) {
                Some(d) => self.reply(sock, 0, 0, 0, &cap(d, be16(cmd, 7))),
                // Only the polled form is supported, as in the Windows client.
                None => self.send(sock, 5, 0x24, 0, 0),
            },
            MODE_SENSE_10 if self.drive == Drive::Cdrom => {
                // Header only: mode data length 6, medium type 1 (120 mm CD-ROM,
                // data only), no block descriptors, no pages.
                let d = vec![0, 6, 1, 0, 0, 0, 0, 0];
                self.reply(sock, 0, 0, 0, &cap(d, be16(cmd, 7)))
            }
            _ => self.send(sock, 5, 0x24, 0, 0), // invalid field in CDB
        }
    }

    /// Serve a READ_10/READ_12. Unlike the browser client, which gives up above
    /// 128K, this streams any length the host asks for in 32K chunks.
    fn read(&mut self, sock: &mut WebSocket, cmd: &[u8], stats: &Arc<Stats>) -> bool {
        let Some((offset, length)) = self.extent(cmd) else {
            return self.send(sock, 5, 0x21, 0, 0); // logical block address out of range
        };
        if length == 0 {
            return self.send(sock, 0, 0, 0, 0);
        }
        if self.file.seek(SeekFrom::Start(offset)).is_err() {
            return self.send(sock, 3, 0x11, 0, 0); // unrecovered read error
        }
        if !self.send(sock, 0, 0, 0, length as u32) {
            return false;
        }
        let mut left = length as usize;
        let mut buf = vec![0u8; MAX_CHUNK];
        while left > 0 {
            let want = left.min(MAX_CHUNK);
            match self.file.read(&mut buf[..want]) {
                Ok(0) => return false, // short file: the header already promised more
                Ok(n) => {
                    if sock.send_binary(&buf[..n]).is_err() {
                        return false;
                    }
                    stats.bytes.fetch_add(n as u64, Ordering::Relaxed);
                    left -= n;
                }
                Err(_) => return false,
            }
        }
        true
    }

    /// Start a WRITE_10/WRITE_12. The payload follows as separate messages, so
    /// the status goes out from `write_data` once the last byte is in.
    fn begin_write(&mut self, sock: &mut WebSocket, cmd: &[u8]) -> bool {
        let Some((offset, length)) = self.extent(cmd) else {
            return self.send(sock, 5, 0x21, 0, 0);
        };
        if length == 0 {
            return self.send(sock, 0, 0, 0, 0);
        }
        let ok = self.file.seek(SeekFrom::Start(offset)).is_ok();
        self.write = Some(PendingWrite { left: length, ok });
        true
    }

    fn write_data(&mut self, sock: &mut WebSocket, data: &[u8], stats: &Arc<Stats>) -> bool {
        let Some(w) = self.write.as_mut() else { return true };
        let take = (data.len() as u64).min(w.left) as usize;
        // Keep draining after a failure: the BMC sends the whole payload
        // regardless, and a status sent early would be read as data.
        if w.ok && self.writable {
            w.ok = self.file.write_all(&data[..take]).is_ok();
        }
        w.left -= take as u64;
        stats.bytes.fetch_add(take as u64, Ordering::Relaxed);
        if w.left > 0 {
            return true;
        }
        let ok = w.ok;
        self.write = None;
        if !self.writable {
            self.send(sock, 7, 0x27, 0, 0) // data protect: write protected
        } else if !ok {
            self.send(sock, 3, 0x0C, 0, 0) // medium error: write error
        } else {
            self.send(sock, 0, 0, 0, 0)
        }
    }

    /// Byte offset and length of a READ/WRITE (10) or (12), or None when it
    /// runs past the end of the image.
    fn extent(&self, cmd: &[u8]) -> Option<(u64, u64)> {
        let sector = self.drive.sector();
        let lba = u32::from_be_bytes([cmd[2], cmd[3], cmd[4], cmd[5]]) as u64;
        let blocks = if cmd[0] == READ_12 || cmd[0] == WRITE_12 {
            u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]) as u64
        } else {
            be16(cmd, 7) as u64
        };
        let (offset, length) = (lba * sector, blocks * sector);
        (offset.saturating_add(length) <= self.size).then_some((offset, length))
    }

    /// A single data track plus the lead-out. The format sits in byte 2 (MMC)
    /// or, from older initiators, the top bits of byte 9 (SFF-8020), which is
    /// where the Windows client looks.
    fn read_toc(&self, cmd: &[u8]) -> Vec<u8> {
        let msf = cmd[1] & 0x02 != 0;
        let format = match cmd[2] & 0x0F {
            0 => cmd[9] >> 6,
            f => f,
        };
        let blocks = self.size / 2048;
        if format == 1 {
            // Session info: first and last session 1, starting at track 1.
            let mut d = vec![0, 10, 1, 1, 0, 0x14, 1, 0, 0, 0, 0, 0];
            toc_addr(&mut d[8..12], 0, msf);
            return d;
        }
        let mut d = vec![0u8; 20];
        d[0..2].copy_from_slice(&18u16.to_be_bytes());
        d[2] = 1; // first track
        d[3] = 1; // last track
        d[5] = 0x14; // ADR 1, data track
        d[6] = 1;
        toc_addr(&mut d[8..12], 0, msf);
        d[13] = 0x14;
        d[14] = 0xAA; // lead-out
        toc_addr(&mut d[16..20], blocks, msf);
        d
    }

    /// The media-class event: "new media" once after the mount, then "no
    /// change", with the medium always present. None for the asynchronous
    /// form, which this target cannot deliver.
    fn event_status(&mut self, cmd: &[u8]) -> Option<Vec<u8>> {
        if cmd[1] & 1 == 0 {
            return None;
        }
        const MEDIA_CLASS: u8 = 0x10;
        if cmd[4] & MEDIA_CLASS == 0 {
            // No supported class was asked for: NEA set, no event data.
            return Some(vec![0, 2, 0x80, MEDIA_CLASS]);
        }
        let event = if self.size > 0 && std::mem::take(&mut self.new_media) { 2 } else { 0 };
        let present = if self.size > 0 { 0x02 } else { 0 };
        Some(vec![0, 6, 0x04, MEDIA_CLASS, event, present, 0, 0])
    }

    fn send(&self, sock: &mut WebSocket, sense: u8, asc: u8, ascq: u8, len: u32) -> bool {
        sock.send_binary(&header(self.flags(), self.media(), sense, asc, ascq, len)).is_ok()
    }

    fn reply(&self, sock: &mut WebSocket, sense: u8, asc: u8, ascq: u8, data: &[u8]) -> bool {
        self.send(sock, sense, asc, ascq, data.len() as u32) && sock.send_binary(data).is_ok()
    }
}

/// An LBA as a TOC address: plain big-endian, or MSF with the 2-second pregap.
fn toc_addr(out: &mut [u8], lba: u64, msf: bool) {
    if msf {
        let f = lba + 150;
        out[0] = 0;
        out[1] = (f / (75 * 60)) as u8;
        out[2] = ((f / 75) % 60) as u8;
        out[3] = (f % 75) as u8;
    } else {
        out.copy_from_slice(&(lba as u32).to_be_bytes());
    }
}

/// Trim a response to the CDB's allocation length.
fn cap(mut d: Vec<u8>, alloc: u16) -> Vec<u8> {
    d.truncate(alloc as usize);
    d
}

fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

fn header(flags: u32, media: u8, sense: u8, asc: u8, ascq: u8, len: u32) -> [u8; 16] {
    let mut h = [0u8; 16];
    h[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    h[4..8].copy_from_slice(&flags.to_le_bytes());
    h[8] = media;
    h[9] = sense;
    h[10] = asc;
    h[11] = ascq;
    h[12..16].copy_from_slice(&len.to_le_bytes());
    h
}

fn attach_error(status: u8) -> &'static str {
    match status {
        33 => "virtual media: the drive is already in use",
        // Also what you get with a perfectly good key and no console session up.
        34 => "virtual media: the session key was rejected - iLO only accepts a \
virtual-media connection while a remote console session is open",
        35 => "virtual media is not licensed on this iLO",
        36 => "virtual media: the session key has expired",
        37 => "virtual media: the drive is not configured",
        38 => "virtual media: a media permit is required",
        _ => "virtual media: the iLO refused the drive connection",
    }
}

fn ioerr(m: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, m.to_string())
}
