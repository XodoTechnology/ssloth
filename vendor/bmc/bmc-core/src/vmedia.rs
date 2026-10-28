//! Virtual media: emulate a USB CD-ROM to the BMC and serve a local ISO.
//!
//! Port of ATENtion's VirtualMediaSession + Storage/*. A separate TLS connection
//! to the vmedia port (default 623) carries a control handshake (health/init),
//! an authenticated attach record, then a USB Mass-Storage (SCSI CD-ROM) command
//! stream that we answer from the ISO file.
//!
//! Framing:
//!   control frame  = [type:u32 BE][len:u32 LE][payload]
//!   data header    = [0x22][0x00][lun][flag][len:u32 LE]   (flag 0x00=data, 0xFF=status)
//!   command header = [0x11][..][lun][..][len:u32 LE] then a 31-byte CBW
//!
//! The attach record is 246 bytes with a trailing HMAC-SHA1 over the first 226.

use crate::auth;
use crate::families::aten::client_cert::{self, Identity};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

const BLOCK: u64 = 2048;

// Device descriptor emitted by ATEN for the "ISO Image" CD-ROM slot.
const CDROM_DESCRIPTOR_HEX: &str =
    "121201000200000040a00e111100020000000127090227000101008064\
     090400000308055000070501020002ff070582020002ff0705830302000104\
     0403090422220346006c0061007300680020004400690073006b0020002000\
     20002000200020002222033400450038004600300039003200430033004600\
     4400370046003800460037001a1a0353004e00300030003000500051004900\
     300030003900200001000a0a060002000000400100";

/// A vmedia transport: TLS (X11) or plaintext (X9). Both carry the same frames.
enum Stream {
    Tls(Box<crate::legacy_tls::Stream>),
    Plain(TcpStream),
}
impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self { Stream::Tls(s) => s.read(buf), Stream::Plain(s) => s.read(buf) }
    }
}
impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self { Stream::Tls(s) => s.write(buf), Stream::Plain(s) => s.write(buf) }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self { Stream::Tls(s) => s.flush(), Stream::Plain(s) => s.flush() }
    }
}

fn connect(host: &str, port: u16, tls: bool, id: &Identity) -> std::io::Result<Stream> {
    let tcp = crate::net::connect(host, port, None)?;
    tcp.set_nodelay(true).ok();
    if !tls {
        return Ok(Stream::Plain(tcp));
    }
    // OpenSSL, not the platform stack, for the X9's TLS 1.0 (see `legacy_tls`).
    // The client certificate is sent only if the port asks for one, as a port
    // fronted by the console's mutual-TLS stunnel does.
    Ok(Stream::Tls(Box::new(crate::legacy_tls::connect(host, tcp, Some(id.pem()))?)))
}

/// Connections to the media port, each after making sure the BMC clock is
/// inside the client certificate's validity when `hold` keeps it there: a
/// BMC's NTP can move it between one connection and the next.
struct Opener<'a> {
    host: &'a str,
    port: u16,
    tls: bool,
    id: Identity,
    hold: Option<&'a crate::clock::Hold>,
    say: &'a dyn Fn(&str),
}

impl Opener<'_> {
    fn open(&self) -> std::io::Result<Stream> {
        if !self.tls || self.hold.is_none() {
            return connect(self.host, self.port, self.tls, &self.id);
        }
        client_cert::handshake(self.hold, self.say, || connect(self.host, self.port, true, &self.id))
            .map_err(ioerr)
    }
}

fn ioerr(m: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, m)
}

fn recvn<S: Read>(s: &mut S, n: usize) -> std::io::Result<Vec<u8>> {
    let mut b = vec![0u8; n];
    s.read_exact(&mut b)?;
    Ok(b)
}

fn ctl_frame(t: u32, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(8 + payload.len());
    f.extend_from_slice(&t.to_be_bytes());
    f.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    f.extend_from_slice(payload);
    f
}

fn read_ctl<S: Read>(s: &mut S) -> std::io::Result<(u32, Vec<u8>)> {
    let pfx = recvn(s, 4)?;
    let len = u32::from_le_bytes(recvn(s, 4)?.try_into().unwrap()) as usize;
    let pay = if len > 0 { recvn(s, len)? } else { Vec::new() };
    Ok((u32::from_be_bytes(pfx.try_into().unwrap()), pay))
}

/// Build the 246-byte authenticated attach record (HMAC-SHA1 over the first 226).
fn attach_record(user: &str, pass: &str) -> Vec<u8> {
    let u = user.as_bytes();
    let p = pass.as_bytes();
    let mut r = vec![0u8; 246];
    r[1] = 0x80; r[3] = 0x01; r[4] = 0x2c;
    r[8..8 + u.len().min(15)].copy_from_slice(&u[..u.len().min(15)]);
    r[24..24 + p.len().min(15)].copy_from_slice(&p[..p.len().min(15)]);
    let ts: u32 = rand_u32();
    r[44..48].copy_from_slice(&ts.to_le_bytes());
    r[48] = 0x85; r[49] = 0x03;
    let desc = hexb(CDROM_DESCRIPTOR_HEX);
    r[52..52 + desc.len()].copy_from_slice(&desc);
    let key = format!("{user}{pass}");
    let digest = hmac_sha1(key.as_bytes(), &r[..226]);
    r[226..246].copy_from_slice(&digest);
    r
}

/// Build the X9 plug-in packet: a 52-byte SID-authenticated attach with no HMAC
/// and no USB descriptor (the BMC synthesises the device from the media byte).
///
/// Layout (reverse-engineered from `FillUSBPlugInPkt` in libSharedLibrary64.so):
///   [0..4]   frame type 1 (big-endian) with only byte 3 set
///   [4]      0x2c  payload length (44)
///   [8..24]  user field = the full 16-char web SID (NOT the account name)
///   [24..44] pass field (the SID again; the server ignores it in SID-auth mode)
///   [44..48] client random nonce
///   [48]     0x85  auth flags: bit7 = SID-auth, low bits select device slot 0
///   [49]     media type (1 = CD-ROM)
///
/// The web SID is the credential the X9 BMC checks — the account password yields
/// status 6 ("BMC is in FW updating"). The SID must be the exact 16-byte cookie.
fn attach_x9(sid: &str, media: u8) -> Vec<u8> {
    let s = sid.as_bytes();
    let n = s.len().min(16);
    let mut b = vec![0u8; 52];
    b[3] = 0x01;
    b[4] = 0x2c;
    b[8..8 + n].copy_from_slice(&s[..n]);
    b[24..24 + n].copy_from_slice(&s[..n]);
    b[44..48].copy_from_slice(&rand_u32().to_le_bytes());
    b[48] = 0x85;
    b[49] = media;
    b
}

fn rand_u32() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos();
    n.wrapping_mul(2654435761).rotate_left(13) ^ 0x9e3779b9
}

// --- minimal HMAC-SHA1 (no external crate) ---
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let ml = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&ml.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3]]);
        }
        for i in 16..80 {
            w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let tmp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
            e = d; d = c; c = b.rotate_left(30); b = a; a = tmp;
        }
        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b); h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d); h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for i in 0..5 { out[i*4..i*4+4].copy_from_slice(&h[i].to_be_bytes()); }
    out
}

fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..20].copy_from_slice(&sha1(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 { ipad[i] ^= k[i]; opad[i] ^= k[i]; }
    let mut inner = ipad.to_vec();
    inner.extend_from_slice(msg);
    let ih = sha1(&inner);
    let mut outer = opad.to_vec();
    outer.extend_from_slice(&ih);
    sha1(&outer)
}

// --- ISO source ---
struct Iso {
    file: crate::media_source::Source,
    total_blocks: u64,
}
impl Iso {
    fn open(path: &str) -> std::io::Result<Iso> {
        let file = crate::media_source::Source::open(path)?;
        let len = file.len()?;
        Ok(Iso { file, total_blocks: (len + BLOCK - 1) / BLOCK })
    }
    fn read_blocks(&mut self, lba: u64, blocks: usize) -> Vec<u8> {
        let mut buf = vec![0u8; blocks * BLOCK as usize];
        let off = lba * BLOCK;
        if self.file.seek(SeekFrom::Start(off)).is_ok() {
            // Loop: a URL source answers from its read-ahead window, so one
            // read may return less than asked. EOF leaves zeros.
            let mut filled = 0;
            while filled < buf.len() {
                match self.file.read(&mut buf[filled..]) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => filled += n,
                }
            }
        }
        buf
    }
}

// --- SCSI CD-ROM target ---
pub struct Scsi {
    iso: Iso,
    sense_key: u8,
    sense_asc: u8,
    sense_ascq: u8,
}

const INQUIRY_DATA: &[u8] = b"\x05\x80\x00\x21\x1F\x00\x00\x00IPMI    Virtual CDROM   3000";

impl Scsi {
    /// Open an ISO as a SCSI CD-ROM target (shared by the ATEN and Quanta vmedia).
    pub fn from_iso(path: &str) -> std::io::Result<Scsi> {
        Ok(Scsi { iso: Iso::open(path)?, sense_key: 0, sense_asc: 0, sense_ascq: 0 })
    }
    /// The image size in bytes, rounded up to whole blocks.
    pub fn image_size(&self) -> u64 {
        self.iso.total_blocks * BLOCK
    }
    /// Execute one SCSI CDB, returning (data, status). `alloc` is the requested
    /// transfer length; `data_in` is true for data-in (read) commands.
    pub fn execute(&mut self, cdb: &[u8], alloc: usize, data_in: bool) -> (Vec<u8>, u8) {
        let op = cdb[0];
        match op {
            0x00 | 0x1B | 0x1E => (vec![], 0),          // TEST UNIT READY / START STOP / PREVENT
            0x03 => (cap(self.request_sense(), alloc), 0), // REQUEST SENSE
            0x12 => (cap(INQUIRY_DATA.to_vec(), alloc), 0), // INQUIRY
            0x25 => (cap(self.read_capacity10(), alloc), 0), // READ CAPACITY(10)
            0x28 => self.read(be32(cdb, 2), be16(cdb, 7) as u64, alloc), // READ(10)
            0xA8 => self.read(be32(cdb, 2), be32(cdb, 6), alloc),        // READ(12)
            0x1A => (cap(vec![0x03, 0, 0, 0], alloc), 0),  // MODE SENSE(6)
            0x5A => (cap(self.mode_sense10(), alloc), 0),  // MODE SENSE(10)
            0x43 => (cap(self.read_toc(cdb), alloc), 0),   // READ TOC
            0x46 => (cap(self.get_configuration(cdb), alloc), 0), // GET CONFIGURATION
            0x4A => (cap(vec![0x00,0x06,0x04,0x5E,0x00,0x02,0x00,0x00], alloc), 0), // GET EVENT STATUS
            0x51 => (cap(hexb("00200e01010101200000000000000000ffffffffffffffff00000000000000000000"), alloc), 0),
            0x52 => (cap(self.track_information(), alloc), 0),
            _ => { let _ = data_in; self.fail(0x05, 0x20, 0x00) }
        }
    }
    fn read(&mut self, lba: u64, blocks: u64, alloc: usize) -> (Vec<u8>, u8) {
        if blocks == 0 { return (vec![], 0); }
        if lba + blocks > self.iso.total_blocks { return self.fail(0x05, 0x21, 0x00); }
        let mut data = self.iso.read_blocks(lba, blocks as usize);
        if alloc > 0 && alloc < data.len() { data.truncate(alloc); }
        (data, 0)
    }
    fn read_capacity10(&self) -> Vec<u8> {
        let last = (self.iso.total_blocks.saturating_sub(1)) as u32;
        let blk = BLOCK as u32;
        let mut v = Vec::new();
        v.extend_from_slice(&last.to_be_bytes());
        v.extend_from_slice(&blk.to_be_bytes());
        v
    }
    fn request_sense(&mut self) -> Vec<u8> {
        let mut s = vec![0u8; 18];
        s[0] = 0x70; s[2] = self.sense_key; s[7] = 10; s[12] = self.sense_asc; s[13] = self.sense_ascq;
        self.sense_key = 0; self.sense_asc = 0; self.sense_ascq = 0;
        s
    }
    fn mode_sense10(&self) -> Vec<u8> {
        hexb("00240100000000002a1c3f00717729231b90010000c61b900010000000000010000000000000")
    }
    fn get_configuration(&self, cdb: &[u8]) -> Vec<u8> {
        let sf = be16(cdb, 2);
        if sf == 0x28 { return hexb("0000004c00000008002a000400010000"); }
        if sf == 0x20 { return hexb("00000054000000080024000400000000002a000400010000"); }
        hexb("0000009800000008000003080010000000080100000103040000000200020704\
              000000000003030429000000001001080000080000000100001d0100001e0504\
              03000000001f0004000001000024000400000000002a000400010000002b0004\
              00000000003b0004000000000100030001030004070001000104030001050704\
              0000000001060004000000010107c00408000000010b0004")
    }
    fn track_information(&self) -> Vec<u8> {
        let mut d = hexb("001c0101000401000000000000000000000000000000000000000000");
        let blocks = self.iso.total_blocks.min(u32::MAX as u64) as u32;
        d[24..28].copy_from_slice(&blocks.to_be_bytes());
        d
    }
    fn read_toc(&self, cdb: &[u8]) -> Vec<u8> {
        let msf = cdb[1] & 0x02 != 0;
        let mut toc = vec![0u8; 4 + 8 + 8];
        let len = (toc.len() - 2) as u16;
        toc[0..2].copy_from_slice(&len.to_be_bytes());
        toc[2] = 0x01; toc[3] = 0x01;
        toc[5] = 0x14; toc[6] = 0x01;
        write_toc_addr(&mut toc, 8, 0, msf);
        toc[13] = 0x14; toc[14] = 0xAA;
        write_toc_addr(&mut toc, 16, self.iso.total_blocks, msf);
        toc
    }
    fn fail(&mut self, key: u8, asc: u8, ascq: u8) -> (Vec<u8>, u8) {
        self.sense_key = key; self.sense_asc = asc; self.sense_ascq = ascq;
        (vec![], 1)
    }
}

fn write_toc_addr(buf: &mut [u8], off: usize, lba: u64, msf: bool) {
    if msf {
        let f = lba + 150;
        buf[off] = 0;
        buf[off + 1] = (f / (75 * 60)) as u8;
        buf[off + 2] = ((f / 75) % 60) as u8;
        buf[off + 3] = (f % 75) as u8;
    } else {
        buf[off..off + 4].copy_from_slice(&(lba as u32).to_be_bytes());
    }
}

fn data_header(lun: u8, flag: u8, len: usize) -> [u8; 8] {
    let l = (len as u32).to_le_bytes();
    [0x22, 0x00, lun, flag, l[0], l[1], l[2], l[3]]
}

fn build_csw(tag: u32, residue: u32, status: u8) -> Vec<u8> {
    let mut c = Vec::with_capacity(13);
    c.extend_from_slice(b"USBS");
    c.extend_from_slice(&tag.to_le_bytes());
    c.extend_from_slice(&residue.to_le_bytes());
    c.push(status);
    c
}

/// Live counters for the serving session.
#[derive(Default)]
pub struct Stats {
    pub commands: AtomicU64,
    pub bytes: AtomicU64,
    pub reads: AtomicU64,
}

/// Handle to a running virtual-media session.
pub struct Mount {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    pub image: String,
    pub size: u64,
    pub stats: Arc<Stats>,
    /// ATEN: this mount's claim on a BMC clock rolled back for the client
    /// certificate, shared with a console on the same BMC.
    clock: Option<crate::clock::Hold>,
}

impl Mount {
    /// Stop serving, and let go of the BMC clock; what could not be put
    /// back comes back, one line naming the host.
    pub fn unmount(mut self) -> Option<String> {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() { let _ = h.join(); }
        self.clock.take().and_then(|h| h.release())
    }
    /// Build a Mount from an externally-driven serve thread (used by the Quanta
    /// IUSB vmedia path, which shares this Mount type for the GUI).
    pub fn from_parts(stop: Arc<AtomicBool>, handle: std::thread::JoinHandle<()>,
                      image: String, size: u64, stats: Arc<Stats>) -> Mount {
        Mount { stop, handle: Some(handle), image, size, stats, clock: None }
    }
}

/// Perform the attach handshake and start serving `iso_path`. Returns once attached;
/// the SCSI command stream is served on a background thread until stop or teardown.
pub fn mount(host: &str, port: u16, user: &str, pass: &str, iso_path: &str, say: &dyn Fn(&str))
    -> std::io::Result<Mount>
{
    // X11 wraps vmedia in TLS; X9 is plaintext. Probe with the health exchange.
    let mut id = client_cert::cached_or_bundled(host);
    let mut hold = None;
    let tls = match probe(host, port, &id) {
        Probe::Answers(tls) => {
            // Answered with an expired certificate while a console here holds
            // the clock rolled back: this mount holds it too, so the console
            // closing cannot restore it under the handshakes to come.
            if tls && crate::clock::held(host) {
                hold = Some(crate::clock::Hold::take(host, user, pass, (id.not_before, id.not_after)));
            }
            tls
        }
        // A TLS alert: the port is TLS and wants a client certificate, as
        // the console's does on boards whose :623 sits behind the same
        // mutual-TLS stunnel. Then the clock is held exactly as for the
        // console, and shared with it.
        Probe::Refused(e) if crate::legacy_tls::alert(&e).is_some() => {
            let (found, why) = client_cert::fetch(host, user, pass);
            if let Some(why) = why {
                say(&format!("using the bundled client certificate ({why})"));
            }
            id = found;
            let h = crate::clock::Hold::take(host, user, pass, (id.not_before, id.not_after));
            let answered = client_cert::handshake(Some(&h), say, || {
                let mut s = connect(host, port, true, &id)?;
                s.write_all(&ctl_frame(8, &[]))?;
                s.flush()?;
                read_ctl(&mut s)
            });
            if let Err(e) = answered {
                // Let go now: nothing else will, as there is no mount.
                return Err(ioerr(match h.release() {
                    Some(p) => format!("{e}; {p}"),
                    None => e,
                }));
            }
            hold = Some(h);
            true
        }
        Probe::Refused(e) => return Err(ioerr(format!(
            "the vmedia port refused TLS: {}", client_cert::describe(&e, false, false)))),
        Probe::Silent => return Err(ioerr(
            "vmedia port not responding to the control handshake".into())),
    };
    let open = Opener { host, port, tls, id, hold: hold.as_ref(), say };

    let mut data = if !tls {
        // --- X9: plaintext, SID-authenticated plug-in (no health/init dance) ---
        // The X9 BMC never answers the type-10 init frame, so we go straight to
        // attach. The credential is the web SID, so fetch a fresh one now.
        let sid = auth::login(host, user, pass)?;
        let mut data = open.open()?;
        data.write_all(&attach_x9(&sid, 0x01))?; data.flush()?;
        let (t, pay) = read_ctl(&mut data)?;
        if t != 2 || pay.first() != Some(&0) {
            return Err(std::io::Error::new(std::io::ErrorKind::Other,
                format!("X9 vmedia attach rejected (type {t}, status {:?})", pay.first())));
        }
        // Set-EP command: hands the device over to the USB Mass-Storage stack.
        data.write_all(&ctl_frame(7, &[]))?; data.flush()?;
        data
    } else {
        // --- X10/X11: TLS with health/init handshake and the HMAC attach record ---
        let mut h = open.open()?;
        h.write_all(&ctl_frame(8, &[]))?; h.flush()?;
        read_ctl(&mut h)?; drop(h);
        let mut i = open.open()?;
        i.write_all(&ctl_frame(10, &[]))?; i.flush()?;
        read_ctl(&mut i)?; drop(i);
        let mut data = open.open()?;
        let mut ph = open.open()?;
        ph.write_all(&ctl_frame(8, &[]))?; ph.flush()?;
        read_ctl(&mut ph)?; drop(ph);
        data.write_all(&attach_record(user, pass))?; data.flush()?;
        let (t, pay) = read_ctl(&mut data)?;
        if t != 2 || pay.is_empty() || pay[0] != 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::Other,
                format!("vmedia attach rejected (type {t}, status {:?})", pay.first())));
        }
        data.write_all(&ctl_frame(7, &[0x05,0x03,0x01,0x10,0x02,0x20,0x03,0x30]))?;
        data.flush()?;
        data
    };

    let iso = Iso::open(iso_path)?;
    let size = iso.total_blocks * BLOCK;
    let mut scsi = Scsi { iso, sense_key: 0, sense_asc: 0, sense_ascq: 0 };
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let stats = Arc::new(Stats::default());
    let stats2 = stats.clone();
    let image = iso_path.to_string();

    let handle = std::thread::spawn(move || {
        if let Err(e) = serve_loop(&mut data, &mut scsi, &stop2, &stats2) {
            if !stop2.load(Ordering::SeqCst) {
                eprintln!("vmedia: serve loop ended: {e}");
            }
        }
    });

    // An error above drops `hold`, which lets go of the clock.
    Ok(Mount { stop, handle: Some(handle), image, size, stats, clock: hold })
}

/// What the media port made of a control frame.
enum Probe {
    /// It answered, over TLS (X10/X11) or in the clear (X9).
    Answers(bool),
    /// The TLS handshake failed; with an alert, the BMC refused us.
    Refused(std::io::Error),
    /// Neither way answered.
    Silent,
}

/// Decide whether vmedia on this port is TLS (X11) or plaintext (X9) by trying
/// TLS first and confirming a control response, then falling back to plain.
/// A TLS handshake refused with an alert is kept: an X9 that serves media in
/// the clear cannot send one, so it means the port wants a certificate.
fn probe(host: &str, port: u16, id: &Identity) -> Probe {
    let mut refused = None;
    for tls in [true, false] {
        match connect(host, port, tls, id) {
            Ok(mut s) => {
                if s.write_all(&ctl_frame(8, &[])).is_ok() && s.flush().is_ok()
                    && read_ctl(&mut s).is_ok()
                {
                    return Probe::Answers(tls);
                }
            }
            Err(e) if tls && crate::legacy_tls::alert(&e).is_some() => refused = Some(e),
            Err(_) => {}
        }
    }
    refused.map(Probe::Refused).unwrap_or(Probe::Silent)
}

fn serve_loop(
    data: &mut Stream,
    scsi: &mut Scsi,
    stop: &Arc<AtomicBool>,
    stats: &Arc<Stats>,
) -> std::io::Result<()> {
    loop {
        if stop.load(Ordering::SeqCst) { return Ok(()); }
        let prefix = recvn(data, 4)?;
        if prefix[0] == 0x11 {
            // command frame: 8-byte header, then 31-byte CBW
            let rest = recvn(data, 4)?;
            let lun = prefix[2];
            let payload_len = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
            if payload_len != 31 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
                    format!("bad vmedia command length {payload_len}")));
            }
            let cbw = recvn(data, 31)?;
            let sig = u32::from_le_bytes([cbw[0], cbw[1], cbw[2], cbw[3]]);
            if sig != 0x4342_5355 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "bad CBW signature"));
            }
            let tag = u32::from_le_bytes([cbw[4], cbw[5], cbw[6], cbw[7]]);
            let dtl = u32::from_le_bytes([cbw[8], cbw[9], cbw[10], cbw[11]]);
            let flags = cbw[12];
            let cdb = &cbw[15..31];
            let data_in = flags & 0x80 != 0;

            let (mut out, status) = scsi.execute(cdb, dtl as usize, data_in);
            stats.commands.fetch_add(1, Ordering::Relaxed);
            if matches!(cdb[0], 0x28 | 0xA8) { stats.reads.fetch_add(1, Ordering::Relaxed); }
            if out.len() > dtl as usize { out.truncate(dtl as usize); }
            let residue = if dtl > out.len() as u32 { dtl - out.len() as u32 } else { 0 };

            if data_in && !out.is_empty() {
                data.write_all(&data_header(lun, 0x00, out.len()))?;
                data.write_all(&out)?;
                stats.bytes.fetch_add(out.len() as u64, Ordering::Relaxed);
            }
            let csw = build_csw(tag, residue, status);
            data.write_all(&data_header(lun, 0xFF, csw.len()))?;
            data.write_all(&csw)?;
            data.flush()?;
        } else {
            // control frame: [type BE][len LE][payload]; consume and check for teardown
            let ty = u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]);
            let len = u32::from_le_bytes(recvn(data, 4)?.try_into().unwrap()) as usize;
            if len > 0 && len <= 1024 * 1024 { recvn(data, len)?; }
            if ty == 4 || ty == 6 { return Ok(()); }
        }
    }
}

fn cap(mut data: Vec<u8>, alloc: usize) -> Vec<u8> {
    if alloc > 0 && alloc < data.len() { data.truncate(alloc); }
    data
}
fn be16(b: &[u8], o: usize) -> u32 { ((b[o] as u32) << 8) | b[o + 1] as u32 }
fn be32(b: &[u8], o: usize) -> u64 {
    ((b[o] as u64) << 24) | ((b[o+1] as u64) << 16) | ((b[o+2] as u64) << 8) | b[o+3] as u64
}
fn hexb(s: &str) -> Vec<u8> {
    let h: Vec<u8> = s.bytes().filter(|c| c.is_ascii_hexdigit()).collect();
    h.chunks(2).map(|p| {
        let hi = (p[0] as char).to_digit(16).unwrap();
        let lo = (p[1] as char).to_digit(16).unwrap();
        (hi * 16 + lo) as u8
    }).collect()
}
