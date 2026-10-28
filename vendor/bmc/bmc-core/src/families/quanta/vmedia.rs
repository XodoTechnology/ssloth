//! Quanta/AMI MegaRAC virtual media — the IUSB CD-ROM redirection protocol
//! (TCP :5120), reverse-engineered from com.ami.iusb.* and libjavacdromwrapper.so.
//!
//! Status: the connect + authentication handshake is verified live against the
//! Quanta (the BMC accepts the token and reports connectionStatus=1, i.e.
//! the virtual CD slot is reserved). The SCSI serve loop is reverse-engineered but
//! NOT yet validated live, because it only exercises once the managed host reads
//! the CD (on boot or an explicit mount) — the AMI client also signals attach via
//! IVTP MEDIA_STATE(24) on the :7578 KVM channel. See docs/QUANTA-JVIEWER.md.
//!
//! Framing — IUSB packet = 32-byte IUSBHeader + payload (little-endian):
//!   [0..8]  "IUSB    "
//!   [8]=major(1) [9]=minor(0) [10]=packetHeaderLen(32)
//!   [11]=checksum(-sum of the 32 header bytes)
//!   [12..16]=dataPacketLen  [17]=deviceType(5=CDROM) [18]=protocol(1)
//!   [19]=direction(0x80) [20]=deviceNumber [21]=interfaceNumber
//!   [23]=Instance(device index)  [24..28]=sequenceNumber  [28..32]=reserved
//! The SCSI CDB sits at packet offset 41 (opcode = byte[41]); the response reuses
//! the 62-byte request header, appends the SCSI data, and writes the data length
//! as an int32 at offset 57. Standard SCSI opcodes: 0x00 TEST UNIT READY,
//! 0x12 INQUIRY, 0x25 READ CAPACITY, 0x28/0xA8 READ(10)/(12), 0x43 READ TOC,
//! 0x1B START/STOP — all already handled by the SCSI engine in vmedia.rs.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub const CD_PORT: u16 = 5120;
const CDROM_DEVICE_TYPE: u8 = 5;
const OP_AUTH_REQUEST: u8 = 0xF2;   // client -> BMC session-token auth
const OP_AUTH_RESPONSE: u8 = 0xF1;  // BMC -> client (connectionStatus at data[30])

/// Build a 32-byte IUSB header for a CD-ROM packet with the given payload length.
fn iusb_header(data_len: u32, instance: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0..8].copy_from_slice(b"IUSB    ");
    b[8] = 1; b[9] = 0; b[10] = 32;
    b[12..16].copy_from_slice(&data_len.to_le_bytes());
    b[17] = CDROM_DEVICE_TYPE; b[18] = 1; b[19] = 0x80;
    b[23] = instance;
    let sum: u32 = b.iter().map(|&x| x as u32).sum();
    b[11] = (0u8).wrapping_sub((sum & 0xff) as u8);
    b
}

fn recvn(s: &mut TcpStream, n: usize) -> std::io::Result<Vec<u8>> {
    let mut v = vec![0u8; n];
    s.read_exact(&mut v)?;
    Ok(v)
}

/// An IUSB packet: the 32-byte header plus its payload.
pub struct IusbPacket {
    pub header: [u8; 32],
    pub payload: Vec<u8>,
}

/// Read one IUSB packet (32-byte header, then dataPacketLen payload bytes).
pub fn read_packet(s: &mut TcpStream) -> std::io::Result<IusbPacket> {
    let h = recvn(s, 32)?;
    if &h[0..8] != b"IUSB    " {
        return Err(ioerr("bad IUSB signature".into()));
    }
    let data_len = u32::from_le_bytes([h[12], h[13], h[14], h[15]]);
    let payload = if data_len > 0 && data_len < 8 * 1024 * 1024 {
        recvn(s, data_len as usize)?
    } else { Vec::new() };
    let mut header = [0u8; 32];
    header.copy_from_slice(&h);
    Ok(IusbPacket { header, payload })
}

/// Connect to the CD-ROM redirection port and authenticate with the KVM launch
/// token. Returns the live socket on success (connectionStatus == 1).
///
/// `token` is the per-launch kvmToken (same one used for the :7578 KVM session).
pub fn connect_cdrom(host: &str, port: u16, token: &str, instance: u8)
    -> std::io::Result<TcpStream>
{
    let mut s = crate::net::connect(host, port, None)?;
    s.set_nodelay(true).ok();
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();

    // Auth packet: 160 bytes = 32-byte IUSB header (dataPacketLen=128) + auth body
    // with OP_AUTH_REQUEST at [41] and the token at [63].
    let mut pkt = vec![0u8; 160];
    pkt[0..32].copy_from_slice(&iusb_header(128, instance));
    pkt[41] = OP_AUTH_REQUEST;
    let t = token.as_bytes();
    let n = t.len().min(160 - 63);
    pkt[63..63 + n].copy_from_slice(&t[..n]);
    s.write_all(&pkt)?;
    s.flush()?;

    let resp = read_packet(&mut s)?;
    let op = resp.payload.get(9).copied().unwrap_or(0);
    let status = resp.payload.get(30).copied().unwrap_or(0);
    if op != OP_AUTH_RESPONSE {
        return Err(ioerr(format!("unexpected IUSB auth opcode {op:#x}")));
    }
    if status != 1 {
        return Err(ioerr("virtual media already in use (connectionStatus != 1)".into()));
    }
    Ok(s)
}

/// Transfer length + direction implied by a SCSI CDB (for sizing the response).
fn cdb_transfer(cdb: &[u8]) -> (usize, bool) {
    let b = |i: usize| *cdb.get(i).unwrap_or(&0) as usize;
    let be16 = |i: usize| (b(i) << 8) | b(i + 1);
    let be32 = |i: usize| (b(i) << 24) | (b(i + 1) << 16) | (b(i + 2) << 8) | b(i + 3);
    match b(0) {
        0x00 | 0x1b | 0x1e | 0x2b | 0x35 => (0, false), // TUR, START/STOP, PREVENT, SEEK, SYNC
        0x12 => (b(4), true),                            // INQUIRY
        0x25 => (8, true),                               // READ CAPACITY(10)
        0x28 => (be16(7) * 2048, true),                  // READ(10)
        0xa8 => (be32(6) * 2048, true),                  // READ(12)
        0x43 => (be16(7), true),                         // READ TOC
        0x1a => (b(4), true),                            // MODE SENSE(6)
        0x5a => (be16(7), true),                         // MODE SENSE(10)
        0x03 => (b(4), true),                            // REQUEST SENSE
        0x46 | 0x4a => (be16(7), true),                  // GET CONFIG / GET EVENT STATUS
        0x42 => (be16(7), true),                         // READ SUB-CHANNEL
        0x51 => (be16(7), true),                         // READ DISC INFO
        _ => (0xffff, true),
    }
}

/// Handle to a running IUSB virtual-media serve session — reuses vmedia::Mount so
/// the GUI treats Quanta and ATEN media identically.
pub type Mount = crate::vmedia::Mount;

/// Connect, authenticate, and serve `iso_path` as a virtual CD-ROM over IUSB.
/// The BMC only issues SCSI once the managed host reads the CD (boot/mount); the
/// caller must also send IVTP MEDIA_STATE(24,1) on the :7578 KVM channel to attach.
pub fn mount(host: &str, port: u16, token: &str, instance: u8, iso_path: &str)
    -> std::io::Result<Mount>
{
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let mut scsi = crate::vmedia::Scsi::from_iso(iso_path)?;
    let size = scsi.image_size();
    let sock = connect_cdrom(host, port, token, instance)?;

    let stop = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(crate::vmedia::Stats::default());
    let (stop2, stats2) = (stop.clone(), stats.clone());
    let mut sock = sock;

    let handle = std::thread::spawn(move || {
        while !stop2.load(Ordering::SeqCst) {
            let req = match read_packet(&mut sock) {
                Ok(p) => p,
                Err(_) => break,
            };
            // The SCSI CDB is at packet offset 41 = payload offset 9.
            if req.payload.len() < 9 { continue; }
            let cdb = &req.payload[9..];
            let (alloc, data_in) = cdb_transfer(cdb);
            let (mut out, status) = scsi.execute(cdb, alloc, data_in);
            if out.len() > alloc && alloc > 0 { out.truncate(alloc); }
            stats2.commands.fetch_add(1, Ordering::Relaxed);
            if matches!(cdb.first(), Some(0x28) | Some(0xa8)) {
                stats2.reads.fetch_add(1, Ordering::Relaxed);
            }
            stats2.bytes.fetch_add(out.len() as u64, Ordering::Relaxed);

            // Response = copy of the request's first 62 bytes (IUSB header + SCSI
            // header), the data length as int32 at offset 57, then the SCSI data at
            // offset 61. (Matches ExecuteSCSICmd in libjavacdromwrapper.so.)
            let mut resp = Vec::with_capacity(61 + out.len());
            resp.extend_from_slice(&req.header);              // [0..32]
            let pcopy = req.payload.len().min(30);
            resp.extend_from_slice(&req.payload[..pcopy]);    // [32..62]
            resp.resize(61, 0);                               // keep [0..61]
            resp[57..61].copy_from_slice(&(out.len() as u32).to_le_bytes());
            let _ = status; // SCSI status rides in the copied sense area / data
            resp.extend_from_slice(&out);                     // data at [61..]
            // Update the IUSB dataPacketLen and header checksum for the response.
            let dpl = (resp.len() - 32) as u32;
            resp[12..16].copy_from_slice(&dpl.to_le_bytes());
            resp[11] = 0;
            let sum: u32 = resp[0..32].iter().map(|&x| x as u32).sum();
            resp[11] = (0u8).wrapping_sub((sum & 0xff) as u8);

            if sock.write_all(&resp).is_err() { break; }
            let _ = sock.flush();
        }
    });

    Ok(crate::vmedia::Mount::from_parts(stop, handle, iso_path.to_string(), size, stats))
}

fn ioerr(m: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, m)
}
