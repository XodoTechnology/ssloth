//! AMI JViewer "IVTP" KVM client for Quanta/AMI MegaRAC BMCs (TCP :7578).
//!
//! Reverse-engineered from the decompiled JViewer applet (see
//! docs/QUANTA-JVIEWER.md). The handshake is verified live against the
//! Quanta; the per-launch 16-byte kvmToken is the one input this needs (delivered
//! in the JViewer JNLP arguments).
//!
//! Wire framing — IVTPPktHdr, 8 bytes little-endian:
//!   [type u16][pktSize u32][status u16]  then `pktSize` payload bytes.
//!
//! Handshake (BMC speaks first):
//!   BMC -> SESSION_ACCEPTED(23)
//!   we  -> GET_WEB_TOKEN(21)          + webSessionToken bytes
//!   we  -> VALIDATE_VIDEO_SESSION(18) + 172-byte body (0x00, 16-byte kvmToken,
//!                                       zero-pad to 107, client-IP ascii, pad)
//!   we  -> RESUME_REDIRECTION(6)
//!   BMC -> VALIDATE_VIDEO_SESSION_RESPONSE(19): body byte != 0 = valid, 0 = invalid
//!   BMC -> VIDEO_FRAGMENT(25) stream  (AST2300; decode mirrors ast2100.rs)

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

// IVTP message types (subset — full list in IVTPPktHdr).
pub const HID_PKT: u16 = 1;
pub const RESUME_REDIRECTION: u16 = 6;
pub const STOP_SESSION: u16 = 8;
pub const VALIDATE_VIDEO_SESSION: u16 = 18;
pub const VALIDATE_VIDEO_SESSION_RESPONSE: u16 = 19;
pub const GET_WEB_TOKEN: u16 = 21;
pub const SESSION_ACCEPTED: u16 = 23;
pub const VIDEO_FRAGMENT: u16 = 25;
/// Recorded for completeness; power is driven over IPMI instead.
#[allow(dead_code)]
pub const POWER_STATUS: u16 = 34;
pub const MEDIA_STATE: u16 = 24;

pub const KVM_PORT: u16 = 7578;

fn hdr(t: u16, size: u32, status: u16) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0..2].copy_from_slice(&t.to_le_bytes());
    b[2..6].copy_from_slice(&size.to_le_bytes());
    b[6..8].copy_from_slice(&status.to_le_bytes());
    b
}

fn read_exact_to(s: &mut TcpStream, n: usize) -> std::io::Result<Vec<u8>> {
    let mut b = vec![0u8; n];
    s.read_exact(&mut b)?;
    Ok(b)
}

/// One decoded IVTP frame: (type, status, payload).
pub struct Frame {
    pub ty: u16,
    pub status: u16,
    pub payload: Vec<u8>,
}

/// Read one IVTP frame (8-byte header + payload).
pub fn read_frame(s: &mut TcpStream) -> std::io::Result<Frame> {
    let h = read_exact_to(s, 8)?;
    let ty = u16::from_le_bytes([h[0], h[1]]);
    let size = u32::from_le_bytes([h[2], h[3], h[4], h[5]]) as usize;
    let status = u16::from_le_bytes([h[6], h[7]]);
    let payload = if size > 0 && size < 16 * 1024 * 1024 { read_exact_to(s, size)? } else { Vec::new() };
    Ok(Frame { ty, status, payload })
}

/// An authenticated IVTP KVM connection, past the video-session validation.
/// Some fields are unread: they record the wire format so a future change
/// does not have to re-derive it from the vendor client.
#[allow(dead_code)]
pub struct KvmConn {
    pub sock: TcpStream,
    pub client_ip: String,
}

/// Connect to :7578 and run the video-session handshake.
///
/// `web_token` is the AMI web SESSION_COOKIE (from `quanta::login`); `kvm_token`
/// is the 16-byte per-launch token from the JViewer JNLP. Returns the live socket
/// positioned at the start of the VIDEO_FRAGMENT stream, or an error if the BMC
/// rejects the session (body byte 0).
pub fn connect(host: &str, web_token: &str, kvm_token: &[u8]) -> std::io::Result<KvmConn> {
    let mut sock = crate::net::connect(host, KVM_PORT, None)?;
    sock.set_nodelay(true).ok();
    sock.set_read_timeout(Some(Duration::from_secs(8))).ok();
    let client_ip = sock.local_addr()?.ip().to_string();

    // 1) BMC greeting: SESSION_ACCEPTED(23)
    let g = read_frame(&mut sock)?;
    if g.ty != SESSION_ACCEPTED {
        return Err(ioerr(format!("unexpected greeting type {} (want 23)", g.ty)));
    }

    // 2) GET_WEB_TOKEN(21) + web session cookie
    sock.write_all(&hdr(GET_WEB_TOKEN, web_token.len() as u32, 0))?;
    sock.write_all(web_token.as_bytes())?;

    // 3) VALIDATE_VIDEO_SESSION(18): 172-byte packet
    let mut v = vec![0u8; 172];
    v[0..8].copy_from_slice(&hdr(VALIDATE_VIDEO_SESSION, 172, 0));
    v[8] = 0x00;
    let n = kvm_token.len().min(16);
    v[9..9 + n].copy_from_slice(&kvm_token[..n]);
    let ip = client_ip.as_bytes();
    let ipn = ip.len().min(172 - 107);
    v[107..107 + ipn].copy_from_slice(&ip[..ipn]);
    sock.write_all(&v)?;

    // 4) RESUME_REDIRECTION(6)
    sock.write_all(&hdr(RESUME_REDIRECTION, 0, 0))?;
    sock.flush()?;

    // 5) VALIDATE_VIDEO_SESSION_RESPONSE(19): body != 0 = valid
    loop {
        let f = read_frame(&mut sock)?;
        match f.ty {
            VALIDATE_VIDEO_SESSION_RESPONSE => {
                if f.payload.first().copied().unwrap_or(0) == 0 {
                    return Err(ioerr("IVTP video session rejected (invalid kvmToken)".into()));
                }
                return Ok(KvmConn { sock, client_ip });
            }
            STOP_SESSION => return Err(ioerr(format!("BMC stopped session (status {})", f.status))),
            // ignore any control chatter before the validate response
            _ => continue,
        }
    }
}

fn ioerr(m: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, m)
}

/// IVTP MEDIA_STATE(24): tell the BMC to attach (on=1) / detach (0) redirected
/// virtual media to the managed host, so the host enumerates the USB CD.
pub fn media_state_packet(on: bool) -> Vec<u8> {
    hdr(MEDIA_STATE, 0, on as u16).to_vec()
}

// --- HID input (IVTP HID_PKT) ---
// The AMI "USB message" (hid/USBKeyboardRep, USBMouseRep) wraps an HID report:
//   [0..8]  IVTP header: type=1 (HID_PKT), size=(33+report_len), status=0
//   [8..16] signature "IUSB    "
//   [16]=1 [17]=0 [18]=32 [19]=checksum(-sum of bytes[8..40])
//   [20..24]=devclass LE  [24]=0 [25]=p25 [26]=p26 [27]=0x80 [28]=2 [29]=p29
//   [30..32]=0  [32..36]=SeqNum LE  [36..40]=0  [40]=report_len  [41..]=report
// Per-device constants (from the decompiled reports):
//   keyboard: devclass=9, p25=48, p26=16, p29=0, report=8 bytes
//   mouse:    devclass=7, p25=49, p26=32, p29=1, report=6 bytes
fn ivtp_usb_msg(devclass: u32, p25: u8, p26: u8, p29: u8, seq: u32, report: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 41 + report.len()];
    b[0..2].copy_from_slice(&HID_PKT.to_le_bytes());
    b[2..6].copy_from_slice(&((33 + report.len()) as u32).to_le_bytes());
    b[8..16].copy_from_slice(b"IUSB    ");
    b[16] = 1; b[17] = 0; b[18] = 32;
    b[20..24].copy_from_slice(&devclass.to_le_bytes());
    b[24] = 0; b[25] = p25; b[26] = p26; b[27] = 0x80; b[28] = 2; b[29] = p29;
    b[32..36].copy_from_slice(&seq.to_le_bytes());
    b[40] = report.len() as u8;
    b[41..41 + report.len()].copy_from_slice(report);
    // checksum over bytes[8..40] into [19]
    let sum: u32 = b[8..40].iter().map(|&x| x as u32).sum();
    b[19] = (0u8).wrapping_sub((sum & 0xff) as u8);
    b
}

/// Keyboard HID_PKT: one key at a time. `hid` = USB HID usage code (0 on release),
/// `mods` = USB modifier bitmask (ctrl=1, shift=2, alt=4). Report is
/// [mods][flag=0][hid][0;5] (8 bytes), per USBKeyboardRep.
pub fn key_packet(hid: u8, down: bool, mods: u8, seq: u32) -> Vec<u8> {
    let report = [mods, 0, if down { hid } else { 0 }, 0, 0, 0, 0, 0];
    ivtp_usb_msg(9, 48, 16, 0, seq, &report)
}

/// Absolute mouse HID_PKT. `x`/`y` in 0..32767 device coords; `buttons` bit0=left,
/// bit1=right, bit2=middle; `wheel` signed. Report is [buttons][x u16][y u16][wheel]
/// (6 bytes), per USBMouseRep.ABSreport.
pub fn mouse_packet(x: u16, y: u16, buttons: u8, wheel: i8, seq: u32) -> Vec<u8> {
    let mut report = [0u8; 6];
    report[0] = buttons;
    report[1..3].copy_from_slice(&x.to_le_bytes());
    report[3..5].copy_from_slice(&y.to_le_bytes());
    report[5] = wheel as u8;
    ivtp_usb_msg(7, 49, 32, 1, seq, &report)
}

// ---------- console sharing (IVTP type 32 / 50) ----------
//
// When a second client connects, the BMC asks the one already in control.
// Both AMI viewers — the Java JViewer and the SP-X H5Viewer — speak this the
// same way (the constants are the H5Viewer's `an.*`):
//
//   type 32 KVM_SHARING / 50 SET_NEXT_MASTER, status low byte:
//     1 REQ_MASTER            asked of us: payload = name[64] + ip[65]
//     0 REQ_CANCEL, 3 TIMEOUT_TO_MASTER   the request went away
//     2 WAIT_SLAVE            we asked; the holder is being prompted
//     4 RESPONSE_TO_SLAVE     the verdict on our request, in the high byte
//   answers (high byte): 0 allowed, 1 denied, 2 partial (view only),
//     3 timed out, 6/8 blocked, 7 the holder reconnected
//
// Our answer echoes the requester's info back with status 1 + (answer << 8);
// a full grant goes on both 32 and 50, as the vendor sends it.

pub const KVM_SHARING: u16 = 32;
pub const SET_NEXT_MASTER: u16 = 50;

/// What a sharing message means for this client.
#[derive(Clone, Debug)]
pub enum Sharing {
    /// Another user wants the console. `full_access` is a type-50 request for
    /// full control from a user already viewing, which cannot be denied — only
    /// answered with full or view-only access.
    Request { user: String, addr: String, info: Vec<u8>, full_access: bool },
    /// A request we were asked about was withdrawn or timed out.
    Withdrawn,
    /// Our own request is waiting on the holder.
    Waiting { user: String },
    /// The holder's answer to our request.
    Verdict(&'static str),
}

pub fn sharing_event(ty: u16, status: u16, payload: &[u8]) -> Option<Sharing> {
    if ty != KVM_SHARING && ty != SET_NEXT_MASTER {
        return None;
    }
    let field = |a: usize, b: usize| {
        let s = payload.get(a..b.min(payload.len())).unwrap_or(&[]);
        let e = s.iter().position(|c| *c == 0).unwrap_or(s.len());
        String::from_utf8_lossy(&s[..e]).trim().to_string()
    };
    let (user, addr) = (field(0, 64), field(64, 129));
    Some(match (status & 0xFF, status >> 8) {
        (1, _) => Sharing::Request { user, addr, info: payload.to_vec(), full_access: ty == SET_NEXT_MASTER },
        (0, _) | (3, _) => Sharing::Withdrawn,
        (2, _) => Sharing::Waiting { user },
        (4, 0) => Sharing::Verdict("the other user gave you full access"),
        (4, 1) => Sharing::Verdict("the other user denied access"),
        (4, 2) => Sharing::Verdict("the other user allowed view-only access; input is ignored"),
        (4, 3) => Sharing::Verdict("the other user did not answer; the request timed out"),
        (4, 6) | (4, 8) => Sharing::Verdict("the other user is blocking access requests"),
        (4, 7) => Sharing::Verdict("the other user reconnected and kept the console"),
        (4, _) => Sharing::Verdict("the other user answered the access request"),
        _ => return None,
    })
}

/// How we answer a sharing request.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ShareAnswer {
    Full,
    ViewOnly,
    Deny,
}

/// The packets that answer a request whose payload was `info`.
pub fn sharing_reply(info: &[u8], answer: ShareAnswer) -> Vec<Vec<u8>> {
    let code: u16 = match answer {
        ShareAnswer::Full => 0,
        ShareAnswer::Deny => 1,
        ShareAnswer::ViewOnly => 2,
    };
    let packet = |ty: u16| {
        let mut p = Vec::with_capacity(8 + info.len());
        p.extend_from_slice(&ty.to_le_bytes());
        p.extend_from_slice(&(info.len() as u32).to_le_bytes());
        p.extend_from_slice(&(1 + (code << 8)).to_le_bytes());
        p.extend_from_slice(info);
        p
    };
    let mut out = vec![packet(KVM_SHARING)];
    if answer == ShareAnswer::Full {
        out.push(packet(SET_NEXT_MASTER));
    }
    out
}
