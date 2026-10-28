//! AMI MegaRAC SP-X H5Viewer console: IVTP over a WebSocket.
//!
//! The protocol underneath is the same IVTP the Java JViewer speaks (see
//! `families/quanta/kvm.rs`) — identical 8-byte header and command numbers,
//! identical AST video and IUSB HID packets. What changed is the transport and
//! the handshake: instead of a raw socket on :7578 it is `wss://<host>/kvm` with
//! the `binary` subprotocol, and the validate packet grew from 172 bytes to 438.
//!
//! Wire framing — IVTPPktHdr, 8 bytes little-endian:
//!   [type u16][pktSize u32][status u16]  then `pktSize` payload bytes.
//! WebSocket message boundaries mean nothing: headers straddle them freely, so
//! everything is fed through one reassembly buffer.
//!
//! Handshake (BMC speaks first):
//!   BMC -> CONNECTION_ALLOWED(23)
//!   we  -> VALIDATE_VIDEO_SESSION(18), status 1, 438-byte body
//!   we  -> RESUME_REDIRECTION(6)
//!  (BMC -> KVM_SHARING(32) status 2 while it asks whoever holds the console)
//!   BMC -> VALIDATED_VIDEO_SESSION(19): payload[0] == 1 is valid
//!   BMC -> VIDEO_PACKETS(25) stream
//!
//! Ported from the BMC's own `viewer.min.js`. See docs/ASROCK-SPX.md.

use crate::families::quanta::kvm::{sharing_event, Sharing};
use crate::ws::{self, WebSocket};
use std::time::{Duration, Instant};

// IVTP message types, as the vendor client names them. The whole table is kept
// rather than only the handful that are sent: the BMC sends several of these
// unprompted, and reading a trace without the table means deriving it from the
// vendor client all over again.
#[allow(dead_code)]
mod cmd {
    pub const SEND_HID_PACKET: u16 = 1;
    pub const REFRESH_VIDEO_SCREEN: u16 = 5;
    pub const RESUME_REDIRECTION: u16 = 6;
    pub const STOP_SESSION_IMMEDIATE: u16 = 8;
    pub const GET_FULL_SCREEN: u16 = 11;
    pub const VALIDATE_VIDEO_SESSION: u16 = 18;
    pub const VALIDATED_VIDEO_SESSION: u16 = 19;
    pub const GET_WEB_TOKEN: u16 = 21;
    pub const CONNECTION_ALLOWED: u16 = 23;
    pub const MEDIA_STATE: u16 = 24;
    pub const VIDEO_PACKETS: u16 = 25;
    pub const POWER_STATUS: u16 = 34;
    pub const KVM_MEDIA_INFO: u16 = 38;
    pub const MEDIA_LICENSE_STATUS: u16 = 53;
    pub const KEEP_ALIVE_PKT: u16 = 57;
    pub const CONNECTION_COMPLETE_PKT: u16 = 58;
    pub const FPS_DIFF: u16 = 60;
}

// The three a caller has to match on.
pub const CMD_VIDEO_PACKETS: u16 = cmd::VIDEO_PACKETS;
pub const CMD_KEEP_ALIVE_PKT: u16 = cmd::KEEP_ALIVE_PKT;
pub const CMD_STOP_SESSION_IMMEDIATE: u16 = cmd::STOP_SESSION_IMMEDIATE;

/// The `VALIDATED_VIDEO_SESSION` header status for the first console on the
/// BMC — the one whose arrival plugs in the virtual keyboard and mouse.
const STATUS_FIRST_KVM_SESSION: u16 = 2;
/// How long both vendor viewers hold off after a console opens on a BMC in USB
/// power-save mode (`DEFAULT_PROCESSING_TIME`, and the older viewer's `B`).
const HID_SETTLE: Duration = Duration::from_secs(5);
const IUSB_DEVICE_KEYBD: u8 = 48;

// Field widths in the validate packet, named as the vendor does.
const SSI_HASH_SIZE: usize = 129;
const CLIENT_USERNAME_LENGTH: usize = 129;
const CLIENT_OWN_IP_LENGTH: usize = 65;
const CLIENT_OWN_MAC_LENGTH: usize = 49;

/// `VALIDATED_VIDEO_SESSION` verdicts, so a refusal can say what was wrong.
fn validate_reason(code: u8) -> &'static str {
    match code {
        0 => "invalid session (the KVM token was rejected)",
        2 => "insufficient privilege, or KVM is disabled for this user",
        // Not the client address: every value tried, including the one the BMC
        // itself reports, gets this.
        3 => "invalid session info",
        8 => "session unregistered",
        _ => "refused",
    }
}

fn ioerr<S: AsRef<str>>(m: S) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, m.as_ref().to_string())
}

/// An IVTP header plus its payload.
pub struct Frame {
    pub ty: u16,
    pub status: u16,
    pub payload: Vec<u8>,
}

pub fn header(ty: u16, size: u32, status: u16) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0..2].copy_from_slice(&ty.to_le_bytes());
    b[2..6].copy_from_slice(&size.to_le_bytes());
    b[6..8].copy_from_slice(&status.to_le_bytes());
    b
}

/// A NUL-padded fixed-width string field.
fn cstr(out: &mut Vec<u8>, s: &str, width: usize) {
    let b = s.as_bytes();
    let n = b.len().min(width.saturating_sub(1));
    out.extend_from_slice(&b[..n]);
    out.resize(out.len() + width - n, 0);
}

/// The console connection: a WebSocket plus the reassembly buffer that turns
/// its messages back into a byte stream of IVTP frames.
pub struct Console {
    pub sock: WebSocket,
    buf: Vec<u8>,
    /// How far into `buf` the parser has consumed.
    pos: usize,
    /// Set once the video session is validated. The vendor client guards its
    /// teardown packet with the same flag (`window._video.running`), and the
    /// guard matters: see `close`.
    running: bool,
    /// Which viewer generation's layouts apply; see `power_save`.
    legacy: bool,
    reconnect: bool,
    /// When the BMC validated the session, and whether it was the first one.
    opened: Option<Instant>,
    first_session: bool,
    /// When keyboard input can reach the host: unset until `KVM_MEDIA_INFO`
    /// says whether the BMC is in power-save mode.
    hid_ready: Option<Instant>,
    /// Keyboard reports waiting for `hid_ready`.
    held: Vec<Vec<u8>>,
}

/// `power_save_mode` from a `KVM_MEDIA_INFO` payload, at the offset each viewer
/// generation reads it from. The older viewer always reads a retry count and
/// interval first and has floppy fields the newer one dropped; the newer reads
/// the retry fields only when the BMC advertises `KVM_SESSION_RECONNECT`.
fn power_save(payload: &[u8], legacy: bool, reconnect: bool) -> Option<bool> {
    let at = if legacy { 50 } else if reconnect { 42 } else { 34 };
    let b = payload.get(at..at + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) == 1)
}

impl Console {
    /// Read the next IVTP frame, waiting up to the socket's poll timeout for
    /// more data. `Ok(None)` means nothing arrived, not that the stream ended.
    pub fn next_frame(&mut self) -> std::io::Result<Option<Frame>> {
        loop {
            if let Some(f) = self.take_frame() {
                if f.ty == cmd::KVM_MEDIA_INFO {
                    self.media_info(&f.payload);
                }
                return Ok(Some(f));
            }
            match self.sock.poll()? {
                Some(msg) => self.buf.extend_from_slice(&msg),
                None => return Ok(None),
            }
        }
    }

    /// Pull one complete frame out of the buffer, if there is one.
    fn take_frame(&mut self) -> Option<Frame> {
        if self.buf.len() - self.pos < 8 {
            self.compact();
            return None;
        }
        let h = &self.buf[self.pos..self.pos + 8];
        let ty = u16::from_le_bytes([h[0], h[1]]);
        let size = u32::from_le_bytes([h[2], h[3], h[4], h[5]]) as usize;
        let status = u16::from_le_bytes([h[6], h[7]]);
        if size > 32 * 1024 * 1024 {
            // Desynchronised: there is no resync marker in IVTP, so the only
            // honest thing is to drop the connection rather than emit garbage.
            self.buf.clear();
            self.pos = 0;
            return None;
        }
        if self.buf.len() - self.pos < 8 + size {
            self.compact();
            return None;
        }
        let payload = self.buf[self.pos + 8..self.pos + 8 + size].to_vec();
        self.pos += 8 + size;
        Some(Frame { ty, status, payload })
    }

    /// Drop consumed bytes once they are worth reclaiming. Video frames run to
    /// hundreds of kilobytes, so this keeps the buffer from growing without
    /// bound over a long session.
    fn compact(&mut self) {
        if self.pos > 64 * 1024 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }

    pub fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.sock.send_binary(data)
    }

    /// Decide, from the first `KVM_MEDIA_INFO`, when keyboard input can reach
    /// the host. In USB power-save mode the BMC plugs its virtual keyboard and
    /// mouse into the host only when the first console opens, and the host
    /// takes seconds to see them: on 192.0.2.75, a Proxmox host, keys sent 2 s
    /// after validation vanished and keys sent at 6 s arrived, with the host
    /// setting the new keyboard's LEDs at 3 s in between. The newer viewer waits
    /// only for the first session, as later ones find the devices attached; the
    /// older one asks whether it holds the console, which a lone session does.
    fn media_info(&mut self, payload: &[u8]) {
        if self.hid_ready.is_some() {
            return;
        }
        let settle = power_save(payload, self.legacy, self.reconnect) == Some(true)
            && (self.legacy || self.first_session);
        let opened = self.opened.unwrap_or_else(Instant::now);
        self.hid_ready = Some(if settle { opened + HID_SETTLE } else { Instant::now() });
    }

    /// Whether keyboard input would still be lost: until `KVM_MEDIA_INFO` has
    /// answered, or `HID_SETTLE` has passed without it, and then until the
    /// host has had time to attach the keyboard.
    pub fn hid_waiting(&self) -> bool {
        let Some(opened) = self.opened else { return false };
        Instant::now() < self.hid_ready.unwrap_or(opened + HID_SETTLE)
    }

    /// Whether the BMC is known to be attaching the keyboard right now, which
    /// is worth telling the user; the brief wait before `KVM_MEDIA_INFO` is not.
    pub fn hid_attaching(&self) -> bool {
        self.hid_ready.is_some_and(|t| Instant::now() < t)
    }

    /// Send a packet from the input side. While `hid_waiting`, keyboard reports
    /// are held for `flush_input` rather than lost — the vendor viewers only
    /// show a notice — and mouse reports are dropped, as each absolute report
    /// supersedes the last. Anything else goes straight out.
    pub fn send_input(&mut self, packet: Vec<u8>) -> std::io::Result<()> {
        let hid = packet.len() > 25 && u16::from_le_bytes([packet[0], packet[1]]) == cmd::SEND_HID_PACKET;
        if hid && self.hid_waiting() {
            if packet[25] == IUSB_DEVICE_KEYBD {
                self.held.push(packet);
            }
            return Ok(());
        }
        self.flush_input()?;
        self.send(&packet)
    }

    /// Send held keyboard reports, in order, once the host can take them.
    pub fn flush_input(&mut self) -> std::io::Result<()> {
        if self.held.is_empty() || self.hid_waiting() {
            return Ok(());
        }
        for p in std::mem::take(&mut self.held) {
            self.send(&p)?;
        }
        Ok(())
    }

    /// Ask for a full screen — the BMC otherwise sends only what changed.
    pub fn request_full_screen(&mut self) -> std::io::Result<()> {
        self.send(&header(cmd::GET_FULL_SCREEN, 0, 1))
    }

    /// Answer a keep-alive. The BMC drops a console that does not.
    pub fn keep_alive(&mut self) -> std::io::Result<()> {
        self.send(&header(CMD_KEEP_ALIVE_PKT, 0, 0))
    }

    /// Close the console cleanly. The BMC counts an abandoned socket as a live
    /// session until it times out, which blocks the next connection.
    pub fn close(&mut self) {
        let _ = self.send(&header(CMD_STOP_SESSION_IMMEDIATE, 0, 0));
        self.sock.close();
    }
}

/// Open `wss://<host>/kvm` and run the video-session handshake.
///
/// `cookie` is the `QSESSIONID=...` pair; `launch` carries the per-launch token
/// and, importantly, the client address *as the BMC sees it* — a NATted client
/// that sends its own socket address here is refused with "invalid session info".
/// `progress` hears about a wait on another user's say-so.
pub fn connect(host: &str, cookie: &str, launch: &crate::families::spx::Launch,
               progress: &dyn Fn(&str))
    -> std::io::Result<Console>
{
    // Without the `binary` subprotocol the BMC base64-encodes every video frame.
    // Never without the cookie: the BMC's proxy refuses the hand-off, and a
    // refused hand-off leaves it refusing every later one until it is reset.
    if cookie.is_empty() {
        return Err(ioerr("no web session for the console"));
    }
    let mut sock = ws::connect_with(host, 443, "/kvm", Some(cookie), Some("binary"))?;
    sock.set_poll_timeout(Duration::from_millis(200)).ok();
    let mut c = Console {
        sock, buf: Vec::new(), pos: 0, running: false,
        legacy: launch.legacy_packet, reconnect: launch.reconnect,
        opened: None, first_session: false, hid_ready: None, held: Vec::new(),
    };

    // 1) the BMC greets us
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        if std::time::Instant::now() > deadline {
            return Err(ioerr("no greeting from the console within 15s"));
        }
        match c.next_frame()? {
            Some(f) if f.ty == cmd::CONNECTION_ALLOWED => break,
            Some(f) if f.ty == CMD_STOP_SESSION_IMMEDIATE => {
                return Err(ioerr(format!("console refused the connection (stop status {})", f.status)))
            }
            Some(_) | None => continue,
        }
    }

    // 2) VALIDATE_VIDEO_SESSION: all fixed-width NUL-padded fields, 438 bytes
    //    on the newer viewer and 373 on the older, which stops at the MAC. The
    //    username and MAC are what the browser client sends when it cannot
    //    know them, and the BMC does not check either.
    let mut body = Vec::with_capacity(438);
    body.push(0u8);
    cstr(&mut body, &launch.token, SSI_HASH_SIZE);
    cstr(&mut body, &launch.client_ip, CLIENT_OWN_IP_LENGTH);
    cstr(&mut body, "domain/username", CLIENT_USERNAME_LENGTH);
    cstr(&mut body, "00-00-00-00-00-00", CLIENT_OWN_MAC_LENGTH);
    if !launch.legacy_packet {
        cstr(&mut body, &launch.server_ip, CLIENT_OWN_IP_LENGTH);
    }

    let mut pkt = Vec::with_capacity(8 + 8 + body.len() + 8);
    // Both vendor viewers put a bare CONNECTION_COMPLETE_PKT header (size 0,
    // status 1) in front when the BMC advertises KVM_SESSION_RECONNECT
    // (`1 == window.reconnect_enabled`). The first port left it out.
    if launch.reconnect {
        pkt.extend_from_slice(&header(cmd::CONNECTION_COMPLETE_PKT, 0, 1));
    }
    pkt.extend_from_slice(&header(cmd::VALIDATE_VIDEO_SESSION, body.len() as u32, 1));
    pkt.extend_from_slice(&body);
    // 3) RESUME_REDIRECTION, in the same message as the vendor client sends it.
    pkt.extend_from_slice(&header(cmd::RESUME_REDIRECTION, 0, 0));
    c.send(&pkt)?;

    // 4) the verdict
    let mut deadline = std::time::Instant::now() + Duration::from_secs(15);
    // The holder's answer to our access request, if the BMC had to ask one.
    let mut verdict = None;
    loop {
        if std::time::Instant::now() > deadline {
            // Withdraw, or the BMC keeps prompting the holder on our behalf.
            c.close();
            return Err(ioerr(match verdict {
                Some(v) => format!("the console never answered the validate packet ({v})"),
                None => "the console never answered the validate packet".to_string(),
            }));
        }
        match c.next_frame()? {
            Some(f) if f.ty == cmd::VALIDATED_VIDEO_SESSION => {
                let code = f.payload.first().copied().unwrap_or(0);
                if code == 1 {
                    c.running = true;
                    c.opened = Some(Instant::now());
                    c.first_session = f.status == STATUS_FIRST_KVM_SESSION;
                    return Ok(c);
                }
                return Err(ioerr(format!("console session {}", validate_reason(code))));
            }
            Some(f) if f.ty == CMD_STOP_SESSION_IMMEDIATE => {
                return Err(ioerr(match verdict {
                    Some(v) => format!("console stopped the session: {v}"),
                    None => format!("console stopped the session (status {})", f.status),
                }))
            }
            Some(f) => match sharing_event(f.ty, f.status, &f.payload) {
                // Someone already holds the console — or held it seconds ago:
                // a just-closed session is not always reaped yet. The BMC asks
                // the holder and answers our validate only once it has, or once
                // its own ~30 s prompt runs out (34 s, measured on an ASUS
                // ESC8000A-E13), so outwait that rather than give up first.
                Some(Sharing::Waiting { user }) => {
                    deadline = std::time::Instant::now() + Duration::from_secs(45);
                    progress(&if user.is_empty() {
                        "waiting for the current user to allow access…".to_string()
                    } else {
                        format!("waiting for {user} to allow access…")
                    });
                }
                Some(Sharing::Verdict(v)) => {
                    verdict = Some(v);
                    progress(v);
                }
                _ => {}
            },
            None => continue,
        }
    }
}

// ---------- video ----------

/// Reassembles `VIDEO_PACKETS` fragments into whole AST frames.
///
/// A frame starts with an 86-byte header (of which the vendor client reads 72)
/// carrying the resolution, the JPEG table selectors and the compressed size;
/// every packet, first or not, begins with 2 bytes that are not part of the
/// payload. Fragments follow until `CompressSize` bytes have arrived — the
/// length is the frame boundary, there is no end marker.
#[derive(Default)]
pub struct VideoAssembler {
    header: Option<FrameHeader>,
    data: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub struct FrameHeader {
    pub width: usize,
    pub height: usize,
    pub jpeg_table: usize,
    /// Byte 45: chroma quantised with the luma tables.
    pub yuv_mapping: bool,
    pub advance_table: usize,
    pub mode420: bool,
    pub compressed_size: usize,
}

fn parse_frame_header(h: &[u8]) -> Option<FrameHeader> {
    if h.len() < 86 {
        return None;
    }
    let w = u16::from_le_bytes([h[4], h[5]]) as usize;
    let ht = u16::from_le_bytes([h[6], h[7]]) as usize;
    if w == 0 || ht == 0 || w > 4096 || ht > 4096 {
        return None;
    }
    Some(FrameHeader {
        width: w,
        height: ht,
        jpeg_table: h[44] as usize,
        yuv_mapping: h[45] == 1,
        advance_table: h[47] as usize,
        mode420: h[55] != 0,
        compressed_size: u32::from_le_bytes([h[69], h[70], h[71], h[72]]) as usize,
    })
}

impl VideoAssembler {
    /// Feed one `VIDEO_PACKETS` payload. Returns a complete frame when the last
    /// fragment of one arrives.
    pub fn push(&mut self, payload: &[u8]) -> Option<(FrameHeader, Vec<u8>)> {
        if payload.len() < 2 {
            return None;
        }
        let rest = &payload[2..];
        let rest = if self.header.is_none() {
            // Start of a frame: the 86-byte header comes first.
            let h = parse_frame_header(rest)?;
            self.header = Some(h);
            self.data.clear();
            if rest.len() < 86 {
                return None;
            }
            &rest[86..]
        } else {
            rest
        };
        self.data.extend_from_slice(rest);
        let h = self.header?;
        if h.compressed_size > 0 && self.data.len() >= h.compressed_size {
            self.data.truncate(h.compressed_size);
            self.header = None;
            return Some((h, std::mem::take(&mut self.data)));
        }
        None
    }
}

// ---------- input ----------

/// Keyboard and mouse packets are byte-identical to the JViewer's, so they come
/// from one implementation rather than two that have to be kept in step.
pub use crate::families::quanta::kvm::key_packet;

#[cfg(test)]
mod tests {
    use super::power_save;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn power_save_on_the_older_viewer() {
        // KVM_MEDIA_INFO from 192.0.2.75 (power-save on), as captured; only
        // its first 64 of 66 bytes were logged.
        let p = hex("030000000a0000000201000000000000000000000000000000000400000004000000\
                     04000000682c50b500000000000000000100000001000000010000000100");
        assert_eq!(power_save(&p, true, false), Some(true));
        let mut off = p.clone();
        off[50] = 0;
        assert_eq!(power_save(&off, true, false), Some(false));
        assert_eq!(power_save(&p[..40], true, false), None);
    }

    #[test]
    fn power_save_on_the_newer_viewer() {
        // Its read order: [retry u32, interval u32 — only with reconnect] u8 u8
        // u32×4 (num_cd last) u32 (num_hd) u32×4 (power_save_mode last) u32 u32.
        let body = |reconnect: bool| {
            let mut b = Vec::new();
            if reconnect {
                b.extend_from_slice(&[3, 0, 0, 0, 10, 0, 0, 0]);
            }
            b.extend_from_slice(&[2, 1]);
            for v in [0u32, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1] {
                b.extend_from_slice(&v.to_le_bytes());
            }
            b
        };
        assert_eq!(power_save(&body(true), false, true), Some(true));
        assert_eq!(power_save(&body(false), false, false), Some(true));
    }
}
