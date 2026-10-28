//! Avocent APCP + AVSP console on TCP 2068 — the Gigabyte/MergePoint console.
//!
//! Ported from the BMC's own `avctKVM.jar` (`com.avocent.kvm.b.*`), decompiled
//! into `~/.config/smc-ikvm/avocent-ref/`. The jar is string-obfuscated, so the
//! constants below were recovered by loading each class and reading its static
//! fields back out, then confirmed against a live capture.
//!
//! Two sockets, both to 2068, each opened the same way:
//!
//! **APCP** is the outer negotiation, 53 bytes each way:
//! ```text
//!   ->  "APCP" u32=53 u16=0x0100 u16=0 u8 channel u8 2 u8 34 u8 0
//!       u32 caps-we-accept(=5) u8 nonce-len(=32) 32 nonce bytes
//!   <-  "APCP" u32=53 u16=0x8100 u16=0  u8 major u8 minor
//!       u32 caps-granted u16 redirect-port u8 nonce-len + 32 nonce bytes
//! ```
//! `channel` is 3 for keyboard/mouse/control and 4 for video. Granted caps bit 0
//! means "stay in the clear", bit 2 means "start TLS now"; the reference prefers
//! bit 0 when both are offered, and this firmware only ever offers bit 2. A
//! non-zero redirect port means reconnect there first. The nonces are exchanged
//! and then, on this firmware, ignored — it answers with 32 zero bytes.
//!
//! **AVSP** is the protocol inside: an 8-byte header of `4 magic bytes,
//! u16 id, u16 total-length`, the length counting the header, everything
//! big-endian. The magic is decorative — the control channel stamps `"BEEF"`,
//! the video channel's status message four zero bytes and its data fragments
//! `de ad be ef`, and the reference reads past all three without looking.
//!
//! Session bring-up:
//! ```text
//!   channel 3:  -> 0x0102 Login Request (console credentials from the JNLP)
//!               <- 0x8305 User Login Response (status, appliance nonce)
//!   channel 4:  -> 0x0001 Video Channel Auth (client nonce, appliance nonce)
//!               <- 0x0084 Video Connect Status
//!   channel 3:  -> 0x030E Video Enable, 0x0302 Set Display Area,
//!                  0x0304 Scale 1:1, 0x0301 Screen Refresh
//!   channel 4:  <- 0x0086 ASpeed JPEG Video fragments
//! ```
//! The control packets go on channel 3 even though the video they turn on
//! arrives on channel 4; sending them on 4 is silently ignored.
//!
//! The video is the same ASPEED hardware codec the ATEN and AMI families use,
//! so it decodes through `ast2100::Decoder::decode_ast2300`. Keyboard input is
//! USB HID usage codes, as for ATEN, AMI and iLO. See docs/GIGABYTE-AVOCENT.md.

use super::Stream;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

/// APCP channel types.
const CH_KVM: u8 = 3;
const CH_VIDEO: u8 = 4;

/// AVSP message ids. The whole set the vendor client knows is kept, not just
/// the ones sent: the BMC pushes several of these unprompted, and reading a
/// trace without the table means deriving it from the jar all over again.
#[allow(dead_code)]
pub mod msg {
    // client -> BMC
    /// Video-stream acknowledgement. Id 0 is not a placeholder: the BMC's
    /// flow-control window is released by a message whose type really is zero.
    pub const VIDEO_ACK: u16 = 0x0000;
    pub const VIDEO_CHANNEL_AUTH: u16 = 0x0001;
    pub const LOGIN_REQUEST: u16 = 0x0102;
    pub const KEYBOARD_DATA: u16 = 0x0200;
    pub const MOUSE_ABSOLUTE: u16 = 0x0201;
    pub const KEYBOARD_LED_REQUEST: u16 = 0x0204;
    pub const MOUSE_RELATIVE: u16 = 0x0209;
    pub const SCREEN_REFRESH: u16 = 0x0301;
    pub const SET_DISPLAY_AREA: u16 = 0x0302;
    pub const SET_SCALE_1TO1: u16 = 0x0304;
    pub const VIDEO_ENABLE: u16 = 0x030E;
    pub const KEEP_ALIVE: u16 = 0x0400;
    pub const SET_POWER_STATE: u16 = 0x0424;
    pub const REQUEST_TEMP_CREDENTIALS: u16 = 0x0427;

    // BMC -> client
    pub const VIDEO_PACKET: u16 = 0x0080;
    pub const VIDEO_CONNECT_STATUS: u16 = 0x0084;
    pub const VIDEO_STOPPED: u16 = 0x0085;
    pub const ASPEED_JPEG_VIDEO: u16 = 0x0086;
    pub const TEXT_MODE_VIDEO: u16 = 0x0087;
    pub const COLOR_PALETTE: u16 = 0x0088;
    pub const FONT_TABLE: u16 = 0x0089;
    pub const RLE_VIDEO: u16 = 0x008B;
    pub const KEYBOARD_LED: u16 = 0x8100;
    pub const MOUSE_ACCEL_RESPONSE: u16 = 0x8102;
    pub const INPUT_RESOLUTION: u16 = 0x8200;
    pub const DISPLAY_RESOLUTION: u16 = 0x8201;
    pub const DVC_COLOR_MODE: u16 = 0x8204;
    pub const INPUT_RESOLUTION_ALT: u16 = 0x8206;
    pub const LOGIN_RESPONSE: u16 = 0x8300;
    pub const LOGIN_RESPONSE_EXT: u16 = 0x8305;
    pub const PROTOCOL_VERSION: u16 = 0x8302;
    pub const USER_PRIVILEGES: u16 = 0x8420;
    pub const SHARED_USERS: u16 = 0x8410;
    pub const AVAILABLE_SERVERS: u16 = 0x8430;
    pub const TEMP_CREDENTIALS: u16 = 0x8434;
}

/// Mouse button bits, as AWT button 1/2/3 map onto them in the reference.
pub const BTN_LEFT: u8 = 1;
pub const BTN_RIGHT: u8 = 2;
pub const BTN_MIDDLE: u8 = 4;

/// The reference sends one of these every 10 seconds on the KVM channel.
pub const KEEPALIVE_EVERY: Duration = Duration::from_secs(10);

fn ioerr<S: AsRef<str>>(m: S) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, m.as_ref().to_string())
}

fn would_block(e: &std::io::Error) -> bool {
    matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
}

/// `User Login Response` status codes, from the reference's own reason table.
fn login_reason(code: u8) -> &'static str {
    match code {
        1 | 2 => "bad login — the console credentials were rejected",
        // What a stale launch looks like: the web session that minted the
        // credentials has to still be logged in.
        3 => "access denied — the web session that minted these credentials is gone",
        4 | 12 => "the console is already in use",
        8 => "all console channels are in use",
        15 => "sharing denied",
        16 => "sharing request timed out",
        _ => "login refused",
    }
}

/// One AVSP message.
pub struct Frame {
    pub id: u16,
    pub payload: Vec<u8>,
}

/// One AVSP channel: a TLS stream plus the buffer that turns partial reads back
/// into whole frames.
///
/// The buffer is not an optimisation. Reads use a short socket timeout so one
/// thread can interleave sending with receiving, and a timeout that lands in
/// the middle of a frame would otherwise desynchronise the stream.
pub struct Chan {
    s: Stream,
    buf: Vec<u8>,
    pos: usize,
}

impl Chan {
    /// How long `poll` waits for data before reporting "nothing yet".
    pub fn set_poll_timeout(&mut self, d: Duration) {
        let _ = self.s.set_read_timeout(Some(d));
    }

    pub fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.s.write_all(data)?;
        self.s.flush()
    }

    /// End the channel. A dropped socket leaves the BMC holding the session.
    pub fn shutdown(&mut self) {
        self.s.shutdown();
    }

    /// Next frame, or `None` if none has arrived within the poll timeout.
    pub fn poll(&mut self) -> std::io::Result<Option<Frame>> {
        loop {
            if let Some(f) = self.take_frame()? {
                return Ok(Some(f));
            }
            let mut tmp = [0u8; 32768];
            match self.s.read(&mut tmp) {
                Ok(0) => return Err(ioerr("the console closed the connection")),
                Ok(n) => self.buf.extend_from_slice(&tmp[..n]),
                Err(ref e) if would_block(e) => return Ok(None),
                Err(e) => return Err(e),
            }
        }
    }

    fn take_frame(&mut self) -> std::io::Result<Option<Frame>> {
        if self.buf.len() - self.pos < 8 {
            self.compact();
            return Ok(None);
        }
        let h = &self.buf[self.pos..self.pos + 8];
        let id = u16::from_be_bytes([h[4], h[5]]);
        let total = u16::from_be_bytes([h[6], h[7]]) as usize;
        // The first four bytes are not a usable check. Three different magics
        // appear on one session — "BEEF" on the control channel, four zero
        // bytes on the video channel's status message and "\xde\xad\xbe\xef" on
        // its data fragments — and the reference reads straight past all of
        // them. Its length bounds are the only framing check there is, so they
        // are the desync detector here too.
        if !(16..=32768).contains(&total) {
            return Err(ioerr(format!(
                "AVSP stream desynchronised (frame id 0x{id:04x} claims {total} bytes)")));
        }
        if self.buf.len() - self.pos < total {
            self.compact();
            return Ok(None);
        }
        let payload = self.buf[self.pos + 8..self.pos + total].to_vec();
        self.pos += total;
        Ok(Some(Frame { id, payload }))
    }

    /// Drop consumed bytes once there are enough to be worth reclaiming.
    fn compact(&mut self) {
        if self.pos > 64 * 1024 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }
}

/// An AVSP frame: `"BEEF"`, the id, and the total length including this header.
pub fn packet(id: u16, payload: &[u8]) -> Vec<u8> {
    let total = (8 + payload.len()) as u16;
    let mut v = Vec::with_capacity(total as usize);
    v.extend_from_slice(b"BEEF");
    v.extend_from_slice(&id.to_be_bytes());
    v.extend_from_slice(&total.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// The video channel's own framing: no magic, a `1` in byte 4 to mark the
/// outbound direction, and an 8-bit id. Only the channel-auth packet is ever
/// sent this way.
fn video_packet(id: u8, payload: &[u8]) -> Vec<u8> {
    let total = (8 + payload.len()) as u16;
    let mut v = vec![0u8; 4];
    v.push(1);
    v.push(id);
    v.extend_from_slice(&total.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// Most control messages are a bare 8-byte payload, zero-padded.
fn small(id: u16, bytes: &[u8]) -> Vec<u8> {
    let mut p = [0u8; 8];
    p[..bytes.len()].copy_from_slice(bytes);
    packet(id, &p)
}

/// A key press or release. `hid` is a USB HID usage code, as for the ATEN, AMI
/// and iLO families — the reference's own Ctrl+Alt+Del macro is 224/226/76.
///
/// Note the inverted sense on the wire: byte 1 is 0 for *pressed*.
pub fn key_packet(hid: u8, down: bool) -> Vec<u8> {
    small(msg::KEYBOARD_DATA, &[0, if down { 0 } else { 1 }, 0, hid])
}

/// Absolute mouse position, in framebuffer pixels, with the buttons currently
/// held and a signed wheel delta (positive is scroll up).
pub fn mouse_packet(x: u16, y: u16, buttons: u8, wheel: i16) -> Vec<u8> {
    let (xb, yb, wb) = (x.to_be_bytes(), y.to_be_bytes(), wheel.to_be_bytes());
    small(msg::MOUSE_ABSOLUTE, &[0, buttons, xb[0], xb[1], yb[0], yb[1], wb[0], wb[1]])
}

pub fn keep_alive() -> Vec<u8> {
    small(msg::KEEP_ALIVE, &[])
}

/// Ask the console for a virtual-media login, valid for `secs`. This is how
/// the iDRAC 8 viewer's "Connect Virtual Media" logs in; the answer is
/// `TEMP_CREDENTIALS`, parsed by [`temp_credentials`].
pub fn request_temp_credentials(secs: u32) -> Vec<u8> {
    small(msg::REQUEST_TEMP_CREDENTIALS, &secs.to_be_bytes())
}

/// The user and password in a `TEMP_CREDENTIALS` payload: two NUL-padded
/// 32-byte fields.
pub fn temp_credentials(p: &[u8]) -> Option<(String, String)> {
    let field = |b: &[u8]| {
        let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
        String::from_utf8_lossy(&b[..n]).into_owned()
    };
    Some((field(p.get(..32)?), field(p.get(32..64)?)))
}

/// Acknowledge `n` video messages, on the video channel.
///
/// This is flow control, not politeness. The BMC sends exactly 96 video
/// packets and then stops — the stream simply ends, with no error and no
/// close — until they are acknowledged. The reference acknowledges after every
/// single packet (its threshold is 1) and so does this, because a larger window
/// buys nothing and the failure mode is a console that dies after a few seconds
/// of video with nothing to say why.
pub fn video_ack(n: u8) -> Vec<u8> {
    small(msg::VIDEO_ACK, &[n])
}

/// True for the video-stream messages the reference acknowledges: everything
/// the BMC pushes down the video channel except the connect-status reply, which
/// arrives before the stream starts and is not part of the window.
pub fn needs_ack(id: u16) -> bool {
    matches!(id,
        msg::VIDEO_PACKET | msg::VIDEO_STOPPED | msg::ASPEED_JPEG_VIDEO
        | msg::TEXT_MODE_VIDEO | msg::COLOR_PALETTE | msg::FONT_TABLE
        | msg::RLE_VIDEO | 0x0081 | 0x0082 | 0x0083 | 0x008A | 0x008D | 0x008F)
}

/// Ask for a full frame. The BMC otherwise sends only what changed.
pub fn screen_refresh() -> Vec<u8> {
    small(msg::SCREEN_REFRESH, &[])
}

/// Chassis power over the console channel. Unused: this BMC leaves IPMI-over-LAN
/// enabled and `avocent::power` goes that way, which needs no console session.
/// Kept because it documents the packet, which is not obvious from the wire.
#[allow(dead_code)]
pub fn power_packet(server: &str, state: u8) -> Vec<u8> {
    let name = server.as_bytes();
    let mut p = Vec::with_capacity(3 + name.len());
    p.extend_from_slice(&(name.len() as u16).to_be_bytes());
    p.extend_from_slice(name);
    p.push(state);
    packet(msg::SET_POWER_STATE, &p)
}

/// Open one console channel through the shared APCP negotiation.
///
/// The console announces protocol 2.34, which is what the reference's
/// `ProtocolAPCP` prints on connect; the media client announces 0.0 instead.
fn channel(host: &str, port: u16, kind: u8) -> std::io::Result<Chan> {
    let s = crate::families::avocent::apcp_channel(host, port, kind, (2, 34))?;
    Ok(Chan { s, buf: Vec::new(), pos: 0 })
}

/// The console login packet: two 97-byte length-prefixed fields, an 8-byte RIP
/// id this firmware leaves zero, two flag bytes, the client nonce the video
/// channel is later authenticated with, and the share mode.
fn login_packet(user: &str, pass: &str, client_nonce: u32) -> Vec<u8> {
    let field = |out: &mut Vec<u8>, s: &str| {
        let b = s.as_bytes();
        let n = b.len().min(96);
        out.push(n as u8);
        out.extend_from_slice(&b[..n]);
        out.resize(out.len() + 96 - n, 0);
    };
    let mut p = Vec::with_capacity(208);
    field(&mut p, user);
    field(&mut p, pass);
    p.extend_from_slice(&[0u8; 8]); // RIP id, unused on this firmware
    p.push(1); // the reference's non-shared connection flag
    p.push(0);
    p.extend_from_slice(&client_nonce.to_be_bytes());
    p.push(0); // share mode 0
    packet(msg::LOGIN_REQUEST, &p)
}

/// A live console: the control channel and the video channel.
///
/// The frame size is not held here — every video fragment carries it, and
/// `ast2100::Decoder` resizes itself when it changes, so a mode switch on the
/// host needs no bookkeeping on this side.
pub struct Console {
    pub kvm: Chan,
    pub video: Chan,
}

/// Turn the video stream on or off. Byte 1 is the stream index, always 1.
pub fn video_enable(on: bool) -> Vec<u8> {
    small(msg::VIDEO_ENABLE, &[on as u8, 1])
}

impl Console {
    /// Turn the video stream on and ask for a first full frame. Runs on the
    /// control channel even though the frames arrive on the video one.
    pub fn start_video(&mut self, w: u16, h: u16) -> std::io::Result<()> {
        self.kvm.send(&video_enable(true))?;
        let d = [(w >> 8) as u8, w as u8, (h >> 8) as u8, h as u8];
        self.kvm.send(&small(msg::SET_DISPLAY_AREA, &d))?;
        self.kvm.send(&small(msg::SET_SCALE_1TO1, &[]))?;
        self.kvm.send(&screen_refresh())
    }

    /// Hand the two channels to separate threads. They are independent sockets,
    /// so unlike the single-socket families each can simply block on its own
    /// reads; no interleaving of sends and polls is needed.
    pub fn split(self) -> (Chan, Chan) {
        (self.kvm, self.video)
    }

    /// Close both channels. The BMC accounts a console session and holds the
    /// channel until its own timeout if the sockets are merely dropped.
    pub fn close(&mut self) {
        let _ = self.kvm.send(&video_enable(false));
        self.kvm.shutdown();
        self.video.shutdown();
    }
}


/// Log in to the console and bring up the video channel.
///
/// `launch` must come from a web session that is still logged in — the BMC ties
/// the credentials to it and answers `ACCESS_DENIED` once it ends.
pub fn connect(host: &str, launch: &super::Launch) -> std::io::Result<Console> {
    let client_nonce = crate::families::avocent::nonce_u32();

    let mut kvm = channel(host, launch.km_port, CH_KVM)?;
    kvm.send(&login_packet(&launch.user, &launch.pass, client_nonce))?;

    // The login response comes first, but a burst of unsolicited state
    // (protocol version, server list, shared users) follows it immediately.
    let deadline = Instant::now() + Duration::from_secs(15);
    let appliance_nonce = loop {
        if Instant::now() > deadline {
            return Err(ioerr("the console never answered the login"));
        }
        let Some(f) = kvm.poll()? else { continue };
        if f.id != msg::LOGIN_RESPONSE && f.id != msg::LOGIN_RESPONSE_EXT {
            continue;
        }
        if f.payload.len() < 8 {
            return Err(ioerr("truncated login response"));
        }
        let status = f.payload[0];
        if status != 0 {
            // The V2 response names whoever holds the console: a length at 10,
            // the name from 11.
            let holder = (f.id == msg::LOGIN_RESPONSE_EXT)
                .then(|| f.payload.get(10).copied())
                .flatten()
                .and_then(|n| f.payload.get(11..11 + n as usize))
                .map(|b| String::from_utf8_lossy(b).trim_end_matches('\0').to_string())
                .filter(|s| !s.is_empty());
            return Err(ioerr(match holder {
                Some(h) => format!("{} by {h} (status {status})", login_reason(status)),
                None => format!("{} (status {status})", login_reason(status)),
            }));
        }
        break u32::from_be_bytes(f.payload[4..8].try_into().unwrap());
    };

    let mut video = channel(host, launch.v_port, CH_VIDEO)?;
    let mut auth = Vec::with_capacity(8);
    auth.extend_from_slice(&client_nonce.to_be_bytes());
    auth.extend_from_slice(&appliance_nonce.to_be_bytes());
    video.send(&video_packet(msg::VIDEO_CHANNEL_AUTH as u8, &auth))?;

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if Instant::now() > deadline {
            return Err(ioerr("the video channel was never acknowledged"));
        }
        let Some(f) = video.poll()? else { continue };
        match f.id {
            msg::VIDEO_CONNECT_STATUS => {
                let code = f.payload.first().copied().unwrap_or(0);
                if code != 0 {
                    return Err(ioerr(format!("the video channel was refused (status {code})")));
                }
                break;
            }
            msg::VIDEO_STOPPED => return Err(ioerr("the BMC stopped the video channel")),
            _ => continue,
        }
    }

    Ok(Console { kvm, video })
}

// ---------- video ----------

/// The 12-byte sub-header on every `ASPEED_JPEG_VIDEO` fragment.
#[derive(Clone, Copy, Debug)]
pub struct FrameHeader {
    pub width: usize,
    pub height: usize,
    /// Luminance quantisation table selector.
    pub y_sel: usize,
    /// Chrominance quantisation table selector.
    pub uv_sel: usize,
    /// 4:2:0 subsampling (16x16 macroblocks) rather than 4:4:4.
    pub mode420: bool,
    /// First fragment of a frame.
    pub first: bool,
    /// Last fragment of a frame.
    pub last: bool,
}

/// Parse the fragment sub-header. The reference reads the same twelve bytes and
/// throws most of them away; the ones kept here are the ones the decoder needs.
pub fn parse_fragment(p: &[u8]) -> Option<FrameHeader> {
    if p.len() < 12 {
        return None;
    }
    let height = u16::from_be_bytes([p[4], p[5]]) as usize;
    let width = u16::from_be_bytes([p[6], p[7]]) as usize;
    if width == 0 || height == 0 || width > 4096 || height > 4096 {
        return None;
    }
    Some(FrameHeader {
        width,
        height,
        // The selectors are only meaningful on the first fragment; later ones
        // carry zero here, which is a valid table index, so a naive reader
        // would silently switch tables mid-frame.
        y_sel: (p[11] >> 4) as usize,
        uv_sel: (p[11] & 0x0F) as usize,
        // The reference masks the mode byte with 1 to get the subsampling flag.
        mode420: p[0] & 1 != 0,
        first: p[8] & 1 != 0,
        last: p[8] & 2 != 0,
    })
}

/// Decodes whichever codec the BMC streams: ASPEED JPEG on the Gigabyte and
/// PowerEdge C boards, Avocent DVC on iDRAC 8. The message id says which, so one
/// console loop serves both.
#[derive(Default)]
pub struct Video {
    asm: VideoAssembler,
    dvc: crate::avct_dvc::Dvc,
}

impl Video {
    /// Feed one video-channel message; true when it completed a frame.
    pub fn feed(&mut self, f: &Frame, fb: &mut crate::ast2100::Decoder) -> bool {
        if f.id == msg::ASPEED_JPEG_VIDEO {
            fb.bytes_in += f.payload.len() as u64;
            if let Some((h, data)) = self.asm.push(&f.payload) {
                fb.decode_ast2300(h.width, h.height, h.mode420, h.y_sel, h.uv_sel, &data);
                return true;
            }
        } else if crate::avct_dvc::handles(f.id) {
            fb.bytes_in += f.payload.len() as u64;
            return self.dvc.push(f.id, &f.payload, fb);
        }
        false
    }
}

/// Reassembles `ASPEED_JPEG_VIDEO` fragments into whole frames.
///
/// Fragment 1 of a frame sets bit 0 of the flag byte and the last sets bit 1;
/// there is no length to count down, so those two bits are the only frame
/// boundary. The vendor client instead renders the previous frame when the next
/// one starts, which costs a frame of latency for no benefit.
#[derive(Default)]
pub struct VideoAssembler {
    header: Option<FrameHeader>,
    data: Vec<u8>,
}

impl VideoAssembler {
    /// Feed one fragment payload; returns a frame when the last one arrives.
    pub fn push(&mut self, payload: &[u8]) -> Option<(FrameHeader, Vec<u8>)> {
        let h = parse_fragment(payload)?;
        if h.first {
            self.header = Some(h);
            self.data.clear();
        } else if self.header.is_none() {
            // Joined mid-frame: wait for the next start rather than decode a
            // bitstream with its head missing.
            return None;
        }
        self.data.extend_from_slice(&payload[12..]);
        if h.last {
            let hdr = self.header.take()?;
            return Some((hdr, std::mem::take(&mut self.data)));
        }
        None
    }
}
