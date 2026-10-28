//! iLO 4 Integrated Remote Console channels.
//!
//! Both channels are binary WebSockets to the same endpoint,
//! `wss://<host>/wss/ircport`, distinguished only by the id in their in-band
//! hello. The server speaks first:
//!
//!   server -> [0]=0x50 CMD_AUTHENTICATE
//!   client -> [0]=channel id (1=KVM, 2=CMD), [1]=32, [2..34]=session key
//!   server -> [0]=0x52 CMD_AUTHENTICATED   (or a refusal / busy negotiation)
//!
//! The KVM channel then carries the DVC video bitstream downstream (decoded in
//! `ilo_dvc.rs`) and HID input upstream. The CMD channel carries 12-byte-header
//! notifications: power and health state, POST codes, virtual-media results.

use crate::ws::{self, WebSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub const KVM_CHANNEL: u8 = 1;
pub const CMD_CHANNEL: u8 = 2;

// Handshake status bytes (the reference's DVCNET table).
const CMD_AUTHENTICATE: u8 = 80;
const CMD_DENIED: u8 = 81;
const CMD_AUTHENTICATED: u8 = 82;
/// Granted without the licence for the full console: the stream starts but
/// licensed features are gated. The HTML5 client never names it; the Windows
/// client treats it as a success.
const CMD_AUTHENTICATED_UNLICENSED: u8 = 87;
const NEG_BUSY: u8 = 83;
const NEG_DROP: u8 = 84;
const NEG_SEIZE: u8 = 85;
const NEG_SHARE: u8 = 86;
const CMD_NO_SESSIONS: u8 = 88;
const NEG_BUSY_NO_MURC: u8 = 89;

/// Open one console channel and complete its authentication handshake.
///
/// When the console is already in use the BMC answers NEG_BUSY; `seize` decides
/// whether to take it over (the vendor console prompts the user at this point).
pub fn open(host: &str, session_key: &str, channel: u8, seize: bool)
    -> std::io::Result<WebSocket>
{
    let mut sock = ws::connect(host, 443, "/wss/ircport", Some(session_key))?;
    let mut seized = false;
    loop {
        let msg = sock.recv(Duration::from_secs(15))?;
        let status = *msg.first().ok_or_else(|| ioerr("empty handshake message"))?;
        match status {
            CMD_AUTHENTICATE => {
                let key = session_key.as_bytes();
                if key.len() != 32 {
                    return Err(ioerr("iLO session key is not 32 characters"));
                }
                let mut hello = [0u8; 34];
                hello[0] = channel;
                hello[1] = 32;
                hello[2..34].copy_from_slice(key);
                sock.send_binary(&hello)?;
            }
            CMD_AUTHENTICATED | CMD_AUTHENTICATED_UNLICENSED => return Ok(sock),
            NEG_BUSY | NEG_BUSY_NO_MURC => {
                if !seize || seized {
                    return Err(ioerr("console is in use by another user"));
                }
                // Take the session over, as the vendor console's "Acquire" does.
                seized = true;
                sock.send_binary(&[NEG_SEIZE, 0])?;
            }
            CMD_DENIED => return Err(ioerr("console access denied (session limit or privilege)")),
            CMD_NO_SESSIONS => return Err(ioerr("no free console sessions on the iLO")),
            NEG_DROP => return Err(ioerr("console session dropped by the iLO")),
            NEG_SEIZE | NEG_SHARE => return Err(ioerr("console seized by another user")),
            2 => return Err(ioerr("console is in use and not shareable")),
            7 => return Err(ioerr("Integrated Remote Console is not licensed on this iLO")),
            other => return Err(ioerr(&format!("console handshake refused (status {other})"))),
        }
    }
}

/// A console session held open in the background.
///
/// iLO refuses a virtual-media connection unless an Integrated Remote Console
/// session is fully established — *both* channels, not just the video one. The
/// GUI already has that by the time its mount button exists; headless callers
/// need this, which opens the pair and drains them without decoding anything.
pub struct ConsoleHold {
    alive: Arc<AtomicBool>,
    handles: Vec<std::thread::JoinHandle<()>>,
}

impl ConsoleHold {
    /// Stop the session and wait for both channels to be closed. Synchronous on
    /// purpose: a BMC counts these channels as sessions and a process that exits
    /// before the close is written leaves them occupied.
    pub fn release(&mut self) {
        self.alive.store(false, Ordering::SeqCst);
        for h in self.handles.drain(..) {
            let _ = h.join();
        }
    }
}

impl Drop for ConsoleHold {
    fn drop(&mut self) {
        self.release();
    }
}

/// Open and hold both console channels until the returned handle is dropped.
pub fn hold_session(host: &str, session_key: &str, seize: bool) -> std::io::Result<ConsoleHold> {
    let mut kvm = open(host, session_key, KVM_CHANNEL, seize)?;
    let mut cmd = open(host, session_key, CMD_CHANNEL, seize)?;
    kvm.set_poll_timeout(Duration::from_millis(200)).ok();
    cmd.set_poll_timeout(Duration::from_millis(200)).ok();
    let alive = Arc::new(AtomicBool::new(true));

    // Drain the video channel so the BMC's send buffer never backs up. We never
    // acknowledge, so it simply stops sending frames — the session stays up.
    let live = alive.clone();
    let h1 = std::thread::spawn(move || {
        while live.load(Ordering::SeqCst) {
            if kvm.poll().is_err() {
                break;
            }
        }
        kvm.close();
    });
    let live = alive.clone();
    let h2 = std::thread::spawn(move || {
        while live.load(Ordering::SeqCst) {
            match cmd.poll() {
                // Decline console-sharing requests rather than leave them hanging.
                Ok(Some(msg)) => {
                    if let Some(n) = parse_notification(&msg) {
                        if matches!(interpret(&n), Event::ShareRequest { .. } | Event::SeizeRequest { .. })
                            && cmd.send_binary(&deny()).is_err()
                        {
                            break;
                        }
                    }
                }
                Ok(None) => {}
                Err(_) => break,
            }
        }
        cmd.close();
    });
    Ok(ConsoleHold { alive, handles: vec![h1, h2] })
}

/// Decode one screen from the console and close it again.
///
/// iLO 4 has no server-side snapshot endpoint: its overview page draws the
/// thumbnail by running the *same* IRC video stream into a small canvas (see
/// `irc.js`, mode "DOCKED"), so a still picture can only come from a real
/// console session. This is that session, made as short as possible — the KVM
/// channel alone, no CMD channel, never seizing a console someone else is
/// using, and closed as soon as the screen stops changing.
///
/// Because it costs a console session, the caller must treat it as an explicit
/// user action, not something to poll.
pub fn snapshot(host: &str, session_key: &str, budget: Duration)
    -> std::io::Result<crate::image::Image>
{
    /// How long the stream must go quiet before the screen counts as drawn.
    const SETTLED: Duration = Duration::from_millis(400);
    /// What counts as a message that redrew something substantial. The opening
    /// full-screen burst arrives as 1460-byte frames; a blinking text cursor is
    /// 7 to 10 bytes and would otherwise keep the screen looking "busy" forever.
    const SUBSTANTIAL: usize = 64;

    let mut kvm = open(host, session_key, KVM_CHANNEL, false)?;
    kvm.set_poll_timeout(Duration::from_millis(50)).ok();
    let mut fb = crate::ast2100::Decoder::new(1024, 768);
    let mut dvc = crate::ilo_dvc::Dvc::new();
    let _ = kvm.send_binary(&refresh());

    let start = std::time::Instant::now();
    let mut last_msg = start;
    let mut last_big: Option<std::time::Instant> = None;
    let mut ended = false;
    while start.elapsed() < budget && !ended {
        // Done once the screen has been drawn and has stopped changing: either
        // the redraw burst has died down, or the stream has gone silent
        // altogether (a blank screen sends nothing at all). A screen that keeps
        // genuinely changing never settles, which is what the budget is for.
        if fb.frames > 0
            && (last_big.is_some_and(|t| t.elapsed() > SETTLED) || last_msg.elapsed() > SETTLED)
        {
            break;
        }
        let msg = match kvm.poll() {
            Ok(Some(m)) => m,
            Ok(None) => continue,
            Err(_) => break,
        };
        last_msg = std::time::Instant::now();
        if msg.len() >= SUBSTANTIAL {
            last_big = Some(last_msg);
        }
        for e in dvc.process(&msg, &mut fb) {
            match e {
                crate::ilo_dvc::Event::SendAck => { let _ = kvm.send_binary(&ack()); }
                crate::ilo_dvc::Event::Refresh => { let _ = kvm.send_binary(&refresh()); }
                crate::ilo_dvc::Event::Exit => ended = true,
                _ => {}
            }
        }
    }
    // Synchronous, like `ConsoleHold::release`: returning before the close is
    // written leaves the console session occupied on the BMC.
    kvm.close();

    if fb.frames == 0 {
        return Err(ioerr("the console sent no video (is the server powered off?)"));
    }
    Ok(crate::image::Image {
        width: fb.width,
        height: fb.height,
        rgb: std::mem::take(&mut fb.framebuffer),
    })
}

// ---------- KVM channel: input and stream control ----------

/// An 8-byte USB HID keyboard report wrapped for the console channel.
/// `mods` is the standard HID modifier bitmap, `keys` up to six usage codes.
pub fn key_report(mods: u8, keys: &[u8]) -> Vec<u8> {
    let mut m = vec![1u8, 0, mods, 0, 0, 0, 0, 0, 0, 0];
    for (i, k) in keys.iter().take(6).enumerate() {
        m[4 + i] = *k;
    }
    m
}

/// Absolute mouse. `ax`/`ay` are 0..3000 across the screen; `wheel` is signed.
pub fn mouse(ax: u16, ay: u16, buttons: u8, wheel: i8) -> Vec<u8> {
    vec![
        2, 0,
        (ax & 0xff) as u8, (ax >> 8) as u8,
        (ay & 0xff) as u8, (ay >> 8) as u8,
        0, 0, // relative dx/dy, unused in absolute mode
        buttons,
        wheel as u8,
    ]
}

/// Mouse button bits, as the vendor console encodes them.
pub const BTN_LEFT: u8 = 1;
pub const BTN_RIGHT: u8 = 2;
pub const BTN_MIDDLE: u8 = 4;

/// The absolute-coordinate range the console expects.
pub const MOUSE_RANGE: f32 = 3000.0;

/// Ask for a full-screen refresh (used after the decoder loses sync).
pub fn refresh() -> Vec<u8> {
    vec![5, 0]
}

/// Acknowledge the stream; the BMC stops sending video until it sees this.
pub fn ack() -> Vec<u8> {
    vec![12, 0]
}

/// Release every key — sent after connecting and whenever focus is lost.
pub fn all_keys_up() -> Vec<u8> {
    key_report(0, &[])
}

/// Ctrl+Alt+Del: press the combination, then release, as two reports.
/// 0xE0 LeftCtrl | 0xE2 LeftAlt in the modifier byte, 0x4C Delete as a key.
pub fn ctrl_alt_del() -> Vec<Vec<u8>> {
    vec![key_report(0x05, &[0x4C]), all_keys_up()]
}

// ---------- CMD channel: notifications ----------

/// A command-channel message: 12-byte little-endian header plus payload.
#[derive(Clone, Debug)]
/// Some fields are unread: they record the wire format so a future change
/// does not have to re-derive it from the vendor client.
#[allow(dead_code)]
pub struct Notification {
    pub cmd: u32,
    pub size: u32,
    pub seq: u16,
    pub flags: u16,
    pub buf: Vec<u8>,
}

pub fn parse_notification(msg: &[u8]) -> Option<Notification> {
    if msg.len() < 12 {
        return None;
    }
    Some(Notification {
        cmd: u32::from_le_bytes(msg[0..4].try_into().ok()?),
        size: u32::from_le_bytes(msg[4..8].try_into().ok()?),
        seq: u16::from_le_bytes(msg[8..10].try_into().ok()?),
        flags: u16::from_le_bytes(msg[10..12].try_into().ok()?),
        buf: msg[12..].to_vec(),
    })
}

/// What a notification means, in the terms the GUI cares about.
#[derive(Clone, Debug)]
/// Some fields are unread: they record the wire format so a future change
/// does not have to re-derive it from the vendor client.
#[allow(dead_code)]
pub enum Event {
    PostComplete,
    Power(bool),
    Health(&'static str),
    PostCode(String),
    /// Another user is asking to take the console over.
    SeizeRequest { user: String, addr: String },
    /// Result of a virtual-media attach/detach.
    MediaResult { ok: bool, reason: String, connected: bool, floppy: bool },
    ShareRequest { user: String, addr: String },
    FirmwareUpdate,
    Unauthorized(&'static str),
    LicenseViolation,
    IloReset,
    Other(u32),
}

pub fn interpret(n: &Notification) -> Event {
    match n.cmd {
        2 => Event::PostComplete,
        3 => Event::Power(n.buf.first().copied().unwrap_or(0) == 1),
        4 => Event::Health(match n.buf.first().copied().unwrap_or(255) {
            0 => "OK",
            1 => "Warning",
            2 => "Critical",
            _ => "Unknown",
        }),
        5 if n.size == 2 && n.buf.len() >= 2 => {
            Event::PostCode(format!("{:02X}{:02X}", n.buf[1], n.buf[0]))
        }
        6 => Event::SeizeRequest { user: field(&n.buf, 0), addr: field(&n.buf, 64) },
        7 if n.size == 4 && n.buf.len() >= 4 => {
            let result = n.buf[0] as i8;
            Event::MediaResult {
                ok: result == 0,
                reason: scsi_error(result).to_string(),
                connected: n.buf[3] != 0,
                floppy: n.buf[1] == 1,
            }
        }
        9 => Event::ShareRequest { user: field(&n.buf, 0), addr: field(&n.buf, 64) },
        10 => Event::FirmwareUpdate,
        11 => Event::Unauthorized(match n.flags {
            2 => "Remote Console",
            3 => "Virtual Media",
            4 => "Virtual Power and Reset",
            _ => "unknown",
        }),
        14 => Event::LicenseViolation,
        15 => Event::IloReset,
        other => Event::Other(other),
    }
}

/// Decline a request (seize/share) on the command channel.
pub fn deny() -> Vec<u8> {
    vec![3, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]
}

/// Grant a request on the command channel: for a seize, hand the console over.
pub fn grant() -> Vec<u8> {
    vec![4, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]
}

/// A fixed-width 64-byte NUL-padded string field.
fn field(buf: &[u8], off: usize) -> String {
    let end = (off + 64).min(buf.len());
    if off >= end {
        return "unknown".into();
    }
    let s = &buf[off..end];
    let n = s.iter().position(|b| *b == 0).unwrap_or(s.len());
    String::from_utf8_lossy(&s[..n]).into_owned()
}

fn scsi_error(code: i8) -> &'static str {
    match code {
        0 => "ok",
        -1 => "cannot parse the image URL",
        -2 | -5 => "a drive is already connected",
        -3 => "image not found",
        -4 => "internal configuration error",
        -6 => "virtual media is not licensed",
        -7 => "connection rejected",
        -8 => "connection failed",
        -9 => "operation failed",
        -10 => "expected an ISO image",
        -11 => "expected a floppy image",
        -12 => "video is still starting up",
        -13 => "a firmware update is in progress",
        -14 => "flash failed",
        _ => "unknown error",
    }
}

fn ioerr(m: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, m.to_string())
}
