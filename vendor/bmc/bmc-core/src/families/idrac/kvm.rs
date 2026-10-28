//! iDRAC 9 virtual console: standard RFB carried over a WebSocket, wrapped in a
//! thin Dell control protocol.
//!
//! `wss://<host>:<port>/vnc/vconsole?vck=<VCSID>` with the `binary`
//! subprotocol. Dell control messages share the stream as RFB message type 247
//! (0xF7) and, during the handshake, arrive as their own WebSocket frames
//! interleaved with the RFB byte stream — so they are filtered at frame level.
//!
//! The server speaks first and will not start RFB until the second ticket is
//! returned:
//!
//!   server -> [0xF7][179]                     "send key2"
//!   client -> [0xF7][179][VCSID2 (24 ASCII)][8 zero bytes]
//!   server -> "RFB 003.008\n"                 ... normal RFB 3.8 from here
//!
//! The client must also send a heartbeat every 20s or the BMC tears the session
//! down with a graceful-shutdown notification.
//!
//! Ported from the console bundle the iDRAC serves at
//! `/restgui/vconsole/main-es5.*.js` (saved in `~/.config/smc-ikvm/idrac9-ref/`).

use crate::ws::{self, WebSocket};
use crate::{families::idrac::Launch, vnc};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Dell extension prefix, occupying RFB message type 247.
const DELL: u8 = 0xF7;
const SUB_HEARTBEAT: u8 = 246;
const SUB_LED: u8 = 178;
const SUB_SHUTDOWN: u8 = 169;
const SUB_KEY2_REQUEST: u8 = 179;
const SUB_CLIENT_LIST: u8 = 172;

const HEARTBEAT: Duration = Duration::from_secs(20);

/// The console transport: a WebSocket carrying RFB plus Dell control frames.
pub struct Stream {
    sock: WebSocket,
    /// RFB bytes received but not yet consumed.
    buf: Vec<u8>,
    /// The ticket the server asks for in-band. The BMC rotates it once the
    /// console is up, and *that* value — not the VCSID2 from the launch URL —
    /// is what the virtual-media channel authenticates with, so it is shared.
    key2: Arc<Mutex<String>>,
    /// Set once the BMC has sent its rotated key.
    rotated: Arc<AtomicBool>,
    last_beat: Instant,
    /// Latest keyboard LED bitmap the BMC reported.
    pub leds: u8,
    /// Last graceful-shutdown reason the BMC reported, if any (informational).
    pub shutdown_reason: Option<u8>,
}

impl Stream {
    /// Read one WebSocket frame. Dell control frames are handled here and never
    /// reach the RFB buffer. Returns false when nothing arrived before the
    /// poll timeout.
    pub fn pump(&mut self) -> std::io::Result<bool> {
        self.beat()?;
        let Some(msg) = self.sock.poll()? else { return Ok(false) };
        if std::env::var("BMCKVM_DEBUG").is_ok() {
            eprintln!("[idrac-kvm] frame {}B: {:02x?}", msg.len(), &msg[..msg.len().min(16)]);
        }
        if msg.first() == Some(&DELL) {
            self.control(&msg)?;
        } else {
            self.buf.extend_from_slice(&msg);
        }
        Ok(true)
    }

    fn control(&mut self, msg: &[u8]) -> std::io::Result<()> {
        match msg.get(1).copied() {
            Some(SUB_KEY2_REQUEST) => {
                let mut m = vec![DELL, SUB_KEY2_REQUEST];
                m.extend_from_slice(self.key2.lock().unwrap().as_bytes());
                m.extend_from_slice(&[0u8; 8]);
                self.sock.send_binary(&m)?;
            }
            Some(SUB_LED) => self.leds = msg.get(2).copied().unwrap_or(0),
            Some(SUB_SHUTDOWN) => {
                // Despite the name, this is not a teardown: the vendor console
                // only records the reason and keeps going, and the BMC sends
                // reason 3 immediately after every ServerInit. Reason 15 is a
                // liveness probe that wants a heartbeat by return. The session
                // is over only when the socket actually closes.
                self.shutdown_reason = msg.get(2).copied();
                if msg.get(2) == Some(&15) {
                    self.sock.send_binary(&[DELL, 0, SUB_HEARTBEAT])?;
                }
            }
            Some(SUB_CLIENT_LIST) => {
                // [F7][AC][4 bytes][24-char key2][8 zeros][...client list]
                if msg.len() >= 30 {
                    if let Ok(k) = std::str::from_utf8(&msg[6..30]) {
                        if k.bytes().all(|b| b.is_ascii_alphanumeric()) {
                            *self.key2.lock().unwrap() = k.to_string();
                            self.rotated.store(true, Ordering::SeqCst);
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Send the periodic keepalive when it falls due.
    fn beat(&mut self) -> std::io::Result<()> {
        if self.last_beat.elapsed() >= HEARTBEAT {
            self.sock.send_binary(&[DELL, 0, SUB_HEARTBEAT])?;
            self.last_beat = Instant::now();
        }
        Ok(())
    }

    /// Block until `n` RFB bytes are available (handshake use).
    fn need(&mut self, n: usize, timeout: Duration) -> std::io::Result<Vec<u8>> {
        let deadline = Instant::now() + timeout;
        while self.buf.len() < n {
            if Instant::now() >= deadline {
                return Err(ioerr(&format!(
                    "iDRAC console: timed out waiting for {n} bytes of RFB data"
                )));
            }
            self.pump()?;
        }
        Ok(self.buf.drain(..n).collect())
    }

    /// Take whatever RFB bytes have arrived, without blocking.
    pub fn take_rfb(&mut self) -> std::io::Result<Vec<u8>> {
        self.pump()?;
        Ok(std::mem::take(&mut self.buf))
    }

    pub fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.sock.send_binary(data)
    }

    pub fn set_poll_timeout(&mut self, d: Duration) -> std::io::Result<()> {
        self.sock.set_poll_timeout(d)
    }

    /// Close the console channel so the BMC releases its session slot.
    pub fn close(&mut self) {
        self.sock.close();
    }
}

/// A connected console, past the RFB handshake and ready to stream.
pub struct Console {
    pub stream: Stream,
    pub width: usize,
    pub height: usize,
    pub name: String,
    pub format: vnc::PixelFormat,
    /// The live media ticket. Hand this to `idrac_vmedia::mount`, not the
    /// VCSID2 from the launch URL — the BMC denies the stale one.
    pub key2: Arc<Mutex<String>>,
}

impl Console {
    /// Wait for the BMC to rotate the media ticket, which it does moments after
    /// the console comes up. Returns the ticket as it stands either way.
    pub fn wait_media_key(&mut self, timeout: Duration) -> String {
        let deadline = Instant::now() + timeout;
        while !self.stream.rotated.load(Ordering::SeqCst) && Instant::now() < deadline {
            if self.stream.pump().is_err() {
                break;
            }
        }
        self.key2.lock().unwrap().clone()
    }
}

/// Open the console and complete both the Dell and RFB handshakes.
pub fn connect(host: &str, cookie: &str, launch: &Launch, shared: bool)
    -> std::io::Result<Console>
{
    let path = format!("/vnc/vconsole?vck={}", launch.vcsid);
    let cookie = format!("-http-session-={cookie}");
    // The server refuses to speak RFB without the `binary` subprotocol.
    let mut sock = ws::connect_with(host, launch.port, &path, Some(&cookie), Some("binary"))?;
    // The handshake is strict request/response and the BMC can take most of a
    // second to answer each step. Keep the socket timeout long for it: a short
    // SO_RCVTIMEO makes reads time out inside a TLS record, which OpenSSL treats
    // as a fatal syscall error rather than "try again", dropping the connection.
    sock.set_poll_timeout(Duration::from_secs(5))?;
    let key2 = Arc::new(Mutex::new(launch.vcsid2.clone()));
    let rotated = Arc::new(AtomicBool::new(false));
    let mut s = Stream {
        sock,
        buf: Vec::new(),
        key2: key2.clone(),
        rotated: rotated.clone(),
        last_beat: Instant::now(),
        leds: 0,
        shutdown_reason: None,
    };

    // ProtocolVersion. The key2 exchange happens inside `pump` while we wait.
    let ver = s.need(12, Duration::from_secs(20))?;
    if !ver.starts_with(b"RFB ") {
        return Err(ioerr("iDRAC console: no RFB greeting (is Virtual Console enabled?)"));
    }
    s.send(b"RFB 003.008\n")?;

    // Security. iDRAC offers None, having already authenticated the tickets.
    let n = s.need(1, Duration::from_secs(15))?[0] as usize;
    if n == 0 {
        let len = s.need(4, Duration::from_secs(10))?;
        let len = u32::from_be_bytes([len[0], len[1], len[2], len[3]]) as usize;
        let reason = s.need(len.min(512), Duration::from_secs(10))?;
        return Err(ioerr(&format!(
            "iDRAC console refused the connection: {}",
            String::from_utf8_lossy(&reason)
        )));
    }
    let types = s.need(n, Duration::from_secs(10))?;
    let chosen = if types.contains(&1) { 1 } else { types[0] };
    if chosen != 1 {
        return Err(ioerr(&format!(
            "iDRAC console wants RFB security type {chosen}, which is not supported"
        )));
    }
    s.send(&[chosen])?;
    let res = s.need(4, Duration::from_secs(15))?;
    if u32::from_be_bytes([res[0], res[1], res[2], res[3]]) != 0 {
        return Err(ioerr("iDRAC console rejected the console ticket"));
    }

    // ClientInit. `shared` is read against the BMC's Virtual Console
    // "Access Privilege" policy: when that is set to Deny Access, a shared
    // connection is accepted and then immediately torn down, so ask for an
    // exclusive session unless the caller wants to share.
    s.send(&[if shared { 1 } else { 0 }])?;
    let si = s.need(24, Duration::from_secs(20))?;
    let width = u16::from_be_bytes([si[0], si[1]]) as usize;
    let height = u16::from_be_bytes([si[2], si[3]]) as usize;
    let format = vnc::PixelFormat::parse(&si[4..20])
        .ok_or_else(|| ioerr("iDRAC console sent a malformed pixel format"))?;
    let nlen = u32::from_be_bytes([si[20], si[21], si[22], si[23]]) as usize;
    let name = String::from_utf8_lossy(&s.need(nlen.min(256), Duration::from_secs(10))?).into_owned();

    if !format.true_colour {
        return Err(ioerr("iDRAC console is in palette mode, which is not supported"));
    }

    // Accept the server's native pixel format rather than asking it to convert:
    // every iDRAC 9 seen so far serves 16bpp RGB555 and the decoder handles it.
    s.send(&vnc::set_encodings(&vnc::SUPPORTED))?;
    s.send(&vnc::framebuffer_update_request(false, 0, 0, width as u16, height as u16))?;
    // Streaming wants a short poll so input can be interleaved; by now the
    // stream is continuous, so reads rarely land mid-record.
    s.set_poll_timeout(Duration::from_millis(100))?;

    Ok(Console { stream: s, width, height, name, format, key2 })
}

/// A console session held open in the background.
///
/// Virtual media rides on the console's rotated ticket and the BMC denies the
/// media channel without one, so headless callers need a console up even though
/// nothing renders the video.
pub struct ConsoleHold {
    alive: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    /// The media ticket, captured before the session was handed to its thread.
    pub key2: String,
}

impl ConsoleHold {
    /// Stop the session and wait for the socket to be closed. Synchronous on
    /// purpose: iDRAC accounts the console as a session of its own, and a
    /// process that exits before the close is written leaks it.
    pub fn release(&mut self) {
        self.alive.store(false, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for ConsoleHold {
    fn drop(&mut self) {
        self.release();
    }
}

/// Open a console and hold it until the handle is dropped, discarding the video.
pub fn hold_session(host: &str, cookie: &str, launch: &Launch) -> std::io::Result<ConsoleHold> {
    let mut con = connect(host, cookie, launch, true)?;
    let key2 = con.wait_media_key(Duration::from_secs(10));
    let alive = Arc::new(AtomicBool::new(true));
    let live = alive.clone();
    let handle = std::thread::spawn(move || {
        // Drain so the BMC's send buffer never backs up; the frames are dropped.
        while live.load(Ordering::SeqCst) {
            if con.stream.take_rfb().is_err() {
                break;
            }
        }
        con.stream.close();
    });
    Ok(ConsoleHold { alive, handle: Some(handle), key2 })
}

fn ioerr(m: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, m.to_string())
}
