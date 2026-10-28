//! Minimal RFC 6455 WebSocket client over TLS.
//!
//! Written for HP iLO's Integrated Remote Console, which carries the KVM and
//! command channels as binary WebSocket messages on `wss://<host>/wss/ircport`.
//! Only what that needs: a client handshake, binary send (always masked, as the
//! RFC requires of clients), fragment reassembly, and ping/close handling.
//!
//! `native_tls::TlsStream` cannot be split for concurrent read/write, so the
//! socket stays owned by one thread and `poll()` is non-blocking: it returns
//! `Ok(None)` when the read times out, letting that thread interleave sends.

use native_tls::TlsConnector;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const OP_CONT: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BIN: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

pub struct WebSocket {
    s: native_tls::TlsStream<TcpStream>,
    /// Bytes received but not yet parsed into a frame.
    buf: Vec<u8>,
    /// Reassembly buffer for a fragmented message.
    frag: Vec<u8>,
    in_frag: bool,
    mask_seed: u32,
}

/// Open a TLS WebSocket to `host:port` at `path`, optionally sending `cookie`
/// (iLO scopes the console endpoint to the web session cookie).
pub fn connect(host: &str, port: u16, path: &str, cookie: Option<&str>) -> std::io::Result<WebSocket> {
    connect_with(host, port, path, cookie, None)
}

/// As `connect`, requesting a subprotocol. iDRAC's console refuses to speak RFB
/// unless the client asks for `binary`, exactly as noVNC does.
pub fn connect_with(
    host: &str,
    port: u16,
    path: &str,
    cookie: Option<&str>,
    protocol: Option<&str>,
) -> std::io::Result<WebSocket> {
    let conn = TlsConnector::builder()
        .danger_accept_invalid_certs(true) // BMCs ship self-signed certs
        .danger_accept_invalid_hostnames(true)
        .build()
        .map_err(oerr)?;
    let tcp = crate::net::connect(host, port, None)?;
    tcp.set_nodelay(true).ok();
    tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut s = conn.connect(host, tcp).map_err(oerr)?;

    let key = b64(&random16());
    // The port belongs in Host even when it is the default for the scheme:
    // iDRAC's console proxy completes the handshake and then silently withholds
    // ServerInit if it is missing. It is legal HTTP either way (RFC 7230 §5.4).
    let mut req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\
         Origin: https://{host}\r\n"
    );
    // iLO wants its own cookie name; other families pass a full `k=v` string.
    if let Some(c) = cookie {
        if c.contains('=') {
            req.push_str(&format!("Cookie: {c}\r\n"));
        } else {
            req.push_str(&format!("Cookie: sessionKey={c}\r\n"));
        }
    }
    if let Some(p) = protocol {
        req.push_str(&format!("Sec-WebSocket-Protocol: {p}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes())?;

    // Read just the response head; anything past it is the first WS frame.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if s.read(&mut byte)? == 0 {
            return Err(ioerr("websocket upgrade: connection closed during handshake"));
        }
        head.push(byte[0]);
        if head.len() > 8192 {
            return Err(ioerr("websocket upgrade: response head too large"));
        }
    }
    let text = String::from_utf8_lossy(&head);
    if std::env::var("BMCKVM_DEBUG").is_ok() {
        eprintln!("[ws] >>>\n{}[ws] <<< {}", req.replace("\r", ""), text.replace("\r", "").trim());
    }
    let status_ok = text.starts_with("HTTP/1.1 101") || text.starts_with("HTTP/1.0 101");
    let upgraded = text.to_ascii_lowercase().contains("upgrade: websocket");
    if !status_ok || !upgraded {
        let line = text.lines().next().unwrap_or("").trim();
        return Err(ioerr(&format!("websocket upgrade rejected: {line}")));
    }

    Ok(WebSocket {
        s,
        buf: Vec::new(),
        frag: Vec::new(),
        in_frag: false,
        mask_seed: u32::from_le_bytes(random16()[..4].try_into().unwrap()) | 1,
    })
}

impl WebSocket {
    /// How long `poll` waits for data before reporting "nothing yet".
    pub fn set_poll_timeout(&mut self, d: Duration) -> std::io::Result<()> {
        self.s.get_ref().set_read_timeout(Some(d))
    }

    /// Next complete data message, or `None` if none has arrived yet.
    pub fn poll(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(m) = self.take_message()? {
                return Ok(Some(m));
            }
            let mut tmp = [0u8; 32768];
            match self.s.read(&mut tmp) {
                Ok(0) => return Err(ioerr("websocket closed by peer (connection dropped)")),
                Ok(n) => self.buf.extend_from_slice(&tmp[..n]),
                Err(e) if would_block(&e) => return Ok(None),
                Err(e) => return Err(e),
            }
        }
    }

    /// Block until the next data message arrives (used during the IRC handshake).
    pub fn recv(&mut self, timeout: Duration) -> std::io::Result<Vec<u8>> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(m) = self.poll()? {
                return Ok(m);
            }
            if std::time::Instant::now() >= deadline {
                return Err(ioerr("websocket read timed out"));
            }
        }
    }

    pub fn send_binary(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.send_frame(OP_BIN, data)
    }

    /// Send a Close frame and shut the socket down.
    ///
    /// Worth doing rather than just dropping the stream: BMCs account for these
    /// channels as sessions of their own, and a connection that merely goes away
    /// can sit in the pool until it times out. iDRAC allows exactly one
    /// virtual-media session, so a leaked one blocks the next mount.
    pub fn close(&mut self) {
        // 1000 "normal closure"; failures here are not worth reporting since we
        // are tearing down regardless.
        let _ = self.send_frame(OP_CLOSE, &1000u16.to_be_bytes());
        let _ = self.s.get_ref().shutdown(std::net::Shutdown::Both);
    }

    fn send_frame(&mut self, opcode: u8, data: &[u8]) -> std::io::Result<()> {
        let mut f = Vec::with_capacity(data.len() + 14);
        f.push(0x80 | opcode); // FIN + opcode
        let n = data.len();
        if n < 126 {
            f.push(0x80 | n as u8); // MASK + len
        } else if n <= 0xFFFF {
            f.push(0x80 | 126);
            f.extend_from_slice(&(n as u16).to_be_bytes());
        } else {
            f.push(0x80 | 127);
            f.extend_from_slice(&(n as u64).to_be_bytes());
        }
        // A client must mask every frame; any key will do as long as it varies.
        self.mask_seed = self.mask_seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let mask = self.mask_seed.to_le_bytes();
        f.extend_from_slice(&mask);
        f.extend(data.iter().enumerate().map(|(i, b)| b ^ mask[i & 3]));
        if std::env::var("BMCKVM_DEBUG").is_ok() {
            eprintln!("[ws] SEND op={opcode} {}B: {:02x?}", data.len(), &data[..data.len().min(16)]);
        }
        self.s.write_all(&f)?;
        self.s.flush()
    }

    /// Parse one frame out of `buf`, answering control frames inline. Returns a
    /// payload only once a full (possibly fragmented) data message is complete.
    fn take_message(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        loop {
            // A BMC whose proxy has lost its back end answers the upgrade with
            // 101 and then writes an ordinary HTTP response over the upgraded
            // connection. Parsed as frames that reads as a close with a nonsense
            // code, so name it instead: nothing the client does will fix it.
            if self.buf.starts_with(b"HTTP/") {
                return Err(ioerr(concat!(
                    "the BMC upgraded the WebSocket and then sent an HTTP response ",
                    "instead of frames: its proxy has stopped handing connections to ",
                    "the back-end service. Only a BMC reset is known to clear it.")));
            }
            let b = &self.buf;
            if b.len() < 2 {
                return Ok(None);
            }
            let fin = b[0] & 0x80 != 0;
            let opcode = b[0] & 0x0F;
            let masked = b[1] & 0x80 != 0;
            let len7 = (b[1] & 0x7F) as usize;
            let (payload_len, mut off) = match len7 {
                126 => {
                    if b.len() < 4 { return Ok(None); }
                    (u16::from_be_bytes([b[2], b[3]]) as usize, 4)
                }
                127 => {
                    if b.len() < 10 { return Ok(None); }
                    (u64::from_be_bytes(b[2..10].try_into().unwrap()) as usize, 10)
                }
                n => (n, 2),
            };
            // A server must not mask, but tolerate it rather than desync.
            let mask: Option<[u8; 4]> = if masked {
                if b.len() < off + 4 { return Ok(None); }
                let m = [b[off], b[off + 1], b[off + 2], b[off + 3]];
                off += 4;
                Some(m)
            } else {
                None
            };
            if b.len() < off + payload_len {
                return Ok(None);
            }
            let mut payload = b[off..off + payload_len].to_vec();
            if let Some(m) = mask {
                for (i, v) in payload.iter_mut().enumerate() {
                    *v ^= m[i & 3];
                }
            }
            self.buf.drain(..off + payload_len);

            match opcode {
                OP_CLOSE => {
                    let code = if payload.len() >= 2 {
                        u16::from_be_bytes([payload[0], payload[1]])
                    } else {
                        0
                    };
                    let why = String::from_utf8_lossy(payload.get(2..).unwrap_or(&[])).into_owned();
                    return Err(ioerr(&format!(
                        "websocket closed by peer (code {code}{})",
                        if why.is_empty() { String::new() } else { format!(": {why}") }
                    )));
                }
                OP_PING => {
                    self.send_frame(OP_PONG, &payload)?;
                    continue;
                }
                OP_PONG => continue,
                OP_BIN | OP_TEXT => {
                    if fin && !self.in_frag {
                        return Ok(Some(payload));
                    }
                    self.frag = payload;
                    self.in_frag = true;
                    if fin {
                        self.in_frag = false;
                        return Ok(Some(std::mem::take(&mut self.frag)));
                    }
                }
                OP_CONT => {
                    self.frag.extend_from_slice(&payload);
                    if fin {
                        self.in_frag = false;
                        return Ok(Some(std::mem::take(&mut self.frag)));
                    }
                }
                other => return Err(ioerr(&format!("websocket: unexpected opcode {other}"))),
            }
        }
    }
}

fn would_block(e: &std::io::Error) -> bool {
    matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
}

fn random16() -> [u8; 16] {
    let mut k = [0u8; 16];
    crate::rand::fill(&mut k);
    k
}

fn b64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

fn ioerr(m: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, m.to_string())
}
fn oerr<E: std::error::Error + Send + Sync + 'static>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e)
}
