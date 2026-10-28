//! RFB 055.008 / ATEN "InsydeVNC" handshake and message layer.
//!
//! Verified sequence (see ~/.config/smc-ikvm/PROTOCOL.md):
//!   S->C  "RFB 055.008\n"
//!   C->S  "RFB 055.008\n"                 (must echo; 003.008 is rejected)
//!   S->C  [count:u8][types:count]         (contains 16 = Insyde)
//!   C->S  [16]
//!   S->C  [challenge: 24 bytes]           (ignored)
//!   C->S  [48 bytes] token ascii[0:24], zeros[24:48]
//!   S->C  [SecurityResult: u32]           (0 = ok)
//!   C->S  [1]  ClientInit (shared)
//!   S->C  ServerInit: w:u16 h:u16 pixfmt[16] namelen:u32 name

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

pub const SEC_INSYDE: u8 = 16;

/// Some fields are unread: they record the wire format so a future change
/// does not have to re-derive it from the vendor client.
#[allow(dead_code)]
pub struct PixelFormat {
    pub bpp: u8,
    pub depth: u8,
    pub big_endian: bool,
    pub true_colour: bool,
    pub rmax: u16, pub gmax: u16, pub bmax: u16,
    pub rshift: u8, pub gshift: u8, pub bshift: u8,
}

/// Some fields are unread: they record the wire format so a future change
/// does not have to re-derive it from the vendor client.
#[allow(dead_code)]
pub struct Rfb {
    sock: Sock,
    pub width: u16,
    pub height: u16,
    pub pixfmt: PixelFormat,
    pub name: String,
    pub session_id: u32,
    pub video_enable: u8,
    pub kbms_enable: u8,
    pub vm_enable: u8,
}

/// The console socket: TLS on most boards, plain on some X9 firmware.
enum Sock {
    Tls(Box<crate::legacy_tls::Stream>),
    Plain(TcpStream),
}

impl Read for Sock {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        match self { Sock::Tls(s) => s.read(b), Sock::Plain(s) => s.read(b) }
    }
}

impl Write for Sock {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        match self { Sock::Tls(s) => s.write(b), Sock::Plain(s) => s.write(b) }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self { Sock::Tls(s) => s.flush(), Sock::Plain(s) => s.flush() }
    }
}

/// True if the console greets in the clear. Some X9 firmware serves plain RFB
/// on :5900 where others front it with stunnel: an RFB server sends its banner
/// unprompted, while a TLS server waits for the client's hello.
fn greets_in_clear(tcp: &TcpStream) -> bool {
    let _ = tcp.set_read_timeout(Some(std::time::Duration::from_secs(1)));
    let mut b = [0u8; 4];
    let plain = matches!(tcp.peek(&mut b), Ok(4)) && &b == b"RFB ";
    let _ = tcp.set_read_timeout(None);
    plain
}

/// `greets_in_clear` on a fresh connection, for discovery.
pub fn serves_plain(host: &str, port: u16) -> bool {
    crate::net::connect(host, port, None).map(|t| greets_in_clear(&t)).unwrap_or(false)
}

impl Rfb {
    /// For one-shot callers without a profile: find out whether the port is
    /// plain or TLS by looking.
    pub fn connect(host: &str, token: &str) -> std::io::Result<Rfb> {
        let tls = !serves_plain(host, 5900);
        // X9 requires mutual TLS on :5900 and pins trust to its viewer's
        // certificate; X10/X11 never ask for one, so a client certificate
        // offered there is never sent, and offering it always is harmless.
        let id = crate::families::aten::client_cert::cached_or_bundled(host);
        Self::connect_gen(host, 5900, token, tls, Some(&id))
    }

    /// `tls` is false for a plain-RFB console. `identity` is the CN=IPMI
    /// client certificate for X9's mutual TLS.
    pub fn connect_gen(host: &str, port: u16, token: &str, tls: bool,
                       identity: Option<&crate::families::aten::client_cert::Identity>)
        -> std::io::Result<Rfb>
    {
        let tcp = crate::net::connect(host, port, None)?;
        tcp.set_nodelay(true).ok();
        let mut sock = if tls {
            // OpenSSL rather than the platform stack: X9 is TLS 1.0 only,
            // which Windows refuses (see `legacy_tls`).
            Sock::Tls(Box::new(crate::legacy_tls::connect(host, tcp, identity.map(|i| i.pem()))?))
        } else {
            Sock::Plain(tcp)
        };

        // 1. version — accept any "RFB xxx.yyy" banner and echo it back verbatim.
        // X11 speaks 055.008 (InsydeVNC); X9/X10 (Java generations) speak 003.008.
        // Both then use the 3.8-style [count][types] security negotiation below.
        let mut banner = [0u8; 12];
        sock.read_exact(&mut banner)?;
        if &banner[..4] != b"RFB " {
            return Err(msg(format!("unexpected RFB banner: {:?}", banner)));
        }
        sock.write_all(&banner)?;

        // 2. security types
        let mut n = [0u8; 1];
        sock.read_exact(&mut n)?;
        if n[0] == 0 {
            return Err(msg("server rejected version (0 security types)".into()));
        }
        let mut types = vec![0u8; n[0] as usize];
        sock.read_exact(&mut types)?;
        if !types.contains(&SEC_INSYDE) {
            return Err(msg(format!("no Insyde auth offered; got {:?}", types)));
        }
        sock.write_all(&[SEC_INSYDE])?;

        // 3. challenge (ignored)
        let mut challenge = [0u8; 24];
        sock.read_exact(&mut challenge)?;

        // 4. credential: token ascii in [0:24], zeros in [24:48]
        let mut cred = [0u8; 48];
        let tb = token.as_bytes();
        let k = tb.len().min(24);
        cred[..k].copy_from_slice(&tb[..k]);
        sock.write_all(&cred)?;

        // 5. SecurityResult
        let mut res = [0u8; 4];
        sock.read_exact(&mut res)?;
        let code = u32::from_be_bytes(res);
        if code != 0 {
            return Err(msg(format!("authentication failed (SecurityResult={code})")));
        }

        // 6. ClientInit (shared = 1)
        sock.write_all(&[1])?;

        // 7. ServerInit
        let mut hdr = [0u8; 24];
        sock.read_exact(&mut hdr)?;
        let width = u16::from_be_bytes([hdr[0], hdr[1]]);
        let height = u16::from_be_bytes([hdr[2], hdr[3]]);
        let pixfmt = PixelFormat {
            bpp: hdr[4], depth: hdr[5], big_endian: hdr[6] != 0, true_colour: hdr[7] != 0,
            rmax: u16::from_be_bytes([hdr[8], hdr[9]]),
            gmax: u16::from_be_bytes([hdr[10], hdr[11]]),
            bmax: u16::from_be_bytes([hdr[12], hdr[13]]),
            rshift: hdr[14], gshift: hdr[15], bshift: hdr[16],
        };
        let namelen = u32::from_be_bytes([hdr[20], hdr[21], hdr[22], hdr[23]]) as usize;
        let mut name = vec![0u8; namelen.min(256)];
        sock.read_exact(&mut name)?;

        // InsydeVNC extended ServerInit header (12 bytes), immediately after the name:
        //   skip 4, SessionID u32, VideoEnable u8, KbMsEnable u8, KickUserEnable u8, VMEnable u8
        let mut ext = [0u8; 12];
        sock.read_exact(&mut ext)?;
        let session_id = u32::from_be_bytes([ext[4], ext[5], ext[6], ext[7]]);
        let video_enable = ext[8];
        let kbms_enable = ext[9];
        let vm_enable = ext[11];

        Ok(Rfb {
            sock, width, height, pixfmt,
            name: String::from_utf8_lossy(&name).into_owned(),
            session_id, video_enable, kbms_enable, vm_enable,
        })
    }

    /// SetEncodings — advertise what the client can decode.
    pub fn set_encodings(&mut self, encodings: &[i32]) -> std::io::Result<()> {
        let mut m = vec![2u8, 0];
        m.extend_from_slice(&(encodings.len() as u16).to_be_bytes());
        for e in encodings {
            m.extend_from_slice(&e.to_be_bytes());
        }
        self.sock.write_all(&m)?;
        self.sock.flush()
    }

    pub fn fb_update_request(&mut self, incremental: bool, x: u16, y: u16, w: u16, h: u16)
        -> std::io::Result<()>
    {
        let mut m = vec![3u8, incremental as u8];
        m.extend_from_slice(&x.to_be_bytes());
        m.extend_from_slice(&y.to_be_bytes());
        m.extend_from_slice(&w.to_be_bytes());
        m.extend_from_slice(&h.to_be_bytes());
        self.sock.write_all(&m)?;
        self.sock.flush()
    }

    pub fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        self.sock.read_exact(buf)
    }
    pub fn read_u8(&mut self) -> std::io::Result<u8> {
        let mut b = [0u8; 1]; self.sock.read_exact(&mut b)?; Ok(b[0])
    }
    pub fn read_u16(&mut self) -> std::io::Result<u16> {
        let mut b = [0u8; 2]; self.sock.read_exact(&mut b)?; Ok(u16::from_be_bytes(b))
    }
    pub fn write_all(&mut self, b: &[u8]) -> std::io::Result<()> {
        self.sock.write_all(b)?;
        self.sock.flush()
    }

    /// Chassis power command: OEM record [0x1a][code]. 0=off 1=on 2=reset 3=soft-off.
    pub fn send_power(&mut self, code: u8) -> std::io::Result<()> {
        self.write_all(&[0x1a, code])
    }

    /// Re-attach the virtual USB keyboard/mouse to the host: single byte 0x3a.
    pub fn send_hotplug(&mut self) -> std::io::Result<()> {
        self.write_all(&[0x3a])
    }
}

fn msg(m: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// A plain-RFB console greets first; a TLS one waits for our hello.
    #[test]
    fn plain_console_is_recognised_by_its_greeting() {
        let serve = |greet: Option<&'static [u8]>| {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = l.local_addr().unwrap().port();
            std::thread::spawn(move || {
                let (mut s, _) = l.accept().unwrap();
                if let Some(g) = greet {
                    s.write_all(g).unwrap();
                }
                std::thread::sleep(std::time::Duration::from_secs(2));
            });
            port
        };
        assert!(serves_plain("127.0.0.1", serve(Some(b"RFB 003.008\n"))));
        assert!(!serves_plain("127.0.0.1", serve(None)));
        assert!(!serves_plain("127.0.0.1", serve(Some(b"\x16\x03\x01"))));
    }
}

/// Read and dispatch one server->client message (InsydeVNC): the ATEN RFB
/// server-message loop, shared by GUI and CLI. Returns true if the message was a framebuffer update, so callers can time
/// the interval between actual frames rather than between any two messages.
pub fn pump_message(rfb: &mut Rfb, dec: &Arc<Mutex<crate::ast2100::Decoder>>) -> std::io::Result<bool> {
    let t = rfb.read_u8()?;
    let mut updated = false;
    match t {
        0 => {                                   // FramebufferUpdate
            let _pad = rfb.read_u8()?;
            let rects = rfb.read_u16()?;
            for _ in 0..rects {
                let mut hdr = [0u8; 20];
                rfb.read_exact(&mut hdr)?;
                let x = u16::from_be_bytes([hdr[0], hdr[1]]) as usize;
                let y = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
                let w = u16::from_be_bytes([hdr[4], hdr[5]]) as usize;
                let h = u16::from_be_bytes([hdr[6], hdr[7]]) as usize;
                let enc = u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
                let mode = u32::from_be_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]);
                let dlen = u32::from_be_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]) as usize;
                let mut data = vec![0u8; dlen];
                if dlen > 0 { rfb.read_exact(&mut data)?; }
                let mut d = dec.lock().unwrap();
                if (w != d.width || h != d.height) && w > 0 && h > 0 && w <= 1920 && h <= 1280 {
                    d.resize(w, h);
                }
                d.decode_rect(x, y, w, h, enc, mode, &data);
            }
            rfb.fb_update_request(true, 0, 0, rfb.width, rfb.height)?;
            updated = true;
        }
        2 => {}                                  // Bell
        4 => {                                    // cursor position/pattern
            let mut head = [0u8; 20];
            rfb.read_exact(&mut head)?;
            let qc_w = u32::from_be_bytes([head[8], head[9], head[10], head[11]]) as usize;
            let qc_h = u32::from_be_bytes([head[12], head[13], head[14], head[15]]) as usize;
            let valid = u32::from_be_bytes([head[16], head[17], head[18], head[19]]);
            if valid == 1 {
                let mut skip = vec![0u8; 4 + qc_w * qc_h * 2];
                rfb.read_exact(&mut skip)?;
            }
        }
        22 => { rfb.read_u8()?; }                 // 1-byte
        53 | 54 | 60 | 63 => { rfb.read_u8()?; }  // VMService, 1 byte
        55 => { let mut b = [0u8; 3]; rfb.read_exact(&mut b)?; } // power/mouse-mode
        57 => { let mut b = [0u8; 264]; rfb.read_exact(&mut b)?; } // ctrl message
        other => {
            return Err(std::io::Error::new(std::io::ErrorKind::Other,
                format!("unknown server message type {other}")));
        }
    }
    Ok(updated)
}
