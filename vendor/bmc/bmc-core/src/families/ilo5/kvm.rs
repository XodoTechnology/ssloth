//! iLO 5 console channels: `/wss/ircport`, protocol version 5.
//!
//! Same two-channel scheme as iLO 4 (a KVM video channel and a CMD channel),
//! but the handshake is client-initiated and every handshake message carries
//! a 16-byte header. Channels are renumbered 0=KVM, 1=CMD (iLO 4 uses 1/2).
//!
//! Post-auth the channels carry the same payloads as iLO 4 — DVC video on
//! KVM, IRC_CMD records on CMD — so the decode/notification paths are shared.

use crate::ws::{self, WebSocket};
use std::io::Error as IoError;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub const KVM_CHANNEL: u8 = 0;
pub const CMD_CHANNEL: u8 = 1;

fn ioerr(m: &str) -> IoError {
    IoError::new(std::io::ErrorKind::Other, m.to_string())
}

/// Open one console channel with the version-5 handshake.
///
/// The client speaks first: a 54-byte hello — 16 zero bytes of v5 header,
/// [16]=openCommand, [17]=channel, [18..22] zero, [22..54]=session_key.
/// `open_command` is 1 only for a seize/acquire request; the normal open is 0.
/// The server's reply carries its status at byte 16 and flags at 17; 0 is the
/// only success.
pub fn open(host: &str, session_key: &str, channel: u8, seize: bool)
    -> std::io::Result<WebSocket>
{
    let mut sock = ws::connect(host, 443, "/wss/ircport", Some(session_key))?;
    let mut hello = [0u8; 54];
    hello[16] = if seize { 1 } else { 0 };
    hello[17] = channel;
    let key = session_key.as_bytes();
    if key.len() != 32 {
        return Err(ioerr("iLO session key is not 32 characters"));
    }
    hello[22..54].copy_from_slice(key);
    sock.send_binary(&hello)?;

    let msg = sock.recv(Duration::from_secs(15))?;
    let status = msg.get(16).copied()
        .ok_or_else(|| ioerr("short v5 handshake reply"))?;
    match status {
        0 => Ok(sock),
        1 => Err(ioerr("console access denied (session limit or privilege)")),
        2 => Err(ioerr("console is in use by another user")),
        3 => Err(ioerr("Integrated Remote Console is not licensed on this iLO")),
        4 => Err(ioerr("console handshake refused (status 4)")),
        other => Err(ioerr(&format!("console handshake refused (status {other})"))),
    }
}

/// A console session held open in the background — see ilo4::kvm::ConsoleHold;
/// iLO still requires both channels up before virtual media connects.
pub struct ConsoleHold {
    alive: Arc<AtomicBool>,
    handles: Vec<std::thread::JoinHandle<()>>,
}

impl ConsoleHold {
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
    let mut cmd = open(host, session_key, CMD_CHANNEL, seize)
        .inspect_err(|_| { kvm.close(); })?;
    let alive = Arc::new(AtomicBool::new(true));
    let a2 = alive.clone();
    let mut handles = Vec::new();
    handles.push(std::thread::spawn(move || {
        while a2.load(Ordering::SeqCst) {
            match cmd.poll() {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => break,
            }
        }
    }));
    let a3 = alive.clone();
    handles.push(std::thread::spawn(move || {
        while a3.load(Ordering::SeqCst) {
            match kvm.poll() {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => break,
            }
        }
    }));
    Ok(ConsoleHold { alive, handles })
}

/// A screen snapshot — same as iLO 4's, opened with the v5 handshake.
pub fn snapshot(host: &str, session_key: &str, budget: Duration)
    -> std::io::Result<crate::image::Image>
{
    let kvm = open(host, session_key, KVM_CHANNEL, false)?;
    crate::families::ilo4::kvm::snapshot_from(kvm, budget)
}
