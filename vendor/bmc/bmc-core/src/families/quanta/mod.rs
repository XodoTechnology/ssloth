//! Quanta (QCT) BMCs running AMI MegaRAC — a different family from the ATEN /
//! Supermicro line the rest of this crate targets.
//!
//! Observed on the Quanta (AST2300, MegaRAC ~3.42, GoAhead-Webs, © AMI
//! 2008-2009):
//!   - web login   : GET /rpc/WEBSES/create.asp?WEBVAR_USERNAME=&WEBVAR_PASSWORD=
//!                    -> JSON-ish body with 'SESSION_COOKIE' (the failure sentinel
//!                       "Failure_Login_..." on bad credentials)
//!   - KVM console : AMI JViewer (Java) on TCP 7578 — NOT RFB/InsydeVNC
//!   - vmedia      : AMI CD/FD/HD redirection on TCP 5120
//!   - IPMI/RMCP+  : UDP 623 (legacy cipher suites)
//!
//! The JViewer video/input/vmedia protocol is unrelated to the ATEN engines in
//! this crate and still needs reverse-engineering against a live session, so this
//! module currently provides detection and web login only.

pub mod kvm;
pub mod vmedia;

use native_tls::TlsConnector;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// AMI KVM video port (JViewer).
pub const KVM_PORT: u16 = 7578;
/// AMI virtual-media (CD/FD/HD redirection) port.
pub const VMEDIA_PORT: u16 = 5120;

fn tls(host: &str) -> std::io::Result<native_tls::TlsStream<TcpStream>> {
    let c = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .map_err(oerr)?;
    let tcp = crate::net::connect(host, 443, None)?;
    tcp.set_read_timeout(Some(Duration::from_secs(6))).ok();
    c.connect(host, tcp).map_err(oerr)
}

fn https(host: &str, request: &str) -> std::io::Result<(String, String)> {
    let mut s = tls(host)?;
    s.write_all(request.as_bytes())?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).ok();
    let text = String::from_utf8_lossy(&raw).into_owned();
    match text.find("\r\n\r\n") {
        Some(i) => Ok((text[..i].to_string(), text[i + 4..].to_string())),
        None => Ok((text, String::new())),
    }
}

/// Detect an AMI MegaRAC / Quanta BMC without authenticating: the GoAhead-Webs
/// front end plus the AMI `create.asp` login endpoint are a reliable signature.
pub fn is_ami_megarac(host: &str) -> bool {
    let req = format!(
        "GET /rpc/WEBSES/create.asp HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    );
    match https(host, &req) {
        Ok((headers, body)) => {
            let goahead = headers.to_ascii_lowercase().contains("goahead");
            // create.asp always mentions the AMI WEB_SESSION struct, even unauthenticated.
            let ami = body.contains("WEB_SESSION") || body.contains("SESSION_COOKIE")
                || body.contains("American Megatrends");
            goahead || ami
        }
        Err(_) => false,
    }
}

/// An authenticated AMI web session (the cookie drives KVM/vmedia arming).
#[derive(Clone, Debug)]
/// Some fields are unread: they record the wire format so a future change
/// does not have to re-derive it from the vendor client.
#[allow(dead_code)]
pub struct AmiSession {
    pub host: String,
    pub cookie: String,
}

/// Log in through the AMI `create.asp` endpoint. Returns the session cookie, or
/// an error carrying the AMI failure reason.
pub fn login(host: &str, user: &str, pass: &str) -> std::io::Result<AmiSession> {
    let req = format!(
        "GET /rpc/WEBSES/create.asp?WEBVAR_USERNAME={}&WEBVAR_PASSWORD={} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n",
        enc(user), enc(pass)
    );
    let (headers, body) = https(host, &req)?;
    if let Some(reason) = between(&body, "'SESSION_COOKIE' : '", "'") {
        if reason.starts_with("Failure") {
            return Err(oerr_s(format!("AMI login rejected: {reason}")));
        }
        // A non-failure SESSION_COOKIE value is the token; the transport cookie is
        // in Set-Cookie (SessionCookie=...).
        let cookie = headers.lines()
            .filter(|l| l.to_ascii_lowercase().starts_with("set-cookie:"))
            .filter_map(|l| l.split("SessionCookie=").nth(1))
            .map(|v| v.split(';').next().unwrap_or("").to_string())
            .find(|v| !v.is_empty())
            .unwrap_or_else(|| reason.to_string());
        return Ok(AmiSession { host: host.to_string(), cookie });
    }
    Err(oerr_s("AMI login: unexpected create.asp response".into()))
}

fn between<'a>(s: &'a str, a: &str, b: &str) -> Option<&'a str> {
    let i = s.find(a)? + a.len();
    let j = s[i..].find(b)? + i;
    Some(&s[i..j])
}

fn enc(s: &str) -> String {
    s.bytes().map(|b| match b {
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
        _ => format!("%{b:02X}"),
    }).collect()
}

fn oerr<E: std::error::Error + Send + Sync + 'static>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e)
}
fn oerr_s(m: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, m)
}

/// Chassis power via IPMI (RMCP+), on the native client in `crate::ipmi` —
/// no `ipmitool` needed. These MegaRAC BMCs speak only cipher suite 3, which
/// the client falls back to on its own. `cmd` is on|off|reset|soft|cycle.
pub fn ipmi_power(host: &str, user: &str, pass: &str, cmd: &str) -> std::io::Result<String> {
    crate::ipmi::power(host, user, pass, cmd)
        .map_err(|e| oerr_s(format!("IPMI power {cmd} failed: {e}")))
}

/// Cold-reset the BMC itself (management controller) via IPMI — restarts BMC
/// firmware (and its web server) without touching host power.
pub fn ipmi_mc_reset(host: &str, user: &str, pass: &str) -> std::io::Result<String> {
    crate::ipmi::mc_reset_cold(host, user, pass)
        .map_err(|e| oerr_s(format!("BMC cold reset failed: {e}")))
}

/// KVM launch parameters parsed from the JViewer JNLP.
#[derive(Clone, Debug)]
/// Some fields are unread: they record the wire format so a future change
/// does not have to re-derive it from the vendor client.
#[allow(dead_code)]
pub struct KvmLaunch {
    pub kvm_token: String,     // 16-byte per-launch token (-kvmtoken)
    pub web_cookie: String,    // web session token echoed to :7578 (-webcookie)
    pub kvm_port: u16,         // -kvmport (7578)
    pub cd_port: u16,          // -cdport (5120)
}

/// Log in and fetch a fresh JViewer launch descriptor. The BMC only fills the
/// JNLP arguments when the request carries `?EXTRNIP=<ip>&JNLPSTR=JViewer` — the
/// exact query the web UI's Launch button uses; without it the CGI emits a
/// truncated, tokenless JNLP (and can wedge the web server), so always pass them.
pub fn fetch_kvm_launch(host: &str, user: &str, pass: &str) -> std::io::Result<KvmLaunch> {
    let sess = login(host, user, pass)?;
    let req = format!(
        "GET /Java/jviewer.jnlp?EXTRNIP={host}&JNLPSTR=JViewer HTTP/1.0\r\nHost: {host}\r\nCookie: SessionCookie={}; test=1\r\nConnection: close\r\n\r\n",
        sess.cookie
    );
    let (_h, body) = https(host, &req)?;
    let args: Vec<&str> = body.split("<argument>")
        .skip(1)
        .filter_map(|s| s.split("</argument>").next())
        .collect();
    let val = |name: &str| -> Option<String> {
        args.iter().position(|a| *a == name).and_then(|i| args.get(i + 1)).map(|s| s.to_string())
    };
    let kvm_token = val("-kvmtoken")
        .ok_or_else(|| oerr_s("JNLP has no -kvmtoken (BMC returned a tokenless launch)".into()))?;
    let web_cookie = val("-webcookie").unwrap_or(sess.cookie.clone());
    let kvm_port = val("-kvmport").and_then(|s| s.trim().parse().ok()).unwrap_or(KVM_PORT);
    let cd_port = val("-cdport").and_then(|s| s.trim().parse().ok()).unwrap_or(VMEDIA_PORT);
    Ok(KvmLaunch { kvm_token, web_cookie, kvm_port, cd_port })
}
