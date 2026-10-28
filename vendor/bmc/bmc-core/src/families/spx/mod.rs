//! AMI MegaRAC SP-X web API (ASRock Rack and the other SP-X OEMs).
//!
//! This is the *newer* AMI stack, and it shares nothing with the GoAhead-era
//! MegaRAC in `quanta.rs` except the IVTP console protocol underneath: there is
//! no `/rpc/WEBSES/create.asp`, no `SESSION_COOKIE`, and no JNLP. Instead a
//! lighttpd REST service under `/api`:
//!
//!   - `POST /api/session` (form) -> `{ ok: 0, CSRFToken, privilege, ... }` and a
//!     `QSESSIONID` cookie. `ok` is 0 on success, not 1.
//!   - `DELETE /api/session` ends it. Every non-GET needs `X-CSRFTOKEN`.
//!   - `GET /api/settings/media/h5viewercfg` -> the console launch parameters,
//!     including a fresh 16-character KVM token (`/api/kvm/token` on older
//!     firmware, which lacks that route).
//!   - `POST /api/actions/power` `{"power_command": n}` drives chassis power.
//!
//! Power *state* and model come from Redfish instead, which SP-X serves under
//! HTTP Basic without consuming a session (verified: the session collection
//! stays empty across repeated Basic requests), so the shared probe in `app.rs`
//! reads `/redfish/v1/Systems/Self` like it does for the other families.
//!
//! Ported from the BMC's own `source.min.js` / `viewer.min.js`, which it serves
//! unauthenticated. See docs/ASROCK-SPX.md.

pub mod kvm;
pub mod vmedia;

use native_tls::TlsConnector;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(12);

/// What an unauthenticated probe can tell us about an SP-X BMC.
#[derive(Clone, Debug)]
pub struct Info {
    /// Redfish `Product`, e.g. "AMI Redfish Server".
    pub product: String,
    /// AMI's Redfish OEM version (`Oem.Ami.RtpVersion`), a rough firmware age.
    pub rtp_version: String,
}

/// A logged-in web session. Both halves are needed: the cookie authenticates,
/// the CSRF token authorises anything that is not a GET.
pub struct Session {
    pub cookie: String,
    pub csrf: String,
}

/// The console launch parameters, straight from `h5viewercfg`.
///
/// `token` is minted per call and the previous one stops working, so fetch it
/// once per console session and no more.
#[derive(Clone, Debug)]
pub struct Launch {
    /// 16-character per-launch KVM token.
    pub token: String,
    /// Our address *as the BMC sees it*, which is what the validate packet must
    /// carry — not the local socket address, which may be behind NAT.
    pub client_ip: String,
    /// The BMC's own address, as it reports it. Empty on the older viewer,
    /// whose validate packet has no field for it.
    pub server_ip: String,
    /// The older viewer's packet: 373 bytes, ending at the MAC. The newer one
    /// appends the server address for 438.
    pub legacy_packet: bool,
    /// The BMC advertises `KVM_SESSION_RECONNECT`, and so expects the validate
    /// packet to be preceded by a bare `CONNECTION_COMPLETE_PKT` header.
    pub reconnect: bool,
}

fn ioerr<S: AsRef<str>>(m: S) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, m.as_ref().to_string())
}

fn oerr<E: std::fmt::Display>(e: E) -> std::io::Error {
    ioerr(e.to_string())
}

fn tls(host: &str) -> std::io::Result<native_tls::TlsStream<TcpStream>> {
    let c = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .map_err(oerr)?;
    let tcp = crate::net::connect(host, 443, Some(TIMEOUT))?;
    tcp.set_read_timeout(Some(TIMEOUT))?;
    c.connect(host, tcp).map_err(oerr)
}

/// One HTTPS request. Returns (status, response headers, body).
fn https(
    host: &str,
    method: &str,
    path: &str,
    sess: Option<&Session>,
    body: Option<(&str, &str)>,
) -> std::io::Result<(u16, String, String)> {
    let mut s = tls(host)?;
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    if let Some(sess) = sess {
        req.push_str(&format!("Cookie: {}\r\n", sess.cookie));
        req.push_str(&format!("X-CSRFTOKEN: {}\r\n", sess.csrf));
    }
    if let Some((ctype, b)) = body {
        req.push_str(&format!("Content-Type: {ctype}\r\nContent-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    if let Some((_, b)) = body {
        req.push_str(b);
    }
    s.write_all(req.as_bytes())?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).ok();

    let split = raw.windows(4).position(|w| w == b"\r\n\r\n");
    let (head, rest) = match split {
        Some(i) => (&raw[..i], &raw[i + 4..]),
        None => (&raw[..], &[][..]),
    };
    let head = String::from_utf8_lossy(head).into_owned();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    // The API answers chunked; the UI assets are gzipped, but no JSON route is.
    let body = if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        crate::auth::dechunk(rest)
    } else {
        rest.to_vec()
    };
    Ok((status, head, String::from_utf8_lossy(&body).into_owned()))
}

/// Pull a `"key": "value"` string out of a JSON body.
fn jstr(body: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\"");
    let i = body.find(&pat)?;
    let rest = body[i + pat.len()..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let e = rest.find('"')?;
    Some(rest[..e].to_string())
}

/// Pull a `"key": <number>` out of a JSON body.
fn jnum(body: &str, key: &str) -> Option<i64> {
    let pat = format!("\"{key}\"");
    let i = body.find(&pat)?;
    let rest = body[i + pat.len()..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let end = rest.find(|c: char| !c.is_ascii_digit() && c != '-').unwrap_or(rest.len());
    rest[..end].parse().ok()
}

/// Identify an SP-X BMC without credentials.
///
/// The Redfish service root is the one thing this stack serves unauthenticated,
/// and AMI stamps it: `Oem.Ami` is typed `#AMIServiceRoot`. Checked against the
/// other families' roots so it cannot misfire — Supermicro X11 serves Redfish
/// with no AMI OEM block, X9 404s, and the GoAhead MegaRAC refuses outright.
pub fn detect(host: &str) -> Option<Info> {
    let (status, _, body) = https(host, "GET", "/redfish/v1/", None, None).ok()?;
    // Newer firmware types the OEM block `#AMIServiceRoot`; older (Redfish
    // 1.0.2, an ASRock Rack board) carries a bare `"Oem": {"Ami": {...}}`.
    let ami = body.contains("AMIServiceRoot") || body.contains("\"Ami\"");
    if status != 200 || !ami {
        return None;
    }
    Some(Info {
        product: jstr(&body, "Product").unwrap_or_else(|| "AMI".into()),
        rtp_version: jstr(&body, "RtpVersion").unwrap_or_default(),
    })
}

pub fn login(host: &str, user: &str, pass: &str) -> std::io::Result<Session> {
    let form = format!("username={}&password={}", urlenc(user), urlenc(pass));
    let (status, head, body) = https(
        host,
        "POST",
        "/api/session",
        None,
        Some(("application/x-www-form-urlencoded", &form)),
    )?;
    // `ok` is 0 for success here, which is the opposite of the older AMI stack.
    if status != 200 || jnum(&body, "ok") != Some(0) {
        return Err(ioerr(format!("login refused (HTTP {status}): {}",
            body.trim().chars().take(160).collect::<String>())));
    }
    let csrf = jstr(&body, "CSRFToken")
        .ok_or_else(|| ioerr("login response carried no CSRFToken"))?;
    let cookie = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("set-cookie: qsessionid="))
        .and_then(|l| l.splitn(2, ": ").nth(1))
        .and_then(|v| v.split(';').next())
        .map(|s| s.trim().to_string())
        .ok_or_else(|| ioerr("login set no QSESSIONID cookie"))?;
    Ok(Session { cookie, csrf })
}

/// End the web session. SP-X keeps a small session table and a console counts
/// against it, so this is not optional politeness.
pub fn logout(host: &str, sess: &Session) {
    let _ = https(host, "DELETE", "/api/session", Some(sess), None);
}

/// Fetch the console launch parameters. Mints a fresh KVM token each call.
///
/// Two firmware generations answer differently. The newer viewer reads
/// `h5viewercfg`; the older one (an ASRock Rack board on Redfish 1.0.2) has no
/// such route — it answers `{"error": "Invalid API Call", "code": 1010}` — and
/// reads `/api/kvm/token` instead, whose `token`/`session`/`client_ip` feed a
/// validate packet one field shorter.
pub fn kvm_launch(host: &str, sess: &Session) -> std::io::Result<Launch> {
    let reconnect = features(host, sess).iter().any(|f| f == "KVM_SESSION_RECONNECT");
    let (status, _, body) =
        https(host, "GET", "/api/settings/media/h5viewercfg", Some(sess), None)?;
    if status == 200 && jstr(&body, "token").is_some() {
        // 0 means the KVM service is switched off in the BMC's settings; the
        // console would otherwise fail later with an unexplained refusal.
        if jnum(&body, "kvm_service_status") == Some(0) {
            return Err(ioerr("the KVM service is disabled on this BMC"));
        }
        return Ok(Launch {
            token: jstr(&body, "token").unwrap_or_default(),
            client_ip: jstr(&body, "client_ip").unwrap_or_default(),
            server_ip: jstr(&body, "server_ip").unwrap_or_else(|| host.to_string()),
            legacy_packet: false,
            reconnect,
        });
    }
    let (status, _, body) = https(host, "GET", "/api/kvm/token", Some(sess), None)?;
    let token = jstr(&body, "token").filter(|_| status == 200).ok_or_else(|| {
        ioerr(format!("no KVM token from h5viewercfg or /api/kvm/token (HTTP {status}): {}",
            body.trim().chars().take(120).collect::<String>()))
    })?;
    Ok(Launch {
        token,
        client_ip: jstr(&body, "client_ip").unwrap_or_default(),
        server_ip: String::new(),
        legacy_packet: true,
        reconnect,
    })
}

/// The BMC's feature list (`/api/configuration/project`), which the viewer
/// consults before it builds the handshake. Empty if it cannot be read.
fn features(host: &str, sess: &Session) -> Vec<String> {
    let Ok((200, _, body)) = https(host, "GET", "/api/configuration/project", Some(sess), None)
    else {
        return Vec::new();
    };
    body.split("\"feature\"")
        .skip(1)
        .filter_map(|rest| {
            let rest = rest.trim_start().strip_prefix(':')?.trim_start().strip_prefix('"')?;
            Some(rest[..rest.find('"')?].to_string())
        })
        .collect()
}

/// `power_command` values, from the vendor UI's radio buttons.
fn power_command(cmd: &str) -> Option<u8> {
    Some(match cmd {
        "off" => 0,
        "on" => 1,
        "cycle" => 2,
        "reset" => 3,
        "softoff" => 5,
        _ => return None,
    })
}

pub fn power(host: &str, user: &str, pass: &str, cmd: &str) -> std::io::Result<String> {
    let code = power_command(cmd).ok_or_else(|| ioerr(format!("unknown power command {cmd}")))?;
    let sess = login(host, user, pass)?;
    let body = format!("{{\"power_command\":{code}}}");
    let r = https(host, "POST", "/api/actions/power", Some(&sess),
                  Some(("application/json", &body)));
    logout(host, &sess);
    let (status, _, resp) = r?;
    if !(200..300).contains(&status) {
        return Err(ioerr(format!("power {cmd} refused (HTTP {status}): {}",
            resp.trim().chars().take(160).collect::<String>())));
    }
    Ok(format!("power {cmd} accepted"))
}

/// Cold-reset the BMC itself (`racadm racreset` / `mc reset cold` equivalent).
pub fn reset_bmc(host: &str, user: &str, pass: &str) -> std::io::Result<String> {
    let sess = login(host, user, pass)?;
    let r = https(host, "POST", "/api/maintenance/reset", Some(&sess),
                  Some(("application/json", "{}")));
    // No logout: the BMC is on its way down and the session goes with it.
    let (status, _, resp) = r?;
    if !(200..300).contains(&status) {
        return Err(ioerr(format!("BMC reset refused (HTTP {status}): {}",
            resp.trim().chars().take(160).collect::<String>())));
    }
    Ok("BMC reset requested; it will be back in about a minute".into())
}

fn urlenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
