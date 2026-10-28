//! HP/HPE iLO 4 (ProLiant Gen8/Gen9) BMC support.
//!
//! Verified against a DL380 Gen9, iLO 4 firmware 2.82:
//!   - identify : GET /xmldata?item=All  (unauthenticated) -> RIMP XML naming
//!                "Integrated Lights-Out 4", the server model and firmware
//!   - web login: POST /json/login_session {"method":"login",...} -> session_key,
//!                the 32-char credential the console channels authenticate with
//!   - console  : Integrated Remote Console over WebSocket (see `kvm.rs`)
//!   - power    : POST /json/host_power {"method": ...}
//!   - vmedia   : Redfish InsertVirtualMedia, which takes an HTTP(S) URL — the
//!                ISO is served from this machine (see httpd.rs) rather than
//!                pushed over a SCSI channel like the other two families
//!   - iLO reset: Redfish Manager.Reset

pub mod kvm;
pub mod vmedia;

use native_tls::TlsConnector;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Redfish path of the CD/DVD virtual-media device (1 is the floppy/USB key).
const VM_CDROM: &str = "/redfish/v1/Managers/1/VirtualMedia/2";

/// What `detect` learns about an iLO without logging in.
#[derive(Clone, Debug)]
pub struct Info {
    pub model: String,
    pub firmware: String,
    pub serial: String,
    /// The server's overall health in Redfish's words ("OK", "Warning",
    /// "Critical"), which the GUI reads for every family.
    pub health: Option<&'static str>,
}

fn tls(host: &str, timeout: Duration) -> std::io::Result<native_tls::TlsStream<TcpStream>> {
    let c = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .map_err(oerr)?;
    let tcp = crate::net::connect(host, 443, Some(timeout))?;
    tcp.set_read_timeout(Some(timeout))?;
    c.connect(host, tcp).map_err(oerr)
}

/// Authentication for a request: none, the web session cookie, or HTTP Basic
/// (Redfish accepts Basic; the /json endpoints want the cookie).
pub enum Auth<'a> {
    None,
    Cookie(&'a str),
    Basic(&'a str, &'a str),
}

/// One HTTPS request/response. Returns (status, body).
fn https(
    host: &str,
    method: &str,
    path: &str,
    auth: Auth,
    body: Option<&str>,
    timeout: Duration,
) -> std::io::Result<(u16, String)> {
    let mut s = tls(host, timeout)?;
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    match auth {
        Auth::None => {}
        Auth::Cookie(k) => req.push_str(&format!("Cookie: sessionKey={k}\r\n")),
        Auth::Basic(u, p) => {
            req.push_str(&format!("Authorization: Basic {}\r\n", b64(format!("{u}:{p}").as_bytes())))
        }
    }
    if let Some(b) = body {
        req.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            b.len()
        ));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }
    s.write_all(req.as_bytes())?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).ok();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let body = match text.find("\r\n\r\n") {
        Some(i) => text[i + 4..].to_string(),
        None => String::new(),
    };
    Ok((status, body))
}

/// Identify an iLO 4 without credentials. `/xmldata` is public on every iLO.
pub fn detect(host: &str) -> Option<Info> {
    let (status, body) = https(host, "GET", "/xmldata?item=All", Auth::None, None,
                               Duration::from_millis(2500)).ok()?;
    if status != 200 {
        return None;
    }
    parse_xmldata(&body)
}

fn parse_xmldata(body: &str) -> Option<Info> {
    if !body.contains("<RIMP>") {
        return None;
    }
    // <MP><PN>Integrated Lights-Out 4 (iLO 4)</PN><FWRI>2.82</FWRI>...
    let mp = between(&body, "<MP>", "</MP>").unwrap_or("");
    let pn = between(mp, "<PN>", "</PN>").unwrap_or("");
    if !pn.contains("iLO 4") && !pn.contains("Lights-Out 4") {
        return None;
    }
    // <HEALTH><STATUS>2</STATUS></HEALTH> is HP's condition code, on the scale
    // its SNMP agents use: 1 other, 2 ok, 3 degraded, 4 failed.
    let health = between(body, "<HEALTH>", "</HEALTH>")
        .and_then(|h| between(h, "<STATUS>", "</STATUS>"))
        .and_then(|code| match code.trim() {
            "2" => Some("OK"),
            "3" => Some("Warning"),
            "4" => Some("Critical"),
            _ => None,
        });
    Some(Info {
        model: between(body, "<SPN>", "</SPN>").unwrap_or("ProLiant").trim().to_string(),
        firmware: between(mp, "<FWRI>", "</FWRI>").unwrap_or("").trim().to_string(),
        serial: between(body, "<SBSN>", "</SBSN>").unwrap_or("").trim().to_string(),
        health,
    })
}

/// A logged-in iLO web session. `key` is the console credential.
#[derive(Clone, Debug)]
pub struct Session {
    pub key: String,
    pub remote_console: bool,
    pub virtual_media: bool,
}

/// Log in and return the session key the console channels authenticate with.
pub fn login(host: &str, user: &str, pass: &str) -> std::io::Result<Session> {
    let body = format!(
        "{{\"method\":\"login\",\"user_login\":\"{}\",\"password\":\"{}\"}}",
        esc(user),
        esc(pass)
    );
    let (status, resp) = https(host, "POST", "/json/login_session", Auth::None, Some(&body),
                               Duration::from_secs(10))?;
    let key = json_str(&resp, "session_key").unwrap_or_default();
    if status != 200 || key.is_empty() {
        // iLO holds only a handful of web sessions and returns the same generic
        // failure when they are all taken, so say so rather than blame the
        // password: sessions linger for the configured idle timeout.
        let detail = json_str(&resp, "details").unwrap_or_default();
        return Err(ioerr(&format!(
            "iLO login rejected{} - check the username/password, or wait for idle \
sessions to expire (iLO allows only a few at a time)",
            if detail.is_empty() { String::new() } else { format!(" ({detail})") })));
    }
    Ok(Session {
        key,
        remote_console: json_num(&resp, "remote_cons_priv").unwrap_or(0) != 0,
        virtual_media: json_num(&resp, "virtual_media_priv").unwrap_or(0) != 0,
    })
}

/// Keep the web session from timing out (iLO expires idle sessions, and the
/// console's virtual-media channel authenticates with the same key). Returns
/// false once the session is gone.
pub fn tickle(host: &str, key: &str) -> bool {
    match https(host, "GET", "/json/session_tickle", Auth::Cookie(key), None,
                Duration::from_secs(8)) {
        Ok((status, body)) => status == 200 && !body.contains("LOST_SESSION"),
        Err(_) => false,
    }
}

/// Drop the web session (iLO allows only a handful at a time).
pub fn logout(host: &str, key: &str) {
    let _ = https(host, "POST", "/json/login_session", Auth::Cookie(key),
                  Some("{\"method\":\"logout\"}"), Duration::from_secs(5));
}

/// Host power state: Some(true) = on.
pub fn power_state(host: &str, key: &str) -> Option<bool> {
    let (_, body) = https(host, "GET", "/json/host_power", Auth::Cookie(key), None,
                          Duration::from_secs(6)).ok()?;
    json_str(&body, "hostpwr_state").map(|s| s.eq_ignore_ascii_case("ON"))
}

/// Chassis power. `cmd` is on|off|reset|soft|cycle, matching the other families.
///
/// iLO exposes physical button semantics rather than on/off verbs: a momentary
/// press toggles (and is the ACPI-graceful path), a press-and-hold forces off.
pub fn power(host: &str, user: &str, pass: &str, cmd: &str) -> std::io::Result<String> {
    let sess = login(host, user, pass)?;
    let on = power_state(host, &sess.key);
    let method = match cmd {
        "on" => {
            if on == Some(true) {
                logout(host, &sess.key);
                return Ok("already on".into());
            }
            "press_power_button"
        }
        "off" => "hold_power_button",
        "soft" | "softoff" | "soft-off" => {
            if on == Some(false) {
                logout(host, &sess.key);
                return Ok("already off".into());
            }
            "press_power_button"
        }
        "reset" => "system_reset",
        "cycle" | "coldboot" => "system_coldboot",
        other => {
            logout(host, &sess.key);
            return Err(ioerr(&format!("unknown power command: {other}")));
        }
    };
    let body = format!("{{\"method\":\"{method}\"}}");
    let (status, resp) = https(host, "POST", "/json/host_power", Auth::Cookie(&sess.key),
                               Some(&body), Duration::from_secs(10))?;
    logout(host, &sess.key);
    if (200..300).contains(&status) {
        Ok(format!("{method} sent"))
    } else {
        Err(ioerr(&format!("iLO power {cmd} failed (HTTP {status}): {}", resp.trim())))
    }
}

/// Cold-reset the iLO itself — no effect on host power; the host OS keeps running.
///
/// Redfish is tried first, then IPMI. The fallback matters: iLO keeps only a
/// handful of web sessions and *Redfish under HTTP Basic consumes one too*, so
/// once the pool is exhausted every HTTPS API returns "no valid session" — which
/// is precisely when a reset is what you want. IPMI has no such pool.
pub fn reset_ilo(host: &str, user: &str, pass: &str) -> std::io::Result<String> {
    let redfish = https(host, "POST", "/redfish/v1/Managers/1/Actions/Manager.Reset/",
                        Auth::Basic(user, pass), Some("{}"), Duration::from_secs(10));
    let detail = match redfish {
        Ok((status, _)) if (200..300).contains(&status) => {
            return Ok("iLO reset requested".into())
        }
        Ok((status, body)) => format!("HTTP {status}: {}", body.trim()),
        Err(e) => e.to_string(),
    };
    match crate::families::quanta::ipmi_mc_reset(host, user, pass) {
        Ok(_) => Ok("iLO reset requested over IPMI".into()),
        Err(e) => Err(ioerr(&format!("iLO reset failed (Redfish: {detail}; IPMI: {e})"))),
    }
}

/// Currently inserted virtual CD image URL, if any.
pub fn vm_image(host: &str, user: &str, pass: &str) -> Option<String> {
    let (_, body) = https(host, "GET", VM_CDROM, Auth::Basic(user, pass), None,
                          Duration::from_secs(8)).ok()?;
    json_str(&body, "Image").filter(|s| !s.is_empty())
}

/// Insert an ISO by URL as the virtual CD-ROM. iLO fetches the image itself over
/// HTTP, so `url` must be reachable *from the BMC*.
pub fn insert_media(host: &str, user: &str, pass: &str, url: &str, boot_next: bool)
    -> std::io::Result<()>
{
    let path = format!("{VM_CDROM}/Actions/Oem/Hp/HpiLOVirtualMedia.InsertVirtualMedia/");
    let body = format!("{{\"Image\":\"{}\"}}", esc(url));
    let (status, resp) = https(host, "POST", &path, Auth::Basic(user, pass), Some(&body),
                               Duration::from_secs(20))?;
    if !(200..300).contains(&status) {
        return Err(ioerr(&format!("insert media failed (HTTP {status}): {}", resp.trim())));
    }
    if boot_next {
        let b = "{\"Oem\":{\"Hp\":{\"BootOnNextServerReset\":true}}}";
        let (s2, r2) = https(host, "PATCH", VM_CDROM, Auth::Basic(user, pass), Some(b),
                             Duration::from_secs(15))?;
        if !(200..300).contains(&s2) {
            return Err(ioerr(&format!("set boot-on-next-reset failed (HTTP {s2}): {}", r2.trim())));
        }
    }
    Ok(())
}

/// Eject the virtual CD-ROM.
pub fn eject_media(host: &str, user: &str, pass: &str) -> std::io::Result<()> {
    let path = format!("{VM_CDROM}/Actions/Oem/Hp/HpiLOVirtualMedia.EjectVirtualMedia/");
    let (status, resp) = https(host, "POST", &path, Auth::Basic(user, pass), Some("{}"),
                               Duration::from_secs(15))?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(ioerr(&format!("eject media failed (HTTP {status}): {}", resp.trim())))
    }
}

// ---------- small helpers ----------

fn between<'a>(s: &'a str, a: &str, b: &str) -> Option<&'a str> {
    let i = s.find(a)? + a.len();
    let j = s[i..].find(b)? + i;
    Some(&s[i..j])
}

fn json_str(body: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\"");
    let i = body.find(&pat)?;
    let rest = body[i + pat.len()..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let e = rest.find('"')?;
    Some(rest[..e].to_string())
}

fn json_num(body: &str, key: &str) -> Option<i64> {
    let pat = format!("\"{key}\"");
    let i = body.find(&pat)?;
    let rest = body[i + pat.len()..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let end = rest.find(|c: char| !c.is_ascii_digit() && c != '-').unwrap_or(rest.len());
    rest[..end].parse().ok()
}

/// Escape a value for embedding in a JSON string literal.
fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
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

#[cfg(test)]
mod tests {
    use super::parse_xmldata;

    /// `/xmldata?item=All` in the shape iLO 4 2.82 answers with, cut to the
    /// elements read here; the NIC's <STATUS> comes before the health's.
    fn xmldata(serial: &str, health: &str) -> String {
        format!(
            "<RIMP>\n<HSI>\n<SBSN>{serial}</SBSN>\n<SPN>ProLiant DL360 Gen9</SPN>\n<NICS>\n<NIC>\n\
             <PORT>1</PORT>\n<STATUS>OK</STATUS>\n</NIC>\n</NICS>\n</HSI>\n<MP>\n<ST>1</ST>\n\
             <PN>Integrated Lights-Out 4 (iLO 4)</PN>\n<FWRI>2.82</FWRI>\n</MP>\n{health}</RIMP>\n"
        )
    }

    #[test]
    fn reads_model_firmware_and_serial() {
        let info = parse_xmldata(&xmldata("[serial]  ", "")).unwrap();
        assert_eq!(info.model, "ProLiant DL360 Gen9");
        assert_eq!(info.firmware, "2.82");
        assert_eq!(info.serial, "[serial]");
    }

    #[test]
    fn a_serial_never_set_reads_as_empty() {
        // A system board whose serial was never set reports sixteen spaces.
        assert_eq!(parse_xmldata(&xmldata(&" ".repeat(16), "")).unwrap().serial, "");
    }

    #[test]
    fn health_codes_become_redfish_words() {
        let health = |code: &str| {
            parse_xmldata(&xmldata("", &format!("<HEALTH>\n<STATUS>{code}</STATUS>\n</HEALTH>\n")))
                .unwrap()
                .health
        };
        assert_eq!(health("2"), Some("OK"));
        assert_eq!(health("3"), Some("Warning"));
        assert_eq!(health("4"), Some("Critical"));
        assert_eq!(health("1"), None);
        // Older firmware has no <HEALTH> at all.
        assert_eq!(parse_xmldata(&xmldata("", "")).unwrap().health, None);
    }

    #[test]
    fn other_lights_out_generations_are_not_ilo4() {
        let ilo5 = xmldata("", "").replace("Lights-Out 4 (iLO 4)", "Lights-Out 5 (iLO 5)");
        assert!(parse_xmldata(&ilo5).is_none());
    }
}
