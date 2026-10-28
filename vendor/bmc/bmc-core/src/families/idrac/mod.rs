//! Dell iDRAC 9 (PowerEdge 14G/15G/16G) BMC support.
//!
//! Verified against a PowerEdge R440, iDRAC 9 firmware 4.40.00.00, Enterprise:
//!   - identify : GET /sysmgmt/2015/bmc/info (unauthenticated) -> firmware
//!                revision, server generation, licence, GUI title
//!   - web login: POST /sysmgmt/2015/bmc/session with the credentials in `user`
//!                and `password` *headers*, each wrapped in literal double
//!                quotes -> `-http-session-` cookie plus an XSRF token
//!   - console  : GET /sysmgmt/2015/server/vconsole?type=eHTML5 returns a launch
//!                URL carrying VCSID/VCSID2; the console itself is standard RFB
//!                over a WebSocket (see `kvm.rs`)
//!   - power    : Redfish ComputerSystem.Reset
//!   - vmedia   : Redfish InsertMedia (URL), or the push channel in idrac_kvm
//!
//! Two quirks shape this module. The GUI's static assets are stored gzipped and
//! Apache will not decompress them, so **every** request must offer
//! `Accept-Encoding: gzip` or it 404s. And iDRAC runs out of web sessions
//! quickly, answering 503 to further logins, so sessions must be released.

pub mod kvm;
pub mod vmedia;

use native_tls::TlsConnector;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const SYSTEM: &str = "/redfish/v1/Systems/System.Embedded.1";
const MANAGER: &str = "/redfish/v1/Managers/iDRAC.Embedded.1";
/// Redfish path of the virtual CD/DVD device.
const VM_CD: &str = "/redfish/v1/Managers/iDRAC.Embedded.1/VirtualMedia/CD";

/// What `detect` learns without credentials.
#[derive(Clone, Debug)]
pub struct Info {
    pub firmware: String,
    pub generation: String,
    pub license: String,
    pub name: String,
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

pub enum Auth<'a> {
    None,
    /// The `-http-session-` cookie plus the XSRF token that goes with it.
    Session(&'a str, &'a str),
    Basic(&'a str, &'a str),
    /// Credentials in Dell's quoted `user`/`password` headers (login only).
    Login(&'a str, &'a str),
}

/// One HTTPS request. Returns (status, headers, body).
fn https(
    host: &str,
    method: &str,
    path: &str,
    auth: Auth,
    body: Option<&str>,
    timeout: Duration,
) -> std::io::Result<(u16, String, Vec<u8>)> {
    let mut s = tls(host, timeout)?;
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\
         Accept-Encoding: gzip\r\nAccept: */*\r\n"
    );
    match auth {
        Auth::None => {}
        Auth::Session(cookie, xsrf) => {
            req.push_str(&format!("Cookie: -http-session-={cookie}\r\nXSRF-TOKEN: {xsrf}\r\n"))
        }
        Auth::Basic(u, p) => req.push_str(&format!(
            "Authorization: Basic {}\r\n",
            b64(format!("{u}:{p}").as_bytes())
        )),
        // Dell's login endpoint wants the values including the quote characters.
        Auth::Login(u, p) => req.push_str(&format!("user: \"{u}\"\r\npassword: \"{p}\"\r\n")),
    }
    if let Some(b) = body {
        req.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            b.len()
        ));
    } else if method == "POST" {
        // A bodyless POST still needs the length, but iDRAC answers 400 to a
        // DELETE that carries one — which silently broke session logout.
        req.push_str("Content-Length: 0\r\n");
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }
    if std::env::var("BMCKVM_DEBUG").is_ok() {
        eprintln!("[idrac] >>>\n{}<<<", req.replace('\r', ""));
    }
    s.write_all(req.as_bytes())?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).ok();

    let split = find(&raw, b"\r\n\r\n");
    let (head, rest) = match split {
        Some(i) => (String::from_utf8_lossy(&raw[..i]).into_owned(), raw[i + 4..].to_vec()),
        None => (String::from_utf8_lossy(&raw).into_owned(), Vec::new()),
    };
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    if std::env::var("BMCKVM_DEBUG").is_ok() {
        eprintln!("[idrac] <<< {}", head.lines().next().unwrap_or(""));
    }
    let lower = head.to_ascii_lowercase();
    let mut body = if lower.contains("transfer-encoding: chunked") {
        dechunk(&rest)
    } else {
        rest
    };
    if lower.contains("content-encoding: gzip") {
        body = crate::inflate::gunzip(&body);
    }
    Ok((status, head, body))
}

/// Identify an iDRAC 9 without credentials.
pub fn detect(host: &str) -> Option<Info> {
    let (status, _h, body) = https(host, "GET", "/sysmgmt/2015/bmc/info", Auth::None, None,
                                   Duration::from_millis(3000)).ok()?;
    if status != 200 {
        return None;
    }
    let text = String::from_utf8_lossy(&body);
    // iDRAC 8 serves the same endpoint, so the generation decides the family.
    let gen = json_str(&text, "ServerGen").unwrap_or_default();
    let fw = json_str(&text, "FwVer").unwrap_or_default();
    let major: u32 = fw.split('.').next().unwrap_or("0").parse().unwrap_or(0);
    if !text.contains("ServerGen") || major < 3 {
        return None;
    }
    Some(Info {
        firmware: fw,
        generation: gen,
        license: json_str(&text, "License").unwrap_or_default(),
        name: json_str(&text, "GUITitleBar").unwrap_or_default(),
    })
}

/// A logged-in iDRAC web session.
#[derive(Clone, Debug)]
pub struct Session {
    pub cookie: String,
    pub xsrf: String,
}

pub fn login(host: &str, user: &str, pass: &str) -> std::io::Result<Session> {
    let (status, head, _b) = https(host, "POST", "/sysmgmt/2015/bmc/session",
                                   Auth::Login(user, pass), None, Duration::from_secs(15))?;
    if status == 503 {
        return Err(ioerr(
            "iDRAC refused the login (HTTP 503) - it is out of web sessions; \
close idle sessions or wait for them to time out",
        ));
    }
    if !(200..300).contains(&status) {
        return Err(ioerr(&format!(
            "iDRAC login rejected (HTTP {status}) - check the username/password"
        )));
    }
    let cookie = header_value(&head, "set-cookie")
        .and_then(|v| v.split("-http-session-=").nth(1).map(|s| s.split(';').next().unwrap_or("").to_string()))
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ioerr("iDRAC login returned no session cookie"))?;
    let xsrf = header_value(&head, "xsrf-token").unwrap_or_default();
    Ok(Session { cookie, xsrf })
}

/// Release the web session. iDRAC's pool is small, so always do this.
pub fn logout(host: &str, s: &Session) {
    let _ = https(host, "DELETE", "/sysmgmt/2015/bmc/session",
                  Auth::Session(&s.cookie, &s.xsrf), None, Duration::from_secs(8));
}

/// Parameters for the virtual console, parsed from the launch URL.
#[derive(Clone, Debug)]
pub struct Launch {
    /// Console ticket, used as `?vck=` on the console WebSocket.
    pub vcsid: String,
    /// Second key, which the server demands in-band before it speaks RFB.
    pub vcsid2: String,
    pub port: u16,
}

/// Ask for an eHTML5 console session. The returned URL carries the tickets.
pub fn launch_console(host: &str, s: &Session) -> std::io::Result<Launch> {
    let (status, _h, body) = https(host, "GET", "/sysmgmt/2015/server/vconsole?type=eHTML5",
                                   Auth::Session(&s.cookie, &s.xsrf), None, Duration::from_secs(15))?;
    let text = String::from_utf8_lossy(&body);
    if !(200..300).contains(&status) {
        return Err(ioerr(&format!("console launch failed (HTTP {status})")));
    }
    let loc = json_str(&text, "Location")
        .ok_or_else(|| ioerr("console launch returned no Location"))?;
    let query = loc.split_once('?').map(|(_, q)| q).unwrap_or("");
    let get = |k: &str| -> Option<String> {
        query.split('&').find_map(|kv| {
            let (a, b) = kv.split_once('=')?;
            (a == k).then(|| b.to_string())
        })
    };
    let vcsid = get("VCSID").filter(|s| !s.is_empty())
        .ok_or_else(|| ioerr("console launch returned no VCSID (is Virtual Console enabled?)"))?;
    if std::env::var("BMCKVM_DEBUG").is_ok() {
        eprintln!("[idrac] Location={loc}");
    }
    Ok(Launch {
        vcsid,
        vcsid2: get("VCSID2").unwrap_or_default(),
        port: get("kvmport").and_then(|p| p.parse().ok()).unwrap_or(443),
    })
}

// ---------- Redfish: power, reset, virtual media ----------

/// Host power state.
pub fn power_state(host: &str, user: &str, pass: &str) -> Option<bool> {
    let (_, _, b) = https(host, "GET", SYSTEM, Auth::Basic(user, pass), None,
                          Duration::from_secs(8)).ok()?;
    json_str(&String::from_utf8_lossy(&b), "PowerState").map(|s| s.eq_ignore_ascii_case("On"))
}

/// Chassis power. `cmd` is on|off|reset|soft|cycle, as the other families use.
pub fn power(host: &str, user: &str, pass: &str, cmd: &str) -> std::io::Result<String> {
    let reset = match cmd {
        "on" => "On",
        "off" => "ForceOff",
        "soft" | "softoff" | "soft-off" => "GracefulShutdown",
        "reset" => "ForceRestart",
        "cycle" => "PowerCycle",
        other => return Err(ioerr(&format!("unknown power command: {other}"))),
    };
    // Redfish rejects On when already on (and vice versa) with a clear error;
    // check first so the common case reads as a no-op rather than a failure.
    match (cmd, power_state(host, user, pass)) {
        ("on", Some(true)) => return Ok("already on".into()),
        ("off" | "soft" | "softoff" | "soft-off", Some(false)) => return Ok("already off".into()),
        _ => {}
    }
    let body = format!("{{\"ResetType\":\"{reset}\"}}");
    let path = format!("{SYSTEM}/Actions/ComputerSystem.Reset");
    let (status, _h, b) = https(host, "POST", &path, Auth::Basic(user, pass), Some(&body),
                                Duration::from_secs(20))?;
    if (200..300).contains(&status) {
        Ok(format!("{reset} sent"))
    } else {
        Err(ioerr(&format!("iDRAC power {cmd} failed (HTTP {status}): {}",
                           message(&String::from_utf8_lossy(&b)))))
    }
}

/// Reset the iDRAC itself. The host keeps running.
pub fn reset_idrac(host: &str, user: &str, pass: &str) -> std::io::Result<String> {
    let path = format!("{MANAGER}/Actions/Manager.Reset");
    let (status, _h, b) = https(host, "POST", &path, Auth::Basic(user, pass),
                                Some("{\"ResetType\":\"GracefulRestart\"}"), Duration::from_secs(20))?;
    if (200..300).contains(&status) {
        Ok("iDRAC reset requested".into())
    } else {
        Err(ioerr(&format!("iDRAC reset failed (HTTP {status}): {}",
                           message(&String::from_utf8_lossy(&b)))))
    }
}

/// Currently inserted virtual CD image, if any.
pub fn vm_image(host: &str, user: &str, pass: &str) -> Option<String> {
    let (_, _, b) = https(host, "GET", VM_CD, Auth::Basic(user, pass), None,
                          Duration::from_secs(8)).ok()?;
    json_str(&String::from_utf8_lossy(&b), "Image").filter(|s| !s.is_empty())
}

/// Insert an ISO by URL. iDRAC fetches it itself, so `url` must be reachable
/// *from the BMC*.
pub fn insert_media(host: &str, user: &str, pass: &str, url: &str) -> std::io::Result<()> {
    let path = format!("{VM_CD}/Actions/VirtualMedia.InsertMedia");
    let body = format!("{{\"Image\":\"{}\",\"Inserted\":true,\"WriteProtected\":true}}", esc(url));
    let (status, _h, b) = https(host, "POST", &path, Auth::Basic(user, pass), Some(&body),
                                Duration::from_secs(30))?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(ioerr(&format!("insert media failed (HTTP {status}): {}",
                           message(&String::from_utf8_lossy(&b)))))
    }
}

pub fn eject_media(host: &str, user: &str, pass: &str) -> std::io::Result<()> {
    let path = format!("{VM_CD}/Actions/VirtualMedia.EjectMedia");
    let (status, _h, b) = https(host, "POST", &path, Auth::Basic(user, pass), Some("{}"),
                                Duration::from_secs(20))?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(ioerr(&format!("eject media failed (HTTP {status}): {}",
                           message(&String::from_utf8_lossy(&b)))))
    }
}

/// Where Redfish lists the BMC's sessions.
const SESSIONS: &str = "/redfish/v1/Sessions";

/// Ids of the sessions the BMC currently holds, as a baseline.
///
/// Redfish is the right channel for this: HTTP Basic costs no session slot
/// here, and it lists the console and virtual-media sessions (as `OEM`) that
/// the `/sysmgmt` API's own logout does not touch.
///
/// A listing that could not be read is an error, never an empty list: taken
/// as a baseline, an empty list would make every session on the BMC look like
/// one of ours. So is a paged one, since a collection can shift between pages
/// and whatever a baseline misses is deleted at the end.
pub fn session_ids(host: &str, user: &str, pass: &str) -> Result<Vec<String>, String> {
    collect_session_ids(false, |path| session_page(host, user, pass, path))
}

/// Ids of the sessions the BMC holds now, every page of them. Unlike a
/// baseline, a listing that misses one here only leaves it to time out.
fn current_session_ids(host: &str, user: &str, pass: &str) -> Result<Vec<String>, String> {
    collect_session_ids(true, |path| session_page(host, user, pass, path))
}

/// One page of the session collection, as text.
fn session_page(host: &str, user: &str, pass: &str, path: &str) -> Result<String, String> {
    let (status, _, b) = https(host, "GET", path, Auth::Basic(user, pass), None,
                               Duration::from_secs(10)).map_err(|e| e.to_string())?;
    if !(200..300).contains(&status) {
        return Err(format!("session list failed (HTTP {status})"));
    }
    Ok(String::from_utf8_lossy(&b).into_owned())
}

/// Read the session collection through `get`, following its pages if
/// `follow` and refusing a paged one otherwise. Links must stay on the BMC's
/// Redfish tree, and a page seen twice ends it.
fn collect_session_ids(follow: bool, mut get: impl FnMut(&str) -> Result<String, String>)
    -> Result<Vec<String>, String>
{
    let mut path = SESSIONS.to_string();
    let mut seen = std::collections::HashSet::new();
    let mut ids = Vec::new();
    loop {
        if !seen.insert(path.clone()) || seen.len() > 64 {
            return Err("session list pages loop or never end".into());
        }
        let body = get(&path)?;
        let page = parse_session_page(&body).ok_or_else(|| {
            // Worth seeing: nothing has checked this parse against every
            // firmware, and a mismatch means sessions are left to time out.
            format!("session list was not a Redfish collection: \"{}\"", excerpt(&body, 120))
        })?;
        ids.extend(page.ids);
        match page.next {
            None => return Ok(ids),
            Some(_) if !follow => return Err("session list came in pages".into()),
            Some(link) => path = crate::event_log::safe_path(&link)?.to_string(),
        }
    }
}

/// One page of a Redfish SessionCollection.
struct SessionPage {
    ids: Vec<String>,
    /// `Members@odata.nextLink`, when there are more.
    next: Option<String>,
}

/// The members of a SessionCollection page, or None when `body` is not one.
fn parse_session_page(body: &str) -> Option<SessionPage> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let ids = match v.get("Members") {
        Some(members) => members.as_array()?.iter()
            .filter_map(|m| m.get("@odata.id")?.as_str())
            // Every id is sent a DELETE, so nothing but a session resource.
            .filter(|id| id.contains("/Sessions/") && !id.ends_with("/Sessions"))
            .map(str::to_string)
            .collect(),
        // An empty collection may leave Members out, so long as it says so.
        None if v.get("Members@odata.count").and_then(|c| c.as_u64()) == Some(0) => Vec::new(),
        None => return None,
    };
    let next = v.get("Members@odata.nextLink").and_then(|n| n.as_str()).map(str::to_string);
    Some(SessionPage { ids, next })
}

/// The first `max` characters of `body`, trimmed, with control characters
/// escaped so the excerpt stays on one line.
fn excerpt(body: &str, max: usize) -> String {
    let body = body.trim();
    let mut out: String = body.chars().take(max)
        .flat_map(|c| if c.is_control() { c.escape_default().collect() } else { vec![c] })
        .collect();
    if body.chars().count() > max {
        out.push('…');
    }
    out
}

/// The sessions to delete: those in `current` that were not in `baseline`.
/// Without a baseline there is no telling ours from sessions that were there
/// before us, so none.
fn sessions_to_release(baseline: Option<&[String]>, current: &[String]) -> Vec<String> {
    let Some(baseline) = baseline else { return Vec::new() };
    current.iter().filter(|id| !baseline.contains(id)).cloned().collect()
}

/// The baseline a release compares against, or — when the listing failed at
/// connect — why there is none, worded for the status line or stderr.
fn baseline_for_release(baseline: &Result<Vec<String>, String>) -> Result<&[String], String> {
    baseline.as_deref().map_err(|cause| {
        format!("could not list iDRAC sessions when connecting ({cause}); leaving ours to time out")
    })
}

/// Delete the sessions that appeared since `baseline` was taken, returning
/// how many went.
///
/// Opening a console or virtual-media channel creates a session of its own that
/// **closing the socket does not release** — it lingers until it times out, and
/// with `VirtualMedia.1.MaxSessions` of 1 that blocks the next mount outright.
/// Comparing against a snapshot spares every session that existed before we
/// connected. It cannot tell ours from one someone else opened while ours was
/// up, though, and deletes that one too (telling them apart by `UserName` or
/// `SessionType` needs checking against a live iDRAC first). With no baseline
/// (the listing failed at connect), or no listing now, nothing is deleted and
/// the error says why: ours time out on their own, whereas someone else's
/// console would not come back.
pub fn release_new_sessions(host: &str, user: &str, pass: &str,
                            baseline: &Result<Vec<String>, String>)
    -> Result<usize, String>
{
    let baseline = baseline_for_release(baseline)?;
    let current = current_session_ids(host, user, pass)
        .map_err(|e| format!("could not list iDRAC sessions ({e}); leaving ours to time out"))?;
    let mut n = 0;
    for id in sessions_to_release(Some(baseline), &current) {
        if https(host, "DELETE", &id, Auth::Basic(user, pass), None, Duration::from_secs(10))
            .map(|(s, _, _)| (200..300).contains(&s))
            .unwrap_or(false)
        {
            n += 1;
        }
    }
    Ok(n)
}

/// A snapshot of the host's screen, as the iDRAC dashboard shows it.
///
/// This is the BMC's own periodic capture, not a console session: it costs no
/// console slot and needs no video decoding, which makes it cheap enough to
/// fetch whenever a host is selected.
pub fn preview(host: &str, s: &Session) -> Option<crate::image::Image> {
    // The BMC refreshes its capture on request; the redirect it answers with is
    // the acknowledgement, not an error.
    let _ = https(host, "GET", "/sysmgmt/2015/server/preview",
                  Auth::Session(&s.cookie, &s.xsrf), None, Duration::from_secs(8));
    let (status, _h, body) = https(host, "GET", "/capconsole/scapture0.png",
                                   Auth::Session(&s.cookie, &s.xsrf), None,
                                   Duration::from_secs(10)).ok()?;
    if status != 200 {
        return None;
    }
    crate::image::decode(&body)
}

/// Delete every web session belonging to `user`. iDRAC's pool is small enough
/// that a few abandoned sessions lock everyone out, and Redfish (HTTP Basic,
/// which does not consume a pool slot here) is the way back in.
pub fn clear_sessions(host: &str, user: &str, pass: &str) -> std::io::Result<usize> {
    let ids = current_session_ids(host, user, pass).map_err(|e| ioerr(&e))?;
    let mut n = 0;
    for id in ids {
        if https(host, "DELETE", &id, Auth::Basic(user, pass), None, Duration::from_secs(10))
            .map(|(s, _, _)| (200..300).contains(&s))
            .unwrap_or(false)
        {
            n += 1;
        }
    }
    Ok(n)
}

// ---------- helpers ----------

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

fn header_value(head: &str, name: &str) -> Option<String> {
    head.lines()
        .find(|l| l.to_ascii_lowercase().starts_with(&format!("{name}:")))
        .map(|l| l.split_once(':').map(|(_, v)| v.trim().to_string()).unwrap_or_default())
}

fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < body.len() {
        let Some(nl) = find(&body[i..], b"\r\n") else { break };
        let len = usize::from_str_radix(
            String::from_utf8_lossy(&body[i..i + nl]).trim().split(';').next().unwrap_or(""),
            16,
        )
        .unwrap_or(0);
        i += nl + 2;
        if len == 0 || i + len > body.len() {
            break;
        }
        out.extend_from_slice(&body[i..i + len]);
        i += len + 2;
    }
    out
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

/// Best-effort extraction of a Redfish extended-error message.
fn message(body: &str) -> String {
    json_str(body, "Message").unwrap_or_else(|| body.trim().chars().take(200).collect())
}

fn esc(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\\' => "\\\\".chars().collect(),
            c => vec![c],
        })
        .collect()
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
    use super::{baseline_for_release, collect_session_ids, excerpt, parse_session_page,
                sessions_to_release, SESSIONS};
    use std::collections::HashMap;

    /// A SessionCollection as the DMTF schema defines it: the collection's own
    /// `@odata.id`, then `Members` as an array of `idRef`s.
    const COLLECTION: &str = r##"{
        "@odata.context": "/redfish/v1/$metadata#SessionCollection.SessionCollection",
        "@odata.id": "/redfish/v1/SessionService/Sessions",
        "@odata.type": "#SessionCollection.SessionCollection",
        "Description": "Session Collection",
        "Name": "Session Collection",
        "Members": [
            {"@odata.id": "/redfish/v1/SessionService/Sessions/12"},
            {"@odata.id": "/redfish/v1/SessionService/Sessions/15"}
        ],
        "Members@odata.count": 2
    }"##;

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// The listing as `collect_session_ids` would fetch it, from canned pages.
    fn listing(pages: &[(&str, &str)], follow: bool) -> Result<Vec<String>, String> {
        let pages: HashMap<String, String> =
            pages.iter().map(|(p, b)| (p.to_string(), b.to_string())).collect();
        collect_session_ids(follow, |path| {
            pages.get(path).cloned().ok_or_else(|| format!("no page at {path}"))
        })
    }

    fn one_page(body: &str) -> Result<Vec<String>, String> {
        listing(&[(SESSIONS, body)], false)
    }

    #[test]
    fn lists_the_members_of_a_session_collection() {
        assert_eq!(
            one_page(COLLECTION),
            Ok(ids(&["/redfish/v1/SessionService/Sessions/12",
                     "/redfish/v1/SessionService/Sessions/15"]))
        );
    }

    #[test]
    fn an_empty_collection_is_an_empty_list() {
        let body = r##"{"@odata.id": "/redfish/v1/SessionService/Sessions",
                       "@odata.type": "#SessionCollection.SessionCollection",
                       "Name": "Session Collection",
                       "Members": [], "Members@odata.count": 0}"##;
        assert_eq!(one_page(body), Ok(Vec::new()));
        // An empty collection may leave Members out, if it counts none.
        let bare = r##"{"@odata.type": "#SessionCollection.SessionCollection",
                       "Members@odata.count": 0}"##;
        assert_eq!(one_page(bare), Ok(Vec::new()));
        // A null next link is the last page, not a paged collection.
        let last = r##"{"Members": [{"@odata.id": "/redfish/v1/SessionService/Sessions/4"}],
                       "Members@odata.nextLink": null}"##;
        assert_eq!(one_page(last), Ok(ids(&["/redfish/v1/SessionService/Sessions/4"])));
    }

    #[test]
    fn anything_but_a_whole_collection_is_no_list() {
        // An error body, an HTML page, a body cut short, an empty one and one
        // without members must never read as "no sessions": as a baseline
        // that deletes everyone's.
        let error = r##"{"error": {"code": "Base.1.0.GeneralError",
                        "message": "A general error has occurred."}}"##;
        for body in [error, "<html><body>Not Found</body></html>",
                     &COLLECTION[..COLLECTION.len() / 2], "",
                     r##"{"Name": "Session Collection", "Members@odata.count": 2}"##] {
            assert!(one_page(body).is_err(), "{body:?} read as a list");
        }
        // And the error carries enough of the body to say what came back.
        let e = one_page("<html><body>Not Found</body></html>").unwrap_err();
        assert!(e.contains("<html><body>Not Found</body></html>"), "{e}");
    }

    #[test]
    fn a_paged_baseline_is_refused() {
        // A collection can shift between pages, and whatever a baseline
        // misses is deleted at the end.
        let first = r##"{"Members": [{"@odata.id": "/redfish/v1/SessionService/Sessions/1"}],
                        "Members@odata.count": 2,
                        "Members@odata.nextLink": "/redfish/v1/Sessions?$skip=1"}"##;
        let second = r##"{"Members": [{"@odata.id": "/redfish/v1/SessionService/Sessions/2"}]}"##;
        let pages = [(SESSIONS, first), ("/redfish/v1/Sessions?$skip=1", second)];
        assert!(listing(&pages, false).is_err());
        // Whereas a listing at release follows them: missing one there only
        // leaves it to time out.
        assert_eq!(listing(&pages, true),
                   Ok(ids(&["/redfish/v1/SessionService/Sessions/1",
                            "/redfish/v1/SessionService/Sessions/2"])));
    }

    #[test]
    fn paging_stays_on_the_bmc_and_ends() {
        let looping = r##"{"Members": [], "Members@odata.nextLink": "/redfish/v1/Sessions"}"##;
        assert!(listing(&[(SESSIONS, looping)], true).is_err());
        for link in ["https://elsewhere.example/redfish/v1/Sessions",
                     "/redfish/v1/../../etc/passwd"] {
            let away = format!(r##"{{"Members": [], "Members@odata.nextLink": "{link}"}}"##);
            assert!(listing(&[(SESSIONS, &away), (link, COLLECTION)], true).is_err(), "{link}");
        }
    }

    #[test]
    fn only_session_resources_are_listed() {
        // Each id is later sent a DELETE, so nothing outside the collection.
        let body = r##"{"Members": [
            {"@odata.id": "/redfish/v1/SessionService/Sessions/3"},
            {"@odata.id": "/redfish/v1/Managers/iDRAC.Embedded.1"},
            {"@odata.id": "/redfish/v1/SessionService/Sessions"},
            {"Id": "4"}
        ]}"##;
        assert_eq!(parse_session_page(body).map(|p| p.ids),
                   Some(ids(&["/redfish/v1/SessionService/Sessions/3"])));
    }

    #[test]
    fn an_excerpt_is_short_and_printable() {
        assert_eq!(excerpt("  {\"a\":\r\n1}\u{1b}  ", 120), "{\"a\":\\r\\n1}\\u{1b}");
        let long = "x".repeat(300);
        assert_eq!(excerpt(&long, 120), format!("{}…", "x".repeat(120)));
        assert_eq!(excerpt("", 120), "");
    }

    #[test]
    fn a_failed_baseline_says_why_at_release() {
        let failed: Result<Vec<String>, String> = Err("session list failed (HTTP 503)".into());
        let e = baseline_for_release(&failed).unwrap_err();
        assert!(e.contains("when connecting (session list failed (HTTP 503))"), "{e}");
        assert!(e.ends_with("leaving ours to time out"), "{e}");
        let taken: Result<Vec<String>, String> = Ok(ids(&["/s/1"]));
        assert_eq!(baseline_for_release(&taken), Ok(&ids(&["/s/1"])[..]));
    }

    #[test]
    fn without_a_baseline_nothing_is_released() {
        let current = ids(&["/s/1", "/s/2"]);
        assert!(sessions_to_release(None, &current).is_empty());
    }

    #[test]
    fn only_sessions_new_since_the_baseline_are_released() {
        let baseline = ids(&["/s/1", "/s/2"]);
        let current = ids(&["/s/1", "/s/2", "/s/7", "/s/8"]);
        assert_eq!(sessions_to_release(Some(&baseline), &current), ids(&["/s/7", "/s/8"]));
    }

    #[test]
    fn an_unchanged_list_releases_nothing() {
        let baseline = ids(&["/s/1", "/s/2"]);
        assert!(sessions_to_release(Some(&baseline), &baseline).is_empty());
        // Sessions that ended meanwhile are not ours to delete either.
        assert!(sessions_to_release(Some(&baseline), &ids(&["/s/2"])).is_empty());
    }
}
