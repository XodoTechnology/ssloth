//! Dell iDRAC 8 (PowerEdge 13G): Dell's own web stack wrapped around an Avocent
//! console.
//!
//! Verified against a PowerEdge R630, iDRAC 8 firmware 2.84.84.84:
//!
//!   - identify : `GET /session?aimGetProp=fwVersion,sysDesc`, unauthenticated
//!   - web login: `POST /data/login` (form) -> XML whose `forwardUrl` carries
//!                both CSRF tokens (`index.html?ST1=…,ST2=…`) and a
//!                `-http-session-` cookie
//!   - console  : `viewer.jnlp(…)` mints one-shot credentials for the Java
//!                client's port (5900), which speaks the same APCP/AVSP as the
//!                MergePoint family, so `avocent::kvm` drives it unchanged. The
//!                video is Avocent DVC (`avct_dvc.rs`) rather than ASPEED JPEG.
//!   - vmedia   : `vmStart(…)` mints a second pair for AVMP on the same port —
//!                again the MergePoint protocol, through `avocent::vmedia`
//!   - preview  : `data?get=consolepreview[manual <ms>]`, then the PNG it wrote
//!   - power    : Redfish, shared with iDRAC 9. IPMI-over-LAN ships disabled.
//!
//! The 9's endpoints are absent: `/sysmgmt/2015/bmc/info` redirects to the
//! login page, which is how this firmware used to fall through to the ATEN
//! guess. The HTML5 viewer (`PluginType=2`) tunnels the same APCP over
//! WebSockets on the same port; the raw socket is the shorter path to it.
//! See docs/IDRAC8-CONSOLE.md.

use super::avocent::{self, https, xml, Launch, Session};

/// What an unauthenticated probe can tell us.
#[derive(Clone, Debug)]
pub struct Info {
    pub firmware: String,
    /// The server model, e.g. "PowerEdge R630".
    pub model: String,
}

fn ioerr<S: AsRef<str>>(m: S) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, m.as_ref().to_string())
}

fn json_str(body: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\"");
    let rest = &body[body.find(&pat)? + pat.len()..];
    let rest = &rest[rest.find('"')? + 1..];
    Some(rest[..rest.find('"')?].to_string())
}

fn stamp() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Identify an iDRAC 7/8 without credentials. The 9 never answers this
/// property query, and is probed first anyway.
pub fn detect(host: &str) -> Option<Info> {
    // Unauthenticated, the BMC answers only the exact property lists its own
    // login page asks for — `hostname,fwVersion` or `fwVersion,sysDesc` get
    // the login redirect. This is the login page's; `fwVersion` alone also
    // passes, and is the fallback should a firmware word it differently.
    let text = [
        "/session?aimGetProp=hostname,gui_str_title_bar,OEMHostName,fwVersion,sysDesc",
        "/session?aimGetProp=fwVersion",
    ]
    .iter()
    .find_map(|q| {
        let (status, _, body) = https(host, "GET", q, None, None).ok()?;
        let text = String::from_utf8_lossy(&body).into_owned();
        (status == 200 && text.contains("aimGetProp")).then_some(text)
    })?;
    let firmware = json_str(&text, "fwVersion")?;
    // iDRAC 7 and 8 are 1.x and 2.x; 3.x and up is the 9's numbering.
    let major: u32 = firmware.split('.').next()?.parse().ok()?;
    if major >= 3 {
        return None;
    }
    Some(Info { firmware, model: json_str(&text, "sysDesc").unwrap_or_default() })
}

/// `authResult` values, from the login page's own message table.
fn login_reason(code: i32) -> &'static str {
    match code {
        1 => "wrong username or password",
        2 => "missing username",
        3 => "missing password",
        4 => "the account lacks the login privilege",
        5 => "the maximum number of sessions is reached",
        _ => "login refused",
    }
}

pub fn login(host: &str, user: &str, pass: &str) -> std::io::Result<Session> {
    let form = format!("user={}&password={}", avocent::urlenc(user), avocent::urlenc(pass));
    let (status, head, body) = https(host, "POST", "/data/login", None, Some(&form))?;
    let text = String::from_utf8_lossy(&body).into_owned();
    if status != 200 {
        return Err(ioerr(format!("login failed (HTTP {status})")));
    }
    match xml(&text, "authResult").and_then(|v| v.parse::<i32>().ok()) {
        Some(0) => {}
        Some(code) => return Err(ioerr(format!("{} (authResult {code})", login_reason(code)))),
        None => return Err(ioerr("login response was not the expected XML")),
    }
    let cookie = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("set-cookie: -http-session-="))
        .and_then(|l| l.splitn(2, ": ").nth(1))
        .and_then(|v| v.split(';').next())
        .map(|s| s.trim().to_string())
        .ok_or_else(|| ioerr("login set no -http-session- cookie"))?;
    // Unlike the MergePoint stack, the tokens come with the login rather than
    // inside index.html: forwardUrl is `index.html?ST1=<hex>,ST2=<hex>`.
    let fwd = xml(&text, "forwardUrl").unwrap_or_default();
    let token = |k: &str| {
        fwd.split(['?', ',', '&'])
            .find_map(|p| p.strip_prefix(k))
            .map(str::to_string)
    };
    let (Some(st1), Some(st2)) = (token("ST1="), token("ST2=")) else {
        let s = Session { cookie, st1: String::new(), st2: String::new() };
        logout(host, &s);
        return Err(ioerr("the login carried no CSRF tokens"));
    };
    Ok(Session { cookie, st1, st2 })
}

/// End the web session. The pool is small and a leaked session holds a slot
/// for the idle timeout — and, as on MergePoint, the console and media
/// credentials die with it, so this runs only once those are done.
pub fn logout(host: &str, sess: &Session) {
    let _ = https(host, "GET", "/data/logout", Some(sess), None);
}

/// Pull `<argument>key=value</argument>` out of a JNLP.
fn jnlp_arg(text: &str, k: &str) -> Option<String> {
    let pat = format!("<argument>{k}=");
    let i = text.find(&pat)? + pat.len();
    let j = text[i..].find('<')? + i;
    Some(text[i..j].trim().to_string())
}

/// GET a JNLP. The parameters are a function call — `<ip>@<ipv6 flag>@<title>
/// @<cache buster>@ST1=<token>` — and the CSRF token rides inside it.
fn jnlp(host: &str, sess: &Session, call: &str) -> std::io::Result<String> {
    let path = format!("{call}({host}@0@bmc-kvm@{}@ST1={})", stamp(), sess.st1);
    let (status, _, body) = https(host, "GET", &path, Some(sess), None)?;
    let text = String::from_utf8_lossy(&body).into_owned();
    if status != 200 || !text.contains("<jnlp") {
        return Err(ioerr(format!("launch refused (HTTP {status})")));
    }
    Ok(text)
}

/// Mint console credentials. The user comes back as `<slot>@@<number>` and is
/// sent to the console exactly so.
pub fn kvm_launch(host: &str, sess: &Session) -> std::io::Result<Launch> {
    let text = jnlp(host, sess, "/viewer.jnlp")?;
    let user = jnlp_arg(&text, "user").ok_or_else(|| ioerr("the JNLP carried no console user"))?;
    let pass = jnlp_arg(&text, "passwd")
        .ok_or_else(|| ioerr("the JNLP carried no console password"))?;
    let port = |k| jnlp_arg(&text, k).and_then(|v| v.parse().ok()).unwrap_or(5900);
    Ok(Launch {
        user,
        pass,
        km_port: port("kmport"),
        v_port: port("vport"),
        platform: avocent::IDRAC8.into(),
        version: jnlp_arg(&text, "version").and_then(|v| v.parse().ok()).unwrap_or(2),
    })
}

/// Mint virtual-media credentials: a separate pair from the console's, spelt
/// `password` rather than `passwd`, as on MergePoint.
pub fn vm_launch(host: &str, sess: &Session) -> std::io::Result<Launch> {
    let text = jnlp(host, sess, "/data?type=jnlp&get=vmStart")?;
    let user = jnlp_arg(&text, "user").ok_or_else(|| ioerr("the media JNLP carried no user"))?;
    let pass = jnlp_arg(&text, "password")
        .ok_or_else(|| ioerr("the media JNLP carried no password"))?;
    let port = jnlp_arg(&text, "port").and_then(|v| v.parse().ok()).unwrap_or(5900);
    Ok(Launch { user, pass, km_port: port, v_port: port, platform: avocent::IDRAC8.into(), version: 2 })
}

/// The dashboard thumbnail: ask for a capture, then fetch the PNG it wrote.
/// Costs no console session.
pub fn preview(host: &str, sess: &Session) -> std::io::Result<crate::image::Image> {
    let t = stamp();
    let path = format!("/data?get=consolepreview[manual%20{t}]");
    let (status, _, _) = https(host, "GET", &path, Some(sess), None)?;
    if status != 200 {
        return Err(ioerr(format!("preview refused (HTTP {status})")));
    }
    let (status, _, png) = https(host, "GET", &format!("/capconsole/scapture0.png?{t}"),
                                 Some(sess), None)?;
    if status != 200 {
        return Err(ioerr(format!("preview image missing (HTTP {status})")));
    }
    crate::image::decode(&png).ok_or_else(|| ioerr("could not decode the preview PNG"))
}

/// Chassis power through Redfish, which iDRAC 8 shares with the 9 path for
/// path. IPMI-over-LAN ships disabled on both.
pub fn power(host: &str, user: &str, pass: &str, cmd: &str) -> std::io::Result<String> {
    super::idrac::power(host, user, pass, cmd)
}

/// Restart the iDRAC itself (Redfish `Manager.Reset`, `GracefulRestart`).
pub fn reset_bmc(host: &str, user: &str, pass: &str) -> std::io::Result<String> {
    super::idrac::reset_idrac(host, user, pass)
}
