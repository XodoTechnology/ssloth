//! Cisco IMC (UCS C-series) — the Avocent wire under Cisco's XML API.
//!
//! Verified against a UCS C220 M4S (CIMC 4.1(2m)):
//!   - console   : APCP/AVSP on :2068, byte-identical to Avocent — the
//!                 in-band `login_packet` authenticates with the account
//!                 credentials directly, so no JNLP/web-session minting is
//!                 needed. `avocent::kvm::connect` works with a synthetic
//!                 `Launch` built here.
//!   - detect    : `POST /nuova` answers `<aaaLogin ...>` XML unauthenticated;
//!                 `/login.html` is gzip'd regardless of Accept-Encoding, so
//!                 the XML probe is the reliable marker.
//!   - web login : `POST /nuova` `<aaaLogin inName inPassword>` -> `outCookie`.
//!   - power/reset: `/nuova` `configConfMo` on computeRackUnit.
//!   - vmedia    : the Avocent AVMP channel on :2068 (same `Launch`).
//!
//! `Session` reuses `avocent::Session`: `cookie` holds the nuova cookie and
//! `st1`/`st2` carry the account credentials — the equivalent of the
//! JNLP-minted pair a real Avocent hands to the console.

use super::avocent::{self, Launch, Session};

use std::time::Duration;

fn ioerr<S: AsRef<str>>(m: S) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, m.as_ref().to_string())
}

fn nuova(host: &str, xml_body: &str) -> std::io::Result<String> {
    let (status, body) = super::ilo4::https(host, "POST", "/nuova",
        super::ilo4::Auth::None, Some(xml_body), Duration::from_secs(15))?;
    if status != 200 {
        return Err(ioerr(format!("nuova answered HTTP {status}")));
    }
    Ok(body)
}

fn attr<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("{key}=\"");
    let i = s.find(&pat)? + pat.len();
    let e = s[i..].find('"')? + i;
    Some(&s[i..e])
}

/// Identify a Cisco IMC without credentials: `/nuova` answers an
/// `<aaaLogin>`-shaped XML response to a bogus login where a plain web
/// server would 404 or 405.
pub fn detect(host: &str) -> Option<avocent::Info> {
    let body = nuova(host, "<aaaLogin inName=\"x\" inPassword=\"x\"/>").ok()?;
    if !body.contains("<aaaLogin") {
        return None;
    }
    // Version travels in the login reply's outVersion; a bogus login keeps
    // it out of the response on most firmware, so report what we can.
    Some(avocent::Info {
        product: "Cisco IMC (UCS C-series)".into(),
        server: attr(&body, "outVersion").unwrap_or("").to_string(),
    })
}

/// Log in on the CIMC XML API. The returned `Session` keeps the nuova cookie
/// in `cookie` and the account credentials in `st1`/`st2` — `kvm_launch` and
/// `vm_launch` turn those into the console `Launch`.
pub fn login(host: &str, user: &str, pass: &str) -> std::io::Result<Session> {
    let req = format!("<aaaLogin inName=\"{user}\" inPassword=\"{pass}\"/>");
    let body = nuova(host, &req)?;
    if body.contains("errorCode=") || !body.contains("outCookie") {
        let reason = attr(&body, "errorDescr").unwrap_or("login rejected");
        return Err(ioerr(format!("{reason}")));
    }
    let cookie = attr(&body, "outCookie")
        .ok_or_else(|| ioerr("nuova login set no outCookie"))?
        .to_string();
    Ok(Session { cookie, st1: user.to_string(), st2: pass.to_string() })
}

/// The console launch — synthetic, because the APCP channel authenticates
/// the account credentials in-band. Ports and protocol are fixed on CIMC.
pub fn kvm_launch(_host: &str, sess: &Session) -> std::io::Result<Launch> {
    Ok(Launch {
        user: sess.st1.clone(),
        pass: sess.st2.clone(),
        km_port: 2068,
        v_port: 2068,
        platform: "ASPEED".into(),
        version: 2,
    })
}

/// The media channel's launch — same synthetic values as the console's.
pub fn vm_launch(_host: &str, sess: &Session) -> std::io::Result<Launch> {
    kvm_launch(_host, sess)
}

/// End the nuova session.
pub fn logout(host: &str, sess: &Session) {
    let _ = nuova(host, &format!("<aaaLogout inCookie=\"{}\"/>", sess.cookie));
}

/// CIMC power actions through `configConfMo` on the rack unit.
pub fn power(host: &str, user: &str, pass: &str, cmd: &str) -> std::io::Result<String> {
    let sess = login(host, user, pass)?;
    let action = match cmd {
        "on" => "power-on",
        "off" => "power-off",
        "reset" => "hard-reset-immediate",
        "cycle" => "power-cycle-immediate",
        "soft" | "softoff" => "soft-shut-down",
        other => return Err(ioerr(format!("unknown power command {other}"))),
    };
    let req = format!(
        "<configConfMo cookie=\"{}\"><inConfig>\
         <computeRackUnit adminPower=\"{action}\" dn=\"sys/rack-unit-1\"/>\
         </inConfig></configConfMo>", sess.cookie);
    let body = nuova(host, &req)?;
    logout(host, &sess);
    if body.contains("errorCode=") || body.contains("fault") {
        return Err(ioerr(format!("power {action} rejected: {}",
            attr(&body, "errorDescr").unwrap_or("unknown"))));
    }
    Ok(format!("power {action} accepted"))
}

/// Reboot the BMC itself (the host is untouched).
pub fn reset_bmc(host: &str, user: &str, pass: &str) -> std::io::Result<String> {
    let sess = login(host, user, pass)?;
    let req = format!(
        "<configConfMo cookie=\"{}\"><inConfig>\
         <computeRackUnit adminAction=\"bmc-reset\" dn=\"sys/rack-unit-1\"/>\
         </inConfig></configConfMo>", sess.cookie);
    let body = nuova(host, &req)?;
    logout(host, &sess);
    Ok(if body.contains("response=\"yes\"") {
        "CIMC rebooting".to_string()
    } else {
        format!("CIMC reset answer: {}", &body[..body.len().min(120)])
    })
}

/// A screen snapshot taken through the console itself — CIMC's web UI has no
/// preview endpoint to reuse the way Avocent's does.
pub fn preview(host: &str, sess: &Session) -> std::io::Result<crate::image::Image> {
    use super::avocent::kvm;
    let launch = kvm_launch(host, sess)?;
    let mut con = kvm::connect(host, &launch)?;
    let _ = con.start_video(1024, 768);
    let (mut _kvm, mut video) = con.split();
    video.set_poll_timeout(Duration::from_millis(80));
    let mut codec = kvm::Video::default();
    let mut dec = crate::ast2100::Decoder::new(1024, 768);
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let mut last = std::time::Instant::now();
    // Settle like the iLO snapshots: stop when the redraw burst has been quiet
    // for 500ms, or at the deadline.
    while std::time::Instant::now() < deadline && last.elapsed() < Duration::from_millis(500) {
        let Some(f) = video.poll()? else { continue };
        if kvm::needs_ack(f.id) {
            let _ = video.send(&kvm::video_ack(1));
        }
        if f.id == kvm::msg::VIDEO_STOPPED { break; }
        if codec.feed(&f, &mut dec) { last = std::time::Instant::now(); }
    }
    video.shutdown();
    if dec.frames == 0 {
        return Err(ioerr("the console sent no video (is the server powered off?)"));
    }
    Ok(crate::image::Image {
        width: dec.width,
        height: dec.height,
        rgb: std::mem::take(&mut dec.framebuffer),
    })
}

/// One `<configResolveClass>`/`<configResolveDn>` fetch against an open session.
fn query(sess: &Session, host: &str, xml_body: &str) -> std::io::Result<String> {
    let req = xml_body.replacen("{}", &sess.cookie, 1);
    nuova(host, &req)
}

/// Parse `<class attr="v" .../>` elements out of a nuova answer into
/// (name, [(attr,value)]) rows — the API is shallow enough that a tiny
/// scanner beats pulling an XML parser into the crate.
fn elements<'a>(body: &'a str, class: &str) -> Vec<Vec<(&'a str, &'a str)>> {
    let open = format!("<{class} ");
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(i) = rest.find(&open) {
        let el = &rest[i + open.len()..];
        let end = el.find("/>").or_else(|| el.find(">")).unwrap_or(el.len());
        let el = &el[..end];
        let mut attrs = Vec::new();
        let mut r = el;
        while let Some(eq) = r.find("=\"") {
            let name_end = r[..eq].rfind(' ').map(|s| s + 1).unwrap_or(0);
            let name = &r[name_end..eq];
            let val_start = eq + 2;
            let Some(vend) = r[val_start..].find('"') else { break };
            attrs.push((name, &r[val_start..val_start + vend]));
            r = &r[val_start + vend + 1..];
        }
        out.push(attrs);
        rest = &rest[i + open.len()..];
    }
    out
}

fn attr_in<'a>(el: &[(&'a str, &'a str)], key: &str) -> &'a str {
    el.iter().find(|(k, _)| *k == key).map(|(_, v)| *v).unwrap_or("")
}

/// Sensor + power telemetry from the CIMC XML API. IPMI-over-LAN is off on
/// these boards by default, so the nuova session is the read path.
pub fn sensors(host: &str, user: &str, pass: &str)
    -> std::io::Result<crate::event_log::Sensors>
{
    use crate::event_log::{Sensor, Sensors};
    let sess = login(host, user, pass)?;
    let mut entries = Vec::new();
    let mut warnings = Vec::new();
    let mut grab = |label: &str, class: &str| -> std::io::Result<String> {
        query(&sess, host,
            &format!("<configResolveClass cookie=\"{{}}\" inHierarchical=\"false\" classId=\"{class}\"/>"))
            .map_err(|e| { warnings.push(format!("{label}: {e}")); e })
    };

    if let Ok(b) = grab("power", "powerMonitor") {
        for el in elements(&b, "powerMonitor") {
            let dom = attr_in(&el, "domain");
            let (cur, avg, max) =
                (attr_in(&el, "current"), attr_in(&el, "average"), attr_in(&el, "maximum"));
            entries.push(Sensor {
                name: format!("Power {dom}"),
                reading: cur.into(), units: "W".into(), status: "ok".into(),
                thresholds: format!("avg {avg}W · peak {max}W"),
            });
        }
    }
    if let Ok(b) = grab("PSU", "equipmentPsu") {
        for el in elements(&b, "equipmentPsu") {
            let (id, model, vin, vout, th) = (
                attr_in(&el, "id"), attr_in(&el, "model"), attr_in(&el, "input"),
                attr_in(&el, "output"), attr_in(&el, "thermal"));
            entries.push(Sensor {
                name: format!("PSU {id}"),
                reading: format!("{vout}W out"),
                units: format!("{vin}W in"), status: th.into(),
                thresholds: model.to_string(),
            });
        }
    }
    if let Ok(b) = grab("fans", "equipmentFan") {
        for el in elements(&b, "equipmentFan") {
            let (mod_, id, op) =
                (attr_in(&el, "module"), attr_in(&el, "id"), attr_in(&el, "operability"));
            entries.push(Sensor {
                name: format!("Fan {mod_}.{id}"),
                reading: attr_in(&el, "power").into(),
                units: String::new(), status: op.into(), thresholds: String::new(),
            });
        }
    }
    if let Ok(b) = query(&sess, host,
        "<configResolveDn cookie=\"{}\" inHierarchical=\"false\" dn=\"sys/rack-unit-1\"/>")
    {
        for el in elements(&b, "computeRackUnit") {
            entries.push(Sensor {
                name: "System".into(),
                reading: format!("power {}", attr_in(&el, "operPower")),
                units: String::new(), status: attr_in(&el, "biosPostState").into(),
                thresholds: format!("{} · {}", attr_in(&el, "model"), attr_in(&el, "serial")),
            });
        }
    }
    let _ = logout(host, &sess);
    if entries.is_empty() {
        return Err(ioerr("no sensor classes answered"));
    }
    Ok(Sensors { source: "CIMC nuova", entries, warnings })
}
