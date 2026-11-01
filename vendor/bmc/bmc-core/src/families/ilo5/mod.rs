//! HP/HPE iLO 5 (ProLiant Gen10/Gen10+) BMC support.
//!
//! Verified against a DL360 Gen10, iLO 5 firmware 3.22:
//!   - web login : identical to iLO 4 — POST /json/login_session -> session_key
//!   - console   : same `wss://<host>/wss/ircport` dual-channel IRC transport,
//!                 but the protocol is version 5: the client speaks first with
//!                 a 54-byte hello — [16]=openCommand, [17]=channel
//!                 (0=KVM, 1=CMD), [22..54]=session_key — and the server's
//!                 replies carry a 16-byte header, status at offset 16,
//!                 flags at 17. Anything but status 0 is a refusal.
//!   - vmport    : `wss://<host>/wss/vmport` answers the same upgrade.
//!   - vmedia    : Redfish `/redfish/v1/Managers/1/VirtualMedia/{1,2}` offers
//!                 InsertMedia/EjectMedia, and the iLO 4 JSON API exists too.
//!
//! Everything that is byte-identical to iLO 4 delegates to `crate::ilo4`;
//! only the console/media transport framing differs.

pub mod kvm;

pub use super::ilo4::vmedia;

use super::ilo4;
use super::ilo4::Info;
use std::time::Duration;

/// Identify an iLO 5 without credentials. `/xmldata` is public on every iLO.
pub fn detect(host: &str) -> Option<Info> {
    let (status, body) = ilo4::https(host, "GET", "/xmldata?item=All",
                                   super::ilo4::Auth::None, None,
                                   Duration::from_millis(2500)).ok()?;
    if status != 200 || !body.contains("<RIMP>") {
        return None;
    }
    let mp = ilo4::between(&body, "<MP>", "</MP>").unwrap_or("");
    let pn = ilo4::between(mp, "<PN>", "</PN>").unwrap_or("");
    if !pn.contains("iLO 5") && !pn.contains("Lights-Out 5") {
        return None;
    }
    let health = ilo4::between(&body, "<HEALTH>", "</HEALTH>")
        .and_then(|h| ilo4::between(h, "<STATUS>", "</STATUS>"))
        .and_then(|code| match code.trim() {
            "2" => Some("OK"),
            "3" => Some("Warning"),
            "4" => Some("Critical"),
            _ => None,
        });
    Some(Info {
        model: ilo4::between(&body, "<SPN>", "</SPN>").unwrap_or("ProLiant").trim().to_string(),
        firmware: ilo4::between(mp, "<FWRI>", "</FWRI>").unwrap_or("").trim().to_string(),
        serial: ilo4::between(&body, "<SBSN>", "</SBSN>").unwrap_or("").trim().to_string(),
        health,
    })
}
