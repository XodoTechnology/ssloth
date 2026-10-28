//! Lightweight background probes used by the host inventory.

use super::Family;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub struct Probe {
    pub reachable: Option<bool>,
    pub power: Option<String>,
    pub model: Option<String>,
    pub checking: bool,
    /// Which BMC family answered, so the list can label it without connecting.
    pub family: Option<Family>,
    /// Who made it, when that differs from what the family implies.
    pub vendor: Option<super::Vendor>,
    pub health: Option<String>,
    pub serial: Option<String>,
    pub bios: Option<String>,
    pub last_seen: Option<std::time::Instant>,
}

impl Probe {
    /// What to call the controller, once the probe has identified it.
    pub fn label(&self) -> Option<String> {
        self.family.map(|f| super::controller_label(f, self.vendor.unwrap_or(f.vendor())))
    }
}

fn base64(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::new();
    for chunk in data.chunks(3) {
        let bytes = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let value = ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[2] as u32;
        output.push(TABLE[(value >> 18) as usize & 63] as char);
        output.push(TABLE[(value >> 12) as usize & 63] as char);
        output.push(if chunk.len() > 1 {
            TABLE[(value >> 6) as usize & 63] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            TABLE[value as usize & 63] as char
        } else {
            '='
        });
    }
    output
}

/// Best-effort Redfish GET over TLS; returns the body.
fn redfish(host: &str, path: &str, user: &str, pass: &str) -> Option<String> {
    let allow_untrusted = crate::hosts::WorkspaceSettings::load().allow_untrusted_certs;
    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(allow_untrusted)
        .danger_accept_invalid_hostnames(allow_untrusted)
        .build()
        .ok()?;
    let tcp = crate::net::connect(host, 443, Some(std::time::Duration::from_millis(1_800))).ok()?;
    // iDRAC 8 takes about five seconds to start answering for its system
    // resource. This runs on a background thread, so waiting costs a spinner.
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .ok()?;
    let mut stream = connector.connect(host, tcp).ok()?;
    let authorization = base64(format!("{user}:{pass}").as_bytes());
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Basic {authorization}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).ok()?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).ok();
    Some(String::from_utf8_lossy(&response).into_owned())
}

/// The Redfish system resource the probe reads a family's details from, or
/// None where it must not send Basic-auth Redfish at all. iLO 4 opens a web
/// session for every such request and holds it for its idle timeout (30 min);
/// its pool is a handful, and once it is full every login fails exactly as a
/// wrong password does.
fn redfish_system(family: Family) -> Option<&'static str> {
    match family {
        Family::Ilo4 => None,
        // iDRAC 8 shares the 9's Redfish tree; `Systems/1` is a 404 there.
        Family::Idrac9 | Family::Idrac8 => Some("/redfish/v1/Systems/System.Embedded.1"),
        Family::Spx => Some("/redfish/v1/Systems/Self"),
        _ => Some("/redfish/v1/Systems/1"),
    }
}

fn json_string(body: &str, key: &str) -> Option<String> {
    let key = format!("\"{key}\"");
    let value = body[body.find(&key)? + key.len()..]
        .split_once(':')?
        .1
        .trim_start()
        .strip_prefix('"')?;
    Some(value[..value.find('"')?].to_string())
}

/// `asked`: the user clicked for this probe (Probe BMC, Refresh discovery),
/// so a route that background probes have stopped trying is tried once more.
pub fn spawn(
    address: String,
    user: String,
    password: String,
    probes: Arc<Mutex<HashMap<String, Probe>>>,
    asked: bool,
) {
    // Marked before the thread starts, not inside it, so the control that
    // asked shows "checking" from the very frame it was clicked.
    probes.lock().unwrap().entry(address.clone()).or_default().checking = true;
    std::thread::spawn(move || {
        if asked {
            crate::net::begin_action();
        }

        let reachable = crate::net::connect(&address, 443, Some(std::time::Duration::from_millis(1_500))).is_ok();

        let (mut power, mut model, mut detected_family) = (None, None, None);
        let mut detected_vendor = None;
        // Whether Redfish named the maker; if it did, IPMI need not be asked.
        let mut redfish_brand = false;
        let (mut health, mut serial, mut bios) = (None, None, None);
        if reachable {
            let (family, vendor) = super::detect_vendor(&address);
            detected_family = Some(family);
            detected_vendor = Some(vendor);
            let system_path = redfish_system(family).filter(|_| !user.is_empty());
            if let Some(system_path) = system_path {
                if let Some(body) = redfish(&address, system_path, &user, &password) {
                    power = json_string(&body, "PowerState");
                    model = json_string(&body, "Model");
                    health = json_string(&body, "Health");
                    serial = json_string(&body, "SerialNumber");
                    bios = json_string(&body, "BiosVersion");
                    // AMI's firmware carries the board maker's name, not AMI's.
                    if family.is_oem_firmware() {
                        if let Some(v) = json_string(&body, "Manufacturer")
                            .and_then(|m| super::Vendor::from_manufacturer(&m))
                        {
                            detected_vendor = Some(v);
                            redfish_brand = true;
                        }
                    }
                }
            }
            // iLO's details come from where they cost no web session: its
            // public /xmldata names the model, serial and health, and IPMI,
            // which has no session pool, the power state and BIOS version.
            if family == Family::Ilo4 {
                if let Some(info) = super::ilo4::detect(&address) {
                    model = Some(info.model).filter(|m| !m.is_empty());
                    serial = Some(info.serial).filter(|s| !s.is_empty());
                    health = info.health.map(str::to_string);
                }
                if !user.is_empty() {
                    power = crate::ipmi::chassis_power_on(&address, &user, &password).ok()
                        .map(|on| if on { "On" } else { "Off" }.to_string());
                    bios = crate::ipmi::system_firmware_version(&address, &user, &password).ok();
                }
            }
        }

        // No Redfish brand (the GoAhead MegaRAC has no Redfish at all): ask IPMI,
        // whose Get Device ID names the maker on every BMC. Only for firmware
        // sold under other brands, and only with credentials.
        if detected_family.is_some_and(|f| f.is_oem_firmware()) {
            if !user.is_empty() && !redfish_brand {
                if let Some(v) = crate::ipmi::manufacturer_id(&address, &user, &password)
                    .ok()
                    .and_then(super::Vendor::from_iana)
                {
                    detected_vendor = Some(v);
                }
            }
        }

        let last_seen = if reachable { Some(std::time::Instant::now()) } else { probes.lock().unwrap().get(&address).and_then(|p|p.last_seen) };
        probes.lock().unwrap().insert(
            address,
            Probe {
                reachable: Some(reachable),
                power,
                model,
                checking: false,
                family: detected_family,
                vendor: detected_vendor,
                health, serial, bios,
                last_seen,
            },
        );
    });
}

#[cfg(test)]
mod tests {
    use super::{base64, json_string, redfish_system};
    use crate::families::Family;

    #[test]
    fn ilo_is_never_sent_basic_auth_redfish() {
        // Each such request costs iLO 4 a web session for 30 minutes.
        assert_eq!(redfish_system(Family::Ilo4), None);
    }

    #[test]
    fn other_families_keep_their_redfish_system() {
        for family in [Family::Idrac9, Family::Idrac8] {
            assert_eq!(redfish_system(family), Some("/redfish/v1/Systems/System.Embedded.1"));
        }
        assert_eq!(redfish_system(Family::Spx), Some("/redfish/v1/Systems/Self"));
        for family in [Family::Aten, Family::Quanta, Family::Avocent] {
            assert_eq!(redfish_system(family), Some("/redfish/v1/Systems/1"));
        }
    }

    #[test]
    fn base64_handles_partial_chunks() {
        assert_eq!(base64(b"u"), "dQ==");
        assert_eq!(base64(b"user"), "dXNlcg==");
        assert_eq!(base64(b"user:pass"), "dXNlcjpwYXNz");
    }

    #[test]
    fn extracts_string_fields() {
        let body = r#"{"PowerState":"On","Model": "PowerEdge R640"}"#;
        assert_eq!(json_string(body, "PowerState").as_deref(), Some("On"));
        assert_eq!(
            json_string(body, "Model").as_deref(),
            Some("PowerEdge R640")
        );
        assert_eq!(json_string(body, "Missing"), None);
    }
}
