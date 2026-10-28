//! Chassis power and BMC resets, out of band. Each runs as a job of its own
//! (`power:<addr>`, `reset:<addr>`), so a second request while one is still
//! going is refused rather than sent twice, and reports its outcome as a
//! `Notice`.

use crate::events::{Event, Sink};
use crate::families::{self, Family};
use crate::jobs::{JobKey, Jobs};
use crate::{auth, rfb};

/// Send a chassis power command out of band and describe the outcome. Blocks:
/// call it from a worker thread. `code` is the GUI's 0=off / 1=on / 2=reset /
/// 3=soft-off encoding.
pub fn send_power(family: Family, h: &str, u: &str, p: &str, code: u8) -> String {
    let cmd = match code { 0 => "off", 1 => "on", 2 => "reset", _ => "soft" };
    let r = match family {
        Family::Idrac9 => crate::families::idrac::power(h, u, p, cmd),
        Family::Idrac8 => crate::families::idrac8::power(h, u, p, cmd),
        Family::Ilo4 => crate::families::ilo4::power(h, u, p, cmd),
        Family::Quanta => crate::families::quanta::ipmi_power(h, u, p, cmd),
        // SP-X spells soft-off "softoff"; everything else shares the verbs.
        Family::Spx => crate::families::spx::power(
            h, u, p, if cmd == "soft" { "softoff" } else { cmd }),
        Family::Aten => aten_power(h, u, p, code),
        Family::Avocent => crate::families::avocent::power(
            h, u, p, if cmd == "soft" { "soft" } else { cmd }),
    };
    match r {
        Ok(m) if m.is_empty() => format!("power {cmd} sent to {h}"),
        Ok(m) => format!("power {cmd} → {h}: {m}"),
        Err(e) => format!("power {cmd} failed: {e}"),
    }
}

/// ATEN carries power commands on the RFB console channel, so it needs a login
/// and a handshake rather than a web-API call.
pub fn aten_power(host: &str, user: &str, pass: &str, code: u8) -> std::io::Result<String> {
    let s = auth::Session::login(host, user, pass)?;
    let mut r = rfb::Rfb::connect(host, &s.token)?;
    r.send_power(code)?;
    // Let the write drain before the connection drops.
    std::thread::sleep(std::time::Duration::from_millis(300));
    Ok(String::new())
}

/// Send a power command on a thread, as the `power:<addr>` job. `family` is
/// the open console's, if there is one; otherwise it is detected, which
/// touches the network and so happens on that thread too. False when a
/// power command to `addr` is still running.
pub fn start_power(jobs: &Jobs, sink: Sink, addr: String, family: Option<Family>,
                   user: String, pass: String, code: u8) -> bool {
    let Some(guard) = jobs.begin(JobKey::Power(addr.clone()),
                                 format!("Sending a power command to {addr}"))
    else {
        return false;
    };
    std::thread::spawn(move || {
        let _guard = guard;
        let msg = crate::net::deliberately(|| {
            let family = family.unwrap_or_else(|| families::detect(&addr));
            send_power(family, &addr, &user, &pass, code)
        });
        sink.emit(Event::Notice(msg));
    });
    true
}

/// Cold-reset the BMC (management controller), blocking: recovers a wedged
/// BMC or web server without touching host power. Describes the outcome.
pub fn reset_bmc(addr: &str, u: &str, p: &str) -> String {
    // iLO resets over Redfish; the other families over IPMI.
    match families::detect(addr) {
        Family::Idrac9 => match crate::families::idrac::reset_idrac(addr, u, p) {
            Ok(_) => format!("iDRAC reset sent to {addr} (back in ~2 min)"),
            Err(e) => format!("iDRAC reset failed: {e}"),
        },
        Family::Ilo4 => match crate::families::ilo4::reset_ilo(addr, u, p) {
            Ok(_) => format!("iLO reset sent to {addr} (back in ~1 min)"),
            Err(e) => format!("iLO reset failed: {e}"),
        },
        // SP-X has IPMI-over-LAN off by default, so this goes through
        // the REST API rather than ipmitool.
        Family::Idrac8 => match crate::families::idrac8::reset_bmc(addr, u, p) {
            Ok(_) => format!("iDRAC reset sent to {addr} (back in ~2 min)"),
            Err(e) => format!("iDRAC reset failed: {e}"),
        },
        Family::Avocent => match crate::families::avocent::reset_bmc(addr, u, p) {
            Ok(m) => format!("BMC reset requested: {m}"),
            Err(e) => format!("BMC reset failed: {e}"),
        },
        Family::Spx => match crate::families::spx::reset_bmc(addr, u, p) {
            Ok(m) => format!("{addr}: {m}"),
            Err(e) => format!("BMC reset failed: {e}"),
        },
        _ => match crate::families::quanta::ipmi_mc_reset(addr, u, p) {
            Ok(_) => format!("BMC cold reset sent to {addr} (back in ~1-2 min)"),
            Err(e) => format!("BMC reset failed: {e}"),
        },
    }
}

/// Reset the BMC on a thread, as the `reset:<addr>` job; `label` names the
/// host in the job's line. False when a reset of `addr` is still running.
pub fn start_reset(jobs: &Jobs, sink: Sink, addr: String, label: &str,
                   user: String, pass: String) -> bool {
    let Some(guard) = jobs.begin(JobKey::Reset(addr.clone()),
                                 format!("Resetting the BMC on {label}"))
    else {
        return false;
    };
    std::thread::spawn(move || {
        let _guard = guard;
        let msg = crate::net::deliberately(|| reset_bmc(&addr, &user, &pass));
        sink.emit(Event::Notice(msg));
    });
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::Recorder;
    use std::sync::Arc;

    #[test]
    fn a_second_request_while_one_runs_is_refused_and_sends_nothing() {
        let jobs = Jobs::default();
        let rec = Recorder::default();
        let _power = jobs.begin(JobKey::Power("192.0.2.5".into()), "power").unwrap();
        let _reset = jobs.begin(JobKey::Reset("192.0.2.5".into()), "reset").unwrap();
        assert!(!start_power(&jobs, Arc::new(rec.clone()), "192.0.2.5".into(), Some(Family::Aten),
                             "admin".into(), "secret".into(), 1));
        assert!(!start_reset(&jobs, Arc::new(rec.clone()), "192.0.2.5".into(), "bmc",
                             "admin".into(), "secret".into()));
        assert!(rec.events().is_empty());
    }
}
