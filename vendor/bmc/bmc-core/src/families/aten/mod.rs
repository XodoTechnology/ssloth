//! ATEN/Supermicro generation detection and per-generation profiles.
//!
//! One `discover()` probes a BMC over its web API and the KVM port, decides
//! which ATEN/Supermicro generation it is, and returns a `Profile` that
//! parameterises the shared RFB / video / virtual-media engines. The
//! generation-specific knowledge lives in the `x9` and `x11` submodules.
//!
//! The other families (`quanta*`, `ilo4*`, `idrac*`, `spx*`, `avocent*`) do not
//! use RFB at all, so they have no `Profile`; `discover` only recognises them
//! well enough to say so.

pub mod client_cert;
pub mod ntp;
pub mod x9;
pub mod x11;

use super::{avocent, ilo4, quanta};
use crate::auth;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Generation {
    /// X9 (ATEN iKVM ~V1.69.39): Java-only, mutual TLS on :5900 with the bundled
    /// CN=IPMI client cert, RFB 003.008, raw RGB565 video, plaintext vmedia.
    X9,
    /// X10 (Java generation): JNLP token, TLS on :5900, AST2100 video, TLS vmedia.
    X10,
    /// X11/X12: HTML5 console token, TLS on :5900, AST2100 video, TLS vmedia.
    X11,
}

impl Generation {
    pub fn label(&self) -> &'static str {
        match self { Generation::X9 => "X9", Generation::X10 => "X10", Generation::X11 => "X11" }
    }
}

/// Everything the connection engines need, resolved once at connect time.
#[derive(Clone, Debug)]
/// Some fields are unread: they record the wire format so a future change
/// does not have to re-derive it from the vendor client.
#[allow(dead_code)]
pub struct Profile {
    pub generation: Generation,
    pub sid: String,
    pub token: String,
    /// The console port speaks TLS; false for X9 firmware that serves plain RFB.
    pub kvm_tls: bool,
    /// The client identity X9's mutual-TLS KVM port demands, from the BMC's
    /// own viewer where it could be read. Only with one does the BMC clock
    /// need rolling back, and then only outside its validity.
    pub client_identity: Option<client_cert::Identity>,
    /// Virtual media transport: TLS (X10/X11) vs plaintext (X9).
    pub vmedia_tls: bool,
    /// KVM port (5900 across all current generations).
    pub kvm_port: u16,
    /// Virtual-media port (623).
    pub vmedia_port: u16,
}

/// As `discover`, reporting each stage to `progress` for a live status line.
pub fn discover_with(host: &str, user: &str, pass: &str, progress: &dyn Fn(&str))
    -> std::io::Result<Profile>
{
    // The other two families have their own console transports; recognise them
    // up front so we give a clear diagnosis instead of failing later with an
    // ATEN-specific error.
    progress("identifying BMC…");
    // iLO announces itself on /xmldata without credentials, so check it first.
    if let Some(i) = ilo4::detect(host) {
        return Err(ioerr(&format!(
            "HP iLO 4 detected ({} fw {}); this family uses the Integrated Remote \
Console path, not ATEN RFB", i.model, i.firmware)));
    }
    if quanta::is_ami_megarac(host) {
        return Err(ioerr(
            "Quanta/AMI MegaRAC BMC detected (AMI JViewer console on :7578). \
Native KVM for this family is not implemented yet; use IPMI/Redfish for power."));
    }
    // Worth naming here too: this one's TLS fails in a way that reads as a
    // client bug ("dh key too small") rather than as the wrong family.
    if let Some(i) = avocent::detect(host) {
        return Err(ioerr(&format!(
            "Avocent MergePoint BMC detected ({}); this family uses the APCP/AVSP \
console on :2068, not ATEN RFB", i.product)));
    }

    progress("logging in…");
    let sid = auth::login(host, user, pass)?;

    // X11 is the only generation with an HTML5 console token.
    progress("detecting console type…");
    if let Some(token) = auth::html5_token(host, &sid) {
        progress("HTML5 console (X11) detected");
        let mut p = x11::profile(&sid, token, Generation::X11);
        // Some X10 firmware serves the HTML5 console page too, yet still fronts
        // :5900 with X9's mutual TLS. The HTML5 token cannot tell them apart,
        // so ask the port.
        if kvm_requires_client_cert(host, 5900) {
            progress("KVM port wants the client certificate");
            p.client_identity = Some(identity(host, &sid, auth::jnlp(host, &sid).as_deref(), progress));
            // Whether minting the Java token retires the HTML5 one is not
            // known, so take the HTML5 token afresh after it.
            if let Some(token) = auth::html5_token(host, &sid) {
                p.token = token;
            }
        }
        return Ok(p);
    }

    // Otherwise a Java generation: the JNLP carries the token and arms the port.
    // One fetch serves both the token and the viewer's name: a second would
    // mint another token.
    progress("arming Java KVM session…");
    let jnlp = auth::jnlp(host, &sid);
    let token = jnlp.as_deref().and_then(auth::token_from_jnlp)
        .ok_or_else(|| ioerr("no KVM token: neither HTML5 console nor Java JNLP available"))?;

    // X9 vs X10: X9's :5900 demands a client certificate (mutual TLS); X10 does not.
    progress("probing KVM port…");
    // Some X9 firmware has no TLS on the console at all; it greets in RFB.
    if crate::rfb::serves_plain(host, 5900) {
        progress("X9 detected (plain RFB KVM)");
        return Ok(Profile { kvm_tls: false, ..x9::profile(&sid, token) });
    }
    if kvm_requires_client_cert(host, 5900) {
        progress("X9 detected (mutual-TLS KVM)");
        let id = identity(host, &sid, jnlp.as_deref(), progress);
        Ok(Profile { client_identity: Some(id), ..x9::profile(&sid, token) })
    } else {
        progress("X10 detected");
        Ok(x11::profile(&sid, token, Generation::X10))
    }
}

/// The client identity from the BMC's own viewer, else the bundled one, and
/// the status line says which.
fn identity(host: &str, sid: &str, jnlp: Option<&str>, progress: &dyn Fn(&str))
    -> client_cert::Identity
{
    progress("reading the client certificate from the BMC's viewer…");
    let (id, why) = client_cert::resolve(host, sid, jnlp);
    match why {
        Some(why) => progress(&format!("using the bundled client certificate ({why})")),
        None => progress(&format!("client certificate from the BMC's viewer, valid until {}",
                                  crate::clock::date(id.not_after))),
    }
    id
}

/// True if the KVM port completes a TLS handshake only when we present a client
/// certificate — the signature of X9's mutual-TLS stunnel front end.
fn kvm_requires_client_cert(host: &str, port: u16) -> bool {
    use std::time::Duration;
    // Without a client cert: X9 aborts the handshake, X10 completes it. This
    // must be the same TLS the console then uses: the platform stack refuses
    // the X9 for reasons of its own (TLS 1.0 on Windows), and judged an X9
    // with TLS 1.2 to be an X10 on Linux, so the console went without a cert.
    match crate::net::connect(host, port, None) {
        Ok(tcp) => {
            tcp.set_read_timeout(Some(Duration::from_secs(4))).ok();
            crate::legacy_tls::connect(host, tcp, None).is_err()
        }
        Err(_) => false, // can't tell; assume no cert needed
    }
}

fn ioerr(m: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, m.to_string())
}
