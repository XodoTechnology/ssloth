//! X9 profile. Supermicro X9 / ATEN iKVM ~V1.69.39 (Nuvoton/WPCM450 era).
//!
//! - No HTML5 console; the KVM token comes from the Java JNLP and equals the SID.
//! - KVM :5900 is mutual TLS fronted by stunnel; the client must present
//!   the CN=IPMI certificate its own Java viewer carries (see client_cert.rs).
//!   RFB banner is 003.008.
//!   Some X9 firmware has no stunnel and serves the same RFB in the clear on
//!   :5900; discovery tells them apart by whether the port greets first.
//! - Video: a full raw RGB555 frame (encoding 0x59) then 16x16 RGB555 tile deltas
//!   (encoding 0). Decoded in ast2100.rs.
//! - Virtual media on :623 is plaintext (no TLS).
//! - That certificate (and the copy bundled here) expired 2026-05-17 and the
//!   BMC enforces it, so the BMC clock must read inside its validity (handled
//!   by the clock helper, from the certificate actually presented).

use super::{Generation, Profile};

pub fn profile(sid: &str, token: String) -> Profile {
    Profile {
        generation: Generation::X9,
        sid: sid.to_string(),
        token,
        kvm_tls: true,
        client_identity: None,
        vmedia_tls: false,
        kvm_port: 5900,
        vmedia_port: 623,
    }
}
