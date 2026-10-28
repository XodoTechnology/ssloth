//! X10 / X11 profile. The modern InsydeVNC generations.
//!
//! - X11 has an HTML5 console; its token comes from the bootstrap page. X10 is
//!   Java-era and uses the JNLP token. Both authenticate the same way on the RFB
//!   channel (security type 16, InsydeVNC).
//! - KVM :5900 is TLS without a client certificate. RFB banner is 055.008 (X11)
//!   or 003.008 (X10) — the engine accepts either.
//! - Video is AST2100 (encoding 0x57). Virtual media on :623 is TLS.

use super::{Generation, Profile};

pub fn profile(sid: &str, token: String, generation: Generation) -> Profile {
    Profile {
        generation,
        sid: sid.to_string(),
        token,
        kvm_tls: true,
        client_identity: None,
        vmedia_tls: true,
        kvm_port: 5900,
        vmedia_port: 623,
    }
}
