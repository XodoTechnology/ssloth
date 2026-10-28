//! TLS for BMCs older than the platform's own TLS stack will talk to.
//!
//! `native-tls` is the system stack: OpenSSL on Linux, but SChannel on Windows
//! and Security.framework on macOS, and current Windows has switched TLS 1.0
//! and the old cipher suites off. A Supermicro X9 offers nothing newer, so on
//! Windows its login failed with SChannel's "no common algorithm"
//! (`SEC_E_ALGORITHM_MISMATCH`, os error -2146893007) before a byte of HTTP.
//! It also lacks the renegotiation-indication extension, which OpenSSL 3
//! refuses by default too ("unsafe legacy renegotiation disabled").
//! OpenSSL is already linked for the Avocent family (vendored off Linux), so
//! these connections use it directly, configured as permissively as the
//! hardware needs: TLS 1.0 up, any cipher at security level 0, no
//! certificate checks — BMC certificates are self-signed anyway.

use openssl::pkey::PKey;
use openssl::ssl::{SslConnector, SslMethod, SslOptions, SslStream, SslVerifyMode, SslVersion};
use openssl::x509::X509;
use std::net::TcpStream;

pub type Stream = SslStream<TcpStream>;

fn oerr<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
}

/// Start TLS on a connected socket. `identity` is a client certificate and
/// key, both PEM, for BMCs that insist on one (X9's console).
pub fn connect(host: &str, tcp: TcpStream, identity: Option<(&str, &str)>)
    -> std::io::Result<Stream>
{
    let mut b = SslConnector::builder(SslMethod::tls_client()).map_err(oerr)?;
    b.set_verify(SslVerifyMode::NONE);
    b.set_min_proto_version(Some(SslVersion::TLS1)).map_err(oerr)?;
    b.set_cipher_list("ALL:!eNULL:!aNULL:@SECLEVEL=0").map_err(oerr)?;
    // Firmware of this age predates the renegotiation-indication extension.
    b.set_options(SslOptions::ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
    if let Some((cert, key)) = identity {
        let cert = X509::from_pem(cert.as_bytes()).map_err(oerr)?;
        let key = PKey::private_key_from_pem(key.as_bytes()).map_err(oerr)?;
        b.set_certificate(&cert).map_err(oerr)?;
        b.set_private_key(&key).map_err(oerr)?;
    }
    b.build()
        .configure()
        .map_err(oerr)?
        .verify_hostname(false)
        // Addressed by IP; a name in SNI only invites a different certificate.
        .use_server_name_indication(false)
        .connect(host, tcp)
        .map_err(oerr)
}

/// The TLS alert a server refused a handshake with, from OpenSSL's error text
/// ("… SSL alert number 45"). The alert is the only place the server says why:
/// 40 (handshake failure) when a required client certificate is missing, 45
/// when it has expired, 48 when it is not the one the server trusts.
pub fn alert(e: &std::io::Error) -> Option<u8> {
    let text = e.to_string();
    let at = text.find("SSL alert number ")? + "SSL alert number ".len();
    text[at..].split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
}

pub const ALERT_HANDSHAKE_FAILURE: u8 = 40;
pub const ALERT_CERTIFICATE_EXPIRED: u8 = 45;
pub const ALERT_UNKNOWN_CA: u8 = 48;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_alert_number_is_read_from_the_error() {
        let e = |s: &str| std::io::Error::new(std::io::ErrorKind::Other, s.to_string());
        assert_eq!(alert(&e("the handshake failed: error:0A000415:SSL routines::ssl/tls alert \
certificate expired:ssl/record/rec_layer_s3.c:918:SSL alert number 45: self-signed")), Some(45));
        assert_eq!(alert(&e("SSL alert number 40")), Some(40));
        assert_eq!(alert(&e("connection refused")), None);
    }
}
