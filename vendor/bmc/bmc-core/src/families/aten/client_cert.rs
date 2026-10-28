//! The client certificate an ATEN console port demands, taken from the BMC's
//! own Java viewer.
//!
//! X9's :5900 is stunnel with `verify = 3`: it accepts exactly the client
//! certificate its firmware pins, so a certificate of our own (even re-dated
//! with the same key) is refused as an unknown CA. The one place that
//! certificate is guaranteed to match the firmware is the viewer the firmware
//! serves, which carries it as `res/client.crt` and `res/client.key` (plain
//! PEM, unencrypted PKCS#8, no keystore password) beside the stunnel that
//! presents it. Firmware with a renewed certificate ships the renewed pair the
//! same way, so reading it from the BMC follows the firmware rather than this
//! repository; the bundled pair is the fallback.
//!
//! The viewer is served as pack200 (`<jar>.pack.gz`; the bare `.jar` is a
//! 404 on the boards seen). Pack200 rebuilds class files but stores every
//! other file's bytes verbatim, in archive order, so the PEM text is in the
//! gunzipped stream as-is and can be found without a pack200 decoder. A plain
//! jar is read as a zip. Either way the pair is whichever certificate matches
//! the private key: the viewer also ships the BMC's server certificate.

use openssl::asn1::{Asn1Time, Asn1TimeRef};
use openssl::pkey::PKey;
use openssl::x509::X509;
use std::path::PathBuf;

const BUNDLED_CRT: &str = include_str!("../../certs/x9-client.crt");
const BUNDLED_KEY: &str = include_str!("../../certs/x9-client.key");

/// Where a client identity came from, for the status line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// Read from the BMC's viewer on this connect.
    Bmc,
    /// Read from the BMC's viewer on an earlier connect.
    Cached,
    /// The copy carried in this binary.
    Bundled,
}

/// A client certificate and key, both PEM, and the certificate's validity in
/// seconds since the epoch.
#[derive(Clone, Debug)]
pub struct Identity {
    pub cert_pem: String,
    pub key_pem: String,
    pub not_before: i64,
    pub not_after: i64,
    pub origin: Origin,
}

impl Identity {
    fn new(cert_pem: String, key_pem: String, origin: Origin) -> Option<Identity> {
        let cert = X509::from_pem(cert_pem.as_bytes()).ok()?;
        Some(Identity {
            not_before: epoch(cert.not_before())?,
            not_after: epoch(cert.not_after())?,
            cert_pem,
            key_pem,
            origin,
        })
    }

    /// The PEM pair, as `legacy_tls::connect` takes it.
    pub fn pem(&self) -> (&str, &str) {
        (&self.cert_pem, &self.key_pem)
    }
}

/// Supermicro's client identity as this binary carries it.
pub fn bundled() -> Identity {
    Identity::new(BUNDLED_CRT.into(), BUNDLED_KEY.into(), Origin::Bundled)
        .expect("the bundled client certificate parses")
}

/// What an earlier connect read from this host's viewer, else the bundled pair.
/// For callers with no web session to fetch the viewer through.
pub fn cached_or_bundled(host: &str) -> Identity {
    std::fs::read_dir(cache_dir())
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with(&format!("{}--", safe(host))))
        // Newest first: after a firmware update the new viewer's file is the
        // one that matches.
        .max_by_key(|e| e.metadata().and_then(|m| m.modified()).ok())
        .and_then(|e| std::fs::read_to_string(e.path()).ok())
        .and_then(|text| from_cache(&text))
        .unwrap_or_else(bundled)
}

/// What an earlier connect read from this host's viewer, if anything.
fn cached(host: &str) -> Option<Identity> {
    let id = cached_or_bundled(host);
    (id.origin != Origin::Bundled).then_some(id)
}

/// The identity the BMC's viewer carries, read in a web session of its own,
/// for callers without one (a mount). Cached after the first time.
pub fn fetch(host: &str, user: &str, pass: &str) -> (Identity, Option<String>) {
    if let Some(id) = cached(host) {
        return (id, None);
    }
    let sid = match crate::auth::login(host, user, pass) {
        Ok(sid) => sid,
        Err(e) => return (bundled(), Some(format!("web login: {e}"))),
    };
    let r = resolve(host, &sid, crate::auth::jnlp(host, &sid).as_deref());
    crate::auth::logout(host, &sid);
    r
}

/// Run the TLS handshake `connect`, with the BMC clock held inside the
/// client certificate's validity by `hold` when it is presented one.
///
/// The clock is checked just before the handshake, since a BMC's NTP can
/// have pulled it forward since the last; a refusal as expired re-checks it
/// and tries once more. The error says why the BMC refused, from its alert.
pub fn handshake<T>(hold: Option<&crate::clock::Hold>, say: &dyn Fn(&str),
                    mut connect: impl FnMut() -> std::io::Result<T>) -> Result<T, String>
{
    use crate::legacy_tls::{alert, ALERT_CERTIFICATE_EXPIRED};
    for attempt in 0..2 {
        if let Some(h) = hold {
            h.ensure(say)?;
        }
        match connect() {
            Ok(v) => return Ok(v),
            Err(e) if hold.is_some() && attempt == 0 && alert(&e) == Some(ALERT_CERTIFICATE_EXPIRED) => {
                say("the BMC refused the certificate as expired; checking its clock again…");
            }
            Err(e) => return Err(describe(&e, hold.is_some(), hold.is_some_and(|h| h.ntp_paused()))),
        }
    }
    unreachable!("the second attempt returns")
}

/// A refused handshake, said by its cause. `rolled`: the clock was held
/// inside the certificate's validity for it; `paused`: and NTP was paused.
pub fn describe(e: &std::io::Error, rolled: bool, paused: bool) -> String {
    use crate::legacy_tls::*;
    match alert(e) {
        Some(ALERT_CERTIFICATE_EXPIRED) if rolled => format!(
            "the BMC refused its client certificate as expired although its clock was set inside the certificate's validity: something reset the clock again, most likely the BMC's NTP{}; turn NTP off on the BMC for the session ({e})", if paused { ", although it was paused" } else { "" }),
        Some(ALERT_CERTIFICATE_EXPIRED) => format!(
            "the BMC refused the client certificate as expired; its clock would have to be set back inside the certificate's validity ({e})"),
        Some(ALERT_HANDSHAKE_FAILURE) => format!(
            "the BMC refused the TLS handshake: it wants a client certificate, and not this one ({e})"),
        Some(ALERT_UNKNOWN_CA) => format!(
            "the BMC does not trust this client certificate: it accepts only the one its own viewer carries ({e})"),
        _ => e.to_string(),
    }
}

/// The identity the BMC's own viewer carries, from the JNLP `jnlp` fetched in
/// the web session `sid`, read from the cache when this viewer has been read
/// before. Falls back to the bundled pair, with the reason.
pub fn resolve(host: &str, sid: &str, jnlp: Option<&str>) -> (Identity, Option<String>) {
    match from_viewer(host, sid, jnlp) {
        Ok(id) => (id, None),
        Err(why) => (bundled(), Some(why)),
    }
}

fn from_viewer(host: &str, sid: &str, jnlp: Option<&str>) -> Result<Identity, String> {
    let jar = jnlp.and_then(jar_href).ok_or("no viewer jar named in the JNLP")?;
    let path = cache_dir().join(format!("{}--{}.pem", safe(host), safe(&jar)));
    // The jar's name carries its version (Java Web Start's own cache key), so
    // a name read before is the same viewer and needs no 3 MB download.
    if let Ok(text) = std::fs::read_to_string(&path) {
        return from_cache(&text).ok_or_else(|| "the viewer has no client certificate".into());
    }
    let body = download(host, sid, &jar)?;
    let digest = hex(&openssl::sha::sha256(&body));
    let found = find_identity(&body);
    // Recorded even when there is none, so a viewer without one is not
    // downloaded again on every connect.
    let mut text = format!("# {jar} sha256 {digest}\n");
    if let Some((crt, key)) = &found {
        text.push_str(crt);
        text.push_str(key);
    }
    if let Err(e) = store(&path, &text) {
        eprintln!("aten: could not cache the viewer's client certificate: {e}");
    }
    let (crt, key) = found.ok_or("the viewer has no client certificate")?;
    Identity::new(crt, key, Origin::Bmc).ok_or_else(|| "the viewer's certificate does not parse".into())
}

/// The jar the JNLP launches: pack200 first, as Java Web Start asks for it
/// under `jnlp.packEnabled`, then the bare jar.
fn download(host: &str, sid: &str, jar: &str) -> Result<Vec<u8>, String> {
    let mut last = String::new();
    for path in [format!("/{jar}.pack.gz"), format!("/{jar}")] {
        match crate::auth::get_bytes(host, sid, &path) {
            Ok((head, body)) if head.starts_with("HTTP/1.1 200") && !body.is_empty() => return Ok(body),
            Ok((head, _)) => last = format!("{path}: {}", head.lines().next().unwrap_or("no answer")),
            Err(e) => last = format!("{path}: {e}"),
        }
    }
    Err(format!("could not fetch the viewer ({last})"))
}

fn from_cache(text: &str) -> Option<Identity> {
    let crt = pem_blocks(text.as_bytes()).into_iter().find(|b| b.contains("CERTIFICATE"))?;
    let key = pem_blocks(text.as_bytes()).into_iter().find(|b| b.contains("PRIVATE KEY"))?;
    Identity::new(crt, key, Origin::Cached)
}

fn cache_dir() -> PathBuf {
    crate::hosts::config_dir().join("aten-client-certs")
}

/// A private key: readable by this user only.
fn store(path: &std::path::Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    std::fs::create_dir_all(path.parent().unwrap())?;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)?.write_all(text.as_bytes())
}

/// A host or jar name as a file-name component.
fn safe(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' }).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The main `<jar href>` of a JNLP (the native-library jars are `nativelib`).
pub fn jar_href(jnlp: &str) -> Option<String> {
    let at = jnlp.find("<jar ")?;
    let tag = &jnlp[at..at + jnlp[at..].find('>')?];
    let v = &tag[tag.find("href=\"")? + 6..];
    let name = v[..v.find('"')?].trim_start_matches('/');
    // Only a name beside the codebase: it is requested from this BMC.
    (!name.is_empty() && !name.contains("://")).then(|| name.to_string())
}

/// The client certificate and key in a viewer, PEM, from either a pack200
/// stream (gzipped or not) or a zip.
pub fn find_identity(viewer: &[u8]) -> Option<(String, String)> {
    let blobs: Vec<Vec<u8>> = if viewer.starts_with(b"PK\x03\x04") {
        zip_entries(viewer).into_iter().map(|(_, b)| b).collect()
    } else {
        vec![crate::inflate::gunzip(viewer)]
    };
    let blocks: Vec<String> = blobs.iter().flat_map(|b| pem_blocks(b)).collect();
    let keys = blocks.iter().filter(|b| b.contains("PRIVATE KEY"));
    for key in keys {
        let Ok(k) = PKey::private_key_from_pem(key.as_bytes()) else { continue };
        for crt in blocks.iter().filter(|b| b.contains("-----BEGIN CERTIFICATE-----")) {
            let Ok(c) = X509::from_pem(crt.as_bytes()) else { continue };
            if c.public_key().map(|p| p.public_eq(&k)).unwrap_or(false) {
                return Some((crt.clone(), key.clone()));
            }
        }
    }
    None
}

/// Every `-----BEGIN X-----` .. `-----END X-----` block in `data`, newline
/// terminated. Binary around them is skipped.
pub fn pem_blocks(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(b) = find(&data[i..], b"-----BEGIN ") {
        let start = i + b;
        // Past this BEGIN, whatever it turns out to be: a stray one in binary
        // must not hide a real block after it.
        i = start + 11;
        let Some(eol) = find(&data[i..], b"-----") else { break };
        let label = &data[i..i + eol];
        if label.is_empty() || label.len() > 40
            || !label.iter().all(|c| c.is_ascii_uppercase() || *c == b' ')
        {
            continue;
        }
        let end_marker = [b"-----END ".as_slice(), label, b"-----"].concat();
        let Some(e) = find(&data[start..], &end_marker) else { continue };
        let end = start + e + end_marker.len();
        if let Ok(s) = std::str::from_utf8(&data[start..end]) {
            out.push(format!("{s}\n"));
        }
        i = end;
    }
    out
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Every file in a zip, from its central directory: stored and deflated
/// entries; anything else is skipped.
pub fn zip_entries(zip: &[u8]) -> Vec<(String, Vec<u8>)> {
    let u16le = |at: usize| zip.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]) as usize);
    let u32le = |at: usize| zip.get(at..at + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize);
    // The end-of-central-directory record is the last 22 bytes plus a comment.
    let Some(eocd) = (0..zip.len().saturating_sub(21)).rev()
        .find(|&i| zip[i..].starts_with(b"PK\x05\x06")) else { return Vec::new() };
    let (Some(count), Some(mut at)) = (u16le(eocd + 10), u32le(eocd + 16)) else { return Vec::new() };
    let mut out = Vec::new();
    for _ in 0..count {
        if !zip.get(at..).is_some_and(|z| z.starts_with(b"PK\x01\x02")) {
            break;
        }
        let (Some(method), Some(csize), Some(nlen), Some(xlen), Some(clen), Some(local)) =
            (u16le(at + 10), u32le(at + 20), u16le(at + 28), u16le(at + 30), u16le(at + 32), u32le(at + 42))
            else { break };
        let name = String::from_utf8_lossy(zip.get(at + 46..at + 46 + nlen).unwrap_or(&[])).into_owned();
        at += 46 + nlen + xlen + clen;
        // The local header's name and extra field can differ from the
        // central directory's, so its own lengths say where the data starts.
        let (Some(lnlen), Some(lxlen)) = (u16le(local + 26), u16le(local + 28)) else { continue };
        let data_at = local + 30 + lnlen + lxlen;
        let Some(raw) = zip.get(data_at..data_at + csize) else { continue };
        match method {
            0 => out.push((name, raw.to_vec())),
            8 => out.push((name, crate::inflate::inflate(raw))),
            _ => {}
        }
    }
    out
}

/// Seconds since the epoch.
fn epoch(t: &Asn1TimeRef) -> Option<i64> {
    let d = Asn1Time::from_unix(0).ok()?.diff(t).ok()?;
    Some(d.days as i64 * 86400 + d.secs as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::Private;
    use openssl::x509::X509NameBuilder;

    fn key() -> PKey<Private> {
        let g = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(EcKey::generate(&g).unwrap()).unwrap()
    }

    /// A self-signed CN=IPMI certificate valid `from`..`to` (epoch seconds).
    fn cert(k: &PKey<Private>, from: i64, to: i64) -> String {
        let mut n = X509NameBuilder::new().unwrap();
        n.append_entry_by_text("CN", "IPMI").unwrap();
        let n = n.build();
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        b.set_subject_name(&n).unwrap();
        b.set_issuer_name(&n).unwrap();
        b.set_pubkey(k).unwrap();
        b.set_not_before(&Asn1Time::from_unix(from as _).unwrap()).unwrap();
        b.set_not_after(&Asn1Time::from_unix(to as _).unwrap()).unwrap();
        b.sign(k, MessageDigest::sha256()).unwrap();
        String::from_utf8(b.build().to_pem().unwrap()).unwrap()
    }

    fn key_pem(k: &PKey<Private>) -> String {
        String::from_utf8(k.private_key_to_pem_pkcs8().unwrap()).unwrap()
    }

    /// gzip of `data` in DEFLATE stored blocks (RFC 1951 3.2.4, RFC 1952).
    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut o = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
        let chunks: Vec<&[u8]> = data.chunks(0xffff).collect();
        for (i, c) in chunks.iter().enumerate() {
            o.push((i + 1 == chunks.len()) as u8);
            o.extend((c.len() as u16).to_le_bytes());
            o.extend((!(c.len() as u16)).to_le_bytes());
            o.extend(*c);
        }
        o.extend([0; 8]); // CRC and size: not checked
        o
    }

    /// A zip (APPNOTE 4.3) of `files`, each deflated as one stored block when
    /// `deflate`, else stored.
    fn zip(files: &[(&str, &[u8])], deflate: bool) -> Vec<u8> {
        let (mut body, mut cd) = (Vec::new(), Vec::new());
        for (name, data) in files {
            let packed = if deflate {
                let mut d = vec![1];
                d.extend((data.len() as u16).to_le_bytes());
                d.extend((!(data.len() as u16)).to_le_bytes());
                d.extend(*data);
                d
            } else {
                data.to_vec()
            };
            let method: u16 = if deflate { 8 } else { 0 };
            let local = body.len() as u32;
            body.extend(b"PK\x03\x04");
            body.extend([20, 0, 0, 0]);
            body.extend(method.to_le_bytes());
            body.extend([0; 8]); // time, date, crc
            body.extend((packed.len() as u32).to_le_bytes());
            body.extend((data.len() as u32).to_le_bytes());
            body.extend((name.len() as u16).to_le_bytes());
            body.extend(0u16.to_le_bytes());
            body.extend(name.as_bytes());
            body.extend(&packed);
            cd.extend(b"PK\x01\x02");
            cd.extend([20, 0, 20, 0, 0, 0]);
            cd.extend(method.to_le_bytes());
            cd.extend([0; 8]);
            cd.extend((packed.len() as u32).to_le_bytes());
            cd.extend((data.len() as u32).to_le_bytes());
            cd.extend((name.len() as u16).to_le_bytes());
            cd.extend([0; 12]); // extra, comment, disk, internal & external attrs
            cd.extend(local.to_le_bytes());
            cd.extend(name.as_bytes());
        }
        let cd_at = body.len() as u32;
        let n = files.len() as u16;
        body.extend(&cd);
        body.extend(b"PK\x05\x06");
        body.extend([0; 4]);
        body.extend(n.to_le_bytes());
        body.extend(n.to_le_bytes());
        body.extend((cd.len() as u32).to_le_bytes());
        body.extend(cd_at.to_le_bytes());
        body.extend([0; 2]);
        body
    }

    /// A pack200 archive as the X9 serves one: magic, bands, and the resource
    /// files' bytes verbatim in archive order — server.crt, then the client
    /// key, then the client certificate — among binary class data.
    fn pack(files: &[&str]) -> Vec<u8> {
        let mut p = vec![0xca, 0xfe, 0xd0, 0x0d, 0x01, 0xa0];
        p.extend((0..=255u8).cycle().take(3000));
        for f in files {
            p.extend(f.as_bytes());
            p.extend([0, 0x80, 0xff, 0x2d]); // a stray '-' between files
        }
        p.extend([0xfe; 100]);
        p
    }

    const Y2016: i64 = 1_463_651_196; // 2016-05-19 09:46:36
    const Y2026: i64 = 1_779_011_196; // 2026-05-17 09:46:36

    #[test]
    fn the_x9_viewer_layout_yields_its_client_pair() {
        // X9 (iKVM 1.69.39): res/server.crt, res/client.key, res/client.crt.
        let (server, client) = (key(), key());
        let server_crt = cert(&server, Y2016, Y2026);
        let (crt, k) = (cert(&client, Y2016, Y2026), key_pem(&client));
        let viewer = gzip(&pack(&[&server_crt, &k, &crt]));
        let (c, kk) = find_identity(&viewer).expect("pair found");
        assert_eq!((c.as_str(), kk.as_str()), (crt.as_str(), k.as_str()));
        let id = Identity::new(c, kk, Origin::Bmc).unwrap();
        assert_eq!((id.not_before, id.not_after), (Y2016, Y2026));
    }

    #[test]
    fn the_x10_viewer_layout_has_no_client_pair() {
        // X10 (iKVM 1.69.44): only res/server.crt; its stunnel presents no
        // client certificate at all.
        let viewer = gzip(&pack(&[&cert(&key(), Y2016, Y2026)]));
        assert_eq!(find_identity(&viewer), None);
    }

    #[test]
    fn a_key_without_its_certificate_is_no_pair() {
        let viewer = pack(&[&cert(&key(), Y2016, Y2026), &key_pem(&key())]);
        assert_eq!(find_identity(&viewer), None);
    }

    #[test]
    fn a_plain_jar_is_read_as_a_zip_stored_or_deflated() {
        let (server, client) = (key(), key());
        let server_crt = cert(&server, Y2016, Y2026);
        let (crt, k) = (cert(&client, Y2016, Y2026), key_pem(&client));
        for deflate in [false, true] {
            let jar = zip(&[("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\n"),
                            ("res/server.crt", server_crt.as_bytes()),
                            ("res/client.crt", crt.as_bytes()),
                            ("res/client.key", k.as_bytes())], deflate);
            let names: Vec<String> = zip_entries(&jar).into_iter().map(|(n, _)| n).collect();
            assert_eq!(names.len(), 4);
            assert_eq!(names[2], "res/client.crt");
            assert_eq!(find_identity(&jar), Some((crt.clone(), k.clone())));
        }
    }

    #[test]
    fn pem_blocks_skip_what_is_not_pem() {
        let data = b"\x00-----BEGIN junk\x01 no end\n-----BEGIN CERTIFICATE-----\nQUJD\n\
-----END CERTIFICATE-----\x00\xff-----BEGIN PRIVATE KEY-----\nREVG\n-----END PRIVATE KEY-----";
        let b = pem_blocks(data);
        assert_eq!(b, vec![
            "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n".to_string(),
            "-----BEGIN PRIVATE KEY-----\nREVG\n-----END PRIVATE KEY-----\n".to_string(),
        ]);
    }

    #[test]
    fn the_jnlp_names_its_main_jar() {
        let jnlp = r#"<jnlp spec="1.0+" codebase="https://192.0.2.10:443/"><resources>
<property name="jnlp.packEnabled" value="true"/>
<jar href="iKVM__V1.69.39.0x0.jar" download="eager" main="true"/></resources>
<resources os="Linux" arch="x86_64"><nativelib href="liblinux_x86_64__V1.0.5.jar"/></resources></jnlp>"#;
        assert_eq!(jar_href(jnlp).as_deref(), Some("iKVM__V1.69.39.0x0.jar"));
        assert_eq!(jar_href(r#"<jar href="https://example.invalid/x.jar"/>"#), None);
        assert_eq!(jar_href("<jnlp></jnlp>"), None);
    }

    #[test]
    fn the_bundled_pair_is_the_2016_to_2026_certificate() {
        let b = bundled();
        assert_eq!((b.not_before, b.not_after), (Y2016, Y2026));
        assert!(find_identity(format!("{}{}", b.cert_pem, b.key_pem).as_bytes()).is_some());
    }

    #[test]
    fn a_refusal_is_described_by_its_alert() {
        let e = |n: u8| std::io::Error::new(std::io::ErrorKind::Other,
            format!("the handshake failed: error:0A000415:ssl/tls alert:SSL alert number {n}"));
        assert!(describe(&e(45), true, false).contains("most likely the BMC's NTP; turn NTP off"));
        assert!(describe(&e(45), true, true).contains("although it was paused"));
        assert!(describe(&e(45), false, false).contains("refused the client certificate as expired"));
        assert!(describe(&e(40), false, false).contains("wants a client certificate"));
        assert!(describe(&e(48), false, false).contains("does not trust"));
    }

    #[test]
    fn a_cache_file_round_trips_and_an_empty_one_is_none() {
        let b = bundled();
        let text = format!("# iKVM.jar sha256 00\n{}{}", b.cert_pem, b.key_pem);
        let c = from_cache(&text).unwrap();
        assert_eq!((c.origin, c.not_after), (Origin::Cached, Y2026));
        assert!(from_cache("# iKVM.jar sha256 00\n").is_none());
    }
}
