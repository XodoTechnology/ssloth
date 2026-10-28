//! Gigabyte BMCs running Avocent/Emerson "MergePoint Embedded Management
//! Software" — the sixth family, and the only one whose console is neither RFB,
//! IVTP nor a WebSocket.
//!
//! Observed on a Gigabyte AST2400 board (Mbedthis-Appweb 2.4.2, Avocent
//! copyright 2001-2015, `gbtdata` power extension):
//!
//!   - web login   : `POST /data/login` (form) -> XML `<authResult>0</authResult>`
//!                   and an `_appwebSessionId_` cookie. Every later GET carries
//!                   `?ST1=<token>`, every XHR an `ST2:` header — two different
//!                   CSRF tokens, both minted into `index.html`.
//!   - KVM console : Avocent APCP/AVSP on TCP 2068 (`kvm.rs`)
//!   - preview     : `data?get=consolePreview[force]` then `preview/scapture0.png`
//!   - power       : IPMI-over-LAN, which this BMC leaves enabled
//!
//! Two quirks are load-bearing:
//!
//! **The console credentials die with the web session.** `viewer.jnlp(...)`
//! mints a one-shot numeric user/password pair for port 2068, but they are only
//! honoured while the web session that minted them is still logged in — log out
//! first and the console login comes back `ACCESS_DENIED` (status 3), which
//! looks exactly like a wrong password. So a console session holds the web
//! session open for its whole life and logs out at the end.
//!
//! **The BMC's TLS offers Diffie-Hellman parameters below OpenSSL's floor.**
//! Left to choose, the server picks a DHE suite and the handshake dies with
//! "dh key too small" on both 443 and 2068. Excluding DHE — rather than lowering
//! the security level, which would also accept the weak parameters everywhere
//! else — makes it settle on plain RSA key exchange and AES256-GCM. That needs a
//! cipher list, which `native_tls` cannot express, so this family talks to
//! OpenSSL directly; the crate is already in the tree underneath `native-tls`.

pub mod kvm;
pub mod vmedia;

use openssl::ssl::{SslConnector, SslMethod, SslOptions, SslStream, SslVerifyMode, SslVersion};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(12);

/// `Launch::platform` for a launch minted by iDRAC 8, whose virtual media
/// differs in its map request.
pub const IDRAC8: &str = "iDRAC8";

/// Console and virtual-media both live here; the JNLP names it twice
/// (`kmport`/`vport`) but has only ever been seen with one value.
pub const KVM_PORT: u16 = 2068;

/// This BMC is weak in two separate ways and each needs its own answer.
///
/// Its Diffie-Hellman group is far below any modern floor, so a DHE suite dies
/// with `tls_process_ske_dhe:dh key too small`. Excluding DHE outright is the
/// fix: the server then settles on plain RSA key exchange with AES256-GCM,
/// which is sound.
///
/// Its certificate is 1024-bit RSA (Avocent's own, issued 2016), which trips
/// `EE certificate key too weak` on any distribution whose openssl.cnf raises
/// the default security level to 2 — as this one does. There is no second
/// certificate to reach for, so the level has to come down. Dropping it to 0
/// alone would *also* re-admit the weak DH group, which is why both halves are
/// here: accept the certificate we cannot change, refuse the key exchange we
/// can.
const CIPHERS: &str = "DEFAULT:!DH:!kDHE:@SECLEVEL=0";

/// What an unauthenticated probe can tell us.
#[derive(Clone, Debug)]
pub struct Info {
    /// The product name off the login page, e.g. "MergePoint® Embedded
    /// Management Software".
    pub product: String,
    /// The web server it identifies as; recorded because it is half the
    /// fingerprint.
    pub server: String,
}

/// A logged-in web session. All three parts are needed: the cookie
/// authenticates, `st1` authorises a GET and `st2` authorises an XHR.
pub struct Session {
    pub cookie: String,
    pub st1: String,
    pub st2: String,
}

/// Console launch parameters, parsed out of `viewer.jnlp(...)`.
///
/// `user`/`pass` are decimal strings minted per launch. They are not account
/// credentials — on this firmware they are consecutive `rand()` values — and
/// they stop working the moment the web session ends.
#[derive(Clone, Debug)]
/// Some fields are unread: they record what the JNLP carries so a future change
/// does not have to re-derive it from the vendor client.
#[allow(dead_code)]
pub struct Launch {
    pub user: String,
    pub pass: String,
    pub km_port: u16,
    pub v_port: u16,
    /// "ASPEED" on this board; the video codec follows from it.
    pub platform: String,
    /// AVSP protocol version the BMC advertised in the JNLP (2 here).
    pub version: u8,
}

fn ioerr<S: AsRef<str>>(m: S) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, m.as_ref().to_string())
}

fn oerr<E: std::fmt::Display>(e: E) -> std::io::Error {
    ioerr(e.to_string())
}

/// Either half of what APCP can hand back: the console channels come out of the
/// negotiation wrapped in TLS, the virtual-media channel stays in the clear.
///
/// One type rather than two code paths, because everything above the socket —
/// framing, timeouts, teardown — is identical either way.
pub enum Stream {
    Plain(TcpStream),
    Tls(Box<SslStream<TcpStream>>),
}

impl Stream {
    pub fn set_read_timeout(&self, d: Option<Duration>) -> std::io::Result<()> {
        match self {
            Stream::Plain(t) => t.set_read_timeout(d),
            Stream::Tls(s) => s.get_ref().set_read_timeout(d),
        }
    }

    pub fn shutdown(&mut self) {
        match self {
            Stream::Plain(t) => { let _ = t.shutdown(std::net::Shutdown::Both); }
            Stream::Tls(s) => { let _ = s.shutdown(); }
        }
    }
}

impl Read for Stream {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(t) => t.read(b),
            Stream::Tls(s) => s.read(b),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(t) => t.write(b),
            Stream::Tls(s) => s.write(b),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Stream::Plain(t) => t.flush(),
            Stream::Tls(s) => s.flush(),
        }
    }
}

/// Start TLS on a socket that is already connected — the console port needs
/// this, because its APCP negotiation happens in the clear first.
pub fn tls_over(host: &str, tcp: TcpStream) -> std::io::Result<SslStream<TcpStream>> {
    let mut b = SslConnector::builder(SslMethod::tls_client()).map_err(oerr)?;
    b.set_verify(SslVerifyMode::NONE);
    b.set_cipher_list(CIPHERS).map_err(oerr)?;
    // The Dell PowerEdge C builds of the same firmware (2013) speak nothing
    // newer than TLS 1.0, and predate the renegotiation-indication extension
    // that OpenSSL 3 otherwise insists on. Neither setting changes what a
    // newer MergePoint negotiates.
    b.set_min_proto_version(Some(SslVersion::TLS1)).map_err(oerr)?;
    b.set_options(SslOptions::ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
    b.build()
        .configure()
        .map_err(oerr)?
        .verify_hostname(false)
        // The BMC has no SNI name and its certificate says "avocent.com"; the
        // extension only invites a different, equally wrong, certificate.
        .use_server_name_indication(false)
        .connect(host, tcp)
        .map_err(oerr)
}

/// Run the APCP negotiation on a freshly connected socket and hand back the
/// channel it agreed to, wrapping it in TLS if that is what it asked for.
///
/// `kind` is the channel type: 2 for virtual media, 3 for console control, 4
/// for console video. The three do not agree on the answer — this firmware
/// insists on TLS for 3 and 4 and offers only cleartext for 2 — so neither can
/// be assumed. Bit 0 (cleartext) wins over bit 2 (TLS) when both are set, which
/// is the order the vendor client checks them in.
///
/// `version` is the protocol the client announces: the console client says
/// 2.34, the media client says 0.0, and they are not interchangeable.
pub fn apcp_channel(host: &str, port: u16, kind: u8, version: (u8, u8))
    -> std::io::Result<Stream>
{
    let mut tcp = crate::net::connect(host, port, Some(TIMEOUT))?;
    tcp.set_nodelay(true).ok();
    tcp.set_read_timeout(Some(Duration::from_secs(30)))?;

    let mut hello = Vec::with_capacity(53);
    hello.extend_from_slice(b"APCP");
    hello.extend_from_slice(&53u32.to_be_bytes());
    hello.extend_from_slice(&0x0100u16.to_be_bytes());
    hello.extend_from_slice(&0u16.to_be_bytes());
    hello.push(kind);
    hello.push(version.0);
    hello.push(version.1);
    hello.push(0);
    hello.extend_from_slice(&5u32.to_be_bytes()); // we accept cleartext or TLS
    hello.push(32);
    hello.extend_from_slice(&nonce32());
    tcp.write_all(&hello)?;

    let mut r = [0u8; 53];
    tcp.read_exact(&mut r)?;
    if &r[..4] != b"APCP" {
        return Err(ioerr("no APCP header from the channel port"));
    }
    if u16::from_be_bytes([r[8], r[9]]) != 0x8100 {
        return Err(ioerr("unexpected APCP message type"));
    }
    let caps = u32::from_be_bytes([r[14], r[15], r[16], r[17]]);
    let redirect = u16::from_be_bytes([r[18], r[19]]);
    // A non-zero port means "carry on over there instead".
    if redirect != 0 && redirect != port {
        return apcp_channel(host, redirect, kind, version);
    }
    if caps & 1 != 0 {
        return Ok(Stream::Plain(tcp));
    }
    if caps & 4 != 0 {
        return Ok(Stream::Tls(Box::new(tls_over(host, tcp)?)));
    }
    Err(ioerr(format!("the channel offered nothing usable (capabilities {caps})")))
}

/// 32 random bytes for the APCP nonce. This firmware echoes zeros back and
/// never refers to it again, but the field is mandatory and length-checked.
fn nonce32() -> [u8; 32] {
    let mut n = [0u8; 32];
    crate::rand::fill(&mut n);
    n
}

/// A 32-bit nonce for the console login, from the same source as the APCP one.
pub fn nonce_u32() -> u32 {
    u32::from_be_bytes(nonce32()[..4].try_into().unwrap())
}

/// A TLS connection this BMC will actually complete.
fn tls(host: &str, port: u16) -> std::io::Result<SslStream<TcpStream>> {
    let tcp = crate::net::connect(host, port, Some(TIMEOUT))?;
    tcp.set_nodelay(true).ok();
    tcp.set_read_timeout(Some(TIMEOUT))?;
    tls_over(host, tcp)
}

/// One HTTPS request, retried if the server drops the body.
///
/// Appweb 2.4 under connection pressure sends a complete set of headers —
/// `Content-length` included — and then closes without the body. It recovers
/// within a second or two. Retrying is safe for a GET; the login POST is not
/// retried, because re-sending it could leave a second session behind and a
/// leaked session here costs a slot in a very small pool.
pub(super) fn https(
    host: &str,
    method: &str,
    path: &str,
    sess: Option<&Session>,
    body: Option<&str>,
) -> std::io::Result<(u16, String, Vec<u8>)> {
    let mut last = https_once(host, method, path, sess, body);
    if method != "GET" {
        return last;
    }
    for wait in [300u64, 900] {
        if last.is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(wait));
        last = https_once(host, method, path, sess, body);
    }
    last
}

/// One HTTPS request. Returns (status, response headers, body bytes) — bytes
/// because the console preview comes back as a PNG through the same path.
fn https_once(
    host: &str,
    method: &str,
    path: &str,
    sess: Option<&Session>,
    body: Option<&str>,
) -> std::io::Result<(u16, String, Vec<u8>)> {
    let mut s = tls(host, 443)?;
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    if let Some(sess) = sess {
        req.push_str(&format!("Cookie: {}\r\n", sess.cookie));
        // The page scripts attach this to every XHR; the `data` endpoints 401
        // without it even when the cookie and ST1 are both right.
        if !sess.st2.is_empty() {
            req.push_str(&format!("ST2: {}\r\n", sess.st2));
        }
    }
    if let Some(b) = body {
        req.push_str(&format!(
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n",
            b.len()
        ));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }
    s.write_all(req.as_bytes())?;

    // Read to the end of the body rather than to EOF. `read_to_end` is wrong
    // here: this server hands over the headers and the body in separate TLS
    // records and can stall between them, and a stall or an unclean shutdown
    // makes `read_to_end` return an error having produced only the headers. Left
    // unchecked that reads as a valid 200 with an empty body, which made the
    // family probe fail intermittently and fall through to another family.
    let mut raw = Vec::new();
    let mut head_end = None;
    let mut want: Option<usize> = None;
    let mut chunked = false;
    let mut buf = [0u8; 16384];
    loop {
        if head_end.is_none() {
            if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                head_end = Some(i + 4);
                let h = String::from_utf8_lossy(&raw[..i]).to_ascii_lowercase();
                chunked = h.contains("transfer-encoding: chunked");
                want = h.lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse().ok());
            }
        }
        if let Some(he) = head_end {
            // A chunked body ends at its terminator; a Content-Length body at
            // its length; anything else only at EOF.
            if chunked {
                if raw[he..].windows(5).any(|w| w == b"0\r\n\r\n") { break; }
            } else if let Some(n) = want {
                if raw.len() - he >= n { break; }
            }
        }
        match s.read(&mut buf) {
            // EOF. Fine for a response with no declared length; a lie if the
            // server promised a Content-Length it then did not send, which this
            // one does under load — see `https`.
            Ok(0) => {
                if let (Some(he), Some(n)) = (head_end, want) {
                    if raw.len() - he < n {
                        return Err(ioerr(format!(
                            "the BMC closed after the headers with {} of {n} body bytes",
                            raw.len() - he)));
                    }
                }
                break;
            }
            Ok(n) => raw.extend_from_slice(&buf[..n]),
            // An unclean shutdown after a complete body is this firmware's
            // normal way of ending a `Connection: close` response.
            Err(e) => {
                let done = head_end.is_some() && want.is_none() && !chunked;
                if done { break; }
                return Err(e);
            }
        }
    }

    let (head, rest) = match head_end {
        Some(i) => (&raw[..i - 4], &raw[i..]),
        None => (&raw[..], &[][..]),
    };
    let head = String::from_utf8_lossy(head).into_owned();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let body = if chunked { crate::auth::dechunk(rest) } else { rest.to_vec() };
    Ok((status, head, body))
}

/// Text between `<tag>` and `</tag>` in the BMC's little XML replies.
pub(super) fn xml(body: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let i = body.find(&open)? + open.len();
    let j = body[i..].find(&close)? + i;
    Some(body[i..j].trim().to_string())
}

/// Identify a MergePoint BMC without credentials.
///
/// The login page is served unauthenticated and carries two independent marks:
/// the Avocent product title and the Mbedthis Appweb server header. Both are
/// required, because Appweb alone is generic and some other vendors' pages
/// mention Avocent in passing.
pub fn detect(host: &str) -> Option<Info> {
    let (status, head, body) = https(host, "GET", "/login.html", None, None).ok()?;
    if status != 200 {
        return None;
    }
    let text = String::from_utf8_lossy(&body);
    let appweb = head.to_ascii_lowercase().contains("appweb");
    let avocent = text.contains("MergePoint") || text.contains("avctstylesheet");
    if !(appweb && avocent) {
        return None;
    }
    Some(Info {
        product: xml(&text, "title").unwrap_or_else(|| "MergePoint EMS".into()),
        server: head
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("server:"))
            .map(|l| l[7..].trim().to_string())
            .unwrap_or_default(),
    })
}

/// Percent-encode for a form field, as `encodeURIComponent` does.
pub(super) fn urlenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~'
            | b'!' | b'*' | b'\'' | b'(' | b')' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The password encoding the login page uses (`encodeSetValue`): backslash-escape
/// the characters the BMC's own request tokenizer treats as delimiters, *then*
/// percent-encode. A password containing `=` or `&` fails without this, and the
/// failure is indistinguishable from a wrong password.
fn enc_set_value(s: &str) -> String {
    let mut esc = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '\\' | ':' | ',' | '(' | ')' | '=' | '&' | '?') {
            esc.push('\\');
        }
        esc.push(c);
    }
    urlenc(&esc)
}

/// `authResult` values from the login page's own message table.
fn login_reason(code: i32) -> &'static str {
    match code {
        1 => "wrong username or password",
        2 => "missing username",
        3 => "missing password",
        4 => "the account lacks the 'Login to Embedded Management Software' privilege",
        5 => "the maximum number of user sessions is reached",
        6 => "a GUI session for this browser is already active",
        7 => "another session is already open for this user",
        100 => "a firmware update is in progress",
        _ => "login refused",
    }
}

pub fn login(host: &str, user: &str, pass: &str) -> std::io::Result<Session> {
    let form = format!("user={}&password={}", urlenc(user), enc_set_value(pass));
    let (status, head, body) = https(host, "POST", "/data/login", None, Some(&form))?;
    let text = String::from_utf8_lossy(&body).into_owned();
    if status != 200 {
        return Err(ioerr(format!("login failed (HTTP {status})")));
    }
    match xml(&text, "authResult").and_then(|v| v.parse::<i32>().ok()) {
        Some(0) => {}
        Some(code) => return Err(ioerr(format!("{} (authResult {code})", login_reason(code)))),
        None => {
            return Err(ioerr(format!(
                "login response was not the expected XML: {}",
                text.trim().chars().take(160).collect::<String>()
            )))
        }
    }
    let cookie = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("set-cookie: _appwebsessionid_="))
        .and_then(|l| l.splitn(2, ": ").nth(1))
        .and_then(|v| v.split(';').next())
        .map(|s| s.trim().to_string())
        .ok_or_else(|| ioerr("login set no _appwebSessionId_ cookie"))?;

    // The CSRF tokens exist only inside index.html, which the login response
    // points at; there is no endpoint that hands them over on their own.
    let mut sess = Session { cookie, st1: String::new(), st2: String::new() };
    let (_, _, idx) = https(host, "GET", "/index.html", Some(&sess), None)?;
    let idx = String::from_utf8_lossy(&idx).into_owned();
    let (st1, st2) = csrf_tokens(&idx)
        .ok_or_else(|| ioerr("index.html carried no CSRF tokens"))?;
    sess.st1 = st1;
    sess.st2 = st2;
    Ok(sess)
}

/// Pull the two CSRF tokens out of the `new CSRFHandler("ST1", "...", "ST2",
/// "...", true)` call index.html is built around.
fn csrf_tokens(idx: &str) -> Option<(String, String)> {
    // The Dell PowerEdge C build writes them as plain assignments instead:
    //   CSRF_TOKEN_1 = "ST1" + "=" + "<hex>";  CSRF_TOKEN_2_VALUE = "<hex>";
    let assigned = |key: &str| -> Option<String> {
        let rest = &idx[idx.find(key)? + key.len()..];
        let line = &rest[..rest.find(';').unwrap_or(rest.len())];
        let last = line.rsplit('"').nth(1)?;
        (!last.is_empty()).then(|| last.to_string())
    };
    if let (Some(v1), Some(v2)) = (assigned("CSRF_TOKEN_1"), assigned("CSRF_TOKEN_2_VALUE")) {
        return Some((v1, v2));
    }
    let i = idx.find("CSRFHandler(")?;
    let rest = &idx[i..];
    let end = rest.find(')')?;
    let mut quoted = rest[..end].split('"').skip(1).step_by(2);
    let (_n1, v1, _n2, v2) = (quoted.next()?, quoted.next()?, quoted.next()?, quoted.next()?);
    Some((v1.to_string(), v2.to_string()))
}

/// End the web session.
///
/// Not optional politeness: the session pool is small enough that the login
/// page has a dedicated "maximum number of user sessions is reached" message,
/// and a leaked session holds a slot until the idle timeout.
pub fn logout(host: &str, sess: &Session) {
    let path = format!("/data/logout?ST1={}", sess.st1);
    let _ = https(host, "GET", &path, Some(sess), None);
}

/// Mint console credentials for port 2068.
///
/// The URL really is a function call with the parameters inside parentheses —
/// `viewer.jnlp(<ip>@<ipv6 flag>@<cache buster>)` — which is how this web stack
/// spells every parameterised GET.
pub fn kvm_launch(host: &str, sess: &Session) -> std::io::Result<Launch> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let path = format!("/viewer.jnlp({host}@0@{stamp})?ST1={}", sess.st1);
    let (status, _, body) = https(host, "GET", &path, Some(sess), None)?;
    if status != 200 {
        return Err(ioerr(format!("KVM launch refused (HTTP {status})")));
    }
    let text = String::from_utf8_lossy(&body).into_owned();
    let arg = |k: &str| -> Option<String> {
        let pat = format!("<argument>{k}=");
        let i = text.find(&pat)? + pat.len();
        let j = text[i..].find('<')? + i;
        Some(text[i..j].trim().to_string())
    };
    let user = arg("user").ok_or_else(|| ioerr("the JNLP carried no console user"))?;
    let pass = arg("passwd").ok_or_else(|| ioerr("the JNLP carried no console password"))?;
    Ok(Launch {
        user,
        pass,
        km_port: arg("kmport").and_then(|v| v.parse().ok()).unwrap_or(KVM_PORT),
        v_port: arg("vport").and_then(|v| v.parse().ok()).unwrap_or(KVM_PORT),
        // The JNLP sets `platform` twice: the board ("ast2400") and then the
        // codec family ("ASPEED"). The second one wins, which is the one that
        // matters, so take the last.
        platform: text
            .match_indices("<argument>platform=")
            .last()
            .and_then(|(i, p)| {
                let i = i + p.len();
                text[i..].find('<').map(|j| text[i..i + j].trim().to_string())
            })
            .unwrap_or_default(),
        version: arg("version").and_then(|v| v.parse().ok()).unwrap_or(2),
    })
}

/// Mint credentials for the virtual-media channel.
///
/// A separate grant from `kvm_launch`, with its own one-shot user/password, but
/// the same `viewer.jnlp`-style call syntax and the same dependence on the web
/// session staying logged in.
pub fn vm_launch(host: &str, sess: &Session) -> std::io::Result<Launch> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let path = format!("/data?type=jnlp&get=vmStart({host}@0@{stamp})&ST1={}", sess.st1);
    let (status, _, body) = https(host, "GET", &path, Some(sess), None)?;
    if status != 200 {
        return Err(ioerr(format!("virtual-media launch refused (HTTP {status})")));
    }
    let text = String::from_utf8_lossy(&body).into_owned();
    let arg = |k: &str| -> Option<String> {
        let pat = format!("<argument>{k}=");
        let i = text.find(&pat)? + pat.len();
        let j = text[i..].find('<')? + i;
        Some(text[i..j].trim().to_string())
    };
    // The media JNLP spells the password field `password`, where the console's
    // spells it `passwd`.
    let user = arg("user").ok_or_else(|| ioerr("the media JNLP carried no user"))?;
    let pass = arg("password").ok_or_else(|| ioerr("the media JNLP carried no password"))?;
    let port = arg("port").and_then(|v| v.parse().ok()).unwrap_or(KVM_PORT);
    Ok(Launch {
        user,
        pass,
        km_port: port,
        v_port: port,
        platform: String::new(),
        version: 2,
    })
}

/// Ask the BMC to capture a frame, then fetch the PNG it wrote.
///
/// Despite being exposed by the dashboard, `consolePreview[force]` uses the
/// same capture resource as KVM on the tested firmware and can disconnect an
/// active console. Callers must therefore treat this as an exclusive,
/// explicitly requested console operation rather than a background thumbnail.
pub fn preview(host: &str, sess: &Session) -> std::io::Result<crate::image::Image> {
    let path = format!("/data?get=consolePreview[force]&ST1={}", sess.st1);
    let (status, _, body) = https(host, "GET", &path, Some(sess), None)?;
    let text = String::from_utf8_lossy(&body).into_owned();
    if status != 200 {
        return Err(ioerr(format!("preview refused (HTTP {status})")));
    }
    // statusCode is "<n>-preview"; the page's own table names the two failures.
    // The Dell PowerEdge C build of this firmware has no preview at all: its
    // pages never ask for one, and the request comes back with no statusCode.
    let Some(code) = xml(&text, "statusCode")
        .and_then(|s| s.split('-').next().and_then(|n| n.parse::<i32>().ok()))
    else {
        return Err(ioerr("this BMC has no console preview"));
    };
    match code {
        0 => {}
        32 => return Err(ioerr("no video signal detected")),
        33 => return Err(ioerr("the BMC failed to process the preview image")),
        _ => return Err(ioerr(format!("preview capture failed (status {code})"))),
    }
    let path = format!("/preview/scapture0.png?ST1={}", sess.st1);
    let (status, _, png) = https(host, "GET", &path, Some(sess), None)?;
    if status != 200 {
        return Err(ioerr(format!("preview image missing (HTTP {status})")));
    }
    crate::image::decode(&png).ok_or_else(|| ioerr("could not decode the preview PNG"))
}

/// Chassis power. This BMC leaves IPMI-over-LAN enabled, and the web path is a
/// Gigabyte-specific detour (`gbtdata?set=PowerOn` for power-on only), so IPMI
/// is both the simpler and the more uniform route.
pub fn power(host: &str, user: &str, pass: &str, cmd: &str) -> std::io::Result<String> {
    super::quanta::ipmi_power(host, user, pass, cmd)
}

/// Cold-reset the BMC itself.
pub fn reset_bmc(host: &str, user: &str, pass: &str) -> std::io::Result<String> {
    super::quanta::ipmi_mc_reset(host, user, pass)
}
