//! BMC login + KVM session-token retrieval over HTTPS.
//!
//! Flow (verified against ATEN firmware 01.74.19):
//!   1. POST /cgi/login.cgi   name=<user>&pwd=<pass>   -> Set-Cookie: SID=<sid>
//!   2. GET  /cgi/url_redirect.cgi?url_name=man_ikvm_html5_bootstrap  (Cookie: SID)
//!      -> HTML contains  <input id="entry_value" value="<TOKEN>">
//! The TOKEN is a fresh, single-use 24-char base64 string and is the KVM credential.

use std::io::{Read, Write};

/// Some fields are unread: they record the wire format so a future change
/// does not have to re-derive it from the vendor client.
#[allow(dead_code)]
pub struct Session {
    pub host: String,
    pub sid: String,
    pub token: String,
}

/// The X9's web server speaks only TLS 1.0, which Windows' own TLS stack
/// refuses; see `legacy_tls`.
fn tls_connect(host: &str) -> std::io::Result<crate::legacy_tls::Stream> {
    let tcp = crate::net::connect(host, 443, None)?;
    crate::legacy_tls::connect(host, tcp, None)
}

/// As `https`, but keeping the body as bytes — snapshots are images.
fn https_bytes(host: &str, request: &str) -> std::io::Result<(String, Vec<u8>)> {
    let mut s = tls_connect(host)?;
    s.write_all(request.as_bytes())?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).ok();
    let sep = raw.windows(4).position(|w| w == b"\r\n\r\n");
    let (head, body) = match sep {
        Some(i) => (String::from_utf8_lossy(&raw[..i]).into_owned(), raw[i + 4..].to_vec()),
        None => return Ok((String::from_utf8_lossy(&raw).into_owned(), Vec::new())),
    };
    // Snapshots come back chunked, and a megabyte of BMP is not going to
    // reassemble itself.
    let body = if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        dechunk(&body)
    } else {
        body
    };
    Ok((head, body))
}

pub fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        let Some(nl) = body[i..].windows(2).position(|w| w == b"\r\n") else { break };
        let len = usize::from_str_radix(
            String::from_utf8_lossy(&body[i..i + nl]).trim().split(';').next().unwrap_or(""),
            16,
        )
        .unwrap_or(0);
        i += nl + 2;
        if len == 0 || i + len > body.len() {
            break;
        }
        out.extend_from_slice(&body[i..i + len]);
        i += len + 2; // skip the CRLF that ends the chunk
    }
    out
}

/// The BMC's own screen snapshot, as its home page shows it.
///
/// The BMC does not keep one: it answers "File Not Found" until a capture is
/// taken, so the trigger is load-bearing rather than an optimisation. Which
/// trigger depends on the generation, and they are tried in turn:
///
///   - newer (X11): `POST /cgi/op.cgi  op=sys_preview`, guarded by a CSRF token
///   - older (X9):  `POST /cgi/CapturePreview.cgi  IKVM_PREVIEW.XML=(0,0)`
///
/// Capturing takes a moment — the vendor UI waits three seconds — so the image
/// is polled for rather than slept on, which returns sooner when the BMC is
/// quick and still copes when it is not.
///
/// The result is an uncompressed BMP, not JPEG.
pub fn snapshot(host: &str, sid: &str) -> Option<Vec<u8>> {
    if let Some(token) = csrf_token(host, sid) {
        let body = "op=sys_preview";
        // Mirrors what the web UI sends, referer included: this BMC checks it.
        let req = format!(
            "POST /cgi/op.cgi HTTP/1.1\r\nHost: {host}\r\nCookie: {cookie}\r\n\
             CSRF-TOKEN: {token}\r\nX-Requested-With: XMLHttpRequest\r\n\
             Referer: https://{host}/cgi/url_redirect.cgi?url_name=sys_info\r\n\
             Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len(),
        cookie = cookie(sid));
        let _ = https(host, &req);
    } else {
        // Older firmware: no CSRF, and no op.cgi to post to.
        let body = "IKVM_PREVIEW.XML=(0,0)";
        let req = format!(
            "POST /cgi/CapturePreview.cgi HTTP/1.1\r\nHost: {host}\r\nCookie: {cookie}\r\n\
             X-Requested-With: XMLHttpRequest\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len(),
        cookie = cookie(sid));
        let _ = https(host, &req);
    }

    for attempt in 0..10 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        if let Some(img) = fetch_snapshot(host, sid) {
            return Some(img);
        }
    }
    None
}

fn fetch_snapshot(host: &str, sid: &str) -> Option<Vec<u8>> {
    // The timestamp is the web UI's cache-buster; the BMC does not parse it.
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let req = format!(
        "GET /cgi/url_redirect.cgi?url_name=Snapshot&url_type=img&time_stamp={ts} HTTP/1.1\r\n\
         Host: {host}\r\nCookie: {cookie}\r\nAccept: image/*\r\nConnection: close\r\n\r\n",
    cookie = cookie(sid));
    let (head, body) = https_bytes(host, &req).ok()?;
    if std::env::var("BMCKVM_DEBUG").is_ok() {
        eprintln!("[aten-snap] {} | {} bytes", head.lines().next().unwrap_or(""), body.len());
    }
    if !head.starts_with("HTTP/1.1 200") || !body.starts_with(b"BM") {
        return None;
    }
    Some(body)
}

/// The CSRF token newer firmware requires on `op.cgi`. Older firmware has no
/// token and no `op.cgi`, and returns None here.
///
/// It lives on the page the web UI posts from, so look there — the same page the
/// browser sends as its referer.
fn csrf_token(host: &str, sid: &str) -> Option<String> {
    csrf_token_on(host, sid, "sys_info")
}

/// As `csrf_token`, from the page `url_name`. The token is the session's, the
/// same on every page, but a page has to exist to carry it: X9 firmware has
/// no `sys_info`.
pub fn csrf_token_on(host: &str, sid: &str, url_name: &str) -> Option<String> {
    let req = format!(
        "GET /cgi/url_redirect.cgi?url_name={url_name} HTTP/1.1\r\nHost: {host}\r\n\
         Cookie: {cookie}\r\nConnection: close\r\n\r\n",
    cookie = cookie(sid));
    let (_, page) = https(host, &req).ok()?;
    let is_tok = |c: char| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_');
    for marker in ["CSRF_TOKEN", "csrf-token", "csrftoken", "CSRFTOKEN"] {
        let mut from = 0;
        while let Some(i) = page[from..].find(marker) {
            let at = from + i + marker.len();
            from = at;
            // Skip whatever separates the name from the value: `="x"`, `: 'x'`,
            // or a `value="x"` attribute a little further along.
            let tail = &page[at..page.len().min(at + 160)];
            let start = match tail.find("value=") {
                Some(v) if v < 40 => v + 6,
                _ => 0,
            };
            let rest = &tail[start..];
            let Some(b) = rest.find(is_tok) else { continue };
            let tok: String = rest[b..].chars().take_while(|c| is_tok(*c)).collect();
            if tok.len() >= 16 {
                return Some(tok);
            }
        }
    }
    None
}

/// POST a form to `path` as the web UI's page `url_name` does, CSRF token
/// included when there is one. The X9 generation reads it from a header
/// named `CSRF_TOKEN` (its `SmcCsrfInsert`), the newer from `CSRF-TOKEN`;
/// each ignores the other, so both are sent.
pub fn post_form(host: &str, sid: &str, path: &str, body: &str, url_name: &str,
                 csrf: Option<&str>) -> std::io::Result<(String, String)> {
    let token = csrf.map(|t| format!("CSRF_TOKEN: {t}\r\nCSRF-TOKEN: {t}\r\n")).unwrap_or_default();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nCookie: {cookie}\r\n{token}\
         X-Requested-With: XMLHttpRequest\r\n\
         Referer: https://{host}/cgi/url_redirect.cgi?url_name={url_name}\r\n\
         Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    cookie = cookie(sid));
    https(host, &req)
}

/// Drop the web session. These BMCs allow only a handful at a time.
pub fn logout(host: &str, sid: &str) {
    let req = format!(
        "GET /cgi/logout.cgi HTTP/1.1\r\nHost: {host}\r\nCookie: {cookie}\r\n\
         Connection: close\r\n\r\n",
    cookie = cookie(sid));
    let _ = https(host, &req);
}

/// Minimal one-shot HTTPS request returning (headers, body).
fn https(host: &str, request: &str) -> std::io::Result<(String, String)> {
    let mut s = tls_connect(host)?;
    s.write_all(request.as_bytes())?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).ok();
    let text = String::from_utf8_lossy(&raw).into_owned();
    match text.find("\r\n\r\n") {
        Some(i) => Ok((text[..i].to_string(), text[i + 4..].to_string())),
        None => Ok((text, String::new())),
    }
}

impl Session {
    /// Convenience for callers that just want a ready token; discovery uses the
    /// primitives below directly.
    pub fn login(host: &str, user: &str, password: &str) -> std::io::Result<Session> {
        let sid = login(host, user, password)?;
        let token = html5_token(host, &sid)
            .or_else(|| jnlp_token(host, &sid))
            .ok_or_else(|| err("no KVM token from HTML5 bootstrap or Java JNLP"))?;
        Ok(Session { host: host.to_string(), sid, token })
    }
}

/// The session cookie, under both names the firmware uses: Supermicro calls it
/// `SID`, Intel's build of the same firmware `__Host-SID`. Each BMC reads the
/// one it knows and ignores the other.
fn cookie(sid: &str) -> String {
    format!("SID={sid}; __Host-SID={sid}")
}

/// POST credentials to login.cgi and return the SID cookie's value.
///
/// `encodedpwd` is the base64 password Intel's build insists on (its login
/// page fills the hidden field with `btoa(pwd)`); Supermicro's form has no
/// such field and ignores it.
pub fn login(host: &str, user: &str, password: &str) -> std::io::Result<String> {
    let body = format!("name={}&pwd={}&encodedpwd={}", enc(user), enc(password),
                       enc(&b64(password.as_bytes())));
    let req = format!(
        "POST /cgi/login.cgi HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let (headers, _) = https(host, &req)?;
    headers
        .lines()
        .filter(|l| l.to_ascii_lowercase().starts_with("set-cookie:"))
        .filter_map(|l| l.split("SID=").nth(1))
        .map(|v| v.split(';').next().unwrap_or("").to_string())
        .find(|v| !v.is_empty() && v.to_uppercase() != "NULL")
        .ok_or_else(|| err("login rejected - check username/password"))
}

/// X11 HTML5 console token from the bootstrap page (None on X9/X10).
pub fn html5_token(host: &str, sid: &str) -> Option<String> {
    let req = format!(
        "GET /cgi/url_redirect.cgi?url_name=man_ikvm_html5_bootstrap HTTP/1.1\r\nHost: {host}\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n",
    cookie = cookie(sid));
    let (_, page) = https(host, &req).ok()?;
    extract_token(&page)
}

/// Fetch the Java iKVM JNLP and return its first credential argument (the KVM
/// token). On X9/X10 the token equals the SID; fetching also arms the port.
pub fn jnlp_token(host: &str, sid: &str) -> Option<String> {
    jnlp(host, sid).and_then(|body| token_from_jnlp(&body))
}

/// The Java iKVM JNLP itself. Fetching it mints the token it carries, so a
/// caller that wants both the token and the viewer jar's name reads them from
/// one fetch rather than fetching twice.
pub fn jnlp(host: &str, sid: &str) -> Option<String> {
    // The Referer is the console page the browser's button lives on. Older
    // firmware (an X7SB3 on 2016's 3.52) answers 500 without it, and serves
    // the JNLP with it; the newer boards do not care either way.
    let req = format!(
        "GET /cgi/url_redirect.cgi?url_name=ikvm&url_type=jwsk HTTP/1.1\r\nHost: {host}\r\nCookie: {cookie}\r\n\
         Referer: https://{host}/cgi/url_redirect.cgi?url_name=man_ikvm\r\nConnection: close\r\n\r\n",
    cookie = cookie(sid));
    let (_, body) = https(host, &req).ok()?;
    body.contains("<jnlp").then_some(body)
}

/// The KVM token from a JNLP: arguments in order are host, token, token, ...
pub fn token_from_jnlp(body: &str) -> Option<String> {
    let args: Vec<&str> = body.match_indices("<argument>")
        .filter_map(|(i, _)| {
            let rest = &body[i + 10..];
            rest.find("</argument>").map(|e| rest[..e].trim())
        })
        .collect();
    args.get(1).map(|s| s.to_string())
}

/// GET `path` from the BMC's web server inside the session, as bytes.
pub fn get_bytes(host: &str, sid: &str, path: &str) -> std::io::Result<(String, Vec<u8>)> {
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n",
    cookie = cookie(sid));
    https_bytes(host, &req)
}

fn extract_token(html: &str) -> Option<String> {
    // <input ... id="entry_value" ... value="TOKEN">  (attribute order varies)
    let anchor = html.find("entry_value")?;
    let tail = &html[anchor..];
    let vpos = tail.find("value=")?;
    let after = &tail[vpos + 6..];
    let quote = after.chars().next()?;              // ' or "
    let after = &after[1..];
    let end = after.find(quote)?;
    Some(after[..end].to_string())
}

pub fn enc(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => o.push(b as char),
            _ => o.push_str(&format!("%{:02X}", b)),
        }
    }
    o
}

fn err(m: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, m.to_string())
}

/// Standard base64, for `encodedpwd`.
fn b64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let v = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[(v >> (18 - 6 * i)) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}
